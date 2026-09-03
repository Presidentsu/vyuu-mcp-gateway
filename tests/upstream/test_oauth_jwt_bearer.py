"""Unit tests for the RFC 7523 JWT-bearer assertion grant provider.

These tests stub the SecretStore + httpx token endpoint so we never
touch real network or real JWKS endpoints. The crypto path is real —
we generate an RSA keypair with `cryptography`, sign assertions with
the private key, and verify in the test stub with the public key. If
PyJWT or our claim-construction logic regresses, signature
verification will fail and the test will catch it.

Coverage:
  - Provider builds + signs an assertion with the configured claims
  - Auth header is the bearer token from the response
  - Cache hit on a fresh second call (no second token-endpoint hit)
  - Cache invalidates after expires_in - safety_buffer
  - Concurrent calls collapse to one assertion exchange
  - Non-200 from token endpoint surfaces as OAuthTokenError
  - Missing access_token in body surfaces as OAuthTokenError
  - additional_claims merge — added but cannot override structural ones
  - Signature verification round-trip with auth-server's public key
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from uuid import uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from vyuu_gateway.secrets import InMemorySecretStore
from vyuu_gateway.upstream.oauth import OAuthTokenError
from vyuu_gateway.upstream.oauth_jwt_bearer import (
    OAuthJwtBearerConfig,
    OAuthJwtBearerTokenProvider,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _generate_rsa_keypair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


class _StubAuthServer:
    """ASGI app pretending to be the IdP token endpoint. Verifies the
    incoming assertion against the configured public key (so a sign-
    side regression in our provider trips the test) and returns a
    canned access token + expires_in."""

    def __init__(
        self,
        *,
        public_pem: str,
        audience: str,
        issuer: str,
        access_token: str = "fake-access-token",
        expires_in: int | None = 3600,
        status_code: int = 200,
        body_override: dict[str, Any] | None = None,
        latency_seconds: float = 0.0,
    ) -> None:
        self.public_pem = public_pem
        self.audience = audience
        self.issuer = issuer
        self.access_token = access_token
        self.expires_in = expires_in
        self.status_code = status_code
        self.body_override = body_override
        self.latency_seconds = latency_seconds
        self.requests: list[dict[str, str]] = []
        self.assertions: list[dict[str, Any]] = []

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        body_bytes = b""
        more = True
        while more:
            event = await receive()
            body_bytes += event.get("body", b"")
            more = event.get("more_body", False)
        form = dict(
            f.split("=", 1) for f in body_bytes.decode().split("&") if "=" in f
        )
        # url-decode the assertion field that httpx form-encoded.
        from urllib.parse import unquote_plus

        assertion = unquote_plus(form.get("assertion", ""))
        if assertion:
            decoded = jwt.decode(
                assertion,
                self.public_pem,
                algorithms=["RS256", "RS384", "RS512", "ES256", "PS256"],
                audience=self.audience,
                issuer=self.issuer,
            )
            self.assertions.append(decoded)
        self.requests.append(form)
        if self.latency_seconds > 0:
            await asyncio.sleep(self.latency_seconds)
        if self.body_override is not None:
            payload: dict[str, Any] = self.body_override
        else:
            payload = {"access_token": self.access_token, "token_type": "Bearer"}
            if self.expires_in is not None:
                payload["expires_in"] = self.expires_in
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": json.dumps(payload).encode()})


class _MockClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _build_provider(
    *,
    server_app: _StubAuthServer,
    private_pem: str,
    audience: str = "https://idp.example/token",
    issuer: str = "vyuu-gateway-sa@example.iam.gserviceaccount.com",
    subject: str = "vyuu-gateway-sa@example.iam.gserviceaccount.com",
    additional_claims: dict[str, Any] | None = None,
    scope: str | None = None,
    clock: _MockClock | None = None,
) -> tuple[OAuthJwtBearerTokenProvider, _MockClock]:
    tenant = uuid4()
    store = InMemorySecretStore()
    store.put(tenant, "sa-key", private_pem)
    config = OAuthJwtBearerConfig(
        token_url="https://idp.example/token",
        algorithm="RS256",
        private_key_ref="sa-key",
        issuer=issuer,
        subject=subject,
        audience=audience,
        scope=scope,
        additional_claims=additional_claims or {},
    )
    cache_clock = clock or _MockClock()
    # Wall clock is fixed at a known value so iat/exp are deterministic.
    fixed_wall = time.time()

    def http_factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=server_app))  # type: ignore[arg-type]

    provider = OAuthJwtBearerTokenProvider(
        config=config,
        tenant_id=tenant,
        secret_store=store,
        clock=cache_clock,
        wall_clock=lambda: fixed_wall,
        http_client_factory=http_factory,
    )
    return provider, cache_clock


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_fetch_token_signs_assertion_and_returns_access_token() -> None:
    """Round-trip: provider signs an RS256 assertion, the stub auth
    server verifies the signature against the configured public key,
    and the provider returns the issued access token."""

    private_pem, public_pem = _generate_rsa_keypair()
    issuer = "vyuu-gateway-sa@example.iam.gserviceaccount.com"
    audience = "https://idp.example/token"
    server = _StubAuthServer(public_pem=public_pem, audience=audience, issuer=issuer)
    provider, _ = _build_provider(
        server_app=server,
        private_pem=private_pem,
        audience=audience,
        issuer=issuer,
        subject=issuer,  # SA-as-itself, no impersonation
    )

    token = asyncio.run(provider.fetch_token())

    assert token == server.access_token
    assert len(server.requests) == 1
    assert server.requests[0]["grant_type"] == (
        "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
    )
    # Assertion carried iss/sub/aud + iat/exp/jti.
    claims = server.assertions[0]
    assert claims["iss"] == issuer
    assert claims["sub"] == issuer
    assert claims["aud"] == audience
    assert "iat" in claims
    assert "exp" in claims
    assert claims["exp"] > claims["iat"]
    assert "jti" in claims and claims["jti"]


def test_fetch_token_supports_workspace_impersonation_via_subject() -> None:
    """Google Workspace SA delegation: `sub` is the user-to-impersonate,
    distinct from `iss` which is the SA email. The auth server (Google
    OAuth) uses the assertion to mint a token bound to the impersonated
    user."""

    private_pem, public_pem = _generate_rsa_keypair()
    issuer = "automation-sa@project.iam.gserviceaccount.com"
    impersonated = "alice@corp.example"
    audience = "https://oauth2.googleapis.com/token"
    server = _StubAuthServer(public_pem=public_pem, audience=audience, issuer=issuer)
    provider, _ = _build_provider(
        server_app=server,
        private_pem=private_pem,
        audience=audience,
        issuer=issuer,
        subject=impersonated,
        additional_claims={"scope": "https://www.googleapis.com/auth/drive.readonly"},
    )

    asyncio.run(provider.fetch_token())

    claims = server.assertions[0]
    assert claims["iss"] == issuer
    assert claims["sub"] == impersonated
    assert claims["scope"] == "https://www.googleapis.com/auth/drive.readonly"


def test_fetch_token_caches_until_expiry_minus_safety_buffer() -> None:
    private_pem, public_pem = _generate_rsa_keypair()
    server = _StubAuthServer(
        public_pem=public_pem,
        audience="https://idp.example/token",
        issuer="iss-1",
        expires_in=3600,
    )
    clock = _MockClock()
    provider, _ = _build_provider(
        server_app=server,
        private_pem=private_pem,
        issuer="iss-1",
        subject="iss-1",
        clock=clock,
    )

    asyncio.run(provider.fetch_token())
    clock.advance(60)
    asyncio.run(provider.fetch_token())
    assert len(server.requests) == 1  # still cached
    # Past the expiry minus 60s safety buffer (3600 - 60 = 3540).
    clock.advance(3500)  # total 3560 > 3540 cutoff.
    asyncio.run(provider.fetch_token())
    assert len(server.requests) == 2


def test_concurrent_calls_collapse_to_one_assertion_exchange() -> None:
    """Lock must serialise — N callers during a refresh window emit
    ONE token-endpoint request, not N. Same contract as phase-3."""

    private_pem, public_pem = _generate_rsa_keypair()
    server = _StubAuthServer(
        public_pem=public_pem,
        audience="https://idp.example/token",
        issuer="iss-1",
        latency_seconds=0.05,
    )
    provider, _ = _build_provider(
        server_app=server,
        private_pem=private_pem,
        issuer="iss-1",
        subject="iss-1",
    )

    async def run() -> list[str]:
        return await asyncio.gather(*(provider.fetch_token() for _ in range(8)))

    results = asyncio.run(run())
    assert all(r == server.access_token for r in results)
    assert len(server.requests) == 1


def test_non_2xx_response_surfaces_as_oauth_token_error() -> None:
    private_pem, public_pem = _generate_rsa_keypair()
    server = _StubAuthServer(
        public_pem=public_pem,
        audience="https://idp.example/token",
        issuer="iss-1",
        status_code=401,
    )
    provider, _ = _build_provider(
        server_app=server,
        private_pem=private_pem,
        issuer="iss-1",
        subject="iss-1",
    )

    with pytest.raises(OAuthTokenError, match="401"):
        asyncio.run(provider.fetch_token())


def test_missing_access_token_surfaces_as_oauth_token_error() -> None:
    private_pem, public_pem = _generate_rsa_keypair()
    server = _StubAuthServer(
        public_pem=public_pem,
        audience="https://idp.example/token",
        issuer="iss-1",
        body_override={"token_type": "Bearer"},
    )
    provider, _ = _build_provider(
        server_app=server,
        private_pem=private_pem,
        issuer="iss-1",
        subject="iss-1",
    )

    with pytest.raises(OAuthTokenError, match="missing access_token"):
        asyncio.run(provider.fetch_token())


def test_additional_claims_cannot_override_structural_claims() -> None:
    """Defense in depth: even if a stale config slips an `iss`
    override into additional_claims, the structural claim wins. The
    schema validator rejects overrides at registration time, but the
    provider double-checks at sign time."""

    private_pem, public_pem = _generate_rsa_keypair()
    server = _StubAuthServer(
        public_pem=public_pem,
        audience="https://idp.example/token",
        issuer="real-issuer",
    )
    # additional_claims tries (and fails) to override iss / aud.
    provider, _ = _build_provider(
        server_app=server,
        private_pem=private_pem,
        issuer="real-issuer",
        subject="real-issuer",
        # Schema would reject this, but the provider also enforces it
        # — bypass the schema by going straight to the provider.
        additional_claims={"iss": "evil-issuer", "scope": "drive.read"},
    )

    asyncio.run(provider.fetch_token())

    claims = server.assertions[0]
    assert claims["iss"] == "real-issuer"  # NOT evil-issuer
    assert claims["scope"] == "drive.read"  # additive claim merged


def test_scope_param_is_sent_in_form_body() -> None:
    """When `scope` is set on the spec, it goes in the form-body as
    `scope=...` (separate from any `scope` claim inside the assertion).
    Some auth servers honor body-level scope; others honor only the
    in-assertion scope. Schema lets operators specify either or both."""

    private_pem, public_pem = _generate_rsa_keypair()
    server = _StubAuthServer(
        public_pem=public_pem,
        audience="https://idp.example/token",
        issuer="iss-1",
    )
    provider, _ = _build_provider(
        server_app=server,
        private_pem=private_pem,
        issuer="iss-1",
        subject="iss-1",
        scope="api:read api:write",
    )

    asyncio.run(provider.fetch_token())

    body = server.requests[0]
    # httpx URL-encodes spaces as `+` in form bodies.
    assert body["scope"] == "api%3Aread+api%3Awrite"


def test_principal_id_is_ignored_jwt_bearer_is_m2m() -> None:
    """JWT-bearer is a service-account identity owned by the gateway —
    different callers share the same access token. principal_id must
    NOT cause separate token fetches per caller."""

    private_pem, public_pem = _generate_rsa_keypair()
    server = _StubAuthServer(
        public_pem=public_pem,
        audience="https://idp.example/token",
        issuer="iss-1",
    )
    provider, _ = _build_provider(
        server_app=server,
        private_pem=private_pem,
        issuer="iss-1",
        subject="iss-1",
    )

    user_a = uuid4()
    user_b = uuid4()
    asyncio.run(provider.fetch_token(principal_id=user_a))
    asyncio.run(provider.fetch_token(principal_id=user_b))

    # ONE assertion exchange — both users got the same cached token.
    assert len(server.requests) == 1
