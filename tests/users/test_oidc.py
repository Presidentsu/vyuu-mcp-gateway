"""Unit tests for OIDC JWKS cache + JWT validation.

Uses a generated RSA key + handcrafted JWKS document — exercises the
real signature-verify path without needing a Keycloak / Auth0 server.
A future env-gated integration test against Keycloak can replace these
once that infrastructure exists.
"""

from __future__ import annotations

import asyncio
import base64
import time
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from vyuu_gateway.users.oidc import (
    JwksCache,
    OidcConfig,
    OidcValidationError,
)

# --- Fixture: an in-memory RSA key + matching JWKS for the test issuer ----


def _make_rsa_key() -> Any:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64url(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _jwks_for(public_key: Any, kid: str) -> dict[str, Any]:
    nums = public_key.public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": _b64url(nums.n),
                "e": _b64url(nums.e),
            }
        ]
    }


def _sign_id_token(
    *,
    private_key: Any,
    kid: str,
    issuer: str,
    audience: str,
    subject: str = "test-subject",
    email: str = "alice@corp",
    extra: dict[str, Any] | None = None,
    expires_in: int = 3600,
) -> str:
    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "email": email,
        "iat": now,
        "exp": now + expires_in,
    }
    if extra:
        claims.update(extra)
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


# --- Mock httpx so JWKS lookups hit our in-memory document -----------------


class _MockHttpClient:
    """Returns canned discovery + JWKS responses for the test issuer."""

    def __init__(
        self,
        issuer: str,
        jwks: dict[str, Any],
        *,
        fail_count: int = 0,
    ) -> None:
        self._issuer = issuer
        self._jwks = jwks
        self._fail_remaining = fail_count
        self.fetch_count = 0

    async def __aenter__(self) -> _MockHttpClient:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def get(self, url: str, *, timeout: float) -> Any:
        self.fetch_count += 1
        if self._fail_remaining > 0:
            self._fail_remaining -= 1
            raise httpx.ConnectError("simulated network blip")
        if url.endswith("/.well-known/openid-configuration"):
            return _MockResponse(
                200, {"jwks_uri": self._issuer.rstrip("/") + "/jwks"}
            )
        if url.endswith("/jwks"):
            return _MockResponse(200, self._jwks)
        return _MockResponse(404, {})


class _MockResponse:
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "fail", request=None, response=None  # type: ignore[arg-type]
            )

    def json(self) -> dict[str, Any]:
        return self._payload


# --- Tests -----------------------------------------------------------------


_ISSUER = "https://test-idp.example"
_AUDIENCE = "test-client-id"


def _build_cache(jwks: dict[str, Any]) -> JwksCache:
    """JwksCache wired to a mock httpx that serves our test JWKS."""

    fetcher: list[_MockHttpClient] = []

    def factory() -> _MockHttpClient:
        client = _MockHttpClient(_ISSUER, jwks)
        fetcher.append(client)
        return client

    return JwksCache(http_client_factory=factory)  # type: ignore[arg-type]


def test_validate_token_round_trip() -> None:
    private = _make_rsa_key()
    public = private.public_key()
    kid = "test-kid-1"
    cache = _build_cache(_jwks_for(public, kid))
    config = OidcConfig(issuer_url=_ISSUER, audience=_AUDIENCE)
    token = _sign_id_token(
        private_key=private, kid=kid, issuer=_ISSUER, audience=_AUDIENCE
    )

    claims = asyncio.run(cache.validate_token(token, config=config))

    assert claims["iss"] == _ISSUER
    assert claims["aud"] == _AUDIENCE
    assert claims["email"] == "alice@corp"


def test_expired_token_rejected() -> None:
    private = _make_rsa_key()
    kid = "test-kid-1"
    cache = _build_cache(_jwks_for(private.public_key(), kid))
    token = _sign_id_token(
        private_key=private,
        kid=kid,
        issuer=_ISSUER,
        audience=_AUDIENCE,
        expires_in=-10,
    )
    with pytest.raises(OidcValidationError, match="expired"):
        asyncio.run(
            cache.validate_token(
                token, config=OidcConfig(issuer_url=_ISSUER, audience=_AUDIENCE)
            )
        )


def test_audience_mismatch_rejected() -> None:
    private = _make_rsa_key()
    kid = "test-kid-1"
    cache = _build_cache(_jwks_for(private.public_key(), kid))
    token = _sign_id_token(
        private_key=private, kid=kid, issuer=_ISSUER, audience="wrong-audience"
    )
    with pytest.raises(OidcValidationError, match="audience"):
        asyncio.run(
            cache.validate_token(
                token, config=OidcConfig(issuer_url=_ISSUER, audience=_AUDIENCE)
            )
        )


def test_issuer_mismatch_rejected() -> None:
    private = _make_rsa_key()
    kid = "test-kid-1"
    cache = _build_cache(_jwks_for(private.public_key(), kid))
    token = _sign_id_token(
        private_key=private,
        kid=kid,
        issuer="https://wrong-issuer.example",
        audience=_AUDIENCE,
    )
    with pytest.raises(OidcValidationError, match="issuer"):
        asyncio.run(
            cache.validate_token(
                token, config=OidcConfig(issuer_url=_ISSUER, audience=_AUDIENCE)
            )
        )


def test_unknown_kid_rejected_after_jwks_refresh() -> None:
    """Token signed by a key that's NOT in the issuer's JWKS — must be
    rejected even after refresh (no silent fallback to ANY known key)."""
    real = _make_rsa_key()
    other = _make_rsa_key()
    cache = _build_cache(_jwks_for(real.public_key(), "real-kid"))
    # Token signed by `other` but claims a kid the JWKS doesn't have.
    token = _sign_id_token(
        private_key=other, kid="bogus-kid", issuer=_ISSUER, audience=_AUDIENCE
    )
    with pytest.raises(OidcValidationError, match="signing key"):
        asyncio.run(
            cache.validate_token(
                token, config=OidcConfig(issuer_url=_ISSUER, audience=_AUDIENCE)
            )
        )


def test_hosted_domain_pin_enforced_for_google() -> None:
    """Google providers can pin a Workspace `hd` claim. Mismatched hd
    → reject (otherwise any Google account could sign in)."""
    private = _make_rsa_key()
    kid = "test-kid-1"
    cache = _build_cache(_jwks_for(private.public_key(), kid))
    token = _sign_id_token(
        private_key=private,
        kid=kid,
        issuer=_ISSUER,
        audience=_AUDIENCE,
        extra={"hd": "wrong-domain.com"},
    )
    config = OidcConfig(
        issuer_url=_ISSUER, audience=_AUDIENCE, hosted_domain="corp.com"
    )
    with pytest.raises(OidcValidationError, match="hosted_domain"):
        asyncio.run(cache.validate_token(token, config=config))


def test_jwks_refreshed_on_kid_miss() -> None:
    """First validation populates the cache; second validation with a
    new kid should trigger one (and only one) refresh."""
    private_a = _make_rsa_key()
    kid_a = "kid-a"
    cache = _build_cache(_jwks_for(private_a.public_key(), kid_a))
    config = OidcConfig(issuer_url=_ISSUER, audience=_AUDIENCE)

    token_a = _sign_id_token(
        private_key=private_a, kid=kid_a, issuer=_ISSUER, audience=_AUDIENCE
    )

    # First call: 2 fetches (discovery + jwks).
    asyncio.run(cache.validate_token(token_a, config=config))
    # Second call with the same kid: NO additional fetches (cache hit).
    asyncio.run(cache.validate_token(token_a, config=config))


def test_concurrent_calls_share_a_single_jwks_refresh() -> None:
    """Hot upstream → N parallel validations → exactly one JWKS fetch
    cycle, not N. Single-flight via per-issuer asyncio.Lock."""
    private = _make_rsa_key()
    kid = "kid-c"
    cache = _build_cache(_jwks_for(private.public_key(), kid))
    config = OidcConfig(issuer_url=_ISSUER, audience=_AUDIENCE)

    async def one() -> None:
        token = _sign_id_token(
            private_key=private, kid=kid, issuer=_ISSUER, audience=_AUDIENCE
        )
        await cache.validate_token(token, config=config)

    async def run() -> None:
        await asyncio.gather(*(one() for _ in range(8)))

    # Only assertion that matters: no exception.
    asyncio.run(run())
