"""OAuth 2.0 JWT-bearer assertion grant (RFC 7523 / phase 5 / A2).

The flow:

  1. Gateway resolves `private_key_ref` from the SecretStore (PEM key).
  2. Builds an assertion JWT with claims {iss, sub, aud, exp, iat, jti,
     **additional_claims} signed by `algorithm` (RS256 / ES256 / PS256).
  3. POSTs to `token_url`:
       grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
       assertion=<signed jwt>
       [scope=...]                 (optional body-form param)
  4. Auth server validates the assertion's signature against the
     gateway's pre-registered public key, then issues a regular bearer
     access token.
  5. Gateway caches the access token until expiry — same caching shape
     as `CachedOAuthTokenProvider` (phase 3); the only difference is
     how the request is authenticated.

Where this fits vs other modes:
- `auth_oauth` (phase 3 client_credentials): symmetric secret, basic auth.
- `auth_authcode` (phase 4): per-user delegated, refresh-token-driven.
- **`auth_jwt_bearer` (phase 5)**: asymmetric service-account identity
  signed with a private key. Gateway acts as the SA. Used by
  Workspace SAs, IAM Roles Anywhere, vendor APIs that require
  asymmetric service identities.

The provider implements `OAuthTokenProvider`; `principal_id` is
ignored because the assertion is gateway-owned (M2M). For Google
Workspace impersonation, the impersonated user identity goes in the
`sub` claim — a single provider instance impersonates a single user.
Per-user impersonation would require one provider per user, which is
out of scope for v1; the configured `subject` is the only identity
threaded through.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import httpx
import jwt

from vyuu_gateway.secrets import SecretStore
from vyuu_gateway.upstream.oauth import OAuthTokenError

_JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"


@dataclass(frozen=True)
class OAuthJwtBearerConfig:
    """Per-server JWT-bearer configuration. Mirrors the JSONB persisted
    in `mcp_servers.auth_jwt_bearer` but as a frozen dataclass for the
    provider runtime."""

    token_url: str
    algorithm: str
    private_key_ref: str
    issuer: str
    subject: str
    audience: str
    scope: str | None = None
    additional_claims: dict[str, Any] = field(default_factory=dict)
    assertion_ttl_seconds: int = 60
    key_id: str | None = None


class OAuthJwtBearerTokenProvider:
    """In-memory token cache + on-demand assertion-grant exchange.

    Same caching contract as `CachedOAuthTokenProvider` — concurrent
    fetches during a refresh are serialized by an async lock so the
    auth server only sees one assertion exchange per refresh, not N.

    The signing key is resolved fresh on every refresh so a rotated
    key in the SecretStore takes effect on the next cycle without
    a gateway restart.
    """

    _SAFETY_BUFFER_SECONDS = 60.0
    _DEFAULT_EXPIRES_IN_SECONDS = 3600.0
    _REQUEST_TIMEOUT_SECONDS = 10.0

    def __init__(
        self,
        *,
        config: OAuthJwtBearerConfig,
        tenant_id: UUID,
        secret_store: SecretStore,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
    ) -> None:
        self._config = config
        self._tenant_id = tenant_id
        self._secret_store = secret_store
        self._clock = clock
        # Two clocks: monotonic for the cache TTL (immune to wall-clock
        # adjustments — important for short-lived tokens) and wall-clock
        # for the JWT iat/exp claims (the auth server compares against
        # its own wall clock, so we must too).
        self._wall_clock = wall_clock
        self._http_client_factory = http_client_factory or (lambda: httpx.AsyncClient())
        self._access_token: str | None = None
        self._expires_at: float = 0.0
        self._lock = asyncio.Lock()

    async def fetch_token(self, *, principal_id: UUID | None = None) -> str:
        # JWT-bearer is a service-account identity owned by the gateway
        # — same token serves every caller. principal_id ignored.
        del principal_id
        if self._access_token is not None and self._clock() < self._expires_at:
            return self._access_token
        async with self._lock:
            if self._access_token is not None and self._clock() < self._expires_at:
                return self._access_token
            await self._refresh()
            assert self._access_token is not None
            return self._access_token

    async def invalidate(self, *, principal_id: UUID | None = None) -> None:
        """A4 — discard the cached service-account token. Next
        fetch_token will mint a fresh assertion + exchange it."""
        del principal_id
        async with self._lock:
            self._access_token = None
            self._expires_at = 0.0

    async def _refresh(self) -> None:
        private_key = await self._secret_store.get_secret(
            self._tenant_id, self._config.private_key_ref
        )

        assertion = self._build_assertion(private_key)

        body: dict[str, str] = {
            "grant_type": _JWT_BEARER_GRANT_TYPE,
            "assertion": assertion,
        }
        if self._config.scope:
            body["scope"] = self._config.scope

        async with self._http_client_factory() as http:
            try:
                response = await http.post(
                    self._config.token_url,
                    data=body,
                    # See `oauth.py` for rationale — RFC says JSON,
                    # GitHub-shaped IdPs need the explicit Accept.
                    headers={"Accept": "application/json"},
                    timeout=self._REQUEST_TIMEOUT_SECONDS,
                )
            except httpx.HTTPError as exc:
                raise OAuthTokenError(
                    f"jwt-bearer token request failed: {exc.__class__.__name__}"
                ) from exc

        if response.status_code != 200:
            raise OAuthTokenError(
                f"jwt-bearer token endpoint returned {response.status_code}"
            )

        try:
            payload: dict[str, Any] = response.json()
        except ValueError as exc:
            raise OAuthTokenError(
                "jwt-bearer token endpoint returned non-JSON"
            ) from exc

        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise OAuthTokenError("jwt-bearer response missing access_token")

        expires_in = payload.get("expires_in")
        if isinstance(expires_in, (int, float)) and expires_in > 0:
            ttl = float(expires_in)
        else:
            ttl = self._DEFAULT_EXPIRES_IN_SECONDS

        self._access_token = token
        self._expires_at = self._clock() + max(0.0, ttl - self._SAFETY_BUFFER_SECONDS)

    def _build_assertion(self, private_key: str) -> str:
        """Build + sign the JWT assertion per RFC 7523 §3.

        Required claims: iss, sub, aud, exp, iat. We also stamp `jti`
        (unique per assertion — RFC 7523 §3 says the auth server MAY
        require it for replay protection) and merge `additional_claims`
        (e.g. Google's required `scope` claim inside the assertion)."""

        now = int(self._wall_clock())
        claims: dict[str, Any] = {
            "iss": self._config.issuer,
            "sub": self._config.subject,
            "aud": self._config.audience,
            "iat": now,
            "exp": now + self._config.assertion_ttl_seconds,
            "jti": _new_jti(),
        }
        # additional_claims merges UNDER the structural ones — the
        # schema validator already rejects overrides at registration
        # time, but we double-check at sign time so a future
        # configuration loophole can't slip an `iss` override past us.
        for k, v in self._config.additional_claims.items():
            if k in claims:
                continue
            claims[k] = v

        headers: dict[str, str] = {}
        if self._config.key_id:
            headers["kid"] = self._config.key_id

        return jwt.encode(
            claims,
            private_key,
            algorithm=self._config.algorithm,
            headers=headers if headers else None,
        )


def _new_jti() -> str:
    """16 bytes of CSPRNG, URL-safe base64 — about 22 chars. Plenty of
    entropy for a single-use assertion identifier."""

    return secrets.token_urlsafe(16)
