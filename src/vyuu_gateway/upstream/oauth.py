"""OAuth 2.0 client-credentials grant for outbound upstream auth.

Some upstream MCPs (Wiz, certain Datadog tenancies, anything OIDC-spec
compliant) require token *exchange* rather than a static API key. The
gateway holds the durable identity (`client_id`, `client_secret`) in the
`SecretStore` and brokers the M2M flow on each upstream connection:

  POST {token_url}
    Authorization: Basic base64(client_id:client_secret)
    Content-Type: application/x-www-form-urlencoded
    Body: grant_type=client_credentials[&scope=...][&audience=...]

  → 200 {"access_token": "...", "token_type": "Bearer", "expires_in": 3600}

The access token rides on every upstream call as
`Authorization: Bearer <access_token>` until it expires, at which point
the next call refreshes it.

Tokens are NEVER persisted by the gateway — only the credential refs
(opaque pointers into the SecretStore) are durable. The token cache is
in-memory and vanishes on gateway restart by design.

For RFC 6749 client-credentials specifically (not the authorization-code
flow that involves user consent / redirects). Authorization code lands
in a future phase.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

import httpx

from vyuu_gateway.secrets import SecretStore


class OAuthTokenError(Exception):
    """Token request failed (network error, 4xx/5xx, malformed response).

    Carries no upstream payload detail — the auth server's body could
    contain identifying info we don't want surfacing in operator-visible
    error strings. The class name alone is operator-actionable.
    """


@dataclass(frozen=True)
class OAuthClientCredentialsConfig:
    """Per-server OAuth 2.0 client-credentials configuration.

    `client_id_ref` and `client_secret_ref` are SecretStore references;
    the gateway resolves them right before each token request, so a
    rotated secret in the store takes effect on the next refresh.
    """

    token_url: str
    client_id_ref: str
    client_secret_ref: str
    scope: str | None = None
    # Some auth servers (Auth0, Okta) require an `audience` claim to
    # constrain which API the token is valid for. Optional per RFC 8693.
    audience: str | None = None


class OAuthTokenProvider(Protocol):
    """Resolves a fresh access token, hiding cache + refresh from callers.

    Implementations:
    - `CachedOAuthTokenProvider` (phase 3 — client-credentials) — one
      gateway-owned credential per server. `principal_id` is ignored.
    - `OAuthAuthCodeTokenProvider` (phase 4 / A1) — per-user delegated
      tokens. `principal_id` is REQUIRED (the user whose stored
      refresh token to use).
    - Test fakes inject pre-canned tokens to bypass the network call.

    The `principal_id` parameter is the discriminator between phase-3
    and phase-4 in a single Protocol: phase 3 implementations ignore
    it, phase 4 implementations raise a clear error when omitted. The
    outbound MCP client passes whatever it has from the lifecycle.
    """

    async def fetch_token(self, *, principal_id: UUID | None = None) -> str:
        """Return a non-expired access token for the configured upstream.

        Args:
            principal_id: For phase-4 (auth_authcode) — the end user
                whose stored token to retrieve. Phase-3 implementations
                ignore this argument.

        Raises:
            OAuthTokenError: if the token endpoint is unreachable, returns
                a non-2xx, or returns an unparseable response. Phase-4
                also raises this when no token row exists for
                `(tenant, principal, server)` — the user must connect
                via `/api/v1/oauth-authcode/{server}/initiate` first.
        """

    async def invalidate(self, *, principal_id: UUID | None = None) -> None:
        """Discard the cached token so the next `fetch_token` does a
        fresh refresh. Used by **A4 — 401-driven refresh**: when an
        upstream returns 401 with what we thought was a valid bearer,
        the gateway invalidates the cached entry and retries once
        before surfacing the failure to the client.

        Phase-3 implementations clear their single in-memory token.
        Phase-4 implementations clear ONLY the (server, principal)
        entry — other users' cached tokens stay live.

        Default no-op so non-cached / test-fake providers don't have
        to override.
        """


class CachedOAuthTokenProvider:
    """In-memory token cache + on-demand refresh per upstream server.

    Tokens are cached until `expires_at - safety_buffer`. On expiry, the
    next `fetch_token()` triggers a fresh `client_credentials` grant.
    Concurrent fetches during a refresh are serialized by an async lock
    so the auth server only sees one token request per refresh, not N
    racing requests.

    The token never leaves memory. The credential refs (the durable
    identity, resolved through `SecretStore`) are pulled fresh on every
    refresh, so a rotated secret in the store takes effect on the next
    cycle without restarting the gateway.
    """

    # 60s buffer means a token cached at T (with `expires_in=3600`) is
    # treated as expired at T+3540. Avoids a race where the gateway sends
    # a token at the exact moment it expires upstream.
    _SAFETY_BUFFER_SECONDS = 60.0
    # Cap default expiry when the token endpoint omits `expires_in`.
    # RFC 6749 says it's optional; conservative default avoids holding a
    # potentially-expired token indefinitely.
    _DEFAULT_EXPIRES_IN_SECONDS = 3600.0
    # Hard timeout on the token request itself. Auth servers should
    # respond well under a second; 10s leaves room for cold-start TLS.
    _REQUEST_TIMEOUT_SECONDS = 10.0

    def __init__(
        self,
        *,
        config: OAuthClientCredentialsConfig,
        tenant_id: UUID,
        secret_store: SecretStore,
        clock: Callable[[], float] = time.monotonic,
        http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
    ) -> None:
        self._config = config
        self._tenant_id = tenant_id
        self._secret_store = secret_store
        self._clock = clock
        # Factory rather than instance so each refresh uses a fresh client
        # (no connection-state leakage across token requests). Tests
        # inject an ASGITransport-backed factory to avoid the network.
        self._http_client_factory = http_client_factory or (lambda: httpx.AsyncClient())
        self._access_token: str | None = None
        self._expires_at: float = 0.0
        self._lock = asyncio.Lock()

    async def fetch_token(self, *, principal_id: UUID | None = None) -> str:
        # Phase-3 ignores principal_id — same gateway-owned credential
        # serves every caller.
        del principal_id
        # Fast path: cached, not yet expired. No lock acquisition.
        if self._access_token is not None and self._clock() < self._expires_at:
            return self._access_token
        async with self._lock:
            # Re-check under the lock — a concurrent caller may have
            # already refreshed while we were waiting on the lock.
            if self._access_token is not None and self._clock() < self._expires_at:
                return self._access_token
            await self._refresh()
            assert self._access_token is not None
            return self._access_token

    async def invalidate(self, *, principal_id: UUID | None = None) -> None:
        """A4 — discard the cached client-credentials token. Next
        fetch_token will refresh from the auth server."""
        del principal_id  # phase-3: gateway-owned, no per-principal split
        async with self._lock:
            self._access_token = None
            self._expires_at = 0.0

    async def _refresh(self) -> None:
        """Issue a `client_credentials` grant and cache the result."""

        client_id = await self._secret_store.get_secret(
            self._tenant_id, self._config.client_id_ref
        )
        client_secret = await self._secret_store.get_secret(
            self._tenant_id, self._config.client_secret_ref
        )

        body: dict[str, str] = {"grant_type": "client_credentials"}
        if self._config.scope:
            body["scope"] = self._config.scope
        if self._config.audience:
            body["audience"] = self._config.audience

        async with self._http_client_factory() as http:
            try:
                response = await http.post(
                    self._config.token_url,
                    data=body,
                    # `Accept: application/json` defends against IdPs
                    # (notably GitHub) that default to form-urlencoded
                    # responses unless explicitly asked for JSON. RFC
                    # 6749 §5.1 mandates JSON; reality varies.
                    headers={"Accept": "application/json"},
                    auth=(client_id, client_secret),
                    timeout=self._REQUEST_TIMEOUT_SECONDS,
                )
            except httpx.HTTPError as exc:
                raise OAuthTokenError(
                    f"token request failed: {exc.__class__.__name__}"
                ) from exc

        if response.status_code != 200:
            # Don't leak the response body — auth servers often echo back
            # the failed credential or other identifying info in errors.
            raise OAuthTokenError(
                f"token endpoint returned {response.status_code}"
            )

        try:
            payload: dict[str, Any] = response.json()
        except ValueError as exc:
            raise OAuthTokenError("token endpoint returned non-JSON") from exc

        token = payload.get("access_token")
        expires_in = payload.get("expires_in")
        if not isinstance(token, str) or not token:
            raise OAuthTokenError("token response missing access_token")

        if isinstance(expires_in, (int, float)) and expires_in > 0:
            ttl = float(expires_in)
        else:
            # RFC 6749 §5.1: expires_in is RECOMMENDED but optional.
            ttl = self._DEFAULT_EXPIRES_IN_SECONDS

        self._access_token = token
        self._expires_at = self._clock() + max(0.0, ttl - self._SAFETY_BUFFER_SECONDS)
