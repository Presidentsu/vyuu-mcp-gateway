"""OAuth 2.0 authorization-code (phase 4 / A1) — per-user delegated tokens.

Where phase-3 (`CachedOAuthTokenProvider`) holds ONE gateway-owned
credential per upstream and brokers M2M tokens for all callers, phase-4
holds a refresh token PER (tenant, user, server) and brokers per-user
access tokens.

Lifecycle of a phase-4 token:

  1. Operator registers an MCP with `auth_authcode = {auth_url,
     token_url, client_id_ref, client_secret_ref, scopes, redirect_uri}`.
  2. End user opens `/portal`, hits a catalog row using auth_authcode,
     clicks "Connect".
  3. Portal calls `POST /api/v1/oauth-authcode/{server}/initiate`,
     receives the IdP authorization URL with a signed state token.
  4. Browser navigates to the IdP, user consents.
  5. IdP redirects back to `/api/v1/oauth-authcode/callback` with the
     authorization code + state.
  6. Callback validates state, exchanges code for access + refresh
     tokens, persists to `oauth_user_tokens`.
  7. Subsequent inbound MCP calls from this user trigger
     `OAuthAuthCodeTokenProvider.fetch_token(principal_id)`:
       a. If the access token in DB is still valid → return it.
       b. If expired → use refresh token to get a new access token,
          UPDATE the row, return.
       c. If no row → raise OAuthTokenError("user must connect first").

The provider is one instance per (tenant, server). User identity is
threaded in via `fetch_token(principal_id=...)` per call. This keeps
the upstream connection pool keyed by (tenant, server) — no
fragmentation per-user — while still serving each call with the right
user's token.

Concurrency: a per-(tenant, user, server) `asyncio.Lock` serializes
refreshes. Two concurrent calls from the same user during a refresh
window collapse to ONE token-endpoint hit, not N.

Refresh token rotation: per RFC 6749 §6, the auth server MAY return a
new refresh_token on each refresh. We honor that: if the response
includes a new refresh_token, we update the row.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import httpx
from sqlalchemy import delete as sa_delete
from sqlalchemy import select

from vyuu_gateway.crypto import (
    get_envelope_cipher,
    seal_token,
    unseal_token,
)
from vyuu_gateway.db.models import McpServerDcrClient, OAuthUserToken
from vyuu_gateway.secrets import SecretStore
from vyuu_gateway.siem.bridges import record_tool_auth
from vyuu_gateway.siem.events import ToolAuthAction
from vyuu_gateway.upstream.oauth import OAuthTokenError

logger = logging.getLogger(__name__)


def _looks_like_invalid_client(response: httpx.Response) -> bool:
    """RFC 6749 §5.2 — token endpoint returns 4xx with JSON
    `{"error": "invalid_client", ...}` when the client credentials
    are unknown / revoked. Returns True on that exact shape.

    DCR specifically: the AS issued our client_id at registration
    time, but a later eviction (operator-side delete, AS state
    rotation, idle timeout) drops it. The next refresh hits this
    code path.

    Defensive parsing: malformed JSON / missing `error` field returns
    False so we don't accidentally trigger DCR re-registration on
    unrelated 401s (rate limits, network blips returned as 401).
    """
    if response.status_code not in (400, 401):
        return False
    try:
        body = response.json()
    except ValueError:
        return False
    return isinstance(body, dict) and body.get("error") == "invalid_client"


@dataclass(frozen=True)
class OAuthAuthCodeConfig:
    """Per-server authorization-code configuration. Mirrors the JSONB
    persisted in `mcp_servers.auth_authcode` but as a frozen dataclass
    for the provider runtime.

    `dcr_enabled=True` switches the credential resolution path from
    SecretStore (for static refs) to the `mcp_server_dcr_clients` table
    (for DCR-issued credentials). `auth_url` / `token_url` /
    `client_id_ref` / `client_secret_ref` are unused in DCR mode — the
    token endpoint comes from the dcr_clients row, which was cached at
    registration time from AS metadata discovery.
    """

    auth_url: str
    token_url: str
    client_id_ref: str
    client_secret_ref: str
    redirect_uri: str
    scopes: tuple[str, ...] = ()
    dcr_enabled: bool = False


class OAuthAuthCodeTokenProvider:
    """Per-(tenant, server) provider that brokers per-user access tokens.

    Cheap to construct — no DB / network I/O until `fetch_token` is
    called. The DB session factory is invoked per call so the provider
    can be safely shared across requests / threads.
    """

    _SAFETY_BUFFER_SECONDS = 60.0
    _DEFAULT_EXPIRES_IN_SECONDS = 3600.0
    _REQUEST_TIMEOUT_SECONDS = 10.0

    def __init__(
        self,
        *,
        config: OAuthAuthCodeConfig,
        tenant_id: UUID,
        server_id: UUID,
        secret_store: SecretStore,
        db_session_factory: Any,
        http_client_factory: Any = None,
    ) -> None:
        self._config = config
        self._tenant_id = tenant_id
        self._server_id = server_id
        self._secret_store = secret_store
        self._db_session_factory = db_session_factory
        self._http_client_factory = http_client_factory or (lambda: httpx.AsyncClient())
        # Per-user lock so concurrent calls from the same user
        # collapse to one refresh, but different users don't block.
        self._user_locks: dict[UUID, asyncio.Lock] = {}
        # A4 — set of principal_ids whose cached token has been
        # invalidated by an upstream 401. Next `fetch_token` for any
        # principal in this set forces a refresh-token exchange.
        # Cleared on successful refresh.
        self._invalidated: set[UUID] = set()

    def _seal(
        self, row: OAuthUserToken, value: str | None, field: str
    ) -> str | None:
        # AAD comes from the ROW, not from provider state: one provider
        # instance serves every user of a server, so binding to `self`
        # would seal under the wrong identity and fail to open.
        return seal_token(
            get_envelope_cipher(),
            value,
            tenant_id=row.tenant_id,
            user_id=row.user_id,
            server_id=row.server_id,
            field=field,
        )

    def _unseal(self, row: OAuthUserToken, field: str) -> str | None:
        # AAD is derived from the ROW, not from provider state: one
        # provider instance serves every user of a server, so binding to
        # `self` would authenticate the wrong identity.
        return unseal_token(
            get_envelope_cipher(),
            getattr(row, field),
            tenant_id=row.tenant_id,
            user_id=row.user_id,
            server_id=row.server_id,
            field=field,
        )

    async def fetch_token(self, *, principal_id: UUID | None = None) -> str:
        if principal_id is None:
            raise OAuthTokenError(
                "auth_authcode requires a principal_id "
                "(threaded from the inbound request's identity)"
            )

        lock = self._user_locks.setdefault(principal_id, asyncio.Lock())
        async with lock:
            row = self._load_token_row(principal_id)
            if row is None:
                raise OAuthTokenError(
                    "user has not yet authorised this server "
                    "(POST /api/v1/oauth-authcode/{server}/initiate)"
                )
            # A4 — invalidation flag wins over expiry check. Set by
            # `invalidate(principal_id=...)` when the upstream returns
            # 401 with a token we thought was good.
            if (principal_id in self._invalidated
                    or _is_expired(row)):
                if not row.refresh_token:
                    raise OAuthTokenError(
                        "stored token has expired and no refresh_token is "
                        "available — user must re-authorise"
                    )
                await self._refresh_in_place(row)
                # Clear the invalidation flag — we just got a fresh token.
                self._invalidated.discard(principal_id)
            # AWS-KMS-1 · rows may be sealed. `unseal` passes plaintext
            # through untouched, so a deployment that has not enabled
            # encryption — or has rows written before it did — is
            # unaffected.
            return self._unseal(row, "access_token")

    async def invalidate(self, *, principal_id: UUID | None = None) -> None:
        """A4 — discard the cached token for ONE user. Other users'
        cached tokens stay live (per-user phase-4 semantics).

        Single-flight via the same per-user lock as `fetch_token`, so
        a concurrent fetch in progress completes before invalidation
        takes effect — the invalidated token isn't half-used.
        """
        if principal_id is None:
            return
        lock = self._user_locks.setdefault(principal_id, asyncio.Lock())
        async with lock:
            self._invalidated.add(principal_id)

    def _load_token_row(self, principal_id: UUID) -> OAuthUserToken | None:
        with self._db_session_factory() as session:
            from vyuu_gateway.db.session import bind_tenant_context

            bind_tenant_context(session, self._tenant_id)
            row = cast(
                OAuthUserToken | None,
                session.scalar(
                    select(OAuthUserToken).where(
                        OAuthUserToken.tenant_id == self._tenant_id,
                        OAuthUserToken.user_id == principal_id,
                        OAuthUserToken.server_id == self._server_id,
                    )
                ),
            )
            if row is None:
                return None
            # Detach from session so we can read fields without raising
            # `DetachedInstanceError` after the session closes.
            session.expunge(row)
            return row

    def _invalidate_dcr_state(self) -> None:
        """Drop the stale `mcp_server_dcr_clients` row + every
        `oauth_user_tokens` row for this server.

        Called when the upstream AS returns `invalid_client` at the
        token endpoint — the gateway's DCR-issued credentials are
        dead and every refresh token issued under them is dead too.
        Wiping both means the next operator-side `/initiate` call
        lazy-re-registers via the existing helper, and users see
        "not connected" + a Connect button in /portal so they can
        re-authorize cleanly.

        Single-flight: caller (token refresh path) is already inside
        the per-user `_user_locks` lock, so concurrent refreshes for
        the same user collapse. Different users may hit this in
        parallel — `delete_all_for_server` is idempotent so the
        cleanup is safe to run multiple times.
        """
        from vyuu_gateway.db.session import bind_tenant_context

        with self._db_session_factory() as session:
            bind_tenant_context(session, self._tenant_id)
            # Drop the DCR row first so the next `/initiate` triggers
            # rediscovery + registration.
            session.execute(
                sa_delete(McpServerDcrClient).where(
                    McpServerDcrClient.server_id == self._server_id
                )
            )
            # Drop every stored user token — the refresh tokens were
            # issued under the now-dead client_id and the AS will
            # reject them with the same `invalid_client` error if any
            # other user tries to refresh.
            session.execute(
                sa_delete(OAuthUserToken).where(
                    OAuthUserToken.tenant_id == self._tenant_id,
                    OAuthUserToken.server_id == self._server_id,
                )
            )
            session.commit()
        logger.warning(
            "dcr_client_invalidated_state_dropped",
            extra={
                "tenant_id": str(self._tenant_id),
                "server_id": str(self._server_id),
            },
        )
        record_tool_auth(
            tenant_id=self._tenant_id,
            action=ToolAuthAction.CLIENT_INVALIDATED,
            server_id=self._server_id,
            reason="authorization server rejected the registered client; "
            "registration and every user token dropped",
        )

    async def _resolve_client_creds(self) -> tuple[str, str | None, str]:
        """Return (client_id, client_secret, token_url) for the current
        config — from `mcp_server_dcr_clients` if `dcr_enabled`, else
        from the SecretStore.

        For DCR mode, raises `OAuthTokenError` if no row has been
        provisioned yet (caller hasn't completed the discovery +
        registration in `/initiate` first). Public-client DCR returns
        `client_secret=None`.
        """
        if self._config.dcr_enabled:
            from vyuu_gateway.db.models import McpServerDcrClient
            from vyuu_gateway.db.session import bind_tenant_context

            with self._db_session_factory() as session:
                bind_tenant_context(session, self._tenant_id)
                dcr_row = session.get(McpServerDcrClient, self._server_id)
                if dcr_row is None:
                    raise OAuthTokenError(
                        "DCR client not yet registered for this server — "
                        "complete `/oauth-authcode/{server_id}/initiate` "
                        "first to trigger discovery + registration"
                    )
                return dcr_row.client_id, dcr_row.client_secret, dcr_row.token_endpoint

        client_id = await self._secret_store.get_secret(
            self._tenant_id, self._config.client_id_ref
        )
        client_secret = await self._secret_store.get_secret(
            self._tenant_id, self._config.client_secret_ref
        )
        return client_id, client_secret, self._config.token_url

    async def _refresh_in_place(self, row: OAuthUserToken) -> None:
        """Use the stored refresh token to mint a new access token,
        update the DB row in place, and mutate the cached `row` object
        so the caller sees the new values without re-reading."""

        client_id, client_secret, token_url = await self._resolve_client_creds()

        body: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": self._unseal(row, "refresh_token") or "",
        }

        # Public clients (DCR-issued, no secret) — send client_id in
        # the body per RFC 6749 §3.2.1 instead of HTTP Basic auth.
        # Confidential clients use Basic. Notion + GitHub + Linear all
        # issue confidential clients today; this branch is for forward-
        # compat with PKCE-only AS implementations.
        request_kwargs: dict[str, Any] = {
            "data": body,
            "headers": {"Accept": "application/json"},
            "timeout": self._REQUEST_TIMEOUT_SECONDS,
        }
        if client_secret:
            request_kwargs["auth"] = (client_id, client_secret)
        else:
            body["client_id"] = client_id

        async with self._http_client_factory() as http:
            try:
                response = await http.post(token_url, **request_kwargs)
            except httpx.HTTPError as exc:
                raise OAuthTokenError(
                    f"refresh request failed: {exc.__class__.__name__}"
                ) from exc

        if response.status_code != 200:
            # RFC 6749 §5.2: token endpoint returns 4xx + JSON body
            # `{"error": "<code>", ...}` on failure. `invalid_client`
            # specifically means the AS no longer recognizes our
            # client_id — for DCR upstreams this happens when the
            # gateway-issued credentials get evicted (operator deleted
            # them, AS rotated state, etc.). Detect it, drop the stale
            # `mcp_server_dcr_clients` row + all stored user tokens
            # (those refresh tokens were minted under the old
            # client_id and won't work with a fresh registration),
            # and raise so the user gets prompted to re-Connect.
            # The next `/initiate` call lazy-re-registers.
            if self._config.dcr_enabled and _looks_like_invalid_client(response):
                self._invalidate_dcr_state()
                raise OAuthTokenError(
                    "upstream OAuth client credentials were revoked by the "
                    "authorization server — gateway has dropped the stale "
                    "DCR registration. Reconnect from /portal to issue "
                    "fresh credentials."
                )
            raise OAuthTokenError(
                f"refresh endpoint returned {response.status_code}"
            )

        try:
            payload: dict[str, Any] = response.json()
        except ValueError as exc:
            raise OAuthTokenError("refresh endpoint returned non-JSON") from exc

        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise OAuthTokenError("refresh response missing access_token")

        expires_in = payload.get("expires_in")
        ttl = (
            float(expires_in)
            if isinstance(expires_in, (int, float)) and expires_in > 0
            else self._DEFAULT_EXPIRES_IN_SECONDS
        )
        new_expires_at = datetime.now(UTC) + timedelta(seconds=max(0.0, ttl))

        # Per RFC 6749 §6 the auth server MAY return a new refresh_token
        # — if so, replace the stored one. If absent, keep the old one
        # (the spec doesn't require rotation).
        new_refresh = payload.get("refresh_token")
        new_refresh_value: str | None = (
            new_refresh
            if isinstance(new_refresh, str) and new_refresh
            # Falls back to the EXISTING value, which may be sealed —
            # unseal it so the re-seal below encrypts plaintext rather
            # than encrypting a ciphertext.
            else self._unseal(row, "refresh_token")
        )

        new_scope = payload.get("scope")
        if not isinstance(new_scope, str):
            new_scope = row.scope

        # Persist the new tokens back to the row.
        with self._db_session_factory() as session:
            from vyuu_gateway.db.session import bind_tenant_context

            bind_tenant_context(session, self._tenant_id)
            db_row = session.get(OAuthUserToken, row.id)
            if db_row is None:
                # Row was deleted between read and write — surface as a
                # clear "user must reconnect" error.
                raise OAuthTokenError(
                    "stored token row vanished mid-refresh — user must reconnect"
                )
            db_row.access_token = self._seal(db_row, access_token, "access_token")
            db_row.refresh_token = self._seal(
                db_row, new_refresh_value, "refresh_token"
            )
            db_row.expires_at = new_expires_at
            db_row.scope = new_scope
            db_row.last_refreshed_at = datetime.now(UTC)
            session.commit()
            session.refresh(db_row)
            session.expunge(db_row)

        # Mutate the cached row object the caller is about to read from.
        # Keep the cached row in the SAME representation as the DB, so a
        # later `_unseal` on it behaves identically either way.
        row.access_token = self._seal(row, access_token, "access_token")
        row.refresh_token = self._seal(row, new_refresh_value, "refresh_token")
        row.expires_at = new_expires_at
        row.scope = new_scope


def _is_expired(row: OAuthUserToken) -> bool:
    """Token is treated as expired if `expires_at` is in the past or
    within the safety buffer.

    `expires_at IS NULL` semantics:
    - When `refresh_token` is also NULL → trust the upstream's
      indefinite-lifetime contract (no `expires_in` was returned at
      token exchange, no refresh path exists). GitHub OAuth Apps fall
      in this bucket — their access tokens are long-lived bearers
      that only expire on user revocation. If they DO get revoked
      upstream, the call will return 401 and the lifecycle's
      upstream-error path surfaces that.
    - When `refresh_token` IS present → we have something to refresh
      with, so be conservative and treat NULL as expired so we
      proactively refresh rather than ride on a stale token.
    """

    if row.expires_at is None:
        # No expiry recorded; only refresh proactively if we *can*.
        return row.refresh_token is not None
    safety = timedelta(seconds=OAuthAuthCodeTokenProvider._SAFETY_BUFFER_SECONDS)
    return datetime.now(UTC) + safety >= row.expires_at
