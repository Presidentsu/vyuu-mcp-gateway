"""Unit tests for the OAuth authorization-code (phase 4 / A1) token
provider — per-user delegated tokens.

These tests stub the DB session factory + httpx client so we never
touch real Postgres or a real auth server. The end-to-end "row in DB
+ refresh round-trips correctly" guarantee is covered by the
integration tests against the lab once a real upstream is wired.

Coverage:
  - fetch_token raises if no row exists ("user must connect first")
  - fetch_token returns the cached token when not expired
  - fetch_token refreshes when expired, updates the in-memory row
  - refresh-token rotation honoured (RFC 6749 §6)
  - refresh-token absent → keeps the existing one
  - non-200 response from token endpoint surfaces as OAuthTokenError
  - missing access_token in response surfaces as OAuthTokenError
  - per-user lock collapses concurrent refreshes (single-flight)
  - principal_id required (M2M-style call without one is an error)
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest

from vyuu_gateway.db.models import OAuthUserToken
from vyuu_gateway.secrets import InMemorySecretStore
from vyuu_gateway.upstream.oauth import OAuthTokenError
from vyuu_gateway.upstream.oauth_authcode import (
    OAuthAuthCodeConfig,
    OAuthAuthCodeTokenProvider,
)

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _RecordingTokenIssuer:
    """ASGI app that pretends to be the IdP token endpoint. Tracks every
    call so the single-flight test can assert the lock collapsed
    concurrent refreshes."""

    def __init__(
        self,
        *,
        access_token: str = "new-access",
        refresh_token: str | None = "new-refresh",
        expires_in: int | None = 3600,
        scope: str | None = "user:read",
        status_code: int = 200,
        body_override: dict[str, Any] | None = None,
        latency_seconds: float = 0.0,
    ) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_in = expires_in
        self.scope = scope
        self.status_code = status_code
        self.body_override = body_override
        self.latency_seconds = latency_seconds
        self.requests: list[dict[str, str]] = []

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
        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
        self.requests.append({**form, "_authorization": headers.get("authorization", "")})
        if self.latency_seconds > 0:
            await asyncio.sleep(self.latency_seconds)
        if self.body_override is not None:
            payload: dict[str, Any] = self.body_override
        else:
            payload = {"access_token": self.access_token, "token_type": "Bearer"}
            if self.refresh_token is not None:
                payload["refresh_token"] = self.refresh_token
            if self.expires_in is not None:
                payload["expires_in"] = self.expires_in
            if self.scope is not None:
                payload["scope"] = self.scope
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": json.dumps(payload).encode()})


class _FakeSession:
    """In-memory Session stand-in. Holds a dict of OAuthUserToken rows
    keyed by id; supports `scalar(select(...))`, `get(...)`, `commit()`,
    `refresh()`, `expunge()`, and the `with` protocol the provider uses.

    Cheaper to write than spinning up a real DB; the provider's only DB
    interaction surface is "load by tenant/user/server" + "load by id +
    update + commit"."""

    def __init__(
        self,
        rows: dict[UUID, OAuthUserToken] | None = None,
        *,
        dcr_client: Any = None,
    ) -> None:
        self.rows: dict[UUID, OAuthUserToken] = rows or {}
        self.info: dict[str, Any] = {}
        self.commit_count = 0
        # Records every `execute(stmt)` so tests can assert the
        # provider's invalid_client cleanup path actually ran the
        # delete-from-dcr_clients + delete-from-oauth_user_tokens
        # statements without standing up a real DB.
        self.executed_statements: list[Any] = []
        # Optional `McpServerDcrClient`-shaped object returned from
        # `get(McpServerDcrClient, ...)` so DCR-mode tests can seed
        # the credentials the provider expects without a real DB.
        self._dcr_client = dcr_client

    def __enter__(self) -> _FakeSession:
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def scalar(self, statement: Any) -> OAuthUserToken | None:
        # Compile to extract bind params: provider always queries by
        # (tenant_id, user_id, server_id). We match against stored rows.
        params = _compiled_params(statement)
        wanted_tenant = params.get("tenant_id_1")
        wanted_user = params.get("user_id_1")
        wanted_server = params.get("server_id_1")
        for row in self.rows.values():
            if (
                (wanted_tenant is None or row.tenant_id == wanted_tenant)
                and (wanted_user is None or row.user_id == wanted_user)
                and (wanted_server is None or row.server_id == wanted_server)
            ):
                return row
        return None

    def get(self, model: Any, ident: UUID) -> Any:
        # DCR-mode lookup goes through the same `get()` hook for the
        # `McpServerDcrClient` model — return the fake row when seeded.
        from vyuu_gateway.db.models import McpServerDcrClient

        if model is McpServerDcrClient:
            return self._dcr_client
        return self.rows.get(ident)

    def execute(self, statement: Any) -> Any:
        self.executed_statements.append(statement)
        return None

    def commit(self) -> None:
        self.commit_count += 1

    def refresh(self, _row: OAuthUserToken) -> None:
        return None

    def expunge(self, _row: OAuthUserToken) -> None:
        return None


def _compiled_params(statement: Any) -> dict[str, Any]:
    try:
        return dict(statement.compile(compile_kwargs={"literal_binds": False}).params or {})
    except Exception:  # noqa: BLE001
        return {}


def _make_row(
    *,
    tenant_id: UUID,
    user_id: UUID,
    server_id: UUID,
    access_token: str = "old-access",
    refresh_token: str | None = "old-refresh",
    scope: str = "user:read",
    expires_at: datetime | None = None,
) -> OAuthUserToken:
    return OAuthUserToken(
        id=uuid4(),
        tenant_id=tenant_id,
        user_id=user_id,
        server_id=server_id,
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="Bearer",
        scope=scope,
        expires_at=expires_at,
        last_refreshed_at=datetime.now(UTC),
    )


def _build_provider(
    *,
    issuer: _RecordingTokenIssuer | None = None,
    rows: dict[UUID, OAuthUserToken] | None = None,
    tenant_id: UUID,
    server_id: UUID,
    dcr_enabled: bool = False,
) -> tuple[OAuthAuthCodeTokenProvider, _FakeSession, _RecordingTokenIssuer | None]:
    config = OAuthAuthCodeConfig(
        auth_url="https://idp.example/authorize",
        token_url="https://idp.example/token",
        client_id_ref="client-id-ref",
        client_secret_ref="client-secret-ref",
        redirect_uri="https://gateway.example/callback",
        scopes=("user:read",),
        dcr_enabled=dcr_enabled,
    )
    secret_store = InMemorySecretStore()
    secret_store.put(tenant_id, "client-id-ref", "demo-client")
    secret_store.put(tenant_id, "client-secret-ref", "demo-secret")
    # DCR-mode tests need a fake `McpServerDcrClient` row so the
    # provider's `_resolve_client_creds()` doesn't bail out before
    # hitting the issuer. Use a SimpleNamespace so we don't need the
    # real ORM (no DB connection).
    dcr_client = None
    if dcr_enabled:
        from types import SimpleNamespace
        dcr_client = SimpleNamespace(
            client_id="dcr-issued-client",
            client_secret="dcr-issued-secret",
            token_endpoint="https://idp.example/token",
        )
    session = _FakeSession(rows=rows or {}, dcr_client=dcr_client)

    def session_factory() -> _FakeSession:
        return session

    if issuer is None:
        return (
            OAuthAuthCodeTokenProvider(
                config=config,
                tenant_id=tenant_id,
                server_id=server_id,
                secret_store=secret_store,
                db_session_factory=session_factory,
            ),
            session,
            None,
        )

    def http_factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=issuer))  # type: ignore[arg-type]

    return (
        OAuthAuthCodeTokenProvider(
            config=config,
            tenant_id=tenant_id,
            server_id=server_id,
            secret_store=secret_store,
            db_session_factory=session_factory,
            http_client_factory=http_factory,
        ),
        session,
        issuer,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_principal_id_required() -> None:
    """auth_authcode is per-user — a None principal_id means the caller
    forgot to thread the inbound identity through. Fail loud, not
    silent (M2M would be a security violation here)."""

    tenant = uuid4()
    server = uuid4()
    provider, _, _ = _build_provider(tenant_id=tenant, server_id=server)

    with pytest.raises(OAuthTokenError, match="principal_id"):
        asyncio.run(provider.fetch_token(principal_id=None))


def test_no_row_means_user_must_connect_first() -> None:
    """The user hasn't been through /initiate yet → there's no row for
    (tenant, user, server). The provider must surface an actionable
    error rather than silently returning some default."""

    tenant = uuid4()
    server = uuid4()
    user = uuid4()
    provider, _, _ = _build_provider(tenant_id=tenant, server_id=server)

    with pytest.raises(OAuthTokenError, match="not yet authorised"):
        asyncio.run(provider.fetch_token(principal_id=user))


def test_returns_cached_token_when_not_expired() -> None:
    tenant = uuid4()
    server = uuid4()
    user = uuid4()
    row = _make_row(
        tenant_id=tenant,
        user_id=user,
        server_id=server,
        access_token="cached-access",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    issuer = _RecordingTokenIssuer()
    provider, _, _ = _build_provider(
        issuer=issuer, rows={row.id: row}, tenant_id=tenant, server_id=server
    )

    token = asyncio.run(provider.fetch_token(principal_id=user))

    assert token == "cached-access"
    assert issuer.requests == []  # never touched the IdP


def test_refreshes_and_persists_when_expired() -> None:
    tenant = uuid4()
    server = uuid4()
    user = uuid4()
    row = _make_row(
        tenant_id=tenant,
        user_id=user,
        server_id=server,
        access_token="old-access",
        refresh_token="old-refresh",
        expires_at=datetime.now(UTC) - timedelta(seconds=10),  # already expired
    )
    issuer = _RecordingTokenIssuer(
        access_token="fresh-access",
        refresh_token="rotated-refresh",
        expires_in=3600,
        scope="user:read user:write",
    )
    provider, session, _ = _build_provider(
        issuer=issuer, rows={row.id: row}, tenant_id=tenant, server_id=server
    )

    token = asyncio.run(provider.fetch_token(principal_id=user))

    assert token == "fresh-access"
    assert issuer.requests, "expected exactly one token-endpoint hit"
    body = issuer.requests[0]
    assert body["grant_type"] == "refresh_token"
    assert body["refresh_token"] == "old-refresh"
    # Basic auth: client_id:client_secret base64-encoded.
    assert body["_authorization"].startswith("Basic ")
    # Row was persisted (commit fired exactly once).
    assert session.commit_count == 1
    # The cached row the provider mutates also got the new values.
    assert row.access_token == "fresh-access"
    assert row.refresh_token == "rotated-refresh"
    assert row.scope == "user:read user:write"


def test_refresh_keeps_existing_refresh_token_when_response_omits_one() -> None:
    """RFC 6749 §6: the auth server MAY rotate. If it doesn't, the
    existing refresh token must remain usable."""

    tenant = uuid4()
    server = uuid4()
    user = uuid4()
    row = _make_row(
        tenant_id=tenant,
        user_id=user,
        server_id=server,
        refresh_token="keep-me",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    issuer = _RecordingTokenIssuer(refresh_token=None)  # response omits refresh_token
    provider, _, _ = _build_provider(
        issuer=issuer, rows={row.id: row}, tenant_id=tenant, server_id=server
    )

    asyncio.run(provider.fetch_token(principal_id=user))

    assert row.refresh_token == "keep-me"


def test_refresh_fails_when_no_refresh_token_on_row() -> None:
    """If the access token expired and there's no refresh_token to use,
    the user must reconnect — the provider can't synthesise a new
    access token from nothing."""

    tenant = uuid4()
    server = uuid4()
    user = uuid4()
    row = _make_row(
        tenant_id=tenant,
        user_id=user,
        server_id=server,
        refresh_token=None,
        expires_at=datetime.now(UTC) - timedelta(seconds=10),
    )
    provider, _, _ = _build_provider(
        rows={row.id: row}, tenant_id=tenant, server_id=server
    )

    with pytest.raises(OAuthTokenError, match="re-authorise"):
        asyncio.run(provider.fetch_token(principal_id=user))


def test_refresh_invalid_client_drops_dcr_state_and_user_tokens() -> None:
    """U10 — when a DCR-enabled upstream returns RFC 6749 §5.2
    `invalid_client` from the token endpoint, the gateway must drop
    the stale `mcp_server_dcr_clients` row + every `oauth_user_tokens`
    row for the server (those refresh tokens were minted under the
    dead client_id and won't work with a fresh registration).

    The error message guides the user to reconnect; the next
    /initiate call will lazy-re-register via the existing helper.
    """


    tenant = uuid4()
    server = uuid4()
    user = uuid4()
    row = _make_row(
        tenant_id=tenant,
        user_id=user,
        server_id=server,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    issuer = _RecordingTokenIssuer(
        status_code=401,
        body_override={
            "error": "invalid_client",
            "error_description": "Client credentials not recognised",
        },
    )
    provider, session, _ = _build_provider(
        issuer=issuer,
        rows={row.id: row},
        tenant_id=tenant,
        server_id=server,
        dcr_enabled=True,
    )

    with pytest.raises(OAuthTokenError, match="revoked"):
        asyncio.run(provider.fetch_token(principal_id=user))

    # The cleanup ran: one DELETE for dcr_clients + one for user tokens.
    delete_stmts = [
        s for s in session.executed_statements
        if hasattr(s, "is_delete") or "DELETE" in str(s).upper()
    ]
    assert len(delete_stmts) == 2, (
        f"expected DELETE on dcr_clients + DELETE on oauth_user_tokens; "
        f"got {len(delete_stmts)}"
    )
    targeted = {str(s).split()[2] for s in delete_stmts}
    assert "mcp_server_dcr_clients" in targeted
    assert "oauth_user_tokens" in targeted


def test_refresh_invalid_client_skipped_for_static_creds_servers() -> None:
    """`invalid_client` cleanup only fires for `dcr_enabled` upstreams.
    Static-creds servers (GitHub-style) get the same generic OAuth
    error today — the operator dashboard is the source of truth, so
    nuking stored tokens automatically would be the wrong call."""
    tenant = uuid4()
    server = uuid4()
    user = uuid4()
    row = _make_row(
        tenant_id=tenant,
        user_id=user,
        server_id=server,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    issuer = _RecordingTokenIssuer(
        status_code=401,
        body_override={"error": "invalid_client"},
    )
    provider, session, _ = _build_provider(
        issuer=issuer,
        rows={row.id: row},
        tenant_id=tenant,
        server_id=server,
        dcr_enabled=False,
    )

    with pytest.raises(OAuthTokenError, match="401"):
        asyncio.run(provider.fetch_token(principal_id=user))

    # No deletes for static-creds servers — operator owns the lifecycle.
    assert session.executed_statements == []


def test_refresh_surfaces_non_2xx_as_oauth_token_error() -> None:
    tenant = uuid4()
    server = uuid4()
    user = uuid4()
    row = _make_row(
        tenant_id=tenant,
        user_id=user,
        server_id=server,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    issuer = _RecordingTokenIssuer(status_code=401)
    provider, _, _ = _build_provider(
        issuer=issuer, rows={row.id: row}, tenant_id=tenant, server_id=server
    )

    with pytest.raises(OAuthTokenError, match="401"):
        asyncio.run(provider.fetch_token(principal_id=user))


def test_refresh_surfaces_missing_access_token_as_oauth_token_error() -> None:
    tenant = uuid4()
    server = uuid4()
    user = uuid4()
    row = _make_row(
        tenant_id=tenant,
        user_id=user,
        server_id=server,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    issuer = _RecordingTokenIssuer(body_override={"token_type": "Bearer"})
    provider, _, _ = _build_provider(
        issuer=issuer, rows={row.id: row}, tenant_id=tenant, server_id=server
    )

    with pytest.raises(OAuthTokenError, match="missing access_token"):
        asyncio.run(provider.fetch_token(principal_id=user))


def test_refresh_sends_accept_json_header_for_github_compat() -> None:
    """Regression: GitHub's token endpoint returns form-urlencoded by
    default and JSON only when `Accept: application/json` is sent.
    Without this header, `response.json()` fails with "non-JSON".
    The token-exchange POST must always carry the header."""

    tenant = uuid4()
    server = uuid4()
    user = uuid4()
    row = _make_row(
        tenant_id=tenant,
        user_id=user,
        server_id=server,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    issuer = _RecordingTokenIssuer()

    # Wrap the issuer to capture the inbound headers.
    captured_headers: list[dict[str, str]] = []

    class _HeaderCapturingIssuer:
        async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
            captured_headers.append(
                {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
            )
            await issuer(scope, receive, send)

    config = OAuthAuthCodeConfig(
        auth_url="https://idp.example/authorize",
        token_url="https://idp.example/token",
        client_id_ref="cid",
        client_secret_ref="csec",
        redirect_uri="https://gateway.example/callback",
    )
    secret_store = InMemorySecretStore()
    secret_store.put(tenant, "cid", "client-id")
    secret_store.put(tenant, "csec", "client-secret")
    session = _FakeSession(rows={row.id: row})

    def http_factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=_HeaderCapturingIssuer()))  # type: ignore[arg-type]

    provider = OAuthAuthCodeTokenProvider(
        config=config,
        tenant_id=tenant,
        server_id=server,
        secret_store=secret_store,
        db_session_factory=lambda: session,
        http_client_factory=http_factory,
    )

    asyncio.run(provider.fetch_token(principal_id=user))

    assert captured_headers, "expected at least one captured request"
    assert captured_headers[0].get("accept") == "application/json"


def test_concurrent_callers_for_same_user_collapse_to_one_refresh() -> None:
    """The per-user asyncio.Lock must serialise refreshes — N concurrent
    calls during a refresh window must produce ONE token-endpoint call,
    not N. (Different users still proceed in parallel — covered in
    a separate test below.)"""

    tenant = uuid4()
    server = uuid4()
    user = uuid4()
    row = _make_row(
        tenant_id=tenant,
        user_id=user,
        server_id=server,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    issuer = _RecordingTokenIssuer(latency_seconds=0.05)
    provider, _, _ = _build_provider(
        issuer=issuer, rows={row.id: row}, tenant_id=tenant, server_id=server
    )

    async def run() -> list[str]:
        return await asyncio.gather(
            *(provider.fetch_token(principal_id=user) for _ in range(8))
        )

    results = asyncio.run(run())
    assert all(r == issuer.access_token for r in results)
    assert len(issuer.requests) == 1


def test_different_users_do_not_block_each_other() -> None:
    """Per-user locks must not serialise traffic across users — that
    would turn refresh contention from per-user into per-server, which
    defeats the design."""

    tenant = uuid4()
    server = uuid4()
    user_a = uuid4()
    user_b = uuid4()
    row_a = _make_row(
        tenant_id=tenant,
        user_id=user_a,
        server_id=server,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    row_b = _make_row(
        tenant_id=tenant,
        user_id=user_b,
        server_id=server,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    issuer = _RecordingTokenIssuer(latency_seconds=0.05)
    provider, _, _ = _build_provider(
        issuer=issuer,
        rows={row_a.id: row_a, row_b.id: row_b},
        tenant_id=tenant,
        server_id=server,
    )

    async def run() -> None:
        # Two users in parallel — both should land in the issuer with
        # overlap. We can't directly assert overlap (the issuer doesn't
        # measure peak in-flight here), but we can assert two distinct
        # refreshes happened.
        await asyncio.gather(
            provider.fetch_token(principal_id=user_a),
            provider.fetch_token(principal_id=user_b),
        )

    asyncio.run(run())
    assert len(issuer.requests) == 2
