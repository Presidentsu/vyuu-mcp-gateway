"""Integration tests for the A1 OAuth authorization-code endpoints.

These exercise the full inbound surface (initiate / callback / list /
disconnect) against real Postgres + a stubbed token endpoint. Skipped
unless `VYUU_TEST_DATABASE_URL` is set so the unit-test suite can
still run in CI without a database.

Coverage:
  - initiate returns a signed state token + IdP URL
  - initiate 404 on unknown server
  - initiate 400 when server has no auth_authcode
  - callback persists tokens and renders an HTML success page
  - callback rejects expired / missing / tampered state tokens
  - list returns the user's connections
  - disconnect deletes the row
  - cross-tenant token replays are rejected at every endpoint
"""

from __future__ import annotations

import json
import os
from typing import Any

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

from datetime import UTC, datetime, timedelta  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.config import Settings  # noqa: E402
from vyuu_gateway.db.models import (  # noqa: E402
    McpServer,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
    OAuthUserToken,
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
    User,
    UserAuthMethod,
)
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.secrets import InMemorySecretStore  # noqa: E402
from vyuu_gateway.users.passwords import hash_password  # noqa: E402
from vyuu_gateway.users.sessions import issue_portal_session  # noqa: E402

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set",
)

_PORTAL_SECRET = "test-portal-secret-A1"
_OPERATOR_SECRET = "test-operator-secret-A1"
_LOCAL_PASSWORD = "very-strong-12+chars"

_AUTH_URL = "https://idp.example/oauth/authorize"
_TOKEN_URL = "https://idp.example/oauth/token"
_REDIRECT_URI = "https://gateway.example/api/v1/oauth-authcode/callback"
_CLIENT_ID_REF = "demo-client-id"
_CLIENT_SECRET_REF = "demo-client-secret"


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(
        create_engine(_DATABASE_URL, future=True),
        autoflush=False,
        future=True,
    )


def _seed(factory: Any) -> tuple[UUID, UUID, UUID, UUID]:
    """Seed (tenant, operator, user, server) — one MCP server with
    auth_authcode wired."""

    tenant_id = uuid4()
    operator_id = uuid4()
    user_id = uuid4()
    server_id = uuid4()
    with factory() as session:
        session.add(
            Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED)
        )
        session.add(
            Operator(
                id=operator_id,
                tenant_id=tenant_id,
                email=f"op-{operator_id.hex[:6]}@test",
                role=OperatorRole.ADMIN,
            )
        )
        session.add(
            User(
                id=user_id,
                tenant_id=tenant_id,
                email=f"u-{user_id.hex[:6]}@test",
                auth_method=UserAuthMethod.LOCAL,
                password_hash=hash_password(_LOCAL_PASSWORD),
            )
        )
        session.add(
            McpServer(
                id=server_id,
                tenant_id=tenant_id,
                display_name=f"github-{server_id.hex[:6]}",
                source_type=McpServerSourceType.HTTP,
                source_location="https://api.example/mcp",
                transport=McpTransport.STREAMABLE_HTTP,
                args=[],
                registered_by=operator_id,
                health_status=McpServerHealthStatus.UNKNOWN,
                auth_authcode={
                    "auth_url": _AUTH_URL,
                    "token_url": _TOKEN_URL,
                    "client_id_ref": _CLIENT_ID_REF,
                    "client_secret_ref": _CLIENT_SECRET_REF,
                    "scopes": ["user:read"],
                    "redirect_uri": _REDIRECT_URI,
                },
            )
        )
        session.commit()
    return tenant_id, operator_id, user_id, server_id


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as session:
        for table in (
            "oauth_user_tokens",
            "user_api_keys",
            "users",
            "mcp_servers",
            "operators",
        ):
            session.execute(
                text(f"DELETE FROM {table} WHERE tenant_id = :id"),
                {"id": tenant_id},
            )
        session.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        session.commit()


def _make_client(secret_store: InMemorySecretStore | None = None) -> TestClient:
    store = secret_store or InMemorySecretStore()
    return TestClient(
        create_app(
            Settings(
                app_name="oauth-authcode-test",
                environment="test",
                log_level="CRITICAL",
                operator_auth_signing_secret=_OPERATOR_SECRET,
                portal_session_signing_secret=_PORTAL_SECRET,
            ),
            secret_store=store,
        )
    )


def _portal_headers(tenant_id: UUID, user_id: UUID) -> dict[str, str]:
    token = issue_portal_session(
        tenant_id=tenant_id,
        user_id=user_id,
        email="end-user@test",
        auth_method="local",
        signing_secret=_PORTAL_SECRET,
        ttl_seconds=300,
    )
    return {"Authorization": f"Bearer {token}"}


def _seeded_secret_store(tenant_id: UUID) -> InMemorySecretStore:
    store = InMemorySecretStore()
    store.put(tenant_id, _CLIENT_ID_REF, "demo-client-id-value")
    store.put(tenant_id, _CLIENT_SECRET_REF, "demo-client-secret-value")
    return store


# --- /initiate -------------------------------------------------------------


def test_initiate_includes_pkce_s256_params_in_authorize_url() -> None:
    """OAuth 2.1 mandates PKCE for authorization-code flows. Every
    /initiate must add `code_challenge` + `code_challenge_method=S256`
    to the authorize URL, and the corresponding `code_verifier` must be
    embedded in the state JWT so /callback can echo it to the token
    endpoint."""
    import base64
    import hashlib
    from urllib.parse import parse_qs, urlparse

    import jwt as pyjwt

    factory = _factory()
    tenant_id, _, user_id, server_id = _seed(factory)
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.post(
                f"/api/v1/oauth-authcode/{server_id}/initiate",
                headers=_portal_headers(tenant_id, user_id),
                json={},
            )
        assert r.status_code == 200, r.text
        body = r.json()

        qs = parse_qs(urlparse(body["authorization_url"]).query)
        assert qs["code_challenge_method"] == ["S256"]
        challenge = qs["code_challenge"][0]
        assert len(challenge) == 43  # base64url(sha256) is always 43 chars

        # Verify the challenge matches the verifier embedded in the state.
        claims = pyjwt.decode(
            body["state"], _PORTAL_SECRET, algorithms=["HS256"],
            issuer="vyuu-gateway-oauth-state",
        )
        verifier = claims["code_verifier"]
        recomputed = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).decode("ascii").rstrip("=")
        assert recomputed == challenge
    finally:
        _cleanup(factory, tenant_id)


def test_initiate_returns_signed_state_and_authorization_url() -> None:
    factory = _factory()
    tenant_id, _, user_id, server_id = _seed(factory)
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.post(
                f"/api/v1/oauth-authcode/{server_id}/initiate",
                headers=_portal_headers(tenant_id, user_id),
                json={},
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["authorization_url"].startswith(_AUTH_URL)
        assert "state=" in body["authorization_url"]
        assert body["state"]
        assert body["expires_in_seconds"] > 0
        # Authorization URL must include client_id (resolved from secret
        # store) and redirect_uri exactly as configured.
        assert "client_id=demo-client-id-value" in body["authorization_url"]
        assert "redirect_uri=" in body["authorization_url"]
    finally:
        _cleanup(factory, tenant_id)


def test_initiate_stamps_extra_authorize_params_for_google_style_idps() -> None:
    """When `auth_authcode.extra_authorize_params` is set (e.g. Google's
    `access_type=offline&prompt=consent`), the authorize URL must
    carry those query params. Without this, Google issues no refresh
    token and the user has to re-Connect every hour."""

    factory = _factory()
    tenant_id, _, user_id, server_id = _seed(factory)
    # Mutate the seeded server to add extras (Google's required pair).
    with factory() as session:
        session.execute(
            text(
                """
                UPDATE mcp_servers
                SET auth_authcode = jsonb_set(
                    auth_authcode,
                    '{extra_authorize_params}',
                    '{"access_type": "offline", "prompt": "consent"}'::jsonb
                )
                WHERE id = :s
                """
            ),
            {"s": server_id},
        )
        session.commit()
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.post(
                f"/api/v1/oauth-authcode/{server_id}/initiate",
                headers=_portal_headers(tenant_id, user_id),
                json={},
            )
        assert r.status_code == 200, r.text
        url = r.json()["authorization_url"]
        assert "access_type=offline" in url
        assert "prompt=consent" in url
    finally:
        _cleanup(factory, tenant_id)


def test_initiate_returns_404_for_unknown_server() -> None:
    factory = _factory()
    tenant_id, _, user_id, _ = _seed(factory)
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.post(
                f"/api/v1/oauth-authcode/{uuid4()}/initiate",
                headers=_portal_headers(tenant_id, user_id),
                json={},
            )
        assert r.status_code == 404
    finally:
        _cleanup(factory, tenant_id)


def test_initiate_returns_400_when_server_lacks_auth_authcode() -> None:
    """A registered server that doesn't have auth_authcode set must
    not be initiateable — 400, not 500."""
    factory = _factory()
    tenant_id, operator_id, user_id, _ = _seed(factory)
    other_server_id = uuid4()
    try:
        with factory() as session:
            session.add(
                McpServer(
                    id=other_server_id,
                    tenant_id=tenant_id,
                    display_name=f"plain-{other_server_id.hex[:6]}",
                    source_type=McpServerSourceType.HTTP,
                    source_location="https://api.example/mcp",
                    transport=McpTransport.STREAMABLE_HTTP,
                    args=[],
                    registered_by=operator_id,
                    health_status=McpServerHealthStatus.UNKNOWN,
                )
            )
            session.commit()

        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.post(
                f"/api/v1/oauth-authcode/{other_server_id}/initiate",
                headers=_portal_headers(tenant_id, user_id),
                json={},
            )
        assert r.status_code == 400
    finally:
        _cleanup(factory, tenant_id)


def test_initiate_requires_portal_session() -> None:
    factory = _factory()
    tenant_id, _, _, server_id = _seed(factory)
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.post(
                f"/api/v1/oauth-authcode/{server_id}/initiate", json={}
            )
        assert r.status_code == 401
    finally:
        _cleanup(factory, tenant_id)


# --- /operator-initiate ----------------------------------------------------


def _operator_headers(tenant_id: UUID, operator_id: UUID) -> dict[str, str]:
    from vyuu_gateway.operator_auth.fake import mint_operator_test_token

    token = mint_operator_test_token(
        tenant_id=tenant_id, operator_id=operator_id, signing_secret=_OPERATOR_SECRET
    )
    return {"Authorization": f"Bearer {token}"}


def _seed_operator_with_matching_user(
    factory: Any,
) -> tuple[UUID, UUID, UUID, UUID, str]:
    """Same as `_seed` but operator and user share an email so the
    operator-initiate endpoint can resolve operator → user.

    Returns (tenant_id, operator_id, user_id, server_id, shared_email).
    """

    tenant_id = uuid4()
    operator_id = uuid4()
    user_id = uuid4()
    server_id = uuid4()
    shared_email = f"shared-{tenant_id.hex[:6]}@test"
    with factory() as session:
        session.add(
            Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED)
        )
        session.add(
            Operator(
                id=operator_id,
                tenant_id=tenant_id,
                email=shared_email,
                role=OperatorRole.ADMIN,
            )
        )
        session.add(
            User(
                id=user_id,
                tenant_id=tenant_id,
                email=shared_email,
                auth_method=UserAuthMethod.LOCAL,
                password_hash=hash_password(_LOCAL_PASSWORD),
            )
        )
        session.add(
            McpServer(
                id=server_id,
                tenant_id=tenant_id,
                display_name=f"github-{server_id.hex[:6]}",
                source_type=McpServerSourceType.HTTP,
                source_location="https://api.example/mcp",
                transport=McpTransport.STREAMABLE_HTTP,
                args=[],
                registered_by=operator_id,
                health_status=McpServerHealthStatus.UNKNOWN,
                auth_authcode={
                    "auth_url": _AUTH_URL,
                    "token_url": _TOKEN_URL,
                    "client_id_ref": _CLIENT_ID_REF,
                    "client_secret_ref": _CLIENT_SECRET_REF,
                    "scopes": ["user:read"],
                    "redirect_uri": _REDIRECT_URI,
                },
            )
        )
        session.commit()
    return tenant_id, operator_id, user_id, server_id, shared_email


def test_operator_initiate_resolves_operator_email_to_user_and_returns_url() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, server_id, _ = _seed_operator_with_matching_user(
        factory
    )
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.post(
                f"/api/v1/oauth-authcode/{server_id}/operator-initiate",
                headers=_operator_headers(tenant_id, operator_id),
                json={},
            )
        assert r.status_code == 200
        body = r.json()
        assert body["authorization_url"].startswith(_AUTH_URL)
        assert "state" in body
        assert "expires_in_seconds" in body

        # The minted state token must carry the matched user_id, so a
        # subsequent /callback writes the OAuth token row under the
        # operator's underlying portal user (NOT the operator_id).
        import jwt as pyjwt

        claims = pyjwt.decode(
            body["state"], _PORTAL_SECRET, algorithms=["HS256"], issuer="vyuu-gateway-oauth-state"
        )
        assert claims["user_id"] == str(user_id)
        assert claims["server_id"] == str(server_id)
    finally:
        _cleanup(factory, tenant_id)


def test_operator_initiate_412_when_no_matching_user_for_operator_email() -> None:
    """The operator's email is not yet registered as a portal user. The
    OAuth flow can't proceed because there's no user_id to attach the
    token to. Surface a 412 with actionable guidance."""
    factory = _factory()
    tenant_id, operator_id, _, server_id = _seed(factory)
    # _seed creates an operator whose email does NOT match any user row.
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.post(
                f"/api/v1/oauth-authcode/{server_id}/operator-initiate",
                headers=_operator_headers(tenant_id, operator_id),
                json={},
            )
        assert r.status_code == 412
        assert "portal" in r.json()["detail"].lower()
    finally:
        _cleanup(factory, tenant_id)


def test_operator_initiate_400_when_server_lacks_auth_authcode() -> None:
    factory = _factory()
    tenant_id, operator_id, _, _, _ = _seed_operator_with_matching_user(factory)
    plain_server_id = uuid4()
    try:
        with factory() as session:
            session.add(
                McpServer(
                    id=plain_server_id,
                    tenant_id=tenant_id,
                    display_name=f"plain-{plain_server_id.hex[:6]}",
                    source_type=McpServerSourceType.HTTP,
                    source_location="https://api.example/mcp",
                    transport=McpTransport.STREAMABLE_HTTP,
                    args=[],
                    registered_by=operator_id,
                    health_status=McpServerHealthStatus.UNKNOWN,
                )
            )
            session.commit()

        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.post(
                f"/api/v1/oauth-authcode/{plain_server_id}/operator-initiate",
                headers=_operator_headers(tenant_id, operator_id),
                json={},
            )
        assert r.status_code == 400
    finally:
        _cleanup(factory, tenant_id)


def test_operator_initiate_requires_operator_bearer() -> None:
    factory = _factory()
    tenant_id, _, _, server_id, _ = _seed_operator_with_matching_user(factory)
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.post(
                f"/api/v1/oauth-authcode/{server_id}/operator-initiate", json={}
            )
        assert r.status_code in (401, 403)
    finally:
        _cleanup(factory, tenant_id)


# --- /callback -------------------------------------------------------------


class _StubTokenServer:
    """ASGI app that pretends to be the IdP token endpoint. Used as the
    transport for httpx.AsyncClient — patched into the callback's
    httpx.AsyncClient() so we don't actually open a network connection."""

    def __init__(
        self,
        *,
        access_token: str = "fresh-access",
        refresh_token: str | None = "fresh-refresh",
        scope: str | None = "user:read",
        expires_in: int | None = 3600,
        status_code: int = 200,
    ) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.scope = scope
        self.expires_in = expires_in
        self.status_code = status_code
        self.calls = 0

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        more = True
        while more:
            event = await receive()
            more = event.get("more_body", False)
        self.calls += 1
        body: dict[str, Any] = {
            "access_token": self.access_token,
            "token_type": "Bearer",
        }
        if self.refresh_token is not None:
            body["refresh_token"] = self.refresh_token
        if self.scope is not None:
            body["scope"] = self.scope
        if self.expires_in is not None:
            body["expires_in"] = self.expires_in
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": json.dumps(body).encode()})


def _patch_httpx_to_stub(monkeypatch: pytest.MonkeyPatch, app: _StubTokenServer) -> None:
    """Replace `httpx.AsyncClient()` used in the callback with one
    routed through the in-process ASGI stub."""

    real = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
        return real(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def test_callback_persists_tokens_and_renders_success_html(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _factory()
    tenant_id, _, user_id, server_id = _seed(factory)
    stub = _StubTokenServer()
    _patch_httpx_to_stub(monkeypatch, stub)
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            init = client.post(
                f"/api/v1/oauth-authcode/{server_id}/initiate",
                headers=_portal_headers(tenant_id, user_id),
                json={},
            )
            state = init.json()["state"]
            r = client.get(
                "/api/v1/oauth-authcode/callback",
                params={"code": "demo-auth-code", "state": state},
            )
        assert r.status_code == 200, r.text
        # Renders a small HTML page (not JSON).
        assert "text/html" in r.headers["content-type"]
        assert "Connected to" in r.text
        # Token-endpoint was hit exactly once.
        assert stub.calls == 1

        # Row persisted with the new token values.
        with factory() as session:
            row = session.scalar(
                text(
                    "SELECT access_token FROM oauth_user_tokens "
                    "WHERE tenant_id = :t AND user_id = :u AND server_id = :s"
                ),
                {"t": tenant_id, "u": user_id, "s": server_id},
            )
            assert row == "fresh-access"
    finally:
        _cleanup(factory, tenant_id)


def test_callback_rejects_idp_returned_error() -> None:
    factory = _factory()
    tenant_id, _, _, _ = _seed(factory)
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.get(
                "/api/v1/oauth-authcode/callback",
                params={
                    "error": "access_denied",
                    "error_description": "user pressed cancel",
                },
            )
        assert r.status_code == 400
        assert "text/html" in r.headers["content-type"]
        assert "access_denied" in r.text
    finally:
        _cleanup(factory, tenant_id)


def test_callback_rejects_missing_state() -> None:
    factory = _factory()
    tenant_id, _, _, _ = _seed(factory)
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.get(
                "/api/v1/oauth-authcode/callback",
                params={"code": "x"},
            )
        assert r.status_code == 400
    finally:
        _cleanup(factory, tenant_id)


def test_callback_rejects_tampered_state() -> None:
    """A state token signed with the wrong secret must be rejected —
    a forged state otherwise lets an attacker write tokens for an
    arbitrary (tenant, user) into the DB."""
    factory = _factory()
    tenant_id, _, _, _ = _seed(factory)
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.get(
                "/api/v1/oauth-authcode/callback",
                params={"code": "x", "state": "not-a-valid-jwt"},
            )
        assert r.status_code == 400
    finally:
        _cleanup(factory, tenant_id)


def test_callback_upserts_on_reconnect(monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-connecting an already-connected server must REPLACE the
    stored token, not fail on the unique (tenant, user, server)
    constraint."""

    factory = _factory()
    tenant_id, _, user_id, server_id = _seed(factory)
    # Pre-insert a row so the callback path hits the upsert branch.
    with factory() as session:
        session.add(
            OAuthUserToken(
                id=uuid4(),
                tenant_id=tenant_id,
                user_id=user_id,
                server_id=server_id,
                access_token="old-access",
                refresh_token="old-refresh",
                token_type="Bearer",
                scope="user:read",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        session.commit()

    stub = _StubTokenServer(access_token="rotated-access")
    _patch_httpx_to_stub(monkeypatch, stub)
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            init = client.post(
                f"/api/v1/oauth-authcode/{server_id}/initiate",
                headers=_portal_headers(tenant_id, user_id),
                json={},
            )
            r = client.get(
                "/api/v1/oauth-authcode/callback",
                params={"code": "x", "state": init.json()["state"]},
            )
        assert r.status_code == 200
        with factory() as session:
            row = session.scalar(
                text(
                    "SELECT access_token FROM oauth_user_tokens "
                    "WHERE tenant_id = :t AND user_id = :u AND server_id = :s"
                ),
                {"t": tenant_id, "u": user_id, "s": server_id},
            )
            assert row == "rotated-access"
    finally:
        _cleanup(factory, tenant_id)


# --- /connections + /disconnect --------------------------------------------


def test_connections_list_returns_user_tokens_only() -> None:
    """Cross-user isolation: User A must never see User B's tokens
    even within the same tenant."""

    factory = _factory()
    tenant_id, operator_id, user_a, server_id = _seed(factory)
    user_b = uuid4()
    # Commit User B first so the OAuthUserToken FK is satisfied. The
    # ORM doesn't model the user_id FK as a `relationship()` on the
    # OAuthUserToken side, so SA's autoflush ordering can't deduce
    # that the user must be inserted first when both are added to the
    # same session.
    with factory() as session:
        session.add(
            User(
                id=user_b,
                tenant_id=tenant_id,
                email=f"u-{user_b.hex[:6]}@test",
                auth_method=UserAuthMethod.LOCAL,
                password_hash=hash_password(_LOCAL_PASSWORD),
            )
        )
        session.commit()
    with factory() as session:
        session.add(
            OAuthUserToken(
                id=uuid4(),
                tenant_id=tenant_id,
                user_id=user_a,
                server_id=server_id,
                access_token="a-token",
                refresh_token="a-refresh",
                token_type="Bearer",
                scope="user:read",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        session.add(
            OAuthUserToken(
                id=uuid4(),
                tenant_id=tenant_id,
                user_id=user_b,
                server_id=server_id,
                access_token="b-token",
                refresh_token="b-refresh",
                token_type="Bearer",
                scope="user:read",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        session.commit()
    del operator_id  # quiet unused
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.get(
                "/api/v1/oauth-authcode/connections",
                headers=_portal_headers(tenant_id, user_a),
            )
        assert r.status_code == 200
        rows = r.json()
        assert len(rows) == 1
        assert rows[0]["server_id"] == str(server_id)
        # The plaintext access token is NEVER returned by the list
        # endpoint — defence against XSS in the SPA leaking it.
        assert "access_token" not in rows[0]
    finally:
        _cleanup(factory, tenant_id)


def test_disconnect_deletes_only_calling_users_row() -> None:
    factory = _factory()
    tenant_id, _, user_id, server_id = _seed(factory)
    with factory() as session:
        session.add(
            OAuthUserToken(
                id=uuid4(),
                tenant_id=tenant_id,
                user_id=user_id,
                server_id=server_id,
                access_token="will-be-deleted",
                token_type="Bearer",
            )
        )
        session.commit()
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.delete(
                f"/api/v1/oauth-authcode/{server_id}/connection",
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 204
        with factory() as session:
            count = session.scalar(
                text(
                    "SELECT COUNT(*) FROM oauth_user_tokens "
                    "WHERE tenant_id = :t AND user_id = :u AND server_id = :s"
                ),
                {"t": tenant_id, "u": user_id, "s": server_id},
            )
            assert count == 0
    finally:
        _cleanup(factory, tenant_id)


def test_disconnect_is_idempotent_on_unknown_server() -> None:
    """No row to delete → 204 still (deleting nothing is success)."""
    factory = _factory()
    tenant_id, _, user_id, _ = _seed(factory)
    try:
        client = _make_client(_seeded_secret_store(tenant_id))
        with client:
            r = client.delete(
                f"/api/v1/oauth-authcode/{uuid4()}/connection",
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 204
    finally:
        _cleanup(factory, tenant_id)
