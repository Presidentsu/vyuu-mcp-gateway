"""End-to-end tests for the A3-δ end-user portal endpoints.

Covers:
- `GET    /me`            — whoami round-trip
- `GET    /catalog`       — public + private-with-grant + private-without
- `GET/POST/DELETE /api-keys` — self-issue, list, revoke
- `POST   /password`      — self-rotate (local-auth only)

Plus a smoke test for the static `/portal` HTML/CSS/JS endpoints.
"""

from __future__ import annotations

import os

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

from datetime import UTC, datetime  # noqa: E402
from typing import Any  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.audit.events import (  # noqa: E402
    AuditDecision,
    AuditDecisionMode,
    AuditEvent,
    AuditEventType,
    AuditPrincipal,
    AuditPrincipalType,
    UpstreamStatus,
)
from vyuu_gateway.audit.recent import RecentAuditEmitter  # noqa: E402
from vyuu_gateway.config import Settings  # noqa: E402
from vyuu_gateway.db.models import (  # noqa: E402
    GrantPrincipalKind,
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
    User,
    UserAuthMethod,
    VirtualServer,
    VirtualServerGrant,
    VirtualServerVisibility,
)
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.users.passwords import hash_password  # noqa: E402
from vyuu_gateway.users.sessions import issue_portal_session  # noqa: E402

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set",
)

_PORTAL_SECRET = "test-portal-secret-A3δ"
_OPERATOR_SECRET = "test-operator-secret-A3δ"
_LOCAL_PASSWORD = "very-strong-12+chars"


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(create_engine(_DATABASE_URL, future=True), autoflush=False, future=True)


def _seed_world(factory: Any) -> tuple[UUID, UUID, UUID, UUID, UUID]:
    """Seed (tenant, operator, user, public_vserver, private_vserver)."""
    tenant_id = uuid4()
    operator_id = uuid4()
    user_id = uuid4()
    pub_id = uuid4()
    priv_id = uuid4()
    with factory() as session:
        session.add(Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED))
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
            VirtualServer(
                id=pub_id,
                tenant_id=tenant_id,
                name=f"pub-{pub_id.hex[:6]}",
                visibility=VirtualServerVisibility.PUBLIC,
                created_by=operator_id,
            )
        )
        session.add(
            VirtualServer(
                id=priv_id,
                tenant_id=tenant_id,
                name=f"priv-{priv_id.hex[:6]}",
                visibility=VirtualServerVisibility.PRIVATE,
                created_by=operator_id,
            )
        )
        session.commit()
    return tenant_id, operator_id, user_id, pub_id, priv_id


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as session:
        for table in (
            "access_requests",
            "user_group_memberships",
            "virtual_server_grants",
            "user_api_keys",
            "groups",
            "users",
            "virtual_server_tools",
            "virtual_servers",
            "operators",
        ):
            if table == "user_group_memberships":
                session.execute(
                    text(
                        "DELETE FROM user_group_memberships WHERE user_id IN "
                        "(SELECT id FROM users WHERE tenant_id = :id)"
                    ),
                    {"id": tenant_id},
                )
            else:
                session.execute(
                    text(f"DELETE FROM {table} WHERE tenant_id = :id"),
                    {"id": tenant_id},
                )
        session.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        session.commit()


def _make_client() -> TestClient:
    return TestClient(
        create_app(
            Settings(
                app_name="portal-test",
                environment="test",
                log_level="CRITICAL",
                operator_auth_signing_secret=_OPERATOR_SECRET,
                portal_session_signing_secret=_PORTAL_SECRET,
            )
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


# --- whoami ----------------------------------------------------------------


def test_whoami_returns_session_user() -> None:
    factory = _factory()
    tenant_id, _, user_id, _, _ = _seed_world(factory)
    try:
        with _make_client() as client:
            r = client.get(
                f"/api/v1/portal/{tenant_id}/me",
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 200
        body = r.json()
        assert body["user_id"] == str(user_id)
        assert body["tenant_id"] == str(tenant_id)
        assert body["auth_method"] == "local"
    finally:
        _cleanup(factory, tenant_id)


def test_whoami_cross_tenant_token_403() -> None:
    factory = _factory()
    tenant_id, _, user_id, _, _ = _seed_world(factory)
    try:
        with _make_client() as client:
            r = client.get(
                f"/api/v1/portal/{uuid4()}/me",
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 403
    finally:
        _cleanup(factory, tenant_id)


# --- catalog ---------------------------------------------------------------


def test_catalog_marks_public_vservers_as_accessible() -> None:
    """Public vservers always show `has_access=true` regardless of grants."""
    factory = _factory()
    tenant_id, _, user_id, pub_id, priv_id = _seed_world(factory)
    try:
        with _make_client() as client:
            r = client.get(
                f"/api/v1/portal/{tenant_id}/catalog",
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 200
        rows = {row["vserver_id"]: row for row in r.json()}
        assert rows[str(pub_id)]["has_access"] is True
        assert rows[str(pub_id)]["visibility"] == "public"
        assert rows[str(priv_id)]["has_access"] is False
        assert rows[str(priv_id)]["visibility"] == "private"
    finally:
        _cleanup(factory, tenant_id)


def test_catalog_surfaces_requires_user_auth_servers_for_authcode_upstreams() -> None:
    """A1: vservers wrapping an MCP server with `auth_authcode` must
    expose that server in `requires_user_auth_servers` so the portal
    can render a Connect button. `connected=False` until the user goes
    through /initiate + /callback."""

    from vyuu_gateway.db.models import (
        McpServer,
        McpServerHealthStatus,
        McpServerSourceType,
        McpTransport,
        OAuthUserToken,
        VirtualServerTool,
    )

    factory = _factory()
    tenant_id, operator_id, user_id, pub_id, _ = _seed_world(factory)
    server_id = uuid4()
    try:
        with factory() as session:
            session.add(
                McpServer(
                    id=server_id,
                    tenant_id=tenant_id,
                    display_name="GitHub",
                    source_type=McpServerSourceType.HTTP,
                    source_location="https://api.example/mcp",
                    transport=McpTransport.STREAMABLE_HTTP,
                    args=[],
                    registered_by=operator_id,
                    health_status=McpServerHealthStatus.UNKNOWN,
                    auth_authcode={
                        "auth_url": "https://idp.example/authorize",
                        "token_url": "https://idp.example/token",
                        "client_id_ref": "id-ref",
                        "client_secret_ref": "secret-ref",
                        "scopes": ["user:read"],
                        "redirect_uri": "https://gw.example/callback",
                    },
                )
            )
            session.add(
                VirtualServerTool(
                    tenant_id=tenant_id,
                    vserver_id=pub_id,
                    server_id=server_id,
                    tool_name="search_repos",
                )
            )
            session.commit()

        with _make_client() as client:
            r = client.get(
                f"/api/v1/portal/{tenant_id}/catalog",
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 200
        rows = {row["vserver_id"]: row for row in r.json()}
        required = rows[str(pub_id)]["requires_user_auth_servers"]
        assert len(required) == 1
        assert required[0]["server_id"] == str(server_id)
        assert required[0]["server_display_name"] == "GitHub"
        assert required[0]["connected"] is False

        # Insert a token row for this user → connected flips to True.
        with factory() as session:
            session.add(
                OAuthUserToken(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    user_id=user_id,
                    server_id=server_id,
                    access_token="t",
                    token_type="Bearer",
                )
            )
            session.commit()

        with _make_client() as client:
            r = client.get(
                f"/api/v1/portal/{tenant_id}/catalog",
                headers=_portal_headers(tenant_id, user_id),
            )
        rows = {row["vserver_id"]: row for row in r.json()}
        assert rows[str(pub_id)]["requires_user_auth_servers"][0]["connected"] is True
    finally:
        # oauth_user_tokens isn't in the default cleanup set; explicit purge here.
        with factory() as session:
            session.execute(
                text("DELETE FROM oauth_user_tokens WHERE tenant_id = :id"),
                {"id": tenant_id},
            )
            session.execute(
                text("DELETE FROM mcp_servers WHERE tenant_id = :id"),
                {"id": tenant_id},
            )
            session.commit()
        _cleanup(factory, tenant_id)


def test_catalog_marks_private_with_user_grant_as_accessible() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, _, priv_id = _seed_world(factory)
    try:
        with factory() as session:
            session.add(
                VirtualServerGrant(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    vserver_id=priv_id,
                    principal_kind=GrantPrincipalKind.USER,
                    principal_id=user_id,
                    granted_by=operator_id,
                )
            )
            session.commit()
        with _make_client() as client:
            r = client.get(
                f"/api/v1/portal/{tenant_id}/catalog",
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 200
        rows = {row["vserver_id"]: row for row in r.json()}
        assert rows[str(priv_id)]["has_access"] is True
    finally:
        _cleanup(factory, tenant_id)


# --- API keys --------------------------------------------------------------


def test_self_issue_api_key_returns_plaintext_once() -> None:
    factory = _factory()
    tenant_id, _, user_id, _, _ = _seed_world(factory)
    try:
        with _make_client() as client:
            issue = client.post(
                f"/api/v1/portal/{tenant_id}/api-keys",
                json={"label": "MacBook Claude Desktop"},
                headers=_portal_headers(tenant_id, user_id),
            )
            assert issue.status_code == 201
            issued = issue.json()
            assert issued["plaintext"].startswith("vyuu_user_")
            key_id = issued["id"]

            # Listing must NOT return plaintext.
            r = client.get(
                f"/api/v1/portal/{tenant_id}/api-keys",
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 200
        rows = r.json()
        assert len(rows) == 1
        assert "plaintext" not in rows[0]
        assert rows[0]["id"] == key_id
    finally:
        _cleanup(factory, tenant_id)


def test_self_revoke_api_key_marks_revoked_at() -> None:
    factory = _factory()
    tenant_id, _, user_id, _, _ = _seed_world(factory)
    try:
        with _make_client() as client:
            issue = client.post(
                f"/api/v1/portal/{tenant_id}/api-keys",
                json={"label": "rev-test"},
                headers=_portal_headers(tenant_id, user_id),
            )
            key_id = issue.json()["id"]
            r = client.delete(
                f"/api/v1/portal/{tenant_id}/api-keys/{key_id}",
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 200
        assert r.json()["revoked_at"] is not None
    finally:
        _cleanup(factory, tenant_id)


def test_revoke_other_users_key_returns_404_anti_enumeration() -> None:
    """User A cannot revoke User B's key — gets 404 (looks identical to
    a nonexistent key id, so attacker can't enumerate)."""
    factory = _factory()
    tenant_id, _, user_id, _, _ = _seed_world(factory)
    try:
        with _make_client() as client:
            issue = client.post(
                f"/api/v1/portal/{tenant_id}/api-keys",
                json={"label": "owner-key"},
                headers=_portal_headers(tenant_id, user_id),
            )
            key_id = issue.json()["id"]
            other_user_id = uuid4()
            r = client.delete(
                f"/api/v1/portal/{tenant_id}/api-keys/{key_id}",
                headers=_portal_headers(tenant_id, other_user_id),
            )
        assert r.status_code == 404
    finally:
        _cleanup(factory, tenant_id)


# --- Self-rotate password --------------------------------------------------


def test_rotate_password_succeeds_with_correct_current() -> None:
    factory = _factory()
    tenant_id, _, user_id, _, _ = _seed_world(factory)
    try:
        with _make_client() as client:
            r = client.post(
                f"/api/v1/portal/{tenant_id}/password",
                json={
                    "current_password": _LOCAL_PASSWORD,
                    "new_password": "even-stronger-pw-22+chars",
                },
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 200
        assert r.json()["must_change_password"] is False
    finally:
        _cleanup(factory, tenant_id)


def test_rotate_password_rejects_wrong_current_with_401() -> None:
    factory = _factory()
    tenant_id, _, user_id, _, _ = _seed_world(factory)
    try:
        with _make_client() as client:
            r = client.post(
                f"/api/v1/portal/{tenant_id}/password",
                json={
                    "current_password": "wrong",
                    "new_password": "even-stronger-pw-22+chars",
                },
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 401
    finally:
        _cleanup(factory, tenant_id)


def test_rotate_password_rejects_weak_new_password_with_422() -> None:
    factory = _factory()
    tenant_id, _, user_id, _, _ = _seed_world(factory)
    try:
        with _make_client() as client:
            r = client.post(
                f"/api/v1/portal/{tenant_id}/password",
                json={
                    "current_password": _LOCAL_PASSWORD,
                    "new_password": "short",
                },
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 422
    finally:
        _cleanup(factory, tenant_id)


# --- /portal static surface ------------------------------------------------


def test_portal_html_served_with_security_headers() -> None:
    """Static `/portal` HTML/CSS/JS endpoints respond 200 with the
    expected CSP / nosniff headers."""
    with _make_client() as client:
        for path, ctype in (
            ("/portal", "text/html"),
            ("/portal/app.css", "text/css"),
            ("/portal/app.js", "text/javascript"),
        ):
            r = client.get(path)
            assert r.status_code == 200, path
            assert ctype in r.headers["content-type"]
            assert "Content-Security-Policy" in r.headers
            assert r.headers["X-Content-Type-Options"] == "nosniff"


# --- Recent tool calls (Home + Tool history) ------------------------------


def test_recent_tool_calls_empty_when_no_keys() -> None:
    """User with no API keys → empty list (200), not 404."""
    factory = _factory()
    tenant_id, _, user_id, _, _ = _seed_world(factory)
    try:
        with _make_client() as client:
            r = client.get(
                f"/api/v1/portal/{tenant_id}/recent-tool-calls",
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 200
        assert r.json() == []
    finally:
        _cleanup(factory, tenant_id)


def test_recent_tool_calls_filters_to_the_calling_user() -> None:
    """Audit events whose principal.id matches one of the user's API
    keys are returned; events from other principals are not."""
    factory = _factory()
    tenant_id, _, user_id, _, _ = _seed_world(factory)
    try:
        with _make_client() as client:
            issue = client.post(
                f"/api/v1/portal/{tenant_id}/api-keys",
                json={"label": "history-test"},
                headers=_portal_headers(tenant_id, user_id),
            )
            assert issue.status_code == 201
            my_key_id = issue.json()["id"]

            # Inject 3 events into the gateway's recent emitter:
            # (a) one from THIS USER, (b) one from a different
            # principal id (still api_key kind), (c) one from a
            # different tenant.
            #
            # The principal id is the USER id, not the API-key id —
            # `ApiKeyIdentityProvider` builds
            # `ApiKeyPrincipal(id=str(user_id), key_id=str(key_id))`.
            # This test used to inject the key id, which matched the
            # endpoint's (wrong) filter and so passed while the real
            # endpoint returned an empty list for every user. See
            # `test_recent_tool_calls_principal_matches_the_provider`.
            # client.app is typed as ASGI callable; cast to FastAPI to
            # reach .state. (TestClient gives back the wrapped app.)
            from fastapi import FastAPI
            assert isinstance(client.app, FastAPI)
            emitter = client.app.state.recent_audit_emitter
            assert isinstance(emitter, RecentAuditEmitter)

            def _ev(principal_id: str, t_id: UUID) -> AuditEvent:
                return AuditEvent(
                    tenant_id=t_id,
                    gateway_instance_id="test-gw",
                    event_type=AuditEventType.TOOL_CALL,
                    principal=AuditPrincipal(
                        type=AuditPrincipalType.API_KEY,
                        id=principal_id,
                        display="cursor",
                    ),
                    tool="ping",
                    args_summary={},
                    decision=AuditDecision.ALLOW,
                    decision_mode=AuditDecisionMode.ENFORCE,
                    upstream_status=UpstreamStatus.OK,
                    timestamp=datetime.now(UTC),
                )

            emitter.emit_nowait(_ev(str(user_id), tenant_id))
            emitter.emit_nowait(_ev(str(uuid4()), tenant_id))
            emitter.emit_nowait(_ev(str(user_id), uuid4()))  # other tenant
            # A call authenticated with this user's key but recorded
            # under the key id must NOT match: nothing emits that shape,
            # and accepting it would re-admit the original bug.
            emitter.emit_nowait(_ev(my_key_id, tenant_id))

            r = client.get(
                f"/api/v1/portal/{tenant_id}/recent-tool-calls",
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 200
        rows = r.json()
        # Only the (this user, this tenant) event comes back — the
        # other-tenant event is tenant-filtered, and both the
        # different-principal and the key-id-shaped events are
        # principal-filtered.
        assert len(rows) == 1
        assert rows[0]["via"] == "cursor"
    finally:
        _cleanup(factory, tenant_id)


def test_recent_tool_calls_principal_matches_the_provider() -> None:
    """Pin the contract the portal's filter depends on, against the REAL
    provider rather than a hand-built principal.

    The portal scopes "my tool calls" by comparing an audit event's
    `principal.id` to the session's user id. That only works because
    `ApiKeyIdentityProvider` puts the USER id there and carries the key
    id separately in `key_id`.

    The failure this guards is invisible: if the two sides drift, the
    endpoint still answers 200 with an empty list, which looks exactly
    like a user who has made no calls. That is how the original bug
    survived — the endpoint test injected synthetic events using the key
    id, so it agreed with the endpoint and neither matched reality.
    """

    from vyuu_gateway.identity.api_key_provider import ApiKeyIdentityProvider
    from vyuu_gateway.identity.provider import IdentityCredentials

    factory = _factory()
    tenant_id, _, user_id, _, _ = _seed_world(factory)
    try:
        with _make_client() as client:
            issue = client.post(
                f"/api/v1/portal/{tenant_id}/api-keys",
                json={"label": "provider-contract"},
                headers=_portal_headers(tenant_id, user_id),
            )
            assert issue.status_code == 201
            issued = issue.json()

        principal = ApiKeyIdentityProvider(factory).validate_principal(
            tenant_id=tenant_id,
            credentials=IdentityCredentials(
                headers={"Authorization": f"Bearer {issued['plaintext']}"}
            ),
        )

        # The identity is the human, not the credential.
        assert principal.id == str(user_id), (
            "the portal filters on principal.id == user_id; if this "
            "becomes the key id, /recent-tool-calls silently returns "
            "nothing for every user"
        )
        # And the key is still recorded, separately — that is what makes
        # filtering on it look plausible while never matching.
        assert getattr(principal, "key_id", None) == issued["id"]
        assert principal.id != issued["id"]
    finally:
        _cleanup(factory, tenant_id)


def test_recent_tool_calls_cross_tenant_403() -> None:
    """Session for tenant A cannot read tenant B's recent calls."""
    factory = _factory()
    tenant_id, _, user_id, _, _ = _seed_world(factory)
    other_tenant = uuid4()
    try:
        with _make_client() as client:
            r = client.get(
                f"/api/v1/portal/{other_tenant}/recent-tool-calls",
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 403
    finally:
        _cleanup(factory, tenant_id)


def test_catalog_ignores_servers_whose_authcode_is_json_null() -> None:
    """A server with no OAuth config must not ask users to connect one.

    `auth_authcode=None` does NOT store SQL NULL: SQLAlchemy's
    `none_as_null` defaults to False on JSONB, so it stores the JSON
    value `null` — and `'null'::jsonb IS NOT NULL` is TRUE. The catalog
    query filtered with `.is_not(None)` and so matched every unconfigured
    server, telling end users to connect an account for an OAuth flow
    that did not exist.
    """

    from vyuu_gateway.db.models import (
        McpServer,
        McpServerHealthStatus,
        McpServerSourceType,
        McpTransport,
        VirtualServerTool,
    )

    factory = _factory()
    tenant_id, operator_id, user_id, pub_id, _ = _seed_world(factory)
    server_id = uuid4()
    try:
        with factory() as session:
            session.add(
                McpServer(
                    id=server_id,
                    tenant_id=tenant_id,
                    display_name="No-Auth Server",
                    source_type=McpServerSourceType.HTTP,
                    source_location="https://api.example/mcp",
                    transport=McpTransport.STREAMABLE_HTTP,
                    args=[],
                    registered_by=operator_id,
                    health_status=McpServerHealthStatus.UNKNOWN,
                    auth_authcode=None,
                )
            )
            session.add(
                VirtualServerTool(
                    tenant_id=tenant_id,
                    vserver_id=pub_id,
                    server_id=server_id,
                    tool_name="ping",
                )
            )
            session.commit()

        # Confirm the row really is JSON null, not SQL NULL — otherwise
        # this test would pass for the wrong reason.
        with factory() as session:
            kind = session.execute(
                text(
                    "SELECT jsonb_typeof(auth_authcode) FROM mcp_servers "
                    "WHERE id = :id"
                ),
                {"id": server_id},
            ).scalar_one()
        assert kind == "null"

        with _make_client() as client:
            r = client.get(
                f"/api/v1/portal/{tenant_id}/catalog",
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 200
        rows = {row["vserver_id"]: row for row in r.json()}
        assert rows[str(pub_id)]["requires_user_auth_servers"] == []
    finally:
        with factory() as session:
            session.execute(
                text("DELETE FROM mcp_servers WHERE tenant_id = :id"),
                {"id": tenant_id},
            )
            session.commit()
        _cleanup(factory, tenant_id)
