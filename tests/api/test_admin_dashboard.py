"""End-to-end tests for `GET /api/v1/admin/dashboard`.

Verifies the KPI aggregation: identity counts from the recent-events
buffer, registry counts from real Postgres, OAuth-connection counts
from `oauth_user_tokens`. Skipped unless `VYUU_TEST_DATABASE_URL`
is set since the catalog/grant counts query Postgres directly.
"""

from __future__ import annotations

import os

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

from datetime import UTC, datetime, timedelta  # noqa: E402
from typing import Any  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.audit.events import (  # noqa: E402
    AuditDecision,
    AuditDecisionMode,
    AuditPrincipal,
    AuditPrincipalType,
    UpstreamStatus,
    create_tool_call_audit_event,
)
from vyuu_gateway.config import Settings  # noqa: E402
from vyuu_gateway.db.models import (  # noqa: E402
    AccessRequest,
    AccessRequestStatus,
    McpCapability,
    McpCapabilityKind,
    McpServer,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
    OAuthUserToken,
    Operator,
    OperatorRole,
    RiskCategory,
    Tenant,
    TenantTier,
    User,
    UserAuthMethod,
    VirtualServer,
    VirtualServerVisibility,
)
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.operator_auth.fake import mint_operator_test_token  # noqa: E402
from vyuu_gateway.users.passwords import hash_password  # noqa: E402

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set",
)

_SECRET = "admin-dashboard-test-secret"


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(
        create_engine(_DATABASE_URL, future=True), autoflush=False, future=True
    )


def _seed(factory: Any) -> dict[str, UUID]:
    """Seed: 1 tenant + operator + user + 2 mcp_servers + 1 vserver
    + 1 capability + 1 oauth_user_tokens + 1 pending access_request.
    Assigns predictable UUIDs so tests can assert reachability."""

    ids: dict[str, UUID] = {
        "tenant": uuid4(),
        "operator": uuid4(),
        "alice": uuid4(),
        "server_a": uuid4(),
        "server_b": uuid4(),
        "vs": uuid4(),
        "cap_delete": uuid4(),
        "token": uuid4(),
        "access_req": uuid4(),
    }
    with factory() as s:
        s.add(Tenant(id=ids["tenant"], name=f"t-{ids['tenant'].hex[:6]}", tier=TenantTier.SHARED))
        s.commit()
    with factory() as s:
        s.add(
            Operator(
                id=ids["operator"],
                tenant_id=ids["tenant"],
                email=f"op-{ids['operator'].hex[:6]}@test",
                role=OperatorRole.ADMIN,
            )
        )
        s.add(
            User(
                id=ids["alice"],
                tenant_id=ids["tenant"],
                email=f"alice-{ids['alice'].hex[:6]}@test",
                auth_method=UserAuthMethod.LOCAL,
                password_hash=hash_password("very-strong-12+chars"),
            )
        )
        s.commit()
    # Catalog rows next: mcp_servers, virtual_servers, capabilities.
    with factory() as s:
        for sid, name in (
            (ids["server_a"], "github-mock"),
            (ids["server_b"], "drive-mock"),
        ):
            s.add(
                McpServer(
                    id=sid,
                    tenant_id=ids["tenant"],
                    display_name=name,
                    source_type=McpServerSourceType.HTTP,
                    source_location=f"https://{name}.example/mcp",
                    transport=McpTransport.STREAMABLE_HTTP,
                    args=[],
                    registered_by=ids["operator"],
                    health_status=McpServerHealthStatus.UNKNOWN,
                )
            )
        s.add(
            VirtualServer(
                id=ids["vs"],
                tenant_id=ids["tenant"],
                name="test-vs",
                visibility=VirtualServerVisibility.PRIVATE,
                created_by=ids["operator"],
            )
        )
        s.add(
            McpCapability(
                id=ids["cap_delete"],
                tenant_id=ids["tenant"],
                server_id=ids["server_a"],
                kind=McpCapabilityKind.TOOL,
                name="delete_repo",
                schema_json={},
                risk_category=RiskCategory.DELETE,
            )
        )
        s.commit()
    # Workflow / token rows last — they FK into the catalog above.
    with factory() as s:
        s.add(
            AccessRequest(
                id=ids["access_req"],
                tenant_id=ids["tenant"],
                user_id=ids["alice"],
                vserver_id=ids["vs"],
                status=AccessRequestStatus.PENDING,
            )
        )
        s.add(
            OAuthUserToken(
                id=ids["token"],
                tenant_id=ids["tenant"],
                user_id=ids["alice"],
                server_id=ids["server_a"],
                access_token="t",
                token_type="Bearer",
            )
        )
        s.commit()
    return ids


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as s:
        for table in (
            "oauth_user_tokens",
            "access_requests",
            "user_group_memberships",
            "virtual_server_grants",
            "virtual_server_tools",
            "virtual_servers",
            "mcp_capabilities",
            "mcp_servers",
            "user_api_keys",
            "groups",
            "users",
            "operators",
        ):
            if table == "user_group_memberships":
                s.execute(
                    text(
                        "DELETE FROM user_group_memberships WHERE user_id IN "
                        "(SELECT id FROM users WHERE tenant_id = :id)"
                    ),
                    {"id": tenant_id},
                )
            else:
                s.execute(
                    text(f"DELETE FROM {table} WHERE tenant_id = :id"),
                    {"id": tenant_id},
                )
        s.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        s.commit()


def _client_and_headers(tenant_id: UUID) -> tuple[TestClient, FastAPI, dict[str, str]]:
    app = create_app(
        Settings(
            app_name="admin-dashboard-test",
            environment="test",
            log_level="CRITICAL",
            operator_auth_signing_secret=_SECRET,
        )
    )
    token = mint_operator_test_token(
        tenant_id=tenant_id, operator_id=uuid4(), signing_secret=_SECRET
    )
    return TestClient(app), app, {"Authorization": f"Bearer {token}"}


def _emit(
    app: FastAPI,
    *,
    tenant_id: UUID,
    principal_id: str = "p",
    upstream_server_id: UUID | None = None,
    tool: str = "t",
    decision: AuditDecision = AuditDecision.ALLOW,
    upstream_status: UpstreamStatus = UpstreamStatus.OK,
    timestamp: datetime | None = None,
) -> None:
    event = create_tool_call_audit_event(
        tenant_id=tenant_id,
        gateway_instance_id="g",
        principal=AuditPrincipal(type=AuditPrincipalType.API_KEY, id=principal_id),
        tool=tool,
        arguments={},
        decision=decision,
        decision_mode=AuditDecisionMode.ENFORCE,
        upstream_status=upstream_status,
        upstream_server_id=upstream_server_id,
    )
    if timestamp is not None:
        event = event.model_copy(update={"timestamp": timestamp})
    app.state.recent_audit_emitter.emit_nowait(event)


# ---------------------------------------------------------------------------


def test_dashboard_kpis_reflect_db_and_recent_events() -> None:
    factory = _factory()
    ids = _seed(factory)
    try:
        client, app, headers = _client_and_headers(ids["tenant"])
        # Two principals; one calls the high-risk delete tool, both fresh.
        _emit(app, tenant_id=ids["tenant"], principal_id="alice",
              upstream_server_id=ids["server_a"], tool="delete_repo")
        _emit(app, tenant_id=ids["tenant"], principal_id="alice",
              upstream_server_id=ids["server_a"], tool="delete_repo",
              decision=AuditDecision.DENY)
        _emit(app, tenant_id=ids["tenant"], principal_id="bob",
              upstream_server_id=ids["server_b"], tool="search",
              upstream_status=UpstreamStatus.ERROR)
        with client:
            r = client.get("/api/v1/admin/dashboard", headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        # DB-derived counts.
        assert body["mcp_servers_registered"] == 2
        assert body["virtual_servers_published"] == 1
        assert body["pending_access_requests"] == 1
        assert body["oauth_connected_users"] == 1
        assert body["oauth_connected_servers"] == 1
        assert body["users_total"] == 1
        # Recent-events derived counts.
        assert body["nhi_total"] == 2
        assert body["nhi_active_24h"] == 2
        assert body["mcp_servers_active_24h"] == 2
        assert body["high_risk_calls_24h"] >= 1  # delete_repo allowed call
        assert body["denied_calls_24h"] == 1
        assert body["upstream_errors_24h"] == 1
    finally:
        _cleanup(factory, ids["tenant"])


def test_dashboard_excludes_events_older_than_24h_from_active_metrics() -> None:
    """Total NHI count includes everyone in the buffer; active-24h
    metrics excludes events outside the rolling window."""

    factory = _factory()
    ids = _seed(factory)
    try:
        client, app, headers = _client_and_headers(ids["tenant"])
        long_ago = datetime.now(UTC) - timedelta(days=2)
        _emit(app, tenant_id=ids["tenant"], principal_id="ancient",
              timestamp=long_ago, upstream_server_id=ids["server_a"])
        _emit(app, tenant_id=ids["tenant"], principal_id="recent",
              upstream_server_id=ids["server_a"])
        with client:
            r = client.get("/api/v1/admin/dashboard", headers=headers)
        body = r.json()
        # Both seen ever; only 'recent' counts as active in the last 24h.
        assert body["nhi_total"] == 2
        assert body["nhi_active_24h"] == 1
    finally:
        _cleanup(factory, ids["tenant"])


def test_dashboard_unauthenticated_returns_401() -> None:
    factory = _factory()
    ids = _seed(factory)
    try:
        client, _, _ = _client_and_headers(ids["tenant"])
        with client:
            r = client.get("/api/v1/admin/dashboard")
        assert r.status_code == 401
    finally:
        _cleanup(factory, ids["tenant"])


def test_dashboard_only_returns_callers_tenant_data() -> None:
    """Cross-tenant defence: an operator JWT scoped to tenant A must
    not see tenant B's mcp_servers / users / oauth connections."""

    factory = _factory()
    ids_a = _seed(factory)
    ids_b = _seed(factory)
    try:
        # client scoped to tenant A
        client, _, headers = _client_and_headers(ids_a["tenant"])
        with client:
            r = client.get("/api/v1/admin/dashboard", headers=headers)
        body = r.json()
        # Each seed inserts 2 servers; we should see exactly tenant A's 2,
        # not 4 from both.
        assert body["mcp_servers_registered"] == 2
        assert body["users_total"] == 1
    finally:
        _cleanup(factory, ids_a["tenant"])
        _cleanup(factory, ids_b["tenant"])
