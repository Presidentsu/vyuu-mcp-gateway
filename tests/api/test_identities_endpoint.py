"""End-to-end tests for the N1 Identities endpoints.

Boots a TestClient against a real Postgres (when `VYUU_TEST_DATABASE_URL`
is set), seeds tenant + operator + (optionally) `mcp_servers` /
`mcp_capabilities` for risk classification, emits audit events through
the audit fan-out chain so they land in the persistent
`tool_call_events` table, then asserts the operator-side queries return
the right shapes + filters.

The endpoints read from the persistent store (not the in-memory
buffer) so the dashboard survives gateway restarts. Tests therefore
need a real DB; the legacy fake-session test setup was removed.
"""

from __future__ import annotations

import os

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

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
    McpCapability,
    McpCapabilityKind,
    McpServer,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
    Operator,
    OperatorRole,
    RiskCategory,
    Tenant,
    TenantTier,
)
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.operator_auth.fake import mint_operator_test_token  # noqa: E402

_SECRET = "identities-test-secret"

pgmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set",
)


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(
        create_engine(_DATABASE_URL, future=True),
        autoflush=False,
        future=True,
    )


def _seed(
    factory: Any,
    *,
    capability_rows: list[tuple[UUID, str, RiskCategory]] | None = None,
) -> tuple[UUID, UUID, UUID | None]:
    """Returns (tenant_id, operator_id, server_id-or-None).

    `capability_rows` of `(server_id, tool_name, risk)` seed
    `mcp_capabilities` so risk-floor / high-risk-only assertions see
    real classifications. The server_id of the FIRST row is used as
    the seeded `mcp_servers.id`; later rows must reuse the same id.
    """

    tenant_id = uuid4()
    operator_id = uuid4()
    with factory() as s:
        s.add(
            Tenant(
                id=tenant_id,
                name=f"t-{tenant_id.hex[:6]}",
                tier=TenantTier.SHARED,
            )
        )
        s.commit()
    with factory() as s:
        s.add(
            Operator(
                id=operator_id,
                tenant_id=tenant_id,
                email=f"op-{operator_id.hex[:6]}@test",
                role=OperatorRole.ADMIN,
            )
        )
        s.commit()

    server_id: UUID | None = None
    if capability_rows:
        server_id = capability_rows[0][0]
        with factory() as s:
            s.add(
                McpServer(
                    id=server_id,
                    tenant_id=tenant_id,
                    display_name=f"srv-{server_id.hex[:6]}",
                    source_type=McpServerSourceType.HTTP,
                    source_location="https://example/mcp",
                    transport=McpTransport.STREAMABLE_HTTP,
                    args=[],
                    registered_by=operator_id,
                    health_status=McpServerHealthStatus.UNKNOWN,
                )
            )
            for cap_server, tool_name, risk in capability_rows:
                s.add(
                    McpCapability(
                        tenant_id=tenant_id,
                        server_id=cap_server,
                        kind=McpCapabilityKind.TOOL,
                        name=tool_name,
                        risk_category=risk,
                        schema_json={},
                    )
                )
            s.commit()
    return tenant_id, operator_id, server_id


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as s:
        # Cascade from tenants drops everything tenant-scoped.
        s.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        s.commit()


def _make_client(tenant_id: UUID, operator_id: UUID) -> tuple[TestClient, FastAPI, dict[str, str]]:
    app = create_app(
        Settings(
            app_name="identities-test",
            environment="test",
            log_level="CRITICAL",
            operator_auth_signing_secret=_SECRET,
        )
    )
    client = TestClient(app)
    token = mint_operator_test_token(
        tenant_id=tenant_id, operator_id=operator_id, signing_secret=_SECRET
    )
    return client, app, {"Authorization": f"Bearer {token}"}


def _emit(
    app: FastAPI,
    *,
    tenant_id: UUID,
    principal_id: str = "p",
    tool: str = "t",
    upstream_server_id: UUID | None = None,
    vserver_id: UUID | None = None,
    decision: AuditDecision = AuditDecision.ALLOW,
    upstream_status: UpstreamStatus = UpstreamStatus.OK,
) -> None:
    """Emit through the full fan-out so the event lands in
    `tool_call_events` (the endpoint's source of truth)."""

    app.state.recent_audit_emitter.emit_nowait(
        create_tool_call_audit_event(
            tenant_id=tenant_id,
            gateway_instance_id="g",
            principal=AuditPrincipal(type=AuditPrincipalType.API_KEY, id=principal_id),
            tool=tool,
            arguments={},
            decision=decision,
            decision_mode=AuditDecisionMode.ENFORCE,
            upstream_status=upstream_status,
            vserver_id=vserver_id,
            upstream_server_id=upstream_server_id,
        )
    )


# --- /identities -----------------------------------------------------------


@pgmark
def test_list_identities_aggregates_per_principal() -> None:
    factory = _factory()
    tenant, operator, _ = _seed(factory)
    try:
        client, app, headers = _make_client(tenant, operator)
        _emit(app, tenant_id=tenant, principal_id="alice", tool="search")
        _emit(app, tenant_id=tenant, principal_id="alice", tool="get_file")
        _emit(app, tenant_id=tenant, principal_id="bob", tool="search")

        with client:
            r = client.get("/api/v1/identities", headers=headers)

        assert r.status_code == 200, r.text
        rows = {row["principal_id"]: row for row in r.json()}
        assert rows["alice"]["total_calls"] == 2
        assert rows["alice"]["distinct_tools"] == 2
        assert rows["bob"]["total_calls"] == 1
    finally:
        _cleanup(factory, tenant)


@pgmark
def test_list_identities_only_returns_callers_tenant() -> None:
    factory = _factory()
    tenant, operator, _ = _seed(factory)
    other_tenant, _, _ = _seed(factory)
    try:
        client, app, headers = _make_client(tenant, operator)
        _emit(app, tenant_id=tenant, principal_id="mine")
        _emit(app, tenant_id=other_tenant, principal_id="theirs")

        with client:
            r = client.get("/api/v1/identities", headers=headers)

        assert r.status_code == 200, r.text
        assert {row["principal_id"] for row in r.json()} == {"mine"}
    finally:
        _cleanup(factory, tenant)
        _cleanup(factory, other_tenant)


@pgmark
def test_list_identities_high_risk_only_filters_to_dangerous_actions() -> None:
    factory = _factory()
    server = uuid4()
    cap_rows = [
        (server, "read_file", RiskCategory.READ),
        (server, "delete_repo", RiskCategory.DELETE),
    ]
    tenant, operator, _ = _seed(factory, capability_rows=cap_rows)
    try:
        client, app, headers = _make_client(tenant, operator)
        _emit(app, tenant_id=tenant, principal_id="reader",
              tool="read_file", upstream_server_id=server)
        _emit(app, tenant_id=tenant, principal_id="dangerous",
              tool="delete_repo", upstream_server_id=server)

        with client:
            r_all = client.get("/api/v1/identities", headers=headers)
            r_high = client.get(
                "/api/v1/identities?high_risk_only=true", headers=headers
            )

        assert {row["principal_id"] for row in r_all.json()} == {"reader", "dangerous"}
        assert [row["principal_id"] for row in r_high.json()] == ["dangerous"]
    finally:
        _cleanup(factory, tenant)


def test_list_identities_unauthenticated_returns_401() -> None:
    app = create_app(
        Settings(
            app_name="identities-test-noauth",
            environment="test",
            log_level="CRITICAL",
            operator_auth_signing_secret=_SECRET,
        )
    )
    with TestClient(app) as client:
        r = client.get("/api/v1/identities")
    assert r.status_code == 401


@pgmark
def test_list_identities_returns_empty_when_no_events() -> None:
    factory = _factory()
    tenant, operator, _ = _seed(factory)
    try:
        client, _, headers = _make_client(tenant, operator)
        with client:
            r = client.get("/api/v1/identities", headers=headers)
        assert r.status_code == 200
        assert r.json() == []
    finally:
        _cleanup(factory, tenant)


@pgmark
def test_list_identities_excludes_access_attempt_events() -> None:
    """access_attempt events (auth/access denials at the gate) are
    surfaced separately — they shouldn't inflate per-identity tool
    counts in the dashboard."""

    from vyuu_gateway.audit.events import (
        AuthFailureReason,
        create_access_attempt_audit_event,
    )

    factory = _factory()
    tenant, operator, _ = _seed(factory)
    try:
        client, app, headers = _make_client(tenant, operator)
        _emit(app, tenant_id=tenant, principal_id="real")
        # Add an access_attempt for a different principal id — it must not
        # surface as its own row in the identities feed.
        app.state.recent_audit_emitter.emit_nowait(
            create_access_attempt_audit_event(
                tenant_id=tenant,
                gateway_instance_id="g",
                principal=AuditPrincipal(
                    type=AuditPrincipalType.API_KEY, id="bouncer-victim"
                ),
                vserver_name="locked-vs",
                auth_failure_reason=AuthFailureReason.NO_GRANT,
            )
        )

        with client:
            r = client.get("/api/v1/identities", headers=headers)

        rows = r.json()
        ids = {row["principal_id"] for row in rows}
        assert "real" in ids
        assert "bouncer-victim" not in ids
    finally:
        _cleanup(factory, tenant)


# --- /identities/{principal_id}/timeline -----------------------------------


@pgmark
def test_timeline_returns_only_target_principal_events() -> None:
    factory = _factory()
    tenant, operator, _ = _seed(factory)
    try:
        client, app, headers = _make_client(tenant, operator)
        _emit(app, tenant_id=tenant, principal_id="alice", tool="t1")
        _emit(app, tenant_id=tenant, principal_id="bob", tool="t2")
        _emit(app, tenant_id=tenant, principal_id="alice", tool="t3")

        with client:
            r = client.get("/api/v1/identities/alice/timeline", headers=headers)

        assert r.status_code == 200, r.text
        tools = {row["tool"] for row in r.json()}
        assert tools == {"t1", "t3"}
    finally:
        _cleanup(factory, tenant)


@pgmark
def test_timeline_filters_by_decision() -> None:
    factory = _factory()
    tenant, operator, _ = _seed(factory)
    try:
        client, app, headers = _make_client(tenant, operator)
        _emit(app, tenant_id=tenant, principal_id="alice",
              tool="ok", decision=AuditDecision.ALLOW)
        _emit(app, tenant_id=tenant, principal_id="alice",
              tool="bad", decision=AuditDecision.DENY)

        with client:
            r = client.get(
                "/api/v1/identities/alice/timeline?decision=deny",
                headers=headers,
            )

        assert r.status_code == 200, r.text
        rows = r.json()
        assert [row["tool"] for row in rows] == ["bad"]
    finally:
        _cleanup(factory, tenant)


@pgmark
def test_timeline_risk_floor_excludes_lower_severity_events() -> None:
    factory = _factory()
    server = uuid4()
    cap_rows = [
        (server, "read_file", RiskCategory.READ),
        (server, "delete_repo", RiskCategory.DELETE),
        (server, "grant_admin", RiskCategory.ADMIN),
    ]
    tenant, operator, _ = _seed(factory, capability_rows=cap_rows)
    try:
        client, app, headers = _make_client(tenant, operator)
        _emit(app, tenant_id=tenant, principal_id="alice",
              tool="read_file", upstream_server_id=server)
        _emit(app, tenant_id=tenant, principal_id="alice",
              tool="delete_repo", upstream_server_id=server)
        _emit(app, tenant_id=tenant, principal_id="alice",
              tool="grant_admin", upstream_server_id=server)

        with client:
            r = client.get(
                "/api/v1/identities/alice/timeline?risk_floor=admin",
                headers=headers,
            )

        assert r.status_code == 200, r.text
        timeline = r.json()
        assert [row["tool"] for row in timeline] == ["grant_admin"]
    finally:
        _cleanup(factory, tenant)


@pgmark
def test_timeline_cross_tenant_returns_empty() -> None:
    """Operator JWT pins tenant; events for other tenants are never
    visible — even if the principal_id matches."""

    factory = _factory()
    tenant, operator, _ = _seed(factory)
    other_tenant, _, _ = _seed(factory)
    try:
        client, app, headers = _make_client(tenant, operator)
        _emit(app, tenant_id=other_tenant, principal_id="alice")

        with client:
            r = client.get("/api/v1/identities/alice/timeline", headers=headers)

        assert r.status_code == 200, r.text
        assert r.json() == []
    finally:
        _cleanup(factory, tenant)
        _cleanup(factory, other_tenant)
