"""Unit tests for the access-attempt audit event surface.

Three layers:
1. `create_access_attempt_audit_event` — factory shape + sentinel tool.
2. `RecentAuditEmitter.query(event_type=...)` — filter discriminates.
3. `GET /api/v1/audit-events?event_type=access_attempt` — endpoint
   threads the filter (real-DB integration, gated on
   `VYUU_TEST_DATABASE_URL` because the endpoint reads from the
   persistent `tool_call_events` table).

The inbound-route emission path is exercised by the existing
`tests/api/test_inbound_mcp.py` round-trips — adding inbound emit
coverage here would duplicate that scaffolding without adding value.
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
    AuditEvent,
    AuditEventType,
    AuditPrincipal,
    AuditPrincipalType,
    AuthFailureReason,
    create_access_attempt_audit_event,
    create_tool_call_audit_event,
)
from vyuu_gateway.audit.recent import RecentAuditEmitter  # noqa: E402
from vyuu_gateway.config import Settings  # noqa: E402
from vyuu_gateway.db.models import (  # noqa: E402
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
)
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.operator_auth.fake import mint_operator_test_token  # noqa: E402

_OP_SECRET = "access-attempt-test-secret"

pgmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set",
)


# --- Factory --------------------------------------------------------------


def _principal() -> AuditPrincipal:
    return AuditPrincipal(type=AuditPrincipalType.API_KEY, id="alice")


def test_factory_sets_event_type_and_sentinel_tool() -> None:
    event = create_access_attempt_audit_event(
        tenant_id=uuid4(),
        gateway_instance_id="g",
        principal=_principal(),
        auth_failure_reason=AuthFailureReason.NO_GRANT,
        vserver_id=uuid4(),
        vserver_name="vs-finance",
    )
    assert event.event_type == AuditEventType.ACCESS_ATTEMPT
    assert event.tool == "<connect>"
    assert event.decision == AuditDecision.DENY
    assert event.auth_failure_reason == AuthFailureReason.NO_GRANT
    assert event.vserver_name == "vs-finance"
    # policy_rule_id mirrors the failure reason so audit-pipeline
    # consumers that group by rule_id surface auth-failures cleanly.
    assert event.policy_rule_id == "no_grant"


def test_factory_works_without_vserver_id_for_unknown_vserver() -> None:
    """Vserver-not-found case: we only have the URL-path name, no
    canonical UUID. Both fields should be writable independently."""
    event = create_access_attempt_audit_event(
        tenant_id=uuid4(),
        gateway_instance_id="g",
        principal=_principal(),
        auth_failure_reason=AuthFailureReason.VSERVER_NOT_FOUND,
        vserver_name="probably-typo-vs",
    )
    assert event.vserver_id is None
    assert event.vserver_name == "probably-typo-vs"


# --- RecentAuditEmitter filter -------------------------------------------


def _tool_call_event(tenant_id: UUID, *, tool: str = "x") -> AuditEvent:
    return create_tool_call_audit_event(
        tenant_id=tenant_id,
        gateway_instance_id="g",
        principal=_principal(),
        tool=tool,
        arguments={},
        decision=AuditDecision.ALLOW,
    )


def _access_attempt_event(tenant_id: UUID, *, vserver_name: str = "vs-x") -> AuditEvent:
    return create_access_attempt_audit_event(
        tenant_id=tenant_id,
        gateway_instance_id="g",
        principal=_principal(),
        auth_failure_reason=AuthFailureReason.NO_GRANT,
        vserver_name=vserver_name,
    )


def test_recent_emitter_filters_by_event_type() -> None:
    emitter = RecentAuditEmitter()
    tenant = uuid4()
    emitter.emit_nowait(_tool_call_event(tenant, tool="ok"))
    emitter.emit_nowait(_access_attempt_event(tenant, vserver_name="probed-1"))
    emitter.emit_nowait(_tool_call_event(tenant, tool="ok-2"))
    emitter.emit_nowait(_access_attempt_event(tenant, vserver_name="probed-2"))

    only_attempts = emitter.query(
        tenant_id=tenant, event_type=AuditEventType.ACCESS_ATTEMPT
    )
    only_calls = emitter.query(
        tenant_id=tenant, event_type=AuditEventType.TOOL_CALL
    )
    everything = emitter.query(tenant_id=tenant)

    assert {e.event_type for e in only_attempts} == {AuditEventType.ACCESS_ATTEMPT}
    assert {e.event_type for e in only_calls} == {AuditEventType.TOOL_CALL}
    assert len(everything) == 4


# --- /audit-events endpoint ----------------------------------------------


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(
        create_engine(_DATABASE_URL, future=True),
        autoflush=False,
        future=True,
    )


def _seed_tenant(factory: Any) -> tuple[UUID, UUID]:
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
    return tenant_id, operator_id


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as s:
        s.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        s.commit()


def _make_client(tenant_id: UUID, operator_id: UUID) -> tuple[TestClient, FastAPI, dict[str, str]]:
    app = create_app(
        Settings(
            app_name="access-attempt-endpoint-test",
            environment="test",
            log_level="CRITICAL",
            operator_auth_signing_secret=_OP_SECRET,
        )
    )
    client = TestClient(app)
    token = mint_operator_test_token(
        tenant_id=tenant_id,
        operator_id=operator_id,
        signing_secret=_OP_SECRET,
    )
    return client, app, {"Authorization": f"Bearer {token}"}


@pgmark
def test_endpoint_filter_returns_only_access_attempts() -> None:
    factory = _factory()
    tenant_id, operator_id = _seed_tenant(factory)
    try:
        client, app, headers = _make_client(tenant_id, operator_id)
        app.state.recent_audit_emitter.emit_nowait(_tool_call_event(tenant_id, tool="ok"))
        app.state.recent_audit_emitter.emit_nowait(
            _access_attempt_event(tenant_id, vserver_name="probed")
        )

        with client:
            r = client.get(
                "/api/v1/audit-events?event_type=access_attempt", headers=headers
            )

        assert r.status_code == 200, r.text
        rows = r.json()
        assert all(row["event_type"] == "access_attempt" for row in rows)
        assert len(rows) == 1
        assert rows[0]["vserver_name"] == "probed"
        assert rows[0]["auth_failure_reason"] == "no_grant"
    finally:
        _cleanup(factory, tenant_id)


@pgmark
def test_endpoint_returns_both_types_by_default() -> None:
    factory = _factory()
    tenant_id, operator_id = _seed_tenant(factory)
    try:
        client, app, headers = _make_client(tenant_id, operator_id)
        app.state.recent_audit_emitter.emit_nowait(_tool_call_event(tenant_id))
        app.state.recent_audit_emitter.emit_nowait(_access_attempt_event(tenant_id))

        with client:
            r = client.get("/api/v1/audit-events", headers=headers)

        assert r.status_code == 200, r.text
        rows = r.json()
        types = {row["event_type"] for row in rows}
        assert types == {"tool_call", "access_attempt"}
    finally:
        _cleanup(factory, tenant_id)


def test_endpoint_rejects_invalid_event_type_query() -> None:
    """Pure query-validation — no DB interaction. Runs without
    `VYUU_TEST_DATABASE_URL`."""

    app = create_app(
        Settings(
            app_name="access-attempt-bad-query",
            environment="test",
            log_level="CRITICAL",
            operator_auth_signing_secret=_OP_SECRET,
        )
    )
    token = mint_operator_test_token(
        tenant_id=uuid4(),
        operator_id=uuid4(),
        signing_secret=_OP_SECRET,
    )
    headers = {"Authorization": f"Bearer {token}"}
    with TestClient(app) as client:
        r = client.get(
            "/api/v1/audit-events?event_type=bogus", headers=headers
        )
    assert r.status_code == 422
