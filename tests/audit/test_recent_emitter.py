"""Unit tests for `RecentAuditEmitter` ring buffer + tenant-scoped query."""

from __future__ import annotations

from uuid import UUID, uuid4

from vyuu_gateway.audit.emitter import EmitResult
from vyuu_gateway.audit.events import (
    AuditDecision,
    AuditDecisionMode,
    AuditEvent,
    AuditPrincipal,
    AuditPrincipalType,
    UpstreamStatus,
    create_tool_call_audit_event,
)
from vyuu_gateway.audit.recent import RecentAuditEmitter


def _event(
    *,
    tenant_id: UUID,
    vserver_id: UUID | None = None,
    upstream_server_id: UUID | None = None,
    tool: str = "t",
) -> AuditEvent:
    return create_tool_call_audit_event(
        tenant_id=tenant_id,
        gateway_instance_id="g",
        principal=AuditPrincipal(type=AuditPrincipalType.API_KEY, id="p"),
        tool=tool,
        arguments={},
        decision=AuditDecision.ALLOW,
        decision_mode=AuditDecisionMode.ENFORCE,
        upstream_status=UpstreamStatus.OK,
        vserver_id=vserver_id,
        upstream_server_id=upstream_server_id,
    )


def test_query_returns_events_newest_first_for_tenant_only() -> None:
    emitter = RecentAuditEmitter()
    tenant_a = uuid4()
    tenant_b = uuid4()

    e1 = _event(tenant_id=tenant_a, tool="first")
    e2 = _event(tenant_id=tenant_b, tool="other-tenant")
    e3 = _event(tenant_id=tenant_a, tool="second")

    emitter.emit_nowait(e1)
    emitter.emit_nowait(e2)
    emitter.emit_nowait(e3)

    rows = emitter.query(tenant_id=tenant_a)
    assert [e.tool for e in rows] == ["second", "first"]
    # tenant_b's event must not appear in tenant_a's query.
    assert all(e.tenant_id == tenant_a for e in rows)


def test_query_ring_buffer_drops_oldest_past_max_events() -> None:
    emitter = RecentAuditEmitter(max_events=3)
    tenant = uuid4()
    for i in range(5):
        emitter.emit_nowait(_event(tenant_id=tenant, tool=f"call-{i}"))
    # Only the last 3 events survive.
    rows = emitter.query(tenant_id=tenant)
    assert [e.tool for e in rows] == ["call-4", "call-3", "call-2"]


def test_query_filters_by_vserver_id() -> None:
    emitter = RecentAuditEmitter()
    tenant = uuid4()
    target_vs = uuid4()
    other_vs = uuid4()

    emitter.emit_nowait(_event(tenant_id=tenant, vserver_id=target_vs, tool="match"))
    emitter.emit_nowait(_event(tenant_id=tenant, vserver_id=other_vs, tool="other"))
    emitter.emit_nowait(_event(tenant_id=tenant, vserver_id=target_vs, tool="match2"))

    rows = emitter.query(tenant_id=tenant, vserver_id=target_vs)
    assert [e.tool for e in rows] == ["match2", "match"]


def test_query_filters_by_upstream_server_id() -> None:
    emitter = RecentAuditEmitter()
    tenant = uuid4()
    target_upstream = uuid4()
    emitter.emit_nowait(_event(tenant_id=tenant, upstream_server_id=target_upstream, tool="hit"))
    emitter.emit_nowait(_event(tenant_id=tenant, upstream_server_id=uuid4(), tool="miss"))

    rows = emitter.query(tenant_id=tenant, upstream_server_id=target_upstream)
    assert [e.tool for e in rows] == ["hit"]


def test_query_respects_limit() -> None:
    emitter = RecentAuditEmitter()
    tenant = uuid4()
    for i in range(10):
        emitter.emit_nowait(_event(tenant_id=tenant, tool=f"t-{i}"))
    rows = emitter.query(tenant_id=tenant, limit=3)
    assert len(rows) == 3
    # Newest first.
    assert rows[0].tool == "t-9"


def test_inner_emitter_receives_every_event() -> None:
    """Wrapping an inner emitter must not swallow events; the inner
    sees the same event the buffer recorded."""
    captured: list[AuditEvent] = []

    class _Capture:
        def emit_nowait(self, event: AuditEvent) -> EmitResult:
            captured.append(event)
            return EmitResult(accepted=True)

    emitter = RecentAuditEmitter(inner=_Capture())
    tenant = uuid4()
    emitter.emit_nowait(_event(tenant_id=tenant, tool="passthrough"))
    assert len(captured) == 1
    assert captured[0].tool == "passthrough"


def test_query_with_zero_limit_returns_empty() -> None:
    emitter = RecentAuditEmitter()
    tenant = uuid4()
    emitter.emit_nowait(_event(tenant_id=tenant))
    assert emitter.query(tenant_id=tenant, limit=0) == []
