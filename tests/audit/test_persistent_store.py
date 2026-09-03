"""Tests for `PostgresToolCallEventStore` — durability across restart.

This is the load-bearing guarantee for the operator dashboard: if a
gateway process is killed, restarted, or upgraded, the Events / NHI map
/ Identities panels must still show historical traffic. The earlier
in-memory ring buffer broke this because the buffer reset to empty on
process boot.

The fan-out chain now writes to `tool_call_events` synchronously on
every emit, and the buffer is rehydrated from that table during
lifespan startup.

Tests below run against real Postgres (skipped without
`VYUU_TEST_DATABASE_URL`):

1. `test_emit_persists_to_postgres` — emit through the chain, verify
   the row landed in `tool_call_events` with the right shape.
2. `test_query_returns_persisted_events_after_restart` — emit, drop
   the in-memory buffer entirely, query the endpoint surface, confirm
   events come back from Postgres.
3. `test_buffer_warmup_rehydrates_from_postgres` — seed `tool_call_events`
   directly, run the lifespan startup hook, confirm the new buffer is
   populated from the table.
4. `test_rls_blocks_cross_tenant_reads` — events for tenant A are
   invisible to a session bound to tenant B, even via direct query.
"""

from __future__ import annotations

import os

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

from typing import Any  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import pytest  # noqa: E402
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
from vyuu_gateway.audit.persistent import (  # noqa: E402
    PostgresToolCallEventStore,
    query_tool_call_events,
    seed_recent_buffer_from_postgres,
)
from vyuu_gateway.audit.recent import RecentAuditEmitter  # noqa: E402
from vyuu_gateway.db.models import (  # noqa: E402
    Tenant,
    TenantTier,
    ToolCallEvent,
)
from vyuu_gateway.db.session import bind_tenant_context  # noqa: E402

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


def _seed_tenant(factory: Any) -> UUID:
    tenant_id = uuid4()
    with factory() as s:
        s.add(
            Tenant(
                id=tenant_id,
                name=f"t-{tenant_id.hex[:6]}",
                tier=TenantTier.SHARED,
            )
        )
        s.commit()
    return tenant_id


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as s:
        s.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        s.commit()


def _event(tenant_id: UUID, *, tool: str = "search", principal_id: str = "alice") -> Any:
    return create_tool_call_audit_event(
        tenant_id=tenant_id,
        gateway_instance_id="g",
        principal=AuditPrincipal(
            type=AuditPrincipalType.API_KEY, id=principal_id, display=principal_id
        ),
        tool=tool,
        arguments={},
        decision=AuditDecision.ALLOW,
        decision_mode=AuditDecisionMode.ENFORCE,
        upstream_status=UpstreamStatus.OK,
    )


@pgmark
def test_emit_persists_to_postgres() -> None:
    factory = _factory()
    tenant_id = _seed_tenant(factory)
    try:
        store = PostgresToolCallEventStore(factory)
        event = _event(tenant_id, tool="repo.list")
        result = store.emit_nowait(event)
        assert result.accepted is True
        assert result.durable is True

        with factory() as s:
            bind_tenant_context(s, tenant_id)
            row = s.get(ToolCallEvent, event.event_id)
            assert row is not None
            assert row.tool == "repo.list"
            assert row.tenant_id == tenant_id
            assert row.principal_id == "alice"
    finally:
        _cleanup(factory, tenant_id)


@pgmark
def test_query_returns_persisted_events_after_restart() -> None:
    """Emit through the chain, drop the buffer entirely, query the
    Postgres-backed surface — the events come back. Proves the dashboard
    survives a process restart."""

    factory = _factory()
    tenant_id = _seed_tenant(factory)
    try:
        store = PostgresToolCallEventStore(factory)
        for tool in ("a", "b", "c"):
            store.emit_nowait(_event(tenant_id, tool=tool))

        # Simulate a restart: open a brand-new session (no buffer state),
        # query directly. This is what the post-restart endpoint sees.
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            events = query_tool_call_events(s, tenant_id=tenant_id)

        tools = [e.tool for e in events]
        assert set(tools) == {"a", "b", "c"}
    finally:
        _cleanup(factory, tenant_id)


@pgmark
def test_buffer_warmup_rehydrates_from_postgres() -> None:
    """`seed_recent_buffer_from_postgres` populates a fresh buffer from
    the persistent table — the operator UI sees historical context
    before any new traffic arrives."""

    factory = _factory()
    tenant_id = _seed_tenant(factory)
    try:
        store = PostgresToolCallEventStore(factory)
        for tool in ("x", "y"):
            store.emit_nowait(_event(tenant_id, tool=tool))

        fresh_buffer = RecentAuditEmitter(max_events=100)
        seeded = seed_recent_buffer_from_postgres(
            factory, buffer_appender=fresh_buffer.warm_load
        )
        assert seeded >= 2
        loaded = fresh_buffer.query(tenant_id=tenant_id)
        loaded_tools = {e.tool for e in loaded}
        assert {"x", "y"}.issubset(loaded_tools)
    finally:
        _cleanup(factory, tenant_id)


@pgmark
def test_rls_blocks_cross_tenant_reads() -> None:
    """A session bound to tenant B cannot read tenant A's events even
    by primary-key lookup. RLS is the wire-level guarantee."""

    factory = _factory()
    tenant_a = _seed_tenant(factory)
    tenant_b = _seed_tenant(factory)
    try:
        store = PostgresToolCallEventStore(factory)
        a_event = _event(tenant_a, tool="secret-a")
        store.emit_nowait(a_event)

        with factory() as s:
            bind_tenant_context(s, tenant_b)
            row = s.get(ToolCallEvent, a_event.event_id)
            assert row is None  # RLS hides it

            events = query_tool_call_events(s, tenant_id=tenant_a)
            assert events == []  # explicit query is also gated
    finally:
        _cleanup(factory, tenant_a)
        _cleanup(factory, tenant_b)
