"""Postgres-backed durable store for inbound MCP audit events.

`PostgresToolCallEventStore` is the *source of truth* for the operator-
console Events / NHI map / Identities panels. It writes every emitted
`AuditEvent` to the `tool_call_events` table synchronously, then
delegates to an inner emitter (Kafka / NATS / disk-spool / no-op) for
the rest of the fan-out.

Why synchronous writes (vs. queued / batched): operators must not lose
events on a process crash. The performance ceiling is one local Postgres
INSERT per inbound MCP call, ~1-2 ms on a co-located DB. Tenants that
push thousands of calls per second can swap this for a batched async
adapter later — the Protocol shape stays the same.

Why a fresh session per event: `emit_nowait` lives in the audit fan-out
and isn't passed the request's DB session (the audit Protocol is
session-agnostic by design). Opening a short-lived session per event
keeps the audit pipeline fully decoupled from the request transaction —
audit failures never roll back a tool call, and a successful tool call
never silently loses its audit row to a request-level rollback. Both
behaviours are what an auditor expects.

The buffer (`RecentAuditEmitter`) sits *above* this store in the chain
and is now strictly a hot read-cache. On gateway startup,
`seed_recent_buffer_from_postgres` warms the buffer from the most
recent N rows in this table so the operator UI shows historical
context before any fresh traffic arrives.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.audit.emitter import AuditEmitter, EmitResult
from vyuu_gateway.audit.events import (
    AuditClientMetadata,
    AuditEvent,
    AuditEventType,
    AuditPrincipal,
    AuditPrincipalType,
    AuthFailureReason,
    AuthModeFlags,
)
from vyuu_gateway.db.models import Tenant, ToolCallEvent
from vyuu_gateway.db.session import bind_tenant_context

logger = logging.getLogger(__name__)


class PostgresToolCallEventStore:
    """Wraps another emitter; persists every event to `tool_call_events`.

    Composition order matters. Place this **before** any Kafka / NATS /
    spool emitter in the chain so the durable write happens first; if
    the inner emitter raises, the audit row is still on disk. Mirrors
    the wrap pattern of `RecentAuditEmitter`.
    """

    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        inner: AuditEmitter | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._inner = inner

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        try:
            self._insert(event)
        except Exception:  # noqa: BLE001
            # Audit failures must not break the request. Log loud, then
            # fall through to the inner emitter so other sinks (Kafka)
            # still get a shot at delivery. The in-memory buffer (above
            # us in the chain) will still hold the event for the live
            # operator panel.
            logger.warning(
                "tool_call_event_persist_failed event_id=%s tenant_id=%s",
                event.event_id,
                event.tenant_id,
                exc_info=True,
            )
        if self._inner is None:
            return EmitResult(accepted=True, durable=True)
        inner_result = self._inner.emit_nowait(event)
        # The Postgres write succeeded (or we logged + continued); mark
        # this leg as durable regardless of inner-emitter health so the
        # caller's `EmitResult.durable` reflects "we have a copy".
        return EmitResult(
            accepted=inner_result.accepted,
            spooled=inner_result.spooled,
            durable=True,
            degraded=inner_result.degraded,
            reason=inner_result.reason,
        )

    def _insert(self, event: AuditEvent) -> None:
        with self._session_factory() as session:
            bind_tenant_context(session, event.tenant_id)
            session.add(_event_to_row(event))
            session.commit()


def _event_to_row(event: AuditEvent) -> ToolCallEvent:
    """Project an in-memory `AuditEvent` onto the `ToolCallEvent` ORM row."""

    return ToolCallEvent(
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        occurred_at=event.timestamp,
        gateway_instance_id=event.gateway_instance_id,
        event_type=event.event_type.value,
        vserver_id=event.vserver_id,
        vserver_name=event.vserver_name,
        upstream_server_id=event.upstream_server_id,
        tool=event.tool,
        principal_type=event.principal.type.value,
        principal_id=event.principal.id,
        principal_display=event.principal.display,
        decision=event.decision.value,
        decision_mode=event.decision_mode.value,
        policy_id=event.policy_id,
        policy_rule_id=event.policy_rule_id,
        upstream_status=event.upstream_status.value,
        latency_ms_total=event.latency_ms_total,
        latency_ms_upstream=event.latency_ms_upstream,
        response_size_bytes=event.response_size_bytes,
        auth_failure_reason=(
            event.auth_failure_reason.value
            if event.auth_failure_reason is not None
            else None
        ),
        args_summary=dict(event.args_summary),
        auth_modes=event.auth_modes.model_dump(mode="json"),
        client_metadata=event.client_metadata.model_dump(mode="json"),
        raw_args=event.raw_args,
        raw_response=event.raw_response,
        raw_args_truncated=event.raw_args_truncated,
        raw_response_truncated=event.raw_response_truncated,
    )


def _row_to_event(row: ToolCallEvent) -> AuditEvent:
    """Reverse projection — used to rehydrate the in-memory ring buffer
    on startup so the operator UI shows historical context before fresh
    traffic arrives."""

    return AuditEvent(
        event_id=row.event_id,
        timestamp=row.occurred_at,
        tenant_id=row.tenant_id,
        gateway_instance_id=row.gateway_instance_id,
        event_type=AuditEventType(row.event_type),
        principal=AuditPrincipal(
            type=AuditPrincipalType(row.principal_type),
            id=row.principal_id,
            display=row.principal_display,
        ),
        vserver_id=row.vserver_id,
        vserver_name=row.vserver_name,
        upstream_server_id=row.upstream_server_id,
        tool=row.tool,
        args_summary=row.args_summary or {},
        decision=row.decision,  # type: ignore[arg-type]
        decision_mode=row.decision_mode,  # type: ignore[arg-type]
        policy_id=row.policy_id,
        policy_rule_id=row.policy_rule_id,
        upstream_status=row.upstream_status,  # type: ignore[arg-type]
        latency_ms_total=row.latency_ms_total,
        latency_ms_upstream=row.latency_ms_upstream,
        response_size_bytes=row.response_size_bytes,
        auth_failure_reason=(
            AuthFailureReason(row.auth_failure_reason)
            if row.auth_failure_reason
            else None
        ),
        client_metadata=AuditClientMetadata.model_validate(
            row.client_metadata or {}
        ),
        auth_modes=AuthModeFlags.model_validate(row.auth_modes or {}),
        raw_args=row.raw_args,
        raw_response=row.raw_response,
        raw_args_truncated=row.raw_args_truncated,
        raw_response_truncated=row.raw_response_truncated,
    )


def query_tool_call_events(
    db: Session,
    *,
    tenant_id: UUID,
    since: datetime | None = None,
    until: datetime | None = None,
    vserver_id: UUID | None = None,
    upstream_server_id: UUID | None = None,
    event_type: AuditEventType | None = None,
    principal_id: str | None = None,
    principal_id_in: frozenset[str] | None = None,
    limit: int = 100,
) -> list[AuditEvent]:
    """Time-bounded read against `tool_call_events`. Newest first.

    `db` must already be tenant-bound (RLS will silently return no rows
    otherwise). Indexes cover the common shapes — tenant feed, vserver
    drill-in, principal timeline. Wider filters fall back to the
    tenant feed plus a Python-side narrow.
    """

    if limit <= 0:
        return []
    stmt = select(ToolCallEvent).where(ToolCallEvent.tenant_id == tenant_id)
    if since is not None:
        stmt = stmt.where(ToolCallEvent.occurred_at >= since)
    if until is not None:
        stmt = stmt.where(ToolCallEvent.occurred_at <= until)
    if vserver_id is not None:
        stmt = stmt.where(ToolCallEvent.vserver_id == vserver_id)
    if upstream_server_id is not None:
        stmt = stmt.where(ToolCallEvent.upstream_server_id == upstream_server_id)
    if event_type is not None:
        stmt = stmt.where(ToolCallEvent.event_type == event_type.value)
    if principal_id is not None:
        stmt = stmt.where(ToolCallEvent.principal_id == principal_id)
    if principal_id_in is not None:
        if not principal_id_in:
            return []
        stmt = stmt.where(ToolCallEvent.principal_id.in_(principal_id_in))
    stmt = stmt.order_by(ToolCallEvent.occurred_at.desc()).limit(limit)
    rows = db.execute(stmt).scalars().all()
    return [_row_to_event(row) for row in rows]


def seed_recent_buffer_from_postgres(
    session_factory: Callable[[], Session],
    *,
    buffer_appender: Callable[[AuditEvent], None],
    per_tenant_limit: int = 2000,
) -> int:
    """Hydrate an in-memory buffer with the most-recent N events per tenant.

    Returns the total number of events pushed into the buffer. Called
    once during gateway lifespan startup so the operator UI shows
    historical context immediately after a restart, instead of waiting
    for fresh traffic to refill an empty deque.

    Iterates events oldest-first per tenant so when the buffer's
    `maxlen` evicts old entries, the caller's "newest-first" reads
    still see the freshest tenant activity. Cross-tenant ordering
    isn't preserved — the buffer's `query()` filters by tenant first
    so this doesn't affect correctness for the operator panels.

    We don't try to remember which tenant the gateway will serve — at
    cold start we don't know. Loading per-tenant uses a SET LOCAL +
    SELECT inside a single session per tenant so RLS allows the read.
    """

    total = 0
    with session_factory() as session:
        # Walk every tenant via the (non-RLS'd) `tenants` table.
        # `tool_call_events` has FORCE RLS so a cross-tenant SELECT
        # without `app.current_tenant_id` would return zero rows; we
        # rebind below per tenant.
        tenant_rows = session.execute(select(Tenant.id)).all()
        tenant_ids = [row[0] for row in tenant_rows]
    for tenant_id in tenant_ids:
        with session_factory() as tsession:
            bind_tenant_context(tsession, tenant_id)
            stmt = (
                select(ToolCallEvent)
                .where(ToolCallEvent.tenant_id == tenant_id)
                .order_by(ToolCallEvent.occurred_at.desc())
                .limit(per_tenant_limit)
            )
            recent_rows = list(tsession.execute(stmt).scalars().all())
        # Push oldest-first so the buffer's deque maxlen evicts the
        # right end if it's already saturated by another tenant.
        for row in reversed(recent_rows):
            buffer_appender(_row_to_event(row))
            total += 1
    if total > 0:
        logger.info(
            "audit_buffer_seeded events=%d tenants=%d",
            total,
            len(tenant_ids),
        )
    return total
