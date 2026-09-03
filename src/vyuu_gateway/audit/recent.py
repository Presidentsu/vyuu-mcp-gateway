"""In-memory ring buffer of recent audit events.

Mounted on every gateway as `app.state.recent_audit_events` (a
`RecentAuditEmitter` instance) so the operator console's "Tool-call
activity" panel can show recent events without standing up a separate
audit query store. The buffer wraps another `AuditEmitter` (typically
the production Kafka/NATS one) — every event passes through the inner
emitter unchanged AND is recorded locally for query.

Bounded ring buffer (default 1000 events). Reset on gateway restart.
This is **not** a durable audit log — production durable audit goes
through Kafka / NATS. The recent-events buffer is a UI affordance.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from threading import Lock
from uuid import UUID

from vyuu_gateway.audit.emitter import AuditEmitter, EmitResult
from vyuu_gateway.audit.events import AuditEvent, AuditEventType


class RecentAuditEmitter:
    """Wraps another emitter; also keeps the last N events for query.

    Thread-safe: every operation that touches the deque takes a lock.
    The hot path is `emit_nowait` (one append + delegate), which is fast
    enough that contention isn't a concern at single-gateway scale.
    """

    def __init__(
        self,
        inner: AuditEmitter | None = None,
        *,
        max_events: int = 1000,
    ) -> None:
        self._inner = inner
        self._buffer: deque[AuditEvent] = deque(maxlen=max_events)
        self._lock = Lock()

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        with self._lock:
            self._buffer.append(event)
        if self._inner is None:
            return EmitResult(accepted=True)
        return self._inner.emit_nowait(event)

    def warm_load(self, event: AuditEvent) -> None:
        """Append a historical event to the buffer without re-emitting.

        Used by the lifespan startup hook to seed the buffer from
        Postgres so the operator UI shows context after a restart.
        Distinct from `emit_nowait` because we must NOT push these
        events back through the inner emitter chain — they were already
        durably persisted on the original emit.
        """

        with self._lock:
            self._buffer.append(event)

    def query(
        self,
        *,
        tenant_id: UUID,
        vserver_id: UUID | None = None,
        upstream_server_id: UUID | None = None,
        event_type: AuditEventType | None = None,
        principal_id_in: frozenset[str] | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Return the most-recent events, newest first, scoped to a tenant.

        Tenant scoping is mandatory — operators can only see their own
        tenant's events. `vserver_id`, `upstream_server_id`, and
        `event_type` are optional filters; when set the AND is applied.
        `principal_id_in` (when set) keeps only events whose
        `principal.id` is in the given set — used by the portal's
        per-user "Tool history" panel to scope to one user's API keys.
        `limit` caps the response (default 100, max bounded by
        `max_events`).
        """

        if limit <= 0:
            return []
        with self._lock:
            snapshot = list(self._buffer)
        # Iterate newest-first.
        results: list[AuditEvent] = []
        for event in reversed(snapshot):
            if event.tenant_id != tenant_id:
                continue
            if vserver_id is not None and event.vserver_id != vserver_id:
                continue
            if (
                upstream_server_id is not None
                and event.upstream_server_id != upstream_server_id
            ):
                continue
            if event_type is not None and event.event_type != event_type:
                continue
            if (
                principal_id_in is not None
                and event.principal.id not in principal_id_in
            ):
                continue
            results.append(event)
            if len(results) >= limit:
                break
        return results

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)

    def all(self) -> Iterable[AuditEvent]:
        """Snapshot copy of the full buffer in insertion order. Test-only."""

        with self._lock:
            return list(self._buffer)
