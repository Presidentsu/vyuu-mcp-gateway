"""Retention prune for the durable audit tables (RETENTION-1).

Closes the last open compliance gap from `SECURITY.md`: `tool_call_events`
and `admin_audit_log` grew without bound, so a deployment's oldest
user-interaction data lived forever whether or not its retention policy
allowed that.

## Default is OFF, on purpose

`tool_call_event_retention_days` and `admin_audit_retention_days` both
default to `0` (keep forever) — this module supplies the *mechanism*, not
the *policy*. The window is a legal/deployment decision (GDPR minimisation
and SOC 2 evidence retention pull in opposite directions), the deletion is
irreversible, and an operator upgrading the gateway must never discover
that restarting it silently destroyed a year of audit history. Ops opt in
per deployment; 90 days is the documented starting point.

## Why the deletes are chunked

`DELETE FROM tool_call_events WHERE occurred_at < cutoff` on a table with
millions of rows holds one long transaction, bloats WAL, and can block
concurrent inserts on the hot audit write path. Instead we delete in
`batch_size` chunks keyed on the primary key, committing each chunk, and
stop at `max_rows_per_cycle` so one cycle can never run unbounded. A
backlog larger than the cap simply drains over subsequent cycles.

## Why it is per-tenant

Both tables are ENABLE + FORCE row-level security, so an unscoped DELETE
matches zero rows (the same trap that made an unscoped SELECT look like
data loss during the lab DB migration). We enumerate tenants via the
non-RLS'd `tenants` table and rebind `app.current_tenant_id` per tenant —
identical to `seed_recent_buffer_from_postgres`.

## Audit-row placement (a deliberate exception)

`audit/admin_audit.py` requires the audit row to share the mutation's
transaction. A chunked prune has no single transaction to share, so the
`retention.prune` row is written afterwards as a summary of the completed
sweep. The tradeoff is explicit: if that insert fails after chunks have
committed, rows are gone without a DB-side record — so the failure path
logs at ERROR with the full detail (tenant, table, cutoff, count) for
reconstruction from the log pipeline. Holding a multi-million-row delete
open in one transaction purely to preserve atomicity with a bookkeeping
row would trade a rare, logged, reconstructible gap for a routine
production hazard.

Ordering guardrail: `admin_audit_log` must not be pruned sooner than
`tool_call_events`, or the record explaining why events vanished would be
deleted while the gap it explains is still visible. `create_app` refuses
to start on that inversion.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from vyuu_gateway.audit.admin_audit import (
    AdminAuditActor,
    AdminAuditTarget,
    record_admin_action,
)
from vyuu_gateway.db.models import AdminAuditLog, Tenant, ToolCallEvent
from vyuu_gateway.db.session import bind_tenant_context

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], Session]

# Daily, not hourly. The window is measured in days, so hourly resolution
# buys nothing and multiplies the `retention.prune` audit rows by 24.
DEFAULT_INTERVAL_SECONDS = 24 * 3600.0

# Hold off the first sweep so a large backlog prune doesn't contend with
# bootstrap, capability sync, and buffer warm-up on a cold start.
DEFAULT_INITIAL_DELAY_SECONDS = 60.0

# Rows per committed chunk. Large enough that the per-statement overhead
# is irrelevant, small enough that each lock is held for milliseconds.
DEFAULT_BATCH_SIZE = 5_000

# Ceiling per table per tenant per cycle. A first prune against years of
# accumulated history drains over several cycles instead of hammering the
# DB for an hour on the first restart after opt-in.
DEFAULT_MAX_ROWS_PER_CYCLE = 200_000

_ACTOR_LABEL = "retention_sweeper"

# `(model, primary key, timestamp column, audit label)` — the two durable
# audit tables share a prune shape, so the loop is table-driven rather
# than copy-pasted.
_TARGETS: tuple[tuple[Any, Any, Any, str], ...] = (
    (ToolCallEvent, ToolCallEvent.event_id, ToolCallEvent.occurred_at, "tool_call_events"),
    (AdminAuditLog, AdminAuditLog.id, AdminAuditLog.occurred_at, "admin_audit_log"),
)


@dataclass
class PruneReport:
    """What one sweep actually did. Surfaced in the diagnostic bundle so
    an operator can answer 'is retention running, and is it keeping up?'"""

    rows_deleted: dict[str, int] = field(default_factory=dict)
    tenants_scanned: int = 0
    # True when any table hit `max_rows_per_cycle` — the backlog is
    # larger than one cycle can drain, so more cycles are still owed.
    capped: bool = False

    @property
    def total_deleted(self) -> int:
        return sum(self.rows_deleted.values())


def _prune_table_for_tenant(
    session_factory: SessionFactory,
    *,
    tenant_id: UUID,
    model: Any,
    pk_column: Any,
    ts_column: Any,
    cutoff: datetime,
    batch_size: int,
    max_rows: int,
) -> tuple[int, bool]:
    """Delete rows older than `cutoff` in committed chunks.

    Returns `(rows_deleted, hit_cap)`. Each chunk is its own session +
    transaction: locks stay short, and a failure part-way leaves the
    already-committed chunks deleted rather than rolling back the whole
    backlog.
    """

    deleted = 0
    while deleted < max_rows:
        chunk = min(batch_size, max_rows - deleted)
        # `DELETE ... WHERE pk IN (SELECT pk ... LIMIT n)` — the standard
        # Postgres batching idiom. Ordering by the timestamp deletes
        # oldest-first, so an interrupted sweep still moves the floor up.
        doomed = (
            select(pk_column)
            .where(model.tenant_id == tenant_id, ts_column < cutoff)
            .order_by(ts_column.asc())
            .limit(chunk)
            .scalar_subquery()
        )
        with session_factory() as session:
            bind_tenant_context(session, tenant_id)
            result = session.execute(
                delete(model).where(pk_column.in_(doomed)),
                execution_options={"synchronize_session": False},
            )
            session.commit()
        removed = result.rowcount or 0
        deleted += removed
        if removed < chunk:
            # Fewer than asked for means the backlog is drained.
            return deleted, False
    return deleted, True


def prune_once(
    session_factory: SessionFactory,
    *,
    tool_call_event_retention_days: int,
    admin_audit_retention_days: int,
    batch_size: int = DEFAULT_BATCH_SIZE,
    max_rows_per_cycle: int = DEFAULT_MAX_ROWS_PER_CYCLE,
    now: datetime | None = None,
) -> PruneReport:
    """Run one retention pass across every tenant. Synchronous — the
    worker schedules it onto an executor thread.

    A retention of `0` (or less) for a table means "keep forever" and is
    skipped entirely, so an all-zero config costs one `SELECT id FROM
    tenants` per cycle and nothing else.
    """

    retention_days = {
        "tool_call_events": tool_call_event_retention_days,
        "admin_audit_log": admin_audit_retention_days,
    }
    report = PruneReport()
    if all(days <= 0 for days in retention_days.values()):
        return report

    moment = now or datetime.now(UTC)

    # `tenants` carries no RLS, so this cross-tenant read is legitimate;
    # every delete below rebinds the GUC for its own tenant.
    with session_factory() as session:
        tenant_ids = [row[0] for row in session.execute(select(Tenant.id)).all()]
    report.tenants_scanned = len(tenant_ids)

    for tenant_id in tenant_ids:
        for model, pk_column, ts_column, label in _TARGETS:
            days = retention_days[label]
            if days <= 0:
                continue
            cutoff = moment - timedelta(days=days)
            try:
                deleted, hit_cap = _prune_table_for_tenant(
                    session_factory,
                    tenant_id=tenant_id,
                    model=model,
                    pk_column=pk_column,
                    ts_column=ts_column,
                    cutoff=cutoff,
                    batch_size=batch_size,
                    max_rows=max_rows_per_cycle,
                )
            except Exception:  # noqa: BLE001 — one tenant must not stop the sweep
                logger.warning(
                    "retention_prune_tenant_failed",
                    extra={"tenant_id": str(tenant_id), "table": label},
                    exc_info=True,
                )
                continue
            if not deleted:
                continue
            report.rows_deleted[label] = report.rows_deleted.get(label, 0) + deleted
            report.capped = report.capped or hit_cap
            _record_prune(
                session_factory,
                tenant_id=tenant_id,
                table=label,
                rows_deleted=deleted,
                cutoff=cutoff,
                retention_days=days,
                hit_cap=hit_cap,
            )
    return report


def _record_prune(
    session_factory: SessionFactory,
    *,
    tenant_id: UUID,
    table: str,
    rows_deleted: int,
    cutoff: datetime,
    retention_days: int,
    hit_cap: bool,
) -> None:
    """Append the `retention.prune` summary row. See the module docstring
    for why this is not in the deletes' transaction — and why a failure
    here is logged at ERROR rather than swallowed."""

    detail = {
        "table": table,
        "rows_deleted": rows_deleted,
        "cutoff": cutoff.isoformat(),
        "retention_days": retention_days,
        # Tells the auditor the sweep was truncated, so the absence of
        # older rows in a later report isn't a second unexplained gap.
        "hit_cycle_cap": hit_cap,
    }
    try:
        with session_factory() as session:
            bind_tenant_context(session, tenant_id)
            record_admin_action(
                session,
                tenant_id=tenant_id,
                actor=AdminAuditActor.system(_ACTOR_LABEL),
                action="retention.prune",
                target=AdminAuditTarget(kind="table", id=None, display=table),
                detail=detail,
            )
            session.commit()
    except Exception:  # noqa: BLE001
        # The rows are already gone; the log line is now the only record.
        logger.error(
            "retention_prune_audit_failed tenant_id=%s detail=%s",
            tenant_id,
            detail,
            exc_info=True,
        )


class RetentionSweeper:
    """Async cron-style task that prunes the durable audit tables.

    Same shape as `HardDeleteSweeper` — `start()` / `stop()` plus
    `run_one_cycle()` so tests drive it deterministically without
    `asyncio.sleep`.
    """

    def __init__(
        self,
        *,
        session_factory: SessionFactory,
        tool_call_event_retention_days: int,
        admin_audit_retention_days: int = 0,
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
        initial_delay_seconds: float = DEFAULT_INITIAL_DELAY_SECONDS,
        batch_size: int = DEFAULT_BATCH_SIZE,
        max_rows_per_cycle: int = DEFAULT_MAX_ROWS_PER_CYCLE,
    ) -> None:
        self._session_factory = session_factory
        self._tool_call_event_retention_days = int(tool_call_event_retention_days)
        self._admin_audit_retention_days = int(admin_audit_retention_days)
        self._interval = max(1.0, float(interval_seconds))
        self._initial_delay = max(0.0, float(initial_delay_seconds))
        self._batch_size = max(1, int(batch_size))
        self._max_rows_per_cycle = max(1, int(max_rows_per_cycle))
        self._task: asyncio.Task[None] | None = None
        self._cycle_count = 0
        self._last_report = PruneReport()
        self._last_run_at: datetime | None = None

    @property
    def enabled(self) -> bool:
        """False when every table is set to keep-forever. The worker still
        starts (so the diagnostic bundle can say so) but each cycle is a
        no-op."""

        return (
            self._tool_call_event_retention_days > 0
            or self._admin_audit_retention_days > 0
        )

    @property
    def cycle_count(self) -> int:
        return self._cycle_count

    @property
    def last_report(self) -> PruneReport:
        return self._last_report

    @property
    def last_run_at(self) -> datetime | None:
        return self._last_run_at

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def aclose(self) -> None:
        await self.stop()

    async def run_one_cycle(self) -> PruneReport:
        loop = asyncio.get_running_loop()
        report = await loop.run_in_executor(None, self._prune)
        self._cycle_count += 1
        self._last_report = report
        self._last_run_at = datetime.now(UTC)
        if report.total_deleted:
            logger.info(
                "retention_prune_cycle rows=%s tenants=%d capped=%s",
                report.rows_deleted,
                report.tenants_scanned,
                report.capped,
            )
        return report

    async def _run(self) -> None:
        if self._initial_delay:
            await asyncio.sleep(self._initial_delay)
        while True:
            try:
                await self.run_one_cycle()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — never crash the worker
                logger.warning("retention_prune_cycle_failed", exc_info=True)
            await asyncio.sleep(self._interval)

    def _prune(self) -> PruneReport:
        return prune_once(
            self._session_factory,
            tool_call_event_retention_days=self._tool_call_event_retention_days,
            admin_audit_retention_days=self._admin_audit_retention_days,
            batch_size=self._batch_size,
            max_rows_per_cycle=self._max_rows_per_cycle,
        )
