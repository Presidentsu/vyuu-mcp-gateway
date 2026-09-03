"""RETENTION-1 — durable-audit retention prune (`audit/retention.py`).

Closes the last open compliance gap: `tool_call_events` and
`admin_audit_log` previously grew without bound.

The interesting behaviour is all at the DB boundary, so most of these run
against real Postgres (skipped without `VYUU_TEST_DATABASE_URL`):

1. `test_prune_deletes_only_rows_past_the_cutoff` — the actual contract.
2. `test_prune_is_tenant_scoped` — a prune bound to tenant A must not
   touch tenant B, which is what FORCE RLS is there to guarantee.
3. `test_prune_batches_and_stops_at_the_cycle_cap` — a backlog larger
   than one cycle drains partially and reports `capped`, rather than
   holding one enormous transaction.
4. `test_prune_writes_a_retention_prune_audit_row` — rows must never
   vanish without a record an auditor can find.
5. `test_admin_audit_log_is_kept_when_its_retention_is_zero` — the two
   windows are independent.
6. `test_sweeper_cycle_updates_reported_state` — the diagnostic bundle
   reads these fields to answer "is the cron firing?".

Plus no-DB tests for the keep-forever default and the startup guardrail,
which must hold whether or not a database is reachable.
"""

from __future__ import annotations

import asyncio
import os

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

from datetime import UTC, datetime, timedelta  # noqa: E402
from typing import Any  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import pytest  # noqa: E402
from sqlalchemy import create_engine, select, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.audit.retention import (  # noqa: E402
    RetentionSweeper,
    prune_once,
)
from vyuu_gateway.config import Settings  # noqa: E402
from vyuu_gateway.db.models import (  # noqa: E402
    AdminAuditActorKind,
    AdminAuditLog,
    Tenant,
    TenantTier,
    ToolCallEvent,
)
from vyuu_gateway.db.session import bind_tenant_context  # noqa: E402
from vyuu_gateway.main import create_app  # noqa: E402

pgmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set",
)


# --- Helpers ---------------------------------------------------------------


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(
        create_engine(_DATABASE_URL, future=True), autoflush=False, future=True
    )


def _seed_tenant(factory: Any) -> UUID:
    tenant_id = uuid4()
    with factory() as s:
        s.add(Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED))
        s.commit()
    return tenant_id


def _cleanup(factory: Any, *tenant_ids: UUID) -> None:
    with factory() as s:
        for tenant_id in tenant_ids:
            s.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        s.commit()


def _seed_events(factory: Any, tenant_id: UUID, *, age_days: float, count: int) -> None:
    """Insert `count` events dated `age_days` in the past."""
    occurred = datetime.now(UTC) - timedelta(days=age_days)
    with factory() as s:
        bind_tenant_context(s, tenant_id)
        for i in range(count):
            s.add(
                ToolCallEvent(
                    event_id=uuid4(),
                    tenant_id=tenant_id,
                    occurred_at=occurred,
                    gateway_instance_id="g",
                    event_type="tool_call",
                    tool=f"tool-{i}",
                    principal_type="api_key",
                    principal_id="alice",
                    principal_display="alice",
                    decision="allow",
                    decision_mode="enforce",
                    upstream_status="ok",
                )
            )
        s.commit()


def _event_count(factory: Any, tenant_id: UUID) -> int:
    with factory() as s:
        bind_tenant_context(s, tenant_id)
        return len(list(s.execute(
            select(ToolCallEvent.event_id).where(ToolCallEvent.tenant_id == tenant_id)
        ).all()))


def _admin_rows(factory: Any, tenant_id: UUID, action: str | None = None) -> list[Any]:
    with factory() as s:
        bind_tenant_context(s, tenant_id)
        stmt = select(AdminAuditLog).where(AdminAuditLog.tenant_id == tenant_id)
        if action is not None:
            stmt = stmt.where(AdminAuditLog.action == action)
        return list(s.execute(stmt).scalars().all())


# --- No-DB -----------------------------------------------------------------


class _ExplodingFactory:
    """A session factory that fails the test if it is ever called. Proves
    the keep-forever default costs nothing, rather than merely deleting
    nothing."""

    def __call__(self) -> Any:
        raise AssertionError("retention opened a DB session while disabled")


def test_keep_forever_default_never_touches_the_database() -> None:
    report = prune_once(
        _ExplodingFactory(),
        tool_call_event_retention_days=0,
        admin_audit_retention_days=0,
    )
    assert report.total_deleted == 0
    assert report.tenants_scanned == 0


def test_sweeper_reports_disabled_when_both_windows_are_zero() -> None:
    sweeper = RetentionSweeper(
        session_factory=_ExplodingFactory(),
        tool_call_event_retention_days=0,
        admin_audit_retention_days=0,
    )
    assert sweeper.enabled is False
    sweeper_on = RetentionSweeper(
        session_factory=_ExplodingFactory(),
        tool_call_event_retention_days=90,
    )
    assert sweeper_on.enabled is True


def test_startup_rejects_admin_retention_shorter_than_event_retention() -> None:
    """`admin_audit_log` records the `tool_call_events` prunes. Discarding
    it first would delete the explanation for a gap that is still
    visible — refuse to boot rather than let two plausible env vars
    quietly produce that."""

    with pytest.raises(RuntimeError, match="must be >="):
        create_app(
            Settings(
                app_name="Vyuu MCP Gateway",
                environment="test",
                log_level="CRITICAL",
                version="test-version",
                tool_call_event_retention_days=90,
                admin_audit_retention_days=30,
            )
        )


def test_startup_allows_admin_retention_longer_than_event_retention() -> None:
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
            tool_call_event_retention_days=90,
            admin_audit_retention_days=365,
        )
    )
    assert app is not None


# --- Real Postgres ---------------------------------------------------------


@pgmark
def test_prune_deletes_only_rows_past_the_cutoff() -> None:
    factory = _factory()
    tenant_id = _seed_tenant(factory)
    try:
        _seed_events(factory, tenant_id, age_days=120, count=4)   # past a 90d window
        _seed_events(factory, tenant_id, age_days=10, count=3)    # inside it
        assert _event_count(factory, tenant_id) == 7

        report = prune_once(
            factory,
            tool_call_event_retention_days=90,
            admin_audit_retention_days=0,
        )

        assert report.rows_deleted.get("tool_call_events") == 4
        assert report.capped is False
        assert _event_count(factory, tenant_id) == 3
    finally:
        _cleanup(factory, tenant_id)


@pgmark
def test_prune_is_tenant_scoped() -> None:
    """Both tenants hold equally old rows, but only tenant A is swept —
    proving the per-tenant GUC binding actually bounds the DELETE. A
    prune that ignored RLS would empty both."""

    factory = _factory()
    tenant_a = _seed_tenant(factory)
    tenant_b = _seed_tenant(factory)
    try:
        _seed_events(factory, tenant_a, age_days=120, count=3)
        _seed_events(factory, tenant_b, age_days=120, count=3)

        from vyuu_gateway.audit.retention import _prune_table_for_tenant

        deleted, capped = _prune_table_for_tenant(
            factory,
            tenant_id=tenant_a,
            model=ToolCallEvent,
            pk_column=ToolCallEvent.event_id,
            ts_column=ToolCallEvent.occurred_at,
            cutoff=datetime.now(UTC) - timedelta(days=90),
            batch_size=100,
            max_rows=1000,
        )

        assert (deleted, capped) == (3, False)
        assert _event_count(factory, tenant_a) == 0
        assert _event_count(factory, tenant_b) == 3
    finally:
        _cleanup(factory, tenant_a, tenant_b)


@pgmark
def test_prune_batches_and_stops_at_the_cycle_cap() -> None:
    """25 stale rows, batches of 10, cap of 17 → exactly 17 go, the sweep
    reports `capped`, and the remaining 8 wait for the next cycle.

    The cap is deliberately NOT a multiple of the batch size: with
    17 = 10 + 7 the final chunk has to be short, so a cap that only
    bounded the loop count (and not the chunk size) would overshoot to
    20 and fail here. A 20/10 pair would pass either way.
    """

    factory = _factory()
    tenant_id = _seed_tenant(factory)
    try:
        _seed_events(factory, tenant_id, age_days=120, count=25)

        report = prune_once(
            factory,
            tool_call_event_retention_days=90,
            admin_audit_retention_days=0,
            batch_size=10,
            max_rows_per_cycle=17,
        )
        assert report.rows_deleted.get("tool_call_events") == 17
        assert report.capped is True
        assert _event_count(factory, tenant_id) == 8

        # Next cycle drains the tail and no longer reports capped.
        report2 = prune_once(
            factory,
            tool_call_event_retention_days=90,
            admin_audit_retention_days=0,
            batch_size=10,
            max_rows_per_cycle=17,
        )
        assert report2.rows_deleted.get("tool_call_events") == 8
        assert report2.capped is False
        assert _event_count(factory, tenant_id) == 0
    finally:
        _cleanup(factory, tenant_id)


@pgmark
def test_prune_writes_a_retention_prune_audit_row() -> None:
    """Rows must not vanish silently — an auditor asking "where is March?"
    needs a row that says what was deleted and why."""

    factory = _factory()
    tenant_id = _seed_tenant(factory)
    try:
        _seed_events(factory, tenant_id, age_days=120, count=2)
        prune_once(
            factory,
            tool_call_event_retention_days=90,
            admin_audit_retention_days=0,
        )

        rows = _admin_rows(factory, tenant_id, action="retention.prune")
        assert len(rows) == 1
        row = rows[0]
        assert row.actor_kind == AdminAuditActorKind.SYSTEM
        assert row.actor_display == "retention_sweeper"
        assert row.target_kind == "table"
        assert row.target_display == "tool_call_events"
        assert row.detail["rows_deleted"] == 2
        assert row.detail["retention_days"] == 90
        assert row.detail["hit_cycle_cap"] is False
        assert row.detail["cutoff"]
    finally:
        _cleanup(factory, tenant_id)


@pgmark
def test_no_audit_row_when_nothing_was_deleted() -> None:
    """A daily cron over a quiet tenant must not manufacture a row a day."""

    factory = _factory()
    tenant_id = _seed_tenant(factory)
    try:
        _seed_events(factory, tenant_id, age_days=10, count=3)
        report = prune_once(
            factory,
            tool_call_event_retention_days=90,
            admin_audit_retention_days=0,
        )
        assert report.total_deleted == 0
        assert _admin_rows(factory, tenant_id, action="retention.prune") == []
        assert _event_count(factory, tenant_id) == 3
    finally:
        _cleanup(factory, tenant_id)


@pgmark
def test_admin_audit_log_is_kept_when_its_retention_is_zero() -> None:
    """The two windows are independent: pruning events at 90 days must not
    imply pruning the auditor's table."""

    factory = _factory()
    tenant_id = _seed_tenant(factory)
    try:
        _seed_events(factory, tenant_id, age_days=400, count=1)
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            s.add(
                AdminAuditLog(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    actor_operator_id=None,
                    actor_kind=AdminAuditActorKind.SYSTEM,
                    actor_display="ancient",
                    action="user.disable",
                    detail={},
                    occurred_at=datetime.now(UTC) - timedelta(days=400),
                )
            )
            s.commit()

        prune_once(
            factory,
            tool_call_event_retention_days=90,
            admin_audit_retention_days=0,
        )
        assert _event_count(factory, tenant_id) == 0
        # The 400-day-old admin row survives an events-only prune, and the
        # prune's own record has been added alongside it.
        assert {r.action for r in _admin_rows(factory, tenant_id)} == {
            "user.disable",
            "retention.prune",
        }

        # Now enable admin retention and the ancient row goes too.
        prune_once(
            factory,
            tool_call_event_retention_days=90,
            admin_audit_retention_days=365,
        )
        remaining = {r.action for r in _admin_rows(factory, tenant_id)}
        assert "user.disable" not in remaining
    finally:
        _cleanup(factory, tenant_id)


@pgmark
def test_sweeper_cycle_updates_reported_state() -> None:
    """The diagnostic bundle reads exactly these fields to answer 'is the
    retention cron firing, and is it keeping up?'."""

    factory = _factory()
    tenant_id = _seed_tenant(factory)
    try:
        _seed_events(factory, tenant_id, age_days=120, count=2)
        sweeper = RetentionSweeper(
            session_factory=factory,
            tool_call_event_retention_days=90,
            admin_audit_retention_days=0,
        )
        assert sweeper.cycle_count == 0
        assert sweeper.last_run_at is None

        report = asyncio.run(sweeper.run_one_cycle())

        assert report.rows_deleted.get("tool_call_events") == 2
        assert sweeper.cycle_count == 1
        assert sweeper.last_run_at is not None
        assert sweeper.last_report.total_deleted == 2
        assert _event_count(factory, tenant_id) == 0
    finally:
        _cleanup(factory, tenant_id)
