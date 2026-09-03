"""Hard-delete sweeper for SCIM-soft-deleted users.

When the IdP deactivates a user (SCIM `active=false` or `DELETE`),
we set `users.disabled_at` (so their bearer 401s immediately) and
`users.soft_deleted_at` (the grace-window watermark). After
`grace_seconds` has elapsed, this sweeper hard-deletes the row.

Every hard-delete writes an `admin_audit_log` row with
`actor_kind='system'` so compliance can reconstruct what happened
even if the sweeper is later disabled. The audit row is written in
the same transaction as the DELETE — the synchronous-same-
transaction guarantee from Phase 1d applies here too.

Same async-task shape as `PeriodicCapabilitySyncScheduler` —
`start()` / `stop()` plus `run_one_cycle()` for deterministic
testing without `asyncio.sleep`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session

from vyuu_gateway.audit.admin_audit import AdminAuditActor
from vyuu_gateway.db.session import bind_tenant_context
from vyuu_gateway.idp.service import (
    find_users_due_for_hard_delete,
    hard_delete_user,
)

logger = logging.getLogger(__name__)

# 7 days. Locked in the IDP-1 decision log; a constant rather than a
# config knob because changing it has audit-log implications and
# shouldn't be a per-deploy override.
DEFAULT_GRACE_SECONDS = 7 * 24 * 3600

# Default cadence — once an hour. The sweep is cheap (small index
# scan + N tiny per-row deletes); hourly catches the 7-day expiry
# quickly without burning DB IO.
DEFAULT_INTERVAL_SECONDS = 3600.0

SessionFactory = Callable[[], Session]


class HardDeleteSweeper:
    """Async cron-style task that periodically hard-deletes
    SCIM-soft-deleted users past their grace window."""

    _ACTOR_LABEL = "hard_delete_sweeper"

    def __init__(
        self,
        *,
        session_factory: SessionFactory,
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
        grace_seconds: float = DEFAULT_GRACE_SECONDS,
    ) -> None:
        self._session_factory = session_factory
        self._interval = max(1.0, float(interval_seconds))
        self._grace = max(1.0, float(grace_seconds))
        self._task: asyncio.Task[None] | None = None
        self._cycle_count = 0
        self._last_swept_count = 0

    @property
    def cycle_count(self) -> int:
        return self._cycle_count

    @property
    def last_swept_count(self) -> int:
        """Rows hard-deleted in the most recent cycle. Useful in tests
        + as a future Prometheus gauge."""

        return self._last_swept_count

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

    async def run_one_cycle(self) -> None:
        """Single sweep pass. Synchronous DB work scheduled onto the
        event-loop's default executor so we don't block."""

        loop = asyncio.get_running_loop()
        swept = await loop.run_in_executor(None, self._sweep_once)
        self._cycle_count += 1
        self._last_swept_count = swept

    async def _run(self) -> None:
        while True:
            try:
                await self.run_one_cycle()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — never crash the worker
                logger.warning("hard_delete_sweep_cycle_failed", exc_info=True)
            await asyncio.sleep(self._interval)

    # --- Synchronous core (runs on a thread) ------------------------------

    def _sweep_once(self) -> int:
        """Find soft-deleted rows past the grace window and hard-delete
        each in its own per-tenant transaction. Returns the number of
        rows actually deleted on this pass.

        Why per-tenant transactions:
        - Each commit must bind `app.current_tenant_id` for RLS to
          permit the `admin_audit_log` insert.
        - Failure on one tenant must not roll back deletes that already
          succeeded for another tenant.
        """

        cutoff = datetime.now(UTC) - timedelta(seconds=self._grace)

        # EMA-1 piggyback: drop expired ID-JAG replay reservations. The
        # table only exists to block replays inside a grant's own
        # lifetime (+skew); anything past `expires_at` is dead weight.
        # Untenanted delete — `ema_consumed_jti` is ENABLE-RLS (owner
        # exempt), and the rows carry no secrets. Best-effort: a failed
        # prune never blocks the user sweep below.
        try:
            from vyuu_gateway.db.models import EmaConsumedJti  # local import — avoids cycle

            with self._session_factory() as prune_session:
                prune_session.execute(
                    delete(EmaConsumedJti).where(
                        EmaConsumedJti.expires_at < datetime.now(UTC)
                    )
                )
                prune_session.commit()
        except Exception:  # noqa: BLE001 — table may predate migration in odd envs
            logger.warning("ema_jti_prune_failed", exc_info=True)

        # Scan untenanted — we need to see rows across every tenant to
        # build the work list. The actual delete + audit run inside
        # tenant-bound sessions further down.
        with self._session_factory() as scan_session:
            candidates = find_users_due_for_hard_delete(
                scan_session, older_than=cutoff
            )

        if not candidates:
            return 0

        deleted = 0
        for tenant_id, user_id, captured_email in candidates:
            try:
                with self._session_factory() as session:
                    bind_tenant_context(session, tenant_id)
                    hard_delete_user(
                        session,
                        tenant_id=tenant_id,
                        user_id=user_id,
                        captured_email=captured_email,
                        actor=AdminAuditActor.system(self._ACTOR_LABEL),
                    )
                deleted += 1
            except Exception:  # noqa: BLE001 — log and continue
                logger.warning(
                    "hard_delete_sweep_user_failed",
                    extra={"tenant_id": str(tenant_id), "user_id": str(user_id)},
                    exc_info=True,
                )
        return deleted
