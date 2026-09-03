"""Tests for the hard-delete sweeper.

Real-DB integration — skipped when `VYUU_TEST_DATABASE_URL` is unset.
The point is to exercise the actual SQL + RLS interactions, since
the sweeper's correctness depends on tenant-binding the per-row
delete (otherwise the admin_audit_log insert RLS-fails silently and
the sweep "succeeds" without recording anything).
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ.setdefault("VYUU_DATABASE_URL", _DATABASE_URL)

from sqlalchemy import create_engine, select, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.db.models import (  # noqa: E402
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
    User,
    UserAuthMethod,
)
from vyuu_gateway.idp.sweeper import HardDeleteSweeper  # noqa: E402

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set; skipping sweeper integration",
)


def _build_factory() -> Any:
    assert _DATABASE_URL is not None
    engine = create_engine(_DATABASE_URL, future=True)
    return sessionmaker(engine, autoflush=False, future=True)


def _seed_tenant() -> tuple[UUID, UUID]:
    """Create a fresh tenant + a placeholder operator (the operator
    isn't strictly needed for user-only tests but the schema's
    tenant FK and the `created_by` FK on a few related tables make
    this a useful default)."""

    Session = _build_factory()
    tenant_id = uuid4()
    operator_id = uuid4()
    with Session() as session:
        session.add(Tenant(id=tenant_id, name=f"sweeper-test-{tenant_id}", tier=TenantTier.SHARED))
        session.add(
            Operator(
                id=operator_id,
                tenant_id=tenant_id,
                email=f"sweeper-test-{operator_id}@x.com",
                role=OperatorRole.ADMIN,
                password_hash=None,
                must_change_password=False,
            )
        )
        session.commit()
    return tenant_id, operator_id


def _cleanup_tenant(tenant_id: UUID) -> None:
    Session = _build_factory()
    with Session() as session:
        session.execute(
            text("DELETE FROM tenants WHERE id = :tid"), {"tid": str(tenant_id)}
        )
        session.commit()


def _seed_soft_deleted_user(
    tenant_id: UUID, *, soft_deleted_at: datetime
) -> UUID:
    Session = _build_factory()
    user_id = uuid4()
    with Session() as session:
        session.add(
            User(
                id=user_id,
                tenant_id=tenant_id,
                email=f"leaver-{user_id}@example.com",
                display_name="Departed Leaver",
                auth_method=UserAuthMethod.SCIM,
                disabled_at=soft_deleted_at,
                soft_deleted_at=soft_deleted_at,
            )
        )
        session.commit()
    return user_id


def _audit_rows_for(tenant_id: UUID) -> list[tuple[str, str, str]]:
    """Read admin_audit_log rows for the tenant with RLS bound. Returns
    [(action, actor_kind, target_display), ...]."""

    Session = _build_factory()
    with Session() as session:
        session.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, false)"),
            {"tid": str(tenant_id)},
        )
        rows = session.execute(
            text(
                "SELECT action, actor_kind, target_display "
                "FROM admin_audit_log WHERE tenant_id = :tid "
                "ORDER BY occurred_at"
            ),
            {"tid": str(tenant_id)},
        ).all()
        return [(r[0], r[1], r[2]) for r in rows]


def _user_exists(user_id: UUID, tenant_id: UUID) -> bool:
    Session = _build_factory()
    with Session() as session:
        return session.scalar(
            select(User).where(User.id == user_id, User.tenant_id == tenant_id)
        ) is not None


def test_sweeper_skips_users_inside_grace_window() -> None:
    """A row whose `soft_deleted_at` is within the grace window must
    NOT be hard-deleted. This is the "don't be over-eager" guarantee."""

    tenant_id, _operator_id = _seed_tenant()
    try:
        # Soft-deleted 1 hour ago — well inside a 7-day grace.
        recently_deleted_user = _seed_soft_deleted_user(
            tenant_id,
            soft_deleted_at=datetime.now(UTC) - timedelta(hours=1),
        )
        sweeper = HardDeleteSweeper(
            session_factory=_build_factory(),
            interval_seconds=3600,
            grace_seconds=7 * 24 * 3600,
        )

        asyncio.run(sweeper.run_one_cycle())

        assert sweeper.last_swept_count == 0
        assert _user_exists(recently_deleted_user, tenant_id)
        assert _audit_rows_for(tenant_id) == []
    finally:
        _cleanup_tenant(tenant_id)


def test_sweeper_hard_deletes_users_past_grace_window() -> None:
    """A row whose `soft_deleted_at` is older than the grace window
    must be removed AND a `scim.hard_delete_user` audit row must be
    written with `actor_kind='system'`."""

    tenant_id, _operator_id = _seed_tenant()
    try:
        old_user = _seed_soft_deleted_user(
            tenant_id,
            soft_deleted_at=datetime.now(UTC) - timedelta(days=8),
        )
        sweeper = HardDeleteSweeper(
            session_factory=_build_factory(),
            interval_seconds=3600,
            grace_seconds=7 * 24 * 3600,
        )

        asyncio.run(sweeper.run_one_cycle())

        assert sweeper.last_swept_count == 1
        assert not _user_exists(old_user, tenant_id)
        audit = _audit_rows_for(tenant_id)
        assert len(audit) == 1
        action, actor_kind, target_display = audit[0]
        assert action == "scim.hard_delete_user"
        assert actor_kind == "system"
        assert target_display.endswith("@example.com")
    finally:
        _cleanup_tenant(tenant_id)


def test_sweeper_skips_users_with_no_soft_deleted_marker() -> None:
    """A regular SCIM-provisioned user with no `soft_deleted_at` must
    survive every sweep — only the soft-deletion path advances them
    toward removal."""

    tenant_id, _operator_id = _seed_tenant()
    try:
        Session = _build_factory()
        live_user_id = uuid4()
        with Session() as session:
            session.add(
                User(
                    id=live_user_id,
                    tenant_id=tenant_id,
                    email=f"alive-{live_user_id}@example.com",
                    auth_method=UserAuthMethod.SCIM,
                )
            )
            session.commit()

        sweeper = HardDeleteSweeper(
            session_factory=_build_factory(),
            interval_seconds=3600,
            grace_seconds=7 * 24 * 3600,
        )
        asyncio.run(sweeper.run_one_cycle())

        assert sweeper.last_swept_count == 0
        assert _user_exists(live_user_id, tenant_id)
    finally:
        _cleanup_tenant(tenant_id)


def test_sweeper_runs_per_tenant_transactions() -> None:
    """When two tenants both have expired rows, both must be deleted.
    The sweep walks them in separate transactions so a per-tenant
    failure can't poison the other tenant's cleanup."""

    tenant_a, _ = _seed_tenant()
    tenant_b, _ = _seed_tenant()
    try:
        old = datetime.now(UTC) - timedelta(days=10)
        user_a = _seed_soft_deleted_user(tenant_a, soft_deleted_at=old)
        user_b = _seed_soft_deleted_user(tenant_b, soft_deleted_at=old)

        sweeper = HardDeleteSweeper(
            session_factory=_build_factory(),
            interval_seconds=3600,
            grace_seconds=7 * 24 * 3600,
        )
        asyncio.run(sweeper.run_one_cycle())

        assert sweeper.last_swept_count == 2
        assert not _user_exists(user_a, tenant_a)
        assert not _user_exists(user_b, tenant_b)
        assert len(_audit_rows_for(tenant_a)) == 1
        assert len(_audit_rows_for(tenant_b)) == 1
    finally:
        _cleanup_tenant(tenant_a)
        _cleanup_tenant(tenant_b)
