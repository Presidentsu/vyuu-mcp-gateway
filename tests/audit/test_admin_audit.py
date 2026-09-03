"""Tests for the server-side admin audit log emitter.

Two layers:

1. **Unit-level contract** — `record_admin_action()` calls `db.add()`
   and never `db.commit()`. This is the core of the synchronous-same-
   transaction guarantee (the caller commits both the mutation and
   the audit row together, atomically). Skipping the unit-level test
   risks regressing the contract silently.

2. **Real-DB rollback test** (when `VYUU_TEST_DATABASE_URL` is set) —
   open a transaction, perform a mutation + add an audit row, then
   `rollback()`. Confirm both rows are absent. The auditor's "if the
   action happened, the row exists" guarantee depends on this
   behavior at the DB layer.
"""

from __future__ import annotations

import os
from typing import Any
from uuid import UUID, uuid4

import pytest

# Test DB env-var promotion BEFORE any vyuu_gateway imports — same
# pattern as `tests/users/test_users_api.py` (SessionLocal is built
# at module import time).
_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ.setdefault("VYUU_DATABASE_URL", _DATABASE_URL)

from vyuu_gateway.audit.admin_audit import (  # noqa: E402
    AdminAuditActor,
    AdminAuditTarget,
    record_admin_action,
)
from vyuu_gateway.db.models import (  # noqa: E402
    AdminAuditActorKind,
    AdminAuditLog,
)
from vyuu_gateway.db.session import bind_tenant_context  # noqa: E402
from vyuu_gateway.operator_auth.models import AuthenticatedOperator  # noqa: E402

# --- 1. Unit-level contract --------------------------------------------


class _FakeSession:
    """Smallest stand-in to verify the emitter contract."""

    def __init__(self) -> None:
        self.added: list[Any] = []
        self.commit_calls = 0
        self.rollback_calls = 0

    def add(self, instance: Any) -> None:
        self.added.append(instance)

    def commit(self) -> None:
        self.commit_calls += 1

    def rollback(self) -> None:
        self.rollback_calls += 1


def _operator() -> AuthenticatedOperator:
    return AuthenticatedOperator(
        tenant_id=uuid4(),
        operator_id=uuid4(),
        display="alice@example.com",
    )


def test_record_admin_action_calls_add_not_commit() -> None:
    """The contract: emitter `add()`s, never `commit()`s. Caller commits.

    This is the load-bearing guarantee — without it, the audit insert
    would commit independently of the action and we'd lose the atomic
    "both or neither" property the auditor needs.
    """
    db = _FakeSession()
    op = _operator()

    record_admin_action(
        db,
        tenant_id=op.tenant_id,
        actor=AdminAuditActor.operator(op),
        action="user.disable",
        target=AdminAuditTarget(
            kind="user", id=uuid4(), display="bob@example.com"
        ),
        detail={"reason": "manual revocation"},
    )

    assert len(db.added) == 1
    assert db.commit_calls == 0
    assert db.rollback_calls == 0


def test_record_admin_action_persists_actor_target_detail() -> None:
    db = _FakeSession()
    op = _operator()
    target_id = uuid4()

    row = record_admin_action(
        db,
        tenant_id=op.tenant_id,
        actor=AdminAuditActor.operator(op),
        action="vserver.delete",
        target=AdminAuditTarget(
            kind="vserver", id=target_id, display="finance-readonly"
        ),
        detail={"tool_count": 12, "grant_count": 3},
    )

    assert row is db.added[0]
    assert row.tenant_id == op.tenant_id
    assert row.actor_operator_id == op.operator_id
    assert row.actor_kind == AdminAuditActorKind.OPERATOR
    assert row.actor_display == "alice@example.com"
    assert row.action == "vserver.delete"
    assert row.target_kind == "vserver"
    assert row.target_id == target_id
    assert row.target_display == "finance-readonly"
    assert row.detail == {"tool_count": 12, "grant_count": 3}
    # SQLAlchemy populates id at flush; before that the row carries the
    # uuid4 we generated ourselves. Either way it's not None.
    assert row.id is not None


def test_system_actor_has_no_operator_id() -> None:
    db = _FakeSession()
    tenant_id = uuid4()

    row = record_admin_action(
        db,
        tenant_id=tenant_id,
        actor=AdminAuditActor.system("hard_delete_sweeper"),
        action="scim.hard_delete_user",
        target=AdminAuditTarget(
            kind="user", id=uuid4(), display="terminated@acme.com"
        ),
    )

    assert row.actor_kind == AdminAuditActorKind.SYSTEM
    assert row.actor_operator_id is None
    assert row.actor_display == "hard_delete_sweeper"


def test_scim_actor_displays_directory_name() -> None:
    db = _FakeSession()
    tenant_id = uuid4()

    row = record_admin_action(
        db,
        tenant_id=tenant_id,
        actor=AdminAuditActor.scim("Acme Corp · Entra ID"),
        action="scim.deactivate_user",
        target=AdminAuditTarget(
            kind="user", id=uuid4(), display="leaver@acme.com"
        ),
    )

    assert row.actor_kind == AdminAuditActorKind.SCIM
    assert row.actor_operator_id is None
    assert row.actor_display == "Acme Corp · Entra ID"


def test_target_optional() -> None:
    """Some actions don't have a single target — e.g., `idp.test_connection`.
    The emitter must accept `target=None` gracefully."""
    db = _FakeSession()
    op = _operator()

    row = record_admin_action(
        db,
        tenant_id=op.tenant_id,
        actor=AdminAuditActor.operator(op),
        action="idp.test_connection",
        detail={"directory_kind": "entra"},
    )

    assert row.target_kind is None
    assert row.target_id is None
    assert row.target_display is None
    assert row.detail == {"directory_kind": "entra"}


def test_detail_defaults_to_empty_dict() -> None:
    db = _FakeSession()
    op = _operator()

    row = record_admin_action(
        db,
        tenant_id=op.tenant_id,
        actor=AdminAuditActor.operator(op),
        action="grant.list",
    )

    assert row.detail == {}


# --- 2. Real-DB rollback test -----------------------------------------
#
# The integration test that proves the synchronous-same-transaction
# guarantee at the DB layer. Skipped when no test DB is configured.


pytestmark_db = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set; skipping rollback integration",
)


@pytestmark_db
def test_rollback_drops_audit_row_when_mutation_rolls_back() -> None:
    """Open a transaction, add an audit row alongside a fake mutation,
    rollback. The audit row must NOT survive — it shares the
    transaction with whatever the caller is doing.

    This is the auditor-facing guarantee: if the action didn't
    commit, the audit row didn't either. No "we logged it but the
    user wasn't actually disabled" false positives.
    """
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker

    from vyuu_gateway.db.models import Tenant, TenantTier

    engine = create_engine(_DATABASE_URL, future=True)
    Session = sessionmaker(engine, autoflush=False, future=True)

    tenant_id = uuid4()
    audit_id_to_check: UUID | None = None

    # Seed a tenant the audit row can FK to. Commit this OUT OF BAND
    # so the rollback below only touches the audit + the no-op
    # mutation we're testing.
    with Session() as setup:
        setup.add(Tenant(id=tenant_id, name=f"rollback-test-{tenant_id}", tier=TenantTier.SHARED))
        setup.commit()

    try:
        with Session() as session:
            bind_tenant_context(session, tenant_id)
            # Step 1: pretend we're about to perform a mutation that
            # ends up rolled back. We just add the audit row — the
            # "mutation" is omitted; rollback semantics don't depend
            # on what else was in the transaction.
            row = record_admin_action(
                session,
                tenant_id=tenant_id,
                actor=AdminAuditActor.system("rollback-test"),
                action="test.rollback_drops_audit_row",
                target=AdminAuditTarget(
                    kind="user", id=uuid4(), display="rolled-back-user"
                ),
                detail={"test": True},
            )
            session.flush()  # populates row.id from the DB
            audit_id_to_check = row.id
            session.rollback()

        # Step 2: confirm the audit row is gone.
        assert audit_id_to_check is not None
        with Session() as verify:
            # MUST bind here too: under FORCE RLS an unbound SELECT returns
            # zero rows no matter what is stored, so `is None` below would
            # pass whether or not the rollback actually worked.
            bind_tenant_context(verify, tenant_id)
            persisted = verify.execute(
                select(AdminAuditLog).where(AdminAuditLog.id == audit_id_to_check)
            ).scalar_one_or_none()
            assert persisted is None, (
                "audit row survived a rollback — same-transaction "
                "guarantee is broken; auditor would see a logged "
                "action that never actually happened"
            )
    finally:
        with Session() as cleanup:
            cleanup.execute(
                Tenant.__table__.delete().where(Tenant.id == tenant_id)
            )
            cleanup.commit()


@pytestmark_db
def test_commit_persists_audit_row() -> None:
    """The other half of the contract: when the caller commits, the
    audit row lands. (Sanity check that the rollback test isn't just
    detecting a broken emitter.)"""
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker

    from vyuu_gateway.db.models import Tenant, TenantTier

    engine = create_engine(_DATABASE_URL, future=True)
    Session = sessionmaker(engine, autoflush=False, future=True)

    tenant_id = uuid4()
    with Session() as setup:
        setup.add(Tenant(id=tenant_id, name=f"commit-test-{tenant_id}", tier=TenantTier.SHARED))
        setup.commit()

    audit_id_to_check: UUID | None = None
    try:
        with Session() as session:
            bind_tenant_context(session, tenant_id)
            row = record_admin_action(
                session,
                tenant_id=tenant_id,
                actor=AdminAuditActor.system("commit-test"),
                action="test.commit_persists",
            )
            session.flush()
            audit_id_to_check = row.id
            session.commit()

        assert audit_id_to_check is not None
        with Session() as verify:
            bind_tenant_context(verify, tenant_id)
            persisted = verify.execute(
                select(AdminAuditLog).where(AdminAuditLog.id == audit_id_to_check)
            ).scalar_one_or_none()
            assert persisted is not None
            assert persisted.action == "test.commit_persists"
    finally:
        with Session() as cleanup:
            bind_tenant_context(cleanup, tenant_id)
            cleanup.execute(
                AdminAuditLog.__table__.delete().where(AdminAuditLog.tenant_id == tenant_id)
            )
            cleanup.execute(
                Tenant.__table__.delete().where(Tenant.id == tenant_id)
            )
            cleanup.commit()
