"""Unit-ish tests for the A3-γ service layer.

Run against real Postgres because the partial-unique index on
`(user_id, vserver_id) WHERE status='pending'` is a Postgres-specific
behavior we want to exercise end-to-end. Skipped when
`VYUU_TEST_DATABASE_URL` is unset.
"""

from __future__ import annotations

import os

# Pre-import nudge — same pattern as test_users_api.py.
_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

from typing import Any  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import pytest  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.db.models import (  # noqa: E402
    AccessRequestStatus,
    GrantPrincipalKind,
    Group,
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
    User,
    UserAuthMethod,
    UserGroupMembership,
    VirtualServer,
    VirtualServerGrant,
    VirtualServerVisibility,
)
from vyuu_gateway.registry.access_requests_service import (  # noqa: E402
    AccessRequestNotFoundError,
    DuplicatePendingRequestError,
    UserAlreadyHasAccessError,
    VserverIsPublicError,
    VserverNotFoundForRequestError,
    WrongRequestStateError,
    approve_access_request,
    decline_access_request,
    list_access_requests,
    list_my_access_requests,
    submit_access_request,
    withdraw_access_request,
)

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set",
)


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(create_engine(_DATABASE_URL, future=True), autoflush=False, future=True)


def _seed_world(
    factory: Any,
    *,
    visibility: VirtualServerVisibility = VirtualServerVisibility.PRIVATE,
) -> tuple[UUID, UUID, UUID, UUID]:
    """Spin up a tenant + operator + user + private vserver. Returns
    (tenant_id, operator_id, user_id, vserver_id)."""
    tenant_id = uuid4()
    operator_id = uuid4()
    user_id = uuid4()
    vserver_id = uuid4()
    with factory() as session:
        session.add(Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED))
        session.add(
            Operator(
                id=operator_id,
                tenant_id=tenant_id,
                email=f"op-{operator_id.hex[:6]}@test",
                role=OperatorRole.ADMIN,
            )
        )
        session.add(
            User(
                id=user_id,
                tenant_id=tenant_id,
                email=f"u-{user_id.hex[:6]}@test",
                auth_method=UserAuthMethod.LOCAL,
                password_hash="x" * 60,  # not used in these tests
            )
        )
        session.add(
            VirtualServer(
                id=vserver_id,
                tenant_id=tenant_id,
                name=f"vs-{vserver_id.hex[:6]}",
                visibility=visibility,
                created_by=operator_id,
            )
        )
        session.commit()
    return tenant_id, operator_id, user_id, vserver_id


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as session:
        for table in (
            "access_requests",
            "user_group_memberships",
            "virtual_server_grants",
            "user_api_keys",
            "groups",
            "users",
            "virtual_server_tools",
            "virtual_servers",
            "operators",
        ):
            if table == "user_group_memberships":
                session.execute(
                    text(
                        "DELETE FROM user_group_memberships WHERE user_id IN "
                        "(SELECT id FROM users WHERE tenant_id = :id)"
                    ),
                    {"id": tenant_id},
                )
            else:
                session.execute(
                    text(f"DELETE FROM {table} WHERE tenant_id = :id"),
                    {"id": tenant_id},
                )
        session.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        session.commit()


# --- submit -----------------------------------------------------------------


def test_submit_creates_pending_request_with_optional_note() -> None:
    factory = _factory()
    tenant_id, _, user_id, vserver_id = _seed_world(factory)
    try:
        with factory() as db:
            req = submit_access_request(
                db,
                tenant_id=tenant_id,
                user_id=user_id,
                vserver_id=vserver_id,
                note="need this for project X",
            )
        assert req.status == AccessRequestStatus.PENDING
        assert req.note == "need this for project X"
        assert req.decided_at is None
        assert req.created_grant_id is None
    finally:
        _cleanup(factory, tenant_id)


def test_submit_rejects_unknown_vserver() -> None:
    factory = _factory()
    tenant_id, _, user_id, _ = _seed_world(factory)
    try:
        with factory() as db, pytest.raises(VserverNotFoundForRequestError):
            submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=uuid4()
            )
    finally:
        _cleanup(factory, tenant_id)


def test_submit_rejects_public_vserver() -> None:
    factory = _factory()
    tenant_id, _, user_id, vserver_id = _seed_world(
        factory, visibility=VirtualServerVisibility.PUBLIC
    )
    try:
        with factory() as db, pytest.raises(VserverIsPublicError):
            submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id
            )
    finally:
        _cleanup(factory, tenant_id)


def test_submit_rejects_when_user_already_has_direct_grant() -> None:
    """If the admin already issued a grant, the user shouldn't be able
    to file a noisy request — they already have access."""
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(factory)
    try:
        with factory() as db:
            db.add(
                VirtualServerGrant(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    vserver_id=vserver_id,
                    principal_kind=GrantPrincipalKind.USER,
                    principal_id=user_id,
                    granted_by=operator_id,
                )
            )
            db.commit()
        with factory() as db, pytest.raises(UserAlreadyHasAccessError):
            submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id
            )
    finally:
        _cleanup(factory, tenant_id)


def test_submit_rejects_when_user_already_has_group_grant() -> None:
    """Group-leg of the access check: user is in group G, G has a grant
    on the vserver → submit must reject."""
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(factory)
    try:
        group_id = uuid4()
        with factory() as db:
            db.add(
                Group(
                    id=group_id,
                    tenant_id=tenant_id,
                    name=f"g-{group_id.hex[:6]}",
                    created_by=operator_id,
                )
            )
            db.add(
                UserGroupMembership(
                    user_id=user_id, group_id=group_id, added_by=operator_id
                )
            )
            db.add(
                VirtualServerGrant(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    vserver_id=vserver_id,
                    principal_kind=GrantPrincipalKind.GROUP,
                    principal_id=group_id,
                    granted_by=operator_id,
                )
            )
            db.commit()
        with factory() as db, pytest.raises(UserAlreadyHasAccessError):
            submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id
            )
    finally:
        _cleanup(factory, tenant_id)


def test_submit_rejects_duplicate_pending() -> None:
    """The partial-unique index on (user_id, vserver_id) WHERE
    status='pending' must collapse a second submit into 409."""
    factory = _factory()
    tenant_id, _, user_id, vserver_id = _seed_world(factory)
    try:
        with factory() as db:
            submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id
            )
        with factory() as db, pytest.raises(DuplicatePendingRequestError):
            submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id
            )
    finally:
        _cleanup(factory, tenant_id)


# --- approve ----------------------------------------------------------------


def test_approve_creates_grant_and_marks_request() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(factory)
    try:
        with factory() as db:
            req = submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id
            )
            request_id = req.id
        with factory() as db:
            approved = approve_access_request(
                db,
                tenant_id=tenant_id,
                request_id=request_id,
                operator_id=operator_id,
            )
            grant_id = approved.created_grant_id
            assert approved.status == AccessRequestStatus.APPROVED
            assert approved.decided_by == operator_id
            assert approved.decided_at is not None
            assert grant_id is not None
            grant = db.get(VirtualServerGrant, grant_id)
            assert grant is not None
            assert grant.principal_kind == GrantPrincipalKind.USER
            assert grant.principal_id == user_id
            assert grant.vserver_id == vserver_id
    finally:
        _cleanup(factory, tenant_id)


def test_approve_rejects_already_decided_request() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(factory)
    try:
        with factory() as db:
            req = submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id
            )
            request_id = req.id
        with factory() as db:
            approve_access_request(
                db,
                tenant_id=tenant_id,
                request_id=request_id,
                operator_id=operator_id,
            )
        # A second approve must not silently re-create a grant.
        with factory() as db, pytest.raises(WrongRequestStateError):
            approve_access_request(
                db,
                tenant_id=tenant_id,
                request_id=request_id,
                operator_id=operator_id,
            )
    finally:
        _cleanup(factory, tenant_id)


def test_approve_idempotent_when_user_gained_access_meanwhile() -> None:
    """Race: user submits, admin grants directly via /grants, admin
    then approves the still-pending request. Approval must NOT create
    a duplicate grant — and `created_grant_id` stays null because this
    approval didn't create the grant."""
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(factory)
    try:
        with factory() as db:
            req = submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id
            )
            request_id = req.id
            # Grant access through the manual path:
            db.add(
                VirtualServerGrant(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    vserver_id=vserver_id,
                    principal_kind=GrantPrincipalKind.USER,
                    principal_id=user_id,
                    granted_by=operator_id,
                )
            )
            db.commit()
        with factory() as db:
            approved = approve_access_request(
                db,
                tenant_id=tenant_id,
                request_id=request_id,
                operator_id=operator_id,
            )
            assert approved.status == AccessRequestStatus.APPROVED
            assert approved.created_grant_id is None  # didn't create one
            # Only one grant exists, not two.
            from sqlalchemy import select

            grants = list(
                db.scalars(
                    select(VirtualServerGrant).where(
                        VirtualServerGrant.vserver_id == vserver_id,
                        VirtualServerGrant.principal_id == user_id,
                    )
                ).all()
            )
            assert len(grants) == 1
    finally:
        _cleanup(factory, tenant_id)


# --- decline + withdraw + listing ------------------------------------------


def test_decline_records_note_and_does_not_create_grant() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(factory)
    try:
        with factory() as db:
            req = submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id
            )
            request_id = req.id
        with factory() as db:
            declined = decline_access_request(
                db,
                tenant_id=tenant_id,
                request_id=request_id,
                operator_id=operator_id,
                decision_note="not enough business context",
            )
            assert declined.status == AccessRequestStatus.DECLINED
            assert declined.decision_note == "not enough business context"
            assert declined.created_grant_id is None
    finally:
        _cleanup(factory, tenant_id)


def test_withdraw_pending_succeeds() -> None:
    factory = _factory()
    tenant_id, _, user_id, vserver_id = _seed_world(factory)
    try:
        with factory() as db:
            req = submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id
            )
            request_id = req.id
        with factory() as db:
            withdrawn = withdraw_access_request(
                db, tenant_id=tenant_id, user_id=user_id, request_id=request_id
            )
            assert withdrawn.status == AccessRequestStatus.WITHDRAWN
    finally:
        _cleanup(factory, tenant_id)


def test_withdraw_after_approval_rejected() -> None:
    """Approved is a final state. A user clicking 'withdraw' on what
    they thought was still pending must get a clear 409, not a silent
    rewrite of the audit trail."""
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(factory)
    try:
        with factory() as db:
            req = submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id
            )
            request_id = req.id
        with factory() as db:
            approve_access_request(
                db,
                tenant_id=tenant_id,
                request_id=request_id,
                operator_id=operator_id,
            )
        with factory() as db, pytest.raises(WrongRequestStateError):
            withdraw_access_request(
                db, tenant_id=tenant_id, user_id=user_id, request_id=request_id
            )
    finally:
        _cleanup(factory, tenant_id)


def test_withdraw_only_owner_can_cancel() -> None:
    """A different user cannot withdraw someone else's request — the
    service treats it as not-found rather than 403, matching anti-
    enumeration posture."""
    factory = _factory()
    tenant_id, _, user_id, vserver_id = _seed_world(factory)
    try:
        with factory() as db:
            req = submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id
            )
            request_id = req.id
        other_user_id = uuid4()
        with factory() as db, pytest.raises(AccessRequestNotFoundError):
            withdraw_access_request(
                db,
                tenant_id=tenant_id,
                user_id=other_user_id,
                request_id=request_id,
            )
    finally:
        _cleanup(factory, tenant_id)


def test_list_my_filters_by_user_and_status() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(factory)
    try:
        # Submit + decline; submit + leave pending.
        with factory() as db:
            r1 = submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id
            )
            r1_id = r1.id
        with factory() as db:
            decline_access_request(
                db,
                tenant_id=tenant_id,
                request_id=r1_id,
                operator_id=operator_id,
                decision_note="no",
            )
        # Need a second vserver to submit a fresh pending request for.
        vserver_id_2 = uuid4()
        with factory() as db:
            db.add(
                VirtualServer(
                    id=vserver_id_2,
                    tenant_id=tenant_id,
                    name=f"vs2-{vserver_id_2.hex[:6]}",
                    visibility=VirtualServerVisibility.PRIVATE,
                    created_by=operator_id,
                )
            )
            db.commit()
        with factory() as db:
            submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id_2
            )
        with factory() as db:
            all_mine = list_my_access_requests(
                db, tenant_id=tenant_id, user_id=user_id
            )
            pending = list_my_access_requests(
                db,
                tenant_id=tenant_id,
                user_id=user_id,
                status_filter=AccessRequestStatus.PENDING,
            )
        assert len(all_mine) == 2
        assert len(pending) == 1
        assert pending[0].vserver_id == vserver_id_2
    finally:
        _cleanup(factory, tenant_id)


def test_list_admin_queue_filters_by_status() -> None:
    factory = _factory()
    tenant_id, _, user_id, vserver_id = _seed_world(factory)
    try:
        with factory() as db:
            submit_access_request(
                db, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id
            )
        with factory() as db:
            pending = list_access_requests(
                db,
                tenant_id=tenant_id,
                status_filter=AccessRequestStatus.PENDING,
            )
            all_rows = list_access_requests(db, tenant_id=tenant_id)
        assert len(pending) == 1
        assert len(all_rows) == 1
    finally:
        _cleanup(factory, tenant_id)
