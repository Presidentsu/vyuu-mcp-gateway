"""Business logic for A3-γ access requests.

End-user-side flow: submit → list-mine → withdraw.
Admin-side flow:    list-pending → approve / decline.

All entry points are tenant-scoped — callers MUST pre-bind the session
to the tenant via `bind_tenant_context` (RLS) and pass `tenant_id`
explicitly here for defense-in-depth.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vyuu_gateway.audit.admin_audit import (
    AdminAuditActor,
    AdminAuditTarget,
    record_admin_action,
)
from vyuu_gateway.db.models import (
    AccessRequest,
    AccessRequestStatus,
    GrantPrincipalKind,
    GrantVia,
    Operator,
    User,
    UserGroupMembership,
    VirtualServer,
    VirtualServerGrant,
    VirtualServerVisibility,
)

# --- Errors ---------------------------------------------------------------


class AccessRequestNotFoundError(Exception):
    """No access_request matches (tenant_id, request_id) — or, on the
    end-user path, the requester doesn't own the request."""


class VserverNotFoundForRequestError(Exception):
    """The vserver targeted by the request doesn't exist in the tenant."""


class DuplicatePendingRequestError(Exception):
    """A pending request already exists for this (user, vserver). The
    user must withdraw or wait for a decision before re-requesting."""


class UserAlreadyHasAccessError(Exception):
    """The user already has an active grant (direct OR via group) for
    this vserver — no need to request access."""


class VserverIsPublicError(Exception):
    """Public vservers don't need grants; requesting access is meaningless."""


class InvalidApprovalDurationError(Exception):
    """JIT-1. The approver's duration is not issuable — zero/negative,
    longer than the user asked for, or longer than the vserver's ceiling.

    Deliberately defined here rather than imported from `jit_service`:
    that module imports *from* this one, so the dependency only runs one
    way. It is also the more accurate name on this path — the failure is
    about the approval, not about JIT policy in the abstract.
    """

    def __init__(self, requested_seconds: int, max_seconds: int) -> None:
        self.requested_seconds = requested_seconds
        self.max_seconds = max_seconds
        super().__init__(
            f"cannot approve {requested_seconds}s; maximum issuable is "
            f"{max_seconds}s"
        )


class WrongRequestStateError(Exception):
    """Operation requires `status=pending` but request is in another
    state (already approved / declined / withdrawn)."""


# --- End-user side --------------------------------------------------------


def submit_access_request(
    db: Session,
    *,
    tenant_id: UUID,
    user_id: UUID,
    vserver_id: UUID,
    note: str | None = None,
) -> AccessRequest:
    """End user requests access to a private vserver.

    Pre-conditions:
    - vserver must exist in the tenant
    - vserver must be `private` (public is a no-op for the user)
    - the user must NOT already have access (direct or via group)
    - the user must NOT already have a pending request for this vserver
    """

    vserver = cast(
        VirtualServer | None,
        db.scalar(
            select(VirtualServer).where(
                VirtualServer.tenant_id == tenant_id,
                VirtualServer.id == vserver_id,
            )
        ),
    )
    if vserver is None:
        raise VserverNotFoundForRequestError
    if vserver.visibility == VirtualServerVisibility.PUBLIC:
        raise VserverIsPublicError

    # Reject if they already have access — pointless request, and a
    # signal the SPA should re-fetch the catalog.
    if _user_has_active_grant(db, tenant_id=tenant_id, vserver_id=vserver_id, user_id=user_id):
        raise UserAlreadyHasAccessError

    request = AccessRequest(
        id=uuid4(),
        tenant_id=tenant_id,
        user_id=user_id,
        vserver_id=vserver_id,
        status=AccessRequestStatus.PENDING,
        note=note,
    )
    try:
        db.add(request)
        db.commit()
        db.refresh(request)
    except IntegrityError as exc:
        # Most likely the partial-unique index on
        # (user_id, vserver_id) WHERE status='pending'.
        db.rollback()
        raise DuplicatePendingRequestError from exc
    return request


def list_my_access_requests(
    db: Session,
    *,
    tenant_id: UUID,
    user_id: UUID,
    status_filter: AccessRequestStatus | None = None,
) -> list[AccessRequest]:
    """All requests submitted by `user_id`. Optional status filter."""

    stmt = select(AccessRequest).where(
        AccessRequest.tenant_id == tenant_id,
        AccessRequest.user_id == user_id,
    )
    if status_filter is not None:
        stmt = stmt.where(AccessRequest.status == status_filter)
    return list(db.scalars(stmt.order_by(AccessRequest.created_at.desc())).all())


def withdraw_access_request(
    db: Session,
    *,
    tenant_id: UUID,
    user_id: UUID,
    request_id: UUID,
) -> AccessRequest:
    """User cancels their own pending request. Idempotency: if the
    request was already decided (approved / declined) we raise
    `WrongRequestStateError` — the user shouldn't see "withdraw
    successful" on a request that's actually approved."""

    request = cast(
        AccessRequest | None,
        db.scalar(
            select(AccessRequest).where(
                AccessRequest.tenant_id == tenant_id,
                AccessRequest.user_id == user_id,
                AccessRequest.id == request_id,
            )
        ),
    )
    if request is None:
        raise AccessRequestNotFoundError
    if request.status != AccessRequestStatus.PENDING:
        raise WrongRequestStateError(f"request is {request.status}, not pending")
    request.status = AccessRequestStatus.WITHDRAWN
    db.commit()
    db.refresh(request)
    return request


# --- Admin side -----------------------------------------------------------


def list_access_requests(
    db: Session,
    *,
    tenant_id: UUID,
    status_filter: AccessRequestStatus | None = None,
) -> list[AccessRequest]:
    """Admin queue. Defaults to all statuses; pass
    `status_filter=AccessRequestStatus.PENDING` for the working queue."""

    stmt = select(AccessRequest).where(AccessRequest.tenant_id == tenant_id)
    if status_filter is not None:
        stmt = stmt.where(AccessRequest.status == status_filter)
    return list(db.scalars(stmt.order_by(AccessRequest.created_at.desc())).all())


@dataclass(frozen=True)
class AccessRequestListItem:
    """One row in the operator-console access-request queue — the
    `AccessRequest` plus the joined context the table renders so admins
    can decide approve/decline without an extra UUID lookup."""

    request: AccessRequest
    user_email: str | None
    user_display_name: str | None
    vserver_name: str | None
    vserver_visibility: str | None
    decided_by_email: str | None


def list_access_requests_with_context(
    db: Session,
    *,
    tenant_id: UUID,
    status_filter: AccessRequestStatus | None = None,
) -> list[AccessRequestListItem]:
    """One-trip variant for the admin queue.

    LEFT-joins the requester (`users`), the target vserver
    (`virtual_servers`), and the deciding operator (`operators`) so the
    table renders names/emails/vserver visibility without per-row
    lookups. LEFT joins because either related row could have been
    deleted out from under the request — better to surface an
    `(unknown)` placeholder than to drop the row.
    """

    stmt = (
        select(
            AccessRequest,
            User.email.label("user_email"),
            User.display_name.label("user_display_name"),
            VirtualServer.name.label("vserver_name"),
            VirtualServer.visibility.label("vserver_visibility"),
            Operator.email.label("decided_by_email"),
        )
        .where(AccessRequest.tenant_id == tenant_id)
        .outerjoin(User, User.id == AccessRequest.user_id)
        .outerjoin(VirtualServer, VirtualServer.id == AccessRequest.vserver_id)
        .outerjoin(Operator, Operator.id == AccessRequest.decided_by)
        .order_by(AccessRequest.created_at.desc())
    )
    if status_filter is not None:
        stmt = stmt.where(AccessRequest.status == status_filter)

    rows = db.execute(stmt).all()
    return [
        AccessRequestListItem(
            request=request,
            user_email=user_email,
            user_display_name=user_display_name,
            vserver_name=vserver_name,
            vserver_visibility=(
                vserver_visibility.value
                if hasattr(vserver_visibility, "value")
                else (str(vserver_visibility) if vserver_visibility is not None else None)
            ),
            decided_by_email=decided_by_email,
        )
        for (
            request,
            user_email,
            user_display_name,
            vserver_name,
            vserver_visibility,
            decided_by_email,
        ) in rows
    ]


def approve_access_request(
    db: Session,
    *,
    tenant_id: UUID,
    request_id: UUID,
    operator_id: UUID,
    duration_seconds: int | None = None,
    actor: AdminAuditActor | None = None,
) -> AccessRequest:
    """Admin approves a pending request. Atomically:

    1. Re-checks the request is `pending` (race-safe against a parallel
       withdraw / approve).
    2. If the user already gained access between submit and approve
       (e.g., admin granted manually), short-circuits to approved
       without creating a duplicate grant — but does NOT set
       `created_grant_id` since this approval didn't create the grant.
    3. Otherwise creates a `VirtualServerGrant(principal_kind=user)`
       and writes the new id to `created_grant_id`.

    **JIT-1.** When the request carries a `requested_duration_seconds`,
    the created grant is time-boxed rather than standing. `duration_seconds`
    lets the approver grant *less* than was asked for — the common review
    outcome ("you can have an hour, not a day") — but never more than the
    vserver's ceiling. Approving a JIT request as standing access is not
    offered: it would silently convert a temporary elevation into
    permanent authority, which is the exact failure JIT exists to prevent.
    """

    request = _load_pending(db, tenant_id=tenant_id, request_id=request_id)
    grant_id: UUID | None = None

    # JIT-2 · a request naming a tool creates a per-tool elevation, not a
    # vserver grant. Local import: `jit_service` imports from this module,
    # so the dependency only runs one way at import time (same pattern as
    # `idp/sweeper.py`'s EmaConsumedJti import).
    if request.exposed_tool_name is not None:
        from vyuu_gateway.registry.jit_service import (
            issue_tool_elevation_for_request,
        )

        duration = duration_seconds or request.requested_duration_seconds
        if duration is None or duration <= 0:
            raise InvalidApprovalDurationError(duration or 0, 0)
        if (
            request.requested_duration_seconds is not None
            and duration > request.requested_duration_seconds
        ):
            raise InvalidApprovalDurationError(
                duration, request.requested_duration_seconds
            )
        tool_grant = issue_tool_elevation_for_request(
            db,
            tenant_id=tenant_id,
            request=request,
            operator_id=operator_id,
            duration_seconds=duration,
            actor=actor or AdminAuditActor.system("access_request_approve"),
        )
        request.status = AccessRequestStatus.APPROVED
        request.decided_by = operator_id
        request.decided_at = datetime.now(UTC)
        # NOT `created_grant_id`: that column FKs `virtual_server_grants`,
        # and a tool elevation lives in a different table. Pointing it at
        # a tool-grant id would be a dangling reference that looks valid.
        # The `grant.tool_elevation` audit row carries the linkage.
        if actor is not None:
            record_admin_action(
                db,
                tenant_id=tenant_id,
                actor=actor,
                action="access_request.approve",
                target=AdminAuditTarget(
                    kind="access_request", id=request.id, display=None
                ),
                detail={
                    "user_id": str(request.user_id),
                    "vserver_id": str(request.vserver_id),
                    "exposed_tool_name": request.exposed_tool_name,
                    "tool_elevation_grant_id": str(tool_grant.id),
                    "requested_duration_seconds": request.requested_duration_seconds,
                    "approved_duration_seconds": duration,
                    "justification": request.note,
                },
            )
        db.commit()
        db.refresh(request)
        return request

    if not _user_has_active_grant(
        db,
        tenant_id=tenant_id,
        vserver_id=request.vserver_id,
        user_id=request.user_id,
    ):
        expires_at = _approved_expiry(
            db,
            tenant_id=tenant_id,
            request=request,
            duration_seconds=duration_seconds,
        )
        # Skip the existence check that `users_service.issue_grant` does —
        # the FK constraints + the load above already prove the user and
        # vserver exist. (Inlined to keep the approve flow atomic with the
        # status flip.)
        grant = VirtualServerGrant(
            id=uuid4(),
            tenant_id=tenant_id,
            vserver_id=request.vserver_id,
            principal_kind=GrantPrincipalKind.USER,
            principal_id=request.user_id,
            granted_by=operator_id,
            granted_via=(
                GrantVia.JIT_APPROVED if expires_at is not None
                else GrantVia.OPERATOR
            ),
            justification=request.note,
            expires_at=expires_at,
        )
        db.add(grant)
        db.flush()
        grant_id = grant.id

    request.status = AccessRequestStatus.APPROVED
    request.decided_by = operator_id
    request.decided_at = datetime.now(UTC)
    request.created_grant_id = grant_id
    if actor is not None:
        record_admin_action(
            db,
            tenant_id=tenant_id,
            actor=actor,
            action="access_request.approve",
            target=AdminAuditTarget(
                kind="access_request", id=request.id, display=None
            ),
            detail={
                "user_id": str(request.user_id),
                "vserver_id": str(request.vserver_id),
                "grant_created": grant_id is not None,
                "grant_id": str(grant_id) if grant_id else None,
                # JIT-1. `requested` vs `approved` makes a trimmed
                # approval ("asked for a day, got an hour") legible in
                # the audit log without diffing two rows.
                "requested_duration_seconds": request.requested_duration_seconds,
                "approved_duration_seconds": duration_seconds,
                "justification": request.note,
            },
        )
    db.commit()
    db.refresh(request)
    return request


def _approved_expiry(
    db: Session,
    *,
    tenant_id: UUID,
    request: AccessRequest,
    duration_seconds: int | None,
) -> datetime | None:
    """Resolve the expiry for a grant created by approving `request`.

    Returns None for a plain (non-JIT) request, which keeps the pre-JIT
    behaviour of issuing standing access exactly as it was.

    An approver may grant *less* than was asked for but never more, and
    never more than the vserver's own ceiling — the ceiling is the
    tenant's policy, not the reviewer's discretion. Both over-asks are
    rejected rather than clamped, so a reviewer who fat-fingers a
    duration finds out instead of quietly issuing the wrong window.
    """

    requested = request.requested_duration_seconds
    if requested is None and duration_seconds is None:
        return None

    effective = duration_seconds if duration_seconds is not None else requested
    assert effective is not None  # one of the two is set by the guard above
    if effective <= 0:
        raise InvalidApprovalDurationError(effective, requested or 0)
    if requested is not None and effective > requested:
        # Granting more than was asked for is never the reviewer's
        # intent; it is a typo, and a silent one if we allowed it.
        raise InvalidApprovalDurationError(effective, requested)

    vserver = cast(
        VirtualServer | None,
        db.scalar(
            select(VirtualServer).where(
                VirtualServer.tenant_id == tenant_id,
                VirtualServer.id == request.vserver_id,
            )
        ),
    )
    if vserver is not None and effective > vserver.jit_max_duration_seconds:
        raise InvalidApprovalDurationError(
            effective, vserver.jit_max_duration_seconds
        )
    return datetime.now(UTC) + timedelta(seconds=effective)


def decline_access_request(
    db: Session,
    *,
    tenant_id: UUID,
    request_id: UUID,
    operator_id: UUID,
    decision_note: str = "",
    actor: AdminAuditActor | None = None,
) -> AccessRequest:
    """Admin declines a pending request. `decision_note` is recorded
    verbatim — empty string is allowed (admin who doesn't want to
    explain). The user can re-request later if circumstances change."""

    request = _load_pending(db, tenant_id=tenant_id, request_id=request_id)
    request.status = AccessRequestStatus.DECLINED
    request.decided_by = operator_id
    request.decided_at = datetime.now(UTC)
    request.decision_note = decision_note or None
    if actor is not None:
        record_admin_action(
            db,
            tenant_id=tenant_id,
            actor=actor,
            action="access_request.decline",
            target=AdminAuditTarget(
                kind="access_request", id=request.id, display=None
            ),
            detail={
                "user_id": str(request.user_id),
                "vserver_id": str(request.vserver_id),
                "decision_note": decision_note or None,
            },
        )
    db.commit()
    db.refresh(request)
    return request


# --- Helpers --------------------------------------------------------------


def _load_pending(
    db: Session, *, tenant_id: UUID, request_id: UUID
) -> AccessRequest:
    request = cast(
        AccessRequest | None,
        db.scalar(
            select(AccessRequest).where(
                AccessRequest.tenant_id == tenant_id,
                AccessRequest.id == request_id,
            )
        ),
    )
    if request is None:
        raise AccessRequestNotFoundError
    if request.status != AccessRequestStatus.PENDING:
        raise WrongRequestStateError(f"request is {request.status}, not pending")
    return request


def _user_has_active_grant(
    db: Session, *, tenant_id: UUID, vserver_id: UUID, user_id: UUID
) -> bool:
    """True if `user_id` can already access `vserver_id` via a direct
    grant or via group membership. Mirrors the inbound enforcement in
    `virtual_servers.access.assert_principal_can_access_vserver` — same
    SQL shape, but boolean rather than raise. Inlined intentionally:
    the inbound function takes a `Principal` and is hot-path; here we
    have a `user_id` directly."""

    direct = (
        select(VirtualServerGrant.id)
        .where(
            VirtualServerGrant.tenant_id == tenant_id,
            VirtualServerGrant.vserver_id == vserver_id,
            VirtualServerGrant.principal_kind == GrantPrincipalKind.USER,
            VirtualServerGrant.principal_id == user_id,
            VirtualServerGrant.revoked_at.is_(None),
        )
    )
    via_group = (
        select(VirtualServerGrant.id)
        .join(
            UserGroupMembership,
            UserGroupMembership.group_id == VirtualServerGrant.principal_id,
        )
        .where(
            VirtualServerGrant.tenant_id == tenant_id,
            VirtualServerGrant.vserver_id == vserver_id,
            VirtualServerGrant.principal_kind == GrantPrincipalKind.GROUP,
            VirtualServerGrant.revoked_at.is_(None),
            UserGroupMembership.user_id == user_id,
        )
    )
    candidates = list(db.scalars(direct.union_all(via_group)).all())
    if not candidates:
        return False
    now = datetime.now(UTC)
    grants = list(
        db.scalars(
            select(VirtualServerGrant).where(VirtualServerGrant.id.in_(candidates))
        ).all()
    )
    return any(g.expires_at is None or g.expires_at > now for g in grants)


def get_user_for_session(
    db: Session, *, tenant_id: UUID, user_id: UUID
) -> User | None:
    """Look up the User row for an authenticated portal session. Returns
    None if the user was deleted or the session's user_id doesn't match
    the path-level tenant_id (cross-tenant token replay defense)."""

    return cast(
        User | None,
        db.scalar(
            select(User).where(User.tenant_id == tenant_id, User.id == user_id)
        ),
    )
