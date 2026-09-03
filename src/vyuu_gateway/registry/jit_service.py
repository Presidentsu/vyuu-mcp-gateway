"""JIT-1 · just-in-time (time-boxed) access to private virtual servers.

Standing access is the problem this exists to remove. Before JIT, a user
who needed a private vserver once got a grant that never expired, and the
tenant slowly accumulated permanent authority nobody revisited. A JIT
elevation is temporary *by construction*: the grant carries an
`expires_at` and simply stops being honoured when the clock passes it.

## Why the enforcement path needed no change

`virtual_servers/access.py` already skips grants whose `expires_at` has
passed, and `_authenticate_and_authorize` re-runs that check on **every**
inbound request rather than once at session start. So an elevation that
lapses mid-session cuts off at the caller's next tool call, with no
sweeper, no session invalidation, and no revocation broadcast. This
module only decides *how long* and *on whose say-so*.

## Two paths, one queue

Auto-approve vservers mint the grant inline. Everything else lands in the
same `access_requests` queue operators already work — carrying the
requested duration, so the reviewer sees *how much* access is being asked
for, not merely that access is being asked for. Splitting JIT into a
parallel queue would fragment the one surface an operator actually
watches.

## What is deliberately refused rather than adjusted

A request longer than the vserver's ceiling is **rejected, not clamped**.
A user who asks for 8 hours, is silently given 4, and plans a migration
around access they do not have is worse off than one who is told no. The
error carries the ceiling so the caller can retry correctly.

Per-*tool* JIT (elevating into a single tool rather than a whole vserver)
is a deliberate follow-up, not an oversight — see `BACKLOG.md` JIT-2.
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
    User,
    VirtualServer,
    VirtualServerGrant,
    VirtualServerToolGrant,
    VirtualServerVisibility,
)
from vyuu_gateway.registry.access_requests_service import (
    DuplicatePendingRequestError,
    UserAlreadyHasAccessError,
    VserverIsPublicError,
    VserverNotFoundForRequestError,
    _user_has_active_grant,
)

# Hard ceiling shared with the DB check constraint. Past a week it is
# standing access wearing a JIT label.
MAX_JIT_DURATION_SECONDS = 7 * 24 * 3600

# Actor name on auto-approved elevations. Reads in the audit UI as
# "jit_auto_approve granted alice access to finance-readonly" — which is
# exactly what happened, and visibly not a person.
_AUTO_APPROVE_ACTOR = "jit_auto_approve"

# What the portal offers when a vserver has no opinion. Kept in the
# service (not the UI) so the API and the UI cannot drift apart.
DURATION_PRESETS_SECONDS: tuple[int, ...] = (
    15 * 60,
    60 * 60,
    4 * 3600,
    8 * 3600,
    24 * 3600,
)


# --- Errors ---------------------------------------------------------------


class JitNotEnabledError(Exception):
    """The vserver does not offer just-in-time access."""


class JitDurationTooLongError(Exception):
    """Requested duration exceeds the vserver's ceiling. Carries the
    ceiling so the caller can retry with a legal value rather than
    guess."""

    def __init__(self, requested_seconds: int, max_seconds: int) -> None:
        self.requested_seconds = requested_seconds
        self.max_seconds = max_seconds
        super().__init__(
            f"requested {requested_seconds}s exceeds this vserver's "
            f"maximum of {max_seconds}s"
        )


class JitJustificationRequiredError(Exception):
    """The vserver requires a stated reason and none was given."""


class ToolNotJitEligibleError(Exception):
    """The tool is not listed in the vserver's `jit_tools` policy."""


class VserverAccessRequiredError(Exception):
    """JIT-2 · the user must already hold access to the vserver before
    elevating into one of its tools.

    The locked decision (see BACKLOG JIT-2): a tool elevation NARROWS,
    it does not grant. Letting it imply vserver access would create a
    second path to the same resource, and two paths to one resource is
    how authorization systems become unauditable — "how did they get
    in?" stops having a single answer.
    """


class JitInvalidDurationError(Exception):
    """Duration was zero, negative, or above the platform hard ceiling."""


# --- Results --------------------------------------------------------------


@dataclass(frozen=True)
class JitElevation:
    """Outcome of a JIT request.

    Exactly one of `grant`/`request` is populated: an auto-approve
    vserver returns the live grant, everything else returns the queued
    request. `granted` is the field callers branch on — the portal shows
    "you're in until 14:32" or "sent for approval" off it.
    """

    granted: bool
    grant: VirtualServerGrant | None
    request: AccessRequest | None
    expires_at: datetime | None
    # JIT-2 · a per-tool elevation issues a `VirtualServerToolGrant`,
    # which is a different type from the bundle-level `grant` above and
    # so cannot ride in that field. It used to be dropped entirely, and
    # the endpoint then had nothing to return: an auto-approved caller
    # received `granted: true` with a null id for a grant the operator
    # console could already list by id.
    tool_grant: VirtualServerToolGrant | None = None


@dataclass(frozen=True)
class ActiveElevation:
    """One live time-boxed grant, for the operator's "who is elevated
    right now?" panel."""

    grant_id: UUID
    vserver_id: UUID
    vserver_name: str
    user_id: UUID
    user_email: str | None
    granted_via: str
    justification: str | None
    granted_at: datetime
    expires_at: datetime
    seconds_remaining: int


# --- Policy ---------------------------------------------------------------


def configure_vserver_jit(
    db: Session,
    *,
    tenant_id: UUID,
    vserver_id: UUID,
    enabled: bool,
    max_duration_seconds: int | None = None,
    auto_approve: bool | None = None,
    require_justification: bool | None = None,
    actor: AdminAuditActor,
) -> VirtualServer:
    """Set a vserver's JIT policy. Audited both ways — turning JIT on is
    a standing decision about self-service authority, and turning it off
    silently strands users mid-workflow.

    Does not commit; the caller owns the transaction (see the
    same-transaction guarantee in `audit/admin_audit.py`).
    """

    vserver = _load_vserver(db, tenant_id=tenant_id, vserver_id=vserver_id)

    if enabled and vserver.visibility == VirtualServerVisibility.PUBLIC:
        # A public vserver needs no grant, so there is nothing to
        # elevate into. Enabling JIT here would render a "Request
        # access" button that grants access the user already has.
        raise VserverIsPublicError

    before = {
        "jit_enabled": vserver.jit_enabled,
        "jit_max_duration_seconds": vserver.jit_max_duration_seconds,
        "jit_auto_approve": vserver.jit_auto_approve,
        "jit_require_justification": vserver.jit_require_justification,
    }

    vserver.jit_enabled = enabled
    if max_duration_seconds is not None:
        if not 0 < max_duration_seconds <= MAX_JIT_DURATION_SECONDS:
            raise JitInvalidDurationError(
                f"max_duration_seconds must be 1..{MAX_JIT_DURATION_SECONDS}"
            )
        vserver.jit_max_duration_seconds = max_duration_seconds
    if auto_approve is not None:
        vserver.jit_auto_approve = auto_approve
    if require_justification is not None:
        vserver.jit_require_justification = require_justification

    after = {
        "jit_enabled": vserver.jit_enabled,
        "jit_max_duration_seconds": vserver.jit_max_duration_seconds,
        "jit_auto_approve": vserver.jit_auto_approve,
        "jit_require_justification": vserver.jit_require_justification,
    }
    record_admin_action(
        db,
        tenant_id=tenant_id,
        actor=actor,
        action="vserver.jit_enable" if enabled else "vserver.jit_disable",
        target=AdminAuditTarget(
            kind="vserver", id=vserver.id, display=vserver.name
        ),
        detail={
            "before": before,
            "after": after,
            # Spelled out because "auto-approve + no justification" is
            # the configuration an auditor will ask about by name.
            "self_service": after["jit_enabled"] and after["jit_auto_approve"],
        },
    )
    return vserver


# --- Request path ---------------------------------------------------------


def request_jit_access(
    db: Session,
    *,
    tenant_id: UUID,
    user_id: UUID,
    vserver_id: UUID,
    duration_seconds: int,
    justification: str | None = None,
) -> JitElevation:
    """End user asks for a time-boxed elevation.

    Auto-approve vservers mint the grant inline and return it. Everything
    else queues an `access_request` carrying the duration, for an
    operator to decide.

    Commits — this is a complete user-facing action either way.
    """

    vserver = _load_vserver(db, tenant_id=tenant_id, vserver_id=vserver_id)
    if vserver.visibility == VirtualServerVisibility.PUBLIC:
        raise VserverIsPublicError
    if not vserver.jit_enabled:
        raise JitNotEnabledError

    duration = _validate_duration(duration_seconds, vserver=vserver)
    justification = _validate_justification(justification, vserver=vserver)

    # Already in? Elevating again would stack a second grant that
    # outlives nothing and confuses the "who is elevated" panel.
    if _user_has_active_grant(
        db, tenant_id=tenant_id, vserver_id=vserver_id, user_id=user_id
    ):
        raise UserAlreadyHasAccessError

    if vserver.jit_auto_approve:
        return issue_jit_grant(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            vserver=vserver,
            duration_seconds=duration,
            justification=justification,
            granted_via=GrantVia.JIT_AUTO,
            operator_id=None,
            # No human decided this. `system` is the honest actor kind —
            # attributing it to an operator would put someone's name on a
            # decision they did not make.
            actor=AdminAuditActor.system(_AUTO_APPROVE_ACTOR),
        )

    request = AccessRequest(
        id=uuid4(),
        tenant_id=tenant_id,
        user_id=user_id,
        vserver_id=vserver_id,
        status=AccessRequestStatus.PENDING,
        note=justification,
        requested_duration_seconds=duration,
    )
    try:
        db.add(request)
        db.commit()
        db.refresh(request)
    except IntegrityError as exc:
        # The partial-unique index on (user_id, vserver_id) WHERE pending.
        db.rollback()
        raise DuplicatePendingRequestError from exc
    return JitElevation(
        granted=False, grant=None, request=request, expires_at=None
    )


def issue_jit_grant(
    db: Session,
    *,
    tenant_id: UUID,
    user_id: UUID,
    vserver: VirtualServer,
    duration_seconds: int,
    justification: str | None,
    granted_via: GrantVia,
    operator_id: UUID | None,
    actor: AdminAuditActor,
) -> JitElevation:
    """Mint the time-boxed grant + its audit row in one transaction.

    Shared by the auto-approve path here and the operator-approval path
    in `access_requests_service`, so both produce identically-shaped
    grants and identically-shaped audit rows — an auditor comparing the
    two should not have to know which code path ran.

    The audit row is the compliance artifact: an elevation that is not
    recorded is indistinguishable, after expiry, from access that never
    happened. It shares the grant's transaction, so there is no window
    in which the grant exists unaudited.
    """

    expires_at = datetime.now(UTC) + timedelta(seconds=duration_seconds)
    grant = VirtualServerGrant(
        id=uuid4(),
        tenant_id=tenant_id,
        vserver_id=vserver.id,
        principal_kind=GrantPrincipalKind.USER,
        principal_id=user_id,
        granted_by=operator_id,
        granted_via=granted_via,
        justification=justification,
        expires_at=expires_at,
    )
    db.add(grant)
    db.flush()

    user = db.get(User, user_id)
    record_admin_action(
        db,
        tenant_id=tenant_id,
        actor=actor,
        action="grant.jit_issue",
        target=AdminAuditTarget(
            kind="vserver", id=vserver.id, display=vserver.name
        ),
        detail={
            "grant_id": str(grant.id),
            "user_id": str(user_id),
            "user_email": user.email if user is not None else None,
            "granted_via": granted_via.value,
            "duration_seconds": duration_seconds,
            "expires_at": expires_at.isoformat(),
            "justification": justification,
        },
    )
    db.commit()
    db.refresh(grant)
    return JitElevation(
        granted=True, grant=grant, request=None, expires_at=expires_at
    )


# --- Operator view --------------------------------------------------------


def list_active_elevations(
    db: Session, *, tenant_id: UUID, now: datetime | None = None
) -> list[ActiveElevation]:
    """Every live time-boxed user grant in the tenant, soonest-expiring
    first.

    Includes operator-issued time-boxed grants, not only JIT ones —
    `granted_via` distinguishes them. The operator's question is "who is
    elevated right now", and a hand-issued 2-hour grant is exactly as
    much elevation as an auto-approved one.
    """

    moment = now or datetime.now(UTC)
    rows = db.execute(
        select(VirtualServerGrant, VirtualServer.name, User.email)
        .join(VirtualServer, VirtualServer.id == VirtualServerGrant.vserver_id)
        .outerjoin(User, User.id == VirtualServerGrant.principal_id)
        .where(
            VirtualServerGrant.tenant_id == tenant_id,
            VirtualServerGrant.principal_kind == GrantPrincipalKind.USER,
            VirtualServerGrant.revoked_at.is_(None),
            VirtualServerGrant.expires_at.is_not(None),
            VirtualServerGrant.expires_at > moment,
        )
        .order_by(VirtualServerGrant.expires_at.asc())
    ).all()

    out: list[ActiveElevation] = []
    for grant, vserver_name, user_email in rows:
        assert grant.expires_at is not None  # guaranteed by the WHERE
        expires_at = grant.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        out.append(
            ActiveElevation(
                grant_id=grant.id,
                vserver_id=grant.vserver_id,
                vserver_name=vserver_name,
                user_id=grant.principal_id,
                user_email=user_email,
                granted_via=str(grant.granted_via),
                justification=grant.justification,
                granted_at=grant.granted_at,
                expires_at=expires_at,
                seconds_remaining=int((expires_at - moment).total_seconds()),
            )
        )
    return out


# --- Helpers --------------------------------------------------------------


def _load_vserver(
    db: Session, *, tenant_id: UUID, vserver_id: UUID
) -> VirtualServer:
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
    return vserver


def _validate_duration(
    duration_seconds: int, *, vserver: VirtualServer
) -> int:
    if duration_seconds <= 0 or duration_seconds > MAX_JIT_DURATION_SECONDS:
        raise JitInvalidDurationError(
            f"duration must be 1..{MAX_JIT_DURATION_SECONDS} seconds"
        )
    if duration_seconds > vserver.jit_max_duration_seconds:
        # Rejected, not clamped — see the module docstring.
        raise JitDurationTooLongError(
            duration_seconds, vserver.jit_max_duration_seconds
        )
    return duration_seconds


def _validate_justification(
    justification: str | None, *, vserver: VirtualServer
) -> str | None:
    cleaned = (justification or "").strip() or None
    if vserver.jit_require_justification and cleaned is None:
        raise JitJustificationRequiredError
    return cleaned


# --- JIT-2 · per-tool elevation --------------------------------------------


@dataclass(frozen=True)
class ActiveToolElevation:
    """One live per-tool elevation, for the operator's live list."""

    grant_id: UUID
    vserver_id: UUID
    vserver_name: str
    exposed_tool_name: str
    user_id: UUID
    user_email: str | None
    granted_via: str
    justification: str | None
    granted_at: datetime
    expires_at: datetime
    seconds_remaining: int


def configure_vserver_jit_tools(
    db: Session,
    *,
    tenant_id: UUID,
    vserver_id: UUID,
    jit_tools: dict[str, int],
    actor: AdminAuditActor,
) -> VirtualServer:
    """Set which tools on this vserver are elevation-gated, and each
    tool's ceiling. Replaces the map wholesale — matches how an operator
    edits a list, and how `rename_map` already behaves.

    Does not commit; the caller owns the transaction.
    """

    vserver = _load_vserver(db, tenant_id=tenant_id, vserver_id=vserver_id)
    cleaned: dict[str, int] = {}
    for tool_name, seconds in jit_tools.items():
        name = (tool_name or "").strip()
        if not name:
            raise ToolNotJitEligibleError("tool name must be non-empty")
        if not 0 < int(seconds) <= MAX_JIT_DURATION_SECONDS:
            raise JitInvalidDurationError(
                f"ceiling for {name!r} must be 1..{MAX_JIT_DURATION_SECONDS} seconds"
            )
        cleaned[name] = int(seconds)

    before = dict(vserver.jit_tools or {})
    vserver.jit_tools = cleaned
    record_admin_action(
        db,
        tenant_id=tenant_id,
        actor=actor,
        action="vserver.jit_tools_set",
        target=AdminAuditTarget(kind="vserver", id=vserver.id, display=vserver.name),
        detail={
            "before": before,
            "after": cleaned,
            # Spelled out because "which tools became gated" and "which
            # stopped being gated" are the two questions an auditor asks,
            # and diffing two maps in a log viewer is miserable.
            "newly_gated": sorted(set(cleaned) - set(before)),
            "no_longer_gated": sorted(set(before) - set(cleaned)),
        },
    )
    return vserver


def request_tool_elevation(
    db: Session,
    *,
    tenant_id: UUID,
    user_id: UUID,
    vserver_id: UUID,
    exposed_tool_name: str,
    duration_seconds: int,
    justification: str | None = None,
) -> JitElevation:
    """End user asks to elevate into ONE tool for a bounded window.

    **Requires the user to already hold access to the vserver.** See
    `VserverAccessRequiredError` for why. Commits.
    """

    vserver = _load_vserver(db, tenant_id=tenant_id, vserver_id=vserver_id)
    ceiling = (vserver.jit_tools or {}).get(exposed_tool_name)
    if ceiling is None:
        raise ToolNotJitEligibleError(
            f"{exposed_tool_name!r} is not elevation-gated on this vserver"
        )

    # Narrows, never grants.
    if not _user_has_active_grant(
        db, tenant_id=tenant_id, vserver_id=vserver_id, user_id=user_id
    ):
        raise VserverAccessRequiredError

    duration = _validate_tool_duration(duration_seconds, ceiling=int(ceiling))
    justification = _validate_justification(justification, vserver=vserver)

    if vserver.jit_auto_approve:
        return _issue_tool_elevation(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            vserver=vserver,
            exposed_tool_name=exposed_tool_name,
            duration_seconds=duration,
            justification=justification,
            granted_via=GrantVia.JIT_AUTO,
            operator_id=None,
            actor=AdminAuditActor.system(_AUTO_APPROVE_ACTOR),
        )

    request = AccessRequest(
        id=uuid4(),
        tenant_id=tenant_id,
        user_id=user_id,
        vserver_id=vserver_id,
        status=AccessRequestStatus.PENDING,
        note=justification,
        requested_duration_seconds=duration,
        exposed_tool_name=exposed_tool_name,
    )
    try:
        db.add(request)
        db.commit()
        db.refresh(request)
    except IntegrityError as exc:
        db.rollback()
        raise DuplicatePendingRequestError from exc
    return JitElevation(granted=False, grant=None, request=request, expires_at=None)


def issue_tool_elevation_for_request(
    db: Session,
    *,
    tenant_id: UUID,
    request: AccessRequest,
    operator_id: UUID,
    duration_seconds: int,
    actor: AdminAuditActor,
) -> VirtualServerToolGrant:
    """Approval path for a queued tool elevation. Does NOT commit — it
    shares the approving transaction so the grant and the status flip
    land together."""

    assert request.exposed_tool_name is not None
    vserver = _load_vserver(db, tenant_id=tenant_id, vserver_id=request.vserver_id)
    return _build_tool_grant(
        db,
        tenant_id=tenant_id,
        user_id=request.user_id,
        vserver=vserver,
        exposed_tool_name=request.exposed_tool_name,
        duration_seconds=duration_seconds,
        justification=request.note,
        granted_via=GrantVia.JIT_APPROVED,
        operator_id=operator_id,
        actor=actor,
    )


def _issue_tool_elevation(
    db: Session,
    *,
    tenant_id: UUID,
    user_id: UUID,
    vserver: VirtualServer,
    exposed_tool_name: str,
    duration_seconds: int,
    justification: str | None,
    granted_via: GrantVia,
    operator_id: UUID | None,
    actor: AdminAuditActor,
) -> JitElevation:
    grant = _build_tool_grant(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        vserver=vserver,
        exposed_tool_name=exposed_tool_name,
        duration_seconds=duration_seconds,
        justification=justification,
        granted_via=granted_via,
        operator_id=operator_id,
        actor=actor,
    )
    db.commit()
    db.refresh(grant)
    return JitElevation(
        granted=True, grant=None, request=None, expires_at=grant.expires_at,
        tool_grant=grant
    )


def _build_tool_grant(
    db: Session,
    *,
    tenant_id: UUID,
    user_id: UUID,
    vserver: VirtualServer,
    exposed_tool_name: str,
    duration_seconds: int,
    justification: str | None,
    granted_via: GrantVia,
    operator_id: UUID | None,
    actor: AdminAuditActor,
) -> VirtualServerToolGrant:
    """Row + audit row in the caller's transaction. Shared by the
    auto-approve and operator-approval paths so both produce
    identically-shaped grants and audit rows."""

    expires_at = datetime.now(UTC) + timedelta(seconds=duration_seconds)
    grant = VirtualServerToolGrant(
        id=uuid4(),
        tenant_id=tenant_id,
        vserver_id=vserver.id,
        exposed_tool_name=exposed_tool_name,
        principal_kind=GrantPrincipalKind.USER,
        principal_id=user_id,
        granted_by=operator_id,
        granted_via=granted_via,
        justification=justification,
        expires_at=expires_at,
    )
    db.add(grant)
    db.flush()

    user = db.get(User, user_id)
    record_admin_action(
        db,
        tenant_id=tenant_id,
        actor=actor,
        action="grant.tool_elevation",
        # Target is the TOOL, not the vserver — the operator console
        # groups by target, and "who got db.migrate" is the question.
        target=AdminAuditTarget(
            kind="tool",
            id=vserver.id,
            display=f"{vserver.name}/{exposed_tool_name}",
        ),
        detail={
            "grant_id": str(grant.id),
            "vserver_id": str(vserver.id),
            "exposed_tool_name": exposed_tool_name,
            "user_id": str(user_id),
            "user_email": user.email if user is not None else None,
            "granted_via": granted_via.value,
            "duration_seconds": duration_seconds,
            "expires_at": expires_at.isoformat(),
            "justification": justification,
        },
    )
    return grant


def list_active_tool_elevations(
    db: Session, *, tenant_id: UUID, now: datetime | None = None
) -> list[ActiveToolElevation]:
    """Every live per-tool elevation in the tenant, soonest-expiring first."""

    moment = now or datetime.now(UTC)
    rows = db.execute(
        select(VirtualServerToolGrant, VirtualServer.name, User.email)
        .join(VirtualServer, VirtualServer.id == VirtualServerToolGrant.vserver_id)
        .outerjoin(User, User.id == VirtualServerToolGrant.principal_id)
        .where(
            VirtualServerToolGrant.tenant_id == tenant_id,
            VirtualServerToolGrant.principal_kind == GrantPrincipalKind.USER,
            VirtualServerToolGrant.revoked_at.is_(None),
            VirtualServerToolGrant.expires_at > moment,
        )
        .order_by(VirtualServerToolGrant.expires_at.asc())
    ).all()

    out: list[ActiveToolElevation] = []
    for grant, vserver_name, user_email in rows:
        expires_at = grant.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        out.append(
            ActiveToolElevation(
                grant_id=grant.id,
                vserver_id=grant.vserver_id,
                vserver_name=vserver_name,
                exposed_tool_name=grant.exposed_tool_name,
                user_id=grant.principal_id,
                user_email=user_email,
                granted_via=str(grant.granted_via),
                justification=grant.justification,
                granted_at=grant.granted_at,
                expires_at=expires_at,
                seconds_remaining=int((expires_at - moment).total_seconds()),
            )
        )
    return out


def _validate_tool_duration(duration_seconds: int, *, ceiling: int) -> int:
    if duration_seconds <= 0 or duration_seconds > MAX_JIT_DURATION_SECONDS:
        raise JitInvalidDurationError(
            f"duration must be 1..{MAX_JIT_DURATION_SECONDS} seconds"
        )
    if duration_seconds > ceiling:
        # Rejected, not clamped — same rule as JIT-1.
        raise JitDurationTooLongError(duration_seconds, ceiling)
    return duration_seconds
