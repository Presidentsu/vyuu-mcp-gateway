"""Business logic for users / groups / memberships / API keys / grants.

Sits between the API routes and the ORM. Same shape as
`registry/service.py` (servers + vservers) — keeps tenant scoping
explicit on every entry point and surfaces typed errors that the
route layer can map to HTTP status codes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vyuu_gateway.audit.admin_audit import (
    AdminAuditActor,
    AdminAuditTarget,
    record_admin_action,
)
from vyuu_gateway.db.models import (
    GrantPrincipalKind,
    Group,
    User,
    UserApiKey,
    UserAuthMethod,
    UserGroupMembership,
    VirtualServer,
    VirtualServerGrant,
    VirtualServerVisibility,
)
from vyuu_gateway.users.api_keys import IssuedApiKey, issue_new_key
from vyuu_gateway.users.passwords import (
    hash_password,
    validate_password_strength,
)

# --- Errors ---------------------------------------------------------------


class UserNotFoundError(Exception):
    """User row does not exist in the requested tenant."""


class GroupNotFoundError(Exception):
    """Group row does not exist in the requested tenant."""


class DuplicateUserEmailError(Exception):
    """A user with this email already exists in the tenant."""


class DuplicateGroupNameError(Exception):
    """A group with this name already exists in the tenant."""


class DuplicateApiKeyLabelError(Exception):
    """The user already has an API key with this label."""


class GrantTargetNotFoundError(Exception):
    """The grant's target principal (user or group) doesn't exist."""


class WrongAuthMethodError(Exception):
    """Operation requires `auth_method=local` but user is OIDC-authed."""


# --- Users ----------------------------------------------------------------


def create_local_user(
    db: Session,
    *,
    tenant_id: UUID,
    email: str,
    password: str,
    display_name: str | None = None,
    must_change_password: bool = True,
    actor: AdminAuditActor | None = None,
) -> User:
    """Create a local-password user. Password is validated + hashed here.

    When `actor` is supplied, an `admin_audit_log` row is added in the
    same transaction as the user insert — both succeed atomically or
    both roll back. See `vyuu_gateway.audit.admin_audit`.
    """

    validate_password_strength(password)
    user = User(
        id=uuid4(),
        tenant_id=tenant_id,
        email=email.strip().lower(),
        display_name=display_name,
        auth_method=UserAuthMethod.LOCAL,
        password_hash=hash_password(password),
        must_change_password=must_change_password,
    )
    try:
        db.add(user)
        if actor is not None:
            record_admin_action(
                db,
                tenant_id=tenant_id,
                actor=actor,
                action="user.create",
                target=AdminAuditTarget(
                    kind="user", id=user.id, display=user.email
                ),
                detail={
                    "auth_method": UserAuthMethod.LOCAL.value,
                    "must_change_password": must_change_password,
                    "display_name": display_name,
                },
            )
        db.commit()
        db.refresh(user)
    except IntegrityError as exc:
        db.rollback()
        raise DuplicateUserEmailError from exc
    return user


def list_users(db: Session, *, tenant_id: UUID) -> list[User]:
    return list(
        db.scalars(
            select(User)
            .where(User.tenant_id == tenant_id)
            .order_by(User.created_at.desc(), User.email.asc())
        ).all()
    )


@dataclass(frozen=True)
class UserListItem:
    """One row in the operator-console Users table — a `User` plus the
    aggregates the table renders alongside it. The route layer maps
    this to `UserListItemResponse`."""

    user: User
    api_key_count: int
    group_count: int
    last_api_key_used_at: datetime | None


def list_users_with_aggregates(
    db: Session, *, tenant_id: UUID
) -> list[UserListItem]:
    """One-trip list for the admin Users table.

    Computes per-user counts (active API keys, group memberships) and
    the MAX(last_used_at) across the user's keys in a single SQL —
    two LEFT-JOINed aggregate subqueries. Bounded by the tenant's
    user count; no N+1.

    "Active" key count excludes revoked rows: operators reading the
    table want to know who can currently authenticate, not who used
    to be able to.
    """

    keys_subq = (
        select(
            UserApiKey.user_id.label("user_id"),
            func.count().label("cnt"),
            func.max(UserApiKey.last_used_at).label("last_used"),
        )
        .where(UserApiKey.revoked_at.is_(None))
        .group_by(UserApiKey.user_id)
        .subquery()
    )
    groups_subq = (
        select(
            UserGroupMembership.user_id.label("user_id"),
            func.count().label("cnt"),
        )
        .group_by(UserGroupMembership.user_id)
        .subquery()
    )
    rows = db.execute(
        select(
            User,
            func.coalesce(keys_subq.c.cnt, 0).label("api_key_count"),
            keys_subq.c.last_used.label("last_api_key_used_at"),
            func.coalesce(groups_subq.c.cnt, 0).label("group_count"),
        )
        .outerjoin(keys_subq, keys_subq.c.user_id == User.id)
        .outerjoin(groups_subq, groups_subq.c.user_id == User.id)
        .where(User.tenant_id == tenant_id)
        .order_by(User.created_at.desc(), User.email.asc())
    ).all()
    return [
        UserListItem(
            user=user,
            api_key_count=int(api_key_count or 0),
            group_count=int(group_count or 0),
            last_api_key_used_at=last_api_key_used_at,
        )
        for user, api_key_count, last_api_key_used_at, group_count in rows
    ]


def get_user(db: Session, *, tenant_id: UUID, user_id: UUID) -> User:
    user = cast(
        User | None,
        db.scalar(
            select(User).where(User.tenant_id == tenant_id, User.id == user_id)
        ),
    )
    if user is None:
        raise UserNotFoundError
    return user


def set_password(
    db: Session,
    *,
    tenant_id: UUID,
    user_id: UUID,
    new_password: str,
    require_rotation: bool = False,
    actor: AdminAuditActor | None = None,
) -> User:
    """Set a new password on a local user. Used for admin reset and user
    self-rotate. Strength validated; bcrypt-hashed; `must_change_password`
    can be set so the user is forced to rotate again on next login (admin
    reset path) or unset (user self-rotate path).

    Detail captures whether this is an admin reset (`require_rotation=True`)
    or a self-rotate, but never the password itself.
    """

    user = get_user(db, tenant_id=tenant_id, user_id=user_id)
    if user.auth_method != UserAuthMethod.LOCAL:
        raise WrongAuthMethodError
    validate_password_strength(new_password)
    user.password_hash = hash_password(new_password)
    user.must_change_password = require_rotation
    if actor is not None:
        record_admin_action(
            db,
            tenant_id=tenant_id,
            actor=actor,
            action=(
                "user.password_reset" if require_rotation else "user.password_rotate"
            ),
            target=AdminAuditTarget(
                kind="user", id=user.id, display=user.email
            ),
            detail={"requires_rotation_on_next_login": require_rotation},
        )
    db.commit()
    db.refresh(user)
    return user


def upsert_oidc_user(
    db: Session,
    *,
    tenant_id: UUID,
    email: str,
    external_subject: str,
    auth_method: UserAuthMethod,
    display_name: str | None = None,
) -> User:
    """JIT-provision an OIDC user on first sign-in, or return the existing
    row if the user has signed in before. Match on `(tenant_id, email)`
    to keep the email canonical; update `external_subject` on the first
    OIDC login (admins may have pre-provisioned the row with no subject
    yet).

    Refuses to overwrite a `local`-method user with an OIDC subject — if
    a local user exists with that email, the OIDC sign-in fails generic
    auth (caller surfaces as login error). Same email, two auth methods
    is a misconfig — pick one per user per tenant.
    """

    normalized = email.strip().lower()
    user = cast(
        User | None,
        db.scalar(
            select(User).where(User.tenant_id == tenant_id, User.email == normalized)
        ),
    )
    if user is None:
        user = User(
            id=uuid4(),
            tenant_id=tenant_id,
            email=normalized,
            display_name=display_name,
            auth_method=auth_method,
            external_subject=external_subject,
            password_hash=None,
            must_change_password=False,
        )
        db.add(user)
    else:
        if user.auth_method != auth_method:
            raise WrongAuthMethodError(
                "user exists with a different auth_method"
            )
        # Update fields that may have rotated since prior sign-in.
        user.external_subject = external_subject
        if display_name and not user.display_name:
            user.display_name = display_name
    user.last_login_at = datetime.now(UTC)
    db.commit()
    db.refresh(user)
    return user


def disable_user(
    db: Session,
    *,
    tenant_id: UUID,
    user_id: UUID,
    actor: AdminAuditActor | None = None,
) -> User:
    user = get_user(db, tenant_id=tenant_id, user_id=user_id)
    if user.disabled_at is None:
        user.disabled_at = datetime.now(UTC)
        if actor is not None:
            record_admin_action(
                db,
                tenant_id=tenant_id,
                actor=actor,
                action="user.disable",
                target=AdminAuditTarget(
                    kind="user", id=user.id, display=user.email
                ),
            )
        db.commit()
        db.refresh(user)
    return user


# --- Groups ---------------------------------------------------------------


def create_group(
    db: Session,
    *,
    tenant_id: UUID,
    name: str,
    created_by: UUID,
    description: str | None = None,
    actor: AdminAuditActor | None = None,
) -> Group:
    group = Group(
        id=uuid4(),
        tenant_id=tenant_id,
        name=name,
        description=description,
        created_by=created_by,
    )
    try:
        db.add(group)
        if actor is not None:
            record_admin_action(
                db,
                tenant_id=tenant_id,
                actor=actor,
                action="group.create",
                target=AdminAuditTarget(
                    kind="group", id=group.id, display=group.name
                ),
                detail={"description": description},
            )
        db.commit()
        db.refresh(group)
    except IntegrityError as exc:
        db.rollback()
        raise DuplicateGroupNameError from exc
    return group


def list_groups(db: Session, *, tenant_id: UUID) -> list[Group]:
    return list(
        db.scalars(
            select(Group)
            .where(Group.tenant_id == tenant_id)
            .order_by(Group.name.asc())
        ).all()
    )


@dataclass(frozen=True)
class GroupListItem:
    """One row in the operator-console Groups table — a `Group` plus
    the aggregates the table renders next to it. The route layer maps
    this to `GroupListItemResponse`."""

    group: Group
    member_count: int
    vserver_grant_count: int


def list_groups_with_aggregates(
    db: Session, *, tenant_id: UUID
) -> list[GroupListItem]:
    """One-trip list for the admin Groups table.

    Computes per-group `member_count` and `vserver_grant_count`
    via two LEFT-JOINed aggregate subqueries — bounded by the
    tenant's group count, no N+1.

    `vserver_grant_count` filters to grants whose `principal_kind` is
    `GROUP` (not user grants); a group with `0` here is declared but
    nothing references it — useful signal for stale config.
    """

    members_subq = (
        select(
            UserGroupMembership.group_id.label("group_id"),
            func.count().label("cnt"),
        )
        .group_by(UserGroupMembership.group_id)
        .subquery()
    )
    grants_subq = (
        select(
            VirtualServerGrant.principal_id.label("group_id"),
            func.count().label("cnt"),
        )
        .where(VirtualServerGrant.principal_kind == GrantPrincipalKind.GROUP)
        .group_by(VirtualServerGrant.principal_id)
        .subquery()
    )
    rows = db.execute(
        select(
            Group,
            func.coalesce(members_subq.c.cnt, 0).label("member_count"),
            func.coalesce(grants_subq.c.cnt, 0).label("vserver_grant_count"),
        )
        .outerjoin(members_subq, members_subq.c.group_id == Group.id)
        .outerjoin(grants_subq, grants_subq.c.group_id == Group.id)
        .where(Group.tenant_id == tenant_id)
        .order_by(Group.name.asc())
    ).all()
    return [
        GroupListItem(
            group=group,
            member_count=int(member_count or 0),
            vserver_grant_count=int(vserver_grant_count or 0),
        )
        for group, member_count, vserver_grant_count in rows
    ]


def get_group(db: Session, *, tenant_id: UUID, group_id: UUID) -> Group:
    group = cast(
        Group | None,
        db.scalar(
            select(Group).where(Group.tenant_id == tenant_id, Group.id == group_id)
        ),
    )
    if group is None:
        raise GroupNotFoundError
    return group


def add_group_member(
    db: Session,
    *,
    tenant_id: UUID,
    group_id: UUID,
    user_id: UUID,
    added_by: UUID,
    actor: AdminAuditActor | None = None,
) -> UserGroupMembership:
    """Add a user to a group. Both must already exist in the tenant.
    Idempotent — re-adding an existing member is a no-op (and skips
    the audit row, since nothing actually changed)."""

    group = get_group(db, tenant_id=tenant_id, group_id=group_id)
    user = get_user(db, tenant_id=tenant_id, user_id=user_id)
    existing = cast(
        UserGroupMembership | None,
        db.scalar(
            select(UserGroupMembership).where(
                UserGroupMembership.user_id == user_id,
                UserGroupMembership.group_id == group_id,
            )
        ),
    )
    if existing is not None:
        return existing
    membership = UserGroupMembership(
        user_id=user_id,
        group_id=group_id,
        added_by=added_by,
    )
    db.add(membership)
    if actor is not None:
        record_admin_action(
            db,
            tenant_id=tenant_id,
            actor=actor,
            action="group.add_member",
            target=AdminAuditTarget(
                kind="group", id=group.id, display=group.name
            ),
            detail={"user_id": str(user_id), "user_email": user.email},
        )
    db.commit()
    return membership


def remove_group_member(
    db: Session,
    *,
    tenant_id: UUID,
    group_id: UUID,
    user_id: UUID,
    actor: AdminAuditActor | None = None,
) -> None:
    group = get_group(db, tenant_id=tenant_id, group_id=group_id)
    user = get_user(db, tenant_id=tenant_id, user_id=user_id)
    db.execute(
        sa_delete(UserGroupMembership).where(
            UserGroupMembership.user_id == user_id,
            UserGroupMembership.group_id == group_id,
        )
    )
    if actor is not None:
        record_admin_action(
            db,
            tenant_id=tenant_id,
            actor=actor,
            action="group.remove_member",
            target=AdminAuditTarget(
                kind="group", id=group.id, display=group.name
            ),
            detail={"user_id": str(user_id), "user_email": user.email},
        )
    db.commit()


def list_group_members(
    db: Session,
    *,
    tenant_id: UUID,
    group_id: UUID,
) -> list[User]:
    """Return the users currently in a group.

    Used by the operator console's inline group editor — lets the
    UI show "5 members: alice@…, bob@…" without forcing a separate
    fetch per user. Tenant-scoped via `get_group` (raises
    `GroupNotFoundError` for cross-tenant ids).
    """

    get_group(db, tenant_id=tenant_id, group_id=group_id)
    rows = db.scalars(
        select(User)
        .join(UserGroupMembership, UserGroupMembership.user_id == User.id)
        .where(UserGroupMembership.group_id == group_id)
        .order_by(User.email)
    ).all()
    return list(rows)


# --- API keys -------------------------------------------------------------


def issue_user_api_key(
    db: Session,
    *,
    tenant_id: UUID,
    user_id: UUID,
    label: str,
    expires_at: datetime | None = None,
    actor: AdminAuditActor | None = None,
) -> tuple[UserApiKey, IssuedApiKey]:
    """Issue a new API key for the given user. Returns the persisted row
    + the IssuedApiKey carrying the plaintext (for one-time display).

    The audit row records the label + prefix (NEVER the plaintext).
    """

    user = get_user(db, tenant_id=tenant_id, user_id=user_id)
    key_id = uuid4()
    issued = issue_new_key(key_id=key_id)
    row = UserApiKey(
        id=key_id,
        tenant_id=tenant_id,
        user_id=user_id,
        label=label,
        key_hash=issued.key_hash,
        key_prefix=issued.key_prefix,
        expires_at=expires_at,
    )
    try:
        db.add(row)
        if actor is not None:
            record_admin_action(
                db,
                tenant_id=tenant_id,
                actor=actor,
                action="apikey.issue",
                target=AdminAuditTarget(
                    kind="user", id=user_id, display=user.email
                ),
                detail={
                    "label": label,
                    "key_prefix": issued.key_prefix,
                    "expires_at": expires_at.isoformat() if expires_at else None,
                },
            )
        db.commit()
        db.refresh(row)
    except IntegrityError as exc:
        db.rollback()
        raise DuplicateApiKeyLabelError from exc
    return row, issued


def list_user_api_keys(
    db: Session, *, tenant_id: UUID, user_id: UUID
) -> list[UserApiKey]:
    return list(
        db.scalars(
            select(UserApiKey)
            .where(UserApiKey.tenant_id == tenant_id, UserApiKey.user_id == user_id)
            .order_by(UserApiKey.created_at.desc())
        ).all()
    )


def revoke_user_api_key(
    db: Session,
    *,
    tenant_id: UUID,
    user_id: UUID,
    key_id: UUID,
    actor: AdminAuditActor | None = None,
) -> UserApiKey:
    row = cast(
        UserApiKey | None,
        db.scalar(
            select(UserApiKey).where(
                UserApiKey.tenant_id == tenant_id,
                UserApiKey.user_id == user_id,
                UserApiKey.id == key_id,
            )
        ),
    )
    if row is None:
        raise UserNotFoundError
    if row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        if actor is not None:
            record_admin_action(
                db,
                tenant_id=tenant_id,
                actor=actor,
                action="apikey.revoke",
                target=AdminAuditTarget(
                    kind="apikey", id=key_id, display=row.label
                ),
                detail={"user_id": str(user_id), "key_prefix": row.key_prefix},
            )
        db.commit()
        db.refresh(row)
    return row


# --- Grants on vservers ---------------------------------------------------


def set_vserver_visibility(
    db: Session,
    *,
    tenant_id: UUID,
    vserver_id: UUID,
    visibility: VirtualServerVisibility,
    actor: AdminAuditActor | None = None,
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
        raise GrantTargetNotFoundError
    previous = vserver.visibility
    vserver.visibility = visibility
    if actor is not None and previous != visibility:
        record_admin_action(
            db,
            tenant_id=tenant_id,
            actor=actor,
            action="vserver.set_visibility",
            target=AdminAuditTarget(
                kind="vserver", id=vserver.id, display=vserver.name
            ),
            detail={
                "from": (
                    previous.value if hasattr(previous, "value") else str(previous)
                ),
                "to": (
                    visibility.value
                    if hasattr(visibility, "value")
                    else str(visibility)
                ),
            },
        )
    db.commit()
    db.refresh(vserver)
    return vserver


def issue_grant(
    db: Session,
    *,
    tenant_id: UUID,
    vserver_id: UUID,
    principal_kind: GrantPrincipalKind,
    principal_id: UUID,
    granted_by: UUID,
    expires_at: datetime | None = None,
    actor: AdminAuditActor | None = None,
) -> VirtualServerGrant:
    """Grant a user or group access to a private vserver. Validates that
    the vserver and the target principal both exist in the tenant before
    inserting."""

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
        raise GrantTargetNotFoundError
    principal_display: str | None = None
    if principal_kind == GrantPrincipalKind.USER:
        target_user = get_user(db, tenant_id=tenant_id, user_id=principal_id)
        principal_display = target_user.email
    else:
        target_group = get_group(db, tenant_id=tenant_id, group_id=principal_id)
        principal_display = target_group.name

    grant = VirtualServerGrant(
        id=uuid4(),
        tenant_id=tenant_id,
        vserver_id=vserver_id,
        principal_kind=principal_kind,
        principal_id=principal_id,
        granted_by=granted_by,
        expires_at=expires_at,
    )
    db.add(grant)
    if actor is not None:
        record_admin_action(
            db,
            tenant_id=tenant_id,
            actor=actor,
            action="grant.issue",
            target=AdminAuditTarget(
                kind="vserver", id=vserver.id, display=vserver.name
            ),
            detail={
                "principal_kind": (
                    principal_kind.value
                    if hasattr(principal_kind, "value")
                    else str(principal_kind)
                ),
                "principal_id": str(principal_id),
                "principal_display": principal_display,
                "expires_at": expires_at.isoformat() if expires_at else None,
            },
        )
    db.commit()
    db.refresh(grant)
    return grant


def list_grants(
    db: Session, *, tenant_id: UUID, vserver_id: UUID
) -> list[VirtualServerGrant]:
    return list(
        db.scalars(
            select(VirtualServerGrant)
            .where(
                VirtualServerGrant.tenant_id == tenant_id,
                VirtualServerGrant.vserver_id == vserver_id,
            )
            .order_by(VirtualServerGrant.granted_at.desc())
        ).all()
    )


def revoke_grant(
    db: Session,
    *,
    tenant_id: UUID,
    vserver_id: UUID,
    grant_id: UUID,
    actor: AdminAuditActor | None = None,
) -> VirtualServerGrant:
    grant = cast(
        VirtualServerGrant | None,
        db.scalar(
            select(VirtualServerGrant).where(
                VirtualServerGrant.tenant_id == tenant_id,
                VirtualServerGrant.vserver_id == vserver_id,
                VirtualServerGrant.id == grant_id,
            )
        ),
    )
    if grant is None:
        raise GrantTargetNotFoundError
    if grant.revoked_at is None:
        grant.revoked_at = datetime.now(UTC)
        if actor is not None:
            vserver = cast(
                VirtualServer | None,
                db.scalar(
                    select(VirtualServer).where(
                        VirtualServer.id == vserver_id,
                        VirtualServer.tenant_id == tenant_id,
                    )
                ),
            )
            record_admin_action(
                db,
                tenant_id=tenant_id,
                actor=actor,
                action="grant.revoke",
                target=AdminAuditTarget(
                    kind="vserver",
                    id=vserver_id,
                    display=vserver.name if vserver else None,
                ),
                detail={
                    "grant_id": str(grant_id),
                    "principal_kind": (
                        grant.principal_kind.value
                        if hasattr(grant.principal_kind, "value")
                        else str(grant.principal_kind)
                    ),
                    "principal_id": str(grant.principal_id),
                },
            )
        db.commit()
        db.refresh(grant)
    return grant
