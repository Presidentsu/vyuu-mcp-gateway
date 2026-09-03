"""SCIM <-> `groups` table translation + ops.

Membership is flat — no nested-group expansion (per IDP-1 decision).
Each `members[]` entry is a user UUID; we resolve it through
`users.id` scoped to the same tenant + directory before inserting
into `user_group_memberships`.

Like `scim.users`, every mutation here writes an `admin_audit_log`
row with `actor_kind='scim'`.
"""

from __future__ import annotations

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
    Group,
    IdpDirectory,
    User,
    UserGroupMembership,
)
from vyuu_gateway.scim.schemas import ScimGroup, resolve_member_id


class ScimGroupExists(Exception):
    """SCIM POST against a (directory, externalId) that's already
    known — 409 / scimType=uniqueness."""


def find_by_external_id(
    db: Session, *, directory: IdpDirectory, external_id: str
) -> Group | None:
    return cast(
        Group | None,
        db.scalar(
            select(Group).where(
                Group.tenant_id == directory.tenant_id,
                Group.idp_directory_id == directory.id,
                Group.external_id == external_id,
            )
        ),
    )


def find_by_id(
    db: Session, *, directory: IdpDirectory, group_id: UUID
) -> Group | None:
    return cast(
        Group | None,
        db.scalar(
            select(Group).where(
                Group.tenant_id == directory.tenant_id,
                Group.id == group_id,
            )
        ),
    )


def list_member_ids(
    db: Session, *, group_id: UUID
) -> list[UUID]:
    rows = db.scalars(
        select(UserGroupMembership.user_id).where(
            UserGroupMembership.group_id == group_id
        )
    ).all()
    return list(rows)


def create_from_scim(
    db: Session,
    *,
    directory: IdpDirectory,
    payload: ScimGroup,
    operator_id: UUID,
) -> Group:
    """Provision a new SCIM-sourced group + initial membership.

    `operator_id` is the operator who connected the directory; we
    treat them as `created_by` for FK purposes (the row was
    SCIM-created but `created_by` is non-null, so we have to point
    it at SOMEONE)."""

    group = Group(
        id=uuid4(),
        tenant_id=directory.tenant_id,
        name=payload.displayName,
        description=None,
        created_by=operator_id,
        idp_directory_id=directory.id,
        external_id=payload.externalId or payload.id,
    )
    try:
        db.add(group)
        db.flush()
        added_member_ids = _set_members(
            db,
            directory=directory,
            group=group,
            target_user_ids=_validated_member_ids(payload, directory.tenant_id, db),
            added_by=operator_id,
            replace=False,
        )
        record_admin_action(
            db,
            tenant_id=directory.tenant_id,
            actor=AdminAuditActor.scim(directory.display_name),
            action="scim.create_group",
            target=AdminAuditTarget(
                kind="group", id=group.id, display=group.name
            ),
            detail={
                "directory_id": str(directory.id),
                "external_id": payload.externalId or payload.id,
                "initial_member_count": len(added_member_ids),
            },
        )
        db.commit()
        db.refresh(group)
    except IntegrityError as exc:
        db.rollback()
        raise ScimGroupExists from exc
    return group


def replace_from_scim(
    db: Session,
    *,
    directory: IdpDirectory,
    group: Group,
    payload: ScimGroup,
    operator_id: UUID,
) -> Group:
    """SCIM PUT — replace name + membership wholesale."""

    if payload.displayName != group.name:
        group.name = payload.displayName
    if payload.externalId:
        group.external_id = payload.externalId

    target_ids = _validated_member_ids(payload, directory.tenant_id, db)
    _set_members(
        db,
        directory=directory,
        group=group,
        target_user_ids=target_ids,
        added_by=operator_id,
        replace=True,
    )

    record_admin_action(
        db,
        tenant_id=directory.tenant_id,
        actor=AdminAuditActor.scim(directory.display_name),
        action="scim.replace_group",
        target=AdminAuditTarget(
            kind="group", id=group.id, display=group.name
        ),
        detail={
            "directory_id": str(directory.id),
            "member_count": len(target_ids),
        },
    )
    db.commit()
    db.refresh(group)
    return group


def soft_delete(
    db: Session, *, directory: IdpDirectory, group: Group
) -> None:
    """SCIM DELETE on a group — we hard-delete the row + cascade
    the memberships. Groups don't carry their own credentials, so
    a 7-day grace period adds no security value."""

    captured_name = group.name
    captured_id = group.id

    db.execute(
        UserGroupMembership.__table__.delete().where(
            UserGroupMembership.group_id == group.id
        )
    )
    db.delete(group)
    record_admin_action(
        db,
        tenant_id=directory.tenant_id,
        actor=AdminAuditActor.scim(directory.display_name),
        action="scim.delete_group",
        target=AdminAuditTarget(
            kind="group", id=captured_id, display=captured_name
        ),
        detail={"directory_id": str(directory.id)},
    )
    db.commit()


def add_members(
    db: Session,
    *,
    directory: IdpDirectory,
    group: Group,
    user_ids: list[UUID],
    added_by: UUID,
) -> int:
    """Append members; idempotent on repeats. Returns the count of
    rows actually inserted."""

    if not user_ids:
        return 0
    valid = _filter_to_tenant_users(db, directory.tenant_id, user_ids)
    existing = set(list_member_ids(db, group_id=group.id))
    to_add = [uid for uid in valid if uid not in existing]
    for uid in to_add:
        db.add(
            UserGroupMembership(
                user_id=uid, group_id=group.id, added_by=added_by
            )
        )
    if to_add:
        record_admin_action(
            db,
            tenant_id=directory.tenant_id,
            actor=AdminAuditActor.scim(directory.display_name),
            action="scim.group_add_members",
            target=AdminAuditTarget(
                kind="group", id=group.id, display=group.name
            ),
            detail={
                "directory_id": str(directory.id),
                "added_count": len(to_add),
                "added_user_ids": [str(uid) for uid in to_add],
            },
        )
    db.commit()
    return len(to_add)


def remove_members(
    db: Session,
    *,
    directory: IdpDirectory,
    group: Group,
    user_ids: list[UUID],
) -> int:
    """Remove specific members. Returns the row-count actually
    deleted."""

    if not user_ids:
        return 0
    result = db.execute(
        UserGroupMembership.__table__.delete()
        .where(
            UserGroupMembership.group_id == group.id,
            UserGroupMembership.user_id.in_(user_ids),
        )
    )
    deleted = result.rowcount or 0
    if deleted:
        record_admin_action(
            db,
            tenant_id=directory.tenant_id,
            actor=AdminAuditActor.scim(directory.display_name),
            action="scim.group_remove_members",
            target=AdminAuditTarget(
                kind="group", id=group.id, display=group.name
            ),
            detail={
                "directory_id": str(directory.id),
                "removed_count": deleted,
                "removed_user_ids": [str(uid) for uid in user_ids],
            },
        )
    db.commit()
    return deleted


# --- Helpers --------------------------------------------------------------


def _validated_member_ids(
    payload: ScimGroup, tenant_id: UUID, db: Session
) -> list[UUID]:
    """Parse the inbound `members[]` array down to a list of valid
    UUIDs that exist in the tenant. Silently drops unknown / cross-
    tenant ids — the IdP retries on its own cadence and we don't
    want one stale member to fail the whole group sync."""

    candidates: list[UUID] = []
    for ref in payload.members:
        uid = resolve_member_id(ref.value)
        if uid is not None:
            candidates.append(uid)
    return _filter_to_tenant_users(db, tenant_id, candidates)


def _filter_to_tenant_users(
    db: Session, tenant_id: UUID, user_ids: list[UUID]
) -> list[UUID]:
    if not user_ids:
        return []
    rows = db.scalars(
        select(User.id).where(
            User.tenant_id == tenant_id,
            User.id.in_(user_ids),
        )
    ).all()
    return list(rows)


def _set_members(
    db: Session,
    *,
    directory: IdpDirectory,
    group: Group,
    target_user_ids: list[UUID],
    added_by: UUID,
    replace: bool,
) -> list[UUID]:
    """Drive the membership rows toward `target_user_ids`. When
    `replace=True`, removes anything not in the target. Returns the
    list of newly-added ids."""

    if replace:
        db.execute(
            UserGroupMembership.__table__.delete().where(
                UserGroupMembership.group_id == group.id
            )
        )
        existing: set[UUID] = set()
    else:
        existing = set(list_member_ids(db, group_id=group.id))

    to_add = [uid for uid in target_user_ids if uid not in existing]
    for uid in to_add:
        db.add(
            UserGroupMembership(
                user_id=uid, group_id=group.id, added_by=added_by
            )
        )
    return to_add
