"""SCIM <-> `users` table translation + ops.

Every entry point here is invoked from the SCIM router, which has
already verified the bearer and bound the DB session to the
directory's tenant. So we trust `tenant_id` on this side.

The audit emitter records each SCIM-driven action against
`admin_audit_log` with `actor_kind='scim'` so the operator console
can distinguish "Acme Corp · Entra ID disabled this user" from "Alice
the admin disabled this user".

Soft-delete semantics on DELETE / `active=false`:
- We mark `users.disabled_at = now()` and `users.soft_deleted_at = now()`.
  The auth path stops accepting their bearer immediately
  (existing `disabled_at` check), and the hard-delete sweeper
  picks rows where `now() - soft_deleted_at > 7d` and removes them
  (Phase 3, separate from this module).
"""

from __future__ import annotations

from datetime import UTC, datetime
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
from vyuu_gateway.db.models import IdpDirectory, User, UserAuthMethod
from vyuu_gateway.scim.schemas import ScimUser, primary_email


class ScimUserExistsError(Exception):
    """SCIM POST against an externalId we've already provisioned —
    the spec maps this to `409 Conflict / scimType=uniqueness`."""


def find_by_external_id(
    db: Session, *, directory: IdpDirectory, external_id: str
) -> User | None:
    """Look up a user by `(directory, external_id)` — the SCIM `id`
    we hand back to the IdP IS our `users.id`, but the IdP also
    sometimes searches by `externalId` (its own stable identifier)."""

    return cast(
        User | None,
        db.scalar(
            select(User).where(
                User.tenant_id == directory.tenant_id,
                User.idp_directory_id == directory.id,
                User.external_id == external_id,
            )
        ),
    )


def find_by_id(
    db: Session, *, directory: IdpDirectory, user_id: UUID
) -> User | None:
    return cast(
        User | None,
        db.scalar(
            select(User).where(
                User.tenant_id == directory.tenant_id,
                User.id == user_id,
            )
        ),
    )


def find_by_username(
    db: Session, *, directory: IdpDirectory, username: str
) -> User | None:
    """SCIM `userName` is the tenant-unique handle. We map it to
    `users.email` (the spec allows any string but every IdP we care
    about ships emails)."""

    return cast(
        User | None,
        db.scalar(
            select(User).where(
                User.tenant_id == directory.tenant_id,
                User.email == username.strip().lower(),
            )
        ),
    )


def create_from_scim(
    db: Session,
    *,
    directory: IdpDirectory,
    payload: ScimUser,
) -> User:
    """Provision a new SCIM-sourced user. Commits + returns the row.

    The audit row records the directory as the actor (not a human
    operator) — `actor_kind='scim'`."""

    email = primary_email(payload) or payload.userName
    display_name = payload.displayName or _name_to_display(payload)

    user = User(
        id=uuid4(),
        tenant_id=directory.tenant_id,
        email=email.strip().lower(),
        display_name=display_name,
        auth_method=UserAuthMethod.SCIM,
        password_hash=None,
        external_subject=None,  # OIDC sub, populated on first sign-in
        idp_directory_id=directory.id,
        external_id=payload.externalId or payload.id,
        # Inactive on creation if the IdP says so. Rare but spec-compliant.
        disabled_at=None if payload.active else datetime.now(UTC),
    )
    try:
        db.add(user)
        record_admin_action(
            db,
            tenant_id=directory.tenant_id,
            actor=AdminAuditActor.scim(directory.display_name),
            action="scim.create_user",
            target=AdminAuditTarget(
                kind="user", id=user.id, display=user.email
            ),
            detail={
                "directory_id": str(directory.id),
                "external_id": payload.externalId or payload.id,
                "active": payload.active,
            },
        )
        db.commit()
        db.refresh(user)
    except IntegrityError as exc:
        db.rollback()
        raise ScimUserExistsError from exc
    return user


def replace_from_scim(
    db: Session,
    *,
    directory: IdpDirectory,
    user: User,
    payload: ScimUser,
) -> User:
    """SCIM PUT — full-resource replace. We update the fields we
    persist, leave the rest alone."""

    email = primary_email(payload) or payload.userName
    display_name = payload.displayName or _name_to_display(payload)
    new_email = email.strip().lower()
    new_disabled = None if payload.active else (
        user.disabled_at or datetime.now(UTC)
    )

    user.email = new_email
    user.display_name = display_name
    user.disabled_at = new_disabled
    if payload.externalId:
        user.external_id = payload.externalId

    record_admin_action(
        db,
        tenant_id=directory.tenant_id,
        actor=AdminAuditActor.scim(directory.display_name),
        action="scim.replace_user",
        target=AdminAuditTarget(
            kind="user", id=user.id, display=user.email
        ),
        detail={"active": payload.active},
    )
    db.commit()
    db.refresh(user)
    return user


def soft_delete(
    db: Session, *, directory: IdpDirectory, user: User
) -> None:
    """Soft-delete on SCIM DELETE. Sets `disabled_at` (so the auth
    path 401s immediately) and `soft_deleted_at` (so the hard-delete
    sweeper removes the row after the 7-day grace)."""

    now = datetime.now(UTC)
    user.disabled_at = user.disabled_at or now
    user.soft_deleted_at = now

    record_admin_action(
        db,
        tenant_id=directory.tenant_id,
        actor=AdminAuditActor.scim(directory.display_name),
        action="scim.deactivate_user",
        target=AdminAuditTarget(
            kind="user", id=user.id, display=user.email
        ),
        detail={"directory_id": str(directory.id)},
    )
    db.commit()


def set_active(
    db: Session,
    *,
    directory: IdpDirectory,
    user: User,
    active: bool,
) -> None:
    """`PATCH active=false` (or true) — the most common SCIM PATCH
    op. We treat `false` as a soft-delete, `true` as a re-activation
    (clears `disabled_at` + `soft_deleted_at` so the sweeper skips
    the row)."""

    if active:
        if user.disabled_at is None and user.soft_deleted_at is None:
            return  # already active
        user.disabled_at = None
        user.soft_deleted_at = None
        action = "scim.reactivate_user"
    else:
        # Idempotent — repeat soft-deletes don't double-emit audit rows.
        if user.disabled_at is not None and user.soft_deleted_at is not None:
            return
        now = datetime.now(UTC)
        user.disabled_at = user.disabled_at or now
        user.soft_deleted_at = now
        action = "scim.deactivate_user"

    record_admin_action(
        db,
        tenant_id=directory.tenant_id,
        actor=AdminAuditActor.scim(directory.display_name),
        action=action,
        target=AdminAuditTarget(
            kind="user", id=user.id, display=user.email
        ),
        detail={"directory_id": str(directory.id)},
    )
    db.commit()


def _name_to_display(payload: ScimUser) -> str | None:
    """Build a display from the structured `name` block when
    `displayName` is absent. Most IdPs send one or the other."""

    if payload.name is None:
        return None
    if payload.name.formatted:
        return payload.name.formatted
    parts = [
        payload.name.givenName,
        payload.name.middleName,
        payload.name.familyName,
    ]
    joined = " ".join(p for p in parts if p)
    return joined or None
