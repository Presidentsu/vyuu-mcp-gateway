"""Email + password operator login.

Layered on top of the existing JWT format used by `FakeOperatorAuthProvider`:
a successful login mints the same `<base64url(payload)>.<base64url(hmac)>`
token shape — the existing `authenticate_operator` dependency keeps
verifying tokens unchanged. This module only adds a *second* way to
get a token (the first is `mint_operator_test_token`, used by the lab
+ tests).

Anti-enumeration: every failure path (unknown email, wrong password,
disabled, no password set) returns the same `OperatorLoginError`
without distinguishable detail. Constant-time bcrypt verify against
a dummy hash on the unknown-email branch keeps timing uniform.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.audit.admin_audit import (
    AdminAuditActor,
    AdminAuditTarget,
    record_admin_action,
)
from vyuu_gateway.db.models import Operator
from vyuu_gateway.operator_auth.fake import mint_operator_test_token
from vyuu_gateway.users.passwords import (
    PasswordTooWeakError,
    hash_password,
    validate_password_strength,
    verify_password,
)

# Dummy bcrypt hash used for constant-time comparison on the
# unknown-email path. Generated once at import time.
_DUMMY_HASH = hash_password("anti-enumeration-placeholder-12+chars")


class OperatorLoginError(Exception):
    """Generic login failure. The detail string is fixed — anti-enumeration."""


class OperatorNotFoundError(Exception):
    """Used by admin operations (reset password, disable). Distinct from
    login failures so the operator-management panel can return 404."""


class DuplicateOperatorEmailError(Exception):
    """An operator with this email already exists in the tenant."""


def authenticate_operator_with_password(
    db: Session,
    *,
    tenant_id: UUID,
    email: str,
    password: str,
    signing_secret: str,
) -> tuple[Operator, str]:
    """Verify (email, password) and mint an operator JWT on success.

    Returns the loaded Operator row + the JWT. The Operator's
    `last_login_at` is updated as a side effect on success.
    """

    normalised_email = email.strip().lower()
    operator = cast(
        Operator | None,
        db.scalar(
            select(Operator).where(
                Operator.tenant_id == tenant_id,
                Operator.email == normalised_email,
            )
        ),
    )

    # Always run bcrypt verify — even on the unknown-email path — so
    # the timing is uniform regardless of whether the email exists.
    if operator is None:
        verify_password(password, _DUMMY_HASH)
        raise OperatorLoginError("invalid credentials")

    if operator.disabled_at is not None:
        verify_password(password, _DUMMY_HASH)
        raise OperatorLoginError("invalid credentials")

    if operator.password_hash is None:
        # Legacy / bearer-token-only operator — login by email+password
        # is not supported until an admin sets a password. Same generic
        # error so an attacker can't tell which operators have passwords.
        verify_password(password, _DUMMY_HASH)
        raise OperatorLoginError("invalid credentials")

    if not verify_password(password, operator.password_hash):
        raise OperatorLoginError("invalid credentials")

    operator.last_login_at = datetime.now(UTC)
    db.commit()
    db.refresh(operator)

    token = mint_operator_test_token(
        tenant_id=operator.tenant_id,
        operator_id=operator.id,
        display=operator.email,
        signing_secret=signing_secret,
    )
    return operator, token


# --- Admin-side operator management ----------------------------------------


def create_operator(
    db: Session,
    *,
    tenant_id: UUID,
    email: str,
    role: str,
    password: str,
    must_change_password: bool = True,
    actor: AdminAuditActor | None = None,
) -> Operator:
    """Admin creates a new operator. Initial password is required and
    must pass the same strength check as user-side passwords. Default
    `must_change_password=True` — admin issues a temp credential, the
    new operator rotates on first login."""

    from vyuu_gateway.db.models import OperatorRole

    validate_password_strength(password)
    operator = Operator(
        tenant_id=tenant_id,
        email=email.strip().lower(),
        role=OperatorRole(role),
        password_hash=hash_password(password),
        must_change_password=must_change_password,
    )
    try:
        db.add(operator)
        if actor is not None:
            record_admin_action(
                db,
                tenant_id=tenant_id,
                actor=actor,
                action="admin.create",
                target=AdminAuditTarget(
                    kind="admin", id=operator.id, display=operator.email
                ),
                detail={
                    "role": role,
                    "must_change_password": must_change_password,
                },
            )
        db.commit()
        db.refresh(operator)
    except Exception as exc:  # noqa: BLE001 — narrow on integrity below
        db.rollback()
        from sqlalchemy.exc import IntegrityError

        if isinstance(exc, IntegrityError):
            raise DuplicateOperatorEmailError from exc
        raise
    return operator


def list_operators(db: Session, *, tenant_id: UUID) -> list[Operator]:
    return list(
        db.scalars(
            select(Operator)
            .where(Operator.tenant_id == tenant_id)
            .order_by(Operator.created_at.desc(), Operator.email.asc())
        ).all()
    )


def reset_operator_password(
    db: Session,
    *,
    tenant_id: UUID,
    operator_id: UUID,
    new_password: str,
    must_change_password: bool = True,
    actor: AdminAuditActor | None = None,
) -> Operator:
    """Admin resets another operator's password. Forces
    `must_change_password=True` by default so the target rotates on
    next login."""

    operator = _load_operator(db, tenant_id=tenant_id, operator_id=operator_id)
    validate_password_strength(new_password)
    operator.password_hash = hash_password(new_password)
    operator.must_change_password = must_change_password
    if actor is not None:
        record_admin_action(
            db,
            tenant_id=tenant_id,
            actor=actor,
            action="admin.password_reset",
            target=AdminAuditTarget(
                kind="admin", id=operator.id, display=operator.email
            ),
            detail={"requires_rotation_on_next_login": must_change_password},
        )
    db.commit()
    db.refresh(operator)
    return operator


def disable_operator(
    db: Session,
    *,
    tenant_id: UUID,
    operator_id: UUID,
    actor: AdminAuditActor | None = None,
) -> Operator:
    operator = _load_operator(db, tenant_id=tenant_id, operator_id=operator_id)
    if operator.disabled_at is None:
        operator.disabled_at = datetime.now(UTC)
        if actor is not None:
            record_admin_action(
                db,
                tenant_id=tenant_id,
                actor=actor,
                action="admin.disable",
                target=AdminAuditTarget(
                    kind="admin", id=operator.id, display=operator.email
                ),
            )
        db.commit()
        db.refresh(operator)
    return operator


def rotate_my_operator_password(
    db: Session,
    *,
    tenant_id: UUID,
    operator_id: UUID,
    current_password: str,
    new_password: str,
) -> Operator:
    """Self-rotate. Verifies the current password before swapping —
    same defense as the end-user portal's rotate endpoint."""

    operator = _load_operator(db, tenant_id=tenant_id, operator_id=operator_id)
    if operator.password_hash is None or not verify_password(
        current_password, operator.password_hash
    ):
        raise OperatorLoginError("current password incorrect")
    validate_password_strength(new_password)
    operator.password_hash = hash_password(new_password)
    operator.must_change_password = False
    db.commit()
    db.refresh(operator)
    return operator


def _load_operator(
    db: Session, *, tenant_id: UUID, operator_id: UUID
) -> Operator:
    operator = cast(
        Operator | None,
        db.scalar(
            select(Operator).where(
                Operator.tenant_id == tenant_id,
                Operator.id == operator_id,
            )
        ),
    )
    if operator is None:
        raise OperatorNotFoundError
    return operator


__all__ = [
    "DuplicateOperatorEmailError",
    "OperatorLoginError",
    "OperatorNotFoundError",
    "PasswordTooWeakError",
    "authenticate_operator_with_password",
    "create_operator",
    "disable_operator",
    "list_operators",
    "reset_operator_password",
    "rotate_my_operator_password",
]
