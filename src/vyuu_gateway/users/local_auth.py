"""Verify (email, password) → User row for `auth_method='local'` users.

Anti-enumeration: returns the same exception class regardless of WHY
auth failed (unknown email, wrong password, OIDC user trying password
login, disabled account). Login UI surfaces the same generic message
so attackers can't probe which emails exist.

Tenant scoping: caller passes `tenant_id` explicitly. A login request
on `/portal` infers tenant from the URL (we shipped the gateway as
single-tenant per process for v1; multi-tenant routing comes later).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import User, UserAuthMethod
from vyuu_gateway.users.passwords import verify_password


class InvalidCredentialsError(Exception):
    """Login failed for any reason. Generic by design — see module docstring."""


def authenticate_local_user(
    session: Session,
    *,
    tenant_id: UUID,
    email: str,
    password: str,
) -> User:
    """Verify (email, password) against a local user row in `tenant_id`.

    Returns the matching `User` on success (with `last_login_at` updated).
    Raises `InvalidCredentialsError` on any failure.

    Always runs the bcrypt verification, even on missing-email or
    wrong-method paths. Bcrypt is the slow part of the login flow; a
    fast-path "no email match" early return would let an attacker
    timing-side-channel which emails exist. Constant work for all
    failure modes.
    """

    # Constant per-call work irrespective of which lookup leg fails:
    # always do the bcrypt verify against SOMETHING. If user is None
    # we verify against a fixed dummy hash so the rejection has the
    # same latency as a "real" wrong-password rejection.
    user = cast(
        User | None,
        session.scalar(
            select(User).where(
                User.tenant_id == tenant_id,
                User.email == email.strip().lower(),
            )
        ),
    )

    candidate_hash = (
        user.password_hash
        if user is not None and user.password_hash
        else _DUMMY_HASH_FOR_TIMING
    )
    matched = verify_password(password, candidate_hash)

    if user is None or not matched:
        raise InvalidCredentialsError
    if user.auth_method != UserAuthMethod.LOCAL:
        # User exists but is OIDC-authed; same generic error.
        raise InvalidCredentialsError
    if user.disabled_at is not None:
        raise InvalidCredentialsError
    if not user.password_hash:
        raise InvalidCredentialsError

    user.last_login_at = datetime.now(UTC)
    session.commit()
    return user


# Pre-computed bcrypt hash of a random string, used only to make the
# bcrypt-verify wall-time of "no such user" identical to "wrong password
# for real user". Generated at module import.
_DUMMY_HASH_FOR_TIMING = (
    "$2b$12$KIXxKpUPOlhmPEuXwVZPZeqFvmF.GHlBTPnA9mGZ.W7e7jXoMCvse"
)
