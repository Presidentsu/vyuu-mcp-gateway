"""First-run bootstrap: seed an initial tenant + operator + admin user
from environment variables when no admins exist.

Two ways for the very first admin to exist on a new deployment:

1. **Env-var auto-seed** (this module). If the gateway boots and there
   are no operators for the configured bootstrap tenant, AND the env
   vars below are all set, seed the row. Idempotent: once any
   operator exists, this is a no-op.

2. **Out-of-band SQL** (deployment runbook). For ops teams that don't
   want secrets in env vars, the alternative is to INSERT directly:
   one tenant row + one operator row + one user row with a bcrypt-
   hashed password. Documented in HANDOFF + BACKLOG.

Env vars (all required for the auto-seed to fire):

    VYUU_BOOTSTRAP_TENANT_NAME       = "Acme Corp"
    VYUU_BOOTSTRAP_ADMIN_EMAIL       = "admin@acme.example"
    VYUU_BOOTSTRAP_ADMIN_PASSWORD    = "Initial password (>= 12 chars)"
    VYUU_BOOTSTRAP_ADMIN_DISPLAY     = "Acme admin"   (optional)

When all four are set and no operators yet exist, the bootstrap creates:
- A new `tenants` row.
- A new `users` row with `auth_method=local`, `must_change_password=true`.
- A new `operators` row referencing the new tenant.

Future enhancement (deferred): a `/operator/setup` web wizard that
exposes the same flow when the env vars aren't set, so ops teams that
prefer GUIs can bootstrap interactively.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import (
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
    User,
    UserAuthMethod,
)
from vyuu_gateway.users.passwords import (
    PasswordTooWeakError,
    hash_password,
    validate_password_strength,
)

logger = logging.getLogger(__name__)


def maybe_bootstrap_admin(session: Session) -> None:
    """Idempotently seed the first admin from environment variables.

    Called from the gateway's lifespan startup. If env vars are missing
    OR an operator already exists, this is a no-op. The tenant +
    operator + user are created in a single transaction.

    Logs (at INFO) when the seed actually fires so ops teams know the
    initial credential is now active.
    """

    tenant_name = os.environ.get("VYUU_BOOTSTRAP_TENANT_NAME")
    email = os.environ.get("VYUU_BOOTSTRAP_ADMIN_EMAIL")
    password = os.environ.get("VYUU_BOOTSTRAP_ADMIN_PASSWORD")
    display = os.environ.get("VYUU_BOOTSTRAP_ADMIN_DISPLAY")

    if not (tenant_name and email and password):
        return

    try:
        validate_password_strength(password)
    except PasswordTooWeakError:
        logger.warning(
            "bootstrap_password_too_weak",
            extra={"min_length": 12},
        )
        return

    normalized_email_for_lookup = email.strip().lower()

    # Forward-compat: operators that existed before the
    # `password_hash` column landed have `password_hash=null`. If we
    # find a match for the bootstrap email in the bootstrap tenant
    # AND its password is null, set it now from the env var. This
    # lets existing dev / lab gateways pick up the new login flow on
    # the first restart after the migration without requiring SQL
    # surgery. New deployments hit the create-from-scratch branch
    # below.
    legacy_operator = cast(
        Operator | None,
        session.scalar(
            select(Operator)
            .join(Tenant, Tenant.id == Operator.tenant_id)
            .where(
                Tenant.name == tenant_name,
                Operator.email == normalized_email_for_lookup,
                Operator.password_hash.is_(None),
            )
        ),
    )
    if legacy_operator is not None:
        legacy_operator.password_hash = hash_password(password)
        legacy_operator.must_change_password = True
        session.commit()
        logger.info(
            "bootstrap_legacy_operator_password_seeded",
            extra={
                "tenant_id": str(legacy_operator.tenant_id),
                "operator_id": str(legacy_operator.id),
                "email": legacy_operator.email,
            },
        )
        return

    existing_operator_id = session.scalar(select(Operator.id).limit(1))
    if existing_operator_id is not None:
        return

    tenant_id = uuid4()
    operator_id = uuid4()
    user_id = uuid4()
    now = datetime.now(UTC)
    normalized_email = email.strip().lower()

    tenant = Tenant(
        id=tenant_id,
        name=tenant_name,
        tier=TenantTier.SHARED,
        created_at=now,
    )
    operator = Operator(
        id=operator_id,
        tenant_id=tenant_id,
        email=normalized_email,
        role=OperatorRole.ADMIN,
        # Operator login (post-2026-04-30 batch) verifies against
        # `operators.password_hash`. We seed the SAME bcrypt-hashed
        # password as the user row so a single env-var-set credential
        # works on both `/portal` (end-user side) and `/operator`
        # (admin side). `must_change_password=True` forces rotation
        # on first login.
        password_hash=hash_password(password),
        must_change_password=True,
        created_at=now,
    )
    # Admin's user row carries the same password so the bootstrap
    # admin can also use `/portal` end-user features (catalog, request
    # access, issue API keys) under the same identity.
    user = User(
        id=user_id,
        tenant_id=tenant_id,
        email=normalized_email,
        display_name=display or "Bootstrap admin",
        auth_method=UserAuthMethod.LOCAL,
        password_hash=hash_password(password),
        must_change_password=True,
        created_at=now,
    )
    session.add(tenant)
    session.add(operator)
    session.add(user)
    session.commit()

    logger.info(
        "bootstrap_admin_seeded",
        extra={
            "tenant_id": str(tenant_id),
            "operator_id": str(operator_id),
            "user_id": str(user_id),
            "email": normalized_email,
        },
    )


def find_bootstrap_tenant(session: Session) -> UUID | None:
    """Return the tenant_id matching `VYUU_BOOTSTRAP_TENANT_NAME` if set,
    else None. Lab tooling that wants to talk to the bootstrapped tenant
    without hard-coding the UUID can use this."""

    tenant_name = os.environ.get("VYUU_BOOTSTRAP_TENANT_NAME")
    if not tenant_name:
        return None
    tenant = cast(
        Tenant | None,
        session.scalar(select(Tenant).where(Tenant.name == tenant_name)),
    )
    return tenant.id if tenant is not None else None
