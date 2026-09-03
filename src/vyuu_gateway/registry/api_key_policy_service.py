"""CRED-1 · how long a user's API keys may live.

`UserApiKey.expires_at` has always been enforced on every inbound call
and was never set — both issuance paths defaulted it to NULL. So a user
key lived until somebody remembered to revoke it, and a credential
nobody has to renew is a credential nobody reviews.

This module resolves the ceiling that applies to a given user, and is
the only place that decides it.

## Precedence: user → group → tenant → unlimited

More specific wins. The interesting case is a user in several groups:
the **shortest** policy applies, never the longest.

That direction is deliberate. If the longest won, joining a group would
be a way to extend your own credential lifetime — group membership would
become a privilege escalation, and the admin who added someone to
`contractors` for one reason would silently be granting another. Taking
the shortest means membership can only ever tighten, which is the only
direction that composes safely.

## Unlimited is still reachable, and still says so

No policy at any scope resolves to `None` — the pre-existing behaviour,
keys that never expire. That is not treated as an error, because a
tenant that has not adopted this yet must keep working. It is reported
as `unlimited` rather than as a number, so the operator console can show
it for what it is instead of implying a limit exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.audit.admin_audit import (
    AdminAuditActor,
    AdminAuditTarget,
    record_admin_action,
)
from vyuu_gateway.db.models import (
    ApiKeyPolicy,
    ApiKeyPrincipalKind,
    Group,
    UserApiKey,
    UserGroupMembership,
)

# Mirrors the CHECK constraint. Duplicated deliberately: the database
# is the backstop, but a caller deserves a message naming the limit
# rather than an IntegrityError.
MAX_TTL_SECONDS = 31_536_000  # 365 days


class ApiKeyPolicyError(Exception):
    """Invalid policy input. Message is operator-facing."""


@dataclass(frozen=True)
class ResolvedTtl:
    """The ceiling that applies to one user, and where it came from.

    `source_kind` is carried because "why does my key expire in eight
    hours?" is a question an operator has to be able to answer without
    reading three tables. `None` seconds means unlimited.
    """

    max_ttl_seconds: int | None
    source_kind: ApiKeyPrincipalKind | None
    source_id: UUID | None

    @property
    def is_unlimited(self) -> bool:
        return self.max_ttl_seconds is None

    def expires_at(self, *, now: datetime | None = None) -> datetime | None:
        if self.max_ttl_seconds is None:
            return None
        moment = now or datetime.now(UTC)
        return moment + timedelta(seconds=self.max_ttl_seconds)


def resolve_max_ttl(db: Session, *, tenant_id: UUID, user_id: UUID) -> ResolvedTtl:
    """The API-key ceiling for one user. See the module docstring."""

    policies = list(
        db.scalars(
            select(ApiKeyPolicy).where(ApiKeyPolicy.tenant_id == tenant_id)
        ).all()
    )
    if not policies:
        return ResolvedTtl(None, None, None)

    by_scope: dict[tuple[str, UUID], ApiKeyPolicy] = {
        (str(p.principal_kind), p.principal_id): p for p in policies
    }

    user_policy = by_scope.get((ApiKeyPrincipalKind.USER.value, user_id))
    if user_policy is not None:
        return ResolvedTtl(
            user_policy.max_ttl_seconds, ApiKeyPrincipalKind.USER, user_id
        )

    # `user_group_memberships` carries no tenant column — it is scoped
    # transitively through `groups`. Join rather than trusting the
    # membership row alone, so a group id from another tenant cannot
    # resolve a policy here.
    group_ids = set(
        db.scalars(
            select(UserGroupMembership.group_id)
            .join(Group, Group.id == UserGroupMembership.group_id)
            .where(
                UserGroupMembership.user_id == user_id,
                Group.tenant_id == tenant_id,
            )
        ).all()
    )
    # Shortest wins — see the module docstring on why never the longest.
    group_hits = [
        by_scope[(ApiKeyPrincipalKind.GROUP.value, gid)]
        for gid in group_ids
        if (ApiKeyPrincipalKind.GROUP.value, gid) in by_scope
    ]
    if group_hits:
        tightest = min(group_hits, key=lambda p: p.max_ttl_seconds)
        return ResolvedTtl(
            tightest.max_ttl_seconds,
            ApiKeyPrincipalKind.GROUP,
            tightest.principal_id,
        )

    tenant_policy = by_scope.get((ApiKeyPrincipalKind.TENANT.value, tenant_id))
    if tenant_policy is not None:
        return ResolvedTtl(
            tenant_policy.max_ttl_seconds, ApiKeyPrincipalKind.TENANT, tenant_id
        )

    return ResolvedTtl(None, None, None)


def enforce_requested_expiry(
    resolved: ResolvedTtl,
    requested_expires_at: datetime | None,
    *,
    now: datetime | None = None,
) -> datetime | None:
    """The `expires_at` a key should actually get.

    - Nothing requested → the policy's ceiling (or None if unlimited).
    - Requested within the ceiling → honoured as asked. Somebody who
      wants a 1-hour key under a 30-day policy should get one hour.
    - Requested beyond the ceiling → **rejected, not clamped**, naming
      both numbers. Same rule as JIT durations: silently shortening
      hands back a credential that dies earlier than the caller was
      told, and they find out when something breaks instead of now.
    """

    moment = now or datetime.now(UTC)
    if requested_expires_at is None:
        return resolved.expires_at(now=moment)

    requested = requested_expires_at
    if requested.tzinfo is None:
        requested = requested.replace(tzinfo=UTC)
    if requested <= moment:
        raise ApiKeyPolicyError("requested expiry is already in the past")

    requested_seconds = int((requested - moment).total_seconds())
    if requested_seconds > MAX_TTL_SECONDS:
        raise ApiKeyPolicyError(
            f"requested {requested_seconds}s exceeds the {MAX_TTL_SECONDS}s "
            f"maximum key lifetime"
        )
    if (
        resolved.max_ttl_seconds is not None
        and requested_seconds > resolved.max_ttl_seconds
    ):
        raise ApiKeyPolicyError(
            f"requested {requested_seconds}s exceeds the policy maximum of "
            f"{resolved.max_ttl_seconds}s for this user"
        )
    return requested


# --- Operator CRUD ---------------------------------------------------------


def list_policies(db: Session, *, tenant_id: UUID) -> list[ApiKeyPolicy]:
    return list(
        db.scalars(
            select(ApiKeyPolicy)
            .where(ApiKeyPolicy.tenant_id == tenant_id)
            .order_by(ApiKeyPolicy.principal_kind, ApiKeyPolicy.created_at)
        ).all()
    )


def upsert_policy(
    db: Session,
    *,
    tenant_id: UUID,
    principal_kind: ApiKeyPrincipalKind,
    principal_id: UUID,
    max_ttl_seconds: int,
    note: str | None,
    created_by: UUID,
    actor: AdminAuditActor,
) -> ApiKeyPolicy:
    """Create or update one scope's ceiling. Commits."""

    if max_ttl_seconds <= 0:
        raise ApiKeyPolicyError("max_ttl_seconds must be positive")
    if max_ttl_seconds > MAX_TTL_SECONDS:
        raise ApiKeyPolicyError(
            f"max_ttl_seconds may not exceed {MAX_TTL_SECONDS} (365 days)"
        )
    if principal_kind == ApiKeyPrincipalKind.TENANT and principal_id != tenant_id:
        # The tenant-scope row keys on the tenant id; letting a caller
        # pass anything else would create a second, unreachable default.
        raise ApiKeyPolicyError(
            "a tenant-scope policy must use the tenant's own id"
        )

    existing = db.scalar(
        select(ApiKeyPolicy).where(
            ApiKeyPolicy.tenant_id == tenant_id,
            ApiKeyPolicy.principal_kind == principal_kind.value,
            ApiKeyPolicy.principal_id == principal_id,
        )
    )
    previous = existing.max_ttl_seconds if existing is not None else None
    if existing is not None:
        existing.max_ttl_seconds = max_ttl_seconds
        existing.note = note
        existing.updated_at = datetime.now(UTC)
        row = existing
    else:
        row = ApiKeyPolicy(
            id=uuid4(),
            tenant_id=tenant_id,
            principal_kind=principal_kind,
            principal_id=principal_id,
            max_ttl_seconds=max_ttl_seconds,
            note=note,
            created_by=created_by,
        )
        db.add(row)

    record_admin_action(
        db,
        tenant_id=tenant_id,
        actor=actor,
        action="api_key_policy.set",
        target=AdminAuditTarget(
            kind="api_key_policy", id=principal_id, display=principal_kind.value
        ),
        detail={
            "principal_kind": principal_kind.value,
            "principal_id": str(principal_id),
            "max_ttl_seconds": max_ttl_seconds,
            "previous_max_ttl_seconds": previous,
            "note": note,
        },
    )
    db.commit()
    db.refresh(row)
    return row


def delete_policy(
    db: Session, *, tenant_id: UUID, policy_id: UUID, actor: AdminAuditActor
) -> None:
    """Remove one scope's ceiling. Commits.

    Deleting does NOT lengthen keys already issued — their `expires_at`
    is already stamped. It only changes what the next issuance resolves
    to, which may be a broader scope or unlimited.
    """

    row = db.scalar(
        select(ApiKeyPolicy).where(
            ApiKeyPolicy.tenant_id == tenant_id, ApiKeyPolicy.id == policy_id
        )
    )
    if row is None:
        raise ApiKeyPolicyError("policy not found")
    record_admin_action(
        db,
        tenant_id=tenant_id,
        actor=actor,
        action="api_key_policy.delete",
        target=AdminAuditTarget(
            kind="api_key_policy",
            id=row.principal_id,
            display=str(row.principal_kind),
        ),
        detail={
            "principal_kind": str(row.principal_kind),
            "principal_id": str(row.principal_id),
            "max_ttl_seconds": row.max_ttl_seconds,
        },
    )
    db.delete(row)
    db.commit()


# --- Keys issued before the policy existed ---------------------------------


@dataclass(frozen=True)
class NonConformingKey:
    key_id: UUID
    user_id: UUID
    label: str
    expires_at: datetime | None
    allowed_expires_at: datetime


def find_nonconforming_keys(
    db: Session, *, tenant_id: UUID, now: datetime | None = None
) -> list[NonConformingKey]:
    """Live keys that outlast the ceiling now in force.

    A policy only stamps `expires_at` at issuance, so every key minted
    before the policy existed still carries NULL — the exact keys the
    policy was written to catch. Surfacing them is the difference
    between a rule that applies going forward and one that is actually
    true of the tenant.

    Read-only: nothing here changes a key. See `apply_to_existing_keys`.
    """

    moment = now or datetime.now(UTC)
    keys = list(
        db.scalars(
            select(UserApiKey).where(
                UserApiKey.tenant_id == tenant_id,
                UserApiKey.revoked_at.is_(None),
            )
        ).all()
    )
    out: list[NonConformingKey] = []
    for key in keys:
        resolved = resolve_max_ttl(db, tenant_id=tenant_id, user_id=key.user_id)
        if resolved.max_ttl_seconds is None:
            continue
        allowed = moment + timedelta(seconds=resolved.max_ttl_seconds)
        if key.expires_at is None or key.expires_at > allowed:
            out.append(
                NonConformingKey(
                    key_id=key.id,
                    user_id=key.user_id,
                    label=key.label,
                    expires_at=key.expires_at,
                    allowed_expires_at=allowed,
                )
            )
    return out


def apply_to_existing_keys(
    db: Session,
    *,
    tenant_id: UUID,
    actor: AdminAuditActor,
    now: datetime | None = None,
) -> int:
    """Bring already-issued keys under the current policy. Commits.

    Deliberately an explicit, audited action rather than a side effect of
    saving a policy. Saving a policy is a statement of intent; shortening
    live credentials is an outage for whoever is holding them, and the
    operator should be the one choosing when that lands.

    Keys are shortened to `now + ceiling`, never to the past — the point
    is to bound them, not to break every running agent at once.
    """

    moment = now or datetime.now(UTC)
    affected = find_nonconforming_keys(db, tenant_id=tenant_id, now=moment)
    if not affected:
        return 0
    for item in affected:
        key = db.get(UserApiKey, item.key_id)
        if key is not None:
            key.expires_at = item.allowed_expires_at
    record_admin_action(
        db,
        tenant_id=tenant_id,
        actor=actor,
        action="api_key_policy.apply_existing",
        detail={
            "keys_updated": len(affected),
            "key_ids": [str(item.key_id) for item in affected][:50],
        },
    )
    db.commit()
    return len(affected)
