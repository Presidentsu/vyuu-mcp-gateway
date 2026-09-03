"""CRED-1 · API-key lifetime policy.

The feature exists because `user_api_keys.expires_at` was always
enforced and never set, so a user key lived until somebody remembered to
revoke it. These tests pin the resolution order, and in particular the
direction group policies compose in.

Real Postgres: resolution reads group membership and the policy table.
"""

from __future__ import annotations

import os

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

from datetime import UTC, datetime, timedelta  # noqa: E402
from typing import Any  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import pytest  # noqa: E402
from sqlalchemy import create_engine, select, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.audit.admin_audit import AdminAuditActor  # noqa: E402
from vyuu_gateway.db.models import (  # noqa: E402
    AdminAuditLog,
    ApiKeyPrincipalKind,
    Group,
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
    User,
    UserApiKey,
    UserAuthMethod,
    UserGroupMembership,
)
from vyuu_gateway.db.session import bind_tenant_context  # noqa: E402
from vyuu_gateway.registry.api_key_policy_service import (  # noqa: E402
    ApiKeyPolicyError,
    apply_to_existing_keys,
    delete_policy,
    enforce_requested_expiry,
    find_nonconforming_keys,
    list_policies,
    resolve_max_ttl,
    upsert_policy,
)

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None, reason="VYUU_TEST_DATABASE_URL not set"
)

HOUR = 3600
DAY = 24 * HOUR


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(
        create_engine(_DATABASE_URL, future=True), autoflush=False, future=True
    )


def _seed(factory: Any) -> tuple[UUID, UUID, UUID]:
    tenant_id, operator_id, user_id = uuid4(), uuid4(), uuid4()
    with factory() as s:
        s.add(Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED))
        s.commit()
    with factory() as s:
        bind_tenant_context(s, tenant_id)
        s.add(Operator(id=operator_id, tenant_id=tenant_id,
                       email=f"op-{operator_id.hex[:6]}@test", role=OperatorRole.ADMIN))
        s.add(User(id=user_id, tenant_id=tenant_id, email=f"u-{user_id.hex[:6]}@test",
                   auth_method=UserAuthMethod.LOCAL, password_hash="x" * 60))
        s.commit()
    return tenant_id, operator_id, user_id


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as s:
        # Memberships have no tenant column; clear them via their group.
        s.execute(text(
            "DELETE FROM user_group_memberships WHERE group_id IN "
            "(SELECT id FROM groups WHERE tenant_id = :i)"), {"i": tenant_id})
        for table in ("api_key_policies", "user_api_keys",
                      "admin_audit_log", "groups", "users", "operators"):
            s.execute(text(f"DELETE FROM {table} WHERE tenant_id = :i"), {"i": tenant_id})
        s.execute(text("DELETE FROM tenants WHERE id = :i"), {"i": tenant_id})
        s.commit()


def _actor(operator_id: UUID) -> AdminAuditActor:
    # `operator()` wants an AuthenticatedOperator off a request; these
    # are service-level tests with no request in play.
    return AdminAuditActor.system(f"test-operator-{operator_id.hex[:6]}")


def _add_group(factory: Any, tenant_id: UUID, user_id: UUID, name: str,
               *, created_by: UUID) -> UUID:
    group_id = uuid4()
    with factory() as s:
        bind_tenant_context(s, tenant_id)
        s.add(Group(id=group_id, tenant_id=tenant_id, name=name,
                    created_by=created_by))
        # No tenant_id on this table — scoped through `groups`.
        s.add(UserGroupMembership(user_id=user_id, group_id=group_id,
                                  added_by=created_by))
        s.commit()
    return group_id


def _set(factory: Any, tenant_id: UUID, operator_id: UUID, *,
         kind: ApiKeyPrincipalKind, pid: UUID, ttl: int) -> None:
    with factory() as s:
        bind_tenant_context(s, tenant_id)
        upsert_policy(s, tenant_id=tenant_id, principal_kind=kind, principal_id=pid,
                      max_ttl_seconds=ttl, note=None, created_by=operator_id,
                      actor=_actor(operator_id))


# --- resolution order ------------------------------------------------------


def test_no_policy_is_unlimited() -> None:
    """The pre-existing behaviour. A tenant that has not adopted this
    must keep working, and 'unlimited' has to be reported as such rather
    than as some number."""

    factory = _factory()
    tenant_id, _op, user_id = _seed(factory)
    try:
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            resolved = resolve_max_ttl(s, tenant_id=tenant_id, user_id=user_id)
        assert resolved.is_unlimited
        assert resolved.max_ttl_seconds is None
        assert resolved.expires_at() is None
    finally:
        _cleanup(factory, tenant_id)


def test_tenant_policy_applies_when_nothing_more_specific_exists() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id = _seed(factory)
    try:
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.TENANT, pid=tenant_id, ttl=30 * DAY)
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            resolved = resolve_max_ttl(s, tenant_id=tenant_id, user_id=user_id)
        assert resolved.max_ttl_seconds == 30 * DAY
        assert resolved.source_kind == ApiKeyPrincipalKind.TENANT
    finally:
        _cleanup(factory, tenant_id)


def test_group_policy_beats_tenant() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id = _seed(factory)
    try:
        group_id = _add_group(factory, tenant_id, user_id, "contractors", created_by=operator_id)
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.TENANT, pid=tenant_id, ttl=30 * DAY)
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.GROUP, pid=group_id, ttl=7 * DAY)
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            resolved = resolve_max_ttl(s, tenant_id=tenant_id, user_id=user_id)
        assert resolved.max_ttl_seconds == 7 * DAY
        assert resolved.source_kind == ApiKeyPrincipalKind.GROUP
        assert resolved.source_id == group_id
    finally:
        _cleanup(factory, tenant_id)


def test_user_policy_beats_group_even_when_longer() -> None:
    """The per-user policy is the exception mechanism, so it has to win
    in both directions — otherwise there is no way to grant a documented
    carve-out and the admin works around it by loosening the group."""

    factory = _factory()
    tenant_id, operator_id, user_id = _seed(factory)
    try:
        group_id = _add_group(factory, tenant_id, user_id, "contractors", created_by=operator_id)
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.GROUP, pid=group_id, ttl=7 * DAY)
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.USER, pid=user_id, ttl=90 * DAY)
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            resolved = resolve_max_ttl(s, tenant_id=tenant_id, user_id=user_id)
        assert resolved.max_ttl_seconds == 90 * DAY
        assert resolved.source_kind == ApiKeyPrincipalKind.USER
    finally:
        _cleanup(factory, tenant_id)


def test_the_shortest_group_policy_wins_not_the_longest() -> None:
    """The security property.

    If the longest won, joining a group would extend your own credential
    lifetime — group membership would become a privilege escalation, and
    an admin adding someone to a group for one reason would silently be
    granting another. Membership must only ever tighten.
    """

    factory = _factory()
    tenant_id, operator_id, user_id = _seed(factory)
    try:
        strict = _add_group(factory, tenant_id, user_id, "contractors", created_by=operator_id)
        loose = _add_group(factory, tenant_id, user_id, "engineering", created_by=operator_id)
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.GROUP, pid=strict, ttl=1 * DAY)
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.GROUP, pid=loose, ttl=60 * DAY)
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            resolved = resolve_max_ttl(s, tenant_id=tenant_id, user_id=user_id)
        assert resolved.max_ttl_seconds == 1 * DAY, (
            "joining a second group must not be able to lengthen a key"
        )
        assert resolved.source_id == strict
    finally:
        _cleanup(factory, tenant_id)


def test_a_group_policy_the_user_is_not_in_does_not_apply() -> None:
    """Negative control for the test above — it must be asserting
    membership, not just picking the smallest row in the table."""

    factory = _factory()
    tenant_id, operator_id, user_id = _seed(factory)
    try:
        mine = _add_group(factory, tenant_id, user_id, "engineering", created_by=operator_id)
        other_group_id = uuid4()
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            s.add(Group(id=other_group_id, tenant_id=tenant_id, name="someone-else",
                        created_by=operator_id))
            s.commit()
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.GROUP, pid=mine, ttl=60 * DAY)
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.GROUP, pid=other_group_id, ttl=1 * HOUR)
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            resolved = resolve_max_ttl(s, tenant_id=tenant_id, user_id=user_id)
        assert resolved.max_ttl_seconds == 60 * DAY
    finally:
        _cleanup(factory, tenant_id)


# --- requested lifetimes ---------------------------------------------------


def test_a_shorter_request_is_honoured() -> None:
    """A ceiling is a maximum, not a mandate — asking for one hour under
    a 30-day policy should give one hour."""

    from vyuu_gateway.registry.api_key_policy_service import ResolvedTtl

    now = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    resolved = ResolvedTtl(30 * DAY, ApiKeyPrincipalKind.TENANT, uuid4())
    wanted = now + timedelta(hours=1)
    assert enforce_requested_expiry(resolved, wanted, now=now) == wanted


def test_a_longer_request_is_refused_naming_both_numbers() -> None:
    """Rejected, not clamped. Silently shortening hands back a
    credential that dies earlier than the caller was told."""

    from vyuu_gateway.registry.api_key_policy_service import ResolvedTtl

    now = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    resolved = ResolvedTtl(7 * DAY, ApiKeyPrincipalKind.TENANT, uuid4())
    with pytest.raises(ApiKeyPolicyError) as excinfo:
        enforce_requested_expiry(resolved, now + timedelta(days=30), now=now)
    message = str(excinfo.value)
    assert str(7 * DAY) in message and str(30 * DAY) in message


def test_no_request_takes_the_policy_ceiling() -> None:
    from vyuu_gateway.registry.api_key_policy_service import ResolvedTtl

    now = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    resolved = ResolvedTtl(2 * HOUR, ApiKeyPrincipalKind.USER, uuid4())
    assert enforce_requested_expiry(resolved, None, now=now) == now + timedelta(hours=2)


def test_unlimited_policy_still_allows_a_bounded_request() -> None:
    from vyuu_gateway.registry.api_key_policy_service import ResolvedTtl

    now = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    unlimited = ResolvedTtl(None, None, None)
    assert enforce_requested_expiry(unlimited, None, now=now) is None
    wanted = now + timedelta(days=3)
    assert enforce_requested_expiry(unlimited, wanted, now=now) == wanted


def test_expiry_in_the_past_is_refused() -> None:
    from vyuu_gateway.registry.api_key_policy_service import ResolvedTtl

    now = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    with pytest.raises(ApiKeyPolicyError):
        enforce_requested_expiry(
            ResolvedTtl(None, None, None), now - timedelta(hours=1), now=now
        )


# --- CRUD + audit ----------------------------------------------------------


def test_upsert_replaces_rather_than_duplicating_and_audits_the_delta() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id = _seed(factory)
    try:
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.USER, pid=user_id, ttl=30 * DAY)
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.USER, pid=user_id, ttl=1 * DAY)
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            rows = list_policies(s, tenant_id=tenant_id)
            assert len(rows) == 1
            assert rows[0].max_ttl_seconds == 1 * DAY

            audits = list(s.scalars(select(AdminAuditLog).where(
                AdminAuditLog.tenant_id == tenant_id,
                AdminAuditLog.action == "api_key_policy.set")).all())
            assert len(audits) == 2
            tightened = [a for a in audits
                         if a.detail.get("previous_max_ttl_seconds") == 30 * DAY]
            assert len(tightened) == 1, "the change has to record what it replaced"
            assert tightened[0].detail["max_ttl_seconds"] == 1 * DAY
    finally:
        _cleanup(factory, tenant_id)


def test_a_tenant_policy_must_use_the_tenant_id() -> None:
    """Otherwise a second, unreachable default row appears and the
    tenant silently has no policy."""

    factory = _factory()
    tenant_id, operator_id, _user = _seed(factory)
    try:
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            with pytest.raises(ApiKeyPolicyError):
                upsert_policy(
                    s, tenant_id=tenant_id,
                    principal_kind=ApiKeyPrincipalKind.TENANT,
                    principal_id=uuid4(), max_ttl_seconds=DAY, note=None,
                    created_by=operator_id, actor=_actor(operator_id))
    finally:
        _cleanup(factory, tenant_id)


def test_delete_falls_back_to_the_broader_scope() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id = _seed(factory)
    try:
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.TENANT, pid=tenant_id, ttl=30 * DAY)
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.USER, pid=user_id, ttl=1 * HOUR)
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            user_row = next(p for p in list_policies(s, tenant_id=tenant_id)
                            if p.principal_kind == ApiKeyPrincipalKind.USER.value)
            delete_policy(s, tenant_id=tenant_id, policy_id=user_row.id,
                          actor=_actor(operator_id))
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            resolved = resolve_max_ttl(s, tenant_id=tenant_id, user_id=user_id)
        assert resolved.max_ttl_seconds == 30 * DAY
    finally:
        _cleanup(factory, tenant_id)


# --- keys issued before the policy existed ---------------------------------


def _add_key(factory: Any, tenant_id: UUID, user_id: UUID, *, label: str,
             expires_at: datetime | None) -> UUID:
    key_id = uuid4()
    with factory() as s:
        bind_tenant_context(s, tenant_id)
        s.add(UserApiKey(id=key_id, tenant_id=tenant_id, user_id=user_id,
                         label=label, key_hash="h" * 60, key_prefix=label[:8],
                         expires_at=expires_at))
        s.commit()
    return key_id


def test_never_expiring_keys_are_reported_as_nonconforming() -> None:
    """These are exactly the keys the policy was written to catch — the
    ones minted before it existed, carrying NULL forever."""

    factory = _factory()
    tenant_id, operator_id, user_id = _seed(factory)
    try:
        forever = _add_key(factory, tenant_id, user_id, label="legacy",
                           expires_at=None)
        soon = _add_key(factory, tenant_id, user_id, label="short",
                        expires_at=datetime.now(UTC) + timedelta(minutes=30))
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.TENANT, pid=tenant_id, ttl=7 * DAY)
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            found = find_nonconforming_keys(s, tenant_id=tenant_id)
        ids = {item.key_id for item in found}
        assert forever in ids
        assert soon not in ids, "a key already inside the ceiling is conforming"
    finally:
        _cleanup(factory, tenant_id)


def test_applying_bounds_existing_keys_without_expiring_them_immediately() -> None:
    """Shortened to now + ceiling, not to the past. The point is to bound
    them, not to break every running agent the moment an admin saves."""

    factory = _factory()
    tenant_id, operator_id, user_id = _seed(factory)
    try:
        key_id = _add_key(factory, tenant_id, user_id, label="legacy",
                          expires_at=None)
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.TENANT, pid=tenant_id, ttl=7 * DAY)
        before = datetime.now(UTC)
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            count = apply_to_existing_keys(s, tenant_id=tenant_id,
                                           actor=_actor(operator_id))
        assert count == 1
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            key = s.get(UserApiKey, key_id)
            assert key is not None and key.expires_at is not None
            assert key.expires_at > before, "must not expire the key retroactively"
            assert key.expires_at <= before + timedelta(seconds=7 * DAY + 60)

            audit = s.scalar(select(AdminAuditLog).where(
                AdminAuditLog.tenant_id == tenant_id,
                AdminAuditLog.action == "api_key_policy.apply_existing"))
            assert audit is not None
            assert audit.detail["keys_updated"] == 1
    finally:
        _cleanup(factory, tenant_id)


def test_applying_is_idempotent() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id = _seed(factory)
    try:
        _add_key(factory, tenant_id, user_id, label="legacy", expires_at=None)
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.TENANT, pid=tenant_id, ttl=7 * DAY)
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            assert apply_to_existing_keys(s, tenant_id=tenant_id,
                                          actor=_actor(operator_id)) == 1
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            assert apply_to_existing_keys(s, tenant_id=tenant_id,
                                          actor=_actor(operator_id)) == 0
    finally:
        _cleanup(factory, tenant_id)


def test_revoked_keys_are_left_alone() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id = _seed(factory)
    try:
        key_id = _add_key(factory, tenant_id, user_id, label="dead", expires_at=None)
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            key = s.get(UserApiKey, key_id)
            assert key is not None
            key.revoked_at = datetime.now(UTC)
            s.commit()
        _set(factory, tenant_id, operator_id,
             kind=ApiKeyPrincipalKind.TENANT, pid=tenant_id, ttl=7 * DAY)
        with factory() as s:
            bind_tenant_context(s, tenant_id)
            assert find_nonconforming_keys(s, tenant_id=tenant_id) == []
    finally:
        _cleanup(factory, tenant_id)
