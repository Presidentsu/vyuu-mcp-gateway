"""JIT-1 · just-in-time (time-boxed) vserver access.

The behaviour that matters is at the DB boundary — expiry semantics,
the auto-approve vs queued split, and the audit trail — so these run
against real Postgres (skipped without `VYUU_TEST_DATABASE_URL`).

The load-bearing claim of the whole feature is
`test_expired_jit_grant_stops_granting_access`: a JIT grant is only
"just in time" if the *inbound enforcement path* stops honouring it the
moment it lapses. That test calls the real
`assert_principal_can_access_vserver` — the same function
`_authenticate_and_authorize` runs on every inbound request — rather
than asserting on a column, so it proves access actually ends.
"""

from __future__ import annotations

import contextlib
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
    AccessRequestStatus,
    AdminAuditActorKind,
    AdminAuditLog,
    GrantPrincipalKind,
    GrantVia,
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
    User,
    UserAuthMethod,
    VirtualServer,
    VirtualServerGrant,
    VirtualServerVisibility,
)
from vyuu_gateway.db.session import bind_tenant_context  # noqa: E402
from vyuu_gateway.identity.models import ApiKeyPrincipal  # noqa: E402
from vyuu_gateway.registry.access_requests_service import (  # noqa: E402
    InvalidApprovalDurationError,
    UserAlreadyHasAccessError,
    VserverIsPublicError,
    approve_access_request,
)
from vyuu_gateway.registry.jit_service import (  # noqa: E402
    JitDurationTooLongError,
    JitJustificationRequiredError,
    JitNotEnabledError,
    configure_vserver_jit,
    list_active_elevations,
    request_jit_access,
)
from vyuu_gateway.virtual_servers.access import (  # noqa: E402
    VirtualServerAccessDeniedError,
    assert_principal_can_access_vserver,
)

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set",
)


# --- Harness ---------------------------------------------------------------


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(
        create_engine(_DATABASE_URL, future=True), autoflush=False, future=True
    )


@contextlib.contextmanager
def _bound(factory: Any, tenant_id: UUID) -> Any:
    """A session with `app.current_tenant_id` set, which every JIT path
    needs: `admin_audit_log` is ENABLE + FORCE RLS, so an unbound INSERT
    is refused outright and an unbound SELECT silently returns nothing.

    The production callers get this from `get_tenant_scoped_db` /
    `get_portal_scoped_db`; the tests have to do it themselves. Reading
    the audit rows through a bound session also matters — an unbound read
    would make every "was it audited?" assertion pass vacuously against
    zero rows.
    """

    with factory() as session:
        bind_tenant_context(session, tenant_id)
        yield session


def _seed_world(
    factory: Any,
    *,
    visibility: VirtualServerVisibility = VirtualServerVisibility.PRIVATE,
    jit_enabled: bool = True,
    jit_auto_approve: bool = False,
    jit_require_justification: bool = True,
    jit_max_duration_seconds: int = 4 * 3600,
) -> tuple[UUID, UUID, UUID, UUID]:
    """tenant + operator + user + vserver with a JIT policy already set."""
    tenant_id, operator_id, user_id, vserver_id = (
        uuid4(), uuid4(), uuid4(), uuid4()
    )
    with _bound(factory, tenant_id) as s:
        s.add(Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED))
        s.add(Operator(
            id=operator_id, tenant_id=tenant_id,
            email=f"op-{operator_id.hex[:6]}@test", role=OperatorRole.ADMIN,
        ))
        s.add(User(
            id=user_id, tenant_id=tenant_id,
            email=f"u-{user_id.hex[:6]}@test",
            auth_method=UserAuthMethod.LOCAL, password_hash="x" * 60,
        ))
        s.add(VirtualServer(
            id=vserver_id, tenant_id=tenant_id,
            name=f"vs-{vserver_id.hex[:6]}", visibility=visibility,
            created_by=operator_id,
            jit_enabled=jit_enabled,
            jit_auto_approve=jit_auto_approve,
            jit_require_justification=jit_require_justification,
            jit_max_duration_seconds=jit_max_duration_seconds,
        ))
        s.commit()
    return tenant_id, operator_id, user_id, vserver_id


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with _bound(factory, tenant_id) as s:
        for table in (
            "access_requests", "admin_audit_log", "virtual_server_grants",
            "user_api_keys", "users", "virtual_server_tools",
            "virtual_servers", "operators",
        ):
            s.execute(
                text(f"DELETE FROM {table} WHERE tenant_id = :id"),
                {"id": tenant_id},
            )
        s.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        s.commit()


def _grants(factory: Any, tenant_id: UUID) -> list[VirtualServerGrant]:
    with _bound(factory, tenant_id) as s:
        return list(s.scalars(
            select(VirtualServerGrant).where(
                VirtualServerGrant.tenant_id == tenant_id
            )
        ).all())


def _audit(factory: Any, tenant_id: UUID, action: str) -> list[AdminAuditLog]:
    with _bound(factory, tenant_id) as s:
        return list(s.scalars(
            select(AdminAuditLog).where(
                AdminAuditLog.tenant_id == tenant_id,
                AdminAuditLog.action == action,
            )
        ).all())


# --- The load-bearing one --------------------------------------------------


def test_expired_jit_grant_stops_granting_access() -> None:
    """The whole point of JIT. Drives the REAL inbound enforcement
    function, not a column check — an elevation that lapses must actually
    end, and it must end without anyone revoking anything."""

    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(
        factory, jit_auto_approve=True
    )
    try:
        with _bound(factory, tenant_id) as s:
            elevation = request_jit_access(
                s, tenant_id=tenant_id, user_id=user_id,
                vserver_id=vserver_id, duration_seconds=3600,
                justification="debugging the prod incident",
            )
        assert elevation.granted is True
        grant_id = elevation.grant.id  # type: ignore[union-attr]

        principal = ApiKeyPrincipal(
            tenant_id=tenant_id, id=str(user_id), display="u", key_id=str(uuid4())
        )

        # While live: the inbound check passes.
        with _bound(factory, tenant_id) as s:
            vserver = s.get(VirtualServer, vserver_id)
            assert vserver is not None
            assert_principal_can_access_vserver(
                s, tenant_id=tenant_id, vserver=vserver, principal=principal
            )

        # Move the expiry into the past — nothing else changes. No
        # revocation, no deletion, no session invalidation.
        with _bound(factory, tenant_id) as s:
            grant = s.get(VirtualServerGrant, grant_id)
            assert grant is not None
            grant.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            s.commit()

        with _bound(factory, tenant_id) as s:
            vserver = s.get(VirtualServer, vserver_id)
            assert vserver is not None
            with pytest.raises(VirtualServerAccessDeniedError):
                assert_principal_can_access_vserver(
                    s, tenant_id=tenant_id, vserver=vserver,
                    principal=principal,
                )
    finally:
        _cleanup(factory, tenant_id)


# --- Auto-approve path -----------------------------------------------------


def test_auto_approve_issues_a_time_boxed_grant_inline() -> None:
    factory = _factory()
    tenant_id, _op, user_id, vserver_id = _seed_world(
        factory, jit_auto_approve=True
    )
    try:
        before = datetime.now(UTC)
        with _bound(factory, tenant_id) as s:
            elevation = request_jit_access(
                s, tenant_id=tenant_id, user_id=user_id,
                vserver_id=vserver_id, duration_seconds=900,
                justification="on-call rotation",
            )
        assert elevation.granted is True
        assert elevation.request is None
        assert elevation.expires_at is not None
        # ~15 minutes out, allowing for clock/round-trip slop.
        delta = (elevation.expires_at - before).total_seconds()
        assert 890 < delta < 960

        grants = _grants(factory, tenant_id)
        assert len(grants) == 1
        g = grants[0]
        assert g.granted_via == GrantVia.JIT_AUTO
        assert g.justification == "on-call rotation"
        assert g.principal_kind == GrantPrincipalKind.USER
        assert g.principal_id == user_id
        # No human decided this, so no human is named.
        assert g.granted_by is None
    finally:
        _cleanup(factory, tenant_id)


def test_auto_approved_elevation_is_audited_with_reason_and_window() -> None:
    """An elevation that is not recorded is indistinguishable, after
    expiry, from access that never happened."""

    factory = _factory()
    tenant_id, _op, user_id, vserver_id = _seed_world(
        factory, jit_auto_approve=True
    )
    try:
        with _bound(factory, tenant_id) as s:
            request_jit_access(
                s, tenant_id=tenant_id, user_id=user_id,
                vserver_id=vserver_id, duration_seconds=1800,
                justification="incident 4471",
            )
        rows = _audit(factory, tenant_id, "grant.jit_issue")
        assert len(rows) == 1
        row = rows[0]
        assert row.actor_kind == AdminAuditActorKind.SYSTEM
        assert row.actor_display == "jit_auto_approve"
        assert row.detail["granted_via"] == "jit_auto"
        assert row.detail["duration_seconds"] == 1800
        assert row.detail["justification"] == "incident 4471"
        assert row.detail["user_id"] == str(user_id)
        assert row.detail["expires_at"]
    finally:
        _cleanup(factory, tenant_id)


# --- Queued path -----------------------------------------------------------


def test_non_auto_approve_queues_a_request_carrying_the_duration() -> None:
    factory = _factory()
    tenant_id, _op, user_id, vserver_id = _seed_world(
        factory, jit_auto_approve=False
    )
    try:
        with _bound(factory, tenant_id) as s:
            elevation = request_jit_access(
                s, tenant_id=tenant_id, user_id=user_id,
                vserver_id=vserver_id, duration_seconds=7200,
                justification="quarterly close",
            )
        assert elevation.granted is False
        assert elevation.grant is None
        assert elevation.request is not None
        assert elevation.request.status == AccessRequestStatus.PENDING
        assert elevation.request.requested_duration_seconds == 7200
        assert elevation.request.note == "quarterly close"
        # Nothing granted until an operator decides.
        assert _grants(factory, tenant_id) == []
    finally:
        _cleanup(factory, tenant_id)


def test_approving_a_jit_request_creates_a_time_boxed_grant() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(factory)
    try:
        with _bound(factory, tenant_id) as s:
            elevation = request_jit_access(
                s, tenant_id=tenant_id, user_id=user_id,
                vserver_id=vserver_id, duration_seconds=3600,
                justification="vendor audit",
            )
        request_id = elevation.request.id  # type: ignore[union-attr]

        with _bound(factory, tenant_id) as s:
            approve_access_request(
                s, tenant_id=tenant_id, request_id=request_id,
                operator_id=operator_id,
                actor=AdminAuditActor.system("test"),
            )

        grants = _grants(factory, tenant_id)
        assert len(grants) == 1
        g = grants[0]
        assert g.granted_via == GrantVia.JIT_APPROVED
        assert g.granted_by == operator_id
        assert g.justification == "vendor audit"
        assert g.expires_at is not None
    finally:
        _cleanup(factory, tenant_id)


def test_approver_can_grant_less_than_was_asked_for() -> None:
    """The common review outcome: "you can have an hour, not a day"."""

    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(
        factory, jit_max_duration_seconds=24 * 3600
    )
    try:
        with _bound(factory, tenant_id) as s:
            elevation = request_jit_access(
                s, tenant_id=tenant_id, user_id=user_id,
                vserver_id=vserver_id, duration_seconds=24 * 3600,
                justification="migration",
            )
        request_id = elevation.request.id  # type: ignore[union-attr]

        before = datetime.now(UTC)
        with _bound(factory, tenant_id) as s:
            approve_access_request(
                s, tenant_id=tenant_id, request_id=request_id,
                operator_id=operator_id, duration_seconds=3600,
                actor=AdminAuditActor.system("test"),
            )
        g = _grants(factory, tenant_id)[0]
        assert g.expires_at is not None
        expires_at = g.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        delta = (expires_at - before).total_seconds()
        assert 3500 < delta < 3700, "approver's 1h should win over the 24h ask"
    finally:
        _cleanup(factory, tenant_id)


def test_approver_cannot_grant_more_than_was_asked_for() -> None:
    """Granting more than requested is never the reviewer's intent — it
    is a typo, and a silent one if allowed."""

    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(
        factory, jit_max_duration_seconds=24 * 3600
    )
    try:
        with _bound(factory, tenant_id) as s:
            elevation = request_jit_access(
                s, tenant_id=tenant_id, user_id=user_id,
                vserver_id=vserver_id, duration_seconds=3600,
                justification="migration",
            )
        request_id = elevation.request.id  # type: ignore[union-attr]
        with _bound(factory, tenant_id) as s, pytest.raises(InvalidApprovalDurationError):
            approve_access_request(
                s, tenant_id=tenant_id, request_id=request_id,
                operator_id=operator_id, duration_seconds=8 * 3600,
                actor=AdminAuditActor.system("test"),
            )
        assert _grants(factory, tenant_id) == []
    finally:
        _cleanup(factory, tenant_id)


def test_plain_non_jit_request_still_gets_standing_access() -> None:
    """Back-compat: a request with no duration behaves exactly as it did
    before JIT existed."""

    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(factory)
    try:
        from vyuu_gateway.registry.access_requests_service import (
            submit_access_request,
        )

        with _bound(factory, tenant_id) as s:
            req = submit_access_request(
                s, tenant_id=tenant_id, user_id=user_id,
                vserver_id=vserver_id, note="please",
            )
        with _bound(factory, tenant_id) as s:
            approve_access_request(
                s, tenant_id=tenant_id, request_id=req.id,
                operator_id=operator_id,
                actor=AdminAuditActor.system("test"),
            )
        g = _grants(factory, tenant_id)[0]
        assert g.expires_at is None, "non-JIT approval must stay standing"
        assert g.granted_via == GrantVia.OPERATOR
    finally:
        _cleanup(factory, tenant_id)


# --- Policy enforcement ----------------------------------------------------


def test_duration_over_the_vserver_ceiling_is_rejected_not_clamped() -> None:
    """A user told "yes" and silently given a quarter of what they asked
    for will plan around access they do not have."""

    factory = _factory()
    tenant_id, _op, user_id, vserver_id = _seed_world(
        factory, jit_auto_approve=True, jit_max_duration_seconds=3600
    )
    try:
        with _bound(factory, tenant_id) as s, pytest.raises(JitDurationTooLongError) as exc:
            request_jit_access(
                s, tenant_id=tenant_id, user_id=user_id,
                vserver_id=vserver_id, duration_seconds=8 * 3600,
                justification="x",
            )
        # The ceiling rides on the error so the caller can retry correctly.
        assert exc.value.max_seconds == 3600
        assert exc.value.requested_seconds == 8 * 3600
        assert _grants(factory, tenant_id) == []
    finally:
        _cleanup(factory, tenant_id)


def test_justification_is_required_when_the_vserver_says_so() -> None:
    factory = _factory()
    tenant_id, _op, user_id, vserver_id = _seed_world(
        factory, jit_auto_approve=True, jit_require_justification=True
    )
    try:
        for blank in (None, "", "   "):
            with _bound(factory, tenant_id) as s, pytest.raises(JitJustificationRequiredError):
                request_jit_access(
                    s, tenant_id=tenant_id, user_id=user_id,
                    vserver_id=vserver_id, duration_seconds=600,
                    justification=blank,
                )
        assert _grants(factory, tenant_id) == []
    finally:
        _cleanup(factory, tenant_id)


def test_jit_disabled_vserver_refuses_elevation() -> None:
    factory = _factory()
    tenant_id, _op, user_id, vserver_id = _seed_world(
        factory, jit_enabled=False
    )
    try:
        with _bound(factory, tenant_id) as s, pytest.raises(JitNotEnabledError):
            request_jit_access(
                s, tenant_id=tenant_id, user_id=user_id,
                vserver_id=vserver_id, duration_seconds=600,
                justification="x",
            )
    finally:
        _cleanup(factory, tenant_id)


def test_user_with_standing_access_cannot_stack_an_elevation() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(
        factory, jit_auto_approve=True
    )
    try:
        with _bound(factory, tenant_id) as s:
            s.add(VirtualServerGrant(
                id=uuid4(), tenant_id=tenant_id, vserver_id=vserver_id,
                principal_kind=GrantPrincipalKind.USER, principal_id=user_id,
                granted_by=operator_id,
            ))
            s.commit()
        with _bound(factory, tenant_id) as s, pytest.raises(UserAlreadyHasAccessError):
            request_jit_access(
                s, tenant_id=tenant_id, user_id=user_id,
                vserver_id=vserver_id, duration_seconds=600,
                justification="x",
            )
    finally:
        _cleanup(factory, tenant_id)


# --- Operator policy surface -----------------------------------------------


def test_jit_cannot_be_enabled_on_a_public_vserver() -> None:
    """A public vserver needs no grant, so there is nothing to elevate
    into — the button would grant access the user already has."""

    factory = _factory()
    tenant_id, operator_id, _user, vserver_id = _seed_world(
        factory, visibility=VirtualServerVisibility.PUBLIC, jit_enabled=False
    )
    try:
        with _bound(factory, tenant_id) as s, pytest.raises(VserverIsPublicError):
            configure_vserver_jit(
                s, tenant_id=tenant_id, vserver_id=vserver_id, enabled=True,
                actor=AdminAuditActor.system("test"),
            )
    finally:
        _cleanup(factory, tenant_id)


def test_configuring_jit_is_audited_both_directions() -> None:
    factory = _factory()
    tenant_id, _op, _user, vserver_id = _seed_world(
        factory, jit_enabled=False
    )
    try:
        with _bound(factory, tenant_id) as s:
            configure_vserver_jit(
                s, tenant_id=tenant_id, vserver_id=vserver_id, enabled=True,
                max_duration_seconds=7200, auto_approve=True,
                actor=AdminAuditActor.system("test"),
            )
            s.commit()
        enabled = _audit(factory, tenant_id, "vserver.jit_enable")
        assert len(enabled) == 1
        assert enabled[0].detail["after"]["jit_max_duration_seconds"] == 7200
        # The configuration an auditor asks about by name.
        assert enabled[0].detail["self_service"] is True

        with _bound(factory, tenant_id) as s:
            configure_vserver_jit(
                s, tenant_id=tenant_id, vserver_id=vserver_id, enabled=False,
                actor=AdminAuditActor.system("test"),
            )
            s.commit()
        assert len(_audit(factory, tenant_id, "vserver.jit_disable")) == 1
    finally:
        _cleanup(factory, tenant_id)


def test_active_elevations_lists_live_grants_and_excludes_lapsed() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(
        factory, jit_auto_approve=True
    )
    try:
        with _bound(factory, tenant_id) as s:
            request_jit_access(
                s, tenant_id=tenant_id, user_id=user_id,
                vserver_id=vserver_id, duration_seconds=3600,
                justification="live one",
            )
        # A lapsed grant and a standing grant — neither is an elevation.
        with _bound(factory, tenant_id) as s:
            s.add(VirtualServerGrant(
                id=uuid4(), tenant_id=tenant_id, vserver_id=vserver_id,
                principal_kind=GrantPrincipalKind.USER, principal_id=uuid4(),
                granted_by=operator_id,
                expires_at=datetime.now(UTC) - timedelta(hours=1),
            ))
            s.add(VirtualServerGrant(
                id=uuid4(), tenant_id=tenant_id, vserver_id=vserver_id,
                principal_kind=GrantPrincipalKind.USER, principal_id=uuid4(),
                granted_by=operator_id,
            ))
            s.commit()

        with _bound(factory, tenant_id) as s:
            live = list_active_elevations(s, tenant_id=tenant_id)
        assert len(live) == 1
        e = live[0]
        assert e.user_id == user_id
        assert e.justification == "live one"
        assert e.granted_via == "jit_auto"
        assert 3500 < e.seconds_remaining <= 3600
        assert e.vserver_name.startswith("vs-")
    finally:
        _cleanup(factory, tenant_id)
