"""JIT-2 · per-tool elevation against real Postgres.

The gate itself is covered without a DB in
`tests/tool_calls/test_tool_elevation_gate.py`. These cover what only a
real database can: the RLS-bound checker, the "narrows, never grants"
rule, group elevations, and the one-queue approval path.

The load-bearing one is
`test_elevation_expiry_ends_tool_access_via_the_real_checker`: it drives
the same `DatabaseToolElevationChecker` the inbound gate uses, so an
elevation that lapses genuinely stops opening the tool.
"""

from __future__ import annotations

import os

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

import contextlib  # noqa: E402
from datetime import UTC, datetime, timedelta  # noqa: E402
from typing import Any  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import pytest  # noqa: E402
from sqlalchemy import create_engine, select, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.audit.admin_audit import AdminAuditActor  # noqa: E402
from vyuu_gateway.db.models import (  # noqa: E402
    AccessRequestStatus,
    AdminAuditLog,
    GrantPrincipalKind,
    GrantVia,
    Group,
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
    User,
    UserAuthMethod,
    UserGroupMembership,
    VirtualServer,
    VirtualServerGrant,
    VirtualServerToolGrant,
    VirtualServerVisibility,
)
from vyuu_gateway.db.session import bind_tenant_context  # noqa: E402
from vyuu_gateway.registry.access_requests_service import (  # noqa: E402
    approve_access_request,
)
from vyuu_gateway.registry.jit_service import (  # noqa: E402
    JitDurationTooLongError,
    ToolNotJitEligibleError,
    VserverAccessRequiredError,
    configure_vserver_jit_tools,
    list_active_tool_elevations,
    request_tool_elevation,
)
from vyuu_gateway.virtual_servers.tool_elevation import (  # noqa: E402
    DatabaseToolElevationChecker,
)

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None, reason="VYUU_TEST_DATABASE_URL not set"
)

TOOL = "db_migrate"


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(
        create_engine(_DATABASE_URL, future=True), autoflush=False, future=True
    )


@contextlib.contextmanager
def _bound(factory: Any, tenant_id: UUID) -> Any:
    """`virtual_server_tool_grants` and `admin_audit_log` are both FORCE
    RLS — an unbound INSERT is refused and an unbound SELECT returns
    nothing, which would make "was it audited?" assertions pass
    vacuously against zero rows."""
    with factory() as session:
        bind_tenant_context(session, tenant_id)
        yield session


def _seed(
    factory: Any,
    *,
    jit_tools: dict[str, int] | None = None,
    auto_approve: bool = True,
    require_justification: bool = False,
    with_vserver_grant: bool = True,
) -> tuple[UUID, UUID, UUID, UUID]:
    tenant_id, operator_id, user_id, vserver_id = (
        uuid4(), uuid4(), uuid4(), uuid4()
    )
    with _bound(factory, tenant_id) as s:
        s.add(Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED))
        s.add(Operator(id=operator_id, tenant_id=tenant_id,
                       email=f"op-{operator_id.hex[:6]}@test", role=OperatorRole.ADMIN))
        s.add(User(id=user_id, tenant_id=tenant_id, email=f"u-{user_id.hex[:6]}@test",
                   auth_method=UserAuthMethod.LOCAL, password_hash="x" * 60))
        s.add(VirtualServer(
            id=vserver_id, tenant_id=tenant_id, name=f"vs-{vserver_id.hex[:6]}",
            visibility=VirtualServerVisibility.PRIVATE, created_by=operator_id,
            jit_enabled=False,  # per-tool JIT works with bundle JIT OFF
            jit_auto_approve=auto_approve,
            jit_require_justification=require_justification,
            jit_tools=jit_tools if jit_tools is not None else {TOOL: 1800},
        ))
        if with_vserver_grant:
            s.add(VirtualServerGrant(
                id=uuid4(), tenant_id=tenant_id, vserver_id=vserver_id,
                principal_kind=GrantPrincipalKind.USER, principal_id=user_id,
                granted_by=operator_id,
            ))
        s.commit()
    return tenant_id, operator_id, user_id, vserver_id


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as s:
        for table in (
            "access_requests", "admin_audit_log", "virtual_server_tool_grants",
            "virtual_server_grants", "user_api_keys", "groups",
            "users", "virtual_server_tools", "virtual_servers", "operators",
        ):
            if table == "groups":
                s.execute(text(
                    "DELETE FROM user_group_memberships WHERE user_id IN "
                    "(SELECT id FROM users WHERE tenant_id = :id)"), {"id": tenant_id})
            s.execute(text(f"DELETE FROM {table} WHERE tenant_id = :id"), {"id": tenant_id})
        s.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        s.commit()


def _tool_grants(factory: Any, tenant_id: UUID) -> list[VirtualServerToolGrant]:
    with _bound(factory, tenant_id) as s:
        return list(s.scalars(select(VirtualServerToolGrant).where(
            VirtualServerToolGrant.tenant_id == tenant_id)).all())


# --- The load-bearing one ---------------------------------------------------


def test_elevation_expiry_ends_tool_access_via_the_real_checker() -> None:
    """Drives `DatabaseToolElevationChecker` — the same object the inbound
    gate consults — so this proves tool access actually ends, not merely
    that a column moved."""

    factory = _factory()
    tenant_id, _op, user_id, vserver_id = _seed(factory)
    try:
        with _bound(factory, tenant_id) as s:
            request_tool_elevation(
                s, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id,
                exposed_tool_name=TOOL, duration_seconds=900,
                justification="migration window",
            )
        checker = DatabaseToolElevationChecker(factory)
        assert checker.has_active_tool_elevation(
            tenant_id=tenant_id, vserver_id=vserver_id,
            exposed_tool_name=TOOL, principal_id=str(user_id),
        ) is True

        # Move the expiry into the past. No revocation, no deletion.
        grant = _tool_grants(factory, tenant_id)[0]
        with _bound(factory, tenant_id) as s:
            row = s.get(VirtualServerToolGrant, grant.id)
            assert row is not None
            row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            s.commit()

        assert checker.has_active_tool_elevation(
            tenant_id=tenant_id, vserver_id=vserver_id,
            exposed_tool_name=TOOL, principal_id=str(user_id),
        ) is False
    finally:
        _cleanup(factory, tenant_id)


def test_elevation_is_scoped_to_the_exact_tool() -> None:
    """An elevation into `db_migrate` must not open `db_drop`. This is the
    entire point of per-tool granularity."""

    factory = _factory()
    tenant_id, _op, user_id, vserver_id = _seed(
        factory, jit_tools={TOOL: 1800, "db_drop": 600}
    )
    try:
        with _bound(factory, tenant_id) as s:
            request_tool_elevation(
                s, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id,
                exposed_tool_name=TOOL, duration_seconds=600,
            )
        checker = DatabaseToolElevationChecker(factory)
        kw = {
            "tenant_id": tenant_id,
            "vserver_id": vserver_id,
            "principal_id": str(user_id),
        }
        assert checker.has_active_tool_elevation(exposed_tool_name=TOOL, **kw) is True
        assert checker.has_active_tool_elevation(
            exposed_tool_name="db_drop", **kw) is False
    finally:
        _cleanup(factory, tenant_id)


def test_elevation_is_tenant_scoped() -> None:
    factory = _factory()
    tenant_a, _op_a, user_a, vs_a = _seed(factory)
    tenant_b, _op_b, _user_b, vs_b = _seed(factory)
    try:
        with _bound(factory, tenant_a) as s:
            request_tool_elevation(
                s, tenant_id=tenant_a, user_id=user_a, vserver_id=vs_a,
                exposed_tool_name=TOOL, duration_seconds=600,
            )
        checker = DatabaseToolElevationChecker(factory)
        assert checker.has_active_tool_elevation(
            tenant_id=tenant_a, vserver_id=vs_a,
            exposed_tool_name=TOOL, principal_id=str(user_a)) is True
        # Tenant B's checker must not see tenant A's elevation.
        assert checker.has_active_tool_elevation(
            tenant_id=tenant_b, vserver_id=vs_a,
            exposed_tool_name=TOOL, principal_id=str(user_a)) is False
    finally:
        _cleanup(factory, tenant_a)
        _cleanup(factory, tenant_b)


# --- Narrows, never grants ---------------------------------------------------


def test_elevation_requires_existing_vserver_access() -> None:
    """The locked JIT-2 decision. A tool elevation narrows access; letting
    it imply vserver access would create a second path to the same
    resource, and "how did they get in?" would stop having one answer."""

    factory = _factory()
    tenant_id, _op, user_id, vserver_id = _seed(factory, with_vserver_grant=False)
    try:
        with _bound(factory, tenant_id) as s, pytest.raises(VserverAccessRequiredError):
            request_tool_elevation(
                s, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id,
                exposed_tool_name=TOOL, duration_seconds=600,
            )
        assert _tool_grants(factory, tenant_id) == []
    finally:
        _cleanup(factory, tenant_id)


def test_tool_not_in_jit_tools_is_refused() -> None:
    factory = _factory()
    tenant_id, _op, user_id, vserver_id = _seed(factory, jit_tools={TOOL: 600})
    try:
        with _bound(factory, tenant_id) as s, pytest.raises(ToolNotJitEligibleError):
            request_tool_elevation(
                s, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id,
                exposed_tool_name="something_else", duration_seconds=60,
            )
    finally:
        _cleanup(factory, tenant_id)


def test_duration_over_the_per_tool_ceiling_is_rejected_not_clamped() -> None:
    factory = _factory()
    tenant_id, _op, user_id, vserver_id = _seed(factory, jit_tools={TOOL: 600})
    try:
        with _bound(factory, tenant_id) as s, pytest.raises(JitDurationTooLongError) as exc:
            request_tool_elevation(
                s, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id,
                exposed_tool_name=TOOL, duration_seconds=3600,
            )
        assert exc.value.max_seconds == 600
        assert _tool_grants(factory, tenant_id) == []
    finally:
        _cleanup(factory, tenant_id)


# --- Groups ------------------------------------------------------------------


def test_group_elevation_applies_to_members() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed(factory)
    try:
        group_id = uuid4()
        with _bound(factory, tenant_id) as s:
            s.add(Group(id=group_id, tenant_id=tenant_id, name="dba",
                        created_by=operator_id))
            s.flush()
            s.add(UserGroupMembership(user_id=user_id, group_id=group_id,
                                      added_by=operator_id))
            s.add(VirtualServerToolGrant(
                id=uuid4(), tenant_id=tenant_id, vserver_id=vserver_id,
                exposed_tool_name=TOOL,
                principal_kind=GrantPrincipalKind.GROUP, principal_id=group_id,
                granted_by=operator_id, granted_via=GrantVia.OPERATOR,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            ))
            s.commit()

        checker = DatabaseToolElevationChecker(factory)
        assert checker.has_active_tool_elevation(
            tenant_id=tenant_id, vserver_id=vserver_id,
            exposed_tool_name=TOOL, principal_id=str(user_id)) is True

        # A non-member gets nothing from it.
        assert checker.has_active_tool_elevation(
            tenant_id=tenant_id, vserver_id=vserver_id,
            exposed_tool_name=TOOL, principal_id=str(uuid4())) is False
    finally:
        _cleanup(factory, tenant_id)


# --- Audit + operator surfaces ----------------------------------------------


def test_elevation_is_audited_naming_the_tool() -> None:
    factory = _factory()
    tenant_id, _op, user_id, vserver_id = _seed(factory)
    try:
        with _bound(factory, tenant_id) as s:
            request_tool_elevation(
                s, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id,
                exposed_tool_name=TOOL, duration_seconds=900,
                justification="incident 77",
            )
        with _bound(factory, tenant_id) as s:
            rows = list(s.scalars(select(AdminAuditLog).where(
                AdminAuditLog.tenant_id == tenant_id,
                AdminAuditLog.action == "grant.tool_elevation")).all())
        assert len(rows) == 1
        assert rows[0].target_kind == "tool"
        assert rows[0].target_display.endswith(f"/{TOOL}")
        assert rows[0].detail["exposed_tool_name"] == TOOL
        assert rows[0].detail["justification"] == "incident 77"
        assert rows[0].detail["granted_via"] == "jit_auto"
    finally:
        _cleanup(factory, tenant_id)


def test_configuring_jit_tools_audits_the_delta() -> None:
    """"Which tools became gated" and "which stopped" are the two
    questions an auditor asks; diffing two JSON maps in a log viewer is
    miserable, so the audit row spells both out."""

    factory = _factory()
    tenant_id, _op, _user, vserver_id = _seed(factory, jit_tools={TOOL: 600})
    try:
        with _bound(factory, tenant_id) as s:
            configure_vserver_jit_tools(
                s, tenant_id=tenant_id, vserver_id=vserver_id,
                jit_tools={"db_drop": 300}, actor=AdminAuditActor.system("t"),
            )
            s.commit()
        with _bound(factory, tenant_id) as s:
            row = s.scalars(select(AdminAuditLog).where(
                AdminAuditLog.tenant_id == tenant_id,
                AdminAuditLog.action == "vserver.jit_tools_set")).one()
        assert row.detail["newly_gated"] == ["db_drop"]
        assert row.detail["no_longer_gated"] == [TOOL]
    finally:
        _cleanup(factory, tenant_id)


def test_queued_tool_request_is_approved_into_a_tool_grant() -> None:
    """One approval queue for both granularities: an approve on a request
    naming a tool must create a TOOL elevation, not a vserver grant."""

    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed(
        factory, auto_approve=False
    )
    try:
        with _bound(factory, tenant_id) as s:
            elevation = request_tool_elevation(
                s, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id,
                exposed_tool_name=TOOL, duration_seconds=1200,
                justification="scheduled maintenance",
            )
        assert elevation.granted is False
        request_id = elevation.request.id  # type: ignore[union-attr]
        assert elevation.request.exposed_tool_name == TOOL  # type: ignore[union-attr]

        with _bound(factory, tenant_id) as s:
            approved = approve_access_request(
                s, tenant_id=tenant_id, request_id=request_id,
                operator_id=operator_id, duration_seconds=600,
                actor=AdminAuditActor.system("t"),
            )
        assert approved.status == AccessRequestStatus.APPROVED
        # A tool grant, and NOT a second vserver grant.
        grants = _tool_grants(factory, tenant_id)
        assert len(grants) == 1
        assert grants[0].exposed_tool_name == TOOL
        assert grants[0].granted_via == GrantVia.JIT_APPROVED
        assert grants[0].granted_by == operator_id
        with _bound(factory, tenant_id) as s:
            vserver_grants = list(s.scalars(select(VirtualServerGrant).where(
                VirtualServerGrant.tenant_id == tenant_id)).all())
        assert len(vserver_grants) == 1, "approval must not mint a vserver grant"
        # `created_grant_id` FKs virtual_server_grants; pointing it at a
        # tool-grant id would be a dangling reference that looks valid.
        assert approved.created_grant_id is None
    finally:
        _cleanup(factory, tenant_id)


def test_active_tool_elevations_lists_live_and_excludes_lapsed() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed(factory)
    try:
        with _bound(factory, tenant_id) as s:
            request_tool_elevation(
                s, tenant_id=tenant_id, user_id=user_id, vserver_id=vserver_id,
                exposed_tool_name=TOOL, duration_seconds=1200,
                justification="live",
            )
            s.add(VirtualServerToolGrant(
                id=uuid4(), tenant_id=tenant_id, vserver_id=vserver_id,
                exposed_tool_name="db_drop",
                principal_kind=GrantPrincipalKind.USER, principal_id=uuid4(),
                granted_by=operator_id,
                expires_at=datetime.now(UTC) - timedelta(hours=1),
            ))
            s.commit()

        with _bound(factory, tenant_id) as s:
            live = list_active_tool_elevations(s, tenant_id=tenant_id)
        assert len(live) == 1
        assert live[0].exposed_tool_name == TOOL
        assert live[0].justification == "live"
        assert 1100 < live[0].seconds_remaining <= 1200
    finally:
        _cleanup(factory, tenant_id)


# --- HTTP surface ----------------------------------------------------------
#
# The service-layer tests above cannot see the endpoint's response shape,
# and that is exactly where the `grant_id` bug lived: the elevation was
# created correctly and the operator listing showed its id, while the
# caller who had just created it received `granted: true` with
# `grant_id: null` and nothing to reference it by. Same lesson as the
# workspace-polling 500 — endpoints need endpoint tests.

_PORTAL_SECRET = "portal-secret-for-jit-tool-elevation-tests-0123"


def _elevation_client() -> Any:
    from fastapi.testclient import TestClient

    from vyuu_gateway.config import Settings
    from vyuu_gateway.main import create_app

    return TestClient(create_app(Settings(
        app_name="jit-tool-elevation-api", environment="test",
        log_level="CRITICAL", version="t",
        operator_auth_signing_secret="operator-secret-0123456789abcdef-xyz",
        portal_session_signing_secret=_PORTAL_SECRET,
    )))


def _portal_headers(tenant_id: UUID, user_id: UUID) -> dict[str, str]:
    from vyuu_gateway.users.sessions import issue_portal_session

    return {"Authorization": "Bearer " + issue_portal_session(
        tenant_id=tenant_id, user_id=user_id, email="u@test",
        auth_method="local", signing_secret=_PORTAL_SECRET, ttl_seconds=3600,
    )}


def test_granted_elevation_response_carries_the_grant_id() -> None:
    factory = _factory()
    tenant_id, _op, user_id, vserver_id = _seed(factory, jit_tools={TOOL: 1800})
    try:
        response = _elevation_client().post(
            f"/api/v1/portal/{tenant_id}/tool-elevations",
            headers=_portal_headers(tenant_id, user_id),
            json={
                "vserver_id": str(vserver_id),
                "exposed_tool_name": TOOL,
                "duration_seconds": 600,
                "justification": "incident triage",
            },
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["granted"] is True
        assert body["grant_id"] is not None, (
            "an auto-approved caller got `granted: true` with nothing to "
            "reference the grant by"
        )
        assert body["expires_at"] is not None

        # The id must be real, not merely non-null.
        with _bound(factory, tenant_id) as s:
            grant = s.get(VirtualServerToolGrant, UUID(body["grant_id"]))
            assert grant is not None
            assert grant.exposed_tool_name == TOOL
            assert grant.principal_id == user_id
    finally:
        _cleanup(factory, tenant_id)


def test_queued_elevation_returns_a_request_id_and_no_grant_id() -> None:
    """Negative control: when approval is required there IS no grant
    yet, so null is the correct answer rather than a missing one."""

    factory = _factory()
    tenant_id, _op, user_id, vserver_id = _seed(
        factory, jit_tools={TOOL: 1800}, auto_approve=False
    )
    try:
        response = _elevation_client().post(
            f"/api/v1/portal/{tenant_id}/tool-elevations",
            headers=_portal_headers(tenant_id, user_id),
            json={
                "vserver_id": str(vserver_id),
                "exposed_tool_name": TOOL,
                "duration_seconds": 600,
            },
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["granted"] is False
        assert body["grant_id"] is None
        assert body["request_id"] is not None
    finally:
        _cleanup(factory, tenant_id)
