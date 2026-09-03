"""SIEM-1 · the hooks that turn existing paths into SIEM events."""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID, uuid4

from vyuu_gateway.audit.admin_audit import (
    AdminAuditActor,
    AdminAuditTarget,
    record_admin_action,
)
from vyuu_gateway.audit.emitter import EmitResult
from vyuu_gateway.audit.events import (
    AuditDecision,
    AuditDecisionMode,
    AuditEvent,
    AuditPrincipal,
    AuditPrincipalType,
    UpstreamStatus,
    create_tool_call_audit_event,
)
from vyuu_gateway.siem import registry
from vyuu_gateway.siem.bridges import (
    PENDING_ADMIN_EVENTS_KEY,
    SiemAuditEmitter,
    SiemLogHandler,
    _discard_pending_admin_events,
    _ship_pending_admin_events,
    record_signin,
    record_tool_auth,
)
from vyuu_gateway.siem.events import (
    AuthMethod,
    AuthOutcome,
    AuthSurface,
    SiemCategory,
    SiemEvent,
    ToolAuthAction,
)


class _RecordingExporter:
    def __init__(self) -> None:
        self.events: list[SiemEvent] = []

    def emit_nowait(self, event: SiemEvent) -> None:
        self.events.append(event)


class _Inner:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        self.events.append(event)
        return EmitResult(accepted=True, durable=True)


def _audit_event() -> AuditEvent:
    return create_tool_call_audit_event(
        tenant_id=uuid4(),
        gateway_instance_id="gw-1",
        principal=AuditPrincipal(type=AuditPrincipalType.API_KEY, id="k"),
        tool="query",
        arguments={},
        decision=AuditDecision.DENY,
        decision_mode=AuditDecisionMode.ENFORCE,
        upstream_status=UpstreamStatus.NOT_CALLED,
    )


def _with_exporter() -> _RecordingExporter:
    exporter = _RecordingExporter()
    registry.set_exporter(exporter)  # type: ignore[arg-type]
    return exporter


def teardown_function() -> None:
    registry.set_exporter(None)


# --- audit chain --------------------------------------------------------------


def test_audit_wrapper_projects_and_delegates_unchanged() -> None:
    exporter = _with_exporter()
    inner = _Inner()
    wrapper = SiemAuditEmitter(inner=inner)
    audit = _audit_event()

    result = wrapper.emit_nowait(audit)

    assert result.accepted and result.durable
    assert inner.events == [audit]
    assert len(exporter.events) == 1
    assert exporter.events[0].category == SiemCategory.TOOL_CALL
    assert exporter.events[0].event_id == audit.event_id


def test_audit_wrapper_without_exporter_is_a_pass_through() -> None:
    registry.set_exporter(None)
    inner = _Inner()
    audit = _audit_event()
    assert SiemAuditEmitter(inner=inner).emit_nowait(audit).accepted
    assert inner.events == [audit]


# --- admin actions: staged, shipped at commit, discarded on rollback ----------


class _FakeSession:
    """Just enough of `Session` for `record_admin_action` + the hooks."""

    def __init__(self) -> None:
        self.info: dict[str, Any] = {}
        self.added: list[Any] = []

    def add(self, row: Any) -> None:
        self.added.append(row)


def test_record_admin_action_stages_an_event_but_ships_nothing_yet() -> None:
    exporter = _with_exporter()
    session = _FakeSession()
    tenant = uuid4()
    record_admin_action(
        session,  # type: ignore[arg-type]
        tenant_id=tenant,
        actor=AdminAuditActor.system("sweeper"),
        action="user.disable",
        target=AdminAuditTarget(kind="user", id=uuid4(), display="bob@example.com"),
        detail={"reason": "left"},
    )
    staged = session.info[PENDING_ADMIN_EVENTS_KEY]
    assert len(staged) == 1
    assert staged[0].category == SiemCategory.ADMIN_ACTION
    assert staged[0].tenant_id == tenant
    assert staged[0].body["action"] == "user.disable"
    assert staged[0].body["actor"] == {"kind": "system", "operator_id": None, "display": "sweeper"}
    assert staged[0].body["target"]["display"] == "bob@example.com"
    assert staged[0].body["detail"] == {"reason": "left"}
    # Not shipped: the transaction has not committed.
    assert exporter.events == []


def test_commit_ships_staged_events_and_rollback_discards_them() -> None:
    exporter = _with_exporter()
    session = _FakeSession()
    record_admin_action(
        session,  # type: ignore[arg-type]
        tenant_id=uuid4(),
        actor=AdminAuditActor.system("x"),
        action="vserver.delete",
    )
    _ship_pending_admin_events(session)  # type: ignore[arg-type]
    assert [e.body["action"] for e in exporter.events] == ["vserver.delete"]
    assert PENDING_ADMIN_EVENTS_KEY not in session.info

    rolled = _FakeSession()
    record_admin_action(
        rolled,  # type: ignore[arg-type]
        tenant_id=uuid4(),
        actor=AdminAuditActor.system("x"),
        action="grant.revoke",
    )
    _discard_pending_admin_events(rolled)  # type: ignore[arg-type]
    _ship_pending_admin_events(rolled)  # type: ignore[arg-type]
    assert [e.body["action"] for e in exporter.events] == ["vserver.delete"]


# --- log handler ----------------------------------------------------------------


def test_log_handler_routes_by_explicit_tenant_id_only() -> None:
    exporter = _with_exporter()
    handler = SiemLogHandler(level=logging.DEBUG)
    logger = logging.getLogger("tests.siem.bridge")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    # `create_app` (run on import of `vyuu_gateway.main` by conftest)
    # installs a root-level handler of the same class; stop propagation
    # so this test counts exactly one delivery per record.
    logger.propagate = False
    try:
        tenant = uuid4()
        logger.warning("with_tenant", extra={"tenant_id": str(tenant)})
        logger.warning("without_tenant")
        logger.warning("bad_tenant", extra={"tenant_id": "not-a-uuid"})
    finally:
        logger.removeHandler(handler)
        logger.propagate = True
    assert [e.tenant_id for e in exporter.events] == [tenant, None, None]
    assert all(e.category == SiemCategory.GATEWAY_LOG for e in exporter.events)


def test_log_handler_ignores_its_own_package_to_avoid_a_feedback_loop() -> None:
    exporter = _with_exporter()
    handler = SiemLogHandler(level=logging.DEBUG)
    logger = logging.getLogger("vyuu_gateway.siem.exporter")
    logger.addHandler(handler)
    logger.propagate = False
    try:
        logger.warning("siem_batch_dropped")
    finally:
        logger.removeHandler(handler)
        logger.propagate = True
    assert exporter.events == []


# --- sign-ins and tool auth -------------------------------------------------------


class _FakeTelemetry:
    def __init__(self) -> None:
        self.logins: list[dict[str, str]] = []

    def record_login(self, **kwargs: Any) -> None:
        self.logins.append({k: str(v) for k, v in kwargs.items()})


class _FakeRequest:
    def __init__(self, telemetry: Any) -> None:
        self.client = type("C", (), {"host": "203.0.113.9"})()
        self.headers = {"user-agent": "Mozilla/5.0"}
        self.app = type("A", (), {"state": type("S", (), {"telemetry": telemetry})()})()


def test_record_signin_emits_an_auth_event_and_a_login_metric() -> None:
    exporter = _with_exporter()
    telemetry = _FakeTelemetry()
    tenant = uuid4()
    record_signin(
        _FakeRequest(telemetry),
        tenant_id=tenant,
        surface=AuthSurface.PORTAL,
        method=AuthMethod.OIDC,
        outcome=AuthOutcome.SUCCESS,
        subject="ada@example.com",
        subject_id=uuid4(),
        directory_id=uuid4(),
        directory_display="Acme · Entra",
    )
    assert len(exporter.events) == 1
    body = exporter.events[0].body
    assert body["surface"] == "portal" and body["method"] == "oidc"
    assert body["outcome"] == "success" and body["subject"] == "ada@example.com"
    assert body["client_ip"] == "203.0.113.9" and body["user_agent"] == "Mozilla/5.0"
    assert body["directory_display"] == "Acme · Entra"
    assert telemetry.logins == [
        {"tenant_id": str(tenant), "surface": "portal", "method": "oidc", "outcome": "success"}
    ]


def test_record_signin_never_raises_without_a_request() -> None:
    exporter = _with_exporter()
    record_signin(
        None,
        tenant_id=uuid4(),
        surface=AuthSurface.OPERATOR,
        method=AuthMethod.PASSWORD,
        outcome=AuthOutcome.FAILURE,
        subject="x@example.com",
        reason="invalid credentials",
    )
    assert exporter.events[0].body["client_ip"] is None


def test_record_tool_auth_emits() -> None:
    exporter = _with_exporter()
    server = uuid4()
    record_tool_auth(
        tenant_id=uuid4(),
        action=ToolAuthAction.CLIENT_INVALIDATED,
        server_id=server,
        reason="as rejected client",
    )
    assert exporter.events[0].category == SiemCategory.TOOL_AUTH
    assert exporter.events[0].body["action"] == "client_invalidated"
    assert exporter.events[0].body["server_id"] == str(server)


def test_registry_emit_is_a_noop_without_an_exporter_and_swallows_errors() -> None:
    registry.set_exporter(None)
    registry.emit(SiemEvent(category=SiemCategory.AUTH, tenant_id=None, body={}))

    class _Boom:
        def emit_nowait(self, event: SiemEvent) -> None:
            raise RuntimeError("no")

    registry.set_exporter(_Boom())  # type: ignore[arg-type]
    registry.emit(SiemEvent(category=SiemCategory.AUTH, tenant_id=None, body={}))


def _unused(_: UUID) -> None:  # keeps the UUID import honest for mypy
    return None
