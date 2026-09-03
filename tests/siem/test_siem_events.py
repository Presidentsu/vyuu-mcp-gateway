"""SIEM-1 · event projections: every family lands in one shape."""

from __future__ import annotations

import logging
from uuid import uuid4

from vyuu_gateway.audit.events import (
    AuditDecision,
    AuditDecisionMode,
    AuditPrincipal,
    AuditPrincipalType,
    AuthFailureReason,
    UpstreamStatus,
    create_access_attempt_audit_event,
    create_tool_call_audit_event,
)
from vyuu_gateway.siem.events import (
    AuthMethod,
    AuthOutcome,
    AuthSurface,
    SiemCategory,
    ToolAuthAction,
    auth_event,
    from_audit_event,
    from_log_record,
    heartbeat_event,
    tool_auth_event,
)


def _tool_call(**overrides: object) -> object:
    kwargs: dict[str, object] = {
        "tenant_id": uuid4(),
        "gateway_instance_id": "gw-1",
        "principal": AuditPrincipal(type=AuditPrincipalType.API_KEY, id="k-1", display="Key 1"),
        "tool": "query",
        "arguments": {"sql": "select 1"},
        "decision": AuditDecision.ALLOW,
        "decision_mode": AuditDecisionMode.ENFORCE,
        "upstream_status": UpstreamStatus.OK,
    }
    kwargs.update(overrides)
    return create_tool_call_audit_event(**kwargs)  # type: ignore[arg-type]


def test_tool_call_projects_to_tool_call_category_with_event_identity() -> None:
    audit = _tool_call()
    event = from_audit_event(audit)  # type: ignore[arg-type]
    assert event.category == SiemCategory.TOOL_CALL
    assert event.tenant_id == audit.tenant_id  # type: ignore[attr-defined]
    assert event.event_id == audit.event_id  # type: ignore[attr-defined]
    assert event.timestamp == audit.timestamp  # type: ignore[attr-defined]
    # The envelope carries these; the body must not say them twice.
    assert "event_id" not in event.body
    assert "timestamp" not in event.body
    assert event.body["tool"] == "query"
    assert event.body["decision"] == "allow"
    # Metadata-only by default: the summary, never the values.
    assert event.body["args_summary"]["top_level_keys"] == ["sql"]
    assert "raw_args" not in event.body
    assert event.raw_fields == ()


def test_raw_payloads_are_named_so_a_target_can_strip_them() -> None:
    audit = _tool_call(raw_args={"sql": "select secret"}, raw_response={"rows": [1]})
    event = from_audit_event(audit)  # type: ignore[arg-type]
    assert set(event.raw_fields) == {"raw_args", "raw_response"}
    assert event.body["raw_args"] == {"sql": "select secret"}


def test_access_attempt_projects_to_its_own_category() -> None:
    audit = create_access_attempt_audit_event(
        tenant_id=uuid4(),
        gateway_instance_id="gw-1",
        principal=AuditPrincipal(type=AuditPrincipalType.API_KEY, id="<unknown>"),
        auth_failure_reason=AuthFailureReason.INVALID_BEARER,
        vserver_name="finance",
    )
    event = from_audit_event(audit)
    assert event.category == SiemCategory.ACCESS_ATTEMPT
    assert event.body["auth_failure_reason"] == "invalid_bearer"
    assert event.body["vserver_name"] == "finance"


def test_auth_event_carries_the_subject_on_failure_and_never_a_secret() -> None:
    tenant = uuid4()
    event = auth_event(
        tenant_id=tenant,
        surface=AuthSurface.OPERATOR,
        method=AuthMethod.PASSWORD,
        outcome=AuthOutcome.FAILURE,
        subject="admin@example.com",
        reason="invalid credentials",
        client_ip="10.0.0.5",
        user_agent="curl/8",
    )
    assert event.category == SiemCategory.AUTH
    assert event.tenant_id == tenant
    assert event.body == {
        "surface": "operator",
        "method": "password",
        "outcome": "failure",
        "subject": "admin@example.com",
        "subject_id": None,
        "reason": "invalid credentials",
        "client_ip": "10.0.0.5",
        "user_agent": "curl/8",
        "directory_id": None,
        "directory_display": None,
    }


def test_tool_auth_event_shape() -> None:
    server = uuid4()
    user = uuid4()
    event = tool_auth_event(
        tenant_id=uuid4(),
        action=ToolAuthAction.CONNECTED,
        server_id=server,
        server_display="GitHub",
        user_id=user,
        detail={"scope": "repo"},
    )
    assert event.category == SiemCategory.TOOL_AUTH
    assert event.body["action"] == "connected"
    assert event.body["server_id"] == str(server)
    assert event.body["user_id"] == str(user)
    assert event.body["detail"] == {"scope": "repo"}


def test_log_record_carries_structured_fields_and_level() -> None:
    record = logging.LogRecord(
        name="vyuu_gateway.tool_calls",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="upstream_call_failed",
        args=None,
        exc_info=None,
    )
    record.exc_type = "TimeoutError"
    tenant = uuid4()
    event = from_log_record(record, tenant)
    assert event.category == SiemCategory.GATEWAY_LOG
    assert event.tenant_id == tenant
    assert event.log_level == logging.WARNING
    assert event.body["message"] == "upstream_call_failed"
    assert event.body["level"] == "WARNING"
    assert event.body["exc_type"] == "TimeoutError"


def test_heartbeat_is_tenantless_when_asked() -> None:
    event = heartbeat_event(None, gateway_instance_id="gw-1")
    assert event.category == SiemCategory.HEARTBEAT
    assert event.tenant_id is None
    assert event.body["gateway_instance_id"] == "gw-1"
