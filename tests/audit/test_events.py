from uuid import uuid4

from vyuu_gateway.audit.events import (
    AuditDecision,
    AuditDecisionMode,
    AuditPrincipal,
    AuditPrincipalType,
    UpstreamStatus,
    create_tool_call_audit_event,
    summarize_tool_args,
)


def test_summarize_tool_args_records_shape_without_values() -> None:
    summary = summarize_tool_args(
        {
            "api_key": "secret-value",
            "limit": 10,
            "filters": {"region": "us"},
        }
    )

    assert summary == {
        "top_level_keys": ["api_key", "filters", "limit"],
        "fields": {
            "api_key": {"type": "str", "size": 12},
            "filters": {"type": "dict", "size": 1},
            "limit": {"type": "int", "size": None},
        },
    }
    assert "secret-value" not in str(summary)
    assert "us" not in str(summary)


def test_create_tool_call_audit_event_matches_gateway_schema() -> None:
    tenant_id = uuid4()
    upstream_server_id = uuid4()
    event = create_tool_call_audit_event(
        tenant_id=tenant_id,
        gateway_instance_id="gateway-1",
        principal=AuditPrincipal(
            type=AuditPrincipalType.API_KEY,
            id="key-1",
            display="CI agent",
        ),
        upstream_server_id=upstream_server_id,
        tool="query",
        arguments={"sql": "select 1"},
        decision=AuditDecision.ALLOW,
        decision_mode=AuditDecisionMode.ENFORCE,
        upstream_status=UpstreamStatus.OK,
        latency_ms_total=12.5,
        latency_ms_upstream=9.1,
        response_size_bytes=128,
    )

    payload = event.model_dump(mode="json")

    assert payload["tenant_id"] == str(tenant_id)
    assert payload["source_pep"] == "gateway"
    assert payload["gateway_instance_id"] == "gateway-1"
    assert payload["principal"]["type"] == "api_key"
    assert payload["upstream_server_id"] == str(upstream_server_id)
    assert payload["tool"] == "query"
    assert payload["args_summary"]["top_level_keys"] == ["sql"]
    assert payload["decision"] == "allow"
    assert payload["decision_mode"] == "enforce"
    assert payload["upstream_status"] == "ok"
    assert payload["response_size_bytes"] == 128
