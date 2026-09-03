import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

# H5 · per-payload byte cap for raw args / response capture in audit
# events. Default chosen as a reasonable forensic ceiling; operators
# tune via `Settings.audit_raw_capture_byte_cap` (env:
# `VYUU_AUDIT_RAW_CAPTURE_BYTE_CAP`).
#
# IMPORTANT: this cap applies ONLY to what gets persisted in the audit
# event. Transit through the gateway (request → upstream → response →
# client) is never blocked or truncated by this — large payloads flow
# unchanged. The cap exists purely to bound audit-pipeline + warehouse
# storage cost; the gateway is a proxy, the audit event is a record.
#
# When an opted-in capture exceeds the cap, the audit event records
# the real `total_bytes` count and substitutes a sentinel for the
# captured field so operators see "27 MB flowed, 0 stored due to cap"
# rather than a partial fragment of dubious value.
_AUDIT_RAW_CAPTURE_BYTE_CAP = 10 * 1024 * 1024  # 10 MiB default
_TRUNCATION_MARKER = "[…truncated by gateway audit cap]"


def configure_raw_capture_cap(cap_bytes: int) -> None:
    """Set the module-level raw-capture byte cap from gateway Settings.

    Called once at app startup via `create_app(...)`. Kept as a
    module-level setter (rather than threading the value through every
    `truncate_for_audit_capture` call site) because the cap is a
    deployment-wide ceiling, not a per-event tunable.
    """
    global _AUDIT_RAW_CAPTURE_BYTE_CAP
    if cap_bytes < 1024:
        raise ValueError("audit_raw_capture_byte_cap must be >= 1 KiB")
    _AUDIT_RAW_CAPTURE_BYTE_CAP = cap_bytes


class AuditDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"
    REWRITE = "rewrite"


class AuditDecisionMode(StrEnum):
    MONITOR = "monitor"
    ENFORCE = "enforce"


class AuditPrincipalType(StrEnum):
    ENDPOINT_SESSION = "endpoint_session"
    SERVER_AGENT = "server_agent"
    API_KEY = "api_key"
    # EMA-1 · enterprise-IdP-rooted callers (ID-JAG / EMA tokens).
    # `tool_call_events.principal_type` is free text — no migration.
    FEDERATED_USER = "federated_user"


class UpstreamStatus(StrEnum):
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"
    NOT_CALLED = "not_called"


class AuditEventType(StrEnum):
    """Discriminator on `AuditEvent`. Default `tool_call` (the existing
    behaviour). `access_attempt` records connection-level auth /
    access failures — someone with a (possibly valid) bearer trying
    to reach a vserver they don't have a grant on, etc. These never
    reach the lifecycle so they'd otherwise be invisible on the
    operator-console Events panel."""

    TOOL_CALL = "tool_call"
    ACCESS_ATTEMPT = "access_attempt"


class AuthFailureReason(StrEnum):
    """Why an `access_attempt` event was recorded.

    `invalid_bearer`     — the bearer didn't validate. Principal is a
                           synthetic `<unknown>` since we couldn't
                           identify the caller. Often security noise.
    `vserver_not_found`  — the URL path's vserver name doesn't exist
                           in the tenant. Could be a typo OR probing.
    `no_grant`           — the principal is valid but doesn't have an
                           active grant on a private vserver. The
                           "smart-azz uses someone else's URL" case.
    `disabled_principal` — the API key / user is disabled.
    """

    INVALID_BEARER = "invalid_bearer"
    VSERVER_NOT_FOUND = "vserver_not_found"
    NO_GRANT = "no_grant"
    DISABLED_PRINCIPAL = "disabled_principal"


class AuditPrincipal(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: AuditPrincipalType
    id: str = Field(min_length=1)
    display: str = ""


class AuditClientMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    agent_type: str | None = None
    client_version: str | None = None
    user_agent: str | None = None
    # MCP-2 P1 · which MCP protocol revision the caller spoke.
    # "2026-07-28"+ = modern stateless requests (per-request `_meta`);
    # earlier strings = legacy `initialize`-negotiated sessions. Flows
    # into `tool_call_events.client_metadata` JSONB with no migration —
    # the NHI map / events drill-in can answer "who is on which
    # protocol revision" from here.
    protocol_version: str | None = None
    # EMA-1 P3 · the MCP client application id the enterprise IdP
    # authorized on the ID-JAG. Authoritative where it exists — unlike
    # `user_agent`, which the caller sets freely — so the NHI map trusts
    # it over user-agent sniffing. None for non-federated callers.
    client_id: str | None = None


class AuthModeFlags(BaseModel):
    """Which outbound-auth modes were configured on the upstream MCP server
    that fired this tool call. Operators want to answer "is tenant X actually
    using OAuth / passthrough / static headers?" — these booleans surface
    that without inferring from server config dumps. All-false is valid and
    means no outbound auth was configured (e.g., a tool call that was denied
    before reaching upstream, or a server with no credentials wired)."""

    model_config = ConfigDict(frozen=True)

    auth_org_tier: bool = False
    auth_user_tier_passthrough: bool = False
    auth_oauth_client_credentials: bool = False
    # Phase-4 OAuth (A1) — per-user delegated tokens.
    auth_oauth_authcode: bool = False
    # Phase-5 OAuth (A2) — RFC 7523 JWT-bearer service-account flow.
    auth_oauth_jwt_bearer: bool = False
    # Transport-layer auth: mTLS client cert chain configured.
    auth_mtls: bool = False


class AuditEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tenant_id: UUID
    source_pep: str = "gateway"
    gateway_instance_id: str
    principal: AuditPrincipal
    vserver_id: UUID | None = None
    # Access-attempt events (`event_type=access_attempt`) carry the
    # vserver NAME from the URL path even when the vserver doesn't
    # exist (no UUID to record). For tool-call events this is None;
    # `vserver_id` is the canonical reference.
    vserver_name: str | None = None
    upstream_server_id: UUID | None = None
    tool: str
    args_summary: dict[str, Any]
    decision: AuditDecision
    decision_mode: AuditDecisionMode
    policy_id: UUID | None = None
    policy_rule_id: str | None = None
    latency_ms_total: float | None = None
    latency_ms_upstream: float | None = None
    upstream_status: UpstreamStatus
    response_size_bytes: int | None = None
    client_metadata: AuditClientMetadata = Field(default_factory=AuditClientMetadata)
    auth_modes: AuthModeFlags = Field(default_factory=AuthModeFlags)
    # Discriminator + access-attempt context. Default `tool_call` keeps
    # existing event consumers happy; `access_attempt` events surface
    # connection-level denials that never reached the lifecycle.
    event_type: AuditEventType = AuditEventType.TOOL_CALL
    auth_failure_reason: AuthFailureReason | None = None
    # H5 · raw-arg / raw-response capture, populated only when policy
    # explicitly opts in (PolicyDecision.capture_raw_args /
    # capture_raw_response). Default None means "not captured" — the
    # privacy posture for non-opted-in tenants. When present, values
    # may be truncated; see `_AUDIT_RAW_CAPTURE_BYTE_CAP`. The args
    # dict has the same shape as `tools/call`'s `arguments`; the
    # response is a serialized MCP `CallToolResult` (a dict of the
    # MCP fields). Both fields are size-capped at the gateway boundary
    # so a single large call can't blow up the audit pipeline.
    raw_args: dict[str, Any] | None = None
    raw_response: dict[str, Any] | None = None
    raw_args_truncated: bool = False
    raw_response_truncated: bool = False


def summarize_tool_args(arguments: dict[str, Any]) -> dict[str, Any]:
    """Summarize argument shape without retaining argument values."""

    return {
        "top_level_keys": sorted(arguments),
        "fields": {
            key: {
                "type": type(value).__name__,
                "size": _safe_size(value),
            }
            for key, value in sorted(arguments.items())
        },
    }


def _safe_size(value: Any) -> int | None:
    if isinstance(value, str | bytes | list | tuple | dict | set):
        return len(value)
    return None


def truncate_for_audit_capture(
    payload: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, bool]:
    """Return `(payload-or-sentinel, was_truncated)` for H5 capture.

    Strategy is deliberately simple — whole-or-sentinel:

    1. `None` in → `None` out (capture not opted in).
    2. JSON-serialize to measure real wire bytes.
    3. If serialized size ≤ `_AUDIT_RAW_CAPTURE_BYTE_CAP`: store
       the payload as-is.
    4. If over the cap: substitute a sentinel that records the
       real `total_bytes` so operators see "X bytes flowed through,
       0 stored due to audit-storage cap." Transit is unaffected.

    Earlier versions tried a leaf-cap middle tier (truncate strings
    to 1 KB and re-check). Removed because the partial fragment was
    rarely useful — operators either want the full payload for
    forensics (which is why they opted into capture) or they want
    confirmation the call happened plus a byte count. The middle
    ground produced confusing half-data.
    """

    if payload is None:
        return None, False
    try:
        as_json = json.dumps(payload, default=str)
    except (TypeError, ValueError):
        # Non-serialisable payload — bail to a safe sentinel rather than
        # poisoning the audit pipeline with a partial value.
        return ({"__non_serialisable__": True}, True)
    total_bytes = len(as_json.encode("utf-8"))
    if total_bytes <= _AUDIT_RAW_CAPTURE_BYTE_CAP:
        return payload, False

    # Over-cap path: don't store the body, but record the real size
    # so the audit consumer can surface "27 MB flowed, not stored."
    return (
        {
            "__truncated__": True,
            "total_bytes": total_bytes,
            "stored_bytes": 0,
            "cap_bytes": _AUDIT_RAW_CAPTURE_BYTE_CAP,
            "reason": "exceeds audit_raw_capture_byte_cap; transit unaffected",
            "marker": _TRUNCATION_MARKER,
        },
        True,
    )


def create_access_attempt_audit_event(
    *,
    tenant_id: UUID,
    gateway_instance_id: str,
    principal: AuditPrincipal,
    auth_failure_reason: AuthFailureReason,
    vserver_id: UUID | None = None,
    vserver_name: str | None = None,
    client_metadata: AuditClientMetadata | None = None,
) -> AuditEvent:
    """Build an `AuditEvent` for a connection-level auth/access failure.

    `tool` is set to a sentinel `"<connect>"` because no tool name
    exists at this point — the failure happened before a tool call
    could be selected. The `decision` is always `DENY` for these
    events — they're recorded specifically because the request was
    rejected at the gateway boundary.

    Stays frozen-immutable so the same event can be safely dispatched
    to the inner Kafka / NATS producer + the local recent-events
    buffer without copy semantics.
    """

    return AuditEvent(
        tenant_id=tenant_id,
        gateway_instance_id=gateway_instance_id,
        principal=principal,
        vserver_id=vserver_id,
        vserver_name=vserver_name,
        tool="<connect>",
        args_summary={},
        decision=AuditDecision.DENY,
        decision_mode=AuditDecisionMode.ENFORCE,
        upstream_status=UpstreamStatus.NOT_CALLED,
        client_metadata=client_metadata or AuditClientMetadata(),
        event_type=AuditEventType.ACCESS_ATTEMPT,
        auth_failure_reason=auth_failure_reason,
        policy_rule_id=auth_failure_reason.value,
    )


def create_tool_call_audit_event(
    *,
    tenant_id: UUID,
    gateway_instance_id: str,
    principal: AuditPrincipal,
    tool: str,
    arguments: dict[str, Any],
    decision: AuditDecision,
    decision_mode: AuditDecisionMode = AuditDecisionMode.ENFORCE,
    upstream_status: UpstreamStatus = UpstreamStatus.NOT_CALLED,
    vserver_id: UUID | None = None,
    # Denormalised alongside the id on purpose: an operator filtering the
    # audit table reaches for the name they know, and access_attempt rows
    # already carry it. Populating only one event type meant a query by
    # name silently returned a subset — the worst kind of wrong answer,
    # because it looks like a complete one.
    vserver_name: str | None = None,
    upstream_server_id: UUID | None = None,
    policy_id: UUID | None = None,
    policy_rule_id: str | None = None,
    latency_ms_total: float | None = None,
    latency_ms_upstream: float | None = None,
    response_size_bytes: int | None = None,
    client_metadata: AuditClientMetadata | None = None,
    auth_modes: AuthModeFlags | None = None,
    raw_args: dict[str, Any] | None = None,
    raw_response: dict[str, Any] | None = None,
    event_id: UUID | None = None,
) -> AuditEvent:
    """Build an audit event for a tool call.

    `raw_args` / `raw_response` default to None — they are populated
    ONLY when the policy decision opted in (H5). The lifecycle is the
    sole caller that sets them and only does so after checking
    `decision.capture_raw_args` / `capture_raw_response`. Both fields
    are size-capped via `truncate_for_audit_capture`.
    """

    capped_args, args_truncated = truncate_for_audit_capture(raw_args)
    capped_response, response_truncated = truncate_for_audit_capture(raw_response)
    kwargs: dict[str, Any] = {
        "tenant_id": tenant_id,
        "gateway_instance_id": gateway_instance_id,
        "principal": principal,
        "vserver_id": vserver_id,
        "vserver_name": vserver_name,
        "upstream_server_id": upstream_server_id,
        "tool": tool,
        "args_summary": summarize_tool_args(arguments),
        "decision": decision,
        "decision_mode": decision_mode,
        "policy_id": policy_id,
        "policy_rule_id": policy_rule_id,
        "latency_ms_total": latency_ms_total,
        "latency_ms_upstream": latency_ms_upstream,
        "upstream_status": upstream_status,
        "response_size_bytes": response_size_bytes,
        "client_metadata": client_metadata or AuditClientMetadata(),
        "auth_modes": auth_modes or AuthModeFlags(),
        "raw_args": capped_args,
        "raw_response": capped_response,
        "raw_args_truncated": args_truncated,
        "raw_response_truncated": response_truncated,
    }
    if event_id is not None:
        kwargs["event_id"] = event_id
    return AuditEvent(**kwargs)
