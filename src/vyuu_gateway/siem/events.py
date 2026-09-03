"""SIEM export events — the one shape every category is projected into.

`SiemEvent` is deliberately dumb: a category, the tenant it belongs to,
a timestamp, an id, and a JSON-ready body. Everything Splunk-specific
(HEC envelope, `sourcetype` naming) lives in `hec.py`; everything about
delivery lives in `exporter.py`. Keeping the event free of both means a
second SIEM vendor is a new `hec.py`, not a new event model.

## Tenant routing is the one invariant

`tenant_id` decides who may receive the event. A tenant's configured
SIEM receives events carrying THAT tenant id and nothing else; an event
with no tenant (a gateway-wide log line) goes only to the deployment
target the gateway operator configured. Getting this wrong is a
cross-tenant data leak, so the field is on the envelope rather than
buried in the body, and nothing downstream ever infers it from content.

## Raw payloads are opt-in twice

`raw_args` / `raw_response` reach an `AuditEvent` only when policy opted
in (H5). They are shipped to a SIEM only when THAT target opted in as
well. `raw_fields` names the body keys carrying them so the exporter can
strip exactly those and leave the `*_truncated` flags, which stay true
statements either way.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from vyuu_gateway.audit.events import AuditEvent, AuditEventType
from vyuu_gateway.logging_config import structured_fields

SCHEMA_VERSION = "1"


class SiemCategory(StrEnum):
    """One `sourcetype` each on the Splunk side: `vyuu:mcp:<category>`."""

    # `tools/call` at the gateway: allowed, denied, errored — with the
    # policy rule, latency, upstream status and (when captured) payloads.
    TOOL_CALL = "tool_call"
    # Connection-level rejections that never reached a tool call: bad
    # bearer, unknown virtual server, no grant, disabled principal.
    ACCESS_ATTEMPT = "access_attempt"
    # What admins did to the platform — every `admin_audit_log` row.
    ADMIN_ACTION = "admin_action"
    # Operator-console and end-user-portal sign-ins, success and failure.
    AUTH = "auth"
    # Per-user upstream authorisation: OAuth connect / disconnect /
    # exchange failures / client-identity resolution.
    TOOL_AUTH = "tool_auth"
    # Structured gateway log lines at or above the target's level.
    GATEWAY_LOG = "gateway_log"
    # One synthetic event, sent on demand to prove the pipe works.
    HEARTBEAT = "heartbeat"


# What a target receives when it does not say otherwise. Logs are left
# out: they are the one category that is volume rather than signal, and
# an operator should choose to pay for them.
DEFAULT_CATEGORIES: frozenset[SiemCategory] = frozenset(
    {
        SiemCategory.TOOL_CALL,
        SiemCategory.ACCESS_ATTEMPT,
        SiemCategory.ADMIN_ACTION,
        SiemCategory.AUTH,
        SiemCategory.TOOL_AUTH,
    }
)

SELECTABLE_CATEGORIES: tuple[SiemCategory, ...] = (
    SiemCategory.TOOL_CALL,
    SiemCategory.ACCESS_ATTEMPT,
    SiemCategory.ADMIN_ACTION,
    SiemCategory.AUTH,
    SiemCategory.TOOL_AUTH,
    SiemCategory.GATEWAY_LOG,
)

CATEGORY_DESCRIPTIONS: dict[SiemCategory, str] = {
    SiemCategory.TOOL_CALL: (
        "Every tools/call: who, which tool, allowed or denied and by which "
        "rule, upstream status, latency. Payloads only if captured by policy "
        "and enabled below."
    ),
    SiemCategory.ACCESS_ATTEMPT: (
        "Rejections at the door: invalid bearer, unknown virtual server, no "
        "grant, disabled principal."
    ),
    SiemCategory.ADMIN_ACTION: (
        "What admins did to the platform: users, grants, servers, policies, "
        "identity providers."
    ),
    SiemCategory.AUTH: (
        "Operator-console and portal sign-ins, successes and failures, "
        "including SSO."
    ),
    SiemCategory.TOOL_AUTH: (
        "Per-user upstream authorisation: OAuth connect, disconnect, exchange "
        "failures, client-identity resolution."
    ),
    SiemCategory.GATEWAY_LOG: (
        "Structured gateway log lines at or above the chosen level. High "
        "volume; off by default."
    ),
}


class AuthSurface(StrEnum):
    OPERATOR = "operator"
    PORTAL = "portal"


class AuthMethod(StrEnum):
    PASSWORD = "password"
    OIDC = "oidc"
    SAML = "saml"


class AuthOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


class ToolAuthAction(StrEnum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    EXCHANGE_FAILED = "exchange_failed"
    CLIENT_IDENTITY_RESOLVED = "client_identity_resolved"
    CLIENT_INVALIDATED = "client_invalidated"


@dataclass(frozen=True, slots=True)
class SiemEvent:
    category: SiemCategory
    # None means "belongs to no tenant" — deployment target only.
    tenant_id: UUID | None
    body: dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_id: UUID = field(default_factory=uuid4)
    # Body keys that hold raw tool payloads. Stripped per target policy.
    raw_fields: tuple[str, ...] = ()
    # Only meaningful for GATEWAY_LOG: the record's numeric level, so a
    # target can filter at WARNING without parsing the body.
    log_level: int = 0


# --- projections -------------------------------------------------------


def from_audit_event(event: AuditEvent) -> SiemEvent:
    """Project an `AuditEvent` — tool call or access attempt."""

    body = event.model_dump(mode="json", exclude_none=True)
    # Redundant with the envelope, and confusing next to `event_type`.
    body.pop("event_id", None)
    body.pop("timestamp", None)
    category = (
        SiemCategory.ACCESS_ATTEMPT
        if event.event_type == AuditEventType.ACCESS_ATTEMPT
        else SiemCategory.TOOL_CALL
    )
    raw_fields = tuple(k for k in ("raw_args", "raw_response") if k in body)
    return SiemEvent(
        category=category,
        tenant_id=event.tenant_id,
        body=body,
        timestamp=event.timestamp,
        event_id=event.event_id,
        raw_fields=raw_fields,
    )


def from_admin_action(
    *,
    tenant_id: UUID,
    row_id: UUID,
    actor_kind: str,
    actor_operator_id: UUID | None,
    actor_display: str | None,
    action: str,
    target_kind: str | None,
    target_id: UUID | None,
    target_display: str | None,
    detail: dict[str, Any],
    occurred_at: datetime,
) -> SiemEvent:
    """Project an `admin_audit_log` row.

    Takes fields rather than the ORM row on purpose: this is called
    BEFORE the row's transaction commits (see `bridges.py`), and the
    event must not hold a reference that expires on commit.
    """

    return SiemEvent(
        category=SiemCategory.ADMIN_ACTION,
        tenant_id=tenant_id,
        body={
            "action": action,
            "actor": {
                "kind": actor_kind,
                "operator_id": str(actor_operator_id) if actor_operator_id else None,
                "display": actor_display,
            },
            "target": {
                "kind": target_kind,
                "id": str(target_id) if target_id else None,
                "display": target_display,
            },
            "detail": detail,
        },
        timestamp=occurred_at,
        event_id=row_id,
    )


def auth_event(
    *,
    tenant_id: UUID,
    surface: AuthSurface,
    method: AuthMethod,
    outcome: AuthOutcome,
    subject: str | None,
    subject_id: UUID | None = None,
    reason: str | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    directory_id: UUID | None = None,
    directory_display: str | None = None,
) -> SiemEvent:
    """A sign-in attempt on either console.

    `subject` is the email that was tried. It is present on failures too
    — a SIEM auth log that cannot say WHICH account is being brute-forced
    is not an auth log. Never the password, never a token.
    """

    return SiemEvent(
        category=SiemCategory.AUTH,
        tenant_id=tenant_id,
        body={
            "surface": surface.value,
            "method": method.value,
            "outcome": outcome.value,
            "subject": subject,
            "subject_id": str(subject_id) if subject_id else None,
            "reason": reason,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "directory_id": str(directory_id) if directory_id else None,
            "directory_display": directory_display,
        },
    )


def tool_auth_event(
    *,
    tenant_id: UUID,
    action: ToolAuthAction,
    server_id: UUID | None,
    server_display: str | None = None,
    user_id: UUID | None = None,
    mechanism: str | None = None,
    reason: str | None = None,
    detail: dict[str, Any] | None = None,
) -> SiemEvent:
    """Per-user upstream authorisation lifecycle. Never a token."""

    return SiemEvent(
        category=SiemCategory.TOOL_AUTH,
        tenant_id=tenant_id,
        body={
            "action": action.value,
            "server_id": str(server_id) if server_id else None,
            "server_display": server_display,
            "user_id": str(user_id) if user_id else None,
            "mechanism": mechanism,
            "reason": reason,
            "detail": detail or {},
        },
    )


def from_log_record(record: logging.LogRecord, tenant_id: UUID | None) -> SiemEvent:
    """A structured log line. Same field set as the stdout JSON line."""

    body: dict[str, Any] = {
        "level": record.levelname,
        "logger": record.name,
        "message": record.getMessage(),
    }
    body.update(structured_fields(record))
    if record.exc_info is not None and record.exc_info[0] is not None:
        body["exception"] = logging.Formatter().formatException(record.exc_info)
    return SiemEvent(
        category=SiemCategory.GATEWAY_LOG,
        tenant_id=tenant_id,
        body=body,
        timestamp=datetime.fromtimestamp(record.created, tz=UTC),
        log_level=record.levelno,
    )


def heartbeat_event(tenant_id: UUID | None, *, gateway_instance_id: str) -> SiemEvent:
    return SiemEvent(
        category=SiemCategory.HEARTBEAT,
        tenant_id=tenant_id,
        body={
            "message": "vyuu mcp gateway siem export test",
            "gateway_instance_id": gateway_instance_id,
        },
    )
