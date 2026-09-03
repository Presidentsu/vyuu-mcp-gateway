"""Read-side endpoint for the persistent tool-call event store.

The "Tool-call activity" panel on the operator console hits
`GET /api/v1/audit-events` to render recent tool calls. Auth is the
operator JWT; tenant scoping comes from the bearer (operators see
only their own tenant's events) and is enforced on the DB side via
RLS on `tool_call_events`.

Query params:
- `since` / `until` — ISO-8601 timestamps. Defaults to "last 24h".
- `vserver_id` — narrow to a single virtual server (the panel uses
  this when the operator clicks a vserver card).
- `upstream_server_id` — narrow to a single upstream MCP server.
- `event_type` — `tool_call` (default) or `access_attempt`.
- `limit` — cap the response (default 100, max 500).

Source of truth is the `tool_call_events` Postgres table, which
survives gateway restarts. The in-memory `RecentAuditEmitter` ring
buffer (rehydrated on startup from the same table) is no longer
read here; it stays as a write-side hot path optimization for the
Kafka / NATS fan-out.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.audit.events import (
    AuditDecision,
    AuditEvent,
    AuditEventType,
    AuthFailureReason,
    AuthModeFlags,
    UpstreamStatus,
)
from vyuu_gateway.audit.persistent import query_tool_call_events
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator

router = APIRouter(tags=["audit-events"])

# Default look-back if the caller doesn't pass `since`. Matches the
# operator UI's default time-range picker — "last 24h".
_DEFAULT_LOOKBACK = timedelta(hours=24)


class AuditPrincipalView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    type: str
    id: str
    display: str = ""


class AuditEventView(BaseModel):
    """Operator-facing view of an `AuditEvent`. We don't dump the full
    Pydantic model directly so we can keep the wire shape stable as the
    internal model evolves."""

    model_config = ConfigDict(from_attributes=False)

    event_id: UUID
    timestamp: datetime
    tenant_id: UUID
    vserver_id: UUID | None
    vserver_name: str | None = None
    upstream_server_id: UUID | None
    tool: str
    principal: AuditPrincipalView
    decision: AuditDecision
    upstream_status: UpstreamStatus
    latency_ms_total: float | None
    latency_ms_upstream: float | None
    response_size_bytes: int | None
    args_summary: dict[str, object]
    auth_modes: AuthModeFlags
    policy_rule_id: str | None
    # Discriminator + access-attempt context. Default is `tool_call`
    # (the existing event shape); `access_attempt` events surface
    # connection-level auth/access denials.
    event_type: AuditEventType = AuditEventType.TOOL_CALL
    auth_failure_reason: AuthFailureReason | None = None
    # H5 · only populated when the policy decision opted in. None means
    # "metadata-only event" (the privacy default). Truncation flags are
    # always present so the UI can render a clear indicator.
    raw_args: dict[str, object] | None = None
    raw_response: dict[str, object] | None = None
    raw_args_truncated: bool = False
    raw_response_truncated: bool = False


def _to_view(event: AuditEvent) -> AuditEventView:
    return AuditEventView(
        event_id=event.event_id,
        timestamp=event.timestamp,
        tenant_id=event.tenant_id,
        vserver_id=event.vserver_id,
        vserver_name=event.vserver_name,
        upstream_server_id=event.upstream_server_id,
        tool=event.tool,
        principal=AuditPrincipalView(
            type=str(event.principal.type),
            id=event.principal.id,
            display=event.principal.display,
        ),
        decision=event.decision,
        upstream_status=event.upstream_status,
        latency_ms_total=event.latency_ms_total,
        latency_ms_upstream=event.latency_ms_upstream,
        response_size_bytes=event.response_size_bytes,
        args_summary=event.args_summary,
        auth_modes=event.auth_modes,
        policy_rule_id=event.policy_rule_id,
        event_type=event.event_type,
        auth_failure_reason=event.auth_failure_reason,
        raw_args=event.raw_args,
        raw_response=event.raw_response,
        raw_args_truncated=event.raw_args_truncated,
        raw_response_truncated=event.raw_response_truncated,
    )


@router.get(
    "/audit-events",
    response_model=list[AuditEventView],
)
def list_audit_events_endpoint(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
    since: Annotated[datetime | None, Query()] = None,
    until: Annotated[datetime | None, Query()] = None,
    vserver_id: Annotated[UUID | None, Query()] = None,
    upstream_server_id: Annotated[UUID | None, Query()] = None,
    event_type: Annotated[AuditEventType | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[AuditEventView]:
    effective_since = since or (datetime.now(UTC) - _DEFAULT_LOOKBACK)
    events = query_tool_call_events(
        db,
        tenant_id=operator.tenant_id,
        since=effective_since,
        until=until,
        vserver_id=vserver_id,
        upstream_server_id=upstream_server_id,
        event_type=event_type,
        limit=limit,
    )
    return [_to_view(e) for e in events]
