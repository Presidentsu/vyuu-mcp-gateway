"""Operator dashboard endpoint.

Single endpoint that aggregates the top-of-page KPIs for the
operator console's Dashboard panel:

- **NHIs** — distinct active principals seen in the recent-events
  ring buffer (last 24h, capped by buffer size).
- **MCP servers in place** — total registered (`mcp_servers` rows).
- **MCP servers in use** — distinct upstream_server_ids called in the
  recent ring buffer.
- **Virtual servers published** — total `virtual_servers` rows.
- **Pending access requests** — count of `access_requests` with
  status=pending.
- **Security alerts (24h)** — sum of high-risk tool calls + denied
  calls + upstream errors observed in the recent buffer.
- **Connected SaaS** — distinct OAuth-authcode connections in
  `oauth_user_tokens` (one row per user × server).

All in one request so the dashboard loads with one round trip. The
recent-events buffer is in-memory; the SQL queries are bounded by
tenant size.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.audit.events import (
    AuditDecision,
    AuditEventType,
    UpstreamStatus,
)
from vyuu_gateway.audit.recent import RecentAuditEmitter
from vyuu_gateway.db.models import (
    AccessRequest,
    AccessRequestStatus,
    McpCapability,
    McpCapabilityKind,
    McpServer,
    OAuthUserToken,
    RiskCategory,
    User,
    VirtualServer,
)
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator

router = APIRouter(tags=["admin-dashboard"])


# Same severity buckets as the rest of the NHI surfaces. Centralising
# would couple modules that don't otherwise need to know about each
# other; the duplication is small and stable.
_HIGH_RISK = frozenset(
    {
        RiskCategory.DELETE,
        RiskCategory.EXECUTE,
        RiskCategory.CREDENTIAL_ACCESS,
        RiskCategory.DATA_EXPORT,
        RiskCategory.ADMIN,
    }
)


class DashboardKpis(BaseModel):
    """Wire shape for the dashboard. Stable across model changes —
    the UI binds against this, not the underlying audit event."""

    model_config = ConfigDict(from_attributes=False)

    # --- Identity / activity (from the in-process recent-events buffer)
    nhi_total: int
    nhi_active_24h: int
    high_risk_calls_24h: int
    denied_calls_24h: int
    upstream_errors_24h: int
    # --- Catalog (DB)
    mcp_servers_registered: int
    mcp_servers_active_24h: int  # distinct upstream_server_ids in events
    virtual_servers_published: int
    # --- Workflows (DB)
    pending_access_requests: int
    # --- OAuth identity reach (DB)
    oauth_connected_users: int  # distinct users with at least one connection
    oauth_connected_servers: int  # distinct servers users have linked
    # --- Roster
    users_total: int


@router.get("/admin/dashboard", response_model=DashboardKpis)
def admin_dashboard_endpoint(
    request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> DashboardKpis:
    """One-shot KPI aggregation for the dashboard."""

    recent = cast(
        RecentAuditEmitter | None,
        getattr(request.app.state, "recent_audit_emitter", None),
    )

    # --- Recent-events derived metrics ---------------------------------
    nhi_total = 0
    nhi_active_24h = 0
    high_risk_calls_24h = 0
    denied_calls_24h = 0
    upstream_errors_24h = 0
    mcp_servers_active_24h = 0

    if recent is not None:
        # Build a (server_id, tool) -> risk lookup once.
        cap_rows = list(
            db.execute(
                select(
                    McpCapability.server_id,
                    McpCapability.name,
                    McpCapability.risk_category,
                ).where(
                    McpCapability.tenant_id == operator.tenant_id,
                    McpCapability.kind == McpCapabilityKind.TOOL,
                )
            ).all()
        )
        risk_by_pair: dict[tuple[UUID, str], RiskCategory] = {
            (sid, name): RiskCategory(risk) if not isinstance(risk, RiskCategory) else risk
            for sid, name, risk in cap_rows
        }

        events = recent.query(
            tenant_id=operator.tenant_id,
            event_type=AuditEventType.TOOL_CALL,
            limit=10_000,
        )
        cutoff = datetime.now(UTC) - timedelta(hours=24)

        seen_principals_total: set[str] = set()
        seen_principals_24h: set[str] = set()
        seen_servers_24h: set[UUID] = set()
        for event in events:
            seen_principals_total.add(event.principal.id)
            in_window = event.timestamp >= cutoff
            if not in_window:
                continue
            seen_principals_24h.add(event.principal.id)
            if event.upstream_server_id is not None:
                seen_servers_24h.add(event.upstream_server_id)
            if event.decision == AuditDecision.DENY:
                denied_calls_24h += 1
            if (
                event.decision == AuditDecision.ALLOW
                and event.upstream_status not in (UpstreamStatus.OK, UpstreamStatus.NOT_CALLED)
            ):
                upstream_errors_24h += 1
            if event.upstream_server_id is not None:
                risk = risk_by_pair.get(
                    (event.upstream_server_id, event.tool), RiskCategory.UNKNOWN
                )
                if risk in _HIGH_RISK:
                    high_risk_calls_24h += 1
        nhi_total = len(seen_principals_total)
        nhi_active_24h = len(seen_principals_24h)
        mcp_servers_active_24h = len(seen_servers_24h)

    # --- DB-backed counts ---------------------------------------------
    # Each is a single COUNT(*) — bounded by tenant size.
    mcp_servers_registered = (
        db.scalar(
            select(func.count())
            .select_from(McpServer)
            .where(McpServer.tenant_id == operator.tenant_id)
        )
        or 0
    )
    virtual_servers_published = (
        db.scalar(
            select(func.count())
            .select_from(VirtualServer)
            .where(VirtualServer.tenant_id == operator.tenant_id)
        )
        or 0
    )
    pending_access_requests = (
        db.scalar(
            select(func.count())
            .select_from(AccessRequest)
            .where(
                AccessRequest.tenant_id == operator.tenant_id,
                AccessRequest.status == AccessRequestStatus.PENDING,
            )
        )
        or 0
    )
    users_total = (
        db.scalar(
            select(func.count())
            .select_from(User)
            .where(User.tenant_id == operator.tenant_id)
        )
        or 0
    )
    oauth_connected_users = (
        db.scalar(
            select(func.count(func.distinct(OAuthUserToken.user_id))).where(
                OAuthUserToken.tenant_id == operator.tenant_id
            )
        )
        or 0
    )
    oauth_connected_servers = (
        db.scalar(
            select(func.count(func.distinct(OAuthUserToken.server_id))).where(
                OAuthUserToken.tenant_id == operator.tenant_id
            )
        )
        or 0
    )

    return DashboardKpis(
        nhi_total=nhi_total,
        nhi_active_24h=nhi_active_24h,
        high_risk_calls_24h=high_risk_calls_24h,
        denied_calls_24h=denied_calls_24h,
        upstream_errors_24h=upstream_errors_24h,
        mcp_servers_registered=mcp_servers_registered,
        mcp_servers_active_24h=mcp_servers_active_24h,
        virtual_servers_published=virtual_servers_published,
        pending_access_requests=pending_access_requests,
        oauth_connected_users=oauth_connected_users,
        oauth_connected_servers=oauth_connected_servers,
        users_total=users_total,
    )
