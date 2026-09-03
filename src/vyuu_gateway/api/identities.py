"""Operator-facing endpoints for the NHI / identity dashboard (N1).

Two endpoints:

- `GET /api/v1/identities` — list every distinct principal seen in
  the persistent tool-call event log for this tenant, with aggregated
  call volume + reach + risk metrics.
- `GET /api/v1/identities/{principal_id}/timeline` — drill-in. The
  per-call event stream for one identity, newest-first, with
  optional filters: time range, decision, minimum risk floor.

Both query `tool_call_events` (the durable source of truth) so the
dashboard survives gateway restarts. Tenant scoping is taken from the
operator JWT — operators only see their own tenant's identities, and
RLS on the bound DB session enforces it on the wire.

Risk classification draws from `mcp_capabilities.risk_category`.
We resolve the lookup once per request via `(server_id, tool_name)
-> risk_category`. Bounded by the tenant's capability count.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.api.audit_events import AuditEventView, _to_view
from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.audit.events import (
    AuditDecision,
    AuditEvent,
    AuditEventType,
    AuditPrincipalType,
)
from vyuu_gateway.audit.identity_aggregator import (
    IdentitySummary,
    summarize_identities,
)
from vyuu_gateway.audit.persistent import query_tool_call_events
from vyuu_gateway.db.models import (
    GrantPrincipalKind,
    McpCapability,
    McpCapabilityKind,
    RiskCategory,
)
from vyuu_gateway.graph.identity_graph import (
    DependencyGraph,
    GraphEdge,
    GraphNode,
    OAuthConnection,
    PrincipalSummary,
    ToolRef,
    UpstreamRef,
    VserverRef,
    WhoCanDoResult,
    dependency_chain,
    principal_summary,
    who_can_do,
)
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator

router = APIRouter(tags=["identities"])

# Default look-back if the caller doesn't pass `since`. Matches the
# operator UI's default time-range picker — "last 24h".
_DEFAULT_LOOKBACK = timedelta(hours=24)


class IdentitySummaryView(BaseModel):
    """Wire shape for one identity row. Stable across internal model
    changes — callers depend on this."""

    model_config = ConfigDict(from_attributes=False)

    principal_id: str
    principal_type: AuditPrincipalType
    principal_display: str
    total_calls: int
    allowed_calls: int
    denied_calls: int
    upstream_error_calls: int
    distinct_vservers: int
    distinct_upstreams: int
    distinct_tools: int
    high_risk_calls: int
    last_seen: datetime
    first_seen: datetime
    risk_histogram: dict[str, int]
    # MCP `clientInfo` from the most-recent call. The UI renders these
    # as a "via Cursor 0.42" badge — answers "what interface drove this
    # identity's last action?" Falls back to `latest_user_agent` when
    # `clientInfo` was missing (raw curl, custom scripts).
    latest_client_name: str | None = None
    latest_client_version: str | None = None
    latest_user_agent: str | None = None
    distinct_clients: list[str] = []


def _resolve_risk_lookup(
    db: Session, *, tenant_id: UUID
) -> dict[tuple[UUID, str], RiskCategory]:
    """Build `(server_id, tool_name) -> RiskCategory` for one tenant.

    One query, bounded by tenant's capability count. The lookup is
    used per-request — recomputing each time means a freshly-synced
    capability shows up in the dashboard immediately, with no
    invalidation dance."""

    rows = db.execute(
        select(McpCapability.server_id, McpCapability.name, McpCapability.risk_category)
        .where(
            McpCapability.tenant_id == tenant_id,
            McpCapability.kind == McpCapabilityKind.TOOL,
        )
    ).all()
    lookup: dict[tuple[UUID, str], RiskCategory] = {}
    for server_id, tool_name, risk in rows:
        # `mcp_capabilities.risk_category` is stored as Text + a
        # CheckConstraint (not a real Postgres enum), so SQLAlchemy
        # surfaces the column as a plain str even though the model
        # types it `Mapped[RiskCategory]`. Coerce at the boundary so
        # downstream callers (`summarize_identities`,
        # `IdentitySummaryView`) can rely on enum semantics.
        lookup[(server_id, tool_name)] = (
            risk if isinstance(risk, RiskCategory) else RiskCategory(risk)
        )
    return lookup


def _summary_to_view(s: IdentitySummary) -> IdentitySummaryView:
    return IdentitySummaryView(
        principal_id=s.principal_id,
        principal_type=s.principal_type,
        principal_display=s.principal_display,
        total_calls=s.total_calls,
        allowed_calls=s.allowed_calls,
        denied_calls=s.denied_calls,
        upstream_error_calls=s.upstream_error_calls,
        distinct_vservers=s.distinct_vservers,
        distinct_upstreams=s.distinct_upstreams,
        distinct_tools=s.distinct_tools,
        high_risk_calls=s.high_risk_calls,
        last_seen=s.last_seen,
        first_seen=s.first_seen,
        risk_histogram=s.risk_histogram,
        latest_client_name=s.latest_client_name,
        latest_client_version=s.latest_client_version,
        latest_user_agent=s.latest_user_agent,
        distinct_clients=list(s.distinct_clients),
    )


@router.get(
    "/identities",
    response_model=list[IdentitySummaryView],
)
def list_identities_endpoint(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
    since: Annotated[datetime | None, Query()] = None,
    until: Annotated[datetime | None, Query()] = None,
    # Cap on how many events to scan within the time window. The
    # aggregator is O(events) so this also bounds response time.
    event_window: Annotated[int, Query(ge=1, le=10_000)] = 1000,
    high_risk_only: Annotated[bool, Query()] = False,
) -> list[IdentitySummaryView]:
    """List every distinct principal seen in the persistent event log
    for this tenant. Newest-active identities first.

    Default window is the last 24h; override via `since` / `until`."""

    effective_since = since or (datetime.now(UTC) - _DEFAULT_LOOKBACK)
    events = query_tool_call_events(
        db,
        tenant_id=operator.tenant_id,
        since=effective_since,
        until=until,
        event_type=AuditEventType.TOOL_CALL,
        limit=event_window,
    )
    if not events:
        return []

    risk_lookup = _resolve_risk_lookup(db, tenant_id=operator.tenant_id)
    summaries = summarize_identities(events, risk_lookup=risk_lookup)
    if high_risk_only:
        summaries = [s for s in summaries if s.high_risk_calls > 0]
    return [_summary_to_view(s) for s in summaries]


@router.get(
    "/identities/{principal_id}/timeline",
    response_model=list[AuditEventView],
)
def identity_timeline_endpoint(
    principal_id: str,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
    decision: Annotated[AuditDecision | None, Query()] = None,
    # `risk_floor` filters to capabilities with at least this risk.
    # `unknown` (the default) matches everything — no filtering. This
    # is rendered as a dropdown in the UI.
    risk_floor: Annotated[RiskCategory | None, Query()] = None,
    since: Annotated[datetime | None, Query()] = None,
    until: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[AuditEventView]:
    """Per-principal event timeline. Newest first.

    Default look-back is 24h when `since` is omitted. The DB query
    pre-filters by `principal_id` (covered by the
    `tool_call_events_tenant_principal_idx` index) so we pull a tight
    set; remaining `decision` / `risk_floor` filters happen in Python."""

    if not principal_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="principal_id required",
        )

    effective_since = since or (datetime.now(UTC) - _DEFAULT_LOOKBACK)
    # Pull a wider candidate set than `limit` so the in-Python
    # `decision` / `risk_floor` narrow can still produce up to `limit`
    # rows. 10x is a deliberate over-fetch — the principal index keeps
    # this cheap.
    candidate_cap = min(limit * 10, 10_000)
    events = query_tool_call_events(
        db,
        tenant_id=operator.tenant_id,
        principal_id=principal_id,
        since=effective_since,
        until=until,
        event_type=AuditEventType.TOOL_CALL,
        limit=candidate_cap,
    )

    risk_lookup: dict[tuple[UUID, str], RiskCategory] = {}
    if risk_floor is not None:
        risk_lookup = _resolve_risk_lookup(db, tenant_id=operator.tenant_id)

    filtered: list[AuditEvent] = []
    for event in events:
        if decision is not None and event.decision != decision:
            continue
        if risk_floor is not None:
            if event.upstream_server_id is None:
                # Tool calls without an upstream (denied at the gate)
                # only match when the floor is `unknown` — otherwise
                # they'd silently fail the filter.
                if risk_floor != RiskCategory.UNKNOWN:
                    continue
            else:
                event_risk = risk_lookup.get(
                    (event.upstream_server_id, event.tool), RiskCategory.UNKNOWN
                )
                if not _meets_risk_floor(event_risk, risk_floor):
                    continue
        filtered.append(event)
        if len(filtered) >= limit:
            break

    return [_to_view(e) for e in filtered]


# Severity ordering for the `risk_floor` filter. Operators clicking
# "show admin and above" want the most dangerous categories surfaced —
# `read` is at the bottom, `admin` at the top.
_RISK_SEVERITY: dict[RiskCategory, int] = {
    RiskCategory.READ: 0,
    RiskCategory.NETWORK: 1,
    RiskCategory.WRITE: 2,
    RiskCategory.DATA_EXPORT: 3,
    RiskCategory.EXECUTE: 4,
    RiskCategory.CREDENTIAL_ACCESS: 5,
    RiskCategory.DELETE: 5,
    RiskCategory.ADMIN: 6,
    RiskCategory.UNKNOWN: -1,  # Sorts below `read`; floor=`unknown` matches all.
}


def _meets_risk_floor(event_risk: RiskCategory, floor: RiskCategory) -> bool:
    return _RISK_SEVERITY.get(event_risk, -1) >= _RISK_SEVERITY.get(floor, -1)


# --- N2: graph query endpoints --------------------------------------------


class VserverRefView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    vserver_id: UUID
    name: str
    visibility: str
    grant_path: str


class ToolRefView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    vserver_id: UUID
    upstream_server_id: UUID
    upstream_display_name: str
    tool_name: str
    risk_category: RiskCategory


class UpstreamRefView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    server_id: UUID
    display_name: str
    transport: str
    source_type: str
    oauth_connected: bool | None = None


class OAuthConnectionView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    server_id: UUID
    server_display_name: str
    scope: str | None
    expires_at: datetime | None
    last_refreshed_at: datetime


class PrincipalSummaryView(BaseModel):
    """Wire shape for `GET /api/v1/identities/{id}/summary`."""

    model_config = ConfigDict(from_attributes=False)

    principal_id: UUID
    principal_kind: GrantPrincipalKind
    display: str
    granted_vservers: list[VserverRefView]
    exposed_tools: list[ToolRefView]
    reachable_upstreams: list[UpstreamRefView]
    oauth_connections: list[OAuthConnectionView]
    risk_score: int
    max_risk_category: RiskCategory


class WhoCanDoResultView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    principal_id: UUID
    principal_kind: GrantPrincipalKind
    via_vserver_id: UUID
    via_vserver_name: str
    grant_path: str


class GraphNodeView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    kind: str
    label: str
    risk: str | None = None


class GraphEdgeView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    source: str
    target: str
    kind: str
    detail: str = ""


class DependencyGraphView(BaseModel):
    model_config = ConfigDict(from_attributes=False)
    nodes: list[GraphNodeView]
    edges: list[GraphEdgeView]


def _summary_view_from(s: PrincipalSummary) -> PrincipalSummaryView:
    return PrincipalSummaryView(
        principal_id=s.principal_id,
        principal_kind=s.principal_kind,
        display=s.display,
        granted_vservers=[
            _vserver_ref_view(v) for v in s.granted_vservers
        ],
        exposed_tools=[_tool_ref_view(t) for t in s.exposed_tools],
        reachable_upstreams=[_upstream_ref_view(u) for u in s.reachable_upstreams],
        oauth_connections=[_oauth_view(c) for c in s.oauth_connections],
        risk_score=s.risk_score,
        max_risk_category=s.max_risk_category,
    )


def _vserver_ref_view(v: VserverRef) -> VserverRefView:
    return VserverRefView(
        vserver_id=v.vserver_id,
        name=v.name,
        visibility=v.visibility,
        grant_path=v.grant_path,
    )


def _tool_ref_view(t: ToolRef) -> ToolRefView:
    return ToolRefView(
        vserver_id=t.vserver_id,
        upstream_server_id=t.upstream_server_id,
        upstream_display_name=t.upstream_display_name,
        tool_name=t.tool_name,
        risk_category=t.risk_category,
    )


def _upstream_ref_view(u: UpstreamRef) -> UpstreamRefView:
    return UpstreamRefView(
        server_id=u.server_id,
        display_name=u.display_name,
        transport=u.transport,
        source_type=u.source_type,
        oauth_connected=u.oauth_connected,
    )


def _oauth_view(c: OAuthConnection) -> OAuthConnectionView:
    return OAuthConnectionView(
        server_id=c.server_id,
        server_display_name=c.server_display_name,
        scope=c.scope,
        expires_at=c.expires_at,
        last_refreshed_at=c.last_refreshed_at,
    )


def _who_view(w: WhoCanDoResult) -> WhoCanDoResultView:
    return WhoCanDoResultView(
        principal_id=w.principal_id,
        principal_kind=w.principal_kind,
        via_vserver_id=w.via_vserver_id,
        via_vserver_name=w.via_vserver_name,
        grant_path=w.grant_path,
    )


def _graph_view(g: DependencyGraph) -> DependencyGraphView:
    return DependencyGraphView(
        nodes=[GraphNodeView(**_node_to_dict(n)) for n in g.nodes],
        edges=[GraphEdgeView(**_edge_to_dict(e)) for e in g.edges],
    )


def _node_to_dict(n: GraphNode) -> dict[str, object]:
    return {"id": n.id, "kind": n.kind, "label": n.label, "risk": n.risk}


def _edge_to_dict(e: GraphEdge) -> dict[str, object]:
    return {"source": e.source, "target": e.target, "kind": e.kind, "detail": e.detail}


@router.get(
    "/identities/{principal_id}/summary",
    response_model=PrincipalSummaryView,
)
def identity_summary_endpoint(
    principal_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> PrincipalSummaryView:
    """Full picture of one identity: grants, exposed tools, reachable
    upstreams, OAuth connections, derived risk score. 404 if the
    user doesn't exist in this tenant."""

    summary = principal_summary(
        db, tenant_id=operator.tenant_id, principal_id=principal_id
    )
    if summary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="principal not found in tenant",
        )
    return _summary_view_from(summary)


@router.get(
    "/identities/{principal_id}/graph",
    response_model=DependencyGraphView,
)
def identity_graph_endpoint(
    principal_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> DependencyGraphView:
    """Directed graph: principal → vservers → tools → upstream MCPs.
    Empty graph (200, `nodes:[], edges:[]`) when the principal has
    no grants — distinct from 404 (principal doesn't exist)."""

    summary = principal_summary(
        db, tenant_id=operator.tenant_id, principal_id=principal_id
    )
    if summary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="principal not found in tenant",
        )
    graph = dependency_chain(
        db, tenant_id=operator.tenant_id, principal_id=principal_id
    )
    return _graph_view(graph)


@router.get(
    "/who-can-do",
    response_model=list[WhoCanDoResultView],
)
def who_can_do_endpoint(
    tool_name: Annotated[str, Query(min_length=1, max_length=255)],
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
    risk_floor: Annotated[RiskCategory | None, Query()] = None,
) -> list[WhoCanDoResultView]:
    """Reverse-permission query: who in this tenant can call
    `tool_name`? Optional `risk_floor` filters to capabilities at or
    above the given severity (so "who can do anything dangerous?" is
    one query, not a sweep)."""

    rows = who_can_do(
        db,
        tenant_id=operator.tenant_id,
        tool_name=tool_name,
        risk_floor=risk_floor,
    )
    return [_who_view(r) for r in rows]
