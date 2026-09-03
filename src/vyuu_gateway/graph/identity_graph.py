"""NHI relation-graph query layer (N2).

Three operator-facing reads, all against the existing tables —
no new schema required:

1. **`principal_summary(tenant, principal_id)`** — full picture of one
   identity: granted vservers (direct + via groups), exposed tools
   under those vservers, underlying upstream MCPs, OAuth-authcode
   connections (which SaaS the user has linked their account to),
   and a derived risk score from the grant set's tool risk profile.

2. **`who_can_do(tenant, tool_name, risk_floor)`** — reverse query:
   "who in this tenant can call `delete_repository`?" Walks
   `virtual_server_tools` → `virtual_server_grants` (direct + via
   group memberships) → returns the principal list. Used by the
   security-review workflow ("who could trigger this incident?").

3. **`dependency_chain(tenant, principal_id)`** — directed graph
   edges (principal → vserver → upstream → SaaS) for visualisation
   in the operator UI's graph panel. Plain Python dataclasses;
   the UI does the layout.

Everything is read-only. Tenant scoping comes from the bound session
(RLS + WHERE filters). The SQL stays simple — three or four queries
per surface, joined in Python rather than one massive subquery so
the per-table costs are debuggable when something goes slow.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import (
    GrantPrincipalKind,
    McpCapability,
    McpCapabilityKind,
    McpServer,
    OAuthUserToken,
    RiskCategory,
    User,
    UserGroupMembership,
    VirtualServer,
    VirtualServerGrant,
    VirtualServerTool,
)

# Severity ordering — same as `api/identities.py` so the dashboard
# and the graph layer agree on what counts as "high".
_RISK_SEVERITY: dict[RiskCategory, int] = {
    RiskCategory.READ: 0,
    RiskCategory.NETWORK: 1,
    RiskCategory.WRITE: 2,
    RiskCategory.DATA_EXPORT: 3,
    RiskCategory.EXECUTE: 4,
    RiskCategory.CREDENTIAL_ACCESS: 5,
    RiskCategory.DELETE: 5,
    RiskCategory.ADMIN: 6,
    RiskCategory.UNKNOWN: -1,
}


@dataclass(frozen=True)
class VserverRef:
    """Lightweight reference to a virtual server in graph payloads."""

    vserver_id: UUID
    name: str
    visibility: str
    # `direct` if the principal has a `principal_kind=user` grant,
    # `group:<group_id>` if reached transitively via group membership,
    # `public` if the vserver visibility is public (no grant needed).
    grant_path: str


@dataclass(frozen=True)
class ToolRef:
    """One tool exposed to the principal through their granted vservers."""

    vserver_id: UUID
    upstream_server_id: UUID
    upstream_display_name: str
    tool_name: str
    risk_category: RiskCategory


@dataclass(frozen=True)
class UpstreamRef:
    """One MCP server the principal can reach through their grants."""

    server_id: UUID
    display_name: str
    transport: str
    source_type: str
    # OAuth-authcode connection state from `oauth_user_tokens` —
    # `None` if the upstream isn't `auth_authcode`-configured at all,
    # `connected=True` if there's a stored token row, `False` otherwise.
    oauth_connected: bool | None = None


@dataclass(frozen=True)
class OAuthConnection:
    """One row from `oauth_user_tokens` — the user's linked SaaS
    accounts. Plaintext access tokens are NEVER returned."""

    server_id: UUID
    server_display_name: str
    scope: str | None
    expires_at: datetime | None
    last_refreshed_at: datetime


@dataclass(frozen=True)
class PrincipalSummary:
    """Full picture of one identity — what they can do, what they've
    connected, how dangerous their grant set is."""

    principal_id: UUID
    principal_kind: GrantPrincipalKind
    display: str
    granted_vservers: tuple[VserverRef, ...]
    exposed_tools: tuple[ToolRef, ...]
    reachable_upstreams: tuple[UpstreamRef, ...]
    oauth_connections: tuple[OAuthConnection, ...]
    # Numeric score 0..100 derived from the highest-risk tool the
    # principal can touch. Operators get a tunable signal without
    # threading subjective "is this dangerous?" judgments into the UI.
    risk_score: int
    # Highest individual risk_category in the exposed_tools set —
    # rendered as a label / pill in the UI.
    max_risk_category: RiskCategory


@dataclass(frozen=True)
class GraphNode:
    """One node in `dependency_chain`. `kind` discriminates node type
    so the UI can render different shapes / colours per layer."""

    id: str
    kind: str  # principal | vserver | upstream | tool
    label: str
    risk: str | None = None  # only set on tool nodes


@dataclass(frozen=True)
class GraphEdge:
    """Directed edge between two nodes."""

    source: str
    target: str
    kind: str  # grant | exposes | wraps | calls
    detail: str = ""


@dataclass(frozen=True)
class DependencyGraph:
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]


@dataclass(frozen=True)
class WhoCanDoResult:
    """One principal returned from a reverse-permission query."""

    principal_id: UUID
    principal_kind: GrantPrincipalKind
    via_vserver_id: UUID
    via_vserver_name: str
    grant_path: str  # `direct` | `group:<group_id>`


# ---------------------------------------------------------------------------
# 1. principal_summary
# ---------------------------------------------------------------------------


def principal_summary(
    db: Session, *, tenant_id: UUID, principal_id: UUID
) -> PrincipalSummary | None:
    """Full identity picture for one user. Returns None if the user
    doesn't exist in this tenant."""

    user = db.scalar(
        select(User).where(
            User.tenant_id == tenant_id,
            User.id == principal_id,
        )
    )
    if user is None:
        return None

    granted_vservers = _granted_vservers_for_user(
        db, tenant_id=tenant_id, user_id=principal_id
    )
    exposed_tools = _exposed_tools_for_vservers(
        db, tenant_id=tenant_id, vserver_ids=[v.vserver_id for v in granted_vservers]
    )
    reachable_upstreams = _reachable_upstreams(
        db,
        tenant_id=tenant_id,
        user_id=principal_id,
        upstream_ids={t.upstream_server_id for t in exposed_tools},
    )
    oauth_connections = _oauth_connections(
        db, tenant_id=tenant_id, user_id=principal_id
    )

    max_risk = _max_risk(t.risk_category for t in exposed_tools)
    risk_score = _risk_score(exposed_tools)

    return PrincipalSummary(
        principal_id=principal_id,
        principal_kind=GrantPrincipalKind.USER,
        display=user.email,
        granted_vservers=tuple(granted_vservers),
        exposed_tools=tuple(exposed_tools),
        reachable_upstreams=tuple(reachable_upstreams),
        oauth_connections=tuple(oauth_connections),
        risk_score=risk_score,
        max_risk_category=max_risk,
    )


# ---------------------------------------------------------------------------
# 2. who_can_do
# ---------------------------------------------------------------------------


def who_can_do(
    db: Session,
    *,
    tenant_id: UUID,
    tool_name: str,
    risk_floor: RiskCategory | None = None,
) -> list[WhoCanDoResult]:
    """Reverse query — every user in the tenant who could call
    `tool_name` through any of their granted vservers.

    `risk_floor` (when set) filters which tool exposures count: only
    capabilities whose `risk_category` meets or exceeds the floor.
    Useful for "who can do anything dangerous?" sweeps without
    enumerating tools by hand."""

    # 1. Find every (vserver_id, server_id) pair that exposes this
    # tool — and (if risk_floor set) also passes the floor.
    exposure_q = (
        select(
            VirtualServerTool.vserver_id,
            VirtualServerTool.server_id,
            VirtualServer.name,
        )
        .join(
            VirtualServer,
            (VirtualServer.id == VirtualServerTool.vserver_id)
            & (VirtualServer.tenant_id == tenant_id),
        )
        .where(
            VirtualServerTool.tenant_id == tenant_id,
            VirtualServerTool.tool_name == tool_name,
        )
    )
    if risk_floor is not None:
        exposure_q = exposure_q.join(
            McpCapability,
            (McpCapability.tenant_id == tenant_id)
            & (McpCapability.server_id == VirtualServerTool.server_id)
            & (McpCapability.name == VirtualServerTool.tool_name)
            & (McpCapability.kind == McpCapabilityKind.TOOL),
        ).where(
            McpCapability.risk_category.in_(_categories_at_or_above(risk_floor))
        )

    exposures = list(db.execute(exposure_q).all())
    if not exposures:
        return []

    vserver_ids = [e[0] for e in exposures]
    vserver_names: dict[UUID, str] = {e[0]: e[2] for e in exposures}

    # 2. For every exposing vserver, find every principal who can
    # reach it. Direct user grants + group grants resolved via
    # `user_group_memberships`. Public vservers expand to *every* user
    # in the tenant — out of scope for a "who" query (return empty
    # for public so we don't flood operators with a tenant-wide list).
    now = datetime.now(UTC)
    direct = list(
        db.execute(
            select(
                VirtualServerGrant.principal_id,
                VirtualServerGrant.vserver_id,
            ).where(
                VirtualServerGrant.tenant_id == tenant_id,
                VirtualServerGrant.principal_kind == GrantPrincipalKind.USER,
                VirtualServerGrant.vserver_id.in_(vserver_ids),
                VirtualServerGrant.revoked_at.is_(None),
                (VirtualServerGrant.expires_at.is_(None))
                | (VirtualServerGrant.expires_at > now),
            )
        ).all()
    )
    via_groups = list(
        db.execute(
            select(
                UserGroupMembership.user_id,
                VirtualServerGrant.principal_id,  # group_id
                VirtualServerGrant.vserver_id,
            )
            .join(
                VirtualServerGrant,
                VirtualServerGrant.principal_id == UserGroupMembership.group_id,
            )
            .where(
                VirtualServerGrant.tenant_id == tenant_id,
                VirtualServerGrant.principal_kind == GrantPrincipalKind.GROUP,
                VirtualServerGrant.vserver_id.in_(vserver_ids),
                VirtualServerGrant.revoked_at.is_(None),
                (VirtualServerGrant.expires_at.is_(None))
                | (VirtualServerGrant.expires_at > now),
            )
        ).all()
    )

    results: list[WhoCanDoResult] = []
    seen: set[tuple[UUID, UUID]] = set()
    for user_id, vserver_id in direct:
        key = (user_id, vserver_id)
        if key in seen:
            continue
        seen.add(key)
        results.append(
            WhoCanDoResult(
                principal_id=user_id,
                principal_kind=GrantPrincipalKind.USER,
                via_vserver_id=vserver_id,
                via_vserver_name=vserver_names.get(vserver_id, "?"),
                grant_path="direct",
            )
        )
    for user_id, group_id, vserver_id in via_groups:
        key = (user_id, vserver_id)
        if key in seen:
            continue
        seen.add(key)
        results.append(
            WhoCanDoResult(
                principal_id=user_id,
                principal_kind=GrantPrincipalKind.USER,
                via_vserver_id=vserver_id,
                via_vserver_name=vserver_names.get(vserver_id, "?"),
                grant_path=f"group:{group_id}",
            )
        )
    return results


# ---------------------------------------------------------------------------
# 3. dependency_chain
# ---------------------------------------------------------------------------


def dependency_chain(
    db: Session, *, tenant_id: UUID, principal_id: UUID
) -> DependencyGraph:
    """Build a node + edge graph for one principal: principal → vservers
    → tools → upstream MCPs. Empty graph if the principal doesn't
    exist (vs `principal_summary` which returns `None`)."""

    summary = principal_summary(db, tenant_id=tenant_id, principal_id=principal_id)
    if summary is None:
        return DependencyGraph(nodes=(), edges=())

    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []

    principal_node_id = f"principal:{summary.principal_id}"
    nodes[principal_node_id] = GraphNode(
        id=principal_node_id,
        kind="principal",
        label=summary.display,
        risk=summary.max_risk_category.value,
    )
    for v in summary.granted_vservers:
        vs_id = f"vserver:{v.vserver_id}"
        nodes[vs_id] = GraphNode(id=vs_id, kind="vserver", label=v.name)
        edges.append(
            GraphEdge(
                source=principal_node_id,
                target=vs_id,
                kind="grant",
                detail=v.grant_path,
            )
        )
    for t in summary.exposed_tools:
        vs_id = f"vserver:{t.vserver_id}"
        up_id = f"upstream:{t.upstream_server_id}"
        tool_id = f"tool:{t.upstream_server_id}:{t.tool_name}"
        if up_id not in nodes:
            nodes[up_id] = GraphNode(
                id=up_id, kind="upstream", label=t.upstream_display_name
            )
        nodes[tool_id] = GraphNode(
            id=tool_id,
            kind="tool",
            label=t.tool_name,
            risk=t.risk_category.value,
        )
        edges.append(GraphEdge(source=vs_id, target=tool_id, kind="exposes"))
        edges.append(
            GraphEdge(
                source=tool_id, target=up_id, kind="wraps", detail=t.risk_category.value
            )
        )
    return DependencyGraph(nodes=tuple(nodes.values()), edges=tuple(edges))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _GrantInfo:
    """Internal — one grant edge with the path metadata we need to
    label vserver references."""

    vserver_id: UUID
    grant_path: str
    expires_at: datetime | None = field(default=None)
    revoked_at: datetime | None = field(default=None)


def _granted_vservers_for_user(
    db: Session, *, tenant_id: UUID, user_id: UUID
) -> list[VserverRef]:
    """All vservers the user can reach: public + direct grants +
    group-mediated grants. Deduplicated; latest grant_path wins
    (direct > group > public, in that order)."""

    now = datetime.now(UTC)

    # Public vservers — no grant required.
    public = list(
        db.scalars(
            select(VirtualServer).where(
                VirtualServer.tenant_id == tenant_id,
                VirtualServer.visibility == "public",
            )
        ).all()
    )
    # Direct user grants.
    direct = list(
        db.execute(
            select(
                VirtualServer.id,
                VirtualServer.name,
                VirtualServer.visibility,
            )
            .join(
                VirtualServerGrant,
                (VirtualServerGrant.vserver_id == VirtualServer.id)
                & (VirtualServerGrant.tenant_id == tenant_id),
            )
            .where(
                VirtualServer.tenant_id == tenant_id,
                VirtualServerGrant.principal_kind == GrantPrincipalKind.USER,
                VirtualServerGrant.principal_id == user_id,
                VirtualServerGrant.revoked_at.is_(None),
                (VirtualServerGrant.expires_at.is_(None))
                | (VirtualServerGrant.expires_at > now),
            )
        ).all()
    )
    # Group-mediated grants.
    via_groups = list(
        db.execute(
            select(
                VirtualServer.id,
                VirtualServer.name,
                VirtualServer.visibility,
                UserGroupMembership.group_id,
            )
            .join(
                VirtualServerGrant,
                (VirtualServerGrant.vserver_id == VirtualServer.id)
                & (VirtualServerGrant.tenant_id == tenant_id),
            )
            .join(
                UserGroupMembership,
                UserGroupMembership.group_id == VirtualServerGrant.principal_id,
            )
            .where(
                VirtualServer.tenant_id == tenant_id,
                VirtualServerGrant.principal_kind == GrantPrincipalKind.GROUP,
                VirtualServerGrant.revoked_at.is_(None),
                (VirtualServerGrant.expires_at.is_(None))
                | (VirtualServerGrant.expires_at > now),
                UserGroupMembership.user_id == user_id,
            )
        ).all()
    )

    # Build canonical map — direct beats group, group beats public.
    by_id: dict[UUID, VserverRef] = {}
    for v in public:
        by_id[v.id] = VserverRef(
            vserver_id=v.id, name=v.name, visibility="public", grant_path="public"
        )
    for vid, name, visibility, group_id in via_groups:
        by_id[vid] = VserverRef(
            vserver_id=vid,
            name=name,
            visibility=visibility,
            grant_path=f"group:{group_id}",
        )
    for vid, name, visibility in direct:
        by_id[vid] = VserverRef(
            vserver_id=vid,
            name=name,
            visibility=visibility,
            grant_path="direct",
        )
    return sorted(by_id.values(), key=lambda v: v.name)


def _exposed_tools_for_vservers(
    db: Session, *, tenant_id: UUID, vserver_ids: list[UUID]
) -> list[ToolRef]:
    """Every tool exposure under the given vservers, joined to its
    risk_category from `mcp_capabilities` (UNKNOWN if not synced yet)."""

    if not vserver_ids:
        return []

    rows = list(
        db.execute(
            select(
                VirtualServerTool.vserver_id,
                VirtualServerTool.server_id,
                VirtualServerTool.tool_name,
                McpServer.display_name,
            )
            .join(
                McpServer,
                (McpServer.id == VirtualServerTool.server_id)
                & (McpServer.tenant_id == tenant_id),
            )
            .where(
                VirtualServerTool.tenant_id == tenant_id,
                VirtualServerTool.vserver_id.in_(vserver_ids),
            )
        ).all()
    )
    if not rows:
        return []

    # Pull the risk lookup in one shot — bounded by the tenant's
    # capability count, not by the join cardinality.
    cap_rows = list(
        db.execute(
            select(McpCapability.server_id, McpCapability.name, McpCapability.risk_category)
            .where(
                McpCapability.tenant_id == tenant_id,
                McpCapability.kind == McpCapabilityKind.TOOL,
            )
        ).all()
    )
    risk_by_pair: dict[tuple[UUID, str], RiskCategory] = {
        # psycopg returns the column as a plain str; coerce back to
        # the enum so the dataclass + downstream comparisons work.
        (sid, name): RiskCategory(risk) if not isinstance(risk, RiskCategory) else risk
        for sid, name, risk in cap_rows
    }

    return [
        ToolRef(
            vserver_id=vserver_id,
            upstream_server_id=server_id,
            upstream_display_name=display_name,
            tool_name=tool_name,
            risk_category=risk_by_pair.get(
                (server_id, tool_name), RiskCategory.UNKNOWN
            ),
        )
        for vserver_id, server_id, tool_name, display_name in rows
    ]


def _reachable_upstreams(
    db: Session, *, tenant_id: UUID, user_id: UUID, upstream_ids: set[UUID]
) -> list[UpstreamRef]:
    """The set of MCP servers this user can reach. Annotated with
    OAuth-authcode connection state when the upstream uses that
    auth mode."""

    if not upstream_ids:
        return []

    servers = list(
        db.scalars(
            select(McpServer).where(
                McpServer.tenant_id == tenant_id,
                McpServer.id.in_(upstream_ids),
            )
        ).all()
    )
    # Lookup: which authcode-using servers does this user already have
    # tokens for?
    connected_ids = set(
        db.scalars(
            select(OAuthUserToken.server_id).where(
                OAuthUserToken.tenant_id == tenant_id,
                OAuthUserToken.user_id == user_id,
                OAuthUserToken.server_id.in_(upstream_ids),
            )
        ).all()
    )
    return [
        UpstreamRef(
            server_id=s.id,
            display_name=s.display_name,
            transport=str(s.transport.value if hasattr(s.transport, "value") else s.transport),
            source_type=str(
                s.source_type.value if hasattr(s.source_type, "value") else s.source_type
            ),
            oauth_connected=(
                s.id in connected_ids
                if s.auth_authcode is not None
                else None
            ),
        )
        for s in servers
    ]


def _oauth_connections(
    db: Session, *, tenant_id: UUID, user_id: UUID
) -> list[OAuthConnection]:
    rows = list(
        db.execute(
            select(OAuthUserToken, McpServer).join(
                McpServer,
                (McpServer.id == OAuthUserToken.server_id)
                & (McpServer.tenant_id == tenant_id),
            ).where(
                OAuthUserToken.tenant_id == tenant_id,
                OAuthUserToken.user_id == user_id,
            )
        ).all()
    )
    return [
        OAuthConnection(
            server_id=token.server_id,
            server_display_name=server.display_name,
            scope=token.scope,
            expires_at=token.expires_at,
            last_refreshed_at=token.last_refreshed_at,
        )
        for token, server in rows
    ]


def _max_risk(categories: Iterable[RiskCategory]) -> RiskCategory:
    """Highest-severity category in the iterable. UNKNOWN if empty."""

    best = RiskCategory.UNKNOWN
    best_score = -2
    for c in categories:
        score = _RISK_SEVERITY.get(c, -1)
        if score > best_score:
            best, best_score = c, score
    return best


def _risk_score(tools: Iterable[ToolRef]) -> int:
    """Derive a 0..100 risk score from the principal's tool reach.

    The number is a heuristic, not a math claim — we want operators
    to be able to sort identities by danger without staring at a
    histogram. Formula:

      base    = 10 × (max severity 0..6)        # 0..60
      breadth = min(40, count of high-risk tools × 4)  # 0..40

    A reader-only identity scores 10 (READ + 0 high-risk). A user
    with 10+ high-risk tools maxes at 100.
    """

    tools = list(tools)
    if not tools:
        return 0
    max_severity = max(
        (_RISK_SEVERITY.get(t.risk_category, -1) for t in tools), default=-1
    )
    high_risk_count = sum(
        1
        for t in tools
        if _RISK_SEVERITY.get(t.risk_category, -1) >= _RISK_SEVERITY[RiskCategory.DELETE]
    )
    base = max(0, max_severity) * 10
    breadth = min(40, high_risk_count * 4)
    return min(100, base + breadth)


def _categories_at_or_above(floor: RiskCategory) -> list[RiskCategory]:
    floor_score = _RISK_SEVERITY.get(floor, -1)
    return [c for c, s in _RISK_SEVERITY.items() if s >= floor_score]
