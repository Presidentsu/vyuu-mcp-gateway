"""NHI map: 4-column bipartite graph for the operator dashboard.

Returns the data shape needed to render a "People & AI — who uses
what" visualisation: users, AI apps (the MCP clients calling in:
Cursor, Claude Desktop, ChatGPT, etc. — inferred from
`client_metadata.user_agent` on audit events), MCP servers, and
agents (autonomous callers — heuristically detected from principal
type + display).

Edge weights = number of interactions between the two endpoints in
the time-bounded event window. Sanctioned vs unsanctioned classification:

- An **MCP server** is *sanctioned* if it's registered in
  `mcp_servers` (the gateway knows about it). Calls hit registered
  servers exclusively today, so MCP servers seen in events are all
  sanctioned by definition. The hook stays here so a future
  inferred-from-traffic source can flip the flag.
- An **AI app** is *sanctioned* if it's in the operator's known
  client allowlist (currently a static list of well-known clients
  by user_agent prefix). Anything else (a curl, a custom n8n flow,
  a homegrown agent) renders as unsanctioned with a dashed outline
  in the UI.

This is a read endpoint — no mutations, all aggregation. Pulls from
the persistent `tool_call_events` table so the map survives gateway
restarts. Tenant scoping is enforced via RLS on the bound session.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.audit.events import AuditEvent, AuditEventType
from vyuu_gateway.audit.persistent import query_tool_call_events
from vyuu_gateway.db.models import McpCapability, McpServer, User
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator

# Default look-back if the caller doesn't pass `since`. Matches the
# operator UI's default time-range picker — "last 24h".
_DEFAULT_LOOKBACK = timedelta(hours=24)

router = APIRouter(tags=["nhi-map"])


# Known MCP-client user-agent prefixes. Operators can grow this list
# in code as new sanctioned clients show up. Anything outside the
# allowlist renders as `sanctioned=False` in the UI — a dashed circle.
_KNOWN_CLIENTS: tuple[tuple[str, str], ...] = (
    # (display label, regex against user-agent)
    ("Cursor",         r"(?i)cursor"),
    ("Claude Desktop", r"(?i)claude.?desktop"),
    ("ChatGPT",        r"(?i)chatgpt|openai-?ai"),
    ("Continue",       r"(?i)continue\.dev|continue/"),
    ("Cline",          r"(?i)cline"),
    ("Zed",            r"(?i)zed"),
    ("Goose",          r"(?i)block-?goose|goose/"),
    ("Windsurf",       r"(?i)windsurf"),
)


# Heuristic — principal display strings that look automated. We can't
# distinguish humans from bots perfectly without an explicit type
# tag, so this is best-effort. A future improvement is to plumb a
# `principal.is_agent` field through audit events.
_AGENT_HINTS = re.compile(
    r"(?i)bot|agent|workflow|cron|n8n|zapier|automation|service|sa-",
)


@dataclass(frozen=True)
class _Edge:
    source: str
    target: str
    weight: int


class NhiMapNode(BaseModel):
    """One node in the bipartite map.

    `column` is the layer this node sits on. The full set is:

      - `user`        — human principals (tenant users)
      - `ai_app`      — AI clients (Cursor, Claude Desktop, ChatGPT,
                        Continue, …) inferred from `user_agent`
      - `mcp_server`  — registered upstreams the gateway routes to
      - `agent`       — programmatic principals (named like an agent
                        per the heuristic in `_is_likely_agent`)
      - `tool`        — individual tool names called per server
      - `risk`        — risk category buckets (read / write / delete /
                        execute / admin / etc.); a coarser 5th-column
                        alternative to per-tool nodes

    Only nodes referenced by edges show up in any one render — the
    UI picks which 5th column (tool vs risk) to display via a
    toggle, so both sets are emitted and the FE filters.
    """

    model_config = ConfigDict(from_attributes=False)

    id: str
    column: str  # user | ai_app | mcp_server | agent | tool | risk
    label: str
    sanctioned: bool
    detail: str | None = None


class NhiMapEdge(BaseModel):
    model_config = ConfigDict(from_attributes=False)

    source: str
    target: str
    weight: int


class NhiMap(BaseModel):
    model_config = ConfigDict(from_attributes=False)

    nodes: list[NhiMapNode]
    edges: list[NhiMapEdge]
    # Total events scanned — useful for the UI to show "based on N
    # interactions" without forcing the operator to peek at limits.
    sample_size: int


def _classify_ai_app(
    user_agent: str | None, *, client_id: str | None = None
) -> tuple[str, str, bool]:
    """Map a caller to (id, display, sanctioned) for the AI-app column.

    `client_id` (EMA-1 P3) wins when present: it is the MCP client the
    enterprise IdP authorized on the ID-JAG, so it is attested rather
    than self-declared — unlike `user_agent`, which the caller sets
    freely. Such a client is sanctioned by definition: the IdP's own
    policy gate already vetted it at token-exchange time.

    Falls back to user-agent matching. Returns
    `("unknown:<ua>", "Unknown client", False)` for anything we can't
    recognise — the dashed-outline node in the UI."""

    if client_id:
        return f"idp:{client_id}", client_id, True
    if not user_agent:
        return "unknown:none", "Unknown / no UA", False
    for label, pattern in _KNOWN_CLIENTS:
        if re.search(pattern, user_agent):
            return f"app:{label.lower()}", label, True
    # Truncate for a stable id without overflowing.
    short = user_agent.strip()[:48].replace(" ", "-").lower()
    return f"unknown:{short}", short or "(empty)", False


def _is_likely_agent(display: str, principal_id: str) -> bool:
    """Best-effort 'this looks like an automated caller' heuristic.

    Without an explicit principal-type-is-agent flag, fall back to
    common naming patterns. Conservative — under-detect rather than
    incorrectly classify a human as an agent."""

    return bool(_AGENT_HINTS.search(display) or _AGENT_HINTS.search(principal_id))


@router.get("/nhi-map", response_model=NhiMap)
def nhi_map_endpoint(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
    sanctioned_only: Annotated[bool, Query()] = False,
    since: Annotated[datetime | None, Query()] = None,
    until: Annotated[datetime | None, Query()] = None,
    event_window: Annotated[int, Query(ge=1, le=10_000)] = 2000,
) -> NhiMap:
    """Build the 4-column NHI map.

    Reads from persistent `tool_call_events` so the map survives
    gateway restarts. Default window is the last 24h; the operator
    can override via `since` / `until` ISO timestamps.

    `sanctioned_only=true` filters out unknown clients + (when we add
    inferred upstreams in the future) unregistered MCP servers."""

    effective_since = since or (datetime.now(UTC) - _DEFAULT_LOOKBACK)
    events = query_tool_call_events(
        db,
        tenant_id=operator.tenant_id,
        since=effective_since,
        until=until,
        event_type=AuditEventType.TOOL_CALL,
        limit=event_window,
    )

    # --- DB lookups for label resolution -----------------------------
    # Map known principal_ids that look like UUIDs back to user emails.
    # Failed lookups stay as the raw id — that's fine for non-user
    # principals (anonymous endpoint sessions, etc).
    user_uuids: set[UUID] = set()
    for ev in events:
        try:
            user_uuids.add(UUID(ev.principal.id))
        except (ValueError, AttributeError):
            continue
    user_email_by_id: dict[UUID, str] = {}
    if user_uuids:
        rows = list(
            db.execute(
                select(User.id, User.email).where(
                    User.tenant_id == operator.tenant_id,
                    User.id.in_(user_uuids),
                )
            ).all()
        )
        # SQLAlchemy 2.0 returns Row objects which iterate as tuples;
        # explicit unpack keeps mypy happy without disabling the C416
        # check globally.
        user_email_by_id = {row[0]: row[1] for row in rows}  # noqa: C416

    # MCP server display names — for label resolution on mcp_server nodes.
    server_uuids = {
        ev.upstream_server_id for ev in events if ev.upstream_server_id is not None
    }
    server_label_by_id: dict[UUID, str] = {}
    if server_uuids:
        srv_rows = list(
            db.execute(
                select(McpServer.id, McpServer.display_name).where(
                    McpServer.tenant_id == operator.tenant_id,
                    McpServer.id.in_(server_uuids),
                )
            ).all()
        )
        server_label_by_id = {row[0]: row[1] for row in srv_rows}  # noqa: C416

    # Risk-category lookup for tool nodes — same shape the identities
    # aggregator uses. Joined to `mcp_capabilities` by (server, name);
    # falls back to "unknown" for events whose tool isn't in the
    # capability catalogue (e.g. an upstream returned a tool name we
    # haven't synced yet, or sync ran before the call).
    risk_by_tool: dict[tuple[UUID, str], str] = {}
    if server_uuids:
        cap_rows = list(
            db.execute(
                select(
                    McpCapability.server_id,
                    McpCapability.name,
                    McpCapability.risk_category,
                ).where(
                    McpCapability.tenant_id == operator.tenant_id,
                    McpCapability.server_id.in_(server_uuids),
                )
            ).all()
        )
        for sid, tname, risk in cap_rows:
            # SQLAlchemy may surface the column as str even though the
            # model types it RiskCategory; coerce to its value-string
            # for consistent JSON output.
            risk_str = (
                risk.value if hasattr(risk, "value")
                else (str(risk) if risk else "unknown")
            )
            risk_by_tool[(sid, tname)] = risk_str

    # --- Walk events, build nodes + edges ----------------------------
    nodes: dict[str, NhiMapNode] = {}
    edges: dict[tuple[str, str], int] = {}

    def _add_node(node: NhiMapNode) -> None:
        existing = nodes.get(node.id)
        if existing is None:
            nodes[node.id] = node
        elif not existing.sanctioned and node.sanctioned:
            # Promote: a later event with a richer (sanctioned) shape
            # wins over an earlier ambiguous one.
            nodes[node.id] = node

    def _add_edge(source: str, target: str) -> None:
        key = (source, target)
        edges[key] = edges.get(key, 0) + 1

    for ev in _walk_relevant_events(events):
        # User node
        principal_label = ev.principal.display or ev.principal.id
        try:
            uid = UUID(ev.principal.id)
            principal_label = user_email_by_id.get(uid, principal_label)
            user_node_id = f"user:{ev.principal.id}"
        except (ValueError, AttributeError):
            user_node_id = f"user:{ev.principal.id}"

        # If the principal looks like an automated caller, it goes in
        # the Agents column instead of Users. Either way the source-of-
        # edges is the same node id.
        is_agent = _is_likely_agent(ev.principal.display, ev.principal.id)
        column = "agent" if is_agent else "user"
        _add_node(
            NhiMapNode(
                id=user_node_id,
                column=column,
                label=principal_label,
                sanctioned=True,  # tenant users are always sanctioned
                detail=ev.principal.type.value
                if hasattr(ev.principal.type, "value")
                else str(ev.principal.type),
            )
        )

        # AI app node (from user_agent)
        ua = (
            ev.client_metadata.user_agent
            if ev.client_metadata is not None
            else None
        )
        client_id = (
            ev.client_metadata.client_id if ev.client_metadata is not None else None
        )
        app_id, app_label, app_sanctioned = _classify_ai_app(ua, client_id=client_id)
        if sanctioned_only and not app_sanctioned:
            continue  # filter the whole interaction out
        _add_node(
            NhiMapNode(
                id=app_id,
                column="ai_app",
                label=app_label,
                sanctioned=app_sanctioned,
                detail=ua,
            )
        )

        # MCP server node (only if the call had an upstream)
        mcp_node_id: str | None = None
        if ev.upstream_server_id is not None:
            mcp_node_id = f"mcp:{ev.upstream_server_id}"
            _add_node(
                NhiMapNode(
                    id=mcp_node_id,
                    column="mcp_server",
                    label=server_label_by_id.get(
                        ev.upstream_server_id, str(ev.upstream_server_id)[:8]
                    ),
                    sanctioned=ev.upstream_server_id in server_label_by_id,
                    detail=str(ev.upstream_server_id),
                )
            )

        # Edges: user/agent → ai_app → mcp_server.
        _add_edge(user_node_id, app_id)
        if mcp_node_id is not None:
            _add_edge(app_id, mcp_node_id)

        # 5th column · Tool / Risk nodes for this call. Both shapes
        # are emitted so the FE can toggle between "by tool name" and
        # "by risk category" without a re-fetch. The toggle is the
        # operator UI's `nhi-map-fifth` select.
        if (
            mcp_node_id is not None
            and ev.upstream_server_id is not None
            and ev.tool
        ):
            srv_id: UUID = ev.upstream_server_id
            tool_node_id = f"tool:{srv_id}:{ev.tool}"
            # Tool / risk nodes inherit sanctioned-ness from their
            # parent MCP server. The "sanctioned" flag is reserved for
            # the unrecognized-client signal (an `ai_app` whose user-
            # agent doesn't match any known client) — NOT a "we
            # haven't classified this tool's risk yet" marker. The
            # per-tool risk_category is surfaced in the node's
            # `detail` for hover tooltip without flipping sanctioned.
            tool_risk = risk_by_tool.get((srv_id, ev.tool))
            _add_node(
                NhiMapNode(
                    id=tool_node_id,
                    column="tool",
                    label=ev.tool,
                    sanctioned=True,
                    detail=(
                        f"{server_label_by_id.get(srv_id, '')} · {ev.tool}"
                        + (f" · {tool_risk}" if tool_risk else "")
                    ),
                )
            )
            _add_edge(mcp_node_id, tool_node_id)

            # Risk-category node (one per category seen on this server's
            # tools). Anchors a `mcp_server -> risk` edge so the FE
            # can render either 5th-column variant without losing
            # connectivity.
            risk = tool_risk or "unknown"
            risk_node_id = f"risk:{risk}"
            _add_node(
                NhiMapNode(
                    id=risk_node_id,
                    column="risk",
                    label=risk,
                    sanctioned=True,
                    detail=f"risk class · {risk}",
                )
            )
            _add_edge(mcp_node_id, risk_node_id)

    return NhiMap(
        nodes=list(nodes.values()),
        edges=[
            NhiMapEdge(source=s, target=t, weight=w)
            for (s, t), w in edges.items()
        ],
        sample_size=len(events),
    )


def _walk_relevant_events(events: list[AuditEvent]) -> list[AuditEvent]:
    """Hook for future filtering — for now identity to keep the call
    site readable. Encapsulated so tests can prove the data flow."""

    return events


# Public re-exports for tests.
__all__ = [
    "NhiMap",
    "NhiMapEdge",
    "NhiMapNode",
    "_classify_ai_app",
    "_is_likely_agent",
    "router",
]


# Avoid unused-import warning when the module is imported but `Edge`
# isn't directly referenced (kept for future use).
_ = field, _Edge
