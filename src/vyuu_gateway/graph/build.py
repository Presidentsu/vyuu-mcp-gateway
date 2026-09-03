"""Build NHI graph events from tool-call lifecycle observations.

Pure function. Takes the resolved-state of a single tool call (session,
principal, optionally a resolved tool, and the observed upstream status) and
returns a `GraphEvent` carrying the appropriate normalized edges.

Edge inclusion policy:
- `principal_used_client` and `client_connected_vserver` are included whenever
  we have both a session and a validated principal.
- `vserver_exposed_tool`, `principal_called_tool`, `tool_routed_to_server`
  are included whenever a tool was resolved (i.e., we got past virtual-server
  tool resolution).
- `server_accessed_resource` is included only when the upstream call was
  attempted (status `OK`, `ERROR`, or `TIMEOUT`). The resource node is coarse
  (`tool:<upstream_tool_name>`); we do not derive resource identity from
  arguments because that would require persisting argument content into the
  graph.

The builder takes primitive parameters rather than lifecycle types so the
graph module stays independent of `tool_calls/` (no circular imports).
"""

from __future__ import annotations

from uuid import UUID

from vyuu_gateway.audit.events import AuditPrincipal, UpstreamStatus
from vyuu_gateway.graph.events import (
    GraphEdge,
    GraphEdgeType,
    GraphEvent,
    GraphNode,
    GraphNodeType,
)

_UPSTREAM_ATTEMPTED = frozenset(
    {UpstreamStatus.OK, UpstreamStatus.ERROR, UpstreamStatus.TIMEOUT}
)


def build_tool_call_graph_event(
    *,
    tenant_id: UUID,
    correlation_id: UUID,
    principal: AuditPrincipal,
    session_id: str,
    vserver_name: str,
    upstream_status: UpstreamStatus,
    vserver_id: UUID | None = None,
    client_display: str | None = None,
    resolved_exposed_name: str | None = None,
    resolved_upstream_server_id: UUID | None = None,
    resolved_upstream_tool_name: str | None = None,
) -> GraphEvent:
    edges: list[GraphEdge] = []

    principal_node = _principal_node(principal)
    client_node = _client_node(session_id, client_display)
    vserver_node = _vserver_node(
        tenant_id=tenant_id,
        vserver_id=vserver_id,
        vserver_name=vserver_name,
    )

    edges.append(
        GraphEdge(
            type=GraphEdgeType.PRINCIPAL_USED_CLIENT,
            source=principal_node,
            target=client_node,
        )
    )
    edges.append(
        GraphEdge(
            type=GraphEdgeType.CLIENT_CONNECTED_VSERVER,
            source=client_node,
            target=vserver_node,
        )
    )

    has_resolved_tool = (
        resolved_exposed_name is not None
        and resolved_upstream_server_id is not None
        and resolved_upstream_tool_name is not None
    )
    if has_resolved_tool:
        # Mypy needs the explicit narrowing.
        assert resolved_exposed_name is not None
        assert resolved_upstream_server_id is not None
        assert resolved_upstream_tool_name is not None

        tool_node = _tool_node(vserver_node.id, resolved_exposed_name)
        server_node = _server_node(resolved_upstream_server_id)
        edges.append(
            GraphEdge(
                type=GraphEdgeType.VSERVER_EXPOSED_TOOL,
                source=vserver_node,
                target=tool_node,
            )
        )
        edges.append(
            GraphEdge(
                type=GraphEdgeType.PRINCIPAL_CALLED_TOOL,
                source=principal_node,
                target=tool_node,
            )
        )
        edges.append(
            GraphEdge(
                type=GraphEdgeType.TOOL_ROUTED_TO_SERVER,
                source=tool_node,
                target=server_node,
            )
        )
        if upstream_status in _UPSTREAM_ATTEMPTED:
            resource_node = _resource_node(
                resolved_upstream_server_id,
                resolved_upstream_tool_name,
            )
            edges.append(
                GraphEdge(
                    type=GraphEdgeType.SERVER_ACCESSED_RESOURCE,
                    source=server_node,
                    target=resource_node,
                )
            )

    return GraphEvent(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        edges=tuple(edges),
    )


def _principal_node(principal: AuditPrincipal) -> GraphNode:
    return GraphNode(
        type=GraphNodeType.PRINCIPAL,
        id=f"principal:{principal.type.value}:{principal.id}",
        display=principal.display or None,
    )


def _client_node(session_id: str, client_display: str | None) -> GraphNode:
    return GraphNode(
        type=GraphNodeType.CLIENT,
        id=f"client:{session_id}",
        display=client_display,
    )


def _vserver_node(
    *,
    tenant_id: UUID,
    vserver_id: UUID | None,
    vserver_name: str,
) -> GraphNode:
    if vserver_id is not None:
        node_id = f"vserver:{vserver_id}"
    else:
        node_id = f"vserver:{tenant_id}:{vserver_name}"
    return GraphNode(
        type=GraphNodeType.VSERVER,
        id=node_id,
        display=vserver_name,
    )


def _tool_node(vserver_node_id: str, exposed_name: str) -> GraphNode:
    return GraphNode(
        type=GraphNodeType.TOOL,
        id=f"tool:{vserver_node_id}:{exposed_name}",
        display=exposed_name,
    )


def _server_node(upstream_server_id: UUID) -> GraphNode:
    return GraphNode(
        type=GraphNodeType.SERVER,
        id=f"server:{upstream_server_id}",
    )


def _resource_node(upstream_server_id: UUID, upstream_tool_name: str) -> GraphNode:
    return GraphNode(
        type=GraphNodeType.RESOURCE,
        id=f"resource:server:{upstream_server_id}:tool:{upstream_tool_name}",
        display=upstream_tool_name,
    )
