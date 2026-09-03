"""NHI (Non-Human Identity) graph event schema.

Telemetry feeds two pipelines: audit (per-call decision record) and graph
(normalized identity/access topology). Audit answers "what happened on this
call"; the graph answers "which non-human identity reached which resource via
which path." A graph database is *not* built yet; this module defines the
event payload that a future ingestion service will consume.

A `GraphEvent` is a batch of edges observed from a single tool-call
observation. Edges carry typed source/target nodes; both nodes and edges are
tenant-scoped and pseudonymous (we never serialize tool arguments or response
content into the graph).
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class GraphNodeType(StrEnum):
    PRINCIPAL = "principal"
    CLIENT = "client"
    VSERVER = "vserver"
    TOOL = "tool"
    SERVER = "server"
    RESOURCE = "resource"


class GraphEdgeType(StrEnum):
    PRINCIPAL_USED_CLIENT = "principal_used_client"
    CLIENT_CONNECTED_VSERVER = "client_connected_vserver"
    VSERVER_EXPOSED_TOOL = "vserver_exposed_tool"
    TOOL_ROUTED_TO_SERVER = "tool_routed_to_server"
    SERVER_ACCESSED_RESOURCE = "server_accessed_resource"
    PRINCIPAL_CALLED_TOOL = "principal_called_tool"


class GraphNode(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: GraphNodeType
    # Stable, tenant-scoped identifier of the node, e.g.
    # "principal:endpoint_session:abc", "tool:<vserver_id>:list_repos".
    id: str = Field(min_length=1)
    display: str | None = None


class GraphEdge(BaseModel):
    model_config = ConfigDict(frozen=True)

    edge_id: UUID = Field(default_factory=uuid4)
    type: GraphEdgeType
    source: GraphNode
    target: GraphNode


class GraphEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tenant_id: UUID
    # Same UUID as the audit event for the same tool call so consumers of both
    # pipelines can join records.
    correlation_id: UUID
    edges: tuple[GraphEdge, ...] = Field(default_factory=tuple)

    def edges_of_type(self, edge_type: GraphEdgeType) -> tuple[GraphEdge, ...]:
        return tuple(edge for edge in self.edges if edge.type == edge_type)
