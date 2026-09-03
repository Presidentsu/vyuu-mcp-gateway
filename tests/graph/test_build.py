from typing import Any
from uuid import uuid4

from vyuu_gateway.audit.events import AuditPrincipal, AuditPrincipalType, UpstreamStatus
from vyuu_gateway.graph.build import build_tool_call_graph_event
from vyuu_gateway.graph.events import GraphEdgeType, GraphNodeType


def _principal() -> AuditPrincipal:
    return AuditPrincipal(
        type=AuditPrincipalType.ENDPOINT_SESSION,
        id="endpoint-session-1",
        display="Endpoint Session 1",
    )


def _common_kwargs() -> dict[str, Any]:
    return {
        "tenant_id": uuid4(),
        "correlation_id": uuid4(),
        "principal": _principal(),
        "session_id": "session-1",
        "vserver_name": "finance-readonly",
    }


def test_full_resolved_call_emits_full_chain_with_resource_edge() -> None:
    upstream_server_id = uuid4()
    vserver_id = uuid4()

    event = build_tool_call_graph_event(
        **_common_kwargs(),
        vserver_id=vserver_id,
        upstream_status=UpstreamStatus.OK,
        resolved_exposed_name="query",
        resolved_upstream_server_id=upstream_server_id,
        resolved_upstream_tool_name="query_select",
    )

    edge_types = [edge.type for edge in event.edges]
    assert edge_types == [
        GraphEdgeType.PRINCIPAL_USED_CLIENT,
        GraphEdgeType.CLIENT_CONNECTED_VSERVER,
        GraphEdgeType.VSERVER_EXPOSED_TOOL,
        GraphEdgeType.PRINCIPAL_CALLED_TOOL,
        GraphEdgeType.TOOL_ROUTED_TO_SERVER,
        GraphEdgeType.SERVER_ACCESSED_RESOURCE,
    ]


def test_node_types_and_ids_match_expected_shape() -> None:
    upstream_server_id = uuid4()
    vserver_id = uuid4()
    tenant_id = uuid4()

    event = build_tool_call_graph_event(
        tenant_id=tenant_id,
        correlation_id=uuid4(),
        principal=_principal(),
        session_id="session-1",
        vserver_name="finance-readonly",
        vserver_id=vserver_id,
        client_display="claude_desktop",
        upstream_status=UpstreamStatus.OK,
        resolved_exposed_name="query",
        resolved_upstream_server_id=upstream_server_id,
        resolved_upstream_tool_name="query_select",
    )

    by_type = {edge.type: edge for edge in event.edges}

    principal_used_client = by_type[GraphEdgeType.PRINCIPAL_USED_CLIENT]
    assert principal_used_client.source.type == GraphNodeType.PRINCIPAL
    assert principal_used_client.source.id == "principal:endpoint_session:endpoint-session-1"
    assert principal_used_client.target.type == GraphNodeType.CLIENT
    assert principal_used_client.target.id == "client:session-1"
    assert principal_used_client.target.display == "claude_desktop"

    client_connected_vserver = by_type[GraphEdgeType.CLIENT_CONNECTED_VSERVER]
    assert client_connected_vserver.source.id == "client:session-1"
    assert client_connected_vserver.target.id == f"vserver:{vserver_id}"

    vserver_exposed_tool = by_type[GraphEdgeType.VSERVER_EXPOSED_TOOL]
    assert vserver_exposed_tool.source.id == f"vserver:{vserver_id}"
    assert vserver_exposed_tool.target.id == f"tool:vserver:{vserver_id}:query"

    principal_called_tool = by_type[GraphEdgeType.PRINCIPAL_CALLED_TOOL]
    assert principal_called_tool.source.id == "principal:endpoint_session:endpoint-session-1"
    assert principal_called_tool.target.id == f"tool:vserver:{vserver_id}:query"

    tool_routed_to_server = by_type[GraphEdgeType.TOOL_ROUTED_TO_SERVER]
    assert tool_routed_to_server.source.id == f"tool:vserver:{vserver_id}:query"
    assert tool_routed_to_server.target.id == f"server:{upstream_server_id}"

    server_accessed_resource = by_type[GraphEdgeType.SERVER_ACCESSED_RESOURCE]
    assert server_accessed_resource.source.id == f"server:{upstream_server_id}"
    assert (
        server_accessed_resource.target.id
        == f"resource:server:{upstream_server_id}:tool:query_select"
    )


def test_correlation_and_tenant_id_propagate_to_event() -> None:
    correlation_id = uuid4()
    tenant_id = uuid4()

    event = build_tool_call_graph_event(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        principal=_principal(),
        session_id="session-1",
        vserver_name="finance-readonly",
        upstream_status=UpstreamStatus.OK,
    )

    assert event.tenant_id == tenant_id
    assert event.correlation_id == correlation_id


def test_no_resolved_tool_emits_only_session_chain() -> None:
    event = build_tool_call_graph_event(
        **_common_kwargs(),
        upstream_status=UpstreamStatus.NOT_CALLED,
    )

    assert [edge.type for edge in event.edges] == [
        GraphEdgeType.PRINCIPAL_USED_CLIENT,
        GraphEdgeType.CLIENT_CONNECTED_VSERVER,
    ]


def test_resolved_but_not_called_omits_resource_edge() -> None:
    event = build_tool_call_graph_event(
        **_common_kwargs(),
        upstream_status=UpstreamStatus.NOT_CALLED,
        resolved_exposed_name="query",
        resolved_upstream_server_id=uuid4(),
        resolved_upstream_tool_name="query_select",
    )

    types = [edge.type for edge in event.edges]
    assert GraphEdgeType.SERVER_ACCESSED_RESOURCE not in types
    assert GraphEdgeType.TOOL_ROUTED_TO_SERVER in types
    assert GraphEdgeType.PRINCIPAL_CALLED_TOOL in types


def test_upstream_error_still_records_resource_edge_because_call_was_attempted() -> None:
    event = build_tool_call_graph_event(
        **_common_kwargs(),
        upstream_status=UpstreamStatus.ERROR,
        resolved_exposed_name="query",
        resolved_upstream_server_id=uuid4(),
        resolved_upstream_tool_name="query_select",
    )

    assert any(
        edge.type == GraphEdgeType.SERVER_ACCESSED_RESOURCE for edge in event.edges
    )


def test_upstream_timeout_still_records_resource_edge_because_call_was_attempted() -> None:
    event = build_tool_call_graph_event(
        **_common_kwargs(),
        upstream_status=UpstreamStatus.TIMEOUT,
        resolved_exposed_name="query",
        resolved_upstream_server_id=uuid4(),
        resolved_upstream_tool_name="query_select",
    )

    assert any(
        edge.type == GraphEdgeType.SERVER_ACCESSED_RESOURCE for edge in event.edges
    )


def test_vserver_node_falls_back_to_tenant_scoped_id_when_id_unknown() -> None:
    tenant_id = uuid4()
    event = build_tool_call_graph_event(
        tenant_id=tenant_id,
        correlation_id=uuid4(),
        principal=_principal(),
        session_id="session-1",
        vserver_name="finance-readonly",
        upstream_status=UpstreamStatus.NOT_CALLED,
    )

    client_connected = next(
        edge for edge in event.edges if edge.type == GraphEdgeType.CLIENT_CONNECTED_VSERVER
    )
    assert client_connected.target.id == f"vserver:{tenant_id}:finance-readonly"


def test_edges_have_unique_ids() -> None:
    event = build_tool_call_graph_event(
        **_common_kwargs(),
        upstream_status=UpstreamStatus.OK,
        resolved_exposed_name="query",
        resolved_upstream_server_id=uuid4(),
        resolved_upstream_tool_name="query_select",
    )

    edge_ids = [edge.edge_id for edge in event.edges]
    assert len(edge_ids) == len(set(edge_ids))
