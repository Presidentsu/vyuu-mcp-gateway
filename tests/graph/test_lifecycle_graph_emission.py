"""Lifecycle-level tests verifying NHI graph events are emitted alongside audit."""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from mcp.types import CallToolResult, TextContent

from vyuu_gateway.audit.emitter import EmitResult
from vyuu_gateway.audit.events import (
    AuditClientMetadata,
    AuditEvent,
    AuditPrincipal,
    AuditPrincipalType,
    AuthModeFlags,
)
from vyuu_gateway.graph.emitter import InMemoryGraphEventEmitter
from vyuu_gateway.graph.events import GraphEdgeType, GraphEvent, GraphNodeType
from vyuu_gateway.identity.fake import FakeIdentityProvider
from vyuu_gateway.identity.models import PrincipalType
from vyuu_gateway.identity.provider import IdentityCredentials
from vyuu_gateway.policy.simple import SimplePolicyProvider
from vyuu_gateway.sessions.registry import GatewaySession
from vyuu_gateway.tool_calls.lifecycle import (
    ToolCallLifecycle,
    ToolCallRequest,
    ToolCallStatus,
)
from vyuu_gateway.virtual_servers.resolver import (
    ResolvedToolsList,
    VirtualServerToolCapability,
    synthesize_tools,
)


class FakeSessionRegistry:
    def __init__(self, session: GatewaySession | None) -> None:
        self.session = session

    async def create_session(self, session: GatewaySession) -> None:
        self.session = session

    async def get_session(self, tenant_id: UUID, session_id: str) -> GatewaySession | None:
        if self.session is None:
            return None
        if self.session.tenant_id != tenant_id or self.session.session_id != session_id:
            return None
        return self.session

    async def delete_session(self, tenant_id: UUID, session_id: str) -> None:
        if self.session is not None and (
            self.session.tenant_id == tenant_id
            and self.session.session_id == session_id
        ):
            self.session = None


class FakeResolver:
    def __init__(self, resolved_tools: ResolvedToolsList) -> None:
        self.resolved_tools = resolved_tools

    def resolve_tools(self, tenant_id: UUID, vserver_name: str) -> ResolvedToolsList:
        return self.resolved_tools


class FakeAuditEmitter:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        self.events.append(event)
        return EmitResult(accepted=True)


class FakeUpstreamClient:
    def __init__(
        self,
        *,
        response: CallToolResult | None = None,
        exception: Exception | None = None,
    ) -> None:
        self.response = response or CallToolResult(
            content=[TextContent(type="text", text="ok")],
            isError=False,
        )
        self.exception = exception
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        inbound_headers: dict[str, str] | None = None,  # noqa: ARG002
        principal_id: object = None,  # noqa: ARG002
    ) -> CallToolResult:
        self.calls.append((tool_name, arguments))
        if self.exception is not None:
            raise self.exception
        return self.response


class FakeUpstreamClientProvider:
    def __init__(self, client: FakeUpstreamClient) -> None:
        self.client = client

    def get_client(self, tenant_id: UUID, server_id: UUID) -> FakeUpstreamClient:
        return self.client

    def get_auth_mode_flags(
        self, tenant_id: UUID, server_id: UUID
    ) -> AuthModeFlags:
        return AuthModeFlags()


def _build_lifecycle(
    *,
    tenant_id: UUID,
    session: GatewaySession,
    upstream_server_id: UUID,
    upstream_client: FakeUpstreamClient | None = None,
    policy_provider: SimplePolicyProvider | None = None,
) -> tuple[ToolCallLifecycle, FakeUpstreamClient, FakeAuditEmitter, InMemoryGraphEventEmitter]:
    resolved = synthesize_tools(
        [
            VirtualServerToolCapability(
                server_id=upstream_server_id,
                server_display_name="Postgres",
                tool_name="query_select",
                schema_json={
                    "inputSchema": {
                        "type": "object",
                        "properties": {"sql": {"type": "string"}},
                        "required": ["sql"],
                    }
                },
            )
        ],
        {"query_select": "query"},
    )
    upstream = upstream_client or FakeUpstreamClient()
    audit = FakeAuditEmitter()
    graph = InMemoryGraphEventEmitter()
    lifecycle = ToolCallLifecycle(
        sessions=FakeSessionRegistry(session),
        resolver=FakeResolver(resolved),
        identity_provider=FakeIdentityProvider(),
        policy_provider=policy_provider or SimplePolicyProvider(),
        upstream_clients=FakeUpstreamClientProvider(upstream),
        audit_emitter=audit,
        graph_event_emitter=graph,
        gateway_instance_id="gateway-1",
    )
    return lifecycle, upstream, audit, graph


def _make_session(tenant_id: UUID, *, vserver_id: UUID) -> GatewaySession:
    return GatewaySession(
        session_id="session-1",
        tenant_id=tenant_id,
        vserver_name="finance-readonly",
        vserver_id=vserver_id,
        principal=AuditPrincipal(type=AuditPrincipalType.API_KEY, id="api-key-1"),
        client_metadata=AuditClientMetadata(agent_type="claude_desktop"),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _identity_credentials(tenant_id: UUID) -> IdentityCredentials:
    return IdentityCredentials(
        headers={
            "x-vyuu-tenant-id": str(tenant_id),
            "x-vyuu-principal-type": PrincipalType.ENDPOINT_SESSION.value,
            "x-vyuu-principal-id": "endpoint-session-1",
            "x-vyuu-principal-display": "Endpoint Session 1",
        }
    )


def _only_event(emitter: InMemoryGraphEventEmitter) -> GraphEvent:
    assert len(emitter.events) == 1
    return emitter.events[0]


def test_successful_tool_call_emits_full_graph_chain() -> None:
    tenant_id = uuid4()
    upstream_server_id = uuid4()
    vserver_id = uuid4()
    session = _make_session(tenant_id, vserver_id=vserver_id)

    lifecycle, upstream, audit, graph = _build_lifecycle(
        tenant_id=tenant_id,
        session=session,
        upstream_server_id=upstream_server_id,
    )

    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=tenant_id,
                session_id="session-1",
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=_identity_credentials(tenant_id),
            )
        )
    )

    assert result.status == ToolCallStatus.ALLOWED
    assert upstream.calls == [("query_select", {"sql": "select 1"})]

    event = _only_event(graph)
    assert event.tenant_id == tenant_id
    assert [edge.type for edge in event.edges] == [
        GraphEdgeType.PRINCIPAL_USED_CLIENT,
        GraphEdgeType.CLIENT_CONNECTED_VSERVER,
        GraphEdgeType.VSERVER_EXPOSED_TOOL,
        GraphEdgeType.PRINCIPAL_CALLED_TOOL,
        GraphEdgeType.TOOL_ROUTED_TO_SERVER,
        GraphEdgeType.SERVER_ACCESSED_RESOURCE,
    ]


def test_graph_event_correlation_id_matches_audit_event_id() -> None:
    tenant_id = uuid4()
    session = _make_session(tenant_id, vserver_id=uuid4())

    lifecycle, _upstream, audit, graph = _build_lifecycle(
        tenant_id=tenant_id,
        session=session,
        upstream_server_id=uuid4(),
    )

    asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=tenant_id,
                session_id="session-1",
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=_identity_credentials(tenant_id),
            )
        )
    )

    assert len(audit.events) == 1
    assert len(graph.events) == 1
    assert graph.events[0].correlation_id == audit.events[0].event_id


def test_graph_principal_node_uses_validated_principal_not_session_principal() -> None:
    tenant_id = uuid4()
    session = _make_session(tenant_id, vserver_id=uuid4())

    lifecycle, _upstream, _audit, graph = _build_lifecycle(
        tenant_id=tenant_id,
        session=session,
        upstream_server_id=uuid4(),
    )

    asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=tenant_id,
                session_id="session-1",
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=_identity_credentials(tenant_id),
            )
        )
    )

    event = _only_event(graph)
    principal_used_client = next(
        edge for edge in event.edges if edge.type == GraphEdgeType.PRINCIPAL_USED_CLIENT
    )
    assert principal_used_client.source.type == GraphNodeType.PRINCIPAL
    # Validated principal from credentials, not the session's claimed API_KEY principal.
    assert principal_used_client.source.id == "principal:endpoint_session:endpoint-session-1"


def test_policy_denied_call_emits_chain_without_resource_edge() -> None:
    tenant_id = uuid4()
    session = _make_session(tenant_id, vserver_id=uuid4())

    lifecycle, upstream, _audit, graph = _build_lifecycle(
        tenant_id=tenant_id,
        session=session,
        upstream_server_id=uuid4(),
        policy_provider=SimplePolicyProvider(denied_tools={"query"}),
    )

    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=tenant_id,
                session_id="session-1",
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=_identity_credentials(tenant_id),
            )
        )
    )

    assert result.status == ToolCallStatus.DENIED
    assert upstream.calls == []

    event = _only_event(graph)
    types = [edge.type for edge in event.edges]
    # Resolved tool exists, so we get the full path except for the resource edge.
    assert GraphEdgeType.PRINCIPAL_CALLED_TOOL in types
    assert GraphEdgeType.TOOL_ROUTED_TO_SERVER in types
    assert GraphEdgeType.SERVER_ACCESSED_RESOURCE not in types


def test_tool_not_in_virtual_server_emits_only_session_chain() -> None:
    tenant_id = uuid4()
    session = _make_session(tenant_id, vserver_id=uuid4())

    lifecycle, _upstream, _audit, graph = _build_lifecycle(
        tenant_id=tenant_id,
        session=session,
        upstream_server_id=uuid4(),
    )

    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=tenant_id,
                session_id="session-1",
                tool_name="not_exposed",
                arguments={},
                identity_credentials=_identity_credentials(tenant_id),
            )
        )
    )

    assert result.status == ToolCallStatus.TOOL_NOT_IN_VIRTUAL_SERVER
    event = _only_event(graph)
    assert [edge.type for edge in event.edges] == [
        GraphEdgeType.PRINCIPAL_USED_CLIENT,
        GraphEdgeType.CLIENT_CONNECTED_VSERVER,
    ]


def test_session_not_found_does_not_emit_graph_event() -> None:
    tenant_id = uuid4()
    lifecycle, _upstream, _audit, graph = _build_lifecycle(
        tenant_id=tenant_id,
        session=_make_session(tenant_id, vserver_id=uuid4()),
        upstream_server_id=uuid4(),
    )
    # Session in registry but request points at a different session_id.
    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=tenant_id,
                session_id="missing",
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=_identity_credentials(tenant_id),
            )
        )
    )

    assert result.status == ToolCallStatus.SESSION_NOT_FOUND
    assert graph.events == []


def test_invalid_identity_does_not_emit_graph_event() -> None:
    tenant_id = uuid4()
    session = _make_session(tenant_id, vserver_id=uuid4())

    lifecycle, _upstream, _audit, graph = _build_lifecycle(
        tenant_id=tenant_id,
        session=session,
        upstream_server_id=uuid4(),
    )

    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=tenant_id,
                session_id="session-1",
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=IdentityCredentials(headers={}),
            )
        )
    )

    assert result.status == ToolCallStatus.IDENTITY_INVALID
    assert graph.events == []


def test_upstream_error_emits_resource_edge_because_call_was_attempted() -> None:
    tenant_id = uuid4()
    session = _make_session(tenant_id, vserver_id=uuid4())

    lifecycle, _upstream, _audit, graph = _build_lifecycle(
        tenant_id=tenant_id,
        session=session,
        upstream_server_id=uuid4(),
        upstream_client=FakeUpstreamClient(exception=RuntimeError("boom")),
    )

    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=tenant_id,
                session_id="session-1",
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=_identity_credentials(tenant_id),
            )
        )
    )

    assert result.status == ToolCallStatus.UPSTREAM_ERROR
    event = _only_event(graph)
    assert any(
        edge.type == GraphEdgeType.SERVER_ACCESSED_RESOURCE for edge in event.edges
    )


def test_default_lifecycle_does_not_require_graph_emitter() -> None:
    tenant_id = uuid4()
    session = _make_session(tenant_id, vserver_id=uuid4())
    resolved = synthesize_tools(
        [
            VirtualServerToolCapability(
                server_id=uuid4(),
                server_display_name="Postgres",
                tool_name="query_select",
                schema_json={
                    "inputSchema": {
                        "type": "object",
                        "properties": {"sql": {"type": "string"}},
                        "required": ["sql"],
                    }
                },
            )
        ],
        {"query_select": "query"},
    )
    lifecycle = ToolCallLifecycle(
        sessions=FakeSessionRegistry(session),
        resolver=FakeResolver(resolved),
        identity_provider=FakeIdentityProvider(),
        policy_provider=SimplePolicyProvider(),
        upstream_clients=FakeUpstreamClientProvider(FakeUpstreamClient()),
        audit_emitter=FakeAuditEmitter(),
        gateway_instance_id="gateway-1",
    )

    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=tenant_id,
                session_id="session-1",
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=_identity_credentials(tenant_id),
            )
        )
    )

    assert result.status == ToolCallStatus.ALLOWED
