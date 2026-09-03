"""Network-gated lab test against the real `https://mcp.draw.io/mcp` upstream.

This test proves the gateway → real-MCP-upstream path works end-to-end against
a published server we don't control. It's the closest thing to "real client
testing" we can do from CI / a dev machine.

Skipped unless `VYUU_TEST_DRAWIO_UPSTREAM=1`. The gate exists because:
- the test makes real outbound HTTPS calls to a third-party server, which
  shouldn't happen in default `pytest`;
- the third party can change tool names / schemas / availability at any time,
  so the assertions are intentionally loose (existence + non-error response,
  not exact response shape);
- some sandboxed CI environments have no outbound internet access.

How to run:

    VYUU_TEST_DRAWIO_UPSTREAM=1 pytest tests/lab/test_drawio_upstream.py -v

What it proves:
- The gateway's `ToolCallLifecycle` + `StreamableHttpMcpClient` correctly
  drive a real, non-FastMCP, non-test MCP server.
- The upstream provider's transport classification (Streamable HTTP) is
  consistent with what real published servers actually expose.
- Audit + NHI graph emission survive the round trip with real network
  latency.

This test exercises the Streamable HTTP outbound path. The stdio outbound
path (`npx @drawio/mcp`) is exercised by the lab's pre-baked `drawio-stdio`
vserver and the unit tests under `tests/mcp/test_stdio_outbound.py`.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import AsyncIterator, Iterator
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from mcp.types import TextContent

from vyuu_gateway.api.inbound_mcp import get_inbound_mcp_db
from vyuu_gateway.audit.emitter import EmitResult
from vyuu_gateway.audit.events import AuditEvent
from vyuu_gateway.config import Settings
from vyuu_gateway.db.models import VirtualServer, VirtualServerVisibility
from vyuu_gateway.graph.emitter import InMemoryGraphEventEmitter
from vyuu_gateway.graph.events import GraphEdgeType
from vyuu_gateway.identity.fake import FakeIdentityProvider
from vyuu_gateway.identity.models import PrincipalType
from vyuu_gateway.main import create_app
from vyuu_gateway.mcp.outbound import StreamableHttpMcpClient
from vyuu_gateway.mcp.sdk_compat import sdk_field
from vyuu_gateway.policy.simple import SimplePolicyProvider

DRAWIO_UPSTREAM_URL = "https://mcp.draw.io/mcp"

pytestmark = pytest.mark.skipif(
    os.environ.get("VYUU_TEST_DRAWIO_UPSTREAM") != "1",
    reason="VYUU_TEST_DRAWIO_UPSTREAM=1 is required to make real network calls to mcp.draw.io",
)


class _RecordingAuditEmitter:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        self.events.append(event)
        return EmitResult(accepted=True)


class _ResolverFake:
    def __init__(
        self,
        *,
        virtual_server: VirtualServer | None,
        rows: list[tuple[Any, ...]],
    ) -> None:
        self.virtual_server = virtual_server
        self.rows = rows

    def scalar(self, statement: Any) -> VirtualServer | None:
        return self.virtual_server

    def execute(self, statement: Any) -> list[tuple[Any, ...]]:
        return self.rows


class _FixedClientUpstreamProvider:
    def __init__(self, client: object) -> None:
        self._client = client
        self.calls: list[tuple[UUID, UUID]] = []

    def get_client(self, tenant_id: UUID, server_id: UUID) -> object:
        self.calls.append((tenant_id, server_id))
        return self._client

    def get_auth_mode_flags(self, tenant_id: UUID, server_id: UUID) -> Any:
        from vyuu_gateway.audit.events import AuthModeFlags
        return AuthModeFlags()


def _drawio_capability_rows(*, upstream_server_id: UUID) -> list[tuple[Any, ...]]:
    """Mirror what `mcp.draw.io` exposes today.

    These rows are what `mcp_capabilities` would hold after a successful
    capability sync against the real server. The test pins them rather than
    fetching them live so the resolver path is exercised the same way it
    would be in production.
    """
    create_diagram_schema = {
        "description": "Creates and displays an interactive draw.io diagram.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "xml": {"type": "string"},
            },
        },
    }
    search_shapes_schema = {
        "description": "Search the draw.io shape library by keywords.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
            },
            "required": ["query"],
        },
    }
    return [
        (upstream_server_id, "drawio-mcp-app", "create_diagram", create_diagram_schema),
        (upstream_server_id, "drawio-mcp-app", "search_shapes", search_shapes_schema),
    ]


def _auth_headers(tenant_id: UUID) -> dict[str, str]:
    return {
        "x-vyuu-tenant-id": str(tenant_id),
        "x-vyuu-principal-type": PrincipalType.ENDPOINT_SESSION.value,
        "x-vyuu-principal-id": "drawio-lab-endpoint",
        "x-vyuu-principal-display": "drawio lab",
    }


@contextlib.asynccontextmanager
async def _gateway_pointed_at_drawio(
    *,
    tenant_id: UUID,
) -> AsyncIterator[
    tuple[StreamableHttpMcpClient, _RecordingAuditEmitter, InMemoryGraphEventEmitter]
]:
    """Stand up the gateway with the real `mcp.draw.io` as the upstream.

    No FastMCP, no fake — the upstream provider returns a real
    `StreamableHttpMcpClient` whose httpx client talks over the real network.
    """
    upstream_server_id = uuid4()
    vserver = VirtualServer(
        id=uuid4(),
        tenant_id=tenant_id,
        name="drawio",
        rename_map={},
        visibility=VirtualServerVisibility.PUBLIC,
        created_by=uuid4(),
    )
    rows = _drawio_capability_rows(upstream_server_id=upstream_server_id)

    audit = _RecordingAuditEmitter()
    graph = InMemoryGraphEventEmitter()
    real_drawio_client = StreamableHttpMcpClient(
        DRAWIO_UPSTREAM_URL,
        read_timeout_seconds=20.0,
    )
    upstream_provider = _FixedClientUpstreamProvider(real_drawio_client)

    gateway_app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway (drawio lab)",
            environment="test",
            log_level="CRITICAL",
            version="drawio-lab",
            operator_auth_signing_secret="ignored",
        ),
        identity_provider=FakeIdentityProvider(),
        policy_provider=SimplePolicyProvider(),
        upstream_clients=upstream_provider,
        audit_emitter=audit,
        graph_event_emitter=graph,
    )

    def override_db(tenant_id: UUID) -> Iterator[_ResolverFake]:
        yield _ResolverFake(virtual_server=vserver, rows=rows)

    gateway_app.dependency_overrides[get_inbound_mcp_db] = override_db

    async with gateway_app.router.lifespan_context(gateway_app):
        gateway_transport = httpx.ASGITransport(app=gateway_app)
        async with httpx.AsyncClient(
            transport=gateway_transport,
            base_url="http://gateway",
            headers=_auth_headers(tenant_id),
            timeout=httpx.Timeout(30.0),
        ) as gateway_http:
            sdk = StreamableHttpMcpClient(
                f"http://gateway/v/{tenant_id}/drawio/mcp",
                http_client=gateway_http,
            )
            yield sdk, audit, graph


def test_initialize_round_trips_through_the_gateway_to_drawio() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway_pointed_at_drawio(tenant_id=tenant_id) as (sdk, _audit, _graph):
            init_result = await sdk.initialize()

            # The gateway is what answers `initialize` (it owns the inbound
            # session). The drawio server's name is *not* what the client
            # sees here — it sees the gateway's serverInfo.
            assert sdk_field(init_result, "server_info").name == "Vyuu MCP Gateway (drawio lab)"

    asyncio.run(run())


def test_tools_list_returns_drawio_tools_through_the_gateway() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway_pointed_at_drawio(tenant_id=tenant_id) as (sdk, _audit, _graph):
            tools = await sdk.list_tools()

            tool_names = sorted(tool.name for tool in tools)
            # mcp.draw.io currently exposes these. If the third-party server
            # adds tools we still pass; if it removes one, this assertion
            # is the canary.
            assert "create_diagram" in tool_names
            assert "search_shapes" in tool_names

    asyncio.run(run())


def test_tools_call_against_drawio_succeeds_and_emits_audit_plus_graph() -> None:
    """The fully-real-network path: SDK client → gateway → mcp.draw.io and
    back. Asserts on the audit + graph events the gateway emits, not on the
    drawio response shape (which is a third-party contract we don't control)."""

    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway_pointed_at_drawio(tenant_id=tenant_id) as (sdk, audit, graph):
            result = await sdk.call_tool(
                "search_shapes",
                {"query": "rectangle"},
            )

            # We don't pin the response shape — drawio can return whatever
            # it likes as long as it's a valid CallToolResult. We do require
            # that the gateway didn't classify the round-trip as an error.
            assert not sdk_field(result, "is_error"), _stringify_result(result)
            assert len(result.content) >= 1

            # Audit / graph emission survived the real network round-trip.
            assert len(audit.events) == 1
            audit_event = audit.events[0]
            assert audit_event.decision == "allow"
            assert audit_event.tool == "search_shapes"
            assert audit_event.tenant_id == tenant_id
            assert audit_event.upstream_status == "ok"
            assert audit_event.latency_ms_upstream is not None
            assert audit_event.latency_ms_upstream > 0

            assert len(graph.events) == 1
            edge_types = [edge.type for edge in graph.events[0].edges]
            assert GraphEdgeType.SERVER_ACCESSED_RESOURCE in edge_types
            # correlation_id ties the two pipelines together.
            assert graph.events[0].correlation_id == audit_event.event_id

    asyncio.run(run())


def _stringify_result(result: Any) -> str:
    """Best-effort dump of a `CallToolResult` for debugging on assertion failure."""
    try:
        contents = []
        for c in result.content:
            if isinstance(c, TextContent):
                contents.append(c.text)
            else:
                contents.append(repr(c))
        return f"isError={sdk_field(result, "is_error")} content={contents}"
    except Exception:
        return repr(result)
