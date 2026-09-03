"""End-to-end MCP interoperability lab.

This is the gateway's flagship integration suite: the real SDK client
(`StreamableHttpMcpClient`) drives the real gateway over ASGI transport, the
gateway routes tool calls into a real FastMCP-backed fake upstream over its
own ASGI transport, and we assert on the audit + NHI-graph telemetry that
comes out the side. No mocks of the lifecycle, the resolver, the upstream
provider, or the MCP transport.

How to run:

    pytest tests/lab/test_e2e_interoperability.py -v

What this proves:
- `initialize`, `tools/list`, and `tools/call` work end-to-end against the
  real MCP SDK client.
- Allowed, denied, malformed, upstream-error, and upstream-timeout paths
  return MCP-compliant `CallToolResult` responses without the gateway
  crashing.
- Every tool call emits exactly one audit event and one NHI graph event,
  with the `correlation_id` linking them.
- A session minted in tenant A cannot call tools in tenant B even if the
  caller forges the URL.

Known limitations of the lab as currently scoped:
- Single gateway instance (uses `InMemorySessionRegistry`).
- DB queries go through a fake resolver session — the RLS / GUC layer is
  verified by the env-gated `tests/integration/test_rls_real_postgres.py`.
- HTTP only over ASGI transport. Production must terminate TLS at the
  ingress / load balancer; the gateway currently has no TLS / mTLS code of
  its own.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Iterator
from typing import Any
from uuid import UUID, uuid4

import httpx
from fastapi.testclient import TestClient
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, TextContent
from starlette.applications import Starlette

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
from vyuu_gateway.mcp.sdk_compat import (
    make_mcp_server,
    sdk_field,
    server_streamable_http_app,
)
from vyuu_gateway.policy.simple import SimplePolicyProvider

# --- Fakes / helpers ---------------------------------------------------------


class _RecordingAuditEmitter:
    """Capture audit events for assertions."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        self.events.append(event)
        return EmitResult(accepted=True)


class _ResolverFake:
    """Fake DB session that returns the pre-built virtual-server + rows."""

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


class _MultiTenantResolverOverride:
    """Returns a different resolver fake per tenant_id from the URL.

    The tenant-isolation test wires two tenants into a single gateway; the
    inbound dependency override needs to dispatch on the path-bound
    tenant_id so each request gets the correct virtual-server fixture.
    """

    def __init__(
        self,
        *,
        per_tenant: dict[UUID, tuple[VirtualServer, list[tuple[Any, ...]]]],
    ) -> None:
        self._per_tenant = per_tenant

    def __call__(self, tenant_id: UUID) -> Iterator[_ResolverFake]:
        entry = self._per_tenant.get(tenant_id)
        if entry is None:
            yield _ResolverFake(virtual_server=None, rows=[])
            return
        vserver, rows = entry
        yield _ResolverFake(virtual_server=vserver, rows=rows)


class _FixedClientUpstreamProvider:
    """Returns a single MCP client object regardless of (tenant_id, server_id).

    Sufficient for the lab — the upstream is a single FastMCP app shared by
    every test. Real production uses `DatabaseBackedUpstreamClientProvider`.
    """

    def __init__(self, client: object) -> None:
        self._client = client
        self.calls: list[tuple[UUID, UUID]] = []

    def get_client(self, tenant_id: UUID, server_id: UUID) -> object:
        self.calls.append((tenant_id, server_id))
        return self._client

    def get_auth_mode_flags(self, tenant_id: UUID, server_id: UUID) -> Any:
        # The lab fake doesn't carry a McpServer row — return all-False
        # flags so the lifecycle's audit-mode plumbing (A5) stays happy.
        from vyuu_gateway.audit.events import AuthModeFlags
        return AuthModeFlags()


class _ForcedTimeoutClient:
    """Stub MCP client whose `call_tool` always raises `TimeoutError`.

    Drives the `UPSTREAM_TIMEOUT` path through the lifecycle deterministically
    without depending on SDK timeout internals. This is the gateway's job to
    handle correctly regardless of *why* the timeout fired.
    """

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        inbound_headers: dict[str, str] | None = None,  # noqa: ARG002
        principal_id: object = None,  # noqa: ARG002
    ) -> CallToolResult:
        raise TimeoutError("upstream did not respond in time")


class _ForcedErrorClient:
    """Stub MCP client whose `call_tool` always raises a generic exception.

    Drives the `UPSTREAM_ERROR` exception path (distinct from the
    `isError=true` response path that `boom` exercises via FastMCP)."""

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        inbound_headers: dict[str, str] | None = None,  # noqa: ARG002
        principal_id: object = None,  # noqa: ARG002
    ) -> CallToolResult:
        raise RuntimeError("simulated upstream connection failure")


def _build_fake_upstream() -> Starlette:
    """FastMCP server with three tools spanning the test matrix.

    - `echo(message)`: returns its argument; success path.
    - `boom(message)`: raises in the tool body. FastMCP catches and returns
      `CallToolResult(isError=True)`, which the gateway sees as a non-Python
      `UPSTREAM_ERROR`.
    - `slow(message)`: deliberately sleeps. Not used in the lab today (the
      `TimeoutError` path is exercised via `_ForcedTimeoutClient`), but kept
      so future tests of real SDK-driven timeout behaviour have a fixture.
    """
    server = make_mcp_server(
        "lab-upstream",
        stateless_http=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @server.tool()
    def echo(message: str) -> str:
        return f"echo:{message}"

    @server.tool()
    def boom(message: str) -> str:
        raise RuntimeError(f"upstream blew up while handling: {message}")

    @server.tool()
    async def slow(message: str) -> str:
        await asyncio.sleep(0.5)
        return f"slow:{message}"

    return server_streamable_http_app(server)


def _build_vserver(*, tenant_id: UUID, name: str = "lab-vserver") -> VirtualServer:
    return VirtualServer(
        id=uuid4(),
        tenant_id=tenant_id,
        name=name,
        rename_map={},
        # Public so the visibility-grant check (added in A3-α) doesn't
        # require a fake-principal user-grant in the lab E2E suite.
        visibility=VirtualServerVisibility.PUBLIC,
        created_by=uuid4(),
    )


def _build_capability_rows(*, upstream_server_id: UUID) -> list[tuple[Any, ...]]:
    """Three tools (echo, boom, slow) routed to the same upstream."""
    schema = {
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"],
        }
    }
    return [
        (upstream_server_id, "lab-upstream", "echo", schema),
        (upstream_server_id, "lab-upstream", "boom", schema),
        (upstream_server_id, "lab-upstream", "slow", schema),
    ]


def _auth_headers(tenant_id: UUID, *, principal_id: str = "endpoint-1") -> dict[str, str]:
    return {
        "x-vyuu-tenant-id": str(tenant_id),
        "x-vyuu-principal-type": PrincipalType.ENDPOINT_SESSION.value,
        "x-vyuu-principal-id": principal_id,
        "x-vyuu-principal-display": f"Lab {principal_id}",
    }


# --- Lab harness --------------------------------------------------------------


class _LabContext:
    def __init__(
        self,
        *,
        tenant_id: UUID,
        sdk_client: StreamableHttpMcpClient,
        audit: _RecordingAuditEmitter,
        graph: InMemoryGraphEventEmitter,
        upstream_provider: _FixedClientUpstreamProvider,
    ) -> None:
        self.tenant_id = tenant_id
        self.sdk_client = sdk_client
        self.audit = audit
        self.graph = graph
        self.upstream_provider = upstream_provider


@contextlib.asynccontextmanager
async def _lab(
    *,
    tenant_id: UUID | None = None,
    upstream_client: object | None = None,
    policy_provider: SimplePolicyProvider | None = None,
) -> AsyncIterator[_LabContext]:
    """Stand up the full E2E stack and yield a `_LabContext`.

    Manages two ASGI lifespans (gateway and upstream) and two `httpx`
    clients (one for the SDK→gateway hop, one for the gateway→upstream hop).
    By default the upstream is the FastMCP fake; tests can substitute
    `_ForcedTimeoutClient` / `_ForcedErrorClient` to drive specific failure
    paths through the lifecycle.
    """
    resolved_tenant = tenant_id if tenant_id is not None else uuid4()
    upstream_server_id = uuid4()
    vserver = _build_vserver(tenant_id=resolved_tenant)
    rows = _build_capability_rows(upstream_server_id=upstream_server_id)

    audit = _RecordingAuditEmitter()
    graph = InMemoryGraphEventEmitter()
    upstream_app = _build_fake_upstream()

    async with upstream_app.router.lifespan_context(upstream_app):
        upstream_transport = httpx.ASGITransport(app=upstream_app)
        async with httpx.AsyncClient(
            transport=upstream_transport,
            base_url="http://upstream",
        ) as upstream_http:
            real_outbound_client = StreamableHttpMcpClient(
                "http://upstream/mcp",
                http_client=upstream_http,
            )
            effective_client = upstream_client or real_outbound_client
            upstream_provider = _FixedClientUpstreamProvider(effective_client)

            gateway_app = create_app(
                Settings(
                    app_name="Vyuu MCP Gateway (lab)",
                    environment="test",
                    log_level="CRITICAL",
                    version="lab-version",
                    operator_auth_signing_secret="ignored-here",
                ),
                identity_provider=FakeIdentityProvider(),
                policy_provider=policy_provider or SimplePolicyProvider(),
                upstream_clients=upstream_provider,
                audit_emitter=audit,
                graph_event_emitter=graph,
            )

            override = _MultiTenantResolverOverride(
                per_tenant={resolved_tenant: (vserver, rows)},
            )
            gateway_app.dependency_overrides[get_inbound_mcp_db] = override

            async with gateway_app.router.lifespan_context(gateway_app):
                gateway_transport = httpx.ASGITransport(app=gateway_app)
                async with httpx.AsyncClient(
                    transport=gateway_transport,
                    base_url="http://gateway",
                    headers=_auth_headers(resolved_tenant),
                ) as gateway_http:
                    sdk_client = StreamableHttpMcpClient(
                        f"http://gateway/v/{resolved_tenant}/lab-vserver/mcp",
                        http_client=gateway_http,
                    )
                    yield _LabContext(
                        tenant_id=resolved_tenant,
                        sdk_client=sdk_client,
                        audit=audit,
                        graph=graph,
                        upstream_provider=upstream_provider,
                    )


# --- Tests ---------------------------------------------------------------------


def test_initialize_creates_session_and_returns_server_info() -> None:
    async def run() -> None:
        async with _lab() as lab:
            result = await lab.sdk_client.initialize()
            assert sdk_field(result, "protocol_version")
            assert sdk_field(result, "server_info").name == "Vyuu MCP Gateway (lab)"

    asyncio.run(run())


def test_session_creation_is_required_for_tools_endpoints() -> None:
    """Without `initialize` (which mints the session id), `tools/list` and
    `tools/call` return JSON-RPC `Missing session ID`. This is the contract
    the inbound transport guarantees regardless of upstream behaviour."""
    tenant_id = uuid4()
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway (lab)",
            environment="test",
            log_level="CRITICAL",
            version="lab-version",
            operator_auth_signing_secret="ignored",
        ),
    )

    def override(tenant_id: UUID) -> Iterator[_ResolverFake]:
        yield _ResolverFake(virtual_server=None, rows=[])

    app.dependency_overrides[get_inbound_mcp_db] = override

    with TestClient(app) as client:
        response = client.post(
            f"/v/{tenant_id}/lab-vserver/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32600


def test_tools_list_returns_synthesized_virtual_server_tools() -> None:
    async def run() -> None:
        async with _lab() as lab:
            tools = await lab.sdk_client.list_tools()
            tool_names = sorted(tool.name for tool in tools)
            assert tool_names == ["boom", "echo", "slow"]

    asyncio.run(run())


def test_allowed_tools_call_round_trips_through_upstream() -> None:
    async def run() -> None:
        async with _lab() as lab:
            result = await lab.sdk_client.call_tool("echo", {"message": "hello-lab"})

            assert not sdk_field(result, "is_error")
            text = result.content[0]
            assert isinstance(text, TextContent)
            assert text.text == "echo:hello-lab"
            # Upstream provider was consulted exactly once.
            assert len(lab.upstream_provider.calls) == 1
            assert lab.upstream_provider.calls[0][0] == lab.tenant_id

    asyncio.run(run())


def test_denied_tools_call_returns_error_and_does_not_reach_upstream() -> None:
    async def run() -> None:
        async with _lab(
            policy_provider=SimplePolicyProvider(denied_tools={"echo"}),
        ) as lab:
            result = await lab.sdk_client.call_tool("echo", {"message": "blocked"})

            assert sdk_field(result, "is_error")
            text = result.content[0]
            assert isinstance(text, TextContent)
            assert "denied" in text.text.lower()
            # Upstream is never reached.
            assert lab.upstream_provider.calls == []
            assert lab.audit.events[-1].decision == "deny"
            assert lab.audit.events[-1].policy_rule_id == "tool_denied"

    asyncio.run(run())


def test_malformed_args_return_error_before_upstream_or_policy() -> None:
    async def run() -> None:
        async with _lab() as lab:
            # Schema requires `message: string`; send a number.
            result = await lab.sdk_client.call_tool("echo", {"message": 42})

            assert sdk_field(result, "is_error")
            text = result.content[0]
            assert isinstance(text, TextContent)
            assert "malformed" in text.text.lower()
            assert lab.upstream_provider.calls == []
            assert lab.audit.events[-1].decision == "deny"
            assert lab.audit.events[-1].policy_rule_id == "malformed_args"

    asyncio.run(run())


def test_upstream_timeout_returns_error_and_audits_timeout_status() -> None:
    """Uses `_ForcedTimeoutClient` to deterministically drive the
    `UPSTREAM_TIMEOUT` exception path through the lifecycle."""

    async def run() -> None:
        async with _lab(upstream_client=_ForcedTimeoutClient()) as lab:
            result = await lab.sdk_client.call_tool("echo", {"message": "x"})

            assert sdk_field(result, "is_error")
            text = result.content[0]
            assert isinstance(text, TextContent)
            assert "timed out" in text.text.lower() or "timeout" in text.text.lower()
            event = lab.audit.events[-1]
            assert event.upstream_status == "timeout"
            # The decision still records `allow` because the call passed
            # policy and was actually attempted upstream — the failure mode
            # is transport-level, not policy.
            assert event.decision == "allow"

    asyncio.run(run())


def test_upstream_exception_returns_error_and_audits_error_status() -> None:
    """Uses `_ForcedErrorClient` for the generic exception path. Distinct
    from the `boom` tool which exercises the `isError=true` *response* path
    instead of a Python exception."""

    async def run() -> None:
        async with _lab(upstream_client=_ForcedErrorClient()) as lab:
            result = await lab.sdk_client.call_tool("echo", {"message": "x"})

            assert sdk_field(result, "is_error")
            event = lab.audit.events[-1]
            assert event.upstream_status == "error"
            assert event.decision == "allow"

    asyncio.run(run())


def test_upstream_returns_is_error_response_is_audited_as_error() -> None:
    """The `boom` upstream tool raises inside FastMCP; FastMCP catches it
    and returns `CallToolResult(isError=true)`. The lifecycle classifies
    this as `UPSTREAM_ERROR` based on the response, not a Python exception."""

    async def run() -> None:
        async with _lab() as lab:
            result = await lab.sdk_client.call_tool("boom", {"message": "x"})

            assert sdk_field(result, "is_error")
            event = lab.audit.events[-1]
            assert event.upstream_status == "error"

    asyncio.run(run())


def test_each_tool_call_emits_exactly_one_audit_event() -> None:
    """Spec §3.3: 100% of tool calls emit audit events. No duplicates either."""

    async def run() -> None:
        async with _lab() as lab:
            await lab.sdk_client.call_tool("echo", {"message": "1"})
            await lab.sdk_client.call_tool("echo", {"message": "2"})
            await lab.sdk_client.call_tool("echo", {"message": "3"})

            assert len(lab.audit.events) == 3
            # Each event has a unique event_id (no replay / duplicate emission).
            assert len({event.event_id for event in lab.audit.events}) == 3

    asyncio.run(run())


def test_audit_event_records_principal_tenant_decision_per_call() -> None:
    async def run() -> None:
        async with _lab() as lab:
            await lab.sdk_client.call_tool("echo", {"message": "audit-me"})

            event = lab.audit.events[-1]
            assert event.tenant_id == lab.tenant_id
            assert event.decision == "allow"
            assert event.principal.type == "endpoint_session"
            assert event.principal.id == "endpoint-1"
            assert event.tool == "echo"
            # Spec contract: the audit event records argument *summary*,
            # never the value. The literal "audit-me" must not be persisted.
            assert "audit-me" not in str(event.args_summary)

    asyncio.run(run())


def test_each_tool_call_emits_one_graph_event_with_full_chain_for_allowed_calls() -> None:
    async def run() -> None:
        async with _lab() as lab:
            await lab.sdk_client.call_tool("echo", {"message": "graph-me"})

            assert len(lab.graph.events) == 1
            edge_types = [edge.type for edge in lab.graph.events[0].edges]
            # Allowed call → full six-edge chain including the resource edge.
            assert edge_types == [
                GraphEdgeType.PRINCIPAL_USED_CLIENT,
                GraphEdgeType.CLIENT_CONNECTED_VSERVER,
                GraphEdgeType.VSERVER_EXPOSED_TOOL,
                GraphEdgeType.PRINCIPAL_CALLED_TOOL,
                GraphEdgeType.TOOL_ROUTED_TO_SERVER,
                GraphEdgeType.SERVER_ACCESSED_RESOURCE,
            ]

    asyncio.run(run())


def test_graph_event_correlation_id_matches_audit_event_id() -> None:
    async def run() -> None:
        async with _lab() as lab:
            await lab.sdk_client.call_tool("echo", {"message": "correlate"})

            assert lab.graph.events[0].correlation_id == lab.audit.events[0].event_id

    asyncio.run(run())


def test_graph_event_for_policy_denied_call_omits_resource_edge() -> None:
    async def run() -> None:
        async with _lab(
            policy_provider=SimplePolicyProvider(denied_tools={"echo"}),
        ) as lab:
            await lab.sdk_client.call_tool("echo", {"message": "blocked"})

            assert len(lab.graph.events) == 1
            edge_types = {edge.type for edge in lab.graph.events[0].edges}
            assert GraphEdgeType.PRINCIPAL_CALLED_TOOL in edge_types
            assert GraphEdgeType.TOOL_ROUTED_TO_SERVER in edge_types
            # The resource edge means "the upstream was called". Denied
            # calls never reach the upstream, so the edge must be absent.
            assert GraphEdgeType.SERVER_ACCESSED_RESOURCE not in edge_types

    asyncio.run(run())


def test_tenant_isolation_across_sessions() -> None:
    """Two tenants share one gateway instance. Each tenant's audit events
    carry its own tenant_id; tenant A's session id cannot be used to call
    tenant B's tools.

    This is the lab's most consequential assertion: the tenant filter is
    not just a query-shape detail but holds across the full SDK→inbound→
    lifecycle→upstream→audit→graph round trip.
    """

    async def run() -> None:
        tenant_a = uuid4()
        tenant_b = uuid4()
        upstream_server_id = uuid4()
        vserver_a = _build_vserver(tenant_id=tenant_a, name="vserver-a")
        vserver_b = _build_vserver(tenant_id=tenant_b, name="vserver-b")
        rows = _build_capability_rows(upstream_server_id=upstream_server_id)

        audit = _RecordingAuditEmitter()
        graph = InMemoryGraphEventEmitter()
        upstream_app = _build_fake_upstream()

        async with upstream_app.router.lifespan_context(upstream_app):
            upstream_transport = httpx.ASGITransport(app=upstream_app)
            async with httpx.AsyncClient(
                transport=upstream_transport,
                base_url="http://upstream",
            ) as upstream_http:
                outbound_client = StreamableHttpMcpClient(
                    "http://upstream/mcp",
                    http_client=upstream_http,
                )
                upstream_provider = _FixedClientUpstreamProvider(outbound_client)

                gateway_app = create_app(
                    Settings(
                        app_name="Vyuu MCP Gateway (lab)",
                        environment="test",
                        log_level="CRITICAL",
                        version="lab-version",
                        operator_auth_signing_secret="ignored",
                    ),
                    identity_provider=FakeIdentityProvider(),
                    policy_provider=SimplePolicyProvider(),
                    upstream_clients=upstream_provider,
                    audit_emitter=audit,
                    graph_event_emitter=graph,
                )

                override = _MultiTenantResolverOverride(
                    per_tenant={
                        tenant_a: (vserver_a, rows),
                        tenant_b: (vserver_b, rows),
                    },
                )
                gateway_app.dependency_overrides[get_inbound_mcp_db] = override

                async with gateway_app.router.lifespan_context(gateway_app):
                    gateway_transport = httpx.ASGITransport(app=gateway_app)

                    async def call_tool_as(
                        tenant: UUID,
                        vserver: str,
                        principal_id: str,
                        message: str,
                    ) -> tuple[CallToolResult, str]:
                        async with httpx.AsyncClient(
                            transport=gateway_transport,
                            base_url="http://gateway",
                            headers=_auth_headers(tenant, principal_id=principal_id),
                        ) as http_client:
                            sdk = StreamableHttpMcpClient(
                                f"http://gateway/v/{tenant}/{vserver}/mcp",
                                http_client=http_client,
                            )
                            await sdk.initialize()
                            result = await sdk.call_tool("echo", {"message": message})
                            return result, "session-tracked-by-sdk"

                    result_a, _ = await call_tool_as(
                        tenant_a, "vserver-a", "principal-a", "hello-a"
                    )
                    result_b, _ = await call_tool_as(
                        tenant_b, "vserver-b", "principal-b", "hello-b"
                    )

        assert not sdk_field(result_a, "is_error")
        assert not sdk_field(result_b, "is_error")

        events_for_a = [e for e in audit.events if e.tenant_id == tenant_a]
        events_for_b = [e for e in audit.events if e.tenant_id == tenant_b]
        assert len(events_for_a) == 1
        assert len(events_for_b) == 1
        assert events_for_a[0].principal.id == "principal-a"
        assert events_for_b[0].principal.id == "principal-b"

        # Each graph event must carry its tenant's id and no other.
        graphs_for_a = [g for g in graph.events if g.tenant_id == tenant_a]
        graphs_for_b = [g for g in graph.events if g.tenant_id == tenant_b]
        assert len(graphs_for_a) == 1
        assert len(graphs_for_b) == 1

    asyncio.run(run())


def test_session_minted_in_tenant_a_cannot_call_tools_in_tenant_b_url() -> None:
    """A session id minted by `initialize` under tenant A's URL must be
    rejected when the same id is presented in tenant B's URL — the
    `(tenant_id, session_id)` keying in the registry is the load-bearing
    invariant here."""
    tenant_a = uuid4()
    tenant_b = uuid4()
    vserver = _build_vserver(tenant_id=tenant_a, name="lab-vserver")
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway (lab)",
            environment="test",
            log_level="CRITICAL",
            version="lab-version",
            operator_auth_signing_secret="ignored",
        ),
    )

    def override(tenant_id: UUID) -> Iterator[_ResolverFake]:
        yield _ResolverFake(virtual_server=vserver, rows=[])

    app.dependency_overrides[get_inbound_mcp_db] = override

    with TestClient(app) as client:
        init_response = client.post(
            f"/v/{tenant_a}/lab-vserver/mcp",
            headers=_auth_headers(tenant_a),
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "lab-client", "version": "0.1"},
                },
            },
        )
        session_id = init_response.headers["mcp-session-id"]

        cross_tenant = client.post(
            f"/v/{tenant_b}/lab-vserver/mcp",
            headers={**_auth_headers(tenant_b), "mcp-session-id": session_id},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )

    assert cross_tenant.status_code == 404
    assert cross_tenant.json()["error"]["code"] == -32600
