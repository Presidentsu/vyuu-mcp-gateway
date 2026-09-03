"""End-to-end inbound-MCP tests using the SDK's `StreamableHttpMcpClient`.

These tests stand up the real gateway FastAPI app in-process and drive it
with the official MCP Python SDK client. A fake upstream MCP server (built
with `FastMCP`) is wired into the gateway's `UpstreamToolClientProvider` via
ASGI transport, so the full request path runs without any network or real
Postgres:

    StreamableHttpMcpClient (SDK)
        → ASGI transport
            → gateway FastAPI app
                → ToolCallLifecycle
                    → fake upstream provider
                        → ASGI transport
                            → FastMCP fake upstream
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
from mcp.types import TextContent
from starlette.applications import Starlette

from vyuu_gateway.api.inbound_mcp import get_inbound_mcp_db
from vyuu_gateway.audit.emitter import EmitResult
from vyuu_gateway.audit.events import AuditEvent
from vyuu_gateway.config import Settings
from vyuu_gateway.db.models import VirtualServer, VirtualServerVisibility
from vyuu_gateway.identity.fake import FakeIdentityProvider
from vyuu_gateway.identity.models import PrincipalType
from vyuu_gateway.main import create_app
from vyuu_gateway.mcp.outbound import StreamableHttpMcpClient
from vyuu_gateway.mcp.sdk_compat import (
    make_mcp_server,
    sdk_field,
    server_streamable_http_app,
)
from vyuu_gateway.policy.interfaces import PolicyProvider
from vyuu_gateway.policy.management_plane import ManagementPlanePolicyProvider
from vyuu_gateway.policy.simple import SimplePolicyProvider
from vyuu_gateway.sessions.registry import GatewaySession, InMemorySessionRegistry

# --- Fakes ------------------------------------------------------------------------------


class FakeResolverSession:
    """Per-request fake DB session shaped for `VirtualServerResolver`.

    `scalar` returns the virtual server (or None to simulate "vserver not in
    tenant"), `execute` returns the join result rows the resolver expects.
    Tests configure these via attributes; one instance handles one request.
    """

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


class FakeUpstreamProvider:
    """Routes every (tenant_id, server_id) lookup to a single test client."""

    def __init__(self, client: StreamableHttpMcpClient) -> None:
        self._client = client
        self.calls: list[tuple[UUID, UUID]] = []

    def get_client(self, tenant_id: UUID, server_id: UUID) -> StreamableHttpMcpClient:
        self.calls.append((tenant_id, server_id))
        return self._client

    def get_auth_mode_flags(self, tenant_id: UUID, server_id: UUID) -> Any:
        from vyuu_gateway.audit.events import AuthModeFlags
        return AuthModeFlags()


class RecordingAuditEmitter:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        self.events.append(event)
        return EmitResult(accepted=True)


class RecordingSessionRegistry:
    def __init__(self) -> None:
        self.sessions: dict[tuple[UUID, str], GatewaySession] = {}

    async def create_session(self, session: GatewaySession) -> None:
        self.sessions[(session.tenant_id, session.session_id)] = session

    async def get_session(self, tenant_id: UUID, session_id: str) -> GatewaySession | None:
        return self.sessions.get((tenant_id, session_id))

    async def delete_session(self, tenant_id: UUID, session_id: str) -> None:
        self.sessions.pop((tenant_id, session_id), None)


# --- Helpers ----------------------------------------------------------------------------


def _build_fake_upstream_app() -> Starlette:
    """Spin up a tiny upstream MCP server with one echo-style tool."""
    server = make_mcp_server(
        "fake-upstream",
        stateless_http=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @server.tool()
    def query_select(sql: str) -> str:
        return f"upstream-result for {sql}"

    return server_streamable_http_app(server)


def _build_resolver_payload(
    *,
    tenant_id: UUID,
    upstream_server_id: UUID,
    policy_id: UUID | None = None,
) -> tuple[VirtualServer, list[tuple[Any, ...]]]:
    """One virtual server exposing one tool routed to the fake upstream."""
    vserver = VirtualServer(
        id=uuid4(),
        tenant_id=tenant_id,
        name="finance-readonly",
        rename_map={},
        policy_id=policy_id,
        visibility=VirtualServerVisibility.PUBLIC,
        created_by=uuid4(),
    )
    rows: list[tuple[Any, ...]] = [
        (
            upstream_server_id,
            "fake-upstream",
            "query_select",
            {
                "inputSchema": {
                    "type": "object",
                    "properties": {"sql": {"type": "string"}},
                    "required": ["sql"],
                }
            },
        )
    ]
    return vserver, rows


@contextlib.asynccontextmanager
async def _gateway_with_upstream(
    *,
    tenant_id: UUID,
    auth_headers: dict[str, str] | None = None,
    policy_provider: PolicyProvider | None = None,
    session_registry: RecordingSessionRegistry | None = None,
    policy_id: UUID | None = None,
) -> AsyncIterator[tuple[StreamableHttpMcpClient, RecordingAuditEmitter, FakeUpstreamProvider]]:
    """Stand up gateway + fake upstream + SDK client, yield them.

    The async context manages two ASGI lifespans (gateway and upstream) and
    two httpx clients (one for the gateway test client, one for the gateway's
    own outbound calls to the fake upstream).
    """
    upstream_app = _build_fake_upstream_app()
    upstream_server_id = uuid4()
    vserver, capability_rows = _build_resolver_payload(
        tenant_id=tenant_id,
        upstream_server_id=upstream_server_id,
        policy_id=policy_id,
    )

    audit = RecordingAuditEmitter()

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
            upstream_provider = FakeUpstreamProvider(outbound_client)

            gateway_app = create_app(
                Settings(
                    app_name="Vyuu MCP Gateway",
                    environment="test",
                    log_level="CRITICAL",
                    version="test-version",
                    operator_auth_signing_secret="ignored-here",
                ),
                identity_provider=FakeIdentityProvider(),
                policy_provider=policy_provider or SimplePolicyProvider(),
                upstream_clients=upstream_provider,
                audit_emitter=audit,
                session_registry=session_registry,
            )

            def override_db(tenant_id: UUID) -> Iterator[FakeResolverSession]:
                yield FakeResolverSession(
                    virtual_server=vserver,
                    rows=capability_rows,
                )

            gateway_app.dependency_overrides[get_inbound_mcp_db] = override_db

            async with gateway_app.router.lifespan_context(gateway_app):
                gateway_transport = httpx.ASGITransport(app=gateway_app)
                gateway_url = (
                    f"http://gateway/v/{tenant_id}/finance-readonly/mcp"
                )
                async with httpx.AsyncClient(
                    transport=gateway_transport,
                    base_url="http://gateway",
                    headers=auth_headers or _default_auth_headers(tenant_id),
                ) as gateway_http:
                    sdk_client = StreamableHttpMcpClient(
                        gateway_url,
                        http_client=gateway_http,
                    )
                    yield sdk_client, audit, upstream_provider


def _default_auth_headers(tenant_id: UUID) -> dict[str, str]:
    return {
        "x-vyuu-tenant-id": str(tenant_id),
        "x-vyuu-principal-type": PrincipalType.ENDPOINT_SESSION.value,
        "x-vyuu-principal-id": "endpoint-session-1",
        "x-vyuu-principal-display": "Endpoint Session 1",
    }


# --- Tests: happy-path end-to-end -------------------------------------------------------


def test_inbound_initialize_returns_protocol_version_and_session_id() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway_with_upstream(tenant_id=tenant_id) as (sdk_client, _audit, _up):
            result = await sdk_client.initialize()

            assert sdk_field(result, "protocol_version")
            assert sdk_field(result, "server_info").name == "Vyuu MCP Gateway"

    asyncio.run(run())


def test_inbound_tools_list_returns_synthesized_virtual_server_tools() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway_with_upstream(tenant_id=tenant_id) as (sdk_client, _audit, _up):
            tools = await sdk_client.list_tools()

            assert [tool.name for tool in tools] == ["query_select"]
            assert sdk_field(tools[0], "input_schema")["properties"]["sql"]["type"] == "string"

    asyncio.run(run())


def test_inbound_tools_call_routes_through_lifecycle_to_upstream() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway_with_upstream(tenant_id=tenant_id) as (
            sdk_client,
            audit,
            upstream_provider,
        ):
            result = await sdk_client.call_tool("query_select", {"sql": "select 1"})

            assert not sdk_field(result, "is_error")
            text_content = result.content[0]
            assert isinstance(text_content, TextContent)
            assert "upstream-result for select 1" in text_content.text
            # Upstream provider was consulted exactly once.
            assert len(upstream_provider.calls) == 1
            assert upstream_provider.calls[0][0] == tenant_id
            # Audit recorded one allow event.
            assert len(audit.events) == 1
            assert audit.events[0].decision == "allow"

    asyncio.run(run())


# --- Tests: MCP-compliant error paths ---------------------------------------------------


def test_inbound_tools_call_returns_call_tool_error_for_unknown_tool() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway_with_upstream(tenant_id=tenant_id) as (sdk_client, _a, _u):
            result = await sdk_client.call_tool("nonexistent", {"sql": "x"})

            assert sdk_field(result, "is_error")
            text_content = result.content[0]
            assert isinstance(text_content, TextContent)
            assert "not exposed" in text_content.text

    asyncio.run(run())


def test_inbound_tools_call_returns_call_tool_error_for_malformed_args() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway_with_upstream(tenant_id=tenant_id) as (sdk_client, _a, _u):
            # Schema requires `sql: string` and that field is required.
            result = await sdk_client.call_tool("query_select", {"sql": 42})

            assert sdk_field(result, "is_error")
            text_content = result.content[0]
            assert isinstance(text_content, TextContent)
            assert "malformed" in text_content.text.lower()

    asyncio.run(run())


def test_inbound_tools_call_returns_call_tool_error_for_policy_deny() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway_with_upstream(
            tenant_id=tenant_id,
            policy_provider=SimplePolicyProvider(denied_tools={"query_select"}),
        ) as (sdk_client, audit, upstream_provider):
            result = await sdk_client.call_tool("query_select", {"sql": "select 1"})

            assert sdk_field(result, "is_error")
            text_content = result.content[0]
            assert isinstance(text_content, TextContent)
            assert "denied" in text_content.text.lower()
            # Upstream must NOT be called for a policy-denied tool.
            assert upstream_provider.calls == []
            assert audit.events[-1].decision == "deny"

    asyncio.run(run())


def test_inbound_tools_call_uses_management_plane_policy() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        policy_id = uuid4()

        def handler(request: httpx.Request) -> httpx.Response:
            assert str(tenant_id) in str(request.url)
            assert str(policy_id) in str(request.url)
            return httpx.Response(
                200,
                json={
                    "policy_id": str(policy_id),
                    "version": "v1",
                    "default_decision": "deny",
                    "rules": [
                        {"id": "allow-query", "effect": "allow", "tools": ["query_select"]}
                    ],
                },
            )

        policy_provider = ManagementPlanePolicyProvider(
            base_url="http://mgmt",
            http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        async with _gateway_with_upstream(
            tenant_id=tenant_id,
            policy_provider=policy_provider,
            policy_id=policy_id,
        ) as (sdk_client, audit, upstream_provider):
            result = await sdk_client.call_tool("query_select", {"sql": "select 1"})

            assert not sdk_field(result, "is_error")
            assert upstream_provider.calls == [(tenant_id, upstream_provider.calls[0][1])]
            assert audit.events[-1].policy_id == policy_id
            assert audit.events[-1].policy_rule_id == "allow-query"

    asyncio.run(run())


# --- Tests: protocol-level errors via raw HTTP ------------------------------------------


def test_inbound_request_without_session_id_returns_jsonrpc_invalid_request() -> None:
    """tools/list without `mcp-session-id` returns a JSON-RPC invalid-request
    error rather than 200 OK with empty results — clients must treat missing
    sessions as a transport error."""
    tenant_id = uuid4()
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
            operator_auth_signing_secret="ignored",
        ),
    )

    def override_db(tenant_id: UUID) -> Iterator[FakeResolverSession]:
        yield FakeResolverSession(virtual_server=None, rows=[])

    app.dependency_overrides[get_inbound_mcp_db] = override_db

    with TestClient(app) as client:
        response = client.post(
            f"/v/{tenant_id}/finance-readonly/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )

    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == -32600
    assert "Missing session ID" in body["error"]["message"]


def test_inbound_request_with_unknown_session_id_returns_session_terminated() -> None:
    tenant_id = uuid4()
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
            operator_auth_signing_secret="ignored",
        ),
    )

    def override_db(tenant_id: UUID) -> Iterator[FakeResolverSession]:
        yield FakeResolverSession(virtual_server=None, rows=[])

    app.dependency_overrides[get_inbound_mcp_db] = override_db

    with TestClient(app) as client:
        response = client.post(
            f"/v/{tenant_id}/finance-readonly/mcp",
            headers={"mcp-session-id": "definitely-not-a-real-session"},
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )

    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == -32600
    error_message = body["error"]["message"].lower()
    assert "expired" in error_message or "terminated" in error_message


def test_inbound_initialize_without_credentials_returns_401_jsonrpc_error() -> None:
    tenant_id = uuid4()
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
            operator_auth_signing_secret="ignored",
        ),
        # FakeIdentityProvider with mock-headers disabled — no headers means reject.
        identity_provider=FakeIdentityProvider(allow_mock_headers=False),
    )

    def override_db(tenant_id: UUID) -> Iterator[FakeResolverSession]:
        yield FakeResolverSession(virtual_server=None, rows=[])

    app.dependency_overrides[get_inbound_mcp_db] = override_db

    with TestClient(app) as client:
        response = client.post(
            f"/v/{tenant_id}/finance-readonly/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "tester", "version": "0.1"},
                },
            },
        )

    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"
    body = response.json()
    assert body["error"]["code"] == -32600


def test_inbound_unsupported_method_returns_method_not_found() -> None:
    tenant_id = uuid4()
    vserver = VirtualServer(
        id=uuid4(),
        tenant_id=tenant_id,
        name="finance-readonly",
        rename_map={},
        visibility=VirtualServerVisibility.PUBLIC,
        created_by=uuid4(),
    )
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
            operator_auth_signing_secret="ignored",
        ),
    )

    def override_db(tenant_id: UUID) -> Iterator[FakeResolverSession]:
        yield FakeResolverSession(virtual_server=vserver, rows=[])

    app.dependency_overrides[get_inbound_mcp_db] = override_db

    # First create a session via initialize, then send an unsupported method.
    with TestClient(app) as client:
        init_response = client.post(
            f"/v/{tenant_id}/finance-readonly/mcp",
            headers=_default_auth_headers(tenant_id),
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "tester", "version": "0.1"},
                },
            },
        )
        session_id = init_response.headers["mcp-session-id"]

        response = client.post(
            f"/v/{tenant_id}/finance-readonly/mcp",
            headers={
                **_default_auth_headers(tenant_id),
                "mcp-session-id": session_id,
            },
            json={"jsonrpc": "2.0", "id": 2, "method": "made/up", "params": {}},
        )

    body = response.json()
    assert body["error"]["code"] == -32601
    assert "Method not supported" in body["error"]["message"]


def test_inbound_delete_terminates_session() -> None:
    tenant_id = uuid4()
    vserver = VirtualServer(
        id=uuid4(),
        tenant_id=tenant_id,
        name="finance-readonly",
        rename_map={},
        visibility=VirtualServerVisibility.PUBLIC,
        created_by=uuid4(),
    )
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
            operator_auth_signing_secret="ignored",
        ),
    )

    def override_db(tenant_id: UUID) -> Iterator[FakeResolverSession]:
        yield FakeResolverSession(virtual_server=vserver, rows=[])

    app.dependency_overrides[get_inbound_mcp_db] = override_db

    with TestClient(app) as client:
        init_response = client.post(
            f"/v/{tenant_id}/finance-readonly/mcp",
            headers=_default_auth_headers(tenant_id),
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "tester", "version": "0.1"},
                },
            },
        )
        session_id = init_response.headers["mcp-session-id"]

        # Auth headers on DELETE, as a real client sends on every
        # request. This test previously omitted them and passed, which
        # is how an unauthenticated session-termination shipped.
        delete_response = client.delete(
            f"/v/{tenant_id}/finance-readonly/mcp",
            headers={
                **_default_auth_headers(tenant_id),
                "mcp-session-id": session_id,
            },
        )
        assert delete_response.status_code == 204

        # A subsequent request with the now-terminated session id is rejected.
        response = client.post(
            f"/v/{tenant_id}/finance-readonly/mcp",
            headers={
                **_default_auth_headers(tenant_id),
                "mcp-session-id": session_id,
            },
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert response.status_code == 404


def test_inbound_session_id_does_not_leak_across_tenants() -> None:
    """A session created under tenant A must not be usable under tenant B,
    even if the caller knows the session id."""
    tenant_a = uuid4()
    tenant_b = uuid4()
    vserver = VirtualServer(
        id=uuid4(),
        tenant_id=tenant_a,
        name="finance-readonly",
        rename_map={},
        visibility=VirtualServerVisibility.PUBLIC,
        created_by=uuid4(),
    )
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
            operator_auth_signing_secret="ignored",
        ),
    )

    def override_db(tenant_id: UUID) -> Iterator[FakeResolverSession]:
        yield FakeResolverSession(virtual_server=vserver, rows=[])

    app.dependency_overrides[get_inbound_mcp_db] = override_db

    with TestClient(app) as client:
        init_response = client.post(
            f"/v/{tenant_a}/finance-readonly/mcp",
            headers=_default_auth_headers(tenant_a),
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "tester", "version": "0.1"},
                },
            },
        )
        session_id = init_response.headers["mcp-session-id"]

        cross_tenant_response = client.post(
            f"/v/{tenant_b}/finance-readonly/mcp",
            headers={
                **_default_auth_headers(tenant_b),
                "mcp-session-id": session_id,
            },
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )

    assert cross_tenant_response.status_code == 404


# --- Tests: session termination is authenticated and owner-only ------------------------


def _delete_test_app(tenant_id: UUID) -> tuple[Any, InMemorySessionRegistry]:
    """A gateway app whose resolver always yields `finance-readonly`.

    Returns the registry too, so tests can assert on session state
    directly instead of probing through the resolver (which the fake
    db session is not rich enough to drive).
    """
    vserver = VirtualServer(
        id=uuid4(),
        tenant_id=tenant_id,
        name="finance-readonly",
        rename_map={},
        visibility=VirtualServerVisibility.PUBLIC,
        created_by=uuid4(),
    )
    registry = InMemorySessionRegistry()
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
            operator_auth_signing_secret="ignored",
        ),
        session_registry=registry,
    )

    def override_db(tenant_id: UUID) -> Iterator[FakeResolverSession]:
        yield FakeResolverSession(virtual_server=vserver, rows=[])

    app.dependency_overrides[get_inbound_mcp_db] = override_db
    return app, registry


def _open_session(client: TestClient, tenant_id: UUID, **headers: str) -> str:
    response = client.post(
        f"/v/{tenant_id}/finance-readonly/mcp",
        headers={**_default_auth_headers(tenant_id), **headers},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "tester", "version": "0.1"},
            },
        },
    )
    assert response.status_code == 200
    return response.headers["mcp-session-id"]


def _session_is_live(
    registry: InMemorySessionRegistry, tenant_id: UUID, session_id: str
) -> bool:
    return asyncio.run(registry.get_session(tenant_id, session_id)) is not None


def test_inbound_delete_without_auth_does_not_terminate_session() -> None:
    """The reported vulnerability: a bare session id ended anyone's session.

    Session ids ride in a header through proxies and logs, so this was a
    denial of service reachable by anyone who saw one.
    """
    tenant_id = uuid4()
    app, registry = _delete_test_app(tenant_id)

    with TestClient(app) as client:
        session_id = _open_session(client, tenant_id)

        response = client.delete(
            f"/v/{tenant_id}/finance-readonly/mcp",
            headers={"mcp-session-id": session_id},
        )
        assert response.status_code != 204

        # The session must have survived the unauthenticated attempt.
        assert _session_is_live(registry, tenant_id, session_id)


def test_inbound_delete_by_another_principal_does_not_terminate_session() -> None:
    """Authenticating as yourself does not entitle you to end my session."""
    tenant_id = uuid4()
    app, registry = _delete_test_app(tenant_id)

    with TestClient(app) as client:
        victim_session = _open_session(
            client, tenant_id, **{"x-vyuu-principal-id": "victim"}
        )

        response = client.delete(
            f"/v/{tenant_id}/finance-readonly/mcp",
            headers={
                **_default_auth_headers(tenant_id),
                "x-vyuu-principal-id": "attacker",
                "mcp-session-id": victim_session,
            },
        )
        # 204 on purpose: telling the attacker "not yours" would confirm
        # the id is real, turning this into a session-id oracle.
        assert response.status_code == 204

        assert _session_is_live(registry, tenant_id, victim_session)


def test_inbound_delete_by_owner_terminates_session() -> None:
    tenant_id = uuid4()
    app, registry = _delete_test_app(tenant_id)

    with TestClient(app) as client:
        session_id = _open_session(
            client, tenant_id, **{"x-vyuu-principal-id": "owner"}
        )

        response = client.delete(
            f"/v/{tenant_id}/finance-readonly/mcp",
            headers={
                **_default_auth_headers(tenant_id),
                "x-vyuu-principal-id": "owner",
                "mcp-session-id": session_id,
            },
        )
        assert response.status_code == 204

        assert not _session_is_live(registry, tenant_id, session_id)


def test_inbound_delete_of_unknown_session_is_indistinguishable() -> None:
    """An unknown id and someone else's id must answer identically."""
    tenant_id = uuid4()
    app, registry = _delete_test_app(tenant_id)

    with TestClient(app) as client:
        response = client.delete(
            f"/v/{tenant_id}/finance-readonly/mcp",
            headers={
                **_default_auth_headers(tenant_id),
                "mcp-session-id": "no-such-session",
            },
        )
        assert response.status_code == 204
