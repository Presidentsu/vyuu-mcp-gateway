import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from mcp.server.transport_security import TransportSecuritySettings

from vyuu_gateway.db.models import McpCapabilityKind
from vyuu_gateway.mcp.outbound import StreamableHttpMcpClient
from vyuu_gateway.mcp.sdk_compat import (
    make_mcp_server,
    sdk_field,
    server_streamable_http_app,
)


def build_fake_mcp_server() -> Any:
    server = make_mcp_server(
        "fake-registry-server",
        stateless_http=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @server.tool()
    def echo(message: str) -> str:
        return message

    @server.resource("config://settings")
    def settings() -> str:
        return "settings"

    @server.prompt()
    def greet(name: str) -> str:
        return f"hello {name}"

    return server


def run_against_fake_server(
    assertion: Callable[[StreamableHttpMcpClient], Awaitable[None]],
) -> None:
    async def run() -> None:
        app = server_streamable_http_app(build_fake_mcp_server())
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as http_client:
                client = StreamableHttpMcpClient(
                    "http://testserver/mcp",
                    http_client=http_client,
                )
                await assertion(client)

    asyncio.run(run())


def test_streamable_http_client_initializes_against_fake_server() -> None:
    async def assertion(client: StreamableHttpMcpClient) -> None:
        result = await client.initialize()

        assert sdk_field(result, "server_info").name == "fake-registry-server"
        assert sdk_field(result, "protocol_version")

    run_against_fake_server(assertion)


def test_streamable_http_client_lists_tools_resources_and_prompts() -> None:
    async def assertion(client: StreamableHttpMcpClient) -> None:
        tools = await client.list_tools()
        resources = await client.list_resources()
        prompts = await client.list_prompts()

        assert [tool.name for tool in tools] == ["echo"]
        assert sdk_field(tools[0], "input_schema")["properties"]["message"]["type"] == "string"
        assert [str(resource.uri) for resource in resources] == ["config://settings"]
        assert [prompt.name for prompt in prompts] == ["greet"]

    run_against_fake_server(assertion)


def test_streamable_http_client_calls_tool() -> None:
    async def assertion(client: StreamableHttpMcpClient) -> None:
        result = await client.call_tool("echo", {"message": "hello"})

        assert not sdk_field(result, "is_error")
        assert result.content[0].type == "text"
        assert result.content[0].text == "hello"

    run_against_fake_server(assertion)


def test_streamable_http_client_returns_capability_descriptors() -> None:
    async def assertion(client: StreamableHttpMcpClient) -> None:
        capabilities = await client.list_capabilities()

        assert [(capability.kind, capability.name) for capability in capabilities] == [
            (McpCapabilityKind.TOOL, "echo"),
            (McpCapabilityKind.RESOURCE, "config://settings"),
            (McpCapabilityKind.PROMPT, "greet"),
        ]
        tool_capability = capabilities[0]
        message_schema = tool_capability.schema_json["inputSchema"]["properties"]["message"]
        assert message_schema["type"] == "string"

    run_against_fake_server(assertion)


def test_call_tool_forwards_only_configured_passthrough_headers() -> None:
    """User-tier auth: only headers listed in `auth_passthrough_map` are
    forwarded — random inbound headers are dropped. Header names match
    case-insensitively (Starlette lowercases on the way in).
    """

    seen_headers: list[dict[str, str]] = []

    def build_header_recording_server() -> Any:
        server = make_mcp_server(
            "header-recorder",
            stateless_http=True,
            transport_security=TransportSecuritySettings(
                enable_dns_rebinding_protection=False
            ),
        )

        @server.tool()
        def whoami() -> str:
            return "ok"

        return server

    async def run() -> None:
        app = server_streamable_http_app(build_header_recording_server())

        # Wrap the ASGI app to capture the forwarded headers on every
        # request, so we can assert what the gateway actually sent.
        async def recording_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
            if scope["type"] == "http":
                seen_headers.append(
                    {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
                )
            await app(scope, receive, send)

        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=recording_app)  # type: ignore[arg-type]
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as http_client:
                client = StreamableHttpMcpClient(
                    "http://testserver/mcp",
                    http_client=http_client,
                    auth_passthrough_map={"x-vyuu-user-token": "Authorization"},
                )
                # Inbound carries BOTH the configured passthrough header
                # AND a random unrelated one. Only the configured one is
                # forwarded; the random header is dropped.
                await client.call_tool(
                    "whoami",
                    {},
                    inbound_headers={
                        "X-Vyuu-User-Token": "Bearer alice-personal-pat",
                        "X-Random-Inbound": "should-not-leak",
                        "x-vyuu-tenant-id": "tenant-id",
                    },
                )

        forwarded = next(
            (h for h in seen_headers if h.get("authorization") is not None),
            None,
        )
        assert forwarded is not None, (
            "No request carried Authorization — pass-through did not fire"
        )
        assert forwarded["authorization"] == "Bearer alice-personal-pat"
        assert "x-random-inbound" not in forwarded
        # The original inbound name (x-vyuu-user-token) is the operator's
        # contract with the user's MCP client, not what reaches the upstream
        # — the gateway translates it to the configured upstream name.
        assert "x-vyuu-user-token" not in forwarded

    asyncio.run(run())


def test_call_tool_without_inbound_headers_uses_pooled_client() -> None:
    """If no inbound headers (or none match the passthrough config), the
    call uses the long-lived pooled httpx client — not a one-shot. This
    keeps existing org-tier and no-auth flows on the connection-pooling
    fast path.
    """

    async def run() -> None:
        app = server_streamable_http_app(build_fake_mcp_server())
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as http_client:
                client = StreamableHttpMcpClient(
                    "http://testserver/mcp",
                    http_client=http_client,
                    auth_passthrough_map={"x-token": "Authorization"},
                )
                # No inbound headers at all → pooled path.
                result = await client.call_tool("echo", {"message": "hi"})
                assert not sdk_field(result, "is_error")
                # Same when inbound headers don't match the config.
                result_two = await client.call_tool(
                    "echo", {"message": "hi"}, inbound_headers={"x-other": "v"}
                )
                assert not sdk_field(result_two, "is_error")

    asyncio.run(run())


def test_call_tool_injects_oauth_bearer_from_token_provider() -> None:
    """When `oauth_token_provider` is wired, every call_tool must carry
    `Authorization: Bearer <fetched-token>` to the upstream — proving
    the StreamableHttpMcpClient routes through the one-shot path and
    bakes in the rotating credential."""

    seen_headers: list[dict[str, str]] = []

    class _StubTokenProvider:
        def __init__(self) -> None:
            self.calls = 0

        async def fetch_token(self, *, principal_id: object = None) -> str:
            self.calls += 1
            return f"tok-{self.calls}"

        async def invalidate(self, *, principal_id: object = None) -> None:
            # A4 — Protocol member; default no-op for the test stub.
            return

    def build_server() -> Any:
        s = make_mcp_server(
            "oauth-recorder",
            stateless_http=True,
            transport_security=TransportSecuritySettings(
                enable_dns_rebinding_protection=False
            ),
        )

        @s.tool()
        def whoami() -> str:
            return "ok"

        return s

    async def run() -> None:
        app = server_streamable_http_app(build_server())

        async def recording_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
            if scope["type"] == "http":
                seen_headers.append(
                    {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
                )
            await app(scope, receive, send)

        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=recording_app)  # type: ignore[arg-type]
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as http_client:
                provider = _StubTokenProvider()
                client = StreamableHttpMcpClient(
                    "http://testserver/mcp",
                    http_client=http_client,
                    oauth_token_provider=provider,
                )
                result = await client.call_tool("whoami", {})
                assert not sdk_field(result, "is_error")

        forwarded = next(
            (h for h in seen_headers if h.get("authorization", "").startswith("Bearer ")),
            None,
        )
        assert forwarded is not None, "Authorization header missing on upstream call"
        assert forwarded["authorization"] == "Bearer tok-1"

    asyncio.run(run())


def test_list_capabilities_treats_method_not_found_per_kind_as_empty() -> None:
    """Servers MAY omit any of tools/resources/prompts. Capability sync must
    keep going for the kinds the server *does* implement and just record the
    missing kinds as empty — the symptom that broke
    `POST /api/v1/servers/{id}/sync` against `mcp.draw.io/mcp` (which doesn't
    implement `prompts/list`).
    """

    def build_tools_only_server() -> Any:
        server = make_mcp_server(
            "tools-only-server",
            stateless_http=True,
            transport_security=TransportSecuritySettings(
                enable_dns_rebinding_protection=False
            ),
        )

        @server.tool()
        def echo(message: str) -> str:
            return message

        return server

    async def run() -> None:
        app = server_streamable_http_app(build_tools_only_server())
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as http_client:
                client = StreamableHttpMcpClient(
                    "http://testserver/mcp",
                    http_client=http_client,
                )
                capabilities = await client.list_capabilities()

        # Only tools should land — resources and prompts are unimplemented and
        # must NOT raise.
        assert [(c.kind, c.name) for c in capabilities] == [
            (McpCapabilityKind.TOOL, "echo"),
        ]

    asyncio.run(run())
