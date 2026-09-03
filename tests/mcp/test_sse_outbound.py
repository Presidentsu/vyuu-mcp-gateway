"""Outbound SSE client tests against an in-process SDK SSE server.

The server class is `FastMCP` on MCP SDK v1 and `MCPServer` on v2;
`make_mcp_server` picks the right one, so this suite runs unchanged
on either.

SSE is the legacy MCP transport. The provider now constructs `SseMcpClient`
instances for `transport=sse` registrations; these tests exercise the
client itself in isolation.

Note: SSE in the MCP SDK uses the standard httpx default transport (no
ASGI-transport injection seam like Streamable HTTP). So these tests run a
real Uvicorn server on a free local port, then talk to it over loopback.
Slightly heavier than the StreamableHTTP tests but still entirely offline.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
import time
from collections.abc import Generator
from typing import Any

import pytest
import uvicorn

from vyuu_gateway.mcp.outbound import SseMcpClient
from vyuu_gateway.mcp.sdk_compat import make_mcp_server, sdk_field, server_sse_app


def _free_port() -> int:
    """Pick a free TCP port on localhost — bind, read, release."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _build_sse_server() -> Any:
    server = make_mcp_server("sse-fake-upstream")

    @server.tool()
    def echo(message: str) -> str:
        return message

    @server.tool()
    def whoami() -> str:
        return "sse-fake-upstream"

    return server


@pytest.fixture
def sse_server() -> Generator[str, None, None]:
    """Spawn a real Uvicorn server hosting the SDK's SSE app on a
    free local port; tear down on test exit."""

    port = _free_port()
    app = server_sse_app(_build_sse_server())
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait briefly for the server to start accepting connections.
    deadline = time.time() + 5.0
    while time.time() < deadline:
        with contextlib.suppress(OSError):
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        time.sleep(0.05)

    yield f"http://127.0.0.1:{port}/sse"

    server.should_exit = True
    thread.join(timeout=2.0)


def test_sse_client_lists_tools_against_real_sse_server(sse_server: str) -> None:
    """End-to-end: SseMcpClient → real Uvicorn-hosted SDK SSE app."""

    async def run() -> None:
        client = SseMcpClient(sse_server)
        tools = await client.list_tools()
        names = {tool.name for tool in tools}
        assert names == {"echo", "whoami"}

    asyncio.run(run())


def test_sse_client_calls_tool_round_trip(sse_server: str) -> None:
    async def run() -> None:
        client = SseMcpClient(sse_server)
        result = await client.call_tool("echo", {"message": "hello-sse"})
        assert not sdk_field(result, "is_error")
        text = next((c.text for c in result.content if hasattr(c, "text")), None)
        assert text == "hello-sse"

    asyncio.run(run())


def test_sse_client_filters_passthrough_headers_to_upstream(
    sse_server: str,
) -> None:
    """The user-tier passthrough path must work for SSE the same way it
    does for Streamable HTTP. We can't directly observe the headers
    because the SDK's SSE handler doesn't echo them, but we can confirm
    the call still succeeds when passthrough is configured + supplied."""

    async def run() -> None:
        client = SseMcpClient(
            sse_server,
            auth_passthrough_map={"x-vyuu-user-token": "Authorization"},
        )
        result = await client.call_tool(
            "whoami",
            {},
            inbound_headers={"x-vyuu-user-token": "Bearer ignored-by-test-server"},
        )
        assert not sdk_field(result, "is_error")

    asyncio.run(run())


def test_sse_client_injects_oauth_bearer_token(sse_server: str) -> None:
    """OAuth path: the token provider is called per request, the token
    rides as Authorization. Test server doesn't validate, but we cover
    the wiring."""

    class _StubTokenProvider:
        def __init__(self) -> None:
            self.calls = 0

        async def fetch_token(self, *, principal_id: object = None) -> str:
            self.calls += 1
            return f"sse-tok-{self.calls}"

        async def invalidate(self, *, principal_id: object = None) -> None:
            # A4 — Protocol member; default no-op for the test stub.
            return

    async def run() -> None:
        provider = _StubTokenProvider()
        client = SseMcpClient(sse_server, oauth_token_provider=provider)
        result = await client.call_tool("echo", {"message": "with-oauth"})
        assert not sdk_field(result, "is_error")
        # Token provider was hit at least once during the call.
        assert provider.calls >= 1

    asyncio.run(run())


def test_sse_client_lists_capabilities(sse_server: str) -> None:
    """Capability sync against an SSE upstream — the gateway's existing
    `list_capabilities` machinery must work over both transports."""

    async def run() -> None:
        client = SseMcpClient(sse_server)
        capabilities = await client.list_capabilities()
        names: set[Any] = {(c.kind, c.name) for c in capabilities}
        # SDK defaults: just the two tools, no resources or prompts.
        assert any(name == "echo" for kind, name in names)
        assert any(name == "whoami" for kind, name in names)

    asyncio.run(run())
