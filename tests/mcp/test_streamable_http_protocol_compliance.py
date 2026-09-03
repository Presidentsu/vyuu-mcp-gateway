import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any, cast

import httpx
import pytest
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import LATEST_PROTOCOL_VERSION, TextContent
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from vyuu_gateway.mcp.outbound import StreamableHttpMcpClient
from vyuu_gateway.mcp.sdk_compat import (
    make_mcp_server,
    sdk_field,
    server_streamable_http_app,
)

STREAMABLE_HTTP_HEADERS = {
    "accept": "application/json, text/event-stream",
    "content-type": "application/json",
}


def build_protocol_server(*, stateless_http: bool) -> Any:
    server = make_mcp_server(
        "protocol-compliance-server",
        stateless_http=stateless_http,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @server.tool()
    def echo(message: str) -> str:
        return message

    return server


def run_against_protocol_server(
    assertion: Callable[[httpx.AsyncClient], Awaitable[None]],
    *,
    stateless_http: bool = True,
) -> None:
    async def run() -> None:
        app = server_streamable_http_app(build_protocol_server(stateless_http=stateless_http))
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as http_client:
                await assertion(http_client)

    asyncio.run(run())


def test_streamable_http_initialize_compliance() -> None:
    async def assertion(http_client: httpx.AsyncClient) -> None:
        client = StreamableHttpMcpClient("http://testserver/mcp", http_client=http_client)

        result = await client.initialize()

        assert sdk_field(result, "protocol_version")
        assert sdk_field(result, "server_info").name == "protocol-compliance-server"

    run_against_protocol_server(assertion)


def test_streamable_http_tools_list_compliance() -> None:
    async def assertion(http_client: httpx.AsyncClient) -> None:
        client = StreamableHttpMcpClient("http://testserver/mcp", http_client=http_client)

        tools = await client.list_tools()

        assert [tool.name for tool in tools] == ["echo"]
        assert sdk_field(tools[0], "input_schema")["properties"]["message"]["type"] == "string"

    run_against_protocol_server(assertion)


def test_streamable_http_tools_call_compliance() -> None:
    async def assertion(http_client: httpx.AsyncClient) -> None:
        client = StreamableHttpMcpClient("http://testserver/mcp", http_client=http_client)

        result = await client.call_tool("echo", {"message": "hello"})

        assert not sdk_field(result, "is_error")
        assert result.content[0].type == "text"
        assert result.content[0].text == "hello"

    run_against_protocol_server(assertion)


def test_streamable_http_invalid_method_returns_json_rpc_error() -> None:
    async def assertion(http_client: httpx.AsyncClient) -> None:
        session_id = await initialize_raw_session(http_client)
        headers = {**STREAMABLE_HTTP_HEADERS, "mcp-session-id": session_id}

        response = await http_client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "not/a-real-method", "params": {}},
        )

        assert response.status_code == 200
        payload = parse_sse_json(response.text)
        assert payload["id"] == 2
        # The SDK's own fake server answers an unknown method with
        # "method not found" (-32601) on v2 and "invalid params"
        # (-32602) on v1. This asserts the UPSTREAM's behaviour, not
        # the gateway's, so accept either rather than pinning to the
        # SDK version we happen to be on.
        assert payload["error"]["code"] in (-32601, -32602)
        # Wording is the upstream SDK's, and it changed between versions
        # ("Invalid request parameters" -> "Method not found"). What this
        # test is actually about is that a JSON-RPC error comes back at
        # all, with a message — not its exact prose.
        assert payload["error"]["message"]

    run_against_protocol_server(assertion, stateless_http=False)


def test_streamable_http_unsupported_protocol_version_is_rejected_by_client() -> None:
    async def assertion() -> None:
        app = build_unsupported_protocol_server()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as http_client:
            client = StreamableHttpMcpClient("http://testserver/mcp", http_client=http_client)

            with pytest.raises(ExceptionGroup) as exc_info:
                await client.initialize()

            assert exception_group_contains(
                exc_info.value,
                "Unsupported protocol version from the server: 1900-01-01",
            )

    asyncio.run(assertion())


def test_streamable_http_missing_session_is_rejected() -> None:
    async def assertion(http_client: httpx.AsyncClient) -> None:
        response = await http_client.post(
            "/mcp",
            headers=STREAMABLE_HTTP_HEADERS,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )

        payload = response.json()
        assert response.status_code == 400
        assert payload["error"]["code"] == -32600
        assert "Missing session ID" in payload["error"]["message"]

    run_against_protocol_server(assertion, stateless_http=False)


def test_streamable_http_expired_session_is_rejected_after_termination() -> None:
    async def assertion(http_client: httpx.AsyncClient) -> None:
        session_id = await initialize_raw_session(http_client)
        headers = {**STREAMABLE_HTTP_HEADERS, "mcp-session-id": session_id}

        delete_response = await http_client.delete("/mcp", headers={"mcp-session-id": session_id})
        expired_response = await http_client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
        )

        assert delete_response.status_code == 200
        payload = expired_response.json()
        assert expired_response.status_code == 404
        assert payload["error"]["code"] == -32600
        assert "Session has been terminated" in payload["error"]["message"]

    run_against_protocol_server(assertion, stateless_http=False)


def test_streamable_http_client_reconnects_with_fresh_sessions() -> None:
    async def assertion(http_client: httpx.AsyncClient) -> None:
        client = StreamableHttpMcpClient("http://testserver/mcp", http_client=http_client)

        first = await client.call_tool("echo", {"message": "first"})
        second = await client.call_tool("echo", {"message": "second"})

        first_content = cast(TextContent, first.content[0])
        second_content = cast(TextContent, second.content[0])
        assert first_content.type == "text"
        assert second_content.type == "text"
        assert first_content.text == "first"
        assert second_content.text == "second"

    run_against_protocol_server(assertion, stateless_http=False)


async def initialize_raw_session(http_client: httpx.AsyncClient) -> str:
    response = await http_client.post(
        "/mcp",
        headers=STREAMABLE_HTTP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "protocol-test-client", "version": "0.1"},
            },
        },
    )
    session_id = response.headers["mcp-session-id"]
    await http_client.post(
        "/mcp",
        headers={**STREAMABLE_HTTP_HEADERS, "mcp-session-id": session_id},
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    return session_id


def parse_sse_json(payload: str) -> dict[str, Any]:
    for line in payload.splitlines():
        if line.startswith("data: "):
            parsed = json.loads(line.removeprefix("data: "))
            if not isinstance(parsed, dict):
                raise AssertionError("expected JSON-RPC object")
            return parsed
    raise AssertionError("missing Streamable HTTP SSE data line")


def exception_group_contains(exc: BaseException, message: str) -> bool:
    if message in str(exc):
        return True
    if isinstance(exc, BaseExceptionGroup):
        return any(exception_group_contains(nested, message) for nested in exc.exceptions)
    return False


def build_unsupported_protocol_server() -> Starlette:
    async def endpoint(request: Request) -> Response:
        body = await request.json()
        response = {
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {
                "protocolVersion": "1900-01-01",
                "capabilities": {},
                "serverInfo": {"name": "unsupported-version-server", "version": "0.1"},
            },
        }
        return Response(
            f"event: message\ndata: {json.dumps(response)}\n\n",
            media_type="text/event-stream",
        )

    return Starlette(routes=[Route("/mcp", endpoint, methods=["POST"])])
