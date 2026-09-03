"""Fake stdio MCP upstream, launched as a SUBPROCESS by the stdio tests.

Deliberately self-contained — it cannot import `vyuu_gateway.mcp.sdk_compat`
the way the other test fakes do, because it runs in a fresh interpreter
that has no `src/` on its path. So the one SDK-version branch this file
needs is inlined rather than shared.
"""

try:  # MCP SDK v1
    from mcp.server.fastmcp import FastMCP as _Server
except ModuleNotFoundError:  # v2 renamed FastMCP -> MCPServer
    from mcp.server.mcpserver import MCPServer as _Server

server = _Server("fake-stdio-server")


@server.tool()
def echo(message: str) -> str:
    return message


@server.resource("config://stdio")
def settings() -> str:
    return "stdio-settings"


@server.prompt()
def greet(name: str) -> str:
    return f"hello {name}"


if __name__ == "__main__":
    server.run("stdio")
