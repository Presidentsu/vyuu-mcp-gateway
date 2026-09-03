from uuid import uuid4

from vyuu_gateway.db.models import VirtualServer
from vyuu_gateway.mcp.sdk_compat import sdk_field
from vyuu_gateway.virtual_servers.resolver import (
    VirtualServerResolver,
    VirtualServerToolCapability,
    synthesize_tools,
)


class FakeResolverSession:
    def __init__(self, virtual_server: VirtualServer, rows: list[tuple[object, ...]]) -> None:
        self.virtual_server = virtual_server
        self.rows = rows
        self.scalar_statements: list[object] = []
        self.execute_statements: list[object] = []

    def scalar(self, statement: object) -> VirtualServer:
        self.scalar_statements.append(statement)
        return self.virtual_server

    def execute(self, statement: object) -> list[tuple[object, ...]]:
        self.execute_statements.append(statement)
        return self.rows


def test_synthesize_tools_applies_rename_map() -> None:
    server_id = uuid4()

    result = synthesize_tools(
        [
            VirtualServerToolCapability(
                server_id=server_id,
                server_display_name="Postgres",
                tool_name="query_select",
                schema_json={"inputSchema": {"type": "object"}},
            )
        ],
        {"query_select": "query"},
    )

    assert [tool.exposed_name for tool in result.tools] == ["query"]
    assert result.to_mcp_result().tools[0].name == "query"


def test_synthesize_tools_supports_server_scoped_rename_map() -> None:
    server_id = uuid4()

    result = synthesize_tools(
        [
            VirtualServerToolCapability(
                server_id=server_id,
                server_display_name="Postgres",
                tool_name="query",
                schema_json={"inputSchema": {"type": "object"}},
            )
        ],
        {f"{server_id}:query": "postgres_query_readonly"},
    )

    assert [tool.exposed_name for tool in result.tools] == ["postgres_query_readonly"]


def test_synthesize_tools_prefixes_collisions_with_server_display_name() -> None:
    postgres_id = uuid4()
    mongo_id = uuid4()

    result = synthesize_tools(
        [
            VirtualServerToolCapability(
                server_id=postgres_id,
                server_display_name="Postgres",
                tool_name="query",
                schema_json={"inputSchema": {"type": "object"}},
            ),
            VirtualServerToolCapability(
                server_id=mongo_id,
                server_display_name="Mongo DB",
                tool_name="query",
                schema_json={"inputSchema": {"type": "object"}},
            ),
        ],
        {},
    )

    assert [tool.exposed_name for tool in result.tools] == ["postgres_query", "mongo_db_query"]
    assert [tool.tool.name for tool in result.tools] == ["postgres_query", "mongo_db_query"]


def test_synthesize_tools_builds_mcp_tools_list_from_capability_schema() -> None:
    result = synthesize_tools(
        [
            VirtualServerToolCapability(
                server_id=uuid4(),
                server_display_name="GitHub",
                tool_name="search",
                schema_json={
                    "description": "Search repositories",
                    "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
                    "outputSchema": {"type": "object"},
                },
            )
        ],
        {},
    ).to_mcp_result()

    assert result.tools[0].name == "search"
    assert result.tools[0].description == "Search repositories"
    assert sdk_field(result.tools[0], "input_schema")["properties"]["q"]["type"] == "string"
    assert sdk_field(result.tools[0], "output_schema") == {"type": "object"}


def test_resolver_queries_tenant_scoped_virtual_server_and_capabilities() -> None:
    tenant_id = uuid4()
    vserver_id = uuid4()
    upstream_server_id = uuid4()
    session = FakeResolverSession(
        VirtualServer(
            id=vserver_id,
            tenant_id=tenant_id,
            name="finance-readonly",
            rename_map={},
            created_by=uuid4(),
        ),
        [
            (
                upstream_server_id,
                "Postgres",
                "query",
                {"inputSchema": {"type": "object"}},
            )
        ],
    )

    result = VirtualServerResolver(session).synthesize_tools_list(tenant_id, "finance-readonly")

    assert [tool.name for tool in result.tools] == ["query"]
    assert "virtual_servers.tenant_id" in str(session.scalar_statements[0])
    execute_sql = str(session.execute_statements[0])
    assert "virtual_server_tools.tenant_id" in execute_sql
    assert "mcp_capabilities.tenant_id" in execute_sql
    assert "mcp_capabilities.deprecated" in execute_sql
