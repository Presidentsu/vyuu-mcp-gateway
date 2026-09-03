import asyncio
from collections.abc import Iterable, Iterator
from datetime import datetime
from uuid import UUID, uuid4

import pytest

from vyuu_gateway.capabilities.client import CapabilityDescriptor
from vyuu_gateway.capabilities.fake_client import FakeInMemoryMcpClient
from vyuu_gateway.capabilities.sync import DatabaseCapabilitySyncService, McpServerNotFoundError
from vyuu_gateway.db.models import (
    McpCapability,
    McpCapabilityKind,
    McpServer,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
    RiskCategory,
)


class FakeScalarResult:
    def __init__(self, rows: Iterable[McpCapability]) -> None:
        self._rows = list(rows)

    def __iter__(self) -> Iterator[McpCapability]:
        return iter(self._rows)


class FakeSession:
    def __init__(
        self,
        *,
        server: McpServer | None,
        previous_capabilities: list[McpCapability] | None = None,
    ) -> None:
        self.server = server
        self.previous_capabilities = previous_capabilities or []
        self.added: list[McpCapability] = []
        self.committed = False
        self.scalar_statements: list[object] = []
        self.scalars_statements: list[object] = []

    def scalar(self, statement: object) -> McpServer | None:
        self.scalar_statements.append(statement)
        return self.server

    def scalars(self, statement: object) -> FakeScalarResult:
        self.scalars_statements.append(statement)
        return FakeScalarResult(self.previous_capabilities)

    def add(self, instance: object) -> None:
        if isinstance(instance, McpCapability):
            self.added.append(instance)

    def commit(self) -> None:
        self.committed = True


def make_server(*, tenant_id: UUID, server_id: UUID) -> McpServer:
    return McpServer(
        id=server_id,
        tenant_id=tenant_id,
        display_name="github",
        source_type=McpServerSourceType.NPM,
        source_location="@modelcontextprotocol/server-github",
        transport=McpTransport.STDIO,
        args=[],
        registered_by=uuid4(),
        health_status=McpServerHealthStatus.UNKNOWN,
    )


def make_previous_capability(
    *,
    tenant_id: UUID,
    server_id: UUID,
    name: str,
    schema_json: dict[str, object],
) -> McpCapability:
    return McpCapability(
        id=uuid4(),
        tenant_id=tenant_id,
        server_id=server_id,
        kind=McpCapabilityKind.TOOL,
        name=name,
        schema_json=schema_json,
        deprecated=False,
    )


def make_descriptor(name: str, schema_json: dict[str, object]) -> CapabilityDescriptor:
    return CapabilityDescriptor(
        kind=McpCapabilityKind.TOOL,
        name=name,
        schema_json=schema_json,
    )


def test_sync_persists_new_snapshot_and_marks_previous_rows_deprecated() -> None:
    tenant_id = uuid4()
    server_id = uuid4()
    server = make_server(tenant_id=tenant_id, server_id=server_id)
    previous = [
        make_previous_capability(
            tenant_id=tenant_id,
            server_id=server_id,
            name="query",
            schema_json={"type": "old"},
        ),
        make_previous_capability(
            tenant_id=tenant_id,
            server_id=server_id,
            name="removed",
            schema_json={"type": "object"},
        ),
    ]
    db = FakeSession(server=server, previous_capabilities=previous)
    client = FakeInMemoryMcpClient()
    client.set_capabilities(
        server_id,
        [
            make_descriptor("query", {"type": "new"}),
            make_descriptor("list", {"type": "object"}),
        ],
    )

    result = asyncio.run(
        DatabaseCapabilitySyncService(db, client).sync_server_capabilities(
            tenant_id,
            server_id,
        )
    )

    assert result.capability_count == 2
    assert [(change.kind, change.name) for change in result.drift.added] == [
        (McpCapabilityKind.TOOL, "list")
    ]
    assert [(change.kind, change.name) for change in result.drift.changed] == [
        (McpCapabilityKind.TOOL, "query")
    ]
    assert [(change.kind, change.name) for change in result.drift.removed] == [
        (McpCapabilityKind.TOOL, "removed")
    ]
    assert all(capability.deprecated for capability in previous)
    assert [capability.name for capability in db.added] == ["query", "list"]
    assert all(capability.tenant_id == tenant_id for capability in db.added)
    assert all(capability.server_id == server_id for capability in db.added)
    assert all(not capability.deprecated for capability in db.added)
    assert isinstance(server.last_capabilities_pulled_at, datetime)
    assert db.committed


def test_sync_uses_tenant_filtered_queries() -> None:
    tenant_id = uuid4()
    server_id = uuid4()
    db = FakeSession(server=make_server(tenant_id=tenant_id, server_id=server_id))
    client = FakeInMemoryMcpClient()

    asyncio.run(
        DatabaseCapabilitySyncService(db, client).sync_server_capabilities(tenant_id, server_id)
    )

    assert "mcp_servers.tenant_id" in str(db.scalar_statements[0])
    assert "mcp_servers.id" in str(db.scalar_statements[0])
    assert "mcp_capabilities.tenant_id" in str(db.scalars_statements[0])
    assert "mcp_capabilities.server_id" in str(db.scalars_statements[0])
    assert "mcp_capabilities.deprecated" in str(db.scalars_statements[0])


def test_sync_raises_when_server_not_found_in_tenant() -> None:
    db = FakeSession(server=None)
    client = FakeInMemoryMcpClient()

    with pytest.raises(McpServerNotFoundError):
        asyncio.run(
            DatabaseCapabilitySyncService(db, client).sync_server_capabilities(
                uuid4(), uuid4()
            )
        )

    assert not db.committed


def test_sync_classifies_and_persists_risk_category_per_capability() -> None:
    tenant_id = uuid4()
    server_id = uuid4()
    server = make_server(tenant_id=tenant_id, server_id=server_id)
    db = FakeSession(server=server)
    client = FakeInMemoryMcpClient()
    client.set_capabilities(
        server_id,
        [
            CapabilityDescriptor(
                kind=McpCapabilityKind.TOOL,
                name="list_repos",
                schema_json={"inputSchema": {"type": "object"}},
            ),
            CapabilityDescriptor(
                kind=McpCapabilityKind.TOOL,
                name="delete_file",
                schema_json={"inputSchema": {"type": "object"}},
            ),
            CapabilityDescriptor(
                kind=McpCapabilityKind.TOOL,
                name="get_secret",
                schema_json={"inputSchema": {"type": "object"}},
            ),
            CapabilityDescriptor(
                kind=McpCapabilityKind.TOOL,
                name="op",
                schema_json={
                    "description": "Send the message via webhook.",
                    "inputSchema": {"type": "object"},
                },
            ),
            CapabilityDescriptor(
                kind=McpCapabilityKind.RESOURCE,
                name="config://settings",
                schema_json={},
            ),
        ],
    )

    asyncio.run(
        DatabaseCapabilitySyncService(db, client).sync_server_capabilities(tenant_id, server_id)
    )

    by_name = {capability.name: capability for capability in db.added}
    assert by_name["list_repos"].risk_category == RiskCategory.READ
    assert by_name["delete_file"].risk_category == RiskCategory.DELETE
    assert by_name["get_secret"].risk_category == RiskCategory.CREDENTIAL_ACCESS
    assert by_name["op"].risk_category == RiskCategory.DATA_EXPORT
    assert by_name["config://settings"].risk_category == RiskCategory.UNKNOWN


def test_a_successful_sync_records_the_server_as_healthy() -> None:
    """A completed sync IS a successful connection.

    The automatic health probe runs with a short timeout (5 s by
    default) and, on a newly registered stdio server, races the first
    `uvx` / `npx` package fetch. It loses, marks the row `down`, and
    nothing re-probes — so a server whose very next action pulls 190
    capabilities still reads `down` until an operator clicks. Discarding
    evidence we already have in favour of a stale failure is the bug;
    this is the fix.
    """

    tenant_id, server_id = uuid4(), uuid4()
    server = make_server(tenant_id=tenant_id, server_id=server_id)
    # The exact state the cold-start race leaves behind.
    server.health_status = McpServerHealthStatus.DOWN
    server.last_health_error = "timeout"

    db = FakeSession(server=server, previous_capabilities=[])
    client = FakeInMemoryMcpClient()
    client.set_capabilities(server_id, [make_descriptor("query", {"type": "object"})])

    asyncio.run(
        DatabaseCapabilitySyncService(db, client).sync_server_capabilities(
            tenant_id, server_id
        )
    )

    assert server.health_status == McpServerHealthStatus.HEALTHY
    # The stale reason must go too — a healthy row still carrying
    # "timeout" is exactly the contradiction operators reported.
    assert server.last_health_error is None
    assert isinstance(server.last_health_checked_at, datetime)


def test_a_failed_sync_does_not_claim_health() -> None:
    """Negative control: only a sync that actually completed is
    evidence. If the upstream call raises, the prior state stands."""

    tenant_id, server_id = uuid4(), uuid4()
    server = make_server(tenant_id=tenant_id, server_id=server_id)
    server.health_status = McpServerHealthStatus.DOWN
    server.last_health_error = "timeout"

    class _ExplodingClient(FakeInMemoryMcpClient):
        async def list_capabilities(self, *args: object, **kwargs: object) -> object:
            raise RuntimeError("upstream unreachable")

    db = FakeSession(server=server, previous_capabilities=[])

    with pytest.raises(RuntimeError):
        asyncio.run(
            DatabaseCapabilitySyncService(db, _ExplodingClient()).sync_server_capabilities(
                tenant_id, server_id
            )
        )

    assert server.health_status == McpServerHealthStatus.DOWN
    assert server.last_health_error == "timeout"
