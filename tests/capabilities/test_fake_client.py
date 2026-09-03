import asyncio
from uuid import uuid4

from vyuu_gateway.capabilities.client import CapabilityDescriptor
from vyuu_gateway.capabilities.fake_client import FakeInMemoryMcpClient
from vyuu_gateway.db.models import McpCapabilityKind, McpServer


def test_fake_client_returns_preloaded_capabilities_by_server_id() -> None:
    server_id = uuid4()
    client = FakeInMemoryMcpClient()
    capability = CapabilityDescriptor(
        kind=McpCapabilityKind.TOOL,
        name="query",
        schema_json={"type": "object"},
    )
    client.set_capabilities(server_id, [capability])

    result = asyncio.run(client.list_capabilities(McpServer(id=server_id)))

    assert result == [capability]


def test_fake_client_returns_empty_capabilities_for_unknown_server() -> None:
    client = FakeInMemoryMcpClient()

    result = asyncio.run(client.list_capabilities(McpServer(id=uuid4())))

    assert result == []
