from collections.abc import Iterable
from uuid import UUID

from vyuu_gateway.capabilities.client import CapabilityDescriptor, McpCapabilityClient
from vyuu_gateway.db.models import McpServer


class FakeInMemoryMcpClient(McpCapabilityClient):
    """Test MCP client that returns preloaded capabilities by server id."""

    def __init__(self) -> None:
        self._capabilities_by_server_id: dict[UUID, list[CapabilityDescriptor]] = {}

    def set_capabilities(
        self,
        server_id: UUID,
        capabilities: Iterable[CapabilityDescriptor],
    ) -> None:
        self._capabilities_by_server_id[server_id] = list(capabilities)

    async def list_capabilities(
        self,
        server: McpServer,
        *,
        principal_id: UUID | None = None,
    ) -> list[CapabilityDescriptor]:
        del principal_id  # in-memory fixture ignores per-user OAuth
        return list(self._capabilities_by_server_id.get(server.id, []))
