"""Adapter that exposes the production upstream-client provider as an
`McpCapabilityClient`.

The capability sync service needs to call `list_capabilities()` on whatever
real outbound MCP client the gateway has configured for `(tenant_id,
server_id)`. The upstream provider (`DatabaseBackedUpstreamClientProvider`)
returns those clients; this adapter just forwards.

Tests use `FakeInMemoryMcpClient` directly because they don't need the real
upstream lookup. Production wires this adapter into `create_app` so the
HTTP-driven `POST /api/v1/servers/{id}/sync` endpoint reuses the same client
pool / circuit breakers as the tool-call hot path.
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from vyuu_gateway.capabilities.client import CapabilityDescriptor
from vyuu_gateway.db.models import McpServer


class _UpstreamClientWithCapabilities(Protocol):
    async def list_capabilities(
        self, *, principal_id: UUID | None = None
    ) -> list[CapabilityDescriptor]:
        """Return the upstream's tool/resource/prompt descriptors."""


class _UpstreamProviderLike(Protocol):
    def get_client(self, tenant_id: UUID, server_id: UUID) -> _UpstreamClientWithCapabilities:
        """Return an MCP client capable of `list_capabilities`."""


class UpstreamProviderCapabilityClient:
    """Wraps an upstream client provider to satisfy `McpCapabilityClient`.

    The capability sync service uses `McpCapabilityClient.list_capabilities(server)`;
    upstream clients use `client.list_capabilities()`. The adapter resolves the
    `(tenant_id, server_id)` pair through the provider then forwards.
    """

    def __init__(self, upstream_clients: _UpstreamProviderLike) -> None:
        self._upstream_clients = upstream_clients

    async def list_capabilities(
        self,
        server: McpServer,
        *,
        principal_id: UUID | None = None,
    ) -> list[CapabilityDescriptor]:
        client = self._upstream_clients.get_client(server.tenant_id, server.id)
        return await client.list_capabilities(principal_id=principal_id)
