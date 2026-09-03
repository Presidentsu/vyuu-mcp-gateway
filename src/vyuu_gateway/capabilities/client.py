from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from vyuu_gateway.db.models import McpCapabilityKind, McpServer


@dataclass(frozen=True)
class CapabilityDescriptor:
    kind: McpCapabilityKind
    name: str
    schema_json: dict[str, Any]


class McpCapabilityClient(Protocol):
    """Transport-agnostic MCP capability client.

    Async because the production impl talks to upstream MCP servers over the
    network. The in-process test impl returns immediately but matches the
    async signature so call sites and the Protocol stay consistent.
    """

    async def list_capabilities(
        self,
        server: McpServer,
        *,
        principal_id: UUID | None = None,
    ) -> list[CapabilityDescriptor]:
        """Return the server's current tool/resource/prompt descriptors.

        `principal_id` is required for phase-4 OAuth-authcode upstreams
        (per-user delegated tokens) — sync needs an operator-resolved
        user with a stored token. Phase-3 / stdio implementations
        ignore it.
        """
