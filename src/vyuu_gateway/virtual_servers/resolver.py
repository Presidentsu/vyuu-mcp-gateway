import re
from dataclasses import dataclass, field, replace
from typing import Any, Protocol, cast
from uuid import UUID

from mcp.types import ListToolsResult, Tool
from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import (
    McpCapability,
    McpCapabilityKind,
    McpServer,
    VirtualServer,
    VirtualServerTool,
)
from vyuu_gateway.mcp.sdk_compat import make_tool
from vyuu_gateway.virtual_servers.service import (
    CapabilitiesNotSyncedError,
    VirtualServerNotFoundError,
)


@dataclass(frozen=True)
class VirtualServerToolCapability:
    server_id: UUID
    server_display_name: str
    tool_name: str
    schema_json: dict[str, Any]


@dataclass(frozen=True)
class ResolvedTool:
    exposed_name: str
    upstream_server_id: UUID
    upstream_tool_name: str
    tool: Tool


@dataclass(frozen=True)
class ResolvedToolsList:
    tools: list[ResolvedTool]
    # EMA-1 P3 · `exposed_tool_name -> required OAuth scope`, lifted off
    # the vserver row the resolver already loaded. Carried here (rather
    # than joined into the per-tool query) so the tool row shape — which
    # several test fakes hard-code — stays unchanged.
    required_scopes: dict[str, str] = field(default_factory=dict)
    # JIT-2 · `exposed_tool_name -> max elevation seconds`. Same lift off
    # the same already-loaded vserver row, for the same reason.
    jit_tools: dict[str, int] = field(default_factory=dict)
    # Needed by the JIT-2 gate to look up an elevation. `None` on the
    # synthesize-only paths that never touch a vserver row.
    vserver_id: UUID | None = None

    def to_mcp_result(self) -> ListToolsResult:
        return ListToolsResult(tools=[resolved_tool.tool for resolved_tool in self.tools])


class VirtualServerResolverSession(Protocol):
    def scalar(self, statement: Any) -> Any:
        """Return one scalar ORM result."""

    def execute(self, statement: Any) -> Any:
        """Execute a SQLAlchemy statement."""


class VirtualServerResolver:
    def __init__(self, db: VirtualServerResolverSession | Session) -> None:
        self._db = db

    def resolve_tools(self, tenant_id: UUID, vserver_name: str) -> ResolvedToolsList:
        virtual_server = cast(
            VirtualServer | None,
            self._db.scalar(
                select(VirtualServer).where(
                    VirtualServer.tenant_id == tenant_id,
                    VirtualServer.name == vserver_name,
                )
            ),
        )
        if virtual_server is None:
            raise VirtualServerNotFoundError

        rows = self._db.execute(
            select(
                McpServer.id,
                McpServer.display_name,
                VirtualServerTool.tool_name,
                McpCapability.schema_json,
            )
            .join(
                VirtualServerTool,
                (VirtualServerTool.tenant_id == McpServer.tenant_id)
                & (VirtualServerTool.server_id == McpServer.id),
            )
            .join(
                McpCapability,
                (McpCapability.tenant_id == VirtualServerTool.tenant_id)
                & (McpCapability.server_id == VirtualServerTool.server_id)
                & (McpCapability.name == VirtualServerTool.tool_name)
                & (McpCapability.kind == McpCapabilityKind.TOOL)
                & (McpCapability.deprecated.is_(False)),
            )
            .where(
                VirtualServerTool.tenant_id == tenant_id,
                VirtualServerTool.vserver_id == virtual_server.id,
            )
            .order_by(McpServer.display_name, VirtualServerTool.tool_name)
        )
        capabilities = [
            VirtualServerToolCapability(
                server_id=row[0],
                server_display_name=row[1],
                tool_name=row[2],
                schema_json=row[3],
            )
            for row in rows
        ]
        # Distinguish "no tools mapped at all" (legitimate empty
        # vserver) from "tools mapped but capabilities never synced"
        # (operator-action-required). The capability-row INNER JOIN
        # silently drops the latter; without this check, every tool
        # call returns the misleading `tool_not_in_vserver` deny.
        # Tier-1 stress-test fix.
        if not capabilities:
            mapped_server_ids = list(self._db.execute(
                select(VirtualServerTool.server_id).distinct().where(
                    VirtualServerTool.tenant_id == tenant_id,
                    VirtualServerTool.vserver_id == virtual_server.id,
                )
            ).scalars())
            if mapped_server_ids:
                raise CapabilitiesNotSyncedError(
                    vserver_id=virtual_server.id,
                    server_ids=mapped_server_ids,
                )
        resolved = synthesize_tools(capabilities, virtual_server.rename_map or {})
        # `or {}` also covers non-persisted ORM instances in tests, where
        # the column default has not been applied yet.
        return replace(
            resolved,
            required_scopes=dict(virtual_server.required_scopes or {}),
            jit_tools={
                name: int(seconds)
                for name, seconds in (virtual_server.jit_tools or {}).items()
            },
            vserver_id=virtual_server.id,
        )

    def synthesize_tools_list(self, tenant_id: UUID, vserver_name: str) -> ListToolsResult:
        return self.resolve_tools(tenant_id, vserver_name).to_mcp_result()


def synthesize_tools(
    capabilities: list[VirtualServerToolCapability],
    rename_map: dict[str, str],
) -> ResolvedToolsList:
    desired_names = [_desired_exposed_name(capability, rename_map) for capability in capabilities]
    duplicates = {name for name in desired_names if desired_names.count(name) > 1}

    used_names: set[str] = set()
    resolved_tools: list[ResolvedTool] = []
    for capability, desired_name in zip(capabilities, desired_names, strict=True):
        exposed_name = desired_name
        if desired_name in duplicates:
            prefix = _prefix_from_display_name(capability.server_display_name)
            exposed_name = f"{prefix}_{desired_name}"
        exposed_name = _make_unique(exposed_name, capability.server_id, used_names)
        used_names.add(exposed_name)

        resolved_tools.append(
            ResolvedTool(
                exposed_name=exposed_name,
                upstream_server_id=capability.server_id,
                upstream_tool_name=capability.tool_name,
                tool=_to_mcp_tool(exposed_name, capability.schema_json),
            )
        )

    return ResolvedToolsList(tools=resolved_tools)


def _desired_exposed_name(
    capability: VirtualServerToolCapability,
    rename_map: dict[str, str],
) -> str:
    server_scoped_key = f"{capability.server_id}:{capability.tool_name}"
    return (
        rename_map.get(server_scoped_key)
        or rename_map.get(capability.tool_name)
        or capability.tool_name
    )


def _prefix_from_display_name(display_name: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9]+", "_", display_name.strip().lower()).strip("_")
    return normalized or "server"


def _make_unique(candidate: str, server_id: UUID, used_names: set[str]) -> str:
    if candidate not in used_names:
        return candidate

    suffix = str(server_id).split("-", maxsplit=1)[0]
    unique_candidate = f"{candidate}_{suffix}"
    counter = 2
    while unique_candidate in used_names:
        unique_candidate = f"{candidate}_{suffix}_{counter}"
        counter += 1
    return unique_candidate


def _to_mcp_tool(name: str, schema_json: dict[str, Any]) -> Tool:
    input_schema = schema_json.get("inputSchema", schema_json)
    output_schema = schema_json.get("outputSchema")
    description = schema_json.get("description")
    title = schema_json.get("title")

    # MCP-2 P2 · `make_tool` picks `inputSchema` vs `input_schema` for the
    # installed SDK; call sites always speak the v2 (snake_case) spelling.
    return make_tool(
        name=name,
        title=title if isinstance(title, str) else None,
        description=description if isinstance(description, str) else None,
        input_schema=input_schema,
        output_schema=output_schema if isinstance(output_schema, dict) else None,
    )
