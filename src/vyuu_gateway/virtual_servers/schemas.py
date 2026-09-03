from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from vyuu_gateway.db.models import VirtualServerVisibility

ToolName = Annotated[str, Field(min_length=1, max_length=255)]
VirtualServerName = Annotated[str, Field(min_length=1, max_length=255)]


class AllowlistedTool(BaseModel):
    model_config = ConfigDict(frozen=True)

    server_id: UUID
    tool_name: ToolName


class CreateVirtualServerRequest(BaseModel):
    """Operator-API request for `POST /api/v1/vservers`.

    `tenant_id` and `created_by` are populated from the bearer-token-resolved
    operator context, NOT from the request body — `extra="forbid"` ensures
    that a client trying to slip them into the body returns 422 the same way
    `ServerRegistrationRequest` does.
    """

    model_config = ConfigDict(extra="forbid")

    name: VirtualServerName
    policy_id: UUID | None = None
    rename_map: dict[str, ToolName] = Field(default_factory=dict)
    tools: list[AllowlistedTool] = Field(default_factory=list)


class UpdateVirtualServerRequest(BaseModel):
    """Operator-API request for `PATCH /api/v1/vservers/{id}`.

    Every field is optional; only the ones present are applied. When `tools`
    is set, the existing allowlist is replaced wholesale (matches the
    operator-edits-list UX better than diff/merge).
    """

    model_config = ConfigDict(extra="forbid")

    name: VirtualServerName | None = None
    policy_id: UUID | None = None
    rename_map: dict[str, ToolName] | None = None
    tools: list[AllowlistedTool] | None = None


class VirtualServerToolResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    server_id: UUID
    tool_name: str


class VirtualServerResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    name: str
    policy_id: UUID | None
    rename_map: dict[str, str]
    visibility: VirtualServerVisibility
    # JIT-1 · just-in-time access policy. Surfaced on both response
    # shapes so the console can render the toggle without a second
    # round-trip per vserver.
    jit_enabled: bool = False
    jit_max_duration_seconds: int = 4 * 3600
    jit_auto_approve: bool = False
    jit_require_justification: bool = True
    # JIT-2 · `exposed_tool_name -> max elevation seconds`. On the wire so
    # the console can show HOW MANY tools are gated without a second
    # round-trip per row — without it the count always reads zero, which
    # is worse than not showing one at all.
    jit_tools: dict[str, int] = {}
    created_by: UUID
    created_at: datetime


class VirtualServerListItemResponse(BaseModel):
    """Wire shape for the operator-console Virtual Servers table.

    Strict superset of `VirtualServerResponse` — adds `tool_count` and
    `grant_count` so the table renders in one round-trip instead of
    fanning out per-vserver. The single-vserver endpoints
    (`GET /vservers/{id}`, create, update) keep returning the leaner
    `VirtualServerResponse`.

    `grant_count` includes both user- and group-targeted grants — the
    operator wants to know "how many access paths reference this
    vserver", not "how many distinct users".
    """

    model_config = ConfigDict(from_attributes=False)

    id: UUID
    tenant_id: UUID
    name: str
    policy_id: UUID | None
    rename_map: dict[str, str]
    visibility: VirtualServerVisibility
    # JIT-1 · just-in-time access policy. Surfaced on both response
    # shapes so the console can render the toggle without a second
    # round-trip per vserver.
    jit_enabled: bool = False
    jit_max_duration_seconds: int = 4 * 3600
    jit_auto_approve: bool = False
    jit_require_justification: bool = True
    # JIT-2 · `exposed_tool_name -> max elevation seconds`. On the wire so
    # the console can show HOW MANY tools are gated without a second
    # round-trip per row — without it the count always reads zero, which
    # is worse than not showing one at all.
    jit_tools: dict[str, int] = {}
    created_by: UUID
    created_at: datetime
    tool_count: int = 0
    grant_count: int = 0
