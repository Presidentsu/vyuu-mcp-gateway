"""JIT-1 · Pydantic schemas for just-in-time vserver access.

Split from `access_requests_schemas` because the surfaces differ: those
schemas describe *whether* someone may have access, these describe *for
how long and why*.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from vyuu_gateway.registry.jit_service import (
    DURATION_PRESETS_SECONDS,
    MAX_JIT_DURATION_SECONDS,
)

# --- Operator: policy -----------------------------------------------------


class ConfigureVserverJitRequest(BaseModel):
    """Set a vserver's JIT policy. Every field except `enabled` is
    optional so a caller can flip one knob without restating the rest —
    omitted fields keep their current value rather than reverting to a
    default."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool
    max_duration_seconds: int | None = Field(
        default=None, gt=0, le=MAX_JIT_DURATION_SECONDS
    )
    auto_approve: bool | None = None
    require_justification: bool | None = None


class VserverJitPolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    vserver_id: UUID
    name: str
    jit_enabled: bool
    jit_max_duration_seconds: int
    jit_auto_approve: bool
    jit_require_justification: bool


# --- Operator: live elevations --------------------------------------------


class ActiveElevationResponse(BaseModel):
    """One live time-boxed grant. `seconds_remaining` is served rather
    than left to the client so every surface counts down against the
    gateway's clock, not the browser's."""

    model_config = ConfigDict(from_attributes=True)

    grant_id: UUID
    vserver_id: UUID
    vserver_name: str
    user_id: UUID
    user_email: str | None
    granted_via: str
    justification: str | None
    granted_at: datetime
    expires_at: datetime
    seconds_remaining: int


# --- Operator: approving with a duration ----------------------------------


class ApproveAccessRequestRequest(BaseModel):
    """Optional body on approve. `duration_seconds` lets the reviewer
    grant *less* than was asked for — the common review outcome. Omitted,
    the request's own requested duration is honoured (or standing access
    for a non-JIT request, exactly as before JIT existed)."""

    model_config = ConfigDict(extra="forbid")

    duration_seconds: int | None = Field(
        default=None, gt=0, le=MAX_JIT_DURATION_SECONDS
    )


# --- End user: requesting -------------------------------------------------


class JitAccessRequestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    vserver_id: UUID
    duration_seconds: int = Field(gt=0, le=MAX_JIT_DURATION_SECONDS)
    justification: str | None = Field(default=None, max_length=2000)


class JitAccessRequestResponse(BaseModel):
    """`granted=true` means the elevation is live now (auto-approve
    vserver) and `expires_at` is set. `granted=false` means it is queued
    for an operator and `request_id` identifies it."""

    granted: bool
    grant_id: UUID | None = None
    request_id: UUID | None = None
    expires_at: datetime | None = None


class JitOptionsResponse(BaseModel):
    """What the portal needs to render the request dialog for one
    vserver, so the client never hard-codes a policy the server owns."""

    vserver_id: UUID
    jit_enabled: bool
    max_duration_seconds: int
    auto_approve: bool
    require_justification: bool
    # Presets above the vserver's ceiling are filtered out server-side —
    # offering a choice that will be rejected is a worse experience than
    # offering fewer choices.
    duration_presets_seconds: list[int]

    @classmethod
    def from_vserver(cls, vserver_id: UUID, *, jit_enabled: bool,
                     max_duration_seconds: int, auto_approve: bool,
                     require_justification: bool) -> JitOptionsResponse:
        return cls(
            vserver_id=vserver_id,
            jit_enabled=jit_enabled,
            max_duration_seconds=max_duration_seconds,
            auto_approve=auto_approve,
            require_justification=require_justification,
            duration_presets_seconds=[
                p for p in DURATION_PRESETS_SECONDS if p <= max_duration_seconds
            ],
        )


# --- JIT-2 · per-tool elevation -------------------------------------------


class ConfigureVserverJitToolsRequest(BaseModel):
    """Replace the vserver's elevation-gated tool map wholesale.

    `{exposed_tool_name: max_seconds}`. Wholesale rather than a patch
    because that is how an operator edits a list, and how `rename_map`
    already behaves — a partial update surface invites "did my delete
    apply?" ambiguity.
    """

    model_config = ConfigDict(extra="forbid")

    jit_tools: dict[str, int] = Field(default_factory=dict)


class VserverJitToolsResponse(BaseModel):
    vserver_id: UUID
    name: str
    jit_tools: dict[str, int]


class ToolElevationRequestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    vserver_id: UUID
    exposed_tool_name: str = Field(min_length=1, max_length=200)
    duration_seconds: int = Field(gt=0, le=MAX_JIT_DURATION_SECONDS)
    justification: str | None = Field(default=None, max_length=2000)


class ActiveToolElevationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    grant_id: UUID
    vserver_id: UUID
    vserver_name: str
    exposed_tool_name: str
    user_id: UUID
    user_email: str | None
    granted_via: str
    justification: str | None
    granted_at: datetime
    expires_at: datetime
    seconds_remaining: int


class MyToolElevationOptionsResponse(BaseModel):
    """What the portal needs to render per-tool elevation for one vserver:
    which tools are gated, each ceiling, and whether the user can act at
    all (they must already hold vserver access)."""

    vserver_id: UUID
    has_vserver_access: bool
    auto_approve: bool
    require_justification: bool
    # `{exposed_tool_name: max_seconds}`
    jit_tools: dict[str, int]
    # Tools this user currently holds a live elevation for, so the portal
    # shows "active until …" instead of offering to elevate again.
    active_tool_elevations: dict[str, datetime] = Field(default_factory=dict)
