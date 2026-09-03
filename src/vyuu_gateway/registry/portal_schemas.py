"""Pydantic schemas for the A3-δ end-user portal endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from vyuu_gateway.db.models import VirtualServerVisibility


class RequiredUserAuthServer(BaseModel):
    """One underlying MCP server (wrapped by the vserver) that requires
    per-user OAuth authorisation-code consent before this user can
    actually invoke its tools.

    Threaded through `CatalogEntryResponse.requires_user_auth_servers`
    so the portal knows whether to render a "Connect to GitHub" /
    "Connect to Notion" button next to the vserver — and on click,
    which server_id to POST to `/api/v1/oauth-authcode/{server_id}/initiate`.

    `connected=False` → user has not yet established this connection;
    portal shows "Connect". `connected=True` → user already has a
    valid `oauth_user_tokens` row; portal shows "Reconnect"
    (still calls /initiate, which upserts on callback)."""

    model_config = ConfigDict(from_attributes=False)

    server_id: UUID
    server_display_name: str
    connected: bool


class CatalogEntryResponse(BaseModel):
    """One row in `GET /api/v1/portal/{tenant_id}/catalog`. The SPA
    renders one card per row, with a "Connect" button when
    `has_access=true` and a "Request access" button when not.

    `requires_user_auth_servers` lists underlying servers (wrapped by
    this vserver) that need per-user OAuth consent — empty for vservers
    whose upstreams are all M2M / passthrough / header-auth."""

    model_config = ConfigDict(from_attributes=True)

    vserver_id: UUID
    name: str
    description: str | None
    visibility: VirtualServerVisibility
    has_access: bool
    requires_user_auth_servers: list[RequiredUserAuthServer] = []
    # JIT-1. `jit_enabled` drives the "Request temporary access" button;
    # `access_expires_at` is non-null when the access the user already has
    # is itself a live elevation, so the card can count it down instead of
    # letting their tools stop mid-task without warning.
    jit_enabled: bool = False
    jit_auto_approve: bool = False
    # JIT-2 · tools on this bundle that need their own elevation.
    jit_tools: dict[str, int] = {}
    access_expires_at: datetime | None = None


class IssueMyApiKeyRequest(BaseModel):
    """User self-issues a bearer key for Claude Desktop / Cursor /
    agents. `label` is for them to remember which device it's on."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    label: Annotated[str, Field(min_length=1, max_length=255)]
    expires_at: datetime | None = None


class IssuedMyApiKeyResponse(BaseModel):
    """Returned ONCE on issuance. The plaintext is never re-derivable —
    if the user loses it they must revoke + re-issue."""

    model_config = ConfigDict(from_attributes=False)

    id: UUID
    label: str
    plaintext: str
    key_prefix: str
    created_at: datetime
    expires_at: datetime | None


class MyApiKeySummaryResponse(BaseModel):
    """Listing endpoint never returns the plaintext."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    label: str
    key_prefix: str
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None


class RotateMyPasswordRequest(BaseModel):
    """Self-rotate. Requires the current password — defends against a
    stolen session JWT being used to silently lock out the legitimate
    owner."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    current_password: Annotated[str, Field(min_length=1, max_length=512)]
    new_password: Annotated[str, Field(min_length=1, max_length=512)]


class WhoAmIResponse(BaseModel):
    """`GET /api/v1/portal/{tenant_id}/me` — lets the SPA learn who
    they are without re-decoding the JWT client-side."""

    model_config = ConfigDict(from_attributes=False)

    user_id: UUID
    tenant_id: UUID
    email: str
    auth_method: str
    must_change_password: bool


class ToolHistorySummaryResponse(BaseModel):
    """Aggregated rollup for the portal's Tool history KPI cards.

    Backed by the in-memory `RecentAuditEmitter` ring buffer (last
    ~1000 events). For a tenant with high call rates this is a best-
    effort approximation — anything beyond the buffer's tail is lost
    on gateway restart. Production deploys can swap in a query
    against the durable audit log behind the same response shape.
    """

    model_config = ConfigDict(from_attributes=False)

    window_days: int
    total_calls: int
    distinct_tools: int
    blocked_count: int
    blocked_tool_examples: list[str] = Field(default_factory=list)


class RecentToolCallResponse(BaseModel):
    """One row in `GET /api/v1/portal/{tenant_id}/recent-tool-calls`.

    Surfaces the audit-event ring buffer scoped to the calling user's
    API keys so the portal's Home + Tool history panels can show
    "your last N tool calls" without exposing operator-side audit
    details (no other users' principals, no policy-eval internals).
    """

    model_config = ConfigDict(from_attributes=False)

    event_id: UUID
    observed_at: datetime
    tool: str | None = None
    vserver_id: UUID | None = None
    vserver_name: str | None = None
    decision: str | None = None
    via: str | None = None
    latency_ms: int | None = None
