"""Pydantic schemas for the A3-γ access-request endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from vyuu_gateway.db.models import AccessRequestStatus

# --- End-user side --------------------------------------------------------


class SubmitAccessRequestRequest(BaseModel):
    """End user requests access to a private vserver they don't currently
    have a grant for. Optional `note` is the user's "why I want this"
    blurb shown to the admin in the pending queue."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    vserver_id: UUID
    note: str | None = Field(default=None, max_length=2000)


class AccessRequestResponse(BaseModel):
    """Returned to BOTH end users (their own requests) and admins (the
    pending queue). The fields are non-sensitive — `note` is what the user
    wrote, `decision_note` is what the admin wrote on decline. We don't
    redact `decision_note` for the user; if the admin wants to be private
    they leave it null."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    user_id: UUID
    vserver_id: UUID
    status: AccessRequestStatus
    note: str | None
    # JIT-1. NULL = a request for standing access. Non-NULL = the user
    # asked for a time-boxed elevation of this long.
    requested_duration_seconds: int | None = None
    decision_note: str | None
    decided_by: UUID | None
    decided_at: datetime | None
    created_grant_id: UUID | None
    created_at: datetime


class AccessRequestListItemResponse(BaseModel):
    """Wire shape for the operator-console access-request queue.

    Strict superset of `AccessRequestResponse` — adds the requester's
    email and the target vserver's name + visibility so the table
    is self-explanatory in one round-trip. Admins can decide
    approve/decline without a separate UUID lookup. The portal-side
    endpoints continue using the leaner `AccessRequestResponse`
    (the requester already knows who they are).
    """

    model_config = ConfigDict(from_attributes=False)

    id: UUID
    tenant_id: UUID
    user_id: UUID
    vserver_id: UUID
    status: AccessRequestStatus
    note: str | None
    requested_duration_seconds: int | None = None
    decision_note: str | None
    decided_by: UUID | None
    decided_at: datetime | None
    created_grant_id: UUID | None
    created_at: datetime
    # Joined context — null if the related row was deleted (FK ON
    # DELETE leaves the request orphaned but visible). Also null on
    # `decided_by_email` for requests that haven't been decided.
    user_email: str | None = None
    user_display_name: str | None = None
    vserver_name: str | None = None
    vserver_visibility: str | None = None
    decided_by_email: str | None = None


# --- Admin side -----------------------------------------------------------


class DeclineAccessRequestRequest(BaseModel):
    """Admin declines a pending request. `decision_note` lets the admin
    record context for the user (or future admins reading the queue)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    decision_note: Annotated[str, Field(min_length=0, max_length=2000)] = ""
