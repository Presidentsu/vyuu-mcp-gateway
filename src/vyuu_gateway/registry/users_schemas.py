"""Pydantic schemas for the user / group / grant / API-key admin endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from vyuu_gateway.db.models import (
    GrantPrincipalKind,
    UserAuthMethod,
    VirtualServerVisibility,
)

# --- Users ----------------------------------------------------------------


class CreateLocalUserRequest(BaseModel):
    """Admin creates a local-auth user. Password rules enforced server-side
    (min 12 chars per Q3); generic error on weak passwords (no rule echo)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    email: EmailStr
    password: Annotated[str, Field(min_length=1, max_length=512)]
    display_name: str | None = Field(default=None, max_length=255)
    must_change_password: bool = Field(
        default=True,
        description=(
            "Default true: admin-created passwords are temporary; user must "
            "rotate on first login."
        ),
    )


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    email: str
    display_name: str | None
    auth_method: UserAuthMethod
    must_change_password: bool
    created_at: datetime
    last_login_at: datetime | None
    disabled_at: datetime | None


class UserListItemResponse(BaseModel):
    """Wire shape for the operator-console Users table.

    Strict superset of `UserResponse` — adds aggregate fields so the
    table renders in one round-trip instead of fanning out per-user.
    The single-user endpoints (`GET /users/{id}`, password reset,
    create) keep returning the leaner `UserResponse`.
    """

    model_config = ConfigDict(from_attributes=False)

    id: UUID
    tenant_id: UUID
    email: str
    display_name: str | None
    auth_method: UserAuthMethod
    must_change_password: bool
    created_at: datetime
    last_login_at: datetime | None
    disabled_at: datetime | None
    # Active (non-revoked) keys only. Revoked keys are noise here —
    # operators care about who can currently authenticate.
    api_key_count: int = 0
    group_count: int = 0
    # MAX(user_api_keys.last_used_at) across the user's keys. Answers
    # "is this user actually doing anything?". `None` if no key has
    # ever been used (or the user has no keys at all).
    last_api_key_used_at: datetime | None = None


class SetPasswordRequest(BaseModel):
    """Admin password reset OR user self-rotate."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    new_password: Annotated[str, Field(min_length=1, max_length=512)]


# --- Groups ---------------------------------------------------------------


class CreateGroupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: Annotated[str, Field(min_length=1, max_length=255)]
    description: str | None = Field(default=None, max_length=2000)


class GroupResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    name: str
    description: str | None
    created_by: UUID
    created_at: datetime


class GroupListItemResponse(BaseModel):
    """Wire shape for the operator-console Groups table.

    Strict superset of `GroupResponse` — adds the two aggregates the
    table shows so the panel renders in one round-trip:
      * `member_count` — how many users are in the group right now.
      * `vserver_grant_count` — how many vserver grants target this
        group as the principal. A group with `0` here is declared
        but unused; surfacing that in the UI makes stale config
        visible at a glance.
    The single-group endpoints (POST `/groups`) keep returning the
    leaner `GroupResponse`.
    """

    model_config = ConfigDict(from_attributes=False)

    id: UUID
    tenant_id: UUID
    name: str
    description: str | None
    created_by: UUID
    created_at: datetime
    member_count: int = 0
    vserver_grant_count: int = 0


class AddGroupMemberRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: UUID


# --- API keys (admin issues on behalf of user; OR user issues for self)


class CreateUserApiKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    label: Annotated[str, Field(min_length=1, max_length=255)]
    expires_at: datetime | None = None


class IssuedApiKeyResponse(BaseModel):
    """Response to API-key creation. The plaintext is shown EXACTLY ONCE."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    user_id: UUID
    label: str
    key_prefix: str
    plaintext: str = Field(
        description="Show to the user once; the gateway does not store this."
    )
    created_at: datetime
    expires_at: datetime | None


class UserApiKeySummaryResponse(BaseModel):
    """Listing — no plaintext, just metadata."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    user_id: UUID
    label: str
    key_prefix: str
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None


# --- Grants on virtual servers --------------------------------------------


class CreateGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_kind: GrantPrincipalKind
    principal_id: UUID
    expires_at: datetime | None = None


class GrantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    vserver_id: UUID
    principal_kind: GrantPrincipalKind
    principal_id: UUID
    granted_by: UUID
    granted_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


# --- Vserver visibility patch --------------------------------------------


class SetVisibilityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    visibility: VirtualServerVisibility
