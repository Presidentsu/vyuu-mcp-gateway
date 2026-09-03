"""SCIM 2.0 (RFC 7643) schemas — User, Group, PatchOp, ListResponse.

We accept the flexible inbound shapes Entra and Workspace actually
send (some optional fields, vendor-specific extras), and emit the
strict canonical shape on outbound.

A few intentional simplifications:

- **Users/Groups extension schemas**: we acknowledge the canonical
  `urn:ietf:params:scim:schemas:core:2.0:User` schema and Entra's
  `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`. We
  parse + ignore the latter rather than persisting it (we don't have
  a place for `manager` / `costCenter` etc. in our DB and the IdP-1
  scope sticks to the core shape).
- **`displayName` on User**: many IdPs send this as the user's full
  name; we map it to `users.display_name`. If the IdP omits it we
  fall back to `userName`.
- **`members[]` on Group**: each member is `{"value": "<user-id>",
  "$ref": "..."}`. We accept either the full URL or just the UUID;
  Workspace tends to send full URLs, Entra sends bare UUIDs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

# --- Schema URIs -----------------------------------------------------------

SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCHEMA_LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCHEMA_PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCHEMA_SP_CONFIG = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
SCHEMA_RESOURCE_TYPE = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"


# --- Shared sub-objects ---------------------------------------------------


class ScimMeta(BaseModel):
    """Per-resource metadata block. SCIM clients use `version`/`location`
    for caching; we set `version` from `created_at` so a stable resource
    always has the same `etag`-equivalent."""

    model_config = ConfigDict(extra="ignore")

    resourceType: str
    created: datetime | None = None
    lastModified: datetime | None = None
    location: str | None = None
    version: str | None = None


class ScimName(BaseModel):
    """User name sub-object. All fields optional — some IdPs send
    `formatted` only, others send the structured pieces."""

    model_config = ConfigDict(extra="ignore")

    formatted: str | None = None
    familyName: str | None = None
    givenName: str | None = None
    middleName: str | None = None


class ScimEmail(BaseModel):
    """One entry of a User's `emails[]` array."""

    model_config = ConfigDict(extra="ignore")

    value: str
    type: str | None = None
    primary: bool = False


class ScimGroupMemberRef(BaseModel):
    """One entry of a Group's `members[]` array."""

    model_config = ConfigDict(extra="ignore")

    # The user's id. SCIM defines this as `value`. Some IdPs send the
    # bare UUID, some send the full `https://.../Users/{id}` URL —
    # we normalize at translation time.
    value: str
    display: str | None = None
    # `$ref` is the full URL to the resource; informational, ignored
    # on parse.
    ref: str | None = Field(default=None, alias="$ref")
    type: str | None = None


# --- User -----------------------------------------------------------------


class ScimUser(BaseModel):
    """Inbound or outbound SCIM User resource.

    `id` + `meta` are populated only on outbound responses. On inbound
    POST they're absent (we mint the id) — we keep them Optional so
    one Pydantic model serves both directions.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    schemas: list[str] = Field(default_factory=lambda: [SCHEMA_USER])
    id: str | None = None
    externalId: str | None = None
    userName: str
    name: ScimName | None = None
    displayName: str | None = None
    emails: list[ScimEmail] = Field(default_factory=list)
    active: bool = True
    meta: ScimMeta | None = None


# --- Group ----------------------------------------------------------------


class ScimGroup(BaseModel):
    """Inbound or outbound SCIM Group resource."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    schemas: list[str] = Field(default_factory=lambda: [SCHEMA_GROUP])
    id: str | None = None
    externalId: str | None = None
    displayName: str
    members: list[ScimGroupMemberRef] = Field(default_factory=list)
    meta: ScimMeta | None = None


# --- PatchOp (RFC 7644 §3.5.2) -------------------------------------------


class ScimPatchOperation(BaseModel):
    """One `Operations[]` entry of a PATCH request body.

    Provider quirks worth knowing:

    - **Entra ID** sends each membership change as a separate
      `add` / `remove` op with `path = "members"` and `value` either
      a list (for `add`) or filter (for `remove` like
      `members[value eq "uuid"]`).
    - **Google Workspace** prefers `op = "replace"` with the full new
      `members` array — simpler to handle but less granular.

    We accept both. The `path` field is optional in the spec; on
    PATCH-without-path we apply the op to the whole resource.
    """

    model_config = ConfigDict(extra="ignore")

    op: str  # "add" | "remove" | "replace"
    path: str | None = None
    value: Any | None = None


class ScimPatchRequest(BaseModel):
    """RFC 7644 §3.5.2 PATCH body."""

    model_config = ConfigDict(extra="ignore")

    schemas: list[str] = Field(default_factory=lambda: [SCHEMA_PATCH_OP])
    Operations: list[ScimPatchOperation]


# --- List response (search results) --------------------------------------


class ScimListResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schemas: list[str] = Field(default_factory=lambda: [SCHEMA_LIST_RESPONSE])
    totalResults: int
    Resources: list[Any]
    startIndex: int = 1
    itemsPerPage: int


# --- Discovery: ServiceProviderConfig + ResourceType ---------------------


class ScimServiceProviderConfigFeature(BaseModel):
    """One `supported` block (PATCH, filter, etc.) on
    ServiceProviderConfig."""

    model_config = ConfigDict(extra="ignore")

    supported: bool


class ScimServiceProviderConfig(BaseModel):
    """The SCIM v2 capability advertisement — RFC 7644 §5.

    Entra/Workspace fetch this once at provisioning-app-creation
    time to discover what we support. We advertise only what we
    actually implement: PATCH, filter (eq + eq + and only), no bulk,
    no etag, no sort, no change-password (we don't manage SCIM-
    provisioned-user passwords; that's the IdP's job).
    """

    model_config = ConfigDict(extra="ignore")

    schemas: list[str] = Field(default_factory=lambda: [SCHEMA_SP_CONFIG])
    documentationUri: str | None = None
    patch: ScimServiceProviderConfigFeature
    bulk: dict[str, Any]
    filter: dict[str, Any]
    changePassword: ScimServiceProviderConfigFeature
    sort: ScimServiceProviderConfigFeature
    etag: ScimServiceProviderConfigFeature
    authenticationSchemes: list[dict[str, Any]]


def default_service_provider_config() -> ScimServiceProviderConfig:
    """The fixed advertisement for our SCIM server. Shape is what
    Entra + Workspace expect — extra `supported: false` blocks for
    capabilities we don't implement, no field omitted."""

    return ScimServiceProviderConfig(
        documentationUri=None,
        patch=ScimServiceProviderConfigFeature(supported=True),
        bulk={"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        filter={"supported": True, "maxResults": 200},
        changePassword=ScimServiceProviderConfigFeature(supported=False),
        sort=ScimServiceProviderConfigFeature(supported=False),
        etag=ScimServiceProviderConfigFeature(supported=False),
        authenticationSchemes=[
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": (
                    "Bearer minted at directory-connect time and pasted "
                    "into the IdP's Provisioning config."
                ),
                "primary": True,
            }
        ],
    )


# --- Helpers --------------------------------------------------------------


def primary_email(user: ScimUser) -> str | None:
    """Pick the email the IdP marked `primary`, or fall back to the
    first entry, or `None` if no emails are sent."""

    primary = next((e.value for e in user.emails if e.primary), None)
    if primary:
        return primary
    return user.emails[0].value if user.emails else None


def resolve_member_id(value: str) -> UUID | None:
    """Group member refs come as either a bare UUID (Entra) or a full
    `.../Users/{uuid}` URL (Workspace). Extract the UUID either way;
    return None if it doesn't look like one (let the caller 400)."""

    candidate = value.rstrip("/").rsplit("/", 1)[-1]
    try:
        return UUID(candidate)
    except (ValueError, AttributeError):
        return None
