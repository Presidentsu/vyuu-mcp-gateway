"""Service-layer reads + writes for the end-user portal (A3-δ).

Distinct from the admin services because the access-control posture is
different — the portal user is acting on their OWN data only, scoped
by their session JWT's `user_id`. Admin services accept arbitrary
`user_id` parameters; portal services treat the session's user as the
implicit subject.

What this module covers:

- **Catalog**: list every vserver in the tenant, annotating which the
  user can already access (public OR has a grant) and which would
  require a request.
- **Self-issue API keys**: the user mints / lists / revokes their own
  bearer tokens for Claude Desktop / Cursor / agents. No admin
  intermediary needed.
- **Self-rotate password**: a local-auth user changes their own
  password (must-change-password flow lands here too).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import (
    GrantPrincipalKind,
    McpServer,
    OAuthUserToken,
    User,
    UserApiKey,
    UserAuthMethod,
    UserGroupMembership,
    VirtualServer,
    VirtualServerGrant,
    VirtualServerTool,
    VirtualServerVisibility,
)
from vyuu_gateway.registry.users_service import (
    DuplicateApiKeyLabelError,
    UserNotFoundError,
)
from vyuu_gateway.users.api_keys import IssuedApiKey, issue_new_key
from vyuu_gateway.users.passwords import (
    hash_password,
    validate_password_strength,
    verify_password,
)

# --- Errors ---------------------------------------------------------------


class PortalApiKeyNotFoundError(Exception):
    """The API key doesn't exist OR doesn't belong to the calling user."""


class WrongCurrentPasswordError(Exception):
    """User's self-rotate flow requires the current password — provided
    one didn't match. Generic 401-style error to avoid signalling
    whether the account exists."""


class PortalRequiresLocalAuthError(Exception):
    """Operation needs `auth_method=local` (e.g., self-rotate password)
    but the user is OIDC-authed."""


# --- Catalog --------------------------------------------------------------


@dataclass(frozen=True)
class RequiredUserAuthServer:
    """One underlying MCP server requiring per-user OAuth (auth_authcode)
    that the calling user has not yet (or has previously) connected.
    Surfaced from `list_catalog` so the portal can show / hide the
    "Connect to <SaaS>" button without a second round trip."""

    server_id: UUID
    server_display_name: str
    connected: bool


@dataclass(frozen=True)
class CatalogEntry:
    """One row in the user's catalog. `has_access=True` means the user
    can connect today; `has_access=False` means they'd need a grant
    (the SPA shows a "Request access" button).

    `requires_user_auth_servers` is non-empty iff the vserver wraps one
    or more upstreams configured with `auth_authcode` — those need a
    per-user delegated token before tool calls work."""

    vserver_id: UUID
    name: str
    description: str | None
    visibility: VirtualServerVisibility
    has_access: bool
    requires_user_auth_servers: tuple[RequiredUserAuthServer, ...] = ()
    # JIT-1. Carried on the catalog so the portal can render "Request
    # temporary access" without a per-card round-trip; the full policy
    # (ceiling, presets, whether a reason is required) is fetched from
    # `/jit-options` only when the user actually opens the dialog.
    jit_enabled: bool = False
    jit_auto_approve: bool = False
    # JIT-2 · `exposed_tool_name -> max elevation seconds`. Non-empty
    # means some tools on this bundle need an elevation even for a user
    # who already has bundle access — the portal renders them per-tool.
    jit_tools: dict[str, int] = field(default_factory=dict)
    # Non-None when the user's CURRENT access is itself a live elevation —
    # the portal shows "expires in 42m" so nobody is surprised when their
    # tools stop working mid-task.
    access_expires_at: datetime | None = None


def list_catalog(
    db: Session, *, tenant_id: UUID, user_id: UUID
) -> list[CatalogEntry]:
    """Return every vserver in the tenant + an `has_access` flag.

    Cheap to compute even at scale: one query for the vservers, two
    for the grant set (direct + via groups), then a Python join. The
    grant set is bounded by the number of grants this user has — not
    by the size of the catalog — so the cost stays linear in the number
    of vservers, not quadratic.
    """

    vservers = list(
        db.scalars(
            select(VirtualServer)
            .where(VirtualServer.tenant_id == tenant_id)
            .order_by(VirtualServer.name.asc())
        ).all()
    )

    # All vserver_ids the user has *some* active grant on. Two
    # separate queries kept ORM-mapped (UNION ALL on `select(Model)`
    # erases the entity binding under SA 2.0). Cheap because the user's
    # grant set is bounded by their membership, not by the catalog size.
    now = datetime.now(UTC)
    direct_grants = list(
        db.scalars(
            select(VirtualServerGrant).where(
                VirtualServerGrant.tenant_id == tenant_id,
                VirtualServerGrant.principal_kind == GrantPrincipalKind.USER,
                VirtualServerGrant.principal_id == user_id,
                VirtualServerGrant.revoked_at.is_(None),
            )
        ).all()
    )
    group_grants = list(
        db.scalars(
            select(VirtualServerGrant)
            .join(
                UserGroupMembership,
                UserGroupMembership.group_id == VirtualServerGrant.principal_id,
            )
            .where(
                VirtualServerGrant.tenant_id == tenant_id,
                VirtualServerGrant.principal_kind == GrantPrincipalKind.GROUP,
                VirtualServerGrant.revoked_at.is_(None),
                UserGroupMembership.user_id == user_id,
            )
        ).all()
    )
    granted_ids: set[UUID] = set()
    # JIT-1: remember when this access runs out. A standing grant (NULL
    # expiry) wins over a time-boxed one for the same vserver — the user
    # keeps access either way, so showing a countdown would be a lie.
    access_expiry: dict[UUID, datetime | None] = {}
    for grant in (*direct_grants, *group_grants):
        if grant.expires_at is not None and grant.expires_at <= now:
            continue
        granted_ids.add(grant.vserver_id)
        if grant.vserver_id not in access_expiry:
            access_expiry[grant.vserver_id] = grant.expires_at
        elif grant.expires_at is None:
            access_expiry[grant.vserver_id] = None
        elif access_expiry[grant.vserver_id] is not None:
            # Two live elevations: the later one is when access ends.
            current = access_expiry[grant.vserver_id]
            assert current is not None
            access_expiry[grant.vserver_id] = max(current, grant.expires_at)

    # Underlying servers for each vserver (one row per (vserver, server)
    # tool exposure; we only need the distinct server set per vserver).
    vserver_ids = [v.id for v in vservers]
    server_links: dict[UUID, set[UUID]] = {vid: set() for vid in vserver_ids}
    if vserver_ids:
        link_rows = list(
            db.execute(
                select(VirtualServerTool.vserver_id, VirtualServerTool.server_id).where(
                    VirtualServerTool.tenant_id == tenant_id,
                    VirtualServerTool.vserver_id.in_(vserver_ids),
                )
            ).all()
        )
        for vserver_id, server_id in link_rows:
            server_links[vserver_id].add(server_id)

    # Among all wrapped servers, fetch metadata + auth_authcode flag for
    # the ones that have any per-user auth at all. Bounded by tenant size,
    # not catalog size (most servers don't use authcode).
    referenced_server_ids = {sid for ids in server_links.values() for sid in ids}
    auth_servers: dict[UUID, McpServer] = {}
    if referenced_server_ids:
        auth_rows = list(
            db.scalars(
                select(McpServer).where(
                    McpServer.tenant_id == tenant_id,
                    McpServer.id.in_(referenced_server_ids),
                    # `is_not(None)` alone is WRONG on a JSONB column:
                    # SQL NULL and the JSON value `null` are different
                    # things, and `'null'::jsonb IS NOT NULL` is true.
                    # Nine of this tenant's servers store JSON null, and
                    # every one of them was being listed to end users as
                    # "connect your account before using this server" —
                    # for an OAuth flow that does not exist. Ask for the
                    # shape we actually need instead.
                    func.jsonb_typeof(McpServer.auth_authcode) == "object",
                )
            ).all()
        )
        auth_servers = {s.id: s for s in auth_rows}

    # Lookup of which auth-authcode servers the calling user has already
    # connected — drives the connected=True/False badge in the UI.
    connected_server_ids: set[UUID] = set()
    if auth_servers:
        connected_rows = list(
            db.scalars(
                select(OAuthUserToken.server_id).where(
                    OAuthUserToken.tenant_id == tenant_id,
                    OAuthUserToken.user_id == user_id,
                    OAuthUserToken.server_id.in_(auth_servers.keys()),
                )
            ).all()
        )
        connected_server_ids = set(connected_rows)

    entries: list[CatalogEntry] = []
    for v in vservers:
        required: list[RequiredUserAuthServer] = []
        for sid in sorted(server_links[v.id]):
            srv = auth_servers.get(sid)
            if srv is None:
                continue
            required.append(
                RequiredUserAuthServer(
                    server_id=srv.id,
                    server_display_name=srv.display_name,
                    connected=srv.id in connected_server_ids,
                )
            )
        entries.append(
            CatalogEntry(
                vserver_id=v.id,
                name=v.name,
                description=getattr(v, "description", None),
                visibility=v.visibility,
                has_access=(
                    v.visibility == VirtualServerVisibility.PUBLIC
                    or v.id in granted_ids
                ),
                requires_user_auth_servers=tuple(required),
                jit_enabled=v.jit_enabled,
                jit_auto_approve=v.jit_auto_approve,
                jit_tools={k: int(x) for k, x in (v.jit_tools or {}).items()},
                access_expires_at=access_expiry.get(v.id),
            )
        )
    return entries


# --- Portal-side API key management --------------------------------------


def issue_my_api_key(
    db: Session,
    *,
    tenant_id: UUID,
    user_id: UUID,
    label: str,
    expires_at: datetime | None = None,
) -> tuple[UserApiKey, IssuedApiKey]:
    """User mints their own bearer key. Same shape as the admin path
    (`users_service.issue_user_api_key`), just with the user_id pinned
    by the session rather than supplied by an admin. Returns the
    persisted `UserApiKey` row + the `IssuedApiKey` carrying the
    one-time plaintext."""

    key_id = uuid4()
    issued = issue_new_key(key_id=key_id)
    row = UserApiKey(
        id=key_id,
        tenant_id=tenant_id,
        user_id=user_id,
        label=label,
        key_hash=issued.key_hash,
        key_prefix=issued.key_prefix,
        expires_at=expires_at,
    )
    try:
        db.add(row)
        db.commit()
        db.refresh(row)
    except IntegrityError as exc:
        db.rollback()
        raise DuplicateApiKeyLabelError from exc
    return row, issued


def list_my_api_keys(
    db: Session, *, tenant_id: UUID, user_id: UUID
) -> list[UserApiKey]:
    return list(
        db.scalars(
            select(UserApiKey)
            .where(
                UserApiKey.tenant_id == tenant_id,
                UserApiKey.user_id == user_id,
            )
            .order_by(UserApiKey.created_at.desc())
        ).all()
    )


def revoke_my_api_key(
    db: Session, *, tenant_id: UUID, user_id: UUID, key_id: UUID
) -> UserApiKey:
    """Soft-delete: stamps `revoked_at`. The bearer becomes invalid on
    the next inbound call (api_key_provider checks `revoked_at`).
    Unknown id → `PortalApiKeyNotFoundError` (404 — anti-enumeration:
    a user trying to revoke another user's key gets the same 404)."""

    key = cast(
        UserApiKey | None,
        db.scalar(
            select(UserApiKey).where(
                UserApiKey.tenant_id == tenant_id,
                UserApiKey.user_id == user_id,
                UserApiKey.id == key_id,
            )
        ),
    )
    if key is None:
        raise PortalApiKeyNotFoundError
    if key.revoked_at is None:
        key.revoked_at = datetime.now(UTC)
        db.commit()
        db.refresh(key)
    return key


# --- Self-rotate password -------------------------------------------------


def rotate_my_password(
    db: Session,
    *,
    tenant_id: UUID,
    user_id: UUID,
    current_password: str,
    new_password: str,
) -> User:
    """Local-auth user changes their own password. Verifies the current
    password first — defends against a stolen session JWT being used
    to perform a silent takeover. OIDC users can't rotate this way
    (they have no `password_hash`)."""

    user = cast(
        User | None,
        db.scalar(
            select(User).where(User.tenant_id == tenant_id, User.id == user_id)
        ),
    )
    if user is None:
        raise UserNotFoundError
    if user.auth_method != UserAuthMethod.LOCAL or user.password_hash is None:
        raise PortalRequiresLocalAuthError

    if not verify_password(current_password, user.password_hash):
        raise WrongCurrentPasswordError

    validate_password_strength(new_password)
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    db.commit()
    db.refresh(user)
    return user
