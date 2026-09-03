"""SCIM 2.0 server — FastAPI router.

Mounts at `/scim/v2/{directory_id}/...`. Authenticates via the
`authenticate_scim` dependency, which binds the session's tenant
context to the directory's tenant for the rest of the request.

Schema discovery + service-provider-config land first; Entra and
Workspace both probe these on provisioning-app creation. Then the
two resource types we support: `/Users` and `/Groups`.

Anything outside the spec we don't implement (SearchRequest body,
bulk ops, ETag, sort) returns 501 with the spec error envelope.
"""

from __future__ import annotations

import re
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select

from vyuu_gateway.db.models import (
    Group,
    Operator,
    User,
)
from vyuu_gateway.scim import groups as scim_groups
from vyuu_gateway.scim import users as scim_users
from vyuu_gateway.scim.auth import ScimContext, authenticate_scim
from vyuu_gateway.scim.errors import scim_400, scim_404, scim_409, scim_error
from vyuu_gateway.scim.schemas import (
    SCHEMA_GROUP,
    SCHEMA_LIST_RESPONSE,
    SCHEMA_RESOURCE_TYPE,
    SCHEMA_USER,
    ScimEmail,
    ScimGroup,
    ScimGroupMemberRef,
    ScimMeta,
    ScimPatchRequest,
    ScimUser,
    default_service_provider_config,
    resolve_member_id,
)

router = APIRouter(prefix="/scim/v2/{directory_id}", tags=["scim"])

# RFC 7644 §3.4.2.2 — the default content-type for SCIM responses.
SCIM_CT = "application/scim+json"


# --- Discovery -------------------------------------------------------------


@router.get("/ServiceProviderConfig")
def service_provider_config_endpoint(
    ctx: Annotated[ScimContext, Depends(authenticate_scim)],
) -> JSONResponse:
    """RFC 7644 §5 — what the server supports. Static for our impl."""

    del ctx  # auth-only
    return JSONResponse(
        default_service_provider_config().model_dump(mode="json"),
        media_type=SCIM_CT,
    )


@router.get("/Schemas")
def schemas_endpoint(
    ctx: Annotated[ScimContext, Depends(authenticate_scim)],
) -> JSONResponse:
    """RFC 7644 §4 — the full schema catalogue. We advertise just User
    + Group; the IdP doesn't probe individual schemas in practice."""

    del ctx
    return JSONResponse(
        {
            "schemas": [SCHEMA_LIST_RESPONSE],
            "totalResults": 2,
            "Resources": [
                {"id": SCHEMA_USER, "name": "User"},
                {"id": SCHEMA_GROUP, "name": "Group"},
            ],
            "startIndex": 1,
            "itemsPerPage": 2,
        },
        media_type=SCIM_CT,
    )


@router.get("/ResourceTypes")
def resource_types_endpoint(
    request: Request,
    ctx: Annotated[ScimContext, Depends(authenticate_scim)],
) -> JSONResponse:
    """RFC 7644 §6 — the resource types we host."""

    base = _scim_base_url(request, ctx)
    return JSONResponse(
        {
            "schemas": [SCHEMA_LIST_RESPONSE],
            "totalResults": 2,
            "Resources": [
                {
                    "schemas": [SCHEMA_RESOURCE_TYPE],
                    "id": "User",
                    "name": "User",
                    "endpoint": "/Users",
                    "schema": SCHEMA_USER,
                    "meta": {"location": f"{base}/ResourceTypes/User"},
                },
                {
                    "schemas": [SCHEMA_RESOURCE_TYPE],
                    "id": "Group",
                    "name": "Group",
                    "endpoint": "/Groups",
                    "schema": SCHEMA_GROUP,
                    "meta": {"location": f"{base}/ResourceTypes/Group"},
                },
            ],
            "startIndex": 1,
            "itemsPerPage": 2,
        },
        media_type=SCIM_CT,
    )


# --- Users ---------------------------------------------------------------


@router.post("/Users", status_code=201)
def create_user_endpoint(
    payload: ScimUser,
    request: Request,
    ctx: Annotated[ScimContext, Depends(authenticate_scim)],
) -> JSONResponse:
    """SCIM POST /Users — provision a new user.

    The IdP usually probes `GET /Users?filter=userName eq "x"` first
    to dedup, but we still need to handle the "POST what already
    exists" path safely (Entra/Workspace both retry, sometimes
    aggressively). 409 with `scimType=uniqueness` on that path —
    spec-compliant, IdP swallows the dedup signal."""

    if not payload.userName:
        return scim_400("userName is required")

    # Quick dedup on the unique pair we actually care about.
    existing = scim_users.find_by_username(
        ctx.db, directory=ctx.directory, username=payload.userName
    )
    if existing is not None:
        return scim_409("user with this userName already exists")

    if payload.externalId:
        existing_by_external = scim_users.find_by_external_id(
            ctx.db, directory=ctx.directory, external_id=payload.externalId
        )
        if existing_by_external is not None:
            return scim_409("user with this externalId already exists")

    try:
        user = scim_users.create_from_scim(
            ctx.db, directory=ctx.directory, payload=payload
        )
    except scim_users.ScimUserExistsError:
        return scim_409("user uniqueness conflict on insert")

    return JSONResponse(
        _user_to_scim(user, request, ctx).model_dump(mode="json"),
        status_code=201,
        media_type=SCIM_CT,
    )


@router.get("/Users")
def list_users_endpoint(
    request: Request,
    ctx: Annotated[ScimContext, Depends(authenticate_scim)],
    filter: str | None = Query(default=None),
    startIndex: int = Query(default=1, ge=1),
    count: int = Query(default=100, ge=0, le=200),
) -> JSONResponse:
    """SCIM GET /Users — list with optional `filter`. Supports just
    `eq` on `userName` / `externalId` (the only filter shape Entra +
    Workspace actually send for dedup)."""

    parsed = _parse_eq_filter(filter)
    matches: list[User] = []

    if parsed is None:
        # No filter — return the whole tenant's SCIM-provisioned users.
        # Bounded by `count`; Entra paginates if more.
        rows = ctx.db.scalars(
            select(User).where(
                User.tenant_id == ctx.directory.tenant_id,
                User.idp_directory_id == ctx.directory.id,
            )
            .offset(startIndex - 1)
            .limit(count)
        ).all()
        matches = list(rows)
    elif parsed[0] == "userName":
        u = scim_users.find_by_username(
            ctx.db, directory=ctx.directory, username=parsed[1]
        )
        matches = [u] if u else []
    elif parsed[0] == "externalId":
        u = scim_users.find_by_external_id(
            ctx.db, directory=ctx.directory, external_id=parsed[1]
        )
        matches = [u] if u else []
    else:
        return scim_400(
            f"unsupported filter attribute: {parsed[0]!r}",
            scim_type="invalidFilter",
        )

    return JSONResponse(
        {
            "schemas": [SCHEMA_LIST_RESPONSE],
            "totalResults": len(matches),
            "Resources": [
                _user_to_scim(u, request, ctx).model_dump(mode="json")
                for u in matches
            ],
            "startIndex": startIndex,
            "itemsPerPage": len(matches),
        },
        media_type=SCIM_CT,
    )


@router.get("/Users/{user_id}")
def get_user_endpoint(
    user_id: UUID,
    request: Request,
    ctx: Annotated[ScimContext, Depends(authenticate_scim)],
) -> JSONResponse:
    user = scim_users.find_by_id(
        ctx.db, directory=ctx.directory, user_id=user_id
    )
    if user is None:
        return scim_404("user not found")
    return JSONResponse(
        _user_to_scim(user, request, ctx).model_dump(mode="json"),
        media_type=SCIM_CT,
    )


@router.put("/Users/{user_id}")
def replace_user_endpoint(
    user_id: UUID,
    payload: ScimUser,
    request: Request,
    ctx: Annotated[ScimContext, Depends(authenticate_scim)],
) -> JSONResponse:
    user = scim_users.find_by_id(
        ctx.db, directory=ctx.directory, user_id=user_id
    )
    if user is None:
        return scim_404("user not found")
    user = scim_users.replace_from_scim(
        ctx.db, directory=ctx.directory, user=user, payload=payload
    )
    return JSONResponse(
        _user_to_scim(user, request, ctx).model_dump(mode="json"),
        media_type=SCIM_CT,
    )


@router.patch("/Users/{user_id}")
def patch_user_endpoint(
    user_id: UUID,
    payload: ScimPatchRequest,
    request: Request,
    ctx: Annotated[ScimContext, Depends(authenticate_scim)],
) -> JSONResponse:
    """SCIM PATCH /Users/{id} — partial update.

    The dominant op-path in real traffic is
    `op=replace path=active value=false` (Entra fires this on
    employee termination). We handle that case + the no-path
    `op=replace value={...}` form (Workspace style for general
    field updates)."""

    user = scim_users.find_by_id(
        ctx.db, directory=ctx.directory, user_id=user_id
    )
    if user is None:
        return scim_404("user not found")

    for op in payload.Operations:
        op_kind = op.op.lower()
        if op.path is None:
            # No-path PATCH — `value` is a dict of fields to merge.
            if not isinstance(op.value, dict):
                return scim_400("PATCH without path requires dict value")
            if "active" in op.value and op_kind == "replace":
                scim_users.set_active(
                    ctx.db,
                    directory=ctx.directory,
                    user=user,
                    active=bool(op.value["active"]),
                )
            # We don't persist the other fields (displayName, emails,
            # etc.) on PATCH for IdP-1 — they're rarely changed and
            # not worth re-translating per-attr-path. PUT covers the
            # full-resource update path if the IdP needs it.
            continue

        path_lower = op.path.lower()
        if path_lower == "active" and op_kind == "replace":
            scim_users.set_active(
                ctx.db,
                directory=ctx.directory,
                user=user,
                active=bool(op.value),
            )
        else:
            # Other paths (name, emails, externalId attribute updates)
            # — silently accept + ignore. IdPs hate hard 400s on PATCH
            # because they don't dedup the failing op out of subsequent
            # batches.
            continue

    # Reload — `set_active` committed, the in-memory object may be
    # stale w.r.t. `disabled_at`.
    ctx.db.refresh(user)
    return JSONResponse(
        _user_to_scim(user, request, ctx).model_dump(mode="json"),
        media_type=SCIM_CT,
    )


@router.delete("/Users/{user_id}", status_code=204)
def delete_user_endpoint(
    user_id: UUID,
    ctx: Annotated[ScimContext, Depends(authenticate_scim)],
) -> Response:
    user = scim_users.find_by_id(
        ctx.db, directory=ctx.directory, user_id=user_id
    )
    if user is None:
        return scim_404("user not found")
    scim_users.soft_delete(
        ctx.db, directory=ctx.directory, user=user
    )
    return Response(status_code=204)


# --- Groups --------------------------------------------------------------


@router.post("/Groups", status_code=201)
def create_group_endpoint(
    payload: ScimGroup,
    request: Request,
    ctx: Annotated[ScimContext, Depends(authenticate_scim)],
) -> JSONResponse:
    if not payload.displayName:
        return scim_400("displayName is required")
    if payload.externalId:
        existing = scim_groups.find_by_external_id(
            ctx.db,
            directory=ctx.directory,
            external_id=payload.externalId,
        )
        if existing is not None:
            return scim_409("group with this externalId already exists")
    operator_id = _any_operator_id(ctx)
    if operator_id is None:
        return scim_error(
            status_code=500,
            detail="no operator available for tenant; cannot record created_by",
        )
    try:
        group = scim_groups.create_from_scim(
            ctx.db,
            directory=ctx.directory,
            payload=payload,
            operator_id=operator_id,
        )
    except scim_groups.ScimGroupExistsError:
        return scim_409("group uniqueness conflict on insert")
    return JSONResponse(
        _group_to_scim(group, request, ctx).model_dump(mode="json"),
        status_code=201,
        media_type=SCIM_CT,
    )


@router.get("/Groups")
def list_groups_endpoint(
    request: Request,
    ctx: Annotated[ScimContext, Depends(authenticate_scim)],
    filter: str | None = Query(default=None),
    startIndex: int = Query(default=1, ge=1),
    count: int = Query(default=100, ge=0, le=200),
) -> JSONResponse:
    parsed = _parse_eq_filter(filter)
    matches: list[Group] = []

    if parsed is None:
        rows = ctx.db.scalars(
            select(Group).where(
                Group.tenant_id == ctx.directory.tenant_id,
                Group.idp_directory_id == ctx.directory.id,
            )
            .offset(startIndex - 1)
            .limit(count)
        ).all()
        matches = list(rows)
    elif parsed[0] == "displayName":
        rows = ctx.db.scalars(
            select(Group).where(
                Group.tenant_id == ctx.directory.tenant_id,
                Group.idp_directory_id == ctx.directory.id,
                Group.name == parsed[1],
            )
        ).all()
        matches = list(rows)
    elif parsed[0] == "externalId":
        g = scim_groups.find_by_external_id(
            ctx.db, directory=ctx.directory, external_id=parsed[1]
        )
        matches = [g] if g else []
    else:
        return scim_400(
            f"unsupported filter attribute: {parsed[0]!r}",
            scim_type="invalidFilter",
        )

    return JSONResponse(
        {
            "schemas": [SCHEMA_LIST_RESPONSE],
            "totalResults": len(matches),
            "Resources": [
                _group_to_scim(g, request, ctx).model_dump(mode="json")
                for g in matches
            ],
            "startIndex": startIndex,
            "itemsPerPage": len(matches),
        },
        media_type=SCIM_CT,
    )


@router.get("/Groups/{group_id}")
def get_group_endpoint(
    group_id: UUID,
    request: Request,
    ctx: Annotated[ScimContext, Depends(authenticate_scim)],
) -> JSONResponse:
    group = scim_groups.find_by_id(
        ctx.db, directory=ctx.directory, group_id=group_id
    )
    if group is None:
        return scim_404("group not found")
    return JSONResponse(
        _group_to_scim(group, request, ctx).model_dump(mode="json"),
        media_type=SCIM_CT,
    )


@router.put("/Groups/{group_id}")
def replace_group_endpoint(
    group_id: UUID,
    payload: ScimGroup,
    request: Request,
    ctx: Annotated[ScimContext, Depends(authenticate_scim)],
) -> JSONResponse:
    group = scim_groups.find_by_id(
        ctx.db, directory=ctx.directory, group_id=group_id
    )
    if group is None:
        return scim_404("group not found")
    operator_id = _any_operator_id(ctx)
    if operator_id is None:
        return scim_error(
            status_code=500,
            detail="no operator available for tenant",
        )
    group = scim_groups.replace_from_scim(
        ctx.db,
        directory=ctx.directory,
        group=group,
        payload=payload,
        operator_id=operator_id,
    )
    return JSONResponse(
        _group_to_scim(group, request, ctx).model_dump(mode="json"),
        media_type=SCIM_CT,
    )


@router.patch("/Groups/{group_id}")
def patch_group_endpoint(
    group_id: UUID,
    payload: ScimPatchRequest,
    request: Request,
    ctx: Annotated[ScimContext, Depends(authenticate_scim)],
) -> JSONResponse:
    """SCIM PATCH /Groups/{id} — handles both Entra and Workspace
    membership-mutation styles.

    Entra:
      - `op=add path=members value=[{value: "uid"}]`
      - `op=remove path="members[value eq \\"uid\\"]"`
    Workspace:
      - `op=replace path=members value=[...]`
      - `op=replace value={members: [...]}`
    """

    group = scim_groups.find_by_id(
        ctx.db, directory=ctx.directory, group_id=group_id
    )
    if group is None:
        return scim_404("group not found")

    operator_id = _any_operator_id(ctx)
    if operator_id is None:
        return scim_error(
            status_code=500,
            detail="no operator available for tenant",
        )

    for op in payload.Operations:
        op_kind = op.op.lower()
        path = (op.path or "").strip()

        # --- Membership add (Entra style) ---
        if op_kind == "add" and path.lower() == "members":
            ids = _extract_member_ids(op.value)
            scim_groups.add_members(
                ctx.db,
                directory=ctx.directory,
                group=group,
                user_ids=ids,
                added_by=operator_id,
            )
            continue

        # --- Membership remove (Entra style — filter form) ---
        if op_kind == "remove" and path.lower().startswith("members["):
            uid = _parse_filter_eq_value(path)
            if uid is not None:
                scim_groups.remove_members(
                    ctx.db,
                    directory=ctx.directory,
                    group=group,
                    user_ids=[uid],
                )
            continue
        if op_kind == "remove" and path.lower() == "members":
            ids = _extract_member_ids(op.value)
            scim_groups.remove_members(
                ctx.db,
                directory=ctx.directory,
                group=group,
                user_ids=ids,
            )
            continue

        # --- Membership replace (Workspace style — wholesale) ---
        if op_kind == "replace" and path.lower() == "members":
            ids = _extract_member_ids(op.value)
            # Wholesale replace = remove anything not in `ids`, add
            # whatever's missing. We do it in two passes via the
            # service to keep the audit clean.
            current = set(scim_groups.list_member_ids(ctx.db, group_id=group.id))
            target = set(ids)
            scim_groups.remove_members(
                ctx.db,
                directory=ctx.directory,
                group=group,
                user_ids=list(current - target),
            )
            scim_groups.add_members(
                ctx.db,
                directory=ctx.directory,
                group=group,
                user_ids=list(target - current),
                added_by=operator_id,
            )
            continue

        # --- displayName replace ---
        if op_kind == "replace" and path.lower() == "displayname":
            if isinstance(op.value, str):
                group.name = op.value
                ctx.db.commit()
            continue

        if op_kind == "replace" and path == "" and isinstance(op.value, dict):
            if "members" in op.value:
                ids = _extract_member_ids(op.value["members"])
                current = set(scim_groups.list_member_ids(ctx.db, group_id=group.id))
                target = set(ids)
                scim_groups.remove_members(
                    ctx.db,
                    directory=ctx.directory,
                    group=group,
                    user_ids=list(current - target),
                )
                scim_groups.add_members(
                    ctx.db,
                    directory=ctx.directory,
                    group=group,
                    user_ids=list(target - current),
                    added_by=operator_id,
                )
            if "displayName" in op.value:
                group.name = str(op.value["displayName"])
                ctx.db.commit()
            continue

        # Anything else — silently accept + ignore. IdPs are happier
        # with 200 + idempotent state than with hard 400s on per-op
        # quirks.

    ctx.db.refresh(group)
    return JSONResponse(
        _group_to_scim(group, request, ctx).model_dump(mode="json"),
        media_type=SCIM_CT,
    )


@router.delete("/Groups/{group_id}", status_code=204)
def delete_group_endpoint(
    group_id: UUID,
    ctx: Annotated[ScimContext, Depends(authenticate_scim)],
) -> Response:
    group = scim_groups.find_by_id(
        ctx.db, directory=ctx.directory, group_id=group_id
    )
    if group is None:
        return scim_404("group not found")
    scim_groups.soft_delete(
        ctx.db, directory=ctx.directory, group=group
    )
    return Response(status_code=204)


# --- Helpers --------------------------------------------------------------


def _scim_base_url(request: Request, ctx: ScimContext) -> str:
    return f"{str(request.base_url).rstrip('/')}/scim/v2/{ctx.directory.id}"


def _user_to_scim(user: User, request: Request, ctx: ScimContext) -> ScimUser:
    base = _scim_base_url(request, ctx)
    return ScimUser(
        schemas=[SCHEMA_USER],
        id=str(user.id),
        externalId=user.external_id,
        userName=user.email,
        displayName=user.display_name,
        emails=[ScimEmail(value=user.email, primary=True, type="work")],
        active=user.disabled_at is None and user.soft_deleted_at is None,
        meta=ScimMeta(
            resourceType="User",
            created=user.created_at,
            lastModified=user.created_at,
            location=f"{base}/Users/{user.id}",
        ),
    )


def _group_to_scim(group: Group, request: Request, ctx: ScimContext) -> ScimGroup:
    base = _scim_base_url(request, ctx)
    member_ids = scim_groups.list_member_ids(ctx.db, group_id=group.id)
    members = [
        ScimGroupMemberRef(
            value=str(uid),
            ref=f"{base}/Users/{uid}",  # type: ignore[call-arg]
        )
        for uid in member_ids
    ]
    return ScimGroup(
        schemas=[SCHEMA_GROUP],
        id=str(group.id),
        externalId=group.external_id,
        displayName=group.name,
        members=members,
        meta=ScimMeta(
            resourceType="Group",
            created=group.created_at,
            lastModified=group.created_at,
            location=f"{base}/Groups/{group.id}",
        ),
    )


# --- Filter parsing -------------------------------------------------------


_EQ_RE = re.compile(
    r'^\s*(?P<attr>[A-Za-z][A-Za-z0-9_]*)\s+eq\s+"(?P<value>[^"]*)"\s*$'
)


def _parse_eq_filter(filter_str: str | None) -> tuple[str, str] | None:
    """Parse `attr eq "value"`. Returns (attr, value) or None for no
    filter. We deliberately don't implement the full SCIM filter
    grammar — `eq` covers every dedup probe Entra/Workspace send."""

    if not filter_str:
        return None
    match = _EQ_RE.match(filter_str)
    if not match:
        return None
    return match.group("attr"), match.group("value")


# Entra removal filter: `members[value eq "<uuid>"]`.
_MEMBERS_FILTER_RE = re.compile(
    r'^members\[\s*value\s+eq\s+"(?P<uid>[^"]+)"\s*\]\s*$',
    re.IGNORECASE,
)


def _parse_filter_eq_value(path: str) -> UUID | None:
    match = _MEMBERS_FILTER_RE.match(path)
    if not match:
        return None
    try:
        return UUID(match.group("uid"))
    except ValueError:
        return None


def _extract_member_ids(value: Any) -> list[UUID]:
    """Extract member UUIDs from a PATCH op value.

    Tolerant — accepts a list of dicts (`[{"value": "uid"}]`), a list
    of bare strings (rare), or a single dict (rare). Skips anything
    we can't parse rather than 400-ing the whole batch."""

    if value is None:
        return []
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list):
        return []
    out: list[UUID] = []
    for item in value:
        if isinstance(item, dict):
            raw = item.get("value")
        elif isinstance(item, str):
            raw = item
        else:
            continue
        if not raw:
            continue
        uid = resolve_member_id(str(raw))
        if uid is not None:
            out.append(uid)
    return out


def _any_operator_id(ctx: ScimContext) -> UUID | None:
    """Pick any operator in the tenant — used for the `created_by` FK
    on SCIM-provisioned groups. The audit log carries the truth about
    who created the group (`actor_kind='scim'`); `created_by` is just
    the FK requirement that needs filling.

    Future enhancement: stash `connected_by_operator_id` on the
    directory at connect-time and use it here. Sufficient for IDP-1;
    captured in the IDP-1 backlog item."""

    return ctx.db.scalar(
        select(Operator.id).where(
            Operator.tenant_id == ctx.directory.tenant_id
        ).limit(1)
    )
