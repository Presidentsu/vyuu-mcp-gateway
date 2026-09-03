"""Operator-API endpoints for virtual server CRUD.

A virtual server is the user-facing surface clients connect to: it bundles a
chosen subset of tools from one or more registered upstream servers and
exposes them at `POST /v/{tenant}/{vserver_name}/mcp`. Operators register an
upstream, sync its capabilities (`/api/v1/servers/{id}/sync`), then create a
virtual server here with the tools they want to publish.

Tenant + creator come from the bearer-token-resolved operator context, never
from the request body — `extra="forbid"` on the request schemas + the trusted
kwargs on the service functions enforce that contract end-to-end. Same shape
as `POST /api/v1/servers`.
"""

from __future__ import annotations

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.audit.admin_audit import AdminAuditActor
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator
from vyuu_gateway.registry.access_requests_service import (
    VserverIsPublicError,
    VserverNotFoundForRequestError,
)
from vyuu_gateway.registry.jit_schemas import (
    ActiveElevationResponse,
    ActiveToolElevationResponse,
    ConfigureVserverJitRequest,
    ConfigureVserverJitToolsRequest,
    VserverJitPolicyResponse,
    VserverJitToolsResponse,
)
from vyuu_gateway.registry.jit_service import (
    JitInvalidDurationError,
    ToolNotJitEligibleError,
    configure_vserver_jit,
    configure_vserver_jit_tools,
    list_active_elevations,
    list_active_tool_elevations,
)
from vyuu_gateway.virtual_servers.schemas import (
    CreateVirtualServerRequest,
    UpdateVirtualServerRequest,
    VirtualServerListItemResponse,
    VirtualServerResponse,
    VirtualServerToolResponse,
)
from vyuu_gateway.virtual_servers.service import (
    DuplicateVirtualServerNameError,
    UpstreamServerNotFoundError,
    VirtualServerCreatorNotFoundError,
    VirtualServerNotFoundError,
    create_virtual_server,
    delete_virtual_server,
    get_virtual_server,
    list_virtual_server_tools,
    list_virtual_servers_with_aggregates,
    update_virtual_server,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/vservers", tags=["vservers"])


@router.post(
    "",
    response_model=VirtualServerResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_vserver_endpoint(
    request: CreateVirtualServerRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> VirtualServerResponse:
    try:
        virtual_server = create_virtual_server(
            db,
            request=request,
            tenant_id=operator.tenant_id,
            created_by=operator.operator_id,
            actor=AdminAuditActor.operator(operator),
        )
    except VirtualServerCreatorNotFoundError as exc:
        # Auth said this operator+tenant pair is real, but the operators
        # table disagrees. Same posture as the registration endpoint —
        # reject as 401, the bearer token's claim is invalid.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except DuplicateVirtualServerNameError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="virtual server name already exists in tenant",
        ) from exc
    except UpstreamServerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="one or more allowlisted upstream servers do not exist in this tenant",
        ) from exc

    logger.info("virtual_server_created")
    return VirtualServerResponse.model_validate(virtual_server)


@router.get("", response_model=list[VirtualServerListItemResponse])
def list_vservers_endpoint(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> list[VirtualServerListItemResponse]:
    """List virtual servers in this tenant with the per-row
    aggregates the admin console table renders (tool count + grant
    count). Single SQL — no N+1."""

    items = list_virtual_servers_with_aggregates(
        db, tenant_id=operator.tenant_id
    )
    return [
        VirtualServerListItemResponse(
            id=item.virtual_server.id,
            tenant_id=item.virtual_server.tenant_id,
            name=item.virtual_server.name,
            policy_id=item.virtual_server.policy_id,
            rename_map=item.virtual_server.rename_map,
            visibility=item.virtual_server.visibility,
            jit_enabled=item.virtual_server.jit_enabled,
            jit_max_duration_seconds=item.virtual_server.jit_max_duration_seconds,
            jit_auto_approve=item.virtual_server.jit_auto_approve,
            jit_require_justification=item.virtual_server.jit_require_justification,
            jit_tools=dict(item.virtual_server.jit_tools or {}),
            created_by=item.virtual_server.created_by,
            created_at=item.virtual_server.created_at,
            tool_count=item.tool_count,
            grant_count=item.grant_count,
        )
        for item in items
    ]


@router.get("/{vserver_id}", response_model=VirtualServerResponse)
def get_vserver_endpoint(
    vserver_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> VirtualServerResponse:
    try:
        virtual_server = get_virtual_server(
            db, tenant_id=operator.tenant_id, vserver_id=vserver_id
        )
    except VirtualServerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="virtual server not found",
        ) from exc
    return VirtualServerResponse.model_validate(virtual_server)


@router.get(
    "/{vserver_id}/tools",
    response_model=list[VirtualServerToolResponse],
)
def list_vserver_tools_endpoint(
    vserver_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> list[VirtualServerToolResponse]:
    """The currently allowlisted (server_id, tool_name) tuples for a vserver.

    The operator UI uses this to pre-fill the "edit tool list" form with the
    current selections before letting the operator add or remove tools.
    """
    try:
        rows = list_virtual_server_tools(
            db, tenant_id=operator.tenant_id, vserver_id=vserver_id
        )
    except VirtualServerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="virtual server not found",
        ) from exc
    return [VirtualServerToolResponse.model_validate(row) for row in rows]


@router.patch("/{vserver_id}", response_model=VirtualServerResponse)
def update_vserver_endpoint(
    vserver_id: UUID,
    request: UpdateVirtualServerRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> VirtualServerResponse:
    try:
        virtual_server = update_virtual_server(
            db,
            tenant_id=operator.tenant_id,
            vserver_id=vserver_id,
            request=request,
            actor=AdminAuditActor.operator(operator),
        )
    except VirtualServerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="virtual server not found",
        ) from exc
    except DuplicateVirtualServerNameError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="virtual server name already exists in tenant",
        ) from exc
    except UpstreamServerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="one or more allowlisted upstream servers do not exist in this tenant",
        ) from exc

    return VirtualServerResponse.model_validate(virtual_server)


@router.delete(
    "/{vserver_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_vserver_endpoint(
    vserver_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> None:
    try:
        delete_virtual_server(
            db,
            tenant_id=operator.tenant_id,
            vserver_id=vserver_id,
            actor=AdminAuditActor.operator(operator),
        )
    except VirtualServerNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="virtual server not found",
        ) from exc


# --- JIT-1 · just-in-time access ------------------------------------------
#
# `/jit/elevations` is declared BEFORE `/{vserver_id}/jit` on purpose: it
# is a literal path that would otherwise be shadowed if a future route
# made the vserver segment optional. Cheap insurance, no cost.


@router.get(
    "/jit/elevations",
    response_model=list[ActiveElevationResponse],
)
def list_active_elevations_endpoint(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> list[ActiveElevationResponse]:
    """Who is elevated right now, soonest-expiring first.

    Includes operator-issued time-boxed grants as well as JIT ones —
    `granted_via` distinguishes them. The question is "who has temporary
    access", and a hand-issued 2-hour grant is exactly as much elevation
    as an auto-approved one.
    """

    return [
        ActiveElevationResponse.model_validate(e)
        for e in list_active_elevations(db, tenant_id=operator.tenant_id)
    ]


@router.patch(
    "/{vserver_id}/jit",
    response_model=VserverJitPolicyResponse,
)
def configure_vserver_jit_endpoint(
    vserver_id: UUID,
    request: ConfigureVserverJitRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> VserverJitPolicyResponse:
    """Turn JIT on/off for one vserver and set its ceiling / approval mode.

    Audited as `vserver.jit_enable` / `vserver.jit_disable` — both
    directions matter: enabling delegates standing authority to a
    self-service flow, and disabling strands anyone mid-workflow.
    """

    try:
        vserver = configure_vserver_jit(
            db,
            tenant_id=operator.tenant_id,
            vserver_id=vserver_id,
            enabled=request.enabled,
            max_duration_seconds=request.max_duration_seconds,
            auto_approve=request.auto_approve,
            require_justification=request.require_justification,
            actor=AdminAuditActor.operator(operator),
        )
        db.commit()
    except VserverNotFoundForRequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="virtual server not found",
        ) from exc
    except VserverIsPublicError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "JIT applies only to private virtual servers — a public "
                "one needs no grant, so there is nothing to elevate into"
            ),
        ) from exc
    except JitInvalidDurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    db.refresh(vserver)
    return VserverJitPolicyResponse(
        vserver_id=vserver.id,
        name=vserver.name,
        jit_enabled=vserver.jit_enabled,
        jit_max_duration_seconds=vserver.jit_max_duration_seconds,
        jit_auto_approve=vserver.jit_auto_approve,
        jit_require_justification=vserver.jit_require_justification,
    )


# --- JIT-2 · per-tool elevation -------------------------------------------


@router.get(
    "/jit/tool-elevations",
    response_model=list[ActiveToolElevationResponse],
)
def list_active_tool_elevations_endpoint(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> list[ActiveToolElevationResponse]:
    """Who holds a live per-tool elevation right now, soonest-expiring
    first. Separate from `/jit/elevations` because the questions differ:
    that one is "who can reach this bundle", this one is "who can run
    this specific dangerous tool"."""

    return [
        ActiveToolElevationResponse.model_validate(e)
        for e in list_active_tool_elevations(db, tenant_id=operator.tenant_id)
    ]


@router.patch(
    "/{vserver_id}/jit-tools",
    response_model=VserverJitToolsResponse,
)
def configure_vserver_jit_tools_endpoint(
    vserver_id: UUID,
    request: ConfigureVserverJitToolsRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> VserverJitToolsResponse:
    """Set which tools on this vserver require a just-in-time elevation,
    and each tool's ceiling.

    Independent of the vserver-level `jit_enabled` toggle on purpose: the
    main use case is standing access to the bundle with one dangerous
    tool gated. Audited as `vserver.jit_tools_set`, with the newly-gated
    and no-longer-gated tool names spelled out.
    """

    try:
        vserver = configure_vserver_jit_tools(
            db,
            tenant_id=operator.tenant_id,
            vserver_id=vserver_id,
            jit_tools=request.jit_tools,
            actor=AdminAuditActor.operator(operator),
        )
        db.commit()
    except VserverNotFoundForRequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="virtual server not found",
        ) from exc
    except (ToolNotJitEligibleError, JitInvalidDurationError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    db.refresh(vserver)
    return VserverJitToolsResponse(
        vserver_id=vserver.id,
        name=vserver.name,
        jit_tools=dict(vserver.jit_tools or {}),
    )
