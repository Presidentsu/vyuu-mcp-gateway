"""A3-γ access-request endpoints.

Two surfaces share one router file:

- **Portal (end user, portal-session JWT auth)** under
  `/api/v1/portal/{tenant_id}/access-requests`:
  - POST   submit a request
  - GET    list-mine
  - DELETE withdraw a pending request

- **Admin (operator JWT auth)** under
  `/api/v1/access-requests`:
  - GET           list (with optional `?status=`)
  - POST /approve approve a pending request (auto-creates a grant)
  - POST /decline decline a pending request (with optional note)

Cross-tenant defense on the portal side: the path carries `tenant_id`
and we 403 on mismatch with the session's `tenant_id` claim. The token
itself is signed, so an attacker can't forge a session for another
tenant — but a leaked token replayed against a different tenant's URL
is still rejected.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.audit.admin_audit import AdminAuditActor
from vyuu_gateway.db.models import (
    AccessRequestStatus,
    VirtualServer,
    VirtualServerToolGrant,
)
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator
from vyuu_gateway.registry.access_requests_schemas import (
    AccessRequestListItemResponse,
    AccessRequestResponse,
    DeclineAccessRequestRequest,
    SubmitAccessRequestRequest,
)
from vyuu_gateway.registry.access_requests_service import (
    AccessRequestNotFoundError,
    DuplicatePendingRequestError,
    InvalidApprovalDurationError,
    UserAlreadyHasAccessError,
    VserverIsPublicError,
    VserverNotFoundForRequestError,
    WrongRequestStateError,
    _user_has_active_grant,
    approve_access_request,
    decline_access_request,
    list_access_requests_with_context,
    list_my_access_requests,
    submit_access_request,
    withdraw_access_request,
)
from vyuu_gateway.registry.jit_schemas import (
    ApproveAccessRequestRequest,
    JitAccessRequestRequest,
    JitAccessRequestResponse,
    JitOptionsResponse,
    MyToolElevationOptionsResponse,
    ToolElevationRequestRequest,
)
from vyuu_gateway.registry.jit_service import (
    JitDurationTooLongError,
    JitInvalidDurationError,
    JitJustificationRequiredError,
    JitNotEnabledError,
    ToolNotJitEligibleError,
    VserverAccessRequiredError,
    request_jit_access,
    request_tool_elevation,
)
from vyuu_gateway.users.portal_dependency import (
    authenticate_portal_session,
    get_portal_scoped_db,
)
from vyuu_gateway.users.sessions import PortalSession

# --- Two routers, mounted with different prefixes by main.py -----------

portal_router = APIRouter(tags=["portal"])
admin_router = APIRouter(tags=["access-requests"])


# --- Portal (end-user) endpoints ---------------------------------------


def _enforce_path_tenant(session: PortalSession, tenant_id: UUID) -> None:
    """403 if the session was minted for a different tenant. Defense
    against a leaked token replayed at another tenant's URL."""

    if session.tenant_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="session does not match tenant in path",
        )


@portal_router.post(
    "/{tenant_id}/access-requests",
    response_model=AccessRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
def submit_access_request_endpoint(
    tenant_id: UUID,
    request: SubmitAccessRequestRequest,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
) -> AccessRequestResponse:
    _enforce_path_tenant(session, tenant_id)
    try:
        access_request = submit_access_request(
            db,
            tenant_id=tenant_id,
            user_id=session.user_id,
            vserver_id=request.vserver_id,
            note=request.note,
        )
    except VserverNotFoundForRequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="virtual server not found",
        ) from exc
    except VserverIsPublicError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="virtual server is public; no request needed",
        ) from exc
    except UserAlreadyHasAccessError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="user already has access to this vserver",
        ) from exc
    except DuplicatePendingRequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="a pending request already exists for this vserver",
        ) from exc
    return AccessRequestResponse.model_validate(access_request)


@portal_router.get(
    "/{tenant_id}/access-requests",
    response_model=list[AccessRequestResponse],
)
def list_my_access_requests_endpoint(
    tenant_id: UUID,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
    status_filter: AccessRequestStatus | None = None,
) -> list[AccessRequestResponse]:
    _enforce_path_tenant(session, tenant_id)
    return [
        AccessRequestResponse.model_validate(r)
        for r in list_my_access_requests(
            db,
            tenant_id=tenant_id,
            user_id=session.user_id,
            status_filter=status_filter,
        )
    ]


@portal_router.delete(
    "/{tenant_id}/access-requests/{request_id}",
    response_model=AccessRequestResponse,
)
def withdraw_access_request_endpoint(
    tenant_id: UUID,
    request_id: UUID,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
) -> AccessRequestResponse:
    _enforce_path_tenant(session, tenant_id)
    try:
        request_row = withdraw_access_request(
            db,
            tenant_id=tenant_id,
            user_id=session.user_id,
            request_id=request_id,
        )
    except AccessRequestNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="access request not found",
        ) from exc
    except WrongRequestStateError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="only pending requests can be withdrawn",
        ) from exc
    return AccessRequestResponse.model_validate(request_row)


# --- Admin endpoints ----------------------------------------------------


@admin_router.get(
    "/access-requests",
    response_model=list[AccessRequestListItemResponse],
)
def list_access_requests_endpoint(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
    status_filter: AccessRequestStatus | None = None,
) -> list[AccessRequestListItemResponse]:
    """Admin queue. Pass `?status_filter=pending` for the working
    queue; omit for the full audit log of decisions made + pending.

    Returns the joined view (requester email, target vserver name,
    deciding operator email) so the admin console can render the
    queue in a single round-trip."""

    items = list_access_requests_with_context(
        db,
        tenant_id=operator.tenant_id,
        status_filter=status_filter,
    )
    return [
        AccessRequestListItemResponse(
            id=item.request.id,
            tenant_id=item.request.tenant_id,
            user_id=item.request.user_id,
            vserver_id=item.request.vserver_id,
            status=item.request.status,
            note=item.request.note,
            requested_duration_seconds=item.request.requested_duration_seconds,
            decision_note=item.request.decision_note,
            decided_by=item.request.decided_by,
            decided_at=item.request.decided_at,
            created_grant_id=item.request.created_grant_id,
            created_at=item.request.created_at,
            user_email=item.user_email,
            user_display_name=item.user_display_name,
            vserver_name=item.vserver_name,
            vserver_visibility=item.vserver_visibility,
            decided_by_email=item.decided_by_email,
        )
        for item in items
    ]


@admin_router.post(
    "/access-requests/{request_id}/approve",
    response_model=AccessRequestResponse,
)
def approve_access_request_endpoint(
    request_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
    request: ApproveAccessRequestRequest | None = None,
) -> AccessRequestResponse:
    """Approve a pending request.

    JIT-1: the body is optional and back-compatible — an approve with no
    body behaves exactly as it did before JIT (standing access for a
    plain request, the requested window for a JIT one). Supplying
    `duration_seconds` lets the reviewer grant *less* than was asked for,
    which is the common review outcome.
    """

    try:
        request_row = approve_access_request(
            db,
            tenant_id=operator.tenant_id,
            request_id=request_id,
            operator_id=operator.operator_id,
            duration_seconds=(
                request.duration_seconds if request is not None else None
            ),
            actor=AdminAuditActor.operator(operator),
        )
    except AccessRequestNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="access request not found",
        ) from exc
    except WrongRequestStateError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="only pending requests can be approved",
        ) from exc
    except InvalidApprovalDurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    return AccessRequestResponse.model_validate(request_row)


@admin_router.post(
    "/access-requests/{request_id}/decline",
    response_model=AccessRequestResponse,
)
def decline_access_request_endpoint(
    request_id: UUID,
    request: DeclineAccessRequestRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> AccessRequestResponse:
    try:
        request_row = decline_access_request(
            db,
            tenant_id=operator.tenant_id,
            request_id=request_id,
            operator_id=operator.operator_id,
            decision_note=request.decision_note,
            actor=AdminAuditActor.operator(operator),
        )
    except AccessRequestNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="access request not found",
        ) from exc
    except WrongRequestStateError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="only pending requests can be declined",
        ) from exc
    return AccessRequestResponse.model_validate(request_row)


# --- JIT-1 · end-user just-in-time elevation ------------------------------


@portal_router.get(
    "/{tenant_id}/vservers/{vserver_id}/jit-options",
    response_model=JitOptionsResponse,
)
def jit_options_endpoint(
    tenant_id: UUID,
    vserver_id: UUID,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
) -> JitOptionsResponse:
    """What the portal needs to render the request dialog: the ceiling,
    whether a reason is required, whether it self-approves, and the
    preset durations that actually fit under the ceiling.

    Served rather than hard-coded in the SPA so the client cannot offer a
    duration the server will reject.
    """

    _enforce_path_tenant(session, tenant_id)
    vserver = db.scalar(
        select(VirtualServer).where(
            VirtualServer.tenant_id == tenant_id,
            VirtualServer.id == vserver_id,
        )
    )
    if vserver is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="virtual server not found",
        )
    return JitOptionsResponse.from_vserver(
        vserver.id,
        jit_enabled=vserver.jit_enabled,
        max_duration_seconds=vserver.jit_max_duration_seconds,
        auto_approve=vserver.jit_auto_approve,
        require_justification=vserver.jit_require_justification,
    )


@portal_router.post(
    "/{tenant_id}/jit-requests",
    response_model=JitAccessRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
def request_jit_access_endpoint(
    tenant_id: UUID,
    request: JitAccessRequestRequest,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
) -> JitAccessRequestResponse:
    """Ask for a time-boxed elevation.

    On an auto-approve vserver the grant is live when this returns; on
    any other it lands in the operator's existing approval queue carrying
    the requested duration. `granted` is the field the client branches on.
    """

    _enforce_path_tenant(session, tenant_id)
    try:
        elevation = request_jit_access(
            db,
            tenant_id=tenant_id,
            user_id=session.user_id,
            vserver_id=request.vserver_id,
            duration_seconds=request.duration_seconds,
            justification=request.justification,
        )
    except VserverNotFoundForRequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="virtual server not found",
        ) from exc
    except VserverIsPublicError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="virtual server is public; no elevation needed",
        ) from exc
    except JitNotEnabledError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="this virtual server does not offer just-in-time access",
        ) from exc
    except JitDurationTooLongError as exc:
        # 400 with the ceiling in the message: the caller can retry
        # correctly instead of bisecting for an acceptable value.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except JitInvalidDurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except JitJustificationRequiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="this virtual server requires a reason for the request",
        ) from exc
    except UserAlreadyHasAccessError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="you already have access to this vserver",
        ) from exc
    except DuplicatePendingRequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="a pending request already exists for this vserver",
        ) from exc

    return JitAccessRequestResponse(
        granted=elevation.granted,
        grant_id=elevation.grant.id if elevation.grant else None,
        request_id=elevation.request.id if elevation.request else None,
        expires_at=elevation.expires_at,
    )


# --- JIT-2 · end-user per-tool elevation -----------------------------------


@portal_router.get(
    "/{tenant_id}/vservers/{vserver_id}/tool-elevation-options",
    response_model=MyToolElevationOptionsResponse,
)
def tool_elevation_options_endpoint(
    tenant_id: UUID,
    vserver_id: UUID,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
) -> MyToolElevationOptionsResponse:
    """Which tools on this bundle are elevation-gated, their ceilings,
    and which the caller is already elevated into.

    `has_vserver_access` is served rather than inferred, because a tool
    elevation NARROWS access — it never grants it. The portal uses this
    to explain why the button is disabled instead of letting the user
    click into a 409.
    """

    _enforce_path_tenant(session, tenant_id)
    vserver = db.scalar(
        select(VirtualServer).where(
            VirtualServer.tenant_id == tenant_id,
            VirtualServer.id == vserver_id,
        )
    )
    if vserver is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="virtual server not found",
        )

    now = datetime.now(UTC)
    live = db.execute(
        select(
            VirtualServerToolGrant.exposed_tool_name,
            VirtualServerToolGrant.expires_at,
        ).where(
            VirtualServerToolGrant.tenant_id == tenant_id,
            VirtualServerToolGrant.vserver_id == vserver_id,
            VirtualServerToolGrant.principal_id == session.user_id,
            VirtualServerToolGrant.revoked_at.is_(None),
            VirtualServerToolGrant.expires_at > now,
        )
    ).all()

    return MyToolElevationOptionsResponse(
        vserver_id=vserver.id,
        has_vserver_access=_user_has_active_grant(
            db, tenant_id=tenant_id, vserver_id=vserver_id, user_id=session.user_id
        ),
        auto_approve=vserver.jit_auto_approve,
        require_justification=vserver.jit_require_justification,
        jit_tools={k: int(v) for k, v in (vserver.jit_tools or {}).items()},
        active_tool_elevations=dict(live),
    )


@portal_router.post(
    "/{tenant_id}/tool-elevations",
    response_model=JitAccessRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
def request_tool_elevation_endpoint(
    tenant_id: UUID,
    request: ToolElevationRequestRequest,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
) -> JitAccessRequestResponse:
    """Elevate into one tool for a bounded window.

    Requires the caller to already hold access to the vserver — a tool
    elevation narrows, it does not grant. See `VserverAccessRequiredError`.
    """

    _enforce_path_tenant(session, tenant_id)
    try:
        elevation = request_tool_elevation(
            db,
            tenant_id=tenant_id,
            user_id=session.user_id,
            vserver_id=request.vserver_id,
            exposed_tool_name=request.exposed_tool_name,
            duration_seconds=request.duration_seconds,
            justification=request.justification,
        )
    except VserverNotFoundForRequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="virtual server not found",
        ) from exc
    except ToolNotJitEligibleError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="this tool does not offer just-in-time elevation",
        ) from exc
    except VserverAccessRequiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "request access to this virtual server first — a tool "
                "elevation narrows existing access, it does not grant it"
            ),
        ) from exc
    except JitDurationTooLongError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except JitInvalidDurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except JitJustificationRequiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="this virtual server requires a reason for the request",
        ) from exc
    except DuplicatePendingRequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="a pending request already exists for this tool",
        ) from exc

    return JitAccessRequestResponse(
        granted=elevation.granted,
        # `tool_grant`, not `grant`: a per-tool elevation issues a
        # `VirtualServerToolGrant`. This was hardcoded None while the
        # vserver-level sibling above filled its own field correctly, so
        # an auto-approved caller got `granted: true` with nothing to
        # reference the grant by — even though the operator listing
        # showed its id.
        grant_id=elevation.tool_grant.id if elevation.tool_grant else None,
        request_id=elevation.request.id if elevation.request else None,
        expires_at=elevation.expires_at,
    )
