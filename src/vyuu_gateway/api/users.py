"""Operator-side admin endpoints for users / groups / API keys / grants.

All require operator auth (existing `authenticate_operator` dep). Tenant
scoping is taken from the operator context, not the body. Same security
posture as `/api/v1/servers`.

Naming: route prefix is plural (`/users`, `/groups`) for collection
endpoints, with nested sub-collections for membership / api keys /
grants. Mirrors the existing servers + vservers shape.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.audit.admin_audit import AdminAuditActor
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator
from vyuu_gateway.registry.api_key_policy_service import (
    ApiKeyPolicyError,
    enforce_requested_expiry,
    resolve_max_ttl,
)
from vyuu_gateway.registry.users_schemas import (
    AddGroupMemberRequest,
    CreateGrantRequest,
    CreateGroupRequest,
    CreateLocalUserRequest,
    CreateUserApiKeyRequest,
    GrantResponse,
    GroupListItemResponse,
    GroupResponse,
    IssuedApiKeyResponse,
    SetPasswordRequest,
    SetVisibilityRequest,
    UserApiKeySummaryResponse,
    UserListItemResponse,
    UserResponse,
)
from vyuu_gateway.registry.users_service import (
    DuplicateApiKeyLabelError,
    DuplicateGroupNameError,
    DuplicateUserEmailError,
    GrantTargetNotFoundError,
    GroupNotFoundError,
    UserNotFoundError,
    WrongAuthMethodError,
    add_group_member,
    create_group,
    create_local_user,
    disable_user,
    get_user,
    issue_grant,
    issue_user_api_key,
    list_grants,
    list_group_members,
    list_groups_with_aggregates,
    list_user_api_keys,
    list_users_with_aggregates,
    remove_group_member,
    revoke_grant,
    revoke_user_api_key,
    set_password,
    set_vserver_visibility,
)
from vyuu_gateway.users.passwords import PasswordTooWeakError

router = APIRouter(tags=["users"])


# --- Users ----------------------------------------------------------------


@router.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_local_user_endpoint(
    request: CreateLocalUserRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> UserResponse:
    try:
        user = create_local_user(
            db,
            tenant_id=operator.tenant_id,
            email=request.email,
            password=request.password,
            display_name=request.display_name,
            must_change_password=request.must_change_password,
            actor=AdminAuditActor.operator(operator),
        )
    except PasswordTooWeakError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="password does not meet minimum requirements",
        ) from exc
    except DuplicateUserEmailError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="user with this email already exists in tenant",
        ) from exc
    return UserResponse.model_validate(user)


@router.get("/users", response_model=list[UserListItemResponse])
def list_users_endpoint(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> list[UserListItemResponse]:
    """List users in this tenant with the per-row aggregates the
    admin console table renders (active API-key count, group count,
    last-key-used timestamp). Single SQL — no N+1."""

    items = list_users_with_aggregates(db, tenant_id=operator.tenant_id)
    return [
        UserListItemResponse(
            id=item.user.id,
            tenant_id=item.user.tenant_id,
            email=item.user.email,
            display_name=item.user.display_name,
            auth_method=item.user.auth_method,
            must_change_password=item.user.must_change_password,
            created_at=item.user.created_at,
            last_login_at=item.user.last_login_at,
            disabled_at=item.user.disabled_at,
            api_key_count=item.api_key_count,
            group_count=item.group_count,
            last_api_key_used_at=item.last_api_key_used_at,
        )
        for item in items
    ]


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user_endpoint(
    user_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> UserResponse:
    try:
        user = get_user(db, tenant_id=operator.tenant_id, user_id=user_id)
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="user not found"
        ) from exc
    return UserResponse.model_validate(user)


@router.post("/users/{user_id}/password", response_model=UserResponse)
def set_password_endpoint(
    user_id: UUID,
    request: SetPasswordRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> UserResponse:
    """Admin password reset. Always sets `must_change_password=True` so
    the user is forced to rotate again on first login."""
    try:
        user = set_password(
            db,
            tenant_id=operator.tenant_id,
            user_id=user_id,
            new_password=request.new_password,
            require_rotation=True,
            actor=AdminAuditActor.operator(operator),
        )
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="user not found"
        ) from exc
    except WrongAuthMethodError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cannot set password on an OIDC-authed user",
        ) from exc
    except PasswordTooWeakError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="password does not meet minimum requirements",
        ) from exc
    return UserResponse.model_validate(user)


@router.delete("/users/{user_id}", response_model=UserResponse)
def disable_user_endpoint(
    user_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> UserResponse:
    """Soft-delete by setting `disabled_at`. Existing API keys keep
    failing validation because the auth path checks the user row's
    `disabled_at`. Idempotent."""
    try:
        user = disable_user(
            db,
            tenant_id=operator.tenant_id,
            user_id=user_id,
            actor=AdminAuditActor.operator(operator),
        )
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="user not found"
        ) from exc
    return UserResponse.model_validate(user)


# --- API keys -------------------------------------------------------------


@router.post(
    "/users/{user_id}/api-keys",
    response_model=IssuedApiKeyResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_user_api_key_endpoint(
    user_id: UUID,
    request: CreateUserApiKeyRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> IssuedApiKeyResponse:
    # CRED-1 · the same ceiling applies to an operator-issued key. An
    # admin who set a 7-day policy and then minted a never-expiring key
    # for someone has not made an exception, they have made a mistake —
    # the exception mechanism is a per-user policy, which is visible.
    resolved = resolve_max_ttl(db, tenant_id=operator.tenant_id, user_id=user_id)
    try:
        effective_expiry = enforce_requested_expiry(resolved, request.expires_at)
    except ApiKeyPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    try:
        row, issued = issue_user_api_key(
            db,
            tenant_id=operator.tenant_id,
            user_id=user_id,
            label=request.label,
            expires_at=effective_expiry,
            actor=AdminAuditActor.operator(operator),
        )
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="user not found"
        ) from exc
    except DuplicateApiKeyLabelError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="api key with this label already exists for user",
        ) from exc
    return IssuedApiKeyResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        user_id=row.user_id,
        label=row.label,
        key_prefix=row.key_prefix,
        plaintext=issued.plaintext,
        created_at=row.created_at,
        expires_at=row.expires_at,
    )


@router.get(
    "/users/{user_id}/api-keys",
    response_model=list[UserApiKeySummaryResponse],
)
def list_user_api_keys_endpoint(
    user_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> list[UserApiKeySummaryResponse]:
    return [
        UserApiKeySummaryResponse.model_validate(k)
        for k in list_user_api_keys(db, tenant_id=operator.tenant_id, user_id=user_id)
    ]


@router.delete(
    "/users/{user_id}/api-keys/{key_id}",
    response_model=UserApiKeySummaryResponse,
)
def revoke_user_api_key_endpoint(
    user_id: UUID,
    key_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> UserApiKeySummaryResponse:
    try:
        row = revoke_user_api_key(
            db,
            tenant_id=operator.tenant_id,
            user_id=user_id,
            key_id=key_id,
            actor=AdminAuditActor.operator(operator),
        )
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="api key not found"
        ) from exc
    return UserApiKeySummaryResponse.model_validate(row)


# --- Groups ---------------------------------------------------------------


@router.post(
    "/groups",
    response_model=GroupResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_group_endpoint(
    request: CreateGroupRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> GroupResponse:
    try:
        group = create_group(
            db,
            tenant_id=operator.tenant_id,
            name=request.name,
            description=request.description,
            created_by=operator.operator_id,
            actor=AdminAuditActor.operator(operator),
        )
    except DuplicateGroupNameError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="group with this name already exists in tenant",
        ) from exc
    return GroupResponse.model_validate(group)


@router.get("/groups", response_model=list[GroupListItemResponse])
def list_groups_endpoint(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> list[GroupListItemResponse]:
    """List groups with the per-row aggregates the admin console
    table renders (member count + vserver-grant count). Single SQL,
    no N+1."""

    items = list_groups_with_aggregates(db, tenant_id=operator.tenant_id)
    return [
        GroupListItemResponse(
            id=item.group.id,
            tenant_id=item.group.tenant_id,
            name=item.group.name,
            description=item.group.description,
            created_by=item.group.created_by,
            created_at=item.group.created_at,
            member_count=item.member_count,
            vserver_grant_count=item.vserver_grant_count,
        )
        for item in items
    ]


@router.get(
    "/groups/{group_id}/members",
    response_model=list[UserResponse],
)
def list_group_members_endpoint(
    group_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> list[UserResponse]:
    try:
        members = list_group_members(
            db, tenant_id=operator.tenant_id, group_id=group_id
        )
    except GroupNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="group not found"
        ) from exc
    return [UserResponse.model_validate(u) for u in members]


@router.post(
    "/groups/{group_id}/members",
    status_code=status.HTTP_204_NO_CONTENT,
)
def add_group_member_endpoint(
    group_id: UUID,
    request: AddGroupMemberRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> None:
    try:
        add_group_member(
            db,
            tenant_id=operator.tenant_id,
            group_id=group_id,
            user_id=request.user_id,
            added_by=operator.operator_id,
            actor=AdminAuditActor.operator(operator),
        )
    except (GroupNotFoundError, UserNotFoundError) as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="group or user not found"
        ) from exc


@router.delete(
    "/groups/{group_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_group_member_endpoint(
    group_id: UUID,
    user_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> None:
    try:
        remove_group_member(
            db,
            tenant_id=operator.tenant_id,
            group_id=group_id,
            user_id=user_id,
            actor=AdminAuditActor.operator(operator),
        )
    except (GroupNotFoundError, UserNotFoundError) as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="group or user not found"
        ) from exc


# --- Vserver visibility + grants -----------------------------------------


@router.patch(
    "/vservers/{vserver_id}/visibility",
    status_code=status.HTTP_200_OK,
)
def set_vserver_visibility_endpoint(
    vserver_id: UUID,
    request: SetVisibilityRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> dict[str, str]:
    try:
        vserver = set_vserver_visibility(
            db,
            tenant_id=operator.tenant_id,
            vserver_id=vserver_id,
            visibility=request.visibility,
            actor=AdminAuditActor.operator(operator),
        )
    except GrantTargetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="virtual server not found"
        ) from exc
    # `.visibility` is typed as the enum but SQLAlchemy round-trips it
    # as a plain str. Coerce defensively for the wire format.
    visibility_value = (
        vserver.visibility.value
        if hasattr(vserver.visibility, "value")
        else str(vserver.visibility)
    )
    return {"id": str(vserver.id), "visibility": visibility_value}


@router.post(
    "/vservers/{vserver_id}/grants",
    response_model=GrantResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_grant_endpoint(
    vserver_id: UUID,
    request: CreateGrantRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> GrantResponse:
    try:
        grant = issue_grant(
            db,
            tenant_id=operator.tenant_id,
            vserver_id=vserver_id,
            principal_kind=request.principal_kind,
            principal_id=request.principal_id,
            granted_by=operator.operator_id,
            expires_at=request.expires_at,
            actor=AdminAuditActor.operator(operator),
        )
    except GrantTargetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="virtual server or grant target not found",
        ) from exc
    except UserNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="grant target user not found"
        ) from exc
    except GroupNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="grant target group not found"
        ) from exc
    return GrantResponse.model_validate(grant)


@router.get(
    "/vservers/{vserver_id}/grants",
    response_model=list[GrantResponse],
)
def list_grants_endpoint(
    vserver_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> list[GrantResponse]:
    return [
        GrantResponse.model_validate(g)
        for g in list_grants(db, tenant_id=operator.tenant_id, vserver_id=vserver_id)
    ]


@router.delete(
    "/vservers/{vserver_id}/grants/{grant_id}",
    response_model=GrantResponse,
)
def revoke_grant_endpoint(
    vserver_id: UUID,
    grant_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> GrantResponse:
    try:
        grant = revoke_grant(
            db,
            tenant_id=operator.tenant_id,
            vserver_id=vserver_id,
            grant_id=grant_id,
            actor=AdminAuditActor.operator(operator),
        )
    except GrantTargetNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="grant not found"
        ) from exc
    return GrantResponse.model_validate(grant)
