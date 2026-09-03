"""Operator login + admin-management endpoints.

Login flow:
- `POST /api/v1/operator-auth/login` — `(email, password)` → operator JWT.
  The JWT format and verification are unchanged from the existing
  bearer-token flow — this endpoint just adds a user-facing way to
  obtain one. Operator JWT shape: `<base64url(json)>.<base64url(hmac)>`,
  validated by `authenticate_operator` against
  `Settings.operator_auth_signing_secret`.

Admin management (operator JWT auth):
- `GET    /api/v1/admins`                         — list operators
- `POST   /api/v1/admins`                         — create new admin
- `POST   /api/v1/admins/{id}/password`           — reset password
- `DELETE /api/v1/admins/{id}`                    — disable
- `POST   /api/v1/operator-auth/password`         — self-rotate

Tenant scoping is implicit via the operator JWT — admins only see and
manage operators within their own tenant.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.audit.admin_audit import AdminAuditActor
from vyuu_gateway.db.models import OperatorRole
from vyuu_gateway.db.session import SessionLocal, bind_tenant_context
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator
from vyuu_gateway.operator_auth.password_auth import (
    DuplicateOperatorEmailError,
    OperatorLoginError,
    OperatorNotFoundError,
    authenticate_operator_with_password,
    create_operator,
    disable_operator,
    list_operators,
    reset_operator_password,
    rotate_my_operator_password,
)
from vyuu_gateway.siem.bridges import record_signin
from vyuu_gateway.siem.events import AuthMethod, AuthOutcome, AuthSurface
from vyuu_gateway.users.passwords import PasswordTooWeakError

router = APIRouter(tags=["operator-auth"])


# --- Schemas ---------------------------------------------------------------


class OperatorLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    tenant_id: UUID
    email: EmailStr
    password: Annotated[str, Field(min_length=1, max_length=512)]


class OperatorLoginResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bearer_token: str
    operator_id: UUID
    tenant_id: UUID
    email: str
    role: OperatorRole
    must_change_password: bool


class OperatorView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    email: str
    role: OperatorRole
    must_change_password: bool
    created_at: datetime
    last_login_at: datetime | None
    disabled_at: datetime | None


class CreateOperatorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    email: EmailStr
    role: OperatorRole = OperatorRole.ADMIN
    password: Annotated[str, Field(min_length=1, max_length=512)]
    must_change_password: bool = True


class ResetOperatorPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    new_password: Annotated[str, Field(min_length=1, max_length=512)]


class RotateOwnPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    current_password: Annotated[str, Field(min_length=1, max_length=512)]
    new_password: Annotated[str, Field(min_length=1, max_length=512)]


# --- Login -----------------------------------------------------------------


@router.post(
    "/operator-auth/login",
    response_model=OperatorLoginResponse,
)
def operator_login_endpoint(
    request: OperatorLoginRequest,
    http_request: Request,
) -> OperatorLoginResponse:
    """Email + password login for operators. Mints the same JWT the
    existing bearer-token flow uses; the operator console can keep
    paste-the-token mode as a fallback for automation."""

    settings = http_request.app.state.settings
    # We need a session bound to the *requested* tenant — the auth
    # dep doesn't apply (no bearer yet). Build one explicitly.
    with SessionLocal() as session:
        bind_tenant_context(session, request.tenant_id)
        try:
            operator, token = authenticate_operator_with_password(
                session,
                tenant_id=request.tenant_id,
                email=request.email,
                password=request.password,
                signing_secret=settings.operator_auth_signing_secret,
            )
        except OperatorLoginError as exc:
            record_signin(
                http_request,
                tenant_id=request.tenant_id,
                surface=AuthSurface.OPERATOR,
                method=AuthMethod.PASSWORD,
                outcome=AuthOutcome.FAILURE,
                subject=request.email.strip().lower(),
                reason="invalid credentials",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        record_signin(
            http_request,
            tenant_id=operator.tenant_id,
            surface=AuthSurface.OPERATOR,
            method=AuthMethod.PASSWORD,
            outcome=AuthOutcome.SUCCESS,
            subject=operator.email,
            subject_id=operator.id,
        )
        return OperatorLoginResponse(
            bearer_token=token,
            operator_id=operator.id,
            tenant_id=operator.tenant_id,
            email=operator.email,
            role=operator.role,
            must_change_password=operator.must_change_password,
        )


@router.post(
    "/operator-auth/password",
    response_model=OperatorView,
)
def rotate_own_password_endpoint(
    request: RotateOwnPasswordRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> OperatorView:
    """Self-rotate. Verifies current password before swapping — same
    posture as the end-user portal."""

    try:
        updated = rotate_my_operator_password(
            db,
            tenant_id=operator.tenant_id,
            operator_id=operator.operator_id,
            current_password=request.current_password,
            new_password=request.new_password,
        )
    except OperatorLoginError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="current password incorrect",
        ) from exc
    except PasswordTooWeakError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="new password does not meet minimum requirements",
        ) from exc
    except OperatorNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="operator not found",
        ) from exc
    return OperatorView.model_validate(updated)


# --- Admin management ------------------------------------------------------


@router.get("/admins", response_model=list[OperatorView])
def list_admins_endpoint(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> list[OperatorView]:
    return [
        OperatorView.model_validate(op)
        for op in list_operators(db, tenant_id=operator.tenant_id)
    ]


@router.post(
    "/admins",
    response_model=OperatorView,
    status_code=status.HTTP_201_CREATED,
)
def create_admin_endpoint(
    request: CreateOperatorRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> OperatorView:
    try:
        created = create_operator(
            db,
            tenant_id=operator.tenant_id,
            email=request.email,
            role=request.role.value,
            password=request.password,
            must_change_password=request.must_change_password,
            actor=AdminAuditActor.operator(operator),
        )
    except PasswordTooWeakError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="password does not meet minimum requirements",
        ) from exc
    except DuplicateOperatorEmailError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="operator with this email already exists in tenant",
        ) from exc
    return OperatorView.model_validate(created)


@router.post(
    "/admins/{operator_id}/password",
    response_model=OperatorView,
)
def reset_admin_password_endpoint(
    operator_id: UUID,
    request: ResetOperatorPasswordRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> OperatorView:
    try:
        updated = reset_operator_password(
            db,
            tenant_id=operator.tenant_id,
            operator_id=operator_id,
            new_password=request.new_password,
            actor=AdminAuditActor.operator(operator),
        )
    except PasswordTooWeakError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="password does not meet minimum requirements",
        ) from exc
    except OperatorNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="operator not found",
        ) from exc
    return OperatorView.model_validate(updated)


@router.delete(
    "/admins/{operator_id}",
    response_model=OperatorView,
)
def disable_admin_endpoint(
    operator_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> OperatorView:
    if operator_id == operator.operator_id:
        # Disabling yourself would lock the tenant out — make it explicit.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cannot disable yourself; ask another admin",
        )
    try:
        updated = disable_operator(
            db,
            tenant_id=operator.tenant_id,
            operator_id=operator_id,
            actor=AdminAuditActor.operator(operator),
        )
    except OperatorNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="operator not found",
        ) from exc
    return OperatorView.model_validate(updated)
