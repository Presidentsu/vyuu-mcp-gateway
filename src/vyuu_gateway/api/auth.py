"""Login + OIDC callback endpoints.

POST `/auth/login`              — local-password login → session JWT
GET  `/auth/oidc/{provider}`    — initiate (returns redirect URL + state)
POST `/auth/oidc/{provider}/callback`
                                — exchange code → JIT-provision → session JWT

The session JWT goes in the response body for SPA consumption. A future
γ/δ enhancement could ALSO set an HTTP-only cookie for browser flows;
v1 keeps it body-only so the same routes work for both.

All endpoints take `tenant_id` from a **path parameter** (`/auth/{tenant_id}/login`).
The gateway is multi-tenant — without the path scoping, an attacker
could probe whether an email exists across tenants. Operators front
this behind a path-rewriting reverse proxy in production so end users
hit `corp-name.vyuu.example/login` and the gateway sees `/auth/<corp-id>/login`.
"""

from __future__ import annotations

import secrets
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from vyuu_gateway.db.models import UserAuthMethod
from vyuu_gateway.db.session import SessionLocal, bind_tenant_context
from vyuu_gateway.registry.users_service import (
    WrongAuthMethodError,
    upsert_oidc_user,
)
from vyuu_gateway.siem.bridges import record_signin
from vyuu_gateway.siem.events import AuthMethod, AuthOutcome, AuthSurface
from vyuu_gateway.users.local_auth import (
    InvalidCredentialsError,
    authenticate_local_user,
)
from vyuu_gateway.users.oidc import OidcValidationError
from vyuu_gateway.users.oidc_providers import OidcProvider
from vyuu_gateway.users.sessions import issue_portal_session

router = APIRouter(prefix="/auth", tags=["auth"])


def _auth_method_str(value: object) -> str:
    """SQLAlchemy round-trips enum columns as plain strings; coerce."""
    return value.value if hasattr(value, "value") else str(value)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    email: EmailStr
    password: Annotated[str, Field(min_length=1, max_length=512)]


class LoginResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_token: str
    must_change_password: bool
    user_id: UUID
    email: str
    auth_method: str


class OidcInitiateResponse(BaseModel):
    """Returned by `GET /auth/oidc/{provider}` — front-end redirects the
    user's browser to `authorization_url` and stores `state` to validate
    on callback."""

    authorization_url: str
    state: str


class OidcCallbackRequest(BaseModel):
    """Body of `POST /auth/oidc/{provider}/callback`. The SPA forwards
    the IdP's `code` + the original `state` (echoed back by the IdP)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    code: Annotated[str, Field(min_length=1, max_length=4096)]
    state: Annotated[str, Field(min_length=1, max_length=512)]


@router.post(
    "/{tenant_id}/login",
    response_model=LoginResponse,
)
def local_login(
    tenant_id: UUID,
    request: LoginRequest,
    http_request: Request,
) -> LoginResponse:
    """Verify (email, password) against a local user; mint a session
    JWT on success. Generic error on any failure (wrong email, wrong
    password, OIDC user, disabled) — anti-enumeration."""

    settings = http_request.app.state.settings
    with SessionLocal() as session:
        bind_tenant_context(session, tenant_id)
        try:
            user = authenticate_local_user(
                session,
                tenant_id=tenant_id,
                email=request.email,
                password=request.password,
            )
        except InvalidCredentialsError as exc:
            record_signin(
                http_request,
                tenant_id=tenant_id,
                surface=AuthSurface.PORTAL,
                method=AuthMethod.PASSWORD,
                outcome=AuthOutcome.FAILURE,
                subject=request.email.strip().lower(),
                reason="invalid credentials",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid credentials",
            ) from exc
        record_signin(
            http_request,
            tenant_id=user.tenant_id,
            surface=AuthSurface.PORTAL,
            method=AuthMethod.PASSWORD,
            outcome=AuthOutcome.SUCCESS,
            subject=user.email,
            subject_id=user.id,
        )
        token = issue_portal_session(
            tenant_id=user.tenant_id,
            user_id=user.id,
            email=user.email,
            auth_method=_auth_method_str(user.auth_method),
            signing_secret=settings.portal_session_signing_secret,
            ttl_seconds=settings.portal_session_ttl_seconds,
        )
        return LoginResponse(
            session_token=token,
            must_change_password=user.must_change_password,
            user_id=user.id,
            email=user.email,
            auth_method=_auth_method_str(user.auth_method),
        )


@router.get(
    "/{tenant_id}/oidc/{provider_name}",
    response_model=OidcInitiateResponse,
)
def oidc_initiate(
    tenant_id: UUID,
    provider_name: str,
    http_request: Request,
) -> OidcInitiateResponse:
    """Build the IdP's `/authorize` URL. State carries the tenant_id +
    a random nonce so the callback can rebuild the same context (and
    rejects mismatches — basic CSRF defense)."""

    provider = _provider_for(http_request, provider_name)
    state = f"{tenant_id}.{secrets.token_urlsafe(24)}"
    nonce = secrets.token_urlsafe(16)
    url = provider.authorization_url(state=state, nonce=nonce)
    return OidcInitiateResponse(authorization_url=url, state=state)


@router.post(
    "/{tenant_id}/oidc/{provider_name}/callback",
    response_model=LoginResponse,
)
async def oidc_callback(
    tenant_id: UUID,
    provider_name: str,
    request: OidcCallbackRequest,
    http_request: Request,
) -> LoginResponse:
    """Exchange the IdP code, validate the ID token, JIT-provision
    the user, mint a session JWT."""

    settings = http_request.app.state.settings
    provider = _provider_for(http_request, provider_name)

    # Defense-in-depth: state must be prefixed with the tenant_id from
    # the path, so a callback bound to tenant A can't be replayed
    # against tenant B's URL.
    if not request.state.startswith(f"{tenant_id}."):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="state does not match tenant",
        )

    try:
        result = await provider.exchange_code_for_id_token(code=request.code)
    except OidcValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="OIDC validation failed"
        ) from exc

    auth_method = (
        UserAuthMethod.MICROSOFT
        if provider_name == "microsoft"
        else UserAuthMethod.GOOGLE
    )

    with SessionLocal() as session:
        bind_tenant_context(session, tenant_id)
        try:
            user = upsert_oidc_user(
                session,
                tenant_id=tenant_id,
                email=result.email,
                external_subject=result.subject,
                auth_method=auth_method,
                display_name=result.display_name,
            )
        except WrongAuthMethodError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="user exists with a different auth method",
            ) from exc

        token = issue_portal_session(
            tenant_id=user.tenant_id,
            user_id=user.id,
            email=user.email,
            auth_method=_auth_method_str(user.auth_method),
            signing_secret=settings.portal_session_signing_secret,
            ttl_seconds=settings.portal_session_ttl_seconds,
        )
        return LoginResponse(
            session_token=token,
            must_change_password=False,
            user_id=user.id,
            email=user.email,
            auth_method=_auth_method_str(user.auth_method),
        )


def _provider_for(http_request: Request, name: str) -> OidcProvider:
    """Resolve the configured OIDC provider by name. 404 if not wired."""

    providers: dict[str, OidcProvider] = getattr(
        http_request.app.state, "oidc_providers", {}
    )
    provider = providers.get(name)
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OIDC provider '{name}' not configured",
        )
    return provider


