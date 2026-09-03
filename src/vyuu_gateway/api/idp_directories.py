"""Operator-side endpoints for the connected-directories table.

Five routes mounted under `/api/v1/idp/directories`:

- `POST   /idp/directories`           — connect a new directory + mint
                                        the SCIM bearer (returned ONCE).
- `GET    /idp/directories`           — list connected directories.
- `GET    /idp/directories/{id}`      — read one.
- `DELETE /idp/directories/{id}`      — disconnect (idempotent).

The mint-once semantic on POST mirrors how API-key issuance works
elsewhere in the codebase — the plaintext is shown only at issuance,
the hash is what survives. If an admin loses the bearer they
disconnect + reconnect to mint a fresh one.

Tenant scoping comes from the operator JWT, never from the request
body. Both DB-side RLS and explicit tenant filters defend the boundary.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.audit.admin_audit import AdminAuditActor
from vyuu_gateway.idp.schemas import (
    ConfigureEmaRequest,
    ConfigureWorkspacePollingRequest,
    ConnectIdpDirectoryRequest,
    IdpDirectoryConnectedResponse,
    IdpDirectoryResponse,
)
from vyuu_gateway.idp.service import (
    DuplicateIdpDirectoryError,
    IdpDirectoryNotFoundError,
    WorkspacePollingConfigError,
    configure_directory_ema,
    configure_workspace_polling,
    connect_idp_directory,
    disconnect_idp_directory,
    get_idp_directory,
    list_idp_directories,
)
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator

router = APIRouter(prefix="/idp/directories", tags=["idp"])


def _scim_endpoint_url(request: Request, directory_id: UUID) -> str:
    """Build the SCIM endpoint URL the admin pastes into Entra /
    Workspace's "Provisioning" config. Trailing slashes vary per IdP
    so we omit it; both Entra and Workspace tolerate either form."""

    base = str(request.base_url).rstrip("/")
    return f"{base}/scim/v2/{directory_id}"


def _to_response(
    directory: object, request: Request
) -> IdpDirectoryResponse:
    return IdpDirectoryResponse(
        id=directory.id,
        tenant_id=directory.tenant_id,
        kind=directory.kind,
        display_name=directory.display_name,
        signin_protocol=directory.signin_protocol,
        oidc_issuer=directory.oidc_issuer,
        oidc_client_id=directory.oidc_client_id,
        saml_entity_id=directory.saml_entity_id,
        saml_sso_url=directory.saml_sso_url,
        metadata=directory.metadata_json,
        last_sync_at=directory.last_sync_at,
        created_at=directory.created_at,
        scim_endpoint_url=_scim_endpoint_url(request, directory.id),
        ema_enabled=bool(getattr(directory, "ema_enabled", False)),
        workspace_polling_enabled=bool(
            getattr(directory, "workspace_polling_enabled", False)
        ),
        workspace_customer_id=getattr(directory, "workspace_customer_id", None),
        workspace_admin_subject=getattr(directory, "workspace_admin_subject", None),
        workspace_service_account_ref=getattr(
            directory, "workspace_service_account_ref", None
        ),
        workspace_last_polled_at=getattr(
            directory, "workspace_last_polled_at", None
        ),
        ema_audience=getattr(directory, "ema_audience", None),
        ema_jwks_uri=getattr(directory, "ema_jwks_uri", None),
        ema_allowed_client_ids=list(
            getattr(directory, "ema_allowed_client_ids", None) or []
        ),
    )


@router.post(
    "",
    response_model=IdpDirectoryConnectedResponse,
    status_code=status.HTTP_201_CREATED,
)
def connect_directory_endpoint(
    request_body: ConnectIdpDirectoryRequest,
    request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> IdpDirectoryConnectedResponse:
    """Connect a new Entra / Workspace directory. The response carries
    the SCIM bearer plaintext exactly once — the admin pastes it into
    the IdP's "Provisioning" config alongside the SCIM endpoint URL."""

    try:
        directory, issued = connect_idp_directory(
            db,
            tenant_id=operator.tenant_id,
            request=request_body,
            actor=AdminAuditActor.operator(operator),
        )
    except DuplicateIdpDirectoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"a directory of kind '{request_body.kind.value}' is already "
                "connected to this tenant; disconnect it first to re-pair"
            ),
        ) from exc
    return IdpDirectoryConnectedResponse(
        directory=_to_response(directory, request),
        scim_token_plaintext=issued.plaintext,
    )


@router.get("", response_model=list[IdpDirectoryResponse])
def list_directories_endpoint(
    request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> list[IdpDirectoryResponse]:
    return [
        _to_response(d, request)
        for d in list_idp_directories(db, tenant_id=operator.tenant_id)
    ]


@router.get("/{directory_id}", response_model=IdpDirectoryResponse)
def get_directory_endpoint(
    directory_id: UUID,
    request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> IdpDirectoryResponse:
    try:
        directory = get_idp_directory(
            db, tenant_id=operator.tenant_id, directory_id=directory_id
        )
    except IdpDirectoryNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="directory not found",
        ) from exc
    return _to_response(directory, request)


@router.delete(
    "/{directory_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def disconnect_directory_endpoint(
    directory_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> None:
    try:
        disconnect_idp_directory(
            db,
            tenant_id=operator.tenant_id,
            directory_id=directory_id,
            actor=AdminAuditActor.operator(operator),
        )
    except IdpDirectoryNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="directory not found",
        ) from exc


@router.patch(
    "/{directory_id}/ema",
    response_model=IdpDirectoryResponse,
)
def configure_directory_ema_endpoint(
    directory_id: UUID,
    payload: ConfigureEmaRequest,
    request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> IdpDirectoryResponse:
    """Enable / disable MCP Enterprise-Managed Authorization for one
    directory, and set the audience + client allowlist the token
    endpoint enforces.

    Enabling makes the gateway honour ID-JAG grants from this
    directory's issuer. Disabling revokes every outstanding EMA token
    for it immediately — the inbound hot path re-checks this flag on
    every call. Audited either way.

    A directory with no `oidc_issuer` cannot be EMA-enabled: the issuer
    is what binds an incoming grant to this trust anchor.
    """

    if payload.enabled:
        directory = get_idp_directory(
            db, tenant_id=operator.tenant_id, directory_id=directory_id
        )
        if not directory.oidc_issuer:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "directory has no oidc_issuer; EMA needs an issuer to "
                    "anchor ID-JAG validation against"
                ),
            )

    # Default the audience to the canonical per-tenant resource-AS
    # issuer — the exact value our own RFC 9728 metadata advertises and
    # that the token endpoint checks the ID-JAG `aud` against. Making
    # the operator retype it would only invite a mismatch; an explicit
    # value still wins for IdPs that need a different identifier.
    audience = payload.audience or (
        f"{request.app.state.settings.public_base_url.rstrip('/')}"
        f"/v/{operator.tenant_id}"
        if payload.enabled
        else ""
    )
    directory = configure_directory_ema(
        db,
        tenant_id=operator.tenant_id,
        directory_id=directory_id,
        enabled=payload.enabled,
        audience=audience,
        jwks_uri=payload.jwks_uri,
        allowed_client_ids=payload.allowed_client_ids,
        actor=AdminAuditActor.operator(operator),
    )
    return _to_response(directory, request)


@router.patch(
    "/{directory_id}/workspace-polling",
    response_model=IdpDirectoryResponse,
)
def configure_workspace_polling_endpoint(
    directory_id: UUID,
    payload: ConfigureWorkspacePollingRequest,
    request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> IdpDirectoryResponse:
    """IDP-2 · enable / disable Google Workspace directory polling.

    Workspace **custom SAML apps cannot SCIM-push** — auto-provisioning
    is reserved for apps in Google's own catalog. Without polling, a
    Workspace directory runs on JIT-create at first sign-in with
    **manual deprovisioning**: someone terminated in HR keeps working
    access until an operator notices. That absence is completely silent,
    which is why this is worth a visible control rather than an env var.

    Audited both ways, with the deprovisioning consequence recorded in
    the audit detail.
    """

    try:
        directory = configure_workspace_polling(
            db,
            tenant_id=operator.tenant_id,
            directory_id=directory_id,
            enabled=payload.enabled,
            customer_id=payload.customer_id,
            admin_subject=payload.admin_subject,
            service_account_ref=payload.service_account_ref,
            actor=AdminAuditActor.operator(operator),
        )
        db.commit()
    except IdpDirectoryNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="directory not found"
        ) from exc
    except WorkspacePollingConfigError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    db.refresh(directory)
    return _to_response(directory, request)
