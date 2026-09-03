"""IDP-3 · operator API for a tenant's own settings.

Right now that means one thing: the subdomain slug that lets
`acme.gateway.example.com` land Acme's users on Acme's login page without
anyone pasting a UUID.

Scoped to the *calling operator's own tenant* — there is no tenant_id in
the path, and none is accepted from the body. An operator administers
their tenant; cross-tenant administration is not a thing this API does.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.api.tenant_routing import (
    InvalidTenantSlugError,
    set_tenant_slug,
)
from vyuu_gateway.audit.admin_audit import (
    AdminAuditActor,
    AdminAuditTarget,
    record_admin_action,
)
from vyuu_gateway.db.models import Tenant
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/tenant", tags=["tenant"])


class TenantSettingsResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    name: str
    slug: str | None
    # The full hostname this slug produces, or None when the deployment
    # has no base domain configured. Served rather than assembled in the
    # UI so the console cannot show a URL the gateway would not honour.
    portal_url: str | None = None


class SetTenantSlugRequest(BaseModel):
    """`slug: null` clears it, reverting this tenant to the UUID path."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    slug: str | None = Field(default=None, max_length=63)


def _portal_url(request: Request, slug: str | None) -> str | None:
    base = getattr(request.app.state.settings, "portal_base_domain", None)
    if not base or not slug:
        return None
    return f"https://{slug}.{base}/portal/"


@router.get("/settings", response_model=TenantSettingsResponse)
def get_tenant_settings_endpoint(
    request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> TenantSettingsResponse:
    tenant = db.get(Tenant, operator.tenant_id)
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found"
        )
    return TenantSettingsResponse(
        tenant_id=str(tenant.id),
        name=tenant.name,
        slug=tenant.slug,
        portal_url=_portal_url(request, tenant.slug),
    )


@router.patch("/settings/slug", response_model=TenantSettingsResponse)
def set_tenant_slug_endpoint(
    request: Request,
    payload: SetTenantSlugRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> TenantSettingsResponse:
    """Claim, change, or clear this tenant's subdomain slug.

    Audited both ways: changing it silently breaks every bookmark and
    every IdP redirect URI pointing at the old hostname, which is exactly
    the kind of change someone will need to reconstruct later.
    """

    tenant = db.get(Tenant, operator.tenant_id)
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found"
        )
    before = tenant.slug
    try:
        tenant = set_tenant_slug(db, tenant_id=operator.tenant_id, slug=payload.slug)
    except InvalidTenantSlugError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    record_admin_action(
        db,
        tenant_id=operator.tenant_id,
        actor=AdminAuditActor.operator(operator),
        action="tenant.slug_set" if tenant.slug else "tenant.slug_clear",
        target=AdminAuditTarget(kind="tenant", id=tenant.id, display=tenant.name),
        detail={
            "before": before,
            "after": tenant.slug,
            # The operational consequence, spelled out: whoever reads this
            # row later is probably asking why a bookmark stopped working.
            "invalidates_bookmarks_and_idp_redirect_uris": before is not None
            and before != tenant.slug,
        },
    )
    db.commit()
    db.refresh(tenant)
    return TenantSettingsResponse(
        tenant_id=str(tenant.id),
        name=tenant.name,
        slug=tenant.slug,
        portal_url=_portal_url(request, tenant.slug),
    )
