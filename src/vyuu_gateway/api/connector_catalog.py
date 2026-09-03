"""Operator-facing read-only API for the SaaS connector catalog.

The operator console's "Quick add from catalog" card grid (in the MCP
servers tab) calls `GET /api/v1/operator/connector-catalog` to render
its cards. Clicking a card pre-fills the existing register-server
wizard — there is no separate install endpoint; the wizard still
POSTs to `/api/v1/servers` like any other registration.

Read-only; no DB writes; no per-tenant state. Authenticated under the
same operator-bearer dependency as the rest of the operator API for
consistency, even though the catalog itself is global.
"""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator
from vyuu_gateway.upstream.connector_catalog import (
    ConnectorTemplate,
    get_catalog,
)

router = APIRouter(prefix="/operator", tags=["operator-connector-catalog"])


class ConnectorTemplateResponse(BaseModel):
    """Wire shape of one catalog entry. Mirrors `ConnectorTemplate`
    but lives here so the API contract is independent of internal
    dataclass changes."""

    key: str
    display_name: str
    vendor: str
    tagline: str
    runtime: str
    default_source: str
    default_transport: str
    oauth_authcode: dict[str, Any]
    extra_field_hints: list[str]
    docs_url: str | None
    status: str
    dcr_enabled: bool


class ConnectorCatalogResponse(BaseModel):
    """Paged-style envelope so we can add cursor/filter later
    without breaking the wire shape."""

    items: list[ConnectorTemplateResponse]
    total: int


def _to_response(t: ConnectorTemplate) -> ConnectorTemplateResponse:
    return ConnectorTemplateResponse(
        key=t.key,
        display_name=t.display_name,
        vendor=t.vendor,
        tagline=t.tagline,
        runtime=t.runtime,
        default_source=t.default_source,
        default_transport=t.default_transport,
        oauth_authcode=dict(t.oauth_authcode),
        extra_field_hints=list(t.extra_field_hints),
        docs_url=t.docs_url,
        status=t.status,
        dcr_enabled=t.dcr_enabled,
    )


@router.get("/connector-catalog", response_model=ConnectorCatalogResponse)
def list_connector_catalog(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
) -> ConnectorCatalogResponse:
    """Return the full SaaS connector catalog. Operator-bearer scoped."""
    del operator  # auth-only; catalog itself is global
    items = [_to_response(t) for t in get_catalog()]
    return ConnectorCatalogResponse(items=items, total=len(items))
