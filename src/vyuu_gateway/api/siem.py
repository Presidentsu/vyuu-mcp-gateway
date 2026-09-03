"""SIEM-1 · operator API for a tenant's own SIEM export target.

Scoped to the calling operator's tenant, like `tenant_settings.py`: no
tenant id in the path or body. Mirrors the risk-classifier config
surface deliberately — reference in the row, secret in the store, a
`token_present` probe so "a ref was typed" and "a token is stored" are
reported as the different states they are, and writes into the secret
store only where the backend allows it.

Every change is an admin action: `siem.config_set`, `siem.config_cleared`,
`siem.token_stored`. Changing where a tenant's audit trail is shipped is
exactly the kind of thing an auditor asks about later — and, being an
admin action itself, the change is shipped to the SIEM too, where the
old target sees the event that moved the stream away from it.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.audit.admin_audit import (
    AdminAuditActor,
    AdminAuditTarget,
    record_admin_action,
)
from vyuu_gateway.db.models import TenantSiemTarget
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator
from vyuu_gateway.siem.events import (
    CATEGORY_DESCRIPTIONS,
    DEFAULT_CATEGORIES,
    SELECTABLE_CATEGORIES,
    SiemCategory,
)
from vyuu_gateway.siem.hec import InvalidHecUrlError, normalise_hec_url

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/siem", tags=["siem"])

_LEVEL_NAMES = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class SiemCategoryOption(BaseModel):
    id: str
    label: str
    description: str
    default: bool


class SiemConfigResponse(BaseModel):
    configured: bool
    enabled: bool
    hec_url: str | None
    hec_token_ref: str | None
    index: str | None
    source: str
    host_override: str | None
    verify_tls: bool
    categories: list[str]
    include_raw_payloads: bool
    min_log_level: str
    batch_max_events: int
    flush_interval_seconds: float
    updated_at: datetime | None
    # Whether a token actually resolves under the ref — distinct from
    # `configured`, which only means a ref was typed.
    token_present: bool
    secret_backend: str
    secret_writable: bool
    # The gateway operator's own target, if any. Shown so a tenant admin
    # knows their events already reach a SIEM they do not control.
    deployment_target_configured: bool
    options: list[SiemCategoryOption]
    log_levels: list[str] = list(_LEVEL_NAMES)


class SetSiemConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    enabled: bool = True
    hec_url: str = Field(min_length=1, max_length=1024)
    # A SecretStore ref. The endpoint refuses anything shaped like a
    # HEC token, so a paste-in-the-wrong-box cannot land a live token in
    # the tenants table.
    hec_token_ref: str = Field(min_length=1, max_length=1024)
    index: str | None = Field(default=None, max_length=256)
    source: str = Field(default="vyuu-mcp-gateway", min_length=1, max_length=256)
    host_override: str | None = Field(default=None, max_length=256)
    verify_tls: bool = True
    categories: list[str] = Field(
        default_factory=lambda: sorted(c.value for c in DEFAULT_CATEGORIES)
    )
    include_raw_payloads: bool = False
    min_log_level: str = "WARNING"
    batch_max_events: int = Field(default=100, ge=1, le=1000)
    flush_interval_seconds: float = Field(default=2.0, ge=0.2, le=60.0)

    @field_validator("hec_url")
    @classmethod
    def _valid_url(cls, value: str) -> str:
        try:
            return normalise_hec_url(value)
        except InvalidHecUrlError as exc:
            raise ValueError(str(exc)) from None

    @field_validator("hec_token_ref")
    @classmethod
    def _ref_not_a_token(cls, value: str) -> str:
        candidate = value.strip()
        lowered = candidate.lower()
        if lowered.startswith("splunk "):
            raise ValueError("that is an Authorization header value, not a secret reference")
        try:
            UUID(candidate)
        except ValueError:
            return candidate
        # HEC tokens are GUIDs. A ref that parses as one almost certainly
        # IS the token.
        raise ValueError(
            "that looks like a HEC token itself — enter the NAME of the secret "
            "here, then store the token under it below"
        )

    @field_validator("categories")
    @classmethod
    def _known_categories(cls, value: list[str]) -> list[str]:
        allowed = {c.value for c in SELECTABLE_CATEGORIES}
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise ValueError(
                f"unknown categories {unknown}; choose from {sorted(allowed)}"
            )
        return sorted(set(value))

    @field_validator("min_log_level")
    @classmethod
    def _known_level(cls, value: str) -> str:
        upper = value.strip().upper()
        if upper not in _LEVEL_NAMES:
            raise ValueError(f"min_log_level must be one of {list(_LEVEL_NAMES)}")
        return upper


class SetTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hec_token: str = Field(min_length=8, max_length=4096)


class TokenWriteResponse(BaseModel):
    stored: bool
    ref: str
    backend: str


class SiemTestResponse(BaseModel):
    ok: bool
    detail: str


class SiemStatusResponse(BaseModel):
    configured: bool
    enabled: bool
    exporter_installed: bool
    deployment_target_configured: bool
    stats: dict[str, Any] | None


def _options() -> list[SiemCategoryOption]:
    return [
        SiemCategoryOption(
            id=c.value,
            label=c.value.replace("_", " "),
            description=CATEGORY_DESCRIPTIONS.get(c, ""),
            default=c in DEFAULT_CATEGORIES,
        )
        for c in SELECTABLE_CATEGORIES
    ]


def _exporter(http_request: Request) -> Any:
    return getattr(http_request.app.state, "siem_exporter", None)


async def _token_present(store: Any, tenant_id: UUID, ref: str | None) -> bool:
    """Fetched and discarded — never returned, never logged."""

    if not ref:
        return False
    try:
        return bool(await store.get_secret(tenant_id, ref))
    except Exception:  # noqa: BLE001 - absent, unreachable, or denied
        return False


async def _response(
    http_request: Request, tenant_id: UUID, row: TenantSiemTarget | None
) -> SiemConfigResponse:
    store = http_request.app.state.secret_store
    exporter = _exporter(http_request)
    deployment = bool(exporter and exporter.deployment_target_configured())
    if row is None:
        return SiemConfigResponse(
            configured=False,
            enabled=False,
            hec_url=None,
            hec_token_ref=None,
            index=None,
            source="vyuu-mcp-gateway",
            host_override=None,
            verify_tls=True,
            categories=sorted(c.value for c in DEFAULT_CATEGORIES),
            include_raw_payloads=False,
            min_log_level="WARNING",
            batch_max_events=100,
            flush_interval_seconds=2.0,
            updated_at=None,
            token_present=False,
            secret_backend=type(store).__name__,
            secret_writable=hasattr(store, "put"),
            deployment_target_configured=deployment,
            options=_options(),
        )
    return SiemConfigResponse(
        configured=True,
        enabled=bool(row.enabled),
        hec_url=row.hec_url,
        hec_token_ref=row.hec_token_ref,
        index=row.index,
        source=row.source,
        host_override=row.host_override,
        verify_tls=bool(row.verify_tls),
        categories=sorted(str(c) for c in (row.categories or [])),
        include_raw_payloads=bool(row.include_raw_payloads),
        min_log_level=row.min_log_level,
        batch_max_events=int(row.batch_max_events),
        flush_interval_seconds=float(row.flush_interval_seconds),
        updated_at=row.updated_at,
        token_present=await _token_present(store, tenant_id, row.hec_token_ref),
        secret_backend=type(store).__name__,
        secret_writable=hasattr(store, "put"),
        deployment_target_configured=deployment,
        options=_options(),
    )


def _load(db: Session, tenant_id: UUID) -> TenantSiemTarget | None:
    return db.scalar(
        select(TenantSiemTarget).where(TenantSiemTarget.tenant_id == tenant_id)
    )


@router.get("/config", response_model=SiemConfigResponse)
async def get_siem_config_endpoint(
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> SiemConfigResponse:
    return await _response(http_request, operator.tenant_id, _load(db, operator.tenant_id))


@router.put("/config", response_model=SiemConfigResponse)
async def set_siem_config_endpoint(
    payload: SetSiemConfigRequest,
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> SiemConfigResponse:
    """Create or replace this tenant's target. The row holds the ref;
    the token goes in through `/token`."""

    tenant_id = operator.tenant_id
    row = _load(db, tenant_id)
    before = _snapshot(row)
    now = datetime.now(UTC)
    if row is None:
        row = TenantSiemTarget(id=uuid4(), tenant_id=tenant_id, created_at=now)
        db.add(row)
    row.enabled = payload.enabled
    row.hec_url = payload.hec_url
    row.hec_token_ref = payload.hec_token_ref
    row.index = payload.index or None
    row.source = payload.source
    row.host_override = payload.host_override or None
    row.verify_tls = payload.verify_tls
    row.categories = list(payload.categories)
    row.include_raw_payloads = payload.include_raw_payloads
    row.min_log_level = payload.min_log_level
    row.batch_max_events = payload.batch_max_events
    row.flush_interval_seconds = payload.flush_interval_seconds
    row.updated_at = now
    after = _snapshot(row)
    record_admin_action(
        db,
        tenant_id=tenant_id,
        actor=AdminAuditActor.operator(operator),
        action="siem.config_set",
        target=AdminAuditTarget(kind="siem_target", id=row.id, display=row.hec_url),
        # Where the audit stream goes, before and after. Never the token.
        detail={"before": before, "after": after},
    )
    db.commit()
    db.refresh(row)
    exporter = _exporter(http_request)
    if exporter is not None:
        exporter.invalidate(tenant_id)
    return await _response(http_request, tenant_id, row)


@router.delete("/config", status_code=status.HTTP_204_NO_CONTENT)
def clear_siem_config_endpoint(
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> None:
    tenant_id = operator.tenant_id
    row = _load(db, tenant_id)
    if row is None:
        return
    before = _snapshot(row)
    db.delete(row)
    record_admin_action(
        db,
        tenant_id=tenant_id,
        actor=AdminAuditActor.operator(operator),
        action="siem.config_cleared",
        target=AdminAuditTarget(kind="siem_target", id=row.id, display=row.hec_url),
        detail={"before": before},
    )
    db.commit()
    exporter = _exporter(http_request)
    if exporter is not None:
        exporter.invalidate(tenant_id)


@router.post("/token", response_model=TokenWriteResponse)
def set_siem_token_endpoint(
    payload: SetTokenRequest,
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> TokenWriteResponse:
    """Write the HEC token INTO the secret store, where the backend
    allows it. Same policy as the risk classifier key: only the
    in-memory lab store accepts writes here; Vault / AWS / Kubernetes
    are read-only from this console on purpose, and the refusal names
    the secret to create instead."""

    row = _load(db, operator.tenant_id)
    if row is None or not row.hec_token_ref.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "save a target with a secret-store reference first, then store "
                "the token under it"
            ),
        )
    ref = row.hec_token_ref.strip()
    store = http_request.app.state.secret_store
    backend = type(store).__name__
    put = getattr(store, "put", None)
    if put is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"{backend} is read-only from here. Create the secret named "
                f"{ref!r} in that backend directly — it keeps its own access "
                f"control, rotation and audit, which is why this console does "
                f"not write into it."
            ),
        )
    put(operator.tenant_id, ref, payload.hec_token)
    record_admin_action(
        db,
        tenant_id=operator.tenant_id,
        actor=AdminAuditActor.operator(operator),
        action="siem.token_stored",
        target=AdminAuditTarget(kind="siem_target", id=row.id, display=row.hec_url),
        detail={"ref": ref, "backend": backend},
    )
    db.commit()
    exporter = _exporter(http_request)
    if exporter is not None:
        exporter.invalidate(operator.tenant_id)
    return TokenWriteResponse(stored=True, ref=ref, backend=backend)


@router.post("/test", response_model=SiemTestResponse)
async def test_siem_endpoint(
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
) -> SiemTestResponse:
    """Deliver one heartbeat now, bypassing the queue, and report what
    Splunk said. The only way to know a token and index are right."""

    exporter = _exporter(http_request)
    if exporter is None:
        return SiemTestResponse(ok=False, detail="SIEM export is not installed on this gateway")
    ok, detail = await exporter.send_test(operator.tenant_id)
    return SiemTestResponse(ok=ok, detail=detail)


@router.get("/status", response_model=SiemStatusResponse)
def siem_status_endpoint(
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> SiemStatusResponse:
    row = _load(db, operator.tenant_id)
    exporter = _exporter(http_request)
    stats = None
    if exporter is not None:
        target_stats = exporter.stats_for(operator.tenant_id)
        stats = target_stats.to_json() if target_stats is not None else None
    return SiemStatusResponse(
        configured=row is not None,
        enabled=bool(row.enabled) if row is not None else False,
        exporter_installed=exporter is not None,
        deployment_target_configured=bool(
            exporter and exporter.deployment_target_configured()
        ),
        stats=stats,
    )


def _snapshot(row: TenantSiemTarget | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "enabled": bool(row.enabled),
        "hec_url": row.hec_url,
        "hec_token_ref": row.hec_token_ref,
        "index": row.index,
        "categories": sorted(str(c) for c in (row.categories or [])),
        "include_raw_payloads": bool(row.include_raw_payloads),
        "min_log_level": row.min_log_level,
        "verify_tls": bool(row.verify_tls),
    }


__all__ = ["SiemCategory", "router"]
