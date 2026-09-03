"""RISK-1 · operator API for risk classification.

Transport only. The judgement lives in `risk/`; this decides status
codes and what the console is allowed to see.
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.audit.admin_audit import (
    AdminAuditActor,
    AdminAuditTarget,
    record_admin_action,
)
from vyuu_gateway.db.models import (
    McpServer,
    McpServerRiskAssessment,
    Tenant,
    VirtualServer,
)
from vyuu_gateway.operator_auth.dependency import (
    AuthenticatedOperator,
    authenticate_operator,
)
from vyuu_gateway.risk.providers import (
    DEFAULT_MODEL_ID,
    KNOWN_MODELS,
    RiskModelVendor,
)
from vyuu_gateway.risk.service import (
    EVIDENCE_BASIS,
    RiskServiceError,
    Staleness,
    assess_server,
    assess_vserver,
    latest_server_assessment,
    latest_vserver_assessment,
    preview_vserver_reduction,
    server_assessment_staleness,
    vserver_assessment_staleness,
)
from vyuu_gateway.risk.taxonomy import OWASP_MCP_TITLES, OwaspMcpRisk

router = APIRouter(prefix="/admin/risk", tags=["admin"])
server_router = APIRouter(prefix="/servers", tags=["servers"])
vserver_router = APIRouter(prefix="/vservers", tags=["vservers"])


# --- model configuration ---------------------------------------------------


class RiskModelOption(BaseModel):
    id: str
    vendor: RiskModelVendor
    label: str
    note: str


class RiskModelConfigResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    configured: bool
    model_id: str | None
    model_vendor: RiskModelVendor | None
    api_key_ref: str | None
    base_url: str | None
    options: list[RiskModelOption]
    default_model_id: str
    evidence_basis: str
    # Whether this deployment's secret store accepts writes from here.
    secret_backend: str = ""
    secret_writable: bool = False
    # Whether a key is actually resolvable under the configured ref —
    # distinct from `configured`, which only means a ref was typed. An
    # operator who set a ref and never stored the key had no way to tell
    # until an assessment failed.
    key_present: bool = False


class SetRiskModelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    model_id: str = Field(min_length=1, max_length=200)
    # Required for an id we do not know: the wire format cannot be
    # inferred from the string, and guessing wrong sends a tenant's tool
    # catalogue to the wrong endpoint.
    model_vendor: RiskModelVendor | None = None
    # A SecretStore ref. The endpoint refuses anything that looks like a
    # key, so a paste-in-the-wrong-box does not put a live credential in
    # the tenants table.
    api_key_ref: str = Field(min_length=1, max_length=1024)
    base_url: str | None = Field(default=None, max_length=1024)


def _config_response(
    tenant: Tenant, store: Any = None, key_present: bool = False
) -> RiskModelConfigResponse:
    return RiskModelConfigResponse(
        secret_backend=type(store).__name__ if store is not None else "",
        secret_writable=hasattr(store, "put"),
        key_present=key_present,
        configured=bool(tenant.risk_model_api_key_ref),
        model_id=tenant.risk_model_id,
        model_vendor=(
            RiskModelVendor(tenant.risk_model_vendor)
            if tenant.risk_model_vendor
            else None
        ),
        api_key_ref=tenant.risk_model_api_key_ref,
        base_url=tenant.risk_model_base_url,
        options=[
            RiskModelOption(id=m.id, vendor=m.vendor, label=m.label, note=m.note)
            for m in KNOWN_MODELS
        ],
        default_model_id=DEFAULT_MODEL_ID,
        evidence_basis=EVIDENCE_BASIS,
    )


async def _key_present(store: Any, tenant_id: UUID, ref: str | None) -> bool:
    """Whether a key actually resolves under the configured ref.

    Distinct from "a ref was typed". An operator who set a ref and never
    stored the key had no way to tell until an assessment failed, which
    is a bad place to learn it. The value is fetched and discarded — it
    is never returned or logged.
    """

    if not ref:
        return False
    try:
        return bool(await store.get_secret(tenant_id, ref))
    except Exception:  # noqa: BLE001 — absent, unreachable, or denied
        return False


@router.get("/model", response_model=RiskModelConfigResponse)
async def get_risk_model_endpoint(
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> RiskModelConfigResponse:
    tenant = db.get(Tenant, operator.tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    store = http_request.app.state.secret_store
    present = await _key_present(store, operator.tenant_id, tenant.risk_model_api_key_ref)
    return _config_response(tenant, store, present)


# Shapes of the major vendors' keys. Not a security control — it is a
# usability one, catching the common paste-the-key-not-the-ref mistake
# before a live credential lands in a table that gets dumped.
_KEY_PREFIXES = ("sk-", "sk-ant-", "AIza", "Bearer ")


@router.put("/model", response_model=RiskModelConfigResponse)
async def set_risk_model_endpoint(
    payload: SetRiskModelRequest,
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> RiskModelConfigResponse:
    ref = payload.api_key_ref.strip()
    if any(ref.startswith(p) for p in _KEY_PREFIXES) or len(ref) > 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "that looks like an API key, not a secret-store reference. "
                "Store the key in your secret store and enter its name here "
                "— this value is written to the tenants table."
            ),
        )
    from vyuu_gateway.risk.providers import RiskModelError, vendor_for

    try:
        vendor = vendor_for(payload.model_id, payload.model_vendor)
    except RiskModelError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    tenant = db.get(Tenant, operator.tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    tenant.risk_model_id = payload.model_id
    tenant.risk_model_vendor = vendor.value
    tenant.risk_model_api_key_ref = ref
    tenant.risk_model_base_url = (payload.base_url or "").strip() or None
    record_admin_action(
        db,
        tenant_id=operator.tenant_id,
        actor=AdminAuditActor.operator(operator),
        action="risk.model_set",
        detail={
            "model_id": payload.model_id,
            "vendor": vendor.value,
            "api_key_ref": ref,
            "base_url": tenant.risk_model_base_url,
        },
    )
    db.commit()
    db.refresh(tenant)
    store = http_request.app.state.secret_store
    present = await _key_present(store, operator.tenant_id, tenant.risk_model_api_key_ref)
    return _config_response(tenant, store, present)


# --- assessments -----------------------------------------------------------


class SetApiKeyValueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_key: str = Field(min_length=8, max_length=4096)


class ApiKeyWriteResponse(BaseModel):
    stored: bool
    ref: str
    backend: str


@router.post("/model/api-key", response_model=ApiKeyWriteResponse)
def set_risk_api_key_endpoint(
    payload: SetApiKeyValueRequest,
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> ApiKeyWriteResponse:
    """Write the key INTO the secret store, when the backend allows it.

    Only the in-memory store used by the lab supports writes. Vault, AWS
    Secrets Manager and Kubernetes are read-only through this interface
    deliberately: writing a secret belongs in the backend's own tooling,
    where it gets that system's access control, rotation and audit
    rather than this console's. Refusing is the correct behaviour there,
    so the refusal says exactly what to create instead of pretending.

    The value is never returned, never logged, and never written to the
    tenants table — that column holds the ref only.
    """

    tenant = db.get(Tenant, operator.tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    ref = (tenant.risk_model_api_key_ref or "").strip()
    if not ref:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="set a secret-store reference first, then store the key under it",
        )

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
    put(operator.tenant_id, ref, payload.api_key)
    record_admin_action(
        db,
        tenant_id=operator.tenant_id,
        actor=AdminAuditActor.operator(operator),
        action="risk.api_key_stored",
        # The ref and the backend. Never the value, and never a prefix
        # of it — a logged prefix plus a leak elsewhere is a whole key.
        detail={"ref": ref, "backend": backend},
    )
    db.commit()
    return ApiKeyWriteResponse(stored=True, ref=ref, backend=backend)


class AssessmentResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    id: UUID
    server_id: UUID
    model_id: str
    model_vendor: str
    summary: str
    confidence: str
    findings: list[dict[str, Any]]
    normalised: float
    band: str
    exposure: float
    severity_profile: float
    overall: float
    finding_count: int
    capability_count: int
    truncated: bool
    evidence_basis: str
    assessed_at: datetime
    # RISK-2 · whether this score still describes the tools that are
    # there now. A score with no freshness signal reads as current
    # forever, which is how a server could keep a "moderate" badge it
    # earned before it grew a `delete_*` tool.
    stale: bool = False
    stale_reason: str | None = None
    # "fingerprint" (exact) or "capability_count" (weaker — the row
    # predates fingerprinting). Surfaced so the console can say which.
    staleness_basis: str = "fingerprint"


def _assessment_response(
    row: McpServerRiskAssessment, staleness: Staleness | None = None
) -> AssessmentResponse:
    staleness = staleness or Staleness(stale=False)
    return AssessmentResponse(
        id=row.id, server_id=row.server_id, model_id=row.model_id,
        model_vendor=row.model_vendor, summary=row.summary,
        confidence=row.confidence, findings=list(row.findings or []),
        normalised=row.normalised, band=row.band, exposure=row.exposure,
        severity_profile=row.severity_profile, overall=row.overall,
        finding_count=row.finding_count, capability_count=row.capability_count,
        truncated=row.truncated, evidence_basis=row.evidence_basis,
        assessed_at=row.assessed_at,
        stale=staleness.stale, stale_reason=staleness.reason,
        staleness_basis=staleness.basis,
    )


@server_router.post("/{server_id}/risk-assessment", response_model=AssessmentResponse)
async def assess_server_endpoint(
    server_id: UUID,
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> AssessmentResponse:
    try:
        row = await assess_server(
            db,
            tenant_id=operator.tenant_id,
            server_id=server_id,
            secret_store=http_request.app.state.secret_store,
            assessed_by=operator.operator_id,
        )
    except RiskServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    record_admin_action(
        db,
        tenant_id=operator.tenant_id,
        actor=AdminAuditActor.operator(operator),
        action="risk.server_assessed",
        target=AdminAuditTarget(kind="mcp_server", id=server_id, display=None),
        detail={
            "model_id": row.model_id, "band": row.band,
            "normalised": row.normalised, "findings": row.finding_count,
        },
    )
    db.commit()
    return _assessment_response(row)


@server_router.get("/{server_id}/risk-assessment", response_model=AssessmentResponse)
def get_server_assessment_endpoint(
    server_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> AssessmentResponse:
    row = latest_server_assessment(
        db, tenant_id=operator.tenant_id, server_id=server_id
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="this server has not been assessed yet",
        )
    return _assessment_response(
        row,
        server_assessment_staleness(
            db, tenant_id=operator.tenant_id, server_id=server_id, assessment=row
        ),
    )


class VserverRiskResponse(BaseModel):
    vserver_id: UUID
    inherent_normalised: float
    inherent_band: str
    published_normalised: float
    published_band: str
    points_reduced: float
    percent_reduced: float
    # Positive means curation removed breadth but concentrated what was
    # left. Derived from the two stored bands, so no extra column.
    severity_profile_delta: float
    eliminated: list[dict[str, Any]]
    retained: list[dict[str, Any]]
    source_assessment_ids: list[str]
    # RISK-2 · a reduction claim is about a difference, and publishing
    # one more tool falsifies it. See `vserver_assessment_staleness`.
    stale: bool = False
    stale_reason: str | None = None
    staleness_basis: str = "fingerprint"
    unassessed_server_ids: list[str] = []
    evidence_basis: str
    computed_at: datetime


@vserver_router.post("/{vserver_id}/risk-assessment", response_model=VserverRiskResponse)
def assess_vserver_endpoint(
    vserver_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> VserverRiskResponse:
    try:
        result = assess_vserver(
            db, tenant_id=operator.tenant_id, vserver_id=vserver_id
        )
    except RiskServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    row = result.row
    return VserverRiskResponse(
        vserver_id=row.vserver_id,
        inherent_normalised=row.inherent_normalised,
        inherent_band=row.inherent_band,
        published_normalised=row.published_normalised,
        published_band=row.published_band,
        points_reduced=row.points_reduced,
        percent_reduced=row.percent_reduced,
        severity_profile_delta=round(
            row.published_normalised - row.inherent_normalised, 1),
        eliminated=list(row.eliminated or []),
        retained=list(row.retained or []),
        source_assessment_ids=[str(i) for i in (row.source_assessment_ids or [])],
        unassessed_server_ids=[str(i) for i in result.unassessed_server_ids],
        evidence_basis=EVIDENCE_BASIS,
        computed_at=row.computed_at,
    )


@vserver_router.get("/{vserver_id}/risk-assessment", response_model=VserverRiskResponse)
def get_vserver_assessment_endpoint(
    vserver_id: UUID,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> VserverRiskResponse:
    row = latest_vserver_assessment(
        db, tenant_id=operator.tenant_id, vserver_id=vserver_id
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="this bundle's risk has not been computed yet",
        )
    staleness = vserver_assessment_staleness(
        db, tenant_id=operator.tenant_id, vserver_id=vserver_id, assessment=row
    )
    return VserverRiskResponse(
        vserver_id=row.vserver_id,
        inherent_normalised=row.inherent_normalised,
        inherent_band=row.inherent_band,
        published_normalised=row.published_normalised,
        published_band=row.published_band,
        points_reduced=row.points_reduced,
        percent_reduced=row.percent_reduced,
        severity_profile_delta=round(
            row.published_normalised - row.inherent_normalised, 1),
        eliminated=list(row.eliminated or []),
        retained=list(row.retained or []),
        source_assessment_ids=[str(i) for i in (row.source_assessment_ids or [])],
        stale=staleness.stale,
        stale_reason=staleness.reason,
        staleness_basis=staleness.basis,
        evidence_basis=EVIDENCE_BASIS,
        computed_at=row.computed_at,
    )


class PreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tools: list[dict[str, str]] = Field(default_factory=list, max_length=500)


@router.post("/preview")
def preview_endpoint(
    payload: PreviewRequest,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> dict[str, Any]:
    """Risk of a tool selection BEFORE the bundle exists.

    The point of the feature: an operator should see what they are about
    to hand users while the selection is still editable.
    """

    pairs: list[tuple[UUID, str]] = []
    for entry in payload.tools:
        try:
            pairs.append((UUID(entry["server_id"]), entry["tool_name"]))
        except (KeyError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="each tool needs server_id and tool_name",
            ) from exc
    return preview_vserver_reduction(db, tenant_id=operator.tenant_id, tools=pairs)


# --- the CISO view ---------------------------------------------------------


@router.get("/summary")
def risk_summary_endpoint(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> dict[str, Any]:
    """Tenant-wide posture, for a reader who will not open a server row.

    Reports coverage as prominently as the scores. A "12.4 average risk"
    computed over the three servers that happen to have been assessed is
    a statement about those three, and presenting it as the estate's
    posture is the most likely way this feature misleads.
    """

    tenant_id = operator.tenant_id
    servers = list(
        db.scalars(select(McpServer).where(McpServer.tenant_id == tenant_id)).all()
    )
    assessed: list[McpServerRiskAssessment] = []
    staleness_by_server: dict[UUID, Staleness] = {}
    for server in servers:
        latest = latest_server_assessment(
            db, tenant_id=tenant_id, server_id=server.id
        )
        if latest is not None:
            assessed.append(latest)
            staleness_by_server[server.id] = server_assessment_staleness(
                db, tenant_id=tenant_id, server_id=server.id, assessment=latest
            )

    bands: dict[str, int] = {}
    owasp_counts: dict[str, int] = {}
    top: list[dict[str, Any]] = []
    names = {s.id: s.display_name for s in servers}
    stale_servers = 0
    for row in assessed:
        bands[row.band] = bands.get(row.band, 0) + 1
        for finding in row.findings or []:
            key = str(finding.get("owasp_mcp"))
            owasp_counts[key] = owasp_counts.get(key, 0) + 1
        staleness = staleness_by_server.get(row.server_id, Staleness(stale=False))
        if staleness.stale:
            stale_servers += 1
        top.append(
            {
                "server_id": str(row.server_id),
                "display_name": names.get(row.server_id, "?"),
                "normalised": row.normalised,
                "band": row.band,
                "finding_count": row.finding_count,
                "assessed_at": row.assessed_at.isoformat(),
                "stale": staleness.stale,
                "stale_reason": staleness.reason,
            }
        )
    top.sort(key=lambda r: r["normalised"], reverse=True)

    vservers = list(
        db.scalars(
            select(VirtualServer).where(VirtualServer.tenant_id == tenant_id)
        ).all()
    )
    reductions = []
    stale_bundles = 0
    for vserver in vservers:
        latest = latest_vserver_assessment(
            db, tenant_id=tenant_id, vserver_id=vserver.id
        )
        if latest is None:
            continue
        vserver_staleness = vserver_assessment_staleness(
            db, tenant_id=tenant_id, vserver_id=vserver.id, assessment=latest
        )
        if vserver_staleness.stale:
            stale_bundles += 1
        reductions.append(
            {
                "vserver_id": str(vserver.id),
                "name": vserver.name,
                "inherent_normalised": latest.inherent_normalised,
                "published_normalised": latest.published_normalised,
                "points_reduced": latest.points_reduced,
                "percent_reduced": latest.percent_reduced,
                "findings_eliminated": len(latest.eliminated or []),
                "stale": vserver_staleness.stale,
                "stale_reason": vserver_staleness.reason,
            }
        )
    reductions.sort(key=lambda r: r["points_reduced"], reverse=True)

    total_points = sum(r["points_reduced"] for r in reductions)
    return {
        "servers_total": len(servers),
        "servers_assessed": len(assessed),
        # Counted alongside coverage for the same reason coverage is
        # reported at all: an average over scores that no longer
        # describe the deployed tools is not this estate's posture.
        "servers_stale": stale_servers,
        "bundles_stale": stale_bundles,
        # Stated so the averages below can be read for what they are.
        "coverage_percent": (
            round(len(assessed) / len(servers) * 100, 1) if servers else 0.0
        ),
        "average_normalised": (
            round(sum(a.normalised for a in assessed) / len(assessed), 1)
            if assessed
            else 0.0
        ),
        "bands": bands,
        "owasp_counts": [
            {
                "id": key,
                "title": OWASP_MCP_TITLES.get(OwaspMcpRisk(key), key)
                if key in {r.value for r in OwaspMcpRisk}
                else key,
                "count": count,
            }
            for key, count in sorted(
                owasp_counts.items(), key=lambda kv: kv[1], reverse=True
            )
        ],
        "riskiest_servers": top[:10],
        "bundles_with_reduction": reductions[:10],
        "bundles_measured": len(reductions),
        "total_points_reduced": round(total_points, 1),
        "average_percent_reduced": (
            round(sum(r["percent_reduced"] for r in reductions) / len(reductions), 1)
            if reductions
            else 0.0
        ),
        "evidence_basis": EVIDENCE_BASIS,
    }


_ = math  # kept for future percentile work on the summary
