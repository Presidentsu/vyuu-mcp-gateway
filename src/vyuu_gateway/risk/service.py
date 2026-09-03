"""RISK-1 · running assessments and persisting them.

Ties together the tenant's model choice, the capability surface already
in the database, the classifier, and the reduction arithmetic.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import (
    McpCapability,
    McpServer,
    McpServerRiskAssessment,
    Tenant,
    VirtualServer,
    VirtualServerRiskAssessment,
    VirtualServerTool,
)
from vyuu_gateway.risk.classifier import (
    RESPONSE_SCHEMA,
    SYSTEM_PROMPT,
    Assessment,
    CapabilitySurface,
    ClassifierOutputError,
    Finding,
    build_assessment_payload,
    parse_assessment,
)
from vyuu_gateway.risk.providers import (
    DEFAULT_MODEL_ID,
    RiskModelConfig,
    RiskModelError,
    RiskModelVendor,
    classify_json,
    vendor_for,
)
from vyuu_gateway.risk.reduction import compute_reduction
from vyuu_gateway.risk.taxonomy import (
    McpThreatCategory,
    OwaspMcpRisk,
    RiskFactors,
    aggregate,
)

logger = logging.getLogger(__name__)

# Bumped when the band formula changes: rows written under an older
# version carry a `normalised` that today's thresholds do not describe.
# v2 blends the worst finding into the band; v1 used Rrms alone.
SCORING_VERSION = "2"

# Tools per model call.
#
# A 141-tool CrowdStrike catalogue reliably exhausted the output budget
# mid-generation, and Anthropic returns a PARTIAL tool input when that
# happens — valid JSON with an incomplete `findings`, which reads as a
# schema bug rather than a truncation. Raising the cap moved the
# threshold without removing it: findings scale with the catalogue, so
# there is always a catalogue big enough to break a single call.
#
# Chunking bounds the output per call instead. The cost is that the
# model sees one slice at a time and can miss a risk that only exists in
# the combination of two distant tools — a real loss, accepted because
# the alternative is no assessment at all for exactly the large,
# sprawling servers that most need one.
MAX_TOOLS_PER_CALL = 40

# Repeated on every stored assessment. The limitation travels with the
# number, because a score read six months later without it will be read
# as more than it is.
EVIDENCE_BASIS = (
    "Assessed from the server's PUBLIC SURFACE only — tool names, "
    "descriptions and input schemas as returned by capability sync. No "
    "source code was analysed. This is the same surface an attacking "
    "LLM sees, so it is well suited to tool-poisoning, prompt and "
    "over-sharing classes, and nearly blind to implementation flaws a "
    "description does not advertise."
)


class RiskServiceError(Exception):
    """Operator-facing failure."""


@dataclass(frozen=True)
class ResolvedModel:
    config: RiskModelConfig
    model_id: str
    vendor: RiskModelVendor


async def resolve_model(
    db: Session, *, tenant_id: UUID, secret_store: Any
) -> ResolvedModel:
    """The tenant's configured classifier, with its key resolved.

    Raises rather than falling back to some default vendor: sending a
    tenant's tool catalogue to an LLM nobody chose is not a sane
    recovery from a missing setting.
    """

    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise RiskServiceError("tenant not found")
    key_ref = (tenant.risk_model_api_key_ref or "").strip()
    if not key_ref:
        raise RiskServiceError(
            "no risk-classifier API key configured — set one on the "
            "Risk classifier settings page before running an assessment"
        )
    model_id = (tenant.risk_model_id or DEFAULT_MODEL_ID).strip()
    declared = (
        RiskModelVendor(tenant.risk_model_vendor)
        if tenant.risk_model_vendor
        else None
    )
    try:
        vendor = vendor_for(model_id, declared)
    except RiskModelError as exc:
        raise RiskServiceError(str(exc)) from exc
    try:
        api_key = await secret_store.get_secret(tenant_id, key_ref)
    except Exception as exc:  # noqa: BLE001 — surfaced to the operator
        raise RiskServiceError(
            f"could not resolve API key ref {key_ref!r} from the secret "
            f"store ({exc.__class__.__name__})"
        ) from exc
    return ResolvedModel(
        config=RiskModelConfig(
            model_id=model_id,
            vendor=vendor,
            api_key=api_key,
            base_url=(tenant.risk_model_base_url or None),
        ),
        model_id=model_id,
        vendor=vendor,
    )


def capability_fingerprint(capabilities: Sequence[CapabilitySurface]) -> str:
    """Stable hash of the tool surface a score was computed against.

    Covers name, kind, description and input schema — not just the
    count. An upstream that rewrites a tool's description or widens its
    input schema in place changes what that tool can be talked into
    doing while every count stays identical, and that is exactly the
    change a risk score should not survive.

    Sorted before hashing: capability rows come back in whatever order
    the query planner likes, and an assessment must not read as stale
    because two equal sets were enumerated differently.
    """

    digest = hashlib.sha256()
    for item in sorted(
        capabilities, key=lambda c: (c.kind, c.name, c.description, c.input_schema)
    ):
        # Length-prefixed so ("ab", "c") and ("a", "bc") cannot collide.
        for part in (item.kind, item.name, item.description, item.input_schema):
            encoded = part.encode("utf-8")
            digest.update(str(len(encoded)).encode("ascii"))
            digest.update(b":")
            digest.update(encoded)
    return digest.hexdigest()


def _vserver_inputs_fingerprint(
    source_assessment_ids: Sequence[str], published_tools: Iterable[str]
) -> str:
    """Hash of both inputs to a reduction: sources read, tools published.

    A bundle's headline is a claim about a difference ("publishing 6 of
    190 tools removed this much risk"). Re-assessing an upstream or
    publishing one more tool falsifies it, and publishing one more tool
    is an everyday edit.
    """

    digest = hashlib.sha256()
    digest.update(b"sources:")
    for source_id in sorted(source_assessment_ids):
        digest.update(source_id.encode("utf-8"))
        digest.update(b",")
    digest.update(b"tools:")
    for tool in sorted(published_tools):
        encoded = tool.encode("utf-8")
        digest.update(str(len(encoded)).encode("ascii"))
        digest.update(b":")
        digest.update(encoded)
    return digest.hexdigest()


@dataclass(frozen=True)
class Staleness:
    """Whether a stored score still describes what is deployed now."""

    stale: bool
    # Operator-facing sentence. None when the score is current.
    reason: str | None = None
    # How the verdict was reached, so the console can be honest about a
    # weak check rather than presenting it as certainty.
    #   "fingerprint"      — exact: the assessed surface was compared
    #   "capability_count" — weak: pre-RISK-2 row, only counts compared
    basis: str = "fingerprint"


def _surface(db: Session, *, tenant_id: UUID, server_id: UUID) -> list[CapabilitySurface]:
    rows = list(
        db.scalars(
            select(McpCapability).where(
                McpCapability.tenant_id == tenant_id,
                McpCapability.server_id == server_id,
                McpCapability.deprecated.is_(False),
            )
        ).all()
    )
    out: list[CapabilitySurface] = []
    for row in rows:
        schema = row.schema_json or {}
        description = ""
        if isinstance(schema, dict):
            description = str(schema.get("description") or "")
        out.append(
            CapabilitySurface(
                kind=str(row.kind),
                name=row.name,
                description=description,
                input_schema=json.dumps(
                    schema.get("inputSchema") or schema.get("input_schema") or {}
                )
                if isinstance(schema, dict)
                else "{}",
            )
        )
    return out


async def assess_server(
    db: Session,
    *,
    tenant_id: UUID,
    server_id: UUID,
    secret_store: Any,
    assessed_by: UUID | None = None,
    http: Any = None,
) -> McpServerRiskAssessment:
    """Classify one MCP server and persist the result. Commits."""

    server = db.scalar(
        select(McpServer).where(
            McpServer.tenant_id == tenant_id, McpServer.id == server_id
        )
    )
    if server is None:
        raise RiskServiceError("server not found in tenant")

    capabilities = _surface(db, tenant_id=tenant_id, server_id=server_id)
    if not capabilities:
        raise RiskServiceError(
            "no synced capabilities to assess — run Sync on this server "
            "first. An empty surface would score zero, which reads as "
            "safe rather than unknown."
        )

    resolved = await resolve_model(db, tenant_id=tenant_id, secret_store=secret_store)

    chunks = [
        capabilities[i : i + MAX_TOOLS_PER_CALL]
        for i in range(0, len(capabilities), MAX_TOOLS_PER_CALL)
    ]
    all_findings: list[Finding] = []
    summaries: list[str] = []
    confidences: list[str] = []
    truncated = False
    for index, chunk in enumerate(chunks):
        payload = build_assessment_payload(
            display_name=server.display_name,
            runtime=str(server.source_type),
            source_location=server.source_location,
            capabilities=chunk,
        )
        if len(chunks) > 1:
            # Tell the model it is seeing a slice. Without this it
            # reports "the server exposes only 40 tools", which is false
            # and would be stored as the executive summary.
            payload["note"] = (
                f"This is part {index + 1} of {len(chunks)} of this "
                f"server's catalogue ({len(capabilities)} capabilities "
                f"total). Assess only what is shown."
            )
        truncated = truncated or bool(payload.get("truncated"))
        try:
            raw = await classify_json(
                resolved.config,
                system_prompt=SYSTEM_PROMPT,
                user_prompt=json.dumps(payload, indent=2),
                json_schema=RESPONSE_SCHEMA,
                http=http,
            )
            part = parse_assessment(raw)
        except (RiskModelError, ClassifierOutputError) as exc:
            # Never degrade to an empty or partial assessment. "No
            # findings" from a failure and "no findings" from a clean
            # server render identically, and the operator would publish
            # on the strength of a crash. One bad chunk fails the run.
            raise RiskServiceError(
                "classification failed"
                + (f" on part {index + 1} of {len(chunks)}" if len(chunks) > 1 else "")
                + f": {exc}"
            ) from exc
        all_findings.extend(part.findings)
        if part.summary:
            summaries.append(part.summary)
        confidences.append(part.confidence)

    # Lowest confidence across the parts, not the average: the run is
    # only as trustworthy as its least certain slice.
    order = {"low": 0, "medium": 1, "high": 2}
    confidence = min(confidences, key=lambda c: order.get(c, 0)) if confidences else "low"
    assessment = Assessment(
        summary=" ".join(summaries)[:2000],
        confidence=confidence,
        findings=all_findings,
        score=aggregate([f.risk for f in all_findings]),
    )

    row = McpServerRiskAssessment(
        id=uuid4(),
        tenant_id=tenant_id,
        server_id=server_id,
        model_id=resolved.model_id,
        model_vendor=resolved.vendor.value,
        summary=assessment.summary,
        confidence=assessment.confidence,
        findings=[f.to_json() for f in assessment.findings],
        exposure=assessment.score.exposure,
        severity_profile=assessment.score.severity_profile,
        overall=assessment.score.overall,
        normalised=assessment.score.normalised,
        band=assessment.score.band,
        finding_count=assessment.score.finding_count,
        capability_count=len(capabilities),
        capability_fingerprint=capability_fingerprint(capabilities),
        truncated=truncated,
        evidence_basis=EVIDENCE_BASIS,
        scoring_version=SCORING_VERSION,
        assessed_by=assessed_by,
        assessed_at=datetime.now(UTC),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    logger.info(
        "risk_assessment_completed",
        extra={
            "tenant_id": str(tenant_id),
            "server_id": str(server_id),
            "model": resolved.model_id,
            "band": row.band,
            "findings": row.finding_count,
        },
    )
    return row


def latest_server_assessment(
    db: Session, *, tenant_id: UUID, server_id: UUID
) -> McpServerRiskAssessment | None:
    return db.scalar(
        select(McpServerRiskAssessment)
        .where(
            McpServerRiskAssessment.tenant_id == tenant_id,
            McpServerRiskAssessment.server_id == server_id,
        )
        .order_by(McpServerRiskAssessment.assessed_at.desc())
        .limit(1)
    )


def server_assessment_staleness(
    db: Session,
    *,
    tenant_id: UUID,
    server_id: UUID,
    assessment: McpServerRiskAssessment,
) -> Staleness:
    """Does this score still describe the tools on the server today?"""

    current = _surface(db, tenant_id=tenant_id, server_id=server_id)

    if assessment.capability_fingerprint is None:
        # Written before RISK-2. Freshness is unprovable, so fall back to
        # the one comparison the old row does support. Reported as the
        # weaker basis rather than dressed up as a clean pass.
        if len(current) != assessment.capability_count:
            return Staleness(
                stale=True,
                reason=(
                    f"assessed {assessment.capability_count} capabilities; "
                    f"the server now exposes {len(current)}"
                ),
                basis="capability_count",
            )
        return Staleness(stale=False, basis="capability_count")

    if capability_fingerprint(current) != assessment.capability_fingerprint:
        if len(current) != assessment.capability_count:
            detail = (
                f"assessed {assessment.capability_count} capabilities; "
                f"the server now exposes {len(current)}"
            )
        else:
            # Same count, different surface — a tool was edited or
            # swapped. Worth spelling out; it is the case an operator
            # would otherwise assume could not happen.
            detail = (
                "the tool surface changed since this was assessed "
                "(same number of capabilities, different definitions)"
            )
        return Staleness(stale=True, reason=detail)

    return Staleness(stale=False)


def vserver_assessment_staleness(
    db: Session,
    *,
    tenant_id: UUID,
    vserver_id: UUID,
    assessment: VirtualServerRiskAssessment,
) -> Staleness:
    """Does this reduction still describe what the bundle publishes?

    Stale if the bundle's published tools changed, or if any upstream
    has been re-assessed since — either falsifies the difference the
    headline number claims.
    """

    published_rows = list(
        db.execute(
            select(VirtualServerTool.server_id, VirtualServerTool.tool_name).where(
                VirtualServerTool.tenant_id == tenant_id,
                VirtualServerTool.vserver_id == vserver_id,
            )
        ).all()
    )
    published_tools = {tool for _, tool in published_rows}
    current_sources: list[str] = []
    for server_id in sorted({sid for sid, _ in published_rows}, key=str):
        latest = latest_server_assessment(
            db, tenant_id=tenant_id, server_id=server_id
        )
        if latest is not None:
            current_sources.append(str(latest.id))

    recorded_sources = [str(x) for x in (assessment.source_assessment_ids or [])]

    if assessment.inputs_fingerprint is None:
        # Pre-RISK-2 row: `source_assessment_ids` was always stored, so
        # the source half of the check still works. The published-tool
        # half does not.
        if sorted(current_sources) != sorted(recorded_sources):
            return Staleness(
                stale=True,
                reason="an upstream server has been re-assessed since this ran",
                basis="capability_count",
            )
        return Staleness(stale=False, basis="capability_count")

    expected = _vserver_inputs_fingerprint(recorded_sources, published_tools)
    if expected != assessment.inputs_fingerprint:
        return Staleness(
            stale=True,
            reason="the tools this bundle publishes changed since this ran",
        )
    if sorted(current_sources) != sorted(recorded_sources):
        return Staleness(
            stale=True,
            reason="an upstream server has been re-assessed since this ran",
        )
    return Staleness(stale=False)


def _finding_from_json(item: dict[str, Any]) -> Finding:
    factors = item.get("factors") or {}
    return Finding(
        title=str(item.get("title") or ""),
        owasp_mcp=OwaspMcpRisk(str(item.get("owasp_mcp"))),
        threat_category=McpThreatCategory(str(item.get("threat_category"))),
        cwe_id=item.get("cwe_id"),
        capec_id=item.get("capec_id"),
        affected_tools=[str(t) for t in (item.get("affected_tools") or [])],
        factors=RiskFactors(
            likelihood_of_attack=int(factors.get("likelihood_of_attack", 1)),
            likelihood_of_exploit=int(factors.get("likelihood_of_exploit", 1)),
            modes_of_introduction=int(factors.get("modes_of_introduction", 1)),
            common_consequences=int(factors.get("common_consequences", 1)),
            typical_severity=int(factors.get("typical_severity", 1)),
        ),
        evidence=str(item.get("evidence") or ""),
        mitigation=str(item.get("mitigation") or ""),
    )


@dataclass(frozen=True)
class VserverRiskResult:
    row: VirtualServerRiskAssessment
    # Source servers with no assessment yet. Reported rather than
    # silently excluded: a reduction computed over half the upstreams
    # overstates the coverage of the claim.
    unassessed_server_ids: list[UUID]


def assess_vserver(
    db: Session, *, tenant_id: UUID, vserver_id: UUID
) -> VserverRiskResult:
    """Derive a vserver's risk from its upstreams' assessments. Commits.

    No LLM call — see `risk/reduction.py` for why this must be
    arithmetic over one set of findings rather than a second opinion.
    """

    vserver = db.scalar(
        select(VirtualServer).where(
            VirtualServer.tenant_id == tenant_id, VirtualServer.id == vserver_id
        )
    )
    if vserver is None:
        raise RiskServiceError("virtual server not found in tenant")

    published_rows = list(
        db.execute(
            select(VirtualServerTool.server_id, VirtualServerTool.tool_name).where(
                VirtualServerTool.tenant_id == tenant_id,
                VirtualServerTool.vserver_id == vserver_id,
            )
        ).all()
    )
    if not published_rows:
        raise RiskServiceError(
            "this bundle publishes no tools, so there is nothing to compare"
        )

    renames = vserver.rename_map or {}
    source_ids = {server_id for server_id, _ in published_rows}
    # Compare on the UPSTREAM name: findings name the tools as the
    # classifier saw them on the server, before any rename.
    published_tools = {tool for _, tool in published_rows}

    findings: list[Finding] = []
    source_assessment_ids: list[str] = []
    unassessed: list[UUID] = []
    for server_id in sorted(source_ids, key=str):
        latest = latest_server_assessment(
            db, tenant_id=tenant_id, server_id=server_id
        )
        if latest is None:
            unassessed.append(server_id)
            continue
        source_assessment_ids.append(str(latest.id))
        for item in latest.findings or []:
            try:
                findings.append(_finding_from_json(item))
            except (ValueError, KeyError):
                logger.warning(
                    "risk_finding_unreadable",
                    extra={"assessment_id": str(latest.id)},
                )

    if not source_assessment_ids:
        raise RiskServiceError(
            "none of this bundle's upstream servers have been assessed yet — "
            "assess them first, or the comparison has nothing to reduce from"
        )

    reduction = compute_reduction(findings, published_tools)
    payload = reduction.to_json()
    row = VirtualServerRiskAssessment(
        id=uuid4(),
        tenant_id=tenant_id,
        vserver_id=vserver_id,
        source_assessment_ids=source_assessment_ids,
        inherent_normalised=reduction.inherent.normalised,
        inherent_band=reduction.inherent.band,
        published_normalised=reduction.published.normalised,
        published_band=reduction.published.band,
        points_reduced=reduction.points_reduced,
        percent_reduced=reduction.percent_reduced,
        eliminated=payload["eliminated"],
        retained=payload["retained"],
        scoring_version=SCORING_VERSION,
        inputs_fingerprint=_vserver_inputs_fingerprint(
            source_assessment_ids, published_tools
        ),
        computed_at=datetime.now(UTC),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    _ = renames  # renames affect the payload sent for a server, not this
    return VserverRiskResult(row=row, unassessed_server_ids=unassessed)


def latest_vserver_assessment(
    db: Session, *, tenant_id: UUID, vserver_id: UUID
) -> VirtualServerRiskAssessment | None:
    return db.scalar(
        select(VirtualServerRiskAssessment)
        .where(
            VirtualServerRiskAssessment.tenant_id == tenant_id,
            VirtualServerRiskAssessment.vserver_id == vserver_id,
        )
        .order_by(VirtualServerRiskAssessment.computed_at.desc())
        .limit(1)
    )


def preview_vserver_reduction(
    db: Session, *, tenant_id: UUID, tools: list[tuple[UUID, str]]
) -> dict[str, Any]:
    """What publishing THIS tool set would look like, before creating it.

    The point of the whole feature: an operator should see the risk they
    are about to hand users while the selection is still editable, not
    after the bundle exists.
    """

    if not tools:
        return {"available": False, "reason": "no tools selected"}
    published = {tool for _, tool in tools}
    findings: list[Finding] = []
    unassessed: list[str] = []
    for server_id in sorted({sid for sid, _ in tools}, key=str):
        latest = latest_server_assessment(db, tenant_id=tenant_id, server_id=server_id)
        if latest is None:
            unassessed.append(str(server_id))
            continue
        for item in latest.findings or []:
            try:
                findings.append(_finding_from_json(item))
            except (ValueError, KeyError):
                continue
    if not findings and unassessed:
        return {
            "available": False,
            "reason": "upstream servers have not been assessed yet",
            "unassessed_server_ids": unassessed,
        }
    result = compute_reduction(findings, published).to_json()
    result["available"] = True
    result["unassessed_server_ids"] = unassessed
    result["evidence_basis"] = EVIDENCE_BASIS
    return result
