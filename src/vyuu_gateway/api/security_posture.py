"""Operator-facing view of which platform protections are actually on.

The gateway has accumulated a set of controls that are each individually
configurable, individually defaulted, and — until now — individually
invisible. An operator could not answer "are my users' refresh tokens
encrypted?" or "can an upstream prompt my users?" without reading
`Settings` on the running pod.

That is a real problem rather than a cosmetic one. A security control
nobody can see is a control nobody can verify, and several of these
default **off** deliberately (retention, envelope encryption, MRTR) —
which is only defensible if turning them on is discoverable. A default
that is safe but hidden becomes a default that is never changed.

## Read-only, and reporting effective state

Same posture as `api/secret_store.py`: these are deployment-time env
vars, baked into the pod so they survive restarts and are not an
at-runtime privilege-escalation surface. The panel's job is to report
what is true *as deployed* and name the exact variable to change — not
to offer a toggle whose effect a restart would erase.

Each control reports `on` / `off` plus a `consequence` string saying what
being off actually costs. "Retention: off" means nothing to most readers;
"tool-call history grows without limit" is the sentence that gets it
enabled.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict

from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator

router = APIRouter(prefix="/admin", tags=["admin"])


class ControlStatus(BaseModel):
    """One protection, and what its current state means."""

    model_config = ConfigDict(from_attributes=False)

    key: str
    label: str
    enabled: bool
    # Short state summary — "90 days", "deny all", "local key".
    detail: str
    # What being in this state costs. Written for the *current* state, so
    # the panel does not make an operator infer the consequence from a
    # boolean.
    consequence: str
    # The env var(s) that change it. Empty when the control is not
    # config-driven.
    env_vars: list[str] = []
    # `good` / `warn` / `info` — drives the pill colour. `warn` is
    # reserved for a state with a real, statable cost, not merely a
    # non-default.
    severity: str = "info"


class SecurityPostureResponse(BaseModel):
    controls: list[ControlStatus]
    # The gateway's own CIMD client_id, when it can serve one. Operators
    # hand this to upstream authorization-server admins, so it belongs
    # somewhere copyable rather than in a log line.
    cimd_client_id: str | None = None


def _duration(seconds: float | int) -> str:
    seconds = int(seconds)
    if seconds % 86400 == 0:
        return f"{seconds // 86400}d"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def build_posture(settings: Any, *, request: Request | None = None) -> SecurityPostureResponse:
    """Assemble the posture from `Settings`. Pure, so it is testable
    without an app."""

    controls: list[ControlStatus] = []

    # --- AWS-KMS-1 · at-rest encryption of stored OAuth tokens
    backend = (getattr(settings, "envelope_encryption_backend", "none") or "none").lower()
    encrypted = backend != "none"
    controls.append(
        ControlStatus(
            key="envelope_encryption",
            label="OAuth token encryption at rest",
            enabled=encrypted,
            detail={"none": "off", "local": "local master key", "aws_kms": "AWS KMS"}.get(
                backend, backend
            ),
            consequence=(
                "Per-user refresh tokens are sealed; a database dump does not "
                "expose connected SaaS accounts."
                if encrypted
                else "Per-user refresh tokens are stored in PLAINTEXT. A database "
                "dump, backup or read replica exposes every user's connected "
                "SaaS accounts, and nothing rotates because nobody can tell."
            ),
            env_vars=["VYUU_ENVELOPE_ENCRYPTION_BACKEND", "VYUU_ENVELOPE_MASTER_KEY"],
            severity="good" if encrypted else "warn",
        )
    )

    # --- RETENTION-1
    events_days = int(getattr(settings, "tool_call_event_retention_days", 0) or 0)
    admin_days = int(getattr(settings, "admin_audit_retention_days", 0) or 0)
    controls.append(
        ControlStatus(
            key="audit_retention",
            label="Audit retention prune",
            enabled=events_days > 0 or admin_days > 0,
            detail=(
                f"events {events_days}d · admin {admin_days}d"
                if events_days or admin_days
                else "keep forever"
            ),
            consequence=(
                "Tool-call history is pruned on the configured window, and each "
                "prune writes a retention.prune audit row."
                if events_days
                else "tool_call_events grows without limit. That is a storage "
                "cost and, under data-minimisation rules, a compliance one."
            ),
            env_vars=[
                "VYUU_TOOL_CALL_EVENT_RETENTION_DAYS",
                "VYUU_ADMIN_AUDIT_RETENTION_DAYS",
            ],
            severity="good" if events_days else "warn",
        )
    )

    # --- H1 · SSRF backstop
    ssrf = bool(getattr(settings, "upstream_ssrf_guard_enabled", True))
    allow_private = bool(getattr(settings, "http_url_allow_private_networks", False))
    controls.append(
        ControlStatus(
            key="ssrf_guard",
            label="Outbound SSRF guard (DNS-time)",
            enabled=ssrf,
            detail=("private networks allowed" if allow_private else "public only")
            if ssrf
            else "off",
            consequence=(
                "Upstream hostnames are re-resolved and pinned before each "
                "connection, so a name that resolves to a private or metadata "
                "address is refused."
                if ssrf
                else "A registered hostname that resolves to 169.254.169.254 or "
                "an internal address at call time is dialled without challenge."
            ),
            env_vars=["VYUU_UPSTREAM_SSRF_GUARD_ENABLED"],
            severity="good" if ssrf else "warn",
        )
    )

    # --- MCP-2 P3 · MRTR
    kinds = list(getattr(settings, "mrtr_allowed_input_kinds", []) or [])
    hosts = list(getattr(settings, "mrtr_allowed_elicit_url_hosts", []) or [])
    url_open = "elicit_url" in kinds and not hosts
    controls.append(
        ControlStatus(
            key="mrtr",
            label="Upstream input requests (MRTR)",
            enabled=bool(kinds),
            detail=", ".join(kinds) if kinds else "deny all",
            consequence=(
                "Upstreams may ask your users' side for: "
                + ", ".join(kinds)
                + (
                    ". URL elicitation is unrestricted — an upstream can send "
                    "your users to ANY address, with any message."
                    if url_open
                    else "."
                )
                if kinds
                else "Upstreams cannot drive your users' LLM, read their "
                "filesystem roots, prompt them, or send them to a URL."
            ),
            env_vars=[
                "VYUU_MRTR_ALLOWED_INPUT_KINDS",
                "VYUU_MRTR_ALLOWED_ELICIT_URL_HOSTS",
            ],
            # Deny-all is the SAFE state here, so "off" is `good`. An
            # unrestricted url-elicitation allowlist is the one that warns.
            severity="warn" if url_open else "good",
        )
    )

    # --- MCP-2 P3 · inbound CIMD resolution
    cimd_inbound = bool(getattr(settings, "ema_cimd_resolution_enabled", False))
    cimd_ttl = int(getattr(settings, "ema_cimd_cache_ttl_seconds", 900) or 900)
    controls.append(
        ControlStatus(
            key="cimd_inbound",
            label="Inbound client identity (CIMD)",
            enabled=cimd_inbound,
            detail=f"re-checked every {cimd_ttl // 60} min" if cimd_inbound else "off",
            consequence=(
                "An allowlisted client whose metadata document is taken down "
                "stops being accepted within "
                f"{cimd_ttl // 60} minutes, and the audit trail records the "
                "client's name rather than a bare URL."
                if cimd_inbound
                else "Allowlisted client IDs are matched as strings only. A "
                "client its own operator has decommissioned keeps working "
                "here indefinitely — CIMD revocation is 'stop serving the "
                "document', and nothing is reading the document."
            ),
            env_vars=[
                "VYUU_EMA_CIMD_RESOLUTION_ENABLED",
                "VYUU_EMA_CIMD_CACHE_TTL_SECONDS",
            ],
            # Not a `warn` when off: string matching is the behaviour this
            # gateway has always had and it is not unsafe, merely blind to
            # revocation. Enabling it also makes a third party's uptime part
            # of this auth path, which is a real trade an operator should
            # make deliberately rather than be nagged into.
            severity="good" if cimd_inbound else "info",
        )
    )

    # --- S1.b · binary provenance
    cosign_key = getattr(settings, "binary_cosign_verification_key_path", None)
    controls.append(
        ControlStatus(
            key="binary_provenance",
            label="Binary signature verification",
            enabled=bool(cosign_key),
            detail="cosign key configured" if cosign_key else "off",
            consequence=(
                "Every `binary` upstream is signature-verified before launch, "
                "on each client build."
                if cosign_key
                else "`binary` upstreams are launched on path checks alone — "
                "nothing verifies the file is the one the vendor shipped."
            ),
            env_vars=["VYUU_BINARY_COSIGN_VERIFICATION_KEY_PATH"],
            severity="good" if cosign_key else "info",
        )
    )

    # --- P2 · pooled-credential freshness
    max_age = float(getattr(settings, "upstream_client_max_age_seconds", 0) or 0)
    controls.append(
        ControlStatus(
            key="credential_freshness",
            label="Pooled credential max age",
            enabled=max_age > 0,
            detail=_duration(max_age) if max_age > 0 else "unbounded",
            consequence=(
                f"A rotated upstream secret takes effect within {_duration(max_age)}."
                if max_age > 0
                else "A rotated upstream secret only takes effect when the "
                "connection drops — a stable connection can serve a revoked "
                "credential indefinitely."
            ),
            env_vars=["VYUU_UPSTREAM_CLIENT_MAX_AGE_SECONDS"],
            severity="good" if max_age > 0 else "warn",
        )
    )

    # --- Secret store
    store = (getattr(settings, "secret_store_backend", "memory") or "memory").lower()
    controls.append(
        ControlStatus(
            key="secret_store",
            label="Secret store backend",
            enabled=store != "memory",
            detail=store,
            consequence=(
                "Upstream credentials are resolved from an external store."
                if store != "memory"
                else "Secrets live in process memory — dev and lab only. They "
                "are lost on restart and shared by every worker."
            ),
            env_vars=["VYUU_SECRET_STORE_BACKEND"],
            severity="good" if store != "memory" else "warn",
        )
    )

    # --- IDP-3 · tenant subdomain routing
    base_domain = getattr(settings, "portal_base_domain", None)
    controls.append(
        ControlStatus(
            key="tenant_subdomains",
            label="Per-tenant sign-in subdomains",
            enabled=bool(base_domain),
            detail=base_domain or "off",
            consequence=(
                f"Tenants can sign in at <slug>.{base_domain} without pasting "
                "a tenant id."
                if base_domain
                else "Users must paste a tenant UUID (or follow a ?tenant= link) "
                "to reach their sign-in page."
            ),
            env_vars=["VYUU_PORTAL_BASE_DOMAIN"],
            severity="good" if base_domain else "info",
        )
    )

    cimd_client_id: str | None = None
    public_base = getattr(settings, "public_base_url", "") or ""
    if public_base.lower().startswith("https://"):
        from vyuu_gateway.api.cimd import client_id_url

        cimd_client_id = client_id_url(public_base)

    return SecurityPostureResponse(controls=controls, cimd_client_id=cimd_client_id)


@router.get("/security-posture", response_model=SecurityPostureResponse)
def security_posture_endpoint(
    request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
) -> SecurityPostureResponse:
    """Which platform protections are on, and what each state costs."""

    return build_posture(request.app.state.settings, request=request)
