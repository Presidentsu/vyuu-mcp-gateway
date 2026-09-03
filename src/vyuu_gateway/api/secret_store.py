"""Operator-facing read-only view of the SecretStore wiring.

Surfaces the current backend, recommended use case, connectivity health,
and the env vars an operator would flip to switch backends. **Read-only
on purpose** — the secret-store choice is a deployment-time decision
(env var, baked into the gateway pod) so it survives restarts and
isn't an at-runtime privilege-escalation surface. The panel makes the
choice visible and validates it; the actual switch happens by changing
the deployment.

Why deployment-time and not UI-driven:

1. The store holds long-lived auth — Vault token, AWS creds. Letting
   any operator with UI access flip those mid-flight changes the
   privilege model from "operator can read the catalog" to "operator
   can swap secret storage", which is a meaningfully larger blast
   radius. Customers should treat the env var as part of their IaC.
2. Existing httpx clients in the upstream pool have already-resolved
   secrets baked in. A runtime switch would need pool-wide invalidation,
   in-flight call coordination, and rollback — significant complexity
   for a knob that flips once per environment.
3. Validation: `health_check` here lets operators confirm the
   configured backend works AS-DEPLOYED, which is the actual question
   they need answered.
"""

from __future__ import annotations

from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict

from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator

router = APIRouter(tags=["secret-store"])


class SecretStoreStatusResponse(BaseModel):
    """What the `/secret-store/status` endpoint returns to the UI panel."""

    model_config = ConfigDict(from_attributes=False)

    backend: str
    """Active backend name as configured. One of `memory`, `vault`,
    `aws_secrets_manager`, `kubernetes`."""

    recommended_for: str
    """Plain-English guidance — POC / on-prem / AWS-native / dev-only."""

    healthy: bool
    """Whether the configured backend responds successfully to a probe."""

    health_detail: str
    """Human-readable detail from the health probe — vault version, IAM
    posture, network error class, etc."""

    switch_instructions: dict[str, list[str]]
    """For each non-active backend, the env vars to set. Operators copy
    these into their deployment to flip backends."""


_RECOMMENDATIONS = {
    "memory": (
        "Dev / lab / tests only. Secrets live in process memory and "
        "are lost on restart. Never use for production."
    ),
    "vault": (
        "POC + on-prem-only deployments. Self-hosted alongside the "
        "gateway, no external SaaS dependency."
    ),
    "aws_secrets_manager": (
        "AWS-native deployments and customers standardised on AWS "
        "Secrets Manager. Works on-prem too via IAM Roles Anywhere."
    ),
    "kubernetes": (
        "Kubernetes-resident deployments that would rather not run a "
        "separate KMS. One Secret per tenant so RBAC can scope access "
        "with resourceNames. If the pod can simply MOUNT the secrets it "
        "needs, mount them instead — this is for the case where the set "
        "is not known at deploy time."
    ),
}

_SWITCH_INSTRUCTIONS = {
    "vault": [
        "VYUU_SECRET_STORE_BACKEND=vault",
        "VYUU_VAULT_ADDR=https://vault.your-corp.example:8200",
        "VYUU_VAULT_TOKEN=<service-token-with-read-access>",
        "# optional: VYUU_VAULT_MOUNT, VYUU_VAULT_NAMESPACE, VYUU_VAULT_VALUE_FIELD",
    ],
    "aws_secrets_manager": [
        "VYUU_SECRET_STORE_BACKEND=aws_secrets_manager",
        "VYUU_AWS_REGION=us-east-1",
        "# auth via the boto3 default credential chain:",
        "# - on-prem: IAM Roles Anywhere (recommended) or static keys",
        "#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars",
        "# - on AWS: instance profile / ECS task role / pod identity (no env needed)",
        "# optional: VYUU_AWS_SECRETS_PREFIX (default 'vyuu')",
        "#           VYUU_AWS_SECRETS_VALUE_FIELD (default unset; set if your secrets are JSON)",
    ],
    "kubernetes": [
        "VYUU_SECRET_STORE_BACKEND=kubernetes",
        "# namespace is read from the pod's projected service-account volume;",
        "# set only when running outside a pod:",
        "# VYUU_K8S_NAMESPACE=vyuu-prod",
        "# optional: VYUU_K8S_SECRET_NAME_PREFIX (default 'vyuu')",
        "#           VYUU_K8S_API_SERVER (default https://kubernetes.default.svc)",
        "# RBAC: the pod's service account needs get on secrets, ideally",
        "# scoped per tenant:  resourceNames: ['vyuu-<tenant_id>']",
    ],
    "memory": [
        "VYUU_SECRET_STORE_BACKEND=memory",
        "# no further config — secrets must be seeded via the lab bootstrap",
    ],
}


async def _probe_backend(store: Any) -> tuple[bool, str]:
    """Run the health probe on whatever backend is wired.

    `InMemorySecretStore` doesn't make a network call; it's always
    "healthy" but we annotate the detail to make that obvious in the UI.
    """

    # Duck-typed: any backend that exposes a `health_check` callable.
    health_check = getattr(store, "health_check", None)
    if health_check is None:
        return True, "in-process store (no network probe)"
    try:
        result = health_check()
        if hasattr(result, "__await__"):
            result = await result
    except Exception as exc:  # noqa: BLE001 — surface any failure as ok=False
        return False, f"probe raised: {exc.__class__.__name__}: {exc!s}"
    if isinstance(result, tuple) and len(result) == 2:
        return bool(result[0]), str(result[1])
    return True, "ok"


@router.get(
    "/secret-store/status",
    response_model=SecretStoreStatusResponse,
)
async def secret_store_status_endpoint(
    request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
) -> SecretStoreStatusResponse:
    settings = request.app.state.settings
    backend = str(getattr(settings, "secret_store_backend", "memory")).lower()
    if backend not in _RECOMMENDATIONS:
        # Misconfigured — surface clearly without crashing the panel.
        backend = "memory"
    store = cast(Any, request.app.state.secret_store)
    healthy, detail = await _probe_backend(store)
    return SecretStoreStatusResponse(
        backend=backend,
        recommended_for=_RECOMMENDATIONS[backend],
        healthy=healthy,
        health_detail=detail,
        switch_instructions={
            other: _SWITCH_INSTRUCTIONS[other]
            for other in _SWITCH_INSTRUCTIONS
            if other != backend
        },
    )
