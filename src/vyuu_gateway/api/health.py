from typing import Literal, cast

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict
from starlette.responses import PlainTextResponse

from vyuu_gateway.config import Settings

router = APIRouter(tags=["health"])

# Paths that the per-tenant inflight middleware (and any future
# rate-limit / queueing middleware) must let through unconditionally.
# Exposed as a constant so middleware code references it instead of
# hardcoding strings.
LIVENESS_BYPASS_PATHS: frozenset[str] = frozenset({"/healthz"})


class HealthResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: Literal["ok"]
    service: str
    version: str
    environment: str


@router.get("/health", response_model=HealthResponse)
def health(request: Request) -> HealthResponse:
    """Deep health: reflects gateway-instance metadata (service name,
    version, environment). Used by the operator console env-pill and
    similar UI surfaces.

    For pod-level liveness/readiness probes that must survive even
    while the gateway is queue-saturated, use `/healthz` (mounted at
    the app root, bypasses per-tenant inflight gate).
    """
    settings = cast(Settings, request.app.state.settings)
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        version=settings.version,
        environment=settings.environment,
    )


# Lightweight liveness probe — mounted at app root (NOT under
# `/api/v1/`) and explicitly bypassed by every gateway middleware
# that gates inbound work. K8s liveness/readiness probes, load
# balancer health checks, and external uptime monitors should target
# this endpoint, NOT `/api/v1/health`. Returns "ok" with no body
# parsing so it costs ~zero CPU and doesn't touch app state.
#
# Tier-1 stress-test fix: during the realistic-mix load test, the
# previous `/api/v1/health` endpoint timed out under burst because
# it shared the request queue with `tools/call`. K8s would mark the
# pod unhealthy → traffic redistributed → cascade. `/healthz` exists
# so liveness probes never see false-negative health failures during
# normal back-pressure.
liveness_router = APIRouter(tags=["health"])


@liveness_router.get("/healthz", response_class=PlainTextResponse)
def liveness() -> str:
    return "ok"
