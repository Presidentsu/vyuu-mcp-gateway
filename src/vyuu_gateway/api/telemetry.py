"""OTEL-1 · operator view of the gateway's OpenTelemetry pipeline.

Status and a test signal; configuration is deployment-level and the
panel says which env vars to set. Read-only for the same reason the
secret-store panel is: a tenant-editable collector endpoint would let
one tenant redirect telemetry carrying every tenant's identifiers to a
host of their choosing. See `Settings.otel_*`.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator
from vyuu_gateway.telemetry import Telemetry

router = APIRouter(prefix="/admin/telemetry", tags=["telemetry"])

_SWITCH_INSTRUCTIONS = [
    "VYUU_OTEL_ENABLED=true",
    "VYUU_OTEL_EXPORTER_OTLP_ENDPOINT=http://splunk-otel-collector:4318",
    "# optional: VYUU_OTEL_SERVICE_NAME (default vyuu-mcp-gateway)",
    "#           VYUU_OTEL_TRACES_SAMPLE_RATIO (default 1.0)",
    "#           VYUU_OTEL_METRIC_EXPORT_INTERVAL_SECONDS (default 30)",
    "#           VYUU_OTEL_EXPORTER_OTLP_HEADERS=X-SF-Token=<token>",
    "#             (only when exporting straight to Splunk Observability Cloud)",
    "# install:  pip install vyuu-mcp-gateway[otel]",
]

_SIGNALS = [
    {"name": "vyuu.tool_calls", "kind": "counter",
     "attributes": "tenant_id, vserver, decision, upstream_status"},
    {"name": "vyuu.tool_call.duration", "kind": "histogram (ms)",
     "attributes": "tenant_id, vserver, decision, upstream_status"},
    {"name": "vyuu.upstream.duration", "kind": "histogram (ms)",
     "attributes": "tenant_id, upstream_server_id"},
    {"name": "vyuu.access_attempts", "kind": "counter", "attributes": "tenant_id, reason"},
    {"name": "vyuu.auth.logins", "kind": "counter",
     "attributes": "tenant_id, surface, method, outcome"},
    {"name": "vyuu.siem.events_sent / events_failed", "kind": "counter",
     "attributes": "target"},
    {"name": "vyuu.audit.emit_failures", "kind": "counter", "attributes": "tenant_id"},
    {"name": "vyuu.mcp.request → vyuu.policy_eval → vyuu.upstream.call_tool",
     "kind": "spans", "attributes": "tenant_id, vserver, method, tool, upstream_server_id"},
]


class TelemetryStatusResponse(BaseModel):
    status: dict[str, Any]
    switch_instructions: list[str]
    signals: list[dict[str, str]]


class TelemetryTestResponse(BaseModel):
    ok: bool
    detail: str


def _telemetry(request: Request) -> Telemetry:
    found = getattr(request.app.state, "telemetry", None)
    return found if isinstance(found, Telemetry) else Telemetry()


@router.get("/status", response_model=TelemetryStatusResponse)
def telemetry_status_endpoint(
    request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
) -> TelemetryStatusResponse:
    return TelemetryStatusResponse(
        status=_telemetry(request).status(),
        switch_instructions=list(_SWITCH_INSTRUCTIONS),
        signals=[dict(s) for s in _SIGNALS],
    )


@router.post("/test", response_model=TelemetryTestResponse)
def telemetry_test_endpoint(
    request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
) -> TelemetryTestResponse:
    """One span and one metric increment, flushed synchronously. `ok`
    means the collector accepted them, not merely that the SDK tried."""

    telemetry = _telemetry(request)
    if not telemetry.enabled:
        return TelemetryTestResponse(
            ok=False,
            detail=str(telemetry.status().get("reason") or "telemetry is not enabled"),
        )
    ok = telemetry.emit_test_signal()
    status = telemetry.status()
    if ok:
        return TelemetryTestResponse(
            ok=True,
            detail=f"collector at {status.get('endpoint')} accepted a test span and metric",
        )
    return TelemetryTestResponse(
        ok=False,
        detail=str(
            status.get("last_export_error")
            or status.get("last_instrumentation_error")
            or f"no successful export to {status.get('endpoint')} yet"
        ),
    )
