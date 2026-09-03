"""OTEL-1 · the read-only telemetry status + test-signal endpoints."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from vyuu_gateway.config import Settings
from vyuu_gateway.main import create_app
from vyuu_gateway.operator_auth.fake import mint_operator_test_token

TEST_SIGNING_SECRET = "otel-test-signing-secret"


def _headers() -> dict[str, str]:
    token = mint_operator_test_token(
        tenant_id=uuid4(), operator_id=uuid4(), signing_secret=TEST_SIGNING_SECRET
    )
    return {"Authorization": f"Bearer {token}"}


def _client(**settings: Any) -> tuple[TestClient, Any]:
    app = create_app(
        Settings(
            app_name="otel-test", environment="test", log_level="CRITICAL", version="t",
            operator_auth_signing_secret=TEST_SIGNING_SECRET, **settings,
        )
    )
    return TestClient(app), app


def _in_memory_telemetry(*, fail: bool = False) -> Any:
    """`OtelTelemetry` over the SDK's in-memory exporters — no sockets."""

    from opentelemetry.sdk.metrics.export import MetricExporter, MetricExportResult
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    from vyuu_gateway.telemetry.otel import OtelConfig, OtelTelemetry

    class _FailingSpans(SpanExporter):
        def export(self, spans: Any) -> SpanExportResult:
            return SpanExportResult.FAILURE

        def shutdown(self) -> None:
            return None

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            return True

    class _Metrics(MetricExporter):
        def export(self, metrics_data: Any, timeout_millis: float = 10000, **kw: Any) -> Any:
            return MetricExportResult.FAILURE if fail else MetricExportResult.SUCCESS

        def shutdown(self, timeout_millis: float = 30000, **kw: Any) -> None:
            return None

        def force_flush(self, timeout_millis: float = 10000) -> bool:
            return True

    config = OtelConfig(
        endpoint="http://collector:4318", headers={}, service_name="vyuu-test",
        service_version="t", environment="test", instance_id="gw-test",
        metric_export_interval_seconds=3600.0,
    )
    spans: Any = _FailingSpans() if fail else InMemorySpanExporter()
    return OtelTelemetry(config, span_exporter=spans, metric_exporter=_Metrics())


def test_status_when_disabled_says_so_and_lists_the_switch() -> None:
    client, _ = _client()
    response = client.get("/api/v1/admin/telemetry/status", headers=_headers())
    assert response.status_code == 200
    body = response.json()
    assert body["status"]["enabled"] is False
    assert any(line.startswith("VYUU_OTEL_ENABLED=true") for line in body["switch_instructions"])
    assert any(s["name"] == "vyuu.tool_calls" for s in body["signals"])


def test_test_signal_when_disabled_is_an_honest_no() -> None:
    client, _ = _client()
    response = client.post("/api/v1/admin/telemetry/test", headers=_headers())
    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert "not enabled" in response.json()["detail"]


def test_endpoints_require_an_operator() -> None:
    client, _ = _client()
    assert client.get("/api/v1/admin/telemetry/status").status_code in (401, 403)
    assert client.post("/api/v1/admin/telemetry/test").status_code in (401, 403)


def test_test_signal_reports_the_collectors_verdict() -> None:
    pytest.importorskip("opentelemetry.sdk", reason="[otel] extra not installed")
    headers = _headers()
    client, app = _client()

    good = _in_memory_telemetry()
    app.state.telemetry = good
    response = client.post("/api/v1/admin/telemetry/test", headers=headers)
    assert response.json()["ok"] is True
    assert "accepted" in response.json()["detail"]
    status = client.get("/api/v1/admin/telemetry/status", headers=headers).json()["status"]
    assert status["enabled"] is True and status["export_successes"] >= 1
    good.shutdown()

    bad = _in_memory_telemetry(fail=True)
    app.state.telemetry = bad
    response = client.post("/api/v1/admin/telemetry/test", headers=headers)
    assert response.json()["ok"] is False
    assert "export" in response.json()["detail"]
    bad.shutdown()
