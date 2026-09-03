"""OTEL-1 · the telemetry seam: no-op by default, OTel when asked.

The OTel tests inject the SDK's in-memory exporters through the seam on
`OtelTelemetry`, so nothing here opens a socket. They skip when the
optional `[otel]` extra is not installed — same posture as the Kafka
and NATS producer tests.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from vyuu_gateway.config import Settings
from vyuu_gateway.telemetry import NoOpTelemetry, Telemetry
from vyuu_gateway.telemetry.otel import (
    OtelConfig,
    UnavailableTelemetry,
    build_telemetry,
    parse_otlp_headers,
)

# --- the no-op ------------------------------------------------------------------


def test_noop_span_yields_none_and_records_nothing() -> None:
    telemetry = Telemetry()
    with telemetry.span("anything", tenant_id=uuid4()) as span:
        assert span is None
    telemetry.set_attributes(None, foo="bar")
    telemetry.record_tool_call(
        tenant_id=uuid4(), vserver="v", decision="allow", upstream_status="ok",
        duration_ms=1.0, upstream_ms=None, upstream_server_id=None,
    )
    assert telemetry.enabled is False
    assert telemetry.emit_test_signal() is False
    assert telemetry.status() == {"enabled": False, "backend": "none"}
    assert NoOpTelemetry is Telemetry


def test_build_telemetry_is_noop_when_disabled() -> None:
    telemetry = build_telemetry(Settings(otel_enabled=False))
    assert type(telemetry) is Telemetry


def test_parse_otlp_headers_follows_the_sdk_convention() -> None:
    assert parse_otlp_headers("X-SF-Token=abc, other=1") == {"X-SF-Token": "abc", "other": "1"}
    assert parse_otlp_headers("") == {}
    assert parse_otlp_headers(None) == {}
    assert parse_otlp_headers("novalue") == {}


def test_unavailable_telemetry_explains_itself() -> None:
    status = UnavailableTelemetry("not installed", endpoint="http://c:4318").status()
    assert status["enabled"] is False and status["requested"] is True
    assert status["available"] is False and "not installed" in status["reason"]


# --- the real one, in memory ------------------------------------------------------

otel_sdk = pytest.importorskip("opentelemetry.sdk", reason="[otel] extra not installed")


def _config(**overrides: Any) -> OtelConfig:
    kwargs: dict[str, Any] = {
        "endpoint": "http://collector:4318",
        "headers": {},
        "service_name": "vyuu-test",
        "service_version": "t",
        "environment": "test",
        "instance_id": "gw-test",
        "metric_export_interval_seconds": 3600.0,
    }
    kwargs.update(overrides)
    return OtelConfig(**kwargs)


def _in_memory_exporters(*, fail: bool = False) -> tuple[Any, Any]:
    from opentelemetry.sdk.metrics.export import MetricExporter, MetricExportResult
    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    class _FailingSpans(SpanExporter):
        def export(self, spans: Any) -> SpanExportResult:
            return SpanExportResult.FAILURE

        def shutdown(self) -> None:
            return None

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            return True

    class _Metrics(MetricExporter):
        def __init__(self) -> None:
            super().__init__()
            self.exports = 0

        def export(self, metrics_data: Any, timeout_millis: float = 10000, **kw: Any) -> Any:
            self.exports += 1
            return MetricExportResult.FAILURE if fail else MetricExportResult.SUCCESS

        def shutdown(self, timeout_millis: float = 30000, **kw: Any) -> None:
            return None

        def force_flush(self, timeout_millis: float = 10000) -> bool:
            return True

    spans: Any = _FailingSpans() if fail else InMemorySpanExporter()
    return spans, _Metrics()


def _telemetry(*, fail: bool = False) -> tuple[Any, Any, Any]:
    from vyuu_gateway.telemetry.otel import OtelTelemetry

    spans, metrics = _in_memory_exporters(fail=fail)
    return OtelTelemetry(_config(), span_exporter=spans, metric_exporter=metrics), spans, metrics


def test_spans_nest_and_carry_cleaned_attributes() -> None:
    telemetry, spans, _ = _telemetry()
    tenant = uuid4()
    with telemetry.span("vyuu.mcp.request", tenant_id=tenant, method=None) as outer:
        assert outer is not None
        with telemetry.span("vyuu.policy_eval", tool="query") as inner:
            telemetry.set_attributes(inner, decision="allow")
    telemetry.emit_test_signal()
    finished = {s.name: s for s in spans.get_finished_spans()}
    assert {"vyuu.mcp.request", "vyuu.policy_eval", "vyuu.telemetry.test"} <= set(finished)
    request_span = finished["vyuu.mcp.request"]
    eval_span = finished["vyuu.policy_eval"]
    assert eval_span.parent is not None
    assert eval_span.parent.span_id == request_span.context.span_id
    # UUIDs become strings; None is dropped rather than sent as "None".
    assert request_span.attributes["tenant_id"] == str(tenant)
    assert "method" not in request_span.attributes
    assert eval_span.attributes["decision"] == "allow"
    telemetry.shutdown()


def test_an_exception_inside_a_span_is_recorded_and_re_raised() -> None:
    from opentelemetry.trace import StatusCode

    telemetry, spans, _ = _telemetry()
    with pytest.raises(RuntimeError):
        with telemetry.span("vyuu.upstream.call_tool"):
            raise RuntimeError("upstream exploded")
    telemetry.emit_test_signal()
    span = next(s for s in spans.get_finished_spans() if s.name == "vyuu.upstream.call_tool")
    assert span.status.status_code == StatusCode.ERROR
    assert any(e.name == "exception" for e in span.events)
    telemetry.shutdown()


def test_test_signal_reports_whether_the_collector_accepted() -> None:
    good, _, _ = _telemetry()
    assert good.emit_test_signal() is True
    status = good.status()
    assert status["enabled"] and status["available"]
    assert status["export_successes"] >= 1 and status["export_failures"] == 0
    assert status["spans_started"] >= 1 and status["metrics_recorded"] >= 1
    good.shutdown()

    bad, _, _ = _telemetry(fail=True)
    assert bad.emit_test_signal() is False
    assert bad.status()["export_failures"] >= 1
    assert bad.status()["last_export_error"]
    bad.shutdown()


def test_metric_recorders_never_raise_and_count() -> None:
    telemetry, _, _ = _telemetry()
    before = telemetry.status()["metrics_recorded"]
    telemetry.record_tool_call(
        tenant_id=uuid4(), vserver=None, decision="deny", upstream_status="not_called",
        duration_ms=None, upstream_ms=None, upstream_server_id=None,
    )
    telemetry.record_access_attempt(tenant_id=uuid4(), reason="no_grant")
    telemetry.record_login(tenant_id=uuid4(), surface="portal", method="oidc", outcome="failure")
    telemetry.record_siem_delivery(target="deployment", sent=3, failed=1)
    telemetry.record_audit_emit_failure(tenant_id=uuid4())
    assert telemetry.status()["metrics_recorded"] >= before + 6
    assert telemetry.status()["instrumentation_errors"] == 0
    telemetry.shutdown()


def test_build_telemetry_enabled_returns_the_otel_implementation() -> None:
    from vyuu_gateway.telemetry.otel import OtelTelemetry

    telemetry = build_telemetry(
        Settings(otel_enabled=True, otel_exporter_otlp_endpoint="http://collector:4318/")
    )
    assert isinstance(telemetry, OtelTelemetry)
    assert telemetry.status()["endpoint"] == "http://collector:4318/"
    telemetry.shutdown()
