"""OpenTelemetry implementation of `Telemetry`, for the Splunk OTel Collector.

Exports traces and metrics over OTLP/HTTP to a collector — the Splunk
OpenTelemetry Collector by default (`http://localhost:4318`), but any
OTLP receiver works, which is the point of choosing the standard over a
vendor SDK.

## Optional, and never on the import path

`opentelemetry-*` is the `[otel]` extra, lazy-imported here exactly as
`aiokafka` is in the Kafka producer. When the extra is missing and
`VYUU_OTEL_ENABLED=true`, `build_telemetry` returns an `Unavailable`
no-op whose `status()` says so; the gateway starts, and the console's
Telemetry panel tells the operator what to install.

## Why the providers are not registered globally

`opentelemetry.trace.set_tracer_provider` is one-shot per process.
Holding our own provider objects instead keeps this reconfigurable and
testable (a test can build two instances), and context propagation
still works: `start_as_current_span` attaches to the current context
regardless of which provider issued the span.

## Observed exporters

The SDK swallows OTLP export failures into its own logger, so a
misconfigured endpoint is invisible from the gateway. The two thin
wrappers below count successes and failures and keep the last error,
which is what the status panel and the Test button report.
"""

from __future__ import annotations

import contextlib
import logging
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from vyuu_gateway.telemetry import Telemetry

logger = logging.getLogger(__name__)

_INSTRUMENTATION_NAME = "vyuu_gateway"


@dataclass(frozen=True, slots=True)
class OtelConfig:
    endpoint: str
    headers: dict[str, str]
    service_name: str
    service_version: str
    environment: str
    instance_id: str
    sample_ratio: float = 1.0
    metric_export_interval_seconds: float = 30.0
    traces_enabled: bool = True
    metrics_enabled: bool = True


def parse_otlp_headers(raw: str | None) -> dict[str, str]:
    """`k1=v1,k2=v2` — the OTEL_EXPORTER_OTLP_HEADERS convention, so an
    operator can paste the same value they would give the SDK."""

    out: dict[str, str] = {}
    for pair in (raw or "").split(","):
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        if key.strip():
            out[key.strip()] = value.strip()
    return out


def _clean_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    """OTel accepts str / bool / int / float (and sequences of them).
    UUIDs become strings; None is dropped rather than sent as 'None'."""

    out: dict[str, Any] = {}
    for key, value in attributes.items():
        if value is None:
            continue
        if isinstance(value, UUID):
            out[key] = str(value)
        elif isinstance(value, str | bool | int | float):
            out[key] = value
        else:
            out[key] = str(value)
    return out


class _Health:
    """Shared counters the observed exporters write into."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.export_successes = 0
        self.export_failures = 0
        self.last_export_error: str | None = None
        self.last_export_at: datetime | None = None
        self.last_success_at: datetime | None = None

    def ok(self) -> None:
        with self.lock:
            self.export_successes += 1
            now = datetime.now(UTC)
            self.last_export_at = now
            self.last_success_at = now

    def fail(self, detail: str) -> None:
        with self.lock:
            self.export_failures += 1
            self.last_export_at = datetime.now(UTC)
            self.last_export_error = detail[:300]


class UnavailableTelemetry(Telemetry):
    """Telemetry was requested but cannot run. Says why."""

    def __init__(self, reason: str, *, endpoint: str) -> None:
        self._reason = reason
        self._endpoint = endpoint

    def status(self) -> dict[str, Any]:
        return {
            "enabled": False,
            "requested": True,
            "backend": "opentelemetry",
            "available": False,
            "reason": self._reason,
            "endpoint": self._endpoint,
        }


class OtelTelemetry(Telemetry):
    enabled = True

    def __init__(
        self,
        config: OtelConfig,
        *,
        span_exporter: Any | None = None,
        metric_exporter: Any | None = None,
    ) -> None:
        """`span_exporter` / `metric_exporter` are injection seams for
        tests — pass SDK in-memory exporters and no network is touched.
        Production leaves them None and gets OTLP/HTTP."""

        # Lazy: the extra is optional. An ImportError here is caught by
        # `build_telemetry` and turned into `UnavailableTelemetry`.
        from opentelemetry import metrics as otel_metrics
        from opentelemetry import trace as otel_trace
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
            OTLPMetricExporter,
        )
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import (
            MetricExporter,
            MetricExportResult,
            PeriodicExportingMetricReader,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,
            SpanExporter,
            SpanExportResult,
        )
        from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased

        self._config = config
        self._health = _Health()
        self._spans_started = 0
        self._metrics_recorded = 0
        self._errors = 0
        self._last_error: str | None = None
        endpoint = config.endpoint.rstrip("/")
        resource = Resource.create(
            {
                "service.name": config.service_name,
                "service.version": config.service_version,
                "service.instance.id": config.instance_id,
                "deployment.environment": config.environment,
            }
        )
        health = self._health

        class _ObservedSpanExporter(SpanExporter):
            def __init__(self, inner: Any) -> None:
                self._inner = inner

            def export(self, spans: Sequence[Any]) -> SpanExportResult:
                try:
                    result: SpanExportResult = self._inner.export(spans)
                except Exception as exc:  # noqa: BLE001
                    health.fail(f"{exc.__class__.__name__}: {exc}")
                    return SpanExportResult.FAILURE
                if result == SpanExportResult.SUCCESS:
                    health.ok()
                else:
                    health.fail(f"span export returned {result.name}")
                return result

            def shutdown(self) -> None:
                self._inner.shutdown()

            def force_flush(self, timeout_millis: int = 30000) -> bool:
                return bool(self._inner.force_flush(timeout_millis))

        class _ObservedMetricExporter(MetricExporter):
            def __init__(self, inner: Any) -> None:
                super().__init__(
                    preferred_temporality=getattr(inner, "_preferred_temporality", None),
                    preferred_aggregation=getattr(inner, "_preferred_aggregation", None),
                )
                self._inner = inner

            def export(
                self, metrics_data: Any, timeout_millis: float = 10000, **kwargs: Any
            ) -> MetricExportResult:
                try:
                    result: MetricExportResult = self._inner.export(
                        metrics_data, timeout_millis, **kwargs
                    )
                except Exception as exc:  # noqa: BLE001
                    health.fail(f"{exc.__class__.__name__}: {exc}")
                    return MetricExportResult.FAILURE
                if result == MetricExportResult.SUCCESS:
                    health.ok()
                else:
                    health.fail(f"metric export returned {result.name}")
                return result

            def shutdown(self, timeout_millis: float = 30000, **kwargs: Any) -> None:
                self._inner.shutdown(timeout_millis, **kwargs)

            def force_flush(self, timeout_millis: float = 10000) -> bool:
                return bool(self._inner.force_flush(timeout_millis))

        self._tracer_provider: Any = None
        self._tracer: Any = None
        if config.traces_enabled:
            sampler = ParentBased(TraceIdRatioBased(max(0.0, min(1.0, config.sample_ratio))))
            self._tracer_provider = TracerProvider(resource=resource, sampler=sampler)
            raw_span_exporter = span_exporter or OTLPSpanExporter(
                endpoint=f"{endpoint}/v1/traces", headers=config.headers
            )
            self._tracer_provider.add_span_processor(
                BatchSpanProcessor(_ObservedSpanExporter(raw_span_exporter))
            )
            self._tracer = self._tracer_provider.get_tracer(
                _INSTRUMENTATION_NAME, config.service_version
            )
        else:
            self._tracer = otel_trace.NoOpTracer()

        self._meter_provider: Any = None
        if config.metrics_enabled:
            raw_metric_exporter = metric_exporter or OTLPMetricExporter(
                endpoint=f"{endpoint}/v1/metrics", headers=config.headers
            )
            reader = PeriodicExportingMetricReader(
                _ObservedMetricExporter(raw_metric_exporter),
                export_interval_millis=int(config.metric_export_interval_seconds * 1000),
            )
            self._meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
            meter = self._meter_provider.get_meter(_INSTRUMENTATION_NAME, config.service_version)
        else:
            meter = otel_metrics.NoOpMeter(_INSTRUMENTATION_NAME)

        # Bounded-cardinality instruments. Attribute keys are the whole
        # contract: tenant / vserver / upstream / decision / status /
        # reason. No tool names, no principal ids — see the package
        # docstring.
        self._tool_calls = meter.create_counter(
            "vyuu.tool_calls", unit="1", description="tools/call decisions at the gateway"
        )
        self._tool_call_duration = meter.create_histogram(
            "vyuu.tool_call.duration", unit="ms",
            description="End-to-end tool call latency at the gateway",
        )
        self._upstream_duration = meter.create_histogram(
            "vyuu.upstream.duration", unit="ms",
            description="Upstream MCP server round-trip latency",
        )
        self._access_attempts = meter.create_counter(
            "vyuu.access_attempts", unit="1",
            description="Connection-level rejections by reason",
        )
        self._logins = meter.create_counter(
            "vyuu.auth.logins", unit="1", description="Console and portal sign-ins by outcome"
        )
        self._siem_sent = meter.create_counter(
            "vyuu.siem.events_sent", unit="1", description="Events delivered to SIEM targets"
        )
        self._siem_failed = meter.create_counter(
            "vyuu.siem.events_failed", unit="1",
            description="Events dropped after SIEM delivery failure",
        )
        self._audit_failures = meter.create_counter(
            "vyuu.audit.emit_failures", unit="1",
            description="Audit events the pipeline could not accept",
        )
        self._test_signals = meter.create_counter(
            "vyuu.telemetry.test_signals", unit="1",
            description="Test signals sent from the operator console",
        )

    # --- Telemetry API --------------------------------------------------

    @contextmanager
    def span(self, name: str, **attributes: Any) -> Iterator[Any]:
        try:
            manager = self._tracer.start_as_current_span(
                name, attributes=_clean_attributes(attributes)
            )
            span = manager.__enter__()
        except Exception as exc:  # noqa: BLE001 - never break the hot path
            self._note_error(exc)
            yield None
            return
        self._spans_started += 1
        try:
            yield span
        except BaseException as exc:
            # Mark and re-raise: the span records the failure, the
            # caller's exception handling is untouched.
            with contextlib.suppress(Exception):
                span.record_exception(exc)
                from opentelemetry.trace import Status, StatusCode

                span.set_status(Status(StatusCode.ERROR, str(exc)[:200]))
            manager.__exit__(type(exc), exc, exc.__traceback__)
            raise
        else:
            with contextlib.suppress(Exception):
                manager.__exit__(None, None, None)

    def set_attributes(self, span: Any, **attributes: Any) -> None:
        if span is None:
            return
        try:
            span.set_attributes(_clean_attributes(attributes))
        except Exception as exc:  # noqa: BLE001
            self._note_error(exc)

    def record_tool_call(
        self,
        *,
        tenant_id: UUID,
        vserver: str | None,
        decision: str,
        upstream_status: str,
        duration_ms: float | None,
        upstream_ms: float | None,
        upstream_server_id: UUID | None,
    ) -> None:
        attrs = _clean_attributes(
            {
                "tenant_id": tenant_id,
                "vserver": vserver,
                "decision": decision,
                "upstream_status": upstream_status,
            }
        )
        try:
            self._tool_calls.add(1, attrs)
            if duration_ms is not None:
                self._tool_call_duration.record(duration_ms, attrs)
            if upstream_ms is not None:
                self._upstream_duration.record(
                    upstream_ms,
                    _clean_attributes(
                        {"tenant_id": tenant_id, "upstream_server_id": upstream_server_id}
                    ),
                )
            self._metrics_recorded += 1
        except Exception as exc:  # noqa: BLE001
            self._note_error(exc)

    def record_access_attempt(self, *, tenant_id: UUID, reason: str) -> None:
        self._add(self._access_attempts, {"tenant_id": tenant_id, "reason": reason})

    def record_login(
        self, *, tenant_id: UUID, surface: str, method: str, outcome: str
    ) -> None:
        self._add(
            self._logins,
            {"tenant_id": tenant_id, "surface": surface, "method": method, "outcome": outcome},
        )

    def record_siem_delivery(self, *, target: str, sent: int, failed: int) -> None:
        if sent:
            self._add(self._siem_sent, {"target": target}, amount=sent)
        if failed:
            self._add(self._siem_failed, {"target": target}, amount=failed)

    def record_audit_emit_failure(self, *, tenant_id: UUID) -> None:
        self._add(self._audit_failures, {"tenant_id": tenant_id})

    def emit_test_signal(self) -> bool:
        with self.span("vyuu.telemetry.test", source="operator-console"):
            pass
        self._add(self._test_signals, {"source": "operator-console"})
        flushed = True
        try:
            if self._tracer_provider is not None:
                flushed = bool(self._tracer_provider.force_flush(timeout_millis=5000)) and flushed
            if self._meter_provider is not None:
                flushed = bool(self._meter_provider.force_flush(timeout_millis=5000)) and flushed
        except Exception as exc:  # noqa: BLE001
            self._note_error(exc)
            return False
        # force_flush says the SDK handed batches to the exporter; the
        # observed exporter says whether the collector took them.
        with self._health.lock:
            last_ok = self._health.last_success_at
            last_any = self._health.last_export_at
        return flushed and last_ok is not None and last_ok == last_any

    def status(self) -> dict[str, Any]:
        with self._health.lock:
            health = {
                "export_successes": self._health.export_successes,
                "export_failures": self._health.export_failures,
                "last_export_error": self._health.last_export_error,
                "last_export_at": (
                    self._health.last_export_at.isoformat()
                    if self._health.last_export_at else None
                ),
                "last_success_at": (
                    self._health.last_success_at.isoformat()
                    if self._health.last_success_at else None
                ),
            }
        return {
            "enabled": True,
            "requested": True,
            "backend": "opentelemetry",
            "available": True,
            "endpoint": self._config.endpoint,
            "service_name": self._config.service_name,
            "service_version": self._config.service_version,
            "environment": self._config.environment,
            "instance_id": self._config.instance_id,
            "traces_enabled": self._config.traces_enabled,
            "metrics_enabled": self._config.metrics_enabled,
            "sample_ratio": self._config.sample_ratio,
            "metric_export_interval_seconds": self._config.metric_export_interval_seconds,
            "spans_started": self._spans_started,
            "metrics_recorded": self._metrics_recorded,
            "instrumentation_errors": self._errors,
            "last_instrumentation_error": self._last_error,
            **health,
        }

    def shutdown(self) -> None:
        for provider in (self._tracer_provider, self._meter_provider):
            if provider is None:
                continue
            try:
                provider.shutdown()
            except Exception as exc:  # noqa: BLE001
                self._note_error(exc)

    # --- internals ------------------------------------------------------

    def _add(self, instrument: Any, attributes: dict[str, Any], *, amount: int = 1) -> None:
        try:
            instrument.add(amount, _clean_attributes(attributes))
            self._metrics_recorded += 1
        except Exception as exc:  # noqa: BLE001
            self._note_error(exc)

    def _note_error(self, exc: BaseException) -> None:
        self._errors += 1
        self._last_error = f"{exc.__class__.__name__}: {exc}"[:200]


def build_telemetry(settings: Any) -> Telemetry:
    """The one place `Settings` is turned into a `Telemetry`."""

    if not getattr(settings, "otel_enabled", False):
        return Telemetry()
    endpoint = str(getattr(settings, "otel_exporter_otlp_endpoint", "http://localhost:4318"))
    config = OtelConfig(
        endpoint=endpoint,
        headers=parse_otlp_headers(getattr(settings, "otel_exporter_otlp_headers", None)),
        service_name=str(getattr(settings, "otel_service_name", "vyuu-mcp-gateway")),
        service_version=str(getattr(settings, "version", "unknown")),
        environment=str(getattr(settings, "environment", "local")),
        instance_id=str(getattr(settings, "gateway_instance_id", "gateway-local")),
        sample_ratio=float(getattr(settings, "otel_traces_sample_ratio", 1.0)),
        metric_export_interval_seconds=float(
            getattr(settings, "otel_metric_export_interval_seconds", 30.0)
        ),
        traces_enabled=bool(getattr(settings, "otel_traces_enabled", True)),
        metrics_enabled=bool(getattr(settings, "otel_metrics_enabled", True)),
    )
    try:
        telemetry = OtelTelemetry(config)
    except ImportError as exc:
        reason = (
            "OpenTelemetry libraries are not installed — "
            "`pip install vyuu-mcp-gateway[otel]` "
            f"({exc.__class__.__name__}: {exc})"
        )
        logger.warning("otel_unavailable", extra={"reason": reason})
        return UnavailableTelemetry(reason, endpoint=endpoint)
    except Exception as exc:  # noqa: BLE001 - never fail startup over telemetry
        reason = f"telemetry could not start: {exc.__class__.__name__}: {exc}"
        logger.warning("otel_unavailable", extra={"reason": reason})
        return UnavailableTelemetry(reason, endpoint=endpoint)
    logger.info(
        "otel_enabled",
        extra={"endpoint": endpoint, "service_name": config.service_name},
    )
    return telemetry
