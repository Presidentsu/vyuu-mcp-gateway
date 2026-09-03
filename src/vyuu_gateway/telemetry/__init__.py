"""Operational telemetry — traces and metrics for the people who run the gateway.

Distinct from audit on purpose (spec §4.3: "metrics for SRE; audit for
security"). Audit answers *who did what*; this answers *is the gateway
healthy, where is the latency, what is being denied at what rate*.

The gateway code calls one small internal API — `Telemetry` — and never
imports OpenTelemetry directly. The default implementation is a no-op:
`span()` yields nothing, `record_*()` returns. `OtelTelemetry` in
`otel.py` is the real one, built only when `VYUU_OTEL_ENABLED=true` and
the optional `[otel]` extra is installed. Two reasons for the seam:

1. The base install stays light, like the Kafka / NATS producers.
2. The hot path cannot be broken by a telemetry failure. Every method
   on the real implementation catches and counts; the lifecycle never
   sees an exception from here.

## Cardinality is a contract

Metric attributes are bounded: tenant, virtual server, upstream server,
decision, status, reason. Never a tool name, never a principal id — a
tenant with ten thousand API keys would otherwise mint ten thousand
time series per metric. Tool names go on SPANS only, which are sampled
and not aggregated.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from uuid import UUID


class Telemetry:
    """The no-op implementation and the interface, in one class."""

    enabled: bool = False

    @contextmanager
    def span(self, name: str, **attributes: Any) -> Iterator[Any]:
        """A trace span. The yielded object may be None; callers that
        want to add attributes use `set_attributes` below."""

        yield None

    def set_attributes(self, span: Any, **attributes: Any) -> None:
        return None

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
        return None

    def record_access_attempt(self, *, tenant_id: UUID, reason: str) -> None:
        return None

    def record_login(
        self, *, tenant_id: UUID, surface: str, method: str, outcome: str
    ) -> None:
        return None

    def record_siem_delivery(self, *, target: str, sent: int, failed: int) -> None:
        return None

    def record_audit_emit_failure(self, *, tenant_id: UUID) -> None:
        return None

    def emit_test_signal(self) -> bool:
        """Send one span and one metric increment. False when disabled."""

        return False

    def status(self) -> dict[str, Any]:
        return {"enabled": False, "backend": "none"}

    def shutdown(self) -> None:
        return None


NoOpTelemetry = Telemetry
