"""ASGI middleware that exposes Prometheus metrics on `/metrics`.

**Test/perf-only.** Lives under `tests/perf/` deliberately — the
production gateway image does not import this module and has no
runtime dependency on `prometheus_client`. Customers running the
gateway in production are expected to use whatever observability
they already have (Datadog / Splunk / CloudWatch / native Prometheus
scraping via JSON access logs / etc.).

Wire via `tests/perf/lab_with_metrics.py`:

    from vyuu_gateway.main import create_app
    from tests.perf.metrics_middleware import attach_metrics

    app = create_app()
    attach_metrics(app)        # registers /metrics + per-request hooks
    uvicorn.run(app, ...)

Metrics exposed:

| Metric                                  | Type      | Labels                       |
|-----------------------------------------|-----------|------------------------------|
| vyuu_requests_total                     | counter   | method, route, status        |
| vyuu_request_duration_seconds           | histogram | method, route                |
| vyuu_inflight_requests                  | gauge     | route                        |
| vyuu_rate_limit_503_total               | counter   | tenant                       |
| vyuu_tool_calls_total                   | counter   | vserver, decision            |

Path normalization: high-cardinality URL pieces (UUIDs in `/v/<id>/...`,
`/api/v1/servers/<id>/...`) get collapsed to `:tenant`, `:server_id`,
etc., so labels stay bounded.
"""
from __future__ import annotations

import re
import time
from typing import Any

try:  # pragma: no cover - optional dep, present only with `[perf]` extras
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )
    _HAS_PROMETHEUS = True
except ImportError:  # pragma: no cover
    _HAS_PROMETHEUS = False


# ---- Path normalization ---------------------------------------------------

_PATH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Inbound MCP: /v/<tenant>/<vserver>/mcp
    (re.compile(r"^/v/[0-9a-fA-F-]{36}/[^/]+/mcp/?$"), "/v/:tenant/:vserver/mcp"),
    # Servers admin
    (re.compile(r"^/api/v1/servers/[0-9a-fA-F-]{36}/sync/?$"),
     "/api/v1/servers/:id/sync"),
    (re.compile(r"^/api/v1/servers/[0-9a-fA-F-]{36}/health/check/?$"),
     "/api/v1/servers/:id/health/check"),
    (re.compile(r"^/api/v1/servers/[0-9a-fA-F-]{36}/health/?$"),
     "/api/v1/servers/:id/health"),
    (re.compile(r"^/api/v1/servers/[0-9a-fA-F-]{36}/?$"),
     "/api/v1/servers/:id"),
    # Vservers
    (re.compile(r"^/api/v1/vservers/[0-9a-fA-F-]{36}/?$"),
     "/api/v1/vservers/:id"),
    # Identities
    (re.compile(r"^/api/v1/identities/[^/]+/(graph|timeline|summary)/?$"),
     "/api/v1/identities/:id/\\1"),
    # Users
    (re.compile(r"^/api/v1/users/[0-9a-fA-F-]{36}/password/?$"),
     "/api/v1/users/:id/password"),
    (re.compile(r"^/api/v1/users/[0-9a-fA-F-]{36}/?$"),
     "/api/v1/users/:id"),
]


def _normalize_path(path: str) -> str:
    for pattern, replacement in _PATH_PATTERNS:
        if pattern.match(path):
            return pattern.sub(replacement, path)
    return path


# ---- Metric registry ------------------------------------------------------


class _Metrics:
    """Holds the Prometheus collectors. Built once per app instance."""

    def __init__(self) -> None:
        if not _HAS_PROMETHEUS:
            self.registry: Any = None
            return
        self.registry = CollectorRegistry()
        self.requests_total = Counter(
            "vyuu_requests_total",
            "HTTP requests handled by the gateway",
            ["method", "route", "status"],
            registry=self.registry,
        )
        self.request_duration = Histogram(
            "vyuu_request_duration_seconds",
            "End-to-end request latency including upstream call",
            ["method", "route"],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
                    0.5, 1.0, 2.5, 5.0, 10.0),
            registry=self.registry,
        )
        self.inflight = Gauge(
            "vyuu_inflight_requests",
            "Currently in-flight HTTP requests",
            ["route"],
            registry=self.registry,
        )
        self.rate_limit_503 = Counter(
            "vyuu_rate_limit_503_total",
            "Requests fast-503'd by the per-tenant inflight gate",
            ["tenant"],
            registry=self.registry,
        )
        self.tool_calls = Counter(
            "vyuu_tool_calls_total",
            "tools/call attempts at the inbound gateway",
            ["vserver", "decision"],
            registry=self.registry,
        )


# ---- ASGI middleware ------------------------------------------------------


class PrometheusMiddleware:
    """Wraps the FastAPI app. Records request metrics + serves /metrics."""

    def __init__(self, app: Any, metrics: _Metrics) -> None:
        self._app = app
        self._m = metrics

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        # Serve /metrics directly (no upstream pass-through).
        if path == "/metrics":
            await self._serve_metrics(send)
            return

        method: str = scope.get("method", "GET")
        route = _normalize_path(path)
        if not _HAS_PROMETHEUS:
            await self._app(scope, receive, send)
            return

        # Wrap `send` to capture the response status.
        status_holder = {"status": 0}

        async def send_wrapper(message: Any) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
            await send(message)

        self._m.inflight.labels(route=route).inc()
        t0 = time.perf_counter()
        try:
            await self._app(scope, receive, send_wrapper)
        finally:
            elapsed = time.perf_counter() - t0
            status = status_holder["status"] or 0
            self._m.requests_total.labels(
                method=method, route=route, status=str(status)
            ).inc()
            self._m.request_duration.labels(method=method, route=route).observe(elapsed)
            self._m.inflight.labels(route=route).dec()
            # Tag rate-limit hits separately for easy graphing. The tenant id
            # comes from URL (`/v/<tenant>/...`) or header — best-effort.
            if status == 503:
                tenant = _extract_tenant(scope, path) or "unknown"
                self._m.rate_limit_503.labels(tenant=tenant).inc()

    async def _serve_metrics(self, send: Any) -> None:
        if not _HAS_PROMETHEUS:
            await send({
                "type": "http.response.start",
                "status": 501,
                "headers": [(b"content-type", b"text/plain")],
            })
            await send({"type": "http.response.body",
                        "body": b"prometheus_client not installed"})
            return
        body = generate_latest(self._m.registry)
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", CONTENT_TYPE_LATEST.encode("ascii"))],
        })
        await send({"type": "http.response.body", "body": body})


# ---- Tenant extraction (mirrors the inflight-gate pattern) ----------------

_MCP_TENANT = re.compile(r"^/v/(?P<tenant>[0-9a-fA-F-]{36})/")


def _extract_tenant(scope: Any, path: str) -> str | None:
    m = _MCP_TENANT.match(path)
    if m:
        return m.group("tenant")
    for key, value in scope.get("headers", []):
        if key == b"x-vyuu-tenant-id":
            try:
                return value.decode("ascii")
            except UnicodeDecodeError:
                return None
    return None


# ---- Public entry point ---------------------------------------------------


def attach_metrics(app: Any) -> _Metrics:
    """Install the ASGI metrics middleware on a FastAPI app.

    Call after `create_app()` and before `uvicorn.run(app, ...)`.
    Idempotent — calling twice is a no-op (returns the existing
    metrics registry).
    """
    existing = getattr(app.state, "_perf_metrics", None)
    if existing is not None:
        return existing  # type: ignore[no-any-return]
    metrics = _Metrics()
    app.state._perf_metrics = metrics
    app.add_middleware(PrometheusMiddleware, metrics=metrics)
    return metrics
