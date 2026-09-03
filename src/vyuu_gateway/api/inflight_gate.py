"""Per-tenant inflight semaphore — fast-503 when a single tenant
saturates the gateway.

Tier-1 stress-test fix. The realistic-mix load test showed that
without a per-tenant gate, one runaway tenant's traffic (autonomous
agent in a retry loop, misbehaving CI bot, etc.) can occupy every
worker slot and starve every other tenant on the same gateway pod.

Contract:

- Each tenant gets an `asyncio.Semaphore(N)` lazily on first
  request. Default N is `Settings.inbound_per_tenant_inflight_limit`.
- `acquire_nowait()` semantics: if the semaphore is full when the
  request arrives, return 503 immediately rather than queueing. The
  Vyuu error envelope categorises this as
  `gateway · rate_limited / retryable=true` so MCP clients can
  back off and retry.
- Liveness probes (`/healthz`) and the deep-health endpoint
  (`/api/v1/health`) are unconditionally bypassed — operator
  monitoring must NEVER false-page during normal back-pressure.
- Operator-console / portal-admin routes (`/api/v1/...` paths that
  aren't tenant-scoped) currently fall through unrestricted. A
  follow-up could add a separate gate per operator if needed; for
  v1 the load shape there is human-driven and trivial.

Tenant-id extraction order (first match wins):
  1. URL path: `/v/{uuid}/{vserver}/mcp` — inbound MCP tool calls
  2. HTTP header: `x-vyuu-tenant-id` — management API + identity
     header path

Requests that don't carry a tenant id (operator console, portal,
docs, /healthz) skip the gate.
"""
from __future__ import annotations

import asyncio
import json
import re
from uuid import UUID

from starlette.types import ASGIApp, Receive, Scope, Send

from vyuu_gateway.api.health import LIVENESS_BYPASS_PATHS

# Match the inbound MCP tenant path. The gateway only accepts uuid
# tenants; non-matching paths fall through.
_MCP_PATH = re.compile(
    r"^/v/(?P<tenant>[0-9a-fA-F-]{36})/[^/]+/mcp/?$"
)
_TENANT_HEADER = b"x-vyuu-tenant-id"

# Routes that the gate must never block. Tracked here as a set so the
# bypass logic stays O(1) per request.
_DEEP_HEALTH_PATH = "/api/v1/health"


class PerTenantInflightGate:
    """ASGI middleware. Wrap the FastAPI app at construction time.

    Why ASGI instead of FastAPI's BaseHTTPMiddleware:
    - We want to short-circuit with a 503 *before* any per-request
      setup runs — DB session creation, tenant-scoped middleware,
      etc. BaseHTTPMiddleware runs after CORS but FastAPI executes
      a lot of dependency resolution before the handler — too late
      to defend against burst saturation.
    - ASGI middleware composes once at app build time and has zero
      overhead per request beyond a Set lookup + dict get.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        per_tenant_limit: int,
    ) -> None:
        if per_tenant_limit < 1:
            raise ValueError("per_tenant_limit must be >= 1")
        self._app = app
        self._limit = per_tenant_limit
        # Lazily-allocated per-tenant semaphores. Bounded growth: at
        # most one entry per tenant ever seen. Fine in practice — a
        # gateway pod sees O(100) tenants, each holding a tiny
        # asyncio.Semaphore. No eviction needed.
        self._semaphores: dict[UUID, asyncio.Semaphore] = {}

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        # Liveness probes + deep health are unconditionally bypassed.
        # K8s monitoring must never false-page during back-pressure.
        if path in LIVENESS_BYPASS_PATHS or path == _DEEP_HEALTH_PATH:
            await self._app(scope, receive, send)
            return

        tenant_id = self._extract_tenant(scope, path)
        if tenant_id is None:
            # No tenant context — operator console, docs, portal-mgmt
            # paths. Fall through; a future per-operator gate can
            # plug in here.
            await self._app(scope, receive, send)
            return

        sem = self._semaphores.get(tenant_id)
        if sem is None:
            sem = asyncio.Semaphore(self._limit)
            self._semaphores[tenant_id] = sem

        # Fast-fail when the semaphore is fully booked. `locked()` is
        # the documented public predicate (returns True iff a future
        # acquire would block). `acquire_nowait` doesn't exist on
        # asyncio.Semaphore so this is the simplest correct shape.
        # The race window between `locked()` and `acquire()` is
        # acceptable: the worst case is admitting one extra request
        # past the limit while another is releasing — well within
        # the safety factor of any practical limit value.
        if sem.locked():
            await self._send_503(send, tenant_id=tenant_id)
            return

        await sem.acquire()
        try:
            await self._app(scope, receive, send)
        finally:
            sem.release()

    @staticmethod
    def _extract_tenant(scope: Scope, path: str) -> UUID | None:
        # 1. URL path: /v/<uuid>/<vserver>/mcp
        m = _MCP_PATH.match(path)
        if m:
            try:
                return UUID(m.group("tenant"))
            except ValueError:
                return None
        # 2. Header path
        for key, value in scope.get("headers", []):
            if key == _TENANT_HEADER:
                try:
                    return UUID(value.decode("ascii"))
                except (ValueError, UnicodeDecodeError):
                    return None
        return None

    @staticmethod
    async def _send_503(send: Send, *, tenant_id: UUID) -> None:
        # Synthesize a Vyuu-shaped error envelope so MCP clients
        # decode the 503 the same way they decode any other gateway
        # rate-limit signal. `Retry-After` is a soft hint; clients
        # should backoff exponentially.
        body = json.dumps({
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": (
                    "[gateway · rate_limited] tenant inflight cap reached; "
                    "retry after a short backoff"
                ),
                "data": {
                    "vyuu.error": {
                        "source": "gateway",
                        "category": "rate_limited",
                        "retryable": True,
                        "tenant_id": str(tenant_id),
                    },
                },
            },
        }).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 503,
            "headers": [
                (b"content-type", b"application/json"),
                (b"retry-after", b"1"),
            ],
        })
        await send({"type": "http.response.body", "body": body})
