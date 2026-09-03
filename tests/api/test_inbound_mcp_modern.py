"""MCP-2 P1 — dual-era inbound tests for the 2026-07-28 revision.

The v1 SDK client cannot speak the modern stateless protocol, so these
tests drive the gateway with raw JSON-RPC bodies over httpx/ASGI —
exactly what a 2026-era client puts on the wire (namespaced `_meta`
keys, no `initialize`, no `mcp-session-id` header).

Covered:
- `server/discover` → DiscoverResult shape (supportedVersions /
  capabilities / instructions / ttlMs / cacheScope / serverInfo _meta)
- stateless `tools/list` selected via `_meta` AND via the
  `MCP-Protocol-Version` header alone
- stateless `tools/call` end-to-end through a real FastMCP fake
  upstream, including audit enrichment (protocol_version + clientInfo)
- `UnsupportedProtocolVersionError` (-32022) with the dual-era
  `supported` list
- `HeaderMismatchError` (-32020) when `Mcp-Method` disagrees with the
  body
- era separation regressions: legacy-shaped requests still get
  "Missing session ID"; the legacy `initialize` flow still works and
  its results carry NO `resultType`
- modern requests still hit the full auth pipeline (bad bearer → 401 +
  access_attempt audit)
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Iterator
from typing import Any
from uuid import UUID, uuid4

import anyio
import httpx
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette

from vyuu_gateway.api.inbound_mcp import (
    LEGACY_PROTOCOL_VERSION,
    get_inbound_mcp_db,
)
from vyuu_gateway.audit.emitter import EmitResult
from vyuu_gateway.audit.events import AuditEvent, AuditEventType
from vyuu_gateway.config import Settings
from vyuu_gateway.db.models import VirtualServer, VirtualServerVisibility
from vyuu_gateway.identity.fake import FakeIdentityProvider
from vyuu_gateway.identity.models import PrincipalType
from vyuu_gateway.main import create_app
from vyuu_gateway.mcp.outbound import StreamableHttpMcpClient
from vyuu_gateway.mcp.sdk_compat import (
    make_mcp_server,
    server_streamable_http_app,
)
from vyuu_gateway.policy.simple import SimplePolicyProvider
from vyuu_gateway.sessions.registry import GatewaySession

_META_PV = "io.modelcontextprotocol/protocolVersion"
_META_CI = "io.modelcontextprotocol/clientInfo"
_META_SI = "io.modelcontextprotocol/serverInfo"
MODERN = "2026-07-28"


# --- Fakes (self-contained: test modules are not importable packages) --------


class FakeResolverSession:
    def __init__(
        self,
        *,
        virtual_server: VirtualServer | None,
        rows: list[tuple[Any, ...]],
    ) -> None:
        self.virtual_server = virtual_server
        self.rows = rows

    def scalar(self, statement: Any) -> VirtualServer | None:
        return self.virtual_server

    def execute(self, statement: Any) -> list[tuple[Any, ...]]:
        return self.rows


class FakeUpstreamProvider:
    def __init__(self, client: StreamableHttpMcpClient) -> None:
        self._client = client

    def get_client(self, tenant_id: UUID, server_id: UUID) -> StreamableHttpMcpClient:
        return self._client

    def get_auth_mode_flags(self, tenant_id: UUID, server_id: UUID) -> Any:
        from vyuu_gateway.audit.events import AuthModeFlags

        return AuthModeFlags()


class RecordingAuditEmitter:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        self.events.append(event)
        return EmitResult(accepted=True)


class RecordingSessionRegistry:
    def __init__(self) -> None:
        self.sessions: dict[tuple[UUID, str], GatewaySession] = {}

    async def create_session(self, session: GatewaySession) -> None:
        self.sessions[(session.tenant_id, session.session_id)] = session

    async def get_session(self, tenant_id: UUID, session_id: str) -> GatewaySession | None:
        return self.sessions.get((tenant_id, session_id))

    async def delete_session(self, tenant_id: UUID, session_id: str) -> None:
        self.sessions.pop((tenant_id, session_id), None)


def _build_fake_upstream_app() -> Starlette:
    server = make_mcp_server(
        "fake-upstream",
        stateless_http=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @server.tool()
    def query_select(sql: str) -> str:
        return f"upstream-result for {sql}"

    return server_streamable_http_app(server)


def _vserver_and_rows(
    tenant_id: UUID, upstream_server_id: UUID
) -> tuple[VirtualServer, list[tuple[Any, ...]]]:
    vserver = VirtualServer(
        id=uuid4(),
        tenant_id=tenant_id,
        name="finance-readonly",
        rename_map={},
        policy_id=None,
        visibility=VirtualServerVisibility.PUBLIC,
        created_by=uuid4(),
    )
    rows: list[tuple[Any, ...]] = [
        (
            upstream_server_id,
            "fake-upstream",
            "query_select",
            {
                "inputSchema": {
                    "type": "object",
                    "properties": {"sql": {"type": "string"}},
                    "required": ["sql"],
                }
            },
        )
    ]
    return vserver, rows


def _auth_headers(tenant_id: UUID) -> dict[str, str]:
    return {
        "x-vyuu-tenant-id": str(tenant_id),
        "x-vyuu-principal-type": PrincipalType.ENDPOINT_SESSION.value,
        "x-vyuu-principal-id": "endpoint-session-1",
        "x-vyuu-principal-display": "Endpoint Session 1",
    }


@contextlib.asynccontextmanager
async def _gateway(
    tenant_id: UUID,
) -> AsyncIterator[tuple[httpx.AsyncClient, str, RecordingAuditEmitter, RecordingSessionRegistry]]:
    """Gateway + FastMCP fake upstream; yields a RAW httpx client (no SDK)
    so tests can put 2026-era bodies directly on the wire."""

    upstream_app = _build_fake_upstream_app()
    upstream_server_id = uuid4()
    vserver, rows = _vserver_and_rows(tenant_id, upstream_server_id)
    audit = RecordingAuditEmitter()
    registry = RecordingSessionRegistry()

    async with upstream_app.router.lifespan_context(upstream_app):
        upstream_transport = httpx.ASGITransport(app=upstream_app)
        async with httpx.AsyncClient(
            transport=upstream_transport, base_url="http://upstream"
        ) as upstream_http:
            outbound = StreamableHttpMcpClient(
                "http://upstream/mcp", http_client=upstream_http
            )
            app = create_app(
                Settings(
                    app_name="Vyuu MCP Gateway",
                    environment="test",
                    log_level="CRITICAL",
                    version="test-version",
                    operator_auth_signing_secret="ignored-here",
                ),
                identity_provider=FakeIdentityProvider(),
                policy_provider=SimplePolicyProvider(),
                upstream_clients=FakeUpstreamProvider(outbound),
                audit_emitter=audit,
                session_registry=registry,
            )

            def override_db(tenant_id: UUID) -> Iterator[FakeResolverSession]:
                yield FakeResolverSession(virtual_server=vserver, rows=rows)

            app.dependency_overrides[get_inbound_mcp_db] = override_db

            async with app.router.lifespan_context(app):
                transport = httpx.ASGITransport(app=app)
                url = f"/v/{tenant_id}/finance-readonly/mcp"
                async with httpx.AsyncClient(
                    transport=transport,
                    base_url="http://gateway",
                    headers=_auth_headers(tenant_id),
                ) as http:
                    yield http, url, audit, registry


def _rpc(method: str, params: dict[str, Any] | None = None, id_: Any = 1) -> dict[str, Any]:
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        body["params"] = params
    return body


def _modern_meta(**extra: Any) -> dict[str, Any]:
    meta: dict[str, Any] = {
        _META_PV: MODERN,
        _META_CI: {"name": "ModernTestClient", "version": "9.9.9"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    meta.update(extra)
    return meta


# --- server/discover ---------------------------------------------------------


def test_server_discover_returns_discover_result() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway(tenant_id) as (http, url, _audit, registry):
            # With full spec-shaped _meta.
            r = await http.post(url, json=_rpc("server/discover", {"_meta": _modern_meta()}))
            assert r.status_code == 200
            result = r.json()["result"]
            assert result["resultType"] == "complete"
            assert result["supportedVersions"] == [MODERN]
            assert "tools" in result["capabilities"]
            assert isinstance(result["ttlMs"], int)
            # Grant-dependent catalog ⇒ shared caches must not store it.
            assert result["cacheScope"] == "private"
            assert result["_meta"][_META_SI]["name"] == "Vyuu MCP Gateway"
            assert isinstance(result.get("instructions"), str)

            # A bare stdio-style probe (no _meta) is also answered.
            r2 = await http.post(url, json=_rpc("server/discover"))
            assert r2.status_code == 200
            assert r2.json()["result"]["supportedVersions"] == [MODERN]

            # Discovery is stateless — nothing was registered.
            assert registry.sessions == {}

    anyio.run(run)


# --- stateless tools/list ----------------------------------------------------


def test_modern_tools_list_without_session() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway(tenant_id) as (http, url, _audit, registry):
            r = await http.post(url, json=_rpc("tools/list", {"_meta": _modern_meta()}))
            assert r.status_code == 200
            result = r.json()["result"]
            names = [t["name"] for t in result["tools"]]
            assert "query_select" in names
            # CacheableResult + modern result fields.
            assert result["resultType"] == "complete"
            assert result["cacheScope"] == "private"
            assert isinstance(result["ttlMs"], int)
            assert result["_meta"][_META_SI]["version"] == "test-version"
            assert registry.sessions == {}

    anyio.run(run)


def test_modern_selected_by_header_alone() -> None:
    """The MCP-Protocol-Version header selects the modern path even when
    the body carries no `_meta` (spec: HTTP mirrors the version in a
    header)."""

    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway(tenant_id) as (http, url, _audit, _registry):
            r = await http.post(
                url,
                json=_rpc("tools/list"),
                headers={"mcp-protocol-version": MODERN},
            )
            assert r.status_code == 200
            assert r.json()["result"]["resultType"] == "complete"

    anyio.run(run)


# --- stateless tools/call (end-to-end + audit enrichment) --------------------


def test_modern_tools_call_end_to_end_and_audit() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway(tenant_id) as (http, url, audit, registry):
            r = await http.post(
                url,
                json=_rpc(
                    "tools/call",
                    {
                        "name": "query_select",
                        "arguments": {"sql": "SELECT 1"},
                        "_meta": _modern_meta(),
                    },
                ),
            )
            assert r.status_code == 200
            result = r.json()["result"]
            assert result["resultType"] == "complete"
            assert result["_meta"][_META_SI]["name"] == "Vyuu MCP Gateway"
            text = result["content"][0]["text"]
            assert "upstream-result for SELECT 1" in text
            assert result.get("isError") is not True

            # No protocol session was ever registered.
            assert registry.sessions == {}

            # Audit: the tool_call event carries the modern revision +
            # the per-request clientInfo, and an ephemeral session id.
            calls = [e for e in audit.events if e.event_type == AuditEventType.TOOL_CALL]
            assert calls, "expected a tool_call audit event"
            ev = calls[-1]
            assert ev.client_metadata.protocol_version == MODERN
            assert ev.client_metadata.agent_type == "ModernTestClient"
            assert ev.client_metadata.client_version == "9.9.9"
            assert ev.decision.value == "allow"

    anyio.run(run)


# --- version + header errors -------------------------------------------------


def test_unsupported_modern_version_returns_32022_with_supported_list() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway(tenant_id) as (http, url, _audit, _registry):
            r = await http.post(
                url,
                json=_rpc("tools/list", {"_meta": {**_modern_meta(), _META_PV: "2027-01-01"}}),
            )
            err = r.json()["error"]
            assert err["code"] == -32022
            assert err["data"]["requested"] == "2027-01-01"
            assert MODERN in err["data"]["supported"]
            # Dual-era: the legacy revision is advertised alongside.
            # A dual-era server advertises the legacy revision alongside the
            # modern ones, so a client can pick.
            assert LEGACY_PROTOCOL_VERSION in err["data"]["supported"]

    anyio.run(run)


def test_mcp_method_header_mismatch_returns_32020() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway(tenant_id) as (http, url, _audit, _registry):
            r = await http.post(
                url,
                json=_rpc("tools/list", {"_meta": _modern_meta()}),
                headers={"mcp-method": "tools/call"},
            )
            assert r.status_code == 400
            assert r.json()["error"]["code"] == -32020

    anyio.run(run)


# --- auth still enforced on the modern path ----------------------------------


def test_modern_request_with_invalid_bearer_is_rejected_and_audited() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway(tenant_id) as (http, url, audit, _registry):
            r = await http.post(
                url,
                json=_rpc("tools/list", {"_meta": _modern_meta()}),
                # Strip the fake-identity headers → identity validation fails.
                headers=dict.fromkeys(_auth_headers(tenant_id), ""),
            )
            assert r.status_code == 401
            attempts = [
                e for e in audit.events if e.event_type == AuditEventType.ACCESS_ATTEMPT
            ]
            assert attempts and attempts[-1].auth_failure_reason is not None

    anyio.run(run)


# --- era separation regressions ----------------------------------------------


def test_legacy_shaped_request_still_requires_session() -> None:
    """No `_meta`, no session header, not initialize → the legacy
    'Missing session ID' rejection is preserved verbatim (dual-era
    clients probe exactly this body before falling back)."""

    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway(tenant_id) as (http, url, _audit, _registry):
            r = await http.post(url, json=_rpc("tools/list"))
            assert r.status_code == 400
            assert "Missing session ID" in r.json()["error"]["message"]

    anyio.run(run)


def test_legacy_initialize_flow_unchanged_and_without_result_type() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        async with _gateway(tenant_id) as (http, url, _audit, registry):
            r = await http.post(
                url,
                json=_rpc(
                    "initialize",
                    {
                        "protocolVersion": LEGACY_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "LegacyClient", "version": "1.0"},
                    },
                ),
            )
            assert r.status_code == 200
            init = r.json()["result"]
            # Era separation: legacy results carry NO modern fields.
            assert "resultType" not in init
            session_id = r.headers["mcp-session-id"]
            assert (tenant_id, session_id) in registry.sessions
            # Legacy sessions record their negotiated revision for NHI.
            stored = registry.sessions[(tenant_id, session_id)]
            # The legacy handshake advertises the LEGACY revision, not
            # whatever the SDK calls newest — see LEGACY_PROTOCOL_VERSION
            # in `api/inbound_mcp.py` for why those are different things.
            assert (
                stored.client_metadata.protocol_version
                == LEGACY_PROTOCOL_VERSION
            )

            r2 = await http.post(
                url,
                json=_rpc("tools/list", id_=2),
                headers={"mcp-session-id": session_id},
            )
            assert r2.status_code == 200
            legacy_list = r2.json()["result"]
            assert "resultType" not in legacy_list
            assert [t["name"] for t in legacy_list["tools"]] == ["query_select"]

    anyio.run(run)
