"""Inbound Streamable HTTP MCP endpoint for virtual servers.

This is the gateway's *data-plane* surface: real MCP clients (Claude Desktop,
Cursor, custom Python/Node clients using the official SDK) connect here as if
the gateway were a single MCP server. The endpoint dispatches `initialize`,
`tools/list`, and `tools/call` over JSON-RPC; tool calls are routed through
`ToolCallLifecycle` for identity / schema / policy / audit / upstream
forwarding.

URL shape: `POST /v/{tenant_id}/{vserver_name}/mcp` plus `DELETE` for session
termination. `tenant_id` is a UUID for v1 — the spec mentions tenant slugs
(`/v/acme-bank/...`) but adding a `tenants.slug` column is a separate
migration; UUIDs unblock real-client testing without that change.

Why JSON-only (no SSE) for v1: the MCP spec lets servers respond with either
JSON or SSE based on the client's `Accept` header. SDK clients accept both.
We return JSON to keep the implementation small; SSE is added when streaming
tool responses become a concrete need.

Why a hand-written JSON-RPC handler instead of `lowlevel.Server`: the SDK
server is bound to a single static handler set, while the gateway needs
per-tenant, per-vserver dispatch. The integration tests run the *real* SDK
client (`StreamableHttpMcpClient`) against this endpoint, so spec-compliance
is verified end-to-end rather than assumed from using the SDK on the wire.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from typing import Annotated, Any, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Request, Response, status
from fastapi.responses import JSONResponse
from mcp.types import (
    CallToolResult,
    Implementation,
    InitializeResult,
    ServerCapabilities,
    ToolsCapability,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.api.payload_limits import (
    PayloadTooLargeError,
    assert_request_body_within_cap,
    cap_call_tool_result,
)
from vyuu_gateway.audit.events import (
    AuditClientMetadata,
    AuditPrincipal,
    AuditPrincipalType,
    AuthFailureReason,
    create_access_attempt_audit_event,
)
from vyuu_gateway.db.models import VirtualServer
from vyuu_gateway.db.session import SessionLocal, bind_tenant_context
from vyuu_gateway.identity.models import Principal
from vyuu_gateway.identity.provider import (
    IdentityCredentials,
    IdentityProvider,
    IdentityValidationError,
)
from vyuu_gateway.mcp.sdk_compat import dump_wire, result_is_error
from vyuu_gateway.sessions.registry import (
    GatewaySession,
    SessionRegistry,
    default_expiry,
)
from vyuu_gateway.telemetry import Telemetry
from vyuu_gateway.tool_calls.error_envelope import (
    ErrorCategory,
    ErrorSource,
    build_error_envelope,
    classify_upstream_error_text,
    envelope_from_upstream_iserror,
)
from vyuu_gateway.tool_calls.lifecycle import (
    ToolCallLifecycle,
    ToolCallRequest,
    ToolCallStatus,
)
from vyuu_gateway.virtual_servers.access import (
    VirtualServerAccessDeniedError,
    assert_principal_can_access_vserver,
)
from vyuu_gateway.virtual_servers.resolver import VirtualServerResolver
from vyuu_gateway.virtual_servers.service import VirtualServerNotFoundError

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v", tags=["mcp"])


# JSON-RPC standard error codes. Only the protocol-level ones are surfaced
# here; tool-call decisions (deny, malformed args, upstream error, unknown
# tool) are conveyed via `CallToolResult.isError = true` per MCP convention.
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_PARSE_ERROR = -32700
# MCP 2026-07-28 spec-reserved codes (error-code allocation policy:
# -32020..-32099 belongs to the MCP spec).
JSONRPC_HEADER_MISMATCH = -32020            # HeaderMismatchError
JSONRPC_UNSUPPORTED_PROTOCOL_VERSION = -32022  # UnsupportedProtocolVersionError

# MCP Streamable HTTP session header (legacy revisions ≤ 2025-11-25).
MCP_SESSION_HEADER = "mcp-session-id"

# --- MCP 2026-07-28 ("modern") dual-era support (MCP-2 · P1) -----------------
#
# The 2026-07-28 revision removes the `initialize` handshake and the
# session header entirely: every request carries its protocol version,
# client info, and client capabilities in namespaced `_meta` keys, and
# `server/discover` replaces session-based capability negotiation. We
# are a dual-era server per the spec's compatibility matrix:
#
#   - an `initialize` request selects LEGACY semantics (the existing
#     session-registry path below, unchanged);
#   - a request carrying modern per-request `_meta` (or the
#     `server/discover` method itself) is served STATELESSLY.
#
# Legacy-shaped requests with neither a session header nor modern
# `_meta` keep getting the existing "Missing session ID" rejection —
# that error body is exactly what dual-era CLIENTS probe for when
# deciding to fall back to `initialize`.
MODERN_PROTOCOL_VERSION = "2026-07-28"
_SUPPORTED_MODERN_VERSIONS: tuple[str, ...] = (MODERN_PROTOCOL_VERSION,)

# MCP-2 P2 · the LEGACY (session-based) revision we serve through the
# `initialize` handshake. Pinned as our own constant, NOT read from the
# SDK's `LATEST_PROTOCOL_VERSION`.
#
# That constant means "newest this SDK knows", which is a different thing
# from "the version this handshake implements". Under SDK v1 the two
# coincided at 2025-11-25 and echoing LATEST was harmless. Under SDK v2
# LATEST became 2026-07-28 — the *stateless* revision, which has no
# `initialize` at all — so echoing it answers a stateful handshake by
# claiming to speak the stateless protocol. v2's own client rejects that
# outright, and is right to.
#
# Serving a version is a protocol commitment we make; it must not change
# underneath us because a dependency shipped a release.
LEGACY_PROTOCOL_VERSION = "2025-11-25"
# HTTP carries the version redundantly in a header on modern requests.
MCP_PROTOCOL_VERSION_HEADER = "mcp-protocol-version"
# Required standard headers on modern Streamable HTTP POSTs. We enforce
# body/header agreement only when the header is present so legacy
# clients (which never send it) are unaffected.
MCP_METHOD_HEADER = "mcp-method"
# Namespaced `_meta` keys (verbatim from the 2026-07-28 spec).
_META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
_META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
_META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"


def _emit_access_attempt(
    http_request: Request,
    *,
    tenant_id: UUID,
    vserver_name: str,
    reason: AuthFailureReason,
    principal: AuditPrincipal | None = None,
    vserver_id: UUID | None = None,
) -> None:
    """Emit a `DENY` access-attempt audit event for a connection-level
    failure. Best-effort — never raises; audit failure must not break
    the request path. The event lands in whatever emitter is wired
    (RecentAuditEmitter for the operator-console Events panel, plus
    any inner Kafka / NATS producer).

    `principal=None` is permitted for the `INVALID_BEARER` case where
    we couldn't identify the caller — we synthesise an `<unknown>`
    audit principal so the event still has a valid shape. The
    operator UI renders this clearly so it's not confused with a real
    principal."""

    audit_emitter = getattr(http_request.app.state, "audit_emitter", None)
    if audit_emitter is None:
        return
    settings = http_request.app.state.settings
    audit_principal = principal or AuditPrincipal(
        type=AuditPrincipalType.API_KEY, id="<unknown>", display=""
    )
    try:
        event = create_access_attempt_audit_event(
            tenant_id=tenant_id,
            gateway_instance_id=settings.gateway_instance_id,
            principal=audit_principal,
            auth_failure_reason=reason,
            vserver_id=vserver_id,
            vserver_name=vserver_name,
            client_metadata=_client_metadata_from_request(http_request, params={}),
        )
        audit_emitter.emit_nowait(event)
        telemetry = getattr(http_request.app.state, "telemetry", None)
        if telemetry is not None:
            telemetry.record_access_attempt(tenant_id=tenant_id, reason=reason.value)
    except Exception:  # noqa: BLE001
        # Never break the request path on audit failure.
        logger.warning("access_attempt_audit_emit_failed", exc_info=True)


def get_inbound_mcp_db(tenant_id: UUID) -> Iterator[Session]:
    """Tenant-scoped DB session for inbound MCP requests.

    Symmetric with `get_tenant_scoped_db` but takes `tenant_id` from the URL
    path rather than from an authenticated operator. The bearer token is
    validated separately by the per-request handlers using `IdentityProvider`.
    """
    with SessionLocal() as session:
        bind_tenant_context(session, tenant_id)
        yield session


@router.post("/{tenant_id}/{vserver_name}/mcp")
async def inbound_mcp_post(
    tenant_id: UUID,
    vserver_name: str,
    http_request: Request,
    db: Annotated[Session, Depends(get_inbound_mcp_db)],
) -> Response:
    # OTEL-1 · the root span of the `client → gateway → policy_eval →
    # upstream` hierarchy from spec §4.3. The method is read from the
    # `Mcp-Method` header, which modern clients send so gateways can
    # route without parsing bodies; legacy clients get it set after
    # the body is parsed, below.
    telemetry = getattr(http_request.app.state, "telemetry", None) or Telemetry()
    with telemetry.span(
        "vyuu.mcp.request",
        tenant_id=tenant_id,
        vserver=vserver_name,
        method=http_request.headers.get(MCP_METHOD_HEADER),
    ) as span:
        response = await _inbound_mcp_post(
            tenant_id, vserver_name, http_request, db, telemetry=telemetry, span=span
        )
        telemetry.set_attributes(span, http_status=response.status_code)
        return response


async def _inbound_mcp_post(
    tenant_id: UUID,
    vserver_name: str,
    http_request: Request,
    db: Session,
    *,
    telemetry: Telemetry,
    span: Any,
) -> Response:
    # H3 — fast-413 over-cap requests before any further work. Bounds
    # gateway memory + audit cost; never reaches the upstream.
    settings = http_request.app.state.settings
    raw_body = await http_request.body()
    try:
        assert_request_body_within_cap(
            raw_body, settings.inbound_max_request_body_bytes
        )
    except PayloadTooLargeError as exc:
        return _jsonrpc_error(
            None,
            JSONRPC_INVALID_REQUEST,
            f"Payload too large: {exc.actual_bytes} > {exc.limit_bytes} bytes",
            http_status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        )
    try:
        body = json.loads(raw_body)
    except Exception:
        return _jsonrpc_error(None, JSONRPC_PARSE_ERROR, "Parse error")

    if not isinstance(body, dict):
        return _jsonrpc_error(None, JSONRPC_INVALID_REQUEST, "Request body must be a JSON object")

    method = body.get("method")
    request_id = body.get("id")
    params = body.get("params") or {}
    telemetry.set_attributes(span, method=method)

    if method == "initialize":
        return await _handle_initialize(
            http_request,
            db,
            tenant_id,
            vserver_name,
            request_id,
            params,
        )

    if method == "notifications/initialized":
        # Per MCP spec, notifications carry no `id` and produce no response
        # body. The transport returns 202 Accepted.
        return Response(status_code=status.HTTP_202_ACCEPTED)

    # MCP-2 P1 — dual-era dispatch. Per the 2026-07-28 compatibility
    # matrix: a request carrying modern per-request `_meta` (or the
    # `server/discover` method itself) is served statelessly; anything
    # else continues into the legacy session path below unchanged.
    modern_version = _modern_protocol_version(http_request, params)
    if method == "server/discover" or modern_version is not None:
        return await _handle_modern_request(
            http_request,
            db,
            tenant_id,
            vserver_name,
            method,
            request_id,
            params,
            modern_version,
        )

    session_id = http_request.headers.get(MCP_SESSION_HEADER)
    if not session_id:
        return _jsonrpc_error(
            request_id,
            JSONRPC_INVALID_REQUEST,
            "Missing session ID",
            http_status=status.HTTP_400_BAD_REQUEST,
        )

    session_registry: SessionRegistry = http_request.app.state.session_registry
    session = await session_registry.get_session(tenant_id, session_id)
    if session is None:
        # The most common cause is the session id surviving a gateway-process
        # restart while the inbound store is in-memory. Surfacing the rejected
        # id makes it possible to correlate "client says X" with "registry
        # returned None for X" without having to reproduce.
        logger.warning(
            "inbound_mcp_session_rejected",
            extra={
                "tenant_id": str(tenant_id),
                "session_id": session_id,
                "vserver_name": vserver_name,
                "method": method,
                "reason": "session_not_found_or_expired",
            },
        )
        return _jsonrpc_error(
            request_id,
            JSONRPC_INVALID_REQUEST,
            "Session has been terminated or has expired",
            http_status=status.HTTP_404_NOT_FOUND,
        )

    if session.vserver_name != vserver_name:
        # The session was minted for a different virtual server in the same
        # tenant. Reject so a session id cannot be reused across vservers.
        return _jsonrpc_error(
            request_id,
            JSONRPC_INVALID_REQUEST,
            "Session is not bound to this virtual server",
            http_status=status.HTTP_404_NOT_FOUND,
        )

    if method == "tools/list":
        return _handle_tools_list(db, tenant_id, vserver_name, request_id)

    if method == "tools/call":
        return await _handle_tools_call(http_request, db, session, request_id, params)

    return _jsonrpc_error(
        request_id,
        JSONRPC_METHOD_NOT_FOUND,
        f"Method not supported: {method!r}",
    )


@router.delete("/{tenant_id}/{vserver_name}/mcp")
async def inbound_mcp_delete(
    tenant_id: UUID,
    vserver_name: str,
    http_request: Request,
    db: Annotated[Session, Depends(get_inbound_mcp_db)],
) -> Response:
    """Terminate a legacy session. Requires the session's OWNER.

    This previously took the session id from a header and deleted it,
    with no authentication of any kind: anyone who learned a session id
    could end that session, and session ids travel in headers through
    proxies and logs. A trivially reachable denial of service.

    Now it runs the same bearer -> principal -> vserver -> grant
    pipeline as every other inbound call, then checks that the caller
    is the principal the session was minted for.

    ## Why every authenticated failure returns 204

    Unknown session, someone else's session, and wrong vserver all
    answer the same. Distinguishing them would turn this into a
    session-id oracle: an attacker with any valid key of their own
    could enumerate live session ids by watching the status code.
    Idempotent-delete semantics make 204 the honest answer anyway —
    after the call, that session is not the caller's to use.

    Unauthenticated callers get the pipeline's own rejection, so they
    cannot probe at all.
    """

    session_id = http_request.headers.get(MCP_SESSION_HEADER)
    no_content = Response(status_code=status.HTTP_204_NO_CONTENT)
    if not session_id:
        return no_content

    auth = _authenticate_and_authorize(
        http_request, db, tenant_id, vserver_name, None
    )
    if isinstance(auth, Response):
        # Reuse the status, drop the JSON-RPC body: this is a plain
        # DELETE, and a JSON-RPC envelope here would confuse a client
        # that never sent one.
        return Response(status_code=auth.status_code)
    principal, _virtual_server = auth

    registry: SessionRegistry = http_request.app.state.session_registry
    session = await registry.get_session(tenant_id, session_id)
    if session is None:
        return no_content

    owner = session.principal
    if (
        session.vserver_name != vserver_name
        or str(owner.id) != str(principal.id)
        or str(owner.type) != str(principal.type)
    ):
        logger.warning(
            "inbound_mcp_session_delete_refused",
            extra={
                "tenant_id": str(tenant_id),
                "session_id": session_id,
                "reason": "caller is not the session owner",
            },
        )
        return no_content

    await registry.delete_session(tenant_id, session_id)
    logger.info(
        "inbound_mcp_session_deleted",
        extra={"tenant_id": str(tenant_id), "session_id": session_id},
    )
    return no_content


# --- Method handlers ---------------------------------------------------------


def _modern_protocol_version(
    http_request: Request,
    params: dict[str, Any],
) -> str | None:
    """Return the protocol version a modern (2026-07-28+) request
    declares, or None for legacy-shaped requests.

    The spec carries it in `params._meta["io.modelcontextprotocol/
    protocolVersion"]`; on HTTP it is ALSO mirrored in the
    `MCP-Protocol-Version` header. `_meta` wins when both are present.
    Legacy headers like `2025-11-25` in `MCP-Protocol-Version` (some
    2025-era clients already send it) do NOT select the modern path —
    only versions we recognise as modern do, plus unknown versions,
    which must reach the modern handler to receive the spec's
    `UnsupportedProtocolVersionError` instead of a legacy 400.
    """

    meta = params.get("_meta") if isinstance(params, dict) else None
    declared: str | None = None
    if isinstance(meta, dict):
        raw = meta.get(_META_PROTOCOL_VERSION)
        declared = raw if isinstance(raw, str) and raw else None
    if declared is None:
        raw = http_request.headers.get(MCP_PROTOCOL_VERSION_HEADER)
        declared = raw if isinstance(raw, str) and raw else None
    if declared is None:
        return None
    # A declared LEGACY version (e.g. header-only "2025-11-25") stays on
    # the legacy path — its era is defined by the initialize handshake.
    if declared < MODERN_PROTOCOL_VERSION:
        return None
    return declared


def _modern_result_fields(settings: Any) -> dict[str, Any]:
    """Top-level result fields every 2026-07-28 result must/should carry:
    `resultType: "complete"` (required on all results) and the server's
    self-identification in the result `_meta` (SHOULD)."""

    return {
        "resultType": "complete",
        "_meta": {
            _META_SERVER_INFO: {
                "name": settings.app_name,
                "version": settings.version,
            }
        },
    }


async def _handle_modern_request(
    http_request: Request,
    db: Session,
    tenant_id: UUID,
    vserver_name: str,
    method: Any,
    request_id: Any,
    params: dict[str, Any],
    modern_version: str | None,
) -> Response:
    """Serve one stateless 2026-07-28 request.

    Identity + authorization run per-request through the exact same
    pipeline the legacy handshake uses (`_authenticate_and_authorize`)
    — statelessness removes the session, not the enforcement. The
    tool-call path reuses the legacy handler wholesale by synthesising
    an ephemeral, never-registered `GatewaySession`, so policy / audit /
    upstream behavior cannot drift between eras.
    """

    settings = http_request.app.state.settings

    # Version gate. `server/discover` itself is answered for any
    # declared version (its whole job is telling clients what we
    # support); every other method requires a version we serve.
    if (
        method != "server/discover"
        and modern_version is not None
        and modern_version not in _SUPPORTED_MODERN_VERSIONS
    ):
        return _jsonrpc_error(
            request_id,
            JSONRPC_UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version",
            data={
                # Modern versions we serve statelessly, plus the legacy
                # revision reachable via the `initialize` handshake —
                # dual-era servers advertise both so the client can pick.
                "supported": [*_SUPPORTED_MODERN_VERSIONS, LEGACY_PROTOCOL_VERSION],
                "requested": modern_version,
            },
        )

    # `Mcp-Method` header/body agreement (HeaderMismatchError). The
    # header is required on modern POSTs so gateways can route without
    # parsing bodies; we validate agreement when present but tolerate
    # absence for wire-compat with early 2026 clients.
    header_method = http_request.headers.get(MCP_METHOD_HEADER)
    if header_method and header_method != method:
        return _jsonrpc_error(
            request_id,
            JSONRPC_HEADER_MISMATCH,
            f"Mcp-Method header {header_method!r} does not match body method {method!r}",
            http_status=status.HTTP_400_BAD_REQUEST,
        )

    # Modern notifications: no id, no body. Same transport contract as
    # the legacy `notifications/initialized` branch.
    if isinstance(method, str) and method.startswith("notifications/"):
        return Response(status_code=status.HTTP_202_ACCEPTED)

    # Same bearer→principal→vserver→grant enforcement as `initialize`.
    auth = _authenticate_and_authorize(
        http_request, db, tenant_id, vserver_name, request_id
    )
    if isinstance(auth, Response):
        return auth
    principal, virtual_server = auth

    if method == "server/discover":
        # DiscoverResult (spec §server/discover). `supportedVersions`
        # lists only the revisions we serve *statelessly* — the legacy
        # revision is reachable via `initialize`, which legacy clients
        # find by probing, not by reading this list. The catalog behind
        # this endpoint is grant-dependent per principal, so shared
        # intermediaries must not cache: `cacheScope: "private"`.
        return _jsonrpc_success(
            request_id,
            {
                "resultType": "complete",
                "supportedVersions": list(_SUPPORTED_MODERN_VERSIONS),
                "capabilities": {"tools": {"listChanged": False}},
                "instructions": (
                    f"Vyuu MCP gateway virtual server '{vserver_name}'. "
                    "Tools are governed: every call is authenticated, "
                    "policy-checked, and audited."
                ),
                "ttlMs": 3_600_000,
                "cacheScope": "private",
                "_meta": {
                    _META_SERVER_INFO: {
                        "name": settings.app_name,
                        "version": settings.version,
                    }
                },
            },
        )

    if method == "tools/list":
        # CacheableResult fields are required on modern list results.
        # Short TTL: the catalog changes on publish/sync; private scope:
        # visibility + grants make it principal-specific.
        return _handle_tools_list(
            db,
            tenant_id,
            vserver_name,
            request_id,
            extra_result_fields={
                **_modern_result_fields(settings),
                "ttlMs": 60_000,
                "cacheScope": "private",
            },
        )

    if method == "tools/call":
        # Ephemeral session — NEVER registered in the session registry.
        # It exists only to satisfy the legacy handler's parameter shape
        # so both eras share one tool-call implementation.
        session = GatewaySession(
            session_id=f"stateless-{uuid4().hex[:12]}",
            tenant_id=tenant_id,
            vserver_name=vserver_name,
            principal=principal.to_audit_principal(),
            client_metadata=_client_metadata_from_request(
                http_request,
                params,
                protocol_version=modern_version or MODERN_PROTOCOL_VERSION,
                principal=principal,
            ),
            vserver_id=virtual_server.id,
            policy_id=virtual_server.policy_id,
            expires_at=default_expiry(ttl_seconds=60),
        )
        return await _handle_tools_call(
            http_request,
            db,
            session,
            request_id,
            params,
            extra_result_fields=_modern_result_fields(settings),
        )

    return _jsonrpc_error(
        request_id,
        JSONRPC_METHOD_NOT_FOUND,
        f"Method not supported: {method!r}",
    )


def _authenticate_and_authorize(
    http_request: Request,
    db: Session,
    tenant_id: UUID,
    vserver_name: str,
    request_id: Any,
) -> tuple[Principal, VirtualServer] | Response:
    """Shared bearer→principal→vserver→grant pipeline.

    Used by BOTH eras: the legacy `initialize` handshake and every
    modern (2026-07-28) stateless request. Identity has always been
    per-request in this gateway (the bearer rides on every call), so
    statelessness costs nothing here — this is the same enforcement,
    factored to one place so the two dispatch paths cannot drift.

    Returns `(principal, virtual_server)` on success, or the ready
    JSON-RPC error `Response` (with its access-attempt audit already
    emitted) on any failure.
    """

    identity_provider: IdentityProvider = http_request.app.state.identity_provider

    try:
        principal = identity_provider.validate_principal(
            tenant_id=tenant_id,
            credentials=_credentials_from_request(http_request),
        )
    except IdentityValidationError:
        # Best-effort access-attempt audit so the operator console
        # Events panel surfaces the rejection. Principal=None here →
        # the helper synthesises an `<unknown>` audit principal.
        _emit_access_attempt(
            http_request,
            tenant_id=tenant_id,
            vserver_name=vserver_name,
            reason=AuthFailureReason.INVALID_BEARER,
        )
        # EMA-1: when the resource-authorization-server surface is on,
        # the 401 names its RFC 9728 metadata URL — that pointer is how
        # EMA-capable MCP clients discover WHERE to redeem an ID-JAG.
        settings = http_request.app.state.settings
        www_authenticate = "Bearer"
        if getattr(settings, "ema_enabled", False):
            base = settings.public_base_url.rstrip("/")
            metadata_url = (
                f"{base}/.well-known/oauth-protected-resource"
                f"/v/{tenant_id}/{vserver_name}/mcp"
            )
            www_authenticate = f'Bearer resource_metadata="{metadata_url}"'
        return _jsonrpc_error(
            request_id,
            JSONRPC_INVALID_REQUEST,
            "Authentication failed",
            http_status=status.HTTP_401_UNAUTHORIZED,
            extra_headers={"WWW-Authenticate": www_authenticate},
        )

    virtual_server = cast(
        VirtualServer | None,
        db.scalar(
            select(VirtualServer).where(
                VirtualServer.tenant_id == tenant_id,
                VirtualServer.name == vserver_name,
            )
        ),
    )
    if virtual_server is None:
        # Bearer was valid → we know who's probing for a vserver that
        # doesn't exist. Could be a typo, could be enumeration —
        # operator gets to decide on review.
        _emit_access_attempt(
            http_request,
            tenant_id=tenant_id,
            vserver_name=vserver_name,
            reason=AuthFailureReason.VSERVER_NOT_FOUND,
            principal=principal.to_audit_principal(),
        )
        return _jsonrpc_error(
            request_id,
            JSONRPC_INVALID_REQUEST,
            "Virtual server not found",
            http_status=status.HTTP_404_NOT_FOUND,
        )

    # Visibility / grant enforcement. `public` vservers fall through;
    # `private` vservers require an active grant (direct or via group).
    try:
        assert_principal_can_access_vserver(
            db,
            tenant_id=tenant_id,
            vserver=virtual_server,
            principal=principal,
        )
    except VirtualServerAccessDeniedError:
        # The "smart-azz uses someone else's URL" case — bearer is
        # valid, vserver exists, but no grant. This is the highest-
        # signal access-attempt event for operator review.
        _emit_access_attempt(
            http_request,
            tenant_id=tenant_id,
            vserver_name=vserver_name,
            reason=AuthFailureReason.NO_GRANT,
            principal=principal.to_audit_principal(),
            vserver_id=virtual_server.id,
        )
        return _jsonrpc_error(
            request_id,
            JSONRPC_INVALID_REQUEST,
            "Access denied",
            http_status=status.HTTP_403_FORBIDDEN,
        )

    return principal, virtual_server


async def _handle_initialize(
    http_request: Request,
    db: Session,
    tenant_id: UUID,
    vserver_name: str,
    request_id: Any,
    params: dict[str, Any],
) -> Response:
    settings = http_request.app.state.settings
    session_registry: SessionRegistry = http_request.app.state.session_registry

    auth = _authenticate_and_authorize(
        http_request, db, tenant_id, vserver_name, request_id
    )
    if isinstance(auth, Response):
        return auth
    principal, virtual_server = auth

    session_id = uuid4().hex
    session = GatewaySession(
        session_id=session_id,
        tenant_id=tenant_id,
        vserver_name=vserver_name,
        principal=principal.to_audit_principal(),
        # Legacy sessions negotiated their revision at initialize time;
        # every event this session emits carries it for NHI visibility.
        client_metadata=_client_metadata_from_request(
            http_request,
            params,
            protocol_version=LEGACY_PROTOCOL_VERSION,
            principal=principal,
        ),
        vserver_id=virtual_server.id,
        policy_id=virtual_server.policy_id,
        expires_at=default_expiry(ttl_seconds=settings.session_ttl_seconds),
    )
    await session_registry.create_session(session)
    logger.info(
        "inbound_mcp_session_created",
        extra={
            "tenant_id": str(tenant_id),
            "session_id": session_id,
            "vserver_name": vserver_name,
            "principal_type": principal.type.value,
            "principal_id": principal.id,
            "ttl_seconds": settings.session_ttl_seconds,
        },
    )

    init_result = InitializeResult(
        protocolVersion=LEGACY_PROTOCOL_VERSION,
        capabilities=ServerCapabilities(tools=ToolsCapability(listChanged=False)),
        serverInfo=Implementation(name=settings.app_name, version=settings.version),
    )

    return _jsonrpc_success(
        request_id,
        dump_wire(init_result),
        extra_headers={MCP_SESSION_HEADER: session_id},
    )


def _handle_tools_list(
    db: Session,
    tenant_id: UUID,
    vserver_name: str,
    request_id: Any,
    *,
    extra_result_fields: dict[str, Any] | None = None,
) -> Response:
    resolver = VirtualServerResolver(db)
    try:
        result = resolver.synthesize_tools_list(tenant_id, vserver_name)
    except VirtualServerNotFoundError:
        return _jsonrpc_error(
            request_id,
            JSONRPC_INVALID_REQUEST,
            "Virtual server not found",
            http_status=status.HTTP_404_NOT_FOUND,
        )
    return _jsonrpc_success(
        request_id,
        dump_wire(result),
        extra_result_fields=extra_result_fields,
    )


async def _handle_tools_call(
    http_request: Request,
    db: Session,
    session: GatewaySession,
    request_id: Any,
    params: dict[str, Any],
    *,
    extra_result_fields: dict[str, Any] | None = None,
) -> Response:
    tool_name = params.get("name")
    arguments = params.get("arguments") or {}
    if not isinstance(tool_name, str) or not tool_name:
        return _jsonrpc_error(request_id, JSONRPC_INVALID_PARAMS, "Missing tool name")
    if not isinstance(arguments, dict):
        return _jsonrpc_error(request_id, JSONRPC_INVALID_PARAMS, "arguments must be an object")

    lifecycle = _build_lifecycle_for_request(http_request, db)
    # Pass the inbound request's headers through to the lifecycle. The
    # outbound HTTP client filters them through the server-row
    # `auth_passthrough` map and only forwards the configured entries —
    # the gateway does NOT blindly relay every inbound header.
    inbound_headers = dict(http_request.headers.items())
    result = await lifecycle.handle_tool_call(
        ToolCallRequest(
            tenant_id=session.tenant_id,
            session_id=session.session_id,
            tool_name=tool_name,
            arguments=arguments,
            identity_credentials=_credentials_from_request(http_request),
            inbound_headers=inbound_headers,
            # Both eras hand the lifecycle the session they already
            # hold: legacy dispatch fetched it from the registry above;
            # the modern path synthesised an ephemeral one. Avoids a
            # second registry round-trip either way.
            session=session,
        )
    )

    if result.allowed and result.response is not None:
        # H3 — apply transit caps + opt-in redaction to the upstream
        # response before it reaches the client. Distinct from the
        # audit-storage cap; this is the wire-level limit.
        settings = http_request.app.state.settings
        capped, _meta = cap_call_tool_result(
            result.response,
            limit_bytes=settings.inbound_max_response_body_bytes,
            redact_secrets_in_text=settings.inbound_redact_response_secrets,
        )
        return _jsonrpc_success(
            request_id,
            dump_wire(capped),
            extra_result_fields=extra_result_fields,
        )

    # Upstream-reported errors: the upstream MCP server returned a
    # `CallToolResult` with `isError=True` and meaningful content (e.g.
    # VirusTotal "File not found", GitHub rate-limit, CrowdStrike scope
    # missing). Wrap into the structured envelope so clients get a
    # consistent shape: bracketed `[source · category]` text prefix,
    # original upstream content preserved, plus `meta["vyuu.error"]`
    # with retryable / correlation_id / source / category for
    # programmatic recovery decisions.
    if (
        result.status == ToolCallStatus.UPSTREAM_ERROR
        and result.response is not None
        and result_is_error(result.response)
    ):
        envelope = envelope_from_upstream_iserror(
            result.response,
            correlation_id=getattr(result, "correlation_id", None),
            upstream_server_id=getattr(result, "upstream_server_id", None),
            upstream_tool_name=getattr(result, "upstream_tool_name", None),
        )
        return _jsonrpc_success(
            request_id,
            dump_wire(envelope),
            extra_result_fields=extra_result_fields,
        )

    # Other tool-call decisions (deny, malformed args, upstream timeout,
    # connection failure, unknown tool, audit-pipeline-down) are
    # gateway-initiated failures — synthesise a `CallToolResult` with
    # the gateway's classification message. The JSON-RPC layer is
    # reserved for protocol-level failures (parse error, invalid
    # request, unsupported method).
    error_payload = _tool_error_payload(result)
    return _jsonrpc_success(
        request_id,
        dump_wire(error_payload),
        extra_result_fields=extra_result_fields,
    )


# --- Helpers -----------------------------------------------------------------


def _build_lifecycle_for_request(
    http_request: Request,
    db: Session,
) -> ToolCallLifecycle:
    """Construct a per-request lifecycle.

    The resolver depends on the per-request DB session; everything else comes
    from `app.state`. Construction is cheap so we don't try to amortize it.
    """
    state = http_request.app.state
    return ToolCallLifecycle(
        sessions=state.session_registry,
        resolver=VirtualServerResolver(db),
        identity_provider=state.identity_provider,
        policy_provider=state.policy_provider,
        upstream_clients=state.upstream_clients,
        audit_emitter=state.audit_emitter,
        gateway_instance_id=state.settings.gateway_instance_id,
        audit_failure_mode=state.audit_failure_mode,
        graph_event_emitter=state.graph_event_emitter,
        # JIT-2 · per-tool elevation lookup. `None` when not wired (tests
        # that build the app without it), in which case the gate denies
        # any elevation-gated tool — fail closed, and `jit_tools` is empty
        # by default so nothing is gated unless an operator says so.
        tool_elevation_checker=getattr(state, "tool_elevation_checker", None),
        # MCP-2 P3 · built from settings once at app start; see
        # `main.py`. `None` here would mean "default policy", which is the
        # same deny-all — but reading it from state keeps the deployment's
        # configured allowlist authoritative.
        mrtr_policy=getattr(state, "mrtr_policy", None),
        telemetry=getattr(state, "telemetry", None),
    )


_TOOL_ERROR_MESSAGES: dict[ToolCallStatus, str] = {
    ToolCallStatus.DENIED: "tool call denied by policy",
    ToolCallStatus.MALFORMED_ARGS: "malformed tool arguments",
    ToolCallStatus.TOOL_NOT_IN_VIRTUAL_SERVER: "tool is not exposed by this virtual server",
    ToolCallStatus.IDENTITY_INVALID: "identity validation failed",
    ToolCallStatus.SESSION_NOT_FOUND: "session not found",
    ToolCallStatus.POLICY_ENGINE_ERROR: "policy engine error",
    ToolCallStatus.UPSTREAM_TIMEOUT: "upstream MCP server timed out",
    ToolCallStatus.UPSTREAM_ERROR: "upstream MCP server error",
    ToolCallStatus.AUDIT_UNAVAILABLE: "audit pipeline unavailable",
}


# Per-status mapping into the structured envelope's (source, category)
# tuple. Lets the gateway-side error path produce the same envelope
# shape as upstream-isError responses, so MCP clients only have one
# error format to handle.
_STATUS_TO_ENVELOPE: dict[ToolCallStatus, tuple[ErrorSource, ErrorCategory]] = {
    ToolCallStatus.DENIED: (ErrorSource.POLICY, ErrorCategory.DENIED_BY_POLICY),
    ToolCallStatus.MALFORMED_ARGS: (
        ErrorSource.GATEWAY, ErrorCategory.MALFORMED_ARGS,
    ),
    ToolCallStatus.TOOL_NOT_IN_VIRTUAL_SERVER: (
        ErrorSource.GATEWAY, ErrorCategory.TOOL_NOT_IN_VSERVER,
    ),
    ToolCallStatus.CAPABILITIES_NOT_SYNCED: (
        ErrorSource.GATEWAY, ErrorCategory.CAPABILITIES_NOT_SYNCED,
    ),
    ToolCallStatus.IDENTITY_INVALID: (
        ErrorSource.GATEWAY, ErrorCategory.AUTH_FAILED,
    ),
    ToolCallStatus.SESSION_NOT_FOUND: (
        ErrorSource.GATEWAY, ErrorCategory.UNKNOWN,
    ),
    ToolCallStatus.POLICY_ENGINE_ERROR: (
        ErrorSource.GATEWAY, ErrorCategory.UNKNOWN,
    ),
    ToolCallStatus.UPSTREAM_TIMEOUT: (
        ErrorSource.NETWORK, ErrorCategory.TIMEOUT,
    ),
    ToolCallStatus.UPSTREAM_ERROR: (
        # System-exception path (TypeError, ConnectionError, etc.).
        # Upstream-reported isError=True is handled separately at the
        # JSON-RPC reply site via `envelope_from_upstream_iserror`.
        ErrorSource.NETWORK, ErrorCategory.TRANSIENT,
    ),
    ToolCallStatus.AUDIT_UNAVAILABLE: (
        ErrorSource.GATEWAY, ErrorCategory.UNKNOWN,
    ),
    # These three were absent and therefore rendered as `unknown`, which
    # told the caller nothing about a situation each of them can act on:
    # a JIT elevation is self-service, a scope denial is not, and an MRTR
    # refusal is an operator policy decision. A category that does not
    # discriminate is the same as no category.
    ToolCallStatus.NO_TOOL_ELEVATION: (
        ErrorSource.GATEWAY, ErrorCategory.NEEDS_TOOL_ELEVATION,
    ),
    ToolCallStatus.INSUFFICIENT_SCOPE: (
        ErrorSource.POLICY, ErrorCategory.DENIED_BY_POLICY,
    ),
    ToolCallStatus.INPUT_REQUIRED_DENIED: (
        ErrorSource.GATEWAY, ErrorCategory.UPSTREAM_INPUT_REFUSED,
    ),
}


def _tool_error_payload(result: Any) -> CallToolResult:
    """Render a gateway-initiated lifecycle failure as a structured
    error envelope.

    Three sources flow through here:
      - policy denials (gateway said no before the upstream got hit)
      - args / session / identity / config errors (gateway-side)
      - upstream system exceptions (TypeError, ConnectionError —
        the gateway tried to call the upstream but the call itself
        blew up; distinct from upstream returning isError=True with
        a structured response, which is handled in the reply path).

    Output shape matches `envelope_from_upstream_iserror` so MCP
    clients see the same `[source · category]` text prefix +
    `meta["vyuu.error"]` block on every error path.
    """
    status_value: ToolCallStatus = result.status
    base = _TOOL_ERROR_MESSAGES.get(status_value, "tool call failed")
    detail = result.error_message
    message = f"{base}: {detail}" if detail else base

    source, category = _STATUS_TO_ENVELOPE.get(
        status_value, (ErrorSource.GATEWAY, ErrorCategory.UNKNOWN),
    )
    # If the upstream-system-exception text smells like rate-limiting
    # / not-found / auth-failed (rare but real — e.g. a stdio MCP that
    # raises a vendor SDK exception with the original text), reclassify
    # accordingly so the (source, category) pair is the most useful
    # one we can derive.
    if status_value == ToolCallStatus.UPSTREAM_ERROR and detail:
        finer = classify_upstream_error_text(detail)
        if finer is not ErrorCategory.UNKNOWN:
            category = finer

    upstream_server_id = getattr(result, "upstream_server_id", None)
    upstream_tool_name = getattr(result, "upstream_tool_name", None)
    correlation_id = getattr(result, "correlation_id", None)
    return build_error_envelope(
        source=source,
        category=category,
        message=message,
        correlation_id=correlation_id,
        upstream_server_id=upstream_server_id,
        upstream_tool_name=upstream_tool_name,
    )


def _credentials_from_request(http_request: Request) -> IdentityCredentials:
    """Build identity credentials by snapshotting the inbound headers.

    The IdentityProvider decides which headers it cares about (Bearer in
    `Authorization`, mock `x-vyuu-*` headers, etc.); the transport just hands
    them across.
    """
    headers = {key.lower(): value for key, value in http_request.headers.items()}
    return IdentityCredentials(headers=headers)


def _client_metadata_from_request(
    http_request: Request,
    params: dict[str, Any],
    *,
    protocol_version: str | None = None,
    principal: Principal | None = None,
) -> AuditClientMetadata:
    """Build audit client-metadata from wherever this revision carries it.

    Legacy (≤2025-11-25): `clientInfo` sits in the `initialize` params.
    Modern (2026-07-28): it rides on every request under the namespaced
    `_meta` key. We check the legacy location first, then `_meta`, so
    one helper serves both dispatch paths.
    """

    client_info = params.get("clientInfo") if isinstance(params, dict) else None
    if not isinstance(client_info, dict) and isinstance(params, dict):
        meta = params.get("_meta")
        if isinstance(meta, dict):
            client_info = meta.get(_META_CLIENT_INFO)
    name: str | None = None
    version: str | None = None
    if isinstance(client_info, dict):
        raw_name = client_info.get("name")
        raw_version = client_info.get("version")
        name = raw_name if isinstance(raw_name, str) else None
        version = raw_version if isinstance(raw_version, str) else None

    return AuditClientMetadata(
        agent_type=name,
        client_version=version,
        user_agent=http_request.headers.get("user-agent"),
        protocol_version=protocol_version,
        # Only federated (EMA) principals carry an IdP-vetted client id.
        client_id=getattr(principal, "client_id", None),
    )


def _jsonrpc_success(
    request_id: Any,
    result: Any,
    *,
    extra_headers: dict[str, str] | None = None,
    extra_result_fields: dict[str, Any] | None = None,
) -> Response:
    """Wrap `result` in a JSON-RPC success envelope.

    `extra_result_fields` merges additional top-level keys into the
    result object — the MCP 2026-07-28 path uses it to stamp
    `resultType: "complete"` + the server-identity `_meta` (and, on
    cacheable results, `ttlMs` / `cacheScope`) without the legacy path
    changing shape at all. Merged AFTER the payload so protocol fields
    win over any accidental collision.
    """

    if extra_result_fields and isinstance(result, dict):
        result = {**result, **extra_result_fields}
    return JSONResponse(
        content={"jsonrpc": "2.0", "id": request_id, "result": result},
        headers=extra_headers or {},
    )


def _jsonrpc_error(
    request_id: Any,
    code: int,
    message: str,
    *,
    http_status: int = status.HTTP_200_OK,
    extra_headers: dict[str, str] | None = None,
    data: dict[str, Any] | None = None,
) -> Response:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        # `UnsupportedProtocolVersionError` (-32022) carries the list of
        # versions the server DOES support so modern clients can retry
        # with a mutually supported one instead of falling back blind.
        error["data"] = data
    return JSONResponse(
        content={
            "jsonrpc": "2.0",
            "id": request_id,
            "error": error,
        },
        status_code=http_status,
        headers=extra_headers or {},
    )
