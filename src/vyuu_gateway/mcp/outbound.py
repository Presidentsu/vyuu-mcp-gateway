import asyncio
import logging
import re
import ssl
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path  # noqa: F401 - retained for stdio cwd typing
from typing import Any, Protocol
from uuid import UUID

import httpx
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import CallToolResult, InitializeResult, Prompt, Resource, Tool

from mcp import ClientSession
from vyuu_gateway.capabilities.client import CapabilityDescriptor
from vyuu_gateway.db.models import McpCapabilityKind
from vyuu_gateway.mcp.sdk_compat import (
    McpError,
    open_streamable_http,
    read_timeout_arg,
    sdk_field,
    tool_input_schema,
)
from vyuu_gateway.registry.url_security import UrlSecurityPolicy
from vyuu_gateway.upstream.oauth import OAuthTokenProvider
from vyuu_gateway.upstream.ssrf_guard import SsrfGuardTransport

logger = logging.getLogger(__name__)

# JSON-RPC "Method not found". Upstream MCP servers MAY omit prompts/
# resources/tools entirely; treat each list call as best-effort during
# capability sync so a server that only exposes tools doesn't fail the
# whole snapshot.
_JSONRPC_METHOD_NOT_FOUND = -32601

# Cap on captured stdio stderr surfaced in `UpstreamStartupDiagnosticError`.
# Bounded so a hostile upstream cannot exhaust gateway memory by emitting
# an unbounded error stream before exiting. 512 bytes is enough for the
# common "Configuration error: ..." messages without enabling exfiltration.
_STDERR_CAPTURE_BYTES = 512


def _looks_like_unauthorized(exc: BaseException) -> bool:
    """Heuristic: did the upstream reject our bearer with 401?

    The MCP SDK's streamable-http transport surfaces 401s as raised
    exceptions whose repr/message mention "401" or "unauthorized".
    httpx.HTTPStatusError carries `response.status_code`. McpError
    embeds the auth-failed phrase in its message. We match either
    shape conservatively; false negatives are fine (we just don't
    auto-refresh and the client gets the original error). False
    positives are also fine (we'd refresh once and re-call — at most
    one extra token-refresh round trip per legitimate 4xx).

    Drills through `BaseExceptionGroup` (anyio task-group wrappers).
    """
    while isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) >= 1:
        exc = exc.exceptions[0]
    code = getattr(getattr(exc, "response", None), "status_code", None)
    if isinstance(code, int) and code == 401:
        return True
    text = (str(exc) or "").lower()
    return "401" in text or "unauthorized" in text or "invalid_token" in text


class UpstreamStartupDiagnosticError(Exception):
    """Wraps a stdio upstream startup failure with bounded stderr capture.

    The default (security-correct) behavior is to redirect upstream stderr
    to `/dev/null` so untrusted processes can't leak secrets / customer
    data into gateway logs. But when the upstream EXITS during initialize
    (e.g. `falcon-mcp` without `FALCON_CLIENT_ID`), the actual reason
    sits in stderr and the operator only sees `McpError: Connection
    closed` — useless for diagnostics.

    Compromise: capture stderr ONLY during the initialize window, cap at
    512 bytes, sanitize (strip ANSI, drop control chars, refuse if it
    looks like an MCP JSON message that ended up on stderr by mistake),
    and surface in the upstream-error path. Operator-visible only — the
    inbound MCP error path stays sanitized. See spec §3.3 / AGENTS.md
    for the broader stderr-redirection rationale.
    """

    def __init__(self, original_error_class: str, stderr: str) -> None:
        super().__init__(f"{original_error_class}: {stderr or '<no stderr captured>'}")
        self.original_error_class = original_error_class
        self.stderr = stderr


def _sanitize_stderr_capture(raw: str, max_bytes: int = _STDERR_CAPTURE_BYTES) -> str:
    """Bound + sanitize captured upstream stderr for operator display.

    - Cap at `max_bytes` (defense against a hostile upstream emitting
      gigabytes before exiting).
    - Strip ANSI escape sequences (color codes from CLI tools).
    - Replace control characters with space; preserve newlines.
    - Refuse if it looks like a JSON-RPC message that ended up on
      stderr by mistake — surfacing protocol payloads could leak data
      and confuse operators about what's tool output vs error.
    """

    if not raw:
        return ""
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw)
    text = "".join(c if c == "\n" or c.isprintable() else " " for c in text)
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        return ""
    return stripped[:max_bytes]


@dataclass(frozen=True)
class MtlsClientCredential:
    """PEM-encoded client cert chain + private key, in memory.

    Carried through the provider-build path from SecretStore-resolved
    blobs into the httpx client construction. Held in memory only — the
    PEM bytes never hit disk (we materialise them through `tempfile`
    only when httpx insists on file paths, and that scratch file is
    auto-removed when the spool closes).

    `key_password` is None for unencrypted keys (the common case); set
    when the operator stored a passphrase-protected key. The passphrase
    itself comes from a third SecretStore ref (not modelled yet —
    backlog).
    """

    cert_pem: str
    key_pem: str
    key_password: str | None = None


def _build_mtls_ssl_context(creds: MtlsClientCredential) -> ssl.SSLContext:
    """Build an `ssl.SSLContext` with the client cert chain loaded from
    in-memory PEM strings. Materialises through `tempfile.NamedTemporary
    File` because OpenSSL's `SSL_CTX_use_certificate_chain_file` /
    `_use_PrivateKey_file` only take file paths — there's no public
    `load_cert_chain_from_bytes` API on `ssl.SSLContext` as of 3.12.
    The scratch files are unlinked the moment `load_cert_chain` returns.
    """

    ctx = ssl.create_default_context()
    with (
        tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as cert_f,
        tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as key_f,
    ):
        cert_f.write(creds.cert_pem)
        key_f.write(creds.key_pem)
        cert_path, key_path = cert_f.name, key_f.name
    try:
        ctx.load_cert_chain(
            certfile=cert_path,
            keyfile=key_path,
            password=creds.key_password,
        )
    finally:
        # Unlink immediately — the SSLContext has already absorbed the
        # cert chain into its internal state.
        from os import unlink

        for path in (cert_path, key_path):
            try:
                unlink(path)
            except OSError:
                pass
    return ctx


class OutboundMcpClient(Protocol):
    async def initialize(self) -> InitializeResult:
        """Initialize an outbound MCP session."""

    async def list_tools(self) -> list[Tool]:
        """List tools exposed by the upstream MCP server."""

    async def list_resources(self) -> list[Resource]:
        """List resources exposed by the upstream MCP server."""

    async def list_prompts(self) -> list[Prompt]:
        """List prompts exposed by the upstream MCP server."""

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        inbound_headers: dict[str, str] | None = None,
        principal_id: UUID | None = None,
    ) -> CallToolResult:
        """Call an upstream MCP tool.

        `inbound_headers` carries the end user's per-request headers (from
        the inbound MCP client). The outbound implementation filters them
        through its `auth_passthrough_map` and forwards the matching ones
        to the upstream — the user-tier auth path. Implementations that
        don't support pass-through (stdio) ignore this parameter.

        `principal_id` is the authenticated end user's id, threaded
        through for phase-4 OAuth (per-user delegated tokens). Phase-3
        token providers ignore it; stdio implementations ignore it.
        """

    async def list_capabilities(
        self,
        *,
        principal_id: UUID | None = None,
    ) -> list[CapabilityDescriptor]:
        """List all upstream capabilities as registry descriptors.

        `principal_id` is consumed only by phase-4 OAuth-authcode
        upstreams (per-user delegated tokens) — sync needs an
        operator-resolved user with a stored token to authenticate
        the probe. Phase-3 / stdio implementations ignore it.
        """


class StreamableHttpMcpClient:
    """Outbound MCP client for Streamable HTTP servers.

    `extra_headers` are baked into the httpx client so they ride on every
    outbound request — the upstream MCP receives them on `initialize`,
    `tools/list`, `tools/call`, etc. Used to inject `Authorization: Bearer
    <resolved>` and similar credentials provided by the SecretStore.
    Header values are never logged.
    """

    def __init__(
        self,
        url: str,
        *,
        http_client: httpx.AsyncClient | None = None,
        read_timeout_seconds: float | None = 30.0,
        extra_headers: dict[str, str] | None = None,
        auth_passthrough_map: dict[str, str] | None = None,
        oauth_token_provider: OAuthTokenProvider | None = None,
        mtls_credential: MtlsClientCredential | None = None,
        ssrf_policy: UrlSecurityPolicy | None = None,
    ) -> None:
        self._url = url
        if http_client is not None and extra_headers:
            raise ValueError(
                "extra_headers cannot be combined with a caller-provided http_client; "
                "configure headers on the client instead"
            )
        if http_client is not None and mtls_credential is not None:
            raise ValueError(
                "mtls_credential cannot be combined with a caller-provided http_client; "
                "configure the SSL context on the client instead"
            )
        self._extra_headers = dict(extra_headers) if extra_headers else {}
        # mTLS context: built once at constructor time; httpx reuses
        # the underlying SSL session inside its connection pool. Cached
        # on the instance so the per-call (OAuth one-shot) httpx client
        # can re-use the same context — building a new SSLContext per
        # tool call would be a needless cost on the hot path.
        self._mtls_credential = mtls_credential
        self._mtls_ssl_context = (
            _build_mtls_ssl_context(mtls_credential)
            if mtls_credential is not None
            else None
        )
        client_kwargs: dict[str, Any] = {"headers": self._extra_headers or None}
        if self._mtls_ssl_context is not None:
            client_kwargs["verify"] = self._mtls_ssl_context
        # H1 · DNS-time SSRF backstop. Only applied to clients we own —
        # a caller-provided client (tests' ASGITransport, and any custom
        # transport stack) keeps whatever it was configured with.
        self._ssrf_policy = ssrf_policy
        if http_client is None and ssrf_policy is not None:
            client_kwargs["transport"] = SsrfGuardTransport(
                httpx.AsyncHTTPTransport(
                    verify=self._mtls_ssl_context
                    if self._mtls_ssl_context is not None
                    else True
                ),
                policy=ssrf_policy,
            )
        self._http_client = http_client or httpx.AsyncClient(**client_kwargs)
        self._owns_http_client = http_client is None
        # MCP-2 P2 · v1 wants a `timedelta` here, v2 a plain float. Getting
        # it wrong is not a type error at call time — v1 silently treats a
        # float as "no timeout" — so it goes through the shim.
        self._read_timeout = read_timeout_arg(read_timeout_seconds)
        # `{inbound_header_name → upstream_header_name}` (lower-cased on
        # the inbound side for case-insensitive matching against
        # Starlette's request.headers). Empty = no pass-through configured.
        self._auth_passthrough_map: dict[str, str] = (
            {k.lower(): v for k, v in auth_passthrough_map.items()}
            if auth_passthrough_map
            else {}
        )
        # OAuth client-credentials provider. When set, every call goes
        # through the one-shot session path so the rotating bearer token
        # never lives on the long-lived pooled httpx client. None = no
        # OAuth configured (org-tier static headers or no auth at all).
        self._oauth_token_provider = oauth_token_provider

    async def initialize(self) -> InitializeResult:
        async with self._session() as session:
            return await session.initialize()

    async def list_tools(self) -> list[Tool]:
        async with self._initialized_session() as session:
            result = await session.list_tools()
            return list(result.tools)

    async def list_resources(self) -> list[Resource]:
        async with self._initialized_session() as session:
            result = await session.list_resources()
            return list(result.resources)

    async def list_prompts(self) -> list[Prompt]:
        async with self._initialized_session() as session:
            result = await session.list_prompts()
            return list(result.prompts)

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        inbound_headers: dict[str, str] | None = None,
        principal_id: UUID | None = None,
    ) -> CallToolResult:
        try:
            return await self._call_tool_once(
                tool_name, arguments,
                inbound_headers=inbound_headers,
                principal_id=principal_id,
            )
        except Exception as exc:
            # A4 — 401-driven refresh. If the upstream rejected our
            # bearer (token expired / revoked between cache and call),
            # invalidate the OAuth provider's cache and retry once.
            # Single-flight via the provider's per-principal lock
            # (already enforced by the OAuth implementations); this
            # outer call never spins, just delegates.
            if (self._oauth_token_provider is not None
                    and _looks_like_unauthorized(exc)):
                logger.info(
                    "upstream_returned_401_refreshing_oauth_once",
                    extra={
                        "tool_name": tool_name,
                        "principal_id": str(principal_id) if principal_id else None,
                    },
                )
                await self._oauth_token_provider.invalidate(
                    principal_id=principal_id
                )
                return await self._call_tool_once(
                    tool_name, arguments,
                    inbound_headers=inbound_headers,
                    principal_id=principal_id,
                )
            raise

    async def _call_tool_once(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        inbound_headers: dict[str, str] | None = None,
        principal_id: UUID | None = None,
    ) -> CallToolResult:
        per_call = await self._build_per_call_overrides(
            inbound_headers, principal_id=principal_id
        )
        if not per_call:
            async with self._initialized_session() as session:
                return await session.call_tool(tool_name, arguments)
        # Per-call credential present (user-tier passthrough OR OAuth
        # bearer): spin up a one-shot httpx client with the merged
        # headers so the rotating credential never lives on the long-
        # lived pooled client.
        async with self._call_session(per_call) as session:
            return await session.call_tool(tool_name, arguments)

    async def _build_per_call_overrides(
        self,
        inbound_headers: dict[str, str] | None,
        *,
        principal_id: UUID | None = None,
    ) -> dict[str, str]:
        """Merge user-tier passthrough + OAuth bearer for one call.

        OAuth wins on Authorization (the schema validator already
        prevents auth_passthrough from also setting Authorization, so
        this is belt-and-braces). Returns `{}` when no per-call
        override is needed → the pooled fast path runs.

        `principal_id` flows through to `fetch_token` for phase-4
        OAuth (per-user delegated tokens). Phase-3 token providers
        ignore it.
        """

        overrides = self._select_passthrough(inbound_headers)
        if self._oauth_token_provider is not None:
            token = await self._oauth_token_provider.fetch_token(
                principal_id=principal_id
            )
            overrides["Authorization"] = f"Bearer {token}"
        return overrides

    async def list_capabilities(
        self,
        *,
        principal_id: UUID | None = None,
    ) -> list[CapabilityDescriptor]:
        """Probe the upstream for its tool / resource / prompt catalog.

        For phase-4 OAuth-authcode upstreams, capability sync needs an
        operator-resolved `principal_id` (any user with a stored token
        for this server) — without it, the upstream rejects the probe
        with 401. Phase-3 client-credentials and stdio implementations
        ignore the parameter; the bearer is fetched from the gateway-
        owned credential or env vars respectively.
        """

        per_call = await self._build_per_call_overrides(
            None, principal_id=principal_id
        )
        if not per_call:
            async with self._initialized_session() as session:
                tools = await _list_or_empty(session.list_tools, "tools")
                resources = await _list_or_empty(session.list_resources, "resources")
                prompts = await _list_or_empty(session.list_prompts, "prompts")
        else:
            async with self._call_session(per_call) as session:
                tools = await _list_or_empty(session.list_tools, "tools")
                resources = await _list_or_empty(session.list_resources, "resources")
                prompts = await _list_or_empty(session.list_prompts, "prompts")
        return _build_capability_descriptors(
            tools=tools, resources=resources, prompts=prompts
        )

    async def aclose(self) -> None:
        if self._owns_http_client:
            await self._http_client.aclose()

    def _select_passthrough(
        self, inbound_headers: dict[str, str] | None
    ) -> dict[str, str]:
        """Filter inbound headers through the configured `auth_passthrough_map`.

        Returns `{upstream_header: value}` for the matching entries. Header
        names are matched case-insensitively (Starlette lowercases them).
        Headers not in the configured map are dropped — never blindly
        forwarded.
        """

        if not self._auth_passthrough_map or not inbound_headers:
            return {}
        # Build a lower-cased view of the inbound side for the match.
        lowered = {k.lower(): v for k, v in inbound_headers.items()}
        out: dict[str, str] = {}
        for inbound_lower, upstream in self._auth_passthrough_map.items():
            value = lowered.get(inbound_lower)
            if value:
                out[upstream] = value
        return out

    @asynccontextmanager
    async def _call_session(
        self, passthrough: dict[str, str]
    ) -> AsyncIterator[ClientSession]:
        """Per-call session that merges org-tier `extra_headers` with the
        user-tier `passthrough` for this single tool invocation. Uses a
        one-shot httpx client so a leaked credential cannot bleed into
        another tenant or another user's connection.

        Mirrors the pooled client's transport (when caller-provided) so
        ASGI-transport tests and any custom transports still work — the
        only thing we override is the default headers map.
        """

        merged = {**self._extra_headers, **passthrough}
        # `_transport` is the httpx-private storage for the configured
        # transport. httpx 0.28 has no public getter; reading it is
        # stable and the trade-off is worth keeping the one-shot client
        # truly isolated rather than mutating the shared one.
        transport = getattr(self._http_client, "_transport", None)
        client_kwargs: dict[str, Any] = {"headers": merged}
        if transport is not None:
            client_kwargs["transport"] = transport
        if self._mtls_ssl_context is not None:
            client_kwargs["verify"] = self._mtls_ssl_context
        async with httpx.AsyncClient(**client_kwargs) as one_shot:
            async with open_streamable_http(
                self._url, http_client=one_shot
            ) as (read_stream, write_stream):
                async with ClientSession(
                    read_stream,
                    write_stream,
                    read_timeout_seconds=self._read_timeout,
                ) as session:
                    await session.initialize()
                    yield session

    @asynccontextmanager
    async def _initialized_session(self) -> AsyncIterator[ClientSession]:
        async with self._session() as session:
            await session.initialize()
            yield session

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[ClientSession]:
        async with open_streamable_http(
            self._url, http_client=self._http_client
        ) as (read_stream, write_stream):
            async with ClientSession(
                read_stream,
                write_stream,
                read_timeout_seconds=self._read_timeout,
            ) as session:
                yield session


class SseMcpClient:
    """Outbound MCP client for legacy Server-Sent Events servers.

    SSE was the original MCP transport; Streamable HTTP supersedes it
    in the current spec. A handful of public MCPs are still SSE-only
    (and a few enterprise vendors haven't migrated yet), so the gateway
    needs to speak both.

    Auth shape: SSE doesn't ride a long-lived httpx client like Streamable
    HTTP does — the SDK's `sse_client` accepts a flat `headers` dict on
    each session. So all auth (org-tier `extra_headers`, user-tier
    `auth_passthrough`, OAuth bearer) merges into the per-session headers.
    No pooled-vs-one-shot split here; SSE sessions are lighter than
    Streamable HTTP and rebuild per call anyway.
    """

    def __init__(
        self,
        url: str,
        *,
        read_timeout_seconds: float | None = 30.0,
        extra_headers: dict[str, str] | None = None,
        auth_passthrough_map: dict[str, str] | None = None,
        oauth_token_provider: OAuthTokenProvider | None = None,
        mtls_credential: MtlsClientCredential | None = None,
        ssrf_policy: UrlSecurityPolicy | None = None,
    ) -> None:
        self._url = url
        self._extra_headers = dict(extra_headers) if extra_headers else {}
        # MCP-2 P2 · v1 wants a `timedelta` here, v2 a plain float. Getting
        # it wrong is not a type error at call time — v1 silently treats a
        # float as "no timeout" — so it goes through the shim.
        self._read_timeout = read_timeout_arg(read_timeout_seconds)
        self._auth_passthrough_map: dict[str, str] = (
            {k.lower(): v for k, v in auth_passthrough_map.items()}
            if auth_passthrough_map
            else {}
        )
        self._oauth_token_provider = oauth_token_provider
        # Cached SSLContext for mTLS — passed to `sse_client` via a
        # custom `httpx_client_factory` so the client cert is presented
        # on every TLS handshake.
        self._mtls_ssl_context = (
            _build_mtls_ssl_context(mtls_credential)
            if mtls_credential is not None
            else None
        )
        # H1 · applied via the `httpx_client_factory` below, since
        # `sse_client` owns its own client construction.
        self._ssrf_policy = ssrf_policy

    async def initialize(self) -> InitializeResult:
        async with self._session({}) as session:
            return await session.initialize()

    async def list_tools(self) -> list[Tool]:
        async with self._initialized_session({}) as session:
            result = await session.list_tools()
            return list(result.tools)

    async def list_resources(self) -> list[Resource]:
        async with self._initialized_session({}) as session:
            result = await session.list_resources()
            return list(result.resources)

    async def list_prompts(self) -> list[Prompt]:
        async with self._initialized_session({}) as session:
            result = await session.list_prompts()
            return list(result.prompts)

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        inbound_headers: dict[str, str] | None = None,
        principal_id: UUID | None = None,
    ) -> CallToolResult:
        per_call = await self._build_per_call_overrides(
            inbound_headers, principal_id=principal_id
        )
        async with self._initialized_session(per_call) as session:
            return await session.call_tool(tool_name, arguments)

    async def list_capabilities(
        self,
        *,
        principal_id: UUID | None = None,
    ) -> list[CapabilityDescriptor]:
        per_call = await self._build_per_call_overrides(
            None, principal_id=principal_id
        )
        async with self._initialized_session(per_call) as session:
            tools = await _list_or_empty(session.list_tools, "tools")
            resources = await _list_or_empty(session.list_resources, "resources")
            prompts = await _list_or_empty(session.list_prompts, "prompts")
        return _build_capability_descriptors(
            tools=tools, resources=resources, prompts=prompts
        )

    async def aclose(self) -> None:
        """No persistent connection to close — SSE sessions are per-call."""

    async def _build_per_call_overrides(
        self,
        inbound_headers: dict[str, str] | None,
        *,
        principal_id: UUID | None = None,
    ) -> dict[str, str]:
        """Same merge logic as `StreamableHttpMcpClient`, with the OAuth
        bearer winning on Authorization (schema validator already
        prevents passthrough collision)."""

        overrides: dict[str, str] = {}
        if self._auth_passthrough_map and inbound_headers:
            lowered = {k.lower(): v for k, v in inbound_headers.items()}
            for inbound_lower, upstream in self._auth_passthrough_map.items():
                value = lowered.get(inbound_lower)
                if value:
                    overrides[upstream] = value
        if self._oauth_token_provider is not None:
            token = await self._oauth_token_provider.fetch_token(
                principal_id=principal_id
            )
            overrides["Authorization"] = f"Bearer {token}"
        return overrides

    @asynccontextmanager
    async def _initialized_session(
        self, per_call_overrides: dict[str, str]
    ) -> AsyncIterator[ClientSession]:
        async with self._session(per_call_overrides) as session:
            await session.initialize()
            yield session

    @asynccontextmanager
    async def _session(
        self, per_call_overrides: dict[str, str]
    ) -> AsyncIterator[ClientSession]:
        merged_headers = {**self._extra_headers, **per_call_overrides}
        kwargs: dict[str, Any] = {}
        if self._mtls_ssl_context is not None or self._ssrf_policy is not None:
            # Custom factory plumbs the cached SSL context and/or the H1
            # SSRF guard into every httpx client `sse_client` builds. The
            # signature matches `mcp.shared._httpx_utils.McpHttpClientFactory`.
            mtls_ctx = self._mtls_ssl_context
            ssrf_policy = self._ssrf_policy

            def _factory(
                headers: dict[str, str] | None = None,
                timeout: httpx.Timeout | None = None,
                auth: httpx.Auth | None = None,
            ) -> httpx.AsyncClient:
                verify: Any = mtls_ctx if mtls_ctx is not None else True
                client_kwargs: dict[str, Any] = {
                    "headers": headers,
                    "timeout": timeout if timeout is not None else httpx.Timeout(30.0),
                    "auth": auth,
                    "verify": verify,
                    "follow_redirects": True,
                }
                if ssrf_policy is not None:
                    client_kwargs["transport"] = SsrfGuardTransport(
                        httpx.AsyncHTTPTransport(verify=verify),
                        policy=ssrf_policy,
                    )
                return httpx.AsyncClient(**client_kwargs)

            kwargs["httpx_client_factory"] = _factory
        async with sse_client(
            self._url,
            headers=merged_headers if merged_headers else None,
            **kwargs,
        ) as (read_stream, write_stream):
            async with ClientSession(
                read_stream,
                write_stream,
                read_timeout_seconds=self._read_timeout,
            ) as session:
                yield session


class UpstreamClientBrokenError(Exception):
    """Raised when a `StdioMcpClient`'s persistent subprocess has died
    (or failed to start) and any further method calls would have to
    cold-spawn a new one.

    The pool's `discard=True` release path catches this, closes the
    broken client cleanly, and creates a fresh client on next acquire.
    Operators see the underlying cause via the `__cause__` chain
    (e.g. `BrokenPipeError`, `ConnectionResetError`,
    `UpstreamStartupDiagnosticError`).
    """


class StdioMcpClient:
    """Outbound MCP client for stdio servers — **persistent process**.

    Tier-2 stress-test fix. The previous implementation cold-spawned a
    fresh subprocess per call: every `call_tool` opened
    `stdio_client(...)` + `ClientSession(...)`, ran `initialize()`,
    sent the tool request, and tore everything down. uvx / npx
    cold-start dominated latency (~250 ms), capping per-server stdio
    RPS at ~5 regardless of pool size. The pool kept the wrapper but
    the wrapper held no live state.

    This rewrite holds the subprocess + session for the lifetime of
    the client. Behaviour:

    - Construction is sync (mirrors the previous API). The subprocess
      spawns lazily on first method call, OR explicitly via
      `await client.connect()` — pools call `connect()` so the slot is
      ready when a request lands on it.

    - A long-running supervisor task owns the lifecycle. It enters
      `stdio_client(...)` and `ClientSession(...)` once, runs
      `session.initialize()`, then awaits a stop signal. Caller tasks
      reference the live `ClientSession` via a thread-safe handle
      and call `session.call_tool(...)` directly. The MCP SDK's
      session is designed for cross-task usage — its receive-loop
      demuxes responses by JSON-RPC id internally.

    - On any transport error (broken pipe, EOF, transport-level
      exception), the client marks itself broken and propagates the
      underlying exception. The pool's `discard=True` flow then
      closes it (terminating the subprocess) and constructs a fresh
      client on next acquire.

    - `aclose()` actually terminates the subprocess now. The pool
      calls `aclose()` on discarded clients and on shutdown.

    Public API is unchanged from the previous (cold-spawn) version,
    so capability sync, the pool, the upstream provider, and tests
    keep working with zero call-site changes.

    Concurrency contract: many callers can safely call `call_tool`
    on one StdioMcpClient concurrently. The MCP SDK serializes the
    underlying stream writes; responses fan back out by request id.
    Whether *the upstream itself* serializes internally is the
    upstream's concern — the pool's `max_clients_per_upstream` knob
    spreads work across N persistent subprocesses for upstreams that
    are sync-blocking.

    Stderr safety: stderr is captured to a tempfile for the lifetime
    of the client. Surfaced in `UpstreamStartupDiagnosticError` ONLY
    if the supervisor exits abnormally (subprocess died during startup
    or mid-session). Healthy upstreams' stderr is discarded silently
    — same security posture as before.
    """

    def __init__(
        self,
        *,
        command: str,
        args: list[str] | None = None,
        read_timeout_seconds: float | None = 30.0,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self._command = command
        self._args = list(args or [])
        self._cwd = cwd
        self._env = dict(env) if env else None
        # MCP-2 P2 · v1 wants a `timedelta` here, v2 a plain float. Getting
        # it wrong is not a type error at call time — v1 silently treats a
        # float as "no timeout" — so it goes through the shim.
        self._read_timeout = read_timeout_arg(read_timeout_seconds)
        # Lifecycle state
        self._supervisor: asyncio.Task[None] | None = None
        self._connect_lock = asyncio.Lock()
        # Set by supervisor when ClientSession.initialize() completes.
        # Cleared on shutdown / failure.
        self._session: ClientSession | None = None
        self._initialize_result: InitializeResult | None = None
        # Set when supervisor reaches "ready" (session live OR died).
        self._ready = asyncio.Event()
        # Stop signal — set by aclose() to request graceful shutdown.
        self._stop = asyncio.Event()
        # Captured supervisor failure (if any). Surfaced when callers
        # try to use a broken client.
        self._supervisor_error: BaseException | None = None
        # `True` once the supervisor task has exited (cleanly or via
        # exception). Further method calls raise UpstreamClientBrokenError.
        self._closed = False

    # ------------------------------------------------------------------
    # Public API — call shape unchanged from cold-spawn version.
    # ------------------------------------------------------------------

    async def connect(self) -> InitializeResult:
        """Eagerly spawn the subprocess + run `initialize()`.

        Idempotent. The pool calls this when constructing a client so
        the first tool-call on the slot doesn't pay the cold-start
        latency. Direct callers (capability sync, health checks) can
        skip it; lazy connect kicks in on first method call.
        """
        await self._ensure_connected()
        # `_initialize_result` is set by the supervisor before the
        # ready event fires; if we're here, it's populated.
        assert self._initialize_result is not None
        return self._initialize_result

    async def initialize(self) -> InitializeResult:
        """Return the server's initialize result.

        With persistent state this is `connect()` for new clients
        (subprocess spawned + handshake run) or a cached return for
        already-connected clients.
        """
        return await self.connect()

    async def list_tools(self) -> list[Tool]:
        session = await self._ensure_connected()
        try:
            result = await session.list_tools()
            return list(result.tools)
        except BaseException:
            self._mark_broken()
            raise

    async def list_resources(self) -> list[Resource]:
        session = await self._ensure_connected()
        try:
            result = await session.list_resources()
            return list(result.resources)
        except BaseException:
            self._mark_broken()
            raise

    async def list_prompts(self) -> list[Prompt]:
        session = await self._ensure_connected()
        try:
            result = await session.list_prompts()
            return list(result.prompts)
        except BaseException:
            self._mark_broken()
            raise

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        inbound_headers: dict[str, str] | None = None,  # noqa: ARG002
        principal_id: UUID | None = None,  # noqa: ARG002
    ) -> CallToolResult:
        # Stdio doesn't have HTTP headers to pass through. Ignored on
        # purpose so the Protocol stays uniform across transports;
        # operators get a 422 at registration if they try to set
        # auth_passthrough on a stdio source.
        session = await self._ensure_connected()
        try:
            return await session.call_tool(tool_name, arguments)
        except BaseException:
            # Transport-level failure — mark broken so the pool's
            # discard path closes us and creates a fresh client.
            # Tool-level failures (upstream `isError=true`) come back
            # as a normal CallToolResult; only exceptions reach here.
            self._mark_broken()
            raise

    async def list_capabilities(
        self,
        *,
        principal_id: UUID | None = None,
    ) -> list[CapabilityDescriptor]:
        # Stdio doesn't have a per-user OAuth token concept (auth is
        # via env vars set at spawn). principal_id is accepted only
        # for Protocol conformance with the HTTP impl.
        del principal_id
        session = await self._ensure_connected()
        try:
            tools = await _list_or_empty(session.list_tools, "tools")
            resources = await _list_or_empty(session.list_resources, "resources")
            prompts = await _list_or_empty(session.list_prompts, "prompts")
        except BaseException:
            self._mark_broken()
            raise
        return _build_capability_descriptors(
            tools=tools, resources=resources, prompts=prompts
        )

    async def aclose(self) -> None:
        """Terminate the subprocess gracefully.

        Idempotent. Safe to call from any task — the supervisor task
        owns the actual context-manager teardown; we just signal it
        and wait. After `aclose()`, further method calls raise
        UpstreamClientBrokenError.
        """
        if self._supervisor is None:
            self._closed = True
            return
        self._stop.set()
        try:
            # Allow generous shutdown window — anyio's task-group
            # cleanup can take a moment as it cancels child tasks
            # (the receive loop, the subprocess monitor) and waits
            # for them to drain. If the upstream subprocess hangs on
            # SIGTERM, we cancel the supervisor outright.
            await asyncio.wait_for(self._supervisor, timeout=5.0)
        except TimeoutError:
            self._supervisor.cancel()
            try:
                await self._supervisor
            except (Exception, asyncio.CancelledError):
                # Supervisor's exception path already logged via the
                # supervisor body; swallow here so aclose() never
                # raises into the pool's release path.
                pass
        except (Exception, asyncio.CancelledError):
            pass
        finally:
            self._closed = True
            self._session = None
            self._supervisor = None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _ensure_connected(self) -> ClientSession:
        """Idempotent: if already connected, return the live session.
        If not yet connected, spawn the supervisor and wait for ready.
        Raises `UpstreamClientBrokenError` if the supervisor failed
        to start the subprocess or the subprocess has since died.
        """
        if self._closed:
            raise UpstreamClientBrokenError(
                "stdio client has been closed; pool will create a fresh client"
            )
        if self._session is not None:
            return self._session
        async with self._connect_lock:
            # Re-check after lock acquire — another task may have
            # connected while we were waiting.
            if self._session is not None:
                return self._session
            if self._closed:
                raise UpstreamClientBrokenError(
                    "stdio client closed during connect"
                )
            self._supervisor = asyncio.create_task(
                self._supervisor_loop(),
                name=f"stdio-supervisor:{self._command}",
            )
            await self._ready.wait()
            if self._supervisor_error is not None:
                # Preserve the cold-spawn exception contract:
                # `UpstreamStartupDiagnosticError` (with bounded stderr)
                # surfaces directly so operators see the actionable
                # message; other transport failures surface as their
                # original class. The pool's release path catches any
                # exception and discards the client either way.
                exc = self._supervisor_error
                # Reset state so the next call attempt creates a new
                # supervisor (allows transient-failure retry from a
                # fresh client at the pool level).
                self._closed = True
                self._session = None
                raise exc
            assert self._session is not None
            return self._session

    def _mark_broken(self) -> None:
        """Mark the client broken so the pool's release path discards it.
        Caller's exception propagates after this; the discard path then
        calls `aclose()` to terminate the subprocess.
        """
        self._closed = True
        self._session = None

    async def _supervisor_loop(self) -> None:
        """Long-running task that owns the subprocess + session lifecycle.

        Enters `stdio_client(...)` → `ClientSession(...)` →
        `initialize()`, then awaits the stop signal. On exit (normal
        or via exception), unwinds the contexts in reverse, which
        terminates the subprocess and cancels the receive loop.
        """
        parameters = StdioServerParameters(
            command=self._command,
            args=self._args,
            cwd=self._cwd,
            env=self._env,
        )
        try:
            with tempfile.TemporaryFile(
                mode="w+", encoding="utf-8", errors="replace"
            ) as errlog:
                try:
                    async with stdio_client(parameters, errlog=errlog) as (
                        read_stream,
                        write_stream,
                    ):
                        async with ClientSession(
                            read_stream,
                            write_stream,
                            read_timeout_seconds=self._read_timeout,
                        ) as session:
                            init_result = await session.initialize()
                            self._session = session
                            self._initialize_result = init_result
                            self._ready.set()
                            # Park here until aclose() signals shutdown
                            # OR a transport error trips _mark_broken().
                            # Either way, exiting this await unwinds
                            # the `async with` blocks above, which:
                            # - Cancels the ClientSession's receive-loop
                            # - Closes the read/write streams
                            # - Terminates the subprocess
                            await self._stop.wait()
                except BaseException as exc:
                    # Surface stderr if the subprocess wrote anything
                    # before dying — same posture as the prior
                    # cold-spawn implementation. Drill anyio task-group
                    # wrappers to the real cause.
                    inner: BaseException = exc
                    while (
                        isinstance(inner, BaseExceptionGroup)
                        and len(inner.exceptions) >= 1
                    ):
                        inner = inner.exceptions[0]
                    try:
                        errlog.seek(0)
                        raw = errlog.read(_STDERR_CAPTURE_BYTES * 4)
                    except OSError:
                        raw = ""
                    sanitized = _sanitize_stderr_capture(raw)
                    if sanitized:
                        diagnostic = UpstreamStartupDiagnosticError(
                            inner.__class__.__name__, sanitized
                        )
                        diagnostic.__cause__ = exc
                        self._supervisor_error = diagnostic
                    else:
                        self._supervisor_error = inner
                    raise
        except BaseException:
            # Caller side of `_ensure_connected()` may still be
            # awaiting `_ready` — release them so they raise rather
            # than hang forever.
            self._ready.set()
            # Don't re-raise: the supervisor task ending is normal
            # at shutdown. The captured `_supervisor_error` is what
            # callers consult.
            logger.debug(
                "stdio_supervisor_exited",
                extra={
                    "command": self._command,
                    "error": (
                        self._supervisor_error.__class__.__name__
                        if self._supervisor_error is not None else None
                    ),
                },
            )
        finally:
            self._session = None
            self._closed = True


async def _list_or_empty(
    list_call: Any, kind_label: str
) -> list[Any]:
    """Call an MCP `list_*` method, returning [] if the upstream lacks the method.

    Servers MAY omit any of tools/resources/prompts (the protocol's per-kind
    capability flags advertise this). Capability sync should still succeed
    for servers that only support a subset, so we map JSON-RPC -32601
    "Method not found" to an empty list and re-raise anything else.
    """
    try:
        result = await list_call()
    except McpError as exc:
        code = getattr(exc.error, "code", None)
        if code == _JSONRPC_METHOD_NOT_FOUND:
            return []
        raise
    items = getattr(result, kind_label, None)
    return list(items) if items is not None else []


def _build_capability_descriptors(
    *,
    tools: list[Tool],
    resources: list[Resource],
    prompts: list[Prompt],
) -> list[CapabilityDescriptor]:
    capabilities: list[CapabilityDescriptor] = []
    capabilities.extend(
        CapabilityDescriptor(
            kind=McpCapabilityKind.TOOL,
            name=tool.name,
            schema_json=_tool_schema(tool),
        )
        for tool in tools
    )
    capabilities.extend(
        CapabilityDescriptor(
            kind=McpCapabilityKind.RESOURCE,
            name=str(resource.uri),
            schema_json=_model_schema(resource),
        )
        for resource in resources
    )
    capabilities.extend(
        CapabilityDescriptor(
            kind=McpCapabilityKind.PROMPT,
            name=prompt.name,
            schema_json=_model_schema(prompt),
        )
        for prompt in prompts
    )
    return capabilities


def _tool_schema(tool: Tool) -> dict[str, Any]:
    # The KEYS here are our own `mcp_capabilities.schema_json` storage
    # format and stay camelCase across SDK versions — a persisted row must
    # not change shape because a dependency was upgraded. Only the VALUES
    # come from the SDK, so only those go through the shim.
    schema: dict[str, Any] = {"inputSchema": tool_input_schema(tool)}
    output_schema = sdk_field(tool, "output_schema")
    if output_schema is not None:
        schema["outputSchema"] = output_schema
    if tool.description is not None:
        schema["description"] = tool.description
    if tool.title is not None:
        schema["title"] = tool.title
    return schema


def _model_schema(model: Resource | Prompt) -> dict[str, Any]:
    return model.model_dump(mode="json", exclude_none=True)
