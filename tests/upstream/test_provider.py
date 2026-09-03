"""Unit tests for `DatabaseBackedUpstreamClientProvider`.

These tests exercise the lookup path and error semantics with a fake DB
session — they do not need real Postgres. The integration test that proves
the provider talks to a real Streamable HTTP MCP server lives in
`tests/upstream/test_inbound_outbound_round_trip.py` (run via the inbound
endpoint integration test, which exercises the full request → lifecycle →
provider → upstream path end-to-end).
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import uuid4

import pytest

from vyuu_gateway.db.models import (
    McpServer,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
)
from vyuu_gateway.mcp.outbound import StdioMcpClient, StreamableHttpMcpClient
from vyuu_gateway.mcp.sdk_compat import read_timeout_arg
from vyuu_gateway.upstream.pool import PooledOutboundMcpClient
from vyuu_gateway.upstream.provider import (
    DatabaseBackedUpstreamClientProvider,
    InvalidStdioServerConfigError,
    StdioLaunchPolicy,
    UpstreamServerNotFoundError,
)


class _FakeUpstreamSession:
    """Fake Session: context manager, supports `scalar`, has `.info`."""

    def __init__(self, server: McpServer | None) -> None:
        self.server = server
        self.info: dict[str, Any] = {}
        self.scalar_calls: list[Any] = []

    def __enter__(self) -> _FakeUpstreamSession:
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def scalar(self, statement: Any) -> McpServer | None:
        self.scalar_calls.append(statement)
        return self.server


def _factory_returning(session: _FakeUpstreamSession) -> Any:
    def make() -> _FakeUpstreamSession:
        return session

    return make


def _server(
    *,
    server_id: Any | None = None,
    tenant_id: Any | None = None,
    transport: McpTransport = McpTransport.STREAMABLE_HTTP,
    source_location: str = "https://upstream.example/mcp",
    source_type: McpServerSourceType = McpServerSourceType.HTTP,
    args: list[str] | None = None,
    auth_headers: dict[str, str] | None = None,
    auth_env: dict[str, str] | None = None,
) -> McpServer:
    return McpServer(
        id=server_id or uuid4(),
        tenant_id=tenant_id or uuid4(),
        display_name="upstream",
        source_type=source_type,
        source_location=source_location,
        transport=transport,
        args=args or [],
        auth_headers=auth_headers or {},
        auth_env=auth_env or {},
        registered_by=uuid4(),
        health_status=McpServerHealthStatus.UNKNOWN,
    )


def _pooled(client: object) -> PooledOutboundMcpClient:
    assert isinstance(client, PooledOutboundMcpClient)
    return client


def _build_underlying(client: object) -> Any:
    """Synchronously build the wrapped client a `PooledOutboundMcpClient`'s
    factory would create. `_factory` is async (so it can resolve secrets);
    these tests only care about what it produces, not the awaitable."""

    pooled = _pooled(client)

    async def _run() -> Any:
        return await pooled._factory()  # noqa: SLF001

    return asyncio.run(_run())


def _close_sync(client: object) -> None:
    aclose = getattr(client, "aclose", None)
    if callable(aclose):
        asyncio.run(aclose())


def test_get_client_constructs_streamable_http_client_for_registered_server() -> None:
    server = _server(source_location="https://upstream.example/mcp")
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    client = provider.get_client(server.tenant_id, server.id)

    pooled = _pooled(client)
    assert pooled.key.tenant_id == server.tenant_id
    assert pooled.key.server_id == server.id
    assert pooled.key.transport == McpTransport.STREAMABLE_HTTP
    underlying = _build_underlying(pooled)
    try:
        assert isinstance(underlying, StreamableHttpMcpClient)
        assert underlying._url == "https://upstream.example/mcp"  # noqa: SLF001
    finally:
        _close_sync(underlying)


def test_get_client_caches_pooled_clients_per_tenant_server() -> None:
    server = _server()
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    first = provider.get_client(server.tenant_id, server.id)
    second = provider.get_client(server.tenant_id, server.id)

    assert first is second
    # Cached path must not re-query the DB.
    assert len(session.scalar_calls) == 1


def test_get_client_cache_is_tenant_scoped() -> None:
    server_id = uuid4()
    tenant_a = uuid4()
    tenant_b = uuid4()
    server_a = _server(server_id=server_id, tenant_id=tenant_a)
    server_b = _server(server_id=server_id, tenant_id=tenant_b)
    factory_calls: list[McpServer | None] = [server_a, server_b]

    def session_for_next() -> Any:
        return _FakeUpstreamSession(factory_calls.pop(0))

    provider = DatabaseBackedUpstreamClientProvider(session_for_next)

    client_a = provider.get_client(tenant_a, server_id)
    client_b = provider.get_client(tenant_b, server_id)

    assert client_a is not client_b
    assert _pooled(client_a).key.tenant_id == tenant_a
    assert _pooled(client_b).key.tenant_id == tenant_b


def test_get_client_passes_configured_read_timeout_to_streamable_http_client() -> None:

    server = _server()
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(
        _factory_returning(session),
        read_timeout_seconds=5.0,
    )

    client = provider.get_client(server.tenant_id, server.id)

    underlying = _build_underlying(client)
    try:
        assert isinstance(underlying, StreamableHttpMcpClient)
        # MCP-2 P2 · timedelta on v1, float on v2 — assert against the shim
        # rather than hard-coding either spelling.
        assert underlying._read_timeout == read_timeout_arg(5.0)  # noqa: SLF001
    finally:
        _close_sync(underlying)


def test_get_client_filters_by_tenant_id_and_server_id() -> None:
    server = _server()
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    provider.get_client(server.tenant_id, server.id)

    sql = str(session.scalar_calls[0])
    assert "mcp_servers.tenant_id" in sql
    assert "mcp_servers.id" in sql


def test_get_client_binds_tenant_context_on_lookup_session() -> None:
    """RLS depends on the lookup session having `app.current_tenant_id` set.
    The provider must bind the tenant before issuing the SELECT, otherwise a
    NOBYPASSRLS role would see zero rows and the lookup would 404 on a row
    that actually exists."""
    server = _server()
    session = _FakeUpstreamSession(server)
    tenant_id = server.tenant_id
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    provider.get_client(tenant_id, server.id)

    assert session.info["tenant_id"] == tenant_id


def test_get_client_raises_when_server_not_found() -> None:
    session = _FakeUpstreamSession(server=None)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    with pytest.raises(UpstreamServerNotFoundError):
        provider.get_client(uuid4(), uuid4())


def test_get_client_constructs_stdio_client_for_stdio_server() -> None:
    server = _server(
        source_type=McpServerSourceType.STDIO,
        source_location="python3",
        transport=McpTransport.STDIO,
        args=["-m", "fake_server"],
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    client = provider.get_client(server.tenant_id, server.id)

    underlying = _build_underlying(client)
    assert isinstance(underlying, StdioMcpClient)
    assert underlying._command == "python3"  # noqa: SLF001
    assert underlying._args == ["-m", "fake_server"]  # noqa: SLF001


def test_get_client_constructs_stdio_client_for_npm_server_via_npx() -> None:
    server = _server(
        source_type=McpServerSourceType.NPM,
        source_location="@modelcontextprotocol/server-filesystem",
        transport=McpTransport.STDIO,
        args=["/tmp"],
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    client = provider.get_client(server.tenant_id, server.id)

    underlying = _build_underlying(client)
    assert isinstance(underlying, StdioMcpClient)
    assert underlying._command == "npx"  # noqa: SLF001
    assert underlying._args == ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]  # noqa: SLF001


def test_get_client_constructs_stdio_client_for_pypi_server_via_uvx() -> None:
    """`pypi` is the Python parallel of `npm` — `uvx <package>` resolves+runs."""
    server = _server(
        source_type=McpServerSourceType.PYPI,
        source_location="mcp-server-time",
        transport=McpTransport.STDIO,
        args=["--local-timezone", "UTC"],
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    client = provider.get_client(server.tenant_id, server.id)

    underlying = _build_underlying(client)
    assert isinstance(underlying, StdioMcpClient)
    assert underlying._command == "uvx"  # noqa: SLF001
    # No `-y` — uvx never prompts; package name first, then user args.
    assert underlying._args == [  # noqa: SLF001
        "mcp-server-time",
        "--local-timezone",
        "UTC",
    ]


def test_get_client_allows_pypi_version_pin() -> None:
    """`package@version` syntax must be accepted so prod can pin upstreams."""
    server = _server(
        source_type=McpServerSourceType.PYPI,
        source_location="crowdstrike-falcon-mcp@1.4.0",
        transport=McpTransport.STDIO,
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    client = provider.get_client(server.tenant_id, server.id)
    underlying = _build_underlying(client)
    assert isinstance(underlying, StdioMcpClient)
    assert underlying._args == ["crowdstrike-falcon-mcp@1.4.0"]  # noqa: SLF001


def test_invalid_pypi_package_is_rejected() -> None:
    server = _server(
        source_type=McpServerSourceType.PYPI,
        source_location="../etc/passwd",
        transport=McpTransport.STDIO,
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    with pytest.raises(InvalidStdioServerConfigError):
        provider.get_client(server.tenant_id, server.id)


def test_get_client_allows_explicit_absolute_stdio_command() -> None:
    server = _server(
        source_type=McpServerSourceType.STDIO,
        source_location="/usr/local/bin/custom-mcp",
        transport=McpTransport.STDIO,
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(
        _factory_returning(session),
        stdio_launch_policy=StdioLaunchPolicy(
            allowed_commands=("/usr/local/bin/custom-mcp",),
            allow_absolute_commands=True,
        ),
    )

    client = provider.get_client(server.tenant_id, server.id)

    underlying = _build_underlying(client)
    assert isinstance(underlying, StdioMcpClient)
    assert underlying._command == "/usr/local/bin/custom-mcp"  # noqa: SLF001


def test_invalid_config_failure_is_not_cached() -> None:
    """A failed config (invalid stdio command) must NOT poison the cache —
    if the operator fixes the config and retries, the next call must
    re-resolve. Tests the cache invariant generically."""
    server = _server(
        source_type=McpServerSourceType.STDIO,
        source_location="python3 -m fake_server",  # has a space → rejected
        transport=McpTransport.STDIO,
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    with pytest.raises(InvalidStdioServerConfigError):
        provider.get_client(server.tenant_id, server.id)
    assert (server.tenant_id, server.id) not in provider._clients_by_lookup_key  # noqa: SLF001


def test_get_client_constructs_sse_client_for_sse_transport() -> None:
    """SSE is the legacy MCP transport; some public + enterprise servers
    haven't migrated to Streamable HTTP. Provider must build an
    `SseMcpClient` for HTTP source types with `transport=sse`."""
    from vyuu_gateway.mcp.outbound import SseMcpClient

    server = _server(
        transport=McpTransport.SSE,
        source_location="https://legacy.example/sse",
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    client = provider.get_client(server.tenant_id, server.id)
    underlying = _build_underlying(client)
    try:
        assert isinstance(underlying, SseMcpClient)
        assert underlying._url == "https://legacy.example/sse"  # noqa: SLF001
    finally:
        _close_sync(underlying)


def test_invalid_stdio_command_is_rejected_and_not_cached() -> None:
    server = _server(
        source_type=McpServerSourceType.STDIO,
        source_location="python3 -m fake_server",
        transport=McpTransport.STDIO,
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    with pytest.raises(InvalidStdioServerConfigError):
        provider.get_client(server.tenant_id, server.id)

    assert (server.tenant_id, server.id) not in provider._clients_by_lookup_key  # noqa: SLF001


def test_get_client_constructs_stdio_client_for_binary_source() -> None:
    """`binary` source type — pre-installed native executable. Distinct
    from `stdio` (which is for relative-name commands from a curated
    allowlist). Source location is the absolute path."""
    # Point at a real executable that exists on every Unix box. The
    # validator checks existence + exec bit; a non-real path would be
    # rejected by `validate_binary_path`.
    binary_path = "/usr/bin/env"
    server = _server(
        source_type=McpServerSourceType.BINARY,
        source_location=binary_path,
        transport=McpTransport.STDIO,
        args=["python3", "-m", "fake_server"],
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    client = provider.get_client(server.tenant_id, server.id)
    underlying = _build_underlying(client)
    try:
        assert isinstance(underlying, StdioMcpClient)
        assert underlying._command == binary_path  # noqa: SLF001
        assert underlying._args == [  # noqa: SLF001
            "python3",
            "-m",
            "fake_server",
        ]
    finally:
        _close_sync(underlying)


def test_binary_source_rejects_relative_path() -> None:
    server = _server(
        source_type=McpServerSourceType.BINARY,
        source_location="relative/path/binary",
        transport=McpTransport.STDIO,
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    with pytest.raises(InvalidStdioServerConfigError, match="absolute"):
        provider.get_client(server.tenant_id, server.id)


def test_binary_source_rejects_path_traversal() -> None:
    """Reject `..` segments in the registered path even if they would
    resolve to a legitimate location — the resolved location depends on
    filesystem state at the moment of resolution, so this can't be
    safely allowed."""
    server = _server(
        source_type=McpServerSourceType.BINARY,
        source_location="/opt/connectors/../bin/sh",
        transport=McpTransport.STDIO,
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    with pytest.raises(InvalidStdioServerConfigError, match=".."):
        provider.get_client(server.tenant_id, server.id)


def test_binary_source_rejects_nonexistent_path() -> None:
    server = _server(
        source_type=McpServerSourceType.BINARY,
        source_location="/nonexistent/path/that/does/not/exist/foo-mcp",
        transport=McpTransport.STDIO,
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    with pytest.raises(InvalidStdioServerConfigError, match="does not exist"):
        provider.get_client(server.tenant_id, server.id)


def test_binary_source_rejects_shell_metacharacters() -> None:
    server = _server(
        source_type=McpServerSourceType.BINARY,
        source_location="/usr/bin/env; rm -rf /",
        transport=McpTransport.STDIO,
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    with pytest.raises(InvalidStdioServerConfigError):
        provider.get_client(server.tenant_id, server.id)


def test_binary_source_honors_allowlist_when_configured() -> None:
    """Production sets `allowed_binary_paths` to the explicit list of
    vendor binaries in the gateway image. Anything else gets rejected
    even if it exists and is executable."""
    server = _server(
        source_type=McpServerSourceType.BINARY,
        source_location="/usr/bin/env",  # exists + executable
        transport=McpTransport.STDIO,
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(
        _factory_returning(session),
        stdio_launch_policy=StdioLaunchPolicy(
            allowed_binary_paths=("/opt/vyuu/connectors/falcon-mcp",),
        ),
    )

    with pytest.raises(InvalidStdioServerConfigError, match="allowlist"):
        provider.get_client(server.tenant_id, server.id)


def test_invalid_npm_package_is_rejected() -> None:
    server = _server(
        source_type=McpServerSourceType.NPM,
        source_location="https://example.com/package.tgz",
        transport=McpTransport.STDIO,
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    with pytest.raises(InvalidStdioServerConfigError):
        provider.get_client(server.tenant_id, server.id)


def test_get_client_resolves_auth_headers_and_passes_to_http_client() -> None:
    """For HTTP transports, `auth_headers` refs are resolved through the
    SecretStore and baked into the outbound httpx client. Used to inject
    `Authorization: Bearer <resolved>` for SaaS MCPs (PayPal, Wiz, etc.).
    """
    from vyuu_gateway.secrets import InMemorySecretStore

    tenant_id = uuid4()
    server = _server(
        tenant_id=tenant_id,
        auth_headers={
            "Authorization": "paypal-bearer",
            "X-Trace-Id": "trace-ref",
        },
    )
    session = _FakeUpstreamSession(server)
    secret_store = InMemorySecretStore()
    secret_store.put(tenant_id, "paypal-bearer", "Bearer s3cret")
    secret_store.put(tenant_id, "trace-ref", "trace-abc")
    provider = DatabaseBackedUpstreamClientProvider(
        _factory_returning(session),
        secret_store=secret_store,
    )

    client = provider.get_client(server.tenant_id, server.id)
    underlying = _build_underlying(client)

    try:
        assert isinstance(underlying, StreamableHttpMcpClient)
        # The httpx client must carry the resolved values, not the refs.
        sent_headers = dict(underlying._http_client.headers)  # noqa: SLF001
        assert sent_headers["authorization"] == "Bearer s3cret"
        assert sent_headers["x-trace-id"] == "trace-abc"
    finally:
        _close_sync(underlying)


def test_get_client_resolves_auth_env_and_passes_to_stdio_subprocess() -> None:
    """For stdio transports, `auth_env` refs are resolved via the SecretStore
    and injected into the spawned subprocess's env. Used for CrowdStrike
    Falcon MCP and similar (FALCON_CLIENT_ID, FALCON_CLIENT_SECRET).
    """
    from vyuu_gateway.secrets import InMemorySecretStore

    tenant_id = uuid4()
    server = _server(
        tenant_id=tenant_id,
        source_type=McpServerSourceType.PYPI,
        source_location="crowdstrike-falcon-mcp",
        transport=McpTransport.STDIO,
        auth_env={
            "FALCON_CLIENT_ID": "falcon-id-ref",
            "FALCON_CLIENT_SECRET": "falcon-secret-ref",
        },
    )
    session = _FakeUpstreamSession(server)
    secret_store = InMemorySecretStore()
    secret_store.put(tenant_id, "falcon-id-ref", "abcd1234")
    secret_store.put(tenant_id, "falcon-secret-ref", "wxyz9999")
    provider = DatabaseBackedUpstreamClientProvider(
        _factory_returning(session),
        secret_store=secret_store,
    )

    client = provider.get_client(server.tenant_id, server.id)
    underlying = _build_underlying(client)
    assert isinstance(underlying, StdioMcpClient)
    assert underlying._env == {  # noqa: SLF001
        "FALCON_CLIENT_ID": "abcd1234",
        "FALCON_CLIENT_SECRET": "wxyz9999",
    }


def test_get_client_builds_oauth_provider_when_auth_oauth_configured() -> None:
    """When `auth_oauth` is set on the server row, the provider must
    construct a CachedOAuthTokenProvider and pass it to the outbound
    HTTP client. Reused across builds so the in-memory token cache
    survives circuit-breaker / pool-reconnect cycles."""
    from vyuu_gateway.secrets import InMemorySecretStore
    from vyuu_gateway.upstream.oauth import CachedOAuthTokenProvider

    tenant_id = uuid4()
    oauth_spec = {
        "token_url": "https://auth.example/token",
        "client_id_ref": "client-id-ref",
        "client_secret_ref": "client-secret-ref",
        "audience": "https://api.example",
    }
    server = _server(tenant_id=tenant_id)
    server.auth_oauth = oauth_spec
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(
        _factory_returning(session),
        secret_store=InMemorySecretStore(),
    )

    client = provider.get_client(server.tenant_id, server.id)
    underlying = _build_underlying(client)

    try:
        assert isinstance(underlying, StreamableHttpMcpClient)
        token_provider = underlying._oauth_token_provider  # noqa: SLF001
        assert isinstance(token_provider, CachedOAuthTokenProvider)
        # Same provider instance returned on a re-build (token-cache
        # warm-keeping). Probe via the private cache key.
        cached = provider._oauth_providers[(tenant_id, server.id)]  # noqa: SLF001
        assert cached is token_provider
    finally:
        _close_sync(underlying)


def test_get_client_omits_oauth_provider_when_auth_oauth_unset() -> None:
    server = _server()  # default: auth_oauth=None
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    client = provider.get_client(server.tenant_id, server.id)
    underlying = _build_underlying(client)

    try:
        assert isinstance(underlying, StreamableHttpMcpClient)
        assert underlying._oauth_token_provider is None  # noqa: SLF001
    finally:
        _close_sync(underlying)


def test_get_client_propagates_secret_not_found_to_caller() -> None:
    """A missing secret ref must raise rather than silently produce a
    client without the credential — the caller's existing 502 wrapper
    surfaces the failure to the operator at sync time.
    """
    from vyuu_gateway.secrets import InMemorySecretStore, SecretNotFoundError

    tenant_id = uuid4()
    server = _server(
        tenant_id=tenant_id,
        auth_headers={"Authorization": "missing-ref"},
    )
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(
        _factory_returning(session),
        secret_store=InMemorySecretStore(),  # nothing seeded
    )

    client = provider.get_client(server.tenant_id, server.id)

    with pytest.raises(SecretNotFoundError):
        _build_underlying(client)


def test_get_auth_mode_flags_returns_all_false_for_naked_server() -> None:
    """A5 — server with no auth columns set → all-False flags."""
    server = _server()  # default: no auth_headers / auth_passthrough / auth_oauth
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))
    flags = provider.get_auth_mode_flags(server.tenant_id, server.id)
    assert flags.auth_org_tier is False
    assert flags.auth_user_tier_passthrough is False
    assert flags.auth_oauth_client_credentials is False


def test_get_auth_mode_flags_marks_org_tier_when_auth_headers_set() -> None:
    server = _server(auth_headers={"Authorization": "x"})
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))
    flags = provider.get_auth_mode_flags(server.tenant_id, server.id)
    assert flags.auth_org_tier is True
    assert flags.auth_user_tier_passthrough is False
    assert flags.auth_oauth_client_credentials is False


def test_get_auth_mode_flags_marks_passthrough_and_oauth_when_set() -> None:
    server = _server()
    server.auth_passthrough = {"x-vyuu-token": "Authorization"}
    server.auth_oauth = {
        "token_url": "https://auth.example/token",
        "client_id_ref": "id",
        "client_secret_ref": "secret",
    }
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))
    flags = provider.get_auth_mode_flags(server.tenant_id, server.id)
    assert flags.auth_user_tier_passthrough is True
    assert flags.auth_oauth_client_credentials is True


def test_get_auth_mode_flags_returns_all_false_when_server_missing() -> None:
    """Soft-fail: when the server row can't be looked up (already-deleted,
    or denied before the upstream check), flags must default to all-False
    rather than raising. Auditing must never break the request path."""
    session = _FakeUpstreamSession(None)  # lookup returns None
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))
    flags = provider.get_auth_mode_flags(uuid4(), uuid4())
    assert flags.auth_org_tier is False
    assert flags.auth_user_tier_passthrough is False
    assert flags.auth_oauth_client_credentials is False


# --- A1: per-user authorization-code path ---------------------------------


def _authcode_spec() -> dict[str, Any]:
    return {
        "auth_url": "https://idp.example/authorize",
        "token_url": "https://idp.example/token",
        "client_id_ref": "id-ref",
        "client_secret_ref": "secret-ref",
        "redirect_uri": "https://gateway.example/callback",
        "scopes": ["user:read"],
    }


def test_get_client_builds_authcode_provider_when_auth_authcode_configured() -> None:
    """When `auth_authcode` is set, the provider must construct an
    OAuthAuthCodeTokenProvider (not the M2M client-credentials one)
    and pass it to the outbound HTTP client."""
    from vyuu_gateway.secrets import InMemorySecretStore
    from vyuu_gateway.upstream.oauth_authcode import OAuthAuthCodeTokenProvider

    tenant_id = uuid4()
    server = _server(tenant_id=tenant_id)
    server.auth_authcode = _authcode_spec()
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(
        _factory_returning(session),
        secret_store=InMemorySecretStore(),
    )

    client = provider.get_client(server.tenant_id, server.id)
    underlying = _build_underlying(client)

    try:
        assert isinstance(underlying, StreamableHttpMcpClient)
        token_provider = underlying._oauth_token_provider  # noqa: SLF001
        assert isinstance(token_provider, OAuthAuthCodeTokenProvider)
        # Same provider instance returned on a re-build (per-user lock
        # state must persist across pool rebuilds — otherwise concurrent
        # callers would each get their own lock and the single-flight
        # collapse would be defeated).
        cached = provider._oauth_providers[(tenant_id, server.id)]  # noqa: SLF001
        assert cached is token_provider
    finally:
        _close_sync(underlying)


def test_get_auth_mode_flags_marks_authcode_when_auth_authcode_set() -> None:
    """A1 — `auth_oauth_authcode=True` gets stamped on every audit
    event for a server using the per-user OAuth flow. Operators query
    by it to find which servers are gating tool calls on per-user
    consent."""
    server = _server()
    server.auth_authcode = _authcode_spec()
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))
    flags = provider.get_auth_mode_flags(server.tenant_id, server.id)
    assert flags.auth_oauth_authcode is True
    # Other flags must remain off — auth_authcode shouldn't accidentally
    # also imply auth_oauth (those are mutually exclusive at schema
    # level, but the audit flag should reflect that).
    assert flags.auth_oauth_client_credentials is False
    assert flags.auth_org_tier is False
    assert flags.auth_user_tier_passthrough is False


def test_get_auth_mode_flags_authcode_default_false_for_naked_server() -> None:
    server = _server()
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))
    flags = provider.get_auth_mode_flags(server.tenant_id, server.id)
    assert flags.auth_oauth_authcode is False


# --- H6: header-value templating -------------------------------------------


def test_h6_template_substitutes_secret_ref_into_header_value() -> None:
    """`{secret:foo}` placeholders are replaced by the resolved secret."""
    from vyuu_gateway.secrets import InMemorySecretStore

    tenant_id = uuid4()
    server = _server(
        tenant_id=tenant_id,
        auth_headers={"Authorization": "Bearer {secret:paypal-token}"},
    )
    session = _FakeUpstreamSession(server)
    secret_store = InMemorySecretStore()
    secret_store.put(tenant_id, "paypal-token", "abc123")
    provider = DatabaseBackedUpstreamClientProvider(
        _factory_returning(session),
        secret_store=secret_store,
    )

    client = provider.get_client(server.tenant_id, server.id)
    underlying = _build_underlying(client)
    try:
        assert isinstance(underlying, StreamableHttpMcpClient)
        sent_headers = dict(underlying._http_client.headers)  # noqa: SLF001
        # Resolved value should include the literal "Bearer " + the secret.
        assert sent_headers["authorization"] == "Bearer abc123"
    finally:
        _close_sync(underlying)


def test_h6_bare_ref_remains_backward_compatible() -> None:
    """Pre-H6 config used the whole header value as a bare ref. With no
    `{secret:...}` placeholder we must keep that behavior so existing
    deployments don't break."""
    from vyuu_gateway.secrets import InMemorySecretStore

    tenant_id = uuid4()
    server = _server(
        tenant_id=tenant_id,
        auth_headers={"Authorization": "paypal-bearer"},
    )
    session = _FakeUpstreamSession(server)
    secret_store = InMemorySecretStore()
    secret_store.put(tenant_id, "paypal-bearer", "Bearer s3cret")
    provider = DatabaseBackedUpstreamClientProvider(
        _factory_returning(session),
        secret_store=secret_store,
    )

    client = provider.get_client(server.tenant_id, server.id)
    underlying = _build_underlying(client)
    try:
        sent_headers = dict(underlying._http_client.headers)  # noqa: SLF001
        # Whole secret = "Bearer s3cret", same as the ref content.
        assert sent_headers["authorization"] == "Bearer s3cret"
    finally:
        _close_sync(underlying)


def test_h6_multiple_placeholders_in_one_value() -> None:
    """Two `{secret:...}` placeholders in a single header value resolve
    independently. Useful for `Basic {secret:user}:{secret:pass}` style."""
    from vyuu_gateway.secrets import InMemorySecretStore

    tenant_id = uuid4()
    server = _server(
        tenant_id=tenant_id,
        auth_headers={"X-Multi": "v={secret:a}/{secret:b}"},
    )
    session = _FakeUpstreamSession(server)
    secret_store = InMemorySecretStore()
    secret_store.put(tenant_id, "a", "alpha")
    secret_store.put(tenant_id, "b", "beta")
    provider = DatabaseBackedUpstreamClientProvider(
        _factory_returning(session),
        secret_store=secret_store,
    )

    client = provider.get_client(server.tenant_id, server.id)
    underlying = _build_underlying(client)
    try:
        sent_headers = dict(underlying._http_client.headers)  # noqa: SLF001
        assert sent_headers["x-multi"] == "v=alpha/beta"
    finally:
        _close_sync(underlying)


# --- H4: per-package allowlist ---------------------------------------------


def test_h4_npm_allowlist_rejects_unlisted_package() -> None:
    policy = StdioLaunchPolicy(
        allowed_npm_packages=("@modelcontextprotocol/server-postgres",),
    )
    with pytest.raises(InvalidStdioServerConfigError):
        policy.validate_npm_package("@evil/totally-fine-name")


def test_h4_npm_allowlist_accepts_listed_package() -> None:
    policy = StdioLaunchPolicy(
        allowed_npm_packages=("@modelcontextprotocol/server-postgres",),
    )
    policy.validate_npm_package("@modelcontextprotocol/server-postgres")


def test_h4_npm_empty_allowlist_keeps_lab_default() -> None:
    """Empty `allowed_npm_packages` = no content allowlist (lab default).
    Any name-shape-valid package passes."""
    policy = StdioLaunchPolicy()  # default allowed_npm_packages = ()
    policy.validate_npm_package("@drawio/mcp")
    policy.validate_npm_package("some-random-package")


def test_h4_pypi_allowlist_pinned_version_rejects_mismatched_pin() -> None:
    """Allowlist with a `pkg@version` entry rejects the same package
    with a different version pin OR no pin at all."""
    policy = StdioLaunchPolicy(
        allowed_pypi_packages=("crowdstrike-falcon-mcp@1.4.0",),
    )
    policy.validate_pypi_package("crowdstrike-falcon-mcp@1.4.0")
    with pytest.raises(InvalidStdioServerConfigError):
        policy.validate_pypi_package("crowdstrike-falcon-mcp@1.5.0")
    with pytest.raises(InvalidStdioServerConfigError):
        policy.validate_pypi_package("crowdstrike-falcon-mcp")


def test_lookup_session_factory_is_invoked_per_uncached_call() -> None:
    server_a = _server()
    server_b = _server()
    factory_calls: list[McpServer | None] = []

    def session_for_next() -> Any:
        # Alternate the response each time to simulate two distinct lookups.
        next_server = factory_calls.pop(0)
        return _FakeUpstreamSession(next_server)

    factory_calls.extend([server_a, server_b])
    provider = DatabaseBackedUpstreamClientProvider(session_for_next)

    provider.get_client(server_a.tenant_id, server_a.id)
    provider.get_client(server_b.tenant_id, server_b.id)

    assert factory_calls == []


# --- M-A1.5: mTLS upstream cert + key plumbing -----------------------------


def _generate_self_signed_pem() -> tuple[str, str]:
    """Generate a self-signed RSA cert + private key in PEM form.

    Used by mTLS plumbing tests that need real cryptographic material
    so `ssl.SSLContext.load_cert_chain` actually accepts the inputs —
    a hand-rolled fake PEM blob would fail OpenSSL's parser before we
    could assert anything useful about provider wiring.
    """

    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vyuu-test-mtls")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def test_get_client_resolves_mtls_refs_and_passes_credential_to_streamable_http() -> None:
    """When `mtls_cert_ref` + `mtls_key_ref` are set on the server, the
    provider must resolve the PEM blobs through the SecretStore and
    hand them to `StreamableHttpMcpClient` as a `MtlsClientCredential`.
    The downstream client builds the SSLContext at construction time —
    we assert the credential reached the client, not the SSLContext
    internals (those are OpenSSL's domain)."""

    from vyuu_gateway.mcp.outbound import MtlsClientCredential
    from vyuu_gateway.secrets import InMemorySecretStore

    cert_pem, key_pem = _generate_self_signed_pem()
    tenant_id = uuid4()
    server = _server(tenant_id=tenant_id)
    server.mtls_cert_ref = "corp-cert"
    server.mtls_key_ref = "corp-key"
    secret_store = InMemorySecretStore()
    secret_store.put(tenant_id, "corp-cert", cert_pem)
    secret_store.put(tenant_id, "corp-key", key_pem)
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(
        _factory_returning(session),
        secret_store=secret_store,
    )

    client = provider.get_client(tenant_id, server.id)
    underlying = _build_underlying(client)

    try:
        assert isinstance(underlying, StreamableHttpMcpClient)
        # Credential is held on the client and the SSL context built
        # from it is non-None — confirms the cert chain loaded.
        cred = underlying._mtls_credential  # noqa: SLF001
        assert isinstance(cred, MtlsClientCredential)
        assert cred.cert_pem == cert_pem
        assert cred.key_pem == key_pem
        assert underlying._mtls_ssl_context is not None  # noqa: SLF001
    finally:
        _close_sync(underlying)


def test_get_client_omits_mtls_when_refs_unset() -> None:
    """No mTLS refs → `mtls_credential` is None and no SSL context is
    built. The default httpx TLS verification still runs (the default
    `verify=True` uses the system CA bundle)."""

    server = _server()  # default: mtls_cert_ref / mtls_key_ref are None
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))

    client = provider.get_client(server.tenant_id, server.id)
    underlying = _build_underlying(client)

    try:
        assert isinstance(underlying, StreamableHttpMcpClient)
        assert underlying._mtls_credential is None  # noqa: SLF001
        assert underlying._mtls_ssl_context is None  # noqa: SLF001
    finally:
        _close_sync(underlying)


def test_get_client_raises_when_only_one_mtls_ref_is_set() -> None:
    """Half-configured mTLS (one ref set, the other null) is rejected
    at the provider build stage. Schema validation already catches this
    at registration, but a row mutated via direct SQL could still hit
    the provider — defense in depth."""

    from vyuu_gateway.secrets import InMemorySecretStore
    from vyuu_gateway.upstream.provider import InvalidMtlsConfigError

    tenant_id = uuid4()
    server = _server(tenant_id=tenant_id)
    server.mtls_cert_ref = "cert-only"
    # mtls_key_ref left as None → half-configured.
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(
        _factory_returning(session),
        secret_store=InMemorySecretStore(),
    )

    client = provider.get_client(server.tenant_id, server.id)
    with pytest.raises(InvalidMtlsConfigError):
        _build_underlying(client)


def test_get_client_builds_jwt_bearer_provider_when_auth_jwt_bearer_configured() -> None:
    """A2: when auth_jwt_bearer is set, the provider must construct an
    OAuthJwtBearerTokenProvider (not the M2M client-credentials one,
    not the per-user authcode one) and pass it to the outbound
    client."""
    from vyuu_gateway.secrets import InMemorySecretStore
    from vyuu_gateway.upstream.oauth_jwt_bearer import OAuthJwtBearerTokenProvider

    tenant_id = uuid4()
    server = _server(tenant_id=tenant_id)
    server.auth_jwt_bearer = {
        "token_url": "https://oauth2.googleapis.com/token",
        "algorithm": "RS256",
        "private_key_ref": "sa-key-ref",
        "issuer": "sa@example.iam.gserviceaccount.com",
        "subject": "sa@example.iam.gserviceaccount.com",
        "audience": "https://oauth2.googleapis.com/token",
        "scope": "https://www.googleapis.com/auth/drive.readonly",
        "additional_claims": {},
        "assertion_ttl_seconds": 60,
    }
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(
        _factory_returning(session),
        secret_store=InMemorySecretStore(),
    )

    client = provider.get_client(server.tenant_id, server.id)
    underlying = _build_underlying(client)

    try:
        assert isinstance(underlying, StreamableHttpMcpClient)
        token_provider = underlying._oauth_token_provider  # noqa: SLF001
        assert isinstance(token_provider, OAuthJwtBearerTokenProvider)
        # Per-(tenant, server) cache so the access-token cache survives
        # circuit-breaker / pool rebuilds.
        cached = provider._oauth_providers[(tenant_id, server.id)]  # noqa: SLF001
        assert cached is token_provider
    finally:
        _close_sync(underlying)


def test_get_auth_mode_flags_marks_jwt_bearer_when_configured() -> None:
    """auth_oauth_jwt_bearer flag fires on every audit event for a
    server using the JWT-bearer flow."""
    server = _server()
    server.auth_jwt_bearer = {
        "token_url": "https://idp.example/token",
        "algorithm": "RS256",
        "private_key_ref": "k",
        "issuer": "iss",
        "subject": "sub",
        "audience": "aud",
    }
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))
    flags = provider.get_auth_mode_flags(server.tenant_id, server.id)
    assert flags.auth_oauth_jwt_bearer is True
    assert flags.auth_oauth_client_credentials is False
    assert flags.auth_oauth_authcode is False


def test_get_auth_mode_flags_marks_mtls_when_both_refs_set() -> None:
    """auth_mtls flag fires only when both cert + key refs are set —
    half-configured state should not flip the flag."""
    server = _server()
    server.mtls_cert_ref = "cert"
    server.mtls_key_ref = "key"
    session = _FakeUpstreamSession(server)
    provider = DatabaseBackedUpstreamClientProvider(_factory_returning(session))
    flags = provider.get_auth_mode_flags(server.tenant_id, server.id)
    assert flags.auth_mtls is True

    server2 = _server()
    server2.mtls_cert_ref = "cert"
    # mtls_key_ref left None → half-configured
    flags2 = DatabaseBackedUpstreamClientProvider(
        _factory_returning(_FakeUpstreamSession(server2))
    ).get_auth_mode_flags(server2.tenant_id, server2.id)
    assert flags2.auth_mtls is False
