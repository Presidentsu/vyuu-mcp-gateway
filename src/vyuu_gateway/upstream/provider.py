"""DB-backed implementation of `UpstreamToolClientProvider`.

The lifecycle calls `get_client(tenant_id, server_id)` to get an MCP client
for the upstream server backing a resolved tool. This module looks the row up
in `mcp_servers` (tenant-filtered AND RLS-bound) and returns a transport-typed
client.

Why a separate session: the inbound-MCP route already holds a tenant-bound DB
session, but the upstream provider is constructed at app start, not per
request, so it can't capture that session. Instead it opens its own session
per lookup and re-binds the tenant — `bind_tenant_context` ensures the new
session's transaction sets the same `app.current_tenant_id` GUC, so RLS
applies. The `tenant_id == ...` filter on the SELECT is defence-in-depth on
top of RLS; either alone is sufficient.

v1 supports Streamable HTTP, SSE (legacy), and stdio outbound. npm- and
PyPI-published servers are launched through `npx -y <package>` /
`uvx <package>` respectively and use the same stdio transport.
`UnsupportedUpstreamTransportError` is now a defensive fallthrough — fires
only if a new transport gets added to the enum without a matching branch.

Pooling: provider returns a tenant-scoped pooled proxy. The underlying pool is
bounded per `(tenant_id, server_id, transport)` so a hot upstream cannot create
unbounded outbound clients and cache keys cannot cross tenant boundaries.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.audit.events import AuthModeFlags
from vyuu_gateway.db.models import McpServer, McpServerSourceType, McpTransport
from vyuu_gateway.db.session import bind_tenant_context
from vyuu_gateway.mcp.outbound import (
    MtlsClientCredential,
    OutboundMcpClient,
    SseMcpClient,
    StdioMcpClient,
    StreamableHttpMcpClient,
)
from vyuu_gateway.registry.url_security import UrlSecurityPolicy
from vyuu_gateway.secrets import InMemorySecretStore, SecretStore
from vyuu_gateway.upstream.binary_provenance import CosignPolicy, verify_binary
from vyuu_gateway.upstream.circuit_breaker import UpstreamCircuitBreakerRegistry
from vyuu_gateway.upstream.oauth import (
    CachedOAuthTokenProvider,
    OAuthClientCredentialsConfig,
    OAuthTokenProvider,
)
from vyuu_gateway.upstream.pool import (
    PooledOutboundMcpClient,
    UpstreamClientPool,
    UpstreamPoolKey,
)

logger = logging.getLogger(__name__)

# H6: header-value templating. Matches `{secret:ref-name}` placeholders.
# Refs allow alphanumerics, `-`, `_`, `.`, `/`, `:` (the same chars secret
# stores typically accept) plus `@` for k8s-style namespaced refs.
_SECRET_TEMPLATE_RE = re.compile(r"\{secret:([A-Za-z0-9_\-./:@]*)\}")


class UpstreamServerNotFoundError(Exception):
    """The (tenant_id, server_id) pair does not resolve to a registered server."""


class UnsupportedUpstreamTransportError(Exception):
    """Server is registered but its transport is not yet implemented."""


class InvalidStdioServerConfigError(Exception):
    """Stdio upstream command or package configuration is unsafe or invalid."""


class InvalidMtlsConfigError(Exception):
    """mTLS cert/key ref pair is half-configured (one set, one unset)."""


# `SessionLocal()` (sessionmaker instance) returns a SQLAlchemy `Session`,
# which is itself a context manager — production satisfies this directly.
SessionFactory = Callable[[], Session]

_NPM_PACKAGE_RE = re.compile(
    r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*(?:@[a-zA-Z0-9._~^*-]+)?$"
)

# PEP 508 / PEP 503 distribution name (case-insensitive), optionally
# followed by a `@version` pin understood by `uvx`. Examples that match:
#   mcp-server-time, mcp_server_time, FastMCP, crowdstrike-falcon-mcp@1.4.0
# Rejected: leading dot/hyphen, embedded spaces, path traversal, shell
# metacharacters, scoped npm syntax.
_PYPI_PACKAGE_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
    r"(?:@[A-Za-z0-9][A-Za-z0-9._+!-]*)?$"
)


@dataclass(frozen=True)
class StdioLaunchPolicy:
    """Conservative launch policy for local stdio upstream processes.

    Commands are executed without a shell, but the gateway still restricts
    what can be spawned. Production deployments should replace the defaults
    with an allowlist matching the deployment image.
    """

    allowed_commands: tuple[str, ...] = ("python", "python3", "node", "npx", "uvx")
    allow_absolute_commands: bool = False
    # Optional per-deployment allowlist of absolute binary paths the
    # gateway may launch via `source_type=binary`. Empty tuple = any
    # absolute path that passes shape checks is allowed (lab default).
    # Production sets this to the explicit list of vendor binaries the
    # gateway image ships with (e.g. ("/opt/vyuu/connectors/falcon-mcp",)).
    allowed_binary_paths: tuple[str, ...] = ()
    # H4: optional per-deployment content allowlist for stdio packages.
    # Empty tuple = any name-shape-valid package is allowed (lab default).
    # Production sets these to the exact set of packages the operator
    # has audited and approved — no other names can be registered, even
    # if they're well-formed npm / pypi identifiers. Versions for pypi
    # may be pinned in the entry: ("crowdstrike-falcon-mcp@1.4.0",).
    allowed_npm_packages: tuple[str, ...] = ()
    allowed_pypi_packages: tuple[str, ...] = ()

    def validate_command(self, command: str) -> None:
        if not command or "\x00" in command:
            raise InvalidStdioServerConfigError("stdio command is empty or invalid")
        if any(char.isspace() for char in command):
            raise InvalidStdioServerConfigError(
                "stdio command must be an executable; pass arguments separately"
            )

        path = Path(command)
        if path.is_absolute():
            if self.allow_absolute_commands and command in self.allowed_commands:
                return
            raise InvalidStdioServerConfigError("absolute stdio command is not allowlisted")

        if "/" in command or "\\" in command:
            raise InvalidStdioServerConfigError("relative stdio paths are not allowed")
        if command not in self.allowed_commands:
            raise InvalidStdioServerConfigError("stdio command is not allowlisted")

    def validate_args(self, args: list[str]) -> None:
        for arg in args:
            if not arg or "\x00" in arg:
                raise InvalidStdioServerConfigError("stdio args contain an invalid entry")

    def validate_npm_package(self, package: str) -> None:
        if not _NPM_PACKAGE_RE.fullmatch(package):
            raise InvalidStdioServerConfigError("npm package name is invalid")
        if self.allowed_npm_packages and package not in self.allowed_npm_packages:
            raise InvalidStdioServerConfigError(
                "npm package is not in the deployment allowlist"
            )

    def validate_pypi_package(self, package: str) -> None:
        """Validate a PyPI distribution name (optionally `pkg@version` pin).

        Two-layer check:
        1. Name shape via `_PYPI_PACKAGE_RE`.
        2. (H4) If `allowed_pypi_packages` is non-empty, the package
           string must match an entry verbatim — including any
           `@version` pin. So a deployment that allowlists
           `crowdstrike-falcon-mcp@1.4.0` will reject both
           `crowdstrike-falcon-mcp` (no pin) and
           `crowdstrike-falcon-mcp@1.5.0` (different pin). Production
           pins versions to lock supply chain.
        """

        if not _PYPI_PACKAGE_RE.fullmatch(package):
            raise InvalidStdioServerConfigError("pypi package name is invalid")
        if self.allowed_pypi_packages and package not in self.allowed_pypi_packages:
            raise InvalidStdioServerConfigError(
                "pypi package is not in the deployment allowlist"
            )

    def validate_binary_path(self, binary_path: str) -> None:
        """Validate an absolute path to a pre-installed executable.

        The `binary` source type is for vendor-shipped native binaries
        (e.g. older CrowdStrike connectors, Cloudflare Rust MCPs). Path
        must be:
        - non-empty, no NUL byte, no shell metacharacters
        - absolute (no `..`-traversal, no relative path)
        - resolved (no symlink that escapes its directory)
        - exist on disk
        - executable by the gateway process

        And, if `allowed_binary_paths` is configured, the path must
        match one of the entries verbatim (defense in depth — operator
        can't register `/usr/bin/sh` even if it exists and is executable).

        Symlinks: we resolve the path before the existence/exec check
        so a symlink pointing into a privileged dir gets caught. The
        ALLOWLIST check uses the *un-resolved* path so operators see
        the same string they registered.
        """

        if not binary_path or "\x00" in binary_path:
            raise InvalidStdioServerConfigError("binary path is empty or invalid")
        if any(char.isspace() for char in binary_path):
            raise InvalidStdioServerConfigError(
                "binary path must not contain whitespace; pass args separately"
            )
        if any(c in binary_path for c in (";", "&", "|", "$", "`", "<", ">")):
            raise InvalidStdioServerConfigError(
                "binary path contains shell metacharacters"
            )

        path = Path(binary_path)
        if not path.is_absolute():
            raise InvalidStdioServerConfigError("binary path must be absolute")
        # Reject any `..` segment in the original input — even if it
        # resolves to a legitimate path. Defense against path traversal
        # tricks where the resolved location depends on file-system state.
        if ".." in path.parts:
            raise InvalidStdioServerConfigError("binary path must not contain '..'")

        if self.allowed_binary_paths and binary_path not in self.allowed_binary_paths:
            raise InvalidStdioServerConfigError(
                "binary path is not on the allowlist"
            )

        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise InvalidStdioServerConfigError(
                f"binary path does not exist: {binary_path}"
            ) from exc
        if not resolved.is_file():
            raise InvalidStdioServerConfigError("binary path is not a regular file")
        if not os.access(resolved, os.X_OK):
            raise InvalidStdioServerConfigError("binary is not executable")


class DatabaseBackedUpstreamClientProvider:
    """Resolves `(tenant_id, server_id) → MCP client` via the registry."""

    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        read_timeout_seconds: float | None = 30.0,
        stdio_launch_policy: StdioLaunchPolicy | None = None,
        upstream_pool: UpstreamClientPool | None = None,
        circuit_breakers: UpstreamCircuitBreakerRegistry | None = None,
        max_clients_per_upstream: int = 4,
        client_max_age_seconds: float | None = None,
        cosign_policy: CosignPolicy | None = None,
        secret_store: SecretStore | None = None,
        ssrf_policy: UrlSecurityPolicy | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._read_timeout_seconds = read_timeout_seconds
        # H1 · DNS-time SSRF backstop, applied to HTTP/SSE upstreams at
        # connect time. None disables it (tests, and any deployment that
        # sets VYUU_UPSTREAM_SSRF_GUARD_ENABLED=false).
        self._ssrf_policy = ssrf_policy
        self._stdio_launch_policy = stdio_launch_policy or StdioLaunchPolicy()
        # S1.b · disabled by default, which is the pre-S1.b behaviour.
        self._cosign_policy = cosign_policy or CosignPolicy()
        self._pool = upstream_pool or UpstreamClientPool(
            max_clients_per_upstream=max_clients_per_upstream,
            # P2 · bound how long a pooled client carries the credential
            # it was built with. `None` disables.
            client_max_age_seconds=client_max_age_seconds,
        )
        self._circuit_breakers = circuit_breakers or UpstreamCircuitBreakerRegistry()
        self._clients_by_lookup_key: dict[tuple[UUID, UUID], PooledOutboundMcpClient] = {}
        # Resolves `auth_headers` / `auth_env` secret refs at client-build
        # time. Defaults to an in-memory store with no entries — operators
        # who haven't wired auth yet behave exactly as before.
        self._secret_store = secret_store or InMemorySecretStore()
        # Per-(tenant, server) OAuth token providers. Cached so the
        # access-token cache survives pool client reconnects — otherwise
        # a circuit-breaker reset would refetch tokens unnecessarily.
        self._oauth_providers: dict[tuple[UUID, UUID], OAuthTokenProvider] = {}

    def get_client(self, tenant_id: UUID, server_id: UUID) -> OutboundMcpClient:
        lookup_key = (tenant_id, server_id)
        cached = self._clients_by_lookup_key.get(lookup_key)
        if cached is not None:
            return cached

        server = self._lookup_server(tenant_id, server_id)
        self._validate_supported(server)
        pool_key = UpstreamPoolKey(
            tenant_id=tenant_id,
            server_id=server_id,
            transport=server.transport,
        )
        client = PooledOutboundMcpClient(
            key=pool_key,
            pool=self._pool,
            factory=lambda: self._build_client(server),
            circuit_breakers=self._circuit_breakers,
        )
        self._clients_by_lookup_key[lookup_key] = client
        return client

    async def aclose(self) -> None:
        await self._pool.close_all()

    async def forget_server(self, tenant_id: UUID, server_id: UUID) -> None:
        """Tear down every pooled client for a server that is going away.

        For an stdio upstream, a pooled client owns a live subprocess
        (`uvx` / `npx` / a raw binary). Deleting the server row removed
        the registry entry but nothing told the pool, so those processes
        kept running — holding the credentials they were spawned with,
        and surviving until the gateway itself restarted. A deployment
        that registered and deleted stdio servers a few times accumulated
        orphans indefinitely.

        Safe to call for a server that was never connected to: the
        memo is populated by `get_client`, and pool state only ever
        appears for a key that has a memo entry, so a missing memo means
        there is nothing to close.

        In-flight calls are not interrupted. `close_key` marks the pool
        state closing and closes idle clients now; `release` closes the
        rest as each call finishes.
        """

        lookup_key = (tenant_id, server_id)
        self._oauth_providers.pop(lookup_key, None)
        client = self._clients_by_lookup_key.pop(lookup_key, None)
        if client is None:
            return
        await self._pool.close_key(client.key)

    def get_auth_mode_flags(
        self, tenant_id: UUID, server_id: UUID
    ) -> AuthModeFlags:
        """Return which outbound-auth modes are configured for this
        upstream. Lifecycle calls this once per tool-call so the audit
        event can record whether org-tier headers / passthrough / OAuth
        client-credentials actually fired. Soft-fails to all-False if
        the server can't be looked up — auditing must not break the
        request when the server row is gone (already-deleted, or denied
        before the upstream check)."""

        try:
            server = self._lookup_server(tenant_id, server_id)
        except UpstreamServerNotFoundError:
            return AuthModeFlags()
        return AuthModeFlags(
            auth_org_tier=bool(server.auth_headers or server.auth_env),
            auth_user_tier_passthrough=bool(server.auth_passthrough),
            auth_oauth_client_credentials=bool(server.auth_oauth),
            auth_oauth_authcode=bool(server.auth_authcode),
            auth_oauth_jwt_bearer=bool(server.auth_jwt_bearer),
            auth_mtls=bool(server.mtls_cert_ref and server.mtls_key_ref),
        )

    def _validate_supported(self, server: McpServer) -> None:
        if server.transport == McpTransport.STREAMABLE_HTTP:
            return
        if server.transport == McpTransport.SSE:
            # Legacy MCP transport; superseded by Streamable HTTP in the
            # current spec but still in use by some public + enterprise
            # MCPs. Auth shape mirrors StreamableHttpMcpClient.
            return
        if server.transport == McpTransport.STDIO:
            if server.source_type == McpServerSourceType.NPM:
                self._stdio_launch_policy.validate_command("npx")
                self._stdio_launch_policy.validate_npm_package(server.source_location)
                self._stdio_launch_policy.validate_args(server.args)
                return
            if server.source_type == McpServerSourceType.PYPI:
                self._stdio_launch_policy.validate_command("uvx")
                self._stdio_launch_policy.validate_pypi_package(server.source_location)
                self._stdio_launch_policy.validate_args(server.args)
                return
            if server.source_type == McpServerSourceType.STDIO:
                self._stdio_launch_policy.validate_command(server.source_location)
                self._stdio_launch_policy.validate_args(server.args)
                return
            if server.source_type == McpServerSourceType.BINARY:
                self._stdio_launch_policy.validate_binary_path(server.source_location)
                self._stdio_launch_policy.validate_args(server.args)
                return
            raise InvalidStdioServerConfigError(
                "stdio transport requires npm, pypi, stdio, or binary source_type"
            )

        raise UnsupportedUpstreamTransportError(
            f"upstream transport {server.transport.value!r} is not yet supported"
        )

    async def _build_client(self, server: McpServer) -> OutboundMcpClient:
        if server.transport == McpTransport.STREAMABLE_HTTP:
            extra_headers = await self._resolve_auth_map(server, server.auth_headers)
            oauth_provider = self._build_oauth_provider(server)
            mtls = await self._resolve_mtls_credential(server)
            return StreamableHttpMcpClient(
                server.source_location,
                read_timeout_seconds=self._read_timeout_seconds,
                extra_headers=extra_headers or None,
                auth_passthrough_map=server.auth_passthrough or None,
                oauth_token_provider=oauth_provider,
                mtls_credential=mtls,
                ssrf_policy=self._ssrf_policy,
            )

        if server.transport == McpTransport.SSE:
            extra_headers = await self._resolve_auth_map(server, server.auth_headers)
            oauth_provider = self._build_oauth_provider(server)
            mtls = await self._resolve_mtls_credential(server)
            return SseMcpClient(
                server.source_location,
                read_timeout_seconds=self._read_timeout_seconds,
                extra_headers=extra_headers or None,
                auth_passthrough_map=server.auth_passthrough or None,
                oauth_token_provider=oauth_provider,
                mtls_credential=mtls,
                ssrf_policy=self._ssrf_policy,
            )

        if server.transport == McpTransport.STDIO:
            return await self._build_stdio_client(server)

        raise UnsupportedUpstreamTransportError(
            f"upstream transport {server.transport.value!r} is not yet supported"
        )

    async def _build_stdio_client(self, server: McpServer) -> StdioMcpClient:
        env = await self._resolve_auth_map(server, server.auth_env)

        if server.source_type == McpServerSourceType.NPM:
            self._stdio_launch_policy.validate_command("npx")
            self._stdio_launch_policy.validate_npm_package(server.source_location)
            self._stdio_launch_policy.validate_args(server.args)
            return StdioMcpClient(
                command="npx",
                args=["-y", server.source_location, *server.args],
                read_timeout_seconds=self._read_timeout_seconds,
                env=env or None,
            )

        if server.source_type == McpServerSourceType.PYPI:
            # `uvx <package>` resolves+downloads from PyPI into an ephemeral
            # isolated venv and runs the package's console script. No `-y`
            # equivalent — uvx never prompts. `package@version` is honored
            # by the regex, so production registrations should pin.
            self._stdio_launch_policy.validate_command("uvx")
            self._stdio_launch_policy.validate_pypi_package(server.source_location)
            self._stdio_launch_policy.validate_args(server.args)
            return StdioMcpClient(
                command="uvx",
                args=[server.source_location, *server.args],
                read_timeout_seconds=self._read_timeout_seconds,
                env=env or None,
            )

        if server.source_type == McpServerSourceType.STDIO:
            self._stdio_launch_policy.validate_command(server.source_location)
            self._stdio_launch_policy.validate_args(server.args)
            return StdioMcpClient(
                command=server.source_location,
                args=server.args,
                read_timeout_seconds=self._read_timeout_seconds,
                env=env or None,
            )

        if server.source_type == McpServerSourceType.BINARY:
            # Pre-installed native binary (vendor connectors, etc.).
            # `validate_binary_path` already confirmed absolute, exists,
            # executable, no metacharacters / path traversal, and that
            # it's on the operator allowlist if configured.
            self._stdio_launch_policy.validate_binary_path(server.source_location)
            # S1.b · path validation answers "is this a sane path?"; it
            # cannot answer "is this the file the vendor shipped?".
            # `binary` is the one source type where we execute code we
            # did not fetch, so provenance is checked HERE — at every
            # client build — rather than only at registration. The whole
            # threat is the file changing after it was approved.
            #
            # No-op unless the deployment configured a verification key.
            await verify_binary(server.source_location, self._cosign_policy)
            self._stdio_launch_policy.validate_args(server.args)
            return StdioMcpClient(
                command=server.source_location,
                args=server.args,
                read_timeout_seconds=self._read_timeout_seconds,
                env=env or None,
            )

        raise InvalidStdioServerConfigError(
            "stdio transport requires npm, pypi, stdio, or binary source_type"
        )

    def _build_oauth_provider(
        self, server: McpServer
    ) -> OAuthTokenProvider | None:
        """Return a token provider for `server`, or None if OAuth isn't
        configured. Two grants supported (mutually exclusive per
        schema validation):

        - **`auth_oauth`** — phase 3 client-credentials. One gateway-
          owned credential serves all callers. Cached per
          (tenant, server).
        - **`auth_authcode`** — phase 4 authorization-code (per-user
          delegated tokens). Provider is cached per (tenant, server)
          but `fetch_token(principal_id=...)` looks up the calling
          user's row in `oauth_user_tokens` per call.
        """

        key = (server.tenant_id, server.id)
        cached = self._oauth_providers.get(key)
        if cached is not None:
            return cached

        if server.auth_oauth:
            spec = server.auth_oauth
            config = OAuthClientCredentialsConfig(
                token_url=spec["token_url"],
                client_id_ref=spec["client_id_ref"],
                client_secret_ref=spec["client_secret_ref"],
                scope=spec.get("scope"),
                audience=spec.get("audience"),
            )
            cc_provider = CachedOAuthTokenProvider(
                config=config,
                tenant_id=server.tenant_id,
                secret_store=self._secret_store,
            )
            self._oauth_providers[key] = cc_provider
            return cc_provider

        if server.auth_authcode:
            from vyuu_gateway.upstream.oauth_authcode import (
                OAuthAuthCodeConfig,
                OAuthAuthCodeTokenProvider,
            )

            spec_ac = server.auth_authcode
            ac_config = OAuthAuthCodeConfig(
                # In DCR mode these fields may be empty strings — the
                # provider resolves credentials + token_url from
                # `mcp_server_dcr_clients` instead.
                auth_url=spec_ac.get("auth_url", ""),
                token_url=spec_ac.get("token_url", ""),
                client_id_ref=spec_ac.get("client_id_ref", ""),
                client_secret_ref=spec_ac.get("client_secret_ref", ""),
                redirect_uri=spec_ac["redirect_uri"],
                scopes=tuple(spec_ac.get("scopes") or ()),
                dcr_enabled=bool(spec_ac.get("dcr_enabled", False)),
            )
            ac_provider = OAuthAuthCodeTokenProvider(
                config=ac_config,
                tenant_id=server.tenant_id,
                server_id=server.id,
                secret_store=self._secret_store,
                db_session_factory=self._session_factory,
            )
            self._oauth_providers[key] = ac_provider
            return ac_provider

        if server.auth_jwt_bearer:
            # Lazy import keeps the PyJWT crypto extras off the
            # import-time hot path for deployments that don't use this
            # mode.
            from vyuu_gateway.upstream.oauth_jwt_bearer import (
                OAuthJwtBearerConfig,
                OAuthJwtBearerTokenProvider,
            )

            spec_jb = server.auth_jwt_bearer
            jb_config = OAuthJwtBearerConfig(
                token_url=spec_jb["token_url"],
                algorithm=spec_jb["algorithm"],
                private_key_ref=spec_jb["private_key_ref"],
                issuer=spec_jb["issuer"],
                subject=spec_jb["subject"],
                audience=spec_jb["audience"],
                scope=spec_jb.get("scope"),
                additional_claims=dict(spec_jb.get("additional_claims") or {}),
                assertion_ttl_seconds=int(spec_jb.get("assertion_ttl_seconds") or 60),
                key_id=spec_jb.get("key_id"),
            )
            jb_provider = OAuthJwtBearerTokenProvider(
                config=jb_config,
                tenant_id=server.tenant_id,
                secret_store=self._secret_store,
            )
            self._oauth_providers[key] = jb_provider
            return jb_provider

        return None

    async def _resolve_auth_map(
        self, server: McpServer, refs: dict[str, str]
    ) -> dict[str, str]:
        """Resolve a `{name: value-template}` map to `{name: value}` via
        the store.

        Two value shapes are supported (auto-detected — H6):

        1. **Bare ref** (backward compatible): `"paypal-bearer"` resolves
           to the secret stored under `paypal-bearer`. The whole secret
           value becomes the header / env value.
        2. **Template**: `"Bearer {secret:paypal-token}"` resolves the
           inner ref and substitutes it. Multiple placeholders allowed
           in one value: `"{secret:user}:{secret:pass}"`.

        Detection rule: if `{secret:...}` appears anywhere in the value,
        it's a template; otherwise the whole value is a bare ref.

        Why H6 matters: under the bare-ref model, operators store the
        FULL header value in the secret store (`Bearer eyJ...`). With
        templates, the secret holds only the raw token — cleaner secret
        hygiene and less coupling between the secret content and how it's
        eventually composed into a header.

        Returns `{}` for an empty input. Raises `SecretNotFoundError`
        (surfaced as 502 via `_upstream_sync_error`) on any unresolved ref.
        """

        if not refs:
            return {}
        resolved: dict[str, str] = {}
        for name, value in refs.items():
            resolved[name] = await self._render_secret_template(
                tenant_id=server.tenant_id, value=value
            )
        return resolved

    async def _render_secret_template(self, *, tenant_id: UUID, value: str) -> str:
        """Render a `{secret:ref}`-substituted string. If the input has no
        `{secret:...}` placeholders it's treated as a bare ref to maintain
        backward compatibility with the pre-H6 value shape."""

        matches = list(_SECRET_TEMPLATE_RE.finditer(value))
        if not matches:
            # Bare-ref legacy path.
            return await self._secret_store.get_secret(tenant_id, value)

        out: list[str] = []
        cursor = 0
        for match in matches:
            ref = match.group(1)
            if not ref:
                raise ValueError(
                    "empty secret ref in template value (`{secret:}` is invalid)"
                )
            secret = await self._secret_store.get_secret(tenant_id, ref)
            out.append(value[cursor : match.start()])
            out.append(secret)
            cursor = match.end()
        out.append(value[cursor:])
        return "".join(out)

    async def _resolve_mtls_credential(
        self, server: McpServer
    ) -> MtlsClientCredential | None:
        """Resolve `mtls_cert_ref` + `mtls_key_ref` to PEM blobs.

        Returns `None` when no mTLS is configured. Schema validation
        already guarantees both refs are set together — but we still
        defensively check here so a half-set DB row (e.g. one ref
        deleted via direct SQL) surfaces a clear error rather than a
        cryptic SSL handshake failure.

        Both PEM blobs come back as plain strings from the SecretStore;
        the resolved bytes never hit disk except briefly inside
        `_build_mtls_ssl_context` (which removes the scratch file as
        soon as `load_cert_chain` returns)."""

        cert_ref = server.mtls_cert_ref
        key_ref = server.mtls_key_ref
        if cert_ref is None and key_ref is None:
            return None
        if cert_ref is None or key_ref is None:
            raise InvalidMtlsConfigError(
                "mtls_cert_ref and mtls_key_ref must both be set"
            )
        cert_pem = await self._secret_store.get_secret(server.tenant_id, cert_ref)
        key_pem = await self._secret_store.get_secret(server.tenant_id, key_ref)
        return MtlsClientCredential(cert_pem=cert_pem, key_pem=key_pem)

    def _lookup_server(self, tenant_id: UUID, server_id: UUID) -> McpServer:
        with self._session_factory() as session:
            bind_tenant_context(session, tenant_id)
            server = cast(
                McpServer | None,
                session.scalar(
                    select(McpServer).where(
                        McpServer.tenant_id == tenant_id,
                        McpServer.id == server_id,
                    )
                ),
            )
        if server is None:
            raise UpstreamServerNotFoundError(
                f"server {server_id} not found in tenant {tenant_id}"
            )
        return server
