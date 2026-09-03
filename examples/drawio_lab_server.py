"""Run a single-process Vyuu MCP gateway against real Postgres.

This lab uses the **production code path end-to-end**. The fake resolver and
hand-wired upstream dispatcher that earlier versions of the lab used are gone:
both the inbound MCP route and the operator API talk to the same real DB
through `DatabaseBackedUpstreamClientProvider` and `VirtualServerResolver`.

Two pre-baked virtual servers and their backing upstreams are seeded by
`examples/lab_bootstrap.py` so the printed Cursor / Claude Desktop URLs work
out of the box:

  - `drawio-http`  → Streamable HTTP at https://mcp.draw.io/mcp
                     (tools: create_diagram, search_shapes)
  - `drawio-stdio` → stdio via `npx -y @drawio/mcp`
                     (tools: open_drawio_xml, open_drawio_csv, open_drawio_mermaid)

Beyond those, the operator console at `/operator` lets you register *any*
npm / stdio / HTTP MCP server, sync its capabilities, pick which tools to
expose, and publish a virtual server — exercising the full production flow.

Prerequisites:

    # 1. install + start Postgres locally (one time)
    brew install postgresql@16
    /opt/homebrew/opt/postgresql@16/bin/pg_ctl \\
        -D /opt/homebrew/var/postgresql@16 -l /tmp/pg_lab.log start
    /opt/homebrew/opt/postgresql@16/bin/createuser -h 127.0.0.1 -s vyuu
    /opt/homebrew/opt/postgresql@16/bin/createdb -h 127.0.0.1 vyuu_gateway -O vyuu

    # 2. apply migrations + seed lab tenant/operator/drawio servers/vservers
    python examples/lab_bootstrap.py

    # 3. run the lab
    python examples/drawio_lab_server.py

Stdout shows one `[audit]` line and one `[upstream:<server_id>]` pair per
tool call:

    [audit]    metadata-only summary (decision, latency, tenant/principal,
               args_summary with redacted top-level shape — never values)
    [upstream] raw arguments going out and full response coming back
               (lab-only debug aid; production NEVER captures raw args/responses
               by default — see AGENTS.md and spec §3.3)

What this exercises:
- Inbound MCP Streamable HTTP at `/v/{tenant_id}/{vserver_name}/mcp`.
- Operator API: register / list servers, sync capabilities, vserver CRUD.
- Real Postgres + RLS-binding session through `get_tenant_scoped_db` and
  `get_inbound_mcp_db`.
- Real `DatabaseBackedUpstreamClientProvider` (with pool + circuit breaker)
  building Streamable HTTP / stdio / npm clients per registered upstream.
- Identity validation via `FakeIdentityProvider` and `x-vyuu-*` headers.
- Full `ToolCallLifecycle`: schema validation, policy, audit, NHI graph.

What this does NOT exercise (kept off the demo path):
- Real OIDC / API-key validation. The lab token is HMAC-signed with the
  lab's local secret; production replaces `FakeOperatorAuthProvider` and
  `FakeIdentityProvider` with real providers. Same Protocol contract.
- Durable audit / graph storage. Events live in process memory only.
- TLS termination. The lab speaks HTTP; production must terminate TLS at
  the ingress.
"""

from __future__ import annotations

import json
import logging
import os
import socket
from typing import Any
from uuid import UUID

import uvicorn
from mcp.types import (
    CallToolResult,
    InitializeResult,
    Prompt,
    Resource,
    Tool,
)

from vyuu_gateway.audit.emitter import EmitResult
from vyuu_gateway.audit.events import AuditEvent
from vyuu_gateway.capabilities.client import CapabilityDescriptor
from vyuu_gateway.config import Settings
from vyuu_gateway.db.session import SessionLocal
from vyuu_gateway.graph.emitter import InMemoryGraphEventEmitter
from vyuu_gateway.identity.api_key_provider import ApiKeyIdentityProvider
from vyuu_gateway.identity.fake import FakeIdentityProvider
from vyuu_gateway.identity.provider import IdentityProvider
from vyuu_gateway.main import create_app
from vyuu_gateway.mcp.outbound import OutboundMcpClient
from vyuu_gateway.operator_auth.fake import mint_operator_test_token
from vyuu_gateway.policy.simple import SimplePolicyProvider
from vyuu_gateway.secrets import InMemorySecretStore
from vyuu_gateway.secrets.store import SecretNotFoundError

# IDs MUST match `examples/lab_bootstrap.py` so the printed URLs and the lab
# bearer token resolve to the rows the bootstrap inserts.
LAB_TENANT_ID = UUID("11111111-1111-1111-1111-111111111111")
LAB_OPERATOR_ID = UUID("44444444-4444-4444-4444-444444444444")

LAB_HTTP_VSERVER_NAME = "drawio-http"
LAB_STDIO_VSERVER_NAME = "drawio-stdio"
LAB_PYPI_VSERVER_NAME = "time-pypi"

LAB_HOST = os.environ.get("VYUU_LAB_HOST", "127.0.0.1")


def _advertised_host() -> str:
    """The host to PRINT in URLs, which is not always the bind address.

    `0.0.0.0` means "every interface" to the socket layer and nothing at
    all to a browser — printing it hands the operator a URL that works
    nowhere. When binding to a wildcard, resolve the address this machine
    actually presents on its LAN instead.

    `VYUU_LAB_ADVERTISE_HOST` overrides, for the case where the reachable
    name is not the local interface (a tunnel, a container host).
    """

    explicit = os.environ.get("VYUU_LAB_ADVERTISE_HOST", "").strip()
    if explicit:
        return explicit
    if LAB_HOST not in ("0.0.0.0", "::", ""):
        return LAB_HOST
    # A connect() on a UDP socket sends nothing — it just asks the
    # routing table which local address would be used to reach that
    # destination. 192.0.2.1 is TEST-NET-1 and is never routed.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 1))
        return str(probe.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


LAB_ADVERTISE_HOST = _advertised_host()
# Default stays 8000: the GitHub OAuth app's callback is registered at
# `localhost:8000/api/v1/oauth-authcode/callback`, so moving it silently
# would break the authcode demo. The override exists for the case where
# something else already holds the port (Docker, another gateway) and you
# only need the UI — OAuth-authcode flows will not complete on a
# non-default port until the IdP-side redirect URI is updated to match.
LAB_PORT = int(os.environ.get("VYUU_LAB_PORT", "8000"))

DRAWIO_HTTP_UPSTREAM_URL = "https://mcp.draw.io/mcp"
DRAWIO_NPM_PACKAGE = "@drawio/mcp"
TIME_PYPI_PACKAGE = "mcp-server-time"

LAB_OPERATOR_AUTH_SIGNING_SECRET = "lab-not-for-production"


# --- Lab debug wrappers ---------------------------------------------------


class _StdoutAuditEmitter:
    """Lab debug: print every audit event as JSON, also keep them in memory.

    Production audit emitters route to Kafka / NATS / disk spool; printing to
    stdout is only to make the events visible while iterating locally. The
    `args_summary` payload is the spec-compliant redacted form (top-level
    keys, types, sizes — never raw values).
    """

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        self.events.append(event)
        payload = event.model_dump(mode="json", exclude_none=True)
        print(f"[audit] {json.dumps(payload, separators=(',', ':'))}", flush=True)
        return EmitResult(accepted=True)


class _LoggingUpstreamClient:
    """Wraps an `OutboundMcpClient`, prints raw I/O around `call_tool`.

    Lab-only debug aid; production NEVER captures raw args / responses
    without explicit policy opt-in (see AGENTS.md and spec §3.3). All other
    OutboundMcpClient methods (initialize, list_tools, list_capabilities,
    etc.) delegate without logging — so capability-sync round trips don't
    spam the console.
    """

    def __init__(self, label: str, wrapped: OutboundMcpClient) -> None:
        self._label = label
        self._wrapped = wrapped

    async def initialize(self) -> InitializeResult:
        return await self._wrapped.initialize()

    async def list_tools(self) -> list[Tool]:
        return await self._wrapped.list_tools()

    async def list_resources(self) -> list[Resource]:
        return await self._wrapped.list_resources()

    async def list_prompts(self) -> list[Prompt]:
        return await self._wrapped.list_prompts()

    async def list_capabilities(
        self,
        *,
        principal_id: UUID | None = None,
    ) -> list[CapabilityDescriptor]:
        return await self._wrapped.list_capabilities(principal_id=principal_id)

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        inbound_headers: dict[str, str] | None = None,
        principal_id: UUID | None = None,
    ) -> CallToolResult:
        args_json = json.dumps(arguments, default=str)
        print(
            f"[upstream:{self._label}] >>> tools/call name={tool_name!r} args={args_json}",
            flush=True,
        )
        result = await self._wrapped.call_tool(
            tool_name,
            arguments,
            inbound_headers=inbound_headers,
            principal_id=principal_id,
        )
        print(
            f"[upstream:{self._label}] <<< tools/call name={tool_name!r} "
            f"isError={result.isError} content={_render_call_tool_content(result)}",
            flush=True,
        )
        return result


def _render_call_tool_content(result: CallToolResult) -> str:
    parts: list[str] = []
    for item in result.content:
        item_type = getattr(item, "type", item.__class__.__name__)
        text = getattr(item, "text", None)
        if isinstance(text, str):
            preview = text if len(text) <= 800 else text[:800] + f"…(+{len(text) - 800} chars)"
            parts.append(f"<{item_type}>{preview!r}")
        else:
            dump = getattr(item, "model_dump", None)
            if callable(dump):
                try:
                    body = json.dumps(dump(mode="json", exclude_none=True), default=str)
                    parts.append(f"<{item_type}>{body}")
                    continue
                except Exception:
                    pass
            parts.append(f"<{item_type}>{item!r}")
    return "[" + ", ".join(parts) + "]"


class _LoggingUpstreamProviderWrapper:
    """Wrap the production `DatabaseBackedUpstreamClientProvider` so each
    returned client gets the `_LoggingUpstreamClient` treatment.

    The inner provider does the real DB lookup and returns a `PooledOutboundMcpClient`
    sized by tenant + transport. The wrapper caches the logging-wrapped form
    so successive calls return the same wrapper instance (matching the
    inner provider's pooling guarantees).
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self._wrapped: dict[tuple[UUID, UUID], _LoggingUpstreamClient] = {}

    def get_auth_mode_flags(self, tenant_id: UUID, server_id: UUID) -> Any:
        """Forward to the inner provider — keeps the new audit-mode
        signal (A5) intact through the lab's debug wrapper."""
        return self._inner.get_auth_mode_flags(tenant_id, server_id)

    def get_client(self, tenant_id: UUID, server_id: UUID) -> _LoggingUpstreamClient:
        key = (tenant_id, server_id)
        cached = self._wrapped.get(key)
        if cached is not None:
            return cached
        real_client = self._inner.get_client(tenant_id, server_id)
        # Use the short server-id prefix as a label so [upstream:abc12345]
        # is recognisable in stdout.
        label = str(server_id).split("-", maxsplit=1)[0]
        wrapped = _LoggingUpstreamClient(label, real_client)
        self._wrapped[key] = wrapped
        return wrapped

    async def aclose(self) -> None:
        aclose = getattr(self._inner, "aclose", None)
        if callable(aclose):
            await aclose()


# --- App wiring -----------------------------------------------------------


class _LabPassThroughSecretStore(InMemorySecretStore):
    """Lab-only `InMemorySecretStore` that falls back to literal-pass-
    through on cache miss.

    Why this exists: the in-memory store starts empty on every boot.
    The boot-time seeders (`_seed_oauth_authcode_secrets`,
    `_seed_auth_env_secrets`) walk every `mcp_servers` row at startup
    and seed each ref. But anything the operator registers AFTER boot
    won't be in the store — `get_secret` would raise
    `SecretNotFoundError`, sync 502s, the operator has to restart the
    lab to re-seed. Painful and confusing.

    This subclass overrides `get_secret`: if the ref isn't in the
    backing dict, it returns the ref name itself as the value. That
    matches the literal-pass-through fallback in the boot seeder, but
    extends it to runtime registrations. Operators can paste actual
    credential values directly into auth_env / auth_headers and the
    spawned subprocess receives them as env vars / header values
    immediately, without restarting.

    Production swaps this out for Vault / AWS Secrets Manager which
    have proper key existence semantics. This fallback is strictly a
    lab affordance.
    """

    async def get_secret(self, tenant_id: UUID, ref: str) -> str:
        try:
            return await super().get_secret(tenant_id, ref)
        except SecretNotFoundError:
            print(
                f"[lab] secret '{ref}' not in store — passing through as "
                f"literal env/header value (lab-only behaviour).",
                flush=True,
            )
            return ref


def _seed_oauth_authcode_secrets(store: InMemorySecretStore) -> None:
    """Find every MCP server with auth_authcode set + seed its refs.

    Lab convenience only — the production gateway uses Vault / AWS
    Secrets Manager backed stores that survive restarts. The in-memory
    store starts empty on every boot, so this function bridges what
    `scripts/demo_oauth_authcode.py` would have seeded if it were the
    one running.

    For each server, the env var override pattern is:
        LAB_OAUTH_CLIENT_ID_<REF>     → resolved client_id
        LAB_OAUTH_CLIENT_SECRET_<REF> → resolved client_secret
    where `<REF>` is the secret-store ref name uppercased and
    `-` → `_`. So `github-demo-client-id` reads from
    `LAB_OAUTH_CLIENT_ID_GITHUB_DEMO_CLIENT_ID`.

    Special-cases the well-known `github-demo-*` refs from
    `scripts/demo_oauth_authcode.py` to also accept `DEMO_GH_CLIENT_ID`
    / `DEMO_GH_CLIENT_SECRET` so existing operators don't have to
    rename env vars.
    """
    from sqlalchemy import select

    from vyuu_gateway.db.models import McpServer

    # Each entry is (ref, kind, value, env_var_name, is_real)
    # so we can both seed and print a per-server diagnostic afterwards.
    resolutions: list[tuple[str, str, str, str, bool]] = []

    def _resolve(ref: str, kind: str) -> tuple[str, str, bool]:
        """Return (value, env_var_name, is_real_credential)."""
        # Special-case the demo seed for backwards compat.
        if ref == "github-demo-client-id":
            env_key = "DEMO_GH_CLIENT_ID"
            value = os.environ.get(env_key, "demo-github-client-id")
            return value, env_key, env_key in os.environ
        if ref == "github-demo-client-secret":
            env_key = "DEMO_GH_CLIENT_SECRET"
            value = os.environ.get(env_key, "demo-github-client-secret")
            return value, env_key, env_key in os.environ
        env_key = f"LAB_OAUTH_{kind.upper()}_{ref.upper().replace('-', '_')}"
        value = os.environ.get(env_key, f"placeholder-{ref}")
        return value, env_key, env_key in os.environ

    with SessionLocal() as session:
        rows = list(session.scalars(select(McpServer)))
    servers_with_placeholders: list[tuple[str, list[str]]] = []
    for server in rows:
        spec = server.auth_authcode
        if not spec:
            continue
        client_id_ref = spec.get("client_id_ref")
        client_secret_ref = spec.get("client_secret_ref")
        missing_envs: list[str] = []
        for ref, kind in (
            (client_id_ref, "client_id"),
            (client_secret_ref, "client_secret"),
        ):
            if not ref:
                continue
            value, env_key, is_real = _resolve(ref, kind)
            store.put(server.tenant_id, ref, value)
            resolutions.append((ref, kind, value, env_key, is_real))
            if not is_real:
                missing_envs.append(env_key)
        if missing_envs:
            servers_with_placeholders.append(
                (server.display_name, missing_envs)
            )

    if not resolutions:
        return
    real_count = sum(1 for r in resolutions if r[4])
    placeholder_count = len(resolutions) - real_count
    print(
        f"[lab] seeded {len(resolutions)} OAuth-authcode secret refs "
        f"({real_count} from env, {placeholder_count} placeholder)."
    )
    if servers_with_placeholders:
        # Loud warning — operators will hit a GitHub 404 (or vendor
        # equivalent) on Connect → because the placeholder client_id
        # isn't a registered OAuth app at the IdP. Calling out the
        # exact env-var names they need to set keeps the fix obvious.
        print()
        print("=" * 70)
        print("  ⚠  OAuth-authcode placeholders in use — Connect → will 404")
        print("=" * 70)
        for name, envs in servers_with_placeholders:
            print(f"  · {name}")
            for env in envs:
                print(f"      set {env}=<real value> before booting the lab")
        print()
        print("  Register an OAuth app at:")
        print("    https://github.com/settings/developers → New OAuth App")
        print("    Authorization callback URL:")
        print(f"      http://{LAB_ADVERTISE_HOST}:{LAB_PORT}/api/v1/oauth-authcode/callback")
        print("=" * 70)
        print()


def _seed_risk_classifier_secret(store: InMemorySecretStore) -> None:
    """RISK-1 · put the LLM API key in the store from the environment.

    The gateway stores a secret-store REF for the risk classifier, never
    the key — `PUT /admin/risk/model` refuses anything key-shaped. In
    production that ref resolves against Vault or AWS Secrets Manager.
    In the lab there is nothing to resolve against, so the key comes
    from the environment and is seeded here under whichever ref the
    tenant has configured.

    Set it with:

        VYUU_LAB_RISK_API_KEY=<your key>

    The value is never printed, never written to the database, and never
    included in the payload sent to the model — `classifier.py` builds
    that payload from the capability surface alone.
    """

    key = os.environ.get("VYUU_LAB_RISK_API_KEY", "").strip()
    if not key:
        return
    from sqlalchemy import select as _select

    from vyuu_gateway.db.models import Tenant as _Tenant
    from vyuu_gateway.db.session import SessionLocal as _SessionLocal

    seeded = 0
    with _SessionLocal() as session:
        for tenant in session.scalars(_select(_Tenant)).all():
            ref = (tenant.risk_model_api_key_ref or "").strip()
            if not ref:
                continue
            store.put(tenant.id, ref, key)
            seeded += 1
    # Ref name only. Printing the key into a log that gets pasted into a
    # bug report is exactly how these leak.
    print(
        f"[lab] risk-classifier key seeded for {seeded} tenant(s) "
        f"from VYUU_LAB_RISK_API_KEY.",
        flush=True,
    )


def _seed_auth_env_secrets(store: InMemorySecretStore) -> None:
    """Seed every `auth_env` ref from the `mcp_servers` table.

    `auth_env` is the stdio-MCP env-var injection map:
    `{env_var_name: secret_store_ref}`. When the gateway spawns an
    npm / pypi / stdio / binary subprocess, it resolves each ref
    through the SecretStore and sets the corresponding env var.

    Without seeding, a freshly-registered server with `auth_env` set
    fails sync with `SecretNotFoundError`, then trips the upstream
    pool's circuit breaker (`CircuitBreakerOpenError` on subsequent
    calls). Same lab-restart pattern as the OAuth-authcode seeder
    above — the in-memory store doesn't survive, the DB does.

    Two operator workflows:
      (a) **Ref-style** (production-shaped): the value in auth_env is
          a ref name like `falcon-client-id`. The operator sets the
          real value via `LAB_AUTH_ENV_FALCON_CLIENT_ID=<real>` env
          var before booting the lab. Mirrors how Vault / AWS
          Secrets Manager would resolve in prod.
      (b) **Literal-style** (lab convenience): the value in auth_env
          IS the actual env value (e.g. an operator pastes their
          API client_id directly into the wizard). When no
          `LAB_AUTH_ENV_*` override exists, the ref name itself is
          treated as the env var's value — so the literal flows
          through to the spawned subprocess unchanged.

    Env-var override pattern:
        LAB_AUTH_ENV_<REF>     → resolved env value
    where `<REF>` is the ref name uppercased + non-alphanumerics
    replaced with `_`. Ref-style operators set this for real values;
    literal-style operators don't need to set anything.
    """
    import re as _re

    from sqlalchemy import select

    from vyuu_gateway.db.models import McpServer

    resolutions: list[tuple[str, str, str, str, bool]] = []
    servers_with_placeholders: list[tuple[str, list[str]]] = []

    def _resolve(ref: str) -> tuple[str, str, bool]:
        # Env var key — uppercased, non-alphanumerics → `_`. Without
        # the regex sub, ref names containing `.` / `:` / `/` (e.g. a
        # base-URL pasted as a literal value) produce malformed env
        # var names and `os.environ.get` always returns None silently.
        sanitized = _re.sub(r"[^A-Za-z0-9]+", "_", ref).upper()
        env_key = f"LAB_AUTH_ENV_{sanitized}"
        if env_key in os.environ:
            return os.environ[env_key], env_key, True
        # Literal-style fallback: the operator pasted the actual value
        # in `auth_env` (not a ref name). Pass it through as-is so the
        # spawned subprocess receives the literal env value.
        return ref, env_key, False

    with SessionLocal() as session:
        rows = list(session.scalars(select(McpServer)))
    for server in rows:
        env_map = server.auth_env or {}
        if not env_map:
            continue
        missing_envs: list[str] = []
        for env_var_name, ref in env_map.items():
            if not ref:
                continue
            value, env_key, is_real = _resolve(ref)
            store.put(server.tenant_id, ref, value)
            resolutions.append((ref, env_var_name, value, env_key, is_real))
            if not is_real:
                missing_envs.append(env_key)
        if missing_envs:
            servers_with_placeholders.append((server.display_name, missing_envs))

    if not resolutions:
        return
    real_count = sum(1 for r in resolutions if r[4])
    literal_count = len(resolutions) - real_count
    print(
        f"[lab] seeded {len(resolutions)} auth_env secret refs "
        f"({real_count} from env override, {literal_count} pass-through "
        f"of the ref name as the literal env value)."
    )
    if servers_with_placeholders:
        # Informational, not an error — literal-style works fine for the
        # lab. Operators who want ref-style + real values via env can
        # see exactly what env-var name to set per ref.
        print()
        print("  Tip: to override any of these via env vars, set:")
        for name, envs in servers_with_placeholders:
            for env in envs:
                print(f"    {env}=<real value>     ({name})")
        print()


def _build_lab_app() -> Any:
    """Build the lab gateway against real Postgres.

    The default `create_app` wires `DatabaseBackedUpstreamClientProvider` as
    the upstream provider. We let it construct that, then swap in a logging
    wrapper around it so `[upstream:*]` lines show up. Everything else uses
    the production defaults.

    A pre-seeded `InMemorySecretStore` carries a few demo refs so an
    operator can register an authenticated HTTP MCP (e.g. against
    https://httpbin.org/bearer) and watch the resolved Authorization
    header land on the upstream. Production drops in Vault / AWS Secrets
    Manager via the same `SecretStore` Protocol.
    """

    secret_store = _LabPassThroughSecretStore()
    # Seeded for the lab walkthrough — register an HTTP MCP at
    # https://httpbin.org/bearer with auth_headers={"Authorization": "demo-bearer"}
    # to see header injection in action without needing a real SaaS API key.
    secret_store.put(LAB_TENANT_ID, "demo-bearer", "Bearer demo-token-do-not-ship")

    # Walk every MCP server in the database with `auth_authcode` set and
    # ensure its `client_id_ref` + `client_secret_ref` resolve. Without
    # this, the portal's `Connect →` flow 500s with `SecretNotFoundError`
    # because the in-memory store is process-local and doesn't survive
    # across lab-server restarts (or across switching between
    # `scripts/demo_oauth_authcode.py` and this lab on the same DB).
    #
    # Real OAuth-app credentials come from env (`DEMO_GH_CLIENT_ID`,
    # `DEMO_GH_CLIENT_SECRET`, `LAB_OAUTH_CLIENT_ID_<REF>`,
    # `LAB_OAUTH_CLIENT_SECRET_<REF>`); fall back to fake placeholder
    # values so the redirect to the IdP at least produces a valid URL
    # (consent will fail at the IdP for unknown client_id, which is the
    # right behavior — operators see the GitHub error, not a 500 here).
    _seed_oauth_authcode_secrets(secret_store)
    _seed_auth_env_secrets(secret_store)
    _seed_risk_classifier_secret(secret_store)

    # A3.y · Opt-in to the production `ApiKeyIdentityProvider` for end-to-end
    # smoke testing of the bcrypt-keyed bearer path without standing up OIDC.
    # Default lab behavior remains `FakeIdentityProvider` (so the existing
    # `x-vyuu-*` header-driven principals keep working out of the box).
    use_api_key_identity = os.environ.get("VYUU_LAB_USE_API_KEY_IDENTITY") == "1"
    identity_provider: IdentityProvider = (
        ApiKeyIdentityProvider(session_factory=SessionLocal)
        if use_api_key_identity
        else FakeIdentityProvider()
    )

    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway (drawio lab)",
            environment="local",
            log_level="INFO",
            version="drawio-lab",
            operator_auth_signing_secret=LAB_OPERATOR_AUTH_SIGNING_SECRET,
        ),
        identity_provider=identity_provider,
        policy_provider=SimplePolicyProvider(),
        audit_emitter=_StdoutAuditEmitter(),
        graph_event_emitter=InMemoryGraphEventEmitter(),
        secret_store=secret_store,
    )

    # Wrap the production upstream provider for debug logging. The
    # capability-sync client (also on app.state) uses the same wrapper so
    # sync round-trips also surface in stdout.
    real_provider = app.state.upstream_clients
    wrapped_provider = _LoggingUpstreamProviderWrapper(real_provider)
    app.state.upstream_clients = wrapped_provider

    # Re-construct the capability-sync client against the wrapped provider
    # so HTTP-driven syncs also trigger the upstream-logging wrapper.
    from vyuu_gateway.capabilities.upstream_adapter import UpstreamProviderCapabilityClient

    app.state.capability_sync_client = UpstreamProviderCapabilityClient(wrapped_provider)

    return app


# --- Config snippets ------------------------------------------------------


def _http_url(vserver_name: str) -> str:
    return f"http://{LAB_ADVERTISE_HOST}:{LAB_PORT}/v/{LAB_TENANT_ID}/{vserver_name}/mcp"


def _print_banner() -> None:
    print()
    print("=" * 78)
    print("Vyuu MCP Gateway — drawio lab server (HTTP + stdio upstreams)")
    print("=" * 78)
    print()
    print(f"  Operator console:  http://{LAB_ADVERTISE_HOST}:{LAB_PORT}/operator")
    print(f"  Portal:            http://{LAB_ADVERTISE_HOST}:{LAB_PORT}/portal")
    print(f"  OpenAPI / docs:    http://{LAB_ADVERTISE_HOST}:{LAB_PORT}/docs")
    print(f"  Health endpoint:   http://{LAB_ADVERTISE_HOST}:{LAB_PORT}/api/v1/health")
    if os.environ.get("VYUU_LAB_USE_API_KEY_IDENTITY") == "1":
        print()
        print("  Identity provider: ApiKeyIdentityProvider (real bcrypt-keyed bearer)")
        print("  → Inbound MCP calls require Authorization: Bearer vyuu_user_*")
        print("  → Issue a key from /portal after signing in, then paste into")
        print("    Cursor / Claude Desktop config.")
    else:
        print()
        print("  Identity provider: FakeIdentityProvider (x-vyuu-* headers)")
        print("  → Set VYUU_LAB_USE_API_KEY_IDENTITY=1 to flip to the production")
        print("    auth path.")
    print()
    print("Pre-seeded virtual servers (run examples/lab_bootstrap.py first):")
    print(f"  - {LAB_HTTP_VSERVER_NAME:<14}  → https://mcp.draw.io/mcp")
    print("      tools: create_diagram, search_shapes")
    print(f"      url:   {_http_url(LAB_HTTP_VSERVER_NAME)}")
    print(f"  - {LAB_STDIO_VSERVER_NAME:<14}  → npx -y {DRAWIO_NPM_PACKAGE}")
    print("      tools: open_drawio_xml, open_drawio_csv, open_drawio_mermaid")
    print(f"      url:   {_http_url(LAB_STDIO_VSERVER_NAME)}")
    print(f"  - {LAB_PYPI_VSERVER_NAME:<14}  → uvx {TIME_PYPI_PACKAGE}")
    print("      tools: get_current_time, convert_time")
    print(f"      url:   {_http_url(LAB_PYPI_VSERVER_NAME)}")
    print()
    print("New servers / vservers added via the operator console land in the")
    print("same Postgres and become callable through their own /v/.../mcp URLs.")
    print()


def _print_operator_token() -> None:
    token = mint_operator_test_token(
        tenant_id=LAB_TENANT_ID,
        operator_id=LAB_OPERATOR_ID,
        display="Lab Operator",
        signing_secret=LAB_OPERATOR_AUTH_SIGNING_SECRET,
    )
    print("-" * 78)
    print("Operator bearer token (paste into the console's Bearer-token field)")
    print("-" * 78)
    print(token)
    print()
    print("This is an HMAC-signed test token — minted with the lab signing secret.")
    print("Production replaces `FakeOperatorAuthProvider` with a real OIDC/API-key")
    print("provider; the operator console contract stays the same.")
    print()


def _http_server_block(vserver_name: str, principal_id: str) -> dict[str, Any]:
    return {
        "url": _http_url(vserver_name),
        "type": "streamable-http",
        "headers": {
            "x-vyuu-tenant-id": str(LAB_TENANT_ID),
            "x-vyuu-principal-type": "endpoint_session",
            "x-vyuu-principal-id": principal_id,
            "x-vyuu-principal-display": f"{principal_id} (local lab)",
        },
    }


def _print_cursor_config() -> None:
    print("-" * 78)
    print("Cursor mcp.json  (paste into ~/.cursor/mcp.json)")
    print("-" * 78)
    config = {
        "mcpServers": {
            "drawio-http-via-vyuu": _http_server_block(LAB_HTTP_VSERVER_NAME, "cursor-http"),
            "drawio-stdio-via-vyuu": _http_server_block(LAB_STDIO_VSERVER_NAME, "cursor-stdio"),
        }
    }
    print(json.dumps(config, indent=2))
    print()


def _print_claude_desktop_config() -> None:
    print("-" * 78)
    print("Claude Desktop  (paste into ~/Library/Application Support/Claude/")
    print("                claude_desktop_config.json on macOS, or the equivalent")
    print("                Application Support path on your platform)")
    print("-" * 78)
    print()
    print("# Newer Claude Desktop versions support remote (HTTP) MCP servers")
    print("# directly. Use this block:")
    print()
    config_native = {
        "mcpServers": {
            "drawio-http-via-vyuu": _http_server_block(LAB_HTTP_VSERVER_NAME, "claude-http"),
            "drawio-stdio-via-vyuu": _http_server_block(LAB_STDIO_VSERVER_NAME, "claude-stdio"),
        }
    }
    print(json.dumps(config_native, indent=2))
    print()
    print("# Older Claude Desktop versions only speak stdio MCP. Bridge via")
    print("# `mcp-remote` (npm: `mcp-remote` or `@modelcontextprotocol/mcp-remote`):")
    print()
    config_bridge = {
        "mcpServers": {
            "drawio-http-via-vyuu": {
                "command": "npx",
                "args": [
                    "-y",
                    "mcp-remote",
                    _http_url(LAB_HTTP_VSERVER_NAME),
                    "--header",
                    f"x-vyuu-tenant-id: {LAB_TENANT_ID}",
                    "--header",
                    "x-vyuu-principal-type: endpoint_session",
                    "--header",
                    "x-vyuu-principal-id: claude-http",
                ],
            }
        }
    }
    print(json.dumps(config_bridge, indent=2))
    print()


def _print_footer() -> None:
    print("-" * 78)
    print("Restart your client after saving the config. Watch this process's")
    print("stdout for [audit] and [upstream:<server-id>] lines per tool call.")
    print("Press Ctrl+C to stop the lab.")
    print("=" * 78)
    print()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = _build_lab_app()
    _print_banner()
    _print_operator_token()
    _print_cursor_config()
    _print_claude_desktop_config()
    _print_footer()
    # Tier-1 stress-test fixes: surface the same back-pressure config
    # that production entrypoints will use, so the lab and prod have
    # the same failure mode under burst (fast-503, never silent
    # queueing). Values come from gateway Settings so operators tune
    # via env vars without editing this file.
    settings = app.state.settings
    uvicorn.run(
        app,
        host=LAB_HOST,
        port=LAB_PORT,
        log_level="info",
        limit_concurrency=settings.inbound_limit_concurrency,
        limit_max_requests=(
            settings.inbound_limit_max_requests
            if settings.inbound_limit_max_requests > 0 else None
        ),
        backlog=settings.inbound_backlog,
        timeout_keep_alive=settings.inbound_keep_alive_seconds,
    )


if __name__ == "__main__":
    main()
