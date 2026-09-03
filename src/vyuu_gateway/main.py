import base64
import binascii
import inspect
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from vyuu_gateway.api.access_requests import (
    admin_router as access_requests_admin_router,
)
from vyuu_gateway.api.access_requests import (
    portal_router as access_requests_portal_router,
)
from vyuu_gateway.api.admin_audit import router as admin_audit_router
from vyuu_gateway.api.admin_dashboard import router as admin_dashboard_router
from vyuu_gateway.api.api_key_policies import router as api_key_policies_router
from vyuu_gateway.api.audit_events import router as audit_events_router
from vyuu_gateway.api.auth import router as auth_router
from vyuu_gateway.api.cimd import router as cimd_router
from vyuu_gateway.api.connector_catalog import router as connector_catalog_router
from vyuu_gateway.api.diagnostic_bundle import (
    router as diagnostic_bundle_router,
)
from vyuu_gateway.api.ema_oauth import (
    router as ema_oauth_router,
)
from vyuu_gateway.api.ema_oauth import (
    wellknown_router as ema_wellknown_router,
)
from vyuu_gateway.api.health import (
    liveness_router as health_liveness_router,
)
from vyuu_gateway.api.health import (
    router as health_router,
)
from vyuu_gateway.api.health_overview import router as health_overview_router
from vyuu_gateway.api.identities import router as identities_router
from vyuu_gateway.api.idp_directories import router as idp_directories_router
from vyuu_gateway.api.idp_signin import (
    operator_idp_router as idp_signin_operator_router,
)
from vyuu_gateway.api.idp_signin import router as idp_signin_router
from vyuu_gateway.api.inbound_mcp import router as inbound_mcp_router
from vyuu_gateway.api.nhi_map import router as nhi_map_router
from vyuu_gateway.api.oauth_authcode import router as oauth_authcode_router
from vyuu_gateway.api.operator_auth import router as operator_auth_router
from vyuu_gateway.api.operator_ui import router as operator_ui_router
from vyuu_gateway.api.portal import router as portal_api_router
from vyuu_gateway.api.portal_ui import router as portal_ui_router
from vyuu_gateway.api.risk import router as risk_router
from vyuu_gateway.api.risk import server_router as risk_server_router
from vyuu_gateway.api.risk import vserver_router as risk_vserver_router
from vyuu_gateway.api.secret_store import router as secret_store_router
from vyuu_gateway.api.security_posture import router as security_posture_router
from vyuu_gateway.api.servers import router as servers_router
from vyuu_gateway.api.siem import router as siem_router
from vyuu_gateway.api.telemetry import router as telemetry_router
from vyuu_gateway.api.tenant_settings import router as tenant_settings_router
from vyuu_gateway.api.users import router as users_router
from vyuu_gateway.api.vservers import router as vservers_router
from vyuu_gateway.audit.emitter import AuditEmitter, EmitResult
from vyuu_gateway.audit.events import AuditEvent
from vyuu_gateway.audit.failure import AuditFailureMode
from vyuu_gateway.audit.persistent import (
    PostgresToolCallEventStore,
    seed_recent_buffer_from_postgres,
)
from vyuu_gateway.audit.producer import TestAuditProducer
from vyuu_gateway.audit.recent import RecentAuditEmitter
from vyuu_gateway.audit.retention import RetentionSweeper
from vyuu_gateway.bootstrap import maybe_bootstrap_admin
from vyuu_gateway.capabilities.client import McpCapabilityClient
from vyuu_gateway.capabilities.scheduler import PeriodicCapabilitySyncScheduler
from vyuu_gateway.capabilities.upstream_adapter import UpstreamProviderCapabilityClient
from vyuu_gateway.config import Settings, get_settings
from vyuu_gateway.crypto import (
    AwsKmsKeyProvider,
    EnvelopeCipher,
    LocalMasterKeyProvider,
    NullEnvelopeCipher,
    configure_envelope_cipher,
)
from vyuu_gateway.db.session import SessionLocal
from vyuu_gateway.graph.emitter import GraphEventEmitter, NoOpGraphEventEmitter
from vyuu_gateway.identity.cimd_inbound import InboundCimdResolver
from vyuu_gateway.identity.fake import FakeIdentityProvider
from vyuu_gateway.identity.provider import IdentityProvider
from vyuu_gateway.idp.sweeper import HardDeleteSweeper
from vyuu_gateway.idp.workspace_polling import WorkspacePollingAdapter
from vyuu_gateway.logging_config import configure_logging
from vyuu_gateway.mcp.mrtr import InputRequestKind, MrtrPolicy
from vyuu_gateway.operator_auth.fake import FakeOperatorAuthProvider
from vyuu_gateway.operator_auth.provider import OperatorAuthProvider
from vyuu_gateway.policy.interfaces import PolicyProvider
from vyuu_gateway.policy.management_plane import ManagementPlanePolicyProvider
from vyuu_gateway.policy.simple import SimplePolicyProvider
from vyuu_gateway.registry.url_security import UrlSecurityPolicy
from vyuu_gateway.scim.server import router as scim_router
from vyuu_gateway.secrets import InMemorySecretStore, SecretStore
from vyuu_gateway.sessions.redis_registry import RedisSessionRegistry
from vyuu_gateway.sessions.registry import InMemorySessionRegistry, SessionRegistry
from vyuu_gateway.siem import registry as siem_registry
from vyuu_gateway.siem.bridges import (
    SiemAuditEmitter,
    SiemLogHandler,
    install_admin_audit_hook,
)
from vyuu_gateway.siem.exporter import SiemExporter
from vyuu_gateway.siem.hec import InvalidHecUrlError, SplunkHecClient, normalise_hec_url
from vyuu_gateway.siem.targets import (
    DEPLOYMENT_KEY,
    DatabaseTargetResolver,
    TargetConfig,
    parse_categories,
    parse_log_level,
)
from vyuu_gateway.telemetry.otel import build_telemetry
from vyuu_gateway.upstream.binary_provenance import CosignPolicy
from vyuu_gateway.upstream.circuit_breaker import (
    CircuitBreakerConfig,
    UpstreamCircuitBreakerRegistry,
)
from vyuu_gateway.upstream.health import UpstreamHealthChecker
from vyuu_gateway.upstream.provider import DatabaseBackedUpstreamClientProvider
from vyuu_gateway.users.oidc_providers import OidcProvider
from vyuu_gateway.virtual_servers.tool_elevation import (
    DatabaseToolElevationChecker,
)

logger = logging.getLogger(__name__)


class _LocalAuditEmitter:
    """Trivial emitter for local-dev / smoke tests.

    Records events in-process and reports `accepted=True`. Production
    deployments inject `AsyncAuditEmitter(KafkaProducer, overflow_spool=...)`
    via `create_app(... audit_emitter=...)` once the Kafka producer lands.
    """

    def __init__(self) -> None:
        self.producer = TestAuditProducer()

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        self.producer.events.append(event)
        return EmitResult(accepted=True)


def _build_envelope_cipher(settings: Settings) -> object:
    """AWS-KMS-1 · pick the at-rest cipher for data the gateway stores.

    Default `none` is a `NullEnvelopeCipher`, which still REFUSES to read
    an already-encrypted value rather than returning ciphertext as if it
    were a token. Silently handing a ciphertext to an upstream would
    surface as a baffling 401 instead of "your key is not configured".
    """

    backend = (settings.envelope_encryption_backend or "none").lower()
    if backend == "none":
        return NullEnvelopeCipher()
    if backend == "local":
        if not settings.envelope_master_key:
            raise RuntimeError(
                "VYUU_ENVELOPE_ENCRYPTION_BACKEND=local requires "
                "VYUU_ENVELOPE_MASTER_KEY (base64 of 32 random bytes; "
                "generate with `openssl rand -base64 32`)"
            )
        try:
            key = base64.b64decode(settings.envelope_master_key, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise RuntimeError(
                "VYUU_ENVELOPE_MASTER_KEY must be valid base64"
            ) from exc
        return EnvelopeCipher(LocalMasterKeyProvider(key))
    if backend == "aws_kms":
        if not settings.envelope_kms_key_id:
            raise RuntimeError(
                "VYUU_ENVELOPE_ENCRYPTION_BACKEND=aws_kms requires "
                "VYUU_ENVELOPE_KMS_KEY_ID"
            )
        return EnvelopeCipher(
            AwsKmsKeyProvider(
                key_id=settings.envelope_kms_key_id,
                region_name=settings.aws_region,
            )
        )
    raise RuntimeError(
        "VYUU_ENVELOPE_ENCRYPTION_BACKEND must be 'none', 'local', or "
        f"'aws_kms' (got: {settings.envelope_encryption_backend!r})"
    )


def _valid_mrtr_kind_names() -> list[str]:
    """MRTR kinds an operator may enable. `UNKNOWN` is excluded: it is
    the bucket for requests we could not classify, and is refused even
    when explicitly listed."""

    return [
        k.value for k in InputRequestKind if k is not InputRequestKind.UNKNOWN
    ]


def create_app(
    settings: Settings | None = None,
    *,
    operator_auth: OperatorAuthProvider | None = None,
    identity_provider: IdentityProvider | None = None,
    policy_provider: PolicyProvider | None = None,
    session_registry: SessionRegistry | None = None,
    upstream_clients: object | None = None,
    upstream_health_checker: object | None = None,
    audit_emitter: AuditEmitter | None = None,
    graph_event_emitter: GraphEventEmitter | None = None,
    capability_sync_client: McpCapabilityClient | None = None,
    secret_store: SecretStore | None = None,
) -> FastAPI:
    """Build the gateway FastAPI app.

    All provider arguments default to v1 dev / fake implementations; tests
    inject custom ones. Production wiring (Kafka audit producer, real
    identity provider, mgmt-plane policy provider) replaces the defaults
    via this seam — none of the routes change.
    """

    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings.log_level)

    # RETENTION-1 guardrail. `admin_audit_log` holds the `retention.prune`
    # rows that explain why `tool_call_events` history disappeared; pruning
    # it sooner would delete the explanation while the gap it explains is
    # still visible to an auditor. Fail at startup rather than let a
    # plausible-looking pair of env vars quietly produce that.
    _events_days = resolved_settings.tool_call_event_retention_days
    _admin_days = resolved_settings.admin_audit_retention_days
    if 0 < _admin_days < _events_days:
        raise RuntimeError(
            "VYUU_ADMIN_AUDIT_RETENTION_DAYS "
            f"({_admin_days}) must be >= VYUU_TOOL_CALL_EVENT_RETENTION_DAYS "
            f"({_events_days}) — the admin audit log records the event-table "
            "prunes, so it cannot be discarded first"
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logger.info("gateway_starting")
        # First-run bootstrap (idempotent). Seeds initial tenant +
        # operator + admin user from VYUU_BOOTSTRAP_* env vars if no
        # operators exist yet. No-op otherwise.
        try:
            with SessionLocal() as bootstrap_session:
                maybe_bootstrap_admin(bootstrap_session)
        except Exception:  # noqa: BLE001 - bootstrap failure shouldn't block startup
            logger.warning("bootstrap_seed_failed", exc_info=True)
        scheduler = getattr(app.state, "capability_sync_scheduler", None)
        if scheduler is not None:
            await scheduler.start()
        # IDP-1 Phase 3: hard-delete sweeper. Always on — hourly cycle,
        # 7-day grace. Costs ~one small index scan per hour even with
        # zero soft-deleted rows, so no env flag.
        hard_delete_sweeper = HardDeleteSweeper(session_factory=SessionLocal)
        app.state.hard_delete_sweeper = hard_delete_sweeper
        await hard_delete_sweeper.start()
        # RETENTION-1: durable-audit retention prune. Started
        # unconditionally so the diagnostic bundle can report its
        # configuration, but every cycle is a no-op while both retention
        # windows are 0 (keep forever) — see `audit/retention.py` for why
        # that is the default.
        retention_sweeper = RetentionSweeper(
            session_factory=SessionLocal,
            tool_call_event_retention_days=(
                resolved_settings.tool_call_event_retention_days
            ),
            admin_audit_retention_days=resolved_settings.admin_audit_retention_days,
            interval_seconds=resolved_settings.audit_retention_interval_seconds,
            batch_size=resolved_settings.audit_retention_batch_size,
            max_rows_per_cycle=resolved_settings.audit_retention_max_rows_per_cycle,
        )
        app.state.retention_sweeper = retention_sweeper
        await retention_sweeper.start()
        # IDP-2 · Google Workspace polling. Always started; each cycle
        # is a `SELECT id FROM tenants` plus one indexed query per tenant
        # when no directory has polling enabled, which is the default.
        workspace_poller = WorkspacePollingAdapter(
            session_factory=SessionLocal,
            secret_store=app.state.secret_store,
            interval_seconds=resolved_settings.workspace_poll_interval_seconds,
        )
        app.state.workspace_poller = workspace_poller

        # SIEM-1 · the exporter's workers live on the app's event loop.
        # Started here rather than in `create_app` because there is no
        # running loop at construction time.
        await app.state.siem_exporter.start()
        await workspace_poller.start()
        if retention_sweeper.enabled:
            logger.info(
                "audit_retention_enabled tool_call_events_days=%d "
                "admin_audit_days=%d",
                resolved_settings.tool_call_event_retention_days,
                resolved_settings.admin_audit_retention_days,
            )
        # TOOL-EVENTS-1: rehydrate the in-memory ring buffer from the
        # persistent `tool_call_events` table so the operator-console
        # Events / NHI map / Identities panels show historical context
        # immediately after a restart instead of waiting for fresh
        # traffic. Cheap — one indexed query per tenant, capped at 2000
        # rows each. Best-effort: a failure here just leaves the buffer
        # cold, which falls back to the table on every panel read.
        #
        # Skip the warm-up if the buffer already has entries — tests
        # often emit events through the chain BEFORE entering the
        # `with TestClient(app):` context (which is what triggers
        # lifespan startup). Re-loading those same events from PG
        # would double-count them in the buffer. In production the
        # buffer is empty at startup so this guard is a no-op there.
        recent = getattr(app.state, "recent_audit_emitter", None)
        if recent is not None and len(recent) == 0:
            try:
                seed_recent_buffer_from_postgres(
                    SessionLocal,
                    buffer_appender=recent.warm_load,
                )
            except Exception:  # noqa: BLE001
                logger.warning("audit_buffer_warmup_failed", exc_info=True)
        try:
            yield
        finally:
            await hard_delete_sweeper.stop()
            await retention_sweeper.stop()
            await workspace_poller.stop()
            if scheduler is not None:
                await scheduler.stop()
            await _close_if_supported(app.state.upstream_clients)
            await _close_if_supported(app.state.policy_provider)
            # Give queued SIEM batches a moment to leave, then stop.
            # Bounded: shutdown must not hang on a dead collector.
            await app.state.siem_exporter.flush(timeout_seconds=2.0)
            await app.state.siem_exporter.stop()
            app.state.telemetry.shutdown()
            logger.info("gateway_stopping")

    app = FastAPI(
        title=resolved_settings.app_name,
        version=resolved_settings.version,
        lifespan=lifespan,
    )
    app.state.settings = resolved_settings
    # Wire deployment-wide audit storage cap so opted-in raw-payload
    # capture truncates at the configured ceiling rather than the
    # module default. Transit isn't affected — see
    # `audit/events.py::truncate_for_audit_capture` for the rationale.
    from vyuu_gateway.audit.events import configure_raw_capture_cap
    configure_envelope_cipher(_build_envelope_cipher(resolved_settings))
    configure_raw_capture_cap(resolved_settings.audit_raw_capture_byte_cap)
    app.state.operator_auth = operator_auth or FakeOperatorAuthProvider(
        signing_secret=resolved_settings.operator_auth_signing_secret,
    )
    app.state.identity_provider = identity_provider or _build_default_identity_provider(
        resolved_settings
    )
    app.state.policy_provider = policy_provider or _build_default_policy_provider(
        resolved_settings
    )
    app.state.session_registry = session_registry or _build_default_session_registry(
        resolved_settings
    )
    app.state.upstream_circuit_breakers = UpstreamCircuitBreakerRegistry(
        config=CircuitBreakerConfig(
            failure_threshold=resolved_settings.upstream_circuit_breaker_failure_threshold,
            recovery_timeout_seconds=(
                resolved_settings.upstream_circuit_breaker_recovery_timeout_seconds
            ),
        )
    )
    # Tenant-scoped secret store for outbound auth (headers + stdio env).
    # Default is an in-memory store with no entries — operators who haven't
    # wired auth see no behavioral change.
    app.state.secret_store = secret_store or _build_default_secret_store(
        resolved_settings
    )
    app.state.upstream_clients = upstream_clients or DatabaseBackedUpstreamClientProvider(
        SessionLocal,
        read_timeout_seconds=resolved_settings.upstream_read_timeout_seconds,
        max_clients_per_upstream=resolved_settings.upstream_max_connections_per_server,
        # P2 · 0 disables the TTL; anything positive bounds how long a
        # pooled client keeps serving with a since-rotated credential.
        # S1.b · Sigstore provenance for `binary` upstreams; disabled
        # unless a verification key is configured.
        cosign_policy=CosignPolicy(
            verification_key_path=resolved_settings.binary_cosign_verification_key_path,
            certificate_identity=resolved_settings.binary_cosign_certificate_identity,
            certificate_oidc_issuer=resolved_settings.binary_cosign_certificate_oidc_issuer,
        ),
        client_max_age_seconds=(
            resolved_settings.upstream_client_max_age_seconds
            if resolved_settings.upstream_client_max_age_seconds > 0
            else None
        ),
        circuit_breakers=app.state.upstream_circuit_breakers,
        secret_store=app.state.secret_store,
        # H1 · DNS-time SSRF backstop. Same policy object the registration
        # check uses, so "allowed to register" and "allowed to connect to"
        # cannot drift apart.
        ssrf_policy=(
            UrlSecurityPolicy(
                allow_private_networks=resolved_settings.http_url_allow_private_networks,
                allowlist=tuple(resolved_settings.http_url_allowlist),
                denylist=tuple(resolved_settings.http_url_denylist),
            )
            if resolved_settings.upstream_ssrf_guard_enabled
            else None
        ),
    )
    # JIT-2 · per-tool elevation lookup for the inbound gate. Opens its
    # own tenant-bound session per check; see `tool_elevation.py` for why
    # the lifecycle stays DB-agnostic.
    app.state.tool_elevation_checker = DatabaseToolElevationChecker(SessionLocal)
    # MCP-2 P3 · inbound CIMD. Shares the SSRF policy with registration
    # and outbound connects — a URL this gateway refuses to connect to
    # for an upstream is one it refuses to fetch a client document from.
    # None when disabled, which is the default; the EMA token endpoint
    # then keeps the literal allowlist match it has always done.
    app.state.inbound_cimd_resolver = (
        InboundCimdResolver(
            policy=UrlSecurityPolicy(
                allow_private_networks=resolved_settings.http_url_allow_private_networks,
                allowlist=tuple(resolved_settings.http_url_allowlist),
                denylist=tuple(resolved_settings.http_url_denylist),
            ),
            ttl_seconds=int(resolved_settings.ema_cimd_cache_ttl_seconds),
        )
        if resolved_settings.ema_cimd_resolution_enabled
        else None
    )
    # MCP-2 P3 · MRTR governance. Unknown kind names are refused at
    # startup rather than silently ignored: a typo'd `elicit_urls` that
    # quietly disables the allowlist is worse than a boot failure.
    _mrtr_kinds = set()
    for _raw in resolved_settings.mrtr_allowed_input_kinds:
        try:
            _kind = InputRequestKind(_raw.strip().lower())
        except ValueError as exc:
            raise RuntimeError(
                f"VYUU_MRTR_ALLOWED_INPUT_KINDS contains unknown kind {_raw!r}; "
                f"valid: {', '.join(_valid_mrtr_kind_names())}"
            ) from exc
        if _kind is InputRequestKind.UNKNOWN:
            raise RuntimeError(
                "'unknown' cannot be enabled — unclassifiable input requests "
                "are always refused"
            )
        _mrtr_kinds.add(_kind)
    app.state.mrtr_policy = MrtrPolicy(
        allowed_kinds=frozenset(_mrtr_kinds),
        allowed_elicit_url_hosts=frozenset(
            h.strip().lower() for h in resolved_settings.mrtr_allowed_elicit_url_hosts if h.strip()
        ),
    )
    app.state.upstream_health_checker = upstream_health_checker or UpstreamHealthChecker(
        SessionLocal,
        app.state.upstream_clients,
        timeout_seconds=resolved_settings.upstream_health_timeout_seconds,
    )
    # Capability sync uses the same upstream-client provider the tool-call
    # hot path uses. Tests inject `FakeInMemoryMcpClient` directly to skip
    # the upstream lookup; production wires the adapter so HTTP-driven
    # `/api/v1/servers/{id}/sync` reuses the production pool / breakers.
    app.state.capability_sync_client = capability_sync_client or (
        UpstreamProviderCapabilityClient(app.state.upstream_clients)
    )
    # Periodic capability-sync scheduler. Off by default — operators
    # opt in via `VYUU_CAPABILITY_SYNC_ENABLED=true`. When on, the
    # lifespan starts a background task that walks all registered
    # upstreams on a configurable cadence.
    if resolved_settings.capability_sync_enabled:
        app.state.capability_sync_scheduler = PeriodicCapabilitySyncScheduler(
            session_factory=SessionLocal,
            capability_client=app.state.capability_sync_client,
            interval_seconds=resolved_settings.capability_sync_interval_seconds,
            max_concurrent_per_tenant=(
                resolved_settings.capability_sync_max_concurrent_per_tenant
            ),
            per_call_timeout_seconds=(
                resolved_settings.capability_sync_per_call_timeout_seconds
            ),
        )
    else:
        app.state.capability_sync_scheduler = None
    # A3-β: OIDC providers + JWKS cache. Constructed lazily — only the
    # configured providers are wired. Login endpoints 404 on unknown
    # provider names so a partial config doesn't expose dead routes.
    app.state.oidc_providers = _build_oidc_providers(resolved_settings)

    # Audit fan-out chain (top-down):
    #
    #   RecentAuditEmitter   ← in-memory hot cache (live "tail" view)
    #     └─ PostgresToolCallEventStore   ← durable source of truth
    #          └─ raw_emitter (Kafka / NATS / local stub)
    #
    # Every emitted event traverses all three. The Postgres write is the
    # one that survives gateway restarts — operator panels read from
    # there with proper time windows. The in-memory buffer is rehydrated
    # from Postgres on startup so the UI shows historical context
    # immediately after a deploy.
    #
    # Composition order matters: place the Postgres store *above* the
    # inner Kafka emitter so the durable write happens first; if Kafka
    # is degraded, the audit row is still on disk in our DB.
    # OTEL-1 · traces + metrics. No-op unless `VYUU_OTEL_ENABLED`.
    app.state.telemetry = build_telemetry(resolved_settings)

    # SIEM-1 · one exporter per process. Tenant targets come from the
    # `tenant_siem_targets` table (console-managed); the deployment
    # target from settings. The exporter sits INSIDE the audit chain,
    # below the Postgres store, so the durable write always happens
    # first and a slow SIEM cannot touch the lifecycle's `EmitResult`.
    siem_exporter = SiemExporter(
        client=SplunkHecClient(),
        resolver=DatabaseTargetResolver(
            SessionLocal,
            deployment=_build_deployment_siem_target(resolved_settings),
            ttl_seconds=resolved_settings.siem_target_cache_ttl_seconds,
        ),
        secret_store=app.state.secret_store,
        gateway_instance_id=resolved_settings.gateway_instance_id,
        telemetry=app.state.telemetry,
        max_queue_size=resolved_settings.siem_max_queue_size,
    )
    app.state.siem_exporter = siem_exporter
    siem_registry.set_exporter(siem_exporter)
    install_admin_audit_hook()
    _install_siem_log_handler()

    raw_emitter = audit_emitter or _LocalAuditEmitter()
    persistent_store = PostgresToolCallEventStore(
        SessionLocal, inner=SiemAuditEmitter(inner=raw_emitter)
    )
    recent_emitter = RecentAuditEmitter(inner=persistent_store)
    app.state.audit_emitter = recent_emitter
    app.state.recent_audit_emitter = recent_emitter
    app.state.graph_event_emitter = graph_event_emitter or NoOpGraphEventEmitter()
    # Lifecycle audit-failure mode is currently fixed at MONITOR for v1.
    # Surfaced via app.state so the inbound route can read it without a
    # second settings indirection.
    app.state.audit_failure_mode = AuditFailureMode.MONITOR

    app.include_router(health_router, prefix="/api/v1")
    # `/healthz` is mounted at app root (no `/api/v1` prefix) and is
    # explicitly bypassed by the per-tenant inflight middleware. K8s
    # liveness probes / load-balancer health checks must point here.
    # See `api/health.py::LIVENESS_BYPASS_PATHS` for the bypass list.
    app.include_router(health_liveness_router)
    app.include_router(servers_router, prefix="/api/v1")
    app.include_router(tenant_settings_router, prefix="/api/v1")
    app.include_router(siem_router, prefix="/api/v1")
    app.include_router(telemetry_router, prefix="/api/v1")
    app.include_router(security_posture_router, prefix="/api/v1")
    app.include_router(api_key_policies_router, prefix="/api/v1")
    app.include_router(risk_router, prefix="/api/v1")
    app.include_router(risk_server_router, prefix="/api/v1")
    app.include_router(risk_vserver_router, prefix="/api/v1")
    # CIMD is mounted at the ROOT: the document's URL *is* the
    # client_id, so it cannot sit behind an /api/v1 prefix that a
    # future version bump would move.
    app.include_router(cimd_router)
    # `/api/v1/admin/diagnostic-bundle` — operator-only download of a
    # gateway-wide JSON diagnostic bundle covering process state, DB
    # connectivity, all servers + vservers, circuit-breaker registry,
    # inflight gate, audit ring buffer summary, settings (with secrets
    # redacted). Replaces the ad-hoc ssh+grep+psql troubleshooting
    # workflow during public testing / customer support.
    app.include_router(diagnostic_bundle_router, prefix="/api/v1")
    # Health & Server Info — operator-console "Overview" page (the
    # cloud-style live snapshot). Distinct from `/diagnostic-bundle`,
    # which is a deep one-shot download for support hand-off.
    app.include_router(health_overview_router, prefix="/api/v1")
    app.include_router(vservers_router, prefix="/api/v1")
    app.include_router(users_router, prefix="/api/v1")
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(access_requests_admin_router, prefix="/api/v1")
    app.include_router(access_requests_portal_router, prefix="/api/v1/portal")
    app.include_router(portal_api_router, prefix="/api/v1/portal")
    app.include_router(audit_events_router, prefix="/api/v1")
    app.include_router(secret_store_router, prefix="/api/v1")
    app.include_router(operator_auth_router, prefix="/api/v1")
    app.include_router(oauth_authcode_router, prefix="/api/v1")
    app.include_router(identities_router, prefix="/api/v1")
    app.include_router(idp_directories_router, prefix="/api/v1")
    app.include_router(admin_audit_router, prefix="/api/v1")
    # IDP-1 Phase 4: per-directory OIDC sign-in — `/api/v1/auth/{tenant_id}
    # /idp/{directory_id}/oidc-{start,callback}`. Mounted under /auth so
    # the URL path is symmetric with the existing local-password +
    # provider-per-deployment OIDC routes.
    app.include_router(idp_signin_router, prefix="/api/v1/auth")
    # Operator-side IdP sign-in — mints an operator JWT after the
    # IdP callback by matching the OIDC/SAML email against the
    # `operators` table. Mounted at `/operator-auth/...` so the URL
    # path mirrors the existing operator login routes.
    app.include_router(
        idp_signin_operator_router, prefix="/api/v1/operator-auth"
    )
    # EMA-1 · Resource Authorization Server surface. Prefix-free: the
    # token endpoint lives under the /v resource namespace and the
    # RFC 9728 metadata at the origin-root path-insertion form clients
    # compute. Both 404 when `VYUU_EMA_ENABLED` is off.
    app.include_router(ema_oauth_router)
    app.include_router(ema_wellknown_router)
    # SCIM 2.0 server — IdPs (Entra, Workspace) push provisioning
    # events here. Bearer auth via the directory's scim_token_hash;
    # tenant context is bound from the directory once the bearer
    # check succeeds. Mounted WITHOUT the /api/v1 prefix because
    # SCIM clients normalise `/scim/v2/...` and won't tolerate
    # extra segments in the path.
    app.include_router(scim_router)
    app.include_router(admin_dashboard_router, prefix="/api/v1")
    app.include_router(nhi_map_router, prefix="/api/v1")
    # `/api/v1/operator/connector-catalog` — read-only SaaS connector
    # catalog (GitHub, Notion, Slack, Linear, Atlassian, etc.) that
    # the operator UI's Quick-add card grid renders. Clicking a card
    # pre-fills the existing register-server wizard; no separate
    # install endpoint.
    app.include_router(connector_catalog_router, prefix="/api/v1")
    app.include_router(inbound_mcp_router)
    app.include_router(operator_ui_router)
    app.include_router(portal_ui_router)

    # Per-tenant inflight gate is added LAST so it wraps every
    # router. ASGI middleware composes outside-in: the gate runs
    # before any route handler and short-circuits with 503 when a
    # tenant has too many in-flight calls. `/healthz` and
    # `/api/v1/health` are bypassed inside the gate (see
    # `api/inflight_gate.py`).
    from vyuu_gateway.api.inflight_gate import PerTenantInflightGate
    app.add_middleware(
        PerTenantInflightGate,
        per_tenant_limit=resolved_settings.inbound_per_tenant_inflight_limit,
    )
    return app


async def _close_if_supported(resource: object) -> None:
    close = getattr(resource, "aclose", None)
    if callable(close):
        result = close()
        if inspect.isawaitable(result):
            await result
        return

    close = getattr(resource, "close", None)
    if callable(close):
        result = close()
        if inspect.isawaitable(result):
            await result


def _build_default_identity_provider(settings: Settings) -> IdentityProvider:
    """Pick the identity provider based on `Settings.inbound_identity_provider`.

    `fake` (default) → `FakeIdentityProvider`, which trusts `x-vyuu-*`
    headers. Suitable for the lab and for tests that pre-fab principals.

    `api_key` → `ApiKeyIdentityProvider`, which validates
    `Authorization: Bearer vyuu_user_*` against the `user_api_keys`
    table. The right choice for any deployment serving real Cursor /
    Claude Desktop / agent clients — they only know how to send a
    `Bearer` token, not the lab's custom headers.

    Tests / lab callers that pass `identity_provider=...` to `create_app`
    bypass this branch entirely (the explicit arg wins).
    """

    backend = settings.inbound_identity_provider.lower()
    base: IdentityProvider
    if backend == "fake":
        base = FakeIdentityProvider()
    elif backend == "api_key":
        # Local import keeps the api-key provider's `cryptography` /
        # `bcrypt` deps off the import-time hot path for tests that don't
        # need them.
        from vyuu_gateway.identity.api_key_provider import ApiKeyIdentityProvider

        base = ApiKeyIdentityProvider(session_factory=SessionLocal)
    else:
        raise RuntimeError(
            "VYUU_INBOUND_IDENTITY_PROVIDER must be 'fake' or 'api_key' "
            f"(got: {settings.inbound_identity_provider!r})"
        )

    if not settings.ema_enabled:
        return base

    # EMA-1: chain the ID-JAG access-token provider BEHIND the base
    # mechanism. Both providers fail fast on the other's bearer shape,
    # so the chain costs one string check per non-matching leg.
    # `/v/{tenant}/oauth/token` mints exactly what this leg verifies.
    if len(settings.ema_signing_secret) < 32:
        raise RuntimeError(
            "VYUU_EMA_ENABLED requires VYUU_EMA_SIGNING_SECRET of at least "
            "32 bytes (it signs inbound access tokens)"
        )
    from vyuu_gateway.identity.chain import ChainedIdentityProvider
    from vyuu_gateway.identity.jwt_bearer_provider import IdpJagIdentityProvider

    return ChainedIdentityProvider(
        [
            base,
            IdpJagIdentityProvider(
                SessionLocal,
                signing_secret=settings.ema_signing_secret,
                issuer_base=settings.public_base_url,
            ),
        ]
    )


def _build_default_secret_store(settings: Settings) -> SecretStore:
    """Pick the SecretStore backend per `Settings.secret_store_backend`.

    `memory` (default) → `InMemorySecretStore`. The lab + tests use this;
    the lab seeds a couple of demo refs at startup. **Not** suitable for
    production — secrets live in process memory.

    `vault` → `VaultSecretStore` against `VYUU_VAULT_ADDR` / token.
    KV v2 mode at `{mount}/data/{tenant_id}/{ref}`. Recommended for POC
    and on-prem-only deployments — runs alongside the gateway, no
    external SaaS dependency.

    `kubernetes` → `KubernetesSecretStore`. Reads `Secret` objects via
    the API server, one Secret per tenant (`vyuu-<tenant_id>`) so
    Kubernetes RBAC can scope access per tenant with `resourceNames` —
    the only granularity RBAC offers for Secrets. For k8s-resident
    deployments that would rather not run a separate KMS. If the pod can
    simply *mount* the secrets it needs, mount them instead; this is for
    the case where the set is not known at deploy time.

    `aws_secrets_manager` → `AwsSecretsManagerStore`. Path layout
    `{prefix}/{tenant_id}/{ref}`. Auth via boto3 default credential
    chain (IAM access keys, IAM Roles Anywhere for on-prem, instance
    profile / pod identity for AWS-resident gateways). Recommended for
    AWS-native deployments and customers who already standardise on AWS.
    """

    backend = settings.secret_store_backend.lower()
    if backend == "memory":
        return InMemorySecretStore()
    if backend == "vault":
        from vyuu_gateway.secrets import VaultSecretStore

        if not settings.vault_addr or not settings.vault_token:
            raise RuntimeError(
                "VYUU_VAULT_ADDR and VYUU_VAULT_TOKEN are required when "
                "VYUU_SECRET_STORE_BACKEND=vault"
            )
        return VaultSecretStore(
            base_url=settings.vault_addr,
            token=settings.vault_token,
            mount=settings.vault_mount,
            namespace=settings.vault_namespace,
            value_field=settings.vault_value_field,
            timeout_seconds=settings.vault_timeout_seconds,
        )
    if backend == "aws_secrets_manager":
        from vyuu_gateway.secrets import AwsSecretsManagerStore

        return AwsSecretsManagerStore(
            region_name=settings.aws_region,
            prefix=settings.aws_secrets_prefix,
            value_field=settings.aws_secrets_value_field,
        )
    if backend == "kubernetes":
        from vyuu_gateway.secrets import KubernetesSecretStore

        return KubernetesSecretStore(
            namespace=settings.k8s_namespace,
            api_server=settings.k8s_api_server,
            secret_name_prefix=settings.k8s_secret_name_prefix,
            timeout_seconds=settings.k8s_timeout_seconds,
        )
    raise RuntimeError(
        "VYUU_SECRET_STORE_BACKEND must be 'memory', 'vault', "
        "'aws_secrets_manager', or 'kubernetes' "
        f"(got: {settings.secret_store_backend!r})"
    )


def _build_default_policy_provider(settings: Settings) -> PolicyProvider:
    if settings.policy_provider_backend == "simple":
        return SimplePolicyProvider(
            capture_raw_audit=settings.audit_capture_raw_default,
        )

    if settings.policy_provider_backend == "management_plane":
        if settings.management_plane_policy_base_url is None:
            raise RuntimeError(
                "VYUU_MANAGEMENT_PLANE_POLICY_BASE_URL is required when "
                "VYUU_POLICY_PROVIDER_BACKEND=management_plane"
            )
        return ManagementPlanePolicyProvider(
            base_url=settings.management_plane_policy_base_url,
            ttl_seconds=settings.management_plane_policy_ttl_seconds,
            bearer_token=settings.management_plane_policy_bearer_token,
        )

    raise RuntimeError(
        "VYUU_POLICY_PROVIDER_BACKEND must be 'simple' or 'management_plane'"
    )


def _build_oidc_providers(settings: Settings) -> dict[str, OidcProvider]:
    """Construct configured OIDC providers from settings.

    Returns a name→provider dict; only the providers whose required
    settings are all present are constructed. Empty dict (no logins
    available) is a valid state — operators may still ship a gateway
    that uses local-password only or API-key only.
    """

    from vyuu_gateway.users.oidc import JwksCache
    from vyuu_gateway.users.oidc_providers import (
        GoogleWorkspaceProvider,
        MicrosoftEntraIdProvider,
    )

    providers: dict[str, OidcProvider] = {}
    cache = JwksCache()

    if all(
        v is not None
        for v in (
            settings.oidc_microsoft_tenant_id,
            settings.oidc_microsoft_client_id,
            settings.oidc_microsoft_client_secret,
            settings.oidc_microsoft_redirect_uri,
        )
    ):
        providers["microsoft"] = MicrosoftEntraIdProvider.build(
            microsoft_tenant_id=settings.oidc_microsoft_tenant_id,  # type: ignore[arg-type]
            client_id=settings.oidc_microsoft_client_id,  # type: ignore[arg-type]
            client_secret=settings.oidc_microsoft_client_secret,  # type: ignore[arg-type]
            redirect_uri=settings.oidc_microsoft_redirect_uri,  # type: ignore[arg-type]
            jwks_cache=cache,
        )
    if all(
        v is not None
        for v in (
            settings.oidc_google_client_id,
            settings.oidc_google_client_secret,
            settings.oidc_google_redirect_uri,
        )
    ):
        providers["google"] = GoogleWorkspaceProvider.build(
            client_id=settings.oidc_google_client_id,  # type: ignore[arg-type]
            client_secret=settings.oidc_google_client_secret,  # type: ignore[arg-type]
            redirect_uri=settings.oidc_google_redirect_uri,  # type: ignore[arg-type]
            jwks_cache=cache,
            hosted_domain=settings.oidc_google_hosted_domain,
        )
    return providers


def _build_default_session_registry(settings: Settings) -> SessionRegistry:
    """Choose the default session registry based on configuration.

    `redis_url` set → multi-instance Redis-backed registry.
    `redis_url` unset in local/test only → in-memory registry.

    Tests bypass this entirely by passing `session_registry=...` directly to
    `create_app`; this only handles the app default.
    """
    if settings.redis_url is None:
        if settings.environment not in {"local", "test"}:
            raise RuntimeError(
                "VYUU_REDIS_URL is required outside local/test environments; "
                "in-memory sessions are not safe for multi-instance runtime deployments"
            )
        return InMemorySessionRegistry()
    # Imported lazily so the import-time cost of opening a Redis pool only
    # happens when Redis is actually configured.
    from redis.asyncio import from_url as redis_from_url

    client = redis_from_url(settings.redis_url, decode_responses=True)
    return RedisSessionRegistry(client, key_prefix=settings.session_redis_key_prefix)



def _build_deployment_siem_target(settings: Settings) -> TargetConfig | None:
    """The gateway operator's own SIEM target, from env. `None` unless
    both a URL and a token are set — a URL without a token is logged as
    a misconfiguration rather than silently ignored."""

    url = (settings.siem_hec_url or "").strip()
    if not url:
        return None
    if not (settings.siem_hec_token or "").strip():
        logger.warning(
            "siem_deployment_target_ignored",
            extra={"reason": "VYUU_SIEM_HEC_URL is set but VYUU_SIEM_HEC_TOKEN is empty"},
        )
        return None
    try:
        normalised = normalise_hec_url(url)
    except InvalidHecUrlError as exc:
        logger.warning("siem_deployment_target_ignored", extra={"reason": str(exc)})
        return None
    return TargetConfig(
        key=DEPLOYMENT_KEY,
        tenant_id=None,
        hec_url=normalised,
        token_ref=None,
        token_literal=(settings.siem_hec_token or "").strip(),
        index=(settings.siem_hec_index or None),
        source=settings.siem_hec_source or "vyuu-mcp-gateway",
        host=settings.siem_hec_host or None,
        verify_tls=settings.siem_hec_verify_tls,
        categories=parse_categories(settings.siem_categories),
        include_raw_payloads=settings.siem_include_raw_payloads,
        min_log_level=parse_log_level(settings.siem_log_level),
        batch_max_events=max(1, settings.siem_batch_max_events),
        flush_interval_seconds=max(0.2, settings.siem_flush_interval_seconds),
    )


def _install_siem_log_handler() -> None:
    """Attach the log bridge once. `configure_logging` resets the root
    handlers on every `create_app`, so re-attach — but never twice."""

    root = logging.getLogger()
    for existing in list(root.handlers):
        if isinstance(existing, SiemLogHandler):
            root.removeHandler(existing)
    root.addHandler(SiemLogHandler(level=logging.DEBUG))


app = create_app()
