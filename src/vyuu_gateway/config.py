from functools import lru_cache
from uuid import UUID

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from vyuu_gateway import __version__


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="VYUU_",
        extra="ignore",
    )

    app_name: str = Field(default="Vyuu MCP Gateway")
    database_url: str = Field(default="postgresql+psycopg://vyuu:vyuu@localhost:5432/vyuu_gateway")
    environment: str = Field(default="local")
    log_level: str = Field(default="INFO")
    version: str = Field(default=__version__)

    http_url_allow_private_networks: bool = Field(default=False)
    http_url_allowlist: list[str] = Field(default_factory=list)
    http_url_denylist: list[str] = Field(default_factory=list)

    # H1 · DNS-time SSRF backstop. The registration check above catches
    # unsafe IP *literals*; this re-resolves the hostname immediately
    # before each outbound connection and pins to a validated address, so
    # a name that resolves to 169.254.169.254 at call time cannot slip
    # through. Uses the same three knobs above, so "allowed to register"
    # and "allowed to connect to" cannot drift apart.
    #
    # Default ON: unlike audit retention, the failure mode here is a
    # visible, immediately reversible connection error whose message
    # names the exact remedy — not silent data loss. A deployment whose
    # upstream is genuinely internal sets
    # `http_url_allow_private_networks` or allowlists the host.
    upstream_ssrf_guard_enabled: bool = Field(default=True)

    # --- MCP-2 P3 · MRTR (multi-round tool result) governance ------------
    # Which input-request kinds an upstream may ask the caller's side for
    # when it answers `tools/call` with `InputRequiredResult`. Comma-free
    # list of: sampling, roots, elicit_form, elicit_url.
    #
    # EMPTY by default, which denies all of them — and that is not a new
    # restriction: SDK v2's `call_tool(allow_input_required=False)`
    # already refuses these outright. What changes is that the refusal
    # becomes a `tool_call` audit event naming the kinds, instead of an
    # opaque upstream error.
    #
    # Enable per kind, deliberately. `sampling` lets an upstream drive
    # your users' LLM; `elicit_url` lets it send them to a URL of its
    # choosing. See `mcp/mrtr.py`.
    mrtr_allowed_input_kinds: list[str] = Field(default_factory=list)
    # When `elicit_url` is enabled, restrict destinations. Empty means any
    # host — an explicit decision, not a safe default. Entries match the
    # host or any subdomain of it (`okta.com` matches `login.okta.com`
    # but not `evil-okta.com`).
    mrtr_allowed_elicit_url_hosts: list[str] = Field(default_factory=list)

    # HMAC signing secret used by the v1 fake operator-API auth provider.
    # MUST be overridden in production (a real OIDC/API-key provider replaces
    # this entirely). Default kept only so local-dev and tests can boot.
    operator_auth_signing_secret: str = Field(default="dev-operator-auth-secret")

    # Inbound-MCP identity provider selection. `fake` uses the legacy
    # `x-vyuu-*` header convention (lab default — keeps existing demos
    # and tests working out of the box). `api_key` uses the production
    # `ApiKeyIdentityProvider` that validates `Authorization: Bearer
    # vyuu_user_*` against `user_api_keys` rows. Production deployments
    # set `VYUU_INBOUND_IDENTITY_PROVIDER=api_key`. Tests + lab leave
    # the default. Callers passing `identity_provider=...` to
    # `create_app(...)` explicitly override this setting (the explicit
    # arg always wins).
    inbound_identity_provider: str = Field(default="fake")

    # A6 · SecretStore backend selection. Three backends supported:
    #
    # - `memory` — InMemorySecretStore, dev/lab/test default. Not for prod.
    # - `vault` — HashiCorp Vault KV v2. Recommended for **POC + early
    #   production** because it can run on-prem alongside the gateway, no
    #   external SaaS dependency. Path: `{mount}/data/{tenant_id}/{ref}`.
    # - `aws_secrets_manager` — AWS Secrets Manager. Recommended for
    #   **AWS-native deployments** and customers who already standardise
    #   secrets on AWS. Path: `{prefix}/{tenant_id}/{ref}` (default
    #   prefix `vyuu`). Works on-prem too (HTTPS API call from anywhere
    #   with valid IAM creds — IAM Roles Anywhere is the recommended
    #   on-prem auth path).
    #
    # Production deployments override via `VYUU_SECRET_STORE_BACKEND`.
    # Callers passing `secret_store=...` to `create_app(...)` explicitly
    # override this setting (the explicit arg always wins).
    secret_store_backend: str = Field(default="memory")

    # --- A6.y · Kubernetes Secrets backend --------------------------------
    # Namespace to read from. Left unset, the store reads the pod's own
    # namespace from the projected service-account volume — which is
    # right in-cluster and impossible outside one, hence the override.
    k8s_namespace: str | None = Field(default=None)
    k8s_api_server: str = Field(default="https://kubernetes.default.svc")
    # One Secret per tenant, named `<prefix>-<tenant_id>`. Per-tenant
    # NAMES rather than per-tenant keys inside one Secret, because
    # `resourceNames` is the only per-object granularity Kubernetes RBAC
    # offers — keying inside one object would make every tenant's
    # material reachable by anyone who can read it.
    k8s_secret_name_prefix: str = Field(default="vyuu")
    k8s_timeout_seconds: float = Field(default=5.0)

    # IDP-2 · Google Workspace polling cadence. Per-directory opt-in via
    # `idp_directories.workspace_polling_enabled`, so this only costs a
    # tenant scan when nothing is enabled. 5 minutes: a terminated user
    # keeps access for at most that long, which is the number the whole
    # feature exists to bound.
    workspace_poll_interval_seconds: float = Field(default=300.0)

    # --- AWS-KMS-1 · envelope encryption for data we store ourselves ------
    # `oauth_user_tokens` holds per-user OAuth access + refresh tokens for
    # every connected SaaS. Unencrypted, a database dump / backup / read
    # replica hands over every user's connected accounts at once — and
    # unlike a leaked password, nobody can tell and nothing rotates.
    #
    # Off by default. Turning it on needs NO migration and NO backfill:
    # values are self-describing, so existing plaintext rows keep working
    # and are sealed on their next write.
    #
    # `local`  — 32-byte master key from `VYUU_ENVELOPE_MASTER_KEY`
    #            (base64). Protects against database exposure, not host
    #            compromise; right for on-prem without a KMS.
    # `aws_kms`— master key stays in KMS; only data keys cross the wire.
    envelope_encryption_backend: str = Field(default="none")
    envelope_master_key: str | None = Field(default=None)
    envelope_kms_key_id: str | None = Field(default=None)
    # Vault backend
    vault_addr: str | None = Field(default=None)
    vault_token: str | None = Field(default=None)
    vault_mount: str = Field(default="secret")
    vault_namespace: str | None = Field(default=None)
    vault_value_field: str = Field(default="value")
    vault_timeout_seconds: float = Field(default=5.0)
    # AWS Secrets Manager backend
    aws_region: str | None = Field(default=None)
    aws_secrets_prefix: str = Field(default="vyuu")
    # If non-empty, treat each secret's `SecretString` as JSON and pull
    # this field. Empty / unset means "the whole SecretString IS the
    # value" (the common case — operators paste a Bearer token directly).
    aws_secrets_value_field: str | None = Field(default=None)

    # Inbound MCP session lifetime. Sessions live in memory only (v1) and are
    # dropped on TTL expiry or explicit DELETE. Tune per deployment — short
    # for security, long for client UX.
    session_ttl_seconds: int = Field(default=3600)

    # Identifier emitted with every audit event so operators can tell which
    # gateway instance handled a call. Defaults to a placeholder; production
    # should set per-pod via the deployment.
    gateway_instance_id: str = Field(default="gateway-local")

    # Policy provider backend. `simple` is local/test only. Production should
    # use `management_plane`, which pulls policy documents and evaluates them
    # locally in the hot path.
    policy_provider_backend: str = Field(default="simple")
    management_plane_policy_base_url: str | None = Field(default=None)
    management_plane_policy_ttl_seconds: float = Field(default=60.0)
    management_plane_policy_bearer_token: str | None = Field(default=None)

    # H5 — raw-args / raw-response audit capture default. Default
    # `False` preserves privacy-by-default (spec §3.3): production
    # policies stay metadata-only unless they explicitly opt in via
    # `PolicyDecision.allow(capture_raw_args=True, ...)`. Dev / lab /
    # POC deployments set `VYUU_AUDIT_CAPTURE_RAW_DEFAULT=true` so the
    # `Events` panel renders full bodies without per-rule policy
    # authoring. Currently honored by `SimplePolicyProvider` only —
    # `ManagementPlanePolicyProvider` decides per rule.
    audit_capture_raw_default: bool = Field(default=False)

    # Per-payload byte cap for raw args / response storage in audit
    # events. **Transit is never blocked by this cap** — large requests
    # / responses still flow through the gateway to clients unchanged.
    # Only the audit-storage record is affected: when an opted-in
    # capture exceeds this size, the gateway records the original
    # `total_bytes` count and substitutes a truncation sentinel for the
    # `raw_args` / `raw_response` field. Default 10 MiB is chosen to
    # accommodate large `get_file_contents` / `search_code` responses
    # while keeping a single pathological call from saturating the
    # audit pipeline. Operators with stricter audit-storage budgets can
    # lower this; deployments that want unbounded capture can raise it.
    audit_raw_capture_byte_cap: int = Field(default=10 * 1024 * 1024)

    # --- RETENTION-1: durable-audit retention -----------------------------
    # Both default to 0 = KEEP FOREVER. This ships the prune *mechanism*;
    # the window is a legal/deployment decision, the delete is
    # irreversible, and upgrading the gateway must never silently destroy
    # audit history. 90 days is the documented starting point for
    # `tool_call_events`; auditors typically want `admin_audit_log` kept
    # a year or more. See `audit/retention.py`.
    tool_call_event_retention_days: int = Field(default=0)
    admin_audit_retention_days: int = Field(default=0)
    # Daily. The window is measured in days, so a tighter cadence buys
    # nothing and multiplies the `retention.prune` audit rows.
    audit_retention_interval_seconds: float = Field(default=24 * 3600.0)
    # Rows per committed chunk, and the ceiling per table per tenant per
    # cycle. The cap makes the first prune after opt-in drain over several
    # cycles instead of holding the DB down for an hour.
    audit_retention_batch_size: int = Field(default=5_000)
    audit_retention_max_rows_per_cycle: int = Field(default=200_000)

    # Inbound back-pressure (Tier-1 stress-test fix). The load test at
    # 32 in-flight on a single uvicorn worker queued thousands of
    # requests behind tool calls, then health probes timed out, then
    # session inits cascaded into client-side timeouts. uvicorn has
    # built-in support for fast-fail 503 — wire it via Settings so all
    # entrypoints (lab, prod, custom) get the same protection.
    #
    # `inbound_limit_concurrency`: maximum number of concurrent requests
    # a single worker will service. New requests beyond the cap get an
    # immediate 503 with `Retry-After` instead of queueing. Set per the
    # observed knee for your worker hardware (M5 single core: ~640 RPS
    # at p99=24ms with 8 inflight on the deny path; pick a cap that
    # gives your p99 SLO some headroom).
    inbound_limit_concurrency: int = Field(default=200)
    # Worker recycles after N requests (defends against slow leaks).
    # `0` disables recycling.
    inbound_limit_max_requests: int = Field(default=10_000)
    # Kernel accept-queue depth. Past this, new TCP connections are
    # refused at the OS layer rather than buffered.
    inbound_backlog: int = Field(default=128)
    # Idle keep-alive timeout. Closing idle connections sooner returns
    # FDs faster under load bursts.
    inbound_keep_alive_seconds: int = Field(default=5)

    # Per-tenant inflight semaphore (Tier-1 stress-test fix). Today one
    # tenant's runaway agent can saturate the gateway and starve every
    # other tenant. This caps in-flight tool calls per tenant; calls
    # past the cap fast-503 with `category=rate_limited`. Default is
    # generous; tighten per known tenant tier in policy if needed.
    inbound_per_tenant_inflight_limit: int = Field(default=64)

    # H3 — payload size limits. **Distinct from `audit_raw_capture_byte_cap`**:
    # these caps apply to TRANSIT — over-cap requests get 413 Payload
    # Too Large before reaching the upstream; over-cap responses get
    # truncated with a marker. Audit cap controls only what's stored
    # in the audit event; this controls what's allowed through. Default
    # 5 MiB request / 25 MiB response accommodate the largest typical
    # MCP payloads (file_get_contents on big repos, search-code result
    # sets) while bounding worst-case audit + memory cost.
    inbound_max_request_body_bytes: int = Field(default=5 * 1024 * 1024)
    inbound_max_response_body_bytes: int = Field(default=25 * 1024 * 1024)
    # When True, the inbound layer scans response bodies for common
    # secret shapes (API keys, JWTs, AWS access keys) and replaces
    # matches with `[REDACTED:<kind>]` before forwarding to the
    # client AND before audit emit. Default off — opt-in per tenant
    # via policy.
    inbound_redact_response_secrets: bool = Field(default=False)

    # SQLAlchemy connection pool (Tier-1 stress-test fix). The previous
    # SQLAlchemy default (pool_size=5, max_overflow=10) caps the gateway
    # at 15 concurrent DB transactions. The realistic-mix load test
    # surfaced this as a hidden ceiling: 128 concurrent inbound tool
    # calls all queue at the resolver's vserver lookup, then time out
    # at SQLAlchemy's 30s `pool_timeout`, masquerading as gateway
    # unresponsiveness. Bump defaults to numbers the inflight gate can
    # actually feed — `inbound_per_tenant_inflight_limit + headroom`
    # is the right rough sizing.
    db_pool_size: int = Field(default=20)
    db_pool_max_overflow: int = Field(default=40)
    # Pool acquire timeout: how long a request waits for a free
    # connection before failing. Lower than SQLAlchemy default (30s)
    # because we'd rather fail-fast and 503 than queue silently.
    db_pool_timeout_seconds: float = Field(default=10.0)
    # Recycle connections older than this. Reasonable upper bound vs.
    # Postgres `idle_in_transaction_session_timeout` and
    # `tcp_keepalives_*` GUCs typically set in production.
    db_pool_recycle_seconds: int = Field(default=1800)

    # Default upstream MCP read timeout. Applied by
    # `DatabaseBackedUpstreamClientProvider` when constructing
    # `StreamableHttpMcpClient` instances.
    upstream_read_timeout_seconds: float = Field(default=30.0)
    upstream_max_connections_per_server: int = Field(default=4)
    upstream_health_timeout_seconds: float = Field(default=5.0)
    upstream_circuit_breaker_failure_threshold: int = Field(default=5)
    upstream_circuit_breaker_recovery_timeout_seconds: float = Field(default=30.0)

    # P2 · how long a pooled upstream client may keep serving with the
    # credential it was built from. Org-tier `auth_headers` are resolved
    # from the SecretStore once, in the pool factory, and then baked into
    # the transport client — so without this a rotated secret only takes
    # effect when the connection happens to drop or a circuit breaker
    # opens. A tenant rotating a *leaked* credential could keep serving
    # with it for hours, which is the opposite of what rotating it was
    # for.
    #
    # 15 minutes: short enough that a rotation is effective within one
    # coffee break, long enough that a busy upstream is not rebuilding
    # its transport constantly. Set to 0 to disable and restore the
    # previous keep-until-broken behaviour.
    upstream_client_max_age_seconds: float = Field(default=900.0)

    # --- S1.b · Sigstore provenance for `binary` upstreams ---------------
    # Unset (the default) disables verification entirely — the pre-S1.b
    # behaviour. Setting it is a statement that only signed binaries may
    # run, which is why a MISSING `cosign` then becomes a hard failure
    # rather than a skip: "we could not check" must never silently mean
    # "it is fine".
    #
    # Verification runs on every client build, not only at registration:
    # registration proves the file was good once, and the threat is the
    # file changing afterwards.
    binary_cosign_verification_key_path: str | None = Field(default=None)
    # Optional keyless/OIDC signer constraints, passed through to cosign
    # so the operator's policy lives in one place.
    binary_cosign_certificate_identity: str | None = Field(default=None)
    binary_cosign_certificate_oidc_issuer: str | None = Field(default=None)

    # Redis URL for the multi-instance session registry. When unset in local
    # or test environments, the gateway uses `InMemorySessionRegistry`.
    # Outside local/test, `VYUU_REDIS_URL` is required so runtime deployments
    # do not silently fall back to process-local sessions.
    redis_url: str | None = Field(default=None)
    session_redis_key_prefix: str = Field(default="vyuu:session")

    # Periodic capability-sync worker (S7). Off by default — sync against
    # every registered upstream on a cadence is a real load source. Ops
    # opt in per deployment. Per-tenant concurrency cap prevents a
    # 1000-server tenant from hammering all upstreams in seconds.
    capability_sync_enabled: bool = Field(default=False)
    capability_sync_interval_seconds: float = Field(default=3600.0)
    capability_sync_max_concurrent_per_tenant: int = Field(default=4)
    capability_sync_per_call_timeout_seconds: float = Field(default=30.0)

    # Auto-sync on registration (Tier-1 stress-test fix). Today an
    # operator who registers a server but doesn't click Sync hits the
    # `capabilities_not_synced` deny on every tool call until they
    # do. This kicks off a sync as a fire-and-forget background task
    # immediately after a successful registration. Failures are
    # logged + visible via `mcp_servers.last_capabilities_pulled_at`
    # staying NULL; the periodic scheduler (when enabled) is the
    # long-tail backup. Disable if your deployment registers servers
    # in bulk via a separate orchestrator that drives sync explicitly.
    auto_sync_capabilities_on_registration: bool = Field(default=True)
    # Tight timeout for the inline-after-registration sync attempt.
    # Stdio uvx/npx upstreams cold-start in 2-3s; HTTP MCPs in <1s.
    # 30s is generous but bounds the background task so a stuck sync
    # doesn't hold a worker indefinitely.
    auto_sync_per_call_timeout_seconds: float = Field(default=30.0)

    # A3-β: portal session signing. Used to mint browser-session JWTs
    # after a successful login (local password OR OIDC). Distinct from
    # `operator_auth_signing_secret` which is for the lab's HMAC test
    # tokens. Production MUST set a long random value.
    portal_session_signing_secret: str = Field(default="dev-portal-session-secret")
    portal_session_ttl_seconds: int = Field(default=43200)  # 12h

    # On-prem single-tenant deployments set this to the tenant_id their
    # gateway is bound to. When set, the operator + portal login pages
    # auto-resolve the tenant on load (hide the input, render IdP
    # buttons immediately, no UUID paste). When unset (SaaS / multi-
    # tenant build), the login pages fall back to asking for tenant_id
    # / accepting `?tenant=<uuid>` URL param. The DB still RLS-scopes
    # everything by tenant_id — this knob is purely UX.
    # IDP-3 · the domain tenant subdomains hang off, e.g.
    # `gateway.example.com` so that `acme.gateway.example.com` resolves
    # the tenant with slug `acme`. Unset (the default) disables
    # host-based resolution entirely and the UUID / `default_tenant_id`
    # paths are unchanged.
    #
    # Requires wildcard DNS + a wildcard cert at the deployment side.
    # The `Host` header is client-supplied, so this only decides which
    # login page renders — never who the caller is. See
    # `api/tenant_routing.py`.
    portal_base_domain: str | None = Field(
        default=None,
        validation_alias=AliasChoices("portal_base_domain", "VYUU_PORTAL_BASE_DOMAIN"),
    )

    default_tenant_id: UUID | None = Field(
        default=None,
        validation_alias=AliasChoices("default_tenant_id", "VYUU_DEFAULT_TENANT_ID"),
    )

    # --- EMA-1 · MCP Enterprise-Managed Authorization (ID-JAG) ----------
    # Master switch for the whole EMA surface: the `/oauth/token`
    # jwt-bearer endpoint, RFC 9728 protected-resource metadata, and the
    # EMA leg of the inbound identity chain. Off by default — enabling
    # also requires per-directory `ema_enabled` in `idp_directories`.
    ema_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("ema_enabled", "VYUU_EMA_ENABLED"),
    )
    # HS256 secret for the short-lived access tokens OUR token endpoint
    # mints after validating an IdP's ID-JAG. Distinct from the operator
    # signing secret on purpose: rotating one surface must not log the
    # other out. MUST be ≥32 bytes in production; `create_app` refuses
    # to enable EMA on a shorter one.
    ema_signing_secret: str = Field(
        default="",
        validation_alias=AliasChoices("ema_signing_secret", "VYUU_EMA_SIGNING_SECRET"),
    )
    # Lifetime of minted access tokens. Short by design — revocation is
    # "stop minting" + the per-call directory/user checks; 15 min keeps
    # the exposure window of a leaked token small.
    ema_access_token_ttl_seconds: int = Field(
        default=900,
        validation_alias=AliasChoices(
            "ema_access_token_ttl_seconds", "VYUU_EMA_ACCESS_TOKEN_TTL_SECONDS"
        ),
    )
    # MCP-2 P3 · resolve inbound client_ids that are https URLs against
    # the CIMD document they point at, instead of only string-matching
    # them against `ema_allowed_client_ids`. Buys revocation (a client
    # whose document goes away stops being accepted) and a real client
    # name in the audit trail.
    #
    # Off by default because it makes an allowlisted client's document
    # availability part of this gateway's auth path. Only ALLOWLISTED
    # client_ids are ever fetched — the URL set is chosen by an
    # operator, never by a request; see `identity/cimd_inbound.py`.
    ema_cimd_resolution_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "ema_cimd_resolution_enabled", "VYUU_EMA_CIMD_RESOLUTION_ENABLED"
        ),
    )
    # How long a successfully resolved document is trusted before being
    # re-fetched. This is also the worst-case delay before a revoked
    # client (document taken down) stops being accepted.
    ema_cimd_cache_ttl_seconds: int = Field(
        default=900,
        validation_alias=AliasChoices(
            "ema_cimd_cache_ttl_seconds", "VYUU_EMA_CIMD_CACHE_TTL_SECONDS"
        ),
    )
    # Public origin of this gateway, used to build the per-tenant
    # resource-authorization-server issuer (`{base}/v/{tenant_id}`) that
    # RFC 9728 metadata advertises, ID-JAG `aud` must match, and minted
    # tokens carry as `iss`. Behind a reverse proxy this is the OUTSIDE
    # origin, not the bind address.
    public_base_url: str = Field(
        default="http://127.0.0.1:8000",
        validation_alias=AliasChoices("public_base_url", "VYUU_PUBLIC_BASE_URL"),
    )

    # --- SIEM-1 · deployment-level SIEM export (Splunk HEC) ---------------
    # The gateway OPERATOR's SIEM. Receives every category below for every
    # tenant, plus gateway-wide log lines that belong to no tenant. Tenants
    # configure their own targets in the console (`tenant_siem_targets`);
    # those receive only their own events. Unset = no deployment target.
    #
    # The token is an env value, like `vault_token` and the OIDC client
    # secrets — deployment credentials live in the deployment. Tenant
    # tokens go through the SecretStore instead.
    siem_hec_url: str | None = Field(default=None)
    siem_hec_token: str | None = Field(default=None)
    siem_hec_index: str | None = Field(default=None)
    siem_hec_source: str = Field(default="vyuu-mcp-gateway")
    siem_hec_host: str | None = Field(default=None)
    siem_hec_verify_tls: bool = Field(default=True)
    # `SiemCategory` values. JSON list in env, like `http_url_allowlist`:
    # VYUU_SIEM_CATEGORIES='["tool_call","access_attempt","admin_action",
    # "auth","tool_auth","gateway_log"]'. Unset = every category except
    # `gateway_log`, which is volume rather than signal.
    siem_categories: list[str] | None = Field(default=None)
    # Ship raw tool args / responses when policy captured them (H5). Off:
    # a SIEM is one more place a customer's business data would live.
    siem_include_raw_payloads: bool = Field(default=False)
    # Threshold for the `gateway_log` category, a logging level NAME.
    siem_log_level: str = Field(default="WARNING")
    siem_batch_max_events: int = Field(default=100)
    siem_flush_interval_seconds: float = Field(default=2.0)
    # Per-target in-memory queue. Past this, the newest events are
    # dropped and counted; the console shows the target as degraded.
    siem_max_queue_size: int = Field(default=5000)
    # How long a tenant's target config is cached before re-reading the
    # row. A console save invalidates immediately; this bounds staleness
    # across other gateway instances.
    siem_target_cache_ttl_seconds: float = Field(default=60.0)

    # --- OTEL-1 · OpenTelemetry traces + metrics (Splunk OTel Collector) --
    # Deployment-level on purpose. A tenant-editable collector endpoint
    # would let one tenant redirect the whole gateway's telemetry — span
    # attributes carry every tenant's ids — to a host of their choosing.
    # The console shows status and sends a test signal; the endpoint is
    # set here, as part of the deployment.
    #
    # Requires the `[otel]` extra. With it missing and this on, the
    # gateway starts anyway and the Telemetry panel says what to install.
    otel_enabled: bool = Field(default=False)
    # OTLP/HTTP base; `/v1/traces` and `/v1/metrics` are appended. The
    # Splunk OTel Collector's default.
    otel_exporter_otlp_endpoint: str = Field(default="http://localhost:4318")
    # `k1=v1,k2=v2`, the OTEL_EXPORTER_OTLP_HEADERS convention. Where an
    # access token goes when exporting straight to Splunk Observability
    # Cloud (`X-SF-Token=...`) instead of via a local collector.
    otel_exporter_otlp_headers: str | None = Field(default=None)
    otel_service_name: str = Field(default="vyuu-mcp-gateway")
    otel_traces_enabled: bool = Field(default=True)
    otel_metrics_enabled: bool = Field(default=True)
    # Head sampling ratio for traces. 1.0 = every tool call gets a span.
    otel_traces_sample_ratio: float = Field(default=1.0)
    otel_metric_export_interval_seconds: float = Field(default=30.0)

    # A3-β: OIDC providers (Microsoft Entra ID + Google Workspace). All
    # optional — operators wire whichever they need. Per-tenant routing
    # of these is a future enhancement; v1 is gateway-global.
    oidc_microsoft_tenant_id: str | None = Field(default=None)
    oidc_microsoft_client_id: str | None = Field(default=None)
    oidc_microsoft_client_secret: str | None = Field(default=None)
    oidc_microsoft_redirect_uri: str | None = Field(default=None)
    oidc_google_client_id: str | None = Field(default=None)
    oidc_google_client_secret: str | None = Field(default=None)
    oidc_google_redirect_uri: str | None = Field(default=None)
    oidc_google_hosted_domain: str | None = Field(
        default=None,
        description="Restrict Google Workspace logins to this domain (e.g. 'corp.com').",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
