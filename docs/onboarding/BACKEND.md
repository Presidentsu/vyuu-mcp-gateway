# BACKEND — components and tech

Per-package guide. Each entry: what it owns, what tech, where to look.

## Stack

- **Python 3.12+** (3.14 verified in development)
- **FastAPI** — HTTP framework, routers, dependency injection
- **SQLAlchemy 2.0** — ORM + Core for queries; uses `Mapped[]` typing
- **Alembic** — migrations
- **psycopg v3** — Postgres driver (NOT psycopg2)
- **PostgreSQL 14+** — only durable store
- **pydantic v2** + **pydantic-settings** — schemas + Settings
- **PyJWT** — operator + portal JWTs
- **bcrypt** + **passlib** — password / API-key / SCIM-token hashing
- **pysaml2** — SAML 2.0 IdP integration (wraps `xmlsec1` system bin)
- **httpx** — HTTP client (upstream MCP, OIDC discovery, JWKS)
- **starlette** middleware — used for tenant inflight gate, CORS
- **uvicorn** — ASGI server
- **pytest** + **pytest-asyncio** — tests

Optional / pluggable:
- **Redis** — session registry + Lua atomic ops (in-memory default)
- **Kafka** / **NATS** — audit fan-out (Postgres durable by default)
- **ClickHouse** — long-term audit warehouse (consumer in `audit/clickhouse_consumer.py`)
- **Vault** — secret store backend (in-memory + Postgres backends shipped)

## `src/vyuu_gateway/api/`

One file per HTTP surface. Routers built with `APIRouter`; included in
`main.py`. Conventions:

- Tenant-scoped routes use `Depends(get_tenant_scoped_db)` — opens a
  Session and binds `app.current_tenant_id`.
- Operator routes use `Depends(authenticate_operator)` — verifies JWT.
- Portal routes use `Depends(authenticate_portal_session)` — verifies
  the portal JWT.
- Inbound MCP routes are PER-TENANT URL-pathed and use the bearer
  resolver instead of the operator JWT.

Notable files:

| File | Purpose |
|---|---|
| `inbound_mcp.py` | `/v/{tenant}/{vserver}/mcp` — the hot path. Resolves bearer, runs lifecycle, emits audit. |
| `dependencies.py` | `get_tenant_scoped_db` — the only RLS-aware DB dep for the operator API. |
| `audit_events.py` | `/audit-events` reads from `tool_call_events`. Default 24h window. |
| `nhi_map.py` | 5-column NHI graph. Reads `tool_call_events` + `mcp_capabilities`. |
| `identities.py` | Per-principal aggregates + timeline + dependency graph. |
| `health_overview.py` | Live snapshot for the Health & servers page (KPIs + status cards + servers + p95 chart). |
| `diagnostic_bundle.py` | One-shot JSON download for support hand-off. Bundle version 1.1. |
| `idp_directories.py` | Connect / disconnect Entra / Workspace directories. |
| `idp_signin.py` | Per-directory OIDC + SAML sign-in (portal + operator-side). |
| `admin_audit.py` | Read-side of `admin_audit_log` with filters. |
| `admin_dashboard.py` | KPI rollups for the Dashboard page. |
| `operator_ui.py` | The single-page HTML for the operator console (~12k lines). |
| `portal_ui.py` | Single-page HTML for the end-user portal. |

## `src/vyuu_gateway/audit/`

The audit pipeline.

| File | Purpose |
|---|---|
| `events.py` | `AuditEvent` shape + factories (`create_tool_call_audit_event`, `create_access_attempt_audit_event`). H5 raw-payload capture cap. |
| `emitter.py` | `AuditEmitter` Protocol + `AsyncAuditEmitter`, `DiskSpoolAuditEmitter`. |
| `recent.py` | `RecentAuditEmitter` — in-memory ring buffer, hot read-cache. `warm_load(event)` is the hydration entrypoint. |
| `persistent.py` | **TOOL-EVENTS-1.** `PostgresToolCallEventStore` (sync INSERT), `query_tool_call_events`, `seed_recent_buffer_from_postgres`. |
| `admin_audit.py` | `record_admin_action()` — same-transaction guarantee for admin-action audit rows. Never commits; caller commits both. |
| `producer.py` | Kafka / NATS / TestAuditProducer interfaces. |

## `src/vyuu_gateway/siem/` and `src/vyuu_gateway/telemetry/`

SIEM export (Splunk HEC) and OpenTelemetry.

| File | What |
|---|---|
| `siem/events.py` | `SiemEvent` — one shape for tool calls, rejections, admin actions, sign-ins, tool auth, logs. |
| `siem/hec.py` | Splunk HEC envelope + client. URL normalisation, retryability. |
| `siem/exporter.py` | Non-blocking per-target queues, batching, retry, delivery stats. |
| `siem/targets.py` | Deployment target from `Settings`; tenant targets from `tenant_siem_targets` (cached). |
| `siem/bridges.py` | Audit-chain wrapper; admin-audit ship-at-commit hook; log handler; `record_signin` / `record_tool_auth`. |
| `telemetry/__init__.py` | `Telemetry` — the internal no-op-safe API the hot path calls. |
| `telemetry/otel.py` | `OtelTelemetry` over OTLP/HTTP (lazy import of the `[otel]` extra). |
| `api/siem.py` | `/admin/siem/*` — tenant-scoped config, token, test, status. |
| `api/telemetry.py` | `/admin/telemetry/*` — status + test signal. |
| `spool.py` | `DiskSpool` overflow store for when downstream emitters are down. |
| `failure.py` | `AuditFailureMode` enum (MONITOR / ENFORCE) — controls how the lifecycle reacts to an audit emit failure. |
| `identity_aggregator.py` | `summarize_identities()` — turns the audit event stream into `IdentitySummary` rows. |
| `clickhouse_consumer.py` | Reads from Kafka, writes to ClickHouse (long-term warehouse). |

## `src/vyuu_gateway/db/`

| File | Purpose |
|---|---|
| `models.py` | All SQLAlchemy models. ~1300 lines. RLS-enforced on every tenant-scoped table. |
| `base.py` | `Base = DeclarativeBase` — common base. |
| `session.py` | `engine`, `SessionLocal`, `bind_tenant_context()`, the `after_begin` listener that sets `app.current_tenant_id`. |
| `enums.py` | Postgres enum compatibility helpers. |

`models.py` is intentionally one-file. Splitting it would create
import-cycle risks (the FK graph is dense). It's well-organised with
section banners; use editor go-to-symbol.

## `src/vyuu_gateway/identity/`

Inbound bearer → Principal resolution.

| File | Purpose |
|---|---|
| `provider.py` | `IdentityProvider` Protocol. |
| `api_key.py` | `ApiKeyIdentityProvider` — production. Looks up `vyuu_user_*` bearers in `user_api_keys` (bcrypt verify). |
| `fake.py` | `FakeIdentityProvider` — dev / lab stub. |

## `src/vyuu_gateway/operator_auth/`

Operator console authentication.

| File | Purpose |
|---|---|
| `provider.py` | `OperatorAuthProvider` Protocol. |
| `fake.py` | `FakeOperatorAuthProvider` — HMAC-signed token; lab default. |
| `models.py` | `AuthenticatedOperator` shape (tenant_id, operator_id, display). |
| `dependency.py` | `authenticate_operator` FastAPI dependency. |
| `password_auth.py` | Local-password operator login + bcrypt rehash; emits admin audit. |

## `src/vyuu_gateway/idp/`

IDP-1: per-tenant Entra / Google Workspace directory connection.

| File | Purpose |
|---|---|
| `service.py` | CRUD against `idp_directories` + JIT-create user resolver. |
| `schemas.py` | Pydantic schemas for the connect endpoint. |
| `scim_tokens.py` | Mints `vyuu_scim_*` bearers + bcrypt hash. |
| `saml_provider.py` | `SamlProvider` wrapping `pysaml2.Saml2Client`. Configures `allow_unsolicited`, `want_response_signed`. |
| `sweeper.py` | `HardDeleteSweeper` — hourly cron, 7-day grace before hard-delete of soft-deleted SCIM users. |

## `src/vyuu_gateway/scim/`

RFC 7644 (SCIM 2.0) server.

| File | Purpose |
|---|---|
| `server.py` | FastAPI router at `/scim/v2/{directory_id}`. Routes for ServiceProviderConfig, Schemas, ResourceTypes, Users, Groups (POST/GET/PUT/PATCH/DELETE). |
| `users.py` | `create_from_scim`, `replace_from_scim`, `soft_delete`, `set_active`. |
| `groups.py` | Same shape + `add_members` / `remove_members`. |
| `auth.py` | `authenticate_scim` dependency. Bcrypt-verifies the directory's `scim_token_hash`. |
| `schemas.py` | SCIM Pydantic models + `default_service_provider_config()`. |
| `errors.py` | RFC 7644 §3.12 error envelope. |

The PATCH handler accepts both Entra's `Operations[]` shape and Google
Workspace's `members[]` replacement.

## `src/vyuu_gateway/users/`

| File | Purpose |
|---|---|
| `passwords.py` | bcrypt hash + verify with cost factor 12. |
| `oidc_providers.py` | OIDC providers (Google / Microsoft / generic) wired from Settings. |
| `jwks.py` | JWKS cache with TTL. |
| `login_endpoint.py` | `/auth/login` — local password sign-in for users. |

## `src/vyuu_gateway/registry/`

User / group / API-key / access-request services. These are the
business-logic functions invoked by the operator-API routers.
Every mutating call accepts an `actor` parameter and emits an
`admin_audit_log` row in the same transaction (no separate session).

| File | Purpose |
|---|---|
| `users_service.py` | create / disable / API key issue / grant write. |
| `groups_service.py` | group CRUD + membership. |
| `access_requests_service.py` | approve / decline / withdraw flow. |
| `portal_schemas.py` | Pydantic shapes for portal endpoints. |

## `src/vyuu_gateway/virtual_servers/`

| File | Purpose |
|---|---|
| `service.py` | vserver create / update / delete + tool projection. Emits admin audit. |
| `validation.py` | name regex + uniqueness checks. |

## `src/vyuu_gateway/upstream/`

Upstream MCP client lifecycle.

| File | Purpose |
|---|---|
| `provider.py` | `DatabaseBackedUpstreamClientProvider` — looks up server by id, returns pooled client. |
| `pool.py` | Per-`(server_id, principal)` client pool. |
| `circuit_breaker.py` | `UpstreamCircuitBreakerRegistry` — open / half-open / closed per pool key. |
| `health.py` | `UpstreamHealthChecker` — periodic TCP/HTTP probe. |
| `oauth_authcode.py` | Per-user delegated OAuth (RFC 6749 authorization code) for upstream MCPs that require user-scoped tokens. |
| `oauth_jwt_bearer.py` | RFC 7523 JWT-bearer flow for service-account upstreams. |

## `src/vyuu_gateway/policy/`

Policy decision providers.

| File | Purpose |
|---|---|
| `interfaces.py` | `PolicyProvider` Protocol + `PolicyDecision` shape. |
| `simple.py` | `SimplePolicyProvider` — always-allow + denylist; default. |
| `management_plane.py` | `ManagementPlanePolicyProvider` — calls a remote policy service (OPA-style); for customers with central policy. |

## `src/vyuu_gateway/capabilities/`

`tools/list` cadence.

| File | Purpose |
|---|---|
| `client.py` | `McpCapabilityClient` Protocol. |
| `upstream_adapter.py` | Adapter that uses the production upstream pool to issue `tools/list`. |
| `scheduler.py` | `PeriodicCapabilitySyncScheduler` — opt-in via env. |
| `service.py` | Per-server sync logic; writes to `mcp_capabilities`. |

## `src/vyuu_gateway/sessions/`

| File | Purpose |
|---|---|
| `registry.py` | `InMemorySessionRegistry` — single-instance default. |
| `redis_registry.py` | `RedisSessionRegistry` — multi-instance HA. Uses Lua scripts for atomic ops. |

## `src/vyuu_gateway/secrets/`

Tenant-scoped secret store (for outbound auth headers + stdio env vars).

| File | Purpose |
|---|---|
| `store.py` | `SecretStore` Protocol. |
| `in_memory.py` | `InMemorySecretStore` — dev default. |
| `postgres.py` | `PostgresSecretStore` — production default; encrypted column. |

## `src/vyuu_gateway/graph/`

Read-side queries for the identity graph.

| File | Purpose |
|---|---|
| `identity_graph.py` | `principal_summary`, `dependency_chain`, `who_can_do`. Power the Identities drill-in pages. |
| `emitter.py` | `GraphEventEmitter` Protocol + `NoOpGraphEventEmitter`. |

## `src/vyuu_gateway/main.py`

`create_app(...)` — the single entry point. Builds:
1. `Settings` from env
2. The `lifespan` async context manager (startup + shutdown hooks)
3. `app.state` wiring for every provider (identity, policy, secret store, sessions, audit emitter chain, sync scheduler, sweeper)
4. Router includes for every API surface

The audit emitter chain construction in `main.py:240-260` is the most
load-bearing wiring decision — see TOOL-EVENTS-1 in `BACKLOG.md`.

## Cross-cutting concerns

### RLS

Every tenant-scoped table has an `ENABLE` (and most have `FORCE`) RLS
policy that gates on `app.current_tenant_id`. The GUC is set per
transaction by the `after_begin` listener in `db/session.py`.

### Same-transaction admin audit

`record_admin_action()` in `audit/admin_audit.py` does
`db.add(model_instance)` but **never commits**. The caller commits
both the mutation and the audit row together. If the request rolls
back, the audit row rolls back too — auditor gets exactly the rows
that correspond to actions that actually happened.

### Inflight gate

`api/inflight_gate.py` is a per-tenant concurrency cap (semaphore).
Configured via `VYUU_INBOUND_PER_TENANT_INFLIGHT_LIMIT`. Returns 503
when the cap is exceeded. Bypassed for `/healthz` so liveness probes
aren't affected.

### Circuit breakers

`upstream/circuit_breaker.py` per `(tenant, server_id, principal_id)`
pool key. Opens on N consecutive failures, half-opens after timeout,
closes after a successful probe.
