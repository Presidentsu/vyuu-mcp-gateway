# Vyuu MCP Gateway — Tech stack reference

**Audience.** Full-stack engineers + DevOps + SRE inheriting the
gateway. Every package, every choice, every alternative considered,
with reasoning. Read this if you need to answer "why X and not Y" or
"can we swap Z out for something else".

**Last revision:** 2026-05-02 (post Tier-1 + Tier-2 stress-test
hardening: persistent stdio subprocess pool, per-tenant inflight
gate, uvicorn back-pressure, /healthz outside request pipeline,
audit storage cap + payload-size limits, A4 401-driven OAuth refresh,
audit consumer wiring, deployment manifests, multi-worker validation,
test-only Prometheus + Grafana perf harness).

---

## 0. Production-readiness layer (added in this revision)

The original tech-stack content (sections 1-14 below) covers what
runs the gateway. This new section covers what makes it survive
production load. Skip if you only need the package list; read if
you're standing up an environment.

### 0.1 Stability primitives

| Concern | Mechanism | Where it lives |
|---|---|---|
| Per-tenant fast-fail rate limit | ASGI middleware, `asyncio.Semaphore` per tenant, fast-503 with Vyuu envelope | `src/vyuu_gateway/api/inflight_gate.py` |
| Liveness probes survive burst | `/healthz` route mounted at app root, bypassed by inflight gate | `src/vyuu_gateway/api/health.py` |
| Worker recycle (slow-leak defence) | uvicorn `--limit-max-requests` driven by `Settings.inbound_limit_max_requests` | `examples/drawio_lab_server.py`, `deploy/` manifests |
| Inbound concurrency cap | uvicorn `--limit-concurrency` driven by `Settings.inbound_limit_concurrency` | same |
| Kernel accept-queue cap | uvicorn `--backlog` | same |
| DB connection pool sized to feed inflight cap | `pool_size=20, max_overflow=40, pool_timeout=10s` | `src/vyuu_gateway/db/session.py` |
| Audit storage cap (transit unaffected) | 10 MiB default, `Settings.audit_raw_capture_byte_cap`; sentinel records `total_bytes` | `src/vyuu_gateway/audit/events.py` |
| Payload size limits (transit) | request 5 MiB / response 25 MiB caps; over-cap fast-413 | `src/vyuu_gateway/api/payload_limits.py` |
| Persistent stdio MCP subprocess pool | supervisor-task pattern, one persistent ClientSession per pool slot, multiplexed cross-task | `src/vyuu_gateway/mcp/outbound.py::StdioMcpClient` |
| Auto-sync capabilities on registration | fire-and-forget background task, 30s timeout, swallowed failures | `src/vyuu_gateway/api/servers.py` |
| 401-driven OAuth refresh | one-shot retry on phase-3/4 401 with single-flight per (server, principal) | `src/vyuu_gateway/upstream/oauth*.py` |

### 0.2 Audit pipeline

| Component | Implementation |
|---|---|
| In-process emit | `vyuu_gateway.audit.recent.RecentAuditEmitter` (1000-event ring buffer; feeds operator UI Events panel + NHI dashboard) |
| Durable producer | `vyuu_gateway.audit.nats_producer.NATSAuditProducer` over `nats-py` |
| Backpressure spool | `vyuu_gateway.audit.emitter.DiskSpoolAuditEmitter` — wraps producer; spools to local NDJSON files when broker is slow / unreachable; replays on recovery |
| Consumer (NATS → ClickHouse) | `vyuu_gateway.audit.clickhouse_consumer` — batched inserts every 1 s or 1000 events, `audit_events` MergeTree with daily partitioning |
| Long-tail archive | partition rollover to S3 / MinIO at 90 days (Parquet + ZSTD) |

Chaos-tested: kill NATS mid-load, gateway spools to disk, drains automatically on recovery.

### 0.3 Test-only observability harness

The gateway ships **no built-in `/metrics` endpoint** in production —
customers wire their own observability against structured JSON access
logs + audit events. For our internal load-testing work, the
`tests/perf/` directory contains:

| File | Purpose |
|---|---|
| `tests/perf/metrics_middleware.py` | ASGI middleware emitting `vyuu_requests_total`, `vyuu_request_duration_seconds`, `vyuu_inflight_requests`, `vyuu_rate_limit_503_total`. Path-normalises high-cardinality URL pieces (`/v/<uuid>/...`) to bound label cardinality. |
| `tests/perf/exporter.py` | Standalone Python process polling gateway PID for CPU / RSS / FDs, counting stdio subprocesses, reading Postgres active conns. Exposes `:9100`. |
| `tests/perf/lab_with_metrics.py` | Boots the lab with the middleware attached. |
| `tests/perf/e2e_stress.py` | 5-phase load harness: gateway hot path / stdio persistent path / past-saturation / sustained burst / cleanup. |
| `tests/perf/docker-compose.yml` | Prometheus + Grafana + grafana-image-renderer sidecar. |
| `tests/perf/grafana/dashboards/vyuu-gateway.json` | 14-panel dashboard. |
| `pyproject.toml` `[perf]` extras | `prometheus_client>=0.20.0` opt-in dependency. |

Production builds (`pip install vyuu-mcp-gateway`) do NOT pull
`prometheus_client`. `src/vyuu_gateway/` has zero imports of it.

### 0.4 Measured performance ceilings (single uvicorn worker, M5 core)

From the reproducible E2E harness in `tests/perf/`:

| Path | Sustained RPS | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| Gateway hot path (deny, no upstream) | 723 peak / 432 at 128 in-flight (with 4080 clean 503s past cap) | 11-217 ms | 87-512 ms | — |
| Stdio persistent path (real upstream tool call, sustained 60s) | **378 RPS, 22,867 calls, 0 failures, 100% healthz** | 28 ms | 67 ms | 107 ms |
| Stdio persistent path peak | **425 RPS** at 8 in-flight | 19 ms | 60 ms | 95 ms |

Multi-worker scaling validated at **3.5× for 4 workers** (perf harness
against `lab_with_metrics.py --workers 4`).

Subprocess count for 51,504 successful tool calls during a 15-minute
window: **10**. Pre-Tier-2: would have been ~51,504 cold-spawned
subprocesses. The persistent pool fix is the single biggest perf win
in the codebase's history.

### 0.5 Deployment surfaces (in `deploy/`)

| Surface | Path | Use case |
|---|---|---|
| Docker Compose | `deploy/docker/docker-compose.yml` | single-box appliance, dev stack, mid-market on-prem |
| systemd | `deploy/systemd/vyuu-gateway.service` + `gateway.env.example` | VM / bare-metal install, no container runtime |
| Kubernetes | `deploy/kubernetes/{deployment, configmap, secret.yaml.example}.yaml` | production K8s / OpenShift |

All three surfaces wire the same Tier-1 contract: `/healthz` for
liveness, `restart: on-failure` (or equivalent), memory + pids cap,
read-only root FS, dropped capabilities, runAsNonRoot.

---

---

## 1. Language + runtime

### Python 3.12+ (developed on 3.14)

`pyproject.toml`: `requires-python = ">=3.12"`.

**Why Python:** the MCP ecosystem's reference SDK (`mcp` package
from Anthropic) is Python-first; sticking with Python keeps us close
to the protocol's source of truth. Type-hints (PEP 695, generic
syntax in 3.12+) + strict mypy give us most of what a typed language
would offer without a build step.

**Why 3.12 floor:** structural pattern matching, native `tomllib`,
`typing.override`, faster CPython, generic TypeVar syntax. We don't
gate on 3.13/3.14 features specifically — that's the current dev
environment, but 3.12 is the supported minimum.

**Alternatives considered:**
- **Go** — lower memory, faster boots. Rejected because the MCP SDK
  is Python; reimplementing the protocol surface in Go would be
  significant ongoing maintenance.
- **TypeScript / Node** — alternative MCP SDK exists. Rejected
  because our team's competence is Python-first and the ecosystem
  for the policy / audit / ORM layers is more mature in Python.

---

## 1.5. System architecture — data + streaming pipelines

This is the map you should carry through the rest of this document.
Three views:

1. **Component layout** — what's running, who talks to whom.
2. **Data + streaming pipelines** — where data lives, how it moves,
   what's cached vs persisted vs streamed.
3. **Tool-call lifecycle** — annotated step-by-step of the hot path.

### 1.5.1 Component layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              Client layer                               │
│                                                                         │
│   Cursor / Claude Desktop / AIShield Agent / curl / custom MCP client   │
│                                                                         │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │ HTTPS (Streamable HTTP / SSE)
                                   │ Authorization: Bearer vyuu_user_…
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       Ingress / TLS termination                         │
│                                                                         │
│   NGINX ingress + cert-manager  │  Caddy  │  AWS ALB / GCP Cloud Run    │
│   (TLS 1.2+ / HSTS / optional inbound mTLS)                             │
│                                                                         │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │ HTTP (cluster-internal)
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                  Gateway pod (Python 3.12+ / uvicorn)                   │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                       FastAPI app (ASGI)                          │  │
│  │                                                                   │  │
│  │  /api/v1/auth/…           /api/v1/portal/…    /v/{tenant}/{vs}/   │  │
│  │  /api/v1/operator-auth/…  /api/v1/admins      mcp                 │  │
│  │  /api/v1/users /groups    /api/v1/access-                         │  │
│  │  /api/v1/servers          requests/…                              │  │
│  │  /api/v1/vservers         /api/v1/audit-                          │  │
│  │  /api/v1/secret-store     events                                  │  │
│  │  /api/v1/oauth-authcode/… /api/v1/identities  /api/v1/who-can-do  │  │
│  │  /api/v1/admin/dashboard  /api/v1/nhi-map                         │  │
│  │  /operator (HTML/JS)      /portal (HTML/JS)                       │  │
│  └────────┬───────────────────────────────────────┬──────────────────┘  │
│           │                                       │                     │
│           ▼ (routes resolve dependencies)         │                     │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                   Service / domain layer                          │  │
│  │                                                                   │  │
│  │ identity_provider    operator_auth     policy_provider            │  │
│  │  (api_key / fake)     (password / JWT)  (simple / management_plane│  │
│  │                                                                   │  │
│  │ session_registry     resolver          tool_call lifecycle        │  │
│  │  (Redis / in-mem)    (vserver+grants)   (orchestrator)            │  │
│  │                                                                   │  │
│  │ secret_store         upstream_clients  audit_emitter              │  │
│  │  (Vault / AWS / mem) (httpx pool +      (Recent + inner)          │  │
│  │                       circuit breakers) graph_event_emitter       │  │
│  └────┬────────────────────────┬─────────────────────────┬───────────┘  │
│       │                        │                         │              │
└───────┼────────────────────────┼─────────────────────────┼──────────────┘
        │                        │                         │
        │ async outbound          │ sync ORM                │ async stream
        │ (httpx)                 │ (SQLAlchemy 2.0)        │
        ▼                         ▼                         ▼
┌──────────────────┐   ┌──────────────────────┐   ┌────────────────────────┐
│  Upstream MCPs   │   │   Postgres 16+       │   │  Audit pipeline        │
│                  │   │                      │   │                        │
│  drawio.io       │   │  • catalog tables    │   │  AsyncAuditEmitter     │
│  PayPal          │   │    (servers, vservers│   │       │                │
│  Wiz / Snyk      │   │     capabilities,    │   │       ▼                │
│  internal MCPs   │   │     grants)          │   │  asyncio.Queue         │
│                  │   │  • identity tables   │   │  (max=1000)            │
│  Streamable HTTP │   │    (tenants, users,  │   │       │                │
│  / SSE / stdio   │   │     operators,       │   │       ▼                │
│                  │   │     api_keys,        │   │  Kafka / NATS producer │
└──────────────────┘   │     access_requests) │   │       │                │
                       │  • RLS via           │   │       ▼                │
                       │    app.current_      │   │  Topic / Subject       │
                       │    tenant_id GUC     │   │  (downstream NHI graph,│
                       └──────────────────────┘   │   SIEM, analytics)     │
                                                  └────────────────────────┘
        │                                                  ▲
        │                                                  │
        ▼                                                  │
┌──────────────────┐   ┌──────────────────────┐   ┌────────┴────────────────┐
│  SecretStore     │   │   Redis (optional)   │   │  Graph events pipeline  │
│                  │   │                      │   │                         │
│  • Vault KV v2   │   │  Session registry    │   │  AsyncGraphEventEmitter │
│  • AWS Secrets   │   │  (TTL-bound, shared  │   │  (parallel to audit;    │
│    Manager       │   │   across pods for    │   │   shaped for the NHI    │
│  • InMemory (dev)│   │   horizontal scale)  │   │   graph analytics layer)│
└──────────────────┘   └──────────────────────┘   └─────────────────────────┘
```

### 1.5.2 Data + streaming pipelines

Where data lives and how it flows. Five distinct pipelines run
inside a single gateway pod:

```
PIPELINE 1 — REQUEST/RESPONSE (synchronous, hot path)

  Agent ──▶ Ingress ──▶ uvicorn ──▶ FastAPI route ──▶ service layer
                                                          │
                              ┌───────────────────────────┴──────────────┐
                              ▼                                          ▼
                    ┌──────────────────┐                       ┌──────────────────┐
                    │ httpx.AsyncClient│                       │   SQLAlchemy     │
                    │ pool (per tenant │                       │   sync session   │
                    │ + server,        │                       │   (RLS-bound via │
                    │ pre-resolved auth│                       │   app.current_   │
                    │ headers)         │                       │   tenant_id GUC) │
                    └────────┬─────────┘                       └────────┬─────────┘
                             ▼                                          ▼
                       Upstream MCP                                 Postgres
                             │                                          │
                             ▼                                          ▼
                       CallToolResult                              ORM rows
                             │                                          │
                             └─────────────────┬────────────────────────┘
                                               ▼
                                        return to agent

PIPELINE 2 — AUDIT (async, fan-out)

  Tool call OR access attempt
       │
       ▼
  emit_nowait(AuditEvent)
       │
       ├──▶ RecentAuditEmitter (in-process ring buffer, last 1000)
       │       │
       │       └─▶ /api/v1/audit-events ──▶ /operator Events panel
       │
       └──▶ AsyncAuditEmitter
               │
               ▼
           asyncio.Queue (size=1000)
               │
               ▼ (background worker drains)
           KafkaProducer / NatsProducer
               │
               ▼
           Kafka topic / NATS subject
               │
               ▼
           Downstream consumers (NHI graph, SIEM, analytics)

PIPELINE 3 — GRAPH EVENTS (parallel async, fan-out)

  Tool call (allowed paths only)
       │
       ▼
  build_tool_call_graph_event(...)
       │
       ▼
  GraphEventEmitter.emit_nowait(GraphEvent)
       │
       ├──▶ InMemoryGraphEventEmitter (dev)
       │
       └──▶ AsyncGraphEventEmitter
               │
               ▼
           asyncio.Queue
               │
               ▼
           Kafka / NATS producer
               │
               ▼
           NHI graph topic
               │
               ▼
           Vyuu analytics layer (entity-edge graph for principals,
           upstream servers, tools, tenants — non-human identity
           security analytics)

PIPELINE 4 — CAPABILITY SYNC (periodic OR on-demand)

  Two trigger modes:

  a) Operator clicks "Sync" or POST /api/v1/servers/{id}/sync
       │
       ▼
     DatabaseCapabilitySyncService.sync_server_capabilities()

  b) PeriodicCapabilitySyncScheduler (off by default; opt-in via
     VYUU_CAPABILITY_SYNC_ENABLED=true)
       │
       ▼ (loops per tenant on configurable interval)
     same sync service, with per-tenant concurrency cap

  Both paths:
       │
       ▼
   upstream_clients.get_client() → MCP session.initialize() →
   tools/list + resources/list + prompts/list
       │
       ▼
   diff against mcp_capabilities rows in Postgres
       │
       ▼
   added / removed / changed / unchanged → persist + return drift report
       │
       ▼
   GraphEventEmitter (capability discovery is also a graph signal)

PIPELINE 5 — SECRET RESOLUTION (request-time, with build-time caching)

  Inbound MCP call → upstream_clients.get_client(tenant, server)
       │
       ▼
  Pool cache: existing client with secrets baked in?
       ├── HIT  ──▶ return cached client (NO secret store calls)
       │
       └── MISS ─▶ Build new client:
                       │
                       ▼
                   _build_client() iterates auth_headers / auth_env
                       │
                       ▼
                   For each {header: "{secret:foo}"} value:
                       │
                       ▼
                   secret_store.get_secret(tenant, "foo")
                       │  Vault: GET /v1/{mount}/data/{tenant}/foo
                       │  AWS:   GetSecretValue(SecretId="vyuu/{tenant}/foo")
                       │
                       ▼
                   Substituted values baked into httpx.AsyncClient
                       │
                       ▼
                   For OAuth (auth_oauth / auth_authcode / auth_jwt_bearer):
                       │
                       ▼
                   Token provider with single-flight refresh:
                     · auth_oauth        → CachedOAuthTokenProvider
                                           (M2M client_credentials, in-mem cache)
                     · auth_authcode     → OAuthAuthCodeTokenProvider
                                           (DB-backed per-user, RFC 6749 §6 rotation)
                     · auth_jwt_bearer   → OAuthJwtBearerTokenProvider
                                           (RFC 7523 SA assertion, in-mem cache)
                       │
                       ▼
                   For mTLS (mtls_cert_ref + mtls_key_ref):
                       │
                       ▼
                   PEM blobs → ssl.SSLContext.load_cert_chain
                       │       (scratch tempfile unlinked on return)
                       ▼
                   Cached httpx client returned

  Net effect: secret store hit ONCE per (tenant, server) pool entry,
  not per tool call. Latency to Vault / AWS Secrets Manager is
  amortised over the upstream's lifetime.
```

### 1.5.3 In-process caches summary

Several caches live inside the gateway process. Knowing what's
cached where matters when reasoning about consistency, restart
behaviour, and pod-scaling.

| Cache | What | Refresh / invalidation | Survives restart? |
|---|---|---|---|
| `RecentAuditEmitter` ring buffer | Last 1000 audit events for the operator UI | FIFO drop on overflow; cleared on restart | ❌ |
| `httpx.AsyncClient` pool (`UpstreamConnectionPool`) | Outbound clients per (tenant, server, transport) with secrets baked in | Circuit-breaker open / max-connections / pool eviction | ❌ |
| `CachedOAuthTokenProvider` | OAuth client-credentials access tokens | TTL from `expires_in` minus 60s safety buffer; single-flight refresh on miss | ❌ |
| `JwksCache` | JWKS public keys for OIDC IdPs | 5-minute TTL + on `kid` miss; per-issuer `asyncio.Lock` for single-flight | ❌ |
| `principalCache` (operator UI JS) | Users + groups loaded into the admin dropdowns | Manual refresh by operator | n/a (browser) |
| `catalogCache` / `requestsCache` / `keysCache` (portal UI JS) | Server response cached so search filters operate locally | Refresh button | n/a (browser) |
| `_oauth_providers` (per-server OAuth provider instances) | `(tenant, server)` → CachedOAuthTokenProvider | Held for the gateway pod's lifetime | ❌ |
| Pydantic model schemas | OpenAPI generation, request validation | Process lifetime | ❌ |

What's NOT cached in-process:
- **Identity validation** — every inbound MCP call hits Postgres
  (`user_api_keys` lookup with bcrypt verify). Hot but bounded by
  bcrypt cost; horizontal scale via more pods.
- **Grant enforcement** — every inbound MCP call runs the
  vserver-grant SQL. Indexed; not a hot-path concern at typical
  enterprise scales.
- **Capability list** — populated by sync; served from Postgres for
  every `tools/list` call.
- **Session lookups** — go to Redis (multi-pod) or in-memory map
  (single pod).

### 1.5.4 Tool-call lifecycle (annotated hot path)

The full flow when an agent invokes a tool, with timings + sync/async
markers.

```
[1] HTTPS POST /v/{tenant}/{vserver}/mcp                     (sync, ~1ms)
      Authorization: Bearer vyuu_user_…
      JSON-RPC: {"method":"tools/call","params":{"name":"…","arguments":{…}}}
      │
      ▼
[2] FastAPI route: inbound_mcp_post(tenant_id, vserver_name)  (sync, ~0.5ms)
      Tenant-scoped DB session opened (RLS bound)
      │
      ▼
[3] identity_provider.validate_principal()                    (sync, ~5-15ms)
      bcrypt verify against user_api_keys.key_hash
      ├── FAIL ─▶ access-attempt audit + 401  (PIPELINE 2 fires)
      └── OK   ─▶ Principal{tenant_id, user_id, type=API_KEY}
      │
      ▼
[4] session_registry.get_or_create_session()                  (async, ~1-3ms)
      Redis HGET / SET (or in-memory dict)
      │
      ▼
[5] resolver.resolve_tools(tenant_id, vserver_name)           (sync, ~2-5ms)
      Postgres: virtual_servers + virtual_server_tools join
      ├── No vserver  ─▶ access-attempt audit + 404
      ├── No grant    ─▶ access-attempt audit + 403
      └── OK          ─▶ ResolvedToolsList
      │
      ▼
[6] tool_call lifecycle.handle_tool_call(req)                 (orchestrator)
      │
      ▼
[7] policy_provider.evaluate_tool_call(context)               (sync, <1ms)
      jsonschema validate(arguments) against tool.inputSchema
      Returns PolicyDecision(allow|deny, capture_raw_args?, capture_raw_response?)
      ├── DENY ─▶ tool_call audit (DENY) + JSON-RPC error  (PIPELINE 2)
      └── ALLOW
      │
      ▼
[8] upstream_clients.get_client(tenant, server)               (async, varies)
      Pool HIT  ─▶ ~0.1ms  (existing httpx client returned)
      Pool MISS ─▶ ~50-200ms  (PIPELINE 5: secret store fetches +
                              optional OAuth token refresh +
                              httpx client construction)
      │
      ▼
[9] mcp_client.call_tool(name, args)                          (async, varies)
      Streamable HTTP POST to upstream MCP
      Wrapped in CircuitBreaker (open ─▶ short-circuit)
      Latency dominated by upstream (50ms - 30s)
      │
      ▼
[10] Upstream returns CallToolResult                          (async, network)
      │
      ▼
[11] Lifecycle:                                               (sync, ~2-5ms)
      • Compute response_size_bytes
      • Compute auth_modes flags from server config
      • Build AuditEvent (tool_call) + emit (PIPELINE 2)
      • Build GraphEvent + emit (PIPELINE 3)
      │
      ▼
[12] FastAPI returns JSON-RPC response to agent              (sync, ~1ms)

Total: typically 100-500ms end-to-end, dominated by [9] upstream call.
       Audit + graph emits happen on the response path but are
       non-blocking — emit_nowait queues to asyncio.Queue + returns.
```

### 1.5.5 Where horizontal scaling kicks in

Stateless components (everything in the gateway pod) horizontally
scale by adding more pods. Stateful components are shared:

| Component | Scaling pattern |
|---|---|
| Gateway pods | k8s Deployment, replicas N, HPA on CPU |
| Postgres | Single primary + read replicas; managed (RDS / Cloud SQL) for prod |
| Redis | Single instance OK for sessions; Sentinel / managed for HA |
| Vault | HA cluster with Raft storage + auto-unseal |
| AWS Secrets Manager | n/a — managed |
| Kafka | Existing customer cluster or managed (MSK, Confluent Cloud) |
| Audit consumers | Independent of gateway — they consume from Kafka topic at their own pace |

The only per-pod state that doesn't scale cleanly:

- **`RecentAuditEmitter` ring buffer** is per-pod local. The Events
  panel shows only events served by the pod the operator's browser
  request happened to land on. Mitigation: ingress sticky-session
  on the operator JWT, OR replace with a Redis-backed buffer
  (sized in the backlog, not yet shipped).

- **httpx pool + circuit-breaker state** is per-pod. With sticky-
  session by tenant, each pod warms its own pool. Without sticky
  sessions, every pod independently warms — minor inefficiency,
  not correctness issue.

---

## 2. Web framework

### `fastapi >= 0.115.0`

**Why FastAPI:**
- Native async (`async def` endpoints) — required for non-blocking
  upstream MCP calls + outbound auth refreshes.
- Pydantic v2 integration — same models for request validation +
  ORM dehydration + OpenAPI generation.
- Built-in dependency injection (`Depends(...)`) — keeps auth +
  DB-session wiring composable. We use it for
  `authenticate_operator` / `authenticate_portal_session` /
  `get_tenant_scoped_db`.
- Auto-generated `/docs` (Swagger) + `/redoc` — invaluable for
  operator debugging.

**Alternatives considered:**
- **Flask** — sync-first; would need `gevent` / `eventlet` to do
  what FastAPI does natively.
- **Starlette directly** — FastAPI is built on Starlette; we get the
  same primitives plus Pydantic + DI for free.
- **aiohttp** — older API, less ecosystem.

### `uvicorn[standard] >= 0.32.0`

ASGI server, async-first. The `standard` extras pull in `httptools`,
`uvloop`, `websockets`, `watchgod` — reasonable production defaults.

**Why uvicorn:** FastAPI's recommended runner; we use the standard
production deployment pattern (`uvicorn app:create_app --factory
--workers 4` behind an ingress).

**Alternatives:**
- **gunicorn** — sync-first; would need `gunicorn -k uvicorn.workers.UvicornWorker`
  which is just uvicorn underneath anyway.
- **hypercorn** — comparable to uvicorn, smaller community.

---

## 3. Data layer

### `sqlalchemy >= 2.0.36` (ORM mode)

**Why SQLAlchemy 2.0:**
- The `Mapped[...]` typed-column syntax matches our strict-mypy
  posture — every ORM column has a Python type hint that mypy
  verifies.
- 2.0's unified `select()` API is the modern idiom (post-1.4).
- Relationship loading (`back_populates`, `selectinload`) — clean.
- `bind_tenant_context()` event listener — sets `app.current_tenant_id`
  GUC on every transaction so Postgres RLS policies fire on every
  query without per-call ceremony.

We DON'T use SQLAlchemy's async API. The gateway uses sync
SQLAlchemy from inside `async def` endpoints, with the connection
pool itself non-blocking. This is intentional:

- The async ORM API has rough edges (lazy loading, eager loading
  semantics differ from sync).
- Postgres queries are bound by network round-trip + Postgres CPU,
  not by Python's GIL. A sync query inside an async endpoint
  releases the GIL during the I/O wait, so other async tasks
  (upstream MCP calls, audit emits) make progress.
- Test ergonomics — the FastAPI `TestClient` runs sync against an
  ASGI app; sync ORM calls work cleanly.

### `psycopg[binary] >= 3.2.0`

The Postgres driver. **Important:** `psycopg` (3.x), NOT `psycopg2`.

**Why psycopg 3:**
- Native async support (we don't use the async API per above, but
  having it is future-friendly).
- Better type-stub support than psycopg2.
- The maintainer has good engagement; psycopg2 is in maintenance-only
  mode.
- Supports COPY protocol natively (useful for high-volume inserts —
  not used yet but available for the audit pipeline if we ever
  persist to Postgres).

`[binary]` extra ships pre-built binary wheels — no libpq build at
install time. Production should consider switching to `psycopg[c]`
for ~10% speed wins, but the binary install is the simplest default.

### `alembic >= 1.14.0`

Schema migrations. Eight migrations as of 2026-05-01, all in
`migrations/versions/`. Naming convention: `YYYYMMDD_NNNN_description.py`.

**Why Alembic:**
- The de-facto SQLAlchemy migration tool.
- Auto-generation works well enough for routine column adds; we
  hand-edit for partial indexes / check constraints / RLS policies.
- Supports forward + downgrade paths.

### Postgres 16+ (recommended; 14+ minimum)

Required features:
- **Row-Level Security (RLS)** — every tenant-scoped table has an
  RLS policy gating reads + writes on `current_setting('app.current_tenant_id')`.
- **Partial unique indexes** — used for the `access_requests`
  one-pending-per-(user, vserver) constraint.
- **JSONB** — `mcp_servers.auth_headers`, `auth_env`, `auth_passthrough`,
  `auth_oauth`, `args` columns are all JSONB.
- **GIN indexes** (not yet used; available for future search).

We do NOT depend on:
- `pgvector` / similarity search — not a vector use case.
- `pg_partman` / partitioning — single-region single-tenant-table
  design today.

### `redis >= 5.0.0`

Optional. Used for the multi-instance session registry
(`RedisSessionRegistry`) when `VYUU_REDIS_URL` is set. Falls back to
`InMemorySessionRegistry` for single-process / dev / lab.

**Why Redis (and not just Postgres):**
- Sessions are short-lived (`session_ttl_seconds=3600` by default)
  and read on every inbound MCP call. Postgres can do it but adds
  unnecessary load.
- Horizontal scaling: each gateway pod can read/write the same
  Redis cluster, so MCP traffic can land on any pod and find the
  session.

**When to use:** any deployment with > 1 gateway pod.
**When to skip:** single-pod deployments — `InMemorySessionRegistry`
is faster and one fewer infra dep.

---

## 4. HTTP client (outbound)

### `httpx >= 0.27.0`

**Why httpx:**
- Native async — required for non-blocking MCP calls + OAuth token
  refreshes.
- Per-client config (timeout, base_url, headers, cert) — clean for
  the upstream-pool pattern.
- `httpx.AsyncClient(transport=httpx.MockTransport(...))` — testing
  without standing up an HTTP server.
- HTTP/2 support (lazy-imported).

**Alternatives considered:**
- **aiohttp** — older API, less ergonomic for our use case.
- **requests** — sync-only; non-starter for our async endpoints.
- **urllib3 + asyncio.to_thread** — works but lower-level than we
  need.

httpx is also the SDK used by `mcp` (the Anthropic MCP SDK) for its
HTTP transport — using the same client across the stack means one
TLS / connection-pool / cert-handling story.

---

## 5. MCP protocol

### `mcp >= 1.13.0` (Anthropic's official SDK)

**Provides:**
- `mcp.client.streamable_http` — Streamable HTTP transport client.
  We wrap it in `StreamableHttpMcpClient` (`vyuu_gateway/mcp/outbound.py`).
- `mcp.client.sse` — legacy SSE transport (some upstream MCPs still
  use it).
- `mcp.client.stdio` — local subprocess transport. Used for
  `source_type=stdio | npm | pypi | binary`.
- `mcp.types` — `Tool`, `CallToolResult`, `ListToolsResult`, etc.
  We use these directly on our wire surface (no remapping).
- `mcp.server.fastmcp` — used in the lab fixtures to spin up test
  upstreams.

**Why the official SDK:**
- Tracks the MCP spec as it evolves. We don't hand-roll JSON-RPC
  decoding; the SDK handles protocol-level concerns (initialize,
  capabilities negotiation, batch requests, etc.).
- Maintained by the same team that ships the spec — bugs in our
  protocol handling are upstream's problem, not ours.

**Trade-off:** the SDK's API is still pre-1.0 — version pins matter,
and we'll need to adapt to breaking changes. We've seen one minor
bump in this codebase's lifetime; not a major churn driver yet.

---

## 6. Validation + serialization

### `pydantic-settings >= 2.6.0` (and Pydantic v2 transitively via FastAPI)

**Why Pydantic v2:**
- 5-10× faster than v1 (Rust-based core).
- Strict typing — `model_config = ConfigDict(strict=True)` for
  request bodies catches sloppy types at the wire.
- `ConfigDict(extra="forbid")` — request bodies reject unknown
  fields (HTTP 422). Defense-in-depth against fields a client thinks
  they're sending but we silently ignore.
- `ConfigDict(from_attributes=True)` — clean ORM-to-response
  conversion.

`pydantic-settings` reads env vars with `VYUU_` prefix into the
`Settings` class. Single source of truth for runtime config.

### `email-validator >= 2.0.0`

Required by Pydantic for `EmailStr` validation. Pulled explicitly so
the dependency is visible.

### `jsonschema >= 4.20.0`

Used by `SimplePolicyProvider` to validate `tools/call` arguments
against each tool's published `inputSchema`. Draft-2020-12.

**Why JSON Schema (and not just Pydantic):**
- The MCP spec defines tool schemas as JSON Schema documents we
  receive from upstream MCPs at sync time. We don't control the
  shape — we validate against whatever the upstream published.
- Pydantic models are for OUR API surface; JSON Schema is for the
  data we forward TO upstream MCPs.

---

## 7. Authentication primitives

### `bcrypt >= 4.0.0`

Password hashing. Used for:
- `users.password_hash` (local-auth users)
- `operators.password_hash` (admin password login)
- `user_api_keys.key_hash` (per-user bearer tokens)

**Why bcrypt:**
- Constant-time verification (avoids timing attacks).
- Industry-standard, easy to audit, widely understood.
- Built-in rate-limit via cost factor (rounds=12 for passwords,
  rounds=10 for high-entropy API key secrets — the secret bytes are
  random so a lower work factor still gates brute-force).

**Alternatives considered:**
- **argon2** — newer, theoretically better against GPU brute-force.
  Rejected because: the bcrypt cost factor is sufficient against
  realistic threat models; bcrypt is widely-deployed; the password
  itself has a 12-char minimum which dominates the security
  calculation.
- **scrypt** — comparable to argon2; same trade-off.

### `pyjwt[crypto] >= 2.8.0`

JWT signing + verification. Used for:
- **Portal session JWTs** (HS256) — minted on user login, carried
  by the SPA in `Authorization: Bearer ...`.
- **OIDC ID-token verification** (RS256) — Microsoft Entra ID +
  Google Workspace ID tokens.

`[crypto]` extra pulls in `cryptography` for RS256 keypair handling
+ JWKS verification.

**Operator JWTs are NOT JWTs.** They're a custom HMAC-signed
`<base64url(json)>.<base64url(hmac)>` format from
`operator_auth/fake.py`. Predates the user-side JWT decision; they
work, the format is internal, no migration urgency.

### `cryptography` (transitively via `pyjwt[crypto]`)

Used directly for OIDC JWKS handling — RSA public-key reconstruction
from JWKS modulus/exponent in `vyuu_gateway/users/oidc.py`.

---

## 8. Secret stores

### `boto3 >= 1.35.0`

AWS SDK. Used for `AwsSecretsManagerStore`.

**Why boto3 (and not aiobotocore):**
- boto3 is sync-only but our SecretStore reads happen at
  upstream-client construction time, NOT per-tool-call. Latency is
  amortised; sync is fine.
- The async wrappers (aiobotocore) drift behind boto3 on AWS API
  additions.
- boto3's default credential chain handles every auth path we need:
  IAM access keys (env vars), IAM Roles Anywhere (config file),
  EC2 instance profile / ECS task role / EKS pod identity (metadata
  service). Zero gateway code branches — `boto3.client(...)` figures
  it out.

If the SecretStore ever moves into the hot path, switching to
`aiobotocore` is a half-day refactor. Until then sync is correct.

### Vault (HashiCorp)

No Python client dep. `VaultSecretStore` uses `httpx.AsyncClient`
directly against Vault's KV v2 HTTP API.

**Why no `hvac` (the official Vault Python client):**
- One fewer dep.
- We only need read-side KV v2 — that's a single GET against
  `{mount}/data/{tenant_id}/{ref}`. Hand-rolled is ~30 lines.
- httpx is already a dep; no extra footprint.
- `hvac` is sync-only; we want async for symmetry.

If we add Vault auth-method support beyond static-token (AppRole,
k8s-auth, agent sidecar), `hvac` becomes more compelling. For static-
token, the manual path wins.

---

## 9. Audit pipeline

### `aiokafka >= 0.12.0` (optional)

Kafka producer for the durable audit + graph pipelines. Optional
extra: `pip install vyuu-mcp-gateway[kafka]`.

**Why Kafka:**
- Durable, partitioned, scalable. The audit pipeline must not lose
  events.
- Most regulated tenants already have a Kafka cluster; we plug into
  what they have.
- Asynchronous — `KafkaProducer.emit_nowait` returns immediately;
  the async worker drains the queue.

### `nats-py >= 2.7.0` (optional)

NATS JetStream alternative. `pip install vyuu-mcp-gateway[nats]`.

**Why NATS:**
- Lower operational overhead than Kafka for smaller deployments.
- JetStream provides Kafka-like durability semantics on top.
- Tenants without a Kafka cluster.

### Audit pipeline architecture

```
audit_emitter.emit_nowait(event)
  → RecentAuditEmitter (in-process ring buffer, drives /operator UI)
      ↓
  → AsyncAuditEmitter
      ↓
  → asyncio.Queue (max_queue_size=1000 default)
      ↓
  [background worker]
      ↓
  → KafkaProducer / NatsProducer
      ↓
  Kafka topic / NATS subject
      ↓
  [downstream consumers — Vyuu's analytics layer, SIEM ingest]
```

Local-dev path skips the broker: `_LocalAuditEmitter` keeps events
in `TestAuditProducer.events` and never serializes them out.

Failure mode is `MONITOR` for v1 — a Kafka outage does NOT block
the request hot path. `ENFORCE` mode (deny tool call if audit
event can't be durably queued) is sized in the backlog.

---

## 10. Frontend

**Approach:** vanilla HTML / CSS / JS shipped as Python string
constants in `vyuu_gateway/api/operator_ui.py` + `portal_ui.py`.
Two endpoints per UI: `/operator` (HTML), `/operator/app.js` (JS),
`/operator/app.css` (CSS); same for `/portal`.

**Why no React / Vue / build step:**
- One deployment artefact. No `npm` / `yarn` / `vite` toolchain in
  the gateway repo.
- Strict CSP (`default-src 'self'`) — no remote stylesheets / scripts.
- The UIs are operator + admin tools — not consumer-facing. Total
  code size is ~3000 lines of HTML/CSS/JS combined; React would be
  overkill.
- No backend-for-frontend layer — the UI hits the same `/api/v1/...`
  endpoints external clients use.
- Easy to LLM-generate / iterate on. The Vyuu Design System tokens
  are CSS custom properties; design changes don't require rebuilding
  components.

**Trade-offs accepted:**
- No component reuse across surfaces — common patterns get
  copy-pasted (e.g. the Vyuu `:root` token block lives in BOTH UI
  files; the JS-syntax test asserts they don't drift).
- No client-side routing — tab navigation is JS DOM toggling; deep-
  linking via URL hashes is a nice-to-have for the design pass.
- No type checking on the JS — we have `node --check` regression
  tests catching syntax errors but no semantic checks.

When this stops scaling: the operator UI grows past ~5000 lines of
JS, OR a customer wants to embed the portal in a larger app. At
that point we'd extract `portal_ui.py` into a Vite-built React app
served by the gateway as a static-files mount.

### Vyuu Design System

Tokens defined in the `:root` block at the top of each UI's `_CSS`
constant. The full token list is in
`docs/architecture/vyuu-gateway-spec.md` and `Vyuu Design Handoff/tokens/tokens.css`
(if it exists in the design-handoff repo).

**Type stack:**
- `Fraunces` serif — headings (h1 / h2 / h3)
- `Inter` sans — body, UI text, labels
- `JetBrains Mono` — code, monospace metadata

**Palette (essentials):**
- `--vyuu-bg` `#F7F4ED` — cream paper page background
- `--vyuu-panel` `#FFFEFB` — ivory panel background
- `--vyuu-ink` `#1F2A2E` — primary text
- `--vyuu-orange-deep` `#A85820` — primary action (submit buttons)
- `--vyuu-warn` / `--vyuu-danger` / `--vyuu-info` — semantic accents
  for pills + status

**Pill anatomy:** 3px 9px padding, 999px radius, 11px Inter, solid
tint background + matching ink foreground. Variants encode meaning,
not aesthetics:
- `pill-orange` — positive / active (`healthy`, `connected`,
  `granted`, `approved`)
- `pill-warn` — advisory (`unknown`, `degraded`, `pending`,
  `truncated`)
- `pill-danger` — failure (`down`, `revoked`, `declined`)
- `pill-info` — categorical (transports, source types)
- `pill-neutral` — standby

The pill semantics are stable across both UIs.

---

## 11. Testing

### `pytest >= 8.3.0`

Test runner. 705 passing tests as of 2026-05-01.

**Why pytest:**
- Standard. Anything else would be exotic.
- Fixtures + parametrize — clean for the per-tenant + per-backend
  test patterns.
- `pytest.mark.skipif` — env-gated tests for real-DB / real-Redis /
  real-drawio integration.

### `mypy >= 1.13.0`

Strict type checking. 189 source files, zero errors.

**Config:**
```toml
[tool.mypy]
strict = true
[[tool.mypy.overrides]]
module = ["aiokafka", "boto3", "botocore", "botocore.*", "nats", "nats.*"]
ignore_missing_imports = true
```

The override block is for packages without `py.typed` markers —
boto3 / botocore in particular ship runtime objects but no type
stubs.

### `ruff >= 0.7.0`

Lint + format. Replaces flake8 + isort + black in one tool.

**Config:**
```toml
[tool.ruff]
line-length = 100
[tool.ruff.lint]
extend-select = ["E", "F", "W", "I", "B", "UP", "N", "SIM", "BLE"]
```

`extend-select`:
- `E` / `F` / `W` — pyflakes + pycodestyle
- `I` — import sorting (isort)
- `B` — bugbear (mutable default args, etc.)
- `UP` — pyupgrade (modern syntax)
- `N` — pep8-naming
- `SIM` — simplification suggestions
- `BLE` — blind except (we use `# noqa: BLE001` deliberately at
  audit-emit boundaries)

### `botocore.stub.Stubber`

Used in `test_aws_secrets_manager_store.py`. Boto3's official
testing primitive — declares expected request shape + canned
response, raises if our store fires the wrong API call.

### `httpx.MockTransport`

Used in `test_vault_secret_store.py`, `test_oidc.py`,
`test_manifest.py`. Stub HTTP responses without standing up a
server.

### `node --check` regression test

`tests/test_operator_ui_js_syntax.py` runs node's V8 parser over
both UIs' served JS. Catches Python-string-escape bugs that would
otherwise break the served JS silently. Skipped if `node` is not on
PATH (so CI without node still passes; local + node-equipped CI
runs the check).

### Real-services tests

Env-gated:
- `VYUU_TEST_DATABASE_URL` — real Postgres test cluster (RLS
  integration, full inbound MCP route, every admin endpoint).
- `VYUU_TEST_REDIS_URL` — real Redis (session registry isolation
  + TTL).
- `VYUU_TEST_DRAWIO_UPSTREAM` — drawio public MCP for end-to-end
  outbound smoke.
- `VYUU_TEST_KEYCLOAK_URL` — real-IdP OIDC integration (placeholder
  — the test isn't shipped yet, that's A3-β.x).

---

## 12. Lazy / optional imports

Several modules are import-time costly (boto3, aiokafka, nats-py).
We import them lazily inside factory functions so the base install
+ test runs stay light:

- `vyuu_gateway/main.py::_build_default_secret_store` — lazy
  imports `VaultSecretStore` / `AwsSecretsManagerStore` only when
  the corresponding backend is selected.
- `vyuu_gateway/main.py::_build_default_identity_provider` — lazy
  imports `ApiKeyIdentityProvider` (and its bcrypt dep) only when
  `inbound_identity_provider=api_key`.
- `vyuu_gateway/audit/kafka_producer.py` — lazy imports `aiokafka`
  inside the producer's `__init__`. Tests that don't use Kafka
  don't pay the import cost.

Pattern: `from foo import bar` lives inside the function that uses it,
not at the top of the module. Keeps `python -c "import vyuu_gateway"`
fast.

---

## 13. Dependency tree summary

```
Application
├─ FastAPI
│   ├─ Starlette
│   ├─ Pydantic v2 (validation, serialization)
│   └─ pydantic-settings (env-var config)
├─ uvicorn[standard] (ASGI server)
├─ SQLAlchemy 2.0 (ORM)
│   └─ psycopg[binary] (Postgres driver)
├─ Alembic (migrations)
├─ httpx (async HTTP client — outbound MCPs, OAuth, Vault, manifest fetch)
├─ mcp (Anthropic MCP SDK)
├─ pyjwt[crypto] (portal session JWTs, OIDC verify)
│   └─ cryptography (RSA, JWKS)
├─ bcrypt (passwords + API keys)
├─ jsonschema (tool input validation)
├─ email-validator (Pydantic EmailStr)
├─ boto3 (AWS Secrets Manager — production)
├─ redis (multi-instance session registry — optional)
└─ Optional: aiokafka / nats-py (durable audit pipeline)

Dev:
├─ pytest (test runner)
├─ mypy (strict type-check)
├─ ruff (lint + format)
└─ types-jsonschema (jsonschema stubs)
```

---

## 14. Production runtime considerations

### Container image

Recommended base: `python:3.12-slim-bookworm` (or `3.13`). Minimal
Debian + Python; no extras.

```dockerfile
FROM python:3.12-slim-bookworm
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir .
COPY src/ ./src/
COPY migrations/ ./migrations/
COPY alembic.ini .
EXPOSE 8000
CMD ["uvicorn", "vyuu_gateway.main:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

For Kafka: add `[kafka]` extra. For NATS: `[nats]`. Keep base image
lean — install only what the deployment uses.

### CPU / memory profile

Per-pod, observed under typical lab load:
- **Idle**: ~80 MB RAM, < 1% CPU.
- **Active** (one user, ~10 MCP calls/sec): ~120 MB RAM,
  ~5-10% of one core.
- **Hot** (100 concurrent sessions, 1000 calls/sec): ~250 MB RAM,
  one core saturated. Scale out horizontally.

The audit + graph pipelines + httpx pool are the main per-pod
memory drivers. With 4 uvicorn workers, plan for ~500 MB / pod.

### Horizontal scaling

The gateway is stateless EXCEPT for:
- `InMemorySessionRegistry` — replace with `RedisSessionRegistry`
  via `VYUU_REDIS_URL`. Required for > 1 pod.
- `RecentAuditEmitter` ring buffer — per-pod local; the operator
  console Events panel will show only events served by the pod
  the operator's request hit. Mitigation: sticky-session at the
  ingress, OR replace with a Redis-backed ring buffer (not yet
  shipped; small refactor).

### Deployment pattern

Recommended:
- Kubernetes Deployment with 2-3 replicas + HPA on CPU.
- NGINX ingress with TLS + cert-manager.
- Postgres: managed (RDS, Cloud SQL) or self-hosted with HA primary
  + replica.
- Redis: managed (ElastiCache, MemoryStore) or self-hosted single-
  instance.
- Vault or AWS Secrets Manager for secrets.
- Kafka cluster (existing / managed) for durable audit.

See `docs/operations/tls-and-mtls.md` and
`docs/operations/secret-store-setup.md` for specifics.

---

## 15. Pinned versions + upgrade strategy

Current pins (`pyproject.toml`, all `>=`):
```
alembic >= 1.14.0
bcrypt >= 4.0.0
boto3 >= 1.35.0
email-validator >= 2.0.0
fastapi >= 0.115.0
httpx >= 0.27.0
jsonschema >= 4.20.0
mcp >= 1.13.0
psycopg[binary] >= 3.2.0
pyjwt[crypto] >= 2.8.0
pydantic-settings >= 2.6.0
redis >= 5.0.0
sqlalchemy >= 2.0.36
uvicorn[standard] >= 0.32.0
```

**Why `>=` and not `==`:**
- We want patch updates (security fixes) without releasing.
- Minor versions are usually safe; we test against current and pin
  in production deployments via `pip install` lockfiles.

**Upgrade discipline:**
- Run full test suite + mypy + ruff on every dependency bump.
- Watch for `mcp` SDK breakage — pre-1.0, breaking changes possible
  on minors.
- Watch for Pydantic / SQLAlchemy minors — both are mature but
  occasionally change defaults.

For production, pin the exact version in your image's lockfile:
`pip-compile pyproject.toml > requirements.lock` and `pip install
-r requirements.lock`.

---

## 16. License + licensing audit

Every direct dependency is permissively licensed (MIT / BSD / Apache 2):
- FastAPI, Starlette — MIT
- Pydantic — MIT
- SQLAlchemy — MIT
- Alembic — MIT
- psycopg — LGPL (the LGPL exception clause permits linking from
  closed-source apps)
- httpx — BSD-3
- mcp — MIT (Anthropic)
- pyjwt — MIT
- bcrypt — Apache 2
- boto3 — Apache 2
- jsonschema — MIT
- redis-py — MIT
- aiokafka — Apache 2
- nats-py — Apache 2

No GPL deps — safe to ship in a closed-source product.

---

## 17. Glossary (for new joiners)

- **MCP** — Model Context Protocol. The standard agents use to talk
  to external tools (databases, SaaS APIs, etc.). Spec at
  `https://modelcontextprotocol.io`.
- **Upstream MCP** — a third-party MCP server (drawio, PayPal,
  internal tooling). The gateway calls these.
- **Inbound MCP** — the gateway IS an MCP server from the agent's
  perspective; this is the route the agent hits.
- **Virtual server (vserver)** — a tenant-owned bundle of tools
  pulled from one or more upstream MCPs. The publishing primitive.
- **Tenant** — a customer / org. Top-level isolation boundary.
- **Operator** — admin user; manages catalog.
- **End user** — consumer of MCPs via Cursor / Claude Desktop /
  agents. Has API keys; does NOT manage catalog.
- **Principal** — the entity making an inbound MCP call. Can be a
  user, an agent, a service.
- **Grant** — an explicit ACL row authorising a principal (user OR
  group) to access a private vserver.
- **JWT** — JSON Web Token. Used for portal sessions (HS256) and
  OIDC (RS256). Operator JWTs are a custom format, not real JWTs.
- **JWKS** — JSON Web Key Set. The public-key bundle an OIDC IdP
  publishes for verifying its ID tokens.
- **NHI** — Non-Human Identity (the Vyuu platform concept). The
  graph events emit edges shaped for this analytics layer.
- **PEP** — Policy Enforcement Point. The gateway is a PEP for
  tool-call decisions.
