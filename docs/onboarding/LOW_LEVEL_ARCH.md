# LOW_LEVEL_ARCH — concurrency, transactions, failure modes, perf

The lowest layer of the doc set. Concurrency primitives, transaction
boundaries, RLS GUC mechanics, what blocks the event loop, what
happens when each subsystem fails, performance characteristics on the
hot path.

If you haven't read `BACKEND_DEEP_DIVE.md` yet, start there. This doc
assumes you know the request lifecycles.

## Process model

One uvicorn process per host. Single Python interpreter, single asyncio
event loop. We do **not** use uvicorn workers (`--workers > 1`) because:

- Per-process state matters: the in-memory ring buffer
  (`RecentAuditEmitter`), the circuit-breaker registry, the upstream
  client pool, and the inflight-gate semaphore are all per-process.
  Multi-worker = each worker has its own state, and observability
  reads from the operator console see only the worker that handled
  the request.
- Multi-instance HA is the right answer when you need horizontal
  scale: each instance gets its own state, but the durable layer
  (Postgres) is the source of truth. Today the gateway is single-
  instance; multi-instance is on the roadmap.

```
                  uvicorn process
   ┌─────────────────────────────────────────┐
   │                                         │
   │   asyncio event loop                    │
   │     ↓                                   │
   │   FastAPI / Starlette routing            │
   │     ↓                                   │
   │   request handler (def or async def)     │
   │     ↓                                   │
   │   sync code → run_in_threadpool          │
   │   async code → awaited directly          │
   │                                         │
   │   ────── shared per-process state ──────│
   │   • app.state.recent_audit_emitter      │
   │   • app.state.upstream_clients (pool)   │
   │   • app.state.upstream_circuit_breakers │
   │   • app.state.session_registry          │
   │   • app.state.secret_store              │
   │   • app.state.identity_provider         │
   │   • app.state.policy_provider           │
   │                                         │
   │   ────── background asyncio tasks ──────│
   │   • HardDeleteSweeper (hourly)          │
   │   • PeriodicCapabilitySyncScheduler     │
   │     (opt-in)                            │
   │   • AsyncAuditEmitter producer worker   │
   │     (when wired)                        │
   │                                         │
   │   ────── threadpool (default 40) ───────│
   │   • sync DB calls via SQLAlchemy        │
   │   • bcrypt verify (CPU-bound)           │
   │   • subprocess spawning for stdio MCP   │
   └─────────────────────────────────────────┘
```

## Async vs sync — the rules

The gateway mixes sync and async deliberately:

- **Async (`async def`)**: anything that awaits I/O on the event loop —
  HTTP calls to upstream MCPs (httpx), the audit producer worker, the
  capability sync scheduler, the SCIM sweeper.
- **Sync (`def`)**: SQLAlchemy ORM calls (the synchronous API), bcrypt
  hash/verify, subprocess.Popen for stdio MCP spawn.

FastAPI handles the boundary automatically: a `def` route handler
runs on the threadpool; an `async def` handler runs on the event loop.
The threadpool default size is 40 (anyio default).

**Why not asyncio SQLAlchemy?** Pragmatism. The synchronous SQLAlchemy
API is the better-documented + more predictable surface, and the
threadpool overhead per call is negligible compared to a Postgres
roundtrip. We can migrate per-route if profiling shows a hotspot.

**Rule of thumb when adding code:** if it touches the DB, write it
sync. If it touches HTTP, write it async. If it touches both, write the
route async, wrap DB work in `await run_in_threadpool(sync_fn)`.

## Connection pooling

### Postgres

Configured in [`db/session.py`](src/vyuu_gateway/db/session.py):

```python
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,                                          # heartbeat on checkout
    pool_size=settings.db_pool_size,                             # default 20
    max_overflow=settings.db_pool_max_overflow,                  # default 10
    pool_timeout=settings.db_pool_timeout_seconds,               # default 30
    pool_recycle=settings.db_pool_recycle_seconds,               # default 3600
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
```

`pool_pre_ping=True` issues `SELECT 1` before every checkout — protects
against stale connections after Postgres restart or load-balancer
teardown. Adds < 1 ms per checkout.

`pool_recycle=3600` recycles connections after an hour — protects
against `idle_in_transaction_session_timeout` if Postgres has it set.

### HTTP (httpx)

The upstream pool ([`upstream/pool.py`](src/vyuu_gateway/upstream/pool.py))
keeps one `httpx.AsyncClient` per `(server_id, principal_id)` pair.
Per-client config:
- `timeout=httpx.Timeout(connect=5, read=30, write=30, pool=5)`
- `limits=httpx.Limits(max_connections=10, max_keepalive_connections=5)`
- TLS verify on, follows redirects off (we want explicit visibility).

Idle clients are evicted by `_idle_evictor` every 5 minutes.

### stdio subprocesses

[`upstream/stdio_pool.py`](src/vyuu_gateway/upstream/stdio_pool.py) spawns
the MCP server as a subprocess (npx / uvx / binary). One subprocess per
`(server_id, principal_id)` pair, restarted on crash, killed on idle
timeout (default 10 minutes).

## Transaction boundaries

A SQLAlchemy `Session` is short-lived — typically scoped to one HTTP
request via `get_tenant_scoped_db`. The `with SessionLocal() as session`
context manager closes the session (returns connection to pool) on
exit.

Inside a session, transactions are **explicit**:

```python
session.add(User(...))
session.add(AdminAuditLog(...))
session.commit()              # both rows persist atomically
# or
session.rollback()            # neither row persists
```

`autoflush=False` means we don't flush implicitly on every query —
prevents accidental partial writes from showing up in subsequent reads
within the same transaction.

`autocommit=False` means we always need an explicit `commit()` —
prevents accidental "every query is its own tx" mode.

### Per-request transaction shape

```
Request arrives
  ├─ get_tenant_scoped_db opens Session
  ├─ first DB query → SQLAlchemy implicitly BEGINs tx
  │   ├─ after_begin listener fires → SET LOCAL app.current_tenant_id = '<uuid>'
  │   ├─ subsequent queries see RLS-filtered rows
  │   └─ ...more queries...
  ├─ service function commits OR rolls back
  ├─ (optionally) more work in a NEW transaction on the same session
  │   (after_begin fires again, GUC re-set)
  └─ get_tenant_scoped_db __exit__ closes Session, returns conn to pool
```

The `after_begin` listener pattern means **you can commit multiple
times in one request** and RLS stays correct — the GUC is re-set per
transaction. Important for endpoints that do "validate → commit
intermediate state → continue → commit final state."

### The longest-lived transaction

The `HardDeleteSweeper` per-tenant transaction. For each tenant with
expired soft-deleted users:
1. Open session, bind tenant context.
2. `DELETE FROM users WHERE id = ...` (cascades to api_keys, grants, oauth_tokens).
3. `INSERT INTO admin_audit_log` row recording the hard-delete.
4. Commit.

Even at scale this is < 50 ms per tenant — bounded by the cascade
extent. We don't batch across tenants because a failure on one tenant
shouldn't roll back deletes that already succeeded for others.

## RLS mechanics

The single most important runtime invariant: **every transaction
that reads or writes a tenant-scoped table has `app.current_tenant_id`
set**.

### How the GUC gets set

In [`db/session.py`](src/vyuu_gateway/db/session.py):

```python
@event.listens_for(Session, "after_begin")
def _set_tenant_guc_on_transaction_begin(session, transaction, connection):
    tenant_id = session.info.get("tenant_id")
    if tenant_id is None:
        return
    connection.execute(
        text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
        {"tenant_id": str(tenant_id)},
    )
```

The third arg to `set_config` is `is_local=true` — the GUC is scoped
to the current transaction, cleared on commit/rollback.

`bind_tenant_context(session, tenant_id)` is the only sanctioned way
to set `session.info["tenant_id"]`. It does NOT issue any SQL — it just
stashes the id. The next query triggers `after_begin` and the GUC gets
set.

### Why FORCE for some tables

Default Postgres RLS posture is "owner exempts." The gateway connects
as the table owner (it created the tables), so without FORCE, a row
read with no GUC set returns ALL rows.

For these tables the cost of a missed bind is too high:
- `tool_call_events` — leaks audit history
- `admin_audit_log` — leaks admin actions
- `idp_directories` — leaks IdP config (OIDC client ids etc.)
- `mcp_server_dcr_clients` — leaks DCR registrations

So they use `ALTER TABLE ... FORCE ROW LEVEL SECURITY`. Even the owner
must satisfy the policy. A bug that forgets `bind_tenant_context` on
these tables fails closed (zero rows) instead of leaking everything.

For other tables (`users`, `mcp_servers`, etc.) we use plain ENABLE.
Owner is exempt; the gateway connects as owner so app code reads
work; a non-owner support role would still be gated.

### The cross-tenant scan pattern

When a worker needs to walk every tenant (audit warm-up, sweeper,
cron), it iterates `tenants` (no RLS) first:

```python
with session_factory() as scan_session:
    tenant_ids = scan_session.execute(select(Tenant.id)).all()

for tenant_id in tenant_ids:
    with session_factory() as tenant_session:
        bind_tenant_context(tenant_session, tenant_id)
        # ... do work that hits FORCE-RLS tables ...
```

A separate session per tenant means a failure on one doesn't roll back
the others.

## Concurrency primitives

### `RecentAuditEmitter` lock

[`audit/recent.py`](src/vyuu_gateway/audit/recent.py) wraps every deque
mutation in a `threading.Lock`:

```python
def emit_nowait(self, event):
    with self._lock:
        self._buffer.append(event)
    if self._inner is None:
        return EmitResult(accepted=True)
    return self._inner.emit_nowait(event)
```

The deque append is fast (~microseconds), the lock contention is
negligible at single-gateway scale. The lock is a `threading.Lock`
(NOT `asyncio.Lock`) because emits happen from threadpool-run sync
code.

### Inflight gate semaphore

[`api/inflight_gate.py`](src/vyuu_gateway/api/inflight_gate.py) is a
Starlette middleware that holds a per-tenant `asyncio.Semaphore`:

```python
class InflightGate:
    def __init__(self, app, *, per_tenant_limit):
        self._app = app
        self._per_tenant_limit = per_tenant_limit
        self._semaphores = {}  # tenant_id → asyncio.Semaphore

    async def __call__(self, scope, receive, send):
        if path in LIVENESS_BYPASS_PATHS:
            return await self._app(scope, receive, send)
        sem = self._semaphores.setdefault(
            tenant_id, asyncio.Semaphore(self._per_tenant_limit)
        )
        if not sem.locked():
            async with sem:
                return await self._app(scope, receive, send)
        # Cap exceeded → 503
```

The `setdefault` is safe in single-loop async — no race because
asyncio is cooperative.

### Circuit breaker state

[`upstream/circuit_breaker.py`](src/vyuu_gateway/upstream/circuit_breaker.py)
holds per-pool-key state. State transitions are guarded by a
per-breaker `threading.Lock`:

```
                  ┌─────────┐
        all good  │ CLOSED  │ ← initial
                  └────┬────┘
                       │ N consecutive failures
                       ▼
                  ┌─────────┐
                  │  OPEN   │ ── all calls rejected immediately
                  └────┬────┘    (returns NOT_CALLED status)
                       │ recovery_timeout elapses
                       ▼
                  ┌─────────┐
                  │HALF_OPEN│ ── one trial call allowed
                  └─┬─────┬─┘
       success      │     │      failure
                    ▼     ▼
                 CLOSED  OPEN
```

Tunables in [`config.py`](src/vyuu_gateway/config.py):
`upstream_circuit_breaker_failure_threshold` (default 5),
`upstream_circuit_breaker_recovery_timeout_seconds` (default 30).

## Memory model

What's per-process, what's per-tenant, what's per-request.

### Per-process (lives for the gateway lifetime)

| Item | Bound | Notes |
|---|---|---|
| `RecentAuditEmitter` deque | 1000 events × N tenants | Soft-bounded — `maxlen=1000` evicts oldest. Not per-tenant: one shared deque, tenant_id filter on read. |
| `UpstreamCircuitBreakerRegistry` | One breaker per `(tenant, server, principal)` pool key | Unbounded growth in theory; eviction via the same idle-evictor that retires httpx clients. |
| Upstream `httpx.AsyncClient` pool | Per `(server, principal)` | Idle-evicted after 5 min. Each client uses < 1 MB. |
| `JWKS` cache | Per OIDC issuer | TTL 1 hour. |
| stdio subprocess pool | Per `(server, principal)` | Idle-evicted. Each subprocess is its own OS process — significant memory if many. |
| Capability cache | None (we hit DB on every read) | Considered intentionally — keeps capability sync correctness sharp. |

### Per-tenant (inside the per-process state)

| Item | Bound | Notes |
|---|---|---|
| Inflight gate semaphore | `per_tenant_inflight_limit` slots | Default 100. |
| RLS GUC | one string value | Set per-transaction, cleared on commit. |

### Per-request

| Item | Bound | Notes |
|---|---|---|
| SQLAlchemy `Session` | 1 per request | Returned to pool on `__exit__`. |
| `AuditEvent` instance | 1+ per request | Frozen pydantic; small (~1 KB without raw_args / raw_response). |
| Inflight slot | 1 | Released when request handler returns. |

### Memory budget for a typical on-prem deployment

- Python interpreter + FastAPI: ~150 MB baseline.
- 1000 audit events × ~1 KB: ~1 MB ring buffer.
- 50 upstream clients × ~1 MB: ~50 MB.
- DB connection pool (20 + 10 overflow) × ~5 MB libpq state: ~150 MB.
- stdio subprocesses (varies): each Node MCP ~80 MB, each Python MCP
  ~50 MB. 5 stdio servers active = ~350 MB.

Total ~700 MB headroom for a busy single-tenant deployment. Linear in
the number of stdio servers if you wire many.

## Startup sequence

[`main.py`](src/vyuu_gateway/main.py) `create_app()`:

1. `Settings()` from env.
2. `configure_logging(settings.log_level)`.
3. Build `app = FastAPI(lifespan=lifespan)`.
4. `app.state.settings = settings`.
5. `configure_raw_capture_cap(...)` — set the deployment-wide audit
   raw-capture cap.
6. Wire providers:
   - `operator_auth` (default: `FakeOperatorAuthProvider`)
   - `identity_provider` (default: `ApiKeyIdentityProvider`)
   - `policy_provider`
   - `session_registry`
   - `secret_store`
   - `upstream_clients` (`DatabaseBackedUpstreamClientProvider`)
   - `upstream_circuit_breakers`
   - `upstream_health` checker
   - `capability_sync_client` + `capability_sync_scheduler` (if enabled)
   - `oidc_providers` from settings
7. Build the audit emitter chain (TOOL-EVENTS-1):
   ```
   raw_emitter → PostgresToolCallEventStore → RecentAuditEmitter
   ```
8. `app.state.audit_emitter` + `app.state.recent_audit_emitter` = chain head.
9. `app.state.audit_failure_mode = MONITOR` (for now).
10. Add middleware (inflight_gate, CORS if configured).
11. Include every router under their respective prefixes.

Then on first ASGI lifespan startup event:

1. `maybe_bootstrap_admin(session)` — first-run seeding from
   `VYUU_BOOTSTRAP_*` env vars. Idempotent.
2. `capability_sync_scheduler.start()` if wired.
3. `HardDeleteSweeper(SessionLocal).start()` — always on.
4. `seed_recent_buffer_from_postgres(SessionLocal, ...)` — only if
   `len(recent) == 0` (test-safe guard). Logs `audit_buffer_seeded events=N tenants=M`.

## Shutdown sequence

ASGI lifespan shutdown:

1. `hard_delete_sweeper.stop()` — cancels the asyncio task, awaits
   cleanly with `CancelledError` suppression.
2. `capability_sync_scheduler.stop()` if wired.
3. `_close_if_supported(upstream_clients)` — closes all httpx clients
   + kills stdio subprocesses (graceful: SIGTERM, then SIGKILL after
   timeout).
4. `_close_if_supported(policy_provider)` — closes any HTTP client
   the policy provider holds.
5. Log `gateway_stopping`.

The audit emitter chain has no explicit shutdown — fresh sessions per
emit means no in-flight writes to drain. The async producer worker (if
wired) drains its queue on `stop()`.

## Failure-mode matrix

What happens when each subsystem fails. Recovery column = what brings
the gateway back to healthy.

| Subsystem | Failure | Effect on requests | Recovery |
|---|---|---|---|
| Postgres unavailable | Connection refused / timeout | All operator API + portal API routes 500. Inbound MCP can complete the bearer check on cached state if any, but most paths 500. | Postgres back → `pool_pre_ping` discards stale conns, traffic resumes within seconds. |
| Postgres slow | Queries time out | Inflight gate fills, 503s start | Bump `inbound_per_tenant_inflight_limit` short-term; investigate slow queries |
| Postgres audit INSERT fails | `PostgresToolCallEventStore._insert` raises | Logged warning, request continues, in-memory buffer still has the event, downstream Kafka still emits | Investigate cause (disk full, lock contention); next emit just works |
| Audit buffer warm-up fails | `seed_recent_buffer_from_postgres` raises | Buffer starts cold, panels query Postgres directly (still see 24h of data) | Restart; check for `audit_buffer_warmup_failed` log |
| Upstream MCP down | Connection refused | Circuit breaker opens after 5 failures, all calls return `not_called` | Upstream back → first call after `recovery_timeout` is half-open trial → success closes breaker |
| Upstream MCP slow | Timeouts | Per-call latency rises, breaker may open | Same recovery path |
| stdio subprocess crashes | Pool detects exit, restarts on next request | First call after crash sees a small spawn delay | Automatic |
| OAuth refresh token expired | 401 from upstream → token row marked invalid | User sees an "Action required" link in the portal | User re-authorises from the portal Connections page |
| SCIM bearer wrong | 401 returned to IdP | IdP retries, alarms in IdP UI | Re-issue bearer from operator console, paste into IdP |
| IdP cert expired | SAML signature verify fails | All SSO sign-ins via that directory fail | Update cert via operator console IdP detail page |
| Operator JWT secret rotated | All existing JWTs invalid | Operators see 401, must re-sign-in | Operators sign in again; no graceful overlap by design |
| Inflight gate wedged | Semaphore not releasing | Tenant sees sustained 503s | Restart gateway; investigate async leaks |
| Capability sync scheduler crashes | Background task exits | New upstream tools don't appear in catalog until next manual sync | Restart gateway |
| SCIM hard-delete sweeper crashes | Background task exits | Soft-deleted users don't get hard-deleted | Restart gateway; sweeper resumes the queue |

## Hot-path performance characteristics

Measured locally on Mac M1 against local Postgres + local stdio MCP.
Production numbers vary with infra.

### Inbound MCP `tools/call` (cold)

| Phase | Time |
|---|---|
| Inflight gate check | < 0.1 ms |
| `get_inbound_mcp_db` (open + bind) | ~1 ms |
| `IdentityProvider.identify` (bcrypt verify) | ~50 ms |
| Vserver lookup + grant check | ~1 ms (1 indexed query) |
| MCP lifecycle parse | < 0.1 ms |
| Policy decide (Simple) | < 0.1 ms |
| Upstream call (HTTP MCP, local) | ~5–20 ms |
| Audit emit (RecentBuffer) | < 0.1 ms |
| Audit emit (PostgresStore INSERT) | ~1–2 ms |
| **Total p50** | **~60–80 ms** (dominated by bcrypt) |
| **Total p95** | **~100 ms** |

### Inbound MCP `tools/call` (warm)

The bcrypt verify dominates the cold path. We don't cache verifies
(deliberate — keys can be revoked at any time). Production deployments
that need lower p50 latency can swap to argon2 with a tighter cost
factor or short-TTL verify cache.

### Operator API list endpoints

Per-tenant aggregations (`GET /api/v1/users`, `/groups`, etc.) are
single-trip with LEFT JOINs:

| Endpoint | Time (100 rows) |
|---|---|
| `/users` | ~5–10 ms |
| `/audit-events?since=24h` | ~10–30 ms (depends on row count in window) |
| `/nhi-map` | ~50–100 ms (graph aggregation) |
| `/identities` | ~30–80 ms |
| `/admin/health-overview` | ~20–40 ms (Postgres `percentile_cont` + per-server joins) |
| `/admin/diagnostic-bundle` | ~100–500 ms (lots of sections) |

Indexes on `tool_call_events` cover all the common filter shapes
(see `BACKEND_DEEP_DIVE.md` schema section).

### Capability sync per server

| Phase | Time |
|---|---|
| `tools/list` upstream call | depends on upstream — typically 50 ms – 2 s |
| `mcp_capabilities` upsert | ~5 ms per row |
| Mark missing as deprecated | ~5 ms |

The scheduler's `max_concurrent_per_tenant` cap (default 3) prevents a
tenant with 50 upstream servers from blasting the network all at once.

## Observability hooks

- **Logs:** structured JSON via `logging_config.py`. One line per
  request via FastAPI middleware (configurable). Background workers
  log per cycle.
- **Metrics:** Prometheus endpoint at `/metrics` (opt-in via
  `VYUU_PROMETHEUS_ENABLED`). Exposes per-route latency histograms,
  audit-emit counters, circuit-breaker state gauges.
- **Diagnostic bundle:** [`api/diagnostic_bundle.py`](src/vyuu_gateway/api/diagnostic_bundle.py).
  One-shot JSON download for support hand-off. Bundle v1.1 covers
  every subsystem (see `BACKEND.md`).
- **Health overview:** [`api/health_overview.py`](src/vyuu_gateway/api/health_overview.py).
  Live snapshot for the operator console "Health & servers" page.
  Polled every 15 s.

## What's deliberately NOT done

- **No request-level distributed trace context.** OTel is on the
  roadmap; the gateway emits enough audit shape that you can stitch
  cross-call traces from `principal_id` + `tool` + `occurred_at`
  manually.
- **No per-tenant rate limiting beyond the inflight gate.** Token
  bucket / sliding window are roadmap.
- **No automatic Postgres failover.** Customers running in HA put a
  pgbouncer or a Patroni cluster in front and configure the
  `database_url` accordingly.
- **No end-to-end encryption of tool args / responses.** TLS terminates
  at the reverse proxy. Args are seen in plaintext by the gateway —
  by design (we need to inspect to enforce policy and audit).

## Where to dig further

- A specific request type → `BACKEND_DEEP_DIVE.md` lifecycle section
- A specific module → `BACKEND.md` per-package map
- A specific symptom → `RUNBOOK.md`
- A specific table → `BACKEND_DEEP_DIVE.md` schema section
- A specific feature in code → `KNOWLEDGE_BASE.md` jump-table
