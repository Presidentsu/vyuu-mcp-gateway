# Vyuu MCP Gateway — QA Backlog

**Audience.** QA / SRE / perf champion. The durable to-do list of
testing work beyond what's already in `tests/perf/` and `pytest`.

**What's already shipped:**

| Type | Where | Coverage |
|---|---|---|
| Unit tests | `pytest` | 905 passing, coverage on every service / provider / lifecycle path |
| Integration tests | `pytest` (env-gated) | Postgres + Redis + NATS + drawio MCP |
| Static checks | `ruff` + `mypy --strict` | 199 files, 0 errors |
| Tenant-isolation guard | `tests/tenant_isolation/` | Every tenant-scoped table + every service entry point |
| JS regression | `tests/test_operator_ui_js_syntax.py` | `node --check` over `operator_ui` + `portal_ui` JS |
| Load test (RPS staircase) | `tests/perf/e2e_stress.py` (P1-P2) | Gateway hot path + stdio persistent path |
| Stress test (past saturation) | `tests/perf/e2e_stress.py` (P3) | 256 in-flight against 128-cap gate |
| Soak test (1h) | `tests/perf/soak_runner.py` | RSS plateau confirmed, no leak |
| Chaos (light) | `tests/audit/test_clickhouse_consumer.py`, stdio death tests | Backing-service drop + recovery |

**What's not shipped:** the items below, prioritized by impact × effort.

---

## Tier 1 — High-leverage, low-effort (next sprint)

These five items are the highest-signal-per-hour additions to the perf
posture. All cumulatively buyable in a week.

### P1.1 · CPU flame graph under sustained load

| Field | Value |
|---|---|
| **Effort** | 2 hours |
| **Tool** | `cProfile` + `flameprof` (py-spy needs root on macOS — see `tests/perf/lab_for_profile.py`) |
| **Run during** | 60s sustained 32-in-flight load via `tests/perf/sustained_for_flame.py` |
| **Output** | [`tests/perf/results/flame-2026-05-03.svg`](../tests/perf/results/flame-2026-05-03.svg) — top 5 hot paths in `STRESS-TESTING.md` §13 |
| **Decision driver** | Optimization queue: (1) cache `resolve_tools`, (2) migrate to asyncpg, (3) audit per-call SQL count, (4) pre-compile hot SQL |
| **Status** | **Done** — 2026-05-03 |

### P1.2 · uvloop swap

| Field | Value |
|---|---|
| **Effort** | 30 minutes |
| **Change** | Add `uvloop` to deps; swap in `examples/drawio_lab_server.py` and `tests/perf/lab_with_metrics.py` (not production code path) |
| **Expected gain** | 2-3× per uvicorn worker (typical) |
| **Risk** | Low — uvloop is a drop-in for asyncio's default selector loop |
| **Status** | Not started |

### P1.3 · Tail latency (p99.9, p99.99, max) capture

| Field | Value |
|---|---|
| **Effort** | 1 hour |
| **Why** | "p99 = 50ms" hides "p99.9 = 5s" — the call your prospect's CTO sees in a Cursor demo |
| **Tool** | `wrk2` (with HdrHistogram) instead of plain k6/locust; correct for coordinated-omission |
| **Output** | New row in `STRESS-TESTING.md` headline numbers table |
| **Status** | Not started |

### P1.4 · Spike test (cold-start under burst)

| Field | Value |
|---|---|
| **Effort** | 1 hour |
| **Why** | Real autonomous agents wake on cron boundaries — they don't ramp. The current harness only does gradual ramps. |
| **Change** | New `tests/perf/spike_test.py` — `asyncio.Event` barrier releases N drivers within ~1ms; 2 passes (under-cap 100, over-cap 150) × 3 spikes each, with independent `/healthz` pinger |
| **Output** | `STRESS-TESTING.md` §12; raw [`tests/perf/results/spike-2026-05-03.log`](../tests/perf/results/spike-2026-05-03.log) |
| **Findings** | Inflight gate works (22 clean 503s = 150−128, exact). Surfaced two real issues: (a) audit DB pool exhaustion (`pool_size=20+overflow=40` → 60 connections insufficient for 100-burst, 59× `QueuePool` timeouts in run); (b) MCP stdio queue → 220s tail latency. Cooldown of 20s insufficient for drain. Mitigations listed in §12.6. |
| **Status** | **Done** — 2026-05-03 |

### P1.5 · Slow upstream / circuit breaker test

| Field | Value |
|---|---|
| **Effort** | ½ day |
| **Why** | Circuit breaker code exists in `upstream/circuit_breaker.py`; we've never load-tested it |
| **Change** | Wrap a fake-stdio MCP server that delays responses; verify breaker opens, pool sheds, recovery works |
| **Output** | New test under `tests/perf/test_circuit_breaker_under_load.py` |
| **Status** | Not started |

---

## Tier 2 — Production safety (before first customer GA)

### P2.1 · Network partition tests (Postgres / Redis / NATS)

| Field | Value |
|---|---|
| **Effort** | 1 day |
| **Why** | Standard production failure mode; gateway must survive the 30-second outage and recover cleanly |
| **Tool** | `tc qdisc` or `iptables` to block traffic on the loopback interface for fixed windows |
| **Verify** | `vyuu_proc_alive=1` throughout; healthz green; calls drain when partition heals |
| **Status** | Not started |

### P2.2 · OAuth refresh storm

| Field | Value |
|---|---|
| **Effort** | ½ day |
| **Why** | A4 (401-driven refresh) just shipped. When all users' tokens expire on the same minute, what happens? |
| **Verify** | Single-flight per `(server, principal)` works under 500 concurrent invalidations; no thundering herd against the IdP |
| **Status** | Not started |

### P2.3 · Many-tenants test (1000 tenants on one pod)

| Field | Value |
|---|---|
| **Effort** | 1 day |
| **Why** | Multi-tenant claim needs evidence. Postgres RLS perf, memory per tenant, inflight-gate scaling. |
| **Setup** | Seed 1000 tenants × 3 servers × 5 vservers each, drive load across 100 of them simultaneously |
| **Verify** | Per-tenant inflight gate doesn't cross-contaminate; Postgres RLS predicate stays sharp; memory scales |
| **Status** | Not started |

### P2.4 · 24-hour endurance

| Field | Value |
|---|---|
| **Effort** | Overnight wall-clock, ½ day setup |
| **Why** | 1-hour soak validates short-term bounded RSS. Day-long soak catches slow leaks (handle counts, FD pinning, cached-OAuth expiry). |
| **Setup** | Run the soak harness for 24h instead of 1h; capture full Prometheus history |
| **Verify** | RSS stays bounded across the full window; FD count flat |
| **Status** | Not started |

### P2.5 · Idempotency / race-condition hunt

| Field | Value |
|---|---|
| **Effort** | 1 day |
| **Why** | Concurrent ops on shared state. Two operators registering same server name, two users taking the last grant slot, simultaneous capability syncs. |
| **Tool** | Property-based test with `hypothesis`; many random concurrent operations, assert state consistency invariants |
| **Status** | Not started |

### P2.6 · Tenant isolation under load

| Field | Value |
|---|---|
| **Effort** | ½ day |
| **Why** | Per-tenant inflight gate exists; never measured cross-tenant interference. |
| **Verify** | Tenant A at 80% of its cap doesn't slow Tenant B's tool calls below their own SLO |
| **Status** | Not started |

### P2.7 · Slow consumer / NATS backpressure

| Field | Value |
|---|---|
| **Effort** | ½ day |
| **Why** | The `DiskSpoolAuditEmitter` exists but spool drain under recovery hasn't been load-tested |
| **Setup** | Block ClickHouse consumer for 5 min while gateway emits at 200 RPS; restart; verify spool drains cleanly |
| **Status** | Not started |

---

## Tier 3 — Commercial readiness (post-GA)

### P3.1 · Perf regression CI

| Field | Value |
|---|---|
| **Effort** | ½ day |
| **Why** | Catch regressions on PR. Multiplies engineering velocity. |
| **Setup** | New CI job runs a 5-min subset of `e2e_stress.py`, compares against baseline JSON, fails PR if RPS drops > 10% |
| **Status** | Not started |

### P3.2 · Production-trace replay tooling

| Field | Value |
|---|---|
| **Effort** | 2 days |
| **Why** | Synthetic load is poor proxy for real customer traffic shape. |
| **Setup** | Anonymize a customer's audit-event sample, replay through the harness against a staging gateway |
| **Activate when** | First paying customer is in production for ≥1 week |
| **Status** | Not started |

### P3.3 · Hash flood / algorithmic-complexity audit

| Field | Value |
|---|---|
| **Effort** | 1 day |
| **Why** | Security-adjacent perf. Inputs designed to trigger O(n²) work in the gateway. |
| **Coverage** | Policy evaluator, error envelope classifier, capability resolver, redaction patterns |
| **Status** | Not started |

### P3.4 · Slow loris attack defence

| Field | Value |
|---|---|
| **Effort** | ½ day |
| **Why** | One client opens many connections, dribbles bytes, ties up workers |
| **Tool** | `slowhttptest` |
| **Verify** | uvicorn's `timeout-keep-alive` + ingress-layer timeouts protect us |
| **Status** | Not started |

### P3.5 · FD / port exhaustion stress

| Field | Value |
|---|---|
| **Effort** | ½ day |
| **Why** | Pathological client that opens-closes connections forever. Confirms keep-alive timeout works and FD count stays bounded. |
| **Status** | Not started |

### P3.6 · Multi-region / cross-DC test

| Field | Value |
|---|---|
| **Effort** | Multi-day |
| **Why** | When first multi-region customer signs up. Cross-DC Postgres replication lag, NATS stretched cluster, ClickHouse multi-DC ingest. |
| **Activate when** | Customer with explicit multi-region requirement |
| **Status** | Not started |

---

## Tier 4 — MCP-gateway-specific tests

### P4.1 · HTTP/2 multiplexing measurement

| Field | Value |
|---|---|
| **Effort** | ½ day |
| **Why** | Cursor + Claude Desktop both speak HTTP/2 to MCP servers; multiplexed sessions could shift the per-worker ceiling significantly |
| **Setup** | Compare HTTP/1.1 keep-alive vs HTTP/2 multiplexing at the same RPS |
| **Status** | Not started |

### P4.2 · Large-catalog test

| Field | Value |
|---|---|
| **Effort** | ½ day |
| **Why** | Some enterprise customers will register 100+ MCP servers with 100+ tools each — does `tools/list` perform on a 10,000-tool vserver? |
| **Setup** | Synthetic 10K-capability tenant, time `GET /v/.../mcp` `tools/list` cold and warm |
| **Status** | Not started |

### P4.3 · Streaming response test (when SSE ships)

| Field | Value |
|---|---|
| **Effort** | TBD |
| **Why** | When we add SSE / chunked responses; not in v1 |
| **Status** | Blocked on streaming-response feature |

---

## Tier 5 — Profiling work

### P5.1 · Heap profile under sustained load

| Field | Value |
|---|---|
| **Effort** | 2 hours |
| **Tool** | `memray` |
| **Why** | The 1-hour soak's RSS oscillation pattern (400 → 1083 → 400 MB) — confirm where the working set lives |
| **Status** | Not started |

### P5.2 · GC pause analysis

| Field | Value |
|---|---|
| **Effort** | 2 hours |
| **Why** | Python's stop-the-world GC events under load. The 568ms healthz max latency we observed in P4 may be a GC pause. |
| **Tool** | `gc.callbacks` instrumentation or `objgraph` |
| **Status** | Not started |

### P5.3 · DB query plan audit

| Field | Value |
|---|---|
| **Effort** | ½ day |
| **Why** | Every hot-path SQL query should have an `EXPLAIN ANALYZE`'d execution plan validated. Especially the resolver join, NHI map aggregation, audit-event filter queries. |
| **Status** | Not started |

### P5.4 · Slow query log review

| Field | Value |
|---|---|
| **Effort** | 2 hours |
| **Setup** | `log_min_duration_statement = 100` in Postgres for one load-test run; review |
| **Status** | Not started |

---

## Tier 6 — Functional QA (non-perf)

### Q6.1 · Browser / accessibility testing for operator console

| Field | Value |
|---|---|
| **Effort** | 1 day |
| **Tool** | `axe-core` automated + manual screen-reader pass |
| **Coverage** | Sidebar nav, modal flows, keyboard navigation, ARIA labels |
| **Status** | Not started |

### Q6.2 · API contract tests (OpenAPI conformance)

| Field | Value |
|---|---|
| **Effort** | ½ day |
| **Tool** | `schemathesis` against the FastAPI-generated OpenAPI spec |
| **Why** | Stops API drift between code + docs |
| **Status** | Not started |

### Q6.3 · Mutation testing on critical paths

| Field | Value |
|---|---|
| **Effort** | 1 day |
| **Tool** | `mutmut` |
| **Coverage** | Policy evaluator, OAuth providers, capability resolver, error envelope classifier |
| **Status** | Not started |

### Q6.4 · Migration / rollback test

| Field | Value |
|---|---|
| **Effort** | ½ day |
| **Setup** | Apply every Alembic migration forward + back on a populated database |
| **Why** | "Can we roll back?" is a deployment-day question — must already be answered |
| **Status** | Not started |

### Q6.5 · Cross-browser perf (operator console)

| Field | Value |
|---|---|
| **Effort** | ½ day |
| **Why** | The console renders SVGs (NHI map, identity graph) — heavy DOM. Validate on Chrome / Firefox / Safari. |
| **Status** | Not started |

### Q6.6 · Security review of redaction patterns

| Field | Value |
|---|---|
| **Effort** | 1 day |
| **Why** | The H3 redaction library matches "common secret shapes" — validate against real-world test corpora (e.g., `secrets-patterns-db`) |
| **Status** | Not started |

### Q6.7 · Compliance posture review

| Field | Value |
|---|---|
| **Effort** | Multi-day |
| **Coverage** | SOC 2 controls mapping, GDPR data-handling, audit-event PII surfaces |
| **Activate when** | Customer asks for a SOC2 / ISO 27001 / FedRAMP control mapping |
| **Status** | Not started |

---

## Deliberately NOT on the roadmap

Items considered + decided against, with reasoning:

| Item | Why not |
|---|---|
| Multi-day endurance tests (>72h) | Until you have a real customer running it that long, it's overkill. The 24h endurance test in P2.4 gives 95% of the signal. |
| Thread-vs-async benchmarks | Async is the only sensible choice for this workload. No thread-pool option. |
| GIL contention testing | Async-single-threaded means GIL doesn't bite us. |
| JIT-vs-interpreted (PyPy / Cython / Mypyc) | Python's JIT story is too immature. Hot-path optimisation comes after profiling shows we need it. |
| Custom kernel-level instrumentation (eBPF, dtrace) | Overkill until userspace tools (py-spy / memray) can't explain a real perf mystery. |
| Production shadowing / dark traffic mirror | Overkill for v1. Consider after first multi-customer GA. |
| Property-based tests for every service | High value for the ones in P2.5 (concurrent state mutations). Not productive for the rest. |

---

## How to use this backlog

| Pattern | Use when |
|---|---|
| **Single perf champion** + this backlog as their queue | Small team, ≤5 engineers |
| **Sprint-Review one item per sprint** | Mid-team, perf is a side-quest of regular feature work |
| **Quarterly perf-deep-dive** (1 sprint, multiple flame-graph + optimisation cycles) | When chasing the next order-of-magnitude on RPS or latency |

For Vyuu specifically, my recommendation: **single owner running Tier 1
items in the next two weeks, then evaluating which Tier 2 items matter
most for the first prospective customer.** Tier 3 + 4 + 5 items wait
until we have either (a) a measurable production issue, or (b) a
specific customer ask.

---

## Reference

- [`STRESS-TESTING.md`](./STRESS-TESTING.md) — measured perf + sizing claims (the output of this backlog)
- [`tests/perf/README.md`](../tests/perf/README.md) — running the harness
- [`PLATFORM.md`](./PLATFORM.md) — system architecture
- [`DEVOPS-HANDOFF.md`](./DEVOPS-HANDOFF.md) — production deployment

When an item moves from "Not started" to "Done", update its row's
**Status** + add a one-line link to the PR / commit / report that
shipped it.
