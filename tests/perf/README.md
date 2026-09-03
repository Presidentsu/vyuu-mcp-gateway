# Vyuu MCP Gateway — Perf observability stack

Test-only Prometheus + Grafana for load-testing the gateway. **Not
shipped with the production package.** The gateway codebase has zero
runtime dependency on `prometheus_client`; everything in this directory
is opt-in tooling for our own perf work.

Customers who want metrics in their environment use whatever they
already have (Datadog, Splunk, native CloudWatch, OpenTelemetry, etc.)
against the gateway's structured JSON access logs and audit events.

## What's here

| File | Purpose |
|---|---|
| `metrics_middleware.py` | ASGI middleware: per-request counter / latency histogram / inflight gauge / 503 counter. Mounts `/metrics`. |
| `exporter.py` | Standalone process that polls the gateway PID for CPU / RSS / FDs, counts stdio MCP subprocesses, polls Postgres for active connections. Exposes Prometheus on `:9100`. |
| `lab_with_metrics.py` | Boots `examples/drawio_lab_server.py` with the middleware attached. |
| `e2e_stress.py` | Load harness: 5-phase stress (gateway hot-path, stdio persistent path, past-saturation, sustained burst, cleanup). |
| `docker-compose.yml` | Prometheus (`:9090`) + Grafana (`:3000`) scraping both endpoints. |
| `prometheus.yml` | Scrape config (5s interval, both jobs). |
| `grafana/` | Provisioning configs + the Vyuu dashboard JSON. |

## One-time setup

```bash
# Install perf extras into your venv (test-only; not in default deps)
pip install -e ".[perf]"
```

## Running a perf test

Three terminals (or split panes — they each foreground something useful):

**Terminal 1 — observability stack**
```bash
cd tests/perf
docker-compose up -d
# Prometheus:  http://localhost:9090
# Grafana:     http://localhost:3000  (anon viewer, dashboard pre-provisioned)
```

**Terminal 2 — gateway with metrics**
```bash
python tests/perf/lab_with_metrics.py
# Note the printed PID. Lab listens on http://127.0.0.1:8000
# Metrics endpoint: http://127.0.0.1:8000/metrics
```

**Terminal 3 — exporter + stress harness**
```bash
# Replace <PID> with the lab PID printed by lab_with_metrics.py
python tests/perf/exporter.py --gateway-pid <PID> &
EXPORTER_PID=$!

# Run the stress harness against the running lab
python tests/perf/e2e_stress.py

# Tear down the exporter
kill $EXPORTER_PID
```

Open `http://localhost:3000` while the harness runs — the **Vyuu / Vyuu
MCP Gateway — Perf** dashboard updates every 5s with the live load.

## Tear down

```bash
# In Terminal 2: Ctrl+C the lab
# In Terminal 1:
docker-compose down       # keep Prometheus state
docker-compose down -v    # wipe Prometheus + Grafana state for a fresh run
```

## Dashboard panels

| Section | Panel |
|---|---|
| Header (stat row) | Gateway alive ・ RPS ・ Inflight ・ 503/s ・ Stdio subprocesses |
| Request | RPS by status code ・ Latency p50 / p95 / p99 |
| Routing | RPS by route (top 10) ・ Inflight by route |
| Process | Gateway CPU % ・ Gateway RSS ・ Gateway FDs |
| Backing | Stdio subprocesses (count + RSS) ・ Postgres active connections |

## Adding metrics

If you need a new metric for a load-test investigation:

- **In-process events** (request, response, gate decisions) — add to
  `metrics_middleware.py`. Keep label cardinality bounded; normalize
  paths via `_PATH_PATTERNS`.
- **Process-level / external state** (subprocess counts, DB connections,
  disk usage) — add to `exporter.py`.

Don't add metrics to `src/vyuu_gateway/` — that's the boundary. If a
metric feels like it belongs there, the question is "should we ship a
`/metrics` endpoint as an opt-in feature?" — different conversation.

## What this is NOT

- A production-ready monitoring solution. The Grafana password is
  literally `admin`. Anonymous viewer is enabled. `extra_hosts` is
  Docker Desktop's default. None of this is hardened.
- A general-purpose load tester. The harness is opinionated for the
  Vyuu gateway — multi-vserver mix, MCP session lifecycle, etc.
- An OpenTelemetry collector. We use Prometheus pull-mode for
  simplicity. If we ever ship gateway-native telemetry, OTLP is the
  right protocol; this directory is not the place for it.

## Operational sanity checks before pushing perf claims

When using these tools to publish a sizing / throughput number:

1. **Run the harness twice** — first run pays cold-start (uvx
   subprocess spawn, capability cache miss, Postgres query plan cache
   miss). Second run is the real number.
2. **Watch `vyuu_proc_alive`** — if it flips during the run, the
   gateway crashed. The number is invalid; fix the crash first.
3. **Check `vyuu_stdio_subprocess_count`** — if it equals or exceeds
   the harness's session count, the persistent stdio pool is leaking
   (Tier-2 bug regressed). If it stays bounded by `pool_size × N_servers`,
   the pool is healthy.
4. **Postgres active connections** — should stay well under
   `pool_size + max_overflow`. If pegged at the limit, request latency
   is queueing on DB acquisition, not on real work.
