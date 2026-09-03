# Vyuu MCP Gateway — DevOps handoff

**Audience.** The platform/SRE engineer responsible for getting the
gateway into production: container build, deployment manifests,
backing-service wiring, observability, day-2 operations.

**Status.** All Tier-1 + Tier-2 stability work is shipped and
measured. The deployment surfaces (`deploy/docker/`, `deploy/systemd/`,
`deploy/kubernetes/`) are validated against the load-test harness.

For the platform's user-facing setup (registering MCP servers,
publishing vservers), see [`ADMIN-GUIDE.md`](./ADMIN-GUIDE.md). For
performance numbers and sizing, see [`STRESS-TESTING.md`](./STRESS-TESTING.md).

---

## 1. Components you'll deploy

The gateway is one Python process, but a production deployment has
**six runtime tiers**. Most install at the same time but scale
independently.

| Tier | What it does | Where it lives |
|---|---|---|
| **Gateway pods** (vyuu-gateway) | The actual HTTP / MCP server. FastAPI + uvicorn. Async, stateless. | Container image (this repo's `Dockerfile`) |
| **Postgres** | Config DB — tenants, users, MCP servers, vservers, grants, OAuth tokens, capabilities. NOT audit events. | Managed (RDS / CloudSQL) or self-hosted (Patroni cluster) |
| **Redis** | Multi-instance MCP session registry. Required when running >1 gateway worker / pod. | Managed (ElastiCache / GCP Memorystore) or self-hosted (Sentinel) |
| **NATS JetStream** | Durable audit-event stream. Producer in the gateway, consumer separate. | 3-node RAFT cluster |
| **Audit consumer** (`vyuu_gateway.audit.clickhouse_consumer`) | Drains NATS → ClickHouse in batches. Stateless. | Standalone container; 2 replicas active-active |
| **ClickHouse** | Audit warehouse — every tool call, indexed by tenant + timestamp. 90-day retention default. | 3-node replicated MergeTree |

Optional tiers:
- **Observability** (Prometheus + Grafana) — only if customer doesn't have their own. Gateway has NO built-in `/metrics`; use structured logs + audit events.
- **MinIO / S3** for ClickHouse partition rollover (long-tail retention).

---

## 2. Container image

The repo ships a production-grade `Dockerfile` at the root.

### 2.1 Build

```bash
docker build -t vyuu-gateway:v1.0.0 .
docker tag vyuu-gateway:v1.0.0 ghcr.io/<your-org>/vyuu-gateway:v1.0.0
docker push ghcr.io/<your-org>/vyuu-gateway:v1.0.0
```

### 2.2 What's inside the image

- **Multi-stage** — builder stage compiles wheels; runtime stage carries only what's needed to run.
- **Non-root** — UID 10001 (`vyuu` user). Refuses to run as root.
- **Read-only root FS** assumed by `deploy/` manifests; `/tmp` is `tmpfs` for stdio working dirs.
- **No `--reload`** — production mode only. `--reload` was the dev-image gotcha that wrapper containers inherited.
- **Healthcheck** baked in: `curl --fail http://127.0.0.1:8000/healthz` every 15s. Liveness probes survive even when tool-call traffic is queue-saturated.
- **Default CMD** uses Tier-1 back-pressure flags: `--limit-concurrency 200`, `--limit-max-requests 10000`, `--backlog 128`, `--timeout-keep-alive 5`.

### 2.3 Signing + supply chain (recommended)

```bash
# Sign with cosign (keyless / OIDC-based)
cosign sign --yes ghcr.io/<your-org>/vyuu-gateway:v1.0.0

# Generate SBOM
syft ghcr.io/<your-org>/vyuu-gateway:v1.0.0 -o spdx-json > sbom.json

# Generate vulnerability scan
trivy image ghcr.io/<your-org>/vyuu-gateway:v1.0.0
```

The K8s manifests in `deploy/kubernetes/` use `imagePullPolicy: IfNotPresent`
— rotate by changing the tag, not by re-pushing the same tag.

---

## 3. Deployment surfaces — pick one

The repo ships three production-grade manifests, each enforcing the
same Tier-1 contract differently.

| Surface | Path | Use when |
|---|---|---|
| **Docker Compose** | `deploy/docker/docker-compose.yml` | Single-box appliance, dev stack, mid-market on-prem |
| **systemd** | `deploy/systemd/vyuu-gateway.service` + `gateway.env.example` | VM / bare-metal install, no container runtime |
| **Kubernetes** | `deploy/kubernetes/{deployment,configmap,secret.yaml.example}.yaml` | Production K8s / OpenShift |

The `deploy/README.md` covers each in detail. Highlights below.

### 3.1 Docker Compose (single-box appliance)

```bash
cd deploy/docker
POSTGRES_PASSWORD=$(openssl rand -hex 16) docker-compose up -d
docker-compose logs -f gateway
```

Bundles gateway + Postgres + Redis + NATS in one stack. Resource
limits in compose: `mem_limit: 4g`, `pids_limit: 200`, `restart:
on-failure`, healthcheck targeting `/healthz`, read-only root FS,
`cap_drop: ALL`.

For Standard tier (≤500 devs, ≤90 RPS), this is sufficient. Bump `mem_limit`
and worker count for Production tier.

### 3.2 systemd (VM / bare-metal)

```bash
sudo useradd --system --home-dir /opt/vyuu/gateway --shell /sbin/nologin vyuu
sudo mkdir -p /etc/vyuu /opt/vyuu/gateway
# Install your code at /opt/vyuu/gateway and create a venv
sudo cp deploy/systemd/gateway.env.example /etc/vyuu/gateway.env
# Edit /etc/vyuu/gateway.env with real DB / Redis / NATS URLs + signing secrets
sudo chmod 0600 /etc/vyuu/gateway.env && sudo chown root:vyuu /etc/vyuu/gateway.env
sudo cp deploy/systemd/vyuu-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vyuu-gateway
journalctl -u vyuu-gateway -f
```

Hardening directives: `Restart=on-failure`, `StartLimitBurst=5`,
`MemoryMax=8G`, `TasksMax=512`, full sandbox (`ProtectSystem=strict`,
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`,
`SystemCallFilter=@system-service`, `NoNewPrivileges`, `PrivateTmp`,
`PrivateDevices`, …).

### 3.3 Kubernetes (production)

```bash
kubectl create namespace vyuu
kubectl apply -f deploy/kubernetes/configmap.yaml
cp deploy/kubernetes/secret.yaml.example deploy/kubernetes/secret.yaml
# Edit secret.yaml with real connection strings + signing secrets
kubectl apply -f deploy/kubernetes/secret.yaml
kubectl apply -f deploy/kubernetes/deployment.yaml
kubectl -n vyuu rollout status deploy/vyuu-gateway
```

Manifests include: 3-replica baseline → 12-replica HPA, PodDisruptionBudget
(`minAvailable: 2`), topology spread across nodes, `runAsNonRoot`,
seccomp `RuntimeDefault`, `cap_drop: ALL`, `readOnlyRootFilesystem`,
graceful drain via `lifecycle.preStop`, livenessProbe / readinessProbe /
startupProbe all on `/healthz`.

---

## 4. Backing services — sizing + setup

### 4.1 Postgres

Used for **gateway config only** (NOT audit events). Tables stay
small — tens of MB at most for typical tenants.

| Spec | Value |
|---|---|
| Version | 16+ (recommended), 14+ minimum |
| Default extensions | `uuid-ossp`, `pgcrypto` |
| RLS (row-level security) | **Required** — gateway depends on it |
| Pool sizing | gateway ships `pool_size=20, max_overflow=40, pool_timeout=10s`; tune `max_connections` accordingly: `(workers × pods × 60) + 50` |
| Suggested instance | `db.r6g.large` (2 vCPU, 16 GB) for Standard tier; up to `db.r6g.xlarge` for Production |
| Storage | 200 GB SSD baseline; gateway config + indexes never approaches this |

Schema migrations run via Alembic at gateway startup (idempotent).
Operators don't typically need to touch them. The gateway's
`maybe_bootstrap_admin()` seeds the first tenant + admin from env vars.

### 4.2 Redis

**Required when running >1 gateway worker / pod** — backs the MCP session
registry. Without Redis, sessions are in-process and a load balancer
will route requests for the same session to the wrong pod.

| Spec | Value |
|---|---|
| Version | Redis 7+ |
| Sizing | One key per active MCP session, ~500 bytes each. ~5,200 keys for our canonical 1,000-dev workload = <3 MB |
| Suggested instance | `cache.t4g.small` (1.5 GB) is generous for any deployment we've sized |
| HA | Sentinel (self-hosted) or managed (ElastiCache w/ replication group) |
| Persistence | Optional — sessions are ephemeral; AOF off is fine |

### 4.3 NATS JetStream

Durable audit stream. Gateway produces; the audit consumer (next
section) drains.

| Spec | Value |
|---|---|
| Version | NATS 2.10+ with JetStream |
| Topology | 3-node RAFT cluster (HA, not throughput multiplier — JetStream is single-leader-per-stream) |
| Sizing per node | 4 vCPU, 8 GB RAM, **2 TB NVMe**. 158 GB/day raw audit at 140 RPS canonical workload × 3-day buffer = ~500 GB working set. 2 TB headroom for slow-consumer windows. |
| Stream config | Pre-create at deployment time: `nats stream add VYUU_AUDIT --subjects 'vyuu.audit.events.>' --storage file --retention limits --max-age 72h` |

The gateway does NOT auto-create the stream — that's deliberately the
operator's responsibility, so storage class / retention / replication
factor are decisions you make once with full intent.

### 4.4 Audit consumer (NATS → ClickHouse)

Standalone process, ships in the same gateway image but invoked with a
different entry point.

```bash
docker run --rm vyuu-gateway:v1.0.0 \
  python -m vyuu_gateway.audit.clickhouse_consumer \
    --nats nats://nats.internal:4222 \
    --clickhouse-url http://clickhouse.internal:8123 \
    --clickhouse-user vyuu \
    --clickhouse-password "$CLICKHOUSE_PASSWORD" \
    --batch-size 1000 --batch-interval 1.0
```

K8s deployment: 2 replicas active-active (NATS consumer group balances
the stream across them). Stateless — no PVC needed.

### 4.5 ClickHouse (audit warehouse)

| Spec | Value |
|---|---|
| Version | ClickHouse 24+ |
| Topology | 3-node replicated MergeTree (HA + read parallelism) |
| Sizing per node | 8 vCPU, 32 GB RAM, **4 TB NVMe** |
| Schema | See `vyuu_gateway/audit/clickhouse_consumer.py` docstring (also reproduced in §6 below) |
| Retention | 90 days default via `TTL ... INTERVAL 90 DAY DELETE`. Tune to your compliance requirement; longer = more disk. |
| Long-tail | Roll partitions older than 90 days to S3 / MinIO via Parquet+ZSTD; query via Trino if forensics needs them |

Audit volume reference at canonical workload (140 RPS × 13 KB/event):
- ~158 GB/day raw
- ~16 GB/day after ClickHouse compression (~10× ZSTD on JSON-ish payloads)
- 90-day retention: ~1.4 TB compressed

---

## 5. Configuration reference

All env vars consumed by the gateway runtime. Defaults match
`Settings` in `src/vyuu_gateway/config.py`.

### 5.1 Connection strings

| Var | Default | Purpose |
|---|---|---|
| `VYUU_DATABASE_URL` | `postgresql+psycopg://vyuu:vyuu@localhost:5432/vyuu_gateway` | Postgres URL |
| `VYUU_REDIS_URL` | unset | Required when `>1` worker / pod |
| `VYUU_NATS_URL` | unset | Audit producer target |

### 5.2 Inbound back-pressure (Tier-1 stress-test fix)

| Var | Default | Purpose |
|---|---|---|
| `VYUU_INBOUND_LIMIT_CONCURRENCY` | `200` | Fast-503 past this in-flight count per worker |
| `VYUU_INBOUND_LIMIT_MAX_REQUESTS` | `10000` | Worker recycle threshold (slow-leak defence). 0 disables. |
| `VYUU_INBOUND_BACKLOG` | `128` | Kernel accept-queue depth |
| `VYUU_INBOUND_KEEP_ALIVE_SECONDS` | `5` | Idle conn TTL |
| `VYUU_INBOUND_PER_TENANT_INFLIGHT_LIMIT` | `64` | Per-tenant inflight gate cap |

### 5.3 DB pool

| Var | Default | Purpose |
|---|---|---|
| `VYUU_DB_POOL_SIZE` | `20` | Sized to feed inflight gate |
| `VYUU_DB_POOL_MAX_OVERFLOW` | `40` | Burst capacity |
| `VYUU_DB_POOL_TIMEOUT_SECONDS` | `10` | Acquire timeout |
| `VYUU_DB_POOL_RECYCLE_SECONDS` | `1800` | Conn rotation |

### 5.4 Audit storage

| Var | Default | Purpose |
|---|---|---|
| `VYUU_AUDIT_RAW_CAPTURE_BYTE_CAP` | `10485760` (10 MiB) | Cap on opted-in raw payload storage. Transit unaffected. |

### 5.5 Inbound payload limits (H3)

| Var | Default | Purpose |
|---|---|---|
| `VYUU_INBOUND_MAX_REQUEST_BODY_BYTES` | `5242880` (5 MiB) | Fast-413 over-cap requests |
| `VYUU_INBOUND_MAX_RESPONSE_BODY_BYTES` | `26214400` (25 MiB) | Truncate over-cap responses with marker |
| `VYUU_INBOUND_REDACT_RESPONSE_SECRETS` | `false` | Opt-in regex-based PII / secret redaction in responses |

### 5.6 Auto-sync

| Var | Default | Purpose |
|---|---|---|
| `VYUU_AUTO_SYNC_CAPABILITIES_ON_REGISTRATION` | `true` | Background-sync after server registration |
| `VYUU_AUTO_SYNC_PER_CALL_TIMEOUT_SECONDS` | `30` | Tight cap to bound the bg task |

### 5.7 Operator + portal auth

| Var | Default | Purpose |
|---|---|---|
| `VYUU_OPERATOR_AUTH_SIGNING_SECRET` | `dev-not-for-production` | HMAC for operator console test tokens. **Set to long random string in prod.** |
| `VYUU_PORTAL_SESSION_SIGNING_SECRET` | `dev-portal-session-secret` | HMAC for portal browser sessions. **Set to long random string in prod.** |

---

## 6. ClickHouse audit-events schema

Run once at deployment time:

```sql
CREATE TABLE audit_events (
    event_id UUID,
    timestamp DateTime64(3, 'UTC'),
    tenant_id UUID,
    gateway_instance_id String,
    principal_type LowCardinality(String),
    principal_id String,
    principal_display String,
    vserver_id Nullable(UUID),
    vserver_name Nullable(String),
    upstream_server_id Nullable(UUID),
    tool LowCardinality(String),
    decision LowCardinality(String),
    decision_mode LowCardinality(String),
    policy_rule_id Nullable(String),
    latency_ms_total Nullable(Float64),
    latency_ms_upstream Nullable(Float64),
    upstream_status LowCardinality(String),
    response_size_bytes Nullable(UInt64),
    event_type LowCardinality(String),
    auth_failure_reason Nullable(String),
    raw_args Nullable(String),
    raw_response Nullable(String),
    raw_args_truncated Bool,
    raw_response_truncated Bool,
    full_event String,  -- canonical JSON for forensic queries
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/audit_events', '{replica}')
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (tenant_id, timestamp, event_id)
TTL toDateTime(timestamp) + INTERVAL 90 DAY DELETE;
```

Common queries:

```sql
-- Tool-call rate per tenant, last hour
SELECT tenant_id, count() / 3600 AS rps
FROM audit_events
WHERE timestamp >= now() - INTERVAL 1 HOUR
GROUP BY tenant_id;

-- Top 10 most-called tools across all tenants, today
SELECT tool, count() AS calls
FROM audit_events
WHERE timestamp >= today()
GROUP BY tool
ORDER BY calls DESC
LIMIT 10;

-- Denied calls by reason, today
SELECT policy_rule_id, count()
FROM audit_events
WHERE timestamp >= today() AND decision = 'deny'
GROUP BY policy_rule_id
ORDER BY count() DESC;
```

---

## 7. Observability

Two first-class integrations, plus the structured-log and audit paths
that predate them.

### 7.0 Splunk

**SIEM export (Splunk HEC).** Every security-relevant event — tool calls
(with policy decision, latency, upstream status, and payloads when
policy captured them), connection-level rejections, admin actions,
console/portal sign-ins (success and failure), and per-user tool
authorisation (OAuth connect / disconnect / failures) — is shipped to a
Splunk HTTP Event Collector as `sourcetype=vyuu:mcp:<category>`. Two
tiers:

- **Deployment target** — `VYUU_SIEM_HEC_URL` + `VYUU_SIEM_HEC_TOKEN`
  (+ optional `_INDEX`, `_CATEGORIES`, `_LOG_LEVEL`). Receives every
  tenant's events and gateway-wide log lines. Yours.
- **Tenant targets** — each tenant's admins configure their own in the
  console (Observability → SIEM export). Receives only that tenant's
  events. The HEC token is a SecretStore ref, never stored in Postgres.

Delivery is non-blocking and batched; failures never touch the request
path. Loss is bounded and visible: a target that cannot keep up drops
the newest events, counts them, and shows as degraded in the console
with Splunk's own error text. Postgres remains the durable copy.

**Telemetry (OpenTelemetry → Splunk OTel Collector).** Install the
`[otel]` extra and set `VYUU_OTEL_ENABLED=true` +
`VYUU_OTEL_EXPORTER_OTLP_ENDPOINT=http://<collector>:4318`. Traces:
`vyuu.mcp.request → vyuu.policy_eval → vyuu.upstream.call_tool`.
Metrics (bounded cardinality — tenant, vserver, upstream, decision,
status; never tool names or principal ids): `vyuu.tool_calls`,
`vyuu.tool_call.duration`, `vyuu.upstream.duration`,
`vyuu.access_attempts`, `vyuu.auth.logins`, `vyuu.siem.events_sent`,
`vyuu.siem.events_failed`, `vyuu.audit.emit_failures`. Deployment-level
by design (a tenant-editable collector endpoint would let one tenant
redirect telemetry carrying every tenant's ids); the console's
Observability → Telemetry panel shows status and sends a test signal.

The gateway still ships **no built-in `/metrics` endpoint** — Prometheus
users scrape the OTel Collector's Prometheus exporter instead. Other
customer observability paths:

### 7.1 Recommended customer-side observability

| Signal | Where to consume |
|---|---|
| Tool-call rate / errors / latency | Audit events in ClickHouse — query directly or pipe into your dashboarding tool |
| Process metrics (CPU / RSS / FDs) | Standard host-level monitoring (Datadog Agent, CloudWatch Agent, node_exporter to whatever) |
| HTTP access logs | uvicorn writes structured JSON; ingest into your log pipeline |
| Liveness | `/healthz` returns 200 OK in <1ms — wire into your health-check polling |
| Deep health | `/api/v1/health` returns environment + version metadata |

### 7.2 If you want Prometheus + Grafana

The repo ships a **test-only** Prometheus + Grafana stack at
`tests/perf/`. It's NOT intended for production — it exists for our
load-testing work. Customers wanting Prometheus should:

1. Install via `pip install vyuu-mcp-gateway[perf]` to get the
   ASGI metrics middleware (under `tests.perf.metrics_middleware`).
2. Wrap the FastAPI app at startup (`from tests.perf.metrics_middleware
   import attach_metrics; attach_metrics(app)`).
3. Scrape `/metrics` from their existing Prometheus.

Or build their own integration — the `prometheus_client` library is
stable, the metrics list is small (5-7 series), one engineer can wire
it in a day.

---

## 8. Day-2 ops runbook

### 8.1 Rolling update

```bash
# Build + push new image
docker build -t ghcr.io/<your-org>/vyuu-gateway:v1.1.0 .
docker push ghcr.io/<your-org>/vyuu-gateway:v1.1.0

# K8s
kubectl -n vyuu set image deploy/vyuu-gateway gateway=ghcr.io/<your-org>/vyuu-gateway:v1.1.0
kubectl -n vyuu rollout status deploy/vyuu-gateway

# Compose
docker-compose pull && docker-compose up -d gateway

# systemd
sudo systemctl restart vyuu-gateway
journalctl -u vyuu-gateway -f
```

K8s manifest's `lifecycle.preStop: sleep 10` plus
`terminationGracePeriodSeconds: 30` gives in-flight tool calls 10-30s
to drain before SIGKILL.

### 8.2 Rotating signing secrets

1. Generate new long-random string.
2. Update env var (Settings) in your manifest.
3. Restart pods.
4. Operators with old tokens get 401 on next refresh — they re-sign in.
5. End-user API keys are bcrypt-hashed against the user row, NOT the
   signing secret, so they're unaffected.

### 8.3 Database migration

```bash
# Connect to a gateway pod
kubectl -n vyuu exec -it deploy/vyuu-gateway -- bash

# Run alembic upgrade head
cd /app
alembic upgrade head
```

Migrations are idempotent. The gateway also runs `alembic upgrade head`
at startup (idempotent — no-op if already current).

### 8.4 Backup procedures

| Data | Backup method | RPO target |
|---|---|---|
| Postgres | `pg_dump` nightly to MinIO/S3 | 24h |
| ClickHouse | Partition-level snapshots to MinIO/S3, daily | 24h |
| OAuth refresh tokens | (in Postgres) | 24h |
| Secret store | Per your secret store's procedure (Vault snapshots, etc.) | 24h |
| NATS | NOT backed up — it's a buffer; truth is downstream | — |

For tighter RPO, run Postgres + ClickHouse with WAL streaming /
incremental snapshots.

### 8.5 Disaster recovery

Documented in `deploy/docker/`, `deploy/systemd/`, `deploy/kubernetes/`
README sections — "Restoring from a tarball backup" is the common
scenario. The gateway is fully reconstructable from:
- Postgres dump (config state)
- ClickHouse data (audit history)
- Secret store (credentials)

No state lives in the gateway pods themselves.

---

## 9. Common DevOps tasks

### 9.1 Adding a customer (multi-tenant install)

1. Operator console (as super-admin) → Tenants → Create.
2. Capture the new `tenant_id` (UUID).
3. Provide the tenant's first owner-role operator credentials.
4. Customer sets up MCP servers + vservers per [`ADMIN-GUIDE.md`](./ADMIN-GUIDE.md).

### 9.2 Removing a tenant

1. Operator console → Tenants → Delete.
2. Postgres FK cascade reaps all tenant-scoped rows.
3. ClickHouse audit data is NOT auto-deleted — for compliance you
   typically want it retained per your policy. To purge:
   `ALTER TABLE audit_events DELETE WHERE tenant_id = '<uuid>'` (slow,
   uses mutation); preferred is to wait for partition expiry.

### 9.3 Upgrading from N → N+1

Read `HANDOFF.md` between the version tags — every change is logged
chronologically. For breaking changes, follow the migration steps in
that release's section.

---

## 10. Reference

- [`PLATFORM.md`](./PLATFORM.md) — full architecture
- [`TECH-STACK.md`](./TECH-STACK.md) — packages + libraries + decisions
- [`ADMIN-GUIDE.md`](./ADMIN-GUIDE.md) — admin / operator workflows
- [`STRESS-TESTING.md`](./STRESS-TESTING.md) — measured perf + sizing
- `deploy/docker/` — Compose manifest details
- `deploy/systemd/` — systemd unit details
- `deploy/kubernetes/` — K8s manifest details
- `tests/perf/` — perf observability stack (test-only)
