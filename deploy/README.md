# Vyuu MCP Gateway — deployment manifests

This directory contains the runtime hardening + supervisor + resource-limit
configurations that ship with the gateway. Pick the surface that matches
how the customer is deploying:

| Surface | Path | Use when |
|---|---|---|
| **Docker Compose** | `docker/docker-compose.yml` | Single-box appliance, dev-stack, mid-market on-prem |
| **systemd** | `systemd/vyuu-gateway.service` | VM / bare-metal install, no container runtime |
| **Kubernetes** | `kubernetes/{deployment,configmap,secret}.yaml` + `migrate-job.yaml`, `rbac-secret-store.yaml`, `addons/`, `ingress.yaml.example` | Production on K8s, OpenShift, or compatible PaaS |
| **Scripted setup** | `setup/setup-linux.sh`, `setup/setup-macos.sh` | Either of the above, end to end, in one command |

## What each manifest enforces

All three surfaces wire the same Tier-1 stress-test fixes. The values
differ by surface conventions; the underlying contract is identical.

### 1. Process supervisor (auto-restart on crash)

| Surface | Mechanism |
|---|---|
| Compose | `restart: on-failure` |
| systemd | `Restart=on-failure` + `StartLimitBurst=5` (gives up after 5 crashes in 60s — operator alarm condition) |
| K8s | `restartPolicy: Always` on the Deployment |

The crash break point surfaced by the realistic-mix load test (gateway
process disappeared during sustained 32-in-flight burst) is now contained
by both the runtime fixes (back-pressure + DB pool sizing) AND a
supervisor that brings the gateway back if it ever does crash for a
reason we haven't yet diagnosed.

### 2. Resource limits (clean OOM, bounded subprocess fork)

| Surface | Memory cap | Subprocess cap |
|---|---|---|
| Compose | `mem_limit: 4g` | `pids_limit: 200` |
| systemd | `MemoryMax=8G` + `MemoryHigh=6G` | `TasksMax=512` |
| K8s | `resources.limits.memory: 2Gi` (per pod, scale via replicas) | (use namespace-level `LimitRange` for pids) |

Stdio MCPs spawn subprocesses (`uvx`, `npx`); without a pids cap a
runaway upstream-pool client could fork-bomb the host. With the cap, the
OS kills cleanly and the supervisor restarts.

### 3. Liveness / health probes (target `/healthz`, never `/api/v1/health`)

| Surface | Mechanism |
|---|---|
| Compose | `healthcheck: curl /healthz` |
| systemd | journald + external monitoring polling `/healthz` |
| K8s | `livenessProbe` + `readinessProbe` + `startupProbe` on `/healthz` |

`/healthz` is mounted at the app root and explicitly bypassed by the
per-tenant inflight gate. During load bursts, `/api/v1/health` would
queue behind tool calls and time out — K8s would mark the pod unhealthy
→ traffic redistributes → cascade. `/healthz` stays green at ~1ms even
under saturation, so monitoring never false-pages.

### 4. Inbound back-pressure (uvicorn)

All surfaces set the same env vars that drive uvicorn flags via the
gateway's Settings:

```
VYUU_INBOUND_LIMIT_CONCURRENCY=200       # fast-503 past this
VYUU_INBOUND_LIMIT_MAX_REQUESTS=10000    # worker recycle (defends against leaks)
VYUU_INBOUND_BACKLOG=128                 # kernel accept-queue depth
VYUU_INBOUND_KEEP_ALIVE_SECONDS=5        # idle conn TTL
VYUU_INBOUND_PER_TENANT_INFLIGHT_LIMIT=64
```

Past 200 in-flight (or 64 per-tenant), new requests get an immediate
503 with `Retry-After`. No silent queueing → no client-side timeouts →
no health-check cascade.

### 5. Security hardening

| Concern | All surfaces |
|---|---|
| Run as non-root | UID 10001 (`vyuu` user) |
| Read-only root FS | `read_only: true` (compose) / `readOnlyRootFilesystem: true` (K8s) |
| Drop all capabilities | `cap_drop: ALL` (compose) / `capabilities.drop: ALL` (K8s) |
| No new privileges | `no-new-privileges:true` / `allowPrivilegeEscalation: false` |
| Restrict syscalls | seccomp (K8s); systemd `SystemCallFilter` |
| Restrict address families | systemd `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` |

These are defense-in-depth — they don't fix the core security model
(which is the gateway's policy engine + secret-store + audit pipeline)
but they bound the blast radius if a CVE is discovered in any
runtime dependency.

## Sizing tiers

The same manifests run all tiers; tune via env-var overrides:

| Tier | Workload it carries | Suggested env override (Standard is the default) |
|---|---|---|
| **Starter** | ≤ 100 devs, ≤ 30 RPS | `VYUU_INBOUND_LIMIT_CONCURRENCY=100`, `VYUU_DB_POOL_SIZE=10`, `VYUU_DB_POOL_MAX_OVERFLOW=20`, K8s `replicas: 1`, compose `mem_limit: 1g` |
| **Standard** | ≤ 500 devs, ≤ 90 RPS | (defaults below) — `VYUU_INBOUND_LIMIT_CONCURRENCY=200`, `VYUU_DB_POOL_SIZE=20`, K8s `replicas: 3` |
| **Production** | ≤ 1500 devs + ≤ 200 autonomous, ≤ 200 RPS sustained, ~320 RPS burst | `VYUU_INBOUND_LIMIT_CONCURRENCY=400`, `VYUU_DB_POOL_SIZE=40`, `VYUU_DB_POOL_MAX_OVERFLOW=80`, `VYUU_WORKERS=8`, K8s `replicas: 6` (HPA scales to 12) |

Past Production tier (sustained > 200 RPS, > 1 TB/month audit), follow
the horizontal-split path documented in HANDOFF.md (split ClickHouse
first, then NATS, then Postgres, then add a real load balancer in front
of multiple gateway hosts).

## Quick-start

### Scripted (recommended)

One command per OS sets up either shape end to end — tool checks, secret
generation, migrations, first-admin bootstrap, health and sign-in checks:

```bash
./deploy/setup/setup-linux.sh     # Linux: --mode vm | --mode k8s, --help for options
./deploy/setup/setup-macos.sh     # macOS
./deploy/setup/teardown.sh        # either OS: stop the stack (--purge deletes the data too)
```

Details in [`setup/README.md`](setup/README.md). The manual equivalents:

### Docker Compose
```bash
cd deploy/docker
printf 'POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 16)" > .env
cp ../../.env.example gateway.env        # set signing secrets, VYUU_BOOTSTRAP_*, VYUU_DEFAULT_TENANT_ID
docker compose up -d --wait postgres redis nats
docker compose run --rm --no-deps gateway alembic upgrade head
docker compose up -d --wait gateway
docker compose logs -f gateway
# Operator console: http://localhost:8000/operator
```

### systemd
```bash
sudo useradd --system --home-dir /opt/vyuu/gateway --shell /sbin/nologin vyuu
sudo mkdir -p /etc/vyuu /opt/vyuu/gateway
sudo cp deploy/systemd/gateway.env.example /etc/vyuu/gateway.env
sudo chmod 0600 /etc/vyuu/gateway.env && sudo chown root:vyuu /etc/vyuu/gateway.env
# edit /etc/vyuu/gateway.env to set DB URLs + signing secrets
sudo cp deploy/systemd/vyuu-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vyuu-gateway
journalctl -u vyuu-gateway -f
```

### Kubernetes
```bash
kubectl create namespace vyuu
kubectl apply -f deploy/kubernetes/configmap.yaml
cp deploy/kubernetes/secret.yaml.example deploy/kubernetes/secret.yaml
# edit secret.yaml to set DB URLs + signing secrets
kubectl apply -f deploy/kubernetes/secret.yaml
# optional evaluation-grade Postgres / Redis: deploy/kubernetes/addons/*.yaml
# migrations run from the gateway image: deploy/kubernetes/migrate-job.yaml
kubectl apply -f deploy/kubernetes/deployment.yaml
kubectl -n vyuu rollout status deploy/vyuu-gateway
kubectl -n vyuu port-forward svc/vyuu-gateway 8000:80
# Operator console: http://localhost:8000/operator
```

## What's NOT in here yet

Tier-2 deferrals from the load-test report — these are bigger lifts:

- Persistent stdio subprocess pool (`StdioMcpClient` rewrite). Until shipped,
  stdio-MCP RPS caps at ~5/server.
- Payload-truncation policy beyond audit storage (response-side redaction
  for downstream consumers).
- ClickHouse sidecar for audit warehousing (compose / K8s manifests assume
  external warehouse). Wire the audit-consumer process when shipping the
  full appliance bundle.
- Prometheus exporter + Grafana dashboards. Metrics endpoints exist; the
  scrape target / dashboard library hasn't shipped yet.

Each of these is sized in HANDOFF.md and BACKLOG.md.
