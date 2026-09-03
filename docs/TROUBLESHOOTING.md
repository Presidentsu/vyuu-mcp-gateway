# Vyuu MCP Gateway — Troubleshooting Guide

**Audience.** Operators / SREs / customer support running the gateway
in production or public testing. The first place to look when
something's wrong.

**The TL;DR**: when you see *anything* unexpected — a 503, a stuck
tool call, capability sync failing, slow latency, the dashboard
showing zero — **download a diagnostic bundle first** and walk
through this guide alongside it.

---

## 1. The diagnostic bundle (one-click troubleshooting)

### 1.1 How to download

**Operator console** → **Dashboard** → **Download diagnostic bundle**
(top-right of the page, next to **Refresh**).

Saves a JSON file to your downloads folder named
`vyuu-diagnostic-<env>-<timestamp>.json`. Typical size: 50-200 KB.
Safe to attach to a support ticket / share over email — secrets are
redacted server-side before the response is generated.

**API path** (for scripting / curl):

```bash
curl -OJ \
  -H "Authorization: Bearer <operator-token>" \
  -H "x-vyuu-tenant-id: <tenant-uuid>" \
  "https://<gateway-host>/api/v1/admin/diagnostic-bundle?since_minutes=60"
```

`since_minutes` is configurable (1-1440, default 60).

### 1.2 What's in it

12 sections covering the gateway's full state at the moment of
collection. Each section answers a specific class of question:

| Section | Answers |
|---|---|
| `gateway` | Is the process alive? Uptime? Memory? CPU? FDs? |
| `settings_snapshot` | What's configured? (Secrets redacted; URLs partial-redacted) |
| `connectivity` | Can we reach Postgres / Redis / NATS / secret store? |
| `servers` | How many MCP servers, with what health status? Any with errors? |
| `vservers` | How many vservers, public vs private? |
| `circuit_breakers` | Are any upstream pools' circuit breakers open? |
| `inflight_gate` | What are the configured caps? |
| `stdio_subprocesses` | How many stdio MCPs are live? |
| `audit_buffer` | Recent decisions: how many allows / denies / 503s? Top denial reasons? Sample of last 200 events. |

### 1.3 What's NOT in it

Deliberately excluded (security / privacy / size):

- **Secret values** — only ref names. `database_url`'s password is
  replaced with `***`; same for `redis_url`. Fields matching
  `*_secret`, `*_password`, `*_token`, `*_key`, `signing_secret` are
  replaced with `[REDACTED]`.
- **Raw tool-call payloads** — those live in the audit warehouse
  (ClickHouse), not the bundle. Use the warehouse for forensic
  payload-level queries.
- **Cross-tenant data** — multi-tenant gateways still produce
  one-bundle-per-tenant. An operator can never see another tenant's
  data via the bundle.
- **OS-level logs** — capture those separately via your log
  aggregator. The bundle is gateway-internal state only.

### 1.4 Privacy posture (for compliance reviews)

The redaction guarantees are tested in
`tests/api/test_diagnostic_bundle.py` — specifically:

- `test_diagnostic_bundle_redacts_signing_secret` plants a known
  canary value in `Settings.operator_auth_signing_secret` and asserts
  it never appears in the response body.
- `test_diagnostic_bundle_redacts_database_url_password` does the
  same for the Postgres URL's password segment.

If the redaction logic ever regresses, these tests fail loudly in CI.

---

## 2. Common issues — reading the bundle

This section is a playbook: customer reports a symptom, you walk
through the bundle's relevant fields. Each subsection lists what
to check + what action to take.

### 2.1 "I'm getting 503s on tool calls"

**Step 1 — confirm it's the gateway shedding, not the upstream.**

```jsonc
// In the bundle:
"audit_buffer": {
  "decision_counts": { "allow": 4567, "deny": 234, "redact": 0 },
  // Did inflight_gate fire? It logs a separate denial reason.
  "denial_reasons": {
    "tool_not_in_virtual_server": 23,
    "tool_denied": 12,
    "rate_limited": 0    // ← look for this
  }
}
```

**Step 2 — check the inflight gate caps.**

```jsonc
"inflight_gate": {
  "configured_per_tenant_cap": 64,
  "configured_uvicorn_concurrency": 200,
  "configured_backlog": 128
}
```

If `configured_per_tenant_cap` is too tight for the customer's
workload (they're running >64 concurrent agent sessions), raise
`VYUU_INBOUND_PER_TENANT_INFLIGHT_LIMIT`. Standard tier defaults
to 64; production-tier deployments often raise to 128 or 256.

**Step 3 — check upstream circuit breakers.**

```jsonc
"circuit_breakers": {
  "available": true,
  "by_state": { "closed": 5, "open": 1, "half_open": 0 },
  "open_keys": [
    "(11111111-1111-1111-1111-111111111111, 22222222-2222-2222-2222-222222222244)"
  ]
}
```

A breaker keyed by `(tenant_id, server_id)` being **open** means the
gateway has stopped sending traffic to that upstream because of
repeated failures. Check `servers.with_health_errors` for the
matching server's last error — usually points at credentials, DNS,
or upstream rate-limiting.

### 2.2 "DB seems sluggish / queries timing out"

**Check connectivity:**

```jsonc
"connectivity": {
  "postgres": {
    "reachable": true,
    "version": "16.2",
    "active_connections": 47,    // ← check this
    "url": "postgresql://vyuu:***@db.internal:5432/vyuu_gateway"
  }
}
```

If `active_connections` is at or near `db_pool_size + db_pool_max_overflow`
(default 20 + 40 = 60), you're queueing on connection acquire. Either:

1. Raise pool sizes: `VYUU_DB_POOL_SIZE`, `VYUU_DB_POOL_MAX_OVERFLOW`.
2. Confirm Postgres' `max_connections` is set high enough:
   `(workers × pods × 60) + 50`.

**If `reachable: false`:**

```jsonc
"postgres": {
  "reachable": false,
  "error_type": "OperationalError",  // or NetworkError, AuthError, etc.
  "url": "postgresql://vyuu:***@db.internal:5432/vyuu_gateway"
}
```

The gateway can't reach Postgres at all. Check from the gateway host:

```bash
psql "postgresql://vyuu:<password>@db.internal:5432/vyuu_gateway" -c "SELECT 1"
```

Common causes: wrong DNS, firewall, expired Postgres credentials,
rotated password not propagated to gateway env.

### 2.3 "Tool calls fail with `capabilities_not_synced`"

**Check the servers section:**

```jsonc
"servers": {
  "total": 6,
  "by_health": { "healthy": 5, "unknown": 1 },
  "with_sync_issues": [
    {
      "id": "...",
      "display_name": "github-readonly",
      "registered_at": "2026-05-02T11:20:00Z",
      "issue": "registered > 5min ago, never synced"
    }
  ]
}
```

A server with `with_sync_issues` was registered but never had its
capabilities pulled. Auto-sync (Tier-1 fix) should have run; if it
didn't, the upstream was probably unreachable when the registration
happened. Operator action:

1. Operator console → MCP servers → click the server → **Sync**.
2. If sync fails, check `servers.with_health_errors` for the matching
   row; the upstream-side error tells you what's wrong (auth, DNS,
   rate limit, etc.).

### 2.4 "Stdio MCPs are slow / cold-spawning per call"

**Check the persistent pool is working:**

```jsonc
"stdio_subprocesses": {
  "available": true,
  "total_count": 8,
  "by_pattern": {
    "mcp-server-time": 2,
    "drawio-mcp": 0,
    "falcon-mcp": 0,
    "VirusTotal": 6
  }
}
```

Compare `total_count` to the number of stdio servers × pool size
(default 4 per server). For a deployment with 2 stdio servers and
default pool, expect ~8 subprocesses (2 servers × 4 slots × 1
process per slot, plus uvx wrappers).

**Red flag**: `total_count` swinging widely between bundles taken a
few seconds apart suggests the persistent pool isn't holding —
check that the `StdioMcpClient` Tier-2 fix is in the deployed
version (`PLATFORM.md` §0 lists it under "What's shipped").

### 2.5 "The portal won't load / sign-in fails"

**Check connectivity for Redis (required for multi-worker):**

```jsonc
"connectivity": {
  "redis": {
    "configured": true,
    "url": "redis://redis.internal:6379/0",
    "session_registry_class": "RedisSessionRegistry",
    "in_memory_fallback": false   // ← if true on >1 worker, BAD
  }
}
```

If `in_memory_fallback: true` on a multi-worker deployment, MCP
session affinity is broken — calls for the same session id will
randomly land on different workers and fail. Wire Redis:

```bash
export VYUU_REDIS_URL=redis://your-redis:6379/0
# restart the gateway pods
```

### 2.6 "Audit volume is huge / NATS lagging"

**Check the audit buffer's recent rate:**

```jsonc
"audit_buffer": {
  "recent_total": 12_500,        // events seen in `since_minutes` window
  "decision_counts": { "allow": 12_300, "deny": 200 },
  "by_vserver": {
    "github-readonly": 8000,    // ← one tenant's vserver dominating?
    "drawio-mcp": 4000
  }
}
```

If a single vserver dominates the rate AND you're seeing per-call
audit emit lag, check whether that vserver routes through tools
that return huge responses. The H3 payload-size cap
(`inbound_max_response_body_bytes`, default 25 MiB) bounds individual
calls but per-call rate × payload size is the bandwidth driver.

### 2.7 "How do I know which gateway version is deployed?"

```jsonc
"gateway": {
  "name": "Vyuu MCP Gateway",
  "version": "v1.0.0",
  "environment": "production",
  "python_version": "3.12.7",
  "platform": "Linux/x86_64",
  "hostname": "vyuu-gateway-7d4f-0",
  "process": {
    "pid": 1,
    "uptime_seconds": 86400.5,
    "rss_mb": 480.2,
    "cpu_percent": 12.3,
    "fd_count": 142
  }
}
```

Match `version` against your release tags. `uptime_seconds` tells
you when the pod last restarted (useful for "did this start
happening after the last deploy?").

### 2.8 "Memory keeps climbing / suspecting a leak"

Take **two bundles** 30 minutes apart. Compare:

- `gateway.process.rss_mb` — climbing? (Some climb is normal Python
  GC behavior; a true leak climbs without bound.)
- `gateway.process.fd_count` — climbing? (FD leaks are real bugs;
  bounded FD count proves persistent stdio pool's `aclose()` is
  working.)
- `stdio_subprocesses.total_count` — climbing? (Should stay bounded
  by `pool_size × server_count`.)
- `connectivity.postgres.active_connections` — climbing? (DB-pool
  leak; should stay near steady-state.)

If RSS climbs unboundedly across multiple bundles, capture a heap
profile during steady-state load (`memray` or `tracemalloc`) and
share that with the platform team — see `docs/QA-BACKLOG.md` §P5.1.

---

## 3. The bundle's "smoke signals" — what to scan first

Before deep-diving section by section, scan these five fields.
They're the fastest "is something obviously broken?" check:

| Field | Healthy state | Investigate if… |
|---|---|---|
| `gateway.process.uptime_seconds` | Non-zero | < 60 (process restarted recently) |
| `connectivity.postgres.reachable` | `true` | `false` |
| `circuit_breakers.by_state` | `{closed: N}` | Any `open` count > 0 |
| `servers.by_health` | mostly `healthy` | Significant `down` count |
| `audit_buffer.decision_counts.deny` / `allow` | Mostly allow | Spike in `deny` (policy may have tightened, OR upstream broke) |

---

## 4. When the bundle isn't enough

The bundle covers gateway-internal state. Three things it can't tell
you that you'll occasionally need:

1. **Gateway logs** — Python's `logging` writes structured JSON to
   stdout. Capture via your container runtime (`docker logs`,
   `kubectl logs`, `journalctl -u vyuu-gateway`) or your log
   aggregator. Filter on `tenant_id` for tenant-specific issues.
2. **Operating-system metrics** — host CPU under load, disk fill,
   network errors. Use your standard infra monitoring (Datadog
   Agent, node_exporter, CloudWatch Agent).
3. **Upstream-side logs / behaviour** — for issues that involve a
   third-party MCP (GitHub Copilot MCP, Falcon MCP), the upstream's
   own logs / dashboards / status page often hold the answer.

Combine the bundle with these external sources for full-picture
diagnosis.

---

## 5. Sharing bundles with support

Bundles are designed to be shareable as-is. Expected workflow:

1. Operator hits the issue.
2. Goes to Dashboard → **Download diagnostic bundle**.
3. Files a support ticket with:
   - The bundle (`vyuu-diagnostic-<env>-<ts>.json`).
   - Description of the symptom (when it started, how often, which
     tenant / users / vservers affected).
   - The Cursor / Claude Desktop / agent-side error message
     verbatim.
4. Support engineer opens the bundle, walks through §3 + §2.x for
   the matching symptom.
5. If the bundle isn't enough, support requests the matching log
   slice (per §4.1).

For high-severity issues, consider **two bundles 5 minutes apart**
in the initial report — gives support a delta view rather than a
single snapshot.

---

## 6. Self-service diagnostic checks before opening a ticket

Quick scripted checks an operator can run:

```bash
# Liveness — should always succeed instantly
curl -fsS http://gateway/healthz && echo OK

# Deep health — version + environment metadata
curl -fsS http://gateway/api/v1/health | jq

# Tenant-specific health: download diagnostic bundle, check key fields
curl -OJ -H "Authorization: Bearer $TOKEN" \
  "http://gateway/api/v1/admin/diagnostic-bundle?since_minutes=15" \
&& jq '{
  alive: .gateway.process.uptime_seconds,
  pg: .connectivity.postgres.reachable,
  open_breakers: .circuit_breakers.by_state.open,
  recent_denies: .audit_buffer.decision_counts.deny,
  health_errors: (.servers.with_health_errors | length)
}' vyuu-diagnostic-*.json
```

If any of those return a clearly-bad value, you have something to
investigate before involving support.

---

## 7. Glossary

Cross-reference for terminology that appears in both the bundle
and gateway logs:

| Term | Means |
|---|---|
| **inflight gate** | Per-tenant ASGI middleware that fast-503s past `VYUU_INBOUND_PER_TENANT_INFLIGHT_LIMIT` |
| **circuit breaker** | Per-`(tenant, upstream-server)` failure tracker; opens after N consecutive failures, closes after recovery_timeout |
| **vserver** | Operator-published curated subset of one or more upstream MCPs' tools |
| **upstream MCP server** | The actual MCP server that holds capabilities (GitHub MCP, Notion MCP, etc.) |
| **principal** | The identity of the caller — `endpoint_session` (Cursor / Claude Desktop), `api_key` (issued via portal), `server_agent` (autonomous agent) |
| **decision** | `allow` / `deny` / `redact` / `rewrite` — the policy engine's verdict on a tool call |
| **healthz** | `/healthz` — liveness probe at app root, bypassed by inflight gate. Used by K8s livenessProbe / load balancer health checks. |
| **deep health** | `/api/v1/health` — returns gateway metadata (version, environment) |

---

## 8. Reference

- [`PLATFORM.md`](./PLATFORM.md) — full architecture
- [`TECH-STACK.md`](./TECH-STACK.md) — packages + libraries
- [`ADMIN-GUIDE.md`](./ADMIN-GUIDE.md) — operator workflows
- [`DEVOPS-HANDOFF.md`](./DEVOPS-HANDOFF.md) — deployment + runbook
- [`STRESS-TESTING.md`](./STRESS-TESTING.md) — measured perf + sizing
- [`QA-BACKLOG.md`](./QA-BACKLOG.md) — perf + functional QA work queue
- `src/vyuu_gateway/api/diagnostic_bundle.py` — endpoint source
- `tests/api/test_diagnostic_bundle.py` — secret-redaction tests
