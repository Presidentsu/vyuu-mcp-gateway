# Vyuu MCP Gateway — Technical Specification

**Version:** 0.1 (draft)
**Status:** Internal review, pre-implementation
**Owner:** Krishna Sai Marella
**Date:** 2026-04-28
**Intended readers:** Backend engineering team, security architect, Claude Code (for implementation planning)

---

## 1. Executive summary

The Vyuu MCP Gateway is a server-side, multi-tenant MCP enforcement and observability product, sold as an add-on to the Vyuu endpoint agent within the AI Shield product line. Together, the two products form the AI Shield two-PEP architecture: the endpoint agent intercepts MCP usage on user devices, while the gateway enforces policy and captures telemetry for server-side agents, browser-resident copilots, and shared team MCP servers — cases the endpoint agent cannot reach.

Both PEPs share one policy engine (ported from the Vyuu agent codebase), one audit schema, and one management plane (Vyuu mgmt plane). The gateway is a data plane component. It does not own policies, does not own identity, and does not own the customer-facing dashboard. It is a multi-tenant proxy that registers MCP servers, hosts virtual server compositions, maintains an agent catalog, monitors all traffic, and exports structured telemetry upstream to mgmt plane.

The gateway has its own operator-facing dashboard for SRE and gateway-specific health concerns, distinct from the customer-facing Vyuu mgmt plane dashboard.

This document is the source of truth for engineering. Read it end-to-end before opening pull requests.

---

## 2. Scope

### 2.1 In scope, v1

- Register MCP servers from three source types: npm-published packages, HTTP URLs, and local stdio commands.
- Compose virtual servers — curated bundles of tools drawn from one or more registered servers, exposed as a new MCP endpoint.
- Support current MCP transports: stdio, SSE (legacy), Streamable HTTP (current spec).
- Accept customer-supplied custom MCP servers via URL registration; gateway-side hosting deferred to v2.
- Maintain an A2A agent catalog: agent cards, capabilities, endpoints, discovery metadata. Catalog only; runtime A2A interception deferred.
- Capture every tool call (request, response, decision) as a structured audit event and forward to Vyuu mgmt plane.
- Expose an independent operational dashboard for gateway operators (gateway health, throughput, upstream connectivity, error rates) — separate from the Vyuu customer dashboard.
- Enforce multi-tenant isolation at data, network, and policy layers.
- Scale to 10,000 simultaneously active endpoint sessions per logical gateway deployment.
- Deploy on-prem (Helm-based, air-gappable) and as dedicated-tenancy SaaS.

### 2.2 Out of scope, v1 (deferred to v2 or later)

- Gateway-side hosting of customer MCP servers with sandboxed runtime.
- End-user OAuth 2.1 / OIDC at the gateway (mgmt plane handles operator auth in v1).
- NHI / agent identity delegation chains and propagation.
- Runtime A2A traffic interception and policy enforcement.
- Inline LLM-as-judge for response inspection. v1 supports regex / pattern-based redaction.
- Cross-tenant policy templates and marketplace.

### 2.3 Never in scope

- Replacing the Vyuu mgmt plane. Gateway is data plane only.
- Acting as an LLM model gateway. This product gates tool calls, not inference.
- Storing customer business data beyond what's needed for registry, audit, and operational metrics.

---

## 3. Functional requirements

### 3.1 Feature 1 — MCP server registration

Operators register MCP servers into a tenant via gateway admin API or UI. Three source types, each with distinct lifecycle handling.

**npm-published servers.** Example: `@chkp/harmony-sase-mcp`, `@modelcontextprotocol/server-github`. The gateway downloads the package and runs it inside an isolated container per `(server, tenant)` tuple, exposing the stdio transport as an MCP endpoint internal to the gateway's connection pool. Runtime isolation: gVisor or Firecracker for shared-tenancy deployments; runc with seccomp and AppArmor acceptable for dedicated-tenancy.

**HTTP-URL servers.** Example: `https://mcp.excalidraw.com`, `https://mcp.example.com/sse`. Gateway registers the URL, detects transport (SSE or Streamable HTTP) via probe, treats upstream as remote MCP endpoint reachable via connection pool. No container runtime needed.

**stdio commands.** Example: `python -m my_internal_mcp_server`, `node ./custom-server.js`. Same lifecycle as npm-published: containerized child process, supervised, stdio bridged.

Common registration metadata captured for all source types:

| Field | Type | Notes |
|---|---|---|
| `id` | uuid | Gateway-assigned |
| `tenant_id` | uuid | Required; multi-tenant isolation |
| `display_name` | string | Operator-friendly name |
| `source_type` | enum | `npm` \| `http` \| `stdio` |
| `source_location` | string | Package name, URL, or command |
| `transport` | enum | `stdio` \| `sse` \| `streamable_http` |
| `env_vars_ref` | string | Vault/KMS reference, never plaintext |
| `args` | string[] | For stdio/npm only |
| `registered_by` | uuid | Operator principal |
| `registered_at` | timestamp | |
| `health_status` | enum | `healthy` \| `degraded` \| `down` \| `unknown` |
| `last_capabilities_pulled_at` | timestamp | |

**Acceptance criteria:**

- Registration completes within 30 seconds excluding npm download time.
- Immediate connectivity probe runs after registration; failure surfaces structured error to operator.
- Capability sync (`tools/list`, `resources/list`, `prompts/list`) runs after probe; results stored versioned in `mcp_capabilities`.
- Periodic re-sync runs every 15 minutes (per-tenant configurable).
- Capability drift (tool added, removed, schema changed) emits structured event to mgmt plane.
- Per-server health endpoint exposes: last sync time, last error, current connectivity, request count and latency p50/p99 over last hour.

### 3.2 Feature 2 — Virtual servers (tool bundles)

A virtual server is a curated bundle of tools drawn from one or more registered MCP servers, exposed as a new MCP endpoint. Equivalent in concept to ContextForge "virtual gateways" but designed for tighter Vyuu integration.

**Example.** Tenant `acme-bank` defines virtual server `finance-readonly` exposing read-only tools from registered `postgres-mcp` (tool: `query_select`) and `s3-mcp` (tool: `list_objects`, `get_object`). The virtual server is reachable at `https://gateway.vyuu.example/v/acme-bank/finance-readonly/mcp`. Clients connect to that endpoint as if it were a single MCP server. Behind the scenes, the gateway routes calls to the appropriate upstream and applies the bundle's policy.

**Tool naming and namespacing.** Within a virtual server, tools are exposed under their original names by default. On collision (two upstream servers both exporting `query`), gateway prefixes with the upstream server's display name: `postgres_query`, `mongo_query`. Operators can override the exposed name per tool via a rename map at virtual server creation time.

**Policy attachment.** Every virtual server has a policy reference (`policy_id`). Policy bodies live in mgmt plane and are pulled on a 60-second TTL. The same policy schema used by Vyuu agent applies; the gateway evaluates the policy in the request hot path.

**Acceptance criteria:**

- Operator can create virtual server with allowlist of `(server_id, tool_name)` tuples plus optional rename map.
- Virtual server endpoint is a fully MCP-compliant server: clients can `initialize`, `tools/list`, `tools/call`, etc.
- Tool calls route to the correct upstream server preserving call ordering and session state.
- Calls to tools not in the allowlist return MCP error `MethodNotFound` and emit `audit_event(decision=denied, reason=tool_not_in_vserver)`.
- Schema strict-validation enforced: malformed args rejected before reaching upstream.

### 3.3 Feature 3 — Call monitoring (telemetry)

Every tool call passing through the gateway is captured as a structured audit event and forwarded to Vyuu mgmt plane via a durable async pipeline (Kafka or NATS, never blocking the hot path).

**Audit event schema (shared with Vyuu agent):**

```json
{
  "event_id": "uuid",
  "timestamp": "iso8601",
  "tenant_id": "uuid",
  "source_pep": "gateway",
  "gateway_instance_id": "string",
  "principal": {
    "type": "endpoint_session | server_agent | api_key",
    "id": "string",
    "display": "string"
  },
  "vserver_id": "uuid",
  "upstream_server_id": "uuid",
  "tool": "string",
  "args_summary": { "...": "redacted-or-sampled" },
  "decision": "allow | deny | redact | rewrite",
  "decision_mode": "monitor | enforce",
  "policy_id": "uuid",
  "policy_rule_id": "string",
  "latency_ms_total": "number",
  "latency_ms_upstream": "number",
  "upstream_status": "ok | error | timeout",
  "response_size_bytes": "number",
  "client_metadata": {
    "agent_type": "claude_desktop | cursor | langgraph | custom",
    "client_version": "string",
    "user_agent": "string"
  }
}
```

**Client identity.** The gateway captures whatever client metadata it can observe: user-agent, session metadata, optional client-supplied identity headers. Real identity assertion is mgmt plane's responsibility (v1 uses tenant-scoped API keys; v2 adds OAuth/OIDC). The gateway records what it sees, mgmt plane reconciles.

**Args summary.** Full args may contain PII or secrets. Gateway records a summary (top-level keys, type, size) by default; full args captured only when policy explicitly opts in. Redaction rules (regex / pattern) applied before storage.

**Acceptance criteria:**

- 100 percent of tool calls emit audit events. No silent drops.
- Audit pipeline is non-blocking: gateway hot path latency < 5ms p99 from policy decision to response forwarding, regardless of audit pipeline backpressure.
- On audit pipeline failure, events buffer locally (disk-backed queue) and replay on recovery. Buffer size and retention configurable.
- Audit events visible in Vyuu mgmt plane within 30 seconds p95.

### 3.4 Feature 4 — MCP transport support and customer servers

**Transport support.** The gateway must speak all three current MCP transports as both inbound (gateway-as-server, accepting client connections) and outbound (gateway-as-client, talking to upstream MCP servers):

- `stdio` — for npm-published and stdio-command upstreams; rarely used inbound (only for testing or local agent use).
- `sse` — legacy; supported for compatibility with older MCP clients.
- `streamable_http` — current spec; primary inbound transport for production.

The gateway uses the official MCP Python SDK for transport implementation rather than rolling its own. This is non-negotiable: reimplementing the MCP transport layer is multi-week work that the SDK provides for free, and rolling our own creates subtle interop bugs with real-world clients.

**Customer-supplied MCP servers, v1.** Customers register their own MCP servers as URL-MCP-servers; they self-host in their own infra. The gateway routes through, applies policies, captures telemetry. No gateway-side hosting in v1 — this dodges the security risk of running arbitrary customer code on shared gateway infrastructure.

**Customer-supplied MCP servers, v2.** Gateway-side hosting added in v2 with strong sandboxing. Customers upload a container image or npm package; gateway runs it in an isolated runtime with resource limits. Defer until customer demand justifies the operational complexity.

**Acceptance criteria:**

- Gateway interoperates as inbound server with: Claude Desktop, Cursor, Cline, Continue, custom Python/Node MCP clients using official SDKs.
- Gateway interoperates as outbound client with: all major published MCP servers in `@modelcontextprotocol/*`, `@chkp/*`, popular community servers (excalidraw, etc.).
- Transport mismatch handled cleanly: client connects via Streamable HTTP, upstream is stdio — gateway bridges transparently.
- MCP version negotiation surfaces clearly in errors when client / upstream versions are incompatible.

### 3.5 Feature 5 — Scale and performance

**Design target.** 10,000 simultaneously active endpoint sessions per logical gateway deployment. "Active" means having an open MCP session and emitting tool calls. Steady-state assumption: average 2 tool calls per minute per active endpoint, peak 10x = 20 calls per minute per endpoint during burst.

At target load:
- Steady state: ~333 tool calls/second across the deployment.
- Peak: ~3,300 tool calls/second.

**Architecture for scale:**

- Gateway is horizontally scalable. 3-5 instances behind a load balancer at target load.
- Sessions held in shared Redis (cluster), not in-process. Any gateway instance can serve any session.
- Postgres primary + read replicas for catalog and config queries; audit writes go to Kafka, not Postgres directly.
- Connection pool to upstream MCP servers shared across gateway instances within a deployment, with health-checked pool entries and circuit breakers per upstream.
- Capability sync workers run as separate processes from request-handling gateway instances; sync work cannot starve hot path.

**Per-instance performance targets:**

| Metric | Target |
|---|---|
| Hot path latency (gateway-introduced) p50 | < 2ms |
| Hot path latency (gateway-introduced) p99 | < 10ms |
| Concurrent sessions per instance | 2,500 |
| Tool calls per second per instance | 1,500 sustained |
| Memory per instance | < 4 GB at target load |
| Cold start to ready | < 10 seconds |

"Gateway-introduced latency" excludes upstream MCP server time. The gateway adds policy evaluation, routing, audit emission overhead — not upstream call time.

**Tool catalog scale.** Some MCP vendors expose hundreds of tools (e.g., GitHub MCP exposes 80+). With 100 registered servers at 50 tools each, a tenant could have 5,000 tools in catalog. `tools/list` calls must paginate (MCP spec supports pagination); virtual servers operate on tool subsets so client-visible catalogs stay manageable.

**Capability sync at scale.** With 1,000 registered servers across all tenants on a deployment, syncing every 15 minutes means ~67 syncs/minute. Sync workers must be parallelized; backoff on upstream errors; staggered scheduling to avoid thundering-herd against shared upstream services.

**Acceptance criteria:**

- Load test: 10,000 simulated endpoints, 333 calls/sec sustained for 1 hour. p99 latency stays under target. No errors, no audit event drops.
- Burst test: Ramp to 3,300 calls/sec over 30 seconds, sustain for 2 minutes. p99 latency stays under target after a brief warm-up period.
- Failure test: Kill one of three gateway instances during sustained load. Sessions migrate cleanly via Redis, no client disconnects, p99 latency degrades gracefully.

### 3.6 Feature 6 — A2A agent catalog

The A2A (Agent-to-Agent) catalog is a registry of agents — their cards, capabilities, endpoints, and discovery metadata — exposed to clients via a Vyuu-defined catalog API. v1 is catalog-only: gateway does not yet sit in the A2A traffic path. Runtime A2A interception is v2.

An A2A agent in this catalog is identified by:

| Field | Type | Notes |
|---|---|---|
| `agent_id` | uuid | Gateway-assigned |
| `tenant_id` | uuid | Multi-tenant scope |
| `name` | string | Human-readable |
| `description` | text | What the agent does |
| `endpoint_url` | string | A2A-compatible endpoint (HTTP) |
| `protocol_version` | string | A2A spec version |
| `capabilities` | jsonb | Agent capability descriptors |
| `card` | jsonb | Full A2A agent card |
| `owner_principal` | uuid | Who registered it |
| `discoverability` | enum | `public_in_tenant` \| `private` \| `cross_tenant_shared` |

**Catalog API (v1):** Read-only discovery surface for agents to find each other. Endpoints:

- `GET /a2a/catalog/agents?tenant_id=X` — list all discoverable agents in tenant
- `GET /a2a/catalog/agents/{agent_id}` — fetch full agent card
- `GET /a2a/catalog/search?q=...` — semantic or keyword search across catalog

**Acceptance criteria:**

- Catalog supports 1,000+ agents per tenant without query degradation.
- Search returns results within 200ms p95 for catalogs up to 10,000 entries (use Postgres full-text or pgvector for v1; opensearch if scaling further).
- Agent registration validates the supplied card against the A2A spec; malformed cards rejected.
- Catalog reads do not require authentication beyond tenant API key (v1); v2 adds per-agent ACLs.

### 3.7 Feature 7 — Independent gateway dashboard

The gateway has its own operator-facing dashboard, distinct from the Vyuu mgmt plane customer dashboard. The two serve different audiences:

- **Vyuu mgmt plane dashboard.** Customer-facing. Shows AI usage, policies, audit events, MCP inventory, agent catalog. Owned by the customer's security team or AI security operator.
- **Gateway dashboard.** Operator-facing. Shows gateway health, throughput, upstream connectivity, error rates, capacity utilization, deployment topology. Owned by the gateway operator (Vyuu SRE for SaaS, customer SRE for on-prem).

**Sections of the gateway dashboard:**

- **Overview.** Per-instance health, total throughput, error rate, p50/p99 latency.
- **Upstream servers.** Per-server status, throughput, error rate, capability sync lag.
- **Virtual servers.** Per-vserver throughput, top tools by call volume, deny rate.
- **Tenants.** Per-tenant resource usage, request volume, top virtual servers.
- **Capacity.** Active sessions, connection pool utilization, Redis hit rate, Kafka lag.
- **Audit pipeline.** Events emitted, lag to mgmt plane, buffer state, recent failures.
- **Configuration.** Runtime config, deployed version, rollback options.

**Tech stack.** React + TypeScript + Recharts. Dashboard reads from gateway's metrics endpoint (Prometheus-compatible) and the gateway's own admin API; does not call Vyuu mgmt plane.

**Acceptance criteria:**

- Dashboard loads within 2 seconds for 100-tenant, 10k-endpoint deployments.
- All charts auto-refresh on a configurable interval (default 30s).
- Operators can drill down from any chart to underlying audit events or logs.
- Dashboard is accessible via a separate URL from the customer-facing Vyuu dashboard.
- RBAC: gateway operator role distinct from customer roles in mgmt plane.

---

## 4. Non-functional requirements

### 4.1 Security

- Threat model the gateway as a privileged proxy. Compromise grants attacker access to every customer's upstream MCP servers and audit data.
- All inter-component traffic uses mTLS (gateway ↔ upstream, gateway ↔ Redis, gateway ↔ Postgres, gateway ↔ Kafka).
- Secrets (env vars, API keys, Vault tokens) never in gateway image; injected at runtime via Vault Agent or Kubernetes secret references.
- Container images built from minimal base (distroless or chainguard), scanned in CI, signed via cosign.
- Input validation hard requirements: catastrophic-backtracking-aware regex, JSON schema strict validation, payload size limits per virtual server.
- The gateway must pass an external pen test before GA.

### 4.2 Multi-tenant isolation

- `tenant_id` is a non-null required column on every operational table.
- Postgres row-level security (RLS) enforced for all tenant-scoped tables; gateway connections set `app.current_tenant_id` on session.
- Connection pool entries to upstream servers are tenant-scoped — no shared upstream connections across tenants.
- Per-tenant rate limits and quotas configurable.
- Audit events tagged with `tenant_id`; mgmt plane enforces tenant-scoped read access.

### 4.3 Observability

- Structured JSON logs (one event per line) emitted to stdout; aggregator (Vector, Fluent Bit) ships to operator's log store.
- OpenTelemetry tracing on every tool call: span hierarchy = `client → gateway → policy_eval → upstream`.
- Prometheus metrics with discipline: bound cardinality (tenant, vserver, upstream — never `tool_name` or `principal_id` as labels).
- Gateway-emitted operational metrics distinct from audit events. Metrics for SRE; audit for security.

### 4.4 Deployment

- Helm chart packaged for v1, supporting both SaaS and on-prem.
- Air-gapped install supported: pre-pulled images, offline Helm chart, no calls to internet during install.
- Stateless gateway instances: any instance can serve any request (state in Redis + Postgres + Kafka).
- Rolling upgrade with zero downtime: instances drain sessions before terminating.
- Blue/green or canary deployment supported via mgmt plane.

### 4.5 Reliability

- Per-instance crash recovery: < 30 seconds to redirect sessions to a healthy peer.
- Upstream circuit breakers prevent cascading failures: one bad MCP server doesn't take down the gateway.
- Graceful degradation: if Redis unavailable, sessions degrade to per-instance only (no migration); if Kafka unavailable, audit buffers to disk; if Postgres unavailable, gateway serves cached config for up to 30 minutes.

---

## 5. Architecture

### 5.1 Component view

```
                   [Vyuu mgmt plane]
                  ↑↓ policy + telemetry
   ┌──────────────────────────────────────────┐
   │  Gateway instance (one of N)             │
   │  ┌────────────────────────────────────┐  │
   │  │  Inbound MCP endpoint              │  │
   │  │  (Streamable HTTP, SSE, stdio)     │  │
   │  └─────────────────┬──────────────────┘  │
   │                    ↓                      │
   │  ┌────────────────────────────────────┐  │
   │  │  Session manager (Redis-backed)    │  │
   │  └─────────────────┬──────────────────┘  │
   │                    ↓                      │
   │  ┌────────────────────────────────────┐  │
   │  │  Policy enforcement (PEP)          │  │
   │  │  Reused engine from Vyuu agent     │  │
   │  └─────────────────┬──────────────────┘  │
   │                    ↓                      │
   │  ┌────────────────────────────────────┐  │
   │  │  Virtual server resolver           │  │
   │  └─────────────────┬──────────────────┘  │
   │                    ↓                      │
   │  ┌────────────────────────────────────┐  │
   │  │  Upstream connection pool          │  │
   │  └─────────────────┬──────────────────┘  │
   │                    ↓                      │
   │  ┌────────────────────────────────────┐  │
   │  │  Audit emitter (Kafka producer)    │  │
   │  └────────────────────────────────────┘  │
   └────────────────────┬─────────────────────┘
                        ↓
        ┌───────────────┴───────────────┐
        ↓                               ↓
[Upstream MCP servers]            [A2A registered agents]
(npm, http, stdio)                (HTTP A2A endpoints)

Sidecars per gateway deployment:
  - Postgres (catalog, config, audit metadata)
  - Redis cluster (sessions, rate limits, capability cache)
  - Kafka (audit pipeline)
  - Container runtime (gVisor/runc) for npm/stdio MCP servers
```

### 5.2 Request lifecycle

A tool call from a client through to upstream:

1. **Client connects.** MCP `initialize` against `https://gateway/v/<tenant>/<vserver>/mcp`. Session created in Redis with TTL.
2. **Capability response.** Gateway resolves `<vserver>` to its tool bundle, returns synthesized `tools/list` (intersection of vserver's allowlist and current capability snapshot).
3. **Tool call arrives.** `tools/call { name, args }`.
4. **Session lookup.** Gateway resolves principal from session; loads policy reference for the vserver.
5. **Policy evaluation.** PEP runs: tool allowlist, schema validation, arg patterns. Decision recorded.
6. **If denied.** Return MCP error to client. Audit event emitted with `decision=deny`. Stop.
7. **If allowed.** Resolve `(vserver, tool)` to `(upstream_server, original_tool_name)`. Pull connection from pool (or open new if needed).
8. **Forward call.** `tools/call` to upstream with original tool name. Await response.
9. **Response policy.** Apply response inspection (PII redaction, secret scrubbing). Record decision.
10. **Return to client.** Audit event emitted with full lifecycle data. Pipeline is non-blocking.

End-to-end latency budget: 10ms gateway-introduced + upstream call time. Under target load, gateway introduces 2-5ms typical.

### 5.3 Multi-tenancy model

Single gateway deployment serves multiple tenants. Tenants isolated at:

- **Data layer.** Postgres RLS keyed on `tenant_id`. Redis namespaced per tenant.
- **Network layer.** Upstream connections are per-tenant — no cross-tenant connection sharing. For npm/stdio servers, separate container instance per tenant.
- **Compute layer.** Per-tenant rate limits and quotas. Noisy-neighbor mitigation via fair queueing in scheduler.

Dedicated-tenancy deployments run a single tenant per gateway deployment; the same code paths apply with `tenant_id` always equal to a known constant. No special code paths.

### 5.4 Deployment topology

For SaaS shared-tenancy:

- 3-5 gateway instances behind a load balancer, autoscaled on CPU/memory.
- Postgres primary + 2 read replicas (managed RDS or equivalent).
- Redis cluster: 3 primaries + 3 replicas.
- Kafka: 3-broker cluster, audit topic with 30-day retention.
- Container runtime: dedicated node pool with gVisor for shared-tenancy isolation.

For on-prem dedicated-tenancy:

- 1-3 gateway instances depending on customer scale.
- Postgres single instance acceptable (customer-managed).
- Redis single instance acceptable.
- Kafka optional — file-based audit buffer with mgmt-plane pull acceptable for smaller deployments.
- Container runtime: runc + seccomp + AppArmor (gVisor optional).

---

## 6. Data model

Postgres schema. Selected tables; not exhaustive.

```sql
-- Tenants and operators
CREATE TABLE tenants (
  id            uuid PRIMARY KEY,
  name          text NOT NULL,
  tier          text NOT NULL,  -- 'shared' | 'dedicated'
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE operators (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id),
  email         text NOT NULL,
  role          text NOT NULL,  -- 'admin' | 'editor' | 'viewer'
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- MCP server registry
CREATE TABLE mcp_servers (
  id                          uuid PRIMARY KEY,
  tenant_id                   uuid NOT NULL REFERENCES tenants(id),
  display_name                text NOT NULL,
  source_type                 text NOT NULL,  -- 'npm' | 'http' | 'stdio'
  source_location             text NOT NULL,
  transport                   text NOT NULL,  -- 'stdio' | 'sse' | 'streamable_http'
  env_vars_ref                text,
  args                        text[],
  registered_by               uuid NOT NULL REFERENCES operators(id),
  registered_at               timestamptz NOT NULL DEFAULT now(),
  health_status               text NOT NULL DEFAULT 'unknown',
  last_capabilities_pulled_at timestamptz,
  CONSTRAINT mcp_servers_tenant_name_uq UNIQUE (tenant_id, display_name)
);

-- Capability snapshots
CREATE TABLE mcp_capabilities (
  id            uuid PRIMARY KEY,
  server_id     uuid NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
  kind          text NOT NULL,  -- 'tool' | 'resource' | 'prompt'
  name          text NOT NULL,
  schema_json   jsonb NOT NULL,
  observed_at   timestamptz NOT NULL DEFAULT now(),
  deprecated    boolean NOT NULL DEFAULT false
);

CREATE INDEX mcp_capabilities_server_kind_idx ON mcp_capabilities (server_id, kind);

-- Virtual servers
CREATE TABLE virtual_servers (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id),
  name          text NOT NULL,
  policy_id     uuid,  -- references mgmt plane policy
  rename_map    jsonb,  -- { "original_tool_name": "exposed_tool_name" }
  created_by    uuid NOT NULL REFERENCES operators(id),
  created_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT virtual_servers_tenant_name_uq UNIQUE (tenant_id, name)
);

CREATE TABLE virtual_server_tools (
  vserver_id    uuid NOT NULL REFERENCES virtual_servers(id) ON DELETE CASCADE,
  server_id     uuid NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
  tool_name     text NOT NULL,
  PRIMARY KEY (vserver_id, server_id, tool_name)
);

-- A2A agent catalog
CREATE TABLE a2a_agents (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL REFERENCES tenants(id),
  name              text NOT NULL,
  description       text,
  endpoint_url      text NOT NULL,
  protocol_version  text NOT NULL,
  capabilities      jsonb,
  card              jsonb NOT NULL,
  owner_principal   uuid NOT NULL REFERENCES operators(id),
  discoverability   text NOT NULL DEFAULT 'public_in_tenant',
  registered_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX a2a_agents_tenant_idx ON a2a_agents (tenant_id);
CREATE INDEX a2a_agents_card_gin ON a2a_agents USING GIN (card);

-- Audit metadata (full events go to Kafka; this table stores recent metadata for dashboard queries)
CREATE TABLE audit_metadata (
  event_id          uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL,
  vserver_id        uuid,
  upstream_server_id uuid,
  tool              text,
  decision          text NOT NULL,
  decision_mode     text NOT NULL,
  latency_ms_total  int,
  upstream_status   text,
  observed_at       timestamptz NOT NULL DEFAULT now()
) PARTITION BY RANGE (observed_at);

-- Partition per day, keep 30 days local; full history in Kafka/object storage
```

Row-level security policies enabled on every tenant-scoped table:

```sql
ALTER TABLE mcp_servers ENABLE ROW LEVEL SECURITY;
CREATE POLICY mcp_servers_tenant_isolation ON mcp_servers
  USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
```

---

## 7. API surface

### 7.1 Admin API (operator-facing)

REST + JSON, auth via tenant-scoped API key in `Authorization: Bearer <key>`.

Server registration:
- `POST /api/v1/servers` — register a new MCP server
- `GET /api/v1/servers` — list registered servers in tenant
- `GET /api/v1/servers/{id}` — fetch one
- `PATCH /api/v1/servers/{id}` — update env vars, args, etc.
- `DELETE /api/v1/servers/{id}` — deregister
- `POST /api/v1/servers/{id}/sync` — force capability re-sync

Virtual server management:
- `POST /api/v1/vservers` — create
- `GET /api/v1/vservers` — list
- `GET /api/v1/vservers/{id}` — fetch
- `PATCH /api/v1/vservers/{id}` — update tool bundle, policy, rename map
- `DELETE /api/v1/vservers/{id}` — delete

A2A catalog:
- `POST /api/v1/agents` — register agent
- `GET /api/v1/agents` — list
- `GET /api/v1/agents/{id}` — fetch
- `GET /api/v1/agents/search?q=...` — search

Health and metrics:
- `GET /api/v1/health` — gateway instance health
- `GET /api/v1/metrics` — Prometheus exposition format

### 7.2 MCP gateway endpoints (client-facing)

For each virtual server, the gateway exposes:

- `POST /v/{tenant_slug}/{vserver_name}/mcp` — Streamable HTTP MCP endpoint
- `GET /v/{tenant_slug}/{vserver_name}/sse` — SSE legacy endpoint
- (stdio bridge available for testing only, not exposed in production)

These endpoints implement the full MCP protocol surface. Clients connect as if to a single MCP server.

### 7.3 Telemetry contract with Vyuu mgmt plane

Audit events flow through Kafka topic `vyuu.audit.events.v1`. Schema versioned via header. Mgmt plane is the canonical consumer. Other consumers (SIEM bridges, customer-side log shippers) can subscribe via Kafka Connect or topic mirroring.

Policy fetch: gateway pulls policies via `GET <mgmt_plane>/api/v1/policies?tenant_id=X` every 60 seconds; cached in-memory with last-known-good fallback.

Discovery push: capability drift events go to `vyuu.discovery.events.v1` topic.

---

## 8. Build vs. fork analysis

Two viable approaches: build the gateway from scratch, or fork IBM ContextForge and modify it to fit the requirements. Both can deliver the v1 feature set. The decision rests on engineering velocity, codebase ownership, and architectural fit.

### 8.1 What ContextForge gives

ContextForge (apache 2.0, IBM-backed) covers approximately 50-60 percent of the v1 plumbing:

| Feature | ContextForge coverage |
|---|---|
| MCP server registration (npm, http, stdio) | Yes, mature |
| Virtual servers / virtual gateways | Yes, called "virtual gateways" in their terminology |
| Multi-transport bridging | Yes |
| Federation (gateway-of-gateways) | Yes — beyond our v1 needs |
| Basic admin UI | Yes |
| A2A catalog | Recently added; depth uncertain, needs audit |
| Multi-tenancy | Limited |
| 10k-endpoint scale tuning | Unknown — needs load testing |
| Vyuu policy engine integration | No — would need replacement of their policy approach |
| Vyuu mgmt plane telemetry contract | No |
| Independent gateway dashboard with our visual language | No |
| On-prem air-gapped deployment with our packaging | Partial |

### 8.2 What's left to build either way

Regardless of approach, the following work is required:

- Vyuu policy engine port from the agent codebase and integration into request hot path.
- Vyuu mgmt plane integration: policy pull, audit event emission, capability drift events.
- Gateway dashboard (React + Recharts).
- Multi-tenancy hardening: RLS, per-tenant connection pooling, rate limits.
- Scale testing and tuning to 10k endpoints.
- Helm chart with our deployment model (air-gappable, on-prem-first).
- Pen test and security review.

Estimated work above: 5-6 engineer-weeks regardless of approach.

### 8.3 Effort comparison

**Fork approach:**

| Workstream | Weeks |
|---|---|
| Fork ContextForge, audit codebase, ramp engineers | 1.5 |
| Adapt server registry to our schema | 1 |
| Adapt virtual server model | 0.5 |
| Replace ContextForge's policy approach with Vyuu engine | 1.5 |
| Audit and harden A2A catalog | 1 |
| Mgmt plane integration | 1 |
| Dashboard (greenfield) | 2 |
| Multi-tenancy hardening | 1.5 |
| Scale tuning | 1.5 |
| Helm + deployment | 1 |
| Pen test fixes | 0.5 |
| Buffer / unknowns | 1 |
| **Total** | **~14 weeks** |

**Groundup approach:**

| Workstream | Weeks |
|---|---|
| MCP transport via official Python SDK | 2 |
| Server registry + capability sync | 2 |
| Virtual server resolver | 1.5 |
| Vyuu policy engine port | 1 |
| A2A catalog (greenfield) | 1.5 |
| Mgmt plane integration | 1 |
| Audit pipeline (Kafka producer + buffer) | 1 |
| Dashboard | 2 |
| Multi-tenancy | 1.5 |
| Scale tuning | 1.5 |
| Helm + deployment | 1 |
| Pen test fixes | 0.5 |
| Buffer / unknowns | 1 |
| **Total** | **~17 weeks** |

The fork is roughly 3 weeks faster on paper. In practice, the gap is smaller than this suggests, because:

- ContextForge's policy model and ours are different. Replacing rather than adapting takes engineer effort that doesn't show up cleanly in line-item estimates.
- Forked codebase carries IBM's design choices into ours forever. Every future architectural decision begins with "what does ContextForge already do here?" — a tax that compounds.
- Engineers ramping on ContextForge spend time learning a foreign codebase rather than building intuition for ours.
- Scale to 10k endpoints requires architectural decisions we control end-to-end. A fork inherits whatever ContextForge already chose, and changing those choices means rewriting in the foreign codebase.

### 8.4 Strategic considerations

**Codebase ownership.** Groundup gives clean IP and full control. A fork is technically apache 2.0 (compatible with our commercial use), but the codebase mental model is half ours, half IBM's.

**A2A coverage.** ContextForge's A2A support is recent. If it's mature enough to use as-is, fork wins on this dimension. If it's incomplete, we're rewriting it anyway. Audit ContextForge A2A code before deciding.

**Maintenance posture.** A fork either stays synced with upstream (complex, eventual divergence pain) or stops syncing and becomes our codebase with foreign provenance. The honest path is the latter.

**Architectural fit.** Our two-PEP architecture is differentiated. ContextForge is a single PEP. Adapting it to be the gateway side of a two-PEP product means treating it as data plane only and ripping out its admin/policy ambitions. Significant work, and the result is a heavily modified ContextForge that no longer benefits from upstream improvements.

### 8.5 Recommendation

**Build groundup.** The 3-week premium is worth it for:

- Clean codebase ownership and architectural control.
- A policy engine ported directly from the Vyuu agent, with shared abstractions designed for portability rather than retrofitted.
- A scale architecture designed for 10k endpoints from day 1, not bolted onto ContextForge's existing one.
- No ongoing tax of foreign codebase mental model.

**Treat ContextForge as a reference architecture.** Read their code, learn from their decisions, lift specific algorithms (capability sync logic, virtual server name collision handling) where their approach is clearly good. Cite as inspiration, not provenance.

**One condition.** Groundup works only if the Vyuu agent's policy engine is actually portable to a server-side environment. If during agent v1 development it becomes clear the policy code is too coupled to local OS APIs to extract cleanly, revisit this decision. Build the agent's policy abstraction with portability as a hard architectural constraint from now.

---

## 9. Implementation roadmap

The roadmap is sequenced around dependency rather than calendar weeks, since exact engineering bandwidth is TBD.

**Phase 0 — Foundations (parallel to agent v1 work).**
- Lock policy engine abstraction in Vyuu agent codebase. Engine must compile/run server-side, not just on endpoint OSes.
- Lock audit event schema between agent and gateway.
- Stand up Postgres + Redis + Kafka in dev environment.

**Phase 1 — Core data plane (target 8 weeks).**
- MCP transport (Python SDK integration), inbound and outbound.
- Server registry: registration, capability sync worker.
- Virtual server resolver.
- Connection pool to upstream servers.
- Policy enforcement in hot path (using ported engine).
- Audit emission to Kafka.
- Mgmt plane integration: policy pull, audit push, discovery events.

**Phase 2 — Operator surface (target 4 weeks, parallelizable with late Phase 1).**
- Admin API.
- Gateway dashboard (React + Recharts).
- A2A catalog API.

**Phase 3 — Production hardening (target 4 weeks).**
- Multi-tenancy: RLS, per-tenant pools, rate limits.
- Scale testing and tuning.
- Helm chart, on-prem packaging.
- Pen test and remediation.
- Documentation: operator guide, customer guide, troubleshooting runbook.

**Phase 4 — GA prep (target 1-2 weeks).**
- Beta with 2-3 design partners.
- Final fixes from beta feedback.
- GA release.

Total target: 17-19 weeks from Phase 1 start to GA. Phase 0 happens before Phase 1 starts and is gated on agent v1 maturity.

---

## 10. Open questions

These need resolution before or during Phase 0. They are flagged here for explicit owner assignment.

1. **Policy engine portability.** Is the Vyuu agent's policy engine actually portable to server-side without major rework? Owner: agent lead engineer. Resolution by end of agent v1 sprint 4.

2. **A2A scope in v1.** Is catalog-only sufficient, or does an early customer require runtime A2A enforcement? Owner: product. Resolution before Phase 1 kickoff.

3. **10k-endpoint customer.** Is this a real near-term customer requirement or a design target? If real, who and on what timeline? Owner: GTM. Resolution drives whether scale tuning is Phase 1 or Phase 3.

4. **ContextForge A2A audit.** Does ContextForge's A2A implementation cover what we need, or is it skeletal? Owner: lead engineer. Resolution before final build vs. fork sign-off.

5. **Mgmt plane API contract version.** Vyuu mgmt plane API is evolving. Lock the v1 contract for gateway integration. Owner: mgmt plane lead. Resolution before Phase 1 kickoff.

6. **On-prem air-gap requirements.** Specific customer requirements (BFSI compliance) drive the deployment model. What exactly must be air-gappable? Owner: GTM + lead architect. Resolution before Phase 3.

7. **Container runtime for npm/stdio servers.** gVisor for shared-tenancy, runc for dedicated. Confirm both work in target customer environments (some on-prem k8s setups do not support gVisor). Owner: SRE. Resolution before Phase 3.

---

## 11. Appendix

### 11.1 Glossary

- **PEP** — Policy Enforcement Point. The component that intercepts a call and decides allow/deny.
- **PDP** — Policy Decision Point. The component that evaluates policy. In this product, PEP and PDP are co-located.
- **Virtual server** — A composed view of tools drawn from one or more registered MCP servers, exposed as a new MCP endpoint.
- **A2A** — Agent-to-Agent. Protocol for inter-agent communication, distinct from MCP (which is agent-to-tool).
- **Capability sync** — Periodic refresh of `tools/list`, `resources/list`, `prompts/list` from upstream MCP servers.
- **Capability drift** — A change in upstream tool catalog between syncs (tool added, removed, or schema changed).

### 11.2 References

- MCP specification: https://spec.modelcontextprotocol.io
- A2A specification: https://google.github.io/A2A
- ContextForge: https://github.com/IBM/mcp-context-forge
- Vyuu agent spec: (internal — see AI Shield Phase 1 spec bundle)
- Vyuu mgmt plane API: (internal — see mgmt plane spec)

---

**End of document.**
