# Vyuu MCP Gateway — Platform overview

**Document scope.** Everything that exists in the codebase today, why
it exists, how the pieces fit together, what's intentionally NOT in,
and what the open backlog looks like. Read this first if you've just
inherited the project.

**Last revision:** 2026-05-02 (Tier-1 + Tier-2 stress-test fixes +
persistent stdio pool + measured production-readiness numbers + perf
observability harness + auto-sync on registration + deployment
manifests + audit storage cap + payload-size limits + 401-driven
OAuth refresh + multi-worker validation + audit consumer wiring).

---

## 0. Production readiness — measured (TL;DR for execs / investors)

This section is the bottom-line "what's shipped, what's measured" view.
For the deep technical content, sections 1-8 below are unchanged from
the engineering handoff.

### What the gateway is, in one sentence

A multi-tenant policy-enforcing audit-emitting reverse proxy for the
Model Context Protocol — sits between AI agents (Cursor, Claude
Desktop, autonomous agents) and the upstream MCP servers that hold
real capabilities (GitHub, CrowdStrike, Notion, Drive, internal tools),
brokering identity, authorization, secret resolution, observability,
and per-tenant rate control.

### Why it exists (the problem we solve)

- **Today's reality:** every AI tool ships with its own MCP server.
  Each requires per-user OAuth credentials in plaintext on the
  developer's laptop. Each has its own auth model, its own
  rate-limit shape, its own audit fidelity. Security teams have no
  single chokepoint for governing AI tool usage. CISOs cannot
  answer "which devs can call which tools on which upstreams with
  what data?"
- **What changes with the gateway:** one bearer token per end-user
  authenticates to the gateway itself. Upstream credentials live in
  a KMS-backed secret store. Operators publish a curated subset of
  upstream tools as **virtual servers** with grant-based access
  control. Every tool call lands in the audit pipeline with full
  identity + decision + payload context.

### What's shipped + measured (this revision)

| Capability | State | Evidence |
|---|---|---|
| **Six outbound auth modes** (org-tier headers, user-tier passthrough, OAuth client-credentials, OAuth authorization-code, OAuth JWT-bearer, mTLS) | shipped | unit + integration tests; A1 + A2 + mTLS in HANDOFF.md |
| **401-driven OAuth refresh** (A4) | shipped | one-shot retry on phase-3/4 401, single-flight via per-token lock |
| **Per-tenant inflight gate** (fast-503 past cap, ASGI middleware outside FastAPI) | shipped | load test: 4,080 clean 503s during 128-in-flight burst, healthz green throughout |
| **Persistent stdio MCP subprocess pool** (Tier-2 perf fix) | shipped | **85× RPS uplift** (5 → 425 RPS per backing server measured); subprocess count bounded to pool size irrespective of call volume |
| **uvicorn back-pressure** (limit-concurrency / max-requests / backlog) | shipped | wired in lab + Docker + systemd + K8s manifests |
| **`/healthz` outside request pipeline** | shipped | 100% uptime during burst that previously crashed the gateway |
| **Audit storage cap** (10 MiB default, configurable; transit unaffected) | shipped | sentinel records `total_bytes` for forensic context |
| **Auto-sync capabilities on registration** | shipped | operators no longer need to remember to click Sync |
| **Per-payload size limits** (H3) | shipped | request 5 MiB / response 25 MiB caps; truncation marker; opt-in redaction |
| **DB connection pool** sized to feed inflight gate | shipped | 5+10 → 20+40, eliminates queueing-cascade failure mode |
| **Process supervisor + resource limits** (Docker / systemd / K8s) | shipped | `deploy/` manifests with healthcheck + memory cap + pids cap |
| **Audit pipeline** (NATS JetStream producer + ClickHouse consumer + DiskSpoolAuditEmitter) | shipped | producer + minimal consumer reference + chaos test (kill NATS mid-run) |
| **Capabilities-not-synced error** (replaces misleading `tool_not_in_vserver`) | shipped | unique error category in envelope; retryable=true |
| **Test-only Prometheus + Grafana perf harness** under `tests/perf/` | shipped | 14-panel dashboard, exporter sidecar, automated end-to-end stress |

### Measured throughput (real numbers, not estimates)

Single uvicorn worker on Apple M5, single CPU core (the load-test rig):

| Path | Sustained RPS | p50 | p99 |
|---|---:|---:|---:|
| Gateway hot path (deny / no upstream call) | **723 peak** | 11 ms | 87 ms |
| Stdio persistent path (real upstream tool call) | **425** | 19 ms | 95 ms |
| Sustained 60s @ 16 in-flight | **378 RPS, 22,867 calls, 0 failures** | 28 ms | 107 ms |

Multi-worker scaling validated at **3.5× for 4 workers** on the perf
harness (see stress-test report).

Stress-test crash modes that were fixed: gateway-process death under
sustained 32-in-flight burst (now: 100% uptime under 2× that load),
healthz timeout cascade during back-pressure (now: 100% probe success
during 128-in-flight + 4080 clean 503s).

### Sizing for the canonical workload — measurement-backed

For **1,000 developers × 5 IDEs each + 200 autonomous agents** (≈ 140 RPS sustained, ≈ 315 RPS burst, ≈ 158 GB/day audit volume):

| Deployment shape | Spec | Headroom (vs 315 RPS burst) |
|---|---|---|
| **Starter** (single box) | 8 vCPU / 32 GB / 1 TB NVMe | ~1.2× — works but tight |
| **Standard** (single-box appliance — recommended) | **24 vCPU / 96 GB / 6 TB NVMe** | **~5×** |
| **Production tier** (HA-required) | K8s 3 baseline → 12 HPA pods, 2 vCPU / 6 GB request per pod | ~13× at baseline |

(Full sizing detail with per-component breakdown lives in
`docs/operations/sizing.md` and `deploy/README.md`.)

### How we differentiate (for competitive comparison)

Most "MCP gateway" entrants in the 2026 market fall into one of:

| Category | Examples | What they do |
|---|---|---|
| **SaaS-only managed** | Smithery, MCP.run, MintMCP, MCP Boss, ToolRouter | host MCP servers, expose them through their cloud |
| **Local proxies** | Lasso MCP Gateway, Pomerium-MCP, mcp-proxy, MCPJungle | per-developer machines, no multi-tenant story |
| **Library tooling** | LangChain MCP adapters, Composio | inline integration kits for app builders |

Vyuu sits in a deliberately under-served slice: **server-side
multi-tenant gateway with full enforcement + audit, designed for
on-prem / private-cloud deployment in regulated industries** (financial
services, healthcare, defense, government). The shipped capabilities
that matter for that positioning:

1. **Six outbound auth modes** including OAuth JWT-bearer (RFC 7523)
   and mTLS — required for Workspace SA impersonation, IAM Roles
   Anywhere, and customer-supplied client certs.
2. **Tenant-scoped catalog + RLS-backed isolation** — multiple
   customer tenants on a single appliance with policy-enforced
   isolation via Postgres row-level security, not application-layer
   filters.
3. **Audit pipeline that scales independently** — NATS JetStream
   producer + ClickHouse warehouse consumer, with disk-spool fallback
   for backpressure. Enterprise audit retention (90+ days) at >150 RPS
   sustained without breaking the gateway.
4. **Persistent stdio subprocess pool** — most competitors cold-spawn
   per call (~5 RPS ceiling per upstream); we measured 85× uplift.
5. **Per-tenant fast-fail rate limiting** — at the ASGI layer, with
   structured Vyuu error envelope; one tenant's runaway agent cannot
   starve another tenant on the same gateway pod.
6. **Six identity model** for the data plane: end users (`users`),
   operators (`operators`), API keys (`user_api_keys`),
   server agents (autonomous), endpoint sessions (header-driven for
   prototyping), OAuth tokens (`oauth_user_tokens`). NHI dashboard +
   relation graph + bipartite map all read off this.

---

---

## 1. What is the Vyuu MCP Gateway?

A server-side enforcement, routing, audit, and observability layer for
**Model Context Protocol (MCP) servers**. It sits between AI agents
(Claude Desktop, Cursor, custom agents) and the upstream MCP servers
that hold real capabilities (PayPal, Wiz, Snyk, Datadog, Drive,
internal tools, etc.).

Without the gateway, every agent has to be configured per-MCP-server,
per-user, with each MCP's auth credentials in plaintext on the user's
laptop. With the gateway:

- **One bearer token** per end-user authenticates to the gateway
  itself. The gateway holds upstream credentials in a real
  KMS-backed secret store.
- **Tenant-scoped catalog**: operators register MCPs once;
  end-users see only what they're entitled to.
- **Per-tool allowlists** via virtual servers: the gateway publishes
  a curated subset of an upstream's tools.
- **Grant-based access**: private virtual servers require explicit
  per-user or per-group grants.
- **Full audit trail**: every tool call + every connection-level
  rejection lands in the audit pipeline. The audit stream feeds the
  in-process **NHI dashboard** (per-identity activity), the **NHI
  relation graph** (principal → vserver → tool → upstream), and the
  **NHI map** (4-column "People & AI — who uses what" bipartite).
- **Six outbound auth modes**: org-tier headers, user-tier passthrough,
  OAuth client-credentials (M2M), OAuth authorization-code (per-user
  delegated, "Connect to GitHub / Drive / Notion"), OAuth JWT-bearer
  (RFC 7523 — Workspace SAs, IAM Roles Anywhere), plus transport-layer
  mTLS (cert + key SecretStore refs).

The gateway is an MCP server itself — agents speak the standard MCP
protocol to it (Streamable HTTP, the modern transport). The gateway's
job is to authenticate the caller, resolve which upstream MCP holds
the tool, enforce policy, broker outbound auth, call the upstream,
emit audit events, and return the result.

---

## 2. Architecture at a glance

```
                          ┌────────────────────────────────────────┐
                          │             Vyuu MCP Gateway           │
                          │                                        │
   Claude Desktop ───┐    │  /v/{tenant}/{vserver}/mcp             │
   Cursor ───────────┼──► │    │                                   │
   AIShield Agent ───┘    │    ├─ identity provider                │
                          │    │   (api_key / fake)                │
                          │    │                                   │
                          │    ├─ vserver resolver (tenant +       │
                          │    │   visibility + grants)            │
                          │    │                                   │
                          │    ├─ policy provider                  │
                          │    │   (simple / management_plane)     │
                          │    │                                   │
                          │    ├─ tool-call lifecycle              │
                          │    │   (audit + graph events)          │
                          │    │                                   │
                          │    └─ upstream-client provider         │
                          │        (httpx pool + circuit breakers) │
                          │           │                            │
                          └───────────┼────────────────────────────┘
                                      │
                                      ▼
                          ┌────────────────────────────┐
                          │     Upstream MCPs          │
                          │  drawio, PayPal, Wiz,      │
                          │  Snyk, Datadog, custom…    │
                          └────────────────────────────┘
                                      ▲
                                      │
   ┌────────────────────────┐    ┌──────┴────────┐    ┌────────────────────┐
   │ Postgres (catalog,     │    │ SecretStore   │    │ Kafka / NATS       │
   │ users, grants, audit   │    │ (Vault / AWS  │    │ (durable audit +   │
   │ schema, RLS-bound)     │    │ Secrets Mgr)  │    │  NHI graph events) │
   └────────────────────────┘    └───────────────┘    └────────────────────┘
```

Two operator-facing UIs sit alongside the API:

- **`/operator`** — admin console. Surfaces (in vertical order):
  brand chrome (`MCP SECURITY · Govern every tool call` lockup);
  **Dashboard** KPI grid (NHIs, sanctioned MCPs, MCPs in use,
  pending requests, high-risk calls 24h, denied/errored 24h, OAuth-
  connected SaaS reach); **NHI map** (4-column "People & AI — who
  uses what" bipartite SVG); gateway health + registered servers;
  registration form; vservers + access requests; **Users** (roster
  with admin drill-in: per-user activity + risk score + admin-revoke
  API keys); groups; admins; secret-store status; **Identities**
  (per-principal aggregation with timeline drill-in + radial-
  concentric dependency graph + summary expander); events.
- **`/portal`** — end-user portal: catalog, "My requests", API keys,
  **Connections** (OAuth-authcode-linked SaaS accounts with
  Disconnect), settings.

Both are vanilla HTML / CSS / JS (no React build) shipped as Python
string constants — works under a strict CSP, single-deployment
artefact, fast to iterate on. Brand-aligned via the Vyuu Design
System tokens (cream + ink + saffron-orange palette, Fraunces /
Inter / JetBrains Mono type, 1px lines instead of shadows).

---

## 3. Capabilities by domain

### 3.1 Identity & authentication

#### End-user identity (`users` table)

| Auth method | How a user proves identity | Where the secret lives |
|---|---|---|
| **`local`** | bcrypt password (>= 12 chars) on first sign-in via `/portal` | `users.password_hash` |
| **`microsoft`** | Microsoft Entra ID OIDC (per-tenant issuer) | None on the gateway — IdP holds auth |
| **`google`** | Google Workspace OIDC (optional `hd` hosted-domain pin) | None on the gateway |
| **API key** (post-login) | `Authorization: Bearer vyuu_user_<id>_<secret>` for inbound MCP calls | `user_api_keys.key_hash` (bcrypt) |

Users authenticate to the gateway via `POST /api/v1/auth/{tenant_id}/login`
(local password) or the OIDC initiate/callback pair (β). Successful
login mints an HS256-signed **portal session JWT** carrying
`(tenant_id, user_id, email, auth_method)`. The session JWT drives
the `/portal` UI; users issue **API keys** from the portal for use by
MCP clients (Cursor, Claude Desktop, agents).

JIT user provisioning on first OIDC sign-in: a new `users` row is
created with `auth_method=microsoft|google`, `external_subject` from
the IdP claim, `password_hash=null`. Subsequent logins find the user
by `(tenant_id, external_subject)` even if their email changes.

Anti-enumeration: every login failure path (wrong email, wrong
password, disabled, OIDC user attempting local login) returns the
same generic 401. Constant-time bcrypt verify against a dummy hash
on the unknown-email branch keeps timing uniform.

#### Operator identity (`operators` table)

Operators (admins) manage the catalog. Two ways to authenticate:

1. **Email + password** — `POST /api/v1/operator-auth/login`.
   Validates `(tenant_id, email, password)` against
   `operators.password_hash` (bcrypt), mints the same custom-format
   JWT the legacy paste-token flow uses.
2. **Paste-token** — `mint_operator_test_token(...)` from
   `operator_auth/fake.py` produces tokens directly. Used by the
   lab + most tests.

Both paths produce the same JWT shape:
`<base64url(json_payload)>.<base64url(hmac_sha256)>`. Verified by
`authenticate_operator` against `Settings.operator_auth_signing_secret`.

Bootstrap (first-run env-var auto-seed) accepts
`VYUU_BOOTSTRAP_ADMIN_PASSWORD` and applies it to BOTH the
`operators.password_hash` and the matching `users.password_hash` —
the same bootstrap admin can use `/operator` and `/portal`.

#### Inbound-MCP identity provider selection

`Settings.inbound_identity_provider` (env: `VYUU_INBOUND_IDENTITY_PROVIDER`):

- **`fake`** (lab default) — `FakeIdentityProvider`. Trusts custom
  `x-vyuu-tenant-id` / `x-vyuu-principal-type` / `x-vyuu-principal-id`
  headers. Suitable for tests + the lab where principals are
  pre-fabricated.
- **`api_key`** (production) — `ApiKeyIdentityProvider`. Validates
  `Authorization: Bearer vyuu_user_*` against `user_api_keys`.
  Required for real Cursor / Claude Desktop / agent traffic.

#### Operator-API authentication

Always `authenticate_operator` (the existing dependency). Operators
hit `/api/v1/...` (catalog management, audit query, etc.) with the
operator JWT in `Authorization: Bearer ...`.

#### Portal session authentication

End-users hit `/api/v1/portal/{tenant_id}/...` with the portal session
JWT (HS256, signed with `Settings.portal_session_signing_secret`).
The dependency `authenticate_portal_session` decodes; routes
additionally verify the path's `tenant_id` matches the JWT's claim
(403 on mismatch — defends against a leaked session JWT replayed
against another tenant's URL).

### 3.2 Authorization

#### Vserver visibility + grants

Every virtual server has a `visibility` column:

| Visibility | Semantics |
|---|---|
| `public` | Any authenticated principal in the tenant can connect |
| `private` (default) | Requires an active `virtual_server_grants` row matching the principal |

Grants target either:
- A specific user (`principal_kind=user`, `principal_id=user.id`), OR
- A group (`principal_kind=group`, `principal_id=group.id`) — every
  user in the group inherits access.

`assert_principal_can_access_vserver` runs at every inbound MCP
connection. Grants honor `revoked_at` (soft-delete) and `expires_at`
(time-bound). The check is a single SQL query covering both direct
+ via-group paths.

#### Access-request workflow (γ)

`access_requests` table backs a self-service request → admin approve
flow:

| Action | Endpoint | Auth |
|---|---|---|
| Submit request | `POST /api/v1/portal/{tenant}/access-requests` | Portal session JWT |
| List my requests | `GET /api/v1/portal/{tenant}/access-requests` | Portal session JWT |
| Withdraw pending | `DELETE /api/v1/portal/{tenant}/access-requests/{id}` | Portal session JWT |
| List queue | `GET /api/v1/access-requests` | Operator JWT |
| Approve (auto-create grant) | `POST /api/v1/access-requests/{id}/approve` | Operator JWT |
| Decline (with note) | `POST /api/v1/access-requests/{id}/decline` | Operator JWT |

A partial-unique index on `(user_id, vserver_id) WHERE status='pending'`
prevents a user from filing duplicate pending requests for the same
vserver. Approved/declined/withdrawn don't block re-requesting later.

Anti-enumeration on withdraw: a user trying to withdraw someone
else's request gets 404, not 403 (otherwise they could probe for the
existence of other users' requests).

#### Operator role hierarchy

`OperatorRole` enum: `admin` / `editor` / `viewer`. Currently the
gateway treats all three identically (any authenticated operator can
do all admin actions). The role field is recorded but not enforced.
Production hardening would gate destructive routes (`DELETE`,
`POST /admins`) on `role == admin`. Tracked under the broader policy
backlog.

### 3.3 Catalog management

#### MCP servers (`mcp_servers` table)

The gateway runs four upstream source types today (and one parked):

| Source type | What it is | Transport |
|---|---|---|
| **`http`** | Remote HTTP-served MCP (e.g. `https://mcp.draw.io/mcp`) | `streamable_http` or `sse` |
| **`stdio`** | Pre-installed binary launched via stdio (e.g. `python3`, vendor scripts) | `stdio` |
| **`npm`** | Spawned via `npx -y <package>` | `stdio` |
| **`pypi`** | Spawned via `uvx <package>` | `stdio` |
| **`binary`** | Pre-installed absolute-path executable (e.g. `/opt/vendor/falcon-mcp`) | `stdio` |
| **`oci`** (parked) | Docker / OCI container | parked — daemon-access privilege model |

Per-source validation runs at registration:
- **HTTP**: URL must be HTTPS; configurable allowlist / denylist;
  loopback / RFC1918 / IPv6 private blocked unless `allow_private_networks`.
- **stdio**: command must be in `StdioLaunchPolicy.allowed_commands`
  (default `python`, `python3`, `node`, `npx`, `uvx`); arguments
  validated; path-traversal / metacharacters blocked.
- **npm / pypi**: name shape via regex; optional content allowlist
  via `StdioLaunchPolicy.allowed_npm_packages` / `allowed_pypi_packages`
  (H4 — production-grade supply-chain gating).
- **binary**: absolute path, exists + executable, no symlink-escape,
  optional `allowed_binary_paths` allowlist.

#### Capability discovery

After registering a server, operators trigger capability sync:
`POST /api/v1/servers/{id}/sync` opens an MCP session against the
upstream, calls `tools/list` / `resources/list` / `prompts/list`,
and persists the results to `mcp_capabilities`. Drift detection
(`added` / `removed` / `changed` / `unchanged`) returned in the
response.

Two seeding paths:
- **Sync** — discover-from-upstream (the normal flow).
- **Seed** — `POST /api/v1/servers/{id}/capabilities` with operator-
  supplied descriptors. Used when the upstream isn't reachable yet
  or for over-rides on `risk_category`.

Optional periodic sync (`PeriodicCapabilitySyncScheduler`, S7) — off
by default. Per-tenant concurrency cap so a 1000-server tenant can't
hammer all upstreams in one tick.

#### Manifest pre-fill (S8)

`POST /api/v1/servers/from-manifest` accepts an `mcp.json` URL,
fetches it (HTTPS-only by default), parses a conservative subset of
fields (`name`/`endpoint`/`transport`/`command`+`args`/`auth.scheme`),
returns a pre-filled registration body the operator confirms. **Never
auto-registers** — a malicious manifest URL must not be able to
silently land a server in the registry.

Spec-instability caveat: `mcp.json` schema is fluid upstream. Only
`vyuu_gateway/registry/manifest.py` needs to evolve when the spec
stabilises.

#### Virtual servers (`virtual_servers` table)

A virtual server is a **published bundle of tools**, scoped to a
tenant. Each carries:

- `name` — appears in the inbound URL: `/v/{tenant}/{name}/mcp`.
- `tools[]` — an explicit allowlist of `(server_id, tool_name)` pairs
  pulled from one or more upstream MCPs.
- `rename_map` — optional rename of exposed tool names (so a user
  sees `query` instead of `query_select`).
- `policy_id` (optional) — points at the policy provider's rule set.
- `visibility` — `public` or `private`.

Virtual servers are the **publishing primitive**: an operator picks
which tools from which upstreams to expose, names the bundle, sets
visibility, optionally restricts via grants. Inbound MCP requests
hit the vserver's URL; the gateway resolves which upstream actually
holds each tool.

### 3.4 Outbound authentication (5 application modes + mTLS shipped)

Production MCPs almost always require credentials. The gateway brokers
five application-layer auth styles plus transport-layer mTLS, all
stored as opaque references in `mcp_servers.auth_*` / `mtls_*_ref`
columns and resolved through the SecretStore:

| Mode | Column | What gets sent upstream | Use case |
|---|---|---|---|
| **Phase 1 — `auth_headers`** | `auth_headers: {header: ref}` | `Header: <resolved value>` | One corp credential (Datadog, Wiz tenant, Snyk org) |
| **Phase 2 — `auth_passthrough`** | `auth_passthrough: {inbound_header: upstream_header}` | The end-user's own header value, propagated to the upstream | User-tier credentials (GitHub PAT, Notion, Linear) |
| **Phase 3 — `auth_oauth`** | `auth_oauth: {token_url, client_id_ref, client_secret_ref, scope?, audience?}` | `Authorization: Bearer <minted token>` | M2M token-exchange (Wiz, Auth0/Okta-fronted internal services) |
| **Phase 4 — `auth_authcode`** | `auth_authcode: {auth_url, token_url, client_id_ref, client_secret_ref, scopes[], redirect_uri}` | `Authorization: Bearer <per-user token>` | Per-user delegated tokens — "Connect to GitHub / Notion / Drive" UX. Refresh tokens stored in `oauth_user_tokens` table per (tenant, user, server) |
| **Phase 5 — `auth_jwt_bearer`** | `auth_jwt_bearer: {token_url, algorithm, private_key_ref, issuer, subject, audience, scope?, additional_claims?, ...}` | `Authorization: Bearer <minted token>` | RFC 7523 service-account flows: Workspace SAs (Drive, Calendar, Gmail), AWS IAM Roles Anywhere |
| **Transport — mTLS** | `mtls_cert_ref` + `mtls_key_ref` | Client cert chain on the TLS handshake | Internal corp APIs that demand mutual auth at the connection layer |

The five OAuth-style modes (1-5) are **mutually exclusive** at the schema
level — operators pick exactly one Authorization-header source per
upstream. mTLS coexists freely with any of them (transport-layer vs
application-layer credentials). Per-user (phase 4) is the only mode
where the gateway must thread an inbound `principal_id` through the
hot path; phases 1, 2, 3, 5 are gateway-owned identities.

H6 — `{secret:ref-name}` value templating — applies to `auth_headers`
and `auth_env`. Operators write `{"Authorization": "Bearer {secret:paypal-token}"}`;
the resolver fetches the inner ref from the SecretStore and substitutes
it into the value. Multiple placeholders per value supported. Bare-ref
values without `{secret:...}` still work (auto-detected backward-compat).

A5 — every audit event records which auth mode actually fired:
`auth_modes.auth_org_tier`, `auth_modes.auth_user_tier_passthrough`,
`auth_modes.auth_oauth_client_credentials`,
`auth_modes.auth_oauth_authcode`, `auth_modes.auth_oauth_jwt_bearer`,
`auth_modes.auth_mtls`. Operators can answer "is tenant X actually
using per-user OAuth on this upstream?" without grepping config
dumps.

### 3.5 SecretStore backends

Three backends, selected via `VYUU_SECRET_STORE_BACKEND`:

| Backend | When to use | Config |
|---|---|---|
| **`memory`** (default) | Dev / lab / tests | Pre-seeded by lab bootstrap |
| **`vault`** | POC + on-prem-only | `VYUU_VAULT_ADDR` + `VYUU_VAULT_TOKEN` (KV v2 at `{mount}/data/{tenant_id}/{ref}`) |
| **`aws_secrets_manager`** | AWS-native production | `VYUU_AWS_REGION` + boto3 default credential chain (path: `{prefix}/{tenant_id}/{ref}`) |

Per-tenant URL prefix on both production backends → IAM /
ACL-template scoping just works. Common error-mapping discipline:
`SecretNotFoundError` only on actual not-found; permission /
network / malformed payloads → backend-error class (never masked as
not-found, which would hide ACL misconfiguration).

Operator console "Secret store" panel shows the active backend +
no-cost connectivity probe + switch instructions for the other two.
Read-only on purpose — backend choice is deployment-time
(env vars baked into the gateway pod).

Backlog: AWS KMS direct integration (envelope encryption for at-rest
data we hold ourselves), k8s-secrets backend.

### 3.6 Audit & telemetry

#### Event types

`AuditEvent.event_type`:
- `tool_call` (default) — emitted by the lifecycle for every tool
  invocation. Captures decision, upstream status, latency
  (total + upstream), response size, auth-mode flags, args
  metadata, and (when policy opts in) raw args + raw response.
- `access_attempt` — emitted by the inbound route for connection-
  level auth/access denials. Three failure reasons recorded:
  `invalid_bearer`, `vserver_not_found`, `no_grant`. Surfaces the
  smart-azz-uses-someone-else's-URL case in the operator dashboard.

#### Audit pipeline

Every event lands in:
1. **`RecentAuditEmitter`** — in-process ring buffer (default 1000
   events). Drives the operator-console "Events" panel via
   `GET /api/v1/audit-events`. Reset on gateway restart — NOT
   durable storage.
2. **Inner emitter** — Kafka or NATS in production
   (`AsyncAuditEmitter` wrapping `KafkaProducer` / `NatsProducer`),
   `_LocalAuditEmitter` in dev. The durable audit pipeline.

#### H5 — opt-in raw-args / raw-response capture

`AuditEvent.raw_args` + `AuditEvent.raw_response` populate ONLY when
`PolicyDecision.allow(capture_raw_args=True, capture_raw_response=True)`.
Default off (privacy-by-default per spec §3.3). Dev/POC operators
flip globally via `VYUU_AUDIT_CAPTURE_RAW_DEFAULT=true` —
`SimplePolicyProvider` then opts in on every allow.

Size cap: 16 KB JSON per field, with progressive degradation:
1. Under cap → pass through unchanged
2. Over cap → cap each leaf string to 1 KB + truncation marker,
   re-check
3. Still over → fallback to a `{"__truncated__": True, "size_bytes": N}`
   sentinel
4. Non-serialisable payload → `{"__non_serialisable__": True}` sentinel

Truncation flags surface so the UI can render a "truncated" pill.

#### Operator UI Events panel

`/operator` → "Events" panel:
- Filter by Event type (tool_call / access_attempt), virtual server,
  tool name (substring), decision (allow/deny/redact/rewrite), result
  limit (1-500).
- Each card shows: tool name (or 🚫 access denied for attempts),
  decision pill, upstream-status pill, timestamp, latency, principal,
  vserver, auth-mode flags, args metadata (always),
  Tool input + Tool output (when H5 captured) — with per-block Copy
  buttons.
- Access-attempt cards visually distinct: red left-border, 🚫
  prefix, reason pill, "attempted vserver: \<name>" line.

#### Graph events (NHI graph)

Parallel pipeline to audit. `GraphEventEmitter` produces events shaped
for the Non-Human-Identity graph the platform's analytics layer
consumes: `(principal, tenant, vserver, upstream_server, tool)`
edges with timestamps and decisions. `AsyncGraphEventEmitter` +
Kafka/NATS producer; `InMemoryGraphEventEmitter` for dev.

#### NHI in-process surfaces (3 read endpoints + 3 UI panels)

The audit + capability + grant + oauth_user_tokens tables are joined
in-process to produce three operator surfaces. No new schema; no new
background jobs.

- **Identities dashboard** (`/operator` → Identities panel):
  per-principal aggregation of recent tool calls. Counts total /
  allowed / denied / upstream-error calls, distinct vservers /
  upstreams / tools touched, last-seen + first-seen, per-RiskCategory
  histogram, and a `high_risk_calls` bucket
  (delete + admin + credential_access + data_export + execute).
  Endpoints `GET /api/v1/identities` (list) and
  `GET /api/v1/identities/{id}/timeline` (per-principal event stream
  with risk-floor + decision filters). Backed by
  `audit/identity_aggregator.py`.
- **NHI relation graph** (per-principal): three reads via
  `graph/identity_graph.py`:
  - `GET /api/v1/identities/{id}/summary` — granted vservers
    (direct + group + public), exposed tools (joined to
    risk_category), reachable upstreams (with `oauth_connected`
    state), OAuth connections, derived `risk_score` 0..100.
  - `GET /api/v1/identities/{id}/graph` — node + edge graph
    (principal → vserver → tool → upstream).
  - `GET /api/v1/who-can-do?tool_name=X&risk_floor=Y` — reverse
    permission query for security review.
  The Identities-panel card has three drill-in expanders: "Show
  timeline", "Show graph" (radial-concentric SVG, brand-coloured
  nodes, risk-tinted tool fills), "Show summary" (risk-score
  badge + OAuth connections + reachable upstreams).
- **NHI map ("People & AI — who uses what")** (`/operator` → NHI
  map panel): 4-column bipartite SVG of the entire tenant.
  `GET /api/v1/nhi-map`. Columns: Users / AI Apps / MCP Servers /
  Agents. AI apps are inferred from `client_metadata.user_agent`
  against an allowlist (Cursor, Claude Desktop, ChatGPT, Continue,
  Cline, Zed, Goose, Windsurf); anything else renders dashed
  ("unsanctioned"). Edge thickness scales with interaction count;
  agents are detected heuristically from the principal display
  (`bot`, `agent`, `n8n`, `cron`, etc.). Sanctioned-only filter.

#### Operator dashboard KPIs (top-of-page)

`GET /api/v1/admin/dashboard` aggregates seven KPIs in a single
round trip — drives the Dashboard panel at the top of `/operator`:

- `nhi_total` + `nhi_active_24h` — distinct principals seen ever +
  in last 24h.
- `mcp_servers_registered` + `mcp_servers_active_24h` — sanctioned
  catalog size + how many were actually called.
- `virtual_servers_published` + `users_total` — roster sanity check.
- `pending_access_requests` — admin queue depth (warn-tinted if >0).
- `high_risk_calls_24h` — delete / admin / credential_access /
  data_export / execute (alert-tinted if >0).
- `denied_calls_24h` + `upstream_errors_24h` — failure signal for
  triage.
- `oauth_connected_users` + `oauth_connected_servers` — A1's
  per-user delegated reach.

### 3.7 Reliability primitives

#### Circuit breakers

`UpstreamCircuitBreakerRegistry` per (tenant_id, server_id). Opens
after `failure_threshold` consecutive failures (default 5), reverts to
half-open after `recovery_timeout_seconds` (default 30). Open state
short-circuits with `CircuitBreakerOpenError` so a flapping upstream
doesn't burn caller threads / connection pool slots.

Operator console shows breaker state per upstream card.

#### Connection pool

`UpstreamConnectionPool` keyed by `(tenant_id, server_id, transport)`.
Caps connections per upstream via `Settings.upstream_max_connections_per_server`
(default 4). Pooled httpx clients reused across tool calls. Closed
cleanly on app shutdown via the lifespan teardown.

#### Audit failure mode

`AuditFailureMode.MONITOR` (current default for v1) — audit-emit
failures are logged but never block the request hot path. The future
`ENFORCE` mode would deny a tool call if its audit event can't be
durably queued (compliance posture for regulated tenants).

### 3.8 Two operator-facing UIs

Both ship as Python string constants (HTML/CSS/JS) under
`/operator` and `/portal`. Strict CSP (`default-src 'self'`), no CDN
dependencies, no frontend build step.

#### `/operator` — admin console

Layout: hero + grid of panels.

Panels (in order):
1. **Sign in** (or operator metadata + Log out when signed in)
2. **Gateway health** — public liveness probe
3. **Registered servers** — register / sync / health-check / delete
4. **Capabilities** — discovered tools, picker for vserver creation
5. **Virtual servers** — list + create + tools + Manage access
   (visibility toggle + grants editor)
6. **Pending access requests** — γ queue with one-click approve /
   decline
7. **Admins** — list / create / disable / reset password operators
8. **Users** — list + create local-auth user
9. **Groups** — list / create / add / remove members
10. **Tool-call activity / Events** — filterable audit dashboard
11. **Secret store** — backend status + connectivity health
12. **Register MCP server** form
13. **Create virtual server** form

Visual design: Vyuu Design System (cream paper bg, ink text, burnt-
orange primary, Fraunces serif headings, Inter UI, JetBrains Mono
for code).

#### `/portal` — end-user portal

Layout: hero + tab navigation (pill-rail group) + one panel visible
at a time.

Tabs:
1. **Catalog** — vserver cards in responsive grid (`auto-fill,
   minmax(300px, 1fr)`). Search by name, filter by access. Each
   card shows visibility + access pills, "Request access" or
   "Show config" button. Show config produces copy-pasteable Cursor
   + Claude Desktop JSON snippets with `<YOUR_API_KEY>` placeholder.
2. **My requests** — submitted access requests with status pills.
   Search by note / decision / vserver id. Filter by status.
   Withdraw button on pending.
3. **API keys** — issue / list / revoke own bearer keys. Search by
   label / prefix. Filter by active/revoked. Plaintext shown ONCE
   at issuance.
4. **Settings** — change password (local-auth users only;
   auto-hidden for OIDC users).

Visual design: same Vyuu palette as `/operator`. The two surfaces are
visually consistent — same admin can flip between them and feel one
product.

---

## 4. Data model

Eleven migrations on top of the initial schema. Current state:

```
tenants
  └─ operators (admins)        [+ password_hash, last_login_at, disabled_at,
  │                               must_change_password since 0008]
  ├─ users (end users)         [auth_method, password_hash | external_subject]
  │   ├─ user_api_keys
  │   ├─ user_group_memberships ─┐
  │   ├─ access_requests         │
  │   └─ oauth_user_tokens       │      [phase-4 per-user delegated tokens
  │       (server_id, access,    │       — A1 — RLS-bound, unique per
  │        refresh, scope, exp)  │       (tenant, user, server)]
  │                              │
  ├─ groups ──────────────────────┘
  │   └─ user_group_memberships
  │
  ├─ mcp_servers
  │   ├─ source_type, source_location, transport, args, env_vars_ref
  │   ├─ Outbound auth (5 mutually-exclusive OAuth-style modes +
  │   │   mTLS): auth_headers, auth_env, auth_passthrough,
  │   │   auth_oauth, auth_authcode, auth_jwt_bearer,
  │   │   mtls_cert_ref, mtls_key_ref
  │   ├─ health_status, health_message, last_synced_at
  │   └─ mcp_capabilities (tools/resources/prompts, risk_category)
  │
  └─ virtual_servers
      ├─ name, policy_id, rename_map, visibility, created_by
      ├─ virtual_server_tools (allowlist: server_id × tool_name)
      └─ virtual_server_grants (principal_kind, principal_id, expires_at, revoked_at)
```

Tenant isolation enforced two ways:

1. **Application-level** — every query in service layers takes
   `tenant_id` explicitly and filters on it.
2. **Postgres RLS** — `bind_tenant_context(session, tenant_id)`
   sets `app.current_tenant_id` GUC; RLS policies on every tenant-
   scoped table use it. Defense in depth.

Test `test_tenant_isolation.py` asserts every mutating service entry
point is guarded.

---

## 5. End-to-end user flows

### 5.1 Operator onboarding a new MCP

```
1. Operator signs in to /operator (email + password OR paste token).
2. Fills "Register MCP server" form (display name, source_type, URL,
   auth_headers if needed, etc.). Submits.
3. Server appears in Registered servers panel with health=unknown.
   Background probe fires.
4. Operator clicks "Sync capabilities" on the server card.
5. Capabilities populate the panel below.
6. Operator selects tools, clicks "Create virtual server", names it,
   chooses public/private visibility.
7. Vserver appears in /v/{tenant}/{name}/mcp routing.
8. (Private only) Operator opens "Manage access" expander on the
   vserver card → Issue grant → picks user / group from dropdown.
```

### 5.2 End-user requesting access + connecting

```
1. User signs in to /portal (email + password OR OIDC).
2. Catalog tab shows all tenant vservers; private ones they don't
   have a grant on are marked "Locked".
3. User clicks "Request access" on a Locked card. Optional note.
4. Request lands in /operator → Pending access requests.
5. Admin clicks Approve → grant auto-created → user's catalog now
   shows "Has access" on that vserver.
6. User opens API keys tab → "Issue key" with a label → copies
   plaintext (shown ONCE).
7. User opens the vserver's "Show config" expander → copies the
   Cursor JSON, replaces <YOUR_API_KEY> with the issued plaintext,
   pastes into ~/.cursor/mcp.json.
8. Cursor connects to /v/{tenant}/{vserver}/mcp, sends initialize +
   tools/list + tools/call. Each call audited.
```

### 5.2b End-user connecting a SaaS account (A1 — OAuth authcode)

```
1. Operator registers an MCP with `auth_authcode = {auth_url,
   token_url, client_id_ref, client_secret_ref, scopes,
   redirect_uri}` pointing at the SaaS IdP (GitHub, Drive, Notion).
2. End user opens /portal → Catalog. Vservers wrapping the new MCP
   show a Connect button next to their card (because the catalog
   API surfaces `requires_user_auth_servers`).
3. User clicks "Connect github-demo" → portal POSTs to
   /api/v1/oauth-authcode/{server_id}/initiate → gateway returns
   the IdP authorize URL with a signed state JWT (HS256, 10-min
   TTL). Browser navigates there.
4. User consents on the IdP. IdP redirects browser to
   /api/v1/oauth-authcode/callback?code=...&state=...
5. Gateway validates state, exchanges code at the token endpoint
   (sends `Accept: application/json` for GitHub-style IdPs),
   upserts the row in `oauth_user_tokens` (per tenant × user ×
   server), renders an HTML success page.
6. Catalog now shows "connected (1/1)" + Reconnect button. The
   "Connections" tab lists the linked account with Disconnect.
7. On every subsequent tool call into a vserver wrapping that MCP,
   the lifecycle threads the principal_id → fetch_token() looks up
   the user's row → returns a fresh access token (refresh-rotation
   honoured per RFC 6749 §6) → upstream call rides
   `Authorization: Bearer <user-token>` → SaaS sees the user.
```

### 5.2c Admin reviews an identity (NHI dashboard / map / drill-in)

```
1. Admin signs in to /operator. Dashboard panel at the top shows
   the rolling-24h KPIs.
2. Pending requests > 0 (warn pill) → admin clicks down to the
   Access requests panel and approves / declines.
3. Admin scans the NHI map (4-column "who uses what") to spot
   unsanctioned clients (dashed circles). Clicks Sanctioned filter
   to confirm only allowlisted MCP clients are reaching the gateway.
4. Identities panel: identity with high_risk_calls > 0 catches the
   eye. Admin clicks "Show graph" → radial-concentric SVG showing
   their reachable tools, risk-tinted.
5. Admin clicks "Show summary" → risk score 70, OAuth-connected to
   GitHub, three reachable upstreams. Decides this NHI's reach is
   too broad.
6. Admin scrolls to Users panel, finds the user row, clicks "API
   keys" expander → clicks Revoke (admin) on the suspect key →
   confirms. The key fails with 401 on the next tool call.
```

### 5.3 Tool call lifecycle (the hot path)

```
inbound POST /v/{tenant}/{vserver}/mcp tools/call
  ↓
identity_provider.validate_principal()  → API key → user_id
  ↓
session_registry.get_or_create_session()
  ↓
resolver.resolve_tools(tenant_id, vserver_name)  → vserver + grant check
  ↓
[tool call resolution: vserver allowlist + rename_map]
  ↓
policy_provider.evaluate_tool_call(context)
  → allow / deny / capture_raw_audit flags
  ↓
[upstream call]
upstream_clients.get_client(tenant_id, server_id)
  → secret_store.get_secret() per ref → httpx.AsyncClient(headers=...)
  → circuit_breaker.call_through() → mcp_client.call_tool(...)
  ↓
audit_emitter.emit_nowait(create_tool_call_audit_event(...))
graph_event_emitter.emit_nowait(...)
  ↓
return CallToolResult to client
```

### 5.4 Connection-level rejection (smart-azz scenario)

```
inbound POST /v/{tenant}/private-vserver/mcp initialize
  ↓
identity_provider.validate_principal()  → API key → user_id  ✓
  ↓
vserver lookup  → exists  ✓
  ↓
assert_principal_can_access_vserver()
  → no grant for (user, vserver) and no group grants either
  → raises VirtualServerAccessDeniedError
  ↓
_emit_access_attempt(reason=NO_GRANT, principal=user, vserver_id)
  → AuditEvent(event_type=access_attempt, decision=deny, ...)
  → lands in RecentAuditEmitter + Kafka/NATS
  ↓
return 403 to client
```

The operator sees the attempt on `/operator` → Events panel with
red-bordered card, 🚫 access denied + no_grant pills, the principal
identity, and the attempted vserver.

---

## 6. Configuration surface

All gateway configuration is environment-variable-driven via
`pydantic-settings`. Prefix: `VYUU_`. Full list (current state, not
exhaustive — see `vyuu_gateway/config.py` for canonical):

| Var | Default | Purpose |
|---|---|---|
| `VYUU_DATABASE_URL` | dev placeholder | Postgres URL (psycopg async driver) |
| `VYUU_REDIS_URL` | None | Redis URL for multi-instance session registry |
| `VYUU_LOG_LEVEL` | `INFO` | Structured-log level |
| `VYUU_GATEWAY_INSTANCE_ID` | `gateway-local` | Recorded on every audit event |
| `VYUU_OPERATOR_AUTH_SIGNING_SECRET` | `dev-...` | HMAC for operator JWTs |
| `VYUU_PORTAL_SESSION_SIGNING_SECRET` | `dev-...` | HMAC for portal session JWTs |
| `VYUU_PORTAL_SESSION_TTL_SECONDS` | 43200 | Portal session lifetime |
| `VYUU_INBOUND_IDENTITY_PROVIDER` | `fake` | `api_key` for production |
| `VYUU_SECRET_STORE_BACKEND` | `memory` | `vault` or `aws_secrets_manager` for prod |
| `VYUU_VAULT_ADDR` / `_TOKEN` / `_MOUNT` / `_NAMESPACE` / `_VALUE_FIELD` | — | Vault config |
| `VYUU_AWS_REGION` / `_AWS_SECRETS_PREFIX` / `_VALUE_FIELD` | — | AWS Secrets Manager config |
| `VYUU_AUDIT_CAPTURE_RAW_DEFAULT` | `false` | H5 raw capture default — `true` for dev/POC |
| `VYUU_POLICY_PROVIDER_BACKEND` | `simple` | `management_plane` for production policy |
| `VYUU_MANAGEMENT_PLANE_POLICY_BASE_URL` | None | Required when backend=management_plane |
| `VYUU_OIDC_MICROSOFT_*` (4 fields) | None | Microsoft Entra ID per-tenant OIDC |
| `VYUU_OIDC_GOOGLE_*` (4 fields) | None | Google Workspace OIDC |
| `VYUU_BOOTSTRAP_TENANT_NAME` / `ADMIN_EMAIL` / `ADMIN_PASSWORD` / `ADMIN_DISPLAY` | None | First-run auto-seed |
| `VYUU_HTTP_URL_ALLOWLIST` / `_DENYLIST` / `_ALLOW_PRIVATE_NETWORKS` | empty / false | URL security at registration |
| `VYUU_UPSTREAM_*` (5 fields) | dev defaults | Timeouts, pool size, breaker config |
| `VYUU_CAPABILITY_SYNC_*` (4 fields) | off | Periodic sync config |

---

## 7. What's intentionally NOT in v1

**Not bugs — deliberate design choices.** Documented so they're not
"discovered" later as gaps.

- **Secrets stored in plaintext in memory store**. `InMemorySecretStore`
  is dev-only. Never use for prod. The Vault / AWS backends are
  the prod path.
- **Operator role hierarchy** (admin/editor/viewer) is recorded but
  not enforced. Any authenticated operator does all admin ops.
- **No audit event durability without a Kafka/NATS producer wired**.
  `_LocalAuditEmitter` (default) just keeps events in-process. The
  `RecentAuditEmitter` ring buffer is for the UI panel only — NOT a
  durable audit log.
- **No data-residency controls**. Tenants share a Postgres + a single
  audit pipeline. Multi-region / per-tenant DB isolation is a future
  enhancement.
- **No rate limiting**. A misbehaving agent can spam the gateway. The
  circuit breakers protect the upstreams; the gateway itself relies
  on the ingress / load balancer.
- **No native OCI / Docker source type**. Parked — daemon-access
  privilege model.
- **No real Keycloak integration test** in CI. Shipped against unit-
  test JWKS-mock fixtures; A3-β.x in the backlog standsup a real
  Keycloak realm.
- **No portal UI design pass** — the structural baseline is shipped
  (Vyuu tokens + cards-grid + search), visual polish is intentionally
  left for the design pass.

---

## 8. Backlog

The full canonical list lives in `BACKLOG.md`. Summary as of
2026-05-01 (post-A1 / mTLS / A2 / NHI dashboard / NHI map / Users
admin):

### Recently shipped (this revision — Tier-1 + Tier-2 stress-test fixes)

- **Persistent stdio subprocess pool** (Tier-2 #1) — supervisor-task
  pattern in `StdioMcpClient`; one persistent subprocess + ClientSession
  per pool slot, multiplexed cross-task. **85× RPS uplift measured**
  (5 → 425 RPS per backing server). Bounded subprocess count regardless
  of call volume.
- **uvicorn back-pressure config** — `--limit-concurrency`,
  `--limit-max-requests`, `--backlog`, `--timeout-keep-alive` driven
  by Settings, applied uniformly across lab + Docker + systemd + K8s.
- **`/healthz` outside request pipeline** — top-of-app ASGI route,
  bypassed by per-tenant inflight gate. 100% uptime during burst.
- **Per-tenant inflight gate** — ASGI middleware, fast-503 with Vyuu
  error envelope (`source=gateway, category=rate_limited, retryable=true`).
  Cap configurable via `Settings.inbound_per_tenant_inflight_limit`.
- **DB connection pool** — `pool_size=20, max_overflow=40, pool_timeout=10s`
  configurable via Settings. Eliminates queueing-cascade failure mode
  surfaced by load test.
- **Auto-sync capabilities on registration** — fire-and-forget
  background task with 30s timeout. Disable via
  `Settings.auto_sync_capabilities_on_registration=False`.
- **Capabilities-not-synced error** — `ErrorCategory.CAPABILITIES_NOT_SYNCED`
  replaces misleading `tool_not_in_vserver` when vserver_tools rows
  exist but no capability rows match. Retryable=true.
- **Audit storage cap** — 10 MiB default per opted-in raw-payload
  capture; truncation sentinel records `total_bytes` /
  `stored_bytes` / `cap_bytes`. **Transit unaffected** by the cap.
  `Settings.audit_raw_capture_byte_cap`.
- **H3 — payload size limits** — request 5 MiB / response 25 MiB
  default caps; over-cap requests fast-413 before reaching upstream;
  over-cap responses truncate with marker. Opt-in redaction (regex
  patterns for common secret shapes) via policy decision flags.
- **A4 — 401-driven OAuth refresh** — one-shot retry on phase-3 + 4
  401 responses; single-flight per (server_id, principal_id) via
  asyncio Lock; failure tagged `auth_failed` + `retryable=false` so
  client knows to reconnect.
- **NATS audit producer** + **ClickHouse audit consumer** + **DiskSpoolAuditEmitter**
  — full audit pipeline wired with chaos test (kill NATS mid-run, spool
  drains when it returns).
- **Process supervisor + resource limits** — `deploy/docker/`,
  `deploy/systemd/`, `deploy/kubernetes/` manifests with restart
  policies, memory caps, pids limits, healthcheck on `/healthz`,
  read-only root FS, dropped capabilities.
- **Test-only perf observability harness** — `tests/perf/` with
  Prometheus + Grafana docker-compose, ASGI metrics middleware,
  exporter sidecar, 14-panel dashboard, end-to-end stress harness.
  Production codebase has zero `prometheus_client` runtime dependency.
- **A1** — OAuth authorization-code (phase 4): per-user delegated
  tokens, signed-state CSRF, refresh-rotation, portal Connect/Disconnect.
- **M-A1.5** — mTLS upstream auth: `mtls_cert_ref` + `mtls_key_ref`
  columns, `MtlsClientCredential` plumbed into HTTP clients.
- **A2** — OAuth JWT-bearer (RFC 7523): RS256/ES256/PS256, Workspace
  SA impersonation via `subject` ≠ `issuer`, reserved-claim defence.
- **N1 + N2 + N3** — Identities dashboard + relation graph + radial /
  bipartite SVG.
- **Admin Dashboard** — `/api/v1/admin/dashboard` 7 KPIs in one round trip.
- **NHI map** — `/api/v1/nhi-map` 4-column bipartite (Users / AI Apps /
  MCP Servers / Agents).

### Open (next sprint)

| ID | Item | Effort |
|---|---|---|
| Anomaly alerts | "first ever risk=high action by NHI", "Nx denies in 5min" — new `nhi_alerts` table | 1 day |
| OAuth provider preset catalog | Drive / Slack / Notion / Atlassian / MS Graph drop-down in registration UI | ½ day |
| A3-β.x | Real-Keycloak integration test | ~½ day |
| A6.y | Kubernetes Secrets `SecretStore` impl | ~1 day |
| AWS KMS direct integration | Envelope encryption (esp. for `oauth_user_tokens`) | 1–2 days |
| H1 | DNS-time SSRF backstop | ~½ day |
| Stdio pool auto-scale | grow under burst, shrink when idle | 1 day |
| Tools-list / resolver caching | reduce DB read pressure on session init | 1 day |

### Source types & supply chain

| ID | Item | Effort |
|---|---|---|
| S1.b | Cosign / Sigstore verification for binary source | ~½ day |

### Performance polish (measurement-gated)

| ID | Item | Effort |
|---|---|---|
| P1 | Per-passthrough connection pool | 1 day |
| P2 | Secret-rotation strategy for pooled connections | ~½ day |
| P3 | Shared httpx client for OAuth refreshes | 1 hour |

### UX / design follow-ups

- Portal UI design pass (taking through Claude design — visual
  polish on top of the structural baseline shipped)
- Operator UI design pass

### Parked deliberately

- **S2** OCI / Docker source type — daemon-access privilege model
- **S8** MCP manifest auto-discovery — best-effort version shipped
  (`POST /api/v1/servers/from-manifest`); full auto-discovery waits
  on upstream spec stabilisation
- **S9** Go / Cargo / Bun source types — niche
- **Google Drive native — UNBLOCKED 2026-05-01.** A1 + A2 both shipped.
  Drive integrates two ways out of the box: `auth_authcode` for end-
  user delegated access ("Connect my personal Drive") with
  `extra_authorize_params: {access_type: offline, prompt: consent}`,
  or `auth_jwt_bearer` for Workspace SA + domain-wide delegation
  (organisation-wide reads).

---

## 9. Test posture

`pytest`: **878 passed, 0 skipped** (with full integration env vars
set: Postgres + Redis + NATS + drawio), zero failures as of
2026-05-02. Coverage:

- **Unit tests** — service layers, secret stores, audit emitters,
  policy providers, identity providers, MCP outbound clients,
  identity aggregation (NHI dashboard), OAuth-authcode token
  provider, OAuth JWT-bearer token provider with real RSA
  assertion signature round-trip via `cryptography`.
- **Integration tests** (env-gated on `VYUU_TEST_DATABASE_URL`) —
  every admin-API endpoint, every portal endpoint, RLS isolation
  posture, the full inbound MCP route end-to-end, real upstream
  round-trip against drawio, OAuth-authcode endpoints
  (initiate / callback / list / disconnect), NHI relation graph
  (principal_summary / who_can_do / dependency_chain), admin
  dashboard KPI aggregation, NHI map.
- **Static checks** — `mypy` strict on 191 source files;
  `ruff check` clean.
- **JS regression** — `tests/test_operator_ui_js_syntax.py` runs
  `node --check` over both `operator_ui` + `portal_ui` JS. Catches
  Python-string-escape bugs that would otherwise break the served JS
  silently.
- **Tenant-isolation static guard** — `tests/tenant_isolation/test_tenant_isolation.py`
  asserts every tenant-scoped table has the `tenant_id` column +
  every service entry point requires a tenant context.

To run:

```bash
VYUU_TEST_DATABASE_URL=postgresql+psycopg://... \
VYUU_TEST_REDIS_URL=redis://... \
VYUU_TEST_DRAWIO_UPSTREAM=1 \
pytest && ruff check . && mypy .
```

---

## 10. Reference

- **`HANDOFF.md`** — chronological session log + how-to-resume notes.
  Read this when picking up after a long break.
- **`BACKLOG.md`** — durable to-do list + sized items + parked
  decisions.
- **`docs/architecture/vyuu-gateway-spec.md`** — original
  architectural spec (pre-implementation).
- **`docs/operations/tls-and-mtls.md`** — TLS termination + mTLS
  ops guide.
- **`docs/operations/secret-store-setup.md`** — Vault vs AWS Secrets
  Manager picker, install snippets, POC-→-prod progression.
- **`docs/TECH-STACK.md`** — full-stack + devops handover, packages,
  reasoning. (This document.)
- **`docs/GETTING-STARTED.md`** — step-by-step setup for a new
  deployment. (This document.)
