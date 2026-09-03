# NETWORK — ports, routes, RLS, transports

## Process & port

The gateway is a single uvicorn process bound to one port. Default
8000. On-prem deployments typically front it with nginx / Caddy /
Traefik for TLS termination + basic rate limiting.

```
                ┌──────────────────┐
client traffic  │  TLS terminator  │   localhost:8000  ┌──────────────┐
  ──TLS────────▶│ (nginx / Caddy)  │ ─────HTTP─────────▶│ Vyuu gateway │
                └──────────────────┘                    └──────┬───────┘
                                                               │
                                                       ┌───────┴───────┐
                                                       │ Postgres :5432│
                                                       └───────────────┘
```

The reverse proxy must:
- Pass through the `Authorization` header (every API surface uses it).
- Pass `Host` so RFC 7239 `Forwarded` / `X-Forwarded-*` are honest.
- Allow long polls / streaming on `/v/.../mcp` — MCP uses streamable
  HTTP with chunked transfers.

See `docs/DEPLOYMENT.md` for the reverse-proxy requirements; the shipped manifests are under `deploy/`.

## Route map

By URL prefix:

| Prefix | What | Auth |
|---|---|---|
| `/operator/...`  | Operator console HTML | Public asset; bearer in JS |
| `/portal/...`    | End-user portal HTML | Public asset; session JWT in JS |
| `/api/v1/...`    | Operator + portal JSON APIs | Operator JWT or Portal JWT |
| `/api/v1/portal/...` | Portal-side endpoints | Portal JWT |
| `/api/v1/auth/...` | OIDC + SAML sign-in (per directory) + default-tenant | Public start; cookie-validated callbacks |
| `/api/v1/operator-auth/...` | Operator-side IdP sign-in | Public start; cookie-validated callbacks |
| `/api/v1/admin/...` | Admin-only (diagnostic bundle, dashboard, health-overview) | Operator JWT |
| `/scim/v2/{directory_id}/...` | SCIM 2.0 server | SCIM bearer |
| `/v/{tenant_id}/{vserver_name}/mcp` | Inbound MCP (the hot path) | API key bearer |
| `/healthz` | Liveness probe (NO auth, NO inflight gate) | none |
| `/api/v1/health` | Authed liveness | Operator JWT |
| `/docs`, `/openapi.json` | FastAPI auto-docs | none (consider gating in prod) |

## MCP transport

Inbound MCP is **streamable HTTP** (the modern MCP transport). Wire
shape: JSON-RPC over HTTP with a session id in the URL or header for
long-running sessions (tools that stream incremental results).

- POST `/v/.../mcp` — request
- The response can be a single JSON-RPC reply OR a multi-part
  `text/event-stream` for streaming tools.

Outbound to upstream MCPs supports three transports:

| Transport | When | Code |
|---|---|---|
| `streamable_http` | Modern HTTP MCP servers (the standard now) | `upstream/streamable_http_client.py` |
| `stdio` | Local process MCPs (npm / uvx / binary) | `upstream/stdio_pool.py` |
| `sse` | Legacy SSE MCP servers | `upstream/sse_client.py` |

Stdio servers are spawned as subprocesses and pooled per
`(server_id, principal)` pair. Restart on crash, kill on idle timeout.

## Per-tenant inflight gate

`api/inflight_gate.py` middleware. Per-tenant semaphore with
configurable cap (`VYUU_INBOUND_PER_TENANT_INFLIGHT_LIMIT`, default
100). Returns `503` with a `Retry-After` header when exceeded.

Bypass list: `/healthz` and other liveness paths so probes are never
shed even under load. See `LIVENESS_BYPASS_PATHS` in
`api/inflight_gate.py`.

## RLS posture

Multi-tenant isolation is enforced at the **Postgres row level** via
`row_security` policies:

- Every tenant-scoped table has a policy:
  `USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)`
- The `app.current_tenant_id` GUC is set per **transaction** by the
  `after_begin` event listener registered in `db/session.py`.
- `bind_tenant_context(session, tenant_id)` is the only sanctioned way
  to attach a tenant to a session.

Tables that use `FORCE ROW LEVEL SECURITY` (even owner can't bypass):
`tool_call_events`, `admin_audit_log`, `idp_directories`,
`mcp_server_dcr_clients`. The rest use plain `ENABLE` (owner exempt;
gateway connects as owner so app code reads work; a non-superuser
support role would be gated by RLS).

Cross-tenant reads from operator tooling: explicitly iterate `tenants`
(no RLS) and bind context per tenant. See `idp/sweeper.py` and
`audit/persistent.py::seed_recent_buffer_from_postgres` for the pattern.

## CORS

CORS is OFF by default. Enable for the operator console only if you're
hosting it cross-origin from the API (rare). Code in `api/cors.py`.

## TLS

The gateway does NOT terminate TLS itself. Always run behind a reverse
proxy that handles cert renewal. Recommended: Caddy with automatic
Let's Encrypt for internet-facing deployments; nginx + corp CA for
intranet.

For multi-tenant SaaS with subdomain-per-tenant routing (IDP-3 backlog),
you'll need wildcard cert + DNS at deployment time.

## On-prem ingress assumptions

For the typical on-prem single-tenant deployment:

- 1 gateway process per host (no horizontal scale needed at first).
- Postgres on the same host or adjacent in the data center.
- TLS terminated by an internal load balancer with the corp CA cert.
- Inbound MCP traffic from agents on user laptops, routed via the
  customer's corporate network (no public internet required).
- Outbound MCP traffic from the gateway to:
  - Internal MCPs on private IPs.
  - SaaS MCPs on the public internet (OAuth-AC users sign in once,
    refresh tokens stored encrypted).

Egress firewall rules: allow gateway → upstream MCP hosts. The list of
upstreams is the `mcp_servers.source_location` column.

## DNS pinning

The gateway has no DNS pinning today. If a customer needs it (e.g.
"only resolve `*.internal.corp` via these resolvers"), it goes in the
upstream client pool config in `upstream/pool.py`.

## Observability ports

Optional Prometheus metrics endpoint at `/metrics` (mount in
`main.py` if `VYUU_PROMETHEUS_ENABLED=true`). Default off.

The diagnostic bundle endpoint (`/api/v1/admin/diagnostic-bundle`) is
the one-shot fallback for when metrics aren't wired.
