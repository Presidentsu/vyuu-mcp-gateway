# ARCHITECTURE — what flows through where

Vyuu MCP Gateway sits between AI clients (Cursor, Claude Desktop,
ChatGPT, custom agents) and upstream MCP servers (GitHub, Notion,
Google Drive, internal tools). Every tool call is authenticated,
authorised, audited, and (optionally) policy-rewritten before it
reaches upstream.

```
            ┌────────────────────────┐
 Cursor ───▶│                        │     ┌──────────────┐
 Claude ───▶│   Vyuu MCP Gateway     │────▶│ MCP server A │
 ChatGPT ──▶│  (this codebase)       │────▶│ MCP server B │
 Agent ────▶│                        │────▶│ MCP server N │
            └─────────┬──────────────┘     └──────────────┘
                      │
              ┌───────┴────────┐
              │                │
        ┌─────▼─────┐   ┌──────▼──────┐
        │ Postgres  │   │  Operator   │
        │  + RLS    │   │   console   │
        └───────────┘   └─────────────┘
```

## Three planes

The codebase is organised by who's talking to it.

### 1. Inbound MCP — `/v/{tenant_id}/{vserver_name}/mcp`

The hot path. AI clients hit this; the gateway answers with the MCP
JSON-RPC protocol. Code lives in `src/vyuu_gateway/api/inbound_mcp.py`.

Per-request lifecycle (`api/inbound_mcp.py` → `mcp/lifecycle.py`):

1. **Identity** — extract bearer, resolve to `Principal` via
   `IdentityProvider` (production: `ApiKeyIdentityProvider` against
   `user_api_keys`; lab: `FakeIdentityProvider`).
2. **Tenant binding** — `bind_tenant_context(session, tenant_id)`
   sets `app.current_tenant_id` GUC for RLS on every subsequent query.
3. **Authorization** — vserver lookup + grant check (private vservers
   require an explicit `virtual_server_grants` row).
4. **Policy** — `PolicyProvider.decide(...)` returns `allow` / `deny`
   / `redact` / `rewrite`.
5. **Upstream call** — pool-backed client per `(server_id, principal)`
   pair; circuit breaker per pool key.
6. **Audit emit** — fans out to RecentBuffer + PostgresStore + Kafka
   (when wired). See "Audit pipeline" below.

### 2. Operator API — `/api/v1/...`

The admin surface. Operator JWT-authenticated, tenant-scoped via the
JWT claim. Each operator-facing concern is its own router file in
`src/vyuu_gateway/api/`:

- `servers.py` — register / sync / delete MCP servers
- `vservers.py` — virtual server CRUD + visibility
- `users.py` `groups.py` `access_requests_admin.py` — IAM CRUD
- `audit_events.py` `nhi_map.py` `identities.py` — observability reads
- `idp_directories.py` — connect Entra / Workspace
- `admin_audit.py` — read-side of `admin_audit_log`
- `health_overview.py` — live "Health & servers" snapshot
- `diagnostic_bundle.py` — one-shot JSON for support hand-off

The operator console (single-page HTML served by `operator_ui.py`) is
the web client over this API.

### 3. End-user portal — `/portal/...`

The user-facing surface. Local-password or IdP SSO sign-in, session JWT
in `vyuu.portal.session`, then routes for issuing API keys, viewing
own tool history, requesting access to private vservers. Code:

- `api/portal_ui.py` — single-page HTML
- `api/portal.py` — portal API
- `api/access_requests_portal.py` — user-side access request flow
- `api/idp_signin.py` — per-directory OIDC + SAML sign-in routes
- `users/login_endpoint.py` — local-password sign-in

## Audit pipeline

Three-stage fan-out chain, composed in `main.py`:

```
emit_nowait(event)
   │
   ▼
RecentAuditEmitter   ◀─ in-memory deque, last ~1000 events
   │
   ▼
PostgresToolCallEventStore   ◀─ DURABLE source of truth (TOOL-EVENTS-1)
   │
   ▼
raw_emitter   ◀─ Kafka / NATS / disk-spool / no-op stub
```

- The Postgres store is **synchronous** — every emit INSERTs before
  returning. Survives gateway restarts.
- The in-memory buffer is a **read-cache** for the live tail view.
  On lifespan startup it's rehydrated from Postgres so the UI shows
  history immediately after a deploy.
- Operator-console panels (Events / NHI map / Identities / Health)
  query the **Postgres table** with time-window filters. The buffer
  is not load-bearing for correctness anymore.

See `BACKEND.md` for the per-file detail and `BACKLOG.md` entry
TOOL-EVENTS-1 for the rationale.

## Persistence layout

PostgreSQL is the only durable store. Schema in `src/vyuu_gateway/db/models.py`
with Alembic migrations in `migrations/versions/`. RLS-enforced
multi-tenant isolation: every tenant-scoped table has a
`tenant_isolation` policy gated on `app.current_tenant_id`.

Tables grouped by purpose:

| Group | Tables |
|---|---|
| Tenancy | `tenants` (no RLS), `operators`, `users`, `groups`, `user_group_memberships` |
| Catalog | `mcp_servers`, `mcp_capabilities`, `virtual_servers`, `virtual_server_tools`, `virtual_server_grants` |
| Identity | `user_api_keys`, `oauth_user_tokens`, `mcp_server_dcr_clients`, `idp_directories` |
| Workflow | `access_requests` |
| Audit | `tool_call_events` (durable inbound MCP), `admin_audit_log` (durable admin actions) |
| Lab | `lab_oauth_authcode_state` (drawio lab only) |

## Identity model

Three principal kinds across the codebase:

- **`Operator`** — admin user; signs in to the operator console; JWT
  bearer; tenant-scoped via JWT claim; admin actions audited to
  `admin_audit_log`.
- **`User`** — end user; signs in to the portal; can hold
  `user_api_keys` (the bearer that AI clients present); can be
  granted access to private vservers.
- **`Principal`** (audit shape) — the `(type, id, display)` triple
  recorded on every `tool_call_events` row. Three types:
  `endpoint_session`, `server_agent`, `api_key`.

User provisioning is one of:
- **`local`** — admin or self-signup via local password
- **`microsoft` / `google`** — pre-IDP-1 JIT-OIDC sign-in (legacy)
- **`scim`** — provisioned by an `IdpDirectory` (Entra or Google
  Workspace), authenticated via that directory's chosen protocol
  (OIDC or SAML)

See `AUTH.md` for the full picture.

## Why no Redis as a hard dep

The session registry has both an `InMemorySessionRegistry` and a
`RedisSessionRegistry`. On-prem single-instance deployments use the
in-memory one — no infra dep, no extra config. Multi-instance HA
flips the env var to Redis.

## Why no message broker as a hard dep

Same logic. The audit fan-out has Kafka and NATS producers wired but
they're optional. With TOOL-EVENTS-1, Postgres IS the durable audit
sink. Operators with existing Kafka pipelines can plug them in for
SIEM/SOC fan-out; operators without Kafka still get full UI persistence
because Postgres is canonical.

## Why FORCE ROW LEVEL SECURITY

`tool_call_events`, `admin_audit_log`, `idp_directories`,
`mcp_server_dcr_clients`: all use `FORCE ROW LEVEL SECURITY`. This
means even the table owner can't bypass — every connection must set
`app.current_tenant_id` to read or write. Defense in depth: a bug in
application code that forgets to bind tenant context fails closed
(query returns nothing) instead of leaking cross-tenant.

The trade-off: startup tasks that need to scan across tenants
(SCIM sweeper, audit buffer warm-up) iterate `tenants` (which has no
RLS) first, then bind context per tenant.
