# API_REFERENCE — every endpoint

105 endpoints across 7 router groups. This doc is the curated reference;
the live OpenAPI is at `/docs` (Swagger UI) or `/openapi.json`.

**Auth column key:**

- 🟦 **public** — no auth; usable from the login page or by an external IdP
- 🟩 **operator** — operator JWT (`Authorization: Bearer eyJ...`)
- 🟨 **portal** — portal session JWT
- 🟥 **api_key** — `vyuu_user_*` API key (inbound MCP path)
- 🟪 **scim** — `vyuu_scim_*` SCIM bearer

**Tenant-scope key:** auto-bound from the JWT/bearer claim unless noted.

---

## Inbound MCP (the hot path) — `/v/...`

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/v/{tenant_id}/{vserver_name}/mcp` | 🟥 api_key | Issue an MCP JSON-RPC call (tools/list, tools/call, etc.) |
| DELETE | `/v/{tenant_id}/{vserver_name}/mcp` | 🟥 api_key | Close an MCP session (when the client uses session-id semantics) |

The session-id (when present) is in the `mcp-session-id` header. See
`MCP_SPECIFICS.md` for transport quirks.

---

## Operator console + portal HTML — `/operator`, `/portal`

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/operator` | 🟦 public | The operator console SPA HTML |
| GET | `/operator/app.css` `/operator/app.js` `/operator/logo.svg` | 🟦 public | Static assets |
| GET | `/portal` | 🟦 public | The end-user portal SPA HTML |
| GET | `/portal/app.css` `/portal/app.js` | 🟦 public | Static assets |

The HTML is generated inline by [`api/operator_ui.py`](src/vyuu_gateway/api/operator_ui.py)
and [`api/portal_ui.py`](src/vyuu_gateway/api/portal_ui.py). No build step.

---

## Authentication & sign-in — `/api/v1/auth/...`

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/auth/default-tenant` | 🟦 public | Returns `{tenant_id, display_name}` if `VYUU_DEFAULT_TENANT_ID` is set; 404 otherwise. The login page uses this to hide the tenant input. |
| GET | `/api/v1/auth/{tenant_id}/idp-directories` | 🟦 public | List public IdP directories for the tenant (drives the "Continue with X" buttons) |
| POST | `/api/v1/auth/login` | 🟦 public | Local-password sign-in for end users |
| POST | `/api/v1/auth/{tenant_id}/idp/{directory_id}/oidc-start` | 🟦 public | Build the IdP OIDC authorize URL |
| GET | `/api/v1/auth/{tenant_id}/idp/{directory_id}/oidc-callback` | 🟦 public | OIDC callback (validates state + nonce, exchanges code, mints session) |
| GET | `/api/v1/auth/{tenant_id}/idp/{directory_id}/saml-login` | 🟦 public | Build SAML AuthnRequest, redirect to IdP |
| POST | `/api/v1/auth/{tenant_id}/idp/{directory_id}/saml-acs` | 🟦 public | SAML Assertion Consumer Service — `pysaml2` validates signature + audience + nonce |
| GET | `/api/v1/auth/{tenant_id}/idp/{directory_id}/saml-metadata` | 🟦 public | SP metadata for the IdP to consume during connection setup |

**Operator-side mirror** at `/api/v1/operator-auth/...` mints an operator
JWT instead of a portal session (used when admins sign in via SSO).

---

## Operator: catalog (servers + vservers) — `/api/v1/...`

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/servers` | 🟩 operator | List all MCP servers in the tenant |
| POST | `/api/v1/servers` | 🟩 operator | Register a new MCP server |
| GET | `/api/v1/servers/{server_id}` | 🟩 operator | Server detail |
| PATCH | `/api/v1/servers/{server_id}` | 🟩 operator | Update server config |
| DELETE | `/api/v1/servers/{server_id}` | 🟩 operator | Delete server (cascades to capabilities + vserver_tools) |
| GET | `/api/v1/servers/{server_id}/health` | 🟩 operator | Last health check result + status |
| POST | `/api/v1/servers/{server_id}/health/check` | 🟩 operator | Trigger an immediate health probe |
| POST | `/api/v1/servers/{server_id}/sync` | 🟩 operator | Trigger an immediate `tools/list` sync |
| GET | `/api/v1/servers/{server_id}/capabilities` | 🟩 operator | List discovered capabilities for this server |
| GET | `/api/v1/connector-catalog` | 🟩 operator | Pre-configured SaaS MCP server catalog (drives the Quick Add cards) |
| POST | `/api/v1/vservers` | 🟩 operator | Create a new virtual server |
| GET | `/api/v1/vservers` | 🟩 operator | List vservers (with `tool_count`, `grant_count` aggregates) |
| GET | `/api/v1/vservers/{vserver_id}` | 🟩 operator | Vserver detail |
| GET | `/api/v1/vservers/{vserver_id}/tools` | 🟩 operator | Tools projected through this vserver |
| PATCH | `/api/v1/vservers/{vserver_id}` | 🟩 operator | Update vserver |
| DELETE | `/api/v1/vservers/{vserver_id}` | 🟩 operator | Delete vserver |

---

## Operator: identity & access — `/api/v1/...`

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/users` | 🟩 operator | Create a local user |
| GET | `/api/v1/users` | 🟩 operator | List users (with `api_key_count`, `group_count`, `last_api_key_used_at` aggregates) |
| GET | `/api/v1/users/{user_id}` | 🟩 operator | User detail |
| POST | `/api/v1/users/{user_id}/password` | 🟩 operator | Reset password (admin-driven) |
| DELETE | `/api/v1/users/{user_id}` | 🟩 operator | Disable / delete user |
| POST | `/api/v1/users/{user_id}/api-keys` | 🟩 operator | Issue API key on behalf of a user (admin-driven) |
| GET | `/api/v1/users/{user_id}/api-keys` | 🟩 operator | List user's API keys |
| DELETE | `/api/v1/users/{user_id}/api-keys/{key_id}` | 🟩 operator | Revoke an API key |
| POST | `/api/v1/groups` | 🟩 operator | Create a group |
| GET | `/api/v1/groups` | 🟩 operator | List groups (with `member_count`, `vserver_grant_count`) |
| GET | `/api/v1/groups/{group_id}` | 🟩 operator | Group detail + members |
| POST | `/api/v1/groups/{group_id}/members` | 🟩 operator | Add member |
| DELETE | `/api/v1/groups/{group_id}/members/{user_id}` | 🟩 operator | Remove member |
| PATCH | `/api/v1/vservers/{vserver_id}/grants` | 🟩 operator | Grant or revoke vserver access (user or group) |
| GET | `/api/v1/access-requests` | 🟩 operator | Admin queue of pending access requests |
| POST | `/api/v1/access-requests/{id}/approve` | 🟩 operator | Approve a request (creates the grant) |
| POST | `/api/v1/access-requests/{id}/decline` | 🟩 operator | Decline with optional note |

---

## Operator: identity graph + observability — `/api/v1/...`

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/identities` | 🟩 operator | Per-principal aggregates (calls / risk / clients) over the time window |
| GET | `/api/v1/identities/{principal_id}/timeline` | 🟩 operator | Per-principal event stream with `decision` + `risk_floor` + time filters |
| GET | `/api/v1/identities/{principal_id}/summary` | 🟩 operator | Grants, exposed tools, reachable upstreams, OAuth connections |
| GET | `/api/v1/identities/{principal_id}/graph` | 🟩 operator | Directed graph: principal → vservers → tools → upstreams |
| GET | `/api/v1/who-can-do?tool_name=X` | 🟩 operator | Reverse permission query: who in this tenant can call X? |
| GET | `/api/v1/nhi-map` | 🟩 operator | 5-column NHI bipartite graph (users / agents / AI apps / MCP servers / tools or risk) |
| GET | `/api/v1/audit-events` | 🟩 operator | Read `tool_call_events` with `since`/`until`/`vserver_id`/`event_type`/`limit` |
| GET | `/api/v1/admin-audit` | 🟩 operator | Read `admin_audit_log` with `actor_kind`/`action_prefix`/`target_kind`/`since` filters |

---

## Operator: admin — `/api/v1/admin/...`

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/admin/dashboard` | 🟩 operator | KPI rollup for the Dashboard page |
| GET | `/api/v1/admin/health-overview` | 🟩 operator | Live snapshot for the Health & servers page (KPIs + status cards + servers + p95 chart) |
| GET | `/api/v1/admin/diagnostic-bundle?since_minutes=N` | 🟩 operator | One-shot JSON download for support hand-off (bundle v1.1) |
| POST | `/api/v1/admins` | 🟩 operator | Create a new operator (admin) |
| GET | `/api/v1/admins` | 🟩 operator | List operators in this tenant |
| POST | `/api/v1/admins/{operator_id}/password` | 🟩 operator | Reset operator password |
| DELETE | `/api/v1/admins/{operator_id}` | 🟩 operator | Disable / delete an operator |

---

## Operator: IdP directories + secret store — `/api/v1/...`

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/idp/directories` | 🟩 operator | Connect a new Entra / Workspace directory; returns SCIM bearer (shown ONCE) |
| GET | `/api/v1/idp/directories` | 🟩 operator | List directories |
| GET | `/api/v1/idp/directories/{directory_id}` | 🟩 operator | Directory detail (SAML cert, OIDC URLs, SCIM endpoint) |
| DELETE | `/api/v1/idp/directories/{directory_id}` | 🟩 operator | Disconnect (sweeper hard-deletes JIT users after 7d) |
| GET | `/api/v1/secret-store/status` | 🟩 operator | Backend class + entry count (no secret values returned) |

---

## Operator: outbound OAuth (per-server config) — `/api/v1/...`

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/servers/{server_id}/oauth-authcode/start` | 🟩 operator | Initiate per-user delegated OAuth flow |
| POST | `/api/v1/servers/{server_id}/oauth-authcode/refresh` | 🟩 operator | Force refresh a connection |
| GET | `/api/v1/oauth-authcode/callback` | 🟦 public | Upstream OAuth callback (validates state, stores token) |
| GET | `/api/v1/servers/{server_id}/oauth-connections` | 🟩 operator | List which users have an OAuth-AC connection to this server |
| DELETE | `/api/v1/servers/{server_id}/oauth-connections/{user_id}` | 🟩 operator | Revoke a user's connection |

---

## Portal (end-user) — `/api/v1/portal/...`

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/api/v1/portal/{tenant_id}/me` | 🟨 portal | Current user info |
| GET | `/api/v1/portal/{tenant_id}/api-keys` | 🟨 portal | List my API keys |
| POST | `/api/v1/portal/{tenant_id}/api-keys` | 🟨 portal | Issue a new API key (returns plaintext ONCE) |
| DELETE | `/api/v1/portal/{tenant_id}/api-keys/{key_id}` | 🟨 portal | Revoke my own key |
| GET | `/api/v1/portal/{tenant_id}/recent-tool-calls` | 🟨 portal | My recent tool calls (read-side of `tool_call_events` scoped to my keys) |
| GET | `/api/v1/portal/{tenant_id}/tool-history-summary` | 🟨 portal | KPI rollup over a window |
| GET | `/api/v1/portal/{tenant_id}/vservers` | 🟨 portal | Vservers I can call (public + granted) |
| GET | `/api/v1/portal/{tenant_id}/access-requests` | 🟨 portal | My filed access requests |
| POST | `/api/v1/portal/{tenant_id}/access-requests` | 🟨 portal | File a new access request |

---

## SCIM 2.0 server — `/scim/v2/{directory_id}/...`

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/scim/v2/{directory_id}/ServiceProviderConfig` | 🟪 scim | RFC 7644 §5 |
| GET | `/scim/v2/{directory_id}/Schemas` | 🟪 scim | RFC 7644 §4 |
| GET | `/scim/v2/{directory_id}/ResourceTypes` | 🟪 scim | RFC 7644 §6 |
| POST | `/scim/v2/{directory_id}/Users` | 🟪 scim | Provision a user (idempotent on `(directory_id, external_id)`) |
| GET | `/scim/v2/{directory_id}/Users` | 🟪 scim | List users with optional `?filter=userName eq "alice@..."` |
| GET | `/scim/v2/{directory_id}/Users/{user_id}` | 🟪 scim | Read one user |
| PUT | `/scim/v2/{directory_id}/Users/{user_id}` | 🟪 scim | Replace user attributes |
| PATCH | `/scim/v2/{directory_id}/Users/{user_id}` | 🟪 scim | Mutate (handles both Entra `Operations[]` and Workspace `members[]` shapes) |
| DELETE | `/scim/v2/{directory_id}/Users/{user_id}` | 🟪 scim | Soft-delete (7-day grace before hard delete) |
| POST | `/scim/v2/{directory_id}/Groups` | 🟪 scim | Create group |
| GET | `/scim/v2/{directory_id}/Groups` | 🟪 scim | List groups |
| GET | `/scim/v2/{directory_id}/Groups/{group_id}` | 🟪 scim | Read one group |
| PUT | `/scim/v2/{directory_id}/Groups/{group_id}` | 🟪 scim | Replace |
| PATCH | `/scim/v2/{directory_id}/Groups/{group_id}` | 🟪 scim | Mutate (members add/remove) |
| DELETE | `/scim/v2/{directory_id}/Groups/{group_id}` | 🟪 scim | Delete |

Errors follow RFC 7644 §3.12 — see [`scim/errors.py`](src/vyuu_gateway/scim/errors.py).

---

## Health probes

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/healthz` | 🟦 public | Kubernetes liveness probe; bypassed by inflight gate |
| GET | `/api/v1/health` | 🟩 operator | Authed liveness with extra detail |

---

## OpenAPI

- `GET /openapi.json` — full spec
- `GET /docs` — Swagger UI (consider gating in prod)
- `GET /redoc` — ReDoc UI

## Common request/response patterns

**Operator JWT issued** during sign-in. Format:

```
Authorization: Bearer eyJ0ZW5hbnRfaWQiOiI...IsIm9wZXJhdG9yX2lkIjoi...In0.HMAC_SHA256_SIG
```

**Tenant scoping** comes from the bearer claim, not the URL path
(except for `/v/...` and `/scim/...` which carry the tenant or
directory in the path).

**Time-window endpoints** (`/audit-events`, `/nhi-map`, `/identities`):
default window is the last 24h. Pass `since=<ISO>` and `until=<ISO>`
to override. ISO is RFC 3339, `2026-05-05T18:00:00Z` shape.

**Pagination** is cursor-based where present (`?cursor=<opaque>`),
limit-bounded otherwise.

**Errors** are JSON: `{"detail": "..."}` for FastAPI standard,
RFC 7644 envelope for SCIM, JSON-RPC error envelope for `/v/.../mcp`.
