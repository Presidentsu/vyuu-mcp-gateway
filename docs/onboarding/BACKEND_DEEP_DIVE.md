# BACKEND_DEEP_DIVE — request lifecycles, data flows, schema

This is the level below `BACKEND.md`. It walks the major flows
end-to-end with file:line references, and the schema column-by-column.
Read it when you need to debug a specific path or design a change that
touches multiple modules.

For the higher-level "what flows where" picture, see `ARCHITECTURE.md`.
For low-level concurrency / transaction / failure-mode detail, see
`LOW_LEVEL_ARCH.md`.

## Module dependency graph

The backend is layered. Higher layers depend on lower layers; never the
reverse. There are NO import cycles in `src/vyuu_gateway/`.

```
api/*  ────────────┐    operator-facing routes; thin orchestration
                   │
  registry/*  ─────┤    user/group/access-request services
  virtual_servers/ │    vserver service; emits admin audit
  scim/*  ─────────┤    SCIM 2.0 server
  idp/*   ─────────┤    IdP directory + sweeper + SAML provider
  capabilities/*   │    upstream tools/list cadence
                   │
  audit/*  ────────┤    events, recent buffer, persistent store, admin audit
  upstream/*  ─────┤    pool, circuit breaker, OAuth-AC, JWT-bearer
  policy/*  ───────┤    decision providers
  identity/*  ─────┤    Principal resolver
  operator_auth/*  │    JWT mint + verify
  users/*  ────────┤    OIDC providers + JWKS + login
  graph/*   ───────┤    identity_graph queries
  sessions/*  ─────┤    session registry (in-memory + Redis)
  secrets/*  ──────┤    tenant-scoped secret store
                   │
  db/*  ───────────┤    SQLAlchemy models + Session + RLS binding
  config.py        │    Settings (pydantic-settings)
                   │
  audit/events.py  │    AuditEvent shape (no deps on the rest)
  enums.py         │    Postgres enum compatibility
                   │
  Standard library + third-party (FastAPI / SQLAlchemy / pydantic / pysaml2 / httpx / PyJWT / bcrypt)
```

The `audit/events.py` module is at the bottom of the graph because
every other audit module depends on it but it depends on nothing.
Same for `db/models.py` — base of the DB layer.

`main.py` is the only module that imports from every layer; it's the
composition root.

## Inbound MCP request lifecycle

The hot path. Every tool call from an AI client (Cursor / Claude / agent)
flows through this. URL: `POST /v/{tenant_id}/{vserver_name}/mcp`.

```
                    POST /v/{tenant_id}/{vserver_name}/mcp
                                 │
                    ┌────────────▼───────────┐
                    │ inflight_gate          │ ─── 503 if tenant cap exceeded
                    │ (api/inflight_gate.py) │     (bypass for /healthz)
                    └────────────┬───────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │ inbound_mcp_post         │ api/inbound_mcp.py:163
                    │  - get_inbound_mcp_db    │     opens session, binds tenant
                    │  - extract bearer        │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │ IdentityProvider         │ identity/api_key.py
                    │  .identify(bearer)       │     bcrypt verify (constant-time)
                    │  → Principal             │     → emit access_attempt
                    └────────────┬─────────────┘     if INVALID_BEARER
                                 │
                    ┌────────────▼─────────────┐
                    │ vserver lookup           │ virtual_servers/service.py
                    │  + visibility check      │     → emit access_attempt
                    │  + grant check (if priv) │     if VSERVER_NOT_FOUND
                    └────────────┬─────────────┘     or NO_GRANT
                                 │
                    ┌────────────▼─────────────┐
                    │ MCP lifecycle            │ mcp/lifecycle.py
                    │  - JSON-RPC parse        │
                    │  - tools/call dispatch   │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │ PolicyProvider.decide()  │ policy/simple.py
                    │  → allow/deny/redact/    │   (or management_plane)
                    │     rewrite              │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │ UpstreamClient (pool)    │ upstream/pool.py
                    │  - circuit breaker check │ upstream/circuit_breaker.py
                    │  - HTTP/stdio call       │ upstream/streamable_http_client.py
                    │  - response capture      │   or stdio_pool.py
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │ audit_emitter.emit_nowait│ audit/recent.py
                    │  → RecentBuffer (cache)  │   ↓ delegates to inner
                    │  → PostgresStore (durable)│ audit/persistent.py
                    │  → raw_emitter (Kafka)   │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                          response to client
```

Every "→ emit access_attempt" arrow on the left calls
`_emit_access_attempt_audit_event()` ([api/inbound_mcp.py:106](src/vyuu_gateway/api/inbound_mcp.py)).
That helper synthesises an `AuditEvent` with `event_type=access_attempt`,
sentinel `tool="<connect>"`, `decision=DENY`. Best-effort wrap — never
raises so the request rejection still completes.

### Why per-request DB session opens before bearer resolution

`get_inbound_mcp_db(tenant_id)` ([api/inbound_mcp.py:151](src/vyuu_gateway/api/inbound_mcp.py))
takes the tenant from the URL path and binds it BEFORE the bearer is
resolved. Why: the tenant scope determines which `user_api_keys` rows
the lookup considers. If we resolved the bearer first, we'd have to
either scan untenanted (security risk) or open a second session.

### Why audit emit happens AFTER the response

The current code path emits audit AFTER computing the response but
BEFORE returning it. This is a deliberate trade-off:

- **Emit-after-response (current):** The audit row reflects the
  authoritative outcome (allow + actual upstream status, deny + reason).
  Cost: a slow DB INSERT delays the response. Mitigation: TOOL-EVENTS-1
  uses a fresh session per emit — typically < 2 ms on local Postgres.
- **Emit-before-response:** Faster response, but the audit row records
  intent, not outcome.

We chose the first because for security audit, "did upstream actually
return data?" is more useful than "did we authorise the call?"

## Operator API request lifecycle (with admin audit)

Every mutating operator action emits an `admin_audit_log` row in the
**same transaction** as the mutation. If the request rolls back, the
audit row rolls back too — auditor sees exactly the actions that
happened.

```
              POST /api/v1/users  (operator creates a new local user)
                                 │
                    ┌────────────▼────────────────┐
                    │ authenticate_operator       │ operator_auth/dependency.py
                    │  - parse Bearer JWT          │
                    │  - HMAC verify (signing key) │
                    │  - return AuthenticatedOperator
                    └────────────┬────────────────┘
                                 │
                    ┌────────────▼────────────────┐
                    │ get_tenant_scoped_db        │ api/dependencies.py:22
                    │  - SessionLocal()            │
                    │  - bind_tenant_context       │ db/session.py:62
                    │    (sets app.current_tenant_id
                    │     on every transaction)    │
                    └────────────┬────────────────┘
                                 │
                    ┌────────────▼────────────────┐
                    │ create_local_user(actor=...) │ registry/users_service.py
                    │  - validate input            │
                    │  - hash password (bcrypt)    │
                    │  - db.add(User)              │
                    │  - record_admin_action(      │ audit/admin_audit.py
                    │      db, actor, action="user.create",
                    │      target=AdminAuditTarget("user", user.id, email))
                    │    ⤷ db.add(AdminAuditLog) — DOES NOT COMMIT
                    │  - db.commit()               │ ← single commit for both
                    └────────────┬────────────────┘
                                 │
                                 ▼
                          response: 201 with user dict
```

`record_admin_action()` ([audit/admin_audit.py](src/vyuu_gateway/audit/admin_audit.py))
calls `db.add(...)` but **never** `db.commit()`. The caller (the
service function) commits both rows together. This is the load-bearing
guarantee — verified by `tests/audit/test_admin_audit.py::test_rollback_drops_audit_row_when_mutation_rolls_back`.

### Actor kinds

`AdminAuditActor` has three constructors:

| Constructor | Used by |
|---|---|
| `AdminAuditActor.operator(op)` | Human operator via the operator API |
| `AdminAuditActor.system(label)` | Cron / sweeper / startup migration |
| `AdminAuditActor.scim(directory_display)` | IdP-driven (SCIM provisioning push) |

The actor is propagated via every service's `actor` parameter:

```python
def create_local_user(
    db: Session,
    *,
    tenant_id: UUID,
    email: str,
    password: str,
    actor: AdminAuditActor,
) -> User:
    ...
```

Service functions DO NOT default `actor`; the caller must provide one.
This forces the operator-API endpoint to construct it from the JWT
claim, and the SCIM endpoint to construct it from the directory's
display_name. No silent "system" attribution.

## SCIM provisioning push lifecycle

URL: `POST /scim/v2/{directory_id}/Users`

```
                IdP (Entra / Workspace) POSTs SCIM User payload
                                 │
                    ┌────────────▼────────────────┐
                    │ authenticate_scim            │ scim/auth.py
                    │  - extract Bearer            │
                    │  - look up directory by id   │
                    │  - bcrypt verify token       │ idp/scim_tokens.py
                    │  - bind tenant context       │
                    └────────────┬────────────────┘
                                 │
                    ┌────────────▼────────────────┐
                    │ scim/server.py::create_user  │
                    │  - parse SCIM payload        │
                    │  - find_by_external_id?      │ scim/users.py
                    │    └─ exists → 409 conflict  │
                    │  - create_from_scim()        │
                    │    └─ db.add(User)           │
                    │    └─ record_admin_action(   │
                    │         actor=scim(directory),│
                    │         action="scim.create_user")
                    │    └─ db.commit()            │
                    └────────────┬────────────────┘
                                 │
                                 ▼
                       SCIM 201 with User resource
```

PATCH (group membership update, attribute change) handles two shapes:

- **Entra style:** `Operations: [{op: "Replace", path: "active", value: false}]`
- **Workspace style:** `members: [{value: "user-id"}, ...]` (full replacement)

[`scim/server.py`](src/vyuu_gateway/scim/server.py) detects which by
inspecting the body shape and dispatches to the right handler.

### Soft-delete + 7-day grace + hard-delete sweeper

A SCIM DELETE on a user doesn't drop the row — it sets
`users.soft_deleted_at = now()` and `users.disabled_at = now()`. The
hourly [`HardDeleteSweeper`](src/vyuu_gateway/idp/sweeper.py) finds rows
older than 7 days and hard-deletes them in per-tenant transactions.

Grace window rationale: IdP sync can flap (user temporarily removed
then re-added during a group restructure). 7 days lets the IdP push
a re-add without losing the user's API keys + grants.

## IdP SSO sign-in (per-directory OIDC)

Two routers handle this — one for the user portal, one for the operator
console — both in [`api/idp_signin.py`](src/vyuu_gateway/api/idp_signin.py).

```
                User clicks "Continue with Acme · Entra ID"
                                 │
                    ┌────────────▼────────────────┐
                    │ POST /api/v1/auth/{tenant}/idp/{dir}/oidc-start
                    │  - look up directory          │
                    │  - build OAuth2 authorize URL │
                    │  - generate state + nonce     │
                    │  - return { authorize_url }   │
                    └────────────┬────────────────┘
                                 │ user redirected to IdP
                                 │
                                 │ IdP authenticates user
                                 │ redirects to gateway with ?code=...&state=...
                                 ▼
                    ┌────────────▼────────────────┐
                    │ GET /api/v1/auth/{tenant}/idp/{dir}/oidc-callback
                    │  - validate state             │
                    │  - exchange code for tokens   │
                    │  - fetch JWKS (cached)        │ users/jwks.py
                    │  - verify ID token signature  │
                    │  - validate iss/aud/nonce     │
                    │  - extract sub, email, name   │
                    └────────────┬────────────────┘
                                 │
                    ┌────────────▼────────────────┐
                    │ _find_or_jit_create_user     │ idp/service.py
                    │  - lookup by (directory_id,  │
                    │     external_id=sub)         │
                    │  - if missing: JIT-create    │
                    │    User row (auth_method=    │
                    │    'scim', idp_directory_id  │
                    │    set; SCIM may reconcile   │
                    │    later)                    │
                    └────────────┬────────────────┘
                                 │
                    ┌────────────▼────────────────┐
                    │ mint portal session JWT      │
                    │  - sign with operator secret │
                    │  - return HTML that sets     │
                    │    sessionStorage + redirect │
                    │    to /portal/               │
                    └─────────────────────────────┘
```

For SAML the flow is the same shape but:
- Start = AuthnRequest builder + redirect to IdP SSO URL
- Callback = ACS (Assertion Consumer Service) endpoint that POST-receives
  the SAML Response, validated by [`pysaml2`](src/vyuu_gateway/idp/saml_provider.py)
  for signature + audience + replay nonce + NotOnOrAfter.

## Audit fan-out chain (TOOL-EVENTS-1)

Composed in [`main.py`](src/vyuu_gateway/main.py) lifespan setup:

```python
raw_emitter = audit_emitter or _LocalAuditEmitter()
persistent_store = PostgresToolCallEventStore(SessionLocal, inner=raw_emitter)
recent_emitter = RecentAuditEmitter(inner=persistent_store)
app.state.audit_emitter = recent_emitter
app.state.recent_audit_emitter = recent_emitter
```

Composition reads top-down (the outer wraps the inner):

```
emit_nowait(event)
   │
   ▼
RecentAuditEmitter.emit_nowait                   audit/recent.py
   │ 1. acquire lock, deque.append(event)
   │ 2. delegate ↓
   ▼
PostgresToolCallEventStore.emit_nowait           audit/persistent.py
   │ 1. open fresh session via SessionLocal()
   │ 2. bind_tenant_context(session, event.tenant_id)
   │ 3. session.add(_event_to_row(event))
   │ 4. session.commit()  ← DURABLE WRITE HERE
   │ 5. on exception: log, continue (don't break the request)
   │ 6. delegate ↓
   ▼
raw_emitter.emit_nowait                          (Kafka / NATS / no-op stub)
   │ 1. enqueue to async producer
   ▼
EmitResult propagates back up the chain
```

`EmitResult.durable=True` is set by `PostgresToolCallEventStore` once
the commit succeeds, regardless of whether the inner Kafka emitter
accepts the event. From the caller's perspective, "we have a durable
copy" is satisfied as soon as Postgres commits.

### Buffer warm-up on startup

Lifespan startup hook in [`main.py`](src/vyuu_gateway/main.py):

```python
recent = getattr(app.state, "recent_audit_emitter", None)
if recent is not None and len(recent) == 0:
    seed_recent_buffer_from_postgres(
        SessionLocal,
        buffer_appender=recent.warm_load,
    )
```

`seed_recent_buffer_from_postgres` ([audit/persistent.py](src/vyuu_gateway/audit/persistent.py)):

1. Open one session, `SELECT id FROM tenants` (no RLS on `tenants`).
2. For each tenant: open a fresh session, `bind_tenant_context`,
   `SELECT ... FROM tool_call_events WHERE tenant_id = ... ORDER BY occurred_at DESC LIMIT 2000`.
3. Push events into the buffer **oldest-first** via `warm_load(event)`
   (NOT `emit_nowait` — would re-trigger Postgres write on already-persisted events).

The `len(recent) == 0` guard exists because tests sometimes emit events
through the chain before entering the test client context (which is
what triggers lifespan startup); without the guard, those events would
be re-loaded from Postgres into the buffer that already has them →
double-count. In production the buffer is empty at startup so the
guard is a no-op.

## Capability sync cycle

`PeriodicCapabilitySyncScheduler` runs in a background asyncio task,
opt-in via `VYUU_CAPABILITY_SYNC_ENABLED=true`.

Per cycle:

```
                     scheduler tick (every interval_seconds)
                                 │
                    ┌────────────▼────────────────┐
                    │ select all mcp_servers       │
                    │  ORDER BY last_capabilities_pulled_at NULLS FIRST
                    │  (untenanted scan; no RLS on operator-side scheduler)
                    └────────────┬────────────────┘
                                 │
                    for each server (per-tenant semaphore-bounded):
                                 │
                    ┌────────────▼────────────────┐
                    │ capability_client.list_tools │ capabilities/upstream_adapter.py
                    │  (uses production upstream    │
                    │   pool; honours circuit       │
                    │   breakers + per-call timeout)│
                    └────────────┬────────────────┘
                                 │
                    ┌────────────▼────────────────┐
                    │ store_capabilities()         │ capabilities/service.py
                    │  - bind_tenant_context       │
                    │  - upsert mcp_capabilities   │
                    │    by (server_id, name)      │
                    │  - mark missing rows as      │
                    │    deprecated=true           │
                    │  - update server.            │
                    │    last_capabilities_pulled_at
                    │  - commit                    │
                    └─────────────────────────────┘
```

The `max_concurrent_per_tenant` cap ([config.py](src/vyuu_gateway/config.py)
`capability_sync_max_concurrent_per_tenant`) prevents one chatty
tenant from starving everyone.

## Entity-relationship overview

ASCII ERD of the most-load-bearing relationships. Cardinality on the
edge: `─` = 1, `<` = many. `[F]` = FORCE RLS table.

```
                              ┌───────────┐
                              │  tenants  │  (no RLS — root of cascade)
                              └─────┬─────┘
                       ┌────────────┼─────────────┬───────────────┬──────────────┐
                       │            │             │               │              │
                  ┌────▼────┐  ┌────▼────┐  ┌────▼────┐    ┌──────▼─────┐  ┌─────▼──────┐
                  │operators│  │  users  │  │ groups  │    │ mcp_servers│  │idp_directories
                  └────┬────┘  └────┬────┘  └────┬────┘    └──────┬─────┘  │     [F]    │
                       │            │            │                │        └─────┬──────┘
                       │            │      ┌─────┴────────┐       │              │ ① one-to-many
                       │            │      │              │       │              ▼
                       │            │ ┌────▼─────────┐ ┌──▼───────┴──┐    ┌──────────────┐
                       │            │ │user_group_   │ │mcp_         │    │ users        │
                       │            │ │ memberships  │ │ capabilities│    │  (idp_dir_id │
                       │            │ └──────────────┘ └─────────────┘    │   external_id│
                       │            │                                      │   joined back│
                       │            │                                      │   to a dir)  │
                       │            │                                      └──────────────┘
                       │       ┌────▼─────────┐
                       │       │user_api_keys │  ← `id` is the principal_id on every audit event
                       │       └──────┬───────┘
                       │              │
                       │       ┌──────▼─────────┐
                       │       │oauth_user_     │  ← per-user delegated tokens for upstream MCPs
                       │       │   tokens       │
                       │       └────────────────┘
                       │
                       │
                  ┌────▼────────────────────────┐
                  │  virtual_servers            │
                  └────┬────────────────────────┘
                       │
              ┌────────┴────────┐
              │                 │
        ┌─────▼──────────┐  ┌───▼──────────────────────┐
        │virtual_server_ │  │ virtual_server_grants    │ ← polymorphic principal_id
        │     tools      │  │  (private vservers only)  │   (user OR group)
        └────────────────┘  └──────────────────────────┘

                   ─────────────  audit (TOOL-EVENTS-1)  ─────────────

                  ┌─────────────────────┐  ┌────────────────────┐
                  │ tool_call_events[F] │  │ admin_audit_log[F] │
                  │  (tenant_id CASCADE)│  │ (tenant_id CASCADE)│
                  │  vserver_id  SET NULL│  │ actor_operator_id  │
                  │  upstream_   SET NULL│  │   SET NULL         │
                  │  server_id           │  │ target_id NOT a FK │
                  └─────────────────────┘  └────────────────────┘
                  ↑
                  │ source of truth for:
                  │
              ┌───┴────────────────┬─────────────────┬─────────────────┐
              ▼                    ▼                 ▼                 ▼
        Events panel         NHI map             Identities      Health & servers
        (api/audit_events)   (api/nhi_map)       (api/identities) (api/health_overview)
```

### How to read this

- **Cascade direction:** every arrow from `tenants` is `ON DELETE
  CASCADE`. Drop a tenant, lose everything tenant-scoped.
- **`SET NULL` on audit FKs:** `tool_call_events.vserver_id` and
  `.upstream_server_id` use `ON DELETE SET NULL` so events outlive
  their referent. Denormalised `vserver_name` keeps the row readable.
- **`admin_audit_log.target_id` is intentionally NOT a FK.** The audit
  row must survive its target being deleted (whole point of an audit
  log).
- **Polymorphic principal in grants:** `virtual_server_grants.principal_id`
  references either a user.id or a group.id depending on
  `principal_kind`. No DB-level FK because polymorphic.
- **`oauth_user_tokens` cascades** with `users` (drop user → drop their
  upstream tokens) and `mcp_servers` (drop server → drop its tokens).
- **`mcp_capabilities`** cascades with `mcp_servers` — capability sync
  re-populates after a re-register.

For the per-table column-by-column intent, see the next section.

## Schema deep-dive

Every table that matters, with column intent.

### `tenants`

The root of the tenancy tree. **No RLS** (we need to enumerate tenants
in cron jobs and startup hooks).

| Column | Why |
|---|---|
| `id` | UUID PK |
| `name` | Human label, unique |
| `tier` | `shared` / `dedicated` — enum reserved for future SaaS pricing |
| `created_at` | timestamptz |

ON DELETE CASCADE flows from here through every tenant-scoped table.

### `operators`

Admin users. RLS-enabled.

| Column | Why |
|---|---|
| `id` | UUID PK |
| `tenant_id` | FK |
| `email` | login identifier; unique per tenant |
| `display_name` | UI label |
| `role` | `admin` / `editor` / `viewer` (enum); not yet enforced — admin everywhere today |
| `password_hash` | bcrypt; nullable for SSO-only operators |
| `pending_password_reset_at` | non-null = must set password on next sign-in |
| `disabled_at` | non-null = no sign-in allowed |
| `created_at` | timestamptz |

### `users`

End users. RLS-enabled.

| Column | Why |
|---|---|
| `id` | UUID PK |
| `tenant_id` | FK |
| `email` | login identifier |
| `display_name` | UI label |
| `auth_method` | `local` / `microsoft` / `google` / `scim` (enum) |
| `password_hash` | bcrypt; only for `local` |
| `idp_directory_id` | FK to `idp_directories`; non-null for `scim` (and OIDC after IDP-1) |
| `external_id` | The IdP's stable id (`sub` for OIDC, `id` for SCIM); unique with `(tenant_id, idp_directory_id, external_id)` |
| `disabled_at` | non-null = sign-in blocked |
| `soft_deleted_at` | SCIM deletion grace window; hard-deleted by sweeper after 7d |
| `created_at` | timestamptz |

The `(tenant_id, idp_directory_id, external_id)` unique constraint is
how we de-dup re-pushes from SCIM and JIT-create from OIDC.

### `user_api_keys`

The bearer that AI clients present. RLS-enabled.

| Column | Why |
|---|---|
| `id` | UUID PK; this is the `principal_id` recorded on every audit event |
| `tenant_id` | FK |
| `user_id` | FK; cascade-delete with the user |
| `name` | User-facing label |
| `prefix` | First ~8 chars of plaintext `vyuu_user_<random>` for fast lookup; indexed |
| `secret_hash` | bcrypt of the full plaintext |
| `last_used_at` | bumped on every successful identify |
| `revoked_at` | non-null = bcrypt verify still passes but lookup returns null |
| `created_by` | FK to operators or users (depending on issuance source) |
| `created_at` | timestamptz |

The hot-path identify ([identity/api_key.py](src/vyuu_gateway/identity/api_key.py)):
1. Strip prefix, look up candidate rows by `prefix` (indexed).
2. bcrypt verify each candidate's `secret_hash` — typically 1 row, sometimes a few.
3. Return `Principal(type=API_KEY, id=row.id, display=user.email)`.

### `mcp_servers`

Upstream MCP servers the gateway routes to. RLS-enabled.

| Column | Why |
|---|---|
| `id` | UUID PK |
| `tenant_id` | FK |
| `display_name` | UI label |
| `source_type` | `http` / `stdio` / `pypi` / `binary` (enum) — drives client construction |
| `source_location` | URL for HTTP, package spec for stdio, etc. |
| `transport` | `streamable_http` / `sse` / `stdio` (enum) — wire transport |
| `args` | JSONB; argv for stdio, headers for HTTP |
| `env` | JSONB; env vars for stdio (refs to `secret_store`) |
| `outbound_auth_*` | Several columns: org_tier / user_tier_passthrough / oauth_client_credentials / oauth_authcode / oauth_jwt_bearer / mtls — boolean flags + per-mode metadata |
| `health_status` | `healthy` / `degraded` / `down` / `unknown` (enum) |
| `last_health_*` | timestamps + error message |
| `last_capabilities_pulled_at` | bumped by capability sync |
| `registered_by` | FK to operators |
| `registered_at` | timestamptz |

### `mcp_capabilities`

Tools / prompts / resources discovered on each upstream. RLS-enabled.

| Column | Why |
|---|---|
| `id` | UUID PK |
| `tenant_id` | FK |
| `server_id` | FK; cascade-delete with the server |
| `kind` | `tool` / `prompt` / `resource` (enum) |
| `name` | tool name from the upstream |
| `risk_category` | `read` / `write` / `delete` / `execute` / `network` / `data_export` / `credential_access` / `admin` / `unknown` — drives the risk floor filter |
| `schema_json` | JSONB; the JSON schema for tool args |
| `deprecated` | true when capability sync didn't see this tool last cycle |
| `observed_at` | last seen |

### `virtual_servers`

The user-facing routing endpoint that maps to one or more upstream
tools. RLS-enabled.

| Column | Why |
|---|---|
| `id` | UUID PK |
| `tenant_id` | FK |
| `name` | URL-path component; unique per tenant; regex `^[a-z][a-z0-9-]*$` |
| `display_name` | UI label |
| `visibility` | `public` (any tenant user can call) / `private` (requires explicit grant) |
| `created_by` | FK to operators |
| `created_at` | timestamptz |

### `virtual_server_tools`

Many-to-many: vserver → upstream tools. RLS-enabled.

| Column | Why |
|---|---|
| `vserver_id` | FK |
| `mcp_server_id` | FK |
| `tool_name` | The tool to expose |
| `display_name` | What the AI client sees as the tool name |

### `virtual_server_grants`

ACL rows for `private` vservers. RLS-enabled.

| Column | Why |
|---|---|
| `id` | UUID PK |
| `tenant_id` | FK |
| `vserver_id` | FK; cascade-delete with vserver |
| `principal_kind` | `user` / `group` (enum) |
| `principal_id` | UUID; FK to users or groups depending on kind (no enforced FK because it's polymorphic) |
| `granted_by` | FK to operators |
| `granted_at` | timestamptz |
| `revoked_at` | non-null = grant inactive |

### `idp_directories`

Per-tenant Entra / Google Workspace directory connection. RLS
**FORCE-enabled**.

| Column | Why |
|---|---|
| `id` | UUID PK; appears in SCIM and SSO URL paths |
| `tenant_id` | FK |
| `kind` | `entra` / `google_workspace` (enum) |
| `display_name` | UI label |
| `signin_protocol` | `oidc` / `saml` (enum) — admin picks at connect time |
| `scim_token_hash` | bcrypt of the SCIM bearer; plaintext shown ONCE at connect |
| `oidc_*` | issuer URL, client_id, client_secret_ref, JWKS URL |
| `saml_idp_*` | IdP entity_id, SSO URL, SLO URL, certificate (PEM, public) |
| `last_sync_at` | bumped on every successful SCIM op |
| `created_at` | timestamptz |

### `tool_call_events` (TOOL-EVENTS-1)

The durable inbound MCP audit log. RLS **FORCE-enabled**.

| Column | Why |
|---|---|
| `event_id` | UUID PK; minted by the audit pipeline so the same id appears in the buffer + table + downstream Kafka |
| `tenant_id` | FK; cascade-delete with tenant |
| `occurred_at` | The event's wall-time (NOT inserted-at) |
| `gateway_instance_id` | Which gateway box (relevant once multi-instance) |
| `event_type` | `tool_call` / `access_attempt` |
| `vserver_id` | FK; ON DELETE SET NULL (events outlive vservers) |
| `vserver_name` | Denormalised so the row stays human-readable after vserver deletion |
| `upstream_server_id` | FK; ON DELETE SET NULL |
| `tool` | tool name OR `<connect>` for access_attempt |
| `principal_type` | `endpoint_session` / `server_agent` / `api_key` |
| `principal_id` | The identifier (api_key id usually) |
| `principal_display` | Email / label captured at write time |
| `decision` | `allow` / `deny` / `redact` / `rewrite` |
| `decision_mode` | `monitor` / `enforce` |
| `policy_id`, `policy_rule_id` | What rule matched (free text) |
| `upstream_status` | `ok` / `error` / `timeout` / `not_called` |
| `latency_ms_total`, `latency_ms_upstream` | float; null when no upstream call |
| `response_size_bytes` | int; null when no upstream |
| `auth_failure_reason` | `invalid_bearer` / `vserver_not_found` / `no_grant` / `disabled_principal` (only on access_attempt) |
| `args_summary` | JSONB; structural summary of args (top-level keys + types + sizes) |
| `auth_modes` | JSONB; which outbound auth modes were configured |
| `client_metadata` | JSONB; agent_type, client_version, user_agent (drives the "via Cursor 0.42" badge) |
| `raw_args`, `raw_response` | JSONB; only populated when policy opted in (H5 capture) |
| `raw_args_truncated`, `raw_response_truncated` | bool; true when the cap hit |

Indexes:
- `(tenant_id, occurred_at)` — primary feed query
- `(tenant_id, vserver_id, occurred_at)` — vserver drill-in
- `(tenant_id, principal_id, occurred_at)` — identity timeline
- `(tenant_id, event_type, occurred_at)` — event-type filter

### `virtual_server_grants` — JIT-1 columns

| Column | Why |
|---|---|
| `expires_at` | NULL = standing access. Non-NULL = the grant stops being honoured at this instant. Enforced on **every** inbound request, not just at session start. |
| `granted_via` | `operator` / `jit_auto` / `jit_approved`. Provenance is stored rather than inferred from `expires_at IS NOT NULL`, because an operator can legitimately hand-issue a time-boxed grant without that being JIT. |
| `granted_by` | **Nullable.** NULL on `jit_auto` rows — no operator decided them, and a sentinel operator would misattribute the decision. |
| `justification` | The requester's stated reason, captured at request time. What an auditor actually reads. |

Partial index `virtual_server_grants_active_expiring_idx` on
`(tenant_id, expires_at) WHERE revoked_at IS NULL AND expires_at IS NOT NULL`
backs the "who is elevated right now" query. Partial because standing
grants are the majority and never belong in it.

### `admin_audit_log`

Admin actions on the platform. RLS **FORCE-enabled**. Distinct
retention from `tool_call_events` — and required to be **longer**, since
this table carries the `retention.prune` rows that explain the other
table's gaps (`create_app` refuses to start on the inversion).

| Column | Why |
|---|---|
| `id` | UUID PK |
| `tenant_id` | FK |
| `actor_operator_id` | FK to operators; nullable for non-operator actors |
| `actor_kind` | `operator` / `system` / `scim` |
| `actor_display` | Email / SCIM directory name; captured at write time |
| `action` | Dotted free text: `user.disable`, `vserver.delete`, `idp.connect`, `scim.deactivate_user`, etc. Free text so new endpoints don't need a migration. |
| `target_kind`, `target_id`, `target_display` | What was acted upon |
| `detail` | JSONB; before/after diff or any context |
| `occurred_at` | timestamptz |

`target_id` is NOT a FK — the audit row outlives its target (whole point).

### `oauth_user_tokens`

Per-user delegated OAuth tokens for upstream MCPs. RLS-enabled.

| Column | Why |
|---|---|
| `id` | UUID PK |
| `tenant_id` | FK |
| `user_id` | FK |
| `mcp_server_id` | FK |
| `access_token_encrypted` | secret-store encrypted blob |
| `refresh_token_encrypted` | secret-store encrypted blob |
| `scope` | granted scopes |
| `expires_at` | for refresh-on-401 |
| `last_refreshed_at` | for the connections page |

Cascade-delete with the user; the hard-delete sweeper drops these as
part of the user delete.

### `mcp_server_dcr_clients`

Dynamic Client Registration state for OAuth-AC upstreams. RLS
**FORCE-enabled**.

Records the (client_id, client_secret) we registered with the upstream's
authorization server when we couldn't pre-provision a client (some
SaaS MCPs require DCR per gateway instance).

### `access_requests`

End-user requests to access a private vserver. RLS-enabled.

| Column | Why |
|---|---|
| `id` | UUID PK |
| `tenant_id` | FK |
| `user_id` | FK |
| `vserver_id` | FK |
| `status` | `pending` / `approved` / `declined` / `withdrawn` |
| `justification` | user-supplied free text |
| `decided_by` | FK to operators |
| `decision_note` | free text |
| `created_grant_id` | FK to virtual_server_grants when approved |
| `created_at`, `decided_at` | timestamptz |

## Failure modes overview

For the deeper "what happens when X breaks" matrix, see
`LOW_LEVEL_ARCH.md`. Here's the request-path summary:

| Failure | Lifecycle response |
|---|---|
| Bearer doesn't validate | 401; emit `access_attempt` with reason `invalid_bearer` |
| Vserver doesn't exist | 404; emit `access_attempt` with reason `vserver_not_found` |
| Vserver private + no grant | 403; emit `access_attempt` with reason `no_grant` |
| Principal disabled | 403; emit `access_attempt` with reason `disabled_principal` |
| Policy denies | 200 JSON-RPC error; emit `tool_call` with `decision=deny` |
| Upstream times out | 200 JSON-RPC error; emit `tool_call` with `upstream_status=timeout` |
| Circuit breaker open | 200 JSON-RPC error; emit with `upstream_status=not_called` |
| Postgres audit INSERT fails | log warning, request still succeeds; in-memory buffer still holds the event for the live tail; downstream Kafka still gets a copy. The dashboard panel will show the gap on next read. |
