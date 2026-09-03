# KNOWLEDGE_BASE — where things live

A jump-table by feature. When you ask "where is X?" — look here first.
File:line references; line numbers are approximate but stable.

## Tenant isolation (RLS)

| Question | File |
|---|---|
| How is `app.current_tenant_id` set per request? | `db/session.py:28` (`after_begin` listener) |
| What pins a session to a tenant? | `db/session.py:62` (`bind_tenant_context`) |
| Which tables enforce FORCE RLS? | `migrations/versions/20260505_0015_tool_call_events.py:188`, `migrations/versions/20260504_0014_idp_directories_and_admin_audit.py:132,227,...` |
| The cross-tenant proof harness | `tests/integration/test_rls_real_postgres.py` |
| Untenanted scan + per-tenant rebind pattern | `idp/sweeper.py:119`, `audit/persistent.py::seed_recent_buffer_from_postgres` |

## Audit pipeline (TOOL-EVENTS-1)

| Question | File |
|---|---|
| Audit emitter chain construction | `main.py` (search `recent_emitter = RecentAuditEmitter(`) |
| In-memory hot cache | `audit/recent.py` |
| Durable Postgres write | `audit/persistent.py::PostgresToolCallEventStore` |
| Buffer rehydration on startup | `audit/persistent.py::seed_recent_buffer_from_postgres` |
| Schema migration | `migrations/versions/20260505_0015_tool_call_events.py` |
| ORM model | `db/models.py::ToolCallEvent` |
| Read-side endpoints | `api/audit_events.py`, `api/nhi_map.py`, `api/identities.py` (all use `audit/persistent.py::query_tool_call_events`) |
| Persistence-across-restart tests | `tests/audit/test_persistent_store.py` |
| Decision log | `BACKLOG.md` → search "TOOL-EVENTS-1" |

## Admin-action audit (same-transaction)

| Question | File |
|---|---|
| The emit function | `audit/admin_audit.py::record_admin_action` |
| Actor constructors | `audit/admin_audit.py::AdminAuditActor` |
| Where is it invoked from? | Every mutating service in `registry/`, `virtual_servers/`, `operator_auth/password_auth.py`, `idp/service.py` |
| Read endpoint | `api/admin_audit.py` |
| Operator UI panel | `api/operator_ui.py` (search `data-nav="admin-audit"`) |

## Identity providers (IDP-1)

| Question | File |
|---|---|
| Connect / disconnect a directory | `api/idp_directories.py` |
| Per-directory OIDC sign-in | `api/idp_signin.py` (search `oidc_start`, `oidc_callback`) |
| Per-directory SAML sign-in | `api/idp_signin.py` (search `saml_login`, `saml_acs`) |
| SAML SP wrapper | `idp/saml_provider.py` |
| SCIM token mint + verify | `idp/scim_tokens.py` |
| SCIM server | `scim/server.py` |
| SCIM users service | `scim/users.py` |
| SCIM groups service | `scim/groups.py` |
| SCIM auth dependency | `scim/auth.py` |
| JIT-create user resolver | `idp/service.py` (search `_find_or_jit_create`) |
| Hard-delete sweeper (7d grace) | `idp/sweeper.py` |
| ORM models | `db/models.py::IdpDirectory`, `db/models.py::User` (the `idp_directory_id` + `external_id` columns) |
| Migration | `migrations/versions/20260504_0014_idp_directories_and_admin_audit.py` |

## Operator auth

| Question | File |
|---|---|
| JWT verify dependency | `operator_auth/dependency.py::authenticate_operator` |
| Provider Protocol | `operator_auth/provider.py` |
| Lab JWT mint | `operator_auth/fake.py::mint_operator_test_token` |
| Operator local-password sign-in | `operator_auth/password_auth.py` |
| Settings field | `config.py::operator_auth_signing_secret` |

## End-user auth

| Question | File |
|---|---|
| Local password login | `users/login_endpoint.py` |
| OIDC providers (deployment-wide) | `users/oidc_providers.py` |
| JWKS cache | `users/jwks.py` |
| Portal session verify | `api/portal.py::authenticate_portal_session` |
| API key mint / verify | `registry/users_service.py::issue_user_api_key`, `identity/api_key.py` |
| Default tenant resolution | `api/idp_signin.py` (search `default-tenant`) |

## Inbound MCP (the hot path)

| Question | File |
|---|---|
| URL routing | `api/inbound_mcp.py` |
| Per-request lifecycle | `mcp/lifecycle.py` |
| Bearer → Principal | `identity/api_key.py` |
| vserver lookup + grant check | `virtual_servers/service.py`, `registry/users_service.py` |
| Policy decision | `policy/simple.py` (default), `policy/management_plane.py` |
| Audit emit (allow / deny / access_attempt) | `api/inbound_mcp.py` (search `_emit_access_attempt_audit_event`) |

## Outbound MCP (gateway → upstream)

| Question | File |
|---|---|
| Pool wrapper | `upstream/pool.py` |
| Streamable HTTP client | `upstream/streamable_http_client.py` |
| Stdio process pool | `upstream/stdio_pool.py` |
| SSE client | `upstream/sse_client.py` |
| Circuit breaker | `upstream/circuit_breaker.py` |
| Health checker | `upstream/health.py` |
| OAuth authcode (per-user) | `upstream/oauth_authcode.py` |
| OAuth JWT-bearer (service-account) | `upstream/oauth_jwt_bearer.py` |
| Capability sync (cron) | `capabilities/scheduler.py` |

## Health & diagnostics

| Question | File |
|---|---|
| Live snapshot endpoint | `api/health_overview.py` |
| Diagnostic bundle endpoint | `api/diagnostic_bundle.py` |
| Operator UI Health panel | `api/operator_ui.py` (search `data-nav="health-overview"`) |
| Operator UI Troubleshooting panel | `api/operator_ui.py` (search `data-nav="troubleshooting"`) |
| Bundle version | `api/diagnostic_bundle.py::_BUNDLE_VERSION` |

## Observability panels (operator UI)

| Page | data-nav | JS loader |
|---|---|---|
| Dashboard | `dashboard` | `loadDashboard()` |
| NHI map | `nhi-map` | `loadNhiMap()` |
| Health & servers | `health-overview` | `loadHealthOverview()` |
| MCP servers | `servers` | `loadServers()` |
| Virtual servers | `vservers` | `loadVservers()` |
| Identities | `identities` | `loadIdentities()` |
| Users | `users` | `loadUsers()` |
| Groups | `groups` | `loadGroups()` |
| Access requests | `access-requests` | `loadAccessRequests()` |
| Admins | `admins` | `loadAdmins()` |
| Events | `events` | `loadAuditEvents()` |
| Admin audit | `admin-audit` | `loadAdminAudit()` |
| Identity providers | `idp-directories` | `loadIdpDirectories()` |
| Secret store | `secret-store` | `loadSecretStoreStatus()` |
| Troubleshooting | `troubleshooting` | (no auto-load; user clicks Download) |

The page-load registry is in `api/operator_ui.py` around line 7050
(`const loaders = { ... }`).

## Settings & config

| Question | File |
|---|---|
| All Settings fields | `config.py::Settings` |
| `VYUU_DEFAULT_TENANT_ID` | `config.py` (search `default_tenant_id`) |
| Audit raw-capture cap | `audit/events.py::configure_raw_capture_cap` |
| Inbound inflight cap | `config.py::inbound_per_tenant_inflight_limit` |
| Capability sync interval | `config.py::capability_sync_interval_seconds` |

## Key UI bits

| Question | File:line |
|---|---|
| Login page tenant auto-resolve | `api/operator_ui.py` (search `default-tenant`), `api/portal_ui.py` (same) |
| Time-window picker JS helper | `api/operator_ui.py::windowSelectorToSinceIso` |
| Health page chart (inline SVG) | `api/operator_ui.py::_renderLatencyChart` |
| Sidebar nav structure | `api/operator_ui.py` (search `class="nav-group"`) |

## Migrations history

```
20260429_0001  registry tables (servers, capabilities)
20260429_0002  virtual_servers + tools + grants
20260429_0003  capability risk_category
20260429_0004  mcp_server health metadata
20260430_*     pypi/binary source types, outbound auth columns
20260501_*     OAuth authcode / JWT-bearer
20260502_0012  sync cadence + drift
20260503_0013  DCR clients
20260504_0014  IDP-1: idp_directories + admin_audit_log + users.idp_directory_id
20260505_0015  TOOL-EVENTS-1: tool_call_events
```

Use `alembic history` for the live list; `alembic upgrade head`
to apply.
