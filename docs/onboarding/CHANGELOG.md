# CHANGELOG

Reverse-chronological. Each entry covers a meaningful landing —
schema migration, new endpoint, breaking config change.

For session-by-session detail (rationale, lab proof, snags hit),
see [`HANDOFF.md`](../../HANDOFF.md).

For pending work + decision log, see [`BACKLOG.md`](../../BACKLOG.md).

---

## 2026-09-02 — SIEM export (Splunk HEC) + OpenTelemetry + UI production polish

**Schema:** `20260902_0027` — `tenant_siem_targets` (FORCE RLS): one
per-tenant Splunk HEC target with a secret-store token reference.

**New packages:** `siem/` (events, HEC client, batching exporter,
target resolution, bridges) and `telemetry/` (no-op `Telemetry` seam +
`OtelTelemetry` behind the optional `[otel]` extra).

**Endpoints (new):** `GET|PUT|DELETE /api/v1/admin/siem/config`,
`POST /api/v1/admin/siem/token`, `POST /api/v1/admin/siem/test`,
`GET /api/v1/admin/siem/status`, `GET /api/v1/admin/telemetry/status`,
`POST /api/v1/admin/telemetry/test`.

**New event families:** sign-ins (console, portal, OIDC, SAML — success
and failure) and per-user tool authorisation (OAuth connect, disconnect,
exchange failures, client-identity resolution, client invalidation) are
now events; admin actions ship at commit; structured logs can ship above
a chosen level. Everything lands as `sourcetype=vyuu:mcp:<category>`.

**Telemetry:** spans `vyuu.mcp.request → vyuu.policy_eval →
vyuu.upstream.call_tool`; metrics `vyuu.tool_calls`,
`vyuu.tool_call.duration`, `vyuu.upstream.duration`,
`vyuu.access_attempts`, `vyuu.auth.logins`, `vyuu.siem.events_sent/
failed`, `vyuu.audit.emit_failures` (bounded attributes).

**Config (new):** `VYUU_SIEM_*` (deployment target), `VYUU_OTEL_*`.

**Operator UI:** two Observability panels (SIEM export, Telemetry);
production polish across both apps — every previously undefined design
token defined, focus/disabled/pressed states, unified panel headers,
serif KPI numerals, quiet status lines instead of JSON dumps, SVG icons
and brand mark in the portal, a shown-once API-key reveal with copy.

## 2026-08-28 — RISK-2 · risk assessment staleness

**Schema:** `20260828_0026` — `capability_fingerprint` on
`mcp_server_risk_assessments`, `inputs_fingerprint` on
`virtual_server_risk_assessments`. A score is now tied to the tool
surface it was computed on; the API and console report `stale`.

**Security fixes from the external review:** session `DELETE` now
requires the session's owner (was unauthenticated); registration
responses redact `auth_env` / `auth_headers` values; `structuredContent`
carried through the response cap (was dropped on every call); orphaned
stdio subprocesses torn down on server delete; portal no longer asks
users to connect OAuth for servers whose `auth_authcode` is JSON null.

## 2026-08-27 — RISK-1 · LLM risk classification, CRED-1 · API-key lifetime policy

**Schema:** `20260827_0024` (`api_key_policies`), `20260827_0025`
(`mcp_server_risk_assessments`, `virtual_server_risk_assessments`,
`tenants.risk_model_*`).

**Endpoints (new):** `/api/v1/admin/risk/*` (model config, key store,
preview, summary), `/api/v1/servers/{id}/risk-assessment`,
`/api/v1/vservers/{id}/risk-assessment`, `/api/v1/api-key-policies/*`.

Vendor-pluggable classifier (Anthropic, OpenAI, Gemini) mapping findings
to the OWASP MCP Top 10 and MCP-in-SoS factors; catalogue chunking at 40
tools per call; reduction arithmetic on exposure; key lifetimes per
user / group / tenant, shortest wins. Console: Risk posture, Risk
classifier settings, MCP server drill-in (Tools / Risk / Details).

## 2026-08-25/26 — MCP-2 (SDK v2 + spec 2026-07-28), EMA-1, JIT-1/2, IDP-3, RETENTION-1, H1

**Schema:** `20260825_0017`–`20260826_0023`.

- **MCP-2** — dual-era inbound (legacy `initialize` sessions and the
  stateless 2026-07-28 revision), SDK v1/v2 compatibility layer, MRTR
  (multi-round tool result) governance with per-kind allow-lists and
  audited refusals, CIMD (Client ID Metadata Documents) inbound and
  outbound with recorded `auth_mechanism`.
- **EMA-1** — MCP Enterprise-Managed Authorization: the gateway is the
  MCP resource server and resource-authorization server (`/oauth/token`
  jwt-bearer exchange, RFC 9728 metadata, ID-JAG validation, scope gating,
  per-directory operator toggle, NHI attestation).
- **JIT-1 / JIT-2** — time-boxed access to private bundles and per-tool
  elevation, self-service via access requests.
- **IDP-3** — per-tenant subdomain slugs; **IDP-2** Google Workspace
  directory polling.
- **RETENTION-1** — opt-in prune windows for both audit tables.
- **H1** — DNS-time SSRF guard on every outbound connection.

---

## 2026-05-05 — TOOL-EVENTS-1, single-tenant mode, Health & servers, onboarding doc set

**Schema:** `20260505_0015` — new `tool_call_events` table (FORCE RLS,
4 composite indexes). Replaces the in-memory ring buffer as the source
of truth for the operator-console Events / NHI map / Identities
panels.

**Endpoints (new):**
- `GET /api/v1/admin/health-overview` — live snapshot for the new
  Health & servers page (KPIs + 5 status tiles + MCP servers table +
  p95/p99 latency chart over 24h)
- `GET /api/v1/auth/default-tenant` — public, returns
  `{tenant_id, display_name}` when `VYUU_DEFAULT_TENANT_ID` is set;
  enables single-tenant on-prem login UX

**Endpoints (refactored — backwards-compatible additions):**
- `GET /api/v1/audit-events` — added `since` / `until` ISO params;
  default window is now last 24h (was: last N events from buffer)
- `GET /api/v1/nhi-map` — same; reads from durable table
- `GET /api/v1/identities` + `/{id}/timeline` — same

**Diagnostic bundle:** v1.0 → v1.1. Added sections: `persistent_audit`,
`audit_buffer_warmup`, `idp_directories`, `admin_audit`,
`background_workers`. JSON shape stays additive.

**Operator UI:**
- New page **Health & servers** under Overview group
- New page **Troubleshooting** under Settings group (diagnostic
  bundle download + window picker + 8-card coverage explainer);
  removed the download button from the Dashboard panel
- Time-window picker (`Last 1h / 24h / 7d / 30d`) added to Events,
  NHI map, Identities

**Config:**
- New env: `VYUU_DEFAULT_TENANT_ID` (UUID, optional). Set for
  on-prem single-tenant; leave unset for SaaS multi-tenant.

**Tests:**
- New: `tests/audit/test_persistent_store.py` (4 tests covering
  emit-persists, query-after-restart, buffer-warmup, RLS isolation)
- Converted to real-DB integration: `test_audit_events_endpoint.py`,
  `test_identities_endpoint.py`, `test_access_attempt_events.py`
- 952 pass with `VYUU_TEST_DATABASE_URL`; 804 pass without (the
  delta is the converted endpoint tests that now need a real DB)

**Docs:**
- New `docs/onboarding/` set (12 files): SETUP, ARCHITECTURE,
  BACKEND, FRONTEND, AUTH, NETWORK, TESTING, RUNBOOK,
  KNOWLEDGE_BASE, BACKEND_DEEP_DIVE, LOW_LEVEL_ARCH, plus the
  index README and (new) API_REFERENCE, MIGRATIONS, SECURITY,
  MCP_SPECIFICS, CHANGELOG.

**Handoff folder:** new a sibling handoff folder clean-room
copy with stripped secrets, ready for tarball + dev-lead handoff.

---

## 2026-05-04 — IDP-1 (Entra ID + Google Workspace SCIM + per-directory SSO)

**Schema:** `20260504_0014`
- New tables: `idp_directories` (FORCE RLS), `admin_audit_log` (FORCE RLS)
- `users`: added `idp_directory_id` FK + `external_id` + `soft_deleted_at`
  + `'scim'` to `auth_method` check constraint
- `groups`: same `idp_directory_id` + `external_id`

**Endpoints (new):**
- Operator: `POST/GET/DELETE /api/v1/idp/directories[/{id}]` — connect
  Entra / Workspace; SCIM bearer returned ONCE on POST
- Public: `POST/GET /api/v1/auth/{tenant}/idp/{dir}/oidc-{start,callback}`
  — per-directory OIDC sign-in
- Public: `GET/POST /api/v1/auth/{tenant}/idp/{dir}/saml-{login,acs,metadata}`
  — per-directory SAML sign-in
- Operator-side mirror at `/api/v1/operator-auth/...` for admin SSO
- Operator: `GET /api/v1/admin-audit` with filters
- SCIM 2.0 server at `/scim/v2/{directory_id}/...` — Users + Groups
  POST/GET/PUT/PATCH/DELETE

**Modules (new):**
- `idp/` — service, schemas, scim_tokens, saml_provider, sweeper
- `scim/` — server, users, groups, auth, schemas, errors
- `audit/admin_audit.py` — same-transaction admin-action emit

**Background workers:**
- `HardDeleteSweeper` — hourly cron, 7-day grace before hard-delete
  of soft-deleted SCIM users

**Operator UI:**
- New panel **Identity providers** under Settings
- New panel **Admin audit** under Observability
- SSO buttons on operator + portal login pages (driven by connected
  IdP directories for the tenant)

**System dep:** `xmlsec1` (used by `pysaml2`). Added to setup docs.

---

## 2026-05-04 — Operator UI tabular redesign (6 panels)

Replaced stacked-card layouts on Events / Identities / Users / Groups /
Access requests / Vservers with a unified pattern: eyebrow + serif H1
+ KPI strip + filter pills + search + table + slide-over drawer +
create-modal.

**Backend** — single-trip aggregate response shapes added:
- `UserListItemResponse` + `list_users_with_aggregates()` (api_key_count,
  group_count, last_api_key_used_at)
- `GroupListItemResponse` + `list_groups_with_aggregates()` (member_count,
  vserver_grant_count)
- `AccessRequestListItemResponse` + `list_access_requests_with_context()`
  (user_email, user_display_name, vserver_name, vserver_visibility,
  decided_by_email)
- `VirtualServerListItemResponse` + `list_virtual_servers_with_aggregates()`
  (tool_count, grant_count)
- Identities aggregator: added `latest_client_name`, `latest_client_version`,
  `latest_user_agent`, `distinct_clients` (drives the "via Cursor 0.42"
  badge)

---

## 2026-05-03 — DCR auto-recovery on `invalid_client` (closes U10)

- `mcp_server_dcr_clients` table seen `invalid_client` from the upstream:
  auto-trigger re-DCR + retry the original OAuth request
- Closes a class of "Notion enterprise rotated their realm" issues

## 2026-05-03 — U7 + U8 + U11 (scheduler authcode resolution, ref-field UX, IAT-gated enterprise DCR)

- Capability sync scheduler now resolves OAuth-AC tokens per-tenant
- Operator UI: `*_ref` fields rendered with a typeahead from the
  secret store
- IAT (Initial Access Token) supported for upstreams that gate DCR

---

## 2026-05-02 — Stress testing baseline + DEVOPS hand-off doc

- `docs/STRESS-TESTING.md` documents methodology + results
- `docs/DEVOPS-HANDOFF.md` documents production-deploy posture
- Lab fixed at p95 latency under load with the inflight gate +
  per-tenant cap

## 2026-05-01 — OAuth JWT-bearer (RFC 7523) for service-account upstreams

**Schema:** `20260501_0011`
- `mcp_servers.outbound_auth_oauth_jwt_bearer` flag
- Per-server JWT signing key ref

## 2026-05-01 — OAuth authcode (RFC 6749) per-user delegated tokens

**Schema:** `20260430_0006_users_groups_grants` + `20260501_*`
- `oauth_user_tokens` table (encrypted access + refresh)
- Per-user portal flow to authorise / revoke connections

## 2026-04-30 — Auth modes + binary upstream support

**Schema:** `20260430_0001..0005`
- `mcp_servers.source_type = 'pypi' / 'binary'` added
- Outbound auth columns: org_tier, user_tier_passthrough, oauth_*
- mTLS support for transport-layer auth

## 2026-04-29 — Initial schema landed

**Schema:** `20260429_0001..0004`
- Core tables: `tenants`, `operators`, `users`, `mcp_servers`,
  `mcp_capabilities`, `virtual_servers`, `virtual_server_tools`,
  `virtual_server_grants`
- RLS enabled on all tenant-scoped tables
- Capability `risk_category` + health metadata columns

---

## Versioning policy

We don't ship semver-tagged releases yet — the project is single-trunk
with continuous deployment to lab. Each "landing" above corresponds to
one or more migrations + the matching code. Tag a release once the
project gets a public consumer that needs version pinning.
