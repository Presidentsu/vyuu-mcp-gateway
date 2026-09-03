# Vyuu MCP Gateway — Backlog

The durable list of "what's left to do" for the gateway. Updated whenever an item is sized, decided on, or split.

`HANDOFF.md` is the chronological session log + how-to-resume. This file is the to-do list — re-organized over time as priorities shift.

**Current state at the top of this backlog (2026-05-02, post E2E proven + 11 hotfixes + UX-1/2/3 polish):** 829 tests passing, 0 skipped (with full integration env vars set: Postgres + Redis + NATS + drawio), ruff + mypy clean across 191 source files. **GitHub Copilot MCP** (auth_authcode → real `Presidentsu` profile via Cursor) and **CrowdStrike Falcon MCP** (auth_env → 78 capabilities synced) both proven end-to-end against real upstreams. Eleven hotfixes shipped during the run — see HANDOFF.md for the full table. **UX polish landed on top of the working E2E**: portal env pill now reads from `/api/v1/health` (env + version); Tool history page shows three KPI cards (Calls 7d / Distinct tools / Blocked) backed by a new `tool-history-summary` endpoint over the audit ring buffer; connections panel converted from card-grid to a 5-column table (Account / Scope / Last refreshed / Expires / Disconnect) with a Quick-connect grid below for un-authorised OAuth MCPs. **DELETE /api/v1/servers/{id}** endpoint shipped with cascade-summary response + UI Delete button on every row. **End-user portal `/portal` redesigned end-to-end** to match the Claude Design slates: 248px sticky sidebar app-shell with sectioned nav (`Get started` · `Discover` · `My account`), topbar with breadcrumb + env pill, new Home page (saffron greeting + IDE-config setup card + your-access rail + pending requests + last-5 tool calls), Tool catalog as 2-col bundle-card grid with saffron / amber / grey status pills + filter pills (`All bundles` / `Open to me` / `Needs request` / `Restricted`), live nav-count badges per section, sessionStorage-persisted last-visited nav. New backend endpoint `GET /api/v1/portal/{tenant_id}/recent-tool-calls` surfaces the in-memory `RecentAuditEmitter` ring buffer scoped to the calling user's API keys (extended `RecentAuditEmitter.query()` with a `principal_id_in: frozenset[str] | None` filter; 3 new tests cover empty / filter / cross-tenant cases). Removed the SURFACE toggle from the portal sidebar (it was mock-only; portal users don't need to switch surfaces). **Lab moved from port 8765 → 8000** (`examples/drawio_lab_server.py`, `.claude/launch.json`) so the GitHub OAuth callback at `localhost:8000/api/v1/oauth-authcode/callback` lands on the same gateway process. **MCP server registration is a 5-step wizard** (Runtime → Connection → Authentication → Capabilities → Review) — the existing flat `Register MCP server` form is wrapped as a UX layer with a saffron progress rail, per-step body cards, sticky live-preview rail (manifest JSON + checklist), and a Back / Continue / Register footer. `+ Register` flips `body[data-wizard-active="true"]` and the table panel hides; Cancel or successful submit closes back to list. Per-step gates: step 1 needs runtime + display_name, step 2 needs source_location, step 3 reuses the live `register-preview-checklist-list` (every required field saffron), steps 4–5 are optional / final. Step 4 wires the existing `POST /api/v1/servers/from-manifest` endpoint as an optional manifest-URL preflight. The OAuth preset monkey-patch now also dispatches a synthetic `input` event so form-level listeners (the wizard's gate) re-evaluate after a preset fill. **Per-server capability-sync cadence** lands as `mcp_servers.sync_cadence_minutes` (NULL = use global default; 0 = manual-only / scheduler skip; positive int = throttle to N minutes, capped at 30d). The periodic scheduler now filters `_is_due_for_sync(server, now)` before each cycle so per-server overrides actually take effect. UI: per-row dropdown (Default / Hourly / 6h / Daily / Weekly / Manual only) → `PATCH /api/v1/servers/{id}/sync-cadence`. **Visual diff on capability-sync** lands as `mcp_servers.last_sync_drift` JSONB — both sync paths (upstream probe + manual seed) now serialise the drift + per-entry `risk_category` so the operator console can paint a `+N −M ~K since last sync` pill in the Server cell (risk-toned: `delete` / `admin` / `credential_access` / `data_export` / `execute` → red, plain add/change → amber, removed-only → grey). Click → row drawer in `mode: "drift"` showing three risk-pilled sections. **Notification bell + alert feed** ships as a thin shell over the existing `RecentAuditEmitter` ring buffer — sidebar-foot trigger with danger-toned badge (count of denied / blocked / errored tool calls in the last hour), click → overlay listing recent alert rows, polls every 60 s, no-ops when not signed in. Designed so anomaly alerts on N1 swap in as a data-source upgrade with no UI changes. **Global ⌘K search palette** wires the topbar pattern from the Claude Design handoff — an overlay (triggered from a sidebar-foot button or ⌘K / Ctrl+K from anywhere) that searches across `serversCache`, `principalCache.users`, `principalCache.groups`, and a palette-local `vserversCache`, lazily fetching whichever cache is empty on first open. Results are grouped by kind (MCP servers / Virtual servers / Users / Groups), navigable via ↑/↓, opened via Enter (routes through `setActiveNav`), capped at 25 hits. **Inline rename_map in the Publish vserver drawer** — drawer rows are now a 2-col grid (`checkbox + tool name | rename to: <input>`) so operators can disambiguate collisions without dropping back to the standalone form. **Inline group editor with member chips** — each group card is self-contained: live "MEMBERS · N" count, saffron chip per member with × removal, an Add row whose dropdown filters out current members + disables when everyone's in. Backed by a new `GET /api/v1/groups/{id}/members` endpoint + `users_service.list_group_members` (joins `user_group_memberships`). **Operator console self-stamps every panel with a mono `as of HH:MM:SS` pill** next to the Refresh button after each load — closes the auto-refresh feedback loop. **Light/dark theme toggle and cozy/compact density toggle** sit in the sidebar foot, persist to `localStorage` (`vyuu_ui_theme`, `vyuu_ui_density`), and restore before paint. **Register MCP form is now a 2-col layout** with a sticky right-rail JSON preview pane that mirrors the exact POST shape + a per-mode required-fields checklist (saffron when satisfied) — operators see what they're about to ship before they hit Submit. **Empty + loading state copy upgraded** across every panel: "No admins." / "(no grants)" replaced with action-oriented hints; `Loading...` normalized to `Loading…`. **The MCP servers panel is a proper table** (Server / Runtime / Auth mode / Tools / Health / per-row Sync + Publish vserver), with search bar + runtime filter pills (All · HTTP · stdio·npm · stdio·pypi · stdio · binary) and a single shared row-drawer for the Publish flow. **The standalone Gateway-health card is retired** — replaced with a small status pill in the sidebar foot that reads `service · version`, color-coded dot. **Virtual servers are a mock-aligned 2-column card grid** with the vServer mark prominent, status dot + serif name, visibility pill, lazy-loaded tool count, saffron-tinted mono /v URL with one-click Copy, and a clean action bar. **Auto-refresh on nav switch** (no more clicking Refresh on every panel) and **inline "Publish vserver" drawer on each MCP server card** (sync → pick tools → create, all in one place — no more cross-panel choreography) shipped 2026-05-02. Open items from the Claude Design handoff that didn't make this batch are inventoried below in the new "Operator UI · open items derived from the Claude Design handoff" section. **Two real fixes from preview-session feedback:** (a) 500 on admin `/servers` list — `OAuthAuthCodeSpec.redirect_uri` strict-HTTPS validator now permits HTTP only on localhost / 127.0.0.1 / ::1 hosts, matching Google's own documented exception; (b) Register form replaced its dense JSON-blob auth inputs with a 6-card mode picker (None / Org headers / Pass-through / OAuth M2M / OAuth user / JWT-bearer) + per-mode structured field groups. Provider preset popovers now fill the structured fields directly (auto-flips mode + walks the preset shape). **Operator console is now a proper app shell — 248px sticky sidebar with grouped nav (Overview / Catalog / Identity & access / Observability / Settings), one visible section at a time via `.is-hidden` JS toggle, persisted last-visited nav in sessionStorage, auto-jump from signin → dashboard on auth. Page height dropped from 11,655 px (single stacked scroll) to ~720–2,300 px per focused section.** **Mini-marks (NHI / vServer / ToolCall) + Register-form completion (auth_authcode + auth_jwt_bearer + mtls_cert_ref / key_ref) + OAuth provider preset side-popovers (GitHub / Google Drive / Slack / Notion / MS Graph / Atlassian) shipped 2026-05-01.** Operator can now configure A1 / A2 / mTLS upstreams from the UI; clicking the `i` next to an auth field opens a popover with one-click provider presets that pre-fill the JSON correctly (Google Drive's `access_type=offline` baked in). Cards in Identities / Virtual servers / Events now carry distinctive geometric marks rather than relying on text alone. **Dashboard panel + NHI map + Users-admin drill-in shipped 2026-05-01.** Operator console now opens with a KPI grid (NHIs, sanctioned MCPs, MCPs in use, pending access requests, high-risk calls 24h, denied/errored 24h, OAuth-connected SaaS), followed by a 4-column "People & AI — who uses what" bipartite SVG (Users / AI Apps / MCP Servers / Agents — dashed for unsanctioned clients, edge thickness ∝ interaction count). Existing Users panel gained per-user "Show activity" + "API keys" expanders; admin can revoke API keys directly with confirmation. Brand chrome now matches the Vyuu design system voice — eyebrow "MCP SECURITY · Govern every tool call". **A1 (per-user OAuth authorization-code), M-A1.5 (mTLS upstream), A2 (RFC 7523 JWT-bearer SA flow), and N1 + N2 + N3 (NHI dashboard + relation graph + radial SVG visualisation) all shipped 2026-05-01.** The Identities tab in `/operator` now lists every principal seen in the recent-events buffer with risk-class histogram, drill-in timeline, dependency-graph SVG, and risk-score summary. New endpoints `/api/v1/identities`, `/api/v1/identities/{id}/timeline`, `/api/v1/identities/{id}/summary`, `/api/v1/identities/{id}/graph`, `/api/v1/who-can-do?tool_name=...&risk_floor=...`. Outbound auth modes now fully cover: `auth_headers` (org-tier static KMS), `auth_passthrough` (user-tier inbound forwarding), `auth_oauth` (M2M client_credentials, phase 3), `auth_authcode` (per-user delegated, phase 4 / A1), `auth_jwt_bearer` (asymmetric service-account, RFC 7523 / A2), and transport-layer `mtls_cert_ref` + `mtls_key_ref`. All five OAuth-style modes are mutually exclusive via schema validation; mTLS coexists with any of them as a transport-layer credential.

Portal UI now surfaces "Connect to {SaaS}" + "Reconnect" buttons on catalog cards for vservers wrapping `auth_authcode` upstreams, plus a "My connections" tab with disconnect. State-token CSRF (HS256, 10-minute TTL) protects the OAuth callback; the callback renders an HTML success page rather than raw JSON.

**Portal UI uses the Vyuu Design System** (cream/ink/orange palette, Fraunces/Inter/JetBrains Mono type, pill-rail tabs, responsive cards-as-grid via `auto-fill, minmax(300px, 1fr)`) with search + filter toolbars on Catalog / My requests / My API keys / My connections panels. Operator + portal surfaces visually consistent. Connection-level access attempts land in the operator-console Events panel. Operator login flow (`POST /api/v1/operator-auth/login`) + Admins panel. Audit-capture-by-default flag (`VYUU_AUDIT_CAPTURE_RAW_DEFAULT=true`) flips H5 raw-input/output capture on for dev/POC. SecretStore backends: `memory` / `vault` / `aws_secrets_manager`. Inbound identity: `api_key` / `fake`. **All four A3 phases + A3.x + quick-wins + customer batch + A6/H5/S8/H2 + A6.x + operator-login + access-attempt-telemetry + portal-design-baseline + A1 + M-A1.5 + A2 shipped.** Identity: bcrypt local + Microsoft Entra ID + Google Workspace OIDC + portal sessions + JIT provisioning. UIs: `/portal` (end-user; catalog with per-vserver config snippets for Cursor + Claude Desktop, Connect buttons for OAuth-authcode upstreams) + `/operator` (admin with full A3 panels + γ queue + visibility/grants editors). Audit: per-call auth-mode flags (A5 + A1 + A2 + mTLS) + in-memory `RecentAuditEmitter` ring buffer. Stdio launch hardening: `allowed_npm_packages` + `allowed_pypi_packages` content allowlists (H4). Source types: HTTP, stdio, npm via npx, pypi via uvx, binary.

---

## How to read this backlog

Each item carries:

- **Effort** — rough person-day estimate. ✱ = back-of-envelope, may double under load.
- **Depends on** — items that should land first.
- **Why** — the customer / operational reason it matters. If this section is hand-wavy, the item probably isn't ready to start.
- **Status** — `pending` (no design), `designed` (decision made, code not started), `partial` (some pieces shipped), `parked` (deliberate non-decision).

Within each section, items are listed roughly in enterprise-impact order — not strict priority, but a reasonable starting point.

---

## Auth & identity

### JIT-1 · Just-in-time (time-boxed) vserver access — SHIPPED 2026-08-25

Standing access is what this removes. Before JIT, a user who needed a
private vserver once got a grant that never expired, and the tenant
slowly accumulated permanent authority nobody revisited.

- **Effort:** 1.5 days ✱ (actual: ~1 day)
- **Depends on:** A3-γ (access-request queue), A3-α (users/grants)
- **Status:** shipped

**The enforcement path needed no change.** `virtual_servers/access.py`
already skipped grants past their `expires_at`, and
`_authenticate_and_authorize` re-runs that check on **every** inbound
request rather than once per session — so an elevation that lapses
mid-session cuts off at the caller's next tool call, with no sweeper, no
session invalidation, and no revocation broadcast. JIT only adds the
policy deciding *how long* and *on whose say-so*.

**What landed**

- **Migration `20260825_0018`.** `virtual_servers` gains the per-vserver
  policy (`jit_enabled`, `jit_max_duration_seconds`, `jit_auto_approve`,
  `jit_require_justification`); `access_requests` gains
  `requested_duration_seconds`; `virtual_server_grants` gains
  `granted_via` + `justification`, and `granted_by` becomes **nullable**.
  Downgrade round-trip verified.
- **`registry/jit_service.py`.** Auto-approve mints the grant inline;
  everything else queues into the *existing* operator approval queue
  carrying the duration. One queue, not two.
- **`GET /api/v1/vservers/jit/elevations`** — who is elevated right now,
  soonest-expiring first, including operator-issued time-boxed grants
  (`granted_via` distinguishes them).
- **`PATCH /api/v1/vservers/{id}/jit`** — policy, audited both ways.
- **`POST /api/v1/portal/{tenant}/jit-requests`** +
  **`GET .../vservers/{id}/jit-options`** — the end-user path, with the
  policy served rather than hard-coded in the SPA.
- **Both UIs.** Operator: a JIT column on the vservers table, a
  **LIVE ELEVATIONS** strip above the approval queue (hidden when nobody
  is elevated), and an approve prompt that offers to trim the window.
  Portal: "Get / Request temporary access" on catalog cards, and a
  dashed **Temporary · 42m left** pill when the access a user already
  holds is itself an elevation.

**Decisions worth remembering**

- **`granted_by` is nullable.** An auto-approved elevation has no
  operator behind it, and attributing it to a sentinel operator row would
  put a human's name on a decision they did not make. `granted_via`
  carries provenance, so NULL is never ambiguous.
- **Over-ceiling requests are rejected, not clamped.** A user who asks
  for 8 hours, is silently given 4, and plans a migration around access
  they do not have is worse off than one who is told no. The ceiling
  rides on the error so the caller can retry correctly.
- **An approver may grant less than was asked for, never more.** More is
  never the reviewer's intent; it is a typo, and a silent one if allowed.
- **JIT cannot be enabled on a `public` vserver.** It needs no grant, so
  there is nothing to elevate into — the button would grant access the
  user already has.
- **Justification defaults to required.** A JIT grant with no stated
  reason is worse for an auditor than a standing grant: it also lacks the
  deliberation a standing grant implies.

**Tests:** `tests/users/test_jit_access.py` (15 service) +
`tests/users/test_jit_api.py` (6 HTTP). Three negative controls run and
all three fail correctly: making the inbound path ignore `expires_at`,
making approval issue standing access, and clamping instead of rejecting.

### JIT-2 · Per-tool just-in-time elevation — SHIPPED 2026-08-26

JIT-1 elevates into a whole vserver. JIT-2 elevates into a **single
tool** — "let me run `db.migrate` for 20 minutes" while holding ordinary
standing access to the rest of the bundle.

- **Effort:** 2 days ✱ (actual: ~1 day)
- **Depends on:** JIT-1, EMA-1 P3 — both shipped
- **Status:** shipped

**The open question is settled: an elevation REQUIRES existing vserver
access.** A tool elevation narrows; it never grants. Letting it imply
vserver access would create a second path to the same resource, and two
paths to one resource is how authorization systems become unauditable —
"how did they get in?" stops having a single answer.

**What landed**

- **Migration `20260825_0020`** — `virtual_server_tool_grants` (its own
  table, not a nullable `tool_name` on `virtual_server_grants`: that table
  is read as "may this principal reach this vserver" by the inbound check,
  the catalog, the identity graph and the NHI map, and a tool column would
  change the meaning of every existing row for every query that forgot to
  filter on it). Plus `virtual_servers.jit_tools` and
  `access_requests.exposed_tool_name`.
- **`jit_tools` is independent of `jit_enabled`** — deliberately. The
  primary case is standing bundle access with one dangerous tool gated,
  on a vserver whose whole-bundle JIT is *off*. Coupling them would make
  the main case unreachable.
- **Gate in `tool_calls/lifecycle.py`**, immediately after the EMA-1 scope
  gate, so a denial is a `tool_call` event **naming the tool**
  (`policy_rule_id=no_tool_elevation`) rather than an opaque 403.
  **Fails closed** on every "can't tell": no checker wired, non-user
  principal, lookup raises. A gate that opens when it cannot establish
  authority is not a gate.
- **`DatabaseToolElevationChecker`** — RLS-bound, supports group
  elevations, one query per gated call.
- **One approval queue**, not two: `access_requests` carries the tool
  name. The partial-unique index became
  `(user_id, vserver_id, COALESCE(exposed_tool_name, ''))` — `COALESCE`
  because NULLs compare *distinct* in a Postgres unique index, which would
  have quietly dropped the original one-pending-per-(user, vserver)
  guarantee.
- **`expires_at` is NOT NULL** on tool grants: a permanent per-tool grant
  is an ordinary vserver grant with extra steps.
- Both UIs: operator sees tool elevations in the same LIVE ELEVATIONS
  strip (badged `TOOL`) and configures gated tools per vserver; the portal
  renders one row per gated tool inside a bundle the user can already
  reach.

**Tests:** 7 no-DB gate tests + 11 real-DB. Four negative controls, all
failing correctly: failing open with no checker, ignoring `expires_at`,
ignoring the tool name, and dropping the vserver-access requirement.

### IDP-1 · Entra ID + Google Workspace SCIM provisioning + sign-in — SHIPPED (backlog corrected 2026-08-25)

**Backlog correction:** still marked "IN PROGRESS 2026-05-04", but all
five sub-phases below are in the tree and tested:

1. Schema + admin audit — migration `20260504_0014`.
2. SCIM 2.0 server — `scim/` package. *Was silently broken by FORCE RLS
   until BUG-SCIM-1 was fixed today; the tests that would have caught it
   were being dismissed as environment noise. See that entry.*
3. Hard-delete sweeper — `idp/sweeper.py`, 7-day grace, audited.
4. Sign-in flows — `api/idp_signin.py`, OIDC + SAML per directory, JIT
   user creation.
5. Operator console — Identity providers panel + Admin audit log panel.

Only remaining sub-item is the optional real-Keycloak integration test
(A3-β.x below), which is a test-infrastructure task, not IDP-1 scope.


End-user directory integration: Entra and Google Workspace push user /
group lifecycle events into the gateway via SCIM 2.0; admin-chosen
sign-in protocol (OIDC or SAML) authenticates those users into the
portal. Local-auth users keep working side-by-side.

- **Effort:** 5–6 days ✱
- **Depends on:** A3 (end-user identity foundation, shipped) — extends the
  existing `users` / `groups` tables with `(idp_directory_id, external_id)`
  pairs, no schema replacement.
- **Status:** in progress 2026-05-04
- **Why:** unblocks selling to any tenant with > ~20 users. Manual user
  creation doesn't scale, and security-conscious orgs want HR's IdP to
  drive lifecycle (de-provisioning the moment HR terminates someone).
- **Sub-phases:**
  1. **Schema + admin audit** — `idp_directories`, `admin_audit_log`
     tables; extend `users` / `groups` with FK to directory + external_id;
     `auth_method` gains `'scim'`.
  2. **SCIM 2.0 server** — `/scim/v2/{directory_id}/Users` +
     `/Groups`. Bearer auth via the directory's minted token. Common impl
     covers both Entra (`Operations[]` PATCH) and Workspace (`members[]`).
  3. **Hard-delete sweeper** — soft-disabled SCIM users get hard-removed
     after a 7-day grace; every step recorded in `admin_audit_log`.
  4. **Sign-in flows** — both OIDC and SAML wired per-directory; admin
     picks the protocol at IdP-connect time. JIT user-row creation for
     races where SSO arrives before SCIM.
  5. **Operator console** — Identity providers panel (under SETTINGS),
     Admin audit log panel (under OBSERVABILITY).
- **Decisions locked 2026-05-04:**
  - Entra + Workspace only (no generic SCIM connector).
  - OIDC + SAML both, admin chooses per directory.
  - Secrets: existing `secret_store` (Vault/Postgres) — KMS upgrade
    captured separately under "AWS KMS · Envelope encryption" below.
  - Deprovisioning: soft-disable on SCIM-deactivate, hard-delete after
    7 days, every step audited.
  - Group nesting: flat only.

### EMA-1 · Adopt MCP Enterprise-Managed Authorization (ID-JAG) as an inbound auth mechanism — SHIPPED 2026-08-25 (P1+P2+P3)

Consume the MCP **Enterprise-Managed Authorization** extension (ID-JAG,
now stable; Okta first IdP, Asana/Atlassian/Canva/Figma/Linear/Supabase
already adopting). Lets enterprises centrally govern MCP access in their
own IdP (Okta/Entra) while Vyuu remains the runtime enforcement +
observability point. Strategically: EMA commoditizes the inbound
connection-auth layer but **explicitly cedes** the data path (the spec:
the IdP's visibility "does not extend to the actual MCP traffic") — i.e.
everything that is our moat. Adopting it makes us standards-native and
positions Vyuu as the **EMA bridge** for the long tail of MCP servers
that will never implement EMA themselves.

- **Full design + code-level adoption guide:** [`docs/implementation/EMA-1-adoption-guide.md`](docs/implementation/EMA-1-adoption-guide.md)
- **Effort:** 8–12 days ✱ (P1 provider 2–3 · P2 bridge 3–5 · P3 governance/UX 3–4)
- **Depends on:** IDP-1 (reuses `idp_directories` trust config, `users/oidc.py::JwksCache`, and the `_find_or_jit_create_user` JIT pattern). A3 identity foundation.
- **Status:** **P1 + P2 + P3 all shipped 2026-08-25.**
  Landed: `migrations/20260825_0016` (`idp_directories.ema_enabled / ema_audience /
  ema_jwks_uri / ema_allowed_client_ids` + `ema_consumed_jti` replay table, ENABLE-RLS);
  `api/ema_oauth.py` — RFC 9728 protected-resource metadata at the path-insertion form
  + `POST /v/{tenant}/oauth/token` (jwt-bearer grant) validating the IdP-signed ID-JAG
  (issuer→directory, JWKS sig, `aud`, `resource`→vserver-in-tenant, client allowlist,
  single-use `jti`) then minting a short-lived **HS256** Vyuu token;
  `identity/jwt_bearer_provider.py` — hot-path verify (no JWKS, no async, no network);
  `identity/chain.py` — ordered fall-through (API-key leg → EMA leg, each fast-rejecting
  the other's bearer shape); `identity/models.py` + `audit/events.py` gain
  `FEDERATED_USER` (free-text `principal_type` ⇒ no migration) so NHI separates
  enterprise-federated callers, carrying the IdP `sub` + the MCP `client_id`;
  `idp/service.py::find_or_jit_create_directory_user` — the `(directory_id, external_id)`
  JIT rule refactored out of `idp_signin.py` so OIDC sign-in, SAML sign-in and ID-JAG
  exchange share ONE matching rule; inbound 401s now advertise `WWW-Authenticate: Bearer
  resource_metadata="…"`; sweeper prunes expired `jti` rows.
  **Real bug found + fixed en route:** `virtual_servers/access.py` gated private-vserver
  grants on `principal.type == API_KEY`, which would have silently denied every federated
  user — now accepts any principal type that resolves to a `users.id`.
  Tests: 15 (`tests/identity/test_idp_jag_provider.py` 9 no-DB unit incl. a
  session-factory that raises if touched, proving the hot path does no DB work before
  token validation; `tests/api/test_ema_oauth.py` 6 real-Postgres, driving an RSA-signed
  ID-JAG from a fake Okta whose JWKS is served over `MockTransport` → mint → `/mcp`).
- **P3 shipped:** migration `20260825_0017` adds
  `virtual_servers.required_scopes` (JSONB `exposed_tool_name -> scope`,
  deliberately symmetric with the existing `rename_map` on the same row —
  chosen over a `virtual_server_tools` column because the resolver's
  three-way-join row shape is duplicated across several test fakes, and
  the map is needed exactly where the vserver row is already loaded).
  `ResolvedToolsList` carries it out of the resolver; the lifecycle gates
  on it after tool resolution and before policy, so a denial is a
  `tool_call` event naming the tool (Events panel) rather than a bare
  connection-level 401. New `PolicyDenyReason.INSUFFICIENT_SCOPE` +
  `ToolCallStatus.INSUFFICIENT_SCOPE`. `FederatedUserPrincipal.scopes`
  is parsed from the token's space-delimited `scope` (RFC 6749 §3.3).
  `PATCH /api/v1/idp/directories/{id}/ema` enables/disables EMA per
  directory + sets the client allowlist, audited as
  `idp.ema_enable` / `idp.ema_disable`; the audience defaults to the
  canonical per-tenant issuer the RFC 9728 metadata already advertises
  (an explicit value still wins) so it cannot drift by typo, and EMA
  cannot be enabled on a directory with no `oidc_issuer` to anchor
  trust. Operator console gains an **AGENT AUTH (EMA)** column with an
  inline enable/disable whose confirm text states the blast radius.
  NHI map now classifies the AI-app column from the IdP-attested
  `client_id` (carried on `client_metadata`, no migration) in preference
  to the self-declared user-agent. Portal API-keys page reveals an
  "your organisation uses SSO for AI tools" notice when any connected
  directory is EMA-enabled.
- **P3 decision — scope gating FAILS CLOSED:** a principal carrying no
  scopes at all (an API key — scopes are an EMA concept) is denied on a
  scope-gated tool, because it cannot demonstrate the required
  authority. `required_scopes` is empty by default, so no existing
  deployment changes behaviour; opting a tool in is a deliberate
  operator act. Flip this to "scope only narrows principals that carry
  scopes" if a customer needs service keys to bypass.
- **New env vars:**
  `VYUU_EMA_ENABLED` (default false — master switch; the whole surface 404s when off),
  `VYUU_EMA_SIGNING_SECRET` (≥32 bytes enforced at boot; signs inbound access tokens —
  deliberately NOT the operator secret so rotating one doesn't log the other out),
  `VYUU_EMA_ACCESS_TOKEN_TTL_SECONDS` (default 900),
  `VYUU_PUBLIC_BASE_URL` (outside origin behind a proxy — builds the per-tenant
  resource-AS issuer that ID-JAG `aud` must match).
- **Why:** EMA went stable and is being adopted across the ecosystem.
  Enterprises will expect "no per-app OAuth — provision MCP access in our
  IdP." If we don't consume it we look behind; if we do, we delete a
  chunk of our own auth plumbing AND become the enforcement layer their
  IdP can't be. Net tailwind — *if* we ship it.
- **Architectural rule:** it's **one new `IdentityProvider`**. The single
  integration seam is `api/inbound_mcp.py:300`
  (`identity_provider.validate_principal(...)`). Everything downstream
  (tenant bind → vserver+grant authz → policy → upstream cred broker →
  audit/NHI) is unchanged.
- **Sub-phases:**
  1. **P1 — consume EMA tokens:** `IdpJagIdentityProvider` +
     `ChainedIdentityProvider` (ApiKey → EMA); validate token, map `sub`
     → `User` (JIT), access-attempt audit on failure.
  2. **P2 — be the Resource Authorization Server (the bridge):** RFC 9728
     protected-resource metadata per vserver + `/v/{tenant}/oauth/token`
     (jwt-bearer grant) — validate the IdP-signed ID-JAG against the
     directory JWKS (async, off the hot path), mint a short-lived
     **Vyuu-signed** access token. Hot path verifies the Vyuu token with a
     sync HMAC (no JWKS on the hot path).
  3. **P3 — governance + UX:** scope→tool gating **AND-combined** with
     existing grants/policy; per-vserver `client_id` allowlist; operator
     console enable-toggle + EMA identities in NHI; portal "no key
     needed" messaging.
- **Decisions locked (recommended in the guide):**
  - Build through P2 (the bridge) as the spine, not P1-only — keeps JWKS
    off the hot path and delivers the long-tail-server value.
  - New `PrincipalType.FEDERATED_USER` (2-line enum addition; principal
    free-text in `tool_call_events`, no migration) for clean NHI; reuse
    JIT-to-`User` so grants/groups/audit/RLS all work uniformly.
  - Scope semantics: **AND** with Vyuu grant/policy (defense in depth) —
    keeps our call-time kill-switch meaningful, which EMA structurally
    lacks (no revocation, no traffic visibility).
  - Vyuu access token = HS256 JWT signed with `VYUU_EMA_SIGNING_SECRET`.
  - ID-JAG `jti` replay cache (Redis if present, else Postgres + sweeper).
- **Schema delta:** one migration (`idp_directories.ema_enabled`,
  `ema_audience`, `ema_jwks_uri`, `ema_allowed_client_ids`); optional
  `ema_consumed_jti` replay table; no vserver schema change (resource id
  derived from the connect URL).
- **Backward-compat:** additive + feature-flagged (`VYUU_EMA_ENABLED`,
  per-directory `ema_enabled`). `vyuu_user_*` API keys keep working
  unchanged; both can be used interchangeably by the same caller.

### MCP-2 · Adopt MCP spec 2026-07-28 + Python SDK v2 — SHIPPED (P1+P2+P3)

**P2 shipped 2026-08-26.** The codebase now runs on **both** SDK lines:
the full suite passes on `mcp==1.27.0` **and** `mcp==2.1.1` — 897 tests,
identical on each.

`src/vyuu_gateway/mcp/sdk_compat.py` is the single place that knows which
SDK is installed. It is scaffolding, not architecture: when the pin moves
to `mcp>=2` every branch in it collapses.

**The migration was much smaller than feared — and much sharper.**
`ClientSession`, `streamable_http_client`, `sse_client` and `stdio_client`
all survive v2. What actually breaks:

| v1 | v2 | Where |
|---|---|---|
| `mcp.shared.exceptions.McpError` | `mcp.MCPError` | import |
| `McpError(ErrorData(...))` | `MCPError(code=, message=)` | constructor |
| `Tool.inputSchema` / `.outputSchema` | `.input_schema` / `.output_schema` | attribute |
| `CallToolResult.isError` | `.is_error` | attribute |
| `read_timeout_seconds: timedelta` | `: float` | signature |
| transport yields `(read, write, get_session_id)` | `(read, write)` | arity |
| `httpx.AsyncClient` | `httpx2.AsyncClient` | transport arg |
| `FastMCP` | `mcp.server.mcpserver.MCPServer` | test fakes |
| `stateless_http` on the constructor | on `streamable_http_app()` | test fakes |

**Two real bugs the migration exposed, both silent:**

1. **`model_dump()` stopped producing the wire format.** v2 snake_cased the
   Python attributes but *kept* the camelCase wire aliases. So a bare
   `model_dump()` — correct on v1, where field names already were wire
   names — emits `is_error` and `input_schema` on v2. Nothing errors: the
   gateway returns 200, the JSON looks plausible, and every MCP client
   silently stops seeing the fields. Fixed by routing every wire boundary
   through `dump_wire()`, which forces `by_alias=True` (a no-op on v1).
2. **The legacy `initialize` advertised the stateless protocol version.**
   The handler echoed the SDK's `LATEST_PROTOCOL_VERSION`, which means
   "newest this SDK knows" — a different thing from "the version this
   handshake implements". Under v2 that constant became `2026-07-28`, the
   *stateless* revision that has no `initialize` at all, so a stateful
   handshake was answering "I speak the stateless protocol". v2's own
   client rejects it, correctly. Now pinned as our own
   `LEGACY_PROTOCOL_VERSION` — serving a protocol version is a commitment
   we make, and it must not change because a dependency shipped a release.

   Related: v2 models default `result_type="complete"`, which leaked
   `resultType` into legacy responses. `dump_wire` strips
   `MODERN_ONLY_RESULT_FIELDS`, so era-specific fields now come only from
   era-specific code.

**Still pinned to `mcp<2`.** The proof is our suite plus fake upstreams;
interop with the real third-party MCP servers this gateway fronts (GitHub
Copilot MCP, CrowdStrike Falcon, drawio) has only been exercised on v1.
Flipping is one line in `pyproject.toml` plus adding `httpx2` — do it
after a lab run against v2. v1.x is still maintained, so nothing forces
the date.

**Tests:** `tests/mcp/test_sdk_compat.py` (13) encode the invariants and
run on whichever SDK is installed, so the suite itself answers "is the
flip safe?".

---

#### P3 — SHIPPED 2026-08-26, built as a separate path

Developed as **new modules, off by default**, so the shipped dual-era
inbound path is untouched until each surface is deliberately enabled.
Nothing in P3 changes existing behaviour yet.

**1. MRTR as a policy surface — CORE LANDED.**
`src/vyuu_gateway/mcp/mrtr.py` + 20 tests.

The 2026-07-28 revision lets a tool answer `tools/call` with
`InputRequiredResult` instead of a result. What it can ask for is not
data, it is *capability*:

- `sampling/createMessage` — it drives the CALLER'S LLM (prompt injection
  using the caller's model, quota and context).
- `roots/list` — the caller's filesystem roots: a map of the machine.
- `elicitation/create` (form) — a prompt rendered to the human under a
  schema the upstream chose.
- `elicitation/create` (**url**) — it sends the human to a URL of its
  choosing, with a message of its choosing. *"Your session expired,
  re-authenticate at `https://not-really-okta.example`"* is a well-formed
  MRTR response, arriving through the same channel as a legitimate
  result, inside a tool call the user already consented to. **This is
  phishing as a protocol feature.**

Decisions:

- **Default-deny every kind**, which is not a new restriction: SDK v2's
  `call_tool(allow_input_required=False)` already refuses these. What
  changes is that the refusal becomes visible, attributed and explained
  instead of surfacing as an opaque upstream error.
- **Each kind enables independently.** Turning on form elicitation must
  not turn on sampling — they buy very different amounts of trust.
- **`UNKNOWN` cannot be enabled even deliberately.** A policy listing
  every enum member still refuses unclassifiable requests.
- **A round is all-or-nothing.** Partially satisfying it leaves the
  upstream waiting on a request that will never be answered and the
  caller holding a half-finished call it cannot reason about.
- **Classified by `method` string, not `isinstance`** — the MRTR types
  only exist on SDK v2, and an upstream is not obliged to send something
  our SDK version can parse.
- URL-elicitation host allowlisting requires a real label boundary:
  `okta.com` matches `login.okta.com` but not `evil-okta.com`. Same trap
  as the tenant-subdomain parser.

**2. MRTR wired into the tool-call path — LANDED.** The gate sits where
the upstream response comes back, so a refusal is a `tool_call` audit
event carrying the kinds and the destination URL. "An upstream tried to
send your user to not-really-okta.example" is the finding; a 400 with no
event is not. `_upstream_failure_result` gained a decision override so
the refusal records as a **deny** — a timeout is an ALLOW that failed
upstream, but this is the gateway refusing, and an operator filtering the
Events panel for denials has to see it. Config:
`VYUU_MRTR_ALLOWED_INPUT_KINDS` (empty = deny all) and
`VYUU_MRTR_ALLOWED_ELICIT_URL_HOSTS`. A typo'd kind name **fails
startup** rather than silently disabling the allowlist.

**3. RFC 9207 — Authorization Server Issuer Identification — LANDED.**
The expected issuer is signed into the OAuth `state` at initiate time,
not re-derived at callback time: the state is what ties a response to a
request, so the expectation must be captured when the request is made.
Both entry points (portal Connect and operator Test-connect) carry it —
one without it would silently lose mix-up protection while the other had
it. A mismatched `iss` is refused **before** the code is exchanged, which
is the whole point. A *missing* `iss` is accepted with a log line: most
static providers we front publish no metadata and never send it, and
rejecting would break all of them while stopping no attacker, who can
omit the parameter equally.

**4. DCR `application_type: "web"` — LANDED.** Not just the default:
some AS apply *stricter* redirect_uri rules to `native` clients, so an AS
inferring `native` from an omitted field can silently relax the check
protecting our callback.

**5. CIMD — LANDED (outbound half).** `api/cimd.py` serves the document
at `/.well-known/oauth-client`, mounted at the ROOT because the URL *is*
the client_id and cannot sit behind an `/api/v1` prefix a version bump
would move. `upstream/oauth_cimd.py` decides per-AS from
`client_id_metadata_document_supported`.

Why it matters beyond being newer: every DCR registration is a credential
pair both sides must store, sync and rotate — `U10 · DCR auto-recovery on
invalid_client` exists because that drifts in production. CIMD has nothing
to drift: no secret, no stored registration, revocation is "stop serving
the document".

The decision **falls back to DCR, not closed** — inverting the rule used
elsewhere, and deliberately: both paths grant *identical* authority (same
redirect URI, same scopes, same token), so the choice is a mechanism
decision, not a trust decision.

**6. CIMD inbound half + call-site wiring — LANDED 2026-08-26. P3 is
now complete.**

*Wiring.* `_resolve_client_id_and_auth_url` offers our document URL to
`discover_and_register`, which decides at the point the AS metadata is
already in hand — one discovery implementation, two mechanisms, rather
than a competing second probe. `mcp_server_dcr_clients` gained
`auth_mechanism` and a nullable `registration_endpoint` (migration
`20260826_0023`), because a CIMD row records no registration and a
placeholder there would read as a fact.

The non-obvious part is the **failure mode that had to be designed
away**. `invalid_client` means opposite things per mechanism: for DCR the
registration was evicted, so dropping the row and re-registering fixes
it; for CIMD nothing was registered, so dropping the row would re-probe,
read the same (unchanged) advertisement, present the same refused URL and
fail identically — a permanent Connect failure assembled from two
individually-correct behaviours. A refused CIMD row is therefore **marked
`cimd_rejected`, not deleted**, and that tombstone is what makes the
documented fall-back to DCR actually happen instead of looping.

*Inbound half.* `identity/cimd_inbound.py` resolves an inbound client_id
that is an https URL against the document behind it. What the fetch buys
over string-matching an allowlist is **revocation** — CIMD's revocation
story is "stop serving the document", and a gateway that never fetches
can never observe it, so an allowlisted client stays valid forever
including after its own operator has decommissioned it — plus a real
`client_name` in the audit trail instead of an opaque URL.

Four bounds make the SSRF acceptable, and all four are load-bearing:

1. **Only allowlisted client_ids are ever fetched.** The membership check
   runs *first*; the `allowlist and …` term in `ema_oauth.py` says the
   same thing from the other side, since an empty allowlist means nothing
   vouched for the URL. Without this an unauthenticated caller could name
   any URL and use the gateway to probe our network or amplify traffic at
   a third party. Two tests assert zero outbound requests in exactly
   those cases.
2. **Every fetch goes through `ssrf_guard.py`** — and the resolver takes
   a *transport*, not a client, so no caller (tests included) can opt out
   of the one control that makes the module safe.
3. **Redirects refused.** Following one would move the fetch to a host
   nobody allowlisted and would break the self-identification check.
4. **Answers cached, negatives too** — otherwise every token request is a
   fetch, which reintroduces the amplification (1) removes.

**Failing closed here inverts the outbound rule, deliberately.** Outbound,
CIMD and DCR grant identical authority, so falling back costs no security.
Inbound, the document is how we learn *who the caller is* and no second
mechanism establishes the same fact — treating "the fetch failed" as
"identity confirmed" would make the check worse than not having it.

Off by default (`VYUU_EMA_CIMD_RESOLUTION_ENABLED`): enabling makes an
allowlisted client's uptime part of this gateway's auth path. Surfaced in
the Security posture panel as `info` when off — string matching is not
unsafe, only blind to revocation, and that trade is an operator's to make
rather than be nagged into.

32 tests. P1 (dual-era inbound) shipped 2026-08-25; P2 (SDK v2)
2026-08-26; P3 complete 2026-08-26.

### IDP-3 · Subdomain-per-tenant portal routing — SHIPPED 2026-08-26

`acme.gateway.example.com` resolves Acme without anyone pasting a UUID.

- **Effort:** ~1 day code + ~½ day ops (actual: ~½ day code)
- **Status:** shipped; wildcard DNS + wildcard cert remain a deployment task

**The design deviates from the original sketch, deliberately.** That
sketch called for a `Host`-header dispatcher in `main.py` exposed as a
request-scope dependency for portal + operator routes. It is not needed:
every route is already `/{tenant_id}/…` path-scoped, and after login the
session token carries the tenant. The subdomain only has to answer *which
login page to render* — so extending the existing
`GET /api/v1/auth/default-tenant` was enough, and both login pages already
consume it. Subdomain routing landed with **no change to either page**.

**The security property that matters:** `Host` is client-supplied, so
resolving a tenant from it **grants nothing**. Authentication runs
unchanged and the session token carries the tenant it was minted for. The
worst a forged `Host` achieves is showing someone the wrong login form.
`test_host_resolution_grants_nothing` pins this; if it ever fails,
subdomain routing has become tenant confusion.

**What landed**

- **Migration `20260825_0021`** — `tenants.slug`, unique among non-NULLs,
  with a DB CHECK enforcing a legal DNS label. The constraint is not
  redundant with app validation: a slug containing a dot silently extends
  the subdomain, and the DB is the one place every writer passes through.
- **`api/tenant_routing.py`** — `slug_from_host` handles the cases a naive
  implementation gets wrong: suffix confusion
  (`acme.gateway.example.com.evil.com`), a bare `endswith` without the dot
  separator, multi-label subdomains, ports, trailing dots, and reserved
  labels (`www`, `api`, `admin`, …).
- **Rejects rather than slugifies.** "Acme Corp" fails instead of becoming
  `acme-corp` — a silently-transformed slug is a hostname the operator did
  not choose and will not predict.
- **`GET/PATCH /api/v1/tenant/settings[/slug]`**, audited both ways, with
  the resulting `portal_url` served rather than assembled client-side so
  the console cannot show a hostname the gateway would not honour.
- Operator console: a SIGN-IN ADDRESS strip on the identity-providers
  panel, hidden entirely when the deployment has no base domain.

**Tests:** 33. Four negative controls, all failing correctly: `endswith`
without the dot, `split(".")[0]`, allowing reserved labels, and dropping
uniqueness.

### IDP-2 · Google Workspace polling adapter — SHIPPED 2026-08-26

Migration `20260826_0022` + `idp/workspace_polling.py`, per-directory
opt-in, 5-minute default cadence.

**The original sketch is not implementable as written, and that is worth
recording.** It had the poller POST to our own `/scim/v2/...` endpoint
"as an internal SCIM client" — but we store `scim_token_hash`, a bcrypt
digest. The plaintext bearer is shown to the operator once at connect
time and never persisted, so the gateway cannot authenticate to its own
SCIM endpoint, by design. Calling `scim/users.py`'s service functions
directly is better anyway: no self-HTTP, no self-auth, no second copy of
the reconciliation rules — and identical audit rows, because those
functions are what write them.

**Deactivate, never delete — and only on a complete listing.** Polling
has a failure mode a push does not: "absent from the response" and
"deleted" are the same observation, so a transient error mid-pagination
would read as a mass termination. `list_workspace_users` raises rather
than returning a partial page, `reconcile` refuses to act on absence
unless the listing completed, and the poller has no hard-delete path at
all — the existing sweeper's 7-day grace is what makes a wrong answer
recoverable.

`suspended` and `archived` both count as inactive: Google models them
separately, but treating archived as active would leave departed staff
with working credentials.

**Tests:** `tests/idp/test_workspace_polling.py` (22). Four negative
controls; the unbounded-pagination one hangs forever, which is precisely
the failure it guards against.

Original entry follows.

### IDP-2 · Google Workspace polling adapter — DESIGNED, NOT STARTED

**Why**: Custom SAML apps in Google Workspace **don't support
auto-provisioning via SCIM** — that's reserved for apps in Google's
catalog (Slack, Salesforce, Notion, Atlassian, etc.) where Google has
built and tested a per-app connector. Custom SAML apps you create
yourself only get SAML SSO. So our SCIM endpoint never gets a push
from Google Workspace — Workspace tenants effectively run on
JIT-create at first sign-in, with manual deactivation.

**Fix**: Roll our own polling adapter. Google's Admin SDK Directory
API exposes `users.list` and `users.delete` events. With a Service
Account + domain-wide delegation, we can:

1. Poll `users.list?customer=my_customer&query=isAdmin=false` on a
   cadence (5min default).
2. Diff against our `users` table for rows where
   `idp_directory_id = <workspace_dir_id>`.
3. POST new users to our own `/scim/v2/<dir>/Users` endpoint
   internally; PATCH `active=false` on suspended/deleted users.
4. Reuse the existing SCIM bearer + endpoint — adapter is just an
   internal SCIM client running inside the gateway.

**Effort**: ~1 day ✱
- Service Account auth + domain-wide delegation setup docs
- Polling loop in `idp/workspace_polling.py` (mirrors
  `HardDeleteSweeper` shape: `start()` / `stop()` /
  `run_one_cycle()`)
- `idp_directories` extension: `workspace_service_account_ref`
  (secret-store key) + `workspace_customer_id` columns
- Operator-console UI extension on the Workspace connect modal:
  "Service account JSON ref" field + "Customer ID" field

**Depends on**: IDP-1 phase 1 (schema, SCIM server, audit log) —
shipped 2026-05-04.

**Status**: designed, not blocking initial IDP-1 build.

### A1 · OAuth 2.0 authorization-code flow (phase 4) — shipped 2026-05-01

Per-user delegated tokens. The "Connect to GitHub / Notion / Drive" UX
slate.

- New `mcp_servers.auth_authcode` JSONB column +
  `oauth_user_tokens` table (access + refresh tokens per
  (tenant, user, server), unique-per-principal-server constraint,
  RLS-bound for cross-tenant defence).
- `OAuthAuthCodeTokenProvider` (DB-backed, per-user
  `asyncio.Lock` for single-flight refresh, RFC 6749 §6 refresh-
  rotation honoured, 60s safety buffer, lazy-loaded so PyJWT
  crypto extras stay off the import-time hot path).
- `principal_id` threaded through `fetch_token` /
  `OutboundMcpClient.call_tool` / `PooledOutboundMcpClient` /
  `ToolCallLifecycle` — same pool key (no per-user fragmentation),
  per-call principal lookup. Phase-3 ignores it; phase-4 raises
  `OAuthTokenError("user must connect first")` when missing or no row.
- Endpoints under `/api/v1/oauth-authcode/`: `{server_id}/initiate`
  (signed-state-token JWT, returns IdP authorize URL), `callback`
  (no auth header — state IS auth, upserts on reconnect, renders
  HTML success page), `connections` (list user's tokens, no
  plaintext returned), `{server_id}/connection` DELETE.
- Portal UI: `requires_user_auth_servers` field on each catalog
  entry surfaces wrapped upstreams needing per-user OAuth; "Connect"
  / "Reconnect" buttons on catalog cards; "My connections" tab with
  Disconnect; HTML success page on callback.
- Schema validation: HTTPS-only on all three URLs, no whitespace in
  scopes, mutually exclusive with `auth_oauth` and `auth_jwt_bearer`,
  no Authorization-header collision with `auth_headers` /
  `auth_passthrough`, HTTP-only.
- 33 new tests (10 token-provider unit, 7 schema validation, 12
  endpoint integration vs real Postgres, 1 catalog requires-auth
  surfacing test, 3 hot-path `principal_id` threading, audit flag
  test).

### M-A1.5 · mTLS upstream auth — shipped 2026-05-01

- New `mcp_servers.mtls_cert_ref` + `mtls_key_ref` columns
  (SecretStore refs to PEM-encoded cert + key).
- `MtlsClientCredential` dataclass + `_build_mtls_ssl_context`
  helper that materialises through `tempfile` only briefly (scratch
  files unlinked the moment `load_cert_chain` returns).
- Plumbed into `StreamableHttpMcpClient` (cached SSLContext on the
  pooled httpx client + reused on per-call OAuth one-shots) and
  `SseMcpClient` (custom `httpx_client_factory` plumbed into the
  MCP SDK's `sse_client`).
- Schema: both refs must be set together; HTTP-only; coexists
  freely with header / OAuth modes (transport-layer credential).
- `auth_mtls=true` flag stamped on AuditEvent when both refs set.
- 7 new tests (4 schema validation, 3 provider builder with
  `cryptography`-generated self-signed cert).

### UI-SURF · Surface the 2026-08 features in the operator console — SHIPPED 2026-08-26

Everything shipped in the JIT / IDP / MCP-2 / AWS-KMS batches was reachable by
API but invisible in the console. This closed that gap and, by driving the
result in a browser, found two defects the test suite had not.

**New: Security posture panel** (`api/security_posture.py`, 17 tests).
`GET /api/v1/security-posture` returns eight `ControlStatus` rows — envelope
encryption, MRTR, SSRF guard, binary provenance, CIMD, EMA, RFC 9207, secret
store backend — each with `enabled`, the **consequence of its current state**
in plain language, the env vars that change it, and a severity. Rows sort
`warn → info → good`. MRTR's severity is deliberately inverted from intuition:
deny-all is `good`; the `warn` is url-elicitation allowed with no host
allow-list. `cimd_client_id` is offered only over https.

Rationale: several of these controls default **off** on purpose. That is only
defensible if turning them on is discoverable, which means the console has to
say what staying off costs.

**Also shipped:**
- vservers panel gained a JIT column (`auto · ≤2h` / `1 tool` / `n/a · public`)
  and a LIVE ELEVATIONS strip ordered soonest-expiring-first.
- Portal shows `Temporary · Nm left` and a `TOOLS NEEDING TEMPORARY ELEVATION`
  row with per-tool ceilings.
- IdP `LAST SCIM` column → kind-aware `PROVISIONING` (`polling · …` / `manual`
  for Workspace, SCIM wording elsewhere). It previously read `SCIM · never` for
  Workspace directories that have no SCIM by design — an alarming cell
  describing correct behaviour.
- `PATCH /idp/directories/{id}/workspace-polling` + prompt-chain UI, refusing
  to enable without all three fields (a poller that silently never runs looks
  exactly like a directory with nothing to sync).
- `kubernetes` added to the secret-store recommendations/switch instructions.

**Two defects found only by using the UI:**
1. `jit_tools` missing from `VirtualServerResponse` *and*
   `VirtualServerListItemResponse` — the gated-tool count always read zero.
2. `PATCH …/workspace-polling` 500'd: `_to_response()` needs a `Request` the
   handler never passed, raising **after** commit — the change applied while
   the operator saw a failure. Covered now by
   `tests/idp/test_workspace_polling_api.py` (6 tests). The lesson worth
   keeping: the fault was in FastAPI dependency wiring, so no amount of
   service-layer testing would have caught it. Endpoints need endpoint tests.

### Operator UI · items derived from the Claude Design handoff — ALL SHIPPED (backlog corrected 2026-08-26)

**Backlog correction:** the heading still said "open items", but every
entry below is marked shipped inline except *Tweaks panel + design canvas*,
which the list itself calls out as dev scaffolding deliberately out of
scope. Nothing here is pending. Retitled so it stops reading as a work
queue — the same stale-entry problem corrected for IDP-1 / A4 / H3.

The 2026-05-01 / 2026-05-02 batches shipped most of the design's
high-leverage patterns: mini-marks, sidebar app-shell, OAuth
preset popovers, structured per-mode auth fields, inline Publish
vserver drawer, auto-refresh on nav switch, brand chrome alignment.
What the mock proposed but the gateway DOESN'T have yet — sized
honestly so a future operator-UX session has a punch list:

- **Auto-refresh on nav (shipped 2026-05-02)** + **per-panel "as of
  HH:MM:SS" timestamp (shipped 2026-05-02)**. The dispatch table in
  `setActiveNav` now stamps a mono pill next to each Refresh button
  via `markAsOf()` after the loader resolves.
- **Live JSON manifest preview** in a right rail of the Register
  MCP form (shipped 2026-05-02). 2-col `.register-layout` grid with
  a sticky `.register-preview` rail showing pretty-printed JSON
  payload + a per-mode required-fields checklist that turns saffron
  when satisfied. `buildPreviewPayload` mirrors `serializeAuthFields`
  exactly so the preview is what gets POSTed.
- **Search bar (⌘K palette) (shipped 2026-05-02)** — global
  overlay (triggered from sidebar-foot button or ⌘K / Ctrl+K
  from anywhere) over `serversCache`, `principalCache.users`,
  `principalCache.groups`, and a palette-local `vserversCache`.
  Skipped the originally-sized backend search endpoint — the
  in-memory caches are already populated by the existing list
  endpoints, lazy-fetching only when empty. Tools-search not
  included in v1 (would need a fan-out across server
  capabilities); revisit if operators ask for it.
- **Notification bell (shipped 2026-05-02)** — sidebar-foot trigger
  with danger-toned badge (count of deny / block / error events in
  last hour), click → overlay with alert-row list. Polls every 60 s.
  Filters the existing `RecentAuditEmitter` ring buffer client-side
  — no new backend endpoint. Anomaly alerts on N1 (still pending
  in the Auth & identity section above) will swap in as a richer
  data source with no UI changes required.
- **Density toggle (shipped 2026-05-02)** — `.ui-pref-row` in the
  sidebar foot, `[data-density="compact"]` overrides the cozy
  `--vyuu-pad-card` / `--vyuu-pad-row` tokens plus a few selector-
  level tightenings; persisted in `localStorage` as
  `vyuu_ui_density`.
- **Light/dark theme toggle (shipped 2026-05-02)** —
  `[data-theme="dark"]` token block now actually applied; sidebar-foot
  toggle persists `vyuu_ui_theme` in `localStorage` and restores it
  on page boot before paint to avoid a flash-of-wrong-theme.
- **Empty + loading state copy upgrade (shipped 2026-05-02)** —
  every panel's terse one-word empty state ("No admins.", "No groups.",
  "(no grants)") rewritten as action-oriented hints; `Loading...`
  normalized to `Loading…` everywhere.
- **Inline tool-spec rename map (shipped 2026-05-02)** —
  Publish drawer rows are now a 2-col grid (`checkbox + tool name
  | rename to: <input>`); empty / identity-rename inputs are
  skipped on submit, light client-side regex guard for the rename
  format. Drawer stacks under 580px viewports.
- **Per-server sync cadence (shipped 2026-05-02)** — new
  `mcp_servers.sync_cadence_minutes` column (migration
  `20260502_0012`); NULL = global default, 0 = manual-only
  (scheduler skip), N>0 = throttle to every N minutes (Pydantic
  cap at 30d). New `PATCH /api/v1/servers/{id}/sync-cadence`
  endpoint + per-row dropdown in the operator console. The
  periodic scheduler's `_is_due_for_sync` filter applies the
  override per cycle.
- **Visual diff on capability-sync (shipped 2026-05-02)** — same
  migration adds `mcp_servers.last_sync_drift` JSONB. Both sync
  paths persist the drift + per-entry `risk_category` after each
  run; UI renders a risk-toned `+N −M ~K since last sync` pill
  in the Server cell, click opens a row drawer with three sections
  (added / changed / removed) carrying risk pills. Holds only the
  most recent snapshot (per the original sizing note); a future
  multi-run history table can extend this if customers ask.
- **Group editor inline (shipped 2026-05-02)** — each group
  card now renders live "MEMBERS · N" count + a flex-wrapping
  row of saffron chips (one per member, × button) + an
  Add row whose dropdown filters out current members and
  disables when everyone's in. Optimistic updates with
  inline status. New backend endpoint
  `GET /api/v1/groups/{id}/members` +
  `users_service.list_group_members(...)` join.
- **Tweaks panel + design canvas + Vyuu Deck slides** — dev
  scaffolding from the mock; not user-facing operator code.
  Intentionally not on this list.

### Operator UI · mini-marks + Register-form completion + OAuth preset popovers — shipped 2026-05-01

Three pragmatic patterns ported from the Claude Design handoff bundle
(skipped the over-reach: full sidebar reflow, 5-step wizard, AI-Shield
branding bleed):

- **Mini-marks** for the gateway's three core primitives. Geometric
  SVG glyphs in the saffron + sienna + ocean palette — `markNHI()`
  (human silhouette in a hex machine ring), `markVServer()` (three
  stacked plates fanning out), `markToolCall()` (chevron envelope
  around a centered dot). Wired into Identities / Virtual servers /
  Events card renderers via the new `.has-mark` CSS hook.
- **Register form completion**. The form previously only supported
  `auth_oauth` (M2M); operators had to curl the API for everything
  else. Now `auth_authcode` (A1), `auth_jwt_bearer` (A2),
  `mtls_cert_ref`, and `mtls_key_ref` are first-class fields with
  correct payload serialisation (JSON for the auth_* objects, scalar
  string for the mTLS refs).
- **OAuth provider preset popovers**. Click the `i` next to an auth
  field → side popover with field-specific copy + provider rows →
  one click fills the JSON shape correctly. Six providers shipped:
  GitHub, Google Drive (with `access_type=offline + prompt=consent`
  baked in to ensure refresh tokens), Slack, Notion, Microsoft
  Graph, Atlassian. Visual ack via one-shot flash animation on the
  populated field. Adding a new provider is a one-entry edit to
  `OAUTH_PROVIDER_PRESETS`.

UI-only changes; existing JS-syntax test covers the new JavaScript
via `node --check`. See HANDOFF.md "Sub-session — 2026-05-01 (Claude
Design handoff)" for the full slate, including the patterns we
intentionally skipped.

### Operator dashboard + NHI map + Users-admin drill-in — shipped 2026-05-01

Top-of-page admin surfaces aligned with the Vyuu design system:

- **Dashboard** — `GET /api/v1/admin/dashboard` aggregates 7 KPIs in one
  shot. KPI grid uses the `kpi-label` / `kpi-value` / `kpi-delta`
  pattern from the design handoff (Fraunces 36px display value,
  Inter eyebrow label). Tone variants (`alert` / `warn`) tint the
  value when the metric is non-zero in a way that demands attention.
- **NHI map** — 4-column bipartite SVG (Users / AI Apps / MCP Servers /
  Agents). `GET /api/v1/nhi-map` classifies inbound clients via
  `client_metadata.user_agent` against a known-clients allowlist
  (Cursor, Claude Desktop, ChatGPT, Continue, Cline, Zed, Goose,
  Windsurf). Edge thickness scales with interaction count; unknown
  clients render dashed; sanctioned-only filter. Brand-coloured legend.
- **Users-admin drill-in** — existing Users panel in `/operator` gained
  two per-row expanders. "Show activity" pulls `principal_summary`
  (risk score, OAuth connections, reachable upstreams). "API keys"
  pulls + lists; admin can revoke keys with confirmation
  (`DELETE /api/v1/users/{id}/api-keys/{key_id}` already existed).
- **Brand chrome** — hero eyebrow + heading match the design system's
  voice ("MCP SECURITY · Govern every tool call"). Logo lockup served
  from `/operator/logo.svg`.

10 new tests (4 admin-dashboard, 6 NHI-map). See HANDOFF.md
"Sub-session — 2026-05-01 (Dashboard + NHI map + Users admin)" for
the full slate.

### N1 + N2 + N3 · NHI dashboard, relation graph, and visualisation — shipped 2026-05-01

End-to-end identity surface for the gateway:

- **N1** — `/operator` Identities panel + `audit/identity_aggregator.py`
  + `GET /api/v1/identities` + `GET /api/v1/identities/{id}/timeline`.
  Per-principal call counts, distinct vservers/upstreams/tools touched,
  per-RiskCategory histogram, high-risk-only toggle, drill-in timeline
  with risk-floor filter.
- **N2** — `graph/identity_graph.py` query layer + three HTTP reads:
  `principal_summary` (granted vservers + exposed tools with risk +
  reachable upstreams + OAuth connections + risk_score 0..100),
  `who_can_do` (reverse permission query, with optional risk_floor),
  `dependency_chain` (principal → vserver → tool → upstream node + edge
  graph).
- **N3** — Inline radial-layered SVG visualisation on each identity
  card. Concentric rings by node kind; tool nodes fill-tinted by
  risk so high-privilege capabilities pop visually. Plus a "Show
  summary" expander rendering the risk-score badge + OAuth
  connections + reachable upstreams.

38 new tests (9 aggregator unit, 10 list/timeline endpoint unit,
10 graph-layer integration vs real Postgres, 5 graph-endpoint
integration). Reuses existing tables — no new schema. See
HANDOFF.md "Sub-session — 2026-05-01 (NHI dashboard + relation
graph)" for the full slate.

### A2 · OAuth 2.0 JWT-bearer / service-account flow (RFC 7523) — shipped 2026-05-01

Asymmetric service-account identity. Workspace SAs (Drive, Calendar,
Gmail), AWS IAM Roles Anywhere, vendor APIs that mandate signed JWT
exchange.

- New `mcp_servers.auth_jwt_bearer` JSONB column. Config carries
  `{token_url, algorithm, private_key_ref, issuer, subject, audience,
  scope?, additional_claims?, assertion_ttl_seconds?, key_id?}`.
- `OAuthJwtBearerTokenProvider` — same caching contract as phase 3
  (asyncio.Lock single-flight, 60s safety buffer); on each refresh
  signs a fresh assertion JWT with the resolved private key and
  POSTs `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&
  assertion=<jwt>` to the token endpoint.
- Schema: HTTPS-only token URL, allowed algorithms RS256/RS384/
  RS512/ES256/ES384/PS256 (symmetric / `none` rejected),
  `additional_claims` cannot redefine reserved claims (iss/sub/aud/
  exp/iat/nbf/jti — schema enforced + provider re-checks at sign
  time), `assertion_ttl_seconds` capped at 600 (RFC 7523 §3 says
  short-lived). Mutually exclusive with `auth_oauth` and
  `auth_authcode`. HTTP-only. No Authorization-header collision.
- Workspace impersonation works out of the box: `subject` ≠ `issuer`
  threads the impersonated user-email into the assertion's `sub`
  claim. Google-specific in-assertion `scope` lands via
  `additional_claims={"scope": "https://www.googleapis.com/auth/..."}`.
- `auth_oauth_jwt_bearer=true` flag stamped on AuditEvent.
- 17 new tests (9 provider unit with real RSA keypair + assertion
  signature round-trip via `_StubAuthServer`, 8 schema validation,
  1 provider-builder integration).

### A3-α · End-user identity foundation — shipped 2026-04-30

`users` / `groups` / `user_group_memberships` / `virtual_server_grants` /
`user_api_keys` tables; bcrypt password handling; `ApiKeyIdentityProvider`
(bearer-only, ignores `x-vyuu-*` headers); visibility flip + grant
enforcement on inbound MCP route; admin API for users / groups / API
keys / grants / visibility; first-run env-var bootstrap. See HANDOFF.md
"Sub-session — 2026-04-30 (A3-α)" for the full slate.

### A3-β · OIDC + login flow — shipped 2026-04-30

JWKS cache (~5min TTL, single-flight refresh on `kid` miss); RS256 JWT
validation (signature / `iss` / `aud` / `exp` + optional Google `hd` pin);
`MicrosoftEntraIdProvider` + `GoogleWorkspaceProvider` (per-tenant Entra
issuer, hosted-domain-pin Google); HS256 portal session JWTs; login
endpoints `POST /auth/{tenant_id}/login`, `GET /auth/{tenant_id}/oidc/{provider}`,
`POST /auth/{tenant_id}/oidc/{provider}/callback` (state CSRF prefixed
with tenant_id, anti-enumeration generic 401, JIT-provisioning of OIDC
users via `upsert_oidc_user`). 17 new tests (8 OIDC unit with generated
RSA keys + mock httpx, 4 session JWT round-trip, 5 login endpoint).
Deferred: real-Keycloak integration test (env-gated on
`VYUU_TEST_KEYCLOAK_URL`) — its own infra slice. See HANDOFF
"Sub-session — 2026-04-30 (A3-β)" for the full slate.

### A3-β.x · Real-Keycloak OIDC integration test — SHIPPED 2026-08-26

`tests/idp/test_oidc_keycloak_integration.py` (8), env-gated on
`VYUU_TEST_KEYCLOAK_URL`, provisioning its own realm/client/user through
the admin API — no realm export to drift against a Keycloak version.

**Run against a real Keycloak 26 before landing, which mattered.** Three
things an untested docstring would have got wrong, all found by actually
running it: `KEYCLOAK_ADMIN` was renamed to `KC_BOOTSTRAP_ADMIN_USERNAME`;
the master realm's `sslRequired=external` 403s every plain-HTTP admin call
from inside Docker; and Keycloak's default user profile requires
first/last name, without which every grant fails `invalid_grant` — a
message that says nothing about missing names. Exact commands are in the
module docstring.

**A negative control caught a vacuous test.** The original "token from
another realm is rejected" passed with issuer checking disabled, because
`JwksCache` derives the JWKS URL from `issuer_url` — so a wrong issuer
fails at *key lookup*, never reaching the claim comparison. Replaced with
a tampered-signature test (which can only pass if the live key is really
verifying) and a wrong-audience test (`aud` genuinely is a claim check).
Issuer binding is now asserted on the outcome, with a comment recording
that two layers enforce it.

Original entry follows.

### A3-β.x · Real-Keycloak OIDC integration test

- **Effort:** ~half day
- **Depends on:** A3-β (shipped) + Keycloak in CI
- **Status:** pending — placeholder skipif in `tests/users/test_login_endpoint.py`
- **Why:** β's unit tests cover the JWKS+JWT path with generated RSA keys + a mock httpx — that's the meaningful security check (signature, iss, aud, exp, hosted_domain). What's missing is the *full* OIDC handshake against a real IdP: discovery doc fetch, JWKS fetch from a real URL, code→token exchange, ID token signed by the IdP's actual rotation key. A Keycloak realm with a pre-configured client + test user, env-gated on `VYUU_TEST_KEYCLOAK_URL`, exercises the full provider plumbing including `httpx`-bound discovery + token-endpoint integration.
- **Sub-features:**
  - `docker-compose.test.yml` (or doc-only ladder) standing up Keycloak with a seeded realm export.
  - Env-gated test in `tests/users/test_oidc_keycloak_integration.py` that runs full initiate→callback flow.

### A3-γ · End-user request / admin approval workflow — shipped 2026-04-30

`access_requests` table + service + REST API:
- End-user (portal-session JWT): `POST/GET/DELETE /api/v1/portal/{tenant_id}/access-requests[/{id}]` to submit, list-mine, withdraw.
- Admin (operator JWT): `GET /api/v1/access-requests`, `POST .../approve` (atomically creates a `VirtualServerGrant`), `POST .../decline` (with optional note).
- Idempotent approval: if the user gained access in parallel, approve still succeeds without duplicate-grant-creation.
- Partial unique index `(user_id, vserver_id) WHERE status='pending'` enforces single-pending-per-target.
- Anti-enumeration on withdraw: a user trying to withdraw someone else's request gets 404, not 403.
- 25 new tests. The operator-UI queue panel lands with A3.x; the end-user request form lands with A3-δ. See HANDOFF "Sub-session — 2026-04-30 (A3-γ)" for the full slate.

### A3-δ · End-user portal UI — shipped 2026-04-30

Single-file vanilla-JS portal at `/portal` (HTML/CSS/JS as Python string
constants, mirroring `/operator`). Login screen → dashboard with four
panels: Catalog (public/private + access/locked badges, "Request access"
button on locked rows), My access requests (with withdraw on pending),
My API keys (self-issue with one-shot plaintext display + revoke), Change
password (local-auth only, gated on current password). Backed by 6 new
JSON endpoints under `/api/v1/portal/{tenant_id}` (whoami, catalog, list/
issue/revoke API keys, rotate password). 11 new tests. All four A3 phases
now complete. See HANDOFF "Sub-session — 2026-04-30 (A3-δ)" for the full
slate.

### A3.x · Operator UI extensions for users / groups / grants / access-request queue — shipped 2026-04-30

Three new panels on `/operator` ("Pending access requests", "Users",
"Groups") plus a "Manage access" expander on every vserver card carrying
the visibility toggle and grant editor. Approve creates a grant inline;
decline records a note. No new tests — exercises the already-tested α/γ
admin endpoints. Two trivial test-helper updates were needed to thread
the now-required `visibility` field through the response schema. See
HANDOFF "Sub-session — 2026-04-30 (A3.x)" for the full slate.

### A3.y · Lab integration with `ApiKeyIdentityProvider` — shipped 2026-04-30

`VYUU_LAB_USE_API_KEY_IDENTITY=1` flips `examples/drawio_lab_server.py`
from `FakeIdentityProvider` to the production `ApiKeyIdentityProvider`.
Banner prints which mode is active and how to flip it. Lab's debug
upstream wrapper got a `get_auth_mode_flags` passthrough so A5's audit
signal stays intact through it. See HANDOFF "Sub-session — 2026-04-30
(Quick-wins batch)" for the full slate.

### A4 · 401-driven token refresh on top of phase 3 / phase 4 — SHIPPED (backlog corrected 2026-08-25)

**Backlog correction:** this was still marked `pending`. It is
implemented — `_looks_like_unauthorized()` in `mcp/outbound.py` drills
through anyio `BaseExceptionGroup` wrappers and matches either an
`httpx.HTTPStatusError` status code or the 401/unauthorized/invalid_token
phrasing the MCP SDK surfaces, then invalidates and retries once.
Covered by `tests/upstream/test_oauth_401_refresh.py` (8 tests, passing).
The "catch" the original entry worried about — that the SDK abstracts
away upstream HTTP responses — was solved with the conservative
heuristic rather than by subclassing the SDK transport.

Original entry retained below for context:

- **Effort:** 0.5 day ✱
- **Depends on:** A1 (for phase 4) or just phase 3
- **Why:** Today if a cached token expires mid-call (clock skew between gateway and auth server, or auth-server-side revocation), the call fails and operator must re-sync. Adding a "401 → invalidate + retry once" path makes auth resilient. Catch: the MCP SDK's `streamable_http_client` largely abstracts away upstream HTTP responses, so detecting 401 specifically requires either subclassing the SDK transport or a small protocol-level shim. Worth measuring real-world flake rates before adding.

### A5 · Audit signal for which auth model fired per call — shipped 2026-04-30

`AuthModeFlags` Pydantic model on every `AuditEvent` carries
`auth_org_tier` / `auth_user_tier_passthrough` /
`auth_oauth_client_credentials`. Computed per call by
`DatabaseBackedUpstreamClientProvider.get_auth_mode_flags(tenant_id,
server_id)` — soft-fails to all-False when the server can't be looked
up so audit emission never breaks the request path. `auth_jwt_bearer`
slot reserved for A2. See HANDOFF "Sub-session — 2026-04-30 (Quick-wins
batch)" for the full slate.

### A6 · Per-tenant secret store implementations — Vault shipped 2026-04-30

`VaultSecretStore` (KV v2) lives at
`vyuu_gateway/secrets/vault.py` with full Protocol-compliant lookups,
404 → not-found mapping, 403 / 5xx → backend-error mapping (no
masking of permission errors as missing-secret), per-tenant URL
prefix (`{mount}/data/{tenant_id}/{ref}`), optional Vault Enterprise
namespace header, configurable `value_field`, lazy httpx client.
Wired via `VYUU_SECRET_STORE_BACKEND=vault` + `VYUU_VAULT_ADDR` +
`VYUU_VAULT_TOKEN`. 13 new tests. AWS Secrets Manager + k8s-secrets
follow the same Protocol — lift-and-shift now that Vault is reference.
See HANDOFF "Sub-session — 2026-04-30 (A6 Vault + H5 + S8 + H2)" for
the full slate.

### A6.x · AWS Secrets Manager — shipped 2026-04-30

`AwsSecretsManagerStore` lives at
`vyuu_gateway/secrets/aws_secrets_manager.py`. Same Protocol as Vault.
Path layout `{prefix}/{tenant_id}/{ref}` matches Vault's per-tenant
URL prefix → IAM resource-ARN templating just works. Auth via boto3
default credential chain (IAM keys / IAM Roles Anywhere / instance
profile / pod identity). 15 tests via `botocore.stub.Stubber` (no
live AWS). Wired via `VYUU_SECRET_STORE_BACKEND=aws_secrets_manager`
+ `VYUU_AWS_REGION`. Critical error-mapping discipline preserved:
AccessDeniedException is NEVER masked as not-found.

**Operator-console "Secret store" panel** added on `/operator`
(between Groups and Tool-call activity): shows active backend, no-cost
connectivity health probe (Vault `/sys/health` or AWS `list_secrets`),
recommendation context (memory = dev only, Vault = POC + on-prem,
AWS = AWS-native), and copy-pasteable env vars to switch. Read-only
on purpose — secret-store choice stays a deployment-time decision.

`/api/v1/secret-store/status` REST endpoint backs the panel.
`VaultSecretStore.health_check()` added for symmetry. New ops doc at
`docs/operations/secret-store-setup.md` walks through Vault and AWS
provisioning + the POC → production progression.

### A6.y · Kubernetes Secrets backend — SHIPPED 2026-08-26

`secrets/kubernetes.py`, third implementation of the `SecretStore`
Protocol after Vault and AWS. `VYUU_SECRET_STORE_BACKEND=kubernetes`.

Three decisions worth keeping:

- **One Secret per tenant** (`vyuu-<tenant_id>`), not per-tenant keys
  inside one Secret. `resourceNames` is the only per-object granularity
  Kubernetes RBAC offers for Secrets; keying inside one object would make
  every tenant's material reachable by anyone who can read it, and RBAC
  could not tell them apart.
- **The service-account token is re-read per request.** Projected tokens
  are short-lived and rotated in place by kubelet — caching one means the
  gateway starts failing auth about an hour after start-up, long after
  anyone would connect the failure to this code.
- **403 is a backend error, never "not found".** An RBAC gap reported as
  a missing secret turns a cluster misconfiguration into a silent
  authorization failure across every upstream at once, with nothing to
  grep for.

If the pod can simply *mount* the Secrets it needs, mount them — this is
for the case where the set is not known at deploy time.

**Tests:** `tests/test_kubernetes_secret_store.py` (22). Four negative
controls; one (TLS verification) initially passed because every test
injected a client and never exercised `_ensure_client`, so the `verify`
decision was extracted into a testable method.

Original entry follows.

### A6.y · Kubernetes Secrets backend

- **Effort:** ~1 day ✱
- **Depends on:** A6 (Vault) + A6.x (AWS) — both shipped, both serve as references
- **Status:** pending
- **Why:** Some k8s-resident deployments prefer reading `Secret` resources directly via the k8s API (mounted-at-runtime via projected volumes is fine; this is for the watch / refresh case). Same Protocol, lift-and-shift now that two backends already implement it.

### AWS-KMS-1 · Envelope encryption for at-rest data — SHIPPED 2026-08-26 (candidate (a))

The entry below says "hold off until one of these has concrete demand".
**Candidate (a) — wrapping OAuth tokens — did not need demand.**
`OAuthUserToken`'s own model docstring read: *"Tokens are stored as
plaintext (DB at-rest encryption is the operator's responsibility for
v1)."* A refresh token is durable delegated access to a user's GitHub,
Drive, Slack or Notion; plaintext means a dump, a backup, a read replica
or a `pg_dump` in a support ticket hands over every user's connected
accounts at once — and unlike a password, nobody can tell and nothing
rotates. Postgres-level at-rest encryption does not help: it defends
against disk theft, not against anything that can already run a SELECT.

`crypto/envelope.py` + `crypto/oauth_tokens.py`. Backends: `none`
(default), `local` (master key in config), `aws_kms`.

Decisions:

- **Envelope, not direct KMS encryption.** No plaintext round-trip to the
  KMS, master-key rotation does not rewrite the table, and one data key
  per value makes AES-GCM nonce reuse structurally impossible rather than
  something a later edit could get wrong.
- **Self-describing values (`vyuu:v1:…`), so no migration and no flag
  day.** `decrypt` passes non-prefixed values through, so existing
  plaintext rows keep working and are sealed on their next write. The
  alternative — a boolean column plus a backfill — makes enabling a
  security control an outage-shaped event, which is how it ends up never
  being enabled.
- **AAD binds each value to its row AND column.** A ciphertext copied
  from a privileged user's row into your own — the attack available with
  write-but-not-read DB access — fails authentication instead of
  silently granting someone else's token.
- **Explicit call sites, not a SQLAlchemy `TypeDecorator`.** A decorator
  is transparent but sees one column at a time, so the best AAD it could
  build is a per-column constant — which does nothing about that attack.
- **`NullEnvelopeCipher` refuses to read sealed rows** rather than
  returning ciphertext, so turning encryption off surfaces as "your key
  is missing" and not a baffling upstream 401.

**Tests:** `tests/test_envelope_encryption.py` (21). Four negative
controls; one caught a vacuous test — "fresh key and nonce" compared
whole envelope strings, which differ anyway because the wrapped-key
segment randomises independently, so it passed with a hard-coded data key
and nonce. Now compares the nonce and ciphertext segments.

Candidates (b) KMS-backed portal-JWT signing keys and (c) IdP directory
secrets remain demand-gated, as written below.

### AWS KMS · Envelope encryption for at-rest data

- **Effort:** 1–2 days ✱ (sized when use case is concrete)
- **Depends on:** none
- **Status:** designed, not blocking
- **Why:** `AWS Secrets Manager` already uses KMS internally for the secrets it stores — direct KMS calls are a SEPARATE concern: envelope encryption for data we store ourselves. Three real candidate use cases: (a) wrapping OAuth refresh tokens in our DB; (b) KMS-backed signing keys for portal-session JWTs; (c) **IDP-1 directory client secrets** (OIDC client_secret, SAML signing keys, SCIM bearer-token hashes) — currently routed through `secret_store` (Vault/Postgres). Compliance-sensitive tenants will want envelope encryption with their own KMS key. Hold off until one of these has concrete demand from a paying customer.

---

## Source types & transports

### S1.b · Cosign / Sigstore verification for `binary` upstreams — SHIPPED 2026-08-26

`upstream/binary_provenance.py`. S1 shipped *path* validation — absolute,
no traversal, exists, executable, optionally allowlisted — all of which
answers "is this a sane path?" and none of which answers **"is this the
file the vendor shipped?"**. `binary` is the one source type where the
gateway executes code it did not fetch, so an attacker with write access
to the connector directory gets execution inside the gateway process tree
while every S1 check still passes.

- **Verified on every client build, not only at registration.**
  Registration proves the file was good once; the threat is it changing
  afterwards.
- **A missing `cosign` is a hard failure, not a skip.** A deployment that
  configured a verification key has said "only signed binaries run".
  Skipping would revert the control while leaving the config in place
  looking effective — the worst of both.
- Shells out to `cosign` rather than binding a Python Sigstore library:
  it is the implementation the vendor's release pipeline signed with, the
  cost is milliseconds on a cold path, and it keeps a crypto dependency
  out of our import graph.

`VYUU_BINARY_COSIGN_VERIFICATION_KEY_PATH` is the switch; unset (default)
is exactly the pre-S1.b behaviour.

**Tests:** `tests/upstream/test_binary_provenance.py` (12), cosign
stubbed. Four negative controls, all failing correctly — including the
timeout path, which must kill *and reap* so a hung cosign leaves no
zombie.

Original entry follows.

### S1.b · Cosign / Sigstore signature verification for `binary` source type

- **Effort:** 0.5 day ✱
- **Depends on:** S1 (shipped 2026-04-30 — see HANDOFF)
- **Status:** pending
- **Why:** S1 shipped path validation (absolute, exists, executable, no metacharacters, no traversal, optional allowlist). Cosign verification is the supply-chain provenance layer that makes "binary" production-trustworthy. Operator stores the verification key + expected signer email; gateway shells out to `cosign verify-blob` at registration time. Required for compliance-sensitive tenants (BFSI, healthcare).
- **Sub-features:**
  - Optional `binary_signature_ref` on the server row (path to a `.sig` file co-located with the binary, or a registry-pull URL).
  - `StdioLaunchPolicy.cosign_verification_key_path` config option.
  - Verification runs at register-time and on every gateway restart (binary on disk could have been swapped under us).

### S2 · OCI / Docker source type — PARKED

- **Status:** parked 2026-04-30 (user decision)
- **Why parked:** Gateway-side Docker daemon access is effectively root-equivalent on the host — the privilege-escalation surface isn't worth the convenience for a feature with niche customer demand. Container-published MCPs can still be onboarded by running them outside the gateway (k8s sidecar / systemd unit / nomad task) and registering their **stdio** or **streamable_http** surface through the existing source types.
- **Unparks when:** A customer requires native OCI registration AND we have a deployment story that doesn't grant the gateway daemon access (rootless Podman with explicit AppArmor profile, or a separate runner microservice the gateway RPCs into).

### S3, S4, S5, S6, S7, S10 — shipped 2026-04-30

See HANDOFF.md "Sub-session — 2026-04-30 (production telemetry batch)" for the details:

- **S3** — `KafkaAuditProducer` + `NatsAuditProducer` (JetStream), durable audit publishing.
- **S4** — `AsyncGraphEventEmitter` + Kafka/NATS graph producers, parallel pipeline.
- **S5** — SSE outbound (`SseMcpClient`), legacy MCP transport support.
- **S6** — Registration-time MCP probe (FastAPI `BackgroundTasks`), non-blocking health classification.
- **S7** — `PeriodicCapabilitySyncScheduler`, per-tenant concurrency cap, off-by-default opt-in.
- **S10** — `POST /api/v1/servers/{id}/capabilities` for manual catalog seeding, with optional per-capability `risk_category` overrides.

### S8 · MCP manifest discovery — shipped (best-effort) 2026-04-30

`POST /api/v1/servers/from-manifest` fetches a manifest URL (HTTPS-only
by default), parses a deliberate **conservative subset** of recognised
fields (`name` / `display_name` / `title`, `description` / `summary`,
`transport` / `type`, `endpoint` / `url` / `uri`, `command` + `args`
with `npx` / `uvx` auto-mapping to npm / pypi source types, `auth.scheme`
hint), returns a `ManifestPreviewResponse` with auto-detected fields +
raw payload + `notes` array calling out gaps. **Preview-only — no
auto-registration**: a malicious manifest URL must not land an upstream
in the registry without operator confirmation via the existing
`POST /api/v1/servers`. 17 new tests. Spec stability caveat: when the
upstream `mcp.json` schema stabilises, only `vyuu_gateway/registry/manifest.py`
needs to evolve.

### S9 · Go modules / Cargo / Bun source types — PARKED (same item as Parked-3)

- **Effort:** 1 day per type ✱
- **Status:** **parked** — and duplicated below as `Parked-3`, which is
  the same decision written twice. Kept here so the S-numbering stays
  contiguous; `Parked-3` is the authoritative entry.
- **Why parked:** a real pattern for some vendors (Cloudflare Rust,
  HashiCorp Go) but extremely niche — customers care far less than for
  OCI or static binary.
- **Unparks when:** a customer names one of these as a primary
  requirement. Building it before then is building on speculation, which
  is the thing the parked status exists to prevent.

**Note (2026-08-26):** this reads as open work in any listing that
filters on "not shipped", because the title carries no status word. It is
not open. Same misclassification risk as the stale IDP-1 / A4 / H3
entries corrected earlier.

---

## Security hardening

### RETENTION-1 · Durable-audit retention prune — SHIPPED 2026-08-25

Closes the last open item from `security-issues.md` (A5) and the
`SECURITY.md` retention gap: `tool_call_events` and `admin_audit_log`
grew without bound.

- **Effort:** 0.5 day ✱ (actual: ~0.5 day)
- **Depends on:** TOOL-EVENTS-1 (durable events table), IDP-1 Phase 3
  (`HardDeleteSweeper`, whose worker shape this reuses)
- **Status:** shipped

**What landed**

- `audit/retention.py` — `RetentionSweeper`, a daily async worker plus a
  synchronous `prune_once()` core. Same `start()` / `stop()` /
  `run_one_cycle()` shape as `HardDeleteSweeper` so it is testable
  without `asyncio.sleep`.
- Per-tenant, RLS-bound deletes. Both tables are ENABLE + FORCE RLS, so
  an unscoped `DELETE` matches **zero rows** — the sweeper enumerates
  tenants via the non-RLS'd `tenants` table and rebinds
  `app.current_tenant_id` per tenant, exactly like
  `seed_recent_buffer_from_postgres`.
- Chunked + capped deletes (`batch_size` 5,000; `max_rows_per_cycle`
  200,000) so the first prune after opt-in drains over several cycles
  instead of holding one enormous transaction against the live audit
  write path.
- A `retention.prune` `admin_audit_log` row per sweep that deletes
  anything, carrying table / cutoff / row count / `hit_cycle_cap`.
- Reported in the diagnostic bundle under
  `background_workers.audit_retention_sweeper` (bundle version → 1.2).

**Decisions worth remembering**

- **Default is keep-forever (`0`), not 90 days.** This ships the
  *mechanism*; the window is a legal/deployment decision (GDPR
  minimisation vs SOC 2 evidence retention pull opposite ways) and the
  delete is irreversible. An operator upgrading the gateway must never
  discover that restarting it destroyed a year of audit history. The
  consequence is honest and documented: a deployment that never sets
  `VYUU_TOOL_CALL_EVENT_RETENTION_DAYS` still grows without limit — now
  an explicit choice rather than a missing capability.
- **`create_app` refuses to start when `VYUU_ADMIN_AUDIT_RETENTION_DAYS`
  is shorter than `VYUU_TOOL_CALL_EVENT_RETENTION_DAYS`.** The admin log
  holds the `retention.prune` rows that explain the event table's gaps;
  discarding it first deletes the explanation while the gap is still
  visible to an auditor.
- **The audit row is written after the deletes, not inside them** — a
  deliberate exception to the same-transaction rule in
  `audit/admin_audit.py`, because a chunked prune has no single
  transaction to share. The failure path logs at ERROR with the full
  detail so a lost row is reconstructible from the log pipeline.
  Rationale in the module docstring.

**Tests:** `tests/audit/test_retention.py` — 11 (4 no-DB, 7 real-DB).
Three negative controls run: dropping the tenant binding, removing the
cycle cap, and ignoring the cutoff each fail the suite. The cap test
deliberately uses a cap that is *not* a multiple of the batch size
(17/10) — a 20/10 pair passed even with the cap broken.

### BUG-SCIM-1 · SCIM auth always 401s under FORCE RLS — FIXED 2026-08-25

**Was a live bug, not test drift.** `authenticate_scim` resolves
`idp_directories` by id *before* the tenant is known — the directory row
is what tells us the tenant — but the table is ENABLE + **FORCE** RLS, so
that untenanted SELECT matched zero rows, the dependency read it as
"unknown directory", and **every SCIM request 401'd**, including with a
bearer the gateway had just minted. The same transaction then ran the
`last_sync_at` heartbeat UPDATE, which also matched zero rows and
committed silently.

Blast radius while broken: SCIM provisioning/deprovisioning was dead for
any deployment whose DB role is not superuser or `BYPASSRLS` — the
posture `SECURITY.md` recommends. It had been carried for several
sessions as "SCIM auth setup" environment noise.

**Fix — migration `20260825_0019` + `scim/auth.py`.** A second
PERMISSIVE, **SELECT-only** policy on `idp_directories` that opens the
read only for a caller that asks for it by name:

```sql
USING (
    NULLIF(current_setting('app.current_tenant_id', TRUE), '') IS NULL
    AND current_setting('app.scim_bootstrap', TRUE) = 'on'
)
```

`set_config(..., is_local => true)` scopes the capability to one
transaction, and the dependency `rollback()`s before binding the tenant —
which also fixes the heartbeat, since `bind_tenant_context` only takes
effect via the `after_begin` listener on the *next* transaction.

**Options rejected, and why** (worth keeping — they look right):

- *SECURITY DEFINER function.* Does not work. FORCE RLS subjects the
  table **owner** to its own policies, and the function runs as the
  owner. Only `BYPASSRLS` escapes, and mandating such a role is a
  deployment-level privilege requirement. This was the original
  recommendation in this backlog entry and it was wrong.
- *Relax FORCE → ENABLE.* Works, but the app connects as the owner, so it
  would exempt the entire application from RLS on a table holding SCIM
  token hashes and OIDC client-secret refs.
- *Tenant in the SCIM URL.* Cleanest model; changes the endpoint every
  already-configured IdP points at.

**Guards:** the two previously-failing tests now pass, plus two new ones
— `test_scim_request_stamps_the_directory_heartbeat` (catches the
missing rollback; nothing else did) and
`test_untenanted_directory_read_stays_blocked_without_the_capability`
(catches the policy being widened, or FORCE being relaxed). Four
negative controls run: removing the capability, removing the rollback,
dropping the policy, and widening the policy each fail the suite.

### H1 · DNS-time SSRF backstop — SHIPPED 2026-08-25

- **Effort:** 0.5 day ✱ (actual: ~0.5 day)
- **Depends on:** none
- **Status:** shipped

The registration check in `registry/url_security.py` catches unsafe IP
*literals*. It cannot catch a hostname that passes registration because
it is not an IP literal, and then *resolves* to something internal at call
time — `mcp.evil.test` pointing at `169.254.169.254` sailed straight
through. `upstream/ssrf_guard.py` closes that at the moment it matters.

**Resolve, validate, and PIN.** Checking DNS and then letting httpx
resolve again is not a fix, it is a TOCTOU race — DNS rebinding exists to
win it. `SsrfGuardTransport` resolves once, validates **every** address
the resolver returned, then rewrites the request to connect to the
address it checked. The original hostname rides along as the `Host`
header and httpx's `sni_hostname` extension, so TLS SNI and certificate
validation still run against the registered name, not a bare IP.

**Every address, not the first** — a name resolving to one public and one
private address is rejected outright, so an attacker cannot win by
controlling record order.

**Shared policy.** The same `UrlSecurityPolicy` governs registration and
connect, so the two cannot drift. There is deliberately no second set of
connect-time-only knobs.

**Default ON** (`VYUU_UPSTREAM_SSRF_GUARD_ENABLED=true`). Unlike audit
retention, the failure mode here is a visible, immediately reversible
connection error whose message names the exact remedy — not silent data
loss. Verified against the real resolver: the lab's own `mcp.draw.io`
still connects (pinned to its IPv6 address); `localhost` and `127.0.0.1`
are blocked; `VYUU_HTTP_URL_ALLOW_PRIVATE_NETWORKS=true` restores an
internal target.

**Known limits, stated honestly:** this is not a defence against a
compromised resolver — if DNS lies, we validate and pin to the lie.
Pinning bounds the damage to one answer instead of two. Redirects are
re-checked only because httpx issues each hop as a fresh request through
this transport; preserve that if the transport stack is ever replaced.

**Tests:** `tests/upstream/test_ssrf_guard.py` — 21, DNS stubbed so they
are deterministic and need no network. Four negative controls run and all
fail correctly: checking only the first address, dropping the pinning,
failing open on a resolution error, and dropping `sni_hostname`.

### H3 · Payload-size limits + response inspection / redaction — PARTIALLY SHIPPED

**Backlog correction (2026-08-25):** this was still marked `pending`, but
the limits half shipped some time ago and the entry was never updated.
Anyone picking it up would have rebuilt working code. Verified against
`src/vyuu_gateway/api/payload_limits.py` (wired at
`api/inbound_mcp.py:786`) and `tests/api/test_payload_limits.py`.

**Shipped:**

- Request bodies over `VYUU_INBOUND_MAX_REQUEST_BODY_BYTES` (5 MiB) fail
  fast with a 413 envelope; the upstream is never called.
- Response bodies over `VYUU_INBOUND_MAX_RESPONSE_BODY_BYTES` (25 MiB)
  are truncated with a sentinel marker before forwarding, and the audit
  emit sees the truncation.
- Secret-*shape* redaction (API keys, JWTs, AWS keys →
  `[REDACTED:<kind>]`) behind `VYUU_INBOUND_REDACT_RESPONSE_SECRETS` or a
  per-decision policy opt-in.

**Still open — PII-class response redaction.**

- **Effort:** 2–3 days ✱
- **Depends on:** policy provider gaining response-redaction *rules*
  (email / phone / national-ID classes, per exposed tool), which the
  simple policy provider does not model yet.
- **Why the remaining half is the harder half:** shape-matching a JWT is
  a regex; deciding that a string is a customer's home address is a
  classification problem, and a false positive silently corrupts a tool
  result the caller depends on. Needs the policy surface to express
  *which* classes to redact for *which* tool before the detection work is
  worth starting.

### H4 · Per-package content allowlist on stdio launch policies — shipped 2026-04-30

`StdioLaunchPolicy(allowed_npm_packages=(...), allowed_pypi_packages=(...))`
— when non-empty, the package string must match an entry verbatim
including any `@version` pin. Empty tuples preserve lab default
(name-shape-only validation). See HANDOFF "Sub-session — 2026-04-30
(Quick-wins batch)" for the full slate.

### H5 · Audit raw-args / raw-response capture under explicit policy opt-in — shipped 2026-04-30

`PolicyDecision.allow(capture_raw_args=..., capture_raw_response=...)`
is the opt-in surface (default off — privacy-by-default per spec §3.3).
`AuditEvent` carries `raw_args` / `raw_response` + truncation flags.
16 KB JSON per-field byte cap with progressive degradation: leaf-string
trim → fallback sentinel for pathological payloads, never raises.
Operator-console "Tool-call activity" panel renders separate
`<details>` blocks for raw values when present, with a clear
"truncated" pill when the size cap fired. 11 new tests. See HANDOFF
"Sub-session — 2026-04-30 (A6 Vault + H5 + S8 + H2)" for the full
slate.

### H6 · Header-value templating for org-tier auth — shipped 2026-04-30

`{"Authorization": "Bearer {secret:paypal-token}"}` resolves the inner
ref and substitutes; multiple placeholders per value supported.
Bare-ref values without `{secret:...}` keep working (auto-detected
backward-compat path). Applies to both `auth_headers` and `auth_env`.
See HANDOFF "Sub-session — 2026-04-30 (Quick-wins batch)" for the full
slate.

---

## Operator UX

### U1, U2, U4 — shipped 2026-04-30

Operator-UX batch (small but high-quality-of-life). See HANDOFF.md "Sub-session — UX batch (U1, U2, U4)" for details.

- **U1** — single consolidated `:root` block with Vyuu tokens; meaning-coded pills (`pill-orange`/`-warn`/`-danger`/`-info`/`-neutral`) wired via a `pillClassForHealth()` JS helper.
- **U2** — sync-time advisory banner appears when discovery succeeds against a server that has zero auth configured ("Discovery succeeded but tool calls may still require credentials…").
- **U4** — `_BoundedStderrBuffer` replaced with a tempfile-backed bounded capture; `UpstreamStartupDiagnosticError` carries up to 512 bytes of sanitized upstream stderr; `_upstream_sync_error` includes it in the 502 detail. **Live-verified** against `falcon-mcp` — operator now sees the exact CrowdStrike "Configuration error: API credentials not provided" message.

### U5 · Portal config snippets, principal dropdowns, tool-call activity dashboard — shipped 2026-04-30

Customer-driven UX batch:

- **/portal** catalog rows now expose a "Show config" expander per accessible vserver — copy-pasteable Cursor + Claude Desktop snippets with `<YOUR_API_KEY>` placeholder + Copy buttons.
- **/operator** group + grant flows replaced their `prompt('UUID')` calls with real `<select>` dropdowns of users / groups (lazy-fetched into a shared `principalCache`).
- **/operator** new "Tool-call activity" panel — filterable by vserver, shows decision + upstream-status pills, latency, principal, A5 auth-mode flags, args metadata. Backed by new `RecentAuditEmitter` (in-memory ring buffer of last 1000 events) + `GET /api/v1/audit-events` endpoint. **Args/response values intentionally NOT captured** — opt-in path is H5 (pending). 12 new tests. See HANDOFF "Sub-session — 2026-04-30 (Customer feature batch)" for the full slate.

### U3 · "Connect to {SaaS}" button for OAuth authorization-code (phase 4) — shipped 2026-05-01

Bundled with A1. Catalog cards expose Connect / Reconnect buttons next
to vservers whose underlying upstream uses `auth_authcode`; each
button POSTs to `/oauth-authcode/{server_id}/initiate` and bounces the
browser to the IdP authorize URL with a signed state token. New "My
connections" portal tab lists user's linked accounts with Disconnect
(deletes the `oauth_user_tokens` row, IdP-side revocation deferred).

### U9 · OAuth 2.1 PKCE + Dynamic Client Registration (RFC 7591) — shipped 2026-05-03

Closes the "Notion / Linear need DCR support" follow-up. Now any
spec-compliant MCP server (Notion, Linear, Anthropic-hosted, Cloudflare,
Sentry, anything built on the official MCP SDK) installs with **zero
operator setup** — no OAuth app to create in the vendor dashboard,
no client_id/secret to paste.

What shipped:

- **PKCE (RFC 7636)** — `code_verifier` embedded in the state JWT,
  `code_challenge_method=S256` in the authorize URL, `code_verifier`
  echoed on token exchange. Required by OAuth 2.1; benefits both
  static-creds (GitHub) and DCR (Notion) paths.
- **DCR client** ([`src/vyuu_gateway/upstream/oauth_dcr.py`](src/vyuu_gateway/upstream/oauth_dcr.py)) — full RFC 9728 → 8414 → 7591 discovery + registration. HTTPS-only at every hop (MITM defense). Step-named errors so operators know whether AS metadata, registration, or probe failed.
- **`mcp_server_dcr_clients` table** — one row per server, lazy-populated on first `/initiate` call, cached for all subsequent users. Tenant-scoped RLS.
- **Token provider integration** — `OAuthAuthCodeTokenProvider._resolve_client_creds()` pulls from the DCR table when `dcr_enabled`; falls back to SecretStore for static refs. Token refresh path supports both confidential and public clients.
- **Catalog + wizard** — `ConnectorTemplate.dcr_enabled` flag. Notion + Linear flipped to DCR mode. Wizard step-3 banner appears + static fields collapse when in DCR mode. Card meta line shows "auto OAuth (DCR)" suffix.
- **Tests** — 8 DCR client tests against an ASGI stub (happy + edge cases including IAT-required hint), 1 PKCE round-trip integration test. 939 total pytest pass.

Live-verified end-to-end against real `https://mcp.notion.com/mcp`:
discovery → DCR → got real `client_id` from Notion → PKCE in URL →
row persisted → second call reuses cached row.

### U10 · DCR auto-recovery on `invalid_client` — shipped 2026-05-03

When a DCR-issued client is evicted by the upstream AS (revoked,
rotated, idle-timed-out), the gateway now self-heals:

- **Refresh path** (`OAuthAuthCodeTokenProvider._refresh_in_place`)
  detects `{"error": "invalid_client"}` from the token endpoint per
  RFC 6749 §5.2. New `_invalidate_dcr_state()` drops the
  `mcp_server_dcr_clients` row + every `oauth_user_tokens` row for
  the server (those refresh tokens were minted under the dead
  client_id) and raises a typed `OAuthTokenError` guiding the user
  to reconnect. Static-creds servers unaffected.
- **Callback path** (`/api/v1/oauth-authcode/callback`) same
  detection covers the rare race where the AS evicts our creds
  between authorize and token exchange. Returns 409 "Reconnect
  required" with actionable text.
- **Recovery is automatic** — the cleanup leaves both tables empty
  for the server, so the next operator-side `/operator-initiate`
  (or portal `/initiate`) hits the existing lazy-DCR helper from
  U9, runs fresh discovery + registration, persists the new row.
  Live-verified against real Notion: old `client_id=htnVLUEG8A1rH0qw`
  → cleanup → next initiate → new `client_id=GaVQjfcQOKcsPSX3`.
- **Tests** — 2 new in `tests/upstream/test_oauth_authcode.py`:
  invalid_client triggers cleanup + DELETE statements; non-DCR
  servers keep the existing generic-error path.

The refresh that triggered cleanup still fails (we can't replay an
authorization code) — user gets the actionable error and re-Connects.
Truly transparent retry would require a mid-tool-call OAuth round
trip; not worth the complexity.

### U12 · Wizard checkbox for DCR mode on one-off registration — shipped 2026-05-03

Operators registering a DCR-capable upstream NOT in the catalog
(e.g. trying out Sentry, HuggingFace, PayPal, Cloudflare Workers
before deciding to ship a catalog entry) can now tick a checkbox in
the wizard's step 3 instead of POSTing to `/api/v1/servers` with
curl. Single source of truth via `setDcrMode(enabled)` — both the
catalog click handler and the manual checkbox route through it,
keeping the hidden `auth_authcode_dcr_enabled` input, the visible
checkbox state, and `body[data-authcode-mode]` in lockstep.

What shipped:

- **Checkbox + label** in `operator_ui.py` step-3 auth_authcode group:
  "Use Dynamic Client Registration" with a hint listing the supported
  vendors. Sits above the existing DCR banner.
- **`setDcrMode(enabled)` helper** mirrors state across all three
  surfaces + dispatches a synthetic `input` event so the wizard
  step gate + live-preview manifest re-evaluate.
- **`applyConnectorTemplate` updated** to route through `setDcrMode`
  instead of writing the hidden input directly — catalog clicks now
  also tick the checkbox so the operator sees the toggle reflect
  their choice.
- **Live-preview manifest** now mirrors `dcr_enabled: true` in the
  rendered JSON when the toggle is on, so the operator sees the
  exact payload they're about to submit.
- **Checklist gate** in DCR mode shows only "DCR enabled
  (auto-discover)" + "redirect_uri" (both green by default in DCR
  mode, since the gateway auto-resolves everything else). Static
  mode keeps the existing 5-field gate.
- **Browser-verified**: manually ticking the checkbox flips
  `body[data-authcode-mode]` to "dcr", hides the four static ref
  fields, reveals the banner, sets the hidden input, updates the
  live preview and checklist — all without touching the catalog.

### U11 · Initial Access Token (RFC 7591 §3) for enterprise IdPs — shipped 2026-05-03

DCR now supports IAT-gated enterprise OAuth servers (Okta tenants,
private B2B IdPs that require a Bearer token on registration). New
optional `OAuthAuthCodeSpec.initial_access_token_ref` field; when
populated, the resolver looks it up via the SecretStore and the DCR
client attaches `Authorization: Bearer <iat>` to the RFC 7591
registration POST. Public SaaS DCR servers (Notion, Linear,
Cloudflare, Sentry) leave this blank and continue to register
unauthenticated. UI: optional input below the DCR banner, visible
only when DCR mode is on. 3 new tests cover IAT-attached, IAT-
required-but-missing, and no-IAT-public-AS cases.

### U6 · SaaS connector catalog (Quick add) + Test connect operator flow — shipped 2026-05-03

Eight pre-configured connectors (GitHub Copilot, Notion, Linear, Jira,
Confluence, Slack, Microsoft 365, Asana) ship as `ConnectorTemplate`
entries in [`src/vyuu_gateway/upstream/connector_catalog.py`](src/vyuu_gateway/upstream/connector_catalog.py)
and render as a card grid above the MCP-servers table. Click a card →
the existing 5-step register wizard opens with runtime, source URL,
transport, and OAuth metadata pre-filled — admin only fills in
`client_id_ref` / `client_secret_ref`.

The auth_authcode chicken-and-egg (Sync needs token, Token needs
Connect, Connect needs vserver-access, vserver-access needs Sync)
is broken by **Test connect**: a row-level button visible only when
`auth_authcode` is set. Calls
`POST /api/v1/oauth-authcode/{server_id}/operator-initiate`, which
resolves operator email → matching User row → mints a state JWT
carrying that user_id → returns the IdP authorize URL. Operator
completes OAuth in a new tab; the existing /callback writes the token
under their underlying portal user. Sync then succeeds.

Two related fixes shipped alongside:

- `_only_authcode()` skips auto-sync at registration for authcode-only
  upstreams (the 5×401 → CircuitBreakerOpenError → 502 cascade is
  impossible to satisfy without a stored token).
- `_maybe_raise_authcode_no_token()` translates the manual-sync 502
  → 412 with actionable text when an authcode upstream has no
  `oauth_user_tokens` rows yet.
- `principal_id` threaded through the entire capability sync chain
  (`McpCapabilityClient` Protocol → adapter → `DatabaseCapabilitySyncService`
  → `StreamableHttpMcpClient.list_capabilities`) so the OAuth bearer
  is attached to sync probes for authcode upstreams.

---

### U7 · Periodic capability-sync scheduler resolves principal_id for authcode — shipped 2026-05-03

The scheduler now picks up `oauth_user_tokens` for `auth_authcode`
upstreams. New `_resolve_authcode_principal()` returns the most-
recently-refreshed user's id (lowest expiry risk) and passes it as
`principal_id`. Authcode servers with no token rows yet are skipped
with a structured `capability_sync_skipped_no_authcode_token` log
line; the next operator-side Test connect or portal Connect re-
authorises and the next tick succeeds. Non-authcode upstreams
unchanged. 3 new tests cover the resolve-freshest, no-token-skip,
and non-authcode-passthrough cases.

### U8 · Wizard `_ref` field labeling + soft-validation — shipped 2026-05-03

All five `_ref` inputs across the three OAuth modes (M2M, authcode,
JWT-bearer) now carry an inline hint clarifying "Secret-store key,
NOT the literal credential" with a concrete example. Soft-validation
heuristic detects when the operator's input looks like a literal
OAuth credential (16+ chars mixed-case alphanumeric without
separators, or 32+ chars hex/base64) and renders an inline orange
warning below the field — non-blocking but visible before the
gateway silently falls back to `placeholder-<value>` and OAuth fails
at the IdP. Wired via `data-secret-ref-input` attribute + per-input
listeners. Live-verified by pasting `Ov23li…<redacted client id>` (real
GitHub OAuth client_id format) into `client_id_ref` — warning fires
instantly.

---

## Performance & optimization

### P2 · Secret rotation on pooled connections — SHIPPED 2026-08-26

**Recategorised on the way in: this was filed under "Performance" and
gated on measurement, but it is a correctness / security issue and was
built on its own merits.** Org-tier `auth_headers` are resolved from the
SecretStore once, in the pool factory, then baked into the transport
client — so a rotated secret only took effect when the connection
happened to drop or a circuit breaker opened. A tenant rotating a
*leaked* credential could keep serving traffic with it for hours, which
is the opposite of what rotating it was for. No benchmark was going to
change that.

`UpstreamClientPool` now takes `client_max_age_seconds`
(`VYUU_UPSTREAM_CLIENT_MAX_AGE_SECONDS`, default 900). Aged-out idle
clients are retired on acquire and rebuilt from a fresh factory call.

Decisions worth keeping:

- **Age is measured from BUILD, not from release.** Credential freshness
  is about when the secret was read, and the secret is read once, in the
  factory. Refreshing the stamp on release would let a continuously-busy
  connection stay "fresh" forever — the exact stable-connection case this
  exists for.
- **Checked on acquire, not on a timer.** An idle pool nobody is using
  holds no stale credential in practice, and a sweeper would need its own
  task, failure mode and tests to close a window that only exists at the
  moment of use.
- **Retired clients are closed outside the pool lock** — `aclose()` on a
  stdio upstream can be slow, and holding the lock across it would stall
  every other caller for that upstream.
- Setting it to `0` disables the TTL and restores the previous
  keep-until-broken behaviour; a test documents exactly what that costs,
  so disabling it is an informed choice.

**Tests:** `tests/upstream/test_pool_credential_ttl.py` (8). Four
negative controls: TTL never expiring, age refreshed on release, retired
clients not closed, and capacity not returned (which hangs the pool — the
test's `wait_for` catches it).

### P3 · OAuth phase 3: shared httpx client for token refreshes — MEASURED, NOT DOING

- **Effort:** 1 hour ✱
- **Status:** **decided against on the measurement it was waiting for**
  (2026-08-26). Reopen if the shape of token refresh changes.

The blocker was "hold off until measurement shows it matters", so the
measurement got built: `tests/perf/client_reuse_benchmark.py`.

Result on loopback HTTP, 60 calls: **one-shot 0.857 ms mean vs reused
0.428 ms — reuse saves ~0.43 ms per call (50%)**. That is a *floor*; the
real saving against a remote https auth server is a TLS handshake plus a
round-trip, so call it tens of milliseconds.

**It still does not matter here.** A client-credentials token is fetched
once per token lifetime — minutes to hours — so even at 50 ms saved, a
gateway refreshing a few hundred tokens an hour recovers a couple of
seconds a day. Against that: a long-lived client needs an `aclose()` that
nothing currently calls (`CachedOAuthTokenProvider` has no teardown path
and is not wired into any), so doing it means adding a lifecycle to
reclaim a saving nobody can measure in production.

The per-call number is printed by the benchmark so a deployment with an
unusual refresh rate can multiply it by their own and reach a different
conclusion.

### P1 · Per-passthrough connection pool — MEASURED, STILL DEPLOYMENT-DEPENDENT

Same benchmark, same floor: **~0.43 ms per call, 50% of one-shot cost.**

Unlike P3, passthrough happens **per tool call**, so the arithmetic is
different: at 100 calls/s the loopback floor alone is ~43 ms/s of wall
clock, and with real TLS to a remote upstream it would be seconds per
second. At the low call rates most enterprise MCP deployments actually
run, it is noise.

So this stays open but is no longer *blocked* — the number exists, and
the decision is now a deployment question rather than a research one.
Run the benchmark against a representative upstream before building it;
if the measured rate is under ~10 calls/s per upstream, don't.

---

## Parked / deferred decisions

These are explicit "not now" items — recorded so they don't get rediscovered as fresh ideas.

### Parked-1 · Google Drive native integration

- **Status:** parked 2026-04-30
- **Why parked:** GDrive doesn't fit any of the auth modes shipped today. Google requires authorization-code (phase 4 — A1) or JWT-bearer (A2), neither of which is shipped. The npm `@modelcontextprotocol/server-gdrive` runs its own internal OAuth dance, so registering it through our gateway wouldn't even exercise our auth path. Vyuu's agent layer handles whether GDrive is exposed to a given user — the gateway-level integration waits on A1 or A2.
- **Unparks when:** A1 lands (per-user delegated tokens) or A2 lands (service-account / JWT-bearer for Workspace org-Drive).

### Parked-2 · MCP manifest auto-discovery

- **Status:** parked indefinitely
- **Why parked:** Upstream standardization on `mcp.json` is in flux. Building toward a moving target burns time. See S8.
- **Unparks when:** the spec stabilizes.

### Parked-3 · Go / Cargo / Bun source types

- **Status:** parked
- **Why parked:** Real but extremely niche. See S9.
- **Unparks when:** a customer with one of these as a primary requirement surfaces.

---

## How items get added

When something is deferred mid-session, drop a one-paragraph stub here under the right section before closing the session. Better to over-list and prune later than under-list and forget. If an item lacks a clear "Why," it's not ready — it's a vague observation, not a backlog item.

When an item ships, **delete it from this file**, with a one-line note in `HANDOFF.md` pointing to the session that landed it. The backlog is for what's left, not a changelog.
