# FRONTEND — operator console + portal

## Ideology

**No build step. No framework. No node_modules.** Both the operator
console and the end-user portal are single HTML files served by FastAPI,
with inline CSS and inline JavaScript. They talk to the FastAPI JSON
APIs over `fetch()`.

Why:

- **Easier on-prem deploy.** Customers ship a Docker image with a
  Python process. No second build pipeline, no static-asset CDN, no
  framework version drift.
- **Smaller surface for security review.** The whole frontend is two
  Python strings; a security auditor reads them in a single sitting.
- **Easier to evolve.** A backend change that needs a UI tweak is a
  single-file edit. No "does this need a state-management refactor?"
- **Trade-offs we accept.** The two HTML files are large
  (`operator_ui.py` is ~12k lines including CSS + JS). We use editor
  go-to-symbol heavily; we don't lint inline JS with eslint. If/when a
  customer asks for a React rewrite, we have the API surface to do it
  cleanly — but until that day, this is faster.

## Files

```
src/vyuu_gateway/api/
  operator_ui.py    Operator console — admin UI
  portal_ui.py      End-user portal — issue API keys, see history, request access
```

Both:
- Mount at `/` (operator under `/operator`, portal under `/portal/`).
- Read the bearer / session token from `sessionStorage`
  (`vyuu_operator_token`, `vyuu.portal.token`).
- Auto-fetch the tenant from `/api/v1/auth/default-tenant` if
  `VYUU_DEFAULT_TENANT_ID` is set, hiding the tenant input on login.

## Operator console layout

```
sidebar (data-nav button = page)
  Overview      → Dashboard, NHI map, Health & servers
  Catalog       → MCP servers, Virtual servers
  Identity & access → Identities, Users, Groups, Access requests, Admins
  Observability → Events, Admin audit, SIEM export, Telemetry
  Settings      → Identity providers, Secret store, Troubleshooting
content (one <section data-nav="..."> per page; one shown at a time)
sidebar foot  → status pill, theme/density toggles, search palette, alerts bell, sign-in/out
```

Switching pages is a JS function `setActiveNav(navId)` that toggles
`hidden` on every `[data-nav]` panel and triggers the page's loader
function (registered in a `loaders` map).

## Pattern: adding a new operator panel

1. Add a sidebar nav button (`<button data-nav="my-thing">My thing</button>`)
   in the appropriate `<div class="nav-group">`.
2. Add the panel: `<section class="panel" data-nav="my-thing">...</section>`.
3. Add `loadMyThing()` JS function that fetches your endpoint and
   renders into the panel's DOM.
4. Add a refresh button: `<button id="refresh-my-thing">Refresh</button>`
   and wire it: `document.querySelector("#refresh-my-thing")
   .addEventListener("click", loadMyThing);`
5. Register in the `loaders` map (around `operator_ui.py:7050`) so
   the auto-load on nav-switch fires.

If your panel needs CSS, add it inline to the `<style>` block (search
for the `.events-kpi-grid` rule for an example of where utility classes
live).

## Pattern: time-window picker

Three panels (Events, NHI map, Identities) ship a `<select>` with
1h / 24h / 7d / 30d options. The shared helper:

```js
function windowSelectorToSinceIso(value) {
  const ms = {"1h": 3600e3, "24h": 86400e3, "7d": 7*86400e3, "30d": 30*86400e3}[value] || 86400e3;
  return new Date(Date.now() - ms).toISOString();
}
```

`change` on the select auto-refetches; default 24h matches the server
default in the corresponding endpoint.

## Pattern: live-poll page (Health & servers)

The Health page polls `/api/v1/admin/health-overview` every 15 s while
the panel is visible. Implementation:

```js
let _healthOverviewTimer = null;
function _kickHealthAutoRefresh() {
  if (_healthOverviewTimer) clearInterval(_healthOverviewTimer);
  _healthOverviewTimer = setInterval(() => {
    if (panelIsVisible) loadHealthOverview();
  }, 15000);
}
```

The latency sparkline is drawn as inline SVG — no chart lib. See
`_renderLatencyChart` in `operator_ui.py` for the pattern.

## Pattern: in-page drawer

Several flows (register MCP server, connect IdP, issue grant) use a
slide-in drawer. The pattern:

```html
<aside class="drawer" id="my-drawer" hidden>
  <header>...close button...</header>
  <form>...</form>
</aside>
```

```js
function openMyDrawer() { document.querySelector("#my-drawer").hidden = false; }
```

CSS handles the slide animation. Search for `.drawer {` for the rules.

## Auth flow on the operator console

1. User loads `/operator` → tenant input hidden if default tenant set.
2. User pastes a bearer (or signs in via SSO button if an IdP directory
   is connected).
3. Token stored in `sessionStorage["vyuu_operator_token"]`.
4. Every `api(path)` call adds `Authorization: Bearer <token>` header.
5. 401 from any endpoint → redirect to login + clear sessionStorage.

The same shape applies to the portal with key
`sessionStorage["vyuu.portal.token"]`.

## Theming

Two toggles in the sidebar foot: theme (light / dark) + density (cozy
/ compact). Each writes to `localStorage` and toggles a `data-*`
attribute on `<html>`. CSS uses `[data-theme="dark"] .panel { ... }`
overrides. Density swaps padding / line-height vars.

## Search palette (⌘K)

`#palette-trigger` opens a Ctrl/Cmd-K palette that searches across
servers, vservers, users, groups, audit. Implementation: client-side
filter on caches that the page already loaded. No new endpoint.

## What lives in the END-USER portal

The portal is intentionally minimal compared to the operator console:

| Page | Purpose |
|---|---|
| Sign in | Email + password OR Continue with X (SSO) |
| Home | Quick stats: my API keys, recent activity |
| Tool catalog | Browse public + granted vservers |
| Connections | OAuth-connected upstream servers (per-user delegated tokens) |
| API keys | Issue / revoke API keys; format `vyuu_user_*` |
| My requests | Access requests I've filed |
| Tool history | My recent tool calls (read from `tool_call_events`) |

The portal does NOT show admin data — the operator console is the only
admin surface. End users can't see other users' activity, can't see
admin actions, can't see cross-tenant anything.
