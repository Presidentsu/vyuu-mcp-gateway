from fastapi import APIRouter
from fastapi.responses import HTMLResponse, Response

router = APIRouter(tags=["operator-ui"])

_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


@router.get("/operator", response_class=HTMLResponse)
def operator_console() -> HTMLResponse:
    return HTMLResponse(_HTML, headers=_SECURITY_HEADERS)


@router.get("/operator/app.css")
def operator_console_css() -> Response:
    return Response(_CSS, media_type="text/css", headers=_SECURITY_HEADERS)


@router.get("/operator/app.js")
def operator_console_js() -> Response:
    return Response(_JS, media_type="text/javascript", headers=_SECURITY_HEADERS)


@router.get("/operator/logo.svg")
def operator_console_logo() -> Response:
    return Response(_LOGO_LOCKUP, media_type="image/svg+xml", headers=_SECURITY_HEADERS)


_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Vyuu Gateway Operator Console</title>
    <link rel="stylesheet" href="/operator/app.css">
  </head>
  <body data-active-nav="dashboard">
    <div class="app-shell">
      <aside class="sidebar" id="sidebar">
        <!-- Brand block + sidebar marks lifted from the Vyuu Design
             System (`Vyuu Design System/ui_kits/admin-console/Shell.jsx`).
             The Chakravyuha mark — concentric arcs converging to a
             centre dot — is the brand mark; product-family marks
             (McpMark / AgentMark / PromptMark) are inlined per nav
             group. Operational items use small geometric glyphs
             matching the design system's eyebrow tone. -->
        <a href="/operator" class="brand-block">
          <span class="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 48 48" width="32" height="32" fill="none">
              <path d="M24 4 A20 20 0 1 1 9.86 9.86"
                    stroke="var(--vyuu-orange-deep)" stroke-width="2.4"
                    stroke-linecap="round"/>
              <path d="M38 24 A14 14 0 1 1 14.1 14.1"
                    stroke="var(--vyuu-orange-deep)" stroke-width="2.2"
                    stroke-linecap="round" opacity="0.78"/>
              <path d="M16 24 A8 8 0 1 1 31.66 26.2"
                    stroke="var(--vyuu-orange-deep)" stroke-width="2"
                    stroke-linecap="round" opacity="0.58"/>
              <circle cx="24" cy="24" r="2.4"
                      fill="var(--vyuu-orange-deep)"/>
            </svg>
          </span>
          <div class="brand-text">
            <strong>Vyuu</strong>
            <p class="eyebrow brand-eyebrow">MCP SECURITY · GOVERN EVERY TOOL CALL</p>
          </div>
        </a>
        <nav class="side-nav" aria-label="Main">
          <div class="nav-group">
            <p class="nav-group-label">Overview</p>
            <button type="button" class="nav-item" data-nav="dashboard">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <rect x="2" y="2" width="6" height="6" rx="1"/>
                  <rect x="10" y="2" width="6" height="6" rx="1"/>
                  <rect x="2" y="10" width="6" height="6" rx="1"/>
                  <rect x="10" y="10" width="6" height="6" rx="1"/>
                </svg>
              </span>
              <span class="nav-item-label">Dashboard</span>
            </button>
            <button type="button" class="nav-item" data-nav="risk-summary">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M9 2 15 5v4c0 3.5-2.4 6.3-6 7-3.6-.7-6-3.5-6-7V5z"/>
                  <path d="M9 6.5v3M9 12h.01"/>
                </svg>
              </span>
              <span class="nav-item-label">Risk posture</span>
            </button>
            <button type="button" class="nav-item" data-nav="nhi-map">
              <!-- AgentMark from the design system — almond outline +
                   inner ring + centre dot. The NHI map IS the agent-
                   relationship view, so this glyph fits semantically. -->
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 48 48" width="16" height="16" fill="none">
                  <path d="M4 24 Q24 6 44 24 Q24 42 4 24 Z"
                        stroke="currentColor" stroke-width="2.4" fill="none"/>
                  <circle cx="24" cy="24" r="6" stroke="currentColor"
                          stroke-width="2.4" fill="none"/>
                  <circle cx="24" cy="24" r="2" fill="currentColor"/>
                </svg>
              </span>
              <span class="nav-item-label">NHI map</span>
            </button>
            <button type="button" class="nav-item" data-nav="health-overview">
              <!-- Heartbeat / pulse glyph for the Health & Server Info
                   page. Cloud-style overview: gateway health, MCP server
                   roster, p95 latency chart. -->
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M2 9 H5 L7 4 L11 14 L13 9 H16"/>
                </svg>
              </span>
              <span class="nav-item-label">Health &amp; servers</span>
            </button>
          </div>
          <div class="nav-group">
            <p class="nav-group-label">Catalog</p>
            <button type="button" class="nav-item" data-nav="servers">
              <!-- McpMark — two crossing arcs converging at a point.
                   Each MCP server is a "tool source"; the converging
                   geometry mirrors that. -->
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 48 48" width="16" height="16" fill="none">
                  <path d="M8 10 Q24 20 24 40" stroke="currentColor"
                        stroke-width="3" stroke-linecap="round" fill="none"/>
                  <path d="M40 10 Q24 20 24 40" stroke="currentColor"
                        stroke-width="3" stroke-linecap="round" fill="none"
                        opacity="0.55"/>
                  <circle cx="24" cy="40" r="2.6" fill="currentColor"/>
                </svg>
              </span>
              <span class="nav-item-label">MCP servers</span>
            </button>
            <button type="button" class="nav-item" data-nav="vservers">
              <!-- Three stacked plates fanning out — virtual servers
                   bundle multiple upstream tools into one URL. -->
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.5"
                     stroke-linecap="round" stroke-linejoin="round">
                  <ellipse cx="9" cy="4" rx="6" ry="1.6"/>
                  <path d="M3 4 V8.4 C3 9.4 5.7 10.2 9 10.2 S15 9.4 15 8.4 V4"/>
                  <path d="M3 9 V13.4 C3 14.4 5.7 15.2 9 15.2 S15 14.4 15 13.4 V9"
                        opacity="0.6"/>
                </svg>
              </span>
              <span class="nav-item-label">Virtual servers</span>
            </button>
          </div>
          <div class="nav-group">
            <p class="nav-group-label">Identity &amp; access</p>
            <button type="button" class="nav-item" data-nav="identities">
              <!-- AgentMark · re-used for the Identities tab since it's
                   the per-principal drill-in for what NHI map summarises. -->
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 48 48" width="16" height="16" fill="none">
                  <path d="M4 24 Q24 6 44 24 Q24 42 4 24 Z"
                        stroke="currentColor" stroke-width="2.4" fill="none"/>
                  <circle cx="24" cy="24" r="6" stroke="currentColor"
                          stroke-width="2.4" fill="none"/>
                  <circle cx="24" cy="24" r="2" fill="currentColor"/>
                </svg>
              </span>
              <span class="nav-item-label">Identities</span>
            </button>
            <button type="button" class="nav-item" data-nav="users">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="9" cy="6" r="3"/>
                  <path d="M3 16 C3 12.5 5.5 11 9 11 S15 12.5 15 16"/>
                </svg>
              </span>
              <span class="nav-item-label">Users</span>
            </button>
            <button type="button" class="nav-item" data-nav="groups">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="6" cy="6" r="2.5"/>
                  <circle cx="13" cy="6" r="2.5"/>
                  <path d="M2 14 C2 11.5 4 10 6 10 S10 11.5 10 14"/>
                  <path d="M9 14 C9 11.5 11 10 13 10 S17 11.5 17 14"
                        opacity="0.55"/>
                </svg>
              </span>
              <span class="nav-item-label">Groups</span>
            </button>
            <button type="button" class="nav-item" data-nav="api-key-policy">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="6" cy="9" r="3"/>
                  <path d="M9 9h6M13 9v3"/>
                  <path d="M9.5 3.6a6.5 6.5 0 0 1 0 10.8"/>
                </svg>
              </span>
              <span class="nav-item-label">API key policy</span>
            </button>
            <button type="button" class="nav-item" data-nav="access-requests">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M9 1 A8 8 0 1 1 1.96 12.93"/>
                  <path d="M6 9 L8.5 11.5 L13 7"/>
                </svg>
              </span>
              <span class="nav-item-label">Access requests</span>
            </button>
            <button type="button" class="nav-item" data-nav="admins">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M9 1.5 L14.5 4 V9 C14.5 12.5 12 15.5 9 16.5
                           C6 15.5 3.5 12.5 3.5 9 V4 Z"/>
                  <path d="M6.5 9.2 L8.4 11 L11.8 7.5"/>
                </svg>
              </span>
              <span class="nav-item-label">Admins</span>
            </button>
          </div>
          <div class="nav-group">
            <p class="nav-group-label">Observability</p>
            <button type="button" class="nav-item" data-nav="events">
              <!-- ToolCall mark — chevron envelope around centre dot,
                   the call unit. -->
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M5 4 L1.5 9 L5 14"/>
                  <path d="M13 4 L16.5 9 L13 14"/>
                  <circle cx="9" cy="9" r="1.5" fill="currentColor"/>
                </svg>
              </span>
              <span class="nav-item-label">Events</span>
            </button>
            <button type="button" class="nav-item" data-nav="admin-audit">
              <!-- Admin-audit mark — clipboard with check; what admins
                   did to the platform, captured for auditors. -->
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <rect x="4" y="3" width="10" height="13" rx="1.5"/>
                  <path d="M7 3 V2 H11 V3"/>
                  <path d="M6.5 10 L8 11.5 L11.5 8"/>
                </svg>
              </span>
              <span class="nav-item-label">Admin audit</span>
            </button>
            <button type="button" class="nav-item" data-nav="siem-export">
              <!-- SIEM mark — an outbound arrow leaving a box: events
                   shipped out of the gateway to the tenant's SIEM. -->
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M10 3 H4.5 A1.5 1.5 0 0 0 3 4.5 V13.5 A1.5 1.5 0 0 0 4.5 15 H10"/>
                  <path d="M8 9 H16"/>
                  <path d="M13 6 L16 9 L13 12"/>
                </svg>
              </span>
              <span class="nav-item-label">SIEM export</span>
            </button>
            <button type="button" class="nav-item" data-nav="telemetry">
              <!-- Telemetry mark — a pulse line: traces and metrics for
                   the people who run the gateway. -->
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M2 10 H5 L7 5 L10 14 L12 8 L13.5 10 H16"/>
                </svg>
              </span>
              <span class="nav-item-label">Telemetry</span>
            </button>
          </div>
          <div class="nav-group">
            <p class="nav-group-label">Settings</p>
            <button type="button" class="nav-item" data-nav="idp-directories">
              <!-- IdP-directory mark — globe with plug; an external
                   directory wired into the gateway. -->
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="9" cy="9" r="6"/>
                  <path d="M3 9 H15"/>
                  <path d="M9 3 C11.5 5.5 11.5 12.5 9 15"/>
                  <path d="M9 3 C6.5 5.5 6.5 12.5 9 15"/>
                </svg>
              </span>
              <span class="nav-item-label">Identity providers</span>
            </button>
            <button type="button" class="nav-item" data-nav="security-posture">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M9 2.2 L14.6 4.5 V9 c0 3.4-2.4 5.6-5.6 6.8
                           C5.8 14.6 3.4 12.4 3.4 9 V4.5 Z"/>
                  <path d="M6.6 9.1 L8.3 10.8 L11.6 7.4"/>
                </svg>
              </span>
              <span class="nav-item-label">Security posture</span>
            </button>
            <button type="button" class="nav-item" data-nav="risk-classifier">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <rect x="3" y="4" width="12" height="10" rx="2"/>
                  <path d="M6.5 8h5M6.5 11h3"/>
                </svg>
              </span>
              <span class="nav-item-label">Risk classifier</span>
            </button>
            <button type="button" class="nav-item" data-nav="secret-store">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <rect x="3" y="7.5" width="12" height="8" rx="1.5"/>
                  <path d="M5.5 7.5 V5 A3.5 3.5 0 0 1 12.5 5 V7.5"/>
                  <circle cx="9" cy="11.2" r="1" fill="currentColor"/>
                  <path d="M9 12 V13.5"/>
                </svg>
              </span>
              <span class="nav-item-label">Secret store</span>
            </button>
            <button type="button" class="nav-item" data-nav="troubleshooting">
              <!-- Wrench icon for Troubleshooting — diagnostic bundle
                   download moved here from the Dashboard so it lives
                   alongside other settings/admin tools. -->
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M11.5 2.5 a3.5 3.5 0 0 1 3.5 3.5 a3.5 3.5 0 0 1
                           -4.5 3.4 L4 16 L2 14 L8.6 7.5 a3.5 3.5 0 0 1
                           2.9 -5z"/>
                </svg>
              </span>
              <span class="nav-item-label">Troubleshooting</span>
            </button>
          </div>
        </nav>
        <div class="sidebar-foot">
          <div id="gateway-status-pill" class="gateway-status-pill"
               title="Gateway liveness and build context (auto-refreshed).">
            <span class="status-dot" aria-hidden="true"></span>
            <span class="status-text">checking&hellip;</span>
          </div>
          <div class="ui-pref-row" role="group" aria-label="UI preferences">
            <div class="ui-pref-toggle" role="radiogroup" aria-label="Theme">
              <button type="button" data-theme="light" title="Light theme">☀</button>
              <button type="button" data-theme="dark" title="Dark theme">☾</button>
            </div>
            <div class="ui-pref-toggle" role="radiogroup" aria-label="Density">
              <button type="button" data-density="cozy" title="Cozy density">≡</button>
              <button type="button" data-density="compact" title="Compact density">☰</button>
            </div>
          </div>
          <button type="button" id="palette-trigger" class="palette-trigger"
                  title="Search across servers, vservers, users, groups (⌘K)">
            <span class="palette-trigger-icon" aria-hidden="true">⌕</span>
            <span class="palette-trigger-label">Search</span>
            <kbd class="palette-trigger-kbd">⌘K</kbd>
          </button>
          <button type="button" id="alerts-trigger" class="palette-trigger alerts-trigger"
                  title="Recent denied / blocked tool calls">
            <span class="palette-trigger-icon" aria-hidden="true">◔</span>
            <span class="palette-trigger-label">Alerts</span>
            <span id="alerts-badge" class="alerts-badge" hidden>0</span>
          </button>
          <button type="button" class="nav-item nav-item-quiet"
                  data-nav="signin">
            <span class="nav-item-icon" aria-hidden="true">◔</span>
            <span class="nav-item-label">Sign in / out</span>
          </button>
        </div>
      </aside>
      <main class="content">

      <section class="panel auth-panel" data-nav="signin">
        <div class="auth-head">
          <p class="eyebrow">OPERATOR CONSOLE</p>
          <h2 id="auth-heading">Sign in</h2>
          <p id="auth-subhead" class="events-sub">Email + password &mdash; the credentials
            your tenant admin issued you.</p>
        </div>
        <div id="logged-out">
          <!-- Connected-IdP "Continue with X" buttons. Populated when
               the operator types a tenant_id below — we fetch the
               public list of connected directories for that tenant
               and render one button per kind. Empty by default. -->
          <div id="operator-idp-buttons"
               class="idp-button-row" hidden></div>
          <form id="login-form" class="form-grid">
            <label>
              Tenant ID
              <input name="tenant_id" id="login-tenant-id" required
                     placeholder="00000000-0000-0000-0000-000000000000">
            </label>
            <label>
              Email
              <input name="email" type="email" required
                     placeholder="admin@your-corp.example">
            </label>
            <label>
              Password
              <input name="password" type="password" required
                     autocomplete="current-password">
            </label>
            <button type="submit">Sign in</button>
          </form>
          <details style="margin-top: 12px;">
            <summary style="cursor: pointer; font-size: 0.85rem;">
              Advanced: paste a bearer token directly
            </summary>
            <p class="hint" style="margin-top: 6px;">
              For automation / lab use. Mints from
              <code>mint_operator_test_token()</code> against your
              <code>VYUU_OPERATOR_AUTH_SIGNING_SECRET</code>.
            </p>
            <label>
              Bearer token
              <input id="token" type="password" autocomplete="off" spellcheck="false">
            </label>
            <button id="save-token" type="button">Use token</button>
          </details>
          <pre id="login-output" class="output output-status"
               style="margin-top: 12px;">Not signed in.</pre>
        </div>
        <div id="logged-in" hidden>
          <p id="logged-in-meta" class="hint"></p>
          <button id="logout" type="button" class="ghost">Log out</button>
        </div>
      </section>

      <section class="panel" id="dashboard-panel" data-nav="dashboard">
        <div class="panel-head">
          <div>
            <p class="eyebrow">OVERVIEW &middot; DASHBOARD</p>
            <h2>Dashboard</h2>
            <p class="events-sub"
               title="For gateway health and the MCP-server roster see Health & servers;
                  for support hand-off see Settings · Troubleshooting.">
              Identity reach, catalog usage, queue and security signal &mdash; last 24
              hours.</p>
          </div>
          <div style="display:flex; gap:8px; align-items:center;">
            <button id="refresh-dashboard" type="button">Refresh</button>
          </div>
        </div>
        <div id="dashboard-output" class="kpi-grid">
          Click <strong>Refresh</strong> to load.
        </div>
      </section>

      <section class="panel" id="health-overview-panel"
               data-nav="health-overview">
        <div class="panel-head">
          <div>
            <p class="eyebrow">OVERVIEW &middot; HEALTH &amp; SERVERS</p>
            <h2>Gateway health and server roster</h2>
            <p class="events-sub"
               title="Instance health, security posture, MCP-server roster and p95 / p99
                  latency, polled from /api/v1/admin/health-overview.">
              Live snapshot &mdash; auto-refreshes every 15 s while this tab is open.</p>
          </div>
          <div style="display:flex; gap:8px; align-items:center;">
            <span id="health-last-refreshed" class="muted"
                  style="font-size:12px;"></span>
            <button id="refresh-health-overview" type="button">Refresh</button>
          </div>
        </div>

        <!-- KPI tiles row — mirrors the cloud-overview layout: instance
             count, uptime, p95 latency, cert-tracking count. -->
        <div class="health-kpi-row" id="health-kpi-row">
          <div class="health-kpi">
            <p class="health-kpi-label">GATEWAY INSTANCES</p>
            <p class="health-kpi-num" id="health-kpi-instances">&mdash;</p>
            <p class="health-kpi-sub" id="health-kpi-instances-sub">
              on-prem deployment
            </p>
          </div>
          <div class="health-kpi">
            <p class="health-kpi-label">UPTIME</p>
            <p class="health-kpi-num" id="health-kpi-uptime">&mdash;</p>
            <p class="health-kpi-sub" id="health-kpi-uptime-sub">
              since process boot
            </p>
          </div>
          <div class="health-kpi">
            <p class="health-kpi-label">P95 LATENCY &middot; 1H</p>
            <p class="health-kpi-num" id="health-kpi-p95">&mdash;</p>
            <p class="health-kpi-sub" id="health-kpi-p95-sub">
              avg: &mdash; &middot; samples: 0
            </p>
          </div>
          <div class="health-kpi">
            <p class="health-kpi-label">CERTS TO TRACK</p>
            <p class="health-kpi-num" id="health-kpi-certs">&mdash;</p>
            <p class="health-kpi-sub" id="health-kpi-certs-sub">
              SAML IdP signing certs
            </p>
          </div>
        </div>

        <!-- Tenant info card (analog of the screenshot's tenant block). -->
        <div class="health-tenant-card" id="health-tenant-card">
          <div class="health-tenant-row">
            <div>
              <p class="health-kpi-label">TENANT ID</p>
              <p class="health-tenant-value" id="health-tenant-id">&mdash;</p>
            </div>
            <div>
              <p class="health-kpi-label">SIGNING KEY</p>
              <p class="health-tenant-value" id="health-tenant-key">&mdash;</p>
            </div>
            <div>
              <p class="health-kpi-label">ENVIRONMENT</p>
              <p class="health-tenant-value" id="health-tenant-env">&mdash;</p>
            </div>
            <div>
              <p class="health-kpi-label">VERSION</p>
              <p class="health-tenant-value" id="health-tenant-version">&mdash;</p>
            </div>
          </div>
        </div>

        <!-- 5 status tiles: DB / audit / IdP / capability sync / SCIM. -->
        <div class="health-status-row" id="health-status-row">
          Loading&hellip;
        </div>

        <!-- MCP servers roster (the screenshot's "Control-plane regions"
             table, repurposed for our actual entity). -->
        <h3 class="health-section-head">MCP servers</h3>
        <div class="health-table-wrap">
          <table class="health-table" id="health-servers-table">
            <thead>
              <tr>
                <th>SERVER</th>
                <th>TRANSPORT</th>
                <th>STATUS</th>
                <th>AVG LATENCY &middot; 1H</th>
                <th>CALLS &middot; 1H</th>
                <th>CAPABILITIES</th>
                <th>LAST SYNC</th>
              </tr>
            </thead>
            <tbody id="health-servers-tbody">
              <tr><td colspan="7" class="health-empty">Click <strong>Refresh</strong> to load.</td></tr>
            </tbody>
          </table>
        </div>

        <!-- Per-hour p95 / p99 chart (last 24h) — small inline SVG so
             we don't pull a chart lib. -->
        <h3 class="health-section-head">Upstream call latency &middot; 24h</h3>
        <div class="health-chart-wrap">
          <svg id="health-latency-chart" viewBox="0 0 900 220"
               preserveAspectRatio="none" aria-label="p95 / p99 latency over 24h">
          </svg>
          <p class="muted" id="health-chart-caption" style="font-size:12px;">
            (no upstream calls in window)
          </p>
        </div>
      </section>

      <section class="panel" id="troubleshooting-panel"
               data-nav="troubleshooting">
        <div class="panel-head">
          <div>
            <p class="eyebrow">SETTINGS &middot; TROUBLESHOOTING</p>
            <h2>Troubleshooting</h2>
            <p class="events-sub"
               title="Process state, connectivity, audit pipeline (in-memory and
                  persistent), MCP servers and sync issues, IdP directories, circuit
                  breakers, background workers, recent decisions.">
              A one-shot diagnostic bundle you can hand to support. Secrets are
              redacted.</p>
          </div>
          <div style="display:flex; gap:8px; align-items:center;">
            <label style="font-size:12px;">
              Window
              <select id="diagnostic-bundle-window">
                <option value="15">Last 15 min</option>
                <option value="60" selected>Last 1 h</option>
                <option value="360">Last 6 h</option>
                <option value="1440">Last 24 h</option>
              </select>
            </label>
            <button id="download-diagnostic-bundle" type="button">
              Download diagnostic bundle
            </button>
          </div>
        </div>
        <div class="diagnostic-coverage-grid">
          <div class="diagnostic-coverage-card">
            <h4>Process &amp; host</h4>
            <p>Uptime, RSS, CPU, FDs, host name, platform, Python.</p>
          </div>
          <div class="diagnostic-coverage-card">
            <h4>Connectivity</h4>
            <p>Postgres reachability, Redis (if configured), audit
              emitter chain class, secret store backend.</p>
          </div>
          <div class="diagnostic-coverage-card">
            <h4>MCP servers + vservers</h4>
            <p>Counts, health distribution, sync issues, vserver
              visibility breakdown.</p>
          </div>
          <div class="diagnostic-coverage-card">
            <h4>Audit pipeline</h4>
            <p>Hot-buffer size, persistent <code>tool_call_events</code>
              counts, oldest/newest event, by-decision distribution,
              warm-up state.</p>
          </div>
          <div class="diagnostic-coverage-card">
            <h4>IdP directories</h4>
            <p>Per directory: kind, signin protocol, last SCIM sync,
              users provisioned. SCIM tokens are NEVER included.</p>
          </div>
          <div class="diagnostic-coverage-card">
            <h4>Admin audit</h4>
            <p>Recent admin actions in window, by-actor distribution,
              last 20 rows in detail.</p>
          </div>
          <div class="diagnostic-coverage-card">
            <h4>Background workers</h4>
            <p>SCIM hard-delete sweeper state + cycles. Capability sync
              scheduler state + interval.</p>
          </div>
          <div class="diagnostic-coverage-card">
            <h4>Circuit breakers + inflight gate</h4>
            <p>Per-pool-key state (open / half-open), inflight cap,
              uvicorn concurrency settings.</p>
          </div>
        </div>
        <div id="diagnostic-bundle-output" class="muted"
             style="margin-top:8px; font-size:12px; min-height:1em;"></div>
      </section>

      <section class="panel" id="nhi-map-panel" data-nav="nhi-map">
        <div class="panel-head">
          <div>
            <p class="eyebrow">OVERVIEW &middot; NHI MAP</p>
            <h2>Who uses what</h2>
            <p class="events-sub"
               title="Five-column flow: users and agents, the AI apps inferred from
                  user_agent, the MCP servers the gateway routes to, and either every
                  tool called or the risk-category buckets. Thicker edges = more
                  interactions; dashed outlines = unsanctioned.">
              Users and agents &rarr; AI apps &rarr; MCP servers &rarr; tools. Hover
              to highlight, click to focus.</p>
          </div>
          <div style="display: flex; gap: 8px;">
            <select id="nhi-map-window" title="Time window">
              <option value="1h">Last 1h</option>
              <option value="24h" selected>Last 24h</option>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
            </select>
            <select id="nhi-map-filter">
              <option value="all">All</option>
              <option value="sanctioned_only">Sanctioned</option>
            </select>
            <select id="nhi-map-fifth">
              <option value="tool">5th col · Tools</option>
              <option value="risk">5th col · Risk category</option>
              <option value="off">5th col · Off (4-col view)</option>
            </select>
            <button id="refresh-nhi-map" type="button">Refresh</button>
          </div>
        </div>
        <div id="nhi-map-output">Click <strong>Refresh</strong> to load.</div>
      </section>

      <section class="panel" data-nav="servers">
        <div class="panel-head">
          <div>
            <p class="eyebrow">CATALOG &middot; MCP SERVERS</p>
            <h2>MCP servers</h2>
            <p class="events-sub"
               title="HTTP, stdio (npm / pypi / binary) and SSE all land here. Per-row
                  Sync re-pulls capabilities; Publish opens an inline virtual-server
                  drawer.">
              Every upstream the gateway can route to.</p>
          </div>
          <div style="display: flex; gap: 8px;">
            <button id="refresh-servers" type="button">Refresh</button>
            <button id="register-server-jump" type="button" class="btn-primary">+ Register</button>
          </div>
        </div>
        <!-- Quick-add from connector catalog. Cards are populated from
             GET /api/v1/operator/connector-catalog. Clicking a card
             opens the existing register wizard with everything
             pre-filled except client_id_ref / client_secret_ref. -->
        <div class="connector-catalog-section" id="connector-catalog-section"
             data-collapsed="true">
          <div class="connector-catalog-head">
            <div>
              <h3 class="connector-catalog-title">Quick add from catalog</h3>
              <p class="connector-catalog-sub"
                 title="Pre-fills runtime, URL, transport and OAuth. You add the secret refs.">
                   Pre-configured SaaS MCP servers &mdash; pick one to pre-fill the
                wizard.</p>
            </div>
            <button id="connector-catalog-toggle" type="button"
                    class="connector-catalog-toggle"
                    aria-expanded="true">Show</button>
          </div>
          <div id="connector-catalog-grid" class="connector-catalog-grid"
               role="list" aria-label="SaaS connector catalog">
            <p class="connector-catalog-loading">Loading catalog&hellip;</p>
          </div>
        </div>
        <div class="server-toolbar">
          <input id="servers-search" type="search"
                 placeholder="Search by name, id, runtime, auth mode&hellip;">
          <div class="server-filters" role="tablist">
            <button type="button" class="filter-pill is-active" data-filter="all">All</button>
            <button type="button" class="filter-pill" data-filter="http">HTTP</button>
            <button type="button" class="filter-pill" data-filter="npm">stdio · npm</button>
            <button type="button" class="filter-pill" data-filter="pypi">stdio · pypi</button>
            <button type="button" class="filter-pill" data-filter="stdio">stdio</button>
            <button type="button" class="filter-pill" data-filter="binary">binary</button>
          </div>
          <span id="servers-count" class="toolbar-meta"></span>
        </div>
        <div id="servers-output" class="servers-table-wrap">Not loaded.</div>
        <!-- Inline drawer that opens below a row when "Publish vserver"
             is clicked. Reused across rows so only one drawer is open
             at a time. -->
        <div id="server-row-drawer" class="row-drawer" hidden></div>
      </section>

      <!-- Hidden refresh-health button kept so existing wiring works.
           Gateway-health rendering moved to a small status pill in the
           sidebar foot; the standalone giant card was wasted real
           estate next to a table that's the actual content. -->
      <section data-nav="__hidden_health__" class="is-hidden" hidden>
        <button id="refresh-health" type="button">Refresh</button>
        <pre id="health-output" class="output">Not loaded.</pre>
      </section>

      <section class="panel wizard-shell" data-nav="servers" data-wizard-mode="closed" hidden>
        <header class="wizard-head">
          <div>
            <p class="eyebrow">CATALOG · NEW SERVER</p>
            <h1 class="wizard-title">Register an MCP server</h1>
            <p class="wizard-sub">Wire any MCP-compliant upstream — first-party,
              vendor-hosted, or a local stdio script — and attach the auth
              scheme the gateway should use to call it.</p>
          </div>
          <button type="button" class="wizard-cancel" id="wizard-cancel">Cancel</button>
        </header>

        <ol class="wizard-progress" role="list" aria-label="Registration steps">
          <li class="wizard-step-pill" data-step="1">
            <span class="wizard-step-num">1</span>
            <span class="wizard-step-label">Runtime</span>
          </li>
          <li class="wizard-step-pill" data-step="2">
            <span class="wizard-step-num">2</span>
            <span class="wizard-step-label">Connection</span>
          </li>
          <li class="wizard-step-pill" data-step="3">
            <span class="wizard-step-num">3</span>
            <span class="wizard-step-label">Authentication</span>
          </li>
          <li class="wizard-step-pill" data-step="4">
            <span class="wizard-step-num">4</span>
            <span class="wizard-step-label">Capabilities</span>
          </li>
          <li class="wizard-step-pill" data-step="5">
            <span class="wizard-step-num">5</span>
            <span class="wizard-step-label">Review</span>
          </li>
        </ol>

        <div class="register-layout wizard-body">
        <form id="register-form" class="wizard-form" novalidate>
          <!-- ===== STEP 1 · RUNTIME ===== -->
          <div class="wizard-step" data-step="1">
            <p class="eyebrow">STEP 1 OF 5</p>
            <h2 class="wizard-step-title">Runtime</h2>
            <p class="hint">Pick how the gateway will reach this server.
              HTTP suits vendor-hosted SaaS MCPs; npm / pypi / stdio /
              binary cover locally-spawned subprocesses.</p>

            <div class="runtime-card-grid" role="radiogroup" aria-label="Source type">
              <label class="runtime-card">
                <input type="radio" name="source_type" value="http" checked>
                <span class="runtime-card-title">HTTP</span>
                <span class="runtime-card-hint">Vendor-hosted streamable HTTP</span>
              </label>
              <label class="runtime-card">
                <input type="radio" name="source_type" value="npm">
                <span class="runtime-card-title">npm</span>
                <span class="runtime-card-hint">via npx, stdio</span>
              </label>
              <label class="runtime-card">
                <input type="radio" name="source_type" value="pypi">
                <span class="runtime-card-title">pypi</span>
                <span class="runtime-card-hint">via uvx, stdio</span>
              </label>
              <label class="runtime-card">
                <input type="radio" name="source_type" value="stdio">
                <span class="runtime-card-title">stdio</span>
                <span class="runtime-card-hint">Local script (absolute path)</span>
              </label>
              <label class="runtime-card">
                <input type="radio" name="source_type" value="binary">
                <span class="runtime-card-title">binary</span>
                <span class="runtime-card-hint">Compiled executable</span>
              </label>
            </div>

            <label class="wizard-field">
              <span>Display name <span class="req">*</span></span>
              <input name="display_name" required maxlength="255"
                     placeholder="drawio-http" autocomplete="off">
            </label>
          </div>

          <!-- ===== STEP 2 · CONNECTION ===== -->
          <div class="wizard-step" data-step="2" hidden>
            <p class="eyebrow">STEP 2 OF 5</p>
            <h2 class="wizard-step-title">Connection</h2>
            <p class="hint">Where does the gateway reach this server?
              For HTTP, the streamable-HTTP entrypoint URL. For
              stdio / npm / pypi, the package or path to spawn.</p>

            <label class="wizard-field">
              <span id="source-location-label">Endpoint <span class="req">*</span></span>
              <input name="source_location" required maxlength="2048"
                     placeholder="https://mcp.draw.io/mcp" autocomplete="off">
              <span class="hint" id="source-location-hint">
                The streamable HTTP entrypoint exposed by the upstream MCP server.
              </span>
            </label>

            <div class="wizard-field-row">
              <label class="wizard-field">
                <span>Transport</span>
                <select name="transport">
                  <option value="streamable_http">streamable_http</option>
                  <option value="stdio">stdio</option>
                  <option value="sse">sse legacy</option>
                </select>
              </label>
              <label class="wizard-field" data-stdio-only>
                <span>Args (JSON list)</span>
                <input name="args" placeholder='["--port", "0"]'>
              </label>
              <label class="wizard-field" data-stdio-only>
                <span>Env vars ref</span>
                <input name="env_vars_ref" placeholder="vault://tenant/path">
              </label>
            </div>
          </div>

          <!-- ===== STEP 3 · AUTHENTICATION ===== -->
          <div class="wizard-step" data-step="3" hidden>
          <!-- Auth section: starts here. The dense JSON-blob inputs
               that lived here previously were unreadable; replaced with
               a 6-card mode picker (None / Org headers / Pass-through /
               OAuth M2M / OAuth user / JWT-bearer) that conditionally
               reveals the structured sub-fields for the chosen mode.
               Provider-preset popovers fill those sub-fields directly
               (no JSON typing needed). mTLS sits in its own sub-panel
               below the picker since it&rsquo;s a transport-layer
               credential and coexists with any application-layer mode. -->
          <div class="auth-section" style="grid-column: 1 / -1;">
            <div class="auth-section-head">
              <h3>Outbound authentication</h3>
              <p class="hint"
                 title="One application-layer mode. mTLS is transport-layer and coexists.">
                   How the gateway authenticates to this server. Pick one.</p>
            </div>

            <div class="auth-mode-picker" role="radiogroup"
                 aria-label="Auth mode">
              <label class="auth-mode-card">
                <input type="radio" name="auth_mode" value="none" checked>
                <span class="auth-mode-title">None</span>
                <span class="auth-mode-hint">Public MCP, no creds</span>
              </label>
              <label class="auth-mode-card">
                <input type="radio" name="auth_mode" value="headers">
                <span class="auth-mode-title">Org headers</span>
                <span class="auth-mode-hint">Static creds via SecretStore</span>
              </label>
              <label class="auth-mode-card">
                <input type="radio" name="auth_mode" value="passthrough">
                <span class="auth-mode-title">Pass-through</span>
                <span class="auth-mode-hint">Each user brings their own token</span>
              </label>
              <label class="auth-mode-card">
                <input type="radio" name="auth_mode" value="oauth">
                <span class="auth-mode-title">OAuth M2M</span>
                <span class="auth-mode-hint">RFC 6749 client_credentials</span>
              </label>
              <label class="auth-mode-card">
                <input type="radio" name="auth_mode" value="authcode">
                <span class="auth-mode-title">OAuth user</span>
                <span class="auth-mode-hint">Per-user delegated (A1)</span>
              </label>
              <label class="auth-mode-card">
                <input type="radio" name="auth_mode" value="jwt_bearer">
                <span class="auth-mode-title">JWT-bearer</span>
                <span class="auth-mode-hint">RFC 7523 service account (A2)</span>
              </label>
            </div>

            <!-- Per-mode field groups. Visibility flips via the
                 `body[data-auth-mode="X"]` attribute set by the radio
                 change handler. -->
            <div class="auth-fields" data-mode-fields="headers">
              <div class="auth-fields-head">
                <strong>Header → SecretStore-ref map</strong>
                <span class="hint">JSON object: {"header_name":"secret_ref"}.
                  Headers ride on every outbound HTTP request to this server.</span>
              </div>
              <input name="auth_headers" type="text"
                     placeholder='{"Authorization":"paypal-bearer"}'>
            </div>

            <div class="auth-fields" data-mode-fields="passthrough">
              <div class="auth-fields-head">
                <strong>Inbound → upstream header rename</strong>
                <span class="hint">JSON: {"inbound_header":"upstream_header"}.
                  The user&rsquo;s own credential is forwarded — never stored
                  by the gateway. HTTP transports only.</span>
              </div>
              <input name="auth_passthrough" type="text"
                     placeholder='{"x-vyuu-paypal-token":"Authorization"}'>
            </div>

            <div class="auth-fields" data-mode-fields="oauth">
              <div class="auth-fields-head">
                <strong>OAuth client_credentials (M2M)</strong>
                <span class="hint">One gateway-owned credential serves all
                  callers. Use for SaaS that issues an org-wide service token.</span>
                <button type="button" class="info-btn"
                        data-info="auth-oauth-cc"
                        aria-label="OAuth M2M info">i</button>
              </div>
              <div class="auth-grid">
                <label>Token URL <span class="req">*</span>
                  <input data-auth-oauth="token_url" type="text"
                         placeholder="https://auth.example.com/oauth/token">
                </label>
                <label>Audience
                  <input data-auth-oauth="audience" type="text"
                         placeholder="https://api.example.com">
                </label>
                <label>client_id ref <span class="req">*</span>
                  <span class="hint">Secret-store key, NOT the literal client_id.
                    e.g. <code>example-client-id</code> &rarr; resolves
                    via Vault / env var.</span>
                  <input data-auth-oauth="client_id_ref" type="text"
                         data-secret-ref-input
                         placeholder="example-client-id">
                </label>
                <label>client_secret ref <span class="req">*</span>
                  <span class="hint">Secret-store key, NOT the raw secret.</span>
                  <input data-auth-oauth="client_secret_ref" type="text"
                         data-secret-ref-input
                         placeholder="example-client-secret">
                </label>
                <label class="auth-grid-wide">Scope
                  <input data-auth-oauth="scope" type="text"
                         placeholder="api:read api:write">
                </label>
              </div>
            </div>

            <div class="auth-fields" data-mode-fields="authcode">
              <div class="auth-fields-head">
                <strong>OAuth authorization-code · per-user delegated</strong>
                <span class="hint">Each user grants the gateway access to
                  their own SaaS account. Pick a provider preset to one-click
                  fill the URLs + scopes.</span>
                <button type="button" class="info-btn"
                        data-info="auth-authcode"
                        aria-label="OAuth user-delegated presets">i</button>
              </div>
              <!-- DCR toggle: operator opts in for spec-compliant
                   vendors (Notion, Linear, Sentry, HuggingFace,
                   PayPal, Asana, Cloudflare, Anthropic-hosted, etc.)
                   that follow the MCP-Auth standard. Catalog cards
                   flip this for the operator; manual registrations
                   tick it themselves. State mirrored into the hidden
                   `auth_authcode_dcr_enabled` input that
                   serializeAuthFields() reads on submit. -->
              <label class="auth-dcr-toggle">
                <input type="checkbox" id="auth-authcode-dcr-toggle">
                <span>
                  <strong>Use Dynamic Client Registration</strong>
                  <span class="hint">
                    Gateway auto-discovers the upstream&rsquo;s OAuth
                    metadata and registers itself as a client on first
                    Connect (RFC 9728 + 8414 + 7591). No vendor-side
                    OAuth-app setup needed. Works with Notion, Linear,
                    Sentry, HuggingFace, PayPal, Asana, Cloudflare,
                    and any vendor built on the official MCP SDK auth
                    helpers.
                  </span>
                </span>
              </label>
              <!-- DCR mode banner: appears only when the toggle is on
                   (catalog click or manual tick). The four static
                   fields below collapse via CSS in this mode. -->
              <div class="auth-dcr-banner" data-authcode-dcr-only>
                <strong>Dynamic Client Registration (RFC 7591)</strong>
                <p class="hint" style="margin: 4px 0 0;"
                   title="Discovery + registration run on first Connect. Nothing to provision.">
                  The gateway registers itself on first Connect &mdash; you
                  don&rsquo;t provision <code>client_id</code> yourself.
                </p>
              </div>
              <!-- U11 — Initial Access Token ref. Optional, DCR-only.
                   Required by some enterprise IdPs (Okta, certain
                   Auth0 tenants) that gate /register behind a Bearer
                   token. Public SaaS DCR vendors (Notion, Linear,
                   Cloudflare, Sentry, etc.) leave this blank. -->
              <label class="auth-grid-wide" data-authcode-dcr-only>
                Initial Access Token ref
                <span class="hint">Optional. Secret-store key for an
                  RFC 7591 §3 Initial Access Token. Only fill this in
                  if your IdP gates the registration endpoint behind a
                  Bearer token (Okta, some Auth0 tenants, private B2B
                  IdPs). Notion / Linear / Cloudflare / Sentry don&rsquo;t
                  need one.</span>
                <input data-auth-authcode="initial_access_token_ref" type="text"
                       data-secret-ref-input
                       placeholder="okta-mcp-iat">
              </label>
              <div class="auth-grid">
                <label class="auth-grid-wide" data-authcode-static-only>
                  Authorize URL <span class="req">*</span>
                  <input data-auth-authcode="auth_url" type="text"
                         placeholder="https://github.com/login/oauth/authorize">
                </label>
                <label class="auth-grid-wide" data-authcode-static-only>
                  Token URL <span class="req">*</span>
                  <input data-auth-authcode="token_url" type="text"
                         placeholder="https://github.com/login/oauth/access_token">
                </label>
                <label data-authcode-static-only>client_id ref <span class="req">*</span>
                  <span class="hint">Secret-store key, NOT the literal
                    client_id. e.g. <code>github-client-id</code>
                    &rarr; resolved at runtime via Vault / env var.</span>
                  <input data-auth-authcode="client_id_ref" type="text"
                         data-secret-ref-input
                         placeholder="github-client-id">
                </label>
                <label data-authcode-static-only>client_secret ref <span class="req">*</span>
                  <span class="hint">Secret-store key, NOT the raw secret.</span>
                  <input data-auth-authcode="client_secret_ref" type="text"
                         data-secret-ref-input
                         placeholder="github-client-secret">
                </label>
                <label class="auth-grid-wide">Redirect URI <span class="req">*</span>
                  <input data-auth-authcode="redirect_uri" type="text"
                         placeholder="http://localhost:8000/api/v1/oauth-authcode/callback">
                </label>
                <label class="auth-grid-wide">Scopes
                  <span class="hint">Comma-separated.</span>
                  <input data-auth-authcode="scopes" type="text"
                         placeholder="read:user, repo">
                </label>
                <label class="auth-grid-wide">Extra authorize params
                  <span class="hint">Optional JSON. Google needs
                    <code>{"access_type":"offline","prompt":"consent"}</code>
                    or it won&rsquo;t issue a refresh token.</span>
                  <input data-auth-authcode="extra_authorize_params" type="text"
                         placeholder='{"access_type":"offline","prompt":"consent"}'>
                </label>
              </div>
            </div>

            <div class="auth-fields" data-mode-fields="jwt_bearer">
              <div class="auth-fields-head">
                <strong>JWT-bearer · RFC 7523 service-account assertion</strong>
                <span class="hint">The gateway signs a short-lived JWT and
                  exchanges it for a bearer token. Workspace SAs, IRA, etc.</span>
                <button type="button" class="info-btn"
                        data-info="auth-jwt-bearer"
                        aria-label="JWT-bearer presets">i</button>
              </div>
              <div class="auth-grid">
                <label class="auth-grid-wide">Token URL <span class="req">*</span>
                  <input data-auth-jwt="token_url" type="text"
                         placeholder="https://oauth2.googleapis.com/token">
                </label>
                <label>Algorithm <span class="req">*</span>
                  <select data-auth-jwt="algorithm">
                    <option value="RS256">RS256</option>
                    <option value="RS384">RS384</option>
                    <option value="RS512">RS512</option>
                    <option value="ES256">ES256</option>
                    <option value="ES384">ES384</option>
                    <option value="PS256">PS256</option>
                  </select>
                </label>
                <label>private_key ref <span class="req">*</span>
                  <span class="hint">Secret-store key, NOT the PEM body.
                    The gateway resolves this at sign time and never
                    logs the resolved key.</span>
                  <input data-auth-jwt="private_key_ref" type="text"
                         data-secret-ref-input
                         placeholder="google-sa-private-key">
                </label>
                <label>Issuer (iss) <span class="req">*</span>
                  <input data-auth-jwt="issuer" type="text"
                         placeholder="sa@project.iam.gserviceaccount.com">
                </label>
                <label>Subject (sub) <span class="req">*</span>
                  <span class="hint">For Workspace impersonation: the user
                    being acted on behalf of.</span>
                  <input data-auth-jwt="subject" type="text"
                         placeholder="alice@corp.example">
                </label>
                <label class="auth-grid-wide">Audience (aud) <span class="req">*</span>
                  <input data-auth-jwt="audience" type="text"
                         placeholder="https://oauth2.googleapis.com/token">
                </label>
                <label class="auth-grid-wide">Body-form scope
                  <input data-auth-jwt="scope" type="text"
                         placeholder="api:read">
                </label>
                <label class="auth-grid-wide">Additional claims
                  <span class="hint">Optional JSON. Google needs
                    <code>{"scope":"https://www.googleapis.com/auth/drive.readonly"}</code>
                    inside the assertion.</span>
                  <input data-auth-jwt="additional_claims" type="text"
                         placeholder='{"scope":"https://www.googleapis.com/auth/drive.readonly"}'>
                </label>
              </div>
            </div>

            <div class="auth-fields" data-mode-fields="env">
              <div class="auth-fields-head">
                <strong>Stdio env-var injection</strong>
                <span class="hint">JSON: {"ENV_VAR":"secret_ref"}. Stdio
                  transports only — passed to the spawned subprocess.</span>
              </div>
              <input name="auth_env" type="text"
                     placeholder='{"FALCON_CLIENT_ID":"falcon-id"}'>
            </div>

            <!-- mTLS lives outside the mode picker — it's a transport-
                 layer credential and coexists with any of the modes
                 above. Compact 2-up so it doesn't dominate. -->
            <div class="mtls-fields">
              <div class="auth-fields-head">
                <strong>mTLS client cert</strong>
                <span class="hint">Optional. Both refs must be set together.
                  Coexists with any mode above.</span>
                <button type="button" class="info-btn"
                        data-info="mtls"
                        aria-label="mTLS info">i</button>
              </div>
              <div class="auth-grid">
                <label>cert ref
                  <input name="mtls_cert_ref" type="text"
                         placeholder="corp-mtls-cert">
                </label>
                <label>key ref
                  <input name="mtls_key_ref" type="text"
                         placeholder="corp-mtls-key">
                </label>
              </div>
            </div>
          </div>

          <!-- Hidden inputs the form submission code reads — written by
               the structured-fields → JSON serialiser on submit. -->
          <input type="hidden" name="auth_oauth">
          <input type="hidden" name="auth_authcode">
          <input type="hidden" name="auth_jwt_bearer">
          <!-- DCR flag: catalog click sets this to "true" for vendors
               that follow the MCP-Auth standard (RFC 9728/8414/7591).
               serializeAuthFields() reads it and merges into the
               assembled auth_authcode JSON. Default "false". -->
          <input type="hidden" name="auth_authcode_dcr_enabled" value="false">
          <!-- auth_headers, auth_passthrough, auth_env keep their original
               <input name=...> bindings inside the per-mode field groups
               above; the form serializer picks them up directly. -->
          </div>
          <!-- /step 3 -->

          <!-- ===== STEP 4 · CAPABILITIES PREFLIGHT ===== -->
          <div class="wizard-step" data-step="4" hidden>
            <p class="eyebrow">STEP 4 OF 5</p>
            <h2 class="wizard-step-title">Capabilities</h2>
            <p class="hint"
                 title="Synced on demand, or on the cadence set in Step 5.">
                   Preview a static <code>mcp.json</code> manifest first?</p>
            <div class="wizard-preflight">
              <label class="wizard-field">
                <span>Manifest URL (optional)</span>
                <input type="url" id="wizard-manifest-url"
                       placeholder="https://api.example.com/mcp.json"
                       autocomplete="off">
                <span class="hint">If the vendor publishes a static
                  manifest, paste its URL to auto-detect transport /
                  source / auth hints. Leave blank to skip.</span>
              </label>
              <button type="button" id="wizard-probe-btn">
                Preview manifest
              </button>
              <div id="wizard-probe-output" class="wizard-preflight-output">
                <p class="hint"
                   title="Click Sync on the server row afterwards to pull the live catalogue.">
                     <strong>Skipping is fine.</strong> You can sync after registration.</p>
              </div>
            </div>
          </div>

          <!-- ===== STEP 5 · REVIEW ===== -->
          <div class="wizard-step" data-step="5" hidden>
            <p class="eyebrow">STEP 5 OF 5</p>
            <h2 class="wizard-step-title">Review &amp; register</h2>
            <p class="hint">Confirm the manifest below. Once registered,
              you can publish virtual servers from this catalogue.</p>
            <div class="wizard-review">
              <p class="eyebrow">FINAL MANIFEST</p>
              <pre id="wizard-review-pre" class="output register-preview-pre"></pre>
              <p class="eyebrow">PRE-FLIGHT</p>
              <ul id="wizard-review-checklist" class="wizard-review-checklist"></ul>
            </div>
            <button type="submit" class="btn-primary wizard-register-btn">
              Register MCP server
            </button>
          </div>

        </form>
        <aside class="register-preview" aria-label="Live manifest preview">
          <div class="register-preview-head">
            <p class="eyebrow">LIVE PREVIEW</p>
            <h3>Manifest</h3>
            <p class="hint">Updates as you fill the wizard. Step 5 is the
              final review.</p>
          </div>
          <pre id="register-preview-pre" class="output register-preview-pre"></pre>
          <div class="register-preview-checklist">
            <p class="eyebrow">CHECKLIST</p>
            <ul id="register-preview-checklist-list"></ul>
          </div>
        </aside>
        </div>

        <footer class="wizard-foot">
          <button type="button" id="wizard-back" class="wizard-back" disabled>
            ← Back
          </button>
          <span class="wizard-foot-status" id="wizard-foot-status"></span>
          <button type="button" id="wizard-next" class="btn-primary wizard-next">
            Continue →
          </button>
        </footer>
        <pre id="register-output" class="output output-status" hidden>Waiting for submission.</pre>
      </section>

      <!-- Capabilities panel retired — its data is the same the
           Publish-vserver row drawer already shows in-line on the
           MCP servers table. The tab was reachable from the sidebar
           but always rendered the "click Sync" stub since the row
           Sync button is the natural entry-point. The DOM stub stays
           hidden so any test that probes `#capabilities-output`
           still finds the element. -->
      <section class="panel is-hidden" data-nav="capabilities" hidden>
        <div id="capabilities-output" hidden></div>
      </section>

      <section class="panel events-panel-v2 vservers-panel-v2"
               id="vservers-panel" data-nav="vservers">
        <header class="events-head">
          <div>
            <p class="eyebrow">CATALOG &middot; VIRTUAL SERVERS</p>
            <h1>Tenant-published bundles</h1>
            <p class="events-sub"
               title="A curated tool subset, gated by visibility + grants.">
              Each row exposes <code>/v/&lt;tenant&gt;/&lt;name&gt;/mcp</code>.
            </p>
          </div>
          <div class="events-head-actions">
            <input id="vservers-search" type="search" class="events-icon-btn"
                   placeholder="Search by name&hellip;"
                   style="border-radius: 999px; padding: 7px 14px;
                          min-width: 200px;">
            <button id="open-create-vserver" type="button">+ New vserver</button>
            <button id="refresh-vservers" type="button">Refresh</button>
          </div>
        </header>

        <div class="events-kpi-grid">
          <div class="events-kpi">
            <p class="events-kpi-label">TOTAL VSERVERS</p>
            <p class="events-kpi-num" id="vservers-kpi-total">&mdash;</p>
            <p class="events-kpi-pill">in tenant</p>
          </div>
          <div class="events-kpi events-kpi-distinctive">
            <p class="events-kpi-label">EMPTY</p>
            <p class="events-kpi-num" id="vservers-kpi-empty">&mdash;</p>
            <p class="events-kpi-pill">no tools allowlisted</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">PRIVATE</p>
            <p class="events-kpi-num" id="vservers-kpi-private">&mdash;</p>
            <p class="events-kpi-pill">grant-gated</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">PUBLIC</p>
            <p class="events-kpi-num" id="vservers-kpi-public">&mdash;</p>
            <p class="events-kpi-pill">tenant-wide reach</p>
          </div>
        </div>

        <div class="events-pill-row" role="tablist" aria-label="Vserver filter">
          <button type="button" class="events-pill is-active"
                  data-vservers-pill="all">All</button>
          <button type="button" class="events-pill"
                  data-vservers-pill="public">Public</button>
          <button type="button" class="events-pill"
                  data-vservers-pill="private">Private</button>
          <button type="button" class="events-pill"
                  data-vservers-pill="has_grants">Has grants</button>
          <button type="button" class="events-pill"
                  data-vservers-pill="empty">Empty</button>
        </div>

        <div class="events-table-wrap">
          <table class="events-table vservers-table">
            <thead>
              <tr>
                <th class="vservers-col-name">VSERVER</th>
                <th class="vservers-col-url">URL</th>
                <th class="vservers-col-tools">TOOLS</th>
                <th class="vservers-col-grants">GRANTS</th>
                <th class="vservers-col-jit">JIT</th>
                <th class="vservers-col-created">CREATED</th>
                <th class="vservers-col-actions"></th>
              </tr>
            </thead>
            <tbody id="vservers-output">
              <tr><td colspan="7" class="events-empty">
                Click <strong>Refresh</strong> to load.
              </td></tr>
            </tbody>
          </table>
        </div>
        <p class="identities-footnote">
          <span id="vservers-count" class="toolbar-meta"></span>
        </p>

        <!-- Slide-over drawer: Tools / Access / Settings for one vserver. -->
        <div id="vserver-drawer" class="identity-drawer" hidden
             role="dialog" aria-modal="true" aria-labelledby="vserver-drawer-title">
          <div class="identity-drawer-backdrop"
               data-vserver-drawer-close></div>
          <div class="identity-drawer-panel">
            <header class="identity-drawer-head">
              <div>
                <p class="eyebrow">VIRTUAL SERVER</p>
                <h2 id="vserver-drawer-title">&mdash;</h2>
                <p class="identity-drawer-sub" id="vserver-drawer-sub"></p>
              </div>
              <button type="button" class="events-icon-btn"
                      data-vserver-drawer-close aria-label="Close">
                &times;
              </button>
            </header>
            <div class="identity-drawer-tabs" role="tablist">
              <button type="button" class="identity-drawer-tab is-active"
                      data-vserver-drawer-tab="tools">Tools</button>
              <button type="button" class="identity-drawer-tab"
                      data-vserver-drawer-tab="access">Access</button>
              <button type="button" class="identity-drawer-tab"
                      data-vserver-drawer-tab="jit">JIT</button>
              <button type="button" class="identity-drawer-tab"
                      data-vserver-drawer-tab="risk">Risk</button>
              <button type="button" class="identity-drawer-tab"
                      data-vserver-drawer-tab="settings">Settings</button>
            </div>
            <div class="identity-drawer-body" id="vserver-drawer-body">
              &mdash;
            </div>
          </div>
        </div>

        <!-- Modal: + New vserver. Same lightweight pattern as +New user. -->
        <div id="create-vserver-modal" class="identity-drawer" hidden
             role="dialog" aria-modal="true" aria-labelledby="create-vserver-modal-title">
          <div class="identity-drawer-backdrop"
               data-create-vserver-close></div>
          <div class="identity-drawer-panel users-modal-panel">
            <header class="identity-drawer-head">
              <div>
                <p class="eyebrow">NEW VIRTUAL SERVER</p>
                <h2 id="create-vserver-modal-title">Create virtual server</h2>
                <p class="identity-drawer-sub">
                  Pick tools from the Capabilities panel above (they
                  pre-fill below). The selected tools become the
                  allowlist on the new vserver.
                </p>
              </div>
              <button type="button" class="events-icon-btn"
                      data-create-vserver-close aria-label="Close">
                &times;
              </button>
            </header>
            <div class="identity-drawer-body">
              <form id="vserver-form" class="form-grid">
                <label style="grid-column: 1 / -1;">
                  Name
                  <input name="name" required maxlength="255" placeholder="finance-readonly">
                </label>
                <label style="grid-column: 1 / -1;">
                  Selected tools (server_id:tool_name, one per line)
                  <textarea
                    id="vserver-tools"
                    name="tools"
                    rows="6"
                    class="tool-list"
                    placeholder="22222222-...:create_diagram&#10;22222222-...:search_shapes"
                  ></textarea>
                </label>
                <label style="grid-column: 1 / -1;">
                  Rename map (optional, JSON object {"original": "exposed"})
                  <input name="rename_map" placeholder='{"query_select": "query"}'>
                </label>
                <button type="submit">Create virtual server</button>
              </form>
              <pre id="vserver-output" class="output output-status">Waiting for submission.</pre>
            </div>
          </div>
        </div>
      </section>

      <section class="panel events-panel-v2 access-requests-panel-v2"
               id="access-requests-panel" data-nav="access-requests">
        <header class="events-head">
          <div>
            <p class="eyebrow">IDENTITY &amp; ACCESS &middot; ACCESS REQUESTS</p>
            <h1>Decisions waiting on you</h1>
            <p class="events-sub"
               title="Approving mints a grant. Flip the pill bar to review past decisions.">
              End users asking for access to private bundles.
            </p>
          </div>
          <div class="events-head-actions">
            <input id="access-requests-search" type="search" class="events-icon-btn"
                   placeholder="Search email / vserver&hellip;"
                   style="border-radius: 999px; padding: 7px 14px;
                          min-width: 220px;">
            <button id="refresh-access-requests" type="button">Refresh</button>
          </div>
        </header>

        <div class="events-kpi-grid">
          <div class="events-kpi events-kpi-distinctive">
            <p class="events-kpi-label">PENDING</p>
            <p class="events-kpi-num" id="ar-kpi-pending">&mdash;</p>
            <p class="events-kpi-pill">awaiting decision</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">OLDEST PENDING</p>
            <p class="events-kpi-num" id="ar-kpi-oldest">&mdash;</p>
            <p class="events-kpi-pill" id="ar-kpi-oldest-sub">
              age of waiting request
            </p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">APPROVED &middot; 7D</p>
            <p class="events-kpi-num" id="ar-kpi-approved">&mdash;</p>
            <p class="events-kpi-pill">last 7 days</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">DECLINED &middot; 7D</p>
            <p class="events-kpi-num" id="ar-kpi-declined">&mdash;</p>
            <p class="events-kpi-pill">last 7 days</p>
          </div>
        </div>

        <!-- JIT-1 · who is elevated RIGHT NOW. Deliberately above the
             queue: the queue is about decisions not yet made, this is
             about authority currently live in the tenant, and the second
             is the one an auditor walks in asking about. Hidden entirely
             when nobody is elevated, so it never becomes chrome to scroll
             past. -->
        <div id="jit-elevations-strip" class="jit-strip is-hidden">
          <div class="jit-strip-head">
            <span class="jit-strip-title">LIVE ELEVATIONS</span>
            <span class="jit-strip-sub" id="jit-elevations-count"></span>
          </div>
          <div id="jit-elevations-list" class="jit-strip-list"></div>
        </div>

        <div class="events-pill-row" role="tablist" aria-label="Access-request filter">
          <button type="button" class="events-pill is-active"
                  data-ar-pill="pending">Pending</button>
          <button type="button" class="events-pill"
                  data-ar-pill="all">All</button>
          <button type="button" class="events-pill"
                  data-ar-pill="approved">Approved</button>
          <button type="button" class="events-pill"
                  data-ar-pill="declined">Declined</button>
          <button type="button" class="events-pill"
                  data-ar-pill="withdrawn">Withdrawn</button>
        </div>

        <div class="events-table-wrap">
          <table class="events-table access-requests-table">
            <thead>
              <tr>
                <th class="ar-col-request">REQUEST</th>
                <th class="ar-col-note">NOTE</th>
                <th class="ar-col-status">STATUS</th>
                <th class="ar-col-submitted">SUBMITTED</th>
                <th class="ar-col-actions"></th>
              </tr>
            </thead>
            <tbody id="access-requests-output">
              <tr><td colspan="5" class="events-empty">
                Click <strong>Refresh</strong> to load.
              </td></tr>
            </tbody>
          </table>
        </div>
        <p class="identities-footnote">
          <span id="access-requests-count" class="toolbar-meta"></span>
        </p>

        <!-- Slide-over drawer: full request context, including the
             user's note + decision history. Approve / Decline live
             inline on pending rows, but the drawer also surfaces
             them so admins reading the audit log can act in place. -->
        <div id="ar-drawer" class="identity-drawer" hidden
             role="dialog" aria-modal="true" aria-labelledby="ar-drawer-title">
          <div class="identity-drawer-backdrop"
               data-ar-drawer-close></div>
          <div class="identity-drawer-panel">
            <header class="identity-drawer-head">
              <div>
                <p class="eyebrow">ACCESS REQUEST</p>
                <h2 id="ar-drawer-title">&mdash;</h2>
                <p class="identity-drawer-sub" id="ar-drawer-sub"></p>
              </div>
              <button type="button" class="events-icon-btn"
                      data-ar-drawer-close aria-label="Close">
                &times;
              </button>
            </header>
            <div class="identity-drawer-body" id="ar-drawer-body">
              &mdash;
            </div>
          </div>
        </div>
      </section>

      <section class="panel events-panel-v2 admins-panel-v2"
               id="admins-panel" data-nav="admins">
        <header class="events-head">
          <div>
            <p class="eyebrow">IDENTITY &amp; ACCESS &middot; ADMINS</p>
            <h1>Operators with the keys to the catalog</h1>
            <p class="events-sub"
               title="Distinct from end-user Users, though a human may sit in both lists.">
              Who can administer this tenant.
            </p>
          </div>
          <div class="events-head-actions">
            <input id="admins-search" type="search" class="events-icon-btn"
                   placeholder="Search by email&hellip;"
                   style="border-radius: 999px; padding: 7px 14px;
                          min-width: 200px;">
            <button id="open-create-admin" type="button">+ New admin</button>
            <button id="refresh-admins" type="button">Refresh</button>
          </div>
        </header>

        <div class="events-kpi-grid">
          <div class="events-kpi">
            <p class="events-kpi-label">TOTAL ADMINS</p>
            <p class="events-kpi-num" id="admins-kpi-total">&mdash;</p>
            <p class="events-kpi-pill">in tenant</p>
          </div>
          <div class="events-kpi events-kpi-distinctive">
            <p class="events-kpi-label">DISABLED</p>
            <p class="events-kpi-num" id="admins-kpi-disabled">&mdash;</p>
            <p class="events-kpi-pill">access revoked</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">PENDING RESET</p>
            <p class="events-kpi-num" id="admins-kpi-pending-reset">&mdash;</p>
            <p class="events-kpi-pill">must rotate password</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">NEVER LOGGED IN</p>
            <p class="events-kpi-num" id="admins-kpi-never">&mdash;</p>
            <p class="events-kpi-pill">credentialed but unused</p>
          </div>
        </div>

        <div class="events-pill-row" role="tablist" aria-label="Admin filter">
          <button type="button" class="events-pill is-active"
                  data-admins-pill="all">All</button>
          <button type="button" class="events-pill"
                  data-admins-pill="active">Active</button>
          <button type="button" class="events-pill"
                  data-admins-pill="disabled">Disabled</button>
          <button type="button" class="events-pill"
                  data-admins-pill="admin">Admin</button>
          <button type="button" class="events-pill"
                  data-admins-pill="editor">Editor</button>
          <button type="button" class="events-pill"
                  data-admins-pill="viewer">Viewer</button>
          <button type="button" class="events-pill"
                  data-admins-pill="pending_reset">Pending reset</button>
        </div>

        <div class="events-table-wrap">
          <table class="events-table admins-table">
            <thead>
              <tr>
                <th class="admins-col-admin">ADMIN</th>
                <th class="admins-col-role">ROLE</th>
                <th class="admins-col-last-login">LAST LOGIN</th>
                <th class="admins-col-created">CREATED</th>
                <th class="admins-col-actions"></th>
              </tr>
            </thead>
            <tbody id="admins-output">
              <tr><td colspan="5" class="events-empty">
                Click <strong>Refresh</strong> to load.
              </td></tr>
            </tbody>
          </table>
        </div>
        <p class="identities-footnote">
          <span id="admins-count" class="toolbar-meta"></span>
        </p>

        <!-- Modal: + New admin. Same lightweight pattern as +New user. -->
        <div id="create-admin-modal" class="identity-drawer" hidden
             role="dialog" aria-modal="true" aria-labelledby="create-admin-modal-title">
          <div class="identity-drawer-backdrop"
               data-create-admin-close></div>
          <div class="identity-drawer-panel users-modal-panel">
            <header class="identity-drawer-head">
              <div>
                <p class="eyebrow">NEW ADMIN</p>
                <h2 id="create-admin-modal-title">Create admin</h2>
                <p class="identity-drawer-sub">
                  Issues an operator credential. New admin will be
                  required to rotate the password on first sign-in.
                </p>
              </div>
              <button type="button" class="events-icon-btn"
                      data-create-admin-close aria-label="Close">
                &times;
              </button>
            </header>
            <div class="identity-drawer-body">
              <form id="create-admin-form" class="form-grid">
                <label>
                  Email
                  <input name="email" type="email" required>
                </label>
                <label>
                  Role
                  <select name="role">
                    <option value="admin" selected>admin</option>
                    <option value="editor">editor</option>
                    <option value="viewer">viewer</option>
                  </select>
                </label>
                <label style="grid-column: 1 / -1;">
                  Initial password
                  <input name="password" type="password" required minlength="12">
                </label>
                <button type="submit">Create admin</button>
              </form>
              <pre id="create-admin-output"
                   class="output output-status">Waiting for submission.</pre>
            </div>
          </div>
        </div>
      </section>

      <section class="panel events-panel-v2 users-panel-v2"
               id="users-panel" data-nav="users">
        <header class="events-head">
          <div>
            <p class="eyebrow">IDENTITY &amp; ACCESS &middot; USERS</p>
            <h1>End users you&rsquo;ve issued credentials to</h1>
            <p class="events-sub">
              Distinct from operators &mdash; a human can have rows in
              both. Disabling a user immediately fails any inbound MCP
              call presenting their bearer.
            </p>
          </div>
          <div class="events-head-actions">
            <input id="users-search" type="search" class="events-icon-btn"
                   placeholder="Search by email&hellip;"
                   style="border-radius: 999px; padding: 7px 14px;
                          min-width: 200px;">
            <button id="open-create-user" type="button">+ New user</button>
            <button id="refresh-users" type="button">Refresh</button>
          </div>
        </header>

        <div class="events-kpi-grid">
          <div class="events-kpi">
            <p class="events-kpi-label">TOTAL USERS</p>
            <p class="events-kpi-num" id="users-kpi-total">&mdash;</p>
            <p class="events-kpi-pill">in tenant</p>
          </div>
          <div class="events-kpi events-kpi-distinctive">
            <p class="events-kpi-label">DISABLED</p>
            <p class="events-kpi-num" id="users-kpi-disabled">&mdash;</p>
            <p class="events-kpi-pill">access revoked</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">PENDING RESET</p>
            <p class="events-kpi-num" id="users-kpi-pending-reset">&mdash;</p>
            <p class="events-kpi-pill">must rotate password</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">NEW &middot; 24H</p>
            <p class="events-kpi-num" id="users-kpi-new-24h">&mdash;</p>
            <p class="events-kpi-pill">onboarded recently</p>
          </div>
        </div>

        <div class="events-pill-row" role="tablist" aria-label="User filter">
          <button type="button" class="events-pill is-active"
                  data-users-pill="all">All</button>
          <button type="button" class="events-pill"
                  data-users-pill="active">Active</button>
          <button type="button" class="events-pill"
                  data-users-pill="disabled">Disabled</button>
          <button type="button" class="events-pill"
                  data-users-pill="local">Local auth</button>
          <button type="button" class="events-pill"
                  data-users-pill="oidc">SSO</button>
          <button type="button" class="events-pill"
                  data-users-pill="pending_reset">Pending reset</button>
        </div>

        <div class="events-table-wrap">
          <table class="events-table users-table">
            <thead>
              <tr>
                <th class="users-col-user">USER</th>
                <th class="users-col-auth">AUTH</th>
                <th class="users-col-last-seen">LAST SEEN</th>
                <th class="users-col-keys">API KEYS</th>
                <th class="users-col-groups">GROUPS</th>
                <th class="users-col-created">CREATED</th>
                <th class="users-col-actions"></th>
              </tr>
            </thead>
            <tbody id="users-output">
              <tr><td colspan="7" class="events-empty">
                Click <strong>Refresh</strong> to load.
              </td></tr>
            </tbody>
          </table>
        </div>
        <p class="identities-footnote">
          <span id="users-count" class="toolbar-meta"></span>
        </p>

        <!-- Slide-over drawer: Activity / API keys / Groups for one user.
             Reuses .identity-drawer styles so the two panels feel
             consistent — same backdrop, same panel motion, same tab bar. -->
        <div id="user-drawer" class="identity-drawer" hidden
             role="dialog" aria-modal="true" aria-labelledby="user-drawer-title">
          <div class="identity-drawer-backdrop"
               data-user-drawer-close></div>
          <div class="identity-drawer-panel">
            <header class="identity-drawer-head">
              <div>
                <p class="eyebrow">USER DRILL-IN</p>
                <h2 id="user-drawer-title">&mdash;</h2>
                <p class="identity-drawer-sub" id="user-drawer-sub"></p>
              </div>
              <button type="button" class="events-icon-btn"
                      data-user-drawer-close aria-label="Close">
                &times;
              </button>
            </header>
            <div class="identity-drawer-tabs" role="tablist">
              <button type="button" class="identity-drawer-tab is-active"
                      data-user-drawer-tab="activity">Activity</button>
              <button type="button" class="identity-drawer-tab"
                      data-user-drawer-tab="keys">API keys</button>
              <button type="button" class="identity-drawer-tab"
                      data-user-drawer-tab="groups">Groups</button>
            </div>
            <div class="identity-drawer-body" id="user-drawer-body">
              &mdash;
            </div>
          </div>
        </div>

        <!-- Modal: + New user. Hidden by default; opens via the
             header button. Same lightweight backdrop + ESC-close
             pattern as the drill-in drawer, but smaller. -->
        <div id="create-user-modal" class="identity-drawer" hidden
             role="dialog" aria-modal="true" aria-labelledby="create-user-modal-title">
          <div class="identity-drawer-backdrop"
               data-create-user-close></div>
          <div class="identity-drawer-panel users-modal-panel">
            <header class="identity-drawer-head">
              <div>
                <p class="eyebrow">NEW LOCAL-AUTH USER</p>
                <h2 id="create-user-modal-title">Create user</h2>
                <p class="identity-drawer-sub">
                  Password must be at least 12 chars. The user will be
                  forced to rotate on first sign-in.
                </p>
              </div>
              <button type="button" class="events-icon-btn"
                      data-create-user-close aria-label="Close">
                &times;
              </button>
            </header>
            <div class="identity-drawer-body">
              <form id="create-user-form" class="form-grid">
                <label>
                  Email
                  <input name="email" type="email" required>
                </label>
                <label>
                  Display name
                  <input name="display_name" maxlength="255">
                </label>
                <label style="grid-column: 1 / -1;">
                  Initial password
                  <input name="password" type="password" required minlength="12">
                </label>
                <button type="submit">Create user</button>
              </form>
              <pre id="create-user-output"
                   class="output output-status">Waiting for submission.</pre>
            </div>
          </div>
        </div>
      </section>

      <section class="panel events-panel-v2 groups-panel-v2"
               id="groups-panel" data-nav="groups">
        <header class="events-head">
          <div>
            <p class="eyebrow">IDENTITY &amp; ACCESS &middot; GROUPS</p>
            <h1>Bundles of users for shared access</h1>
            <p class="events-sub"
               title="One grant covers everyone inside. A group with no grants is unreferenced.">
              Grant access to a group instead of user by user.
            </p>
          </div>
          <div class="events-head-actions">
            <input id="groups-search" type="search" class="events-icon-btn"
                   placeholder="Search by name&hellip;"
                   style="border-radius: 999px; padding: 7px 14px;
                          min-width: 200px;">
            <button id="open-create-group" type="button">+ New group</button>
            <button id="refresh-groups" type="button">Refresh</button>
          </div>
        </header>

        <div class="events-kpi-grid">
          <div class="events-kpi">
            <p class="events-kpi-label">TOTAL GROUPS</p>
            <p class="events-kpi-num" id="groups-kpi-total">&mdash;</p>
            <p class="events-kpi-pill">in tenant</p>
          </div>
          <div class="events-kpi events-kpi-distinctive">
            <p class="events-kpi-label">UNUSED</p>
            <p class="events-kpi-num" id="groups-kpi-unused">&mdash;</p>
            <p class="events-kpi-pill">no vserver grants</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">EMPTY</p>
            <p class="events-kpi-num" id="groups-kpi-empty">&mdash;</p>
            <p class="events-kpi-pill">no members yet</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">LARGEST</p>
            <p class="events-kpi-num" id="groups-kpi-largest">&mdash;</p>
            <p class="events-kpi-pill" id="groups-kpi-largest-sub">
              by member count
            </p>
          </div>
        </div>

        <div class="events-pill-row" role="tablist" aria-label="Group filter">
          <button type="button" class="events-pill is-active"
                  data-groups-pill="all">All</button>
          <button type="button" class="events-pill"
                  data-groups-pill="in_use">In use</button>
          <button type="button" class="events-pill"
                  data-groups-pill="empty">Empty</button>
          <button type="button" class="events-pill"
                  data-groups-pill="unused">Unused</button>
        </div>

        <div class="events-table-wrap">
          <table class="events-table groups-table">
            <thead>
              <tr>
                <th class="groups-col-name">GROUP</th>
                <th class="groups-col-members">MEMBERS</th>
                <th class="groups-col-grants">VSERVER GRANTS</th>
                <th class="groups-col-created">CREATED</th>
                <th class="groups-col-actions"></th>
              </tr>
            </thead>
            <tbody id="groups-output">
              <tr><td colspan="5" class="events-empty">
                Click <strong>Refresh</strong> to load.
              </td></tr>
            </tbody>
          </table>
        </div>
        <p class="identities-footnote">
          <span id="groups-count" class="toolbar-meta"></span>
        </p>

        <!-- Slide-over drawer: Members / Vserver grants for one group.
             Reuses .identity-drawer styles so all three drill-ins (Identities,
             Users, Groups) feel like one product. -->
        <div id="group-drawer" class="identity-drawer" hidden
             role="dialog" aria-modal="true" aria-labelledby="group-drawer-title">
          <div class="identity-drawer-backdrop"
               data-group-drawer-close></div>
          <div class="identity-drawer-panel">
            <header class="identity-drawer-head">
              <div>
                <p class="eyebrow">GROUP DRILL-IN</p>
                <h2 id="group-drawer-title">&mdash;</h2>
                <p class="identity-drawer-sub" id="group-drawer-sub"></p>
              </div>
              <button type="button" class="events-icon-btn"
                      data-group-drawer-close aria-label="Close">
                &times;
              </button>
            </header>
            <div class="identity-drawer-tabs" role="tablist">
              <button type="button" class="identity-drawer-tab is-active"
                      data-group-drawer-tab="members">Members</button>
              <button type="button" class="identity-drawer-tab"
                      data-group-drawer-tab="grants">Vserver grants</button>
            </div>
            <div class="identity-drawer-body" id="group-drawer-body">
              &mdash;
            </div>
          </div>
        </div>

        <!-- Modal: + New group. Same lightweight pattern as +New user. -->
        <div id="create-group-modal" class="identity-drawer" hidden
             role="dialog" aria-modal="true" aria-labelledby="create-group-modal-title">
          <div class="identity-drawer-backdrop"
               data-create-group-close></div>
          <div class="identity-drawer-panel users-modal-panel">
            <header class="identity-drawer-head">
              <div>
                <p class="eyebrow">NEW GROUP</p>
                <h2 id="create-group-modal-title">Create group</h2>
                <p class="identity-drawer-sub">
                  Empty groups are fine &mdash; add members from a
                  user&rsquo;s drill-in or from this group&rsquo;s
                  drill-in once it&rsquo;s created.
                </p>
              </div>
              <button type="button" class="events-icon-btn"
                      data-create-group-close aria-label="Close">
                &times;
              </button>
            </header>
            <div class="identity-drawer-body">
              <form id="create-group-form" class="form-grid">
                <label>
                  Name
                  <input name="name" required maxlength="255">
                </label>
                <label>
                  Description
                  <input name="description" maxlength="2000">
                </label>
                <button type="submit">Create group</button>
              </form>
              <pre id="create-group-output"
                   class="output output-status">Waiting for submission.</pre>
            </div>
          </div>
        </div>
      </section>

      <section class="panel events-panel-v2 idp-panel-v2"
               id="idp-directories-panel" data-nav="idp-directories">
        <header class="events-head">
          <div>
            <p class="eyebrow">SETTINGS &middot; IDENTITY PROVIDERS</p>
            <h1>Connect Entra ID or Google Workspace</h1>
            <p class="events-sub"
               title="SCIM for lifecycle, OIDC or SAML for sign-in. Local-auth users keep working.">
              Connected identity directories.
            </p>
          </div>
          <div class="events-head-actions">
            <button id="open-connect-entra" type="button">+ Connect Entra ID</button>
            <button id="open-connect-workspace" type="button">+ Connect Workspace</button>
            <button id="refresh-idp-directories" type="button">Refresh</button>
          </div>
        </header>

        <!-- IDP-3 · the tenant's sign-in address. Lives here because an
             admin configuring identity providers is already thinking
             about "where do my people log in", and the IdP redirect URIs
             they paste next have to match this hostname. -->
        <div id="tenant-slug-strip" class="jit-strip is-hidden">
          <div class="jit-strip-head">
            <span class="jit-strip-title">SIGN-IN ADDRESS</span>
            <span class="jit-strip-sub" id="tenant-slug-sub"></span>
          </div>
          <div class="jit-strip-list">
            <div class="jit-elevation-row">
              <code id="tenant-slug-url"></code>
              <button id="edit-tenant-slug" type="button"
                      class="vservers-row-url-copy">Change</button>
            </div>
          </div>
        </div>

        <div class="events-kpi-grid">
          <div class="events-kpi">
            <p class="events-kpi-label">CONNECTED</p>
            <p class="events-kpi-num" id="idp-kpi-total">&mdash;</p>
            <p class="events-kpi-pill">directories</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">ENTRA ID</p>
            <p class="events-kpi-num" id="idp-kpi-entra">&mdash;</p>
            <p class="events-kpi-pill">Microsoft</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">WORKSPACE</p>
            <p class="events-kpi-num" id="idp-kpi-workspace">&mdash;</p>
            <p class="events-kpi-pill">Google</p>
          </div>
          <div class="events-kpi events-kpi-distinctive">
            <p class="events-kpi-label">RECENT SCIM</p>
            <p class="events-kpi-num" id="idp-kpi-recent-scim">&mdash;</p>
            <p class="events-kpi-pill" id="idp-kpi-recent-scim-sub">
              latest sync timestamp
            </p>
          </div>
        </div>

        <div class="events-pill-row" role="tablist" aria-label="IdP filter">
          <button type="button" class="events-pill is-active"
                  data-idp-pill="all">All</button>
          <button type="button" class="events-pill"
                  data-idp-pill="entra">Entra ID</button>
          <button type="button" class="events-pill"
                  data-idp-pill="google_workspace">Workspace</button>
          <button type="button" class="events-pill"
                  data-idp-pill="oidc">OIDC</button>
          <button type="button" class="events-pill"
                  data-idp-pill="saml">SAML</button>
        </div>

        <div class="events-table-wrap">
          <table class="events-table idp-table">
            <thead>
              <tr>
                <th class="idp-col-directory">DIRECTORY</th>
                <th class="idp-col-protocol">PROTOCOL</th>
                <th class="idp-col-ema">AGENT AUTH (EMA)</th>
                <th class="idp-col-last-sync">PROVISIONING</th>
                <th class="idp-col-created">CONNECTED</th>
                <th class="idp-col-actions"></th>
              </tr>
            </thead>
            <tbody id="idp-directories-output">
              <tr><td colspan="6" class="events-empty">
                Click <strong>Refresh</strong> to load.
              </td></tr>
            </tbody>
          </table>
        </div>
        <p class="identities-footnote">
          <span id="idp-count" class="toolbar-meta"></span>
        </p>

        <!-- Slide-over drawer: Endpoints (SCIM URL, ACS URL, metadata
             URL, OIDC discovery), Connection (kind/protocol/created),
             Settings (disconnect). -->
        <div id="idp-drawer" class="identity-drawer" hidden
             role="dialog" aria-modal="true" aria-labelledby="idp-drawer-title">
          <div class="identity-drawer-backdrop"
               data-idp-drawer-close></div>
          <div class="identity-drawer-panel">
            <header class="identity-drawer-head">
              <div>
                <p class="eyebrow">DIRECTORY DRILL-IN</p>
                <h2 id="idp-drawer-title">&mdash;</h2>
                <p class="identity-drawer-sub" id="idp-drawer-sub"></p>
              </div>
              <button type="button" class="events-icon-btn"
                      data-idp-drawer-close aria-label="Close">
                &times;
              </button>
            </header>
            <div class="identity-drawer-tabs" role="tablist">
              <button type="button" class="identity-drawer-tab is-active"
                      data-idp-drawer-tab="endpoints">Endpoints</button>
              <button type="button" class="identity-drawer-tab"
                      data-idp-drawer-tab="connection">Connection</button>
              <button type="button" class="identity-drawer-tab"
                      data-idp-drawer-tab="settings">Settings</button>
            </div>
            <div class="identity-drawer-body" id="idp-drawer-body">
              &mdash;
            </div>
          </div>
        </div>

        <!-- Modal: + Connect Entra ID. Two-step content reveal:
             protocol picker (OIDC/SAML), then the relevant config
             fields. Submitting reveals the SCIM bearer plaintext
             ONCE — admin pastes it into Entra's Provisioning config. -->
        <div id="connect-idp-modal" class="identity-drawer" hidden
             role="dialog" aria-modal="true" aria-labelledby="connect-idp-title">
          <div class="identity-drawer-backdrop"
               data-connect-idp-close></div>
          <div class="identity-drawer-panel users-modal-panel">
            <header class="identity-drawer-head">
              <div>
                <p class="eyebrow" id="connect-idp-eyebrow">NEW DIRECTORY</p>
                <h2 id="connect-idp-title">Connect directory</h2>
                <p class="identity-drawer-sub" id="connect-idp-sub">
                  Pick a sign-in protocol, then paste the IdP-side
                  config. The SCIM bearer is shown once after submit.
                </p>
              </div>
              <button type="button" class="events-icon-btn"
                      data-connect-idp-close aria-label="Close">
                &times;
              </button>
            </header>
            <div class="identity-drawer-body" id="connect-idp-body">
              &mdash;
            </div>
          </div>
        </div>
      </section>

      <section class="panel events-panel-v2"
               id="risk-summary-panel" data-nav="risk-summary">
        <header class="events-head">
          <div>
            <p class="eyebrow">OVERVIEW &middot; RISK POSTURE</p>
            <h1>What the gateway is holding back</h1>
            <p class="events-sub"
               title="Scored from tool descriptions and schemas, not source code.">
              Every score is an LLM reading the tools your users can reach.
            </p>
          </div>
          <div class="events-head-actions">
            <button id="refresh-risk-summary" type="button">Refresh</button>
          </div>
        </header>
        <div id="risk-summary-body">
          <p class="events-empty">Click <strong>Refresh</strong> to load.</p>
        </div>
      </section>

        <section class="panel events-panel-v2"
               id="risk-classifier-panel" data-nav="risk-classifier">
        <header class="events-head">
          <div>
            <p class="eyebrow">SETTINGS &middot; RISK CLASSIFIER</p>
            <h1>Which model reads your tool catalogue</h1>
            <p class="events-sub"
               title="Names, descriptions and input schemas only. Never credentials or user data.">
              Only the server's public surface is sent to the model.
            </p>
          </div>
          <div class="events-head-actions">
            <button id="refresh-risk-classifier" type="button">Refresh</button>
          </div>
        </header>
        <div id="risk-classifier-body">
          <p class="events-empty">Click <strong>Refresh</strong> to load.</p>
        </div>
      </section>

        <section class="panel events-panel-v2"
               id="api-key-policy-panel" data-nav="api-key-policy">
        <header class="events-head">
          <div>
            <p class="eyebrow">IDENTITY &amp; ACCESS &middot; API KEY POLICY</p>
            <h1>How long a user's key stays alive</h1>
            <p class="events-sub"
               title="User beats group beats tenant. With several groups the SHORTEST wins.">
              Without a policy a key lives until somebody revokes it by hand.
            </p>
          </div>
          <div class="events-head-actions">
            <button id="refresh-api-key-policy" type="button">Refresh</button>
          </div>
        </header>

        <div class="events-kpi-grid">
          <div class="events-kpi">
            <p class="events-kpi-label">TENANT DEFAULT</p>
            <p class="events-kpi-num" id="akp-kpi-default">&mdash;</p>
            <p class="events-kpi-pill">applies with no exception</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">EXCEPTIONS</p>
            <p class="events-kpi-num" id="akp-kpi-exceptions">&mdash;</p>
            <p class="events-kpi-pill">per group or user</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">KEYS OUTLIVING POLICY</p>
            <p class="events-kpi-num" id="akp-kpi-offenders">&mdash;</p>
            <p class="events-kpi-pill" id="akp-kpi-offenders-hint">issued before the rule</p>
          </div>
        </div>

        <div class="jit-strip" id="akp-form-strip">
          <div class="jit-strip-head">
            <span class="jit-strip-title">SET A CEILING</span>
            <span class="jit-strip-sub"
                  title="A maximum, not a mandate — a shorter request still works.">
              a longer request is refused, never silently shortened
            </span>
          </div>
          <div class="jit-strip-list">
            <form id="akp-form" class="akp-form">
              <select id="akp-scope" aria-label="Scope">
                <option value="tenant">Everyone in this tenant</option>
                <option value="group">A group</option>
                <option value="user">One user</option>
              </select>
              <select id="akp-principal" aria-label="Who" disabled></select>
              <input id="akp-ttl" type="number" min="1" placeholder="days"
                     aria-label="Maximum days">
              <input id="akp-note" type="text" maxlength="500"
                     placeholder="why this exception exists" aria-label="Note">
              <button type="submit">Save</button>
              <span id="akp-form-status" class="toolbar-meta"></span>
            </form>
          </div>
        </div>

        <div class="events-table-wrap">
          <table class="events-table">
            <thead>
              <tr>
                <th>SCOPE</th>
                <th>WHO</th>
                <th style="text-align:right;">MAX LIFETIME</th>
                <th>NOTE</th>
                <th></th>
              </tr>
            </thead>
            <tbody id="akp-output">
              <tr><td colspan="5" class="events-empty">
                Click <strong>Refresh</strong> to load.
              </td></tr>
            </tbody>
          </table>
        </div>
      </section>

        <section class="panel events-panel-v2"
               id="security-posture-panel" data-nav="security-posture">
        <header class="events-head">
          <div>
            <p class="eyebrow">SETTINGS &middot; SECURITY POSTURE</p>
            <h1>What is protecting this deployment</h1>
            <p class="events-sub"
               title="Read-only &mdash; these are deployment env vars.">
              Each row says what the CURRENT state costs, not just whether a
              flag is set.
            </p>
          </div>
          <div class="events-head-actions">
            <button id="refresh-security-posture" type="button">Refresh</button>
          </div>
        </header>

        <div id="cimd-row" class="jit-strip is-hidden">
          <div class="jit-strip-head">
            <span class="jit-strip-title">THIS GATEWAY'S OAUTH CLIENT ID (CIMD)</span>
            <span class="jit-strip-sub">
              hand this URL to an upstream's authorization-server admin
              &mdash; it replaces per-server dynamic registration
            </span>
          </div>
          <div class="jit-strip-list">
            <div class="vservers-row-url">
              <code id="cimd-client-id"></code>
              <button id="copy-cimd" type="button"
                      class="vservers-row-url-copy">Copy</button>
            </div>
          </div>
        </div>

        <div class="events-table-wrap">
          <table class="events-table posture-table">
            <thead>
              <tr>
                <th class="posture-col-state">STATE</th>
                <th class="posture-col-control">CONTROL</th>
                <th class="posture-col-consequence">WHAT THAT MEANS TODAY</th>
                <th class="posture-col-env">ENV</th>
              </tr>
            </thead>
            <tbody id="security-posture-output">
              <tr><td colspan="4" class="events-empty">
                Click <strong>Refresh</strong> to load.
              </td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel events-panel-v2"
               id="siem-export-panel" data-nav="siem-export">
        <header class="events-head">
          <div>
            <p class="eyebrow">OBSERVABILITY &middot; SIEM EXPORT</p>
            <h1>Ship this tenant's security events to Splunk</h1>
            <p class="events-sub"
               title="Tool calls, rejections, admin actions, sign-ins and per-user tool
authorisation, one sourcetype each. Only this tenant's events ever reach this target.">
              Splunk HTTP Event Collector. Everything is
              <code>vyuu:mcp:&lt;category&gt;</code>.
            </p>
          </div>
          <div class="events-head-actions">
            <button id="refresh-siem-export" type="button">Refresh</button>
          </div>
        </header>
        <div id="siem-export-body">
          <p class="events-empty">Click <strong>Refresh</strong> to load.</p>
        </div>
      </section>

      <section class="panel events-panel-v2"
               id="telemetry-panel" data-nav="telemetry">
        <header class="events-head">
          <div>
            <p class="eyebrow">OBSERVABILITY &middot; TELEMETRY</p>
            <h1>Traces and metrics for whoever runs this gateway</h1>
            <p class="events-sub"
               title="OpenTelemetry over OTLP/HTTP to a collector — the Splunk OTel Collector
by default. Deployment-level: set with env vars, verified here.">
              OpenTelemetry &rarr; Splunk OTel Collector. Configured in the deployment,
              verified here.
            </p>
          </div>
          <div class="events-head-actions">
            <button id="refresh-telemetry" type="button">Refresh</button>
          </div>
        </header>
        <div id="telemetry-body">
          <p class="events-empty">Click <strong>Refresh</strong> to load.</p>
        </div>
      </section>

      <section class="panel" data-nav="secret-store">
        <div class="panel-head">
          <div>
            <p class="eyebrow">SETTINGS &middot; SECRET STORE</p>
            <h2>Secret store</h2>
            <p class="events-sub"
               title="Backend used to resolve auth_headers, auth_env and OAuth client-
                  credential refs for upstream MCPs. Chosen with
                  VYUU_SECRET_STORE_BACKEND; this panel shows the active wiring and
                  connectivity health.">
              Where upstream credential references resolve. Set at deploy time;
              verified here.</p>
          </div>
          <button id="refresh-secret-store" type="button">Refresh</button>
        </div>
        <div id="secret-store-output" class="cards">Click <strong>Refresh</strong> to load.</div>
      </section>

      <section class="panel events-panel-v2 identities-panel-v2"
               id="identities-panel" data-nav="identities">
        <header class="events-head">
          <div>
            <p class="eyebrow">IDENTITIES &middot; NHI</p>
            <h1>Who&rsquo;s calling, what they&rsquo;re touching</h1>
            <p class="events-sub"
               title="Click a row for its timeline, dependency graph and 7-day summary.">
              Every principal seen in the chosen window.
            </p>
          </div>
          <div class="events-head-actions">
            <select id="identities-window" title="Time window"
                    class="events-icon-btn"
                    style="border-radius: 999px; padding: 7px 14px;">
              <option value="1h">Last 1h</option>
              <option value="24h" selected>Last 24h</option>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
            </select>
            <input id="identities-search" type="search" class="events-icon-btn"
                   placeholder="Search id / email&hellip;"
                   style="border-radius: 999px; padding: 7px 14px;
                          min-width: 200px;">
            <button id="refresh-identities" type="button">Refresh</button>
          </div>
        </header>

        <div class="events-kpi-grid">
          <div class="events-kpi">
            <p class="events-kpi-label">TOTAL IDENTITIES</p>
            <p class="events-kpi-num" id="identities-kpi-total">&mdash;</p>
            <p class="events-kpi-pill">in current buffer</p>
          </div>
          <div class="events-kpi events-kpi-distinctive">
            <p class="events-kpi-label">HIGH-RISK ACTIVITY</p>
            <p class="events-kpi-num" id="identities-kpi-high-risk">&mdash;</p>
            <p class="events-kpi-pill">delete / admin / credential</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">NEW &middot; 24H</p>
            <p class="events-kpi-num" id="identities-kpi-new-24h">&mdash;</p>
            <p class="events-kpi-pill">first-seen recently</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">TOP INTERFACE</p>
            <p class="events-kpi-num" id="identities-kpi-top-client">&mdash;</p>
            <p class="events-kpi-pill" id="identities-kpi-top-client-sub">
              most-active MCP client
            </p>
          </div>
        </div>

        <div class="events-pill-row" role="tablist" aria-label="Identity filter">
          <button type="button" class="events-pill is-active"
                  data-identities-pill="all">
            All
          </button>
          <button type="button" class="events-pill"
                  data-identities-pill="api_key">
            User tokens
          </button>
          <button type="button" class="events-pill"
                  data-identities-pill="endpoint_session">
            Endpoint sessions
          </button>
          <button type="button" class="events-pill"
                  data-identities-pill="server_agent">
            Service agents
          </button>
          <button type="button" class="events-pill"
                  data-identities-pill="high_risk">
            High risk
          </button>
        </div>

        <div class="events-table-wrap">
          <table class="events-table identities-table">
            <thead>
              <tr>
                <th class="identities-col-identity">IDENTITY</th>
                <th class="identities-col-type">TYPE</th>
                <th class="identities-col-via">VIA</th>
                <th class="identities-col-activity">ACTIVITY</th>
                <th class="identities-col-footprint">FOOTPRINT</th>
                <th class="identities-col-risk">RISK</th>
                <th class="identities-col-actions"></th>
              </tr>
            </thead>
            <tbody id="identities-output">
              <tr><td colspan="7" class="events-empty">
                Click <strong>Refresh</strong> to load.
              </td></tr>
            </tbody>
          </table>
        </div>
        <p class="identities-footnote">
          <span id="identities-count" class="toolbar-meta"></span>
        </p>

        <!-- Slide-over drawer for drill-in (timeline / graph / summary).
             Reuses the existing rendering functions; we just relocate
             where they paint. The backdrop intercepts clicks outside
             to close. -->
        <div id="identity-drawer" class="identity-drawer" hidden
             role="dialog" aria-modal="true" aria-labelledby="identity-drawer-title">
          <div class="identity-drawer-backdrop"
               data-identity-drawer-close></div>
          <div class="identity-drawer-panel">
            <header class="identity-drawer-head">
              <div>
                <p class="eyebrow">IDENTITY DRILL-IN</p>
                <h2 id="identity-drawer-title">&mdash;</h2>
                <p class="identity-drawer-sub" id="identity-drawer-sub"></p>
              </div>
              <button type="button" class="events-icon-btn"
                      data-identity-drawer-close aria-label="Close">
                &times;
              </button>
            </header>
            <div class="identity-drawer-tabs" role="tablist">
              <button type="button" class="identity-drawer-tab is-active"
                      data-drawer-tab="timeline">Timeline</button>
              <button type="button" class="identity-drawer-tab"
                      data-drawer-tab="graph">Graph</button>
              <button type="button" class="identity-drawer-tab"
                      data-drawer-tab="summary">Summary</button>
            </div>
            <div class="identity-drawer-body" id="identity-drawer-body"></div>
          </div>
        </div>
      </section>

      <section class="panel events-panel-v2" id="events-panel" data-nav="events">
        <header class="events-head">
          <div>
            <p class="eyebrow">EVENTS &middot; MCP</p>
            <h1>Every action, every identity</h1>
            <p class="events-sub"
               title="Persisted in tool_call_events, so it survives restarts. Default window: 24h.">
              Tool calls and unsanctioned access attempts.
            </p>
          </div>
          <div class="events-head-actions">
            <select id="events-window" title="Time window"
                    class="events-icon-btn"
                    style="border-radius: 999px; padding: 7px 14px;">
              <option value="1h">Last 1h</option>
              <option value="24h" selected>Last 24h</option>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
            </select>
            <button id="events-filter-toggle" type="button"
                    class="events-icon-btn" aria-expanded="false">
              <span class="events-icon-glyph">&#9776;</span> Filter
            </button>
            <button id="events-export" type="button" class="events-icon-btn">
              <span class="events-icon-glyph">&darr;</span> Export
            </button>
            <button id="refresh-audit-events" type="button">Refresh</button>
          </div>
        </header>

        <div class="events-kpi-grid">
          <div class="events-kpi">
            <p class="events-kpi-label">TOOL CALLS &middot; 24H</p>
            <p class="events-kpi-num" id="events-kpi-tool-calls">&mdash;</p>
            <p class="events-kpi-pill" id="events-kpi-tool-calls-sub">
              across <span data-events-server-count>0</span> servers
            </p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">BLOCKED</p>
            <p class="events-kpi-num" id="events-kpi-blocked">&mdash;</p>
            <p class="events-kpi-pill" id="events-kpi-blocked-sub">
              policy denials
            </p>
          </div>
          <div class="events-kpi events-kpi-distinctive">
            <p class="events-kpi-label">UNSANCTIONED ACCESS</p>
            <p class="events-kpi-num" id="events-kpi-unsanctioned">&mdash;</p>
            <p class="events-kpi-pill" id="events-kpi-unsanctioned-sub">
              attempts on undeclared vservers
            </p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">ACTIVE IDENTITIES</p>
            <p class="events-kpi-num" id="events-kpi-identities">&mdash;</p>
            <p class="events-kpi-pill" id="events-kpi-identities-sub">
              human + agent + API key
            </p>
          </div>
        </div>

        <div class="events-pill-row" role="tablist" aria-label="Event filter">
          <button type="button" class="events-pill is-active" data-events-pill="all">
            All events
          </button>
          <button type="button" class="events-pill" data-events-pill="unsanctioned">
            Unsanctioned access
          </button>
          <button type="button" class="events-pill" data-events-pill="blocked">
            Blocked
          </button>
          <button type="button" class="events-pill" data-events-pill="high_risk">
            High risk
          </button>
          <button type="button" class="events-pill" data-events-pill="redacted">
            Redacted
          </button>
        </div>

        <!-- Advanced filters (hidden by default; toggled by the Filter
             button above). The original dropdowns live here so power
             users can still slice by vserver / tool-name substring /
             decision / limit. -->
        <div class="events-advanced-filters" id="events-advanced-filters" hidden>
          <label>
            Virtual server
            <select id="audit-vserver-filter">
              <option value="">&mdash; all &mdash;</option>
            </select>
          </label>
          <label>
            Tool name (substring)
            <input id="audit-tool-filter" type="text" placeholder="e.g. create_">
          </label>
          <label>
            Event type
            <select id="audit-event-type-filter">
              <option value="">&mdash; any &mdash;</option>
              <option value="tool_call">tool calls</option>
              <option value="access_attempt">access attempts (auth failures)</option>
            </select>
          </label>
          <label>
            Decision
            <select id="audit-decision-filter">
              <option value="">&mdash; any &mdash;</option>
              <option value="allow">allow</option>
              <option value="deny">deny</option>
              <option value="redact">redact</option>
              <option value="rewrite">rewrite</option>
            </select>
          </label>
          <label>
            Limit (1-500)
            <input id="audit-limit" type="number" min="1" max="500" value="100">
          </label>
          <button id="apply-audit-filter" type="button">Apply</button>
        </div>

        <div class="events-table-wrap">
          <table class="events-table" id="events-table">
            <thead>
              <tr>
                <th class="events-col-time">TIME</th>
                <th class="events-col-identity">IDENTITY</th>
                <th class="events-col-target">SERVER &middot; TOOL</th>
                <th class="events-col-args">ARGS</th>
                <th class="events-col-risk">RISK</th>
                <th class="events-col-reason">REASON</th>
              </tr>
            </thead>
            <tbody id="audit-events-output">
              <tr><td colspan="6" class="events-empty">
                Click <strong>Refresh</strong> to load.
              </td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel events-panel-v2 admin-audit-panel-v2"
               id="admin-audit-panel" data-nav="admin-audit">
        <header class="events-head">
          <div>
            <p class="eyebrow">OBSERVABILITY &middot; ADMIN AUDIT</p>
            <h1>Who did what to the platform</h1>
            <p class="events-sub"
               title="Distinct from Events, which captures inbound MCP tool calls.">
              Admin-driven changes to this tenant.
            </p>
          </div>
          <div class="events-head-actions">
            <input id="admin-audit-search" type="search" class="events-icon-btn"
                   placeholder="Search action / target&hellip;"
                   style="border-radius: 999px; padding: 7px 14px;
                          min-width: 240px;">
            <button id="refresh-admin-audit" type="button">Refresh</button>
          </div>
        </header>

        <div class="events-kpi-grid">
          <div class="events-kpi">
            <p class="events-kpi-label">ACTIONS &middot; LOADED</p>
            <p class="events-kpi-num" id="aa-kpi-total">&mdash;</p>
            <p class="events-kpi-pill" id="aa-kpi-total-sub">in current view</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">OPERATOR</p>
            <p class="events-kpi-num" id="aa-kpi-operator">&mdash;</p>
            <p class="events-kpi-pill">human-driven</p>
          </div>
          <div class="events-kpi">
            <p class="events-kpi-label">SCIM</p>
            <p class="events-kpi-num" id="aa-kpi-scim">&mdash;</p>
            <p class="events-kpi-pill">IdP-driven</p>
          </div>
          <div class="events-kpi events-kpi-distinctive">
            <p class="events-kpi-label">SYSTEM</p>
            <p class="events-kpi-num" id="aa-kpi-system">&mdash;</p>
            <p class="events-kpi-pill">cron / sweeper</p>
          </div>
        </div>

        <div class="events-pill-row" role="tablist" aria-label="Audit filter">
          <button type="button" class="events-pill is-active"
                  data-aa-pill="all">All</button>
          <button type="button" class="events-pill"
                  data-aa-pill="operator">Operators</button>
          <button type="button" class="events-pill"
                  data-aa-pill="scim">SCIM</button>
          <button type="button" class="events-pill"
                  data-aa-pill="system">System</button>
          <button type="button" class="events-pill"
                  data-aa-pill="user">User actions</button>
          <button type="button" class="events-pill"
                  data-aa-pill="vserver">Vserver actions</button>
          <button type="button" class="events-pill"
                  data-aa-pill="grant">Grant actions</button>
        </div>

        <div class="events-table-wrap">
          <table class="events-table admin-audit-table">
            <thead>
              <tr>
                <th class="aa-col-when">WHEN</th>
                <th class="aa-col-actor">ACTOR</th>
                <th class="aa-col-action">ACTION</th>
                <th class="aa-col-target">TARGET</th>
                <th class="aa-col-detail">DETAIL</th>
              </tr>
            </thead>
            <tbody id="admin-audit-output">
              <tr><td colspan="5" class="events-empty">
                Click <strong>Refresh</strong> to load.
              </td></tr>
            </tbody>
          </table>
        </div>
        <p class="identities-footnote">
          <span id="admin-audit-count" class="toolbar-meta"></span>
        </p>

        <!-- Slide-over drawer: full action detail with the JSON
             `detail` blob pretty-printed. -->
        <div id="admin-audit-drawer" class="identity-drawer" hidden
             role="dialog" aria-modal="true" aria-labelledby="admin-audit-drawer-title">
          <div class="identity-drawer-backdrop"
               data-admin-audit-drawer-close></div>
          <div class="identity-drawer-panel">
            <header class="identity-drawer-head">
              <div>
                <p class="eyebrow">AUDIT EVENT</p>
                <h2 id="admin-audit-drawer-title">&mdash;</h2>
                <p class="identity-drawer-sub" id="admin-audit-drawer-sub"></p>
              </div>
              <button type="button" class="events-icon-btn"
                      data-admin-audit-drawer-close aria-label="Close">
                &times;
              </button>
            </header>
            <div class="identity-drawer-body" id="admin-audit-drawer-body">
              &mdash;
            </div>
          </div>
        </div>
      </section>
        <!-- MCP server drill-in. The tool catalogue used to be visible
             only inside the Publish-vserver flow, which is the wrong
             place to inspect a server: an operator deciding WHETHER to
             publish needs to read the descriptions first, and those
             descriptions are also the tool-poisoning surface. -->
        <div id="server-drawer" class="identity-drawer" hidden
             role="dialog" aria-modal="true" aria-labelledby="server-drawer-title">
          <div class="identity-drawer-backdrop"
               data-server-drawer-close></div>
          <div class="identity-drawer-panel">
            <header class="identity-drawer-head">
              <div>
                <p class="eyebrow">MCP SERVER</p>
                <h2 id="server-drawer-title">&mdash;</h2>
                <p class="identity-drawer-sub" id="server-drawer-sub"></p>
              </div>
              <button type="button" class="events-icon-btn"
                      data-server-drawer-close aria-label="Close">
                &times;
              </button>
            </header>
            <div class="identity-drawer-tabs" role="tablist">
              <button type="button" class="identity-drawer-tab is-active"
                      data-server-drawer-tab="tools">Tools</button>
              <button type="button" class="identity-drawer-tab"
                      data-server-drawer-tab="risk">Risk</button>
              <button type="button" class="identity-drawer-tab"
                      data-server-drawer-tab="details">Details</button>
            </div>
            <div class="identity-drawer-body" id="server-drawer-body">
              &mdash;
            </div>
          </div>
        </div>

      </main>
    </div>
    <div id="palette-overlay" class="palette-overlay" hidden
         role="dialog" aria-modal="true" aria-label="Search">
      <div class="palette-card" role="document">
        <div class="palette-input-row">
          <span class="palette-input-icon" aria-hidden="true">⌕</span>
          <input type="text" id="palette-input" class="palette-input"
                 placeholder="Search servers, vservers, users, groups…"
                 autocomplete="off" spellcheck="false"
                 aria-label="Search">
          <kbd class="palette-input-kbd">esc</kbd>
        </div>
        <div id="palette-results" class="palette-results"
             role="listbox" aria-label="Search results"></div>
        <div class="palette-foot">
          <span><kbd>↑</kbd> <kbd>↓</kbd> navigate</span>
          <span><kbd>↵</kbd> open</span>
          <span><kbd>esc</kbd> close</span>
        </div>
      </div>
    </div>
    <div id="alerts-overlay" class="palette-overlay" hidden
         role="dialog" aria-modal="true" aria-label="Recent alerts">
      <div class="palette-card" role="document">
        <div class="palette-input-row">
          <span class="palette-input-icon" aria-hidden="true">◔</span>
          <span class="palette-input" style="font-weight: 600;">Recent alerts</span>
          <button type="button" id="alerts-refresh"
                  class="palette-input-kbd" style="cursor: pointer;">
            refresh
          </button>
          <kbd class="palette-input-kbd">esc</kbd>
        </div>
        <div id="alerts-results" class="palette-results"
             role="list" aria-label="Recent alerts"></div>
        <div class="palette-foot">
          <span>Surfaces denied / blocked tool calls from the last hour.</span>
        </div>
      </div>
    </div>
    <script src="/operator/app.js"></script>
  </body>
</html>
"""

_CSS = """
/* Vyuu Design System tokens — single source of truth for every value
   used below. See `Vyuu Design Handoff/tokens/tokens.css` for the
   canonical version; this is a copy because the operator UI runs under
   a strict CSP (`default-src 'self'`) and can't import remote stylesheets. */
:root {
  --vyuu-bg: #F7F4ED;
  --vyuu-panel: #FFFEFB;
  --vyuu-ivory: #FBF8F1;
  --vyuu-sand: #E8DFC9;
  --vyuu-ink: #1F2A2E;
  --vyuu-muted: #6B7A7D;
  --vyuu-subtle: #A9B4B5;
  --vyuu-line: #E4DED1;
  --vyuu-line-soft: #EDE8DC;
  --vyuu-orange: #D6843E;
  --vyuu-orange-deep: #A85820;
  --vyuu-orange-soft: #F3DAB6;
  --vyuu-orange-mist: #FAEDD5;
  --vyuu-on-primary: #FBF8F1;
  --vyuu-danger: #C17457;
  --vyuu-danger-tint: #F4E2D9;
  --vyuu-danger-ink: #8A4A34;
  --vyuu-warn: #D4A259;
  --vyuu-warn-tint: #F7EBD4;
  --vyuu-warn-ink: #8A6420;
  --vyuu-info: #4E7A8A;
  --vyuu-info-tint: #DCE7EC;
  --vyuu-info-ink: #2E5565;
  --vyuu-code-bg: #2A3638;
  --vyuu-code-fg: #DCE7EC;
  --vyuu-serif: 'Fraunces', 'Iowan Old Style', 'Apple Garamond', Georgia, serif;
  --vyuu-sans: 'Inter', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif;
  --vyuu-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Consolas, monospace;
  --vyuu-h1: 400 30px/1.10 var(--vyuu-serif);
  --vyuu-h2: 500 22px/1.20 var(--vyuu-serif);
  --vyuu-h3: 500 18px/1.25 var(--vyuu-serif);
  --vyuu-body: 400 13.5px/1.55 var(--vyuu-sans);
  --vyuu-body-lg: 400 15px/1.55 var(--vyuu-sans);
  --vyuu-ui: 500 13px/1.30 var(--vyuu-sans);
  --vyuu-ui-sm: 500 12px/1.30 var(--vyuu-sans);
  --vyuu-label: 500 12.5px/1.30 var(--vyuu-sans);
  --vyuu-eyebrow: 600 10px/1.20 var(--vyuu-sans);
  --vyuu-mono-sm: 400 12px/1.40 var(--vyuu-mono);
  --vyuu-r-md: 8px;
  --vyuu-r-lg: 10px;
  --vyuu-r-xl: 12px;
  --vyuu-r-pill: 999px;
  --vyuu-shadow-md: 0 2px 8px rgba(168, 88, 32, 0.20);
  /* Density spacing scale — tweaked by [data-density="compact"]. Cozy
     defaults below are the original values; compact tightens them. */
  --vyuu-pad-card: 24px;
  --vyuu-pad-row:  14px 16px;
  --vyuu-gap-section: 18px;

  /* ---- Tokens that rules below always referenced but nothing defined.
     Each maps onto the palette above (no new colours): before this,
     `var(--vyuu-r-sm)` left 45 elements square, `--vyuu-ink-muted`
     made 32 secondary-text rules inherit body ink, and `--vyuu-kpi`
     rendered the dashboard numbers at body size. -------------------- */
  --vyuu-r-sm: 6px;
  --vyuu-ink-muted: var(--vyuu-muted);
  --vyuu-cream: var(--vyuu-ivory);
  --vyuu-saffron-soft: var(--vyuu-orange-soft);
  --vyuu-panel-soft: var(--vyuu-ivory);
  --vyuu-warn-bg: var(--vyuu-warn-tint);
  --vyuu-warn-line: var(--vyuu-warn);
  /* Success has no brand token; these are the values the fallbacks
     already painted, named so dark mode can override them. */
  --vyuu-ok-bg: rgba(38, 138, 76, 0.14);
  --vyuu-ok-ink: #1D5B33;
  --vyuu-ok-line: rgba(38, 138, 76, 0.35);
  --vyuu-good: #2F7A3A;
  --vyuu-display-md: 500 24px/1.15 var(--vyuu-serif);
  --vyuu-display-sm: 500 18px/1.20 var(--vyuu-serif);
  --vyuu-kpi: 600 32px/1 var(--vyuu-serif);
  --vyuu-mono-md: 400 13px/1.45 var(--vyuu-mono);
  --vyuu-th: 600 10.5px/1 var(--vyuu-sans);
  --vyuu-th-tracking: 0.08em;
  /* Legacy short names used by the health / diagnostics rules, which
     fell back to off-palette greys and pure white. */
  --muted: var(--vyuu-muted);
  --ink: var(--vyuu-ink);
  --surface: var(--vyuu-panel);
  --surface-alt: var(--vyuu-ivory);
  --border: var(--vyuu-line);
  --err: var(--vyuu-danger-ink);
  /* Focus ring, derived from the brand orange. */
  --vyuu-focus: color-mix(in srgb, var(--vyuu-orange) 45%, transparent);
}

/* Dark theme: applied via [data-theme="dark"] on <html> or <body>.
   Mirrors the canonical tokens.css overrides. The orange brand
   tokens shift slightly (orange-soft becomes a saturated dark
   amber), but `--vyuu-on-primary` stays cream so the brand mark
   reads correctly in both modes. */
[data-theme="dark"] {
  --vyuu-bg:           #1C1F21;
  --vyuu-panel:        #23272A;
  --vyuu-ivory:        #1F2326;
  --vyuu-sand:         #4A3F30;
  --vyuu-ink:          #EAE3D5;
  --vyuu-muted:        #8C857C;
  --vyuu-subtle:       #5C5853;
  --vyuu-line:         #2D3134;
  --vyuu-line-soft:    #25292B;
  --vyuu-orange:       #E89B58;
  --vyuu-orange-deep:  #D6843E;
  --vyuu-orange-soft:  #3A2818;
  --vyuu-orange-mist:  #261B12;
  --vyuu-on-primary:   #FBF8F1;
  --vyuu-danger:       #D88A6A;
  --vyuu-danger-tint:  #3D2820;
  --vyuu-danger-ink:   #E4A88E;
  --vyuu-warn:         #DDB063;
  --vyuu-warn-tint:    #3A2D18;
  --vyuu-warn-ink:     #E8C77E;
  --vyuu-info:         #6F9BAB;
  --vyuu-info-tint:    #1E2D34;
  --vyuu-info-ink:     #95B4C0;
  --vyuu-code-bg:      #1A1E20;
  --vyuu-code-fg:      #DCE7EC;
  --vyuu-ok-bg:        rgba(76, 175, 110, 0.16);
  --vyuu-ok-ink:       #8FD1A5;
  --vyuu-ok-line:      rgba(76, 175, 110, 0.40);
  --vyuu-good:         #7FC591;
}

/* Compact density: tighter padding everywhere. Real value at scale —
   on a 100-server table the 14px row padding eats the screen; 8px
   keeps 50% more rows in view without sacrificing readability. */
[data-density="compact"] {
  --vyuu-pad-card: 14px;
  --vyuu-pad-row:  8px 14px;
  --vyuu-gap-section: 12px;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100vh;
  color: var(--vyuu-ink);
  background: var(--vyuu-bg);
  font: var(--vyuu-body);
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}

h1,
h2,
h3 {
  margin: 0;
}

/* App shell: fixed-width left sidebar + flex-1 content area. The
   sidebar is sticky so it stays visible as the operator scrolls inside
   a single section, and the content area is the only thing that
   scrolls vertically — every panel below is one of N sections, only
   the one matching `body[data-active-nav]` is visible at a time. */
.app-shell {
  display: flex;
  align-items: flex-start;
  width: 100%;
  min-height: 100vh;
}
.sidebar {
  position: sticky;
  top: 0;
  flex: 0 0 248px;
  width: 248px;
  height: 100vh;
  background: var(--vyuu-ivory);
  border-right: 1px solid var(--vyuu-line);
  padding: 22px 14px 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  overflow-y: auto;
}
.sidebar .brand-block {
  display: flex;
  align-items: center;
  gap: 10px;
  text-decoration: none;
  padding: 4px 8px 14px;
  border-bottom: 1px solid var(--vyuu-line);
  margin-bottom: 6px;
}
.sidebar .brand-mark {
  flex-shrink: 0;
  display: inline-flex;
  width: 32px;
  height: 32px;
  align-items: center;
  justify-content: center;
}
.sidebar .brand-text { display: flex; flex-direction: column; gap: 1px; }
.sidebar .brand-text strong {
  font: 500 17px/1.1 var(--vyuu-serif);
  color: var(--vyuu-ink);
  letter-spacing: -0.2px;
}
.sidebar .brand-lockup {
  display: block;
  width: auto;
  height: 36px;
  margin: 0 0 6px;
}
.sidebar .eyebrow {
  margin: 0;
  color: var(--vyuu-orange-deep);
  font: var(--vyuu-eyebrow);
  letter-spacing: 1.6px;
  text-transform: uppercase;
  font-size: 9.5px;
}
.side-nav {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding-top: 4px;
}
.nav-group { margin: 6px 0 4px; }
.nav-group-label {
  margin: 6px 10px 4px;
  font: var(--vyuu-eyebrow);
  letter-spacing: 1.8px;
  text-transform: uppercase;
  color: var(--vyuu-muted);
  font-size: 10px;
}
.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  padding: 7px 10px;
  border: none;
  border-radius: var(--vyuu-r-md);
  background: transparent;
  color: var(--vyuu-ink);
  font: 500 13px/1.3 var(--vyuu-sans);
  cursor: pointer;
  text-align: left;
  margin-bottom: 1px;
  transition: background 0.12s, color 0.12s;
}
.nav-item:hover {
  background: var(--vyuu-line-soft);
}
.nav-item.is-active {
  background: var(--vyuu-orange-soft);
  color: var(--vyuu-orange-deep);
  font-weight: 600;
}
.nav-item-icon {
  display: inline-flex;
  width: 18px;
  height: 18px;
  align-items: center;
  justify-content: center;
  color: var(--vyuu-muted);
  flex-shrink: 0;
}
.nav-item.is-active .nav-item-icon { color: var(--vyuu-orange-deep); }
.nav-item:hover .nav-item-icon { color: var(--vyuu-ink); }
.nav-item-icon svg { width: 16px; height: 16px; display: block; }
.nav-item-label { flex: 1; }
.nav-item-quiet {
  color: var(--vyuu-muted);
  font-weight: 500;
}
.sidebar-foot {
  border-top: 1px solid var(--vyuu-line);
  padding-top: 10px;
  margin-top: 6px;
}
.content {
  flex: 1;
  min-width: 0;
  padding: 32px 40px 80px;
  display: flex;
  flex-direction: column;
  gap: 18px;
  width: 100%;
  max-width: 1280px;
}

/* Section visibility — driven by a `.is-hidden` class toggled in JS
   rather than attribute selectors. Pre-existing rules like
   `.auth-panel { display: grid }` and `section.grid { display: grid }`
   already beat attribute-selector specificity, and we genuinely need
   the hide to win, so the simpler rule + `!important` is correct here. */
.is-hidden { display: none !important; }

/* Mobile fallback: stack vertically (sidebar becomes a top strip). */
@media (max-width: 900px) {
  .app-shell { flex-direction: column; }
  .sidebar {
    position: relative;
    width: 100%;
    height: auto;
    flex: 0 0 auto;
    border-right: none;
    border-bottom: 1px solid var(--vyuu-line);
  }
  .content { padding: 20px; }
}

.shell {
  display: grid;
  grid-template-columns: minmax(250px, 0.32fr) minmax(0, 0.68fr);
  gap: 16px;
  width: min(1440px, calc(100% - 48px));
  padding: 32px 0 80px;
}

.hero,
.panel {
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  background: var(--vyuu-panel);
  box-shadow: none;
  backdrop-filter: none;
}

.hero {
  position: sticky;
  top: 24px;
  align-self: start;
  grid-row: span 5;
  margin: 0;
  padding: 20px;
}

.brand-lockup {
  display: block;
  width: 164px;
  height: auto;
  margin-bottom: 24px;
}

.eyebrow {
  margin: 0 0 6px;
  color: var(--vyuu-orange-deep);
  font: var(--vyuu-eyebrow);
  letter-spacing: 2.5px;
  text-transform: uppercase;
}

h1 {
  max-width: 360px;
  color: var(--vyuu-ink);
  font: var(--vyuu-h1);
  letter-spacing: -0.5px;
}

h2 {
  color: var(--vyuu-ink);
  font: var(--vyuu-h2);
  letter-spacing: -0.3px;
}

h3 {
  color: var(--vyuu-ink);
  font: var(--vyuu-h3);
}

p,
.hint {
  color: var(--vyuu-muted);
  font: var(--vyuu-body);
}

.lede {
  max-width: 360px;
  margin-top: 10px;
  font: var(--vyuu-body-lg);
}

.grid {
  display: grid;
  grid-template-columns: minmax(0, 0.85fr) minmax(0, 1.15fr);
  gap: 16px;
  margin: 0;
}

.panel {
  padding: 20px;
  margin-bottom: 16px;
}

.auth-panel,
.panel-head {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 16px;
  align-items: start;
}

.auth-panel {
  grid-template-columns: minmax(0, 1fr);
}

.panel-head {
  margin-bottom: 16px;
}

label {
  color: var(--vyuu-ink);
  font: var(--vyuu-label);
  letter-spacing: 0;
  text-transform: none;
}

input,
select,
textarea {
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-md);
  background: var(--vyuu-panel);
  color: var(--vyuu-ink);
  font: var(--vyuu-ui);
}

input,
select {
  min-height: 38px;
  padding: 8px 10px;
}

textarea {
  width: 100%;
  padding: 10px;
}

input::placeholder,
textarea::placeholder {
  color: var(--vyuu-subtle);
}

button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 38px;
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-md);
  padding: 9px 16px;
  background: var(--vyuu-panel);
  color: var(--vyuu-ink);
  font: var(--vyuu-ui);
  letter-spacing: 0.1px;
  text-transform: none;
  transition: filter 0.15s;
}

button:hover {
  filter: brightness(0.98);
}

#save-token,
#register-form button,
#vserver-form button {
  border-color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-deep);
  color: var(--vyuu-on-primary);
  box-shadow: var(--vyuu-shadow-md);
}

.danger-action {
  border-color: var(--vyuu-danger);
  color: var(--vyuu-danger-ink);
}

.form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

.form-grid button {
  grid-column: 1 / -1;
  justify-self: start;
}

.hint {
  margin-top: 8px;
}

.output {
  min-height: 104px;
  margin-top: 16px;
  padding: 14px;
  overflow: auto;
  border: 1px solid var(--vyuu-line-soft);
  border-radius: var(--vyuu-r-lg);
  background: var(--vyuu-code-bg);
  color: var(--vyuu-code-fg);
  font: var(--vyuu-mono-sm);
}

.cards {
  display: grid;
  gap: 12px;
  color: var(--vyuu-muted);
}

/* KPI grid — 4 (or 3 / 2 / 1) cards in a row, responsive. Used by the
   Dashboard panel. Each cell renders kpi-label + kpi-value + pill-delta. */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 14px;
}
.kpi-card {
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.kpi-label {
  font: var(--vyuu-eyebrow);
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: var(--vyuu-muted);
}
.kpi-value {
  font: var(--vyuu-kpi);
  letter-spacing: -1px;
  line-height: 1;
  color: var(--vyuu-ink);
}
.kpi-card.alert .kpi-value { color: var(--vyuu-danger-ink); }
.kpi-card.warn  .kpi-value { color: var(--vyuu-warn-ink); }
.kpi-delta { color: var(--vyuu-muted); font: var(--vyuu-ui-sm); }

/* NHI map (4-column bipartite) — SVG sits in this container, columns
   render with the eyebrow style above each layer. */
.nhi-map-frame {
  background: var(--vyuu-ivory);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-lg);
  padding: 16px;
  overflow-x: auto;
}
/* Card-based NHI map. Smooth hover/click transitions; the highlight
   layer hops opacity + stroke-opacity so the focused subgraph
   stands out against the dimmed rest. */
.nhi-map-svg .nhi-card { transition: opacity 120ms ease-out; }
.nhi-map-svg .nhi-card:hover rect {
  filter: drop-shadow(0 1px 4px rgba(31, 42, 46, 0.10));
}
.nhi-map-svg .nhi-edge {
  transition: opacity 120ms ease-out, stroke-opacity 120ms ease-out;
}
.nhi-map-svg .nhi-edge.nhi-edge-hl {
  filter: drop-shadow(0 0 1px rgba(168, 88, 32, 0.45));
}
.nhi-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  margin-top: 8px;
  font: var(--vyuu-ui-sm);
  color: var(--vyuu-muted);
}
.nhi-legend-dot {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  margin-right: 4px;
  vertical-align: -1px;
}

/* Identity dependency graph — same visual language as the NHI map
   (rounded-rect cards in columns, bezier edges, hover-dim full
   reachable subgraph). Frame scrolls vertically when an upstream
   exposes lots of tools (e.g. falcon-mcp's 56 capabilities). */
.identity-graph-frame {
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-lg);
  background: var(--vyuu-ivory);
  padding: 12px;
  max-height: 640px;
  overflow: auto;
}
.identity-graph-svg .identity-graph-card {
  transition: opacity 120ms ease-out;
}
.identity-graph-svg .identity-graph-card:hover rect {
  filter: drop-shadow(0 1px 4px rgba(31, 42, 46, 0.10));
}
.identity-graph-svg .identity-graph-edge {
  transition: opacity 120ms ease-out, stroke-opacity 120ms ease-out;
}
.identity-graph-svg .identity-graph-edge.identity-graph-edge-hl {
  filter: drop-shadow(0 0 1px rgba(168, 88, 32, 0.45));
}
.identity-graph-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  margin-top: 8px;
  font: var(--vyuu-ui-sm);
  color: var(--vyuu-muted);
}
.identity-graph-risk-legend {
  margin-top: 4px;
  gap: 12px;
  padding-top: 8px;
  border-top: 1px dashed var(--vyuu-line);
}
.identity-graph-legend-dot {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  margin-right: 4px;
  vertical-align: -1px;
}
.identity-graph-legend-eyebrow {
  font: 600 10px 'Inter', system-ui, sans-serif;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--vyuu-orange-deep);
  margin-right: 4px;
}

.server-card {
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  background: var(--vyuu-panel);
  padding: 16px;
}

/* Inline group editor — chip list with per-chip × button + a
   filtered Add row. Replaces the prior single-select Add/Remove
   pair that surfaced status only via a panel-shared output. Each
   group card is now self-contained: live members, optimistic
   updates, inline error/success messages. */
.group-card { display: flex; flex-direction: column; }
.group-member-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 8px;
}
.group-member-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 4px 4px 10px;
  background: var(--vyuu-saffron-soft);
  color: var(--vyuu-orange-deep);
  border: 1px solid var(--vyuu-saffron-soft);
  border-radius: 999px;
  font: var(--vyuu-mono-sm);
  white-space: nowrap;
}
.group-member-chip-x {
  appearance: none;
  background: transparent;
  border: 0;
  color: var(--vyuu-orange-deep);
  font-size: 16px;
  line-height: 1;
  padding: 2px 6px;
  border-radius: 999px;
  cursor: pointer;
}
.group-member-chip-x:hover {
  background: var(--vyuu-orange-deep);
  color: var(--vyuu-on-primary);
}
.group-member-empty {
  font: var(--vyuu-body);
  color: var(--vyuu-ink-muted);
}
.group-add-row {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-top: 4px;
  flex-wrap: wrap;
}
.group-add-select {
  flex: 1 1 280px;
  min-width: 240px;
  padding: 6px 10px;
  font: var(--vyuu-body);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  background: var(--vyuu-bg);
  color: var(--vyuu-ink);
}
.group-add-select:focus {
  outline: none;
  border-color: var(--vyuu-orange-deep);
  box-shadow: 0 0 0 2px var(--vyuu-saffron-soft);
}
.group-status { margin: 6px 0 0; }

/* Register MCP form layout: form on the left, live preview rail on
   the right. Stacks under 1100px so the form doesn't compress on a
   laptop. The preview pane shows the JSON body that will be sent
   on submit + a small checklist of required fields — operators get
   confidence in what they're about to commit before clicking. */
/* Wizard chrome — wraps the existing register form fields with a
   5-step navigation (Runtime → Connection → Authentication →
   Capabilities → Review). The flat register panel is hidden by
   default; "+ Register" toggles `data-wizard-mode="open"` to swap
   the servers list for the wizard, with Cancel returning to list. */
.wizard-shell { display: none; }
.wizard-shell[data-wizard-mode="open"] {
  display: block;
}
.wizard-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 18px;
}
.wizard-title {
  font: var(--vyuu-display-md);
  margin: 4px 0 6px;
}
.wizard-sub {
  font: var(--vyuu-body);
  color: var(--vyuu-ink-muted);
  max-width: 720px;
  margin: 0;
}
.wizard-cancel {
  appearance: none;
  background: var(--vyuu-bg);
  color: var(--vyuu-ink);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  padding: 6px 14px;
  cursor: pointer;
  font: 500 13px/1.2 var(--vyuu-sans);
  white-space: nowrap;
}
.wizard-cancel:hover { background: var(--vyuu-line-soft); }

/* Progress rail — one pill per step. Connectors between pills draw
   via a ::after pseudo (so the line is part of the layout, not a
   manually-positioned div). Three states per pill: pending (default),
   current (saffron-bordered), done (saffron-filled). */
.wizard-progress {
  list-style: none;
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 0;
  padding: 0;
  margin: 0 0 22px;
}
.wizard-step-pill {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 0;
  position: relative;
  font: 500 13px/1.2 var(--vyuu-sans);
  color: var(--vyuu-ink-muted);
}
.wizard-step-pill::after {
  content: "";
  position: absolute;
  left: 36px;
  right: 12px;
  top: 50%;
  height: 1px;
  background: var(--vyuu-line);
  z-index: 0;
}
.wizard-step-pill:last-child::after { display: none; }
.wizard-step-num {
  width: 28px;
  height: 28px;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--vyuu-line);
  background: var(--vyuu-bg);
  color: var(--vyuu-ink-muted);
  font: 500 13px/1 var(--vyuu-mono);
  flex-shrink: 0;
  position: relative;
  z-index: 1;
}
.wizard-step-label { white-space: nowrap; }
.wizard-step-pill.is-current .wizard-step-num {
  border-color: var(--vyuu-orange-deep);
  color: var(--vyuu-orange-deep);
  background: var(--vyuu-bg);
}
.wizard-step-pill.is-current { color: var(--vyuu-ink); font-weight: 600; }
.wizard-step-pill.is-done .wizard-step-num {
  border-color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-deep);
  color: var(--vyuu-on-primary);
}
.wizard-step-pill.is-done .wizard-step-num::before {
  content: "✓";
}
.wizard-step-pill.is-done .wizard-step-num span:first-child { display: none; }

/* Per-step body. Only one step visible at a time via `hidden`. */
.wizard-step {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 24px;
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
}
.wizard-step[hidden] { display: none; }
.wizard-step-title {
  font: var(--vyuu-display-sm);
  margin: 0 0 4px;
}
.wizard-form { width: 100%; min-width: 0; }
.wizard-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
  font: 500 13px/1.2 var(--vyuu-sans);
}
.wizard-field input,
.wizard-field select {
  font: var(--vyuu-body);
  padding: 9px 12px;
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  background: var(--vyuu-bg);
  color: var(--vyuu-ink);
}
.wizard-field input:focus,
.wizard-field select:focus {
  outline: none;
  border-color: var(--vyuu-orange-deep);
  box-shadow: 0 0 0 2px var(--vyuu-saffron-soft);
}
.wizard-field-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
}

/* Runtime cards — 5 per row on wide, wraps on small. Uses the
   same radio-card pattern as the auth-mode picker for visual
   consistency. */
.runtime-card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 10px;
}
.runtime-card {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 14px 16px;
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-lg);
  background: var(--vyuu-bg);
  cursor: pointer;
  position: relative;
}
.runtime-card input { position: absolute; opacity: 0; pointer-events: none; }
.runtime-card-title {
  font: 600 14px/1.2 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.runtime-card-hint {
  font: var(--vyuu-eyebrow);
  color: var(--vyuu-ink-muted);
}
.runtime-card:has(input:checked) {
  border-color: var(--vyuu-orange-deep);
  background: var(--vyuu-saffron-soft);
}
.runtime-card:hover { background: var(--vyuu-line-soft); }
.runtime-card:has(input:checked):hover { background: var(--vyuu-saffron-soft); }

/* Stdio-only fields hide when source_type is HTTP. Default is HTTP,
   so on first paint the args / env_vars_ref fields stay collapsed. */
body[data-source-type="http"] [data-stdio-only] {
  display: none;
}

/* Step 4 preflight + Step 5 review chrome. */
.wizard-preflight {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.wizard-preflight-output {
  padding: 14px 16px;
  background: var(--vyuu-bg);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  min-height: 80px;
}
.wizard-review {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.wizard-review-checklist {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.wizard-review-checklist li {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 12px;
  border-radius: var(--vyuu-r-sm);
  background: var(--vyuu-bg);
  border: 1px solid var(--vyuu-line);
  font: 500 13px/1.2 var(--vyuu-sans);
}
.wizard-review-checklist li::before {
  content: "○";
  color: var(--vyuu-ink-muted);
  font-size: 14px;
}
.wizard-review-checklist li.is-ok { border-color: var(--vyuu-orange-deep); }
.wizard-review-checklist li.is-ok::before {
  content: "✓";
  color: var(--vyuu-orange-deep);
  font-weight: 700;
}
.wizard-review-checklist li.is-fail { border-color: var(--vyuu-danger); }
.wizard-review-checklist li.is-fail::before {
  content: "✕";
  color: var(--vyuu-danger);
  font-weight: 700;
}
.wizard-review-checklist .checklist-meta {
  margin-left: auto;
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-ink-muted);
}
.wizard-register-btn {
  margin-top: 14px;
  align-self: flex-start;
  padding: 10px 22px;
}

/* Footer — Back / Continue (or Register on the last step). */
.wizard-foot {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 18px;
  padding-top: 16px;
  border-top: 1px solid var(--vyuu-line);
}
.wizard-foot-status {
  flex: 1;
  font: var(--vyuu-body);
  color: var(--vyuu-ink-muted);
}
.wizard-back, .wizard-next {
  appearance: none;
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  padding: 8px 18px;
  font: 500 13px/1.2 var(--vyuu-sans);
  cursor: pointer;
  background: var(--vyuu-bg);
  color: var(--vyuu-ink);
}
.wizard-back:disabled,
.wizard-next:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.wizard-next {
  background: var(--vyuu-orange-deep);
  color: var(--vyuu-on-primary);
  border-color: var(--vyuu-orange-deep);
}

/* When the wizard is open, hide the rest of the servers panel
   (toolbar / table / drawer). Scoped to `.content` so the sidebar
   nav button (also `data-nav="servers"`) stays visible. */
body[data-wizard-active="true"] .content [data-nav="servers"]:not(.wizard-shell) {
  display: none !important;
}

.register-layout {
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(280px, 1fr);
  gap: 18px;
  align-items: flex-start;
  margin-top: 12px;
}
@media (max-width: 1100px) {
  .register-layout { grid-template-columns: 1fr; }
}
.register-preview {
  position: sticky;
  top: 16px;
  background: var(--vyuu-ivory);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  padding: 16px 18px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.register-preview-head h3 {
  font: var(--vyuu-h3);
  color: var(--vyuu-ink);
  margin: 4px 0 6px;
  letter-spacing: -0.2px;
}
.register-preview .eyebrow {
  margin: 0;
  font: var(--vyuu-eyebrow);
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: var(--vyuu-orange-deep);
}
.register-preview-pre {
  margin: 0;
  font: var(--vyuu-mono-sm);
  white-space: pre;
  overflow-x: auto;
  background: var(--vyuu-code-bg);
  color: var(--vyuu-code-fg);
  padding: 12px 14px;
  border-radius: var(--vyuu-r-md);
  max-height: 380px;
  min-height: 180px;
}
.register-preview-checklist ul {
  list-style: none;
  padding: 0;
  margin: 6px 0 0;
  font: var(--vyuu-body);
}
.register-preview-checklist li {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 3px 0;
  color: var(--vyuu-muted);
}
.register-preview-checklist li::before {
  content: "○";
  color: var(--vyuu-subtle);
  font-size: 13px;
}
.register-preview-checklist li.is-ok {
  color: var(--vyuu-orange-deep);
}
.register-preview-checklist li.is-ok::before {
  content: "●";
  color: var(--vyuu-orange-deep);
}

/* UI preference toggles in the sidebar foot. Two two-button "pill
   groups" — light/dark theme + cozy/compact density. The selected
   button gets the saffron-soft fill; unselected stays neutral. */
.ui-pref-row {
  display: flex;
  gap: 8px;
  margin-bottom: 8px;
}
.ui-pref-toggle {
  flex: 1;
  display: flex;
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-md);
  padding: 2px;
  overflow: hidden;
}
.ui-pref-toggle button {
  flex: 1;
  padding: 4px 0;
  border: none;
  background: transparent;
  color: var(--vyuu-muted);
  font-size: 14px;
  cursor: pointer;
  border-radius: var(--vyuu-r-sm);
  min-height: 24px;
  line-height: 1;
}
.ui-pref-toggle button:hover { background: var(--vyuu-line-soft); }
.ui-pref-toggle button.is-active {
  background: var(--vyuu-orange-soft);
  color: var(--vyuu-orange-deep);
}

/* Search palette — global ⌘K overlay. Searches in-memory caches
   (servers / vservers / users / groups) and routes the operator to
   the right panel on click. No backend search endpoint required;
   the existing list endpoints already populate the caches when the
   user has visited those panels at least once, and the palette
   lazy-fetches anything not loaded. */
.palette-trigger {
  appearance: none;
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 6px 10px;
  background: var(--vyuu-bg);
  color: var(--vyuu-ink-muted);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  cursor: pointer;
  font: var(--vyuu-body);
  text-align: left;
}
.palette-trigger:hover {
  background: var(--vyuu-line-soft);
  color: var(--vyuu-ink);
}
.palette-trigger-icon {
  font-size: 14px;
  color: var(--vyuu-ink-muted);
}
.palette-trigger-label { flex: 1; }
.palette-trigger-kbd {
  font: var(--vyuu-mono-sm);
  padding: 2px 6px;
  border: 1px solid var(--vyuu-line);
  border-radius: 4px;
  background: var(--vyuu-panel);
  color: var(--vyuu-ink-muted);
}

/* Alerts bell — sits next to the search trigger in the sidebar foot.
   The badge becomes visible (hidden=false) when there's at least one
   denied/blocked tool call in the last hour. */
.alerts-trigger { position: relative; }
.alerts-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 18px;
  height: 18px;
  padding: 0 6px;
  font: var(--vyuu-mono-sm);
  font-weight: 600;
  border-radius: 999px;
  background: var(--vyuu-danger);
  color: var(--vyuu-on-primary);
}
.alerts-badge[hidden] { display: none; }

/* Alerts overlay reuses .palette-overlay / .palette-card; the
   per-row styling differs enough to warrant a few extra rules. */
.alert-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 16px;
  border-bottom: 1px solid var(--vyuu-line);
  cursor: pointer;
}
.alert-row:hover { background: var(--vyuu-line-soft); }
.alert-row:last-child { border-bottom: 0; }
.alert-row-decision {
  font: var(--vyuu-mono-sm);
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 999px;
  white-space: nowrap;
}
.alert-row-decision.deny {
  background: color-mix(in srgb, var(--vyuu-danger) 12%, transparent);
  color: var(--vyuu-danger);
}
.alert-row-decision.block {
  background: color-mix(in srgb, var(--vyuu-danger) 18%, transparent);
  color: var(--vyuu-danger);
}
.alert-row-decision.error {
  background: color-mix(in srgb, var(--vyuu-warn) 14%, transparent);
  color: var(--vyuu-warn);
}
.alert-row-text { flex: 1; min-width: 0; }
.alert-row-tool {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-ink);
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.alert-row-meta {
  font: var(--vyuu-eyebrow);
  color: var(--vyuu-ink-muted);
  margin-top: 2px;
}
.alert-row-time {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-ink-muted);
  white-space: nowrap;
}
.alerts-empty {
  padding: 24px 16px;
  color: var(--vyuu-ink-muted);
  text-align: center;
}

.palette-overlay {
  position: fixed;
  inset: 0;
  background: color-mix(in srgb, var(--vyuu-ink) 50%, transparent);
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding-top: 12vh;
  z-index: 1000;
}
.palette-overlay[hidden] { display: none; }
.palette-card {
  width: min(640px, calc(100vw - 32px));
  max-height: 70vh;
  display: flex;
  flex-direction: column;
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  box-shadow: 0 24px 64px rgba(0, 0, 0, 0.18);
  overflow: hidden;
}
.palette-input-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--vyuu-line);
}
.palette-input-icon {
  font-size: 18px;
  color: var(--vyuu-ink-muted);
}
.palette-input {
  flex: 1;
  appearance: none;
  border: 0;
  outline: none;
  font: var(--vyuu-body);
  font-size: 16px;
  background: transparent;
  color: var(--vyuu-ink);
}
.palette-input::placeholder { color: var(--vyuu-ink-muted); }
.palette-input-kbd {
  font: var(--vyuu-mono-sm);
  padding: 2px 6px;
  border: 1px solid var(--vyuu-line);
  border-radius: 4px;
  background: var(--vyuu-bg);
  color: var(--vyuu-ink-muted);
}
.palette-results {
  flex: 1;
  overflow-y: auto;
  padding: 8px 0;
  min-height: 80px;
}
.palette-results:empty::before {
  content: "Type to search across servers, vservers, users, groups.";
  display: block;
  padding: 16px;
  color: var(--vyuu-ink-muted);
  font: var(--vyuu-body);
  text-align: center;
}
.palette-section-label {
  font: var(--vyuu-eyebrow);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--vyuu-ink-muted);
  padding: 6px 16px 2px;
}
.palette-result {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 16px;
  cursor: pointer;
  border: 0;
  background: transparent;
  width: 100%;
  text-align: left;
  color: var(--vyuu-ink);
  font: var(--vyuu-body);
}
.palette-result:hover,
.palette-result.is-focused {
  background: var(--vyuu-saffron-soft);
  color: var(--vyuu-orange-deep);
}
.palette-result-name {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.palette-result-meta {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-ink-muted);
  white-space: nowrap;
}
.palette-result.is-focused .palette-result-meta {
  color: var(--vyuu-orange-deep);
}
.palette-result-kind {
  font: var(--vyuu-mono-sm);
  padding: 1px 6px;
  border-radius: 999px;
  background: var(--vyuu-line-soft);
  color: var(--vyuu-ink-muted);
}
.palette-result.is-focused .palette-result-kind {
  background: var(--vyuu-on-primary);
  color: var(--vyuu-orange-deep);
}
.palette-foot {
  display: flex;
  gap: 14px;
  padding: 10px 16px;
  border-top: 1px solid var(--vyuu-line);
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-ink-muted);
}
.palette-foot kbd {
  padding: 1px 5px;
  border: 1px solid var(--vyuu-line);
  border-radius: 3px;
  background: var(--vyuu-bg);
}
.palette-empty {
  padding: 24px 16px;
  color: var(--vyuu-ink-muted);
  text-align: center;
}

/* Compact-density overrides — re-tighten cards / table rows / panel
   spacing. The CSS-variable approach (set via [data-density]) means
   adding new components with `padding: var(--vyuu-pad-card)` get
   density support automatically. */
[data-density="compact"] .panel { padding: var(--vyuu-pad-card); }
[data-density="compact"] .servers-table tbody td { padding: var(--vyuu-pad-row); }
[data-density="compact"] .vserver-card { padding: 14px 16px; }
[data-density="compact"] .card { padding: 14px; }
[data-density="compact"] .panel-head { margin-bottom: 12px; }
[data-density="compact"] .nav-item { padding: 5px 10px; }

/* Wrapper for the as-of pill + Refresh button so they share a
   single grid column in the panel-head. */
.panel-head-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

/* "As of HH:MM:SS" staleness pill that sits next to each Refresh
   button. Lightweight — no border, mono font, muted colour — the
   point is that operators glance at it; it shouldn't compete with
   actual content for attention. */
.as-of-pill {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-muted);
  margin-right: 8px;
  white-space: nowrap;
  align-self: center;
}

/* Virtual servers — mock-aligned card layout. Two-column responsive
   grid; each card leads with the vServer mark, has the name + status
   dot in serif, a meta pills row, the connect-URL with copy button,
   and an action bar at the bottom. Replaces the meta-line debug-log
   layout the original had. */
#vservers-output.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
  gap: 16px;
}
.vserver-card {
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  background: var(--vyuu-panel);
  padding: 18px 20px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.vserver-head {
  display: flex;
  align-items: flex-start;
  gap: 12px;
}
.vserver-mark {
  flex-shrink: 0;
  margin-top: 2px;
}
.vserver-head-text {
  flex: 1;
  min-width: 0;
}
.vserver-title-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.vserver-title {
  font: var(--vyuu-h3);
  color: var(--vyuu-ink);
  margin: 0;
  letter-spacing: -0.2px;
  word-break: break-word;
}
.vserver-desc {
  font: var(--vyuu-body);
  color: var(--vyuu-muted);
  margin: 4px 0 0;
  line-height: 1.5;
}
.vserver-pills {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}
.vserver-url-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding-top: 10px;
  border-top: 1px solid var(--vyuu-line-soft);
}
.vserver-url {
  flex: 1;
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-mist);
  padding: 6px 10px;
  border-radius: var(--vyuu-r-md);
  overflow-x: auto;
  white-space: nowrap;
}
.copy-btn {
  padding: 6px 12px;
  font: var(--vyuu-ui-sm);
  min-height: 30px;
}
.vserver-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

/* Connector catalog — quick-add card grid above the MCP servers
   table. Each card is a typed `ConnectorTemplate` rendered as a
   compact tile; clicking opens the existing register wizard with
   runtime, source URL, transport and OAuth fields pre-filled. The
   grid auto-fills 2-4 columns depending on viewport. */
.connector-catalog-section {
  margin: 14px 0 18px;
  padding: 16px;
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-md);
  background: var(--vyuu-panel-soft, var(--vyuu-panel));
}
.connector-catalog-section[data-collapsed="true"] .connector-catalog-grid {
  display: none;
}
.connector-catalog-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 12px;
}
.connector-catalog-title {
  margin: 0;
  font: 600 14px/1.2 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.connector-catalog-sub {
  margin: 4px 0 0;
  font: 400 12px/1.5 var(--vyuu-sans);
  color: var(--vyuu-muted);
  max-width: 720px;
}
.connector-catalog-toggle {
  flex-shrink: 0;
  padding: 4px 10px;
  border: 1px solid var(--vyuu-line);
  background: transparent;
  border-radius: var(--vyuu-r-sm);
  color: var(--vyuu-muted);
  font: 500 11px/1 var(--vyuu-sans);
  cursor: pointer;
}
.connector-catalog-toggle:hover {
  color: var(--vyuu-ink);
  border-color: var(--vyuu-orange-soft);
}
.connector-catalog-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 10px;
}
.connector-catalog-loading {
  margin: 0;
  padding: 12px;
  font: 400 12px/1.4 var(--vyuu-sans);
  color: var(--vyuu-muted);
}
.connector-card {
  text-align: left;
  padding: 12px 14px;
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-md);
  background: var(--vyuu-panel);
  cursor: pointer;
  transition: border-color 0.12s, transform 0.08s, box-shadow 0.12s;
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-family: var(--vyuu-sans);
}
.connector-card:hover {
  border-color: var(--vyuu-orange);
  transform: translateY(-1px);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
}
.connector-card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.connector-card-name {
  font: 600 13px/1.2 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.connector-card-status {
  font: 600 9.5px/1 var(--vyuu-sans);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 3px 6px;
  border-radius: var(--vyuu-r-sm);
}
.connector-card-status[data-status="stable"] {
  color: var(--vyuu-good, #2f7a3a);
  background: rgba(47, 122, 58, 0.08);
}
.connector-card-status[data-status="community"] {
  color: var(--vyuu-muted);
  background: rgba(127, 127, 127, 0.10);
}
.connector-card-status[data-status="beta"] {
  color: var(--vyuu-orange);
  background: rgba(220, 122, 0, 0.10);
}
.connector-card-tagline {
  font: 400 11.5px/1.4 var(--vyuu-sans);
  color: var(--vyuu-muted);
  flex: 1;
}
.connector-card-meta {
  font: 500 10px/1.3 var(--vyuu-mono, var(--vyuu-sans));
  color: var(--vyuu-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.connector-card-hints {
  margin: 4px 0 0;
  padding: 0 0 0 14px;
  font: 400 11px/1.4 var(--vyuu-sans);
  color: var(--vyuu-muted);
}
.connector-card-hints li {
  margin-bottom: 2px;
}

/* ============================================================
   Events panel v2 — NHI-event-centric redesign.
   Replaces the old card-grid with a clean tabular layout that
   surfaces unsanctioned access attempts as a first-class event
   type alongside tool calls. KPI strip + filter pills + table.
   ============================================================ */
.events-panel-v2 {
  padding-top: 4px;
}
.events-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 18px;
}
.events-head .eyebrow {
  margin: 0 0 8px;
  font: 600 11px/1 var(--vyuu-sans);
  letter-spacing: 0.12em;
  color: var(--vyuu-orange);
  text-transform: uppercase;
}
.events-head h1 {
  margin: 0 0 8px;
  font: 600 28px/1.15 var(--vyuu-serif, var(--vyuu-sans));
  color: var(--vyuu-ink);
}
.events-head .events-sub {
  margin: 0;
  max-width: 720px;
  font: 400 12.5px/1.5 var(--vyuu-sans);
  color: var(--vyuu-muted);
}
.events-head-actions {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}
.events-icon-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 7px 14px;
  border: 1px solid var(--vyuu-line);
  background: var(--vyuu-panel);
  border-radius: var(--vyuu-r-sm);
  color: var(--vyuu-ink);
  font: 500 12px/1 var(--vyuu-sans);
  cursor: pointer;
}
.events-icon-btn:hover { border-color: var(--vyuu-orange-soft); }
.events-icon-btn .events-icon-glyph {
  font-size: 13px;
  color: var(--vyuu-muted);
}

/* KPI strip — 4 cards, single-row at >900px, wraps on narrow screens. */
/* SIEM-1 / OTEL-1 · settings-style forms and status strips. */
.siem-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px 16px;
  margin: 0 0 12px;
}
.siem-grid label {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font: 500 11.5px/1.4 var(--vyuu-sans);
}
.siem-grid label.siem-check {
  flex-direction: row;
  align-items: center;
  gap: 8px;
}
.siem-grid input[type="text"], .siem-grid input[type="number"], .siem-grid select {
  width: 100%;
  box-sizing: border-box;
}
.siem-categories {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 6px 16px;
  margin: 6px 0 12px;
}
.siem-categories label {
  display: flex;
  gap: 8px;
  align-items: flex-start;
  font: 400 11.5px/1.45 var(--vyuu-sans);
}
.siem-categories input { margin-top: 3px; }
.siem-categories .siem-cat-name { font-weight: 600; }
.siem-categories .siem-cat-desc { color: var(--vyuu-muted); }
.siem-stats {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
  margin: 10px 0 14px;
}
.siem-stat { padding: 8px 10px; border: 1px solid var(--vyuu-line); border-radius: 6px; }
.siem-stat .siem-stat-k {
  font: 500 10px/1.3 var(--vyuu-mono); color: var(--vyuu-muted); letter-spacing: .04em;
}
.siem-stat .siem-stat-v { font: 600 16px/1.3 var(--vyuu-sans); }
.siem-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 6px 0 14px; }
.siem-pre {
  font: 400 11px/1.55 var(--vyuu-mono);
  padding: 10px 12px;
  border: 1px solid var(--vyuu-line);
  border-radius: 6px;
  overflow-x: auto;
  white-space: pre;
  margin: 8px 0 12px;
}
@media (max-width: 900px) {
  .siem-grid, .siem-categories { grid-template-columns: 1fr; }
  .siem-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

.events-kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 18px;
}
@media (max-width: 900px) {
  .events-kpi-grid { grid-template-columns: repeat(2, 1fr); }
}

/* --- Health & Server Info page ----------------------------------- */
.health-kpi-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin: 12px 0 16px;
}
@media (max-width: 900px) {
  .health-kpi-row { grid-template-columns: repeat(2, 1fr); }
}
.health-kpi {
  border: 1px solid var(--border, #e3dfd6);
  border-radius: 10px;
  padding: 14px 16px;
  background: var(--surface, #fff);
}
.health-kpi-label {
  margin: 0;
  font-size: 11px;
  letter-spacing: 0.05em;
  color: var(--muted, #8c8676);
  text-transform: uppercase;
}
.health-kpi-num {
  margin: 4px 0 4px;
  font-size: 28px;
  font-weight: 600;
  color: var(--ink, #2a2620);
}
.health-kpi-sub { margin: 0; font-size: 12px; color: var(--muted, #8c8676); }
.health-tenant-card {
  border: 1px solid var(--border, #e3dfd6);
  border-radius: 10px;
  padding: 14px 16px;
  background: var(--surface, #fff);
  margin-bottom: 16px;
}
.health-tenant-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 14px;
}
@media (max-width: 900px) {
  .health-tenant-row { grid-template-columns: repeat(2, 1fr); }
}
.health-tenant-value {
  margin: 4px 0 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 13px;
  color: var(--ink, #2a2620);
  word-break: break-all;
}
.health-status-row {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 10px;
  margin: 12px 0 16px;
}
@media (max-width: 1100px) {
  .health-status-row { grid-template-columns: repeat(2, 1fr); }
}
.health-status-card {
  border: 1px solid var(--border, #e3dfd6);
  border-radius: 10px;
  padding: 12px 14px;
  background: var(--surface, #fff);
  border-left: 3px solid var(--muted, #aaa);
}
.health-status-card.is-ok    { border-left-color: #5b8a3a; }
.health-status-card.is-warn  { border-left-color: #c79324; }
.health-status-card.is-error { border-left-color: #b84a4a; }
.health-status-icon {
  display: inline-block; width: 18px; height: 18px;
  margin-bottom: 6px; opacity: 0.9;
}
.health-status-label {
  margin: 0; font-weight: 600; font-size: 13px;
  color: var(--ink, #2a2620);
}
.health-status-detail {
  margin: 4px 0 0; font-size: 12px; color: var(--muted, #6f6a5d);
  line-height: 1.4;
}
.health-section-head {
  margin: 18px 0 8px;
  font-size: 13px;
  font-weight: 600;
  color: var(--muted, #6f6a5d);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.health-table-wrap { overflow-x: auto; }
.health-table {
  width: 100%;
  border-collapse: collapse;
  background: var(--surface, #fff);
  border: 1px solid var(--border, #e3dfd6);
  border-radius: 10px;
  overflow: hidden;
}
.health-table th, .health-table td {
  padding: 10px 12px;
  text-align: left;
  border-bottom: 1px solid var(--border, #e3dfd6);
  font-size: 13px;
}
.health-table th {
  font-size: 11px;
  letter-spacing: 0.05em;
  color: var(--muted, #8c8676);
  text-transform: uppercase;
  background: var(--surface-alt, #f8f5ee);
}
.health-table tr:last-child td { border-bottom: none; }
.health-empty {
  text-align: center; color: var(--muted, #8c8676);
  padding: 20px; font-size: 13px;
}
.health-pill {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 999px;
  font-size: 11px;
  border: 1px solid currentColor;
}
.health-pill.is-healthy { color: #5b8a3a; }
.health-pill.is-down    { color: #b84a4a; }
.health-pill.is-degraded{ color: #c79324; }
.health-pill.is-unknown { color: var(--muted, #8c8676); }
.health-chart-wrap {
  background: var(--surface, #fff);
  border: 1px solid var(--border, #e3dfd6);
  border-radius: 10px;
  padding: 12px 14px;
}
#health-latency-chart {
  width: 100%; height: 220px; display: block;
}

/* --- Troubleshooting page ----------------------------------------- */
.diagnostic-coverage-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
  margin: 14px 0 8px;
}
@media (max-width: 1100px) {
  .diagnostic-coverage-grid { grid-template-columns: repeat(2, 1fr); }
}
.diagnostic-coverage-card {
  border: 1px solid var(--border, #e3dfd6);
  border-radius: 8px;
  padding: 10px 12px;
  background: var(--surface, #fff);
}
.diagnostic-coverage-card h4 {
  margin: 0 0 4px;
  font-size: 12px;
  font-weight: 600;
  color: var(--ink, #2a2620);
  letter-spacing: 0.02em;
}
.diagnostic-coverage-card p {
  margin: 0;
  font-size: 12px;
  color: var(--muted, #6f6a5d);
  line-height: 1.4;
}
.events-kpi {
  padding: 16px 18px;
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-md);
  background: var(--vyuu-panel);
}
.events-kpi-distinctive {
  /* Vyuu-distinctive metric — capability competitors don't have.
     Subtle saffron border to draw the eye. */
  border-color: var(--vyuu-orange-soft, rgba(220, 122, 0, 0.4));
  background: linear-gradient(180deg,
    rgba(220, 122, 0, 0.04) 0%,
    var(--vyuu-panel) 60%);
}
.events-kpi-label {
  margin: 0 0 8px;
  font: 600 10.5px/1 var(--vyuu-sans);
  letter-spacing: 0.08em;
  color: var(--vyuu-muted);
  text-transform: uppercase;
}
.events-kpi-num {
  margin: 0 0 8px;
  font: 600 36px/1 var(--vyuu-serif, var(--vyuu-sans));
  color: var(--vyuu-ink);
  font-feature-settings: "tnum";
}
.events-kpi-pill {
  display: inline-block;
  margin: 0;
  padding: 3px 10px;
  background: var(--vyuu-panel-soft, rgba(220, 122, 0, 0.05));
  border-radius: 999px;
  font: 400 11px/1.4 var(--vyuu-sans);
  color: var(--vyuu-muted);
}

/* Filter pills row */
.events-pill-row {
  display: flex;
  gap: 8px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}
.events-pill {
  padding: 7px 18px;
  border: 1px solid var(--vyuu-line);
  background: var(--vyuu-panel);
  border-radius: 999px;
  font: 500 12px/1 var(--vyuu-sans);
  color: var(--vyuu-ink);
  cursor: pointer;
  transition: background 0.12s, color 0.12s, border-color 0.12s;
}
.events-pill:hover {
  border-color: var(--vyuu-orange-soft);
}
.events-pill.is-active {
  background: var(--vyuu-ink);
  color: var(--vyuu-cream, #F7F4ED);
  border-color: var(--vyuu-ink);
}

/* Advanced filters drawer — toggled by the Filter button. The
   `[hidden]` HTML attribute alone is overridden by `display: grid`
   below; explicitly hide when the attribute is present. */
.events-advanced-filters[hidden] { display: none; }
.events-advanced-filters {
  display: grid;
  grid-template-columns: repeat(5, 1fr) auto;
  gap: 12px;
  margin-bottom: 14px;
  padding: 12px 14px;
  border: 1px solid var(--vyuu-line);
  background: var(--vyuu-panel-soft, var(--vyuu-panel));
  border-radius: var(--vyuu-r-sm);
}
.events-advanced-filters label {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font: 500 11px/1.2 var(--vyuu-sans);
  color: var(--vyuu-muted);
}
.events-advanced-filters button {
  align-self: end;
}

/* Events table */
.events-table-wrap {
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-md);
  background: var(--vyuu-panel);
  overflow: hidden;
}
.events-table {
  width: 100%;
  border-collapse: collapse;
  font: 400 12.5px/1.4 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.events-table thead th {
  padding: 12px 14px;
  text-align: left;
  font: 600 10.5px/1 var(--vyuu-sans);
  letter-spacing: 0.08em;
  color: var(--vyuu-muted);
  text-transform: uppercase;
  background: var(--vyuu-panel-soft, var(--vyuu-panel));
  border-bottom: 1px solid var(--vyuu-line);
}
.events-table tbody tr {
  border-bottom: 1px solid var(--vyuu-line);
  transition: background 0.1s;
}
.events-table tbody tr:last-child { border-bottom: none; }
.events-table tbody tr:hover { background: var(--vyuu-panel-soft); }
.events-table tbody td {
  padding: 14px 14px;
  vertical-align: top;
}
.events-table .events-empty {
  text-align: center;
  padding: 32px 14px;
  color: var(--vyuu-muted);
}
.events-col-time     { width: 90px; }
.events-col-identity { width: 220px; }
.events-col-target   { width: 280px; }
.events-col-args     { /* fluid */ }
.events-col-risk     { width: 80px; }
.events-col-reason   { width: 240px; }

.events-row-time {
  font-feature-settings: "tnum";
  color: var(--vyuu-muted);
}

/* Identity cell — type badge + email/key prefix */
.events-row-identity {
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.events-row-identity-name {
  color: var(--vyuu-ink);
  font-weight: 500;
}
.events-identity-badge {
  display: inline-block;
  margin-right: 6px;
  padding: 2px 6px;
  border-radius: 3px;
  font: 600 9.5px/1.2 var(--vyuu-sans);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.events-identity-badge[data-type="endpoint_session"] {
  background: var(--vyuu-info-tint);
  color: var(--vyuu-info-ink);
}
.events-identity-badge[data-type="api_key"] {
  background: var(--vyuu-orange-mist);
  color: var(--vyuu-orange-deep);
}
.events-identity-badge[data-type="server_agent"] {
  background: var(--vyuu-warn-tint);
  color: var(--vyuu-warn-ink);
}

/* Server.tool target cell — kbd-styled mono */
.events-row-target {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.events-row-target code {
  font-family: var(--vyuu-mono);
  font-size: 12px;
  color: var(--vyuu-ink);
}
.events-row-target .events-vserver {
  /* Vserver name reads as plain ink — saffron is reserved for the
     unsanctioned-row left-border + the distinctive KPI card so the
     eye picks out the security-relevant signals first, not "every
     row has a server name." */
  color: var(--vyuu-ink);
  font-weight: 600;
}
.events-row-target .events-meta-line {
  font-size: 10.5px;
  color: var(--vyuu-muted);
}

/* Args cell — single-line truncated with hover-expand */
.events-row-args {
  font-family: var(--vyuu-mono);
  font-size: 11.5px;
  color: var(--vyuu-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 280px;
}

/* Risk pill — compact, readable */
.events-risk-pill {
  display: inline-block;
  padding: 3px 9px;
  border-radius: 3px;
  font: 600 10px/1 var(--vyuu-sans);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.events-risk-pill[data-risk="high"] {
  background: var(--vyuu-danger-tint);
  color: var(--vyuu-danger-ink);
}
.events-risk-pill[data-risk="medium"] {
  background: var(--vyuu-warn-tint);
  color: var(--vyuu-warn-ink);
}
.events-risk-pill[data-risk="low"] {
  background: var(--vyuu-line-soft);
  color: var(--vyuu-muted);
}

/* Reason cell — outcome word + short explanation */
.events-row-reason {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.events-row-reason-outcome {
  font: 600 11px/1.2 var(--vyuu-sans);
}
/* "Allowed" reads via ocean (info) — the brand has no green; cool
   ocean is the calm "approved/decided" cue. The other states use
   semantic warm tokens. */
.events-row-reason-outcome[data-outcome="allowed"] { color: var(--vyuu-info-ink); }
.events-row-reason-outcome[data-outcome="blocked"] { color: var(--vyuu-danger-ink); }
.events-row-reason-outcome[data-outcome="redacted"] {
  color: var(--vyuu-warn-ink);
}
.events-row-reason-outcome[data-outcome="unsanctioned"] {
  color: var(--vyuu-orange-deep);
}
.events-row-reason-detail {
  font-size: 11px;
  color: var(--vyuu-muted);
  line-height: 1.35;
}

/* Row-level cues — unsanctioned access attempts get a left border
   so they stand out in the long event list (the headline metric
   on the KPI strip points operators here). */
.events-table tbody tr[data-event-class="unsanctioned"] {
  background: var(--vyuu-orange-mist);
}
.events-table tbody tr[data-event-class="unsanctioned"] td:first-child {
  box-shadow: inset 3px 0 0 var(--vyuu-orange-deep);
}
.events-table tbody tr[data-event-class="blocked"] td:first-child {
  box-shadow: inset 3px 0 0 var(--vyuu-danger);
}

/* Identities tab — reuses the events-panel-v2 chrome (eyebrow,
   KPIs, pills, table) plus a few identity-specific widths and a
   right-slide drawer for the timeline/graph/summary drill-ins. */
.identities-table .identities-col-identity { width: 280px; }
.identities-table .identities-col-type     { width: 90px; }
.identities-table .identities-col-activity { width: 180px; }
.identities-table .identities-col-footprint { width: 200px; }
.identities-table .identities-col-risk     { width: 100px; }
.identities-table .identities-col-actions  { width: 90px; text-align: right; }

.identities-table tbody tr {
  cursor: pointer;
}
.identities-row-activity {
  display: flex;
  flex-direction: column;
  gap: 2px;
  font-size: 11.5px;
}
.identities-row-activity strong {
  font-weight: 600;
  color: var(--vyuu-ink);
}
.identities-row-activity .identities-meta-line {
  color: var(--vyuu-muted);
  font-size: 10.5px;
}
.identities-row-footprint {
  display: flex;
  gap: 12px;
  font-size: 11px;
  color: var(--vyuu-muted);
}
.identities-row-footprint strong {
  color: var(--vyuu-ink);
  font-weight: 600;
}
.identities-row-action-btn {
  padding: 5px 12px;
  border: 1px solid var(--vyuu-line);
  background: var(--vyuu-panel);
  border-radius: var(--vyuu-r-sm);
  color: var(--vyuu-ink);
  font: 500 11px/1 var(--vyuu-sans);
  cursor: pointer;
}
.identities-row-action-btn:hover { border-color: var(--vyuu-orange-soft); }

/* "via" interface tag — answers "what client drove this call?".
   Visually quiet; the operator's eye should land on the identity name
   first, then the type, then the via tag as supporting context. */
.identities-via-tag {
  display: inline-block;
  padding: 2px 8px;
  border: 1px solid var(--vyuu-line);
  border-radius: 999px;
  background: var(--vyuu-panel);
  color: var(--vyuu-ink);
  font: 500 10.5px/1.5 var(--vyuu-sans);
  white-space: nowrap;
}
.identities-table .identities-col-via { width: 14ch; }

.identities-footnote {
  margin: 10px 0 0;
  font: 400 11.5px/1.4 var(--vyuu-sans);
  color: var(--vyuu-muted);
}

/* High-risk row — same orange-tint cue as unsanctioned events. */
.identities-table tbody tr[data-risk-level="high"] {
  background: var(--vyuu-orange-mist);
}
.identities-table tbody tr[data-risk-level="high"] td:first-child {
  box-shadow: inset 3px 0 0 var(--vyuu-orange-deep);
}

/* --- Users table --------------------------------------------------- */
/* Visually mirrors `.identities-table` so the two panels read as
   one product. Only adds user-specific styling on top: status pill
   colors, auth-source tag, count cells. */
.users-table .users-col-user      { min-width: 28ch; }
.users-table .users-col-auth      { width: 9ch; }
.users-table .users-col-last-seen { width: 14ch; }
.users-table .users-col-keys      { width: 10ch; text-align: right; }
.users-table .users-col-groups    { width: 9ch;  text-align: right; }
.users-table .users-col-created   { width: 14ch; }
.users-table .users-col-actions   { width: 12ch; text-align: right; }

.users-table tbody td.users-row-keys,
.users-table tbody td.users-row-groups { text-align: right; }

.users-row-user {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.users-row-user-line {
  display: flex;
  align-items: center;
  gap: 8px;
  font: 500 12.5px/1.3 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.users-row-user-id {
  font: 400 10.5px/1.3 var(--vyuu-sans);
  color: var(--vyuu-muted);
}

/* Status pill — color sourced from semantic tokens so dark-mode
   flips correctly. The brand palette has no green; "active" uses
   ocean (info), the cool counterpoint to the warm system. */
.users-status-pill {
  display: inline-block;
  padding: 1.5px 8px;
  border-radius: 999px;
  border: 1px solid var(--vyuu-line);
  font: 500 10px/1.5 var(--vyuu-sans);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  background: var(--vyuu-panel);
  color: var(--vyuu-ink);
}
.users-status-pill[data-status="active"] {
  border-color: var(--vyuu-info);
  background: var(--vyuu-info-tint);
  color: var(--vyuu-info-ink);
}
.users-status-pill[data-status="disabled"] {
  border-color: var(--vyuu-danger);
  background: var(--vyuu-danger-tint);
  color: var(--vyuu-danger-ink);
}
.users-status-pill[data-status="pending_reset"] {
  border-color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-mist);
  color: var(--vyuu-orange-deep);
}

.users-auth-tag {
  display: inline-block;
  padding: 1px 8px;
  border: 1px solid var(--vyuu-line);
  border-radius: 999px;
  background: var(--vyuu-panel);
  color: var(--vyuu-ink);
  font: 500 10.5px/1.5 var(--vyuu-sans);
  white-space: nowrap;
}

.users-count-cell {
  font: 600 13px/1 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.users-count-cell.is-zero { color: var(--vyuu-muted); font-weight: 500; }

/* Disabled row gets a subtle dim cue — matches the unsanctioned
   left-border treatment on Events for visual consistency. */
.users-table tbody tr[data-disabled="true"] {
  background: var(--vyuu-danger-tint);
  opacity: 0.78;
}
.users-table tbody tr[data-disabled="true"] td:first-child {
  box-shadow: inset 3px 0 0 var(--vyuu-danger);
}

.users-row-actions {
  display: flex;
  gap: 6px;
  justify-content: flex-end;
}
.users-row-actions button {
  padding: 4px 10px;
  border: 1px solid var(--vyuu-line);
  background: var(--vyuu-panel);
  border-radius: var(--vyuu-r-sm);
  color: var(--vyuu-ink);
  font: 500 11px/1 var(--vyuu-sans);
  cursor: pointer;
}
.users-row-actions button:hover { border-color: var(--vyuu-orange-soft); }
.users-row-actions button.is-danger { color: var(--vyuu-danger-ink); }

/* Slimmer modal panel for the +New user form — narrower than the
   full drill-in drawer because there's nothing to scan vertically. */
.users-modal-panel { max-width: 460px; }

/* --- Groups table -------------------------------------------------- */
/* Same posture as `.users-table` — operator-console panels share the
   same skeleton so muscle memory carries between them. */
.groups-table .groups-col-name    { min-width: 30ch; }
.groups-table .groups-col-members { width: 12ch; text-align: right; }
.groups-table .groups-col-grants  { width: 16ch; text-align: right; }
.groups-table .groups-col-created { width: 14ch; }
.groups-table .groups-col-actions { width: 12ch; text-align: right; }

.groups-table tbody td.groups-row-members,
.groups-table tbody td.groups-row-grants { text-align: right; }

.groups-row-name {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.groups-row-name-line {
  font: 500 12.5px/1.3 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.groups-row-description {
  font: 400 11px/1.4 var(--vyuu-sans);
  color: var(--vyuu-muted);
}

/* Unused-group cue — same warm-tint left-border as the high-risk
   identities row. `data-state="unused"` on the row when
   vserver_grant_count === 0. */
.groups-table tbody tr[data-state="unused"] {
  background: var(--vyuu-orange-mist);
}
.groups-table tbody tr[data-state="unused"] td:first-child {
  box-shadow: inset 3px 0 0 var(--vyuu-orange-deep);
}

/* Member chip styling for the drawer's Members tab — preserves the
   chip-editor experience the prior card layout had, just relocated
   inside the slide-over. */
.group-member-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 12px;
}
.group-member-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border: 1px solid var(--vyuu-line);
  border-radius: 999px;
  background: var(--vyuu-panel);
  font: 500 11.5px/1 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.group-member-chip-remove {
  border: none;
  background: transparent;
  color: var(--vyuu-muted);
  cursor: pointer;
  padding: 0;
  font: 600 14px/1 var(--vyuu-sans);
}
.group-member-chip-remove:hover { color: var(--vyuu-danger-ink); }

/* --- Access requests table ----------------------------------------- */
/* Column widths chosen to fit the inline Approve+Decline pair on the
   actions side without overflowing the panel. The note column is the
   flex column — the rest are fixed. */
/* JIT-1 · time-boxed access.
   The pill is amber rather than the ocean used for "approved": a live
   elevation is a *transient* state an operator may want to end, not a
   settled one. `--vyuu-warn` if the theme defines it, amber otherwise. */
.ar-jit-pill {
  display: inline-block;
  margin-right: 8px;
  padding: 1px 7px;
  border-radius: 999px;
  font-family: var(--vyuu-mono, ui-monospace, monospace);
  font-size: 10.5px;
  letter-spacing: 0.02em;
  white-space: nowrap;
  color: var(--vyuu-warn-ink, #7a4a00);
  background: var(--vyuu-warn-bg, rgba(214, 148, 34, 0.16));
  border: 1px solid var(--vyuu-warn-line, rgba(214, 148, 34, 0.4));
}
.jit-strip {
  margin: 14px 0 4px;
  padding: 12px 14px;
  border-radius: 10px;
  border: 1px solid var(--vyuu-warn-line, rgba(214, 148, 34, 0.4));
  background: var(--vyuu-warn-bg, rgba(214, 148, 34, 0.08));
}
.jit-strip.is-hidden { display: none; }
.jit-strip-head {
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin-bottom: 8px;
}
.jit-strip-title {
  font-family: var(--vyuu-mono, ui-monospace, monospace);
  font-size: 10.5px;
  letter-spacing: 0.08em;
  color: var(--vyuu-warn-ink, #7a4a00);
}
.jit-strip-sub { font-size: 11.5px; color: var(--vyuu-muted); }
.jit-strip-list { display: flex; flex-direction: column; gap: 6px; }
.jit-elevation-row {
  display: flex;
  align-items: baseline;
  gap: 10px;
  flex-wrap: wrap;
  font-size: 12.5px;
}
.jit-elevation-who { font-weight: 600; }
.jit-elevation-target { color: var(--vyuu-muted); }
.jit-elevation-why {
  color: var(--vyuu-muted);
  font-style: italic;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 40ch;
  white-space: nowrap;
}
/* Countdown in mono so the digits don't jitter as it ticks. */
.jit-elevation-left {
  margin-left: auto;
  font-family: var(--vyuu-mono, ui-monospace, monospace);
  font-size: 11.5px;
  color: var(--vyuu-warn-ink, #7a4a00);
}
.access-requests-table .ar-col-request   { width: 28ch; }
.access-requests-table .ar-col-note      { min-width: 20ch; }
.access-requests-table .ar-col-status    { width: 11ch; }
.access-requests-table .ar-col-submitted { width: 12ch; }
.access-requests-table .ar-col-actions   { width: 22ch; text-align: right; }

.ar-row-request {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.ar-row-request-line {
  font: 500 12.5px/1.3 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.ar-row-request-target {
  font: 400 11px/1.4 var(--vyuu-sans);
  color: var(--vyuu-muted);
}
.ar-row-note {
  font: 400 12px/1.5 var(--vyuu-sans);
  color: var(--vyuu-muted);
  font-style: italic;
  /* Single-line ellipsis — full text on hover via title attr. */
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 36ch;
}

/* Status pill — sourced from semantic tokens so dark-mode flips
   cleanly. pending=orange (action-required), approved=info (ocean),
   declined=danger, withdrawn=muted. The brand has no green — info
   is the cool counterpoint we read as "decided positively". */
.ar-status-pill {
  display: inline-block;
  padding: 1.5px 8px;
  border-radius: 999px;
  border: 1px solid var(--vyuu-line);
  font: 500 10px/1.5 var(--vyuu-sans);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  background: var(--vyuu-panel);
  color: var(--vyuu-ink);
}
.ar-status-pill[data-status="pending"] {
  border-color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-mist);
  color: var(--vyuu-orange-deep);
}
.ar-status-pill[data-status="approved"] {
  border-color: var(--vyuu-info);
  background: var(--vyuu-info-tint);
  color: var(--vyuu-info-ink);
}
.ar-status-pill[data-status="declined"] {
  border-color: var(--vyuu-danger);
  background: var(--vyuu-danger-tint);
  color: var(--vyuu-danger-ink);
}
.ar-status-pill[data-status="withdrawn"] {
  color: var(--vyuu-muted);
}

/* Pending rows get the same orange left-border cue as unsanctioned
   events — they're the action-required class. */
.access-requests-table tbody tr[data-status="pending"] td:first-child {
  box-shadow: inset 3px 0 0 var(--vyuu-orange-deep);
}
.access-requests-table tbody tr[data-status="pending"] {
  background: var(--vyuu-orange-mist);
}

/* --- Admins table -------------------------------------------------- */
.admins-table .admins-col-admin      { min-width: 28ch; }
.admins-table .admins-col-role       { width: 11ch; }
.admins-table .admins-col-last-login { width: 14ch; }
.admins-table .admins-col-created    { width: 14ch; }
.admins-table .admins-col-actions    { width: 26ch; text-align: right; }

/* Role tag — neutral by default; admin gets a stronger ink to set
   apart from editor/viewer which are read-mostly roles. */
.admins-role-tag {
  display: inline-block;
  padding: 1px 8px;
  border: 1px solid var(--vyuu-line);
  border-radius: 999px;
  background: var(--vyuu-panel);
  color: var(--vyuu-ink);
  font: 500 10.5px/1.5 var(--vyuu-sans);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  white-space: nowrap;
}
.admins-role-tag[data-role="admin"] {
  border-color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-mist);
  color: var(--vyuu-orange-deep);
}

/* Disabled-row cue mirrors the Users tab. */
.admins-table tbody tr[data-disabled="true"] {
  background: var(--vyuu-danger-tint);
  opacity: 0.78;
}
.admins-table tbody tr[data-disabled="true"] td:first-child {
  box-shadow: inset 3px 0 0 var(--vyuu-danger);
}

/* --- Login-page IdP buttons --------------------------------------- */
/* "Continue with X" buttons on the operator + portal sign-in forms.
   Render only when the tenant has a connected IdP directory. Workspace
   button uses ocean (cool informational), Entra uses warm orange — same
   color story we already use in the Identity providers panel. */
.idp-button-row {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-bottom: 20px;
}
.idp-button-row[hidden] { display: none; }
/* The divider only earns its place when there are SSO buttons above
   the form to divide from. `[hidden]` rows must not leave an orphan
   "or" floating over the tenant field. */
.idp-button-row:not([hidden]) + form,
.idp-button-row:not([hidden]) + .form-grid {
  border-top: 1px solid var(--vyuu-line);
  padding-top: 18px;
  position: relative;
}
.idp-button-row:not([hidden]) + form::before,
.idp-button-row:not([hidden]) + .form-grid::before {
  content: "or";
  position: absolute;
  top: -8px;
  left: 50%;
  transform: translateX(-50%);
  background: var(--vyuu-panel);
  padding: 0 10px;
  font: 500 10.5px/1.4 var(--vyuu-sans);
  color: var(--vyuu-muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.idp-signin-button {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  width: 100%;
  padding: 10px 16px;
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  background: var(--vyuu-panel);
  color: var(--vyuu-ink);
  font: 500 13px/1.3 var(--vyuu-sans);
  cursor: pointer;
  transition: border-color 120ms ease;
}
.idp-signin-button:hover { border-color: var(--vyuu-orange-soft); }
.idp-signin-button[data-kind="entra"] {
  border-color: var(--vyuu-orange-deep);
  color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-mist);
}
.idp-signin-button[data-kind="google_workspace"] {
  border-color: var(--vyuu-info);
  color: var(--vyuu-info-ink);
  background: var(--vyuu-info-tint);
}
.idp-signin-button-icon {
  display: inline-flex;
  width: 18px;
  height: 18px;
  align-items: center;
  justify-content: center;
}
.idp-signin-button-protocol {
  margin-left: auto;
  font: 500 10px/1.4 var(--vyuu-sans);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  opacity: 0.7;
}

/* --- Identity providers table ------------------------------------- */
.idp-table .idp-col-directory  { min-width: 28ch; }
.idp-table .idp-col-protocol   { width: 12ch; }
.idp-table .idp-col-last-sync  { width: 14ch; }
.idp-table .idp-col-created    { width: 14ch; }
.idp-table .idp-col-actions    { width: 18ch; text-align: right; }

.idp-row-directory {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.idp-row-directory-line {
  display: flex;
  align-items: center;
  gap: 8px;
  font: 500 12.5px/1.3 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.idp-row-directory-id {
  font: 400 10.5px/1.3 var(--vyuu-sans);
  color: var(--vyuu-muted);
}

/* Kind tag — Entra warm orange (Microsoft brand-adjacent), Workspace
   ocean (Google brand-adjacent without the actual Google logo). */
.idp-kind-tag {
  display: inline-block;
  padding: 1px 8px;
  border: 1px solid var(--vyuu-line);
  border-radius: 999px;
  background: var(--vyuu-panel);
  font: 500 10.5px/1.5 var(--vyuu-sans);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.idp-kind-tag[data-kind="entra"] {
  border-color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-mist);
  color: var(--vyuu-orange-deep);
}
.idp-kind-tag[data-kind="google_workspace"] {
  border-color: var(--vyuu-info);
  background: var(--vyuu-info-tint);
  color: var(--vyuu-info-ink);
}

.idp-ema-cell { display: flex; align-items: center; gap: 8px; }
.idp-ema-badge {
  font-size: 10.5px; padding: 2px 7px; border-radius: 999px;
  border: 1px solid currentColor; letter-spacing: .04em;
}
.idp-ema-badge[data-on="true"]  { color: var(--vyuu-orange-deep); }
.idp-ema-badge[data-on="false"] { color: var(--vyuu-muted); }
.idp-ema-clients { font-size: 10.5px; color: var(--vyuu-muted); }
.idp-ema-toggle {
  font-size: 10.5px; padding: 2px 9px; border-radius: 999px;
  border: 1px solid var(--vyuu-line); background: transparent;
  color: var(--vyuu-ink); cursor: pointer;
}
.idp-ema-toggle:hover:not(:disabled) { border-color: var(--vyuu-orange); }
.idp-ema-toggle:disabled { opacity: .5; cursor: default; }
.idp-protocol-tag {
  display: inline-block;
  padding: 1px 8px;
  border: 1px solid var(--vyuu-line);
  border-radius: 999px;
  background: var(--vyuu-panel);
  color: var(--vyuu-ink);
  font: 500 10.5px/1.5 var(--vyuu-sans);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

/* Endpoint URLs in the drawer — copy-able, mono. */
.idp-endpoint-row {
  display: flex;
  align-items: center;
  gap: 6px;
  margin: 6px 0;
}
.idp-endpoint-row code {
  flex: 1;
  font: 500 11px/1.4 var(--vyuu-mono);
  color: var(--vyuu-ink);
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  padding: 6px 8px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* Token-reveal box — shown ONCE after connect. Distinct from the
   regular endpoint URLs because losing it means re-issuing. */
.idp-token-reveal {
  border: 1px solid var(--vyuu-orange-deep);
  background: var(--vyuu-orange-mist);
  border-radius: var(--vyuu-r-sm);
  padding: 12px;
  margin: 16px 0;
}
.idp-token-reveal-title {
  font: 600 11px/1.3 var(--vyuu-sans);
  color: var(--vyuu-orange-deep);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin: 0 0 6px;
}
.idp-token-reveal-body {
  font: 500 12px/1.4 var(--vyuu-mono);
  color: var(--vyuu-ink);
  word-break: break-all;
  user-select: all;
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  padding: 8px;
}

/* --- Admin audit table -------------------------------------------- */
.admin-audit-table .aa-col-when    { width: 14ch; }
.admin-audit-table .aa-col-actor   { width: 22ch; }
.admin-audit-table .aa-col-action  { width: 22ch; }
.admin-audit-table .aa-col-target  { width: 24ch; }
.admin-audit-table .aa-col-detail  { min-width: 24ch; }

.aa-actor {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.aa-actor-line {
  font: 500 12.5px/1.3 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.aa-actor-kind {
  font: 500 10px/1.5 var(--vyuu-sans);
  color: var(--vyuu-muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
/* SCIM rows + system rows get a left-border accent so they stand out
   from operator rows in a long log. SCIM = orange (IdP-driven),
   system = ocean (cron-driven). */
.admin-audit-table tbody tr[data-actor="scim"] td:first-child {
  box-shadow: inset 3px 0 0 var(--vyuu-orange-deep);
}
.admin-audit-table tbody tr[data-actor="system"] td:first-child {
  box-shadow: inset 3px 0 0 var(--vyuu-info);
}

.aa-action-tag {
  display: inline-block;
  padding: 2px 8px;
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  background: var(--vyuu-panel);
  color: var(--vyuu-ink);
  font: 500 11px/1.4 var(--vyuu-mono);
}

.aa-detail-snippet {
  font: 400 11px/1.4 var(--vyuu-mono);
  color: var(--vyuu-muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 36ch;
}

.aa-detail-pre {
  font: 500 11.5px/1.45 var(--vyuu-mono);
  color: var(--vyuu-ink);
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  padding: 10px 12px;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 360px;
  overflow: auto;
}

/* --- Virtual servers table ---------------------------------------- */
.vservers-table .vservers-col-name    { min-width: 22ch; }
.vservers-table .vservers-col-url     { min-width: 24ch; }
.vservers-table .vservers-col-tools   { width: 9ch;  text-align: right; }
.vservers-table .vservers-col-grants  { width: 9ch;  text-align: right; }
/* Security posture. `warn` is deliberately reserved for a state with a
   real, statable cost — not merely a non-default — so that a panel full
   of amber means something. */
.posture-table .posture-col-state       { width: 9ch; }
.posture-table .posture-col-control     { width: 30ch; }
.posture-table .posture-col-consequence { min-width: 40ch; }
.posture-table .posture-col-env         { width: 26ch; }
.posture-pill {
  display: inline-block;
  padding: 1px 8px;
  border-radius: 999px;
  font-family: var(--vyuu-mono, ui-monospace, monospace);
  font-size: 10.5px;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.posture-pill[data-severity="good"] {
  color: var(--vyuu-ok-ink, #1d5b33);
  background: var(--vyuu-ok-bg, rgba(38, 138, 76, 0.14));
  border: 1px solid var(--vyuu-ok-line, rgba(38, 138, 76, 0.35));
}
.posture-pill[data-severity="warn"] {
  color: var(--vyuu-warn-ink, #7a4a00);
  background: var(--vyuu-warn-bg, rgba(214, 148, 34, 0.16));
  border: 1px solid var(--vyuu-warn-line, rgba(214, 148, 34, 0.4));
}
.posture-pill[data-severity="info"] {
  color: var(--vyuu-muted);
  background: transparent;
  border: 1px solid var(--vyuu-line, rgba(0, 0, 0, 0.12));
}
.posture-control { font-weight: 600; }
.posture-detail {
  display: block;
  font-family: var(--vyuu-mono, ui-monospace, monospace);
  font-size: 11px;
  color: var(--vyuu-muted);
}
.posture-consequence { font-size: 12.5px; line-height: 1.45; }
.posture-env {
  font-family: var(--vyuu-mono, ui-monospace, monospace);
  font-size: 10.5px;
  color: var(--vyuu-muted);
  word-break: break-all;
}
/* JIT-1 · the column reads as a state, not a control, until hovered —
   an operator scanning the table wants "who offers JIT", not a row of
   buttons competing with the drill-in affordance. */

.vserver-jit-state {
  font-family: var(--vyuu-mono, ui-monospace, monospace);
  font-size: 10.5px;
  letter-spacing: 0.02em;
  padding: 1px 7px;
  border-radius: 999px;
  white-space: nowrap;
}
.vserver-jit-state[data-on="true"] {
  color: var(--vyuu-warn-ink, #7a4a00);
  background: var(--vyuu-warn-bg, rgba(214, 148, 34, 0.16));
  border: 1px solid var(--vyuu-warn-line, rgba(214, 148, 34, 0.4));
}
.vserver-jit-state[data-on="false"] {
  color: var(--vyuu-muted);
  background: transparent;
  border: 1px solid var(--vyuu-line, rgba(0, 0, 0, 0.12));
}
.vserver-jit-state[data-na="true"] { opacity: 0.45; }
/* Capability cards in the server drill-in. Description gets the room,
   because it is what the calling model actually reads — and what a
   hostile upstream would put instructions in. */
.cap-card {
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  padding: 10px 12px;
  margin-bottom: 6px;
}
.cap-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 10px;
}
.cap-name {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-ink);
  word-break: break-all;
}
.cap-kind {
  font: 500 9.5px/1.5 var(--vyuu-sans);
  letter-spacing: 0.6px;
  text-transform: uppercase;
  color: var(--vyuu-muted);
  border: 1px solid var(--vyuu-line);
  border-radius: 3px;
  padding: 1px 5px;
  flex: 0 0 auto;
}
.cap-desc {
  font: 400 12px/1.55 var(--vyuu-sans);
  color: var(--vyuu-muted);
  margin: 6px 0 0;
  white-space: pre-wrap;
}
.cap-desc[data-empty="true"] { font-style: italic; opacity: .7; }
.cap-schema {
  margin-top: 8px;
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-muted);
  background: var(--vyuu-line-soft);
  border-radius: 4px;
  padding: 8px 10px;
  max-height: 220px;
  overflow: auto;
  white-space: pre;
}
.cap-toolbar {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 10px;
  flex-wrap: wrap;
}
.cap-toolbar input { flex: 1; min-width: 160px; }
/* Dashboard bars. Length carries the comparison; the number is there
   for anyone who needs the exact value. Deliberately not a pie or a
   donut — these are ranked magnitudes, and a reader has to be able to
   tell 14 from 9 at a glance. */
.risk-bar-row {
  display: grid;
  grid-template-columns: minmax(150px, 1fr) 3fr auto;
  align-items: center;
  gap: 10px;
  padding: 5px 0;
}
.risk-bar-label {
  font: 400 12px/1.4 var(--vyuu-sans);
  color: var(--vyuu-ink);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.risk-bar-track {
  height: 8px;
  border-radius: 999px;
  background: var(--vyuu-line-soft);
  overflow: hidden;
}
.risk-bar-fill { height: 100%; border-radius: 999px; }
.risk-bar-fill[data-band="critical"] { background:#b8544f; }
.risk-bar-fill[data-band="high"]     { background:#c07a3e; }
.risk-bar-fill[data-band="moderate"] { background:#c9a53e; }
.risk-bar-fill[data-band="low"]      { background:#7ea35c; }
.risk-bar-fill[data-band="neutral"]  { background: var(--vyuu-orange-deep); }
.risk-bar-value {
  font: 600 11px/1 var(--vyuu-mono);
  color: var(--vyuu-muted);
  min-width: 52px;
  text-align: right;
}
/* Coverage: how much of the estate the numbers above actually describe.
   Full width and directly under the KPIs because every average on the
   page is scoped by it. */
.risk-coverage {
  margin: 0 0 18px;
  padding: 10px 14px;
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  background: var(--vyuu-line-soft);
}
/* Risk bands. One colour vocabulary everywhere a score appears, so a
   reader learns it once. */
.risk-band {
  display: inline-flex; align-items: baseline; gap: 5px;
  padding: 2px 8px; border-radius: 999px;
  font: 600 10.5px/1.5 var(--vyuu-sans);
  letter-spacing: 0.5px; text-transform: uppercase; white-space: nowrap;
}
.risk-band[data-band="critical"] { color:#8a2f2f; background:#f7e2e2; }
.risk-band[data-band="high"]     { color:#9a4b1e; background:#fbe8dc; }
.risk-band[data-band="moderate"] { color:#8a6a17; background:#faf0d8; }
.risk-band[data-band="low"]      { color:#4a6b34; background:#e8f2e0; }
.risk-band[data-band="none"],
.risk-band[data-band="unknown"]  { color:var(--vyuu-muted); background:var(--vyuu-line-soft); }
.risk-band-score { font: 600 10.5px/1.5 var(--vyuu-mono); opacity: .75; }
.risk-arrow { color: var(--vyuu-muted); margin: 0 6px; }
.risk-note {
  font: 400 11.5px/1.5 var(--vyuu-sans); color: var(--vyuu-muted);
  border-left: 2px solid var(--vyuu-line); padding-left: 10px; margin: 10px 0 0;
}
.risk-finding {
  border: 1px solid var(--vyuu-line); border-radius: var(--vyuu-r-sm);
  padding: 10px 12px; margin-bottom: 6px;
}
.akp-form {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  width: 100%;
}
.akp-form input[type="number"] { width: 90px; }
.akp-form input[type="text"]   { flex: 1; min-width: 160px; }
.vservers-table .vservers-col-jit     { width: 13ch; }
.vservers-table .vservers-col-created { width: 14ch; }
/* Read-only state badge. The controls live in the drill-in; this exists
   so "which bundles allow temporary access?" is answerable by scanning
   the column instead of opening every row. */
.vserver-jit-badge {
  display: inline-flex;
  align-items: baseline;
  gap: 5px;
  font: var(--vyuu-mono-sm);
  white-space: nowrap;
}
.vserver-jit-badge[data-on="true"]  { color: var(--vyuu-orange-deep); }
.vserver-jit-badge[data-on="false"] { color: var(--vyuu-muted); }
.vserver-jit-badge[data-na="true"]  { color: var(--vyuu-subtle); }
.vserver-jit-gated {
  font: 500 10px/1 var(--vyuu-sans);
  letter-spacing: 0.4px;
  text-transform: uppercase;
  color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-mist);
  border-radius: 3px;
  padding: 2px 5px;
}
.vservers-table .vservers-col-actions { width: 12ch; text-align: right; }

.vservers-table tbody td.vservers-row-tools,
.vservers-table tbody td.vservers-row-grants { text-align: right; }

.vservers-row-name {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.vservers-row-name-line {
  display: flex;
  align-items: center;
  gap: 8px;
  font: 500 12.5px/1.3 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.vservers-row-id {
  font: 400 10.5px/1.3 var(--vyuu-sans);
  color: var(--vyuu-muted);
}

/* Visibility pill — public uses ocean (informational/wide reach),
   private uses orange-deep (action-gated). */
.vservers-visibility-pill {
  display: inline-block;
  padding: 1.5px 8px;
  border-radius: 999px;
  border: 1px solid var(--vyuu-line);
  font: 500 10px/1.5 var(--vyuu-sans);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  background: var(--vyuu-panel);
  color: var(--vyuu-ink);
}
.vservers-visibility-pill[data-visibility="public"] {
  border-color: var(--vyuu-info);
  background: var(--vyuu-info-tint);
  color: var(--vyuu-info-ink);
}
.vservers-visibility-pill[data-visibility="private"] {
  border-color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-mist);
  color: var(--vyuu-orange-deep);
}

/* The /v/.../mcp URL — long; render small mono with copy affordance. */
.vservers-row-url {
  display: flex;
  align-items: center;
  gap: 6px;
  max-width: 36ch;
}
.vservers-row-url code {
  flex: 1;
  font: 500 10.5px/1.4 var(--vyuu-mono);
  color: var(--vyuu-muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.vservers-row-url-copy {
  padding: 2px 8px;
  border: 1px solid var(--vyuu-line);
  background: var(--vyuu-panel);
  border-radius: var(--vyuu-r-sm);
  color: var(--vyuu-ink);
  font: 500 10.5px/1 var(--vyuu-sans);
  cursor: pointer;
  flex-shrink: 0;
}
.vservers-row-url-copy:hover { border-color: var(--vyuu-orange-soft); }
.vservers-row-url-copy[data-copied="true"] {
  color: var(--vyuu-info-ink);
  border-color: var(--vyuu-info);
}

/* Empty-vserver cue — same warm-tint left-border as unsanctioned events.
   `data-state="empty"` when tool_count === 0 (declared but useless). */
.vservers-table tbody tr[data-state="empty"] {
  background: var(--vyuu-orange-mist);
}
.vservers-table tbody tr[data-state="empty"] td:first-child {
  box-shadow: inset 3px 0 0 var(--vyuu-orange-deep);
}

/* Slide-over drawer */
.identity-drawer[hidden] { display: none; }
.identity-drawer {
  position: fixed;
  inset: 0;
  z-index: 50;
  display: flex;
  justify-content: flex-end;
}
.identity-drawer-backdrop {
  position: absolute;
  inset: 0;
  background: rgba(31, 42, 46, 0.32);
  cursor: pointer;
}
.identity-drawer-panel {
  position: relative;
  width: min(720px, 92vw);
  height: 100%;
  background: var(--vyuu-panel, #fff);
  box-shadow: -8px 0 24px rgba(0, 0, 0, 0.10);
  display: flex;
  flex-direction: column;
  animation: identity-drawer-slide 0.18s ease-out;
}
@keyframes identity-drawer-slide {
  from { transform: translateX(40px); opacity: 0; }
  to   { transform: translateX(0); opacity: 1; }
}
.identity-drawer-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 24px 28px 16px;
  border-bottom: 1px solid var(--vyuu-line);
}
.identity-drawer-head h2 {
  margin: 4px 0 4px;
  font: 600 22px/1.2 var(--vyuu-serif, var(--vyuu-sans));
  color: var(--vyuu-ink);
}
.identity-drawer-sub {
  margin: 0;
  font: 400 12px/1.5 var(--vyuu-sans);
  color: var(--vyuu-muted);
}
.identity-drawer-tabs {
  display: flex;
  gap: 4px;
  padding: 12px 28px 0;
  border-bottom: 1px solid var(--vyuu-line);
}
.identity-drawer-tab {
  padding: 8px 16px;
  border: 0;
  border-bottom: 2px solid transparent;
  background: transparent;
  font: 500 12.5px/1 var(--vyuu-sans);
  color: var(--vyuu-muted);
  cursor: pointer;
  margin-bottom: -1px;
}
.identity-drawer-tab:hover { color: var(--vyuu-ink); }
.identity-drawer-tab.is-active {
  color: var(--vyuu-ink);
  border-bottom-color: var(--vyuu-orange-deep, var(--vyuu-orange));
}
.identity-drawer-body {
  flex: 1;
  overflow: auto;
  padding: 18px 28px 28px;
}

/* MCP servers table — the proper enterprise-grade view. Rows are
   scannable, filterable, and act in-place via per-row buttons.
   Replaces the stacked-cards-list which was unusable past 5 servers.
   Layout mirrors the design handoff: one row per server, columns
   for Server (name + id + transport with health dot) / Runtime /
   Auth mode / Tools / Risk / Health / actions. */
.server-toolbar {
  display: flex;
  gap: 12px;
  align-items: center;
  margin: 14px 0 12px;
  flex-wrap: wrap;
}
.server-toolbar input[type="search"] {
  flex: 1 1 260px;
  min-width: 200px;
}
.server-filters {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}
.filter-pill {
  padding: 6px 12px;
  border-radius: var(--vyuu-r-pill);
  border: 1px solid var(--vyuu-line);
  background: var(--vyuu-panel);
  color: var(--vyuu-muted);
  font: 500 11.5px/1.2 var(--vyuu-sans);
  cursor: pointer;
  transition: background 0.12s, color 0.12s, border-color 0.12s;
}
.filter-pill:hover {
  border-color: var(--vyuu-orange-soft);
  color: var(--vyuu-ink);
}
.filter-pill.is-active {
  background: var(--vyuu-orange-soft);
  color: var(--vyuu-orange-deep);
  border-color: var(--vyuu-orange-deep);
}
.toolbar-meta {
  margin-left: auto;
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-muted);
}

.servers-table-wrap {
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  background: var(--vyuu-panel);
  overflow: hidden;
}
.servers-table {
  width: 100%;
  border-collapse: collapse;
  font: var(--vyuu-body);
}
.servers-table thead th {
  background: var(--vyuu-ivory);
  padding: 12px 16px;
  text-align: left;
  font: var(--vyuu-th);
  letter-spacing: var(--vyuu-th-tracking);
  text-transform: uppercase;
  color: var(--vyuu-muted);
  border-bottom: 1px solid var(--vyuu-line);
  white-space: nowrap;
}
.servers-table tbody td {
  padding: 14px 16px;
  border-bottom: 1px solid var(--vyuu-line-soft);
  vertical-align: middle;
  font: var(--vyuu-body);
}
.servers-table tbody tr:last-child td { border-bottom: none; }
.servers-table tbody tr {
  cursor: default;
  transition: background 0.1s;
}
.servers-table tbody tr:hover { background: var(--vyuu-ivory); }
.servers-cell-name {
  display: flex;
  align-items: center;
  gap: 10px;
}
.servers-cell-name strong {
  font: 500 13.5px/1.3 var(--vyuu-sans);
  color: var(--vyuu-ink);
  display: block;
}
.servers-cell-name .meta-line {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-muted);
  margin-top: 2px;
}
.health-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--vyuu-subtle);
  flex-shrink: 0;
}
.health-dot.healthy   { background: var(--vyuu-orange-deep); }
.health-dot.degraded  { background: var(--vyuu-warn); }
.health-dot.down      { background: var(--vyuu-danger); }
.health-dot.unknown   { background: var(--vyuu-subtle); }
.servers-table .row-actions {
  display: flex;
  gap: 6px;
  justify-content: flex-end;
  align-items: center;
  white-space: nowrap;
  flex-wrap: wrap;
}
.servers-table .row-actions button {
  padding: 5px 10px;
  font: 500 11.5px/1.2 var(--vyuu-sans);
  min-height: 28px;
}
/* Inline sync-result toast — appears next to the row's action
   buttons after a sync attempt, fades after a few seconds. */
.row-toast {
  font: var(--vyuu-mono-sm);
  padding: 4px 10px;
  border-radius: 999px;
  white-space: nowrap;
  animation: row-toast-fade 0.2s ease-out;
}
.row-toast-ok {
  background: var(--vyuu-orange-soft);
  color: var(--vyuu-orange-deep);
  border: 1px solid var(--vyuu-orange-deep);
}
@keyframes row-toast-fade {
  from { opacity: 0; transform: translateY(-2px); }
  to { opacity: 1; transform: translateY(0); }
}
/* Sticky banner above the servers table — used after delete (the
   destructive flow can't anchor to the now-removed row). */
.servers-banner {
  margin: 0 0 12px;
  padding: 10px 14px;
  font: var(--vyuu-mono-sm);
  background: var(--vyuu-orange-soft);
  color: var(--vyuu-orange-deep);
  border: 1px solid var(--vyuu-orange-deep);
  border-radius: var(--vyuu-r-sm);
  animation: row-toast-fade 0.2s ease-out;
}

/* Per-row sync-cadence dropdown. Visually distinct from the action
   buttons so operators don't reach for it unintentionally — quieter
   border, mono numerals. The label embeds the prefix "Cadence: " so
   the closed state still reads as "Cadence: Default". */
.cadence-select {
  appearance: none;
  padding: 5px 22px 5px 10px;
  font: 500 11.5px/1.2 var(--vyuu-sans);
  background: var(--vyuu-bg);
  color: var(--vyuu-ink-muted);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  min-height: 28px;
  background-image:
    linear-gradient(45deg, transparent 50%, var(--vyuu-ink-muted) 50%),
    linear-gradient(135deg, var(--vyuu-ink-muted) 50%, transparent 50%);
  background-position:
    calc(100% - 12px) 12px,
    calc(100% - 7px) 12px;
  background-size: 5px 5px, 5px 5px;
  background-repeat: no-repeat;
}
.cadence-select:focus {
  outline: none;
  border-color: var(--vyuu-orange-deep);
  color: var(--vyuu-ink);
}

/* Drift pill — appears in the Server cell when the most recent sync
   captured changes. Click → opens the row drawer scoped to the diff. */
.drift-pill {
  appearance: none;
  display: inline-flex;
  align-items: center;
  margin-top: 4px;
  padding: 2px 8px;
  font: var(--vyuu-mono-sm);
  border: 1px solid transparent;
  border-radius: 999px;
  cursor: pointer;
}
.drift-pill-neutral {
  background: var(--vyuu-line-soft);
  color: var(--vyuu-ink-muted);
  border-color: var(--vyuu-line);
}
.drift-pill-warn {
  background: color-mix(in srgb, var(--vyuu-warn) 14%, transparent);
  color: var(--vyuu-warn);
  border-color: color-mix(in srgb, var(--vyuu-warn) 35%, transparent);
}
.drift-pill-danger {
  background: color-mix(in srgb, var(--vyuu-danger) 12%, transparent);
  color: var(--vyuu-danger);
  border-color: color-mix(in srgb, var(--vyuu-danger) 35%, transparent);
}
.drift-pill:hover { filter: brightness(0.95); }

/* Drift drawer body. Three sections (added/changed/removed); each
   row pairs the tool name with its risk pill. */
.drift-list {
  list-style: none;
  margin: 0 0 6px;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.drift-list li {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 8px;
  border-radius: var(--vyuu-r-sm);
  background: var(--vyuu-bg);
  border: 1px solid var(--vyuu-line);
}
.drift-list-added li {
  border-color: color-mix(in srgb, var(--vyuu-orange-deep) 40%, transparent);
}
.drift-list-changed li {
  border-color: color-mix(in srgb, var(--vyuu-warn) 40%, transparent);
}
.drift-list-removed li {
  border-color: color-mix(in srgb, var(--vyuu-ink-muted) 30%, transparent);
  text-decoration: line-through;
  color: var(--vyuu-ink-muted);
}
.drift-list-name { flex: 1; font: var(--vyuu-mono-sm); color: var(--vyuu-ink); }
.drift-list-removed .drift-list-name { color: var(--vyuu-ink-muted); }
.btn-primary {
  background: var(--vyuu-orange-deep);
  color: var(--vyuu-on-primary);
  border-color: var(--vyuu-orange-deep);
  box-shadow: var(--vyuu-shadow-md);
}
.btn-primary:hover { filter: brightness(0.96); }

/* Row drawer — Publish vserver / Configure / etc opens here as a
   single shared drawer that anchors below the row. Only one open
   at a time. */
.row-drawer {
  margin-top: 10px;
  padding: 16px 20px;
  background: var(--vyuu-ivory);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-lg);
}

/* Gateway status pill in the sidebar foot. Replaces the giant
   "Gateway health" card that ate half the MCP-servers panel. */
.gateway-status-pill {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 10px;
  margin-bottom: 8px;
  border-radius: var(--vyuu-r-md);
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-muted);
}
.gateway-status-pill .status-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--vyuu-subtle);
  flex-shrink: 0;
}
.gateway-status-pill.is-ok .status-dot   { background: var(--vyuu-orange-deep); }
.gateway-status-pill.is-warn .status-dot { background: var(--vyuu-warn); }
.gateway-status-pill.is-down .status-dot { background: var(--vyuu-danger); }
.gateway-status-pill .status-text {
  flex: 1;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* Inline "Publish vserver" drawer on the MCP server card. Drops into
   the same card so operators don't have to switch panels — that was
   the friction point: previously you'd Sync → switch to the Vservers
   panel below → manually type tool ids. Now: pick checkboxes here,
   one click creates the vserver. */
.publish-drawer {
  margin-top: 12px;
  padding: 14px 16px;
  background: var(--vyuu-ivory);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-lg);
}
.publish-drawer h4 {
  font: var(--vyuu-h3);
  color: var(--vyuu-ink);
  letter-spacing: -0.2px;
  margin: 0 0 4px;
}
.publish-tool-list {
  margin-top: 6px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  max-height: 280px;
  overflow-y: auto;
  padding: 4px 0;
}
.publish-tool-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 0.85fr);
  align-items: center;
  gap: 10px;
  padding: 6px 10px;
  border-radius: var(--vyuu-r-sm);
}
.publish-tool-row:hover { background: var(--vyuu-line-soft); }
.publish-tool-row strong {
  font: var(--vyuu-mono-md);
  color: var(--vyuu-ink);
}
.publish-tool-row-left {
  display: flex;
  align-items: center;
  gap: 10px;
  cursor: pointer;
  min-width: 0;
}
.publish-tool-row-left > span {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.publish-tool-row-rename {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}
.publish-tool-row-rename-label {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-ink-muted);
  white-space: nowrap;
}
.publish-tool-row-rename input {
  flex: 1;
  min-width: 0;
  padding: 4px 8px;
  font: var(--vyuu-mono-sm);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  background: var(--vyuu-bg);
  color: var(--vyuu-ink);
}
.publish-tool-row-rename input:focus {
  outline: none;
  border-color: var(--vyuu-orange-deep);
  box-shadow: 0 0 0 2px var(--vyuu-saffron-soft);
}
@media (max-width: 580px) {
  .publish-tool-row {
    grid-template-columns: 1fr;
    gap: 4px;
  }
}
.publish-drawer .btn-primary {
  background: var(--vyuu-orange-deep);
  color: var(--vyuu-on-primary);
  border-color: var(--vyuu-orange-deep);
  box-shadow: var(--vyuu-shadow-md);
}

/* Auth section — clean structured layout. Replaces the dense JSON-blob
   inputs with a 6-card mode picker and per-mode structured fields.
   The mode picker uses radio inputs so we get keyboard navigation +
   form-state for free; visual styling is on the wrapper label. */
.auth-section {
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  background: var(--vyuu-ivory);
  padding: 18px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.auth-section-head h3 {
  font: var(--vyuu-h3);
  color: var(--vyuu-ink);
  margin: 0 0 4px;
  letter-spacing: -0.2px;
}
.auth-section-head p { margin: 0; }
.auth-mode-picker {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 8px;
}
.auth-mode-card {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 12px 14px;
  border: 1.5px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-md);
  background: var(--vyuu-panel);
  cursor: pointer;
  transition: border-color 0.12s, background 0.12s;
}
.auth-mode-card:hover { border-color: var(--vyuu-orange-soft); }
.auth-mode-card input[type="radio"] {
  position: absolute;
  opacity: 0;
  pointer-events: none;
}
.auth-mode-card:has(input:checked) {
  border-color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-mist);
}
.auth-mode-title {
  font: 600 13px/1.3 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.auth-mode-card:has(input:checked) .auth-mode-title {
  color: var(--vyuu-orange-deep);
}
.auth-mode-hint {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-muted);
}

/* Per-mode field groups — only the matching one shows. The
   `body[data-auth-mode="X"]` selector gates visibility; we don't
   reuse `.is-hidden` because that's reserved for the top-level nav
   sections and the `!important` would conflict. */
.auth-fields { display: none; }
body[data-auth-mode="headers"]    .auth-fields[data-mode-fields="headers"],
body[data-auth-mode="passthrough"].auth-fields[data-mode-fields="passthrough"],
body[data-auth-mode="oauth"]      .auth-fields[data-mode-fields="oauth"],
body[data-auth-mode="authcode"]   .auth-fields[data-mode-fields="authcode"],
body[data-auth-mode="jwt_bearer"] .auth-fields[data-mode-fields="jwt_bearer"] {
  display: block;
}
/* `env` is auto-toggled when source_type is stdio (separate from
   the application-layer mode picker). The serializer handles this. */
body[data-source-type="stdio"]  .auth-fields[data-mode-fields="env"],
body[data-source-type="npm"]    .auth-fields[data-mode-fields="env"],
body[data-source-type="pypi"]   .auth-fields[data-mode-fields="env"],
body[data-source-type="binary"] .auth-fields[data-mode-fields="env"] {
  display: block;
}

.auth-fields-head {
  display: flex;
  align-items: baseline;
  gap: 8px;
  margin-bottom: 10px;
  flex-wrap: wrap;
}
.auth-fields-head strong {
  font: 600 13.5px/1.3 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.auth-fields-head .hint {
  flex: 1 1 auto;
  font: var(--vyuu-body);
  color: var(--vyuu-muted);
  min-width: 200px;
}
.auth-fields-head code {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-mist);
  padding: 1px 4px;
  border-radius: 4px;
}
.auth-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 10px 14px;
}
/* DCR mode visibility flip — driven by body[data-authcode-mode] which
   the catalog click sets to "dcr" for spec-compliant vendors and
   "static" otherwise. The DCR banner shows only in DCR mode; the
   static-auth fields (auth_url / token_url / client_id_ref /
   client_secret_ref) hide because the gateway auto-discovers them. */
.auth-dcr-toggle {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  margin: 0 0 10px;
  padding: 10px 12px;
  background: var(--vyuu-panel-soft, var(--vyuu-panel));
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-sm);
  cursor: pointer;
}
.auth-dcr-toggle:hover { border-color: var(--vyuu-orange-soft); }
.auth-dcr-toggle input[type="checkbox"] {
  margin-top: 3px;
  flex-shrink: 0;
}
.auth-dcr-toggle > span {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 12px;
}
.auth-dcr-toggle strong {
  color: var(--vyuu-ink);
  font-weight: 600;
}
.auth-dcr-toggle .hint {
  color: var(--vyuu-muted);
  font-weight: 400;
  line-height: 1.4;
}
.auth-dcr-banner {
  margin-bottom: 10px;
  padding: 10px 12px;
  background: var(--vyuu-orange-soft, rgba(220, 122, 0, 0.07));
  border: 1px solid var(--vyuu-orange-soft, rgba(220, 122, 0, 0.18));
  border-radius: var(--vyuu-r-sm);
  font-size: 12px;
  color: var(--vyuu-ink);
}
.auth-dcr-banner code {
  font-family: var(--vyuu-mono);
  font-size: 11px;
}
body:not([data-authcode-mode="dcr"]) [data-authcode-dcr-only] {
  display: none;
}
body[data-authcode-mode="dcr"] [data-authcode-static-only] {
  display: none;
}
.auth-grid label {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font: var(--vyuu-label);
  color: var(--vyuu-ink);
}
.auth-grid label .hint {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-muted);
  font-weight: 400;
}
.auth-grid label code {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-orange-deep);
}
.auth-grid label input,
.auth-grid label select {
  font: var(--vyuu-mono-sm);
}
.auth-grid-wide { grid-column: 1 / -1; }
.req {
  color: var(--vyuu-danger-ink);
  font-weight: 600;
  margin-left: 2px;
}
/* U8 — soft-warning when an operator pastes a literal OAuth
   credential into a `_ref` input. Inline beneath the field, not
   blocking — they can still submit if they really mean it (lab dev
   mode), but they see the warning before the gateway silently
   resolves to `placeholder-<value>` and OAuth fails at the IdP. */
.secret-ref-warn {
  display: block;
  margin-top: 6px;
  padding: 6px 8px;
  background: var(--vyuu-orange-soft, rgba(220, 122, 0, 0.08));
  border-left: 3px solid var(--vyuu-orange-deep, var(--vyuu-orange));
  border-radius: 3px;
  font: 400 11px/1.4 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.mtls-fields {
  border-top: 1px solid var(--vyuu-line);
  padding-top: 14px;
  margin-top: 4px;
}

/* Info-button (the small "i" pill next to a field label) + side popover.
   Three concerns: (1) the trigger is a 14×14 circle that doesn't shift
   the field-label baseline; (2) the popover is absolutely positioned by
   JS at click time so it sits next to the trigger regardless of the
   form's scroll state; (3) preset rows look like sub-cards so the
   one-click affordance is obvious. */
.info-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
  padding: 0;
  border-radius: 999px;
  border: 1px solid var(--vyuu-subtle);
  background: transparent;
  color: var(--vyuu-muted);
  font: 600 10px/1 var(--vyuu-sans);
  cursor: pointer;
  margin-left: 6px;
  vertical-align: middle;
}
.info-btn:hover {
  background: var(--vyuu-orange-soft);
  color: var(--vyuu-orange-deep);
  border-color: var(--vyuu-orange-deep);
}
.field-label-row {
  display: inline-flex;
  align-items: center;
  gap: 2px;
}
/* Inside a flex row the default `align-items: stretch` overrode the
   16px height, so `border-radius: 999px` rendered a 16x38 capsule
   instead of a circle — the "i" looked like a tab glued to the panel
   edge. Pin both axes and opt out of the stretch. */
.info-btn {
  flex: 0 0 16px;
  align-self: center;
  min-height: 16px;
  max-height: 16px;
  margin-right: 2px;
}
.info-popover {
  z-index: 50;
  /* Was a hard 360px, which overflowed a narrow viewport with no way
     to scroll it back. */
  width: min(360px, calc(100vw - 32px));
  max-height: min(60vh, 520px);
  overflow-y: auto;
  padding: 16px 18px 14px;
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  box-shadow: 0 8px 24px rgba(31, 42, 46, 0.12);
  font: var(--vyuu-body);
  color: var(--vyuu-muted);
}
/* The arrow. Without it the panel floats unattached — it used to be
   hard-shifted 280px left of its trigger, so it pointed at nothing and
   covered the field it was explaining. JS sets `--info-arrow-x` to the
   trigger's centre so the caret tracks the button even after the panel
   is clamped away from it at a viewport edge. */
.info-popover::before,
.info-popover::after {
  content: "";
  position: absolute;
  left: var(--info-arrow-x, 24px);
  width: 0;
  height: 0;
  border-left: 8px solid transparent;
  border-right: 8px solid transparent;
}
.info-popover[data-place="below"]::before {
  top: -9px;
  border-bottom: 9px solid var(--vyuu-line);
}
.info-popover[data-place="below"]::after {
  top: -8px;
  border-bottom: 8px solid var(--vyuu-panel);
}
.info-popover[data-place="above"]::before {
  bottom: -9px;
  border-top: 9px solid var(--vyuu-line);
}
.info-popover[data-place="above"]::after {
  bottom: -8px;
  border-top: 8px solid var(--vyuu-panel);
}
.info-popover-title {
  font: var(--vyuu-h3);
  color: var(--vyuu-ink);
  margin-bottom: 6px;
  letter-spacing: -0.2px;
}
.info-popover-body {
  font: var(--vyuu-body);
  color: var(--vyuu-muted);
  line-height: 1.55;
  margin-bottom: 12px;
}
.info-popover-body code {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-mist);
  padding: 1px 5px;
  border-radius: 4px;
}
.info-popover-eyebrow {
  font: var(--vyuu-eyebrow);
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: var(--vyuu-muted);
  border-top: 1px solid var(--vyuu-line-soft);
  padding-top: 12px;
  margin-top: 4px;
  margin-bottom: 8px;
}
.preset-btn {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  margin-bottom: 6px;
  padding: 9px 12px;
  background: var(--vyuu-ivory);
  border: 1px solid var(--vyuu-line-soft);
  border-radius: var(--vyuu-r-md);
  cursor: pointer;
  text-align: left;
  font-family: var(--vyuu-sans);
}
.preset-btn:hover {
  border-color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-mist);
}
.preset-label {
  font: 500 13px/1.3 var(--vyuu-sans);
  color: var(--vyuu-ink);
}
.preset-hint {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-muted);
}
/* Brief one-shot highlight when a preset fills a field — flash the
   field's border in saffron so the operator sees the value moved
   even if the field scrolled off-screen. */
@keyframes flash-ok {
  0%, 100% { box-shadow: 0 0 0 0 rgba(168, 88, 32, 0); }
  50%      { box-shadow: 0 0 0 3px rgba(168, 88, 32, 0.30); }
}
.flash-ok {
  animation: flash-ok 0.8s ease-out;
}

/* Mini-mark anchor: cards that lead with a NHI / vServer / ToolCall
   glyph adopt position:relative + reserve room in the upper-right.
   The mark itself uses the .mark-icon hook so the SVG stays sized
   consistently regardless of which renderer placed it. */
.has-mark {
  position: relative;
}
.has-mark > .mark-icon {
  position: absolute;
  top: 14px;
  right: 14px;
  opacity: 0.92;
}
.mark-icon {
  display: inline-block;
  vertical-align: -4px;
}

.server-card strong {
  display: block;
  color: var(--vyuu-ink);
  font: var(--vyuu-h3);
}

.meta {
  margin-top: 8px;
  overflow-wrap: anywhere;
  color: var(--vyuu-muted);
  font: var(--vyuu-mono-sm);
}

/* Pill anatomy per Vyuu design spec: 3px 9px, 999px radius, 11px Inter,
   solid tint bg + matching ink fg. Variants encode MEANING — never just
   aesthetics. Pick the variant by what the pill represents:
   - .pill-orange  → positive / active state (`healthy`, `connected`).
   - .pill-warn    → in-flight / advisory  (`unknown`, `degraded`, `expiring`).
   - .pill-danger  → failure              (`down`, `blocked`, `revoked`).
   - .pill-info    → categorical / info   (transport, source_type, kinds).
   - .pill-neutral → standby / not-yet-acted (`standby`, `not connected`). */
.pill {
  display: inline-flex;
  align-items: center;
  margin: 8px 6px 0 0;
  padding: 3px 9px;
  border-radius: var(--vyuu-r-pill);
  font: 500 11px/1.3 var(--vyuu-sans);
  letter-spacing: 0.2px;
  /* Default = orange (active). Variants override below. */
  background: var(--vyuu-orange-soft);
  color: var(--vyuu-orange-deep);
}
.pill-orange {
  background: var(--vyuu-orange-soft);
  color: var(--vyuu-orange-deep);
}
.pill-warn {
  background: var(--vyuu-warn-tint);
  color: var(--vyuu-warn-ink);
}
.pill-danger {
  background: var(--vyuu-danger-tint);
  color: var(--vyuu-danger-ink);
}
.pill-info {
  background: var(--vyuu-info-tint);
  color: var(--vyuu-info-ink);
}
.pill-neutral {
  background: var(--vyuu-line-soft);
  color: var(--vyuu-muted);
}

.tool-list {
  min-height: 120px;
  resize: vertical;
  font: var(--vyuu-mono-sm);
}

.error {
  color: var(--vyuu-danger-ink);
}

/* U2: discovery-succeeded-but-calls-may-need-creds advisory. Renders
   as a small inline note inside the response panel; never replaces
   the existing JSON output, just prefixes it. */
.advisory {
  margin: 0 0 8px;
  padding: 8px 10px;
  border-left: 3px solid var(--vyuu-warn);
  background: var(--vyuu-warn-tint);
  color: var(--vyuu-warn-ink);
  font: var(--vyuu-ui-sm);
  border-radius: var(--vyuu-r-md);
}

hr {
  border-top-color: var(--vyuu-line) !important;
}

@media (max-width: 1080px) {
  .shell {
    grid-template-columns: 1fr;
  }

  .hero {
    position: static;
    grid-row: auto;
  }

  .grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 720px) {
  .shell {
    width: min(100% - 24px, 1440px);
    padding-top: 20px;
  }

  .auth-panel,
  .panel-head,
  .form-grid {
    grid-template-columns: 1fr;
  }
}

/* ==== Interaction states and element defaults (production baseline) ====
   Keyboard focus, disabled, pressed — none existed. Colours are the
   existing tokens; the ring is the brand orange at reduced alpha. */
:focus-visible {
  outline: 2px solid var(--vyuu-orange);
  outline-offset: 2px;
}
button:focus-visible,
.nav-item:focus-visible,
.events-pill:focus-visible,
.events-icon-btn:focus-visible {
  outline: none;
  box-shadow: 0 0 0 3px var(--vyuu-focus);
}
input:focus-visible,
select:focus-visible,
textarea:focus-visible {
  outline: none;
  border-color: var(--vyuu-orange);
  box-shadow: 0 0 0 3px var(--vyuu-focus);
}
button:active:not(:disabled) {
  transform: translateY(0.5px);
  filter: brightness(0.96);
}
button:disabled,
button[disabled] {
  opacity: 0.55;
  cursor: not-allowed;
  filter: none;
  box-shadow: none;
}
button.ghost,
.ghost {
  background: transparent;
  border-color: transparent;
  color: var(--vyuu-muted);
  box-shadow: none;
}
button.ghost:hover,
.ghost:hover {
  color: var(--vyuu-ink);
  background: var(--vyuu-line-soft);
  filter: none;
}
button.danger,
.btn-danger {
  color: var(--vyuu-danger-ink);
  border-color: var(--vyuu-danger-tint);
  background: var(--vyuu-danger-tint);
}
input,
select,
textarea {
  padding: 8px 10px;
  min-height: 36px;
  transition: border-color 0.12s, box-shadow 0.12s;
}
input::placeholder,
textarea::placeholder { color: var(--vyuu-subtle); }
select {
  appearance: none;
  -webkit-appearance: none;
  padding-right: 30px;
  background-image:
    linear-gradient(45deg, transparent 50%, var(--vyuu-muted) 50%),
    linear-gradient(135deg, var(--vyuu-muted) 50%, transparent 50%);
  background-position: calc(100% - 15px) 55%, calc(100% - 10px) 55%;
  background-size: 5px 5px, 5px 5px;
  background-repeat: no-repeat;
}
a { color: var(--vyuu-orange-deep); text-decoration-thickness: 1px; text-underline-offset: 2px; }
a:hover { color: var(--vyuu-ink); }
code {
  font: var(--vyuu-mono-sm);
  padding: 1px 5px;
  border-radius: var(--vyuu-r-sm);
  background: var(--vyuu-orange-mist);
  color: var(--vyuu-orange-deep);
}
pre code { padding: 0; background: transparent; color: inherit; }
summary { cursor: pointer; color: var(--vyuu-muted); font: var(--vyuu-ui-sm); }
summary:hover { color: var(--vyuu-ink); }
details[open] > summary { margin-bottom: 8px; }
hr { border: 0; border-top: 1px solid var(--vyuu-line); margin: 16px 0; }
/* The dark `.output` block is a code surface. Status lines — "Not
   signed in.", "Waiting for submission." — are not code and read as
   errors in a black box. `output-status` keeps the element and its id
   contract but presents it as a quiet line until it has real output. */
.output { min-height: 56px; }
.output.output-status {
  min-height: 0;
  padding: 10px 12px;
  background: var(--vyuu-ivory);
  color: var(--vyuu-muted);
  border: 1px dashed var(--vyuu-line);
  font: var(--vyuu-ui-sm);
  white-space: pre-wrap;
}
.output.output-status.has-result {
  color: var(--vyuu-ink);
  border-style: solid;
  background: var(--vyuu-panel);
}
.output.error {
  background: var(--vyuu-danger-tint);
  color: var(--vyuu-danger-ink);
  border-color: var(--vyuu-danger);
  border-style: solid;
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    transition-duration: 0.01ms !important;
    animation-duration: 0.01ms !important;
  }
}

/* ==== Header, KPI and table alignment ==================================
   The console grew two generations of panels. These rules make the
   older `.panel-head` / `.kpi-*` / `.health-*` panels render with the
   same hierarchy as the v2 `events-*` panels: eyebrow, serif title,
   muted one-line subtitle, actions on the right, serif KPI numbers,
   small-caps table headers. Same fonts, same tokens. */
.panel-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 18px;
}
.panel-head h1,
.panel-head h2 {
  margin: 0 0 8px;
  font: 600 28px/1.15 var(--vyuu-serif);
  color: var(--vyuu-ink);
}
.panel-head > div > p:not(.eyebrow),
.events-sub {
  margin: 0;
  font: var(--vyuu-body);
  color: var(--vyuu-muted);
  max-width: 720px;
}
.panel-head > div:last-child,
.panel-head-actions {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-shrink: 0;
  flex-wrap: wrap;
  justify-content: flex-end;
}
.kpi-grid { gap: 12px; margin-bottom: 18px; }
.kpi-card {
  padding: 16px 18px;
  border-radius: var(--vyuu-r-md);
  gap: 8px;
}
.kpi-label { font: 600 10.5px/1 var(--vyuu-sans); letter-spacing: 0.08em; }
.kpi-value { font-feature-settings: "tnum"; }
.health-kpi { border-radius: var(--vyuu-r-md); padding: 16px 18px; }
.health-kpi-num {
  margin: 8px 0;
  font: 600 32px/1 var(--vyuu-serif);
  font-feature-settings: "tnum";
}
.health-kpi-label { font: 600 10.5px/1 var(--vyuu-sans); letter-spacing: 0.08em; }
.health-kpi-sub { font: var(--vyuu-ui-sm); color: var(--vyuu-muted); }
.health-status-card { border-radius: var(--vyuu-r-md); }
.health-status-label { font: var(--vyuu-ui); }
.health-status-detail { font: var(--vyuu-ui-sm); font-weight: 400; }
.health-section-head {
  margin: 22px 0 10px;
  font: var(--vyuu-eyebrow);
  letter-spacing: 2.5px;
  color: var(--vyuu-orange-deep);
}
.health-table { border-radius: var(--vyuu-r-md); font: 400 12.5px/1.4 var(--vyuu-sans); }
.health-table th {
  padding: 12px 14px;
  font: var(--vyuu-th);
  letter-spacing: var(--vyuu-th-tracking);
  text-transform: uppercase;
  color: var(--vyuu-muted);
  background: var(--vyuu-panel-soft);
}
.health-table td {
  padding: 12px 14px;
  border-bottom: 1px solid var(--vyuu-line);
  vertical-align: top;
}
.health-table tbody tr:last-child td { border-bottom: 0; }
.health-table tbody tr:hover { background: var(--vyuu-panel-soft); }
.diagnostic-coverage-card { border-radius: var(--vyuu-r-md); }
.events-table thead th { position: sticky; top: 0; z-index: 1; }
.events-table tbody tr:last-child { border-bottom: 0; }
.events-table-wrap { max-width: 100%; overflow-x: auto; }
.cards { gap: 12px; }
.muted { color: var(--vyuu-muted); }
/* The health page stamped "refreshed at HH:MM" beside the as-of pill
   every other panel gets; two clocks a few pixels apart. */
#health-last-refreshed { display: none; }
/* Sign-in: one centred card, fields stacked with the label above the
   input. The two-column grid put "Tenant ID" beside "Email" with the
   labels inline, which read as four unrelated boxes. */
.auth-panel {
  display: block;
  max-width: 620px;
  margin: 8px auto 0;
  padding: var(--vyuu-pad-card);
}
.auth-panel .auth-head { margin-bottom: 18px; }
.auth-panel .auth-head h2 { margin: 0 0 8px; font: 600 28px/1.15 var(--vyuu-serif); }
.auth-panel .form-grid,
.auth-panel form {
  display: grid;
  grid-template-columns: 1fr;
  gap: 12px;
  max-width: 440px;
}
.auth-panel label { display: flex; flex-direction: column; gap: 6px; }
.auth-panel label > input { width: 100%; }
.auth-panel button[type="submit"] { justify-self: start; }
.auth-panel details { margin-top: 16px; }
.auth-panel #logged-in:not([hidden]) { display: flex; gap: 12px; align-items: center; }
/* Row action clusters (MCP servers and friends). `.row-actions` had no
   rule, so six controls flowed inline and wrapped wherever the column
   width fell. Now: a right-aligned, compact, evenly spaced group; the
   primary action keeps its weight, Delete is quiet until hovered. */
.row-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
  justify-content: flex-end;
  margin-left: auto;
  max-width: 380px;
}
.row-actions > button,
.row-actions > select,
.row-actions > .cadence-select {
  min-height: 30px;
  padding: 5px 10px;
  font: var(--vyuu-ui-sm);
  border-radius: var(--vyuu-r-sm);
}
.row-actions > .btn-primary { box-shadow: none; }
.row-actions > .danger-action {
  background: transparent;
  border-color: transparent;
  color: var(--vyuu-muted);
}
.row-actions > .danger-action:hover {
  color: var(--vyuu-danger-ink);
  background: var(--vyuu-danger-tint);
  border-color: var(--vyuu-danger-tint);
  filter: none;
}
.servers-table tbody td { vertical-align: middle; }
"""

_LOGO_LOCKUP = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 280 68"
  width="280" height="68" role="img" aria-label="Vyuu AI Shield lockup">
  <title>Vyuu AI Shield</title>
  <rect x="0" y="0" width="68" height="68" rx="18" fill="#A85820"/>
  <g transform="translate(10, 10)">
    <path d="M24 4 A20 20 0 1 1 9.86 9.86" stroke="#FBF8F1"
      stroke-width="2.4" stroke-linecap="round" fill="none"/>
    <path d="M38 24 A14 14 0 1 1 14.1 14.1" stroke="#FBF8F1"
      stroke-width="2.2" stroke-linecap="round" fill="none" opacity="0.78"/>
    <path d="M16 24 A8 8 0 1 1 31.66 26.2" stroke="#FBF8F1"
      stroke-width="2" stroke-linecap="round" fill="none" opacity="0.58"/>
    <circle cx="24" cy="24" r="2.4" fill="#FBF8F1"/>
  </g>
  <text x="88" y="36" font-family="Fraunces, Iowan Old Style, Georgia, serif"
    font-size="32" font-weight="500" fill="#1F2A2E"
    letter-spacing="-0.5">Vyuu</text>
  <text x="88" y="56" font-family="Inter, system-ui, sans-serif"
    font-size="11" font-weight="600" fill="#6B7A7D"
    letter-spacing="3">AI SHIELD</text>
</svg>
"""

_JS = """
const tokenInput = document.querySelector("#token");
const saveTokenButton = document.querySelector("#save-token");
const loginForm = document.querySelector("#login-form");
const loginOutput = document.querySelector("#login-output");
const loggedOut = document.querySelector("#logged-out");
const loggedIn = document.querySelector("#logged-in");
const loggedInMeta = document.querySelector("#logged-in-meta");
const logoutButton = document.querySelector("#logout");

// =========================================================================
// IDP-1 login buttons — "Continue with Workspace / Entra" on the operator
// sign-in page. Populated as the admin types their tenant_id; we fetch
// the public `/api/v1/auth/{tenant_id}/idp-directories` list and render
// one button per connected directory. Each button kicks off the
// per-directory operator-side SAML / OIDC flow we built.
//
// Pre-fills the tenant_id input from (in order): `?tenant=<uuid>` URL
// query param (admin shares a bookmarkable link), then sessionStorage
// from a previous successful sign-in (returning user, kept the tab
// open). Subdomain-per-tenant routing is the proper SaaS pattern;
// tracked in BACKLOG.
// =========================================================================
{
  const buttonsContainer = document.querySelector("#operator-idp-buttons");
  const tenantIdInput = document.querySelector("#login-tenant-id");
  if (buttonsContainer && tenantIdInput) {
    let lastFetchTenant = null;
    let debounceHandle = null;

    // Resolution order: server-configured default tenant (single-
    // tenant on-prem) > URL `?tenant=<uuid>` > sessionStorage from
    // a previous sign-in. First match wins.
    fetch("/api/v1/auth/default-tenant").then(async function(r) {
      if (r.ok) {
        const j = await r.json();
        tenantIdInput.value = j.tenant_id;
        const wrap = tenantIdInput.closest('label');
        if (wrap) wrap.style.display = 'none';
        const subhead = document.querySelector('#auth-subhead');
        if (subhead) {
          subhead.textContent =
            `Sign in to ${j.display_name} — `
            + `same credentials your tenant admin issued you.`;
        }
        sessionStorage.setItem("vyuu.operator.tenant", j.tenant_id);
        scheduleFetch();
        return;
      }
      const urlTenant = new URLSearchParams(window.location.search).get("tenant");
      const storedTenant = sessionStorage.getItem("vyuu.operator.tenant");
      const initial = (urlTenant || storedTenant || "").trim();
      if (initial && /^[0-9a-fA-F-]{36}$/.test(initial)) {
        tenantIdInput.value = initial;
        scheduleFetch();
      }
    }).catch(function(){});

    function scheduleFetch() {
      const value = tenantIdInput.value.trim();
      if (!value) {
        buttonsContainer.replaceChildren();
        buttonsContainer.hidden = true;
        lastFetchTenant = null;
        return;
      }
      // Cheap UUID-shape check before firing the request — saves
      // 4xx noise from typos.
      if (!/^[0-9a-fA-F-]{36}$/.test(value) || value === lastFetchTenant) return;
      if (debounceHandle) clearTimeout(debounceHandle);
      debounceHandle = setTimeout(() => fetchAndRender(value), 250);
    }

    async function fetchAndRender(tenantId) {
      lastFetchTenant = tenantId;
      try {
        const resp = await fetch(
          `/api/v1/auth/${encodeURIComponent(tenantId)}/idp-directories`
        );
        if (!resp.ok) {
          buttonsContainer.replaceChildren();
          buttonsContainer.hidden = true;
          return;
        }
        const directories = await resp.json();
        if (!directories.length) {
          buttonsContainer.replaceChildren();
          buttonsContainer.hidden = true;
          return;
        }
        renderButtons(tenantId, directories);
      } catch {
        buttonsContainer.replaceChildren();
        buttonsContainer.hidden = true;
      }
    }

    function renderButtons(tenantId, directories) {
      buttonsContainer.replaceChildren();
      for (const d of directories) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "idp-signin-button";
        btn.dataset.kind = d.kind;

        const icon = document.createElement("span");
        icon.className = "idp-signin-button-icon";
        icon.innerHTML = d.kind === "entra"
          ? // Microsoft mark — 4-square panes
            '<svg width="16" height="16" viewBox="0 0 18 18" fill="none">'
            + '<rect x="2" y="2" width="6" height="6" fill="currentColor"/>'
            + '<rect x="10" y="2" width="6" height="6" fill="currentColor" opacity="0.7"/>'
            + '<rect x="2" y="10" width="6" height="6" fill="currentColor" opacity="0.7"/>'
            + '<rect x="10" y="10" width="6" height="6" fill="currentColor"/>'
            + '</svg>'
          : // Google Workspace mark — generic globe (we don't ship the Google logo)
            '<svg width="16" height="16" viewBox="0 0 18 18" fill="none" '
            + 'stroke="currentColor" stroke-width="1.6" stroke-linecap="round" '
            + 'stroke-linejoin="round">'
            + '<circle cx="9" cy="9" r="6"/>'
            + '<path d="M3 9 H15"/>'
            + '<path d="M9 3 C11.5 5.5 11.5 12.5 9 15"/>'
            + '<path d="M9 3 C6.5 5.5 6.5 12.5 9 15"/>'
            + '</svg>';
        btn.appendChild(icon);

        const label = document.createElement("span");
        label.textContent = `Continue with ${d.display_name}`;
        btn.appendChild(label);

        const proto = document.createElement("span");
        proto.className = "idp-signin-button-protocol";
        proto.textContent = d.signin_protocol.toUpperCase();
        btn.appendChild(proto);

        btn.addEventListener("click", () => {
          // Fire the operator-side IdP flow. SAML uses a 302 redirect
          // (browser follows the Location header); OIDC start returns
          // a JSON `authorization_url` we have to navigate to.
          const base = `/api/v1/operator-auth/${encodeURIComponent(tenantId)}`
            + `/idp/${encodeURIComponent(d.id)}`;
          if (d.signin_protocol === "saml") {
            window.location.href = `${base}/saml-login`;
            return;
          }
          fetch(`${base}/oidc-start`).then(r => r.json()).then(j => {
            if (j && j.authorization_url) window.location.href = j.authorization_url;
          });
        });

        buttonsContainer.appendChild(btn);
      }
      buttonsContainer.hidden = false;
    }

    tenantIdInput.addEventListener("input", scheduleFetch);
    // Initial prefill is handled inside the default-tenant fetch above
    // so we don't double-fire on a stale value.
  }
}
const authHeading = document.querySelector("#auth-heading");
const authSubhead = document.querySelector("#auth-subhead");
const healthOutput = document.querySelector("#health-output");
const serversOutput = document.querySelector("#servers-output");
const registerOutput = document.querySelector("#register-output");
const registerForm = document.querySelector("#register-form");
const capabilitiesOutput = document.querySelector("#capabilities-output");
const vserversOutput = document.querySelector("#vservers-output");
const vserverForm = document.querySelector("#vserver-form");
const vserverOutput = document.querySelector("#vserver-output");
const vserverToolsField = document.querySelector("#vserver-tools");

// Track logged-in operator metadata (what email is signed in, etc.).
// `vyuu_operator_token` stays the source of truth for auth — this is
// purely UI state. Keys deliberately namespaced.
const STORAGE_TOKEN = "vyuu_operator_token";
const STORAGE_META = "vyuu_operator_meta";

function readStoredMeta() {
  const raw = sessionStorage.getItem(STORAGE_META);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

function setSignedInUI(meta) {
  loggedOut.hidden = true;
  loggedIn.hidden = false;
  authHeading.textContent = "Signed in";
  authSubhead.textContent = "Operator credential active in this browser session.";
  loggedInMeta.textContent =
    `${meta.email}  ·  role ${meta.role}  ·  tenant ${meta.tenant_id}`;
}

function setSignedOutUI() {
  loggedOut.hidden = false;
  loggedIn.hidden = true;
  authHeading.textContent = "Sign in";
  authSubhead.textContent =
    "Email + password — same credentials your tenant admin issued you.";
}

const storedToken = sessionStorage.getItem(STORAGE_TOKEN);
if (storedToken) {
  tokenInput.value = storedToken;
  const meta = readStoredMeta();
  if (meta) setSignedInUI(meta);
}

// =========================================================================
// Sidebar app-shell — single-section visibility + persisted active nav
// =========================================================================
//
// The page renders one giant <main> with N sections; only the section
// matching `body[data-active-nav]` is visible at a time. Clicking a
// sidebar item flips the attribute (see CSS in operator/app.css for
// the visibility selectors). Three guarantees:
//
//   1. First visit (no token) → land on "signin" so the operator
//      sees the auth form before everything else.
//   2. Returning operator (token present) → restore the last-visited
//      section from sessionStorage; default Dashboard.
//   3. Existing handlers (refresh-dashboard, refresh-servers, etc.)
//      keep working — we don't rewire any of them, just toggle which
//      DOM tree is visible.

const STORAGE_NAV = "vyuu_operator_nav";

// UI preferences (theme + density) — persisted to localStorage so
// they survive page reloads. Default theme = light, default density
// = cozy. Applied via `[data-theme]` / `[data-density]` on <html>
// so all child elements pick up the variable overrides defined in
// the CSS at the top of the file.
const PREF_THEME = "vyuu_ui_theme";
const PREF_DENSITY = "vyuu_ui_density";

function applyUiPref(kind, value) {
  if (kind === "theme") {
    if (value === "dark") {
      document.documentElement.dataset.theme = "dark";
    } else {
      delete document.documentElement.dataset.theme;
    }
    try { localStorage.setItem(PREF_THEME, value); } catch {}
  } else if (kind === "density") {
    if (value === "compact") {
      document.documentElement.dataset.density = "compact";
    } else {
      delete document.documentElement.dataset.density;
    }
    try { localStorage.setItem(PREF_DENSITY, value); } catch {}
  }
  // Reflect the active state on the toggle button.
  const attr = `data-${kind}`;
  for (const btn of document.querySelectorAll(`button[${attr}]`)) {
    btn.classList.toggle("is-active", btn.getAttribute(attr) === value);
  }
}

// Restore on boot.
(() => {
  let theme = "light";
  let density = "cozy";
  try {
    theme = localStorage.getItem(PREF_THEME) || theme;
    density = localStorage.getItem(PREF_DENSITY) || density;
  } catch {}
  applyUiPref("theme", theme);
  applyUiPref("density", density);
})();

// Wire the toggle clicks.
document.addEventListener("click", (event) => {
  const themeBtn = event.target.closest && event.target.closest("button[data-theme]");
  if (themeBtn) {
    applyUiPref("theme", themeBtn.dataset.theme);
    return;
  }
  const densityBtn = event.target.closest && event.target.closest("button[data-density]");
  if (densityBtn) {
    applyUiPref("density", densityBtn.dataset.density);
  }
});

// =========================================================================
// Search palette — global ⌘K overlay over servers / vservers / users /
// groups. Pure client-side over already-loaded caches; lazy-fetches
// missing ones on first open. Routes to the right panel on click.
// =========================================================================

const palette = (() => {
  const overlay  = document.querySelector("#palette-overlay");
  const input    = document.querySelector("#palette-input");
  const results  = document.querySelector("#palette-results");
  const trigger  = document.querySelector("#palette-trigger");

  let vserversCache = [];
  let lastResults = [];
  let focusIndex = -1;

  // Map result kind → [navId, optional row-id selector for highlight]
  const navByKind = {
    server:  "servers",
    vserver: "vservers",
    user:    "users",
    group:   "groups",
  };

  function isOpen() {
    return overlay && !overlay.hidden;
  }

  function open() {
    if (!overlay) return;
    overlay.hidden = false;
    input.value = "";
    focusIndex = -1;
    results.replaceChildren();
    // Lazy-load any caches that are still empty. Cheap enough — each
    // is a single GET; we silently no-op the failures (operator may
    // not have signed in yet).
    Promise.allSettled([
      maybeLoadServers(),
      maybeLoadVservers(),
      maybeLoadPrincipals(),
    ]).finally(() => {
      if (isOpen()) refilter();
    });
    setTimeout(() => input.focus(), 0);
  }

  function close() {
    if (!overlay) return;
    overlay.hidden = true;
    focusIndex = -1;
  }

  async function maybeLoadServers() {
    if (typeof serversCache !== "undefined" && serversCache.length) return;
    if (typeof loadServers !== "function") return;
    try { await loadServers(); } catch {}
  }
  async function maybeLoadVservers() {
    try {
      vserversCache = await api("/api/v1/vservers");
    } catch { vserversCache = []; }
  }
  async function maybeLoadPrincipals() {
    if (typeof ensurePrincipalCacheLoaded !== "function") return;
    try { await ensurePrincipalCacheLoaded(); } catch {}
  }

  function refilter() {
    const needle = (input.value || "").trim().toLowerCase();
    const items = collectAll();
    const filtered = needle
      ? items.filter((it) => it.haystack.includes(needle))
      : [];
    lastResults = filtered.slice(0, 25);  // cap UI work
    focusIndex = lastResults.length ? 0 : -1;
    paint();
  }

  function collectAll() {
    const out = [];
    const servers = (typeof serversCache !== "undefined") ? serversCache : [];
    for (const s of servers) {
      out.push({
        kind: "server",
        id: s.id,
        name: s.display_name,
        meta: s.source_type || "",
        haystack:
          `${s.display_name} ${s.id} ${s.source_type || ""} `
          + `${s.source_location || ""}`.toLowerCase(),
      });
    }
    for (const v of vserversCache || []) {
      out.push({
        kind: "vserver",
        id: v.id,
        name: v.name,
        meta: v.visibility || "",
        haystack:
          `${v.name} ${v.id} ${v.visibility || ""} `
          + `${v.description || ""}`.toLowerCase(),
      });
    }
    const users = (typeof principalCache !== "undefined")
      ? (principalCache.users || []) : [];
    for (const u of users) {
      out.push({
        kind: "user",
        id: u.id,
        name: u.email,
        meta: u.auth_method || "",
        haystack: `${u.email} ${u.id} ${u.auth_method || ""}`.toLowerCase(),
      });
    }
    const groups = (typeof principalCache !== "undefined")
      ? (principalCache.groups || []) : [];
    for (const g of groups) {
      out.push({
        kind: "group",
        id: g.id,
        name: g.name,
        meta: g.description || "",
        haystack:
          `${g.name} ${g.id} ${g.description || ""}`.toLowerCase(),
      });
    }
    return out;
  }

  function paint() {
    results.replaceChildren();
    if (!input.value.trim()) {
      // results-empty pseudo-element renders the prompt copy
      return;
    }
    if (!lastResults.length) {
      const empty = document.createElement("p");
      empty.className = "palette-empty";
      empty.textContent =
        `No matches for "${input.value}". Searches across MCP `
        + "servers, virtual servers, users, and groups.";
      results.appendChild(empty);
      return;
    }
    // Group by kind in fixed order.
    const order = ["server", "vserver", "user", "group"];
    const labelFor = {
      server: "MCP servers",
      vserver: "Virtual servers",
      user: "Users",
      group: "Groups",
    };
    let idx = 0;
    for (const kind of order) {
      const inSection = lastResults.filter((r) => r.kind === kind);
      if (!inSection.length) continue;
      const label = document.createElement("p");
      label.className = "palette-section-label";
      label.textContent = labelFor[kind];
      results.appendChild(label);
      for (const item of inSection) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "palette-result";
        btn.dataset.idx = idx;
        btn.dataset.kind = item.kind;
        btn.dataset.id = item.id;
        btn.setAttribute("role", "option");
        const name = document.createElement("span");
        name.className = "palette-result-name";
        name.textContent = item.name;
        btn.appendChild(name);
        if (item.meta) {
          const meta = document.createElement("span");
          meta.className = "palette-result-meta";
          meta.textContent = item.meta;
          btn.appendChild(meta);
        }
        const kindPill = document.createElement("span");
        kindPill.className = "palette-result-kind";
        kindPill.textContent = item.kind;
        btn.appendChild(kindPill);
        btn.addEventListener("click", () => activate(idx));
        results.appendChild(btn);
        idx++;
      }
    }
    paintFocus();
  }

  function paintFocus() {
    const all = results.querySelectorAll(".palette-result");
    all.forEach((el, i) => {
      el.classList.toggle("is-focused", i === focusIndex);
    });
    if (focusIndex >= 0 && all[focusIndex]) {
      all[focusIndex].scrollIntoView({ block: "nearest" });
    }
  }

  function activate(idx) {
    const item = lastResults[idx];
    if (!item) return;
    const navId = navByKind[item.kind];
    if (typeof setActiveNav === "function" && navId) {
      setActiveNav(navId);
    }
    close();
  }

  function moveFocus(delta) {
    if (!lastResults.length) return;
    focusIndex = (focusIndex + delta + lastResults.length)
      % lastResults.length;
    paintFocus();
  }

  // --- wiring -----------------------------------------------------

  if (input) {
    input.addEventListener("input", refilter);
    input.addEventListener("keydown", (event) => {
      if (event.key === "ArrowDown") {
        event.preventDefault();
        moveFocus(1);
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        moveFocus(-1);
      } else if (event.key === "Enter") {
        event.preventDefault();
        if (focusIndex >= 0) activate(focusIndex);
      } else if (event.key === "Escape") {
        event.preventDefault();
        close();
      }
    });
  }

  if (overlay) {
    // Click on the backdrop (but not the card) closes the palette.
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) close();
    });
  }

  if (trigger) {
    trigger.addEventListener("click", () => {
      if (isOpen()) close(); else open();
    });
  }

  // Global ⌘K / Ctrl+K to toggle. Ignore when focused inside an input
  // unless it's the palette's own input — operators expect the
  // shortcut to work from anywhere.
  document.addEventListener("keydown", (event) => {
    const isToggle = (event.metaKey || event.ctrlKey)
      && (event.key === "k" || event.key === "K");
    if (isToggle) {
      event.preventDefault();
      if (isOpen()) close(); else open();
      return;
    }
    if (event.key === "Escape" && isOpen()) {
      close();
    }
  });

  return { open, close, isOpen };
})();

// =========================================================================
// Alerts bell — thin shell over the existing audit-events ring buffer.
// Surfaces denied / blocked tool calls from the last hour. Polls the
// badge count every 60s; full list paints on open. Reuses the
// .palette-overlay / .palette-card markup for visual consistency.
// =========================================================================

const alerts = (() => {
  const overlay  = document.querySelector("#alerts-overlay");
  const trigger  = document.querySelector("#alerts-trigger");
  const refreshBtn = document.querySelector("#alerts-refresh");
  const results  = document.querySelector("#alerts-results");
  const badge    = document.querySelector("#alerts-badge");

  // 1 hour window — matches the existing dashboard's 1h KPIs.
  const WINDOW_MINUTES = 60;
  const POLL_INTERVAL_MS = 60_000;

  let pollTimer = null;

  function isOpen() { return overlay && !overlay.hidden; }

  function open() {
    if (!overlay) return;
    overlay.hidden = false;
    paintList([]);
    results.innerHTML =
      '<p class="alerts-empty">Loading recent alerts…</p>';
    refreshList();
  }

  function close() {
    if (!overlay) return;
    overlay.hidden = true;
  }

  function isAlertEvent(ev) {
    const decision = (ev.decision || "").toLowerCase();
    return decision === "deny" || decision === "block" || decision === "error";
  }

  function withinWindow(ev) {
    if (!ev.observed_at) return false;
    const ts = new Date(ev.observed_at).getTime();
    if (Number.isNaN(ts)) return false;
    return (Date.now() - ts) <= WINDOW_MINUTES * 60_000;
  }

  async function fetchAlertEvents() {
    try {
      const events = await api("/api/v1/audit-events?limit=200");
      return (events || []).filter(isAlertEvent).filter(withinWindow);
    } catch {
      return [];
    }
  }

  async function refreshList() {
    if (!isSignedIn()) return;
    const events = await fetchAlertEvents();
    paintList(events);
    paintBadge(events.length);
  }

  async function refreshBadgeOnly() {
    if (!isSignedIn()) {
      paintBadge(0);
      return;
    }
    const events = await fetchAlertEvents();
    paintBadge(events.length);
  }

  function isSignedIn() {
    try {
      return !!sessionStorage.getItem("vyuu_operator_token");
    } catch {
      return false;
    }
  }

  function paintBadge(count) {
    if (!badge) return;
    if (count <= 0) {
      badge.hidden = true;
      badge.textContent = "0";
      return;
    }
    badge.hidden = false;
    badge.textContent = count > 99 ? "99+" : String(count);
  }

  function paintList(events) {
    if (!results) return;
    results.innerHTML = "";
    if (!events.length) {
      const empty = document.createElement("p");
      empty.className = "alerts-empty";
      empty.textContent =
        "No alerts in the last hour. Denied or blocked tool calls "
        + "show up here in real time.";
      results.appendChild(empty);
      return;
    }
    // Newest first.
    const sorted = events.slice().sort((a, b) =>
      new Date(b.observed_at) - new Date(a.observed_at));
    for (const ev of sorted) {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "alert-row";
      row.setAttribute("role", "listitem");

      const decisionPill = document.createElement("span");
      const dec = (ev.decision || "").toLowerCase();
      decisionPill.className = `alert-row-decision ${dec}`;
      decisionPill.textContent = dec || "?";
      row.appendChild(decisionPill);

      const text = document.createElement("div");
      text.className = "alert-row-text";
      const tool = document.createElement("span");
      tool.className = "alert-row-tool";
      tool.textContent = ev.tool || ev.event_type || "(no tool name)";
      text.appendChild(tool);
      const meta = document.createElement("div");
      meta.className = "alert-row-meta";
      const principal = ev.principal && ev.principal.display
        ? ev.principal.display
        : (ev.principal && ev.principal.id) || "(no principal)";
      const reason = ev.policy_reason || ev.error_message || "";
      meta.textContent = reason
        ? `${principal} · ${reason}`
        : principal;
      text.appendChild(meta);
      row.appendChild(text);

      const time = document.createElement("span");
      time.className = "alert-row-time";
      time.textContent = ev.observed_at
        ? new Date(ev.observed_at).toLocaleTimeString()
        : "";
      row.appendChild(time);

      row.addEventListener("click", () => {
        // Route to the Events panel — operator can drill in there.
        if (typeof setActiveNav === "function") setActiveNav("events");
        close();
      });
      results.appendChild(row);
    }
  }

  function startPolling() {
    if (pollTimer != null) return;
    refreshBadgeOnly();
    pollTimer = setInterval(refreshBadgeOnly, POLL_INTERVAL_MS);
  }

  function stopPolling() {
    if (pollTimer != null) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  if (trigger) {
    trigger.addEventListener("click", () => {
      if (isOpen()) close(); else open();
    });
  }
  if (refreshBtn) {
    refreshBtn.addEventListener("click", refreshList);
  }
  if (overlay) {
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) close();
    });
  }
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && isOpen()) close();
  });

  // Boot: start polling once the page is ready. Polling no-ops when
  // not signed in, so it's safe to start immediately.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startPolling);
  } else {
    startPolling();
  }

  return { open, close, isOpen, refresh: refreshList, stopPolling };
})();

// Stamp a "loaded HH:MM:SS" pill next to the matching Refresh button.
// Closes the auto-refresh feedback loop — operators can see how stale
// a panel is without hitting Refresh and watching for changes.
// Each loader calls `markAsOf(refreshButtonId)` on success.
function markAsOf(refreshButtonId) {
  const btn = document.querySelector(`#${refreshButtonId}`);
  if (!btn) return;
  // Wrap button + pill in a flex container so they sit together in
  // the same panel-head grid column. Without the wrapper, the pill
  // would auto-flow into a 3rd grid column and stretch the button.
  let group = btn.closest(".panel-head-actions");
  if (!group) {
    group = document.createElement("div");
    group.className = "panel-head-actions";
    btn.parentElement.insertBefore(group, btn);
    group.appendChild(btn);
  }
  let pill = group.querySelector(".as-of-pill");
  if (!pill) {
    pill = document.createElement("span");
    pill.className = "as-of-pill";
    group.insertBefore(pill, btn);
  }
  const now = new Date();
  const opts = {hour:'2-digit', minute:'2-digit', second:'2-digit'};
  pill.textContent = `as of ${now.toLocaleTimeString([], opts)}`;
  pill.title = `Last loaded ${now.toLocaleString()}`;
}

function setActiveNav(navId) {
  if (!navId) return;
  document.body.dataset.activeNav = navId;
  // Toggle `.is-hidden` on every content section based on whether
  // its data-nav matches the active id. We deliberately query only
  // *content* sections (descendants of .content), not the sidebar
  // nav-items — the buttons must stay visible regardless.
  const content = document.querySelector(".content");
  if (content) {
    for (const sec of content.querySelectorAll("[data-nav]")) {
      sec.classList.toggle("is-hidden", sec.dataset.nav !== navId);
    }
    content.scrollTop = 0;
  }
  // Active state on the sidebar item — visual cue.
  for (const item of document.querySelectorAll(".nav-item")) {
    item.classList.toggle("is-active", item.dataset.nav === navId);
  }
  try { sessionStorage.setItem(STORAGE_NAV, navId); } catch {}
  window.scrollTo({top: 0, behavior: "instant"});

  // Auto-load the panel's data on navigation. Operators were having to
  // hit Refresh on every section after switching to it — silly when the
  // sidebar click is itself the intent signal. Each loader is no-op
  // safe (renders empty state on tenant with zero rows) and idempotent
  // (re-clicking the same nav re-fetches; cheap because the data
  // sources are either in-memory ring buffers or single SELECTs).
  if (typeof sessionStorage.getItem === "function" &&
      !sessionStorage.getItem(STORAGE_TOKEN)) {
    return;  // No bearer → API calls would 401 noisily; skip.
  }
  // Each entry: [refreshButtonId, loaderFn].  The loader resolves
  // asynchronously; we stamp `as of HH:MM:SS` next to the relevant
  // Refresh button after it completes.
  const _has = (n) => typeof window[n] === "function";
  const loaders = {
    "dashboard":       ["refresh-dashboard",
      () => _has("loadDashboard") && loadDashboard()],
    "nhi-map":         ["refresh-nhi-map",
      () => _has("loadNhiMap") && loadNhiMap()],
    "servers":         ["refresh-servers", async () => {
      if (_has("loadHealth"))  await loadHealth();
      if (_has("loadServers")) await loadServers();
      if (_has("loadConnectorCatalog")) await loadConnectorCatalog();
    }],
    "vservers":        ["refresh-vservers",
      () => _has("loadVservers") && loadVservers()],
    "identities":      ["refresh-identities",
      () => _has("loadIdentities") && loadIdentities()],
    "users":           ["refresh-users",
      () => _has("loadUsers") && loadUsers()],
    "groups":          ["refresh-groups",
      () => _has("loadGroups") && loadGroups()],
    "access-requests": ["refresh-access-requests",
      () => _has("loadAccessRequests") && loadAccessRequests()],
    "admins":          ["refresh-admins",
      () => _has("loadAdmins") && loadAdmins()],
    "events":          ["refresh-audit-events",
      () => _has("loadAuditEvents") && loadAuditEvents()],
    "admin-audit":     ["refresh-admin-audit",
      () => _has("loadAdminAudit") && loadAdminAudit()],
    "idp-directories": ["refresh-idp-directories",
      () => _has("loadIdpDirectories") && loadIdpDirectories()],
    "secret-store":    ["refresh-secret-store",
      () => _has("loadSecretStoreStatus") && loadSecretStoreStatus()],
    "security-posture": ["refresh-security-posture",
      () => _has("loadSecurityPosture") && loadSecurityPosture()],
    "api-key-policy": ["refresh-api-key-policy",
      () => _has("loadApiKeyPolicies") && loadApiKeyPolicies()],
    "risk-summary": ["refresh-risk-summary",
      () => _has("loadRiskSummary") && loadRiskSummary()],
    "risk-classifier": ["refresh-risk-classifier",
      () => _has("loadRiskClassifier") && loadRiskClassifier()],
    "health-overview": ["refresh-health-overview",
      () => _has("loadHealthOverview") && loadHealthOverview()],
    "siem-export": ["refresh-siem-export",
      () => _has("loadSiemExport") && loadSiemExport()],
    "telemetry": ["refresh-telemetry",
      () => _has("loadTelemetry") && loadTelemetry()],
    "troubleshooting": ["download-diagnostic-bundle", () => {}],
  };
  const entry = loaders[navId];
  if (entry) {
    const [btnId, fn] = entry;
    Promise.resolve()
      .then(() => fn())
      .then(() => markAsOf(btnId))
      .catch(() => {});
  }
}

// Refresh-button clicks also stamp on success. Delegated handler so
// it works for buttons added later (e.g. inside drawers).
document.addEventListener("click", (event) => {
  const btn = event.target.closest && event.target.closest('button[id^="refresh-"]');
  if (!btn) return;
  // Loader is async; stamp shortly after click so the data has time
  // to render. 600ms is enough for in-memory ring buffer queries
  // (the slowest are DB joins which return well under 500ms).
  setTimeout(() => markAsOf(btn.id), 600);
});

document.addEventListener("click", (event) => {
  const item = event.target.closest && event.target.closest(".nav-item");
  if (!item || !item.dataset.nav) return;
  setActiveNav(item.dataset.nav);
});

// Restore last-visited nav on load. If the operator has no stored
// token, force the signin section so they don't land on an empty
// dashboard with auth-required errors.
(() => {
  const haveToken = !!sessionStorage.getItem(STORAGE_TOKEN);
  const last = sessionStorage.getItem(STORAGE_NAV);
  setActiveNav(haveToken ? (last || "dashboard") : "signin");
})();

// When the operator successfully signs in, jump straight to the
// dashboard — saves a manual click and signals "you're in".
const _origSetSignedInUI = setSignedInUI;
setSignedInUI = function setSignedInUIWithNav(meta) {
  _origSetSignedInUI(meta);
  // Only auto-jump if we're currently on the signin section.
  if (document.body.dataset.activeNav === "signin") {
    setActiveNav("dashboard");
  }
};

// Email + password login.
loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(loginForm);
  const tenant_id = String(data.get("tenant_id") || "").trim();
  const email = String(data.get("email") || "").trim();
  const password = String(data.get("password") || "");
  if (!tenant_id || !email || !password) {
    renderText(loginOutput, "tenant_id, email and password are required.");
    return;
  }
  try {
    const response = await fetch("/api/v1/operator-auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tenant_id, email, password }),
    });
    const text = await response.text();
    let body;
    try { body = text ? JSON.parse(text) : null; } catch { body = text; }
    if (!response.ok) {
      const detail = body && body.detail ? body.detail : response.statusText;
      throw new Error(`${response.status} ${detail}`);
    }
    sessionStorage.setItem(STORAGE_TOKEN, body.bearer_token);
    const meta = {
      email: body.email,
      role: body.role,
      tenant_id: body.tenant_id,
      operator_id: body.operator_id,
      must_change_password: body.must_change_password,
    };
    sessionStorage.setItem(STORAGE_META, JSON.stringify(meta));
    // Cache the tenant_id under the same key the IdP-button prefiller
    // reads from, so a returning admin doesn't have to re-enter it.
    if (body.tenant_id) {
      sessionStorage.setItem("vyuu.operator.tenant", String(body.tenant_id));
    }
    tokenInput.value = body.bearer_token;
    setSignedInUI(meta);
    renderText(
      loginOutput,
      meta.must_change_password
        ? "Signed in. Password rotation required — use POST /api/v1/operator-auth/password."
        : "Signed in.",
    );
    // Refresh the panels we already render up front.
    loadHealth();
  } catch (error) {
    renderError(loginOutput, error);
  }
});

// Paste-token fallback (lab / automation).
saveTokenButton.addEventListener("click", () => {
  const value = tokenInput.value.trim();
  sessionStorage.setItem(STORAGE_TOKEN, value);
  sessionStorage.removeItem(STORAGE_META);
  renderText(loginOutput, "Token stored for this browser session.");
  setSignedOutUI();  // we don't know the operator's metadata for a
                    // pasted token — keep the form visible.
  // App-shell hook: pasted tokens don't go through setSignedInUI
  // (we don't have the operator metadata to render); jump to the
  // dashboard ourselves so the operator sees something useful.
  if (document.body.dataset.activeNav === "signin") {
    setActiveNav("dashboard");
  }
});

logoutButton.addEventListener("click", () => {
  sessionStorage.removeItem(STORAGE_TOKEN);
  sessionStorage.removeItem(STORAGE_META);
  tokenInput.value = "";
  setSignedOutUI();
  renderText(loginOutput, "Signed out.");
});

document.querySelector("#refresh-health").addEventListener("click", loadHealth);
document.querySelector("#refresh-servers").addEventListener("click", loadServers);

// Servers toolbar — search box + runtime filter pills. Both filter
// the in-memory cache (no extra API calls) so typing is responsive.
{
  const searchEl = document.querySelector("#servers-search");
  if (searchEl) {
    searchEl.addEventListener("input", (e) => {
      SERVER_FILTER.needle = (e.target.value || "").trim().toLowerCase();
      renderServers();
    });
  }
  for (const pill of document.querySelectorAll(".filter-pill")) {
    pill.addEventListener("click", () => {
      SERVER_FILTER.current = pill.dataset.filter;
      for (const p of document.querySelectorAll(".filter-pill")) {
        p.classList.toggle("is-active", p.dataset.filter === SERVER_FILTER.current);
      }
      renderServers();
    });
  }
  const jumpBtn = document.querySelector("#register-server-jump");
  if (jumpBtn) {
    jumpBtn.addEventListener("click", () => {
      if (typeof wizard !== "undefined") wizard.open();
    });
  }
}
document.querySelector("#refresh-vservers").addEventListener("click", loadVservers);
registerForm.addEventListener("submit", registerServer);
vserverForm.addEventListener("submit", createVserver);

loadHealth();

function authHeaders() {
  const token = tokenInput.value.trim() || sessionStorage.getItem("vyuu_operator_token") || "";
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  let payload = text;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = text;
  }
  if (!response.ok) {
    const detail = payload && payload.detail ? payload.detail : response.statusText;
    throw new Error(`${response.status} ${detail}`);
  }
  return payload;
}

async function loadHealth() {
  try {
    const payload = await api("/api/v1/health", { headers: {} });
    renderText(healthOutput, JSON.stringify(payload, null, 2));
    // Mirror into the sidebar foot pill (visible everywhere; tiny;
    // doesn't waste space like the old standalone Gateway-health card).
    updateGatewayStatusPill({status: "ok", payload});
  } catch (error) {
    renderError(healthOutput, error);
    updateGatewayStatusPill({status: "down", error});
  }
}

function updateGatewayStatusPill(state) {
  const el = document.querySelector("#gateway-status-pill");
  if (!el) return;
  el.classList.remove("is-ok", "is-warn", "is-down");
  const text = el.querySelector(".status-text");
  if (state.status === "ok") {
    el.classList.add("is-ok");
    const p = state.payload || {};
    // Show service name + version (or environment) in mono.
    text.textContent = `${p.service || "gateway"} · ${p.version || p.environment || "ok"}`;
  } else if (state.status === "warn") {
    el.classList.add("is-warn");
    text.textContent = state.message || "warn";
  } else {
    el.classList.add("is-down");
    text.textContent = state.error?.message ? state.error.message.slice(0, 30) : "down";
  }
}

// Cached list for filter/search — loadServers refreshes both the cache
// and the rendered rows.
let serversCache = [];
const SERVER_FILTER = { current: "all", needle: "" };

async function loadServers() {
  serversOutput.innerHTML = "Loading…";
  try {
    serversCache = await api("/api/v1/servers");
    renderServers();
  } catch (error) {
    serversOutput.innerHTML = "";
    const node = document.createElement("p");
    node.className = "error";
    node.textContent = String(error.message || error);
    serversOutput.appendChild(node);
  }
}

// ============================================================
// Connector catalog — quick-add card grid above the servers table.
// Cards are pre-configured SaaS templates (GitHub, Notion, Slack,
// Linear, Jira, Confluence, Asana, Microsoft 365). Clicking a card
// opens the existing register-server wizard with everything pre-
// filled except client_id_ref / client_secret_ref. NO new submit
// path — the wizard still POSTs to /api/v1/servers like always.
// ============================================================
let connectorCatalogCache = null;

async function loadConnectorCatalog() {
  const grid = document.querySelector("#connector-catalog-grid");
  if (!grid) return;
  try {
    if (connectorCatalogCache === null) {
      const resp = await api("/api/v1/operator/connector-catalog");
      connectorCatalogCache = resp.items || [];
    }
    renderConnectorCatalog(connectorCatalogCache);
  } catch (error) {
    grid.innerHTML = "";
    const p = document.createElement("p");
    p.className = "connector-catalog-loading";
    p.textContent = `Catalog unavailable: ${error.message || error}`;
    grid.appendChild(p);
  }
}

function renderConnectorCatalog(items) {
  const grid = document.querySelector("#connector-catalog-grid");
  if (!grid) return;
  grid.innerHTML = "";
  if (!items.length) {
    const empty = document.createElement("p");
    empty.className = "connector-catalog-loading";
    empty.textContent = "No connectors configured.";
    grid.appendChild(empty);
    return;
  }
  for (const tpl of items) {
    grid.appendChild(buildConnectorCard(tpl));
  }
}

function buildConnectorCard(tpl) {
  const card = document.createElement("button");
  card.type = "button";
  card.className = "connector-card";
  card.setAttribute("role", "listitem");
  card.dataset.connectorKey = tpl.key;
  card.title = `Pre-fill register wizard for ${tpl.display_name}`;

  const head = document.createElement("div");
  head.className = "connector-card-head";
  const name = document.createElement("span");
  name.className = "connector-card-name";
  name.textContent = tpl.display_name;
  head.appendChild(name);
  const status = document.createElement("span");
  status.className = "connector-card-status";
  status.dataset.status = tpl.status;
  status.textContent = tpl.status;
  head.appendChild(status);
  card.appendChild(head);

  const tagline = document.createElement("div");
  tagline.className = "connector-card-tagline";
  tagline.textContent = tpl.tagline;
  card.appendChild(tagline);

  const meta = document.createElement("div");
  meta.className = "connector-card-meta";
  // DCR badge: vendor follows MCP-Auth spec, gateway auto-registers
  // itself as an OAuth client. Operator skips client_id/secret setup.
  const dcrTag = tpl.dcr_enabled
    ? " · auto OAuth (DCR)"
    : "";
  meta.textContent = `${tpl.runtime} · ${tpl.default_transport}${dcrTag}`;
  card.appendChild(meta);

  if (tpl.extra_field_hints && tpl.extra_field_hints.length) {
    const ul = document.createElement("ul");
    ul.className = "connector-card-hints";
    for (const hint of tpl.extra_field_hints) {
      const li = document.createElement("li");
      li.textContent = hint;
      ul.appendChild(li);
    }
    card.appendChild(ul);
  }

  card.addEventListener("click", () => applyConnectorTemplate(tpl));
  return card;
}

// Pre-fill the register wizard from a template, then open it.
// Mirrors the field-naming used by the wizard's per-step form fields:
// runtime → source_type radio, source_location, transport, display_name,
// auth_mode = authcode + the existing applyPresetToStructuredFields()
// for the OAuth subfields. Admin still completes step 3 (secrets) and
// hits Register on step 5.
// Centralized DCR-mode toggle. Three things move in lockstep:
//   1. Hidden `auth_authcode_dcr_enabled` input — read by
//      serializeAuthFields() on submit.
//   2. Visible checkbox `#auth-authcode-dcr-toggle` — what the
//      operator sees.
//   3. body[data-authcode-mode] — drives CSS that hides static
//      ref fields + reveals the DCR banner.
// Both the catalog click handler and the checkbox change handler
// route through here so the UI never gets out of sync with the
// payload.
function setDcrMode(enabled) {
  const dcrInput = registerForm.querySelector(
    'input[type="hidden"][name="auth_authcode_dcr_enabled"]'
  );
  if (dcrInput) dcrInput.value = enabled ? "true" : "false";
  const checkbox = document.querySelector("#auth-authcode-dcr-toggle");
  if (checkbox) checkbox.checked = enabled;
  document.body.dataset.authcodeMode = enabled ? "dcr" : "static";
  // Refresh the wizard's per-step gate + live-preview manifest so the
  // checklist drops the now-irrelevant client_id_ref / client_secret_ref
  // requirements when DCR is on (or restores them when off).
  registerForm.dispatchEvent(new Event("input", { bubbles: true }));
}

// Catalog-click variant: same as setDcrMode but the name documents
// the intent at the call site.
function setDcrModeFromCatalog(enabled) {
  setDcrMode(enabled);
}

// Manual checkbox toggle — operator-driven path for one-off
// registrations of DCR-capable vendors not in the catalog.
{
  const checkbox = document.querySelector("#auth-authcode-dcr-toggle");
  if (checkbox) {
    checkbox.addEventListener("change", (e) => {
      setDcrMode(e.target.checked);
    });
  }
}

function applyConnectorTemplate(tpl) {
  if (!registerForm) return;

  // Step 1 — runtime + display name
  const runtimeRadio = registerForm.querySelector(
    `input[type="radio"][name="source_type"][value="${tpl.runtime}"]`,
  );
  if (runtimeRadio) {
    runtimeRadio.checked = true;
    // The body[data-source-type] mirror watches `change` events.
    runtimeRadio.dispatchEvent(new Event("change", { bubbles: true }));
  }
  const nameInput = registerForm.querySelector('input[name="display_name"]');
  if (nameInput) {
    nameInput.value = tpl.display_name;
    nameInput.classList.add("flash-ok");
    setTimeout(() => nameInput.classList.remove("flash-ok"), 800);
  }

  // Step 2 — source_location + transport
  const sourceInput = registerForm.querySelector('input[name="source_location"]');
  if (sourceInput) {
    sourceInput.value = tpl.default_source;
    sourceInput.classList.add("flash-ok");
    setTimeout(() => sourceInput.classList.remove("flash-ok"), 800);
  }
  const transportSel = registerForm.querySelector('select[name="transport"]');
  if (transportSel) {
    transportSel.value = tpl.default_transport;
    transportSel.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // Step 3 — flip auth_mode to authcode + fill OAuth subfields via
  // the existing preset machinery. This auto-flips the body data-
  // attribute so the right field group reveals.
  if (typeof applyPresetToStructuredFields === "function" && tpl.oauth_authcode) {
    applyPresetToStructuredFields("auth_authcode", tpl.oauth_authcode);
  }
  // DCR flag: spec-compliant vendors (Notion, Linear, etc.) get
  // dcr_enabled=true. Mirror the state into BOTH the hidden input
  // (read by serializeAuthFields on submit) AND the visible
  // checkbox (so the operator sees the toggle reflect the catalog
  // choice and can flip it off if they want to register manually).
  setDcrModeFromCatalog(!!tpl.dcr_enabled);

  // Re-render the live preview + re-evaluate wizard step gates.
  registerForm.dispatchEvent(new Event("input", { bubbles: true }));

  // Open the wizard (already at step 1) so the operator sees the
  // pre-filled state from the start. Step 4/5 surface the per-step
  // pre-flight checklist so the operator confirms before submitting.
  if (typeof wizard !== "undefined") wizard.open();
}

// Catalog hide/show toggle — preserves the operator's preference
// across nav switches via a body data attribute.
{
  const toggleBtn = document.querySelector("#connector-catalog-toggle");
  const section = document.querySelector("#connector-catalog-section");
  if (toggleBtn && section) {
    // Collapsed by default: the catalog of what you COULD add was
    // pushing the table of what you HAVE below the fold. The choice
    // sticks per browser.
    const KEY = "vyuu_connector_catalog_open";
    const apply = (open) => {
      section.dataset.collapsed = open ? "false" : "true";
      toggleBtn.textContent = open ? "Hide" : "Show";
      toggleBtn.setAttribute("aria-expanded", open ? "true" : "false");
    };
    let open = false;
    try { open = localStorage.getItem(KEY) === "1"; } catch {}
    apply(open);
    toggleBtn.addEventListener("click", () => {
      open = section.dataset.collapsed === "true";
      apply(open);
      try { localStorage.setItem(KEY, open ? "1" : "0"); } catch {}
    });
  }
}

// Build the JSON payload for the active auth mode out of the
// per-mode structured fields. Writes the result into the hidden
// `auth_*` inputs so the existing FormData-driven serializer below
// finds them with no further changes. Returns true on success;
// false (with the error already rendered) if validation fails.
function serializeAuthFields() {
  // Reset any previously-written hidden values so a switch from
  // (e.g.) authcode → none doesn't leak the old JSON into the
  // payload.
  for (const name of ["auth_oauth", "auth_authcode", "auth_jwt_bearer"]) {
    const hidden = registerForm.querySelector(`input[type="hidden"][name="${name}"]`);
    if (hidden) hidden.value = "";
  }

  const mode = registerForm.querySelector(
    'input[name="auth_mode"]:checked',
  )?.value || "none";

  if (mode === "oauth") {
    const cfg = collectAuthSubfields("oauth");
    if (!cfg.token_url || !cfg.client_id_ref || !cfg.client_secret_ref) {
      renderError(registerOutput,
        new Error("OAuth M2M requires token_url, client_id_ref, client_secret_ref"));
      return false;
    }
    setHidden("auth_oauth", cfg);
  } else if (mode === "authcode") {
    const cfg = collectAuthSubfields("authcode");
    // DCR mode: gateway dynamically registers itself at the upstream's
    // /register endpoint on first Connect (RFC 7591). client_id_ref
    // and client_secret_ref are not required because the gateway
    // generates + persists its own credentials. The hidden flag is
    // set by the catalog click for spec-compliant vendors (Notion,
    // Linear) and can also be ticked via a future wizard checkbox.
    const dcrInput = registerForm.querySelector(
      'input[type="hidden"][name="auth_authcode_dcr_enabled"]'
    );
    const dcrEnabled = dcrInput && dcrInput.value === "true";
    if (dcrEnabled) {
      cfg.dcr_enabled = true;
    }
    // Scopes: comma-separated string → trimmed array.
    if (typeof cfg.scopes === "string") {
      cfg.scopes = cfg.scopes.split(",").map(s => s.trim()).filter(Boolean);
    }
    // extra_authorize_params: optional JSON object.
    if (cfg.extra_authorize_params) {
      try {
        const parsed = JSON.parse(cfg.extra_authorize_params);
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
          throw new Error("extra_authorize_params must be a JSON object");
        }
        cfg.extra_authorize_params = parsed;
      } catch (error) {
        renderError(registerOutput, error);
        return false;
      }
    } else {
      delete cfg.extra_authorize_params;
    }
    // In DCR mode auth_url / token_url / client_id_ref / client_secret_ref
    // are auto-discovered + auto-issued — only redirect_uri is required.
    const required = dcrEnabled
      ? ["redirect_uri"]
      : ["auth_url", "token_url", "client_id_ref",
         "client_secret_ref", "redirect_uri"];
    const missing = required.filter(k => !cfg[k]);
    if (missing.length) {
      renderError(registerOutput, new Error(
        `OAuth user-delegated requires: ${missing.join(", ")}`));
      return false;
    }
    setHidden("auth_authcode", cfg);
  } else if (mode === "jwt_bearer") {
    const cfg = collectAuthSubfields("jwt");
    if (cfg.additional_claims) {
      try {
        const parsed = JSON.parse(cfg.additional_claims);
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
          throw new Error("additional_claims must be a JSON object");
        }
        cfg.additional_claims = parsed;
      } catch (error) {
        renderError(registerOutput, error);
        return false;
      }
    } else {
      delete cfg.additional_claims;
    }
    const required = ["token_url", "algorithm", "private_key_ref",
                      "issuer", "subject", "audience"];
    const missing = required.filter(k => !cfg[k]);
    if (missing.length) {
      renderError(registerOutput, new Error(
        `JWT-bearer requires: ${missing.join(", ")}`));
      return false;
    }
    setHidden("auth_jwt_bearer", cfg);
  }
  return true;
}

function collectAuthSubfields(scope) {
  // scope: "oauth" | "authcode" | "jwt"
  const out = {};
  for (const el of registerForm.querySelectorAll(`[data-auth-${scope}]`)) {
    const v = el.value.trim();
    if (v) out[el.dataset[`auth${scope[0].toUpperCase() + scope.slice(1)}`]] = v;
  }
  return out;
}

function setHidden(name, obj) {
  const input = registerForm.querySelector(
    `input[type="hidden"][name="${name}"]`);
  if (input) input.value = JSON.stringify(obj);
}

// Mode-picker → body attribute → CSS visibility flip.
for (const radio of registerForm.querySelectorAll('input[name="auth_mode"]')) {
  radio.addEventListener("change", (e) => {
    document.body.dataset.authMode = e.target.value;
    refreshRegisterPreview();
  });
}

// Live manifest preview — renders a pretty JSON of what would be
// POSTed to /api/v1/servers right now. Fires on every form input
// + auth-mode change. Reuses `serializeAuthFields` so the preview
// matches the actual submit payload byte-for-byte.
function buildPreviewPayload() {
  const data = new FormData(registerForm);
  const sourceType = String(data.get("source_type") || "http");
  const payload = {
    display_name: String(data.get("display_name") || "").trim() || null,
    source_type: sourceType,
    source_location: String(data.get("source_location") || "").trim() || null,
  };
  // args
  const rawArgs = String(data.get("args") || "").trim();
  if (rawArgs) {
    try { payload.args = JSON.parse(rawArgs); } catch { payload.args = "<invalid JSON>"; }
  }
  const transport = String(data.get("transport") || "");
  if (transport) payload.transport = transport;
  const envVarsRef = String(data.get("env_vars_ref") || "").trim();
  if (envVarsRef) payload.env_vars_ref = envVarsRef;

  // Auth modes — same shape the serializer would produce.
  const mode = registerForm.querySelector(
    'input[name="auth_mode"]:checked')?.value || "none";
  const collectScope = (scope) => {
    const out = {};
    for (const el of registerForm.querySelectorAll(`[data-auth-${scope}]`)) {
      const v = el.value.trim();
      if (v) out[el.dataset[`auth${scope[0].toUpperCase() + scope.slice(1)}`]] = v;
    }
    return out;
  };
  if (mode === "oauth") {
    const cfg = collectScope("oauth");
    if (Object.keys(cfg).length) payload.auth_oauth = cfg;
  } else if (mode === "authcode") {
    const cfg = collectScope("authcode");
    if (typeof cfg.scopes === "string") {
      cfg.scopes = cfg.scopes.split(",").map(s => s.trim()).filter(Boolean);
    }
    if (cfg.extra_authorize_params) {
      try { cfg.extra_authorize_params = JSON.parse(cfg.extra_authorize_params); }
      catch { cfg.extra_authorize_params = "<invalid JSON>"; }
    }
    // Mirror the DCR toggle into the preview payload so the operator
    // sees `dcr_enabled: true` in the JSON manifest before submitting,
    // matching what serializeAuthFields() will actually send.
    const dcrInput = registerForm.querySelector(
      'input[type="hidden"][name="auth_authcode_dcr_enabled"]'
    );
    if (dcrInput && dcrInput.value === "true") {
      cfg.dcr_enabled = true;
    }
    if (Object.keys(cfg).length) payload.auth_authcode = cfg;
  } else if (mode === "jwt_bearer") {
    const cfg = collectScope("jwt");
    if (cfg.additional_claims) {
      try { cfg.additional_claims = JSON.parse(cfg.additional_claims); }
      catch { cfg.additional_claims = "<invalid JSON>"; }
    }
    if (Object.keys(cfg).length) payload.auth_jwt_bearer = cfg;
  } else if (mode === "headers") {
    const raw = String(data.get("auth_headers") || "").trim();
    if (raw) {
      try { payload.auth_headers = JSON.parse(raw); }
      catch { payload.auth_headers = "<invalid JSON>"; }
    }
  } else if (mode === "passthrough") {
    const raw = String(data.get("auth_passthrough") || "").trim();
    if (raw) {
      try { payload.auth_passthrough = JSON.parse(raw); }
      catch { payload.auth_passthrough = "<invalid JSON>"; }
    }
  }
  // Stdio env-vars are independent of the application-layer mode.
  const rawEnv = String(data.get("auth_env") || "").trim();
  if (rawEnv) {
    try { payload.auth_env = JSON.parse(rawEnv); }
    catch { payload.auth_env = "<invalid JSON>"; }
  }
  // mTLS refs
  for (const f of ["mtls_cert_ref", "mtls_key_ref"]) {
    const v = String(data.get(f) || "").trim();
    if (v) payload[f] = v;
  }
  return { mode, payload };
}

function refreshRegisterPreview() {
  const pre = document.querySelector("#register-preview-pre");
  if (!pre) return;
  const { mode, payload } = buildPreviewPayload();
  // Strip nulls so the preview reads cleanly when the operator hasn't
  // typed anything yet.
  const clean = JSON.parse(JSON.stringify(payload, (k, v) => v === null ? undefined : v));
  pre.textContent = JSON.stringify(clean, null, 2);

  // Checklist of required fields per current mode. Helps the operator
  // see at a glance what's missing before they hit Register.
  const list = document.querySelector("#register-preview-checklist-list");
  if (list) {
    list.innerHTML = "";
    const items = [
      ["display_name",    !!clean.display_name],
      ["source_location", !!clean.source_location],
    ];
    if (mode === "oauth") {
      const ok = clean.auth_oauth || {};
      items.push(["oauth · token_url",        !!ok.token_url]);
      items.push(["oauth · client_id_ref",    !!ok.client_id_ref]);
      items.push(["oauth · client_secret_ref",!!ok.client_secret_ref]);
    } else if (mode === "authcode") {
      const ac = clean.auth_authcode || {};
      // DCR mode requires only `redirect_uri` — auth_url, token_url,
      // client_id, client_secret all come from runtime discovery +
      // registration. Show a "DCR enabled" status item so the operator
      // sees their toggle reflected.
      if (ac.dcr_enabled) {
        items.push(["authcode · DCR enabled (auto-discover)", true]);
        items.push(["authcode · redirect_uri", !!ac.redirect_uri]);
      } else {
        const staticFields = [
          "auth_url", "token_url", "client_id_ref",
          "client_secret_ref", "redirect_uri",
        ];
        for (const f of staticFields) {
          items.push([`authcode · ${f}`, !!ac[f]]);
        }
      }
    } else if (mode === "jwt_bearer") {
      const jb = clean.auth_jwt_bearer || {};
      for (const f of ["token_url","algorithm","private_key_ref","issuer","subject","audience"]) {
        items.push([`jwt_bearer · ${f}`, !!jb[f]]);
      }
    }
    for (const [label, ok] of items) {
      const li = document.createElement("li");
      if (ok) li.classList.add("is-ok");
      li.textContent = label;
      list.appendChild(li);
    }
  }
}

// Wire input + change events on every form field so the preview
// stays live. Delegated so per-mode fields added/removed don't need
// individual binding.
registerForm.addEventListener("input", refreshRegisterPreview);
registerForm.addEventListener("change", refreshRegisterPreview);

// U8 — soft-validation on _ref fields. Operators routinely paste the
// LITERAL OAuth client_id / client_secret / private-key body into the
// `_ref` inputs, expecting them to be the value field. The gateway then
// queries the SecretStore for that literal as a key, doesn't find it,
// returns `placeholder-<value>` to the IdP, and OAuth fails silently.
//
// Heuristic: ref names use kebab-case lowercase or path-like
// separators (e.g. `github-mcp-client-id`,
// `secret/vyuu/tenant/github/client_id`). OAuth client_ids are
// 16-40 chars of alphanumeric (often with a vendor prefix like
// `Ov23li`); secrets are typically 32-64 hex/base64 chars. If the
// value looks like a credential, render an inline warning so the
// operator notices BEFORE submitting.
function _looksLikeLiteralCredential(value) {
  if (!value || value.length < 16) return false;
  // Refs almost always contain a separator (- or /) and lowercase
  // letters. Credentials are typically continuous mixed-case
  // alphanumeric or hex. If the string has no separator and no
  // lowercase-only word boundaries, flag it.
  if (value.includes("/")) return false;          // path-like ref
  if (value.startsWith("vault:") || value.startsWith("aws:")) return false;
  // Looks like a hex string (client_secret pattern)?
  if (/^[a-f0-9]{32,}$/i.test(value)) return true;
  // Looks like an OAuth-app client_id (vendor-prefix + alphanumeric,
  // no kebab-case separators, mixed case)?
  if (/^[A-Za-z0-9_]{16,}$/.test(value) && !/[-]/.test(value)) {
    // Final filter: ref names are typically all-lowercase or
    // snake_case. If we see ANY uppercase, it's much more likely a
    // literal credential.
    if (/[A-Z]/.test(value)) return true;
  }
  return false;
}

function _renderRefWarning(input) {
  const label = input.closest("label");
  if (!label) return;
  let warn = label.querySelector(".secret-ref-warn");
  const value = (input.value || "").trim();
  const looksLiteral = _looksLikeLiteralCredential(value);
  if (looksLiteral && !warn) {
    warn = document.createElement("span");
    warn.className = "secret-ref-warn";
    warn.textContent =
      "⚠ This looks like a literal credential, not a secret-store "
      + "key. The gateway will look up this string IN your secret "
      + "store; if you meant to paste the actual value, you've "
      + "missed the indirection layer (PLATFORM.md §3.1). Use a "
      + "key like `vendor-client-id` and put the actual value "
      + "behind that key.";
    label.appendChild(warn);
  } else if (!looksLiteral && warn) {
    warn.remove();
  }
}

for (const input of registerForm.querySelectorAll("[data-secret-ref-input]")) {
  input.addEventListener("input", () => _renderRefWarning(input));
  input.addEventListener("blur", () => _renderRefWarning(input));
}
// Also re-render after a preset auto-fills (the preset writes
// directly to inputs without firing an `input` event in some
// browsers — call explicitly).
const _origApplyPreset = (typeof applyPresetToStructuredFields === "function")
  ? applyPresetToStructuredFields : null;
if (_origApplyPreset) {
  applyPresetToStructuredFields = function presetFillThenPreview(...args) {
    _origApplyPreset(...args);
    refreshRegisterPreview();
    // Also fire a synthetic `input` event on the form so the wizard
    // controller's paint() re-evaluates its step gate. The preset
    // writes directly to .value without dispatching events, so
    // listeners on the form root would otherwise miss the fill.
    registerForm.dispatchEvent(new Event("input", { bubbles: true }));
  };
}
// Initial render so the preview isn't blank on page load.
refreshRegisterPreview();
// Mirror the source_type radio group into body[data-source-type] so
// the stdio-only env-vars sub-panel reveals when relevant. The wizard
// uses radios (one per runtime card) instead of a select.
{
  const sourceTypeRadios = registerForm.querySelectorAll(
    'input[type="radio"][name="source_type"]',
  );
  const syncSourceType = () => {
    const checked = registerForm.querySelector(
      'input[type="radio"][name="source_type"]:checked',
    );
    if (checked) document.body.dataset.sourceType = checked.value;
  };
  for (const radio of sourceTypeRadios) {
    radio.addEventListener("change", syncSourceType);
  }
  syncSourceType();
}
// Initialise body attribute so CSS picks the default selection.
document.body.dataset.authMode = (
  registerForm.querySelector('input[name="auth_mode"]:checked')?.value || "none"
);

// =========================================================================
// MCP registration wizard — 5 steps over the existing register form.
// The wizard is a UX layer; the form fields underneath stay the
// canonical state. Submit goes through the existing registerServer
// handler. Per-step validation gates the Continue button.
// =========================================================================

const wizard = (() => {
  const shell = document.querySelector(".wizard-shell[data-nav='servers']");
  const backBtn = document.querySelector("#wizard-back");
  const nextBtn = document.querySelector("#wizard-next");
  const cancelBtn = document.querySelector("#wizard-cancel");
  const probeBtn = document.querySelector("#wizard-probe-btn");
  const probeOut = document.querySelector("#wizard-probe-output");
  const reviewPre = document.querySelector("#wizard-review-pre");
  const reviewChecklist = document.querySelector("#wizard-review-checklist");
  const footStatus = document.querySelector("#wizard-foot-status");
  const progressItems = document.querySelectorAll(".wizard-step-pill");
  const stepBodies = document.querySelectorAll(".wizard-step");
  const TOTAL = 5;
  let current = 1;

  function open() {
    if (!shell) return;
    shell.removeAttribute("hidden");
    shell.dataset.wizardMode = "open";
    document.body.dataset.wizardActive = "true";
    current = 1;
    paint();
    // Make sure the scroll lands at the top of the wizard.
    shell.scrollIntoView({ block: "start", behavior: "instant" });
  }

  function close() {
    if (!shell) return;
    shell.setAttribute("hidden", "");
    shell.dataset.wizardMode = "closed";
    document.body.dataset.wizardActive = "false";
  }

  function isStepValid(step) {
    const data = new FormData(registerForm);
    if (step === 1) {
      const sourceType = data.get("source_type");
      const displayName = String(data.get("display_name") || "").trim();
      return !!sourceType && displayName.length > 0;
    }
    if (step === 2) {
      const sourceLocation = String(data.get("source_location") || "").trim();
      return sourceLocation.length > 0;
    }
    if (step === 3) {
      // Reuse the existing required-fields checklist logic — same
      // shape as `refreshRegisterPreview` builds. If the checklist
      // shows everything green, we're good to advance.
      const items = document.querySelectorAll(
        "#register-preview-checklist-list li",
      );
      if (!items.length) return true;  // None / Org headers / Pass-through
      for (const li of items) {
        if (!li.classList.contains("is-ok")) return false;
      }
      return true;
    }
    return true;  // Step 4 and 5 are optional / final.
  }

  function paint() {
    // Show the right step body, hide the others.
    for (const body of stepBodies) {
      body.hidden = String(body.dataset.step) !== String(current);
    }
    // Update progress pills.
    progressItems.forEach((li, idx) => {
      const stepNum = idx + 1;
      li.classList.toggle("is-current", stepNum === current);
      li.classList.toggle("is-done", stepNum < current);
    });
    // Back button.
    backBtn.disabled = current === 1;
    // Next button — last step swaps to "skip / register" pair.
    if (current === TOTAL) {
      nextBtn.style.display = "none";
    } else {
      nextBtn.style.display = "";
      nextBtn.textContent =
        current === 4 ? "Continue to review →" : "Continue →";
      nextBtn.disabled = !isStepValid(current);
    }
    // Foot status — surfaces what's blocking Continue.
    if (current < TOTAL && !isStepValid(current)) {
      footStatus.textContent = explainBlock(current);
    } else {
      footStatus.textContent = "";
    }
    // On entering Review, refresh the manifest + checklist.
    if (current === TOTAL) renderReviewStep();
  }

  function explainBlock(step) {
    if (step === 1) return "Pick a runtime + give the server a display name.";
    if (step === 2) return "Endpoint is required.";
    if (step === 3) return "Required auth fields aren't all filled.";
    return "";
  }

  function renderReviewStep() {
    const { payload, mode } = buildPreviewPayload();
    if (reviewPre) reviewPre.textContent = JSON.stringify(payload, null, 2);
    if (!reviewChecklist) return;
    reviewChecklist.innerHTML = "";
    // Detect any "<invalid JSON>" sentinel that buildPreviewPayload
    // stuffs into fields whose value isn't parseable. If any are
    // present, the in-step Register button would otherwise silently
    // abort — surface it loudly and disable the button.
    const invalidJsonFields = Object.entries(payload || {})
      .filter(([, v]) => v === "<invalid JSON>")
      .map(([k]) => k);
    const registerBtn = document.querySelector(".wizard-register-btn");
    if (registerBtn) registerBtn.disabled = invalidJsonFields.length > 0;
    const checks = [
      { label: "Runtime + display name set", ok: isStepValid(1) },
      { label: "Endpoint provided", ok: isStepValid(2) },
      {
        label: `Auth · ${mode}${mode !== "none" ? " required fields complete" : ""}`,
        ok: isStepValid(3),
      },
      {
        label: "JSON fields parse cleanly",
        ok: invalidJsonFields.length === 0,
        meta: invalidJsonFields.length
          ? `fix: ${invalidJsonFields.join(", ")}`
          : "all fields valid JSON",
      },
      {
        label: "Capabilities probe",
        ok: !!probeOut && probeOut.dataset.probeOk === "true",
        meta: probeOut?.dataset.probeMeta || "skipped — sync after registration",
      },
    ];
    for (const c of checks) {
      const li = document.createElement("li");
      if (c.ok) li.classList.add("is-ok");
      const label = document.createElement("span");
      label.textContent = c.label;
      li.appendChild(label);
      if (c.meta) {
        const meta = document.createElement("span");
        meta.className = "checklist-meta";
        meta.textContent = c.meta;
        li.appendChild(meta);
      }
      reviewChecklist.appendChild(li);
    }
  }

  async function probeUpstream() {
    if (!probeOut) return;
    const urlInput = document.querySelector("#wizard-manifest-url");
    const manifestUrl = (urlInput?.value || "").trim();
    if (!manifestUrl) {
      probeOut.dataset.probeOk = "false";
      probeOut.dataset.probeMeta = "skipped";
      probeOut.innerHTML =
        '<p class="hint">Skipped — paste a manifest URL above '
        + 'or click Continue to skip.</p>';
      return;
    }
    probeOut.innerHTML = '<p class="hint">Fetching manifest…</p>';
    try {
      const allowHttp = manifestUrl.startsWith("http://");
      const result = await api("/api/v1/servers/from-manifest", {
        method: "POST",
        body: JSON.stringify({
          manifest_url: manifestUrl,
          allow_http: allowHttp,
        }),
      });
      probeOut.dataset.probeOk = "true";
      const detectedBits = [];
      if (result.transport)       detectedBits.push(`transport=${result.transport}`);
      if (result.source_type)     detectedBits.push(`source=${result.source_type}`);
      if (result.auth_hint)       detectedBits.push(`auth_hint=${result.auth_hint}`);
      probeOut.dataset.probeMeta = detectedBits.join(", ") || "manifest parsed";

      probeOut.innerHTML = "";
      const head = document.createElement("p");
      head.className = "eyebrow";
      head.textContent = "MANIFEST · auto-detected";
      probeOut.appendChild(head);

      const dl = document.createElement("dl");
      dl.style.display = "grid";
      dl.style.gridTemplateColumns = "max-content 1fr";
      dl.style.gap = "4px 12px";
      dl.style.font = "var(--vyuu-mono-sm)";
      const fields = [
        ["display_name", result.display_name],
        ["transport", result.transport],
        ["source_type", result.source_type],
        ["source_location", result.source_location],
        ["auth_hint", result.auth_hint],
      ];
      for (const [k, v] of fields) {
        if (!v) continue;
        const dt = document.createElement("dt");
        dt.style.color = "var(--vyuu-ink-muted)";
        dt.textContent = k;
        const dd = document.createElement("dd");
        dd.style.margin = "0";
        dd.textContent = String(v);
        dl.appendChild(dt);
        dl.appendChild(dd);
      }
      probeOut.appendChild(dl);

      if ((result.notes || []).length) {
        const notesHead = document.createElement("p");
        notesHead.className = "eyebrow";
        notesHead.style.marginTop = "10px";
        notesHead.textContent = "NOTES";
        probeOut.appendChild(notesHead);
        const ul = document.createElement("ul");
        ul.style.margin = "0";
        ul.style.paddingLeft = "18px";
        for (const note of result.notes) {
          const li = document.createElement("li");
          li.className = "hint";
          li.textContent = note;
          ul.appendChild(li);
        }
        probeOut.appendChild(ul);
      }
    } catch (error) {
      probeOut.dataset.probeOk = "false";
      probeOut.dataset.probeMeta = "preview failed";
      probeOut.innerHTML = "";
      const err = document.createElement("p");
      err.className = "error";
      err.textContent = `Manifest preview failed: ${error.message || error}. `
        + "You can still register and sync later.";
      probeOut.appendChild(err);
    }
  }

  function next() {
    if (!isStepValid(current)) return;
    if (current < TOTAL) {
      current++;
      paint();
    }
  }

  function back() {
    if (current > 1) {
      current--;
      paint();
    }
  }

  // Wire everything.
  if (backBtn) backBtn.addEventListener("click", back);
  if (nextBtn) nextBtn.addEventListener("click", next);
  if (cancelBtn) cancelBtn.addEventListener("click", close);
  if (probeBtn) probeBtn.addEventListener("click", probeUpstream);

  // Re-evaluate the Continue gate every time anything changes.
  if (registerForm) {
    const re = () => paint();
    registerForm.addEventListener("input", re);
    registerForm.addEventListener("change", re);
  }

  return { open, close };
})();

async function registerServer(event) {
  event.preventDefault();
  // Whenever we write an error message to registerOutput, unhide it
  // so the operator actually sees it. The wizard hides the block by
  // default; without this every JSON-parse / auth-validation failure
  // would silently abort the submit (no event fires from a hidden
  // pre).
  const showError = (err) => {
    renderError(registerOutput, err);
    registerOutput.removeAttribute("hidden");
  };
  if (!serializeAuthFields()) {
    registerOutput.removeAttribute("hidden");
    return;
  }
  const data = new FormData(registerForm);
  let args = [];
  const rawArgs = String(data.get("args") || "").trim();
  if (rawArgs) {
    try {
      args = JSON.parse(rawArgs);
      if (!Array.isArray(args)) throw new Error("args must be a JSON array");
    } catch (error) {
      showError(error);
      return;
    }
  }

  const sourceType = String(data.get("source_type"));
  const payload = {
    display_name: String(data.get("display_name") || ""),
    source_type: sourceType,
    source_location: String(data.get("source_location") || ""),
    args,
  };
  const envVarsRef = String(data.get("env_vars_ref") || "").trim();
  if (envVarsRef) payload.env_vars_ref = envVarsRef;
  const transport = String(data.get("transport") || "");
  if (transport) payload.transport = transport;
  if (sourceType !== "http" && payload.transport === "streamable_http") {
    payload.transport = "stdio";
  }

  // Auth maps are optional; empty JSON / missing → omit. The server
  // validates that auth_headers is HTTP-only and auth_env is stdio-only.
  const authMaps = [
    ["auth_headers", "auth_headers"],
    ["auth_env", "auth_env"],
    ["auth_passthrough", "auth_passthrough"],
    ["auth_oauth", "auth_oauth"],
    ["auth_authcode", "auth_authcode"],
    ["auth_jwt_bearer", "auth_jwt_bearer"],
  ];
  // Pick the auth_mode the operator selected — fields irrelevant to
  // that mode get skipped on submit so a stale value left in (e.g.)
  // `auth_passthrough` doesn't fail JSON-parse when the operator
  // landed on `none`. `auth_env` is orthogonal to the application-
  // layer mode (it's stdio env-var injection) so it's always read
  // when source_type is in the stdio family.
  const selectedMode = registerForm.querySelector(
    'input[name="auth_mode"]:checked',
  )?.value || "none";
  const fieldRelevantToMode = {
    auth_headers: selectedMode === "headers",
    auth_passthrough: selectedMode === "passthrough",
    auth_oauth: selectedMode === "oauth",
    auth_authcode: selectedMode === "authcode",
    auth_jwt_bearer: selectedMode === "jwt_bearer",
    // auth_env: only meaningful for stdio-family sources.
    auth_env: ["stdio", "npm", "pypi", "binary"].includes(sourceType),
  };
  for (const [field, target] of authMaps) {
    if (!fieldRelevantToMode[field]) continue;
    const raw = String(data.get(field) || "").trim();
    if (!raw) continue;
    try {
      const parsed = JSON.parse(raw);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new Error(`${field} must be a JSON object`);
      }
      payload[target] = parsed;
    } catch (error) {
      // Wrap the parse error with the field name so the operator
      // knows WHICH field is malformed.
      showError(new Error(`${field}: ${error.message || error}`));
      return;
    }
  }
  // mTLS refs are scalar strings (SecretStore refs), not JSON. Schema
  // validation enforces they must both be set or both unset.
  for (const field of ["mtls_cert_ref", "mtls_key_ref"]) {
    const raw = String(data.get(field) || "").trim();
    if (raw) payload[field] = raw;
  }

  try {
    const created = await api("/api/v1/servers", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    renderCreated(registerOutput,
      `Registered ${created.display_name} (${created.source_type} · ${created.transport})`,
      `id ${created.id}`);
    // Reset the form so a follow-up registration starts clean.
    registerForm.reset();
    document.body.dataset.authMode = "none";
    document.body.dataset.sourceType = "http";
    // Refresh the list and exit the wizard back to the table.
    await loadServers();
    if (typeof wizard !== "undefined") wizard.close();
  } catch (error) {
    renderError(registerOutput, error);
    // Don't close the wizard on failure — operator may want to fix
    // the field and retry. Bring the registerOutput back to surface
    // the error message clearly.
    registerOutput.removeAttribute("hidden");
  }
}

// Auth-mode label for the table column.
function authModeLabel(server) {
  if (server.auth_authcode)   return "OAuth user";
  if (server.auth_jwt_bearer) return "JWT-bearer";
  if (server.auth_oauth)      return "OAuth M2M";
  if (server.auth_passthrough && Object.keys(server.auth_passthrough).length)
                              return "Pass-through";
  if (server.auth_headers && Object.keys(server.auth_headers).length)
                              return "Org headers";
  if (server.auth_env && Object.keys(server.auth_env).length)
                              return "Org env";
  if (server.mtls_cert_ref && server.mtls_key_ref)
                              return "mTLS";
  return "None";
}
function authPillTone(label) {
  if (label === "None") return "pill-neutral";
  if (label === "OAuth user") return "pill-orange";
  if (label === "JWT-bearer" || label === "OAuth M2M") return "pill-info";
  if (label === "Pass-through") return "pill-warn";
  return "pill-orange";
}
function sourcePillFor(s) {
  // Match the design's amber/ocean/neutral split.
  if (s === "http") return ["pill-info", "HTTP"];
  if (s === "npm")  return ["pill-warn", "NPX"];
  if (s === "pypi") return ["pill-warn", "uvx"];
  return ["pill-neutral", s];
}

function renderServers() {
  // Apply current filter + search to the cached server list.
  const needle = SERVER_FILTER.needle;
  const filter = SERVER_FILTER.current;
  const matches = serversCache.filter((s) => {
    if (filter !== "all" && s.source_type !== filter) return false;
    if (!needle) return true;
    const hay = `${s.display_name} ${s.id} ${s.source_type} ${s.transport} `
              + `${authModeLabel(s)} ${s.source_location}`.toLowerCase();
    return hay.includes(needle);
  });

  const countEl = document.querySelector("#servers-count");
  if (countEl) {
    countEl.textContent = matches.length === serversCache.length
      ? `${matches.length} servers`
      : `${matches.length} of ${serversCache.length}`;
  }

  if (!serversCache.length) {
    serversOutput.innerHTML =
      `<div style="padding: 24px; color: var(--vyuu-muted); text-align: center;">`
      + `No servers registered for this tenant. Click <strong>+ Register</strong> above.</div>`;
    return;
  }
  if (!matches.length) {
    serversOutput.innerHTML =
      `<div style="padding: 24px; color: var(--vyuu-muted); text-align: center;">`
      + `(no servers match the current filter)</div>`;
    return;
  }

  serversOutput.innerHTML = "";
  const table = document.createElement("table");
  table.className = "servers-table";
  table.innerHTML = `
    <thead><tr>
      <th>Server</th>
      <th>Runtime</th>
      <th>Auth mode</th>
      <th style="text-align:right;">Tools</th>
      <th>Health</th>
      <th></th>
    </tr></thead>
    <tbody></tbody>`;
  const tbody = table.querySelector("tbody");
  for (const s of matches) tbody.appendChild(renderServerRow(s));
  serversOutput.appendChild(table);
  // Always close any open drawer when re-rendering — the row a drawer
  // belongs to may have been filtered out.
  const drawer = document.querySelector("#server-row-drawer");
  if (drawer) { drawer.hidden = true; drawer.innerHTML = ""; }
}

function renderServerRow(server) {
  const tr = document.createElement("tr");
  tr.dataset.serverId = server.id;

  // Server cell — health dot + name + (id · transport) + drift pill
  const tdName = document.createElement("td");
  const nameWrap = document.createElement("div");
  nameWrap.className = "servers-cell-name";
  const dot = document.createElement("span");
  dot.className = `health-dot ${server.health_status || "unknown"}`;
  nameWrap.appendChild(dot);
  const text = document.createElement("div");
  text.style.minWidth = "0";
  const strong = document.createElement("strong");
  strong.textContent = server.display_name;
  text.appendChild(strong);
  const metaLine = document.createElement("div");
  metaLine.className = "meta-line";
  metaLine.textContent = `${server.id.slice(0, 8)}… · ${server.transport}`;
  text.appendChild(metaLine);
  // Drift summary pill — visible only when the most recent sync
  // saw changes. Click → opens the row drawer scoped to the diff.
  const driftPill = renderDriftPillFor(server);
  if (driftPill) text.appendChild(driftPill);
  nameWrap.appendChild(text);
  tdName.appendChild(nameWrap);
  tr.appendChild(tdName);

  // Runtime pill.
  const tdRuntime = document.createElement("td");
  const [runtimeClass, runtimeLabel] = sourcePillFor(server.source_type);
  tdRuntime.innerHTML = `<span class="pill ${runtimeClass}">${runtimeLabel}</span>`;
  tr.appendChild(tdRuntime);

  // Auth mode pill.
  const tdAuth = document.createElement("td");
  const authLabel = authModeLabel(server);
  tdAuth.innerHTML = `<span class="pill ${authPillTone(authLabel)}">${authLabel}</span>`;
  tr.appendChild(tdAuth);

  // Tool count (mono).
  const tdTools = document.createElement("td");
  tdTools.style.textAlign = "right";
  tdTools.style.fontFamily = "var(--vyuu-mono)";
  tdTools.style.color = "var(--vyuu-ink)";
  // The server response doesn't carry a tool count today; show "—"
  // until we plumb it through.
  // `tool_count` comes from the servers list API. It was previously
  // read as `_tool_count`, which nothing ever set — so this column
  // showed "—" on every row forever, including servers exposing
  // hundreds of tools. `null` still means "never synced".
  tdTools.textContent = server.tool_count != null ? String(server.tool_count) : "—";
  tr.appendChild(tdTools);

  // Health label.
  const tdHealth = document.createElement("td");
  tdHealth.style.textTransform = "capitalize";
  tdHealth.style.color = "var(--vyuu-muted)";
  tdHealth.textContent = server.health_status || "unknown";
  tr.appendChild(tdHealth);

  // Per-row actions.
  const tdActions = document.createElement("td");
  const actions = document.createElement("div");
  actions.className = "row-actions";

  // Drill in first: reading the catalogue is what an operator does
  // before deciding anything else on this row.
  const drillBtn = document.createElement("button");
  drillBtn.type = "button";
  drillBtn.textContent = "Drill in →";
  drillBtn.title = "Tools with their descriptions, risk assessment, and details";
  drillBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    openServerDrawer(server);
  });
  actions.appendChild(drillBtn);

  _attachServerRisk(actions, server);

  const syncBtn = document.createElement("button");
  syncBtn.type = "button";
  syncBtn.textContent = "Sync";
  syncBtn.addEventListener("click", async () => {
    syncBtn.disabled = true;
    syncBtn.textContent = "Syncing…";
    try {
      const result = await api(`/api/v1/servers/${server.id}/sync`, { method: "POST" });
      const advisory = needsAuthAdvisory(server, result)
        ? "Discovery succeeded but tool calls may still require credentials— "
          + "this server has no auth_headers / auth_env / auth_passthrough / "
          + "auth_oauth configured."
        : null;
      renderText(registerOutput, JSON.stringify(result, null, 2), { advisory });
      // Surface a quick inline summary on the row itself so the
      // operator sees confirmation without opening the (hidden)
      // wizard's register-output block.
      showRowSyncToast(tr, `synced · ${result.capability_count || 0} tools`);
      // Sync's response includes added/removed/changed lists — mirror
      // them into the cached server row so the drift pill renders
      // immediately without a separate /servers refetch.
      server.last_sync_drift = {
        synced_at: result.synced_at,
        has_changes:
          (result.added || []).length > 0
          || (result.removed || []).length > 0
          || (result.changed || []).length > 0,
        added: (result.added || []).map((c) => ({
          kind: c.kind, name: c.name, risk_category: c.risk_category || null,
        })),
        removed: (result.removed || []).map((c) => ({
          kind: c.kind, name: c.name, risk_category: c.risk_category || null,
        })),
        changed: (result.changed || []).map((c) => ({
          kind: c.kind, name: c.name, risk_category: c.risk_category || null,
        })),
        unchanged_count: (result.unchanged || []).length,
      };
      renderServers();  // re-paint to pick up the drift pill
    } catch (error) {
      renderError(registerOutput, error);
      // The wizard's `registerOutput` block is hidden; without
      // this, sync failures from a row button were completely
      // invisible. Open the row drawer with the full upstream
      // error so the operator can see exactly what the upstream
      // (or the gateway) reported.
      showRowSyncError(tr, server, error);
    } finally {
      syncBtn.disabled = false;
      syncBtn.textContent = "Sync";
    }
  });
  actions.appendChild(syncBtn);

  // Test-connect — operator-side OAuth Connect for auth_authcode
  // upstreams. Without this, the operator can't sync (needs token),
  // can't grant users (needs synced tools to publish a vserver), and
  // can't get a token (needs vserver access via portal Connect → from
  // a granted user). Test-connect breaks the chicken-and-egg by
  // running OAuth as the operator's underlying portal user, so the
  // operator can register → connect → sync → publish without leaving
  // /operator. Only renders when auth_authcode is set.
  if (server.auth_authcode) {
    const connectBtn = document.createElement("button");
    connectBtn.type = "button";
    connectBtn.textContent = "Test connect";
    connectBtn.title =
      "Authorize this OAuth upstream as your own user (resolved from "
      + "your operator email). Required once before Sync can pull "
      + "capabilities — there's no per-user OAuth token until at least "
      + "one user has connected.";
    connectBtn.addEventListener("click", async () => {
      connectBtn.disabled = true;
      connectBtn.textContent = "Opening…";
      try {
        const r = await api(
          `/api/v1/oauth-authcode/${server.id}/operator-initiate`,
          { method: "POST", body: JSON.stringify({}) },
        );
        // Bounce in a new tab so the operator console keeps state.
        // Callback page renders a self-contained success / failure
        // body with a Close-tab affordance.
        window.open(r.authorization_url, "_blank", "noopener");
        showRowSyncToast(tr,
          "Opened OAuth in new tab — complete consent, then click Sync");
      } catch (error) {
        showRowSyncError(tr, server, error);
      } finally {
        connectBtn.disabled = false;
        connectBtn.textContent = "Test connect";
      }
    });
    actions.appendChild(connectBtn);
  }

  // Per-server sync-cadence override. NULL = use the global default;
  // 0 = manual only (scheduler skips); positive int = throttle to N
  // minutes. We don't expose every minute granularity — operators
  // think in days/weeks for "low-change vendors" and hours for
  // "fast-moving partner APIs".
  const cadenceSelect = document.createElement("select");
  cadenceSelect.className = "cadence-select";
  cadenceSelect.title =
    "Capability-sync cadence override for this server. "
    + "Default uses the global tick. Manual disables auto-sync.";
  const cadenceOptions = [
    { label: "Cadence: Default", value: "" },
    { label: "Hourly", value: "60" },
    { label: "6 hours", value: "360" },
    { label: "Daily", value: "1440" },
    { label: "Weekly", value: "10080" },
    { label: "Manual only", value: "0" },
  ];
  for (const opt of cadenceOptions) {
    const o = document.createElement("option");
    o.value = opt.value;
    o.textContent = opt.label;
    cadenceSelect.appendChild(o);
  }
  // Reflect the currently-persisted value.
  cadenceSelect.value = server.sync_cadence_minutes == null
    ? ""
    : String(server.sync_cadence_minutes);
  cadenceSelect.addEventListener("change", async () => {
    const raw = cadenceSelect.value;
    const payload = raw === "" ? { sync_cadence_minutes: null }
      : { sync_cadence_minutes: parseInt(raw, 10) };
    cadenceSelect.disabled = true;
    try {
      const updated = await api(
        `/api/v1/servers/${server.id}/sync-cadence`,
        { method: "PATCH", body: JSON.stringify(payload) },
      );
      // Update the cached row so subsequent re-renders reflect it.
      server.sync_cadence_minutes = updated.sync_cadence_minutes;
    } catch (error) {
      renderError(registerOutput, error);
      // Revert UI on failure.
      cadenceSelect.value = server.sync_cadence_minutes == null
        ? ""
        : String(server.sync_cadence_minutes);
    } finally {
      cadenceSelect.disabled = false;
    }
  });
  actions.appendChild(cadenceSelect);

  const publishBtn = document.createElement("button");
  publishBtn.type = "button";
  publishBtn.className = "btn-primary";
  publishBtn.textContent = "Publish vserver";
  publishBtn.addEventListener("click", () => toggleRowDrawer(tr, server));
  actions.appendChild(publishBtn);

  // (Per-server debug bundle removed — replaced by the gateway-wide
  // diagnostic bundle on the Dashboard. Per-server context is still
  // accessible via Sync's drift output + the Events panel filtered
  // by upstream_server_id; the gateway-wide bundle is what operators
  // actually need for support tickets.)

  // Delete — destructive, gated behind a confirm. Cascade-summary
  // toast on success surfaces what got cleaned up.
  const deleteBtn = document.createElement("button");
  deleteBtn.type = "button";
  deleteBtn.className = "danger-action";
  deleteBtn.textContent = "Delete";
  deleteBtn.addEventListener("click", async () => {
    // Newline escapes below are doubled (`\\n`) on purpose: this JS
    // file lives inside a Python triple-quoted constant, so a single
    // backslash-n would be eaten by Python as a literal newline and
    // break the JS string literals. The regression test
    // `test_operator_js_parses_under_node_check` catches this at CI.
    const ok = confirm(
      `Delete MCP server "${server.display_name}"?\\n\\n`
      + "This cascades:\\n"
      + "  · its capability catalogue (synced tools)\\n"
      + "  · any virtual-server tool exposures wrapping this server\\n"
      + "  · any per-user OAuth tokens issued to this server\\n\\n"
      + "Vservers that wrapped this server keep existing but with an "
      + "empty tool list. This cannot be undone."
    );
    if (!ok) return;
    deleteBtn.disabled = true;
    deleteBtn.textContent = "Deleting…";
    try {
      const summary = await api(`/api/v1/servers/${server.id}`, { method: "DELETE" });
      const bits = [
        `${summary.capabilities_deleted} capabilities`,
        `${summary.vserver_tool_exposures_removed} tool exposures`,
        `${summary.oauth_user_tokens_revoked} OAuth tokens`,
      ];
      // Refresh the table to drop the row.
      await loadServers();
      // The deleted row is gone, so the toast can't anchor to it.
      // Render a banner above the table instead.
      showServersBanner(
        `✓ deleted ${server.display_name} · `
        + bits.filter((b) => !b.startsWith("0 ")).join(" · "),
      );
    } catch (error) {
      // Re-enable the button so the operator can retry — and surface
      // the error inline (the registerOutput is hidden).
      deleteBtn.disabled = false;
      deleteBtn.textContent = "Delete";
      showRowSyncError(tr, server, error);
    }
  });
  actions.appendChild(deleteBtn);

  tdActions.appendChild(actions);
  tr.appendChild(tdActions);

  return tr;
}

// Render a tiny "+N −M ~K" drift pill for the Server cell. Returns
// null when the persisted last-sync drift is empty / absent.
function renderDriftPillFor(server) {
  const drift = server.last_sync_drift;
  if (!drift || !drift.has_changes) return null;
  const added = (drift.added || []).length;
  const removed = (drift.removed || []).length;
  const changed = (drift.changed || []).length;
  const pill = document.createElement("button");
  pill.type = "button";
  pill.className = "drift-pill";
  // Tone: any added/changed risky tool → danger. Any plain
  // additions → warn. Removed-only → neutral.
  const riskyKinds = ["delete","admin","credential_access","data_export","execute"];
  const isRisky = (entry) => riskyKinds.includes(entry.risk_category);
  const hasRiskyChange =
    (drift.added || []).some(isRisky)
    || (drift.changed || []).some(isRisky);
  if (hasRiskyChange) pill.classList.add("drift-pill-danger");
  else if (added > 0 || changed > 0) pill.classList.add("drift-pill-warn");
  else pill.classList.add("drift-pill-neutral");
  pill.textContent = `+${added} −${removed} ~${changed} since last sync`;
  pill.title = "Click to see what changed in the last capability sync";
  pill.addEventListener("click", (event) => {
    event.stopPropagation();
    const tr = pill.closest("tr");
    if (tr) toggleRowDrawer(tr, server, { mode: "drift" });
  });
  return pill;
}

// Inline confirmation pill anchored to a row — fades in for a few
// seconds, then auto-removes. Replaces the silent-write-to-hidden-
// block path that left operators wondering whether sync did anything.
// Banner above the servers table — used by the Delete flow since the
// row that would have anchored a row-toast is gone by the time the
// success message arrives. Auto-dismisses after a few seconds.
function showServersBanner(message) {
  const wrap = document.querySelector("#servers-output");
  if (!wrap) return;
  const existing = wrap.parentNode.querySelector(".servers-banner");
  if (existing) existing.remove();
  const banner = document.createElement("div");
  banner.className = "servers-banner";
  banner.textContent = message;
  wrap.parentNode.insertBefore(banner, wrap);
  setTimeout(() => banner.remove(), 5000);
}

function showRowSyncToast(tr, message) {
  if (!tr) return;
  const existing = tr.querySelector(".row-toast");
  if (existing) existing.remove();
  const toast = document.createElement("span");
  toast.className = "row-toast row-toast-ok";
  toast.textContent = message;
  // Append into the row's actions cell so it sits next to the buttons.
  const actions = tr.querySelector(".row-actions");
  if (actions) actions.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

// On sync failure, open the row drawer with the full upstream error
// rendered as a code block. Operators can read CrowdStrike's actual
// "Failed to authenticate with the Falcon API" or GitHub's 401
// detail line and act on it.
function showRowSyncError(tr, server, error) {
  toggleRowDrawer(tr, server, { mode: "sync-error" });
  const drawer = document.querySelector("#server-row-drawer");
  if (!drawer) return;
  drawer.innerHTML = "";
  const head = document.createElement("h4");
  head.textContent = `Sync failed — ${server.display_name}`;
  head.style.margin = "0 0 6px";
  drawer.appendChild(head);
  const hint = document.createElement("p");
  hint.className = "hint";
  hint.style.margin = "0 0 10px";
  hint.textContent =
    "The gateway tried to probe this upstream and got an error back. "
    + "If the upstream is auth-gated (auth_authcode / auth_env / auth_oauth), "
    + "the most common cause is invalid credentials or a region "
    + "mismatch in the base URL.";
  drawer.appendChild(hint);
  const pre = document.createElement("pre");
  pre.className = "output";
  pre.style.whiteSpace = "pre-wrap";
  pre.textContent = String(error.message || error);
  drawer.appendChild(pre);
}

// Anchor the shared row drawer below `tr`. If the same row is
// already open, clicking again closes. Single-drawer model means
// there's never visual confusion about which row's tools you're
// publishing.
function toggleRowDrawer(tr, server, opts = {}) {
  const drawer = document.querySelector("#server-row-drawer");
  if (!drawer) return;
  const mode = opts.mode || "publish";  // "publish" | "drift"
  const ownerKey = `${server.id}::${mode}`;
  const wasOwner = drawer.dataset.ownerKey === ownerKey;
  // Always detach + re-attach so we land below the new row.
  drawer.hidden = true;
  drawer.innerHTML = "";
  if (wasOwner) {
    drawer.dataset.ownerKey = "";
    return;
  }
  drawer.dataset.ownerKey = ownerKey;
  drawer.dataset.ownerRow = server.id;
  drawer.hidden = false;
  // Insert directly after the row's containing tbody for layout
  // sanity (tables don't host loose <div> children otherwise).
  // Simplest: append a fake tr+td wrapping the drawer content,
  // spanning all 6 columns.
  const wrapTr = document.createElement("tr");
  wrapTr.className = "row-drawer-anchor";
  wrapTr.dataset.ownerRow = server.id;
  const wrapTd = document.createElement("td");
  wrapTd.colSpan = 6;
  wrapTd.style.padding = "0 16px 14px";
  wrapTd.style.background = "var(--vyuu-ivory)";
  wrapTd.appendChild(drawer);
  wrapTr.appendChild(wrapTd);
  // Remove any previously-injected anchor so only one ever exists.
  for (const old of document.querySelectorAll(".row-drawer-anchor")) old.remove();
  tr.parentElement.insertBefore(wrapTr, tr.nextSibling);
  if (mode === "drift") {
    renderDriftDrawer(drawer, server);
  } else {
    renderPublishDrawer(drawer, server);
  }
}

// Visual diff drawer — shows added / removed / changed tools from the
// most recent capability sync. Risk-toned pills so a `delete_*` row
// added in the last sync stands out.
function renderDriftDrawer(container, server) {
  container.innerHTML = "";
  const drift = server.last_sync_drift;
  if (!drift) {
    container.textContent =
      "No persisted drift on this server. Click Sync to capture one.";
    return;
  }

  const title = document.createElement("h4");
  title.textContent = `Last capability sync — ${server.display_name}`;
  title.style.margin = "0 0 6px";
  container.appendChild(title);

  const subtitle = document.createElement("p");
  subtitle.className = "hint";
  subtitle.style.margin = "0 0 12px";
  const when = drift.synced_at
    ? new Date(drift.synced_at).toLocaleString()
    : "(unknown)";
  const counts = `+${(drift.added||[]).length} added, `
    + `−${(drift.removed||[]).length} removed, `
    + `~${(drift.changed||[]).length} changed, `
    + `${drift.unchanged_count || 0} unchanged.`;
  subtitle.textContent = `Synced ${when}. ${counts}`;
  container.appendChild(subtitle);

  if (!drift.has_changes) {
    const calm = document.createElement("p");
    calm.className = "hint";
    calm.textContent =
      "✓ No drift — the upstream tool catalogue matched the prior sync.";
    container.appendChild(calm);
    return;
  }

  const sections = [
    { label: "Added", entries: drift.added || [], tone: "added" },
    { label: "Changed (schema differs)", entries: drift.changed || [], tone: "changed" },
    { label: "Removed", entries: drift.removed || [], tone: "removed" },
  ];
  for (const sec of sections) {
    if (!sec.entries.length) continue;
    const head = document.createElement("p");
    head.className = "eyebrow";
    head.style.margin = "10px 0 4px";
    head.textContent = `${sec.label.toUpperCase()} · ${sec.entries.length}`;
    container.appendChild(head);
    const list = document.createElement("ul");
    list.className = `drift-list drift-list-${sec.tone}`;
    for (const entry of sec.entries) {
      const li = document.createElement("li");
      const name = document.createElement("span");
      name.className = "drift-list-name";
      name.textContent = entry.name;
      li.appendChild(name);
      if (entry.risk_category && entry.risk_category !== "unknown") {
        const pill = document.createElement("span");
        const danger = ["delete","admin","credential_access","data_export","execute"]
          .includes(entry.risk_category);
        pill.className = `pill pill-${
          danger ? "danger"
          : entry.risk_category === "write" ? "warn" : "info"
        }`;
        pill.textContent = entry.risk_category;
        li.appendChild(pill);
      }
      list.appendChild(li);
    }
    container.appendChild(list);
  }
}

async function renderPublishDrawer(container, server) {
  container.innerHTML = "Loading tools…";
  // Fetch the server's capabilities. If the list is empty we
  // auto-trigger a sync so the operator doesn't have to toggle
  // panels — that was the friction point: previously you had to
  // click Sync, then Show tools, then scroll past the page to the
  // separate vserver-create form.
  let caps;
  try {
    caps = await api(`/api/v1/servers/${server.id}/capabilities`);
    if (!caps.length) {
      container.textContent = "Syncing capabilities from upstream…";
      await api(`/api/v1/servers/${server.id}/sync`, { method: "POST" });
      caps = await api(`/api/v1/servers/${server.id}/capabilities`);
    }
  } catch (error) {
    renderError(container, error);
    return;
  }
  const tools = caps.filter((c) => c.kind === "tool");
  if (!tools.length) {
    container.textContent =
      "(no tools discovered — Sync capabilities first or check upstream credentials)";
    return;
  }

  container.innerHTML = "";

  const title = document.createElement("h4");
  title.textContent = `Publish a virtual server from ${server.display_name}`;
  title.style.margin = "0 0 6px";
  container.appendChild(title);

  const hint = document.createElement("p");
  hint.className = "hint";
  hint.style.margin = "0 0 10px";
  hint.textContent =
    "Pick the tools you want to expose. Rename any of them inline "
    + "to disambiguate collisions or match your team's naming. "
    + "The vserver becomes /v/{tenant}/{name}/mcp once created.";
  container.appendChild(hint);

  const nameRow = document.createElement("label");
  nameRow.style.display = "flex";
  nameRow.style.flexDirection = "column";
  nameRow.style.gap = "4px";
  nameRow.style.fontWeight = "500";
  nameRow.innerHTML =
    `<span>Virtual server name <span class="req">*</span></span>`;
  const nameInput = document.createElement("input");
  nameInput.type = "text";
  nameInput.placeholder = `${server.display_name}-curated`;
  nameInput.required = true;
  nameRow.appendChild(nameInput);
  container.appendChild(nameRow);

  const toolsHead = document.createElement("p");
  toolsHead.className = "eyebrow";
  toolsHead.style.margin = "12px 0 6px";
  toolsHead.textContent = `TOOLS · ${tools.length} discovered`;
  container.appendChild(toolsHead);

  const toolList = document.createElement("div");
  toolList.className = "publish-tool-list";
  for (const tool of tools) {
    // Each row: checkbox + name/risk + inline "rename to" input.
    // Restructured from a single <label> to a <div> so the rename
    // input is its own focus target (clicking the rename input
    // shouldn't toggle the checkbox via implicit label association).
    const row = document.createElement("div");
    row.className = "publish-tool-row";

    const left = document.createElement("label");
    left.className = "publish-tool-row-left";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.value = tool.name;
    cb.checked = true;  // default to all selected; quicker than 0-of-N
    cb.dataset.role = "tool-pick";
    left.appendChild(cb);
    const span = document.createElement("span");
    span.innerHTML =
      `<strong>${escapeHtmlOp(tool.name)}</strong>`
      + (tool.risk_category && tool.risk_category !== "unknown"
          ? ` <span class="pill pill-${
              ["delete","admin","credential_access","data_export","execute"]
                .includes(tool.risk_category) ? "danger"
                : tool.risk_category === "write" ? "warn" : "info"
            }">${escapeHtmlOp(tool.risk_category)}</span>`
          : "");
    left.appendChild(span);
    row.appendChild(left);

    // Rename-to input — empty = no rename, anything else = rename_map
    // entry keyed on the upstream tool name. Lets operators
    // disambiguate collisions across multi-server vservers (the
    // standalone form supports that case; we keep parity here).
    const renameWrap = document.createElement("div");
    renameWrap.className = "publish-tool-row-rename";
    const renameLabel = document.createElement("span");
    renameLabel.className = "publish-tool-row-rename-label";
    renameLabel.textContent = "rename to";
    renameWrap.appendChild(renameLabel);
    const renameInput = document.createElement("input");
    renameInput.type = "text";
    renameInput.placeholder = tool.name;
    renameInput.dataset.role = "tool-rename";
    renameInput.dataset.toolName = tool.name;
    renameInput.spellcheck = false;
    renameInput.autocomplete = "off";
    renameWrap.appendChild(renameInput);
    row.appendChild(renameWrap);

    toolList.appendChild(row);
  }
  container.appendChild(toolList);

  const actions = document.createElement("div");
  actions.style.marginTop = "12px";
  actions.style.display = "flex";
  actions.style.gap = "8px";
  const createBtn = document.createElement("button");
  createBtn.type = "button";
  createBtn.className = "btn-primary";
  createBtn.textContent = "Create virtual server";
  const status = document.createElement("span");
  status.className = "hint";
  status.style.alignSelf = "center";
  actions.appendChild(createBtn);
  actions.appendChild(status);
  container.appendChild(actions);

  createBtn.addEventListener("click", async () => {
    const name = nameInput.value.trim();
    if (!name) {
      status.textContent = "name is required";
      status.style.color = "var(--vyuu-danger-ink)";
      nameInput.focus();
      return;
    }
    const picked = Array.from(
      toolList.querySelectorAll('input[data-role="tool-pick"]:checked'),
    ).map((cb) => ({ server_id: server.id, tool_name: cb.value }));
    if (!picked.length) {
      status.textContent = "pick at least one tool";
      status.style.color = "var(--vyuu-danger-ink)";
      return;
    }
    // Harvest rename_map from the per-row "rename to" inputs.
    // Keyed on the upstream tool name (the resolver also accepts
    // `{server_id}:{tool_name}` keys but we don't need them here —
    // the drawer is single-server). Empty / whitespace inputs are
    // skipped, and a value identical to the original is also
    // skipped so we don't ship a no-op rename.
    const pickedNames = new Set(picked.map((p) => p.tool_name));
    const renameMap = {};
    const renameInputs = toolList.querySelectorAll(
      'input[data-role="tool-rename"]',
    );
    let renameError = "";
    for (const input of renameInputs) {
      const original = input.dataset.toolName;
      if (!pickedNames.has(original)) continue;  // unchecked → skip
      const renamed = (input.value || "").trim();
      if (!renamed || renamed === original) continue;
      // Light client-side guard — server enforces the canonical
      // rule, but a friendly inline error beats a 422 round-trip.
      if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,127}$/.test(renamed)) {
        renameError = `"${renamed}" isn't a valid tool name `
          + "(letters, digits, _ and -, must start with a letter)";
        break;
      }
      renameMap[original] = renamed;
    }
    if (renameError) {
      status.textContent = renameError;
      status.style.color = "var(--vyuu-danger-ink)";
      return;
    }
    createBtn.disabled = true;
    createBtn.textContent = "Creating…";
    try {
      const created = await api("/api/v1/vservers", {
        method: "POST",
        body: JSON.stringify({ name, tools: picked, rename_map: renameMap }),
      });
      status.textContent = `✓ created /v/${created.tenant_id}/${created.name}/mcp`;
      status.style.color = "var(--vyuu-orange-deep)";
      // Auto-refresh the Vservers list so the new row appears when
      // the operator clicks the sidebar.
      if (typeof loadVservers === "function") loadVservers();
    } catch (error) {
      status.textContent = String(error.message || error);
      status.style.color = "var(--vyuu-danger-ink)";
    } finally {
      createBtn.disabled = false;
      createBtn.textContent = "Create virtual server";
    }
  });
}

async function loadCapabilitiesForServer(serverId, displayName) {
  capabilitiesOutput.textContent = `Loading tools for ${displayName}…`;
  try {
    const capabilities = await api(`/api/v1/servers/${serverId}/capabilities`);
    if (!capabilities.length) {
      capabilitiesOutput.textContent =
        `No tools synced yet for ${displayName}. Click Sync `
        + `capabilities on the server row to pull its tool catalogue.`;
      return;
    }
    capabilitiesOutput.replaceChildren(
      ...capabilities.map((cap) => renderCapability(cap, displayName)),
    );
  } catch (error) {
    capabilitiesOutput.innerHTML = "";
    const node = document.createElement("p");
    node.className = "error";
    node.textContent = String(error.message || error);
    capabilitiesOutput.appendChild(node);
  }
}

function renderCapability(capability, serverDisplayName) {
  const card = document.createElement("article");
  card.className = "server-card";
  card.style.display = "flex";
  card.style.gap = "12px";
  card.style.alignItems = "center";

  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.style.width = "20px";
  checkbox.style.minWidth = "20px";
  checkbox.style.height = "20px";
  checkbox.value = `${capability.server_id}:${capability.name}`;
  checkbox.addEventListener("change", () => {
    const lines = vserverToolsField.value.split("\\n").map((s) => s.trim()).filter(Boolean);
    const target = checkbox.value;
    if (checkbox.checked && !lines.includes(target)) {
      lines.push(target);
    } else if (!checkbox.checked) {
      const index = lines.indexOf(target);
      if (index >= 0) lines.splice(index, 1);
    }
    vserverToolsField.value = lines.join("\\n");
  });

  const body = document.createElement("div");
  body.style.flex = "1";
  body.style.minWidth = "0";

  const title = document.createElement("strong");
  title.textContent = `${capability.name}`;
  body.appendChild(title);

  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = `${capability.kind} · ${capability.risk_category} · from ${serverDisplayName}`;
  body.appendChild(meta);

  if (capability.schema_json && capability.schema_json.description) {
    const desc = document.createElement("div");
    desc.className = "meta";
    desc.textContent = String(capability.schema_json.description).slice(0, 200);
    body.appendChild(desc);
  }

  card.appendChild(checkbox);
  card.appendChild(body);
  return card;
}

// --- Virtual servers panel ---------------------------------------------
// Tabular redesign — same shape as the rest of the operator console.
// The list endpoint returns aggregates (tool_count, grant_count) so
// the table renders in one round-trip. Drill-in drawer holds the
// per-vserver Tools / Access / Settings tabs.

const vserversSearch = document.querySelector("#vservers-search");
const vserversCount = document.querySelector("#vservers-count");

let vserversCache = [];
const vserversPillState = { current: "all" };

if (vserversSearch) vserversSearch.addEventListener("input", () => renderVservers());
for (const pill of document.querySelectorAll("[data-vservers-pill]")) {
  pill.addEventListener("click", () => {
    vserversPillState.current = pill.dataset.vserversPill;
    for (const p of document.querySelectorAll("[data-vservers-pill]")) {
      p.classList.toggle("is-active", p === pill);
    }
    renderVservers();
  });
}

async function loadVservers() {
  vserversOutput.innerHTML =
    '<tr><td colspan="7" class="events-empty">Loading…</td></tr>';
  try {
    vserversCache = await api("/api/v1/vservers");
    renderVservers();
  } catch (error) {
    vserversOutput.innerHTML = "";
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 7;
    td.className = "events-empty";
    td.textContent = String(error.message || error);
    tr.appendChild(td);
    vserversOutput.appendChild(tr);
  }
}

function renderVservers() {
  renderVserversKpis(vserversCache);

  const needle = (vserversSearch && vserversSearch.value || "").trim().toLowerCase();
  const pill = vserversPillState.current;
  const filtered = vserversCache.filter((v) => {
    if (needle && !v.name.toLowerCase().includes(needle)) return false;
    if (pill === "public") return v.visibility === "public";
    if (pill === "private") return v.visibility !== "public";
    if (pill === "has_grants") return (v.grant_count || 0) > 0;
    if (pill === "empty") return (v.tool_count || 0) === 0;
    return true;
  });

  vserversCount.textContent =
    filtered.length === vserversCache.length
      ? `${filtered.length} vservers`
      : `${filtered.length} of ${vserversCache.length} vservers`;

  vserversOutput.innerHTML = "";
  if (!filtered.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 7;
    td.className = "events-empty";
    td.textContent = vserversCache.length === 0
      ? "No virtual servers published yet. Sync capabilities on a registered "
        + "MCP server, then click + New vserver to publish a curated bundle."
      : `(0 of ${vserversCache.length} vservers match the active filter)`;
    tr.appendChild(td);
    vserversOutput.appendChild(tr);
    return;
  }
  for (const v of filtered) {
    vserversOutput.appendChild(renderVserverRow(v));
  }
}

function renderVserversKpis(rows) {
  let total = 0;
  let empty = 0;
  let priv = 0;
  let pub = 0;
  for (const v of rows) {
    total++;
    if ((v.tool_count || 0) === 0) empty++;
    if (v.visibility === "public") pub++;
    else priv++;
  }
  const set = (id, v) => {
    const el = document.querySelector(`#${id}`);
    if (el) el.textContent = v;
  };
  set("vservers-kpi-total", total.toLocaleString());
  set("vservers-kpi-empty", empty.toLocaleString());
  set("vservers-kpi-private", priv.toLocaleString());
  set("vservers-kpi-public", pub.toLocaleString());
}

// JIT-1 · configure a vserver's just-in-time policy.
//
// A prompt chain rather than a modal: this is a rarely-touched policy
// control, and the three questions it asks (how long, who approves,
// reason required) are exactly the three fields. A modal here would be
// more chrome than the decision warrants — revisit if per-tool JIT
// (JIT-2) adds a fourth axis.
// JIT configuration lives in the vserver drill-in, not the table row.
//
// It used to be three chained `confirm()`/`prompt()` dialogs plus a
// `name=minutes` textarea. That was wrong for the task in two ways: a
// chain of modal prompts cannot be reviewed before committing (answer
// question two and question one is already gone), and it cannot show
// which tools the bundle actually publishes — so the operator was
// typing tool names from memory into a free-text box that failed only
// after submit. Here every gated tool is picked from the real
// allowlist, and the whole policy is visible at once before Save.

function _jitField(labelText, hintText) {
  const wrap = document.createElement("label");
  wrap.style.display = "block";
  wrap.style.marginBottom = "12px";
  const label = document.createElement("span");
  label.style.display = "block";
  label.style.font = "500 12px/1.4 var(--vyuu-sans)";
  label.style.color = "var(--vyuu-ink)";
  label.textContent = labelText;
  if (hintText) label.title = hintText;
  wrap.appendChild(label);
  return wrap;
}

function _jitCheckbox(labelText, checked, hintText) {
  const row = document.createElement("label");
  row.style.display = "flex";
  row.style.alignItems = "flex-start";
  row.style.gap = "8px";
  row.style.marginBottom = "10px";
  row.style.cursor = "pointer";
  if (hintText) row.title = hintText;
  const box = document.createElement("input");
  box.type = "checkbox";
  box.checked = !!checked;
  box.style.marginTop = "2px";
  const text = document.createElement("span");
  text.style.font = "400 12.5px/1.45 var(--vyuu-sans)";
  text.style.color = "var(--vyuu-ink)";
  text.textContent = labelText;
  row.appendChild(box);
  row.appendChild(text);
  row.input = box;
  return row;
}

function _jitSectionTitle(text, hint) {
  const el = document.createElement("p");
  el.className = "eyebrow";
  el.style.margin = "0 0 8px";
  el.textContent = text;
  if (hint) el.title = hint;
  return el;
}

async function renderVserverDrawerJit(container, vserver, ticket) {
  if (vserverDrawerRenderIsStale(ticket)) return;
  container.innerHTML = "";

  if (vserver.visibility === "public") {
    const note = document.createElement("p");
    note.className = "events-empty";
    note.textContent =
      "Public bundle — every user in the tenant already reaches it, so "
      + "there is no standing grant to elevate above. Make it private on "
      + "the Access tab first.";
    container.appendChild(note);
    return;
  }

  // --- Bundle-level elevation ------------------------------------------
  container.appendChild(_jitSectionTitle(
    "BUNDLE ELEVATION",
    "Whether users can request temporary access to the whole bundle."));

  const enable = _jitCheckbox(
    "Users can request temporary access to this bundle",
    vserver.jit_enabled,
    "Off means access is standing-grant only. Elevations already issued "
    + "keep running until they expire.");
  container.appendChild(enable);

  const maxField = _jitField(
    "Longest elevation (minutes)",
    "Requests above this are rejected outright, not silently shortened.");
  const maxInput = document.createElement("input");
  maxInput.type = "number";
  maxInput.min = "1";
  maxInput.value = String(Math.round(
    (vserver.jit_max_duration_seconds || 4 * 3600) / 60));
  maxInput.style.width = "120px";
  maxInput.style.marginTop = "4px";
  maxInput.title = "Requests above this are rejected outright, not shortened.";
  maxField.appendChild(maxInput);
  container.appendChild(maxField);

  const auto = _jitCheckbox(
    "Approve automatically",
    vserver.jit_auto_approve,
    "On: users self-serve immediately — still time-boxed, still audited. "
    + "Off: every request waits in the approval queue.");
  container.appendChild(auto);

  const justify = _jitCheckbox(
    "Require a written reason",
    vserver.jit_require_justification,
    "The reason is what an auditor reads six months later. Recommended.");
  container.appendChild(justify);

  const bundleStatus = document.createElement("span");
  bundleStatus.style.marginLeft = "10px";
  bundleStatus.style.font = "400 11.5px/1 var(--vyuu-sans)";
  bundleStatus.style.color = "var(--vyuu-muted)";

  const saveBundle = document.createElement("button");
  saveBundle.type = "button";
  saveBundle.className = "vservers-row-url-copy";
  saveBundle.textContent = "Save";
  saveBundle.addEventListener("click", async () => {
    const minutes = Number(maxInput.value);
    if (!Number.isFinite(minutes) || minutes <= 0) {
      bundleStatus.textContent = "Enter a positive number of minutes.";
      return;
    }
    saveBundle.disabled = true;
    bundleStatus.textContent = "Saving…";
    try {
      const updated = await api(
        `/api/v1/vservers/${encodeURIComponent(vserver.id)}/jit`,
        {
          method: "PATCH",
          body: JSON.stringify({
            enabled: enable.input.checked,
            max_duration_seconds: Math.round(minutes * 60),
            auto_approve: auto.input.checked,
            require_justification: justify.input.checked,
          }),
        });
      // Keep the in-memory row in step so reopening the drawer (or
      // re-rendering the table) does not show the pre-save state.
      vserver.jit_enabled = updated.jit_enabled;
      vserver.jit_max_duration_seconds = updated.jit_max_duration_seconds;
      vserver.jit_auto_approve = updated.jit_auto_approve;
      vserver.jit_require_justification = updated.jit_require_justification;
      bundleStatus.textContent = "Saved.";
      await loadVservers();
    } catch (error) {
      bundleStatus.textContent = String(error);
    } finally {
      saveBundle.disabled = false;
    }
  });

  const bundleBar = document.createElement("div");
  bundleBar.style.margin = "4px 0 20px";
  bundleBar.appendChild(saveBundle);
  bundleBar.appendChild(bundleStatus);
  container.appendChild(bundleBar);

  // --- JIT-2 · per-tool elevation ---------------------------------------
  const toolsTitle = _jitSectionTitle(
    "ELEVATION-GATED TOOLS",
    "These need their own elevation even for users who already hold the "
    + "bundle. Independent of the toggle above.");
  toolsTitle.style.borderTop = "1px solid var(--vyuu-line-soft)";
  toolsTitle.style.paddingTop = "16px";
  container.appendChild(toolsTitle);

  const toolsHint = document.createElement("p");
  toolsHint.style.font = "400 12px/1.5 var(--vyuu-sans)";
  toolsHint.style.color = "var(--vyuu-muted)";
  toolsHint.style.margin = "0 0 10px";
  toolsHint.textContent =
    "Set a ceiling in minutes to gate a tool. Leave blank to leave it open.";
  container.appendChild(toolsHint);

  const toolsBox = document.createElement("div");
  toolsBox.textContent = "Loading tools…";
  container.appendChild(toolsBox);

  let tools = [];
  try {
    tools = await api(`/api/v1/vservers/${encodeURIComponent(vserver.id)}/tools`);
  } catch (error) {
    if (!vserverDrawerRenderIsStale(ticket)) renderError(toolsBox, error);
    return;
  }
  if (vserverDrawerRenderIsStale(ticket)) return;

  const current = vserver.jit_tools || {};
  toolsBox.innerHTML = "";
  if (!tools.length) {
    const empty = document.createElement("p");
    empty.className = "events-empty";
    empty.textContent =
      "This bundle publishes no tools yet, so there is nothing to gate.";
    toolsBox.appendChild(empty);
    return;
  }

  // Gate by the EXPOSED name, not the upstream one. `jit_tools` is
  // matched against `resolved_tool.exposed_name` at call time, so a
  // renamed tool gated under its upstream name would gate nothing —
  // the caller invokes `warehouse_query`, never `query`. The tools
  // endpoint returns upstream names only, so apply the rename here.
  const renames = vserver.rename_map || {};
  const inputs = new Map();
  for (const t of tools) {
    const upstreamName = t.tool_name;
    const name = renames[upstreamName] || upstreamName;
    const row = document.createElement("div");
    row.style.display = "flex";
    row.style.alignItems = "center";
    row.style.justifyContent = "space-between";
    row.style.gap = "10px";
    row.style.padding = "6px 10px";
    row.style.border = "1px solid var(--vyuu-line)";
    row.style.borderRadius = "var(--vyuu-r-sm)";
    row.style.marginBottom = "4px";

    const label = document.createElement("code");
    label.style.font = "var(--vyuu-mono-sm)";
    label.style.color = "var(--vyuu-ink)";
    label.textContent = name;
    if (name !== upstreamName) {
      // Say what it was, or a renamed tool is unrecognisable to the
      // operator who published it.
      label.title = `exposed as ${name} · upstream ${upstreamName}`;
      const from = document.createElement("small");
      from.style.font = "400 10.5px/1 var(--vyuu-sans)";
      from.style.color = "var(--vyuu-muted)";
      from.style.marginLeft = "6px";
      from.textContent = `← ${upstreamName}`;
      label.appendChild(from);
    }
    row.appendChild(label);

    const right = document.createElement("span");
    right.style.display = "flex";
    right.style.alignItems = "center";
    right.style.gap = "6px";
    const box = document.createElement("input");
    box.type = "number";
    box.min = "1";
    box.placeholder = "open";
    box.style.width = "84px";
    box.title = `Minutes of elevation granted for ${name}. Blank = not gated.`;
    if (current[name]) box.value = String(Math.round(current[name] / 60));
    const unit = document.createElement("span");
    unit.style.font = "400 11px/1 var(--vyuu-sans)";
    unit.style.color = "var(--vyuu-muted)";
    unit.textContent = "min";
    right.appendChild(box);
    right.appendChild(unit);
    row.appendChild(right);

    inputs.set(name, box);
    toolsBox.appendChild(row);
  }

  const toolsStatus = document.createElement("span");
  toolsStatus.style.marginLeft = "10px";
  toolsStatus.style.font = "400 11.5px/1 var(--vyuu-sans)";
  toolsStatus.style.color = "var(--vyuu-muted)";

  const saveTools = document.createElement("button");
  saveTools.type = "button";
  saveTools.className = "vservers-row-url-copy";
  saveTools.textContent = "Save gated tools";
  saveTools.addEventListener("click", async () => {
    const jitTools = {};
    for (const [name, box] of inputs) {
      const raw = box.value.trim();
      if (!raw) continue;
      const minutes = Number(raw);
      if (!Number.isFinite(minutes) || minutes <= 0) {
        toolsStatus.textContent = `${name}: enter a positive number of minutes.`;
        return;
      }
      jitTools[name] = Math.round(minutes * 60);
    }
    saveTools.disabled = true;
    toolsStatus.textContent = "Saving…";
    try {
      const updated = await api(
        `/api/v1/vservers/${encodeURIComponent(vserver.id)}/jit-tools`,
        { method: "PATCH", body: JSON.stringify({ jit_tools: jitTools }) });
      vserver.jit_tools = updated.jit_tools || {};
      const n = Object.keys(vserver.jit_tools).length;
      toolsStatus.textContent = n
        ? `Saved — ${n} tool${n === 1 ? "" : "s"} gated.`
        : "Saved — nothing gated.";
      await loadVservers();
      if (typeof loadActiveElevations === "function") await loadActiveElevations();
    } catch (error) {
      toolsStatus.textContent = String(error);
    } finally {
      saveTools.disabled = false;
    }
  });

  const toolsBar = document.createElement("div");
  toolsBar.style.marginTop = "10px";
  toolsBar.appendChild(saveTools);
  toolsBar.appendChild(toolsStatus);
  container.appendChild(toolsBar);
}

function renderVserverRow(vserver) {
  const tr = document.createElement("tr");
  if ((vserver.tool_count || 0) === 0) tr.dataset.state = "empty";
  tr.addEventListener("click", () => openVserverDrawer(vserver));

  // VSERVER — visibility pill + name + truncated id
  const nameCell = document.createElement("td");
  const wrap = document.createElement("div");
  wrap.className = "vservers-row-name";
  const line = document.createElement("span");
  line.className = "vservers-row-name-line";
  const visPill = document.createElement("span");
  visPill.className = "vservers-visibility-pill";
  visPill.dataset.visibility = vserver.visibility;
  visPill.textContent = vserver.visibility;
  line.appendChild(visPill);
  line.appendChild(document.createTextNode(vserver.name));
  wrap.appendChild(line);
  const idLine = document.createElement("span");
  idLine.className = "vservers-row-id";
  idLine.textContent = vserver.id.slice(0, 8) + "…";
  wrap.appendChild(idLine);
  nameCell.appendChild(wrap);
  tr.appendChild(nameCell);

  // URL — copyable, ellipsis-truncated
  const urlCell = document.createElement("td");
  const urlRow = document.createElement("div");
  urlRow.className = "vservers-row-url";
  const fullUrl =
    `${window.location.origin}/v/${vserver.tenant_id}/${vserver.name}/mcp`;
  const code = document.createElement("code");
  code.textContent = fullUrl;
  code.title = fullUrl;
  urlRow.appendChild(code);
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "vservers-row-url-copy";
  copy.textContent = "Copy";
  copy.addEventListener("click", (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(fullUrl).then(
      () => {
        copy.textContent = "Copied";
        copy.dataset.copied = "true";
        setTimeout(() => {
          copy.textContent = "Copy";
          delete copy.dataset.copied;
        }, 1200);
      },
      () => { copy.textContent = "Failed"; },
    );
  });
  urlRow.appendChild(copy);
  urlCell.appendChild(urlRow);
  tr.appendChild(urlCell);

  // TOOLS count
  const toolsCell = document.createElement("td");
  toolsCell.className = "vservers-row-tools";
  const toolsSpan = document.createElement("span");
  toolsSpan.className = "users-count-cell";
  if ((vserver.tool_count || 0) === 0) toolsSpan.classList.add("is-zero");
  toolsSpan.textContent = String(vserver.tool_count || 0);
  toolsCell.appendChild(toolsSpan);
  tr.appendChild(toolsCell);

  // GRANTS count
  const grantsCell = document.createElement("td");
  grantsCell.className = "vservers-row-grants";
  const grantsSpan = document.createElement("span");
  grantsSpan.className = "users-count-cell";
  if ((vserver.grant_count || 0) === 0) grantsSpan.classList.add("is-zero");
  grantsSpan.textContent = String(vserver.grant_count || 0);
  grantsCell.appendChild(grantsSpan);
  tr.appendChild(grantsCell);

  // JIT — READ-ONLY. Configuration moved to the drill-in, but the state
  // stayed here: "which bundles allow temporary access?" is a scanning
  // question, and making it cost one drill-in per row turned a glance
  // into an audit. No buttons — click Drill in to change any of it.
  const jitCell = document.createElement("td");
  const jitBadge = document.createElement("span");
  jitBadge.className = "vserver-jit-badge";
  const isPublic = vserver.visibility === "public";
  const gatedCount = Object.keys(vserver.jit_tools || {}).length;

  const state = document.createElement("span");
  if (isPublic) {
    // Public bundles need no grant, so there is nothing to elevate
    // above. Showing "off" would imply a control that could be turned
    // on; "n/a" says the question does not apply.
    jitBadge.dataset.on = "false";
    jitBadge.dataset.na = "true";
    state.textContent = "n/a";
    jitBadge.title = "Public bundle — no standing grant to elevate above.";
  } else if (vserver.jit_enabled) {
    jitBadge.dataset.on = "true";
    // NOT `window` — that shadows the global inside this block, which
    // is legal and quietly breaks anything here that reaches for it.
    const ceiling = formatDuration(vserver.jit_max_duration_seconds);
    state.textContent = vserver.jit_auto_approve
      ? `auto · ≤${ceiling}`
      : `review · ≤${ceiling}`;
    jitBadge.title = vserver.jit_auto_approve
      ? `Users self-serve a temporary grant, up to ${ceiling}. Still audited.`
      : `Users request a temporary grant, up to ${ceiling}. An operator approves.`;
  } else {
    jitBadge.dataset.on = "false";
    state.textContent = "off";
    jitBadge.title = "Access to this bundle is standing-grant only.";
  }
  jitBadge.appendChild(state);

  // Per-tool gating is independent of the bundle toggle — the common
  // case is standing bundle access with one dangerous tool gated — so
  // it has to show even when the state above reads "off".
  if (gatedCount) {
    const gated = document.createElement("span");
    gated.className = "vserver-jit-gated";
    gated.textContent = `${gatedCount} gated`;
    gated.title = `${gatedCount} tool${gatedCount === 1 ? "" : "s"} on this `
      + "bundle need their own elevation, whatever the bundle setting says.";
    jitBadge.appendChild(gated);
  }

  jitCell.appendChild(jitBadge);
  tr.appendChild(jitCell);

  // CREATED
  const createdCell = document.createElement("td");
  createdCell.style.color = "var(--vyuu-muted)";
  createdCell.style.fontSize = "11.5px";
  createdCell.textContent = formatRelativeTime(vserver.created_at);
  createdCell.title = new Date(vserver.created_at).toLocaleString();
  tr.appendChild(createdCell);

  // ACTIONS — drill-in
  const actionsCell = document.createElement("td");
  const actions = document.createElement("div");
  actions.className = "users-row-actions";
  const drill = document.createElement("button");
  drill.type = "button";
  drill.textContent = "Drill in →";
  drill.addEventListener("click", (e) => {
    e.stopPropagation();
    openVserverDrawer(vserver);
  });
  actions.appendChild(drill);
  actionsCell.appendChild(actions);
  tr.appendChild(actionsCell);

  return tr;
}

// ---------- Vserver drawer (slide-over) -------------------------------
// --- MCP server drill-in --------------------------------------------------
//
// The tool catalogue was previously reachable only from inside the
// Publish-vserver flow. That is the wrong moment: an operator deciding
// WHETHER to publish needs to read the descriptions first, and those
// descriptions are also where a hostile upstream would hide
// instructions aimed at the calling model. This shows the same surface
// an MCP client sees on `tools/list`.

const _serverDrawer = {
  el: () => document.querySelector("#server-drawer"),
  body: () => document.querySelector("#server-drawer-body"),
  title: () => document.querySelector("#server-drawer-title"),
  sub: () => document.querySelector("#server-drawer-sub"),
  currentServer: null,
  currentTab: "tools",
  capabilities: null,
};

let _serverDrawerRender = 0;

function serverDrawerRenderIsStale(ticket) {
  return ticket !== _serverDrawerRender;
}

function openServerDrawer(server) {
  _serverDrawer.currentServer = server;
  // Cached per open, not per tab: switching tabs must not re-fetch a
  // 190-capability catalogue.
  _serverDrawer.capabilities = null;
  _serverDrawer.title().textContent = server.display_name;
  _serverDrawer.sub().textContent = [
    server.source_type,
    server.transport,
    server.tool_count != null ? `${server.tool_count} tools` : "never synced",
    server.health_status || "unknown",
  ].join(" · ");
  _serverDrawer.el().hidden = false;
  document.body.style.overflow = "hidden";
  switchServerDrawerTab("tools");
}

function closeServerDrawer() {
  _serverDrawer.el().hidden = true;
  _serverDrawer.body().innerHTML = "";
  document.body.style.overflow = "";
}

function switchServerDrawerTab(tab) {
  _serverDrawer.currentTab = tab;
  const ticket = ++_serverDrawerRender;
  for (const t of document.querySelectorAll("[data-server-drawer-tab]")) {
    t.classList.toggle("is-active", t.dataset.serverDrawerTab === tab);
  }
  const body = _serverDrawer.body();
  body.innerHTML = "Loading…";
  const srv = _serverDrawer.currentServer;
  if (tab === "tools") renderServerDrawerTools(body, srv, ticket);
  else if (tab === "risk") renderServerDrawerRisk(body, srv, ticket);
  else renderServerDrawerDetails(body, srv);
}

{
  for (const el of document.querySelectorAll("[data-server-drawer-close]")) {
    el.addEventListener("click", closeServerDrawer);
  }
  for (const tab of document.querySelectorAll("[data-server-drawer-tab]")) {
    tab.addEventListener("click", () => switchServerDrawerTab(tab.dataset.serverDrawerTab));
  }
  document.addEventListener("keydown", (e) => {
    const drawer = _serverDrawer.el();
    if (e.key === "Escape" && drawer && !drawer.hidden) closeServerDrawer();
  });
}

async function _serverCapabilities(server) {
  if (_serverDrawer.capabilities) return _serverDrawer.capabilities;
  const rows = await api(
    `/api/v1/servers/${encodeURIComponent(server.id)}/capabilities`);
  _serverDrawer.capabilities = Array.isArray(rows) ? rows : (rows.items || []);
  return _serverDrawer.capabilities;
}

function _capDescription(cap) {
  const schema = cap.schema_json || {};
  // Tools carry `description`; resources often carry only a display
  // `name` and a mimeType. Fall back so a resource row is not blank.
  return schema.description
    || (cap.kind !== "tool" && schema.name ? schema.name : "")
    || "";
}

async function renderServerDrawerTools(container, server, ticket) {
  container.innerHTML = "Loading…";
  let caps;
  try {
    caps = await _serverCapabilities(server);
  } catch (error) {
    if (!serverDrawerRenderIsStale(ticket)) renderError(container, error);
    return;
  }
  if (serverDrawerRenderIsStale(ticket)) return;
  container.innerHTML = "";

  const live = caps.filter((c) => !c.deprecated);
  if (!live.length) {
    const empty = document.createElement("p");
    empty.className = "events-empty";
    empty.textContent = "No capabilities synced yet. Click Sync on the server "
      + "row to pull the live catalogue.";
    container.appendChild(empty);
    return;
  }

  const bar = document.createElement("div");
  bar.className = "cap-toolbar";
  const search = document.createElement("input");
  search.type = "search";
  search.placeholder = "Search name or description…";
  const kindSel = document.createElement("select");
  const kinds = ["all", ...Array.from(new Set(live.map((c) => c.kind))).sort()];
  for (const k of kinds) {
    const o = document.createElement("option");
    o.value = k;
    o.textContent = k === "all" ? `All (${live.length})`
      : `${k} (${live.filter((c) => c.kind === k).length})`;
    kindSel.appendChild(o);
  }
  const schemaToggle = document.createElement("label");
  schemaToggle.style.display = "inline-flex";
  schemaToggle.style.alignItems = "center";
  schemaToggle.style.gap = "5px";
  schemaToggle.style.font = "400 11.5px/1 var(--vyuu-sans)";
  schemaToggle.style.color = "var(--vyuu-muted)";
  const schemaBox = document.createElement("input");
  schemaBox.type = "checkbox";
  schemaToggle.append(schemaBox, document.createTextNode("show schemas"));
  const count = document.createElement("span");
  count.className = "toolbar-meta";
  bar.append(search, kindSel, schemaToggle, count);
  container.appendChild(bar);

  const list = document.createElement("div");
  container.appendChild(list);

  const render = () => {
    const q = search.value.trim().toLowerCase();
    const kind = kindSel.value;
    const rows = live.filter((c) => {
      if (kind !== "all" && c.kind !== kind) return false;
      if (!q) return true;
      return c.name.toLowerCase().includes(q)
        || _capDescription(c).toLowerCase().includes(q);
    });
    count.textContent = rows.length === live.length
      ? `${live.length} capabilities`
      : `${rows.length} of ${live.length}`;
    list.innerHTML = "";
    for (const cap of rows.slice().sort((a, b) =>
        a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name))) {
      const card = document.createElement("div");
      card.className = "cap-card";

      const head = document.createElement("div");
      head.className = "cap-head";
      const name = document.createElement("code");
      name.className = "cap-name";
      name.textContent = cap.name;
      const right = document.createElement("span");
      right.style.display = "flex";
      right.style.gap = "6px";
      right.style.alignItems = "center";
      if (cap.risk_category && cap.risk_category !== "unknown") {
        const risk = document.createElement("span");
        risk.className = "vserver-jit-gated";
        risk.textContent = cap.risk_category;
        risk.title = "Risk category assigned by the capability classifier "
          + "from the tool name and description.";
        right.appendChild(risk);
      }
      const kindPill = document.createElement("span");
      kindPill.className = "cap-kind";
      kindPill.textContent = cap.kind;
      right.appendChild(kindPill);
      head.append(name, right);
      card.appendChild(head);

      const desc = document.createElement("p");
      desc.className = "cap-desc";
      const text = _capDescription(cap);
      if (text) {
        desc.textContent = text;
      } else {
        // Worth calling out rather than leaving blank: a tool with no
        // description is one the calling model has to guess at.
        desc.dataset.empty = "true";
        desc.textContent = "(no description — the calling model sees only "
          + "the name and schema)";
      }
      card.appendChild(desc);

      if (schemaBox.checked) {
        const schema = document.createElement("pre");
        schema.className = "cap-schema";
        schema.textContent = JSON.stringify(cap.schema_json || {}, null, 2);
        card.appendChild(schema);
      }
      list.appendChild(card);
    }
  };
  search.addEventListener("input", render);
  kindSel.addEventListener("change", render);
  schemaBox.addEventListener("change", render);
  render();
}

async function renderServerDrawerRisk(container, server, ticket) {
  container.innerHTML = "Loading…";
  let data = null;
  try {
    data = await api(
      `/api/v1/servers/${encodeURIComponent(server.id)}/risk-assessment`);
  } catch { data = null; }
  if (serverDrawerRenderIsStale(ticket)) return;
  container.innerHTML = "";

  const run = document.createElement("button");
  run.type = "button";
  run.className = "vservers-row-url-copy";
  run.textContent = data ? "Re-assess" : "Assess risk";
  const status = document.createElement("span");
  status.className = "toolbar-meta";
  status.style.marginLeft = "10px";
  run.addEventListener("click", async () => {
    run.disabled = true;
    status.textContent = "Assessing… this calls the configured model.";
    try {
      await api(`/api/v1/servers/${encodeURIComponent(server.id)}/risk-assessment`,
                { method: "POST" });
      await renderServerDrawerRisk(container, server, ticket);
      return;
    } catch (error) {
      status.textContent = String(error);
    } finally { run.disabled = false; }
  });

  if (!data) {
    const empty = document.createElement("p");
    empty.className = "events-empty";
    empty.style.textAlign = "left";
    empty.textContent = "Not assessed yet.";
    container.append(empty, run, status);
    return;
  }

  const head = document.createElement("div");
  head.style.marginBottom = "8px";
  head.appendChild(riskBand(data.band, data.normalised));
  const meta = document.createElement("span");
  meta.style.marginLeft = "10px";
  meta.style.font = "400 11.5px/1 var(--vyuu-sans)";
  meta.style.color = "var(--vyuu-muted)";
  meta.textContent = `${data.model_id} · ${data.finding_count} finding(s) · `
    + `confidence ${data.confidence}`;
  head.appendChild(meta);
  container.appendChild(head);

  if (data.stale) container.appendChild(staleRiskBanner(data));

  if (data.summary) {
    const sum = document.createElement("p");
    sum.style.font = "400 12.5px/1.55 var(--vyuu-sans)";
    sum.style.margin = "0 0 12px";
    sum.textContent = data.summary;
    container.appendChild(sum);
  }
  const bar = document.createElement("div");
  bar.style.marginBottom = "14px";
  bar.append(run, status);
  container.appendChild(bar);

  for (const f of (data.findings || []).slice().sort((a, b) => b.risk - a.risk)) {
    const card = document.createElement("div");
    card.className = "cap-card";
    const h = document.createElement("div");
    h.className = "cap-head";
    const t = document.createElement("span");
    t.style.font = "500 12.5px/1.4 var(--vyuu-sans)";
    t.textContent = f.title;
    const meta2 = document.createElement("span");
    meta2.style.font = "var(--vyuu-mono-sm)";
    meta2.style.color = "var(--vyuu-muted)";
    meta2.style.flex = "0 0 auto";
    meta2.textContent = `${f.owasp_mcp} · R=${f.risk}`;
    meta2.title = `${f.owasp_title || ""} · likelihood ${f.likelihood} × `
      + `impact ${f.impact}`;
    h.append(t, meta2);
    card.appendChild(h);
    if ((f.affected_tools || []).length) {
      const tools = document.createElement("code");
      tools.className = "cap-name";
      tools.style.display = "block";
      tools.style.marginTop = "4px";
      tools.textContent = f.affected_tools.join(", ");
      card.appendChild(tools);
    }
    // The quote is the point: it is what makes the finding checkable.
    const ev = document.createElement("p");
    ev.className = "cap-desc";
    ev.textContent = `“${f.evidence}”`;
    card.appendChild(ev);
    if (f.mitigation) {
      const mit = document.createElement("p");
      mit.className = "risk-note";
      mit.style.margin = "8px 0 0";
      mit.textContent = f.mitigation;
      card.appendChild(mit);
    }
    container.appendChild(card);
  }
  container.appendChild(riskNote(data.evidence_basis));
}

function renderServerDrawerDetails(container, server) {
  container.innerHTML = "";
  const rows = [
    ["Runtime", server.source_type],
    ["Transport", server.transport],
    ["Source", server.source_location],
    ["Health", server.health_status || "unknown"],
    ["Last sync", server.last_capabilities_pulled_at
      ? new Date(server.last_capabilities_pulled_at).toLocaleString()
      : "never"],
    ["Tools", server.tool_count != null ? String(server.tool_count) : "never synced"],
    ["Registered", new Date(server.registered_at).toLocaleString()],
    ["Server id", server.id],
  ];
  for (const [label, value] of rows) {
    const row = document.createElement("div");
    row.className = "cap-card";
    row.style.display = "flex";
    row.style.justifyContent = "space-between";
    row.style.gap = "12px";
    const l = document.createElement("span");
    l.style.font = "500 12px/1.4 var(--vyuu-sans)";
    l.textContent = label;
    const v = document.createElement("code");
    v.className = "cap-name";
    v.textContent = String(value ?? "—");
    row.append(l, v);
    container.appendChild(row);
  }
}

const _vserverDrawer = {
  el: () => document.querySelector("#vserver-drawer"),
  body: () => document.querySelector("#vserver-drawer-body"),
  title: () => document.querySelector("#vserver-drawer-title"),
  sub: () => document.querySelector("#vserver-drawer-sub"),
  currentVserver: null,
  currentTab: "tools",
};

function openVserverDrawer(vserver) {
  _vserverDrawer.currentVserver = vserver;
  _vserverDrawer.title().textContent = vserver.name;
  const parts = [
    vserver.visibility,
    `${vserver.tool_count || 0} tools`,
    `${vserver.grant_count || 0} grants`,
    `created ${formatRelativeTime(vserver.created_at)}`,
  ];
  _vserverDrawer.sub().textContent = parts.join(" · ");
  _vserverDrawer.el().hidden = false;
  document.body.style.overflow = "hidden";
  switchVserverDrawerTab("tools");
}

function closeVserverDrawer() {
  _vserverDrawer.el().hidden = true;
  _vserverDrawer.body().innerHTML = "";
  document.body.style.overflow = "";
}

// Every tab renderer is async and they all write into ONE container,
// so a slower earlier render can land on top of a faster later one —
// opening the drawer (which renders Tools) and immediately clicking
// another tab left the wrong body with the new tab's buttons appended
// underneath. Each switch takes a ticket; a renderer that is no longer
// the current one drops its output instead of painting it.
let _vserverDrawerRender = 0;

function vserverDrawerRenderIsStale(ticket) {
  return ticket !== _vserverDrawerRender;
}

function switchVserverDrawerTab(tab) {
  _vserverDrawer.currentTab = tab;
  const ticket = ++_vserverDrawerRender;
  for (const t of document.querySelectorAll("[data-vserver-drawer-tab]")) {
    t.classList.toggle("is-active", t.dataset.vserverDrawerTab === tab);
  }
  const body = _vserverDrawer.body();
  body.innerHTML = "Loading…";
  const v = _vserverDrawer.currentVserver;
  if (tab === "tools") renderVserverDrawerTools(body, v, ticket);
  else if (tab === "access") renderVserverDrawerAccess(body, v);
  else if (tab === "jit") renderVserverDrawerJit(body, v, ticket);
  else if (tab === "risk") renderVserverDrawerRisk(body, v, ticket);
  else if (tab === "settings") renderVserverDrawerSettings(body, v);
}

// Wire drawer close + tab switch (button, backdrop, ESC).
{
  for (const el of document.querySelectorAll("[data-vserver-drawer-close]")) {
    el.addEventListener("click", closeVserverDrawer);
  }
  for (const tab of document.querySelectorAll("[data-vserver-drawer-tab]")) {
    tab.addEventListener("click", () => switchVserverDrawerTab(tab.dataset.vserverDrawerTab));
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !_vserverDrawer.el().hidden) {
      closeVserverDrawer();
    }
  });
}

async function renderVserverDrawerTools(container, vserver, ticket) {
  container.innerHTML = "Loading…";
  try {
    const tools = await api(`/api/v1/vservers/${encodeURIComponent(vserver.id)}/tools`);
    if (vserverDrawerRenderIsStale(ticket)) return;
    container.innerHTML = "";
    if (!tools.length) {
      const empty = document.createElement("p");
      empty.className = "events-empty";
      empty.textContent =
        "(no tools allowlisted — this vserver is published but exposes nothing)";
      container.appendChild(empty);
      return;
    }
    const eyebrow = document.createElement("p");
    eyebrow.className = "eyebrow";
    eyebrow.style.margin = "0 0 6px";
    eyebrow.textContent = `ALLOWLISTED · ${tools.length}`;
    container.appendChild(eyebrow);
    const list = document.createElement("ul");
    list.style.listStyle = "none";
    list.style.padding = "0";
    list.style.margin = "0";
    for (const t of tools) {
      const li = document.createElement("li");
      li.style.padding = "8px 12px";
      li.style.border = "1px solid var(--vyuu-line)";
      li.style.borderRadius = "var(--vyuu-r-sm)";
      li.style.marginBottom = "4px";
      li.style.fontFamily = "var(--vyuu-mono)";
      li.style.fontSize = "11.5px";
      li.innerHTML = `<strong>${escapeHtml(t.tool_name)}</strong>
        <small style="display:block; color: var(--vyuu-muted); font-family: var(--vyuu-sans);">
          upstream ${escapeHtml(t.server_id)}</small>`;
      list.appendChild(li);
    }
    container.appendChild(list);
  } catch (error) {
    renderError(container, error);
  }
}

async function renderVserverDrawerAccess(container, vserver) {
  container.innerHTML = "Loading…";
  // Visibility toggle + grants list + issue-grant form. Re-renders
  // itself after each change so counts stay in sync.
  function rerender() { renderVserverDrawerAccess(container, vserver); }

  try {
    const grants = await api(`/api/v1/vservers/${encodeURIComponent(vserver.id)}/grants`);
    const active = grants.filter(g => !g.revoked_at);
    container.innerHTML = "";

    // Visibility toggle row
    const visRow = document.createElement("div");
    visRow.className = "users-row-actions";
    visRow.style.justifyContent = "flex-start";
    visRow.style.marginBottom = "16px";
    const visLabel = document.createElement("span");
    visLabel.style.font = "500 12px/1.4 var(--vyuu-sans)";
    visLabel.style.color = "var(--vyuu-ink)";
    visLabel.textContent = `Visibility: ${vserver.visibility}`;
    visRow.appendChild(visLabel);
    const flip = document.createElement("button");
    flip.type = "button";
    flip.textContent = vserver.visibility === "public" ? "Make private" : "Make public";
    flip.addEventListener("click", async () => {
      const next = vserver.visibility === "public" ? "private" : "public";
      try {
        await api(`/api/v1/vservers/${encodeURIComponent(vserver.id)}/visibility`, {
          method: "PATCH",
          body: JSON.stringify({ visibility: next }),
        });
        vserver.visibility = next;
        loadVservers();  // refresh table cache
        rerender();
      } catch (error) { alert(String(error)); }
    });
    visRow.appendChild(flip);
    container.appendChild(visRow);

    // Active grants
    const eyebrow = document.createElement("p");
    eyebrow.className = "eyebrow";
    eyebrow.style.margin = "0 0 6px";
    eyebrow.textContent = `ACTIVE GRANTS · ${active.length}`;
    container.appendChild(eyebrow);
    if (!active.length) {
      const empty = document.createElement("p");
      empty.className = "events-empty";
      empty.textContent = "(no active grants — pick a principal below to issue one)";
      container.appendChild(empty);
    } else {
      const list = document.createElement("ul");
      list.style.listStyle = "none";
      list.style.padding = "0";
      list.style.margin = "0 0 12px";
      for (const grant of active) {
        const li = document.createElement("li");
        li.style.padding = "8px 12px";
        li.style.border = "1px solid var(--vyuu-line)";
        li.style.borderRadius = "var(--vyuu-r-sm)";
        li.style.marginBottom = "4px";
        li.style.display = "flex";
        li.style.justifyContent = "space-between";
        li.style.alignItems = "center";
        const meta = document.createElement("span");
        meta.innerHTML = `<strong>${escapeHtml(grant.principal_kind)}</strong>
          <small style="display:block; color: var(--vyuu-muted);">
            ${escapeHtml(grant.principal_id)}</small>`;
        li.appendChild(meta);
        const revoke = document.createElement("button");
        revoke.type = "button";
        revoke.className = "is-danger";
        revoke.style.padding = "4px 10px";
        revoke.style.border = "1px solid var(--vyuu-line)";
        revoke.style.background = "var(--vyuu-panel)";
        revoke.style.borderRadius = "var(--vyuu-r-sm)";
        revoke.style.font = "500 11px/1 var(--vyuu-sans)";
        revoke.style.cursor = "pointer";
        revoke.textContent = "Revoke";
        revoke.addEventListener("click", async () => {
          if (!confirm(
            `Revoke grant for ${grant.principal_kind} ${grant.principal_id}?`
          )) return;
          try {
            await api(
              `/api/v1/vservers/${encodeURIComponent(vserver.id)}/grants/${encodeURIComponent(grant.id)}`,
              { method: "DELETE" });
            loadVservers();
            rerender();
          } catch (error) { alert(String(error)); }
        });
        li.appendChild(revoke);
        list.appendChild(li);
      }
      container.appendChild(list);
    }

    // Issue-grant form
    const form = document.createElement("div");
    form.style.padding = "12px";
    form.style.border = "1px solid var(--vyuu-line)";
    form.style.borderRadius = "var(--vyuu-r-sm)";
    form.style.background = "var(--vyuu-panel)";
    const formHead = document.createElement("p");
    formHead.className = "eyebrow";
    formHead.style.margin = "0 0 8px";
    formHead.textContent = "ISSUE GRANT";
    form.appendChild(formHead);
    const kindSel = document.createElement("select");
    kindSel.style.padding = "6px 10px";
    kindSel.style.border = "1px solid var(--vyuu-line)";
    kindSel.style.borderRadius = "var(--vyuu-r-sm)";
    for (const kind of ["user", "group"]) {
      const opt = document.createElement("option");
      opt.value = kind;
      opt.textContent = kind;
      kindSel.appendChild(opt);
    }
    const principalSel = document.createElement("select");
    principalSel.style.padding = "6px 10px";
    principalSel.style.marginLeft = "6px";
    principalSel.style.minWidth = "260px";
    principalSel.style.border = "1px solid var(--vyuu-line)";
    principalSel.style.borderRadius = "var(--vyuu-r-sm)";
    const grantBtn = document.createElement("button");
    grantBtn.type = "button";
    grantBtn.style.marginLeft = "6px";
    grantBtn.textContent = "Grant";
    form.appendChild(kindSel);
    form.appendChild(principalSel);
    form.appendChild(grantBtn);
    container.appendChild(form);

    async function refreshPrincipalOptions() {
      await ensurePrincipalCacheLoaded();
      if (kindSel.value === "user") {
        fillSelectOptions(principalSel, principalCache.users, userLabel);
      } else {
        fillSelectOptions(principalSel, principalCache.groups, groupLabel);
      }
    }
    kindSel.addEventListener("change", refreshPrincipalOptions);
    await refreshPrincipalOptions();

    grantBtn.addEventListener("click", async () => {
      if (!principalSel.value) return;
      try {
        await api(`/api/v1/vservers/${encodeURIComponent(vserver.id)}/grants`, {
          method: "POST",
          body: JSON.stringify({
            principal_kind: kindSel.value,
            principal_id: principalSel.value,
          }),
        });
        loadVservers();
        rerender();
      } catch (error) { alert(String(error)); }
    });
  } catch (error) {
    renderError(container, error);
  }
}

function renderVserverDrawerSettings(container, vserver) {
  container.innerHTML = "";
  const note = document.createElement("p");
  note.style.font = "400 12.5px/1.5 var(--vyuu-sans)";
  note.style.color = "var(--vyuu-muted)";
  note.style.marginTop = "0";
  note.textContent =
    `Deleting "${vserver.name}" disconnects every client currently using ` +
    `the /v/.../${vserver.name}/mcp endpoint. The grant rows + tool ` +
    `allowlist are removed; audit history is preserved.`;
  container.appendChild(note);

  const del = document.createElement("button");
  del.type = "button";
  del.className = "is-danger";
  del.style.padding = "8px 14px";
  del.style.border = "1px solid var(--vyuu-danger)";
  del.style.background = "var(--vyuu-danger-tint)";
  del.style.borderRadius = "var(--vyuu-r-sm)";
  del.style.color = "var(--vyuu-danger-ink)";
  del.style.font = "500 12px/1 var(--vyuu-sans)";
  del.style.cursor = "pointer";
  del.textContent = "Delete this vserver";
  del.addEventListener("click", async () => {
    if (!confirm(
      `Delete virtual server "${vserver.name}"? Connected clients will ` +
      `fail with 404 immediately. This cannot be undone.`
    )) return;
    try {
      await api(`/api/v1/vservers/${encodeURIComponent(vserver.id)}`,
                { method: "DELETE" });
      closeVserverDrawer();
      await loadVservers();
    } catch (error) { alert(String(error)); }
  });
  container.appendChild(del);
}

// --- Create-vserver modal -------------------------------------------------
{
  const open = document.querySelector("#open-create-vserver");
  const modal = document.querySelector("#create-vserver-modal");
  if (open && modal) {
    open.addEventListener("click", () => {
      modal.hidden = false;
      document.body.style.overflow = "hidden";
    });
  }
  for (const el of document.querySelectorAll("[data-create-vserver-close]")) {
    el.addEventListener("click", () => {
      modal.hidden = true;
      document.body.style.overflow = "";
    });
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modal && !modal.hidden) {
      modal.hidden = true;
      document.body.style.overflow = "";
    }
  });
}

async function createVserver(event) {
  event.preventDefault();
  const data = new FormData(vserverForm);
  const name = String(data.get("name") || "").trim();
  if (!name) {
    renderError(vserverOutput, new Error("name is required"));
    return;
  }
  const rawTools = String(data.get("tools") || "").trim();
  const tools = [];
  if (rawTools) {
    for (const line of rawTools.split("\\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const colon = trimmed.indexOf(":");
      if (colon <= 0 || colon === trimmed.length - 1) {
        const msg = `Invalid tool line: ${trimmed} (expected server_id:tool_name)`;
        renderError(vserverOutput, new Error(msg));
        return;
      }
      tools.push({
        server_id: trimmed.slice(0, colon),
        tool_name: trimmed.slice(colon + 1),
      });
    }
  }
  let renameMap = {};
  const rawRename = String(data.get("rename_map") || "").trim();
  if (rawRename) {
    try {
      renameMap = JSON.parse(rawRename);
      if (typeof renameMap !== "object" || Array.isArray(renameMap)) {
        throw new Error("rename_map must be a JSON object");
      }
    } catch (error) {
      renderError(vserverOutput, error);
      return;
    }
  }
  try {
    const created = await api("/api/v1/vservers", {
      method: "POST",
      body: JSON.stringify({ name, tools, rename_map: renameMap }),
    });
    renderCreated(vserverOutput, `Published ${created.name} (${created.visibility})`,
      `id ${created.id}`);
    vserverForm.reset();
    await loadVservers();
  } catch (error) {
    renderError(vserverOutput, error);
  }
}

function renderCreated(target, headline, detail) {
  // A created row shows up in its table; the JSON that used to be
  // dumped here said the same thing in 30 lines. One line, plus the
  // identifier someone might need to paste.
  target.classList.remove("error");
  target.classList.add("has-result");
  target.hidden = false;
  target.textContent = detail ? `${headline}  ·  ${detail}` : headline;
}

function renderText(target, text, options) {
  target.classList.remove("error");
  target.classList.toggle("has-result", Boolean(text));
  // Sibling advisory banner — surfaces above the JSON output without
  // replacing it. We render it as a sibling node managed alongside the
  // <pre>, so re-renders cleanly remove the prior advisory.
  const existingAdvisory = target.parentNode &&
    target.parentNode.querySelector(".advisory[data-target='" + target.id + "']");
  if (existingAdvisory) existingAdvisory.remove();
  if (options && options.advisory && target.parentNode) {
    const note = document.createElement("p");
    note.className = "advisory";
    note.dataset.target = target.id;
    note.textContent = options.advisory;
    target.parentNode.insertBefore(note, target);
  }
  target.textContent = text;
}

function renderError(target, error) {
  target.classList.add("error");
  // Clear any sibling advisory from a prior success render.
  const existingAdvisory = target.parentNode &&
    target.parentNode.querySelector(".advisory[data-target='" + target.id + "']");
  if (existingAdvisory) existingAdvisory.remove();
  target.textContent = String(error.message || error);
}

// ---------------------------------------------------------------------------
// Mini-marks for the gateway's three core primitives. Each glyph encodes the
// concept geometrically — not stock-icon repurposing — so the surfaces feel
// designed rather than scaffolded:
//
//   NHI  → human silhouette inside a hex "machine ring" (the binding between
//          a human and the machine principal that calls tools on their behalf)
//   vServer → three offset stacked plates with a fan-out chord at the bottom
//             (one URL → many tools, the curated bundle)
//   ToolCall → chevron-bracket envelope around a centered dot (the call unit)
//
// Returned as live SVG nodes so callers append them directly via
// `card.prepend(markNHI())` rather than dumping HTML strings (which would
// require innerHTML and forfeit the live element handle).
// ---------------------------------------------------------------------------

function markNHI(size = 22) {
  return _svgMark(size, [
    '<path d="M12 2 L21 7 L21 17 L12 22 L3 17 L3 7 Z" fill="#F3DAB6" '
    + 'stroke="#A85820" stroke-width="1.6" stroke-linejoin="round"/>',
    '<circle cx="12" cy="10.2" r="2.1" fill="#A85820"/>',
    '<path d="M7.6 17.2 Q12 12.6 16.4 17.2" fill="none" '
    + 'stroke="#A85820" stroke-width="1.8" stroke-linecap="round"/>',
    '<circle cx="19" cy="6" r="1.4" fill="#A85820"/>',
  ]);
}

function markVServer(size = 22) {
  return _svgMark(size, [
    '<rect x="4" y="4" width="14" height="3.2" rx="1.2" '
    + 'fill="#DCE7EC" stroke="#2E5565" stroke-width="1.4"/>',
    '<rect x="6" y="9" width="14" height="3.2" rx="1.2" '
    + 'fill="#DCE7EC" stroke="#2E5565" stroke-width="1.4"/>',
    '<rect x="4" y="14" width="14" height="3.2" rx="1.2" '
    + 'fill="#2E5565" stroke="#2E5565" stroke-width="1.4"/>',
    '<path d="M11 17.4 V19 M11 19 H7.5 V21 M11 19 H11 V21 M11 19 H14.5 V21" '
    + 'fill="none" stroke="#2E5565" stroke-width="1.4" '
    + 'stroke-linecap="round" stroke-linejoin="round"/>',
  ]);
}

function markToolCall(size = 22) {
  return _svgMark(size, [
    '<rect x="3" y="6" width="18" height="12" rx="3" '
    + 'fill="#F7EBD4" stroke="#8A6420" stroke-width="1.4"/>',
    '<path d="M8 10 L5.5 12 L8 14 M16 10 L18.5 12 L16 14" '
    + 'fill="none" stroke="#8A6420" stroke-width="1.6" '
    + 'stroke-linecap="round" stroke-linejoin="round"/>',
    '<circle cx="12" cy="12" r="1.4" fill="#8A6420"/>',
  ]);
}

function _svgMark(size, paths) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("width", size);
  svg.setAttribute("height", size);
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "mark-icon");
  svg.style.flexShrink = "0";
  // We rely on the literal SVG fragments above (not DOM-built children) so
  // the mark stays a single visual unit; the host CSS only needs to size +
  // align the wrapper.
  svg.innerHTML = paths.join("");
  return svg;
}

function pillClassForHealth(status) {
  // Map server `health_status` to the right Vyuu pill variant. Encodes
  // MEANING — not just aesthetics. Operators should be able to glance
  // at the row and tell good from bad without reading the label.
  switch (String(status)) {
    case "healthy":
      return "pill-orange";  // positive / active
    case "down":
      return "pill-danger";   // failure
    case "degraded":
      return "pill-warn";     // advisory / partial
    case "unknown":
    default:
      return "pill-neutral";  // standby / not yet acted on
  }
}

function needsAuthAdvisory(server, syncResult) {
  // Surface the "discovery succeeded but calls may need credentials"
  // hint when ALL of these are true:
  // 1. The sync just succeeded (server is reachable, tools/list works).
  // 2. The server has zero auth configured of any kind.
  // 3. The server actually exposes capabilities (otherwise the warning
  //    would fire on benign empty servers and become noise).
  if (!syncResult || typeof syncResult.capability_count !== "number") return false;
  if (syncResult.capability_count === 0) return false;
  const empty = (obj) => !obj || Object.keys(obj).length === 0;
  return (
    empty(server.auth_headers) &&
    empty(server.auth_env) &&
    empty(server.auth_passthrough) &&
    !server.auth_oauth
  );
}

// =========================================================================
// A3.x · Operator-console panels for users / groups / grants / access queue
// =========================================================================

const accessRequestsOutput = document.querySelector("#access-requests-output");
const usersOutput = document.querySelector("#users-output");
const createUserForm = document.querySelector("#create-user-form");
const createUserOutput = document.querySelector("#create-user-output");
const groupsOutput = document.querySelector("#groups-output");
const createGroupForm = document.querySelector("#create-group-form");
const createGroupOutput = document.querySelector("#create-group-output");
const adminsOutput = document.querySelector("#admins-output");
const createAdminForm = document.querySelector("#create-admin-form");
const createAdminOutput = document.querySelector("#create-admin-output");

document.querySelector("#refresh-access-requests").addEventListener("click", loadAccessRequests);
document.querySelector("#refresh-users").addEventListener("click", loadUsers);
document.querySelector("#refresh-groups").addEventListener("click", loadGroups);
document.querySelector("#refresh-admins").addEventListener("click", loadAdmins);
createUserForm.addEventListener("submit", createUser);
createGroupForm.addEventListener("submit", createGroup);
createAdminForm.addEventListener("submit", createAdmin);

// --- Admins panel (operator management) -----------------------------
// Tabular redesign — same shape as Users / Groups. The list endpoint
// already returns everything we need (role, must_change_password,
// last_login_at, disabled_at), so this is a UI-only rebuild.

const adminsSearch = document.querySelector("#admins-search");
const adminsCount = document.querySelector("#admins-count");

let adminsCache = [];
const adminsPillState = { current: "all" };

if (adminsSearch) adminsSearch.addEventListener("input", () => renderAdmins());
for (const pill of document.querySelectorAll("[data-admins-pill]")) {
  pill.addEventListener("click", () => {
    adminsPillState.current = pill.dataset.adminsPill;
    for (const p of document.querySelectorAll("[data-admins-pill]")) {
      p.classList.toggle("is-active", p === pill);
    }
    renderAdmins();
  });
}

async function loadAdmins() {
  adminsOutput.innerHTML =
    '<tr><td colspan="5" class="events-empty">Loading…</td></tr>';
  try {
    adminsCache = await api("/api/v1/admins");
    renderAdmins();
  } catch (error) {
    adminsOutput.innerHTML = "";
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "events-empty";
    td.textContent = String(error.message || error);
    tr.appendChild(td);
    adminsOutput.appendChild(tr);
  }
}

function renderAdmins() {
  renderAdminsKpis(adminsCache);

  const needle = (adminsSearch && adminsSearch.value || "").trim().toLowerCase();
  const pill = adminsPillState.current;
  const filtered = adminsCache.filter((a) => {
    if (needle && !a.email.toLowerCase().includes(needle)) return false;
    if (pill === "active") return !a.disabled_at;
    if (pill === "disabled") return !!a.disabled_at;
    if (pill === "admin" || pill === "editor" || pill === "viewer") {
      return a.role === pill;
    }
    if (pill === "pending_reset") return !!a.must_change_password && !a.disabled_at;
    return true;
  });

  adminsCount.textContent =
    filtered.length === adminsCache.length
      ? `${filtered.length} admins`
      : `${filtered.length} of ${adminsCache.length} admins`;

  adminsOutput.innerHTML = "";
  if (!filtered.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "events-empty";
    td.textContent = adminsCache.length === 0
      ? "No admins yet. Click + New admin above to invite one."
      : `(0 of ${adminsCache.length} admins match the active filter)`;
    tr.appendChild(td);
    adminsOutput.appendChild(tr);
    return;
  }
  for (const a of filtered) {
    adminsOutput.appendChild(renderAdminRow(a));
  }
}

function renderAdminsKpis(rows) {
  let total = 0;
  let disabled = 0;
  let pendingReset = 0;
  let never = 0;
  for (const a of rows) {
    total++;
    if (a.disabled_at) disabled++;
    else {
      if (a.must_change_password) pendingReset++;
      if (!a.last_login_at) never++;
    }
  }
  const set = (id, v) => {
    const el = document.querySelector(`#${id}`);
    if (el) el.textContent = v;
  };
  set("admins-kpi-total", total.toLocaleString());
  set("admins-kpi-disabled", disabled.toLocaleString());
  set("admins-kpi-pending-reset", pendingReset.toLocaleString());
  set("admins-kpi-never", never.toLocaleString());
}

function adminStatus(admin) {
  if (admin.disabled_at) return { key: "disabled", label: "Disabled" };
  if (admin.must_change_password) return { key: "pending_reset", label: "Reset" };
  return { key: "active", label: "Active" };
}

function renderAdminRow(admin) {
  const tr = document.createElement("tr");
  if (admin.disabled_at) tr.dataset.disabled = "true";

  // ADMIN — status pill + email + truncated id
  const adminCell = document.createElement("td");
  const wrap = document.createElement("div");
  wrap.className = "users-row-user";
  const line = document.createElement("span");
  line.className = "users-row-user-line";
  const status = adminStatus(admin);
  const pill = document.createElement("span");
  pill.className = "users-status-pill";
  pill.dataset.status = status.key;
  pill.textContent = status.label;
  line.appendChild(pill);
  line.appendChild(document.createTextNode(admin.email));
  wrap.appendChild(line);
  const idLine = document.createElement("span");
  idLine.className = "users-row-user-id";
  idLine.textContent = `${admin.id.slice(0, 8)}…`;
  wrap.appendChild(idLine);
  adminCell.appendChild(wrap);
  tr.appendChild(adminCell);

  // ROLE — color-coded tag (admin ink-stroked, editor/viewer neutral)
  const roleCell = document.createElement("td");
  const roleTag = document.createElement("span");
  roleTag.className = "admins-role-tag";
  roleTag.dataset.role = admin.role;
  roleTag.textContent = admin.role;
  roleCell.appendChild(roleTag);
  tr.appendChild(roleCell);

  // LAST LOGIN — relative or "never"
  const loginCell = document.createElement("td");
  loginCell.style.color = "var(--vyuu-muted)";
  loginCell.style.fontSize = "11.5px";
  if (admin.last_login_at) {
    loginCell.textContent = formatRelativeTime(admin.last_login_at);
    loginCell.title = new Date(admin.last_login_at).toLocaleString();
  } else {
    loginCell.textContent = "never";
  }
  tr.appendChild(loginCell);

  // CREATED — relative
  const createdCell = document.createElement("td");
  createdCell.style.color = "var(--vyuu-muted)";
  createdCell.style.fontSize = "11.5px";
  createdCell.textContent = formatRelativeTime(admin.created_at);
  createdCell.title = new Date(admin.created_at).toLocaleString();
  tr.appendChild(createdCell);

  // ACTIONS — Reset password / Disable inline
  const actionsCell = document.createElement("td");
  const actions = document.createElement("div");
  actions.className = "users-row-actions";
  const reset = document.createElement("button");
  reset.type = "button";
  reset.textContent = "Reset password";
  reset.addEventListener("click", async () => {
    const newPw = prompt("New password (min 12 chars):");
    if (!newPw) return;
    try {
      await api(`/api/v1/admins/${encodeURIComponent(admin.id)}/password`, {
        method: "POST",
        body: JSON.stringify({ new_password: newPw }),
      });
      alert(`Password reset for ${admin.email}. They must rotate on next sign-in.`);
      await loadAdmins();
    } catch (error) {
      alert(String(error));
    }
  });
  actions.appendChild(reset);
  if (!admin.disabled_at) {
    const disable = document.createElement("button");
    disable.type = "button";
    disable.className = "is-danger";
    disable.textContent = "Disable";
    disable.addEventListener("click", async () => {
      if (!confirm(
        `Disable ${admin.email}? They will not be able to sign in to the ` +
        `operator console. This is reversible by API.`
      )) return;
      try {
        await api(`/api/v1/admins/${encodeURIComponent(admin.id)}`,
                  { method: "DELETE" });
        await loadAdmins();
      } catch (error) {
        alert(String(error));
      }
    });
    actions.appendChild(disable);
  }
  actionsCell.appendChild(actions);
  tr.appendChild(actionsCell);

  return tr;
}

// --- Create-admin modal -------------------------------------------------
{
  const open = document.querySelector("#open-create-admin");
  const modal = document.querySelector("#create-admin-modal");
  if (open && modal) {
    open.addEventListener("click", () => {
      modal.hidden = false;
      document.body.style.overflow = "hidden";
    });
  }
  for (const el of document.querySelectorAll("[data-create-admin-close]")) {
    el.addEventListener("click", () => {
      modal.hidden = true;
      document.body.style.overflow = "";
    });
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modal && !modal.hidden) {
      modal.hidden = true;
      document.body.style.overflow = "";
    }
  });
}

async function createAdmin(event) {
  event.preventDefault();
  const data = new FormData(createAdminForm);
  const payload = {
    email: String(data.get("email") || "").trim(),
    role: String(data.get("role") || "admin"),
    password: String(data.get("password") || ""),
    must_change_password: true,
  };
  try {
    const created = await api("/api/v1/admins", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    renderCreated(createAdminOutput, `Created admin ${created.email} (${created.role})`);
    createAdminForm.reset();
    const modal = document.querySelector("#create-admin-modal");
    if (modal) {
      modal.hidden = true;
      document.body.style.overflow = "";
    }
    await loadAdmins();
  } catch (error) {
    renderError(createAdminOutput, error);
  }
}

// Cached principal lists, refreshed by `loadUsers` / `loadGroups` and
// reused by every dropdown (Issue grant, Add/remove member). Stale data
// is bounded by the operator clicking Refresh on the source panel.
const principalCache = { users: [], groups: [] };

function fillSelectOptions(selectEl, items, labelFor) {
  selectEl.innerHTML = "";
  if (!items.length) {
    const opt = document.createElement("option");
    opt.value = "";
    opt.textContent = "(none — refresh the panel above)";
    opt.disabled = true;
    selectEl.appendChild(opt);
    return;
  }
  for (const item of items) {
    const opt = document.createElement("option");
    opt.value = item.id;
    opt.textContent = labelFor(item);
    selectEl.appendChild(opt);
  }
}

// --- Pending access-request queue ---------------------------------------
// Tabular redesign — same shape as Identities / Users / Groups. The
// list endpoint returns the joined view (user_email, vserver_name,
// decided_by_email) so the table is self-explanatory in one trip.

const accessRequestsSearch = document.querySelector("#access-requests-search");
const accessRequestsCount = document.querySelector("#access-requests-count");

let accessRequestsCache = [];
// Default to "pending" — the working queue is what operators land
// here to do. Toggling to "all" / "approved" / "declined" reveals
// the audit history.
const accessRequestsPillState = { current: "pending" };

if (accessRequestsSearch) {
  accessRequestsSearch.addEventListener("input", () => renderAccessRequests());
}
for (const pill of document.querySelectorAll("[data-ar-pill]")) {
  pill.addEventListener("click", () => {
    accessRequestsPillState.current = pill.dataset.arPill;
    for (const p of document.querySelectorAll("[data-ar-pill]")) {
      p.classList.toggle("is-active", p === pill);
    }
    renderAccessRequests();
  });
}

// The servers table has no risk COLUMN — the header is fixed and a
// stray cell would misalign every row. The badge lives in the action
// bar instead, which is also where the operator would look to act on
// it. Fetched per row and only on demand: a catalogue of 24 servers
// should not fire 24 requests to render a list nobody has asked to see
// scored yet.
function _attachServerRisk(actions, server) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.textContent = "Risk";
  btn.title = "Open the risk assessment. Scored from tool descriptions "
    + "and schemas, not source code.";

  const show = (data) => {
    btn.textContent = "";
    btn.appendChild(riskBand(data.band, data.normalised));
    btn.title = `${data.finding_count} finding(s) · ${data.model_id}. `
      + "Click to re-assess.";
  };

  // Opens the drill-in rather than firing the assessment directly. A
  // click here spends real money at an LLM vendor, and a table row is
  // too easy to hit by accident; the drawer makes the action explicit
  // and shows the findings where there is room to read them.
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    openServerDrawer(server);
    switchServerDrawerTab("risk");
  });

  // If it has been assessed before, show that without re-running a paid
  // call — but do not block the row render on it.
  api(`/api/v1/servers/${encodeURIComponent(server.id)}/risk-assessment`)
    .then(show)
    .catch(() => {});

  actions.appendChild(btn);
}

async function renderVserverDrawerRisk(container, vserver, ticket) {
  if (vserverDrawerRenderIsStale(ticket)) return;
  container.innerHTML = "Loading…";

  let data = null;
  try {
    data = await api(
      `/api/v1/vservers/${encodeURIComponent(vserver.id)}/risk-assessment`);
  } catch {
    data = null;  // 404 = never computed. Not an error, just not done.
  }
  if (vserverDrawerRenderIsStale(ticket)) return;
  container.innerHTML = "";

  const compute = document.createElement("button");
  compute.type = "button";
  compute.className = "vservers-row-url-copy";
  compute.textContent = data ? "Recompute" : "Compute risk reduction";
  const status = document.createElement("span");
  status.className = "toolbar-meta";
  status.style.marginLeft = "10px";
  compute.addEventListener("click", async () => {
    compute.disabled = true;
    status.textContent = "Computing…";
    try {
      await api(`/api/v1/vservers/${encodeURIComponent(vserver.id)}/risk-assessment`,
                { method: "POST" });
      status.textContent = "";
      await renderVserverDrawerRisk(container, vserver, ticket);
      return;
    } catch (error) {
      status.textContent = String(error);
    } finally {
      compute.disabled = false;
    }
  });

  if (!data) {
    const empty = document.createElement("p");
    empty.className = "events-empty";
    empty.style.textAlign = "left";
    empty.textContent = "Not computed yet. This compares what the upstream "
      + "servers expose against what this bundle actually publishes — so "
      + "every upstream must be assessed first.";
    container.appendChild(empty);
    const bar = document.createElement("div");
    bar.append(compute, status);
    container.appendChild(bar);
    return;
  }

  // The headline. Two bands and an arrow, because "high to low" is the
  // sentence somebody repeats in a meeting; the numbers are support.
  const headline = document.createElement("div");
  headline.style.display = "flex";
  headline.style.alignItems = "center";
  headline.style.marginBottom = "6px";
  const bandLabel = document.createElement("span");
  bandLabel.style.font = "500 10px/1.5 var(--vyuu-sans)";
  bandLabel.style.letterSpacing = "0.5px";
  bandLabel.style.color = "var(--vyuu-muted)";
  bandLabel.style.marginRight = "8px";
  bandLabel.textContent = "SEVERITY PROFILE";
  bandLabel.title = "How bad the findings are, on an RMS basis. Separate "
    + "from how MUCH risk is reachable — see the percentage below.";
  headline.appendChild(bandLabel);
  headline.appendChild(riskBand(data.inherent_band, data.inherent_normalised));
  const arrow = document.createElement("span");
  arrow.className = "risk-arrow";
  arrow.textContent = "→";
  headline.appendChild(arrow);
  headline.appendChild(riskBand(data.published_band, data.published_normalised));
  container.appendChild(headline);

  const claim = document.createElement("p");
  claim.style.font = "400 12.5px/1.5 var(--vyuu-sans)";
  claim.style.margin = "0 0 14px";
  claim.textContent = data.percent_reduced > 0
    ? `Publishing this bundle instead of the raw upstreams puts `
      + `${data.percent_reduced}% of the upstream risk out of reach, `
      + `eliminating ${data.eliminated.length} finding(s).`
    : "This bundle publishes everything its upstreams expose, so it removes "
      + "no risk. Withholding a tool is what creates the reduction.";
  container.appendChild(claim);

  if (data.stale) container.appendChild(staleRiskBanner(data));

  // A rising severity profile alongside a large reduction is real, not
  // a glitch: less risk is reachable, but what remains is concentrated.
  // An operator who has just cut 24 findings and sees the band go UP
  // will not trust anything else on the page without this sentence.
  if (data.severity_profile_delta > 0) {
    const concentrated = document.createElement("p");
    concentrated.className = "risk-note";
    concentrated.textContent =
      `The band rose ${data.severity_profile_delta} points even though risk `
      + "fell. Curation removed many moderate findings and left the worst "
      + "ones, so less is reachable but what remains is more severe. "
      + "Withholding the tools listed under STILL REACHABLE is what would "
      + "move the band.";
    container.appendChild(concentrated);
  }

  const bar = document.createElement("div");
  bar.style.marginBottom = "16px";
  bar.append(compute, status);
  container.appendChild(bar);

  container.appendChild(_riskSection(
    `NO LONGER REACHABLE · ${data.eliminated.length}`, data.eliminated,
    (f) => _riskFindingLine(f)));
  container.appendChild(_riskSection(
    `STILL REACHABLE · ${data.retained.length}`, data.retained,
    (f) => _riskFindingLine(f)));

  if ((data.unassessed_server_ids || []).length) {
    const warn = document.createElement("p");
    warn.className = "risk-note";
    warn.textContent = `${data.unassessed_server_ids.length} upstream server(s) `
      + "have not been assessed, so their risk is missing from this comparison.";
    container.appendChild(warn);
  }
  container.appendChild(riskNote(data.evidence_basis));
}

function staleRiskBanner(data) {
  // Deliberately loud and placed ABOVE the findings. A stale score is
  // not a smaller version of a fresh one — the tools it describes are
  // not the tools that are deployed — so it must not be read first and
  // qualified afterwards.
  const banner = document.createElement("p");
  banner.className = "risk-note";
  banner.style.borderLeft = "2px solid var(--vyuu-warn, var(--vyuu-muted))";
  banner.style.paddingLeft = "8px";
  const reason = data.stale_reason
    || "the capabilities changed since this was assessed";
  const hedge = data.staleness_basis === "capability_count"
    // Pre-RISK-2 row: only counts could be compared, so an in-place
    // edit to a tool would not have been caught. Say so rather than
    // implying the check was exact.
    ? " (this assessment predates capability fingerprinting, so only the "
      + "number of capabilities could be compared — an edited tool would "
      + "not show up here)"
    : "";
  banner.textContent = `OUT OF DATE — ${reason}${hedge}. Re-assess before `
    + "treating this as current posture.";
  return banner;
}

function _riskFindingLine(f) {
  const line = document.createElement("div");
  const top = document.createElement("div");
  top.style.display = "flex";
  top.style.justifyContent = "space-between";
  top.style.gap = "10px";
  const title = document.createElement("span");
  title.style.fontSize = "12.5px";
  title.textContent = f.title;
  const score = document.createElement("span");
  score.style.fontFamily = "var(--vyuu-mono)";
  score.style.fontSize = "11px";
  score.style.color = "var(--vyuu-muted)";
  score.textContent = `${f.owasp_mcp} · R=${f.risk}`;
  top.append(title, score);
  line.appendChild(top);
  if ((f.affected_tools || []).length) {
    const tools = document.createElement("small");
    tools.style.display = "block";
    tools.style.marginTop = "3px";
    tools.style.color = "var(--vyuu-muted)";
    tools.style.fontFamily = "var(--vyuu-mono)";
    tools.textContent = f.affected_tools.join(", ");
    line.appendChild(tools);
  } else {
    const wide = document.createElement("small");
    wide.style.display = "block";
    wide.style.marginTop = "3px";
    wide.style.color = "var(--vyuu-muted)";
    // Says why it survives curation, where the operator is looking.
    wide.textContent = "server-wide — not addressable by choosing tools";
    line.appendChild(wide);
  }
  return line;
}

// --- RISK-1 · LLM risk classification ------------------------------------
//
// Three surfaces over one engine: a settings page for WHICH model, a
// tenant-wide posture view for a reader who will not open a server row,
// and a per-bundle before/after that names what curation removed.
//
// Scores come from tool descriptions and input schemas, never source
// code. That caveat is repeated on every surface rather than stated
// once in a docstring, because a number whose provenance is invisible
// gets read as more than it is.

function riskBand(band, score) {
  const el = document.createElement("span");
  el.className = "risk-band";
  el.dataset.band = band || "unknown";
  el.textContent = band || "unknown";
  if (score !== undefined && score !== null) {
    const n = document.createElement("span");
    n.className = "risk-band-score";
    n.textContent = String(score);
    el.appendChild(n);
  }
  return el;
}

function riskNote(text) {
  const el = document.createElement("p");
  el.className = "risk-note";
  el.textContent = text;
  return el;
}

// --- settings: which model ------------------------------------------------

async function loadRiskClassifier() {
  const body = document.querySelector("#risk-classifier-body");
  if (!body) return;
  body.textContent = "Loading…";
  let cfg;
  try {
    cfg = await api("/api/v1/admin/risk/model");
  } catch (error) { renderError(body, error); return; }

  body.innerHTML = "";
  const form = document.createElement("form");
  form.className = "akp-form";
  form.style.marginBottom = "10px";

  const select = document.createElement("select");
  for (const option of cfg.options) {
    const opt = document.createElement("option");
    opt.value = option.id;
    opt.textContent = `${option.label} · ${option.vendor}`;
    opt.title = option.note;
    select.appendChild(opt);
  }
  // An id newer than our registry is a legitimate answer — model names
  // move faster than this console ships.
  const custom = document.createElement("option");
  custom.value = "__custom__";
  custom.textContent = "Other (type an id)";
  select.appendChild(custom);
  select.value = cfg.model_id && cfg.options.some((o) => o.id === cfg.model_id)
    ? cfg.model_id : (cfg.model_id ? "__custom__" : cfg.default_model_id);

  const customId = document.createElement("input");
  customId.type = "text";
  customId.placeholder = "model id";
  customId.style.width = "170px";
  if (select.value === "__custom__") customId.value = cfg.model_id || "";
  const vendorSel = document.createElement("select");
  for (const v of ["anthropic", "openai", "gemini"]) {
    const o = document.createElement("option");
    o.value = v; o.textContent = v; vendorSel.appendChild(o);
  }
  if (cfg.model_vendor) vendorSel.value = cfg.model_vendor;
  const syncCustom = () => {
    const isCustom = select.value === "__custom__";
    customId.style.display = isCustom ? "" : "none";
    vendorSel.style.display = isCustom ? "" : "none";
  };
  select.addEventListener("change", syncCustom);
  syncCustom();

  const keyRef = document.createElement("input");
  keyRef.type = "text";
  keyRef.placeholder = "secret-store ref (not the key)";
  keyRef.style.flex = "1";
  keyRef.style.minWidth = "180px";
  keyRef.title = "The NAME of the secret, not its value. This is written "
    + "to the tenants table.";
  keyRef.value = cfg.api_key_ref || "";

  const baseUrl = document.createElement("input");
  baseUrl.type = "text";
  baseUrl.placeholder = "base url (optional)";
  baseUrl.style.width = "180px";
  baseUrl.title = "For Azure OpenAI, Vertex, or an inspecting egress proxy.";
  baseUrl.value = cfg.base_url || "";

  const save = document.createElement("button");
  save.type = "submit";
  save.textContent = "Save";
  const status = document.createElement("span");
  status.className = "toolbar-meta";

  form.append(select, customId, vendorSel, keyRef, baseUrl, save, status);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const modelId = select.value === "__custom__"
      ? customId.value.trim() : select.value;
    if (!modelId) { status.textContent = "Enter a model id."; return; }
    if (!keyRef.value.trim()) { status.textContent = "Enter a secret ref."; return; }
    status.textContent = "Saving…";
    try {
      await api("/api/v1/admin/risk/model", {
        method: "PUT",
        body: JSON.stringify({
          model_id: modelId,
          model_vendor: select.value === "__custom__" ? vendorSel.value : null,
          api_key_ref: keyRef.value.trim(),
          base_url: baseUrl.value.trim() || null,
        }),
      });
      status.textContent = "Saved.";
      await loadRiskClassifier();
    } catch (error) { status.textContent = String(error); }
  });
  body.appendChild(form);

  // --- the key itself -------------------------------------------------
  //
  // "A ref is set" and "a key is actually stored under it" are
  // different states, and an operator who had only the first found out
  // when an assessment failed. Report them separately.
  const keyStrip = document.createElement("div");
  keyStrip.className = "jit-strip";
  keyStrip.style.marginTop = "14px";
  const keyHead = document.createElement("div");
  keyHead.className = "jit-strip-head";
  const keyTitle = document.createElement("span");
  keyTitle.className = "jit-strip-title";
  keyTitle.textContent = "API KEY";
  const keySub = document.createElement("span");
  keySub.className = "jit-strip-sub";
  keySub.textContent = cfg.key_present
    ? `stored under ${cfg.api_key_ref} · ${cfg.secret_backend}`
    : cfg.api_key_ref
      ? `no key found under ${cfg.api_key_ref} · ${cfg.secret_backend}`
      : "set a reference above first";
  keyHead.append(keyTitle, keySub);
  keyStrip.appendChild(keyHead);

  const keyBody = document.createElement("div");
  keyBody.className = "jit-strip-list";
  if (!cfg.api_key_ref) {
    const p0 = document.createElement("p");
    p0.className = "events-empty";
    p0.style.textAlign = "left";
    p0.textContent = "Save a secret-store reference first.";
    keyBody.appendChild(p0);
  } else if (cfg.secret_writable) {
    const keyForm = document.createElement("form");
    keyForm.className = "akp-form";
    const keyInput = document.createElement("input");
    keyInput.type = "password";
    keyInput.placeholder = cfg.key_present ? "replace the stored key" : "paste the API key";
    keyInput.autocomplete = "off";
    keyInput.style.flex = "1";
    keyInput.style.minWidth = "220px";
    const keySave = document.createElement("button");
    keySave.type = "submit";
    keySave.textContent = cfg.key_present ? "Replace" : "Store";
    const keyStatus = document.createElement("span");
    keyStatus.className = "toolbar-meta";
    keyForm.append(keyInput, keySave, keyStatus);
    keyForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const value = keyInput.value.trim();
      if (!value) { keyStatus.textContent = "Paste a key."; return; }
      keyStatus.textContent = "Storing…";
      try {
        await api("/api/v1/admin/risk/model/api-key", {
          method: "POST", body: JSON.stringify({ api_key: value }),
        });
        // Clear it from the DOM immediately. The field is the only
        // place the plaintext ever lives on this page.
        keyInput.value = "";
        keyStatus.textContent = "Stored.";
        await loadRiskClassifier();
      } catch (error) { keyStatus.textContent = String(error); }
    });
    keyBody.appendChild(keyForm);
    const warn = document.createElement("p");
    warn.className = "risk-note";
    warn.textContent = `${cfg.secret_backend} keeps secrets in process memory `
      + "and loses them on restart. Fine for a lab; in production point the "
      + "gateway at Vault, AWS Secrets Manager or Kubernetes and create the "
      + "secret there.";
    keyBody.appendChild(warn);
  } else {
    const readonly = document.createElement("p");
    readonly.className = "risk-note";
    readonly.style.borderLeftColor = "var(--vyuu-orange-deep)";
    readonly.textContent = `${cfg.secret_backend} is read-only from here. `
      + `Create a secret named "${cfg.api_key_ref}" in that backend directly — `
      + "it keeps its own access control, rotation and audit, which is why "
      + "this console does not write into it.";
    keyBody.appendChild(readonly);
  }
  keyStrip.appendChild(keyBody);
  body.appendChild(keyStrip);

  const state = document.createElement("p");
  state.className = "events-empty";
  state.style.textAlign = "left";
  state.textContent = cfg.key_present
    ? `Ready: ${cfg.model_id} (${cfg.model_vendor}). Assessments can run.`
    : cfg.configured
      ? "Reference saved, but no key resolves under it — assessments will fail."
      : "Not configured. Assessments will refuse to run until a model and key "
        + "are set: sending your tool catalogue to a model nobody chose is not "
        + "a sane default.";
  body.appendChild(state);
  body.appendChild(riskNote(cfg.evidence_basis));
}

// --- the CISO view --------------------------------------------------------

async function loadRiskSummary() {
  const body = document.querySelector("#risk-summary-body");
  if (!body) return;
  body.textContent = "Loading…";
  let data;
  try {
    data = await api("/api/v1/admin/risk/summary");
  } catch (error) { renderError(body, error); return; }
  body.innerHTML = "";

  const kpis = document.createElement("div");
  kpis.className = "events-kpi-grid";
  const cards = [
    ["SERVERS ASSESSED", `${data.servers_assessed}/${data.servers_total}`,
     `${data.coverage_percent}% coverage`,
     "Every average on this page describes only the assessed ones."],
    ["AVERAGE RISK", String(data.average_normalised), "of 100, assessed servers",
     "Mean normalised score across servers that have been assessed."],
    ["RISK REMOVED", `${data.total_points_reduced}`,
     `points across ${data.bundles_measured} bundle(s)`,
     "Sum of the drop between each bundle's upstreams and what it publishes."],
    ["AVERAGE REDUCTION", `${data.average_percent_reduced}%`, "per measured bundle",
     "How much of the upstream risk curation removed, on average."],
  ];
  for (const [label, value, pill, tip] of cards) {
    const card = document.createElement("div");
    card.className = "events-kpi";
    card.title = tip;
    card.innerHTML =
      `<p class="events-kpi-label">${label}</p>`
      + `<p class="events-kpi-num">${_escape(value)}</p>`
      + `<p class="events-kpi-pill">${_escape(pill)}</p>`;
    kpis.appendChild(card);
  }
  body.appendChild(kpis);

  if (!data.servers_assessed) {
    const empty = document.createElement("p");
    empty.className = "events-empty";
    empty.textContent = "Nothing assessed yet. Open MCP servers, pick one, and "
      + "run Assess risk — then publish a bundle to see what curation removes.";
    body.appendChild(empty);
    body.appendChild(riskNote(data.evidence_basis));
    return;
  }

  // Coverage first: it scopes every number above it.
  const coverage = document.createElement("div");
  coverage.className = "risk-coverage";
  const covLabel = document.createElement("div");
  covLabel.style.display = "flex";
  covLabel.style.justifyContent = "space-between";
  covLabel.style.marginBottom = "6px";
  // Built through the DOM rather than innerHTML: the console ships a
  // CSP of `style-src 'self'`, which blocks a `style=` ATTRIBUTE but
  // not CSSOM assignment. Written as innerHTML these two labels
  // rendered unstyled with a console error and no visible failure.
  const covName = document.createElement("span");
  covName.style.font = "500 11.5px/1.4 var(--vyuu-sans)";
  covName.textContent = "ASSESSMENT COVERAGE";
  const covCount = document.createElement("span");
  covCount.style.font = "600 11px/1 var(--vyuu-mono)";
  covCount.style.color = "var(--vyuu-muted)";
  covCount.textContent = `${data.servers_assessed} of ${data.servers_total} servers`;
  covLabel.append(covName, covCount);
  coverage.appendChild(covLabel);
  coverage.appendChild(_riskBar(data.coverage_percent, 100, "neutral", ""));
  if (data.coverage_percent < 100) {
    const gap = document.createElement("p");
    gap.style.margin = "8px 0 0";
    gap.style.font = "400 11.5px/1.5 var(--vyuu-sans)";
    gap.style.color = "var(--vyuu-muted)";
    gap.textContent =
      `${data.servers_total - data.servers_assessed} server(s) have never been `
      + "assessed. Every figure above describes only the assessed ones — an "
      + "unassessed server is not a safe server, it is an unknown one.";
    coverage.appendChild(gap);
  }
  const staleTotal = (data.servers_stale || 0) + (data.bundles_stale || 0);
  if (staleTotal > 0) {
    // Sits with the coverage caveat because it is the same kind of
    // claim: a score that no longer describes the deployed tools is
    // not evidence about them, any more than an unassessed server is.
    const note = document.createElement("p");
    note.style.margin = "8px 0 0";
    note.style.font = "400 11.5px/1.5 var(--vyuu-sans)";
    note.style.color = "var(--vyuu-warn, var(--vyuu-muted))";
    const parts = [];
    if (data.servers_stale) parts.push(`${data.servers_stale} server(s)`);
    if (data.bundles_stale) parts.push(`${data.bundles_stale} bundle(s)`);
    note.textContent =
      `${parts.join(" and ")} changed since last assessed. Those scores `
      + "describe a tool surface that is no longer deployed — re-assess "
      + "before reading them as current posture.";
    coverage.appendChild(note);
  }
  body.appendChild(coverage);

  body.appendChild(_riskBarSection("WHERE THE RISK IS",
    data.riskiest_servers.map((r) => ({
      label: r.display_name, value: r.normalised, max: 100,
      band: r.band, note: `${r.finding_count} finding(s)`,
      display: `${r.normalised}`,
      stale: r.stale, stale_reason: r.stale_reason,
    }))));

  body.appendChild(_riskBarSection("WHAT CURATION REMOVED",
    data.bundles_with_reduction.map((r) => ({
      label: r.name, value: r.percent_reduced, max: 100, band: "neutral",
      note: `${r.findings_eliminated} eliminated`,
      display: `${r.percent_reduced}%`,
      stale: r.stale, stale_reason: r.stale_reason,
    }))));

  if ((data.owasp_counts || []).length) {
    const top = Math.max(...data.owasp_counts.map((o) => o.count));
    body.appendChild(_riskBarSection("BY OWASP MCP TOP 10",
      data.owasp_counts.map((o) => ({
        label: `${o.id.split(":")[0]} · ${o.title}`, value: o.count, max: top,
        band: "neutral", note: "", display: String(o.count),
      }))));
  }
  body.appendChild(riskNote(data.evidence_basis));
}

// Thresholds mirror AggregateRisk.band on the server. Duplicated so a
// bundle row can be coloured from a stored number without a round trip;
// if the server-side bands move, move these with them.
function _bandFor(score) {
  if (score >= 70) return "critical";
  if (score >= 45) return "high";
  if (score >= 20) return "moderate";
  if (score > 0) return "low";
  return "none";
}

function _riskBar(value, max, band, title) {
  const track = document.createElement("div");
  track.className = "risk-bar-track";
  if (title) track.title = title;
  const fill = document.createElement("div");
  fill.className = "risk-bar-fill";
  fill.dataset.band = band || "neutral";
  const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;
  // A non-zero value must show SOMETHING. A 0.2/100 bar rounding to
  // zero pixels reads as "no risk", which is a different claim.
  fill.style.width = pct > 0 ? `${Math.max(2, pct)}%` : "0";
  track.appendChild(fill);
  return track;
}

function _riskBarSection(title, rows) {
  const wrap = document.createElement("div");
  wrap.style.marginBottom = "20px";
  const head = document.createElement("p");
  head.className = "eyebrow";
  head.style.margin = "0 0 8px";
  head.textContent = title;
  wrap.appendChild(head);
  if (!rows || !rows.length) {
    const empty = document.createElement("p");
    empty.className = "events-empty";
    empty.style.textAlign = "left";
    empty.textContent = "(nothing yet)";
    wrap.appendChild(empty);
    return wrap;
  }
  for (const row of rows) {
    const line = document.createElement("div");
    line.className = "risk-bar-row";
    const label = document.createElement("span");
    label.className = "risk-bar-label";
    label.textContent = row.label;
    label.title = row.note ? `${row.label} — ${row.note}` : row.label;
    if (row.stale) {
      // The number beside this bar describes a tool surface that has
      // since changed. Marked per row, not just in a page-level
      // banner: a reader scanning "where the risk is" is comparing
      // these servers against each other, and a stale row is not
      // comparable to a fresh one.
      const flag = document.createElement("span");
      flag.textContent = "STALE";
      flag.className = "pill pill-warn";
      flag.style.marginLeft = "6px";
      flag.style.font = "600 9px/1 var(--vyuu-mono)";
      flag.style.padding = "2px 4px";
      flag.title = row.stale_reason
        || "Re-assess: the capabilities changed since this score.";
      label.appendChild(flag);
    }
    const value = document.createElement("span");
    value.className = "risk-bar-value";
    value.textContent = row.display;
    line.append(label, _riskBar(row.value, row.max, row.band, row.note), value);
    wrap.appendChild(line);
  }
  return wrap;
}

function _riskSection(title, rows, renderRow) {
  const wrap = document.createElement("div");
  wrap.style.marginBottom = "18px";
  const head = document.createElement("p");
  head.className = "eyebrow";
  head.style.margin = "0 0 8px";
  head.textContent = title;
  wrap.appendChild(head);
  if (!rows || !rows.length) {
    const empty = document.createElement("p");
    empty.className = "events-empty";
    empty.style.textAlign = "left";
    empty.textContent = "(nothing yet)";
    wrap.appendChild(empty);
    return wrap;
  }
  for (const row of rows) {
    const card = document.createElement("div");
    card.className = "risk-finding";
    card.appendChild(renderRow(row));
    wrap.appendChild(card);
  }
  return wrap;
}

const riskSummaryBtn = document.querySelector("#refresh-risk-summary");
if (riskSummaryBtn) riskSummaryBtn.addEventListener("click", loadRiskSummary);
const riskClassifierBtn = document.querySelector("#refresh-risk-classifier");
if (riskClassifierBtn) riskClassifierBtn.addEventListener("click", loadRiskClassifier);

// --- SIEM-1 · SIEM export (Splunk HEC) ------------------------------------
//
// One target per tenant. The row holds a secret-store REFERENCE; the
// token is stored through its own endpoint and never comes back. The
// status strip reads the exporter's in-process delivery counters, so
// "degraded" here means this gateway instance is dropping batches for
// this tenant right now — and `last_error` is Splunk's own message.

function _el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function _siemField(labelText, input, title) {
  const label = _el("label");
  if (title) label.title = title;
  label.appendChild(_el("span", null, labelText));
  label.appendChild(input);
  return label;
}

function _siemCheck(labelText, checked, title) {
  const label = _el("label", "siem-check");
  if (title) label.title = title;
  const input = document.createElement("input");
  input.type = "checkbox";
  input.checked = !!checked;
  label.append(input, _el("span", null, labelText));
  return [label, input];
}

function _siemStatusStrip(cfg, stat) {
  const strip = _el("div", "jit-strip");
  const head = _el("div", "jit-strip-head");
  const title = _el("span", "jit-strip-title", "DELIVERY");
  const stats = stat && stat.stats;
  let subText;
  if (!cfg.configured) subText = "no target configured for this tenant";
  else if (!cfg.enabled) subText = "target saved but disabled";
  else if (!stats) subText = "enabled · nothing sent from this gateway instance yet";
  else subText = stats.degraded ? "DEGRADED · batches are being dropped" : "delivering";
  const sub = _el("span", "jit-strip-sub", subText);
  if (stats && stats.degraded) sub.style.color = "var(--vyuu-orange-deep)";
  head.append(title, sub);
  strip.appendChild(head);

  const body = _el("div", "jit-strip-list");
  if (stats) {
    const grid = _el("div", "siem-stats");
    const cells = [
      ["SENT", stats.sent_events], ["DROPPED", stats.dropped_events],
      ["FAILED BATCHES", stats.failed_batches], ["QUEUE", stats.queue_depth],
    ];
    for (const [k, v] of cells) {
      const cell = _el("div", "siem-stat");
      cell.append(_el("div", "siem-stat-k", k), _el("div", "siem-stat-v", v));
      grid.appendChild(cell);
    }
    body.appendChild(grid);
    const fmt = (iso) => iso ? new Date(iso).toLocaleString() : "—";
    body.appendChild(_el("p", "toolbar-meta",
      `last success ${fmt(stats.last_success_at)} · last failure ${fmt(stats.last_failure_at)}`
      + ` · retried ${stats.retried_batches}`));
    if (stats.last_error) {
      const err = _el("p", "risk-note", `Last error: ${stats.last_error}`);
      err.style.borderLeftColor = "var(--vyuu-orange-deep)";
      body.appendChild(err);
    }
  }
  if (cfg.deployment_target_configured) {
    body.appendChild(_el("p", "risk-note",
      "This gateway also ships every tenant's events to a deployment-level SIEM "
      + "configured by whoever operates it. Your target below is in addition to that."));
  }
  strip.appendChild(body);
  return strip;
}

async function loadSiemExport() {
  const body = document.querySelector("#siem-export-body");
  if (!body) return;
  body.textContent = "Loading…";
  let cfg, stat;
  try {
    cfg = await api("/api/v1/admin/siem/config");
    stat = await api("/api/v1/admin/siem/status");
  } catch (error) { renderError(body, error); return; }
  body.innerHTML = "";

  body.appendChild(_siemStatusStrip(cfg, stat));

  // --- the target ------------------------------------------------------
  const form = _el("form");
  form.style.marginTop = "14px";
  const grid = _el("div", "siem-grid");

  const [enabledLabel, enabled] = _siemCheck("Enabled", cfg.configured ? cfg.enabled : true,
    "Off keeps the settings but ships nothing.");
  const [verifyLabel, verify] = _siemCheck("Verify TLS certificate", cfg.verify_tls,
    "Turn off only for a Splunk with a self-signed certificate you trust.");

  const url = document.createElement("input");
  url.type = "text"; url.placeholder = "https://splunk.corp:8088"; url.value = cfg.hec_url || "";
  const ref = document.createElement("input");
  ref.type = "text"; ref.placeholder = "secret-store ref (not the token)";
  ref.value = cfg.hec_token_ref || "";
  const index = document.createElement("input");
  index.type = "text"; index.placeholder = "index (optional)"; index.value = cfg.index || "";
  const source = document.createElement("input");
  source.type = "text"; source.value = cfg.source || "vyuu-mcp-gateway";
  const host = document.createElement("input");
  host.type = "text"; host.placeholder = "defaults to the gateway instance id";
  host.value = cfg.host_override || "";
  const level = document.createElement("select");
  for (const name of cfg.log_levels || ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]) {
    const o = document.createElement("option"); o.value = name; o.textContent = name;
    level.appendChild(o);
  }
  level.value = cfg.min_log_level || "WARNING";
  const batch = document.createElement("input");
  batch.type = "number"; batch.min = "1"; batch.max = "1000"; batch.value = cfg.batch_max_events;
  const flush = document.createElement("input");
  flush.type = "number"; flush.min = "0.2"; flush.max = "60"; flush.step = "0.1";
  flush.value = cfg.flush_interval_seconds;

  grid.append(
    _siemField("HEC URL", url,
      "The collector origin. A pasted /services/collector/event path is fine; it is normalised."),
    _siemField("Token secret ref", ref,
      "The NAME of the secret holding the HEC token. Written to the tenants table; "
      + "the token is not."),
    _siemField("Index", index, "Leave empty to use the token's default index."),
    _siemField("Source", source, "The HEC source field."),
    _siemField("Host", host, "The HEC host field."),
    _siemField("Gateway log level", level, "Only matters when the gateway log category is on."),
    _siemField("Batch size", batch, "Events per POST."),
    _siemField("Flush interval (s)", flush, "How long to wait for a batch to fill."),
    enabledLabel, verifyLabel,
  );
  form.appendChild(grid);

  // Categories: what leaves. Each is a documented sourcetype.
  const catHead = _el("p", "eyebrow", "WHAT TO SEND");
  catHead.style.margin = "6px 0 2px";
  form.appendChild(catHead);
  const cats = _el("div", "siem-categories");
  const chosen = new Set(cfg.categories || []);
  const catInputs = {};
  for (const opt of cfg.options || []) {
    const label = _el("label");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = cfg.configured ? chosen.has(opt.id) : opt.default;
    catInputs[opt.id] = input;
    const text = _el("span");
    text.append(_el("span", "siem-cat-name", `${opt.label} `),
                _el("span", "siem-cat-desc", opt.description));
    label.append(input, text);
    cats.appendChild(label);
  }
  form.appendChild(cats);

  const [rawLabel, raw] = _siemCheck("Include raw tool payloads", cfg.include_raw_payloads,
    "Only when policy already captures them (H5). A SIEM is one more place customer "
    + "data would live.");
  rawLabel.style.margin = "0 0 12px";
  form.appendChild(rawLabel);

  const actions = _el("div", "siem-actions");
  const save = _el("button", null, cfg.configured ? "Save" : "Create target");
  save.type = "submit";
  const test = _el("button", null, "Send test event");
  test.type = "button";
  test.disabled = !cfg.configured || !cfg.token_present;
  test.title = test.disabled ? "Save a target and store its token first."
    : "Delivers one heartbeat now, bypassing the queue, and shows Splunk's answer.";
  const clear = _el("button", null, "Remove target");
  clear.type = "button";
  clear.disabled = !cfg.configured;
  const status = _el("span", "toolbar-meta");
  actions.append(save, test, clear, status);
  form.appendChild(actions);

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!url.value.trim()) { status.textContent = "Enter the HEC URL."; return; }
    if (!ref.value.trim()) { status.textContent = "Enter a secret ref."; return; }
    status.textContent = "Saving…";
    try {
      await api("/api/v1/admin/siem/config", {
        method: "PUT",
        body: JSON.stringify({
          enabled: enabled.checked,
          hec_url: url.value.trim(),
          hec_token_ref: ref.value.trim(),
          index: index.value.trim() || null,
          source: source.value.trim() || "vyuu-mcp-gateway",
          host_override: host.value.trim() || null,
          verify_tls: verify.checked,
          categories: Object.keys(catInputs).filter((k) => catInputs[k].checked),
          include_raw_payloads: raw.checked,
          min_log_level: level.value,
          batch_max_events: Number(batch.value) || 100,
          flush_interval_seconds: Number(flush.value) || 2,
        }),
      });
      status.textContent = "Saved.";
      await loadSiemExport();
    } catch (error) { status.textContent = String(error); }
  });
  test.addEventListener("click", async () => {
    status.textContent = "Sending…";
    try {
      const result = await api("/api/v1/admin/siem/test", { method: "POST" });
      status.textContent = (result.ok ? "OK — " : "Failed — ") + result.detail;
      status.style.color = result.ok ? "" : "var(--vyuu-orange-deep)";
    } catch (error) { status.textContent = String(error); }
  });
  clear.addEventListener("click", async () => {
    const sure = window.confirm(
      "Remove this tenant's SIEM target? Nothing ships until one is created again.");
    if (!sure) return;
    status.textContent = "Removing…";
    try {
      await api("/api/v1/admin/siem/config", { method: "DELETE" });
      status.textContent = "Removed.";
      await loadSiemExport();
    } catch (error) { status.textContent = String(error); }
  });
  body.appendChild(form);

  // --- the token itself ---------------------------------------------------
  //
  // Same three states as the risk classifier key: no ref yet, a ref with
  // no token behind it, a token stored. Reported separately because an
  // operator who only had the second found out when nothing arrived.
  const keyStrip = _el("div", "jit-strip");
  keyStrip.style.marginTop = "14px";
  const keyHead = _el("div", "jit-strip-head");
  const keyTitle = _el("span", "jit-strip-title", "HEC TOKEN");
  const keySub = _el("span", "jit-strip-sub", cfg.token_present
    ? `stored under ${cfg.hec_token_ref} · ${cfg.secret_backend}`
    : cfg.hec_token_ref
      ? `no token found under ${cfg.hec_token_ref} · ${cfg.secret_backend}`
      : "save a target with a secret ref first");
  keyHead.append(keyTitle, keySub);
  keyStrip.appendChild(keyHead);
  const keyBody = _el("div", "jit-strip-list");
  if (!cfg.configured) {
    const p0 = _el("p", "events-empty", "Create the target above first.");
    p0.style.textAlign = "left";
    keyBody.appendChild(p0);
  } else if (cfg.secret_writable) {
    const keyForm = _el("form", "akp-form");
    const keyInput = document.createElement("input");
    keyInput.type = "password";
    keyInput.placeholder = cfg.token_present ? "replace the stored token" : "paste the HEC token";
    keyInput.autocomplete = "off";
    keyInput.style.flex = "1";
    keyInput.style.minWidth = "220px";
    const keySave = _el("button", null, cfg.token_present ? "Replace" : "Store");
    keySave.type = "submit";
    const keyStatus = _el("span", "toolbar-meta");
    keyForm.append(keyInput, keySave, keyStatus);
    keyForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const value = keyInput.value.trim();
      if (!value) { keyStatus.textContent = "Paste a token."; return; }
      keyStatus.textContent = "Storing…";
      try {
        await api("/api/v1/admin/siem/token", {
          method: "POST", body: JSON.stringify({ hec_token: value }),
        });
        keyInput.value = "";
        keyStatus.textContent = "Stored.";
        await loadSiemExport();
      } catch (error) { keyStatus.textContent = String(error); }
    });
    keyBody.appendChild(keyForm);
    keyBody.appendChild(_el("p", "risk-note",
      `${cfg.secret_backend} keeps secrets in process memory and loses them on restart. `
      + "Fine for a lab; in production point the gateway at Vault, AWS Secrets Manager or "
      + "Kubernetes and create the secret there."));
  } else {
    const readonly = _el("p", "risk-note",
      `${cfg.secret_backend} is read-only from here. Create a secret named "${cfg.hec_token_ref}" `
      + "in that backend directly — it keeps its own access control, rotation and audit, "
      + "which is why this console does not write into it.");
    readonly.style.borderLeftColor = "var(--vyuu-orange-deep)";
    keyBody.appendChild(readonly);
  }
  keyStrip.appendChild(keyBody);
  body.appendChild(keyStrip);
}

// --- OTEL-1 · Telemetry (OpenTelemetry → Splunk OTel Collector) -------------

async function loadTelemetry() {
  const body = document.querySelector("#telemetry-body");
  if (!body) return;
  body.textContent = "Loading…";
  let data;
  try {
    data = await api("/api/v1/admin/telemetry/status");
  } catch (error) { renderError(body, error); return; }
  body.innerHTML = "";
  const st = data.status || {};

  const strip = _el("div", "jit-strip");
  const head = _el("div", "jit-strip-head");
  const title = _el("span", "jit-strip-title", "PIPELINE");
  let subText;
  if (st.enabled) subText = `exporting to ${st.endpoint} as ${st.service_name}`;
  else if (st.requested && st.available === false) subText = "requested but unavailable";
  else subText = "off";
  const sub = _el("span", "jit-strip-sub", subText);
  if (st.requested && st.available === false) sub.style.color = "var(--vyuu-orange-deep)";
  head.append(title, sub);
  strip.appendChild(head);
  const stripBody = _el("div", "jit-strip-list");
  if (st.enabled) {
    const grid = _el("div", "siem-stats");
    const cells = [
      ["SPANS STARTED", st.spans_started], ["METRICS RECORDED", st.metrics_recorded],
      ["EXPORTS OK", st.export_successes], ["EXPORTS FAILED", st.export_failures],
    ];
    for (const [k, v] of cells) {
      const cell = _el("div", "siem-stat");
      cell.append(_el("div", "siem-stat-k", k), _el("div", "siem-stat-v", v ?? 0));
      grid.appendChild(cell);
    }
    stripBody.appendChild(grid);
    const fmt = (iso) => iso ? new Date(iso).toLocaleString() : "—";
    stripBody.appendChild(_el("p", "toolbar-meta",
      `traces ${st.traces_enabled ? "on" : "off"} (sample ${st.sample_ratio}) · metrics `
      + `${st.metrics_enabled ? "on" : "off"} every ${st.metric_export_interval_seconds}s · `
      + `last export ${fmt(st.last_export_at)}`));
    if (st.last_export_error) {
      const err = _el("p", "risk-note", `Last export error: ${st.last_export_error}`);
      err.style.borderLeftColor = "var(--vyuu-orange-deep)";
      stripBody.appendChild(err);
    }
    const actions = _el("div", "siem-actions");
    const test = _el("button", null, "Send test signal");
    test.type = "button";
    test.title = "One span and one metric, flushed now. OK means the collector accepted them.";
    const status = _el("span", "toolbar-meta");
    test.addEventListener("click", async () => {
      status.textContent = "Sending…";
      try {
        const result = await api("/api/v1/admin/telemetry/test", { method: "POST" });
        status.textContent = (result.ok ? "OK — " : "Failed — ") + result.detail;
        status.style.color = result.ok ? "" : "var(--vyuu-orange-deep)";
        if (result.ok) await loadTelemetry();
      } catch (error) { status.textContent = String(error); }
    });
    actions.append(test, status);
    stripBody.appendChild(actions);
  } else if (st.reason) {
    const why = _el("p", "risk-note", st.reason);
    why.style.borderLeftColor = "var(--vyuu-orange-deep)";
    stripBody.appendChild(why);
  } else {
    const off = _el("p", "events-empty",
      "Not enabled. Set the variables below on the deployment and restart.");
    off.style.textAlign = "left";
    stripBody.appendChild(off);
  }
  strip.appendChild(stripBody);
  body.appendChild(strip);

  // Why this is not a form: one tenant must not be able to point the
  // whole gateway's telemetry — which carries every tenant's ids in
  // span attributes — at a collector of their choosing.
  const note = _el("p", "risk-note",
    "Deployment-level on purpose. Span attributes carry every tenant's identifiers, so the "
    + "collector endpoint is set by whoever runs the gateway, not from this console.");
  note.style.marginTop = "14px";
  body.appendChild(note);

  const howHead = _el("p", "eyebrow", "TO ENABLE OR CHANGE");
  howHead.style.margin = "12px 0 4px";
  body.appendChild(howHead);
  const pre = _el("pre", "siem-pre");
  pre.textContent = (data.switch_instructions || []).join(String.fromCharCode(10));
  body.appendChild(pre);

  const sigHead = _el("p", "eyebrow", "WHAT IS EMITTED");
  sigHead.style.margin = "12px 0 4px";
  body.appendChild(sigHead);
  const table = _el("table", "akp-table");
  const thead = _el("thead"); const hr = _el("tr");
  for (const h of ["Signal", "Kind", "Attributes (bounded cardinality)"]) {
    hr.appendChild(_el("th", null, h));
  }
  thead.appendChild(hr); table.appendChild(thead);
  const tbody = _el("tbody");
  for (const sig of data.signals || []) {
    const tr = _el("tr");
    const name = _el("td"); name.appendChild(_el("code", null, sig.name));
    tr.append(name, _el("td", null, sig.kind), _el("td", null, sig.attributes));
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  body.appendChild(table);
}

const siemExportBtn = document.querySelector("#refresh-siem-export");
if (siemExportBtn) siemExportBtn.addEventListener("click", loadSiemExport);
const telemetryBtn = document.querySelector("#refresh-telemetry");
if (telemetryBtn) telemetryBtn.addEventListener("click", loadTelemetry);


// --- CRED-1 · API key lifetime policy ------------------------------------
//
// `user_api_keys.expires_at` was always enforced and never set, so a
// user key lived until somebody remembered to revoke it. This panel is
// where the ceiling gets declared.
//
// Precedence is user > group > tenant > unlimited, and with several
// groups the SHORTEST wins — otherwise joining a group would extend
// your own credential lifetime. The copy says so, because an operator
// setting a loose group policy needs to know it cannot widen anyone.

const akpOutput = document.querySelector("#akp-output");
const akpScope = document.querySelector("#akp-scope");
const akpPrincipal = document.querySelector("#akp-principal");
const akpTtl = document.querySelector("#akp-ttl");
const akpNote = document.querySelector("#akp-note");
const akpForm = document.querySelector("#akp-form");
const akpFormStatus = document.querySelector("#akp-form-status");

let akpCache = { policies: [], nonconforming: [] };

function akpDays(seconds) {
  const days = seconds / 86400;
  if (days >= 1 && Number.isInteger(days)) {
    return `${days} day${days === 1 ? "" : "s"}`;
  }
  return formatDuration(seconds);
}

async function akpRefreshPrincipalOptions() {
  if (!akpScope || !akpPrincipal) return;
  if (akpScope.value === "tenant") {
    // The tenant row keys on the tenant's own id — there is nobody to
    // pick, and offering a list would imply otherwise.
    akpPrincipal.innerHTML = "";
    akpPrincipal.disabled = true;
    return;
  }
  akpPrincipal.disabled = false;
  await ensurePrincipalCacheLoaded();
  if (akpScope.value === "user") {
    fillSelectOptions(akpPrincipal, principalCache.users, userLabel);
  } else {
    fillSelectOptions(akpPrincipal, principalCache.groups, groupLabel);
  }
}

if (akpScope) akpScope.addEventListener("change", akpRefreshPrincipalOptions);

if (akpForm) {
  akpForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const days = Number(akpTtl.value);
    if (!Number.isFinite(days) || days <= 0) {
      akpFormStatus.textContent = "Enter a positive number of days.";
      return;
    }
    const body = {
      principal_kind: akpScope.value,
      max_ttl_seconds: Math.round(days * 86400),
      note: akpNote.value.trim() || null,
    };
    if (akpScope.value !== "tenant") {
      if (!akpPrincipal.value) {
        akpFormStatus.textContent = "Pick who this applies to.";
        return;
      }
      body.principal_id = akpPrincipal.value;
    }
    akpFormStatus.textContent = "Saving…";
    try {
      await api("/api/v1/admin/api-key-policies", {
        method: "PUT",
        body: JSON.stringify(body),
      });
      akpFormStatus.textContent = "Saved.";
      akpTtl.value = "";
      akpNote.value = "";
      await loadApiKeyPolicies();
    } catch (error) {
      akpFormStatus.textContent = String(error);
    }
  });
}

async function loadApiKeyPolicies() {
  if (!akpOutput) return;
  akpOutput.innerHTML =
    '<tr><td colspan="5" class="events-empty">Loading…</td></tr>';
  try {
    akpCache = await api("/api/v1/admin/api-key-policies");
  } catch (error) {
    akpOutput.innerHTML = "";
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "events-empty";
    td.textContent = String(error);
    tr.appendChild(td);
    akpOutput.appendChild(tr);
    return;
  }
  await akpRefreshPrincipalOptions();
  renderApiKeyPolicies();
}

function renderApiKeyPolicies() {
  const policies = akpCache.policies || [];
  const offenders = akpCache.nonconforming || [];

  const tenantRow = policies.find((p) => p.principal_kind === "tenant");
  const defaultEl = document.querySelector("#akp-kpi-default");
  if (defaultEl) {
    defaultEl.textContent = tenantRow ? akpDays(tenantRow.max_ttl_seconds) : "none";
    defaultEl.title = tenantRow
      ? "Applies to any user with no group or user policy of their own."
      : "No tenant default — keys issued to users without a more specific "
        + "policy never expire.";
  }
  const exceptionsEl = document.querySelector("#akp-kpi-exceptions");
  if (exceptionsEl) {
    exceptionsEl.textContent = String(
      policies.filter((p) => p.principal_kind !== "tenant").length);
  }
  const offendersEl = document.querySelector("#akp-kpi-offenders");
  const offendersHint = document.querySelector("#akp-kpi-offenders-hint");
  if (offendersEl) offendersEl.textContent = String(offenders.length);
  if (offendersHint) {
    if (!offenders.length) {
      offendersHint.textContent = "every live key is within policy";
      offendersHint.title = "";
    } else {
      // The action is separate from saving a policy on purpose:
      // shortening credentials that are in use is an outage for
      // whoever holds them, and the operator picks when it lands.
      offendersHint.innerHTML = "";
      const apply = document.createElement("button");
      apply.type = "button";
      apply.className = "vservers-row-url-copy";
      apply.textContent = `Bring ${offenders.length} into policy`;
      apply.title = offenders
        .slice(0, 8)
        .map((k) => `${k.user_email || k.user_id} · ${k.label}`)
        .join(" | ");
      apply.addEventListener("click", async () => {
        const names = offenders.slice(0, 5)
          .map((k) => `${k.user_email || k.user_id} (${k.label})`).join(", ");
        if (!confirm(
          `Shorten ${offenders.length} live key(s) to the current policy?`
          + ` Includes: ${names}.`
          + " They keep working until the new expiry, they are not revoked now."
        )) return;
        apply.disabled = true;
        try {
          const result = await api(
            "/api/v1/admin/api-key-policies/apply-existing", { method: "POST" });
          await loadApiKeyPolicies();
          alert(`${result.keys_updated} key(s) now expire within policy.`);
        } catch (error) {
          alert(String(error));
        } finally {
          apply.disabled = false;
        }
      });
      offendersHint.appendChild(apply);
    }
  }

  akpOutput.innerHTML = "";
  if (!policies.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "events-empty";
    td.textContent = "No policy set — API keys in this tenant never expire on "
      + "their own. Set a tenant default above to change that.";
    tr.appendChild(td);
    akpOutput.appendChild(tr);
    return;
  }

  for (const policy of policies) {
    const tr = document.createElement("tr");

    const scope = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = "vserver-jit-gated";
    pill.textContent = policy.principal_kind;
    scope.appendChild(pill);
    tr.appendChild(scope);

    const who = document.createElement("td");
    who.textContent = policy.principal_display
      || `${policy.principal_id.slice(0, 8)}…`;
    who.title = policy.principal_id;
    tr.appendChild(who);

    const ttl = document.createElement("td");
    ttl.style.textAlign = "right";
    ttl.style.fontFamily = "var(--vyuu-mono)";
    ttl.textContent = akpDays(policy.max_ttl_seconds);
    tr.appendChild(ttl);

    const note = document.createElement("td");
    note.style.color = "var(--vyuu-muted)";
    note.style.fontSize = "11.5px";
    note.textContent = policy.note || "—";
    tr.appendChild(note);

    const actions = document.createElement("td");
    const del = document.createElement("button");
    del.type = "button";
    del.className = "vservers-row-url-copy";
    del.textContent = "Remove";
    del.title = "Removing does not lengthen keys already issued — their "
      + "expiry is already stamped. It changes what the next one resolves to.";
    del.addEventListener("click", async () => {
      if (!confirm(
        `Remove the ${policy.principal_kind} policy for `
        + `${policy.principal_display || policy.principal_id}?`
        + " Future keys fall back to the next broader scope."
      )) return;
      try {
        await api(
          `/api/v1/admin/api-key-policies/${encodeURIComponent(policy.id)}`,
          { method: "DELETE" });
        await loadApiKeyPolicies();
      } catch (error) { alert(String(error)); }
    });
    actions.appendChild(del);
    tr.appendChild(actions);

    akpOutput.appendChild(tr);
  }
}

const akpRefreshBtn = document.querySelector("#refresh-api-key-policy");
if (akpRefreshBtn) akpRefreshBtn.addEventListener("click", loadApiKeyPolicies);


// --- Security posture ----------------------------------------------------
//
// Renders the CONSEQUENCE of each control's current state, not just a
// boolean. "Retention: off" means nothing to most readers; "tool-call
// history grows without limit" is the sentence that gets it enabled.

async function loadSecurityPosture() {
  const tbody = document.querySelector("#security-posture-output");
  if (!tbody) return;
  tbody.innerHTML =
    '<tr><td colspan="4" class="events-empty">Loading…</td></tr>';
  let data;
  try {
    data = await api("/api/v1/admin/security-posture");
  } catch (error) {
    tbody.innerHTML = "";
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 4;
    td.className = "events-empty";
    td.textContent = String(error.message || error);
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  // CIMD id, when this gateway can serve one (needs an https public
  // base url — the whole trust model is "whoever controls this URL is
  // the client", which over http is whoever controls the network).
  const cimdRow = document.querySelector("#cimd-row");
  if (cimdRow) {
    cimdRow.classList.toggle("is-hidden", !data.cimd_client_id);
    if (data.cimd_client_id) {
      document.querySelector("#cimd-client-id").textContent = data.cimd_client_id;
    }
  }

  tbody.innerHTML = "";
  // Warnings first: a panel is scanned top-down, and the rows that cost
  // something should not be below the ones that do not.
  const order = { warn: 0, info: 1, good: 2 };
  const rows = [...data.controls].sort(
    (a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9)
  );
  for (const control of rows) {
    const tr = document.createElement("tr");

    const stateCell = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = "posture-pill";
    pill.dataset.severity = control.severity;
    pill.textContent = control.enabled ? "on" : "off";
    stateCell.appendChild(pill);
    tr.appendChild(stateCell);

    const nameCell = document.createElement("td");
    const name = document.createElement("span");
    name.className = "posture-control";
    name.textContent = control.label;
    nameCell.appendChild(name);
    const detail = document.createElement("span");
    detail.className = "posture-detail";
    detail.textContent = control.detail;
    nameCell.appendChild(detail);
    tr.appendChild(nameCell);

    const consequenceCell = document.createElement("td");
    consequenceCell.className = "posture-consequence";
    consequenceCell.textContent = control.consequence;
    tr.appendChild(consequenceCell);

    const envCell = document.createElement("td");
    envCell.className = "posture-env";
    // Comma-joined rather than newline-joined: `operator_ui._JS` is a
    // plain (non-raw) Python string, so a newline escape here becomes a
    // REAL newline in the served JS and breaks the double-quoted
    // string. It also reads better in a table cell that has no
    // `white-space` styling to honour line breaks.
    envCell.textContent = (control.env_vars || []).join(", ");
    tr.appendChild(envCell);

    tbody.appendChild(tr);
  }
}

const _refreshPostureBtn = document.querySelector("#refresh-security-posture");
if (_refreshPostureBtn) {
  _refreshPostureBtn.addEventListener("click", loadSecurityPosture);
}
const _copyCimdBtn = document.querySelector("#copy-cimd");
if (_copyCimdBtn) {
  _copyCimdBtn.addEventListener("click", () => {
    const value = document.querySelector("#cimd-client-id").textContent || "";
    navigator.clipboard.writeText(value).then(
      () => {
        _copyCimdBtn.textContent = "Copied";
        _copyCimdBtn.dataset.copied = "true";
        setTimeout(() => {
          _copyCimdBtn.textContent = "Copy";
          delete _copyCimdBtn.dataset.copied;
        }, 1200);
      },
      () => { _copyCimdBtn.textContent = "Failed"; },
    );
  });
}

// --- JIT-1 · live elevations --------------------------------------------
// Server-computed `seconds_remaining` is the source of truth (the
// browser's clock may be minutes off, and "expires in 3m" being wrong is
// exactly the kind of thing that erodes trust in a security console). We
// tick it down locally between refreshes purely so the number moves.

const jitElevationsStrip = document.querySelector("#jit-elevations-strip");
const jitElevationsList = document.querySelector("#jit-elevations-list");
const jitElevationsCount = document.querySelector("#jit-elevations-count");
let jitElevationsCache = [];
let jitTickHandle = null;

async function loadActiveElevations() {
  if (!jitElevationsStrip) return;
  try {
    // Both granularities in one strip: "who holds temporary authority
    // right now" is one question, and splitting it across two panels
    // would let an operator answer half of it and think they were done.
    const [vserverLevel, toolLevel] = await Promise.all([
      api("/api/v1/vservers/jit/elevations"),
      api("/api/v1/vservers/jit/tool-elevations"),
    ]);
    jitElevationsCache = [
      ...vserverLevel,
      ...toolLevel.map((e) => ({ ...e, is_tool: true })),
    ].sort((a, b) => a.seconds_remaining - b.seconds_remaining);
  } catch {
    // A failure here must not take the approval queue down with it —
    // the strip is context, the queue is the job.
    jitElevationsCache = [];
  }
  renderActiveElevations();
}

function renderActiveElevations() {
  if (!jitElevationsStrip) return;
  const rows = jitElevationsCache.filter((e) => e.seconds_remaining > 0);
  jitElevationsStrip.classList.toggle("is-hidden", rows.length === 0);
  if (jitTickHandle) { clearInterval(jitTickHandle); jitTickHandle = null; }
  if (!rows.length) return;

  jitElevationsCount.textContent =
    `${rows.length} ${rows.length === 1 ? "person has" : "people have"} temporary access right now`;
  jitElevationsList.innerHTML = "";
  for (const e of rows) {
    const row = document.createElement("div");
    row.className = "jit-elevation-row";

    const who = document.createElement("span");
    who.className = "jit-elevation-who";
    who.textContent = e.user_email || `user ${(e.user_id || "").slice(0, 8)}…`;
    row.appendChild(who);

    const target = document.createElement("span");
    target.className = "jit-elevation-target";
    // `granted_via` distinguishes a self-served elevation from one a
    // human approved — the first is the one worth a second look. A tool
    // elevation names the tool, because "elevated into finance-readonly"
    // and "elevated into finance-readonly/db_migrate" are very different
    // amounts of authority.
    const scope = e.is_tool
      ? `${e.vserver_name}/${e.exposed_tool_name}`
      : e.vserver_name;
    target.textContent = `→ ${scope} · ${e.granted_via.replace("_", " ")}`;
    row.appendChild(target);
    if (e.is_tool) {
      const badge = document.createElement("span");
      badge.className = "ar-jit-pill";
      badge.textContent = "TOOL";
      badge.title = "Elevation into a single tool, not the whole bundle";
      row.appendChild(badge);
    }

    if (e.justification) {
      const why = document.createElement("span");
      why.className = "jit-elevation-why";
      why.textContent = `"${e.justification}"`;
      why.title = e.justification;
      row.appendChild(why);
    }

    const left = document.createElement("span");
    left.className = "jit-elevation-left";
    left.dataset.expiresAt = e.expires_at;
    left.dataset.remaining = String(e.seconds_remaining);
    left.textContent = `${formatDuration(e.seconds_remaining)} left`;
    left.title = `expires ${new Date(e.expires_at).toLocaleString()}`;
    row.appendChild(left);

    jitElevationsList.appendChild(row);
  }

  jitTickHandle = setInterval(() => {
    let anyLive = false;
    for (const el of jitElevationsList.querySelectorAll(".jit-elevation-left")) {
      const remaining = Number(el.dataset.remaining) - 1;
      el.dataset.remaining = String(remaining);
      if (remaining > 0) {
        anyLive = true;
        el.textContent = `${formatDuration(remaining)} left`;
      } else {
        el.textContent = "expired";
      }
    }
    // Everything lapsed — re-fetch rather than leave a strip of
    // "expired" rows implying access that has already ended.
    if (!anyLive) loadActiveElevations();
  }, 1000);
}

async function loadAccessRequests() {
  loadActiveElevations();
  accessRequestsOutput.innerHTML =
    '<tr><td colspan="5" class="events-empty">Loading…</td></tr>';
  try {
    // Always fetch all statuses — the pill bar filters client-side
    // so toggling between "pending" and "approved" is instant. The
    // KPIs also need full-cache data (approved · 7d, declined · 7d).
    accessRequestsCache = await api("/api/v1/access-requests");
    renderAccessRequests();
  } catch (error) {
    accessRequestsOutput.innerHTML = "";
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "events-empty";
    td.textContent = String(error.message || error);
    tr.appendChild(td);
    accessRequestsOutput.appendChild(tr);
  }
}

function renderAccessRequests() {
  renderAccessRequestsKpis(accessRequestsCache);

  const needle = (accessRequestsSearch && accessRequestsSearch.value || "")
    .trim().toLowerCase();
  const pill = accessRequestsPillState.current;
  const filtered = accessRequestsCache.filter((r) => {
    if (needle) {
      const hay = `${r.user_email || ""} ${r.vserver_name || ""} ${r.note || ""}`.toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    if (pill === "all") return true;
    return r.status === pill;
  });

  accessRequestsCount.textContent =
    filtered.length === accessRequestsCache.length
      ? `${filtered.length} requests`
      : `${filtered.length} of ${accessRequestsCache.length} requests`;

  accessRequestsOutput.innerHTML = "";
  if (!filtered.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "events-empty";
    td.textContent = pill === "pending"
      ? "No pending requests — the queue is empty."
      : (accessRequestsCache.length === 0
          ? "No access requests recorded yet."
          : `(0 of ${accessRequestsCache.length} requests match the active filter)`);
    tr.appendChild(td);
    accessRequestsOutput.appendChild(tr);
    return;
  }
  for (const r of filtered) {
    accessRequestsOutput.appendChild(renderAccessRequestRow(r));
  }
}

function renderAccessRequestsKpis(rows) {
  let pending = 0;
  let approved7d = 0;
  let declined7d = 0;
  let oldestPendingAt = null;
  const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  for (const r of rows) {
    if (r.status === "pending") {
      pending++;
      const t = Date.parse(r.created_at);
      if (Number.isFinite(t) && (oldestPendingAt === null || t < oldestPendingAt)) {
        oldestPendingAt = t;
      }
    } else if (r.decided_at) {
      const t = Date.parse(r.decided_at);
      if (Number.isFinite(t) && t >= sevenDaysAgo) {
        if (r.status === "approved") approved7d++;
        else if (r.status === "declined") declined7d++;
      }
    }
  }
  const set = (id, v) => {
    const el = document.querySelector(`#${id}`);
    if (el) el.textContent = v;
  };
  set("ar-kpi-pending", pending.toLocaleString());
  set("ar-kpi-approved", approved7d.toLocaleString());
  set("ar-kpi-declined", declined7d.toLocaleString());
  if (oldestPendingAt !== null) {
    set("ar-kpi-oldest", formatAge(oldestPendingAt));
    set("ar-kpi-oldest-sub", "longest waiting");
  } else {
    set("ar-kpi-oldest", "—");
    set("ar-kpi-oldest-sub", "no pending requests");
  }
}

// Coarser-than-formatRelativeTime variant that stays relative even
// past 24h. The KPI tile reads as a "how long" number ("3d", "2w"),
// not a timestamp.
function formatAge(epochMs) {
  const seconds = Math.max(0, (Date.now() - epochMs) / 1000);
  if (seconds < 60) return "<1m";
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  if (seconds < 86400 * 14) return `${Math.round(seconds / 86400)}d`;
  return `${Math.round(seconds / (86400 * 7))}w`;
}

function renderAccessRequestRow(req) {
  const tr = document.createElement("tr");
  tr.dataset.status = req.status;
  tr.addEventListener("click", () => openAccessRequestDrawer(req));

  // REQUEST — user email + vserver name (the human-readable summary)
  const reqCell = document.createElement("td");
  const wrap = document.createElement("div");
  wrap.className = "ar-row-request";
  const top = document.createElement("span");
  top.className = "ar-row-request-line";
  top.textContent = req.user_email
    || (req.user_display_name)
    || `(user ${(req.user_id || "").slice(0, 8)}…)`;
  wrap.appendChild(top);
  const target = document.createElement("span");
  target.className = "ar-row-request-target";
  const visBadge = req.vserver_visibility ? ` · ${req.vserver_visibility}` : "";
  target.textContent = `wants → ${req.vserver_name || `vserver ${(req.vserver_id || "").slice(0, 8)}…`}${visBadge}`;
  wrap.appendChild(target);
  reqCell.appendChild(wrap);
  tr.appendChild(reqCell);

  // NOTE — the user's "why I want this" blurb. Truncate via CSS;
  // full text in title attr.
  const noteCell = document.createElement("td");
  // JIT-1: the window comes first. "How much access" is the question the
  // reviewer is answering; the prose reason is supporting evidence.
  if (req.requested_duration_seconds) {
    const jit = document.createElement("span");
    jit.className = "ar-jit-pill";
    jit.textContent = `JIT · ${formatDuration(req.requested_duration_seconds)}`;
    jit.title = "Time-boxed elevation — expires automatically";
    noteCell.appendChild(jit);
  }
  const noteSpan = document.createElement("span");
  noteSpan.className = "ar-row-note";
  if (req.note) {
    noteSpan.textContent = `"${req.note}"`;
    noteSpan.title = req.note;
  } else {
    noteSpan.textContent = "(no note)";
    noteSpan.style.opacity = "0.65";
  }
  noteCell.appendChild(noteSpan);
  tr.appendChild(noteCell);

  // STATUS pill
  const statusCell = document.createElement("td");
  const pill = document.createElement("span");
  pill.className = "ar-status-pill";
  pill.dataset.status = req.status;
  pill.textContent = req.status;
  statusCell.appendChild(pill);
  tr.appendChild(statusCell);

  // SUBMITTED — relative time
  const subCell = document.createElement("td");
  subCell.style.color = "var(--vyuu-muted)";
  subCell.style.fontSize = "11.5px";
  subCell.textContent = formatRelativeTime(req.created_at);
  subCell.title = new Date(req.created_at).toLocaleString();
  tr.appendChild(subCell);

  // ACTIONS — Approve / Decline inline on pending rows; Drill in
  // always available for context.
  const actionsCell = document.createElement("td");
  const actions = document.createElement("div");
  actions.className = "users-row-actions";
  if (req.status === "pending") {
    const approve = document.createElement("button");
    approve.type = "button";
    approve.textContent = "Approve";
    approve.addEventListener("click", (e) => {
      e.stopPropagation();
      approveAccessRequest(req);
    });
    actions.appendChild(approve);
    const decline = document.createElement("button");
    decline.type = "button";
    decline.className = "is-danger";
    decline.textContent = "Decline";
    decline.addEventListener("click", (e) => {
      e.stopPropagation();
      declineAccessRequest(req);
    });
    actions.appendChild(decline);
  } else {
    const view = document.createElement("button");
    view.type = "button";
    view.textContent = "View →";
    view.addEventListener("click", (e) => {
      e.stopPropagation();
      openAccessRequestDrawer(req);
    });
    actions.appendChild(view);
  }
  actionsCell.appendChild(actions);
  tr.appendChild(actionsCell);

  return tr;
}

// JIT-1. A request carrying `requested_duration_seconds` is a bid for
// *temporary* elevation, and the reviewer's real decision is usually
// "yes, but for less time" — so the prompt offers the window rather than
// making the approver accept the ask wholesale. A plain request has no
// duration and keeps the original one-click confirm.
async function approveAccessRequest(req) {
  const target = req.vserver_name || req.vserver_id;
  const who = req.user_email || req.user_id;
  let body = null;

  if (req.requested_duration_seconds) {
    const asked = formatDuration(req.requested_duration_seconds);
    const answer = prompt(
      `Approve ${who} for ${target}?\\n\\n` +
      `They asked for ${asked}. Grant how long?\\n` +
      `Enter minutes (you can grant less, never more), or Cancel to abort.`,
      String(Math.round(req.requested_duration_seconds / 60)),
    );
    if (answer === null) return;
    const minutes = Number(answer);
    if (!Number.isFinite(minutes) || minutes <= 0) {
      alert("Enter a positive number of minutes.");
      return;
    }
    body = JSON.stringify({ duration_seconds: Math.round(minutes * 60) });
  } else if (!confirm(
    `Approve ${who} for ${target}? ` +
    `This mints a standing vserver grant immediately.`
  )) {
    return;
  }

  try {
    await api(`/api/v1/access-requests/${encodeURIComponent(req.id)}/approve`,
              body === null ? { method: "POST" } : { method: "POST", body });
    await loadAccessRequests();
    if (typeof loadActiveElevations === "function") await loadActiveElevations();
  } catch (error) {
    alert(String(error));
  }
}

// Compact human duration: "45m", "4h", "2h 30m", "3d". Used by the
// approve prompt, the queue rows, and the live-elevations strip so all
// three read the same way.
function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d) return h ? `${d}d ${h}h` : `${d}d`;
  if (h) return m ? `${h}h ${m}m` : `${h}h`;
  return `${m || 1}m`;
}

async function declineAccessRequest(req) {
  const note = prompt(
    `Decline ${req.user_email || req.user_id}'s request for ` +
    `${req.vserver_name || req.vserver_id}.\n\nDecision note ` +
    `(visible to the user, optional):`,
    "",
  );
  if (note === null) return;  // user hit Cancel
  try {
    await api(`/api/v1/access-requests/${encodeURIComponent(req.id)}/decline`, {
      method: "POST",
      body: JSON.stringify({ decision_note: note }),
    });
    await loadAccessRequests();
  } catch (error) {
    alert(String(error));
  }
}

// ---------- Access-request drawer (slide-over) -----------------------
const _arDrawer = {
  el: () => document.querySelector("#ar-drawer"),
  body: () => document.querySelector("#ar-drawer-body"),
  title: () => document.querySelector("#ar-drawer-title"),
  sub: () => document.querySelector("#ar-drawer-sub"),
};

function openAccessRequestDrawer(req) {
  _arDrawer.title().textContent =
    req.user_email || `User ${(req.user_id || "").slice(0, 8)}…`;
  const targetLine = `wants ${req.vserver_name || `vserver ${(req.vserver_id || "").slice(0, 8)}…`}`;
  _arDrawer.sub().textContent =
    `${targetLine} · ${req.status} · submitted ${formatRelativeTime(req.created_at)}`;
  _arDrawer.body().innerHTML = "";
  _arDrawer.body().appendChild(buildAccessRequestDrawerBody(req));
  _arDrawer.el().hidden = false;
  document.body.style.overflow = "hidden";
}

function closeAccessRequestDrawer() {
  _arDrawer.el().hidden = true;
  _arDrawer.body().innerHTML = "";
  document.body.style.overflow = "";
}

function buildAccessRequestDrawerBody(req) {
  const root = document.createElement("div");

  // Pending rows get the action bar at the top — admins reading the
  // drawer often want to act without going back to the table.
  if (req.status === "pending") {
    const actionsBar = document.createElement("div");
    actionsBar.className = "users-row-actions";
    actionsBar.style.justifyContent = "flex-start";
    actionsBar.style.marginBottom = "16px";
    const approve = document.createElement("button");
    approve.type = "button";
    approve.textContent = "Approve";
    approve.addEventListener("click", async () => {
      await approveAccessRequest(req);
      closeAccessRequestDrawer();
    });
    actionsBar.appendChild(approve);
    const decline = document.createElement("button");
    decline.type = "button";
    decline.className = "is-danger";
    decline.textContent = "Decline";
    decline.addEventListener("click", async () => {
      await declineAccessRequest(req);
      closeAccessRequestDrawer();
    });
    actionsBar.appendChild(decline);
    root.appendChild(actionsBar);
  }

  // Detail card — built as a small dl so the labels align.
  const dl = document.createElement("dl");
  dl.style.display = "grid";
  dl.style.gridTemplateColumns = "max-content 1fr";
  dl.style.columnGap = "12px";
  dl.style.rowGap = "8px";
  dl.style.font = "400 12px/1.5 var(--vyuu-sans)";

  function addRow(label, value, opts) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    dt.style.color = "var(--vyuu-muted)";
    dt.style.fontSize = "10.5px";
    dt.style.textTransform = "uppercase";
    dt.style.letterSpacing = "0.08em";
    dt.style.alignSelf = "start";
    dt.style.paddingTop = "2px";
    const dd = document.createElement("dd");
    dd.style.margin = "0";
    if (opts && opts.italic) dd.style.fontStyle = "italic";
    if (opts && opts.muted && (value === null || value === undefined || value === "")) {
      dd.style.color = "var(--vyuu-muted)";
    }
    dd.textContent = (value === null || value === undefined || value === "")
      ? "—" : String(value);
    dl.appendChild(dt);
    dl.appendChild(dd);
  }

  addRow("Requester", req.user_email
    ? `${req.user_email}${req.user_display_name ? ` · ${req.user_display_name}` : ""}`
    : `(user ${(req.user_id || "").slice(0, 8)}…)`);
  addRow("Target vserver", req.vserver_name
    ? `${req.vserver_name}${req.vserver_visibility ? ` · ${req.vserver_visibility}` : ""}`
    : `(vserver ${(req.vserver_id || "").slice(0, 8)}…)`);
  addRow("User note", req.note || "—", { italic: true, muted: true });
  addRow("Status", req.status);
  addRow("Submitted", new Date(req.created_at).toLocaleString());
  if (req.decided_at) {
    addRow("Decided",
      `${new Date(req.decided_at).toLocaleString()} (${formatRelativeTime(req.decided_at)})`);
    addRow("Decided by", req.decided_by_email || `(operator ${(req.decided_by || "").slice(0, 8)}…)`);
    addRow("Decision note", req.decision_note || "—", { italic: true, muted: true });
  }
  if (req.created_grant_id) {
    addRow("Grant created", req.created_grant_id);
  }
  root.appendChild(dl);

  return root;
}

// Drawer wiring (close button, backdrop, ESC).
{
  for (const el of document.querySelectorAll("[data-ar-drawer-close]")) {
    el.addEventListener("click", closeAccessRequestDrawer);
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !_arDrawer.el().hidden) {
      closeAccessRequestDrawer();
    }
  });
}

// --- Users panel --------------------------------------------------------
// Tabular redesign — same shape as Events / Identities. The list
// endpoint returns aggregates (api_key_count, group_count,
// last_api_key_used_at) so the table renders in one round-trip.

const usersSearch = document.querySelector("#users-search");
const usersCount = document.querySelector("#users-count");

let usersCache = [];
const usersPillState = { current: "all" };

if (usersSearch) usersSearch.addEventListener("input", () => renderUsers());
for (const pill of document.querySelectorAll("[data-users-pill]")) {
  pill.addEventListener("click", () => {
    usersPillState.current = pill.dataset.usersPill;
    for (const p of document.querySelectorAll("[data-users-pill]")) {
      p.classList.toggle("is-active", p === pill);
    }
    renderUsers();
  });
}

async function loadUsers() {
  usersOutput.innerHTML =
    '<tr><td colspan="7" class="events-empty">Loading…</td></tr>';
  try {
    const rows = await api("/api/v1/users");
    usersCache = rows;
    // Keep the cross-panel cache populated — grant builders read it.
    principalCache.users = rows;
    renderUsers();
  } catch (error) {
    usersOutput.innerHTML = "";
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 7;
    td.className = "events-empty";
    td.textContent = String(error.message || error);
    tr.appendChild(td);
    usersOutput.appendChild(tr);
  }
}

function renderUsers() {
  // KPIs reflect the unfiltered cache so toggling pills doesn't mask
  // the totals (matches the Identities behaviour).
  renderUsersKpis(usersCache);

  const needle = (usersSearch && usersSearch.value || "").trim().toLowerCase();
  const pill = usersPillState.current;
  const filtered = usersCache.filter((u) => {
    if (needle) {
      const hay = `${u.email} ${u.display_name || ""} ${u.id}`.toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    if (pill === "active") return !u.disabled_at;
    if (pill === "disabled") return !!u.disabled_at;
    if (pill === "local") return u.auth_method === "local";
    if (pill === "oidc") return u.auth_method !== "local";
    if (pill === "pending_reset") return !!u.must_change_password && !u.disabled_at;
    return true;
  });

  usersCount.textContent =
    filtered.length === usersCache.length
      ? `${filtered.length} users`
      : `${filtered.length} of ${usersCache.length} users`;

  usersOutput.innerHTML = "";
  if (!filtered.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 7;
    td.className = "events-empty";
    td.textContent = usersCache.length === 0
      ? "No tenant users yet. Click + New user above to invite one."
      : `(0 of ${usersCache.length} users match the active filter)`;
    tr.appendChild(td);
    usersOutput.appendChild(tr);
    return;
  }
  for (const u of filtered) {
    usersOutput.appendChild(renderUserRow(u));
  }
}

function renderUsersKpis(rows) {
  let total = 0;
  let disabled = 0;
  let pendingReset = 0;
  let new24h = 0;
  const dayAgo = Date.now() - 24 * 60 * 60 * 1000;
  for (const u of rows) {
    total++;
    if (u.disabled_at) disabled++;
    else if (u.must_change_password) pendingReset++;
    if (u.created_at && Date.parse(u.created_at) >= dayAgo) new24h++;
  }
  const set = (id, v) => {
    const el = document.querySelector(`#${id}`);
    if (el) el.textContent = v;
  };
  set("users-kpi-total", total.toLocaleString());
  set("users-kpi-disabled", disabled.toLocaleString());
  set("users-kpi-pending-reset", pendingReset.toLocaleString());
  set("users-kpi-new-24h", new24h.toLocaleString());
}

function renderUserRow(user) {
  const tr = document.createElement("tr");
  if (user.disabled_at) tr.dataset.disabled = "true";
  tr.addEventListener("click", () => openUserDrawer(user));

  // USER — email + status pill + truncated id
  const userCell = document.createElement("td");
  const wrap = document.createElement("div");
  wrap.className = "users-row-user";
  const line = document.createElement("span");
  line.className = "users-row-user-line";
  const status = userStatus(user);
  const pill = document.createElement("span");
  pill.className = "users-status-pill";
  pill.dataset.status = status.key;
  pill.textContent = status.label;
  line.appendChild(pill);
  line.appendChild(document.createTextNode(user.email));
  wrap.appendChild(line);
  const idLine = document.createElement("span");
  idLine.className = "users-row-user-id";
  const display = user.display_name ? `${user.display_name} · ` : "";
  idLine.textContent = `${display}${user.id.slice(0, 8)}…`;
  wrap.appendChild(idLine);
  userCell.appendChild(wrap);
  tr.appendChild(userCell);

  // AUTH — Local / SSO tag
  const authCell = document.createElement("td");
  const authTag = document.createElement("span");
  authTag.className = "users-auth-tag";
  authTag.textContent = user.auth_method === "local" ? "Local" : "SSO";
  authCell.appendChild(authTag);
  tr.appendChild(authCell);

  // LAST SEEN — last API-key use beats last login. Both nullable.
  const seenCell = document.createElement("td");
  seenCell.style.color = "var(--vyuu-muted)";
  seenCell.style.fontSize = "11.5px";
  const seen = user.last_api_key_used_at || user.last_login_at;
  if (seen) {
    seenCell.textContent = formatRelativeTime(seen);
    seenCell.title = new Date(seen).toLocaleString();
  } else {
    seenCell.textContent = "never";
  }
  tr.appendChild(seenCell);

  // API KEYS count
  const keysCell = document.createElement("td");
  keysCell.className = "users-row-keys";
  const keysSpan = document.createElement("span");
  keysSpan.className = "users-count-cell";
  if ((user.api_key_count || 0) === 0) keysSpan.classList.add("is-zero");
  keysSpan.textContent = String(user.api_key_count || 0);
  keysCell.appendChild(keysSpan);
  tr.appendChild(keysCell);

  // GROUPS count
  const groupsCell = document.createElement("td");
  groupsCell.className = "users-row-groups";
  const groupsSpan = document.createElement("span");
  groupsSpan.className = "users-count-cell";
  if ((user.group_count || 0) === 0) groupsSpan.classList.add("is-zero");
  groupsSpan.textContent = String(user.group_count || 0);
  groupsCell.appendChild(groupsSpan);
  tr.appendChild(groupsCell);

  // CREATED — relative time
  const createdCell = document.createElement("td");
  createdCell.style.color = "var(--vyuu-muted)";
  createdCell.style.fontSize = "11.5px";
  createdCell.textContent = formatRelativeTime(user.created_at);
  createdCell.title = new Date(user.created_at).toLocaleString();
  tr.appendChild(createdCell);

  // ACTIONS — inline reset/disable for local users; drill-in always
  const actionsCell = document.createElement("td");
  const actions = document.createElement("div");
  actions.className = "users-row-actions";
  const drill = document.createElement("button");
  drill.type = "button";
  drill.textContent = "Drill in →";
  drill.addEventListener("click", (e) => {
    e.stopPropagation();
    openUserDrawer(user);
  });
  actions.appendChild(drill);
  actionsCell.appendChild(actions);
  tr.appendChild(actionsCell);

  return tr;
}

function userStatus(user) {
  if (user.disabled_at) return { key: "disabled", label: "Disabled" };
  if (user.must_change_password) return { key: "pending_reset", label: "Reset" };
  return { key: "active", label: "Active" };
}

// ---------- User drawer (slide-over) ----------------------------------
const _userDrawer = {
  el: () => document.querySelector("#user-drawer"),
  body: () => document.querySelector("#user-drawer-body"),
  title: () => document.querySelector("#user-drawer-title"),
  sub: () => document.querySelector("#user-drawer-sub"),
  currentUser: null,
  currentTab: "activity",
};

function openUserDrawer(user) {
  _userDrawer.currentUser = user;
  _userDrawer.title().textContent = user.email;
  const status = userStatus(user);
  const seen = user.last_api_key_used_at || user.last_login_at;
  const parts = [
    user.auth_method === "local" ? "Local auth" : "SSO",
    `${user.api_key_count || 0} API keys · ${user.group_count || 0} groups`,
    seen ? `last seen ${formatRelativeTime(seen)}` : "never seen",
    status.label,
  ];
  _userDrawer.sub().textContent = parts.join(" · ");
  _userDrawer.el().hidden = false;
  document.body.style.overflow = "hidden";
  switchUserDrawerTab("activity");
}

function closeUserDrawer() {
  _userDrawer.el().hidden = true;
  _userDrawer.body().innerHTML = "";
  document.body.style.overflow = "";
}

function switchUserDrawerTab(tab) {
  _userDrawer.currentTab = tab;
  for (const t of document.querySelectorAll("[data-user-drawer-tab]")) {
    t.classList.toggle("is-active", t.dataset.userDrawerTab === tab);
  }
  const body = _userDrawer.body();
  body.innerHTML = "Loading…";
  const user = _userDrawer.currentUser;
  if (tab === "activity") renderUserDrawerActivity(body, user);
  else if (tab === "keys") renderUserDrawerKeys(body, user);
  else if (tab === "groups") renderUserDrawerGroups(body, user);
}

// Wire drawer close (button, backdrop, ESC) + tab switch.
{
  for (const el of document.querySelectorAll("[data-user-drawer-close]")) {
    el.addEventListener("click", closeUserDrawer);
  }
  for (const tab of document.querySelectorAll("[data-user-drawer-tab]")) {
    tab.addEventListener("click", () => switchUserDrawerTab(tab.dataset.userDrawerTab));
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !_userDrawer.el().hidden) {
      closeUserDrawer();
    }
  });
}

async function renderUserDrawerActivity(container, user) {
  // Reuses the per-identity summary endpoint — same shape as the
  // identities drawer's Summary tab. Plus admin actions (reset
  // password / disable) up top for one-click ops.
  container.innerHTML = "Loading…";
  const adminBar = document.createElement("div");
  adminBar.className = "users-row-actions";
  adminBar.style.justifyContent = "flex-start";
  adminBar.style.marginBottom = "12px";
  if (user.auth_method === "local" && !user.disabled_at) {
    const reset = document.createElement("button");
    reset.type = "button";
    reset.textContent = "Reset password";
    reset.addEventListener("click", async () => {
      const newPw = prompt("New password (min 12 chars):");
      if (!newPw) return;
      try {
        await api(`/api/v1/users/${user.id}/password`, {
          method: "POST",
          body: JSON.stringify({ new_password: newPw }),
        });
        alert("Password reset. The user must rotate on next sign-in.");
        await loadUsers();
      } catch (error) {
        alert(String(error));
      }
    });
    adminBar.appendChild(reset);
  }
  if (!user.disabled_at) {
    const disable = document.createElement("button");
    disable.type = "button";
    disable.className = "is-danger";
    disable.textContent = "Disable user";
    disable.addEventListener("click", async () => {
      if (!confirm(
        `Disable ${user.email}? All API keys fail with 401 immediately. ` +
        `This is reversible — re-enable from a future iteration of this UI ` +
        `or by API.`
      )) return;
      try {
        await api(`/api/v1/users/${user.id}`, { method: "DELETE" });
        closeUserDrawer();
        await loadUsers();
      } catch (error) {
        alert(String(error));
      }
    });
    adminBar.appendChild(disable);
  }
  container.innerHTML = "";
  if (adminBar.childElementCount) container.appendChild(adminBar);

  const summaryBox = document.createElement("div");
  container.appendChild(summaryBox);
  try {
    const summary = await api(
      `/api/v1/identities/${encodeURIComponent(user.id)}/summary`,
    );
    const scoreColor = summary.risk_score >= 70 ? "danger"
                     : summary.risk_score >= 40 ? "warn" : "granted";
    const oauthList = summary.oauth_connections.length
      ? summary.oauth_connections
          .map((c) => `<li>${escapeHtml(c.server_display_name)}
              ${c.scope ? `· scope <code>${escapeHtml(c.scope)}</code>` : ""}</li>`)
          .join("")
      : "<li>(no SaaS connections)</li>";
    const upstreamList = summary.reachable_upstreams.length
      ? summary.reachable_upstreams
          .map((u) => {
            const conn = u.oauth_connected === true ? "✓ connected"
                       : u.oauth_connected === false ? "✗ not connected"
                       : "(M2M auth)";
            return `<li>${escapeHtml(u.display_name)}
                <small>${conn}</small></li>`;
          })
          .join("")
      : "<li>(none)</li>";
    summaryBox.innerHTML = `
      <div style="display: flex; gap: 16px; flex-wrap: wrap;">
        <span class="badge ${scoreColor}">risk score ${summary.risk_score}/100</span>
        <span class="badge">max risk: ${escapeHtml(summary.max_risk_category)}</span>
        <span class="badge">${summary.granted_vservers.length} vservers</span>
        <span class="badge">${summary.exposed_tools.length} tools reachable</span>
      </div>
      <details open style="margin-top: 8px;">
        <summary>OAuth connections (${summary.oauth_connections.length})</summary>
        <ul style="margin: 4px 0;">${oauthList}</ul>
      </details>
      <details style="margin-top: 4px;">
        <summary>Reachable upstreams (${summary.reachable_upstreams.length})</summary>
        <ul style="margin: 4px 0;">${upstreamList}</ul>
      </details>`;
  } catch (error) {
    if (String(error).includes("404")) {
      summaryBox.textContent =
        "(no activity recorded — user hasn't been granted any vservers yet)";
    } else {
      renderError(summaryBox, error);
    }
  }
}

async function renderUserDrawerKeys(container, user) {
  container.innerHTML = "Loading…";
  try {
    const keys = await api(
      `/api/v1/users/${encodeURIComponent(user.id)}/api-keys`,
    );
    container.innerHTML = "";
    if (!keys.length) {
      const empty = document.createElement("p");
      empty.className = "events-empty";
      empty.textContent = "(no API keys issued)";
      container.appendChild(empty);
      return;
    }
    for (const k of keys) {
      const row = document.createElement("article");
      row.className = "card";
      row.style.marginBottom = "6px";
      const statusBadge = k.revoked_at
        ? `<span class="badge danger">revoked</span>`
        : `<span class="badge granted">active</span>`;
      const meta = document.createElement("div");
      meta.className = "card-meta";
      meta.innerHTML = `
        <strong>${escapeHtml(k.label)}</strong>
        <div>${statusBadge}</div>
        <small>prefix ${escapeHtml(k.key_prefix)}…</small>
        <small>created ${escapeHtml(k.created_at)}
          · last used ${escapeHtml(k.last_used_at || "never")}</small>`;
      row.appendChild(meta);

      if (!k.revoked_at) {
        const actions = document.createElement("div");
        actions.className = "card-actions";
        const revoke = document.createElement("button");
        revoke.className = "danger";
        revoke.textContent = "Revoke (admin)";
        revoke.addEventListener("click", async () => {
          if (!confirm(
            `Revoke API key "${k.label}" for ${user.email}? `
            + `Any client using this key will fail with 401 immediately.`
          )) return;
          try {
            await api(
              `/api/v1/users/${encodeURIComponent(user.id)}/api-keys/${encodeURIComponent(k.id)}`,
              { method: "DELETE" },
            );
            renderUserDrawerKeys(container, user);
            // Refresh the table so the count updates without a manual
            // Refresh click — small win, big perception.
            loadUsers();
          } catch (error) {
            alert(String(error));
          }
        });
        actions.appendChild(revoke);
        row.appendChild(actions);
      }
      container.appendChild(row);
    }
  } catch (error) {
    renderError(container, error);
  }
}

async function renderUserDrawerGroups(container, user) {
  container.innerHTML = "Loading…";
  try {
    const groups = await api("/api/v1/groups");
    // Determine which groups this user is a member of. The /groups
    // endpoint doesn't return per-user membership, so fan out to
    // /groups/{id}/members. Bounded by the group count (typically
    // small) and only when the operator opens this tab.
    const memberships = await Promise.all(
      groups.map(async (g) => {
        try {
          const members = await api(`/api/v1/groups/${encodeURIComponent(g.id)}/members`);
          return { group: g, isMember: members.some((m) => m.id === user.id) };
        } catch {
          return { group: g, isMember: false };
        }
      }),
    );
    container.innerHTML = "";
    const memberOf = memberships.filter((m) => m.isMember);
    if (!memberOf.length) {
      const empty = document.createElement("p");
      empty.className = "events-empty";
      empty.textContent = "(not a member of any group)";
      container.appendChild(empty);
    } else {
      const list = document.createElement("ul");
      list.style.listStyle = "none";
      list.style.padding = "0";
      list.style.margin = "0 0 12px";
      for (const { group } of memberOf) {
        const li = document.createElement("li");
        li.style.padding = "8px 12px";
        li.style.border = "1px solid var(--vyuu-line)";
        li.style.borderRadius = "var(--vyuu-r-sm)";
        li.style.marginBottom = "6px";
        li.innerHTML = `<strong>${escapeHtml(group.name)}</strong>
          <small style="display:block; color: var(--vyuu-muted);">
            ${escapeHtml(group.description || "")}</small>`;
        list.appendChild(li);
      }
      container.appendChild(list);
    }
    // Add-to-group control — surface non-member groups in a select.
    const nonMember = memberships.filter((m) => !m.isMember).map((m) => m.group);
    if (nonMember.length) {
      const wrap = document.createElement("div");
      wrap.className = "users-row-actions";
      wrap.style.justifyContent = "flex-start";
      const sel = document.createElement("select");
      sel.style.padding = "6px 10px";
      sel.style.border = "1px solid var(--vyuu-line)";
      sel.style.borderRadius = "var(--vyuu-r-sm)";
      const placeholder = document.createElement("option");
      placeholder.value = "";
      placeholder.textContent = "+ Add to group…";
      sel.appendChild(placeholder);
      for (const g of nonMember) {
        const opt = document.createElement("option");
        opt.value = g.id;
        opt.textContent = g.name;
        sel.appendChild(opt);
      }
      const add = document.createElement("button");
      add.type = "button";
      add.textContent = "Add";
      add.addEventListener("click", async () => {
        if (!sel.value) return;
        try {
          await api(`/api/v1/groups/${encodeURIComponent(sel.value)}/members`, {
            method: "POST",
            body: JSON.stringify({ user_id: user.id }),
          });
          renderUserDrawerGroups(container, user);
          loadUsers();
        } catch (error) {
          alert(String(error));
        }
      });
      wrap.appendChild(sel);
      wrap.appendChild(add);
      container.appendChild(wrap);
    }
  } catch (error) {
    renderError(container, error);
  }
}

// --- Create-user modal -------------------------------------------------
{
  const open = document.querySelector("#open-create-user");
  const modal = document.querySelector("#create-user-modal");
  if (open && modal) {
    open.addEventListener("click", () => {
      modal.hidden = false;
      document.body.style.overflow = "hidden";
    });
  }
  for (const el of document.querySelectorAll("[data-create-user-close]")) {
    el.addEventListener("click", () => {
      modal.hidden = true;
      document.body.style.overflow = "";
    });
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modal && !modal.hidden) {
      modal.hidden = true;
      document.body.style.overflow = "";
    }
  });
}

async function createUser(event) {
  event.preventDefault();
  const data = new FormData(createUserForm);
  const payload = {
    email: String(data.get("email") || "").trim(),
    password: String(data.get("password") || ""),
  };
  const display = String(data.get("display_name") || "").trim();
  if (display) payload.display_name = display;
  try {
    const created = await api("/api/v1/users", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    renderCreated(createUserOutput, `Created user ${created.email}`,
      created.id ? `id ${created.id}` : "");
    createUserForm.reset();
    // Close the modal on success — the new user shows up in the table.
    const modal = document.querySelector("#create-user-modal");
    if (modal) {
      modal.hidden = true;
      document.body.style.overflow = "";
    }
    await loadUsers();
  } catch (error) {
    renderError(createUserOutput, error);
  }
}

// --- Groups panel ------------------------------------------------------
// Tabular redesign — same shape as Identities / Users. The list
// endpoint returns `member_count` + `vserver_grant_count` aggregates
// so the table renders in one round-trip.

const groupsSearch = document.querySelector("#groups-search");
const groupsCount = document.querySelector("#groups-count");

let groupsCache = [];
const groupsPillState = { current: "all" };

if (groupsSearch) groupsSearch.addEventListener("input", () => renderGroups());
for (const pill of document.querySelectorAll("[data-groups-pill]")) {
  pill.addEventListener("click", () => {
    groupsPillState.current = pill.dataset.groupsPill;
    for (const p of document.querySelectorAll("[data-groups-pill]")) {
      p.classList.toggle("is-active", p === pill);
    }
    renderGroups();
  });
}

async function loadGroups() {
  groupsOutput.innerHTML =
    '<tr><td colspan="5" class="events-empty">Loading…</td></tr>';
  try {
    const rows = await api("/api/v1/groups");
    groupsCache = rows;
    // Cross-panel cache populates dropdowns elsewhere — only the
    // shared `Group` fields are read there, so the enriched rows
    // are a strict superset.
    principalCache.groups = rows;
    renderGroups();
  } catch (error) {
    groupsOutput.innerHTML = "";
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "events-empty";
    td.textContent = String(error.message || error);
    tr.appendChild(td);
    groupsOutput.appendChild(tr);
  }
}

async function ensurePrincipalCacheLoaded() {
  // Lazy-fetch users + groups if the operator hasn't clicked Refresh on
  // those panels yet. Keeps dropdowns populated without forcing the
  // operator to manually refresh first.
  const promises = [];
  if (!principalCache.users.length) promises.push(loadUsers());
  if (!principalCache.groups.length) promises.push(loadGroups());
  if (promises.length) await Promise.all(promises);
}

function userLabel(u) {
  return `${u.email}${u.disabled_at ? " [disabled]" : ""}  ·  ${u.id.slice(0, 8)}…`;
}

function groupLabel(g) {
  return `${g.name}  ·  ${g.id.slice(0, 8)}…`;
}

function renderGroups() {
  renderGroupsKpis(groupsCache);

  const needle = (groupsSearch && groupsSearch.value || "").trim().toLowerCase();
  const pill = groupsPillState.current;
  const filtered = groupsCache.filter((g) => {
    if (needle) {
      const hay = `${g.name} ${g.description || ""}`.toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    if (pill === "in_use") return (g.vserver_grant_count || 0) > 0;
    if (pill === "empty") return (g.member_count || 0) === 0;
    if (pill === "unused") return (g.vserver_grant_count || 0) === 0;
    return true;
  });

  groupsCount.textContent =
    filtered.length === groupsCache.length
      ? `${filtered.length} groups`
      : `${filtered.length} of ${groupsCache.length} groups`;

  groupsOutput.innerHTML = "";
  if (!filtered.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "events-empty";
    td.textContent = groupsCache.length === 0
      ? "No groups defined. Click + New group to define one."
      : `(0 of ${groupsCache.length} groups match the active filter)`;
    tr.appendChild(td);
    groupsOutput.appendChild(tr);
    return;
  }
  for (const g of filtered) {
    groupsOutput.appendChild(renderGroupRow(g));
  }
}

function renderGroupsKpis(rows) {
  let total = 0;
  let unused = 0;
  let empty = 0;
  let largestName = null;
  let largestCount = -1;
  for (const g of rows) {
    total++;
    if ((g.vserver_grant_count || 0) === 0) unused++;
    if ((g.member_count || 0) === 0) empty++;
    if ((g.member_count || 0) > largestCount) {
      largestCount = g.member_count || 0;
      largestName = g.name;
    }
  }
  const set = (id, v) => {
    const el = document.querySelector(`#${id}`);
    if (el) el.textContent = v;
  };
  set("groups-kpi-total", total.toLocaleString());
  set("groups-kpi-unused", unused.toLocaleString());
  set("groups-kpi-empty", empty.toLocaleString());
  if (largestName !== null) {
    set("groups-kpi-largest", largestName.length > 18
      ? largestName.slice(0, 16) + "…" : largestName);
    set("groups-kpi-largest-sub",
      `${largestCount} member${largestCount === 1 ? "" : "s"}`);
  } else {
    set("groups-kpi-largest", "—");
    set("groups-kpi-largest-sub", "no groups yet");
  }
}

function renderGroupRow(group) {
  const tr = document.createElement("tr");
  if ((group.vserver_grant_count || 0) === 0) tr.dataset.state = "unused";
  tr.addEventListener("click", () => openGroupDrawer(group));

  // GROUP — name + description
  const nameCell = document.createElement("td");
  const wrap = document.createElement("div");
  wrap.className = "groups-row-name";
  const line = document.createElement("span");
  line.className = "groups-row-name-line";
  line.textContent = group.name;
  wrap.appendChild(line);
  const desc = document.createElement("span");
  desc.className = "groups-row-description";
  desc.textContent = group.description || "(no description)";
  wrap.appendChild(desc);
  nameCell.appendChild(wrap);
  tr.appendChild(nameCell);

  // MEMBERS count
  const memberCell = document.createElement("td");
  memberCell.className = "groups-row-members";
  const memberSpan = document.createElement("span");
  memberSpan.className = "users-count-cell";
  if ((group.member_count || 0) === 0) memberSpan.classList.add("is-zero");
  memberSpan.textContent = String(group.member_count || 0);
  memberCell.appendChild(memberSpan);
  tr.appendChild(memberCell);

  // VSERVER GRANTS count
  const grantsCell = document.createElement("td");
  grantsCell.className = "groups-row-grants";
  const grantsSpan = document.createElement("span");
  grantsSpan.className = "users-count-cell";
  if ((group.vserver_grant_count || 0) === 0) grantsSpan.classList.add("is-zero");
  grantsSpan.textContent = String(group.vserver_grant_count || 0);
  grantsCell.appendChild(grantsSpan);
  tr.appendChild(grantsCell);

  // CREATED — relative
  const createdCell = document.createElement("td");
  createdCell.style.color = "var(--vyuu-muted)";
  createdCell.style.fontSize = "11.5px";
  createdCell.textContent = formatRelativeTime(group.created_at);
  createdCell.title = new Date(group.created_at).toLocaleString();
  tr.appendChild(createdCell);

  // ACTIONS — drill-in
  const actionsCell = document.createElement("td");
  const actions = document.createElement("div");
  actions.className = "users-row-actions";
  const drill = document.createElement("button");
  drill.type = "button";
  drill.textContent = "Drill in →";
  drill.addEventListener("click", (e) => {
    e.stopPropagation();
    openGroupDrawer(group);
  });
  actions.appendChild(drill);
  actionsCell.appendChild(actions);
  tr.appendChild(actionsCell);

  return tr;
}

// ---------- Group drawer (slide-over) ---------------------------------
const _groupDrawer = {
  el: () => document.querySelector("#group-drawer"),
  body: () => document.querySelector("#group-drawer-body"),
  title: () => document.querySelector("#group-drawer-title"),
  sub: () => document.querySelector("#group-drawer-sub"),
  currentGroup: null,
  currentTab: "members",
};

function openGroupDrawer(group) {
  _groupDrawer.currentGroup = group;
  _groupDrawer.title().textContent = group.name;
  const parts = [
    group.description || "(no description)",
    `${group.member_count || 0} members`,
    `${group.vserver_grant_count || 0} vserver grants`,
  ];
  _groupDrawer.sub().textContent = parts.join(" · ");
  _groupDrawer.el().hidden = false;
  document.body.style.overflow = "hidden";
  switchGroupDrawerTab("members");
}

function closeGroupDrawer() {
  _groupDrawer.el().hidden = true;
  _groupDrawer.body().innerHTML = "";
  document.body.style.overflow = "";
}

function switchGroupDrawerTab(tab) {
  _groupDrawer.currentTab = tab;
  for (const t of document.querySelectorAll("[data-group-drawer-tab]")) {
    t.classList.toggle("is-active", t.dataset.groupDrawerTab === tab);
  }
  const body = _groupDrawer.body();
  body.innerHTML = "Loading…";
  const group = _groupDrawer.currentGroup;
  if (tab === "members") renderGroupDrawerMembers(body, group);
  else if (tab === "grants") renderGroupDrawerGrants(body, group);
}

// Wire drawer close (button, backdrop, ESC) + tab switch.
{
  for (const el of document.querySelectorAll("[data-group-drawer-close]")) {
    el.addEventListener("click", closeGroupDrawer);
  }
  for (const tab of document.querySelectorAll("[data-group-drawer-tab]")) {
    tab.addEventListener("click", () => switchGroupDrawerTab(tab.dataset.groupDrawerTab));
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !_groupDrawer.el().hidden) {
      closeGroupDrawer();
    }
  });
}

async function renderGroupDrawerMembers(container, group) {
  // Member chips with per-chip × + an add-row dropdown — same UX the
  // prior card had, just relocated into the drawer.
  container.innerHTML = "Loading…";
  let members = [];
  try {
    members = await api(`/api/v1/groups/${encodeURIComponent(group.id)}/members`);
  } catch (error) {
    renderError(container, error);
    return;
  }
  await ensurePrincipalCacheLoaded();

  container.innerHTML = "";
  const eyebrow = document.createElement("p");
  eyebrow.className = "eyebrow";
  eyebrow.style.margin = "0 0 6px";
  eyebrow.textContent = `MEMBERS · ${members.length}`;
  container.appendChild(eyebrow);

  const chipList = document.createElement("div");
  chipList.className = "group-member-chips";
  container.appendChild(chipList);

  function paintChips() {
    chipList.replaceChildren();
    eyebrow.textContent = `MEMBERS · ${members.length}`;
    if (!members.length) {
      const empty = document.createElement("span");
      empty.className = "events-empty";
      empty.textContent = "No members yet — pick one below.";
      chipList.appendChild(empty);
      return;
    }
    for (const u of members) {
      const chip = document.createElement("span");
      chip.className = "group-member-chip";
      const label = document.createElement("span");
      label.textContent = u.email;
      chip.appendChild(label);
      const x = document.createElement("button");
      x.type = "button";
      x.className = "group-member-chip-remove";
      x.title = `Remove ${u.email} from ${group.name}`;
      x.setAttribute("aria-label", `Remove ${u.email}`);
      x.textContent = "×";
      x.addEventListener("click", () => removeMember(u));
      chip.appendChild(x);
      chipList.appendChild(chip);
    }
  }

  // Add row
  const addWrap = document.createElement("div");
  addWrap.className = "users-row-actions";
  addWrap.style.justifyContent = "flex-start";
  addWrap.style.marginTop = "12px";
  const sel = document.createElement("select");
  sel.style.padding = "6px 10px";
  sel.style.border = "1px solid var(--vyuu-line)";
  sel.style.borderRadius = "var(--vyuu-r-sm)";
  const addBtn = document.createElement("button");
  addBtn.type = "button";
  addBtn.textContent = "Add member";
  addBtn.disabled = true;
  sel.addEventListener("change", () => { addBtn.disabled = !sel.value; });
  addWrap.appendChild(sel);
  addWrap.appendChild(addBtn);
  container.appendChild(addWrap);

  function refreshOptions() {
    const memberIds = new Set(members.map((m) => m.id));
    const candidates = (principalCache.users || [])
      .filter((u) => !memberIds.has(u.id))
      .sort((a, b) => a.email.localeCompare(b.email));
    sel.replaceChildren();
    if (!candidates.length) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "(every user is already a member)";
      sel.appendChild(opt);
      sel.disabled = true;
      addBtn.disabled = true;
      return;
    }
    sel.disabled = false;
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "Pick a user to add…";
    sel.appendChild(placeholder);
    for (const u of candidates) {
      const opt = document.createElement("option");
      opt.value = u.id;
      opt.textContent = u.email;
      sel.appendChild(opt);
    }
    addBtn.disabled = !sel.value;
  }

  async function addMember() {
    if (!sel.value) return;
    addBtn.disabled = true;
    const userId = sel.value;
    try {
      await api(`/api/v1/groups/${encodeURIComponent(group.id)}/members`, {
        method: "POST",
        body: JSON.stringify({ user_id: userId }),
      });
      const added = (principalCache.users || []).find((u) => u.id === userId);
      if (added) members.push(added);
      members.sort((a, b) => a.email.localeCompare(b.email));
      paintChips();
      refreshOptions();
      // Refresh the table so member counts update without a manual click.
      loadGroups();
    } catch (error) {
      alert(String(error));
    } finally {
      addBtn.disabled = !sel.value;
    }
  }
  addBtn.addEventListener("click", addMember);

  async function removeMember(u) {
    if (!confirm(`Remove ${u.email} from ${group.name}?`)) return;
    try {
      await api(
        `/api/v1/groups/${encodeURIComponent(group.id)}/members/${encodeURIComponent(u.id)}`,
        { method: "DELETE" },
      );
      members = members.filter((m) => m.id !== u.id);
      paintChips();
      refreshOptions();
      loadGroups();
    } catch (error) {
      alert(String(error));
    }
  }

  paintChips();
  refreshOptions();
}

async function renderGroupDrawerGrants(container, group) {
  // "Which vservers grant access via this group?" There's no
  // server-side endpoint for that today, so we list vservers and
  // call /grants per vserver. Bounded by the tenant's vserver count
  // — only runs when the operator opens this tab.
  container.innerHTML = "Loading…";
  try {
    const vservers = await api("/api/v1/vservers");
    const matches = [];
    await Promise.all(
      vservers.map(async (v) => {
        try {
          const grants = await api(
            `/api/v1/vservers/${encodeURIComponent(v.id)}/grants`,
          );
          for (const g of grants) {
            if (g.principal_kind === "group" && g.principal_id === group.id) {
              matches.push({ vserver: v, grant: g });
            }
          }
        } catch {
          // Skip vservers we can't read grants for; still report the rest.
        }
      }),
    );
    container.innerHTML = "";
    if (!matches.length) {
      const empty = document.createElement("p");
      empty.className = "events-empty";
      empty.textContent =
        "(no vserver grants reference this group — it's defined but unused)";
      container.appendChild(empty);
      return;
    }
    const list = document.createElement("ul");
    list.style.listStyle = "none";
    list.style.padding = "0";
    list.style.margin = "0";
    for (const { vserver, grant } of matches) {
      const li = document.createElement("li");
      li.style.padding = "10px 12px";
      li.style.border = "1px solid var(--vyuu-line)";
      li.style.borderRadius = "var(--vyuu-r-sm)";
      li.style.marginBottom = "6px";
      const expires = grant.expires_at
        ? `expires ${new Date(grant.expires_at).toLocaleString()}`
        : "no expiry";
      li.innerHTML = `
        <strong>${escapeHtml(vserver.name)}</strong>
        <small style="display:block; color: var(--vyuu-muted);">
          visibility: ${escapeHtml(vserver.visibility)} · ${escapeHtml(expires)}
        </small>`;
      list.appendChild(li);
    }
    container.appendChild(list);
  } catch (error) {
    renderError(container, error);
  }
}

// --- Create-group modal ------------------------------------------------
{
  const open = document.querySelector("#open-create-group");
  const modal = document.querySelector("#create-group-modal");
  if (open && modal) {
    open.addEventListener("click", () => {
      modal.hidden = false;
      document.body.style.overflow = "hidden";
    });
  }
  for (const el of document.querySelectorAll("[data-create-group-close]")) {
    el.addEventListener("click", () => {
      modal.hidden = true;
      document.body.style.overflow = "";
    });
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modal && !modal.hidden) {
      modal.hidden = true;
      document.body.style.overflow = "";
    }
  });
}

async function createGroup(event) {
  event.preventDefault();
  const data = new FormData(createGroupForm);
  const payload = { name: String(data.get("name") || "").trim() };
  const desc = String(data.get("description") || "").trim();
  if (desc) payload.description = desc;
  try {
    const created = await api("/api/v1/groups", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    renderCreated(createGroupOutput, `Created group ${created.name || created.display_name || ""}`,
      created.id ? `id ${created.id}` : "");
    createGroupForm.reset();
    const modal = document.querySelector("#create-group-modal");
    if (modal) {
      modal.hidden = true;
      document.body.style.overflow = "";
    }
    await loadGroups();
  } catch (error) {
    renderError(createGroupOutput, error);
  }
}

// =========================================================================
// Dashboard panel — KPI grid
// =========================================================================

const dashboardOutput = document.querySelector("#dashboard-output");

document.querySelector("#refresh-dashboard").addEventListener("click", loadDashboard);

// Gateway-wide diagnostic bundle. One button on the Dashboard;
// downloads a JSON snapshot of process state + connectivity + all
// servers + vservers + circuit breakers + inflight gate + recent
// audit decisions. The whole point: when a customer reports an issue
// during public testing, the operator clicks this once and shares
// the file. Secrets are server-side redacted before the response is
// generated — see api/diagnostic_bundle.py docstring.
document.querySelector("#download-diagnostic-bundle")
  .addEventListener("click", async (event) => {
    const btn = event.currentTarget;
    const out = document.querySelector("#diagnostic-bundle-output");
    const windowSel = document.querySelector("#diagnostic-bundle-window");
    const windowMin = windowSel ? Number(windowSel.value) || 60 : 60;
    btn.disabled = true;
    btn.textContent = "Collecting diagnostic…";
    out.textContent = "";
    try {
      const token = sessionStorage.getItem("vyuu_operator_token");
      const tenantId = sessionStorage.getItem("vyuu_operator_tenant");
      const response = await fetch(
        `/api/v1/admin/diagnostic-bundle?since_minutes=${windowMin}`,
        {
          headers: {
            "Authorization": `Bearer ${token || ""}`,
            ...(tenantId ? { "x-vyuu-tenant-id": tenantId } : {}),
            "Accept": "application/json",
          },
        },
      );
      if (!response.ok) {
        const text = await response.text();
        out.textContent =
          `Failed: HTTP ${response.status} — ${text.slice(0, 200)}`;
        out.style.color = "var(--vyuu-danger)";
        return;
      }
      const disp = response.headers.get("Content-Disposition") || "";
      const m = /filename="([^"]+)"/.exec(disp);
      const filename = m ? m[1] : "vyuu-diagnostic.json";
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      out.textContent =
        `Downloaded ${filename} · ${(blob.size / 1024).toFixed(1)} KiB · `
        + "safe to share with support (secrets redacted server-side)";
      out.style.color = "var(--vyuu-orange-deep)";
    } catch (error) {
      out.textContent = `Failed: ${error.message || error}`;
      out.style.color = "var(--vyuu-danger)";
    } finally {
      btn.disabled = false;
      btn.textContent = "Download diagnostic bundle";
    }
  });

async function loadDashboard() {
  dashboardOutput.textContent = "Loading…";
  try {
    const k = await api(`/api/v1/admin/dashboard`);
    dashboardOutput.replaceChildren(...renderKpiCards(k));
  } catch (error) {
    renderError(dashboardOutput, error);
  }
}

// =========================================================================
// Health & Server Info — live snapshot of gateway + MCP servers.
// =========================================================================

function _humanUptime(seconds) {
  if (seconds == null) return "—";
  const s = Math.floor(seconds);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
}

function _humanMs(ms) {
  if (ms == null) return "—";
  if (ms < 1) return `${ms.toFixed(2)} ms`;
  if (ms < 100) return `${ms.toFixed(1)} ms`;
  return `${Math.round(ms)} ms`;
}

function _statusCardHtml(card) {
  const cls =
    card.status === "ok" ? "is-ok"
    : card.status === "warn" ? "is-warn"
    : "is-error";
  const glyph =
    card.status === "ok" ? "✓"
    : card.status === "warn" ? "⚠"
    : "✗";
  return `
    <div class="health-status-card ${cls}">
      <span class="health-status-icon">${glyph}</span>
      <p class="health-status-label">${_escape(card.label)}</p>
      <p class="health-status-detail">${_escape(card.detail || "")}</p>
    </div>
  `;
}

function _escape(s) {
  return String(s || "").replace(/[&<>"]/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;",
  }[c]));
}

function _renderHealthServers(rows) {
  const tbody = document.querySelector("#health-servers-tbody");
  if (!rows || rows.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="7" class="health-empty">'
      + 'No MCP servers registered for this tenant.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map((r) => {
    const pill = `<span class="health-pill is-${_escape(r.health_status)}">${_escape(r.health_status)}</span>`;
    const lastSync = r.last_capabilities_pulled_at
      ? new Date(r.last_capabilities_pulled_at).toLocaleString()
      : '—';
    return `
      <tr>
        <td><strong>${_escape(r.display_name)}</strong>
            <div class="muted" style="font-size:11px">${_escape(r.server_id)}</div></td>
        <td>${_escape(r.transport)}</td>
        <td>${pill}</td>
        <td>${_humanMs(r.avg_latency_ms_1h)}</td>
        <td>${r.calls_last_1h ?? 0}</td>
        <td>${r.capability_count ?? 0}</td>
        <td>${lastSync}</td>
      </tr>
    `;
  }).join("");
}

function _renderLatencyChart(series) {
  const svg = document.querySelector("#health-latency-chart");
  const caption = document.querySelector("#health-chart-caption");
  if (!svg) return;
  if (!series || series.length === 0) {
    svg.innerHTML = "";
    if (caption) caption.textContent = "(no upstream calls in window)";
    return;
  }
  const W = 900, H = 220, PAD_L = 50, PAD_R = 20, PAD_T = 12, PAD_B = 28;
  const xs = series.map((b) => new Date(b.hour).getTime());
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const allY = series.flatMap((b) => [b.p95_ms, b.p99_ms].filter(v => v != null));
  if (allY.length === 0) {
    svg.innerHTML = "";
    if (caption) caption.textContent = "(no latency samples in window)";
    return;
  }
  const minY = 0;
  const maxY = Math.max(...allY) * 1.15;
  const xPos = (t) => maxX === minX
    ? PAD_L + (W - PAD_L - PAD_R) / 2
    : PAD_L + ((t - minX) / (maxX - minX)) * (W - PAD_L - PAD_R);
  const yPos = (v) => H - PAD_B - ((v - minY) / (maxY - minY)) * (H - PAD_T - PAD_B);

  const pathFor = (key) => series
    .filter((b) => b[key] != null)
    .map((b, i) => `${i === 0 ? 'M' : 'L'}${xPos(new Date(b.hour).getTime()).toFixed(1)} ${yPos(b[key]).toFixed(1)}`)
    .join(' ');

  // Y-axis ticks at 0, 25%, 50%, 75%, 100%.
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => {
    const val = minY + f * (maxY - minY);
    const y = yPos(val);
    return `
      <line x1="${PAD_L}" x2="${W - PAD_R}" y1="${y}" y2="${y}"
            stroke="#e3dfd6" stroke-dasharray="2 3" stroke-width="1"/>
      <text x="${PAD_L - 8}" y="${y + 4}" text-anchor="end"
            font-size="10" fill="#8c8676">${Math.round(val)} ms</text>
    `;
  }).join('');

  // X-axis: first / mid / last hour labels.
  const xLabels = [0, Math.floor(series.length / 2), series.length - 1]
    .map((i) => series[i])
    .filter(Boolean)
    .map((b) => {
      const t = new Date(b.hour);
      const x = xPos(t.getTime());
      const lbl = `${t.getHours().toString().padStart(2, '0')}:00`;
      return `<text x="${x}" y="${H - 8}" text-anchor="middle"
                    font-size="10" fill="#8c8676">${lbl}</text>`;
    }).join('');

  svg.innerHTML = `
    ${yTicks}
    ${xLabels}
    <path d="${pathFor('p99')}" fill="none" stroke="#c79324"
          stroke-width="2" stroke-dasharray="4 3"/>
    <path d="${pathFor('p95')}" fill="none" stroke="#b85a1f" stroke-width="2"/>
    <text x="${W - PAD_R - 6}" y="${PAD_T + 12}" text-anchor="end"
          font-size="11" fill="#b85a1f">— p95</text>
    <text x="${W - PAD_R - 6}" y="${PAD_T + 28}" text-anchor="end"
          font-size="11" fill="#c79324">--- p99</text>
  `;
  if (caption) {
    const total = series.reduce((s, b) => s + (b.samples || 0), 0);
    caption.textContent = `${series.length} hourly buckets · ${total} samples`;
  }
}

async function loadHealthOverview() {
  const stamp = document.querySelector("#health-last-refreshed");
  if (stamp) stamp.textContent = "Loading…";
  try {
    const h = await api("/api/v1/admin/health-overview");
    // KPIs
    document.querySelector("#health-kpi-instances").textContent = h.kpis.gateway_instances;
    document.querySelector("#health-kpi-uptime").textContent = _humanUptime(h.kpis.uptime_seconds);
    document.querySelector("#health-kpi-uptime-sub").textContent =
      `boot at ${new Date(h.gateway_info.boot_at).toLocaleString()}`;
    document.querySelector("#health-kpi-p95").textContent = _humanMs(h.kpis.p95_latency_ms_1h);
    document.querySelector("#health-kpi-p95-sub").textContent =
      `avg: ${_humanMs(h.kpis.avg_latency_ms_1h)} · samples: ${h.kpis.latency_sample_size_1h}`;
    document.querySelector("#health-kpi-certs").textContent =
      h.kpis.idp_certificates_to_track.length;
    // Tenant card
    document.querySelector("#health-tenant-id").textContent = h.tenant_id;
    const sk = h.kpis.signing_key;
    document.querySelector("#health-tenant-key").textContent =
      sk.configured ? `configured · ${sk.key_length_bytes} bytes` : "NOT CONFIGURED";
    document.querySelector("#health-tenant-env").textContent = h.gateway_info.environment;
    document.querySelector("#health-tenant-version").textContent = h.gateway_info.version;
    // Status cards
    const row = document.querySelector("#health-status-row");
    row.innerHTML = Object.values(h.status_cards).map(_statusCardHtml).join("");
    // MCP servers table
    _renderHealthServers(h.mcp_servers);
    // Latency chart
    _renderLatencyChart(h.latency_series);
    if (stamp) stamp.textContent =
      `refreshed at ${new Date(h.generated_at).toLocaleTimeString()}`;
  } catch (error) {
    if (stamp) stamp.textContent = `Failed: ${error.message || error}`;
  }
}

document.querySelector("#refresh-health-overview")
  ?.addEventListener("click", loadHealthOverview);

// Auto-refresh every 15s while the Health panel is the active nav.
let _healthOverviewTimer = null;
function _kickHealthAutoRefresh() {
  if (_healthOverviewTimer) clearInterval(_healthOverviewTimer);
  _healthOverviewTimer = setInterval(() => {
    const active = document.querySelector('[data-nav="health-overview"].is-active');
    const panelVisible = document.querySelector(
      '#health-overview-panel:not([hidden])',
    );
    if (active || panelVisible) loadHealthOverview();
  }, 15000);
}
_kickHealthAutoRefresh();

function renderKpiCards(k) {
  // Card spec: { label, value, delta, tone }
  // tone: "" (default) | "alert" | "warn" — drives the kpi-value colour
  // and the delta pill class.
  const cards = [
    {
      label: "Non-human identities",
      value: k.nhi_total,
      delta: `${k.nhi_active_24h} active in last 24h`,
      tone: "",
    },
    {
      label: "Sanctioned MCP servers",
      value: k.mcp_servers_registered,
      delta: `${k.mcp_servers_active_24h} called in last 24h`,
      tone: "",
    },
    {
      label: "Virtual servers published",
      value: k.virtual_servers_published,
      delta: `${k.users_total} users in tenant`,
      tone: "",
    },
    {
      label: "Pending access requests",
      value: k.pending_access_requests,
      delta: k.pending_access_requests > 0 ? "Awaiting admin review" : "All clear",
      tone: k.pending_access_requests > 0 ? "warn" : "",
    },
    {
      label: "High-risk calls (24h)",
      value: k.high_risk_calls_24h,
      delta: k.high_risk_calls_24h > 0
        ? "delete · admin · credential_access · etc."
        : "No dangerous tool calls",
      tone: k.high_risk_calls_24h > 0 ? "alert" : "",
    },
    {
      label: "Denied / errored (24h)",
      value: (k.denied_calls_24h || 0) + (k.upstream_errors_24h || 0),
      delta:
        `${k.denied_calls_24h} denied · ${k.upstream_errors_24h} upstream errors`,
      tone:
        k.denied_calls_24h + k.upstream_errors_24h > 0 ? "warn" : "",
    },
    {
      label: "OAuth-connected SaaS",
      value: k.oauth_connected_servers,
      delta: `${k.oauth_connected_users} users with at least one connection`,
      tone: "",
    },
  ];

  return cards.map((c) => {
    const card = document.createElement("article");
    card.className = `kpi-card${c.tone ? ` ${c.tone}` : ""}`;
    const label = document.createElement("div");
    label.className = "kpi-label";
    label.textContent = c.label;
    const value = document.createElement("div");
    value.className = "kpi-value";
    value.textContent = String(c.value);
    const delta = document.createElement("div");
    delta.className = "kpi-delta";
    delta.textContent = c.delta;
    card.appendChild(label);
    card.appendChild(value);
    card.appendChild(delta);
    return card;
  });
}


// =========================================================================
// NHI map panel — 4-column bipartite SVG ("People & AI — who uses what")
// =========================================================================

const nhiMapOutput = document.querySelector("#nhi-map-output");
const nhiMapFilter = document.querySelector("#nhi-map-filter");

document.querySelector("#refresh-nhi-map").addEventListener("click", loadNhiMap);
document.querySelector("#nhi-map-window")?.addEventListener("change", loadNhiMap);
nhiMapFilter.addEventListener("change", loadNhiMap);
// 5th-column toggle is a pure FE filter (the backend always returns
// both tool + risk node sets); re-render against the cached map
// rather than refetching.
{
  const fifthSel = document.querySelector("#nhi-map-fifth");
  if (fifthSel) {
    fifthSel.addEventListener("change", () => {
      if (typeof _lastNhiMap === "object" && _lastNhiMap) {
        renderNhiMap(_lastNhiMap);
      }
    });
  }
}

// Cache the latest NHI map so the 5th-column toggle can re-render
// without a refetch. Only the FE filter changes — every shape
// (tool nodes + risk nodes) is already in the response.
let _lastNhiMap = null;

async function loadNhiMap() {
  nhiMapOutput.textContent = "Loading…";
  const params = new URLSearchParams();
  if (nhiMapFilter.value === "sanctioned_only") {
    params.set("sanctioned_only", "true");
  }
  const nhiWindowSelect = document.querySelector("#nhi-map-window");
  if (nhiWindowSelect) {
    params.set("since", windowSelectorToSinceIso(nhiWindowSelect.value));
  }
  try {
    const map = await api(`/api/v1/nhi-map?${params.toString()}`);
    _lastNhiMap = map;
    renderNhiMap(map);
  } catch (error) {
    renderError(nhiMapOutput, error);
  }
}

function renderNhiMap(map) {
  if (!map.nodes.length) {
    nhiMapOutput.textContent =
      "(no tool-call events seen yet — once traffic flows through, it'll show here)";
    return;
  }
  // Card-based interactive bipartite. Replaces the prior circle+
  // floating-label layout where labels for left columns ran rightward
  // INTO the connecting bezier curves and got hidden by them. Now
  // every node is a rounded-rect card with the label INSIDE it; edges
  // enter/exit from the card's left/right edges so labels never
  // collide with curves. Hover a card → highlight its connected edges
  // and dim the rest. Click a card → "focus mode" (only neighbours +
  // their connections). Click empty space → clear focus.
  const fifthMode = (
    document.querySelector("#nhi-map-fifth")?.value || "tool"
  );
  // Filter the node set down to the active 5th-column mode.
  const nodes = map.nodes.filter((n) => {
    if (n.column === "tool") return fifthMode === "tool";
    if (n.column === "risk") return fifthMode === "risk";
    return true;
  });
  const nodeIds = new Set(nodes.map((n) => n.id));
  const edges = map.edges.filter(
    (e) => nodeIds.has(e.source) && nodeIds.has(e.target),
  );

  const COLUMNS = fifthMode === "off"
    ? ["user", "ai_app", "mcp_server", "agent"]
    : (fifthMode === "risk"
        ? ["user", "ai_app", "mcp_server", "agent", "risk"]
        : ["user", "ai_app", "mcp_server", "agent", "tool"]);
  const COL_LABELS = {
    user: "USERS",
    ai_app: "AI APPS",
    mcp_server: "MCP SERVERS",
    agent: "AGENTS",
    tool: "TOOLS CALLED",
    risk: "RISK CATEGORY",
  };
  const COL_COLORS = {
    user:       "var(--vyuu-orange-deep)",
    ai_app:     "var(--vyuu-danger)",
    mcp_server: "var(--vyuu-info)",
    agent:      "var(--vyuu-warn)",
    tool:       "var(--vyuu-orange)",
    risk:       "var(--vyuu-danger-ink)",
  };

  // Group filtered nodes by column + sort each column by degree
  // (most-connected at top — matches typical Sankey legibility).
  const byCol = { user: [], ai_app: [], mcp_server: [], agent: [],
                   tool: [], risk: [] };
  for (const n of nodes) {
    if (byCol[n.column]) byCol[n.column].push(n);
  }
  const degree = {};
  for (const e of edges) {
    degree[e.source] = (degree[e.source] || 0) + e.weight;
    degree[e.target] = (degree[e.target] || 0) + e.weight;
  }
  for (const col of COLUMNS) {
    byCol[col].sort((a, b) => (degree[b.id] || 0) - (degree[a.id] || 0));
  }

  // Layout: card geometry. Each card is a rounded rectangle with the
  // label INSIDE, so text never collides with the connection curves.
  // Card width is chosen so a typical email / vserver name fits
  // without truncation; long labels get an ellipsis.
  const COL_COUNT = COLUMNS.length;
  const W = COL_COUNT === 4 ? 1180 : 1340;
  const PAD_X = 28;
  const CARD_W = 200;
  const CARD_H = 36;
  const ROW_GAP = 14;
  const HDR_H = 36;
  const PAD_TOP = HDR_H + 18;
  const COL_GAP = (W - PAD_X * 2 - CARD_W * COL_COUNT) /
                  Math.max(1, COL_COUNT - 1);

  const tallest = Math.max(
    1, ...COLUMNS.map((c) => byCol[c].length || 0),
  );
  const H = PAD_TOP + tallest * (CARD_H + ROW_GAP) + 24;

  // Position lookup: each node's card top-left (x, y), centre (cx, cy).
  const pos = new Map();
  COLUMNS.forEach((col, i) => {
    const x = PAD_X + i * (CARD_W + COL_GAP);
    byCol[col].forEach((n, idx) => {
      const y = PAD_TOP + idx * (CARD_H + ROW_GAP);
      pos.set(n.id, {
        x, y, col,
        cx: x + CARD_W / 2,
        cy: y + CARD_H / 2,
        rightAnchor: { x: x + CARD_W, y: y + CARD_H / 2 },
        leftAnchor:  { x: x,          y: y + CARD_H / 2 },
      });
    });
  });

  // Build edge → DOM-element index for hover/click highlighting.
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("width", "100%");
  svg.setAttribute("preserveAspectRatio", "xMinYMin meet");
  svg.setAttribute("style", "max-width: 100%; height: auto;");
  svg.classList.add("nhi-map-svg");

  // Column headers (eyebrow tone).
  COLUMNS.forEach((col, i) => {
    const x = PAD_X + i * (CARD_W + COL_GAP);
    const t = document.createElementNS(ns, "text");
    t.setAttribute("x", x);
    t.setAttribute("y", 22);
    t.setAttribute("text-anchor", "start");
    t.setAttribute(
      "style",
      "font: 600 10px 'Inter', system-ui, sans-serif; "
      + "letter-spacing: 2.5px; fill: var(--vyuu-orange-deep); "
      + "text-transform: uppercase;",
    );
    t.textContent = COL_LABELS[col];
    svg.appendChild(t);
    // Count under the header.
    const count = document.createElementNS(ns, "text");
    count.setAttribute("x", x);
    count.setAttribute("y", 36);
    count.setAttribute(
      "style",
      "font: 400 11px 'JetBrains Mono', ui-monospace, monospace; "
      + "fill: var(--vyuu-muted);",
    );
    count.textContent = `${byCol[col].length} ${
      byCol[col].length === 1 ? "node" : "nodes"
    }`;
    svg.appendChild(count);
  });

  const maxWeight = Math.max(1, ...edges.map((e) => e.weight));
  // Edges layer (rendered before nodes so cards paint on top).
  const edgeLayer = document.createElementNS(ns, "g");
  edgeLayer.classList.add("nhi-edges");
  svg.appendChild(edgeLayer);

  // Adjacency for highlight / focus.
  const edgesByNode = new Map();
  const edgePathById = new Map();
  for (const e of edges) {
    if (!edgesByNode.has(e.source)) edgesByNode.set(e.source, []);
    if (!edgesByNode.has(e.target)) edgesByNode.set(e.target, []);
    edgesByNode.get(e.source).push(e);
    edgesByNode.get(e.target).push(e);
  }

  for (const e of edges) {
    const a = pos.get(e.source);
    const b = pos.get(e.target);
    if (!a || !b) continue;
    const ax = a.rightAnchor.x;
    const ay = a.rightAnchor.y;
    const bx = b.leftAnchor.x;
    const by = b.leftAnchor.y;
    const path = document.createElementNS(ns, "path");
    const cx1 = ax + (bx - ax) * 0.5;
    const cx2 = bx - (bx - ax) * 0.5;
    path.setAttribute(
      "d",
      `M ${ax} ${ay} C ${cx1} ${ay}, ${cx2} ${by}, ${bx} ${by}`,
    );
    path.setAttribute("fill", "none");
    path.setAttribute(
      "stroke", COL_COLORS[a.col] || "var(--vyuu-line)",
    );
    path.setAttribute("stroke-opacity", "0.42");
    path.setAttribute(
      "stroke-width", String(1 + (e.weight / maxWeight) * 4),
    );
    const aN = nodes.find((n) => n.id === e.source);
    const bN = nodes.find((n) => n.id === e.target);
    if (aN && !aN.sanctioned || bN && !bN.sanctioned) {
      path.setAttribute("stroke-dasharray", "4 4");
    }
    path.dataset.source = e.source;
    path.dataset.target = e.target;
    path.classList.add("nhi-edge");
    edgeLayer.appendChild(path);
    const key = `${e.source}::${e.target}`;
    edgePathById.set(key, path);
  }

  // Nodes layer (cards as foreignObject so we get HTML/CSS for the
  // label, while the card outline lives in pure SVG for crisp lines
  // at any zoom level).
  const nodeLayer = document.createElementNS(ns, "g");
  nodeLayer.classList.add("nhi-nodes");
  svg.appendChild(nodeLayer);

  for (const n of nodes) {
    const p = pos.get(n.id);
    if (!p) continue;
    const g = document.createElementNS(ns, "g");
    g.classList.add("nhi-card");
    g.dataset.nodeId = n.id;
    g.dataset.column = n.column;
    g.dataset.sanctioned = n.sanctioned ? "1" : "0";

    const rect = document.createElementNS(ns, "rect");
    rect.setAttribute("x", p.x);
    rect.setAttribute("y", p.y);
    rect.setAttribute("rx", 8);
    rect.setAttribute("ry", 8);
    rect.setAttribute("width", CARD_W);
    rect.setAttribute("height", CARD_H);
    rect.setAttribute("fill", n.sanctioned
      ? "var(--vyuu-panel)" : "var(--vyuu-ivory)");
    rect.setAttribute("stroke", COL_COLORS[n.column] || "var(--vyuu-line)");
    rect.setAttribute("stroke-width", "1.4");
    if (!n.sanctioned) rect.setAttribute("stroke-dasharray", "4 3");
    g.appendChild(rect);

    // Status dot inside the card (left).
    const dot = document.createElementNS(ns, "circle");
    dot.setAttribute("cx", p.x + 14);
    dot.setAttribute("cy", p.cy);
    dot.setAttribute("r", 4);
    dot.setAttribute(
      "fill", COL_COLORS[n.column] || "var(--vyuu-line)",
    );
    g.appendChild(dot);

    // Label (truncated to fit). Width budget = card width minus the
    // status-dot gutter and right padding.
    const truncated = n.label.length > 22
      ? n.label.slice(0, 20) + "…" : n.label;
    const text = document.createElementNS(ns, "text");
    text.setAttribute("x", p.x + 26);
    text.setAttribute("y", p.cy + 4);
    text.setAttribute(
      "style",
      "font: 500 12px 'Inter', system-ui, sans-serif; "
      + "fill: var(--vyuu-ink); pointer-events: none;",
    );
    text.textContent = truncated;
    g.appendChild(text);

    // Native tooltip — operators get full label + detail on hover.
    const title = document.createElementNS(ns, "title");
    const sancTag = n.sanctioned ? "sanctioned" : "unsanctioned";
    const detail = n.detail ? ` · ${n.detail}` : "";
    title.textContent = `${COL_LABELS[n.column]}: ${n.label} · `
      + `${sancTag}${detail} · degree ${degree[n.id] || 0}`;
    g.appendChild(title);

    nodeLayer.appendChild(g);
  }

  // --- Interactivity --------------------------------------------------

  // Highlight: dim everything except nodes ON A DIRECTED PATH through
  // the hovered/focused node. Computed as the union of:
  //   - ancestors  : every node from which you can REACH nodeId by
  //                  walking forward (source → target) edges
  //   - descendants: every node REACHABLE FROM nodeId by walking
  //                  forward edges
  // Lit edges are those whose both endpoints fall on the same side
  // (both ancestors, or both descendants — nodeId belongs to both
  // sets, so the seam-edges incident to it are covered).
  //
  // Why directional and not full-component BFS: in a Sankey-style
  // graph every column shares the same far ends (every user is
  // connected to every AI app, etc.), so an undirected BFS from any
  // single node lights up the whole canvas. Directional traversal
  // produces what an operator actually wants: hovering "filesystem
  // MCP" lights only the users who reach it, the AI apps that route
  // to it, and the agents/tools/risks it fans out to — not unrelated
  // columns that happen to share peers two hops away.
  function setHighlight(nodeId) {
    const litNodes = new Set();
    const litEdges = new Set();  // keys: "src::tgt"
    if (nodeId) {
      const ancestors = new Set([nodeId]);
      const aQueue = [nodeId];
      while (aQueue.length) {
        const cur = aQueue.shift();
        for (const e of (edgesByNode.get(cur) || [])) {
          if (e.target === cur && !ancestors.has(e.source)) {
            ancestors.add(e.source);
            aQueue.push(e.source);
          }
        }
      }
      const descendants = new Set([nodeId]);
      const dQueue = [nodeId];
      while (dQueue.length) {
        const cur = dQueue.shift();
        for (const e of (edgesByNode.get(cur) || [])) {
          if (e.source === cur && !descendants.has(e.target)) {
            descendants.add(e.target);
            dQueue.push(e.target);
          }
        }
      }
      for (const id of ancestors)   litNodes.add(id);
      for (const id of descendants) litNodes.add(id);
      for (const e of edges) {
        const inUp   = ancestors.has(e.source)   && ancestors.has(e.target);
        const inDown = descendants.has(e.source) && descendants.has(e.target);
        if (inUp || inDown) litEdges.add(`${e.source}::${e.target}`);
      }
    }
    nodeLayer.querySelectorAll(".nhi-card").forEach((g) => {
      const dimmed = nodeId && !litNodes.has(g.dataset.nodeId);
      g.style.opacity = dimmed ? "0.18" : "1";
    });
    edgeLayer.querySelectorAll(".nhi-edge").forEach((p) => {
      const key = `${p.dataset.source}::${p.dataset.target}`;
      const involved = nodeId && litEdges.has(key);
      if (nodeId) {
        p.style.opacity = involved ? "1" : "0.05";
        if (involved) {
          p.setAttribute("stroke-opacity", "0.85");
          p.classList.add("nhi-edge-hl");
        } else {
          p.classList.remove("nhi-edge-hl");
        }
      } else {
        p.style.opacity = "";
        p.classList.remove("nhi-edge-hl");
        p.setAttribute("stroke-opacity", "0.42");
      }
    });
  }

  let focusedId = null;
  nodeLayer.querySelectorAll(".nhi-card").forEach((g) => {
    g.style.cursor = "pointer";
    g.addEventListener("mouseenter", () => {
      if (!focusedId) setHighlight(g.dataset.nodeId);
    });
    g.addEventListener("mouseleave", () => {
      if (!focusedId) setHighlight(null);
    });
    g.addEventListener("click", (event) => {
      event.stopPropagation();
      const id = g.dataset.nodeId;
      focusedId = focusedId === id ? null : id;
      setHighlight(focusedId);
    });
  });
  // Click empty space → clear focus.
  svg.addEventListener("click", () => {
    focusedId = null;
    setHighlight(null);
  });

  // --- Frame, legend, sample-size annotation -------------------------
  const frame = document.createElement("div");
  frame.className = "nhi-map-frame";
  frame.appendChild(svg);

  const legend = document.createElement("div");
  legend.className = "nhi-legend";
  for (const col of COLUMNS) {
    const span = document.createElement("span");
    const dot = document.createElement("span");
    dot.className = "nhi-legend-dot";
    dot.style.background = COL_COLORS[col];
    span.appendChild(dot);
    span.appendChild(document.createTextNode(
      COL_LABELS[col].toLowerCase(),
    ));
    legend.appendChild(span);
  }
  const dashed = document.createElement("span");
  const dashDot = document.createElement("span");
  dashDot.className = "nhi-legend-dot";
  dashDot.style.background = "var(--vyuu-ivory)";
  dashDot.style.border = "1.5px dashed var(--vyuu-muted)";
  dashed.appendChild(dashDot);
  dashed.appendChild(document.createTextNode("unsanctioned"));
  legend.appendChild(dashed);

  const sample = document.createElement("p");
  sample.className = "kpi-delta";
  sample.style.marginTop = "8px";
  sample.textContent = `Based on ${map.sample_size} recent tool calls.`
    + ` Hover a card to highlight its connections; click to focus.`;

  nhiMapOutput.replaceChildren(frame, legend, sample);
}


// =========================================================================
// Identities panel (N1) — per-principal aggregation of recent events
// =========================================================================

const identitiesOutput = document.querySelector("#identities-output");
const identitiesSearch = document.querySelector("#identities-search");
const identitiesCount = document.querySelector("#identities-count");

let identitiesCache = [];
const identitiesPillState = { current: "all" };

document.querySelector("#refresh-identities").addEventListener("click", () => {
  loadIdentities();
});
document.querySelector("#identities-window")?.addEventListener("change", () => {
  loadIdentities();
});
identitiesSearch.addEventListener("input", () => renderIdentities());
for (const pill of document.querySelectorAll("[data-identities-pill]")) {
  pill.addEventListener("click", () => {
    identitiesPillState.current = pill.dataset.identitiesPill;
    for (const p of document.querySelectorAll("[data-identities-pill]")) {
      p.classList.toggle("is-active", p === pill);
    }
    renderIdentities();
  });
}

async function loadIdentities() {
  identitiesOutput.innerHTML =
    '<tr><td colspan="7" class="events-empty">Loading…</td></tr>';
  try {
    // Fetch the full set; pill filtering happens client-side so the
    // pill bar is responsive (no API round-trip per pill click).
    const params = new URLSearchParams();
    const identitiesWindowSelect = document.querySelector("#identities-window");
    if (identitiesWindowSelect) {
      params.set(
        "since",
        windowSelectorToSinceIso(identitiesWindowSelect.value),
      );
    }
    const url = "/api/v1/identities" +
      (params.toString() ? `?${params.toString()}` : "");
    identitiesCache = await api(url);
    renderIdentities();
  } catch (error) {
    identitiesOutput.innerHTML = "";
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 7;
    td.className = "events-empty";
    td.textContent = String(error.message || error);
    tr.appendChild(td);
    identitiesOutput.appendChild(tr);
  }
}

function renderIdentities() {
  // KPIs always reflect the unfiltered cache so toggling pills doesn't
  // mask the totals.
  renderIdentitiesKpis(identitiesCache);

  const needle = (identitiesSearch.value || "").trim().toLowerCase();
  const pill = identitiesPillState.current;
  const filtered = identitiesCache.filter((row) => {
    if (needle) {
      const hay = `${row.principal_id} ${row.principal_display || ""}`.toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    if (pill === "high_risk") return (row.high_risk_calls || 0) > 0;
    if (pill === "api_key" || pill === "endpoint_session" || pill === "server_agent") {
      return row.principal_type === pill;
    }
    return true;
  });

  identitiesCount.textContent =
    filtered.length === identitiesCache.length
      ? `${filtered.length} identities`
      : `${filtered.length} of ${identitiesCache.length} identities`;

  identitiesOutput.innerHTML = "";
  if (!filtered.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 7;
    td.className = "events-empty";
    td.textContent = identitiesCache.length === 0
      ? "No tool-call events recorded yet — fire a tool call and click Refresh."
      : `(0 of ${identitiesCache.length} identities match the active filter)`;
    tr.appendChild(td);
    identitiesOutput.appendChild(tr);
    return;
  }
  for (const row of filtered) {
    identitiesOutput.appendChild(renderIdentityRow(row));
  }
}

function renderIdentitiesKpis(rows) {
  let total = 0;
  let highRisk = 0;
  let new24h = 0;
  // Most-active interface across the buffer. Operators glance at this
  // to answer "what's calling our gateway right now?" — Cursor 0.42 is
  // very different from a swarm of curl scripts.
  const clientCalls = new Map();
  const dayAgo = Date.now() - 24 * 60 * 60 * 1000;
  for (const row of rows) {
    total++;
    if ((row.high_risk_calls || 0) > 0) highRisk++;
    if (row.first_seen && Date.parse(row.first_seen) >= dayAgo) new24h++;
    const key = row.latest_client_name || (row.latest_user_agent ? "(no clientInfo)" : null);
    if (key) {
      clientCalls.set(key, (clientCalls.get(key) || 0) + (row.total_calls || 0));
    }
  }
  let topClient = null;
  let topCalls = 0;
  for (const [name, calls] of clientCalls) {
    if (calls > topCalls) { topClient = name; topCalls = calls; }
  }
  const set = (id, v) => {
    const el = document.querySelector(`#${id}`);
    if (el) el.textContent = v;
  };
  set("identities-kpi-total", total.toLocaleString());
  set("identities-kpi-high-risk", highRisk.toLocaleString());
  set("identities-kpi-new-24h", new24h.toLocaleString());
  if (topClient) {
    set("identities-kpi-top-client", prettifyClientName(topClient));
    set(
      "identities-kpi-top-client-sub",
      `${topCalls} call${topCalls === 1 ? "" : "s"} · ${clientCalls.size} interfaces`,
    );
  } else {
    set("identities-kpi-top-client", "—");
    set("identities-kpi-top-client-sub", "no clientInfo seen");
  }
}

function renderIdentityRow(row) {
  const tr = document.createElement("tr");
  // Risk-level cue on the row (left-border) — only when the principal
  // has executed at least one high-risk capability. Mirrors the
  // unsanctioned-row cue on Events for visual consistency.
  if ((row.high_risk_calls || 0) > 0) {
    tr.dataset.riskLevel = "high";
  }
  tr.addEventListener("click", () => openIdentityDrawer(row));

  // IDENTITY — type badge + display name + truncated id
  const idCell = document.createElement("td");
  const idWrap = document.createElement("div");
  idWrap.className = "events-row-identity";
  const headLine = document.createElement("span");
  headLine.className = "events-row-identity-name";
  const badge = document.createElement("span");
  badge.className = "events-identity-badge";
  badge.dataset.type = row.principal_type;
  badge.textContent = labelForIdentityType(row.principal_type);
  headLine.appendChild(badge);
  const displayName = row.principal_display
    || (row.principal_id.length > 20
        ? row.principal_id.slice(0, 18) + "…"
        : row.principal_id);
  headLine.appendChild(document.createTextNode(displayName));
  idWrap.appendChild(headLine);
  if (row.principal_display) {
    const sub = document.createElement("span");
    sub.className = "events-meta-line";
    sub.style.fontSize = "10.5px";
    sub.style.color = "var(--vyuu-muted)";
    sub.textContent = row.principal_id.length > 32
      ? row.principal_id.slice(0, 30) + "…"
      : row.principal_id;
    idWrap.appendChild(sub);
  }
  idCell.appendChild(idWrap);
  tr.appendChild(idCell);

  // TYPE — friendly label (User token / Endpoint session / Service agent)
  const typeCell = document.createElement("td");
  typeCell.style.fontSize = "11.5px";
  typeCell.style.color = "var(--vyuu-muted)";
  typeCell.textContent = labelForIdentityType(row.principal_type);
  tr.appendChild(typeCell);

  // VIA — interface that drove the call (e.g., "Cursor 0.42").
  // Falls back to user-agent first-token, then "—".
  const viaCell = document.createElement("td");
  const viaLabel = formatClientInterface(row);
  if (viaLabel) {
    const tag = document.createElement("span");
    tag.className = "identities-via-tag";
    tag.textContent = viaLabel;
    if (row.latest_user_agent) tag.title = row.latest_user_agent;
    viaCell.appendChild(tag);
    if ((row.distinct_clients || []).length > 1) {
      const more = document.createElement("span");
      more.className = "identities-meta-line";
      more.textContent = `+${row.distinct_clients.length - 1} other`;
      viaCell.appendChild(more);
    }
  } else {
    viaCell.textContent = "—";
    viaCell.style.color = "var(--vyuu-muted)";
  }
  tr.appendChild(viaCell);

  // ACTIVITY — calls + last-seen relative
  const actCell = document.createElement("td");
  const actWrap = document.createElement("div");
  actWrap.className = "identities-row-activity";
  const callsLine = document.createElement("strong");
  callsLine.textContent = `${row.total_calls} calls`;
  actWrap.appendChild(callsLine);
  const lastSeen = document.createElement("span");
  lastSeen.className = "identities-meta-line";
  lastSeen.textContent = `last seen ${formatRelativeTime(row.last_seen)}`;
  actWrap.appendChild(lastSeen);
  if ((row.denied_calls || 0) > 0 || (row.upstream_error_calls || 0) > 0) {
    const errs = document.createElement("span");
    errs.className = "identities-meta-line";
    const parts = [];
    if (row.denied_calls > 0) parts.push(`${row.denied_calls} denied`);
    if (row.upstream_error_calls > 0) {
      parts.push(`${row.upstream_error_calls} upstream errors`);
    }
    errs.textContent = parts.join(" · ");
    errs.style.color = "var(--vyuu-orange-deep)";
    actWrap.appendChild(errs);
  }
  actCell.appendChild(actWrap);
  tr.appendChild(actCell);

  // FOOTPRINT — distinct tools / vservers / upstreams
  const fpCell = document.createElement("td");
  const fp = document.createElement("div");
  fp.className = "identities-row-footprint";
  fp.innerHTML = `
    <span><strong>${row.distinct_tools}</strong> tools</span>
    <span><strong>${row.distinct_vservers}</strong> vservers</span>
    <span><strong>${row.distinct_upstreams}</strong> upstreams</span>`;
  fpCell.appendChild(fp);
  tr.appendChild(fpCell);

  // RISK — pill driven by high_risk_calls count
  const riskCell = document.createElement("td");
  const riskPill = document.createElement("span");
  riskPill.className = "events-risk-pill";
  if ((row.high_risk_calls || 0) > 0) {
    riskPill.dataset.risk = "high";
    riskPill.textContent = `${row.high_risk_calls} high`;
  } else if ((row.denied_calls || 0) > 0) {
    riskPill.dataset.risk = "medium";
    riskPill.textContent = "medium";
  } else {
    riskPill.dataset.risk = "low";
    riskPill.textContent = "low";
  }
  riskCell.appendChild(riskPill);
  tr.appendChild(riskCell);

  // ACTIONS — drill-in arrow (whole row is clickable, this is just
  // the visual cue)
  const actionsCell = document.createElement("td");
  actionsCell.style.textAlign = "right";
  const arrow = document.createElement("button");
  arrow.type = "button";
  arrow.className = "identities-row-action-btn";
  arrow.textContent = "Drill in →";
  arrow.addEventListener("click", (e) => {
    e.stopPropagation();
    openIdentityDrawer(row);
  });
  actionsCell.appendChild(arrow);
  tr.appendChild(actionsCell);

  return tr;
}

// Relative-time formatter for "last seen X ago". Falls back to absolute
// timestamp for anything older than ~1 day.
function formatRelativeTime(iso) {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (isNaN(t)) return iso;
  const seconds = Math.max(0, (Date.now() - t) / 1000);
  if (seconds < 60) return `${Math.round(seconds)}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return new Date(t).toLocaleString();
}

// ---------- Identity drawer (slide-over for drill-ins) -----------------
const _identityDrawer = {
  el: () => document.querySelector("#identity-drawer"),
  body: () => document.querySelector("#identity-drawer-body"),
  title: () => document.querySelector("#identity-drawer-title"),
  sub: () => document.querySelector("#identity-drawer-sub"),
  currentRow: null,
  currentTab: "timeline",
};

function openIdentityDrawer(row) {
  _identityDrawer.currentRow = row;
  _identityDrawer.title().textContent =
    row.principal_display || row.principal_id;
  const parts = [
    labelForIdentityType(row.principal_type),
    row.principal_id,
  ];
  const via = formatClientInterface(row);
  if (via) parts.push(`via ${via}`);
  _identityDrawer.sub().textContent = parts.join(" · ");
  _identityDrawer.el().hidden = false;
  document.body.style.overflow = "hidden";
  // Default tab: timeline (most operators want chronological view first).
  switchIdentityDrawerTab("timeline");
}

function closeIdentityDrawer() {
  _identityDrawer.el().hidden = true;
  _identityDrawer.body().innerHTML = "";
  document.body.style.overflow = "";
}

function switchIdentityDrawerTab(tab) {
  _identityDrawer.currentTab = tab;
  for (const t of document.querySelectorAll(".identity-drawer-tab")) {
    t.classList.toggle("is-active", t.dataset.drawerTab === tab);
  }
  const body = _identityDrawer.body();
  body.innerHTML = "Loading…";
  const principalId = _identityDrawer.currentRow.principal_id;
  if (tab === "timeline") {
    renderTimelineControls(body, principalId);
  } else if (tab === "graph") {
    renderIdentityGraph(body, principalId);
  } else if (tab === "summary") {
    renderIdentitySummary(body, principalId);
  }
}

// Drawer wiring — close button, backdrop click, Escape key, tab switch
{
  const drawerCloseEls = document.querySelectorAll("[data-identity-drawer-close]");
  for (const el of drawerCloseEls) {
    el.addEventListener("click", closeIdentityDrawer);
  }
  for (const tab of document.querySelectorAll(".identity-drawer-tab")) {
    tab.addEventListener("click", () => switchIdentityDrawerTab(tab.dataset.drawerTab));
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !_identityDrawer.el().hidden) {
      closeIdentityDrawer();
    }
  });
}


// =========================================================================
// N3: identity dependency-graph visualisation (4-column card layout)
// =========================================================================
// Replaces the prior radial-concentric layout. The radial design fell
// apart for any upstream that exposes >15 tools (looking at you,
// falcon-mcp with 56) — the outer ring's labels overlapped each
// other AND collided with the next ring's labels above them. The
// column layout (a) gives every label its own row, (b) lets us
// truncate predictably with ellipsis, (c) matches the NHI map redesign
// for visual consistency, (d) handles 50+ tools by simply growing the
// canvas vertically (the parent `.identity-graph-frame` provides scroll).

async function renderIdentityGraph(container, principalId) {
  container.innerHTML = "Loading…";
  let graph;
  try {
    graph = await api(
      `/api/v1/identities/${encodeURIComponent(principalId)}/graph`,
    );
  } catch (error) {
    renderError(container, error);
    return;
  }
  if (!graph.nodes.length) {
    container.textContent = "(no granted vservers — graph is empty)";
    return;
  }

  const COLUMNS = ["principal", "vserver", "tool", "upstream"];
  const COL_LABELS = {
    principal: "IDENTITY",
    vserver:   "VSERVERS",
    tool:      "TOOLS EXPOSED",
    upstream:  "UPSTREAM MCPs",
  };
  const COL_COLORS = {
    principal: "var(--vyuu-orange-deep)",
    vserver:   "var(--vyuu-info)",
    tool:      "var(--vyuu-orange)",
    upstream:  "var(--vyuu-ink)",
  };
  // Risk-tone overlay for tool cards (status dot + left border).
  // Brighter = higher danger so the eye picks out destructive
  // capabilities first.
  const RISK_COLOR = {
    admin:             "#A85820",
    delete:            "#C17457",
    credential_access: "#C17457",
    execute:           "#D4A259",
    data_export:       "#D4A259",
    write:             "#4E7A8A",
    network:           "#6B7A7D",
    read:              "#A9B4B5",
    unknown:           "#A9B4B5",
  };

  // Bin nodes by kind; sort so the most-connected sits at top of
  // each column (Sankey-style — easier to read).
  const byCol = { principal: [], vserver: [], tool: [], upstream: [] };
  for (const n of graph.nodes) {
    if (byCol[n.kind]) byCol[n.kind].push(n);
  }
  const degree = {};
  for (const e of graph.edges) {
    degree[e.source] = (degree[e.source] || 0) + 1;
    degree[e.target] = (degree[e.target] || 0) + 1;
  }
  for (const col of COLUMNS) {
    byCol[col].sort((a, b) => (degree[b.id] || 0) - (degree[a.id] || 0));
  }

  // Card geometry — same as NHI map for visual consistency.
  const CARD_W = 220;
  const CARD_H = 36;
  const ROW_GAP = 10;
  const PAD_X = 28;
  const HDR_H = 36;
  const PAD_TOP = HDR_H + 18;
  const W = 1100;
  const COL_GAP = (W - PAD_X * 2 - CARD_W * COLUMNS.length) /
                  Math.max(1, COLUMNS.length - 1);

  // Tool column drives canvas height (it's the heavy one).
  const tallest = Math.max(
    1, ...COLUMNS.map((c) => byCol[c].length || 0),
  );
  const H = PAD_TOP + tallest * (CARD_H + ROW_GAP) + 24;

  // Position lookup: (x,y) of card top-left + left/right anchors.
  const pos = new Map();
  COLUMNS.forEach((col, i) => {
    const x = PAD_X + i * (CARD_W + COL_GAP);
    byCol[col].forEach((n, idx) => {
      const y = PAD_TOP + idx * (CARD_H + ROW_GAP);
      pos.set(n.id, {
        x, y, col,
        cx: x + CARD_W / 2,
        cy: y + CARD_H / 2,
        rightAnchor: { x: x + CARD_W, y: y + CARD_H / 2 },
        leftAnchor:  { x: x,          y: y + CARD_H / 2 },
      });
    });
  });

  container.innerHTML = "";
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("width", "100%");
  svg.setAttribute("preserveAspectRatio", "xMinYMin meet");
  svg.setAttribute("style", "max-width: 100%; height: auto;");
  svg.classList.add("identity-graph-svg");

  // Column headers.
  COLUMNS.forEach((col, i) => {
    const x = PAD_X + i * (CARD_W + COL_GAP);
    const t = document.createElementNS(ns, "text");
    t.setAttribute("x", x);
    t.setAttribute("y", 22);
    t.setAttribute(
      "style",
      "font: 600 10px 'Inter', system-ui, sans-serif; "
      + "letter-spacing: 2.5px; fill: var(--vyuu-orange-deep); "
      + "text-transform: uppercase;",
    );
    t.textContent = COL_LABELS[col];
    svg.appendChild(t);
    const count = document.createElementNS(ns, "text");
    count.setAttribute("x", x);
    count.setAttribute("y", 36);
    count.setAttribute(
      "style",
      "font: 400 11px 'JetBrains Mono', ui-monospace, monospace; "
      + "fill: var(--vyuu-muted);",
    );
    count.textContent = `${byCol[col].length} ${
      byCol[col].length === 1 ? "node" : "nodes"
    }`;
    svg.appendChild(count);
  });

  // Adjacency for hover-highlight (BFS over reachable subgraph,
  // same pattern as the NHI map).
  const edgesByNode = new Map();
  for (const e of graph.edges) {
    if (!edgesByNode.has(e.source)) edgesByNode.set(e.source, []);
    if (!edgesByNode.has(e.target)) edgesByNode.set(e.target, []);
    edgesByNode.get(e.source).push(e);
    edgesByNode.get(e.target).push(e);
  }

  // Edges layer (under nodes).
  const edgeLayer = document.createElementNS(ns, "g");
  edgeLayer.classList.add("identity-graph-edges");
  svg.appendChild(edgeLayer);

  for (const e of graph.edges) {
    const a = pos.get(e.source);
    const b = pos.get(e.target);
    if (!a || !b) continue;
    const ax = a.rightAnchor.x;
    const ay = a.rightAnchor.y;
    const bx = b.leftAnchor.x;
    const by = b.leftAnchor.y;
    const path = document.createElementNS(ns, "path");
    const cx1 = ax + (bx - ax) * 0.5;
    const cx2 = bx - (bx - ax) * 0.5;
    path.setAttribute(
      "d",
      `M ${ax} ${ay} C ${cx1} ${ay}, ${cx2} ${by}, ${bx} ${by}`,
    );
    path.setAttribute("fill", "none");
    path.setAttribute(
      "stroke", COL_COLORS[a.col] || "var(--vyuu-line)",
    );
    path.setAttribute("stroke-opacity", "0.42");
    path.setAttribute("stroke-width", "1.4");
    path.dataset.source = e.source;
    path.dataset.target = e.target;
    path.classList.add("identity-graph-edge");
    edgeLayer.appendChild(path);
  }

  // Nodes layer.
  const nodeLayer = document.createElementNS(ns, "g");
  nodeLayer.classList.add("identity-graph-nodes");
  svg.appendChild(nodeLayer);

  for (const n of graph.nodes) {
    const p = pos.get(n.id);
    if (!p) continue;
    const g = document.createElementNS(ns, "g");
    g.classList.add("identity-graph-card");
    g.dataset.nodeId = n.id;
    g.dataset.kind = n.kind;
    g.style.cursor = "pointer";

    const baseColor = COL_COLORS[n.kind] || "var(--vyuu-line)";
    const dotColor = (n.kind === "tool" && n.risk)
      ? (RISK_COLOR[n.risk] || baseColor)
      : baseColor;

    const rect = document.createElementNS(ns, "rect");
    rect.setAttribute("x", p.x);
    rect.setAttribute("y", p.y);
    rect.setAttribute("rx", 8);
    rect.setAttribute("ry", 8);
    rect.setAttribute("width", CARD_W);
    rect.setAttribute("height", CARD_H);
    rect.setAttribute("fill", "var(--vyuu-panel)");
    rect.setAttribute("stroke", baseColor);
    rect.setAttribute("stroke-width", "1.4");
    g.appendChild(rect);

    // Status dot (left). For tools, the dot is risk-coloured.
    const dot = document.createElementNS(ns, "circle");
    dot.setAttribute("cx", p.x + 14);
    dot.setAttribute("cy", p.cy);
    dot.setAttribute("r", 4);
    dot.setAttribute("fill", dotColor);
    g.appendChild(dot);

    // Principal cards get a slightly thicker accent ring.
    if (n.kind === "principal") {
      const ring = document.createElementNS(ns, "circle");
      ring.setAttribute("cx", p.x + 14);
      ring.setAttribute("cy", p.cy);
      ring.setAttribute("r", 6.5);
      ring.setAttribute("fill", "none");
      ring.setAttribute("stroke", baseColor);
      ring.setAttribute("stroke-width", "1");
      ring.setAttribute("stroke-opacity", "0.6");
      g.appendChild(ring);
    }

    const truncated = n.label.length > 24
      ? n.label.slice(0, 22) + "…" : n.label;
    const text = document.createElementNS(ns, "text");
    text.setAttribute("x", p.x + 26);
    text.setAttribute("y", p.cy + 4);
    text.setAttribute(
      "style",
      "font: 500 12px 'Inter', system-ui, sans-serif; "
      + "fill: var(--vyuu-ink); pointer-events: none;",
    );
    text.textContent = truncated;
    g.appendChild(text);

    // Risk tag on the right edge of tool cards.
    if (n.kind === "tool" && n.risk) {
      const riskTag = document.createElementNS(ns, "text");
      riskTag.setAttribute("x", p.x + CARD_W - 10);
      riskTag.setAttribute("y", p.cy + 4);
      riskTag.setAttribute("text-anchor", "end");
      riskTag.setAttribute(
        "style",
        "font: 600 9px 'JetBrains Mono', ui-monospace, monospace; "
        + "letter-spacing: 1.2px; "
        + `fill: ${RISK_COLOR[n.risk] || "var(--vyuu-muted)"}; `
        + "text-transform: uppercase; pointer-events: none;",
      );
      riskTag.textContent = n.risk;
      g.appendChild(riskTag);
    }

    const title = document.createElementNS(ns, "title");
    title.textContent = n.risk
      ? `${n.kind}: ${n.label} · risk=${n.risk}`
      : `${n.kind}: ${n.label}`;
    g.appendChild(title);

    nodeLayer.appendChild(g);
  }

  // --- Hover-highlight: directional flow through the hovered node ----
  // Lit = ancestors (anything that flows INTO nodeId) ∪ descendants
  // (anything nodeId flows OUT to). Edges within each side stay lit;
  // unrelated edges dim. See the longer explainer in renderNhiMap.
  function setHighlight(nodeId) {
    const litNodes = new Set();
    const litEdges = new Set();
    if (nodeId) {
      const ancestors = new Set([nodeId]);
      const aQueue = [nodeId];
      while (aQueue.length) {
        const cur = aQueue.shift();
        for (const e of (edgesByNode.get(cur) || [])) {
          if (e.target === cur && !ancestors.has(e.source)) {
            ancestors.add(e.source);
            aQueue.push(e.source);
          }
        }
      }
      const descendants = new Set([nodeId]);
      const dQueue = [nodeId];
      while (dQueue.length) {
        const cur = dQueue.shift();
        for (const e of (edgesByNode.get(cur) || [])) {
          if (e.source === cur && !descendants.has(e.target)) {
            descendants.add(e.target);
            dQueue.push(e.target);
          }
        }
      }
      for (const id of ancestors)   litNodes.add(id);
      for (const id of descendants) litNodes.add(id);
      for (const e of graph.edges) {
        const inUp   = ancestors.has(e.source)   && ancestors.has(e.target);
        const inDown = descendants.has(e.source) && descendants.has(e.target);
        if (inUp || inDown) litEdges.add(`${e.source}::${e.target}`);
      }
    }
    nodeLayer.querySelectorAll(".identity-graph-card").forEach((el) => {
      const dimmed = nodeId && !litNodes.has(el.dataset.nodeId);
      el.style.opacity = dimmed ? "0.18" : "1";
    });
    edgeLayer.querySelectorAll(".identity-graph-edge").forEach((p) => {
      const key = `${p.dataset.source}::${p.dataset.target}`;
      const involved = nodeId && litEdges.has(key);
      if (nodeId) {
        p.style.opacity = involved ? "1" : "0.06";
        p.setAttribute("stroke-opacity", involved ? "0.85" : "0.06");
        if (involved) p.classList.add("identity-graph-edge-hl");
        else p.classList.remove("identity-graph-edge-hl");
      } else {
        p.style.opacity = "";
        p.setAttribute("stroke-opacity", "0.42");
        p.classList.remove("identity-graph-edge-hl");
      }
    });
  }

  let focusedId = null;
  nodeLayer.querySelectorAll(".identity-graph-card").forEach((el) => {
    el.addEventListener("mouseenter", () => {
      if (!focusedId) setHighlight(el.dataset.nodeId);
    });
    el.addEventListener("mouseleave", () => {
      if (!focusedId) setHighlight(null);
    });
    el.addEventListener("click", (event) => {
      event.stopPropagation();
      const id = el.dataset.nodeId;
      focusedId = focusedId === id ? null : id;
      setHighlight(focusedId);
    });
  });
  svg.addEventListener("click", () => {
    focusedId = null;
    setHighlight(null);
  });

  // Frame + legend.
  const frame = document.createElement("div");
  frame.className = "identity-graph-frame";
  frame.appendChild(svg);

  const legend = document.createElement("div");
  legend.className = "identity-graph-legend";
  for (const col of COLUMNS) {
    const span = document.createElement("span");
    const dot = document.createElement("span");
    dot.className = "identity-graph-legend-dot";
    dot.style.background = COL_COLORS[col];
    span.appendChild(dot);
    span.appendChild(document.createTextNode(
      COL_LABELS[col].toLowerCase(),
    ));
    legend.appendChild(span);
  }
  // Risk legend row — only if there's at least one tool with a risk.
  if (byCol.tool.some((t) => t.risk)) {
    const riskRow = document.createElement("div");
    riskRow.className = "identity-graph-legend identity-graph-risk-legend";
    const eyebrow = document.createElement("span");
    eyebrow.textContent = "risk";
    eyebrow.className = "identity-graph-legend-eyebrow";
    riskRow.appendChild(eyebrow);
    for (const [label, color] of [
      ["admin",             RISK_COLOR.admin],
      ["delete",            RISK_COLOR.delete],
      ["credential_access", RISK_COLOR.credential_access],
      ["execute",           RISK_COLOR.execute],
      ["data_export",       RISK_COLOR.data_export],
      ["write",             RISK_COLOR.write],
      ["network",           RISK_COLOR.network],
      ["read",              RISK_COLOR.read],
    ]) {
      const span = document.createElement("span");
      const dot = document.createElement("span");
      dot.className = "identity-graph-legend-dot";
      dot.style.background = color;
      span.appendChild(dot);
      span.appendChild(document.createTextNode(label));
      riskRow.appendChild(span);
    }
    container.appendChild(frame);
    container.appendChild(legend);
    container.appendChild(riskRow);
    return;
  }
  container.appendChild(frame);
  container.appendChild(legend);
}


async function renderIdentitySummary(container, principalId) {
  container.innerHTML = "Loading…";
  let summary;
  try {
    summary = await api(
      `/api/v1/identities/${encodeURIComponent(principalId)}/summary`,
    );
  } catch (error) {
    renderError(container, error);
    return;
  }

  // Score badge (0..100). Colour-coded by severity bucket.
  const scoreColor = summary.risk_score >= 70 ? "danger"
                   : summary.risk_score >= 40 ? "warn" : "granted";

  const oauth = summary.oauth_connections.length
    ? summary.oauth_connections
        .map((c) => `<li>${escapeHtml(c.server_display_name)}
            ${c.scope ? `· scope <code>${escapeHtml(c.scope)}</code>` : ""}</li>`)
        .join("")
    : "<li>(none)</li>";

  const upstreams = summary.reachable_upstreams.length
    ? summary.reachable_upstreams
        .map((u) => {
          const conn = u.oauth_connected === true ? "✓ connected"
                     : u.oauth_connected === false ? "✗ not connected"
                     : "(M2M auth)";
          return `<li>${escapeHtml(u.display_name)}
              · ${escapeHtml(u.transport)}
              <small>${conn}</small></li>`;
        })
        .join("")
    : "<li>(none)</li>";

  container.innerHTML = `
    <div style="display: flex; gap: 16px; flex-wrap: wrap;">
      <span class="badge ${scoreColor}">risk score ${summary.risk_score}/100</span>
      <span class="badge">max risk: ${escapeHtml(summary.max_risk_category)}</span>
      <span class="badge">${summary.granted_vservers.length} vservers</span>
      <span class="badge">${summary.exposed_tools.length} tools reachable</span>
    </div>
    <details style="margin-top: 8px;">
      <summary>OAuth connections (${summary.oauth_connections.length})</summary>
      <ul style="margin: 4px 0;">${oauth}</ul>
    </details>
    <details style="margin-top: 4px;">
      <summary>Reachable upstreams (${summary.reachable_upstreams.length})</summary>
      <ul style="margin: 4px 0;">${upstreams}</ul>
    </details>`;
}

// Compact one-event entry for the identity-drawer timeline tab.
// Cards (not table rows) — the drawer is narrow and a vertical
// stack scans better than a wide table. Mirrors the events-table
// styling cues (red border on unsanctioned, color-coded outcome).
function renderTimelineEntry(event) {
  const card = document.createElement("article");
  const eventClass = (event.event_type === "access_attempt") ? "unsanctioned"
    : (event.decision === "deny") ? "blocked"
    : (event.decision === "redact" || event.decision === "rewrite") ? "redacted"
    : "allowed";
  card.style.padding = "10px 12px";
  card.style.marginBottom = "8px";
  card.style.border = "1px solid var(--vyuu-line)";
  card.style.borderRadius = "var(--vyuu-r-sm, 4px)";
  card.style.fontSize = "12px";
  if (eventClass === "unsanctioned") {
    card.style.borderLeft = "3px solid #A85820";
    card.style.background = "rgba(168, 88, 32, 0.03)";
  } else if (eventClass === "blocked") {
    card.style.borderLeft = "3px solid rgba(168, 88, 32, 0.4)";
  }

  // Top line: timestamp + outcome word + tool/vserver
  const head = document.createElement("div");
  head.style.display = "flex";
  head.style.justifyContent = "space-between";
  head.style.gap = "10px";
  head.style.marginBottom = "6px";
  const ts = new Date(event.timestamp);
  const left = document.createElement("span");
  left.style.color = "var(--vyuu-muted)";
  left.style.fontFamily = "var(--vyuu-mono, monospace)";
  left.textContent = ts.toLocaleTimeString(undefined, {
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  });
  head.appendChild(left);
  const outcome = document.createElement("span");
  outcome.className = "events-row-reason-outcome";
  outcome.dataset.outcome = eventClass;
  outcome.style.fontSize = "10.5px";
  if (eventClass === "unsanctioned") outcome.textContent = "Unsanctioned";
  else if (eventClass === "blocked") outcome.textContent = "Blocked";
  else if (eventClass === "redacted") outcome.textContent = "Redacted";
  else outcome.textContent = "Allowed";
  head.appendChild(outcome);
  card.appendChild(head);

  // Body: vserver · tool, then args summary.
  const body = document.createElement("div");
  const vserverName = event.vserver_name
    || (event.vserver_id && vserverNameById.get(event.vserver_id))
    || (event.vserver_id ? event.vserver_id.slice(0, 8) + "…" : "—");
  const tool = event.tool || "<connect>";
  body.innerHTML = `
    <strong>${escapeHtmlOp(vserverName)}</strong>
    <span style="color: var(--vyuu-muted);"> · </span>
    <code style="font-family: var(--vyuu-mono);">${escapeHtmlOp(tool)}</code>`;
  card.appendChild(body);

  // Latency / reason on the third line for tool_calls.
  if (event.event_type === "tool_call" && event.latency_ms_total != null) {
    const meta = document.createElement("div");
    meta.style.fontSize = "10.5px";
    meta.style.color = "var(--vyuu-muted)";
    meta.style.marginTop = "4px";
    const total = `${event.latency_ms_total.toFixed(0)}ms`;
    const up = event.latency_ms_upstream != null
      ? ` · upstream ${event.latency_ms_upstream.toFixed(0)}ms`
      : "";
    meta.textContent = `${total}${up} · ${event.upstream_status || "ok"}`;
    card.appendChild(meta);
  } else if (event.event_type === "access_attempt") {
    const meta = document.createElement("div");
    meta.style.fontSize = "10.5px";
    meta.style.color = "var(--vyuu-orange-deep)";
    meta.style.marginTop = "4px";
    meta.textContent = labelForAuthFailure(
      event.auth_failure_reason || "auth_failure",
    );
    card.appendChild(meta);
  }
  return card;
}

function renderTimelineControls(container, principalId) {
  // One-shot: build the timeline filter UI + initial load.
  container.innerHTML = `
    <div class="form-grid" style="grid-template-columns: repeat(3, 1fr) auto;">
      <label>
        Decision
        <select data-timeline-decision>
          <option value="">— any —</option>
          <option value="allow">allow</option>
          <option value="deny">deny</option>
          <option value="redact">redact</option>
          <option value="rewrite">rewrite</option>
        </select>
      </label>
      <label>
        Risk floor
        <select data-timeline-risk>
          <option value="">— any —</option>
          <option value="read">read +</option>
          <option value="network">network +</option>
          <option value="write">write +</option>
          <option value="data_export">data_export +</option>
          <option value="execute">execute +</option>
          <option value="delete">delete +</option>
          <option value="credential_access">credential_access +</option>
          <option value="admin">admin only</option>
        </select>
      </label>
      <label>
        Limit
        <input data-timeline-limit type="number" min="1" max="500" value="50">
      </label>
      <button data-timeline-apply class="ghost" style="align-self: end;">
        Apply
      </button>
    </div>
    <div data-timeline-output class="cards" style="margin-top: 8px;">
      Loading…
    </div>`;

  const decisionSel = container.querySelector("[data-timeline-decision]");
  const riskSel = container.querySelector("[data-timeline-risk]");
  const limitInput = container.querySelector("[data-timeline-limit]");
  const applyBtn = container.querySelector("[data-timeline-apply]");
  const output = container.querySelector("[data-timeline-output]");

  async function load() {
    output.textContent = "Loading…";
    const params = new URLSearchParams();
    if (decisionSel.value) params.set("decision", decisionSel.value);
    if (riskSel.value) params.set("risk_floor", riskSel.value);
    const limit = Math.max(1, Math.min(500, Number(limitInput.value) || 50));
    params.set("limit", String(limit));
    try {
      const rows = await api(
        `/api/v1/identities/${encodeURIComponent(principalId)}/timeline?${params.toString()}`
      );
      if (!rows.length) {
        output.textContent = "(no events match the filters)";
        return;
      }
      output.replaceChildren(...rows.map(renderTimelineEntry));
    } catch (error) {
      renderError(output, error);
    }
  }

  applyBtn.addEventListener("click", load);
  load();
}


// =========================================================================
// Events panel — read-side of the persistent `tool_call_events` table
// =========================================================================

// Convert a window selector value (1h / 24h / 7d / 30d) to an ISO
// timestamp suitable for the `since=` query param. Centralised so the
// Events / NHI map / Identities panels stay in lockstep.
function windowSelectorToSinceIso(value) {
  const ms = {
    "1h": 3600e3,
    "24h": 86400e3,
    "7d": 7 * 86400e3,
    "30d": 30 * 86400e3,
  }[value] || 86400e3;
  return new Date(Date.now() - ms).toISOString();
}

const auditEventsOutput = document.querySelector("#audit-events-output");
const auditVserverFilter = document.querySelector("#audit-vserver-filter");
const auditToolFilter = document.querySelector("#audit-tool-filter");
const auditDecisionFilter = document.querySelector("#audit-decision-filter");
const auditEventTypeFilter = document.querySelector("#audit-event-type-filter");
const auditLimitInput = document.querySelector("#audit-limit");

document.querySelector("#refresh-audit-events").addEventListener("click", async () => {
  // Sequence matters: populate the vserver_id → name map BEFORE
  // rendering rows, otherwise the first refresh shows UUID prefixes
  // until the second refresh populates the cache.
  await populateAuditVserverOptions();
  await loadAuditEvents();
});
document.querySelector("#events-window")?.addEventListener("change", loadAuditEvents);
document.querySelector("#apply-audit-filter").addEventListener("click", loadAuditEvents);

// Cache of vserver_id → vserver_name. Populated by
// `populateAuditVserverOptions` so the events table can resolve the
// human-readable name even when the audit row only carries the
// vserver_id (tool_call events leave `vserver_name` null because the
// resolver stamps it only on access_attempts).
const vserverNameById = new Map();

async function populateAuditVserverOptions() {
  // Reuse the existing /api/v1/vservers feed to drive the filter
  // dropdown AND populate the name-lookup map. Quietly no-op if the
  // call fails — empty dropdown is benign and the table falls back
  // to showing the vserver_id prefix.
  try {
    const rows = await api("/api/v1/vservers");
    const current = auditVserverFilter.value;
    auditVserverFilter.innerHTML = '<option value="">— all —</option>';
    vserverNameById.clear();
    for (const v of rows) {
      vserverNameById.set(v.id, v.name);
      const opt = document.createElement("option");
      opt.value = v.id;
      opt.textContent = `${v.name}  ·  ${v.id.slice(0, 8)}…`;
      auditVserverFilter.appendChild(opt);
    }
    if (current) auditVserverFilter.value = current;
  } catch {
    // ignore — operator can still load all events
  }
}

// Pill-driven filter state. `all` shows everything; the others narrow
// by event class, decision, or risk. Combines with the advanced-
// filters dropdown values (server-side + client-side) so power users
// can stack the pill + advanced filters.
const eventsPillState = { current: "all" };
let eventsCache = [];

async function loadAuditEvents() {
  const tbody = document.querySelector("#audit-events-output");
  tbody.innerHTML = '<tr><td colspan="6" class="events-empty">Loading…</td></tr>';
  const params = new URLSearchParams();
  const vserverId = auditVserverFilter.value;
  if (vserverId) params.set("vserver_id", vserverId);
  const eventType = auditEventTypeFilter.value;
  if (eventType) params.set("event_type", eventType);
  const limit = Math.max(1, Math.min(500, Number(auditLimitInput.value) || 100));
  params.set("limit", String(limit));
  // Time-window picker — drives the `since=` query param. Defaults to
  // last 24h via the <select>'s `selected` option, matching the
  // server-side default in `audit_events.py`.
  const eventsWindowSelect = document.querySelector("#events-window");
  if (eventsWindowSelect) {
    params.set("since", windowSelectorToSinceIso(eventsWindowSelect.value));
  }
  try {
    eventsCache = await api(`/api/v1/audit-events?${params.toString()}`);
    refreshEventsView();
  } catch (error) {
    tbody.innerHTML = "";
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 7;
    td.className = "events-empty";
    td.textContent = String(error.message || error);
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
}

function refreshEventsView() {
  const rows = applyEventsFilters(eventsCache);
  renderEventsKpis(eventsCache);  // KPIs over the unfiltered set
  renderEventsTable(rows);
}

// Tool-name substring + decision come from advanced filters; the
// active pill maps to a coarser class predicate (event-class + risk).
function applyEventsFilters(rows) {
  const toolNeedle = (auditToolFilter.value || "").trim().toLowerCase();
  const decisionNeedle = auditDecisionFilter.value;
  const pill = eventsPillState.current;
  return rows.filter((ev) => {
    if (toolNeedle && !String(ev.tool || "").toLowerCase().includes(toolNeedle)) {
      return false;
    }
    if (decisionNeedle && ev.decision !== decisionNeedle) return false;
    if (pill === "unsanctioned") {
      return ev.event_type === "access_attempt";
    }
    if (pill === "blocked") {
      return ev.decision === "deny" || ev.event_type === "access_attempt";
    }
    if (pill === "high_risk") {
      return classifyEventRisk(ev) === "high";
    }
    if (pill === "redacted") {
      return ev.decision === "redact" || ev.decision === "rewrite";
    }
    return true;
  });
}

// Map a single event to (low | medium | high). Heuristic: an
// unsanctioned access attempt is high; an explicit deny is high; a
// redact/rewrite is medium; allow is low. Refined when richer
// risk_category lands on tool_call events.
function classifyEventRisk(ev) {
  if (ev.event_type === "access_attempt") return "high";
  if (ev.decision === "deny") return "high";
  if (ev.decision === "redact" || ev.decision === "rewrite") return "medium";
  return "low";
}

// Walk the cached rows and update the four KPI numbers in place.
// Window is "everything in the buffer" — operator can dial limit
// down/up to widen or narrow the window.
function renderEventsKpis(rows) {
  let toolCalls = 0;
  let blocked = 0;
  let unsanctioned = 0;
  const identities = new Set();
  const servers = new Set();
  const dayAgo = Date.now() - 24 * 60 * 60 * 1000;
  for (const ev of rows) {
    const t = Date.parse(ev.timestamp);
    if (ev.event_type === "tool_call" && t >= dayAgo) toolCalls++;
    if (ev.decision === "deny") blocked++;
    if (ev.event_type === "access_attempt") unsanctioned++;
    if (ev.principal && ev.principal.id) {
      identities.add(`${ev.principal.type}:${ev.principal.id}`);
    }
    if (ev.upstream_server_id) servers.add(ev.upstream_server_id);
  }
  document.querySelector("#events-kpi-tool-calls").textContent = toolCalls.toLocaleString();
  document.querySelector("#events-kpi-blocked").textContent = blocked.toLocaleString();
  document.querySelector("#events-kpi-unsanctioned").textContent = unsanctioned.toLocaleString();
  document.querySelector("#events-kpi-identities").textContent = identities.size.toLocaleString();
  const serverEl = document.querySelector("[data-events-server-count]");
  if (serverEl) serverEl.textContent = servers.size;
}

function renderEventsTable(rows) {
  const tbody = document.querySelector("#audit-events-output");
  tbody.innerHTML = "";
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 7;
    td.className = "events-empty";
    td.textContent = eventsCache.length === 0
      ? "No events recorded yet — fire a tool call and click Refresh."
      : `(0 of ${eventsCache.length} events match the active filter)`;
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const ev of rows) {
    tbody.appendChild(renderEventRow(ev));
  }
}

// Class label drives the row's left-border colour cue (red for
// unsanctioned, muted-red for blocked, none for allowed).
function eventClassFor(ev) {
  if (ev.event_type === "access_attempt") return "unsanctioned";
  if (ev.decision === "deny") return "blocked";
  if (ev.decision === "redact" || ev.decision === "rewrite") return "redacted";
  return "allowed";
}

function renderEventRow(ev) {
  const tr = document.createElement("tr");
  tr.dataset.eventClass = eventClassFor(ev);

  // TIME — HH:MM:SS only (date is implicit "recent" for ring buffer).
  const timeCell = document.createElement("td");
  timeCell.className = "events-row-time";
  const ts = new Date(ev.timestamp);
  timeCell.textContent = ts.toLocaleTimeString(undefined, {
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  });
  tr.appendChild(timeCell);

  // IDENTITY — type badge + display name (or principal id prefix).
  const identityCell = document.createElement("td");
  const idWrap = document.createElement("div");
  idWrap.className = "events-row-identity";
  const idLine = document.createElement("span");
  idLine.className = "events-row-identity-name";
  const badge = document.createElement("span");
  badge.className = "events-identity-badge";
  badge.dataset.type = ev.principal.type;
  badge.textContent = labelForIdentityType(ev.principal.type);
  idLine.appendChild(badge);
  // Prefer display name; fall back to id (truncated for long API keys).
  const displayName = ev.principal.display
    || (ev.principal.id.length > 20
        ? ev.principal.id.slice(0, 18) + "…"
        : ev.principal.id);
  idLine.appendChild(document.createTextNode(displayName));
  idWrap.appendChild(idLine);
  if (ev.principal.display && ev.principal.id) {
    const sub = document.createElement("span");
    sub.className = "events-meta-line";
    sub.style.fontSize = "10.5px";
    sub.style.color = "var(--vyuu-muted)";
    sub.textContent = ev.principal.id.length > 32
      ? ev.principal.id.slice(0, 30) + "…"
      : ev.principal.id;
    idWrap.appendChild(sub);
  }
  identityCell.appendChild(idWrap);
  tr.appendChild(identityCell);

  // SERVER · TOOL — vserver name (kbd-styled) plus tool. For access
  // attempts we don't have a tool, so show "<connect>". Name
  // resolution: prefer the audit-stamped `vserver_name` (set on
  // access_attempt), fall back to the client-side
  // vserver_id → name map (populated from /api/v1/vservers), fall
  // back to the UUID prefix for vservers that no longer exist (e.g.
  // a row whose vserver was deleted between event capture and view).
  const targetCell = document.createElement("td");
  const targetWrap = document.createElement("div");
  targetWrap.className = "events-row-target";
  const headLine = document.createElement("div");
  const vserverName = ev.vserver_name
    || (ev.vserver_id && vserverNameById.get(ev.vserver_id))
    || (ev.vserver_id ? ev.vserver_id.slice(0, 8) + "…" : "—");
  const vsSpan = document.createElement("span");
  vsSpan.className = "events-vserver";
  vsSpan.textContent = vserverName;
  headLine.appendChild(vsSpan);
  if (ev.tool) {
    headLine.appendChild(document.createTextNode(" · "));
    const toolCode = document.createElement("code");
    toolCode.textContent = ev.tool;
    headLine.appendChild(toolCode);
  }
  targetWrap.appendChild(headLine);
  // Latency / upstream meta on second line for tool_call events
  if (ev.event_type === "tool_call" && ev.latency_ms_total != null) {
    const meta = document.createElement("div");
    meta.className = "events-meta-line";
    const total = `${ev.latency_ms_total.toFixed(0)}ms`;
    const up = ev.latency_ms_upstream != null
      ? ` · upstream ${ev.latency_ms_upstream.toFixed(0)}ms`
      : "";
    meta.textContent = `${total}${up}`;
    targetWrap.appendChild(meta);
  }
  targetCell.appendChild(targetWrap);
  tr.appendChild(targetCell);

  // ARGS — first key=value pair compacted, full JSON in title attr.
  const argsCell = document.createElement("td");
  argsCell.className = "events-row-args";
  const summary = ev.args_summary || {};
  argsCell.textContent = formatArgsSummary(summary);
  argsCell.title = JSON.stringify(summary, null, 2);
  tr.appendChild(argsCell);

  // RISK
  const riskCell = document.createElement("td");
  const riskPill = document.createElement("span");
  const risk = classifyEventRisk(ev);
  riskPill.className = "events-risk-pill";
  riskPill.dataset.risk = risk;
  riskPill.textContent = risk;
  riskCell.appendChild(riskPill);
  tr.appendChild(riskCell);

  // REASON — outcome word + short explanation.
  const reasonCell = document.createElement("td");
  const reasonWrap = document.createElement("div");
  reasonWrap.className = "events-row-reason";
  const outcome = document.createElement("span");
  outcome.className = "events-row-reason-outcome";
  const detail = document.createElement("span");
  detail.className = "events-row-reason-detail";
  if (ev.event_type === "access_attempt") {
    outcome.dataset.outcome = "unsanctioned";
    outcome.textContent = "Unsanctioned";
    detail.textContent = labelForAuthFailure(ev.auth_failure_reason || "auth_failure");
  } else if (ev.decision === "deny") {
    outcome.dataset.outcome = "blocked";
    outcome.textContent = "Blocked";
    detail.textContent = ev.policy_rule_id
      ? `Policy: ${ev.policy_rule_id}`
      : "Policy denial";
  } else if (ev.decision === "redact") {
    outcome.dataset.outcome = "redacted";
    outcome.textContent = "Redacted";
    detail.textContent = "PII / sensitive content masked";
  } else if (ev.decision === "rewrite") {
    outcome.dataset.outcome = "redacted";
    outcome.textContent = "Rewritten";
    detail.textContent = "Args rewritten by policy";
  } else {
    outcome.dataset.outcome = "allowed";
    outcome.textContent = "Allowed";
    detail.textContent = ev.upstream_status === "ok"
      ? "Upstream OK"
      : `Upstream: ${ev.upstream_status || "—"}`;
  }
  reasonWrap.appendChild(outcome);
  reasonWrap.appendChild(detail);
  reasonCell.appendChild(reasonWrap);
  tr.appendChild(reasonCell);

  return tr;
}

function labelForIdentityType(t) {
  switch (String(t)) {
    case "endpoint_session": return "Endpoint session";
    case "api_key":          return "User token";
    case "server_agent":     return "Service agent";
    default:                 return String(t);
  }
}

// Pretty-print the MCP client interface for the "via" column. Falls
// back through clientInfo → user_agent → "—". `clientInfo` (when sent)
// is the protocol-level signal; `user_agent` catches lazy clients
// (raw httpx, mcp-remote shims) that don't fill in `clientInfo`.
function formatClientInterface(row) {
  const name = row.latest_client_name;
  const version = row.latest_client_version;
  if (name) {
    const pretty = prettifyClientName(name);
    return version ? `${pretty} ${version}` : pretty;
  }
  const ua = row.latest_user_agent;
  if (ua) {
    // Most UAs are noisy ("Mozilla/5.0 (...)"). Show the first token —
    // operators can hover the cell for the full UA via title attr.
    const first = String(ua).split(/[\\s/]/)[0] || ua;
    return first.length > 24 ? first.slice(0, 22) + "…" : first;
  }
  return null;
}

function prettifyClientName(name) {
  // Map known MCP client identifiers to display labels. Everything
  // else passes through with first-letter capitalised.
  const lookup = {
    "cursor": "Cursor",
    "cursor-mcp": "Cursor",
    "claude-ai": "Claude Desktop",
    "claude": "Claude Desktop",
    "claude-desktop": "Claude Desktop",
    "mcp-remote": "mcp-remote",
    "vscode": "VS Code",
    "windsurf": "Windsurf",
    "continue": "Continue",
    "zed": "Zed",
  };
  const key = String(name).toLowerCase();
  if (lookup[key]) return lookup[key];
  return name.charAt(0).toUpperCase() + name.slice(1);
}

function formatArgsSummary(summary) {
  const fields = summary && summary.fields;
  if (!fields || typeof fields !== "object") return "—";
  const pairs = [];
  for (const [k, v] of Object.entries(fields)) {
    let valStr = "";
    if (v && typeof v === "object" && "type" in v) {
      valStr = v.type;
      if ("size" in v) valStr += `(${v.size})`;
    } else {
      valStr = String(v);
    }
    pairs.push(`${k}=${valStr}`);
  }
  return pairs.length ? pairs.join(", ") : "—";
}

// Filter button toggles the advanced-filter dropdown row.
{
  const filterBtn = document.querySelector("#events-filter-toggle");
  const filterPanel = document.querySelector("#events-advanced-filters");
  if (filterBtn && filterPanel) {
    filterBtn.addEventListener("click", () => {
      const expanded = filterBtn.getAttribute("aria-expanded") === "true";
      filterBtn.setAttribute("aria-expanded", expanded ? "false" : "true");
      filterPanel.hidden = expanded;
    });
  }
}

// Pill row — drives the coarse event-class filter.
for (const pill of document.querySelectorAll("[data-events-pill]")) {
  pill.addEventListener("click", () => {
    eventsPillState.current = pill.dataset.eventsPill;
    for (const p of document.querySelectorAll("[data-events-pill]")) {
      p.classList.toggle("is-active", p === pill);
    }
    refreshEventsView();
  });
}

// Export — download the filtered events as JSON. Operators can pipe
// to jq / pivot in spreadsheets / attach to an incident ticket.
{
  const exportBtn = document.querySelector("#events-export");
  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      const rows = applyEventsFilters(eventsCache);
      const blob = new Blob(
        [JSON.stringify(rows, null, 2)],
        { type: "application/json" },
      );
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const ts = new Date().toISOString().replace(/[:.]/g, "-");
      a.download = `vyuu-events-${ts}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  }
}

function pillForDecision(decision) {
  switch (String(decision)) {
    case "allow": return "pill pill-orange";
    case "deny": return "pill pill-danger";
    case "redact": return "pill pill-warn";
    case "rewrite": return "pill pill-info";
    default: return "pill pill-neutral";
  }
}

function labelForAuthFailure(reason) {
  switch (String(reason)) {
    case "invalid_bearer":     return "invalid bearer";
    case "vserver_not_found":  return "vserver not found";
    case "no_grant":           return "no grant";
    case "disabled_principal": return "principal disabled";
    default:                   return reason;
  }
}

function pillForUpstreamStatus(status) {
  switch (String(status)) {
    case "ok": return "pill pill-orange";
    case "error": return "pill pill-danger";
    case "timeout": return "pill pill-warn";
    case "not_called": return "pill pill-neutral";
    default: return "pill pill-neutral";
  }
}

function renderRawCaptureBlock(label, payload, truncated) {
  // Renders a collapsible block with pretty-printed JSON + a Copy
  // button per block. Used for both H5 raw_args and raw_response.
  const block = document.createElement("details");
  block.style.marginTop = "8px";
  block.open = true;
  const truncBadge = truncated
    ? ' <span class="pill pill-warn">truncated</span>' : "";
  const summary = document.createElement("summary");
  summary.style.cursor = "pointer";
  summary.style.fontSize = "0.85rem";
  summary.innerHTML = `${escapeHtmlOp(label)} (policy opt-in)${truncBadge}`;
  block.appendChild(summary);

  const pretty = JSON.stringify(payload, null, 2);
  const pre = document.createElement("pre");
  pre.className = "output";
  pre.style.marginTop = "8px";
  pre.textContent = pretty;
  block.appendChild(pre);

  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.className = "ghost";
  copyBtn.textContent = "Copy";
  copyBtn.style.marginTop = "4px";
  copyBtn.addEventListener("click", () => {
    navigator.clipboard.writeText(pretty).then(
      () => {
        copyBtn.textContent = "Copied!";
        setTimeout(() => { copyBtn.textContent = "Copy"; }, 1200);
      },
      () => { copyBtn.textContent = "Copy failed"; },
    );
  });
  block.appendChild(copyBtn);

  return block;
}

function escapeHtmlOp(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
// Alias — historically called both `escapeHtml` (15+ sites in
// identities / connections / api-keys renderers) and `escapeHtmlOp`
// (5 sites in publish-drawer / events). Without this alias the
// Identities tab hits `ReferenceError: escapeHtml is not defined`
// and the whole panel crashes. Same semantics either way.
const escapeHtml = escapeHtmlOp;


// =========================================================================
// OAuth provider preset catalog + info-button side popovers (Register form)
// =========================================================================
// The biggest pain point of registering an MCP with auth_authcode /
// auth_jwt_bearer is "what URLs / scopes do Google / GitHub / Slack
// actually expect?". The presets below carry the canonical values so an
// operator clicks the `i` next to the field, picks the provider, and the
// JSON pre-fills with the right shape — only client_id_ref + secret ref
// remain to be entered.
//
// Refs use the convention `<provider>-<role>` so operators can seed the
// SecretStore with matching keys; rename in-place if your environment
// mandates different names.

const OAUTH_PROVIDER_PRESETS = [
  // Each `authcode` entry produces a JSON shape that matches the
  // auth_authcode column 1:1. `extra_authorize_params` is included
  // where the IdP needs it (Google's `access_type=offline` is critical
  // — without it, no refresh tokens are issued and access tokens
  // expire after 1 hour).
  {
    id: "github",
    label: "GitHub",
    hint: "OAuth user-delegated · per-user PATs replaced",
    authcode: {
      auth_url: "https://github.com/login/oauth/authorize",
      token_url: "https://github.com/login/oauth/access_token",
      client_id_ref: "github-client-id",
      client_secret_ref: "github-client-secret",
      scopes: ["read:user", "repo"],
      redirect_uri:
        "http://localhost:8000/api/v1/oauth-authcode/callback",
    },
  },
  {
    id: "google_drive",
    label: "Google Drive",
    hint: "Per-user delegated · access_type=offline",
    authcode: {
      auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
      token_url: "https://oauth2.googleapis.com/token",
      client_id_ref: "google-client-id",
      client_secret_ref: "google-client-secret",
      scopes: ["https://www.googleapis.com/auth/drive.readonly"],
      redirect_uri:
        "http://localhost:8000/api/v1/oauth-authcode/callback",
      extra_authorize_params: {
        access_type: "offline",
        prompt: "consent",
      },
    },
    jwt_bearer: {
      // Google Workspace SAs use this path — operator supplies the SA
      // private key as `private_key_ref` and a domain user as `subject`.
      token_url: "https://oauth2.googleapis.com/token",
      algorithm: "RS256",
      private_key_ref: "google-sa-private-key",
      issuer: "vyuu-sa@your-project.iam.gserviceaccount.com",
      subject: "alice@your-corp.example",
      audience: "https://oauth2.googleapis.com/token",
      additional_claims: {
        scope: "https://www.googleapis.com/auth/drive.readonly",
      },
    },
  },
  {
    id: "slack",
    label: "Slack",
    hint: "OAuth v2 · workspace install + bot scopes",
    authcode: {
      auth_url: "https://slack.com/oauth/v2/authorize",
      token_url: "https://slack.com/api/oauth.v2.access",
      client_id_ref: "slack-client-id",
      client_secret_ref: "slack-client-secret",
      scopes: ["chat:write", "channels:read", "users:read"],
      redirect_uri:
        "http://localhost:8000/api/v1/oauth-authcode/callback",
    },
  },
  {
    id: "notion",
    label: "Notion",
    hint: "OAuth · per-workspace consent",
    authcode: {
      auth_url: "https://api.notion.com/v1/oauth/authorize",
      token_url: "https://api.notion.com/v1/oauth/token",
      client_id_ref: "notion-client-id",
      client_secret_ref: "notion-client-secret",
      scopes: [],
      redirect_uri:
        "http://localhost:8000/api/v1/oauth-authcode/callback",
    },
  },
  {
    id: "microsoft_graph",
    label: "Microsoft Graph",
    hint: "Entra ID · v2 endpoint · /common authority",
    authcode: {
      auth_url:
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
      token_url:
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
      client_id_ref: "microsoft-client-id",
      client_secret_ref: "microsoft-client-secret",
      scopes: [
        "User.Read",
        "Files.Read",
        "offline_access",
      ],
      redirect_uri:
        "http://localhost:8000/api/v1/oauth-authcode/callback",
    },
  },
  {
    id: "atlassian",
    label: "Atlassian (Jira / Confluence)",
    hint: "OAuth 2.0 (3LO) · audience = api.atlassian.com",
    authcode: {
      auth_url: "https://auth.atlassian.com/authorize",
      token_url: "https://auth.atlassian.com/oauth/token",
      client_id_ref: "atlassian-client-id",
      client_secret_ref: "atlassian-client-secret",
      scopes: ["read:jira-work", "offline_access"],
      redirect_uri:
        "http://localhost:8000/api/v1/oauth-authcode/callback",
      extra_authorize_params: {
        audience: "api.atlassian.com",
        prompt: "consent",
      },
    },
  },
];

// Static body copy for each info-button. Plain English, no jargon — the
// goal is to translate "what does this field even mean?" so the operator
// doesn't bounce to docs.
const INFO_BUTTON_COPY = {
  "auth-oauth-cc": {
    title: "OAuth M2M (client_credentials)",
    body:
      "One credential the gateway owns calls the upstream on behalf of "
      + "all users. Use for SaaS that issues an org-wide service "
      + "credential (Auth0/Okta-fronted internal services, some "
      + "vendor M2M flows). Distinct from per-user OAuth (authcode) "
      + "below — that's the right tool for &lsquo;Connect to GitHub&rsquo; UX.",
    presetField: null,  // No common presets for M2M; vendor-specific.
  },
  "auth-authcode": {
    title: "OAuth user-delegated (authcode + PKCE)",
    body:
      "Each user grants the gateway access to their own account at the "
      + "SaaS provider. The gateway stores a refresh token per "
      + "(tenant, user, server) and rides the user&rsquo;s access token "
      + "on every upstream call. This is the &ldquo;Connect to GitHub / "
      + "Drive / Notion&rdquo; pattern. Pick a provider below to "
      + "pre-fill the URLs + scopes.",
    presetField: "auth_authcode",
  },
  "auth-jwt-bearer": {
    title: "JWT-bearer assertion (RFC 7523)",
    body:
      "The gateway signs a short-lived JWT with a configured private "
      + "key and exchanges it for a bearer token. Used by Workspace "
      + "service accounts (Drive / Calendar / Gmail) and AWS IAM Roles "
      + "Anywhere. For Workspace, set <code>subject</code> to the user "
      + "you&rsquo;re impersonating; for AWS IRA, the subject is the "
      + "trust anchor.",
    presetField: "auth_jwt_bearer",
  },
  "mtls": {
    title: "mTLS — transport-layer client cert",
    body:
      "Internal corporate APIs that demand mutual TLS at the connection "
      + "layer. Both <code>mtls_cert_ref</code> and <code>mtls_key_ref</code> "
      + "must be set together — they point at PEM-encoded blobs in the "
      + "SecretStore. Coexists freely with any application-layer auth "
      + "mode (headers / OAuth / JWT-bearer).",
    presetField: null,
  },
};

document.addEventListener("click", (event) => {
  const btn = event.target.closest && event.target.closest(".info-btn");
  if (btn) {
    event.preventDefault();
    toggleInfoPopover(btn);
    return;
  }
  // Click outside any open popover closes it.
  const open = document.querySelector(".info-popover.open");
  if (open && !event.target.closest(".info-popover")) {
    if (open._cleanup) open._cleanup();
    open.classList.remove("open");
    open.remove();
  }
});

// Fill the structured per-mode fields from a provider preset config
// dict. Auto-flips the auth-mode picker so the operator immediately
// sees the populated form. `presetField` is the JSON-shape name
// ("auth_authcode" / "auth_jwt_bearer") which we map to the matching
// `data-auth-*` selector prefix.
function applyPresetToStructuredFields(presetField, cfg) {
  const scope = presetField === "auth_authcode" ? "authcode"
              : presetField === "auth_jwt_bearer" ? "jwt"
              : null;
  if (!scope) return;

  // Flip mode picker first so the relevant fields are visible.
  const modeRadio = registerForm.querySelector(
    `input[name="auth_mode"][value="${
      scope === "authcode" ? "authcode" : "jwt_bearer"
    }"]`);
  if (modeRadio) {
    modeRadio.checked = true;
    document.body.dataset.authMode = modeRadio.value;
  }

  // Walk the cfg shape and write each value into its matching
  // data-auth-<scope> input. Special-case the array + object fields
  // so they go in as their wire-friendly text representations.
  for (const [key, value] of Object.entries(cfg)) {
    const input = registerForm.querySelector(
      `[data-auth-${scope}="${key}"]`);
    if (!input) continue;
    let textValue;
    if (Array.isArray(value)) textValue = value.join(", ");
    else if (typeof value === "object" && value !== null)
      textValue = JSON.stringify(value);
    else textValue = String(value);
    input.value = textValue;
    input.classList.add("flash-ok");
    setTimeout(() => input.classList.remove("flash-ok"), 800);
  }

  // Scroll the auth section into view so the operator confirms.
  registerForm.querySelector(".auth-section")?.scrollIntoView({
    block: "start", behavior: "smooth",
  });
}

function toggleInfoPopover(btn) {
  const existing = document.querySelector(".info-popover.open");
  if (existing) {
    const wasOwn = existing.dataset.owner === btn.dataset.info;
    if (existing._cleanup) existing._cleanup();
    existing.classList.remove("open");
    existing.remove();
    if (wasOwn) return;  // toggle off
  }
  const key = btn.dataset.info;
  const copy = INFO_BUTTON_COPY[key];
  if (!copy) return;

  const pop = document.createElement("div");
  pop.className = "info-popover open";
  pop.dataset.owner = key;

  const title = document.createElement("div");
  title.className = "info-popover-title";
  title.textContent = copy.title;
  pop.appendChild(title);

  const body = document.createElement("div");
  body.className = "info-popover-body";
  // copy.body is trusted authored content (not user input) — innerHTML
  // is acceptable here for the tiny embedded `<code>` inside.
  body.innerHTML = copy.body;
  pop.appendChild(body);

  if (copy.presetField) {
    const sep = document.createElement("div");
    sep.className = "info-popover-eyebrow";
    sep.textContent = "QUICK FILL — PROVIDERS";
    pop.appendChild(sep);

    for (const preset of OAUTH_PROVIDER_PRESETS) {
      const cfg = key === "auth-jwt-bearer"
        ? preset.jwt_bearer
        : preset.authcode;
      if (!cfg) continue;
      const row = document.createElement("button");
      row.type = "button";
      row.className = "preset-btn";
      row.innerHTML = `
        <span class="preset-label">${escapeHtmlOp(preset.label)}</span>
        <span class="preset-hint">${escapeHtmlOp(preset.hint)}</span>`;
      row.addEventListener("click", () => {
        applyPresetToStructuredFields(copy.presetField, cfg);
        if (pop._cleanup) pop._cleanup();
        pop.classList.remove("open");
        pop.remove();
      });
      pop.appendChild(row);
    }
  }

  // Anchor to the trigger, centred under it, clamped inside the
  // viewport, flipped above when there is no room below.
  //
  // The previous rule was `left = rect.left - 280`: a fixed shift that
  // put the panel to the LEFT of a button sitting at the panel's right
  // edge, so it pointed at nothing and covered the field it explained.
  // It also never checked either viewport edge.
  pop.style.position = "absolute";
  pop.style.visibility = "hidden";
  document.body.appendChild(pop);

  const place = () => {
    const rect = btn.getBoundingClientRect();
    const popW = pop.offsetWidth;
    const popH = pop.offsetHeight;
    const margin = 12;
    const gap = 10;

    const roomBelow = window.innerHeight - rect.bottom;
    const below = roomBelow >= popH + gap || roomBelow >= rect.top;
    pop.dataset.place = below ? "below" : "above";
    pop.style.top = below
      ? `${window.scrollY + rect.bottom + gap}px`
      : `${window.scrollY + rect.top - popH - gap}px`;

    const centre = rect.left + rect.width / 2;
    const maxLeft = window.innerWidth - popW - margin;
    const left = Math.min(Math.max(centre - popW / 2, margin), Math.max(margin, maxLeft));
    pop.style.left = `${window.scrollX + left}px`;

    // Keep the caret on the trigger even after the panel is clamped,
    // inset far enough that it never overlaps the rounded corner.
    const arrowX = Math.min(Math.max(centre - left, 18), Math.max(18, popW - 18));
    pop.style.setProperty("--info-arrow-x", `${arrowX - 8}px`);
    pop.style.visibility = "visible";
  };

  place();
  // An absolutely-positioned panel detaches from its trigger the moment
  // anything scrolls, so follow the scroll rather than leave it stranded.
  const reposition = () => {
    if (!pop.isConnected) return;
    place();
  };
  window.addEventListener("scroll", reposition, true);
  window.addEventListener("resize", reposition);
  pop._cleanup = () => {
    window.removeEventListener("scroll", reposition, true);
    window.removeEventListener("resize", reposition);
  };
}


// =========================================================================
// Secret store panel — read-only view of the configured backend
// =========================================================================

const secretStoreOutput = document.querySelector("#secret-store-output");
document.querySelector("#refresh-secret-store").addEventListener("click", loadSecretStoreStatus);

async function loadSecretStoreStatus() {
  secretStoreOutput.textContent = "Loading…";
  try {
    const status = await api("/api/v1/secret-store/status");
    secretStoreOutput.replaceChildren(renderSecretStoreCard(status));
  } catch (error) {
    renderError(secretStoreOutput, error);
  }
}

function renderSecretStoreCard(status) {
  const card = document.createElement("article");
  card.className = "server-card";

  const title = document.createElement("strong");
  const healthPill = status.healthy
    ? '<span class="pill pill-orange">healthy</span>'
    : '<span class="pill pill-danger">unhealthy</span>';
  title.innerHTML = `Active backend: <code>${escapeHtmlOp(status.backend)}</code> ${healthPill}`;
  card.appendChild(title);

  const recommended = document.createElement("p");
  recommended.className = "meta";
  recommended.style.marginTop = "6px";
  recommended.textContent = `Recommended for: ${status.recommended_for}`;
  card.appendChild(recommended);

  const detail = document.createElement("p");
  detail.className = "meta";
  detail.style.marginTop = "4px";
  detail.textContent = `Health probe: ${status.health_detail}`;
  card.appendChild(detail);

  const switchHeader = document.createElement("p");
  switchHeader.style.marginTop = "12px";
  switchHeader.innerHTML = "<strong>Switch backend (deploy-time)</strong>";
  card.appendChild(switchHeader);

  const note = document.createElement("p");
  note.className = "meta";
  note.textContent =
    "The backend is a deployment-time choice — set env vars on the" +
    " gateway pod and restart.";
  card.appendChild(note);

  for (const [otherBackend, envVars] of Object.entries(status.switch_instructions || {})) {
    const block = document.createElement("details");
    block.style.marginTop = "8px";
    block.innerHTML = `
      <summary style="cursor: pointer; font-size: 0.85rem;">
        Switch to <code>${escapeHtmlOp(otherBackend)}</code>
      </summary>
      <pre class="output" style="margin-top: 6px;"></pre>`;
    block.querySelector("pre").textContent = envVars.join("\\n");
    card.appendChild(block);
  }

  return card;
}

// =========================================================================
// Identity providers panel (IDP-1 Phase 5a)
// =========================================================================
//
// Lists connected Entra / Workspace directories, opens a connect-wizard
// modal for new ones, drills into one for endpoint URLs + disconnect.
// The "+ Connect" submit reveals the SCIM bearer plaintext exactly
// once — we never show it again, since the hash is what survives.

const idpDirectoriesOutput = document.querySelector("#idp-directories-output");
const idpCount = document.querySelector("#idp-count");
let idpDirectoriesCache = [];
const idpPillState = { current: "all" };

if (document.querySelector("#refresh-idp-directories")) {
  document.querySelector("#refresh-idp-directories")
    .addEventListener("click", loadIdpDirectories);
}
for (const pill of document.querySelectorAll("[data-idp-pill]")) {
  pill.addEventListener("click", () => {
    idpPillState.current = pill.dataset.idpPill;
    for (const p of document.querySelectorAll("[data-idp-pill]")) {
      p.classList.toggle("is-active", p === pill);
    }
    renderIdpDirectories();
  });
}

// IDP-3 · the tenant's own sign-in hostname.
//
// Hidden entirely when the deployment has no base domain configured
// (`portal_url` comes back null), because offering to set a subdomain on
// a gateway that cannot route one would be a promise we do not keep.
async function loadTenantSlug() {
  const strip = document.querySelector("#tenant-slug-strip");
  if (!strip) return;
  let settings;
  try {
    settings = await api("/api/v1/tenant/settings");
  } catch {
    strip.classList.add("is-hidden");
    return;
  }
  // `slug` set but `portal_url` null means the slug exists and the
  // deployment cannot serve it — worth showing, because that mismatch is
  // invisible otherwise.
  const configured = settings.portal_url !== null || settings.slug !== null;
  strip.classList.toggle("is-hidden", !configured);
  if (!configured) return;

  document.querySelector("#tenant-slug-url").textContent =
    settings.portal_url ||
    `(slug "${settings.slug}" set, but this gateway has no base domain)`;
  document.querySelector("#tenant-slug-sub").textContent = settings.slug
    ? "your team signs in here — no tenant ID to paste"
    : "not set; your team must paste the tenant ID to sign in";
  document.querySelector("#edit-tenant-slug").textContent =
    settings.slug ? "Change" : "Set";
}

async function editTenantSlug() {
  let current = null;
  try {
    current = (await api("/api/v1/tenant/settings")).slug;
  } catch (error) { alert(String(error)); return; }

  const answer = prompt(
    `Sign-in subdomain for your tenant.` + "\\n" + "\\n" +
    `Lowercase letters, digits and hyphens (it becomes a DNS label).` + "\\n" +
    `Leave EMPTY to clear it and go back to pasting the tenant ID.` + "\\n\\n" +
    `Changing it breaks existing bookmarks and any IdP redirect URI ` +
    `pointing at the old hostname.`,
    current || "",
  );
  if (answer === null) return;
  const slug = answer.trim() || null;

  try {
    await api("/api/v1/tenant/settings/slug", {
      method: "PATCH",
      body: JSON.stringify({ slug }),
    });
    await loadTenantSlug();
  } catch (error) { alert(String(error)); }
}

const _editTenantSlugBtn = document.querySelector("#edit-tenant-slug");
if (_editTenantSlugBtn) {
  _editTenantSlugBtn.addEventListener("click", editTenantSlug);
}

async function loadIdpDirectories() {
  loadTenantSlug();
  if (!idpDirectoriesOutput) return;
  idpDirectoriesOutput.innerHTML =
    '<tr><td colspan="5" class="events-empty">Loading…</td></tr>';
  try {
    idpDirectoriesCache = await api("/api/v1/idp/directories");
    renderIdpDirectories();
  } catch (error) {
    idpDirectoriesOutput.innerHTML = "";
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "events-empty";
    td.textContent = String(error.message || error);
    tr.appendChild(td);
    idpDirectoriesOutput.appendChild(tr);
  }
}

// IDP-2 · Google Workspace directory polling.
//
// The consequence is stated up front rather than buried: an operator
// turning this OFF is choosing manual deprovisioning, and the failure
// mode (a terminated user keeping access) is invisible until someone
// audits.
async function configureWorkspacePolling(directory, button) {
  if (directory.workspace_polling_enabled) {
    if (confirm(
      `Stop polling "${directory.display_name}"?\n\n` +
      `Workspace custom SAML apps cannot push SCIM, so nothing will ` +
      `deprovision automatically. A user terminated in Google keeps ` +
      `their gateway access until someone disables them by hand.\n\n` +
      `OK = stop polling. Cancel = keep polling and edit the settings.`
    )) {
      try {
        await api(
          `/api/v1/idp/directories/${encodeURIComponent(directory.id)}/workspace-polling`,
          { method: "PATCH", body: JSON.stringify({ enabled: false }) },
        );
        await loadIdpDirectories();
      } catch (error) { alert(String(error)); }
      return;
    }
  }

  const customer = prompt(
    `Google customer ID for "${directory.display_name}"\n\n` +
    `Use "my_customer" for your own tenant, or the C0xxxxxxx id.\n` +
    `Required — without it a reseller service account would enumerate ` +
    `other customers' directories.`,
    directory.workspace_customer_id || "my_customer",
  );
  if (customer === null) return;

  const admin = prompt(
    `Delegated admin email\n\n` +
    `Domain-wide delegation impersonates a real admin; Google refuses ` +
    `the call without one.`,
    directory.workspace_admin_subject || "",
  );
  if (admin === null) return;

  const ref = prompt(
    `Secret-store REFERENCE for the service-account JSON\n\n` +
    `A key in your configured secret store — not the JSON itself. That ` +
    `credential can read every user in the directory, so it never goes ` +
    `in the database.`,
    directory.workspace_service_account_ref || "",
  );
  if (ref === null) return;

  try {
    await api(
      `/api/v1/idp/directories/${encodeURIComponent(directory.id)}/workspace-polling`,
      {
        method: "PATCH",
        body: JSON.stringify({
          enabled: true,
          customer_id: customer.trim(),
          admin_subject: admin.trim(),
          service_account_ref: ref.trim(),
        }),
      },
    );
    await loadIdpDirectories();
  } catch (error) { alert(String(error)); }
}

function renderIdpDirectories() {
  if (!idpDirectoriesOutput) return;
  renderIdpKpis(idpDirectoriesCache);

  const pill = idpPillState.current;
  const filtered = idpDirectoriesCache.filter((d) => {
    if (pill === "entra") return d.kind === "entra";
    if (pill === "google_workspace") return d.kind === "google_workspace";
    if (pill === "oidc") return d.signin_protocol === "oidc";
    if (pill === "saml") return d.signin_protocol === "saml";
    return true;
  });

  idpCount.textContent =
    filtered.length === idpDirectoriesCache.length
      ? `${filtered.length} directories`
      : `${filtered.length} of ${idpDirectoriesCache.length} directories`;

  idpDirectoriesOutput.innerHTML = "";
  if (!filtered.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 6;
    td.className = "events-empty";
    td.textContent = idpDirectoriesCache.length === 0
      ? "No directories connected. Click + Connect Entra ID or + Connect Workspace above."
      : `(0 of ${idpDirectoriesCache.length} directories match the active filter)`;
    tr.appendChild(td);
    idpDirectoriesOutput.appendChild(tr);
    return;
  }
  for (const d of filtered) {
    idpDirectoriesOutput.appendChild(renderIdpRow(d));
  }
}

async function toggleIdpEma(directory, button) {
  const turningOn = !directory.ema_enabled;
  const confirmMsg = turningOn
    ? `Enable Enterprise-Managed Authorization for "${directory.display_name}"?\n\n`
      + "Agents will be able to exchange an ID-JAG grant from this "
      + "directory's issuer for a gateway token. Grants, visibility and "
      + "policy still apply on every call."
    : `Disable Enterprise-Managed Authorization for "${directory.display_name}"?\n\n`
      + "This revokes every token already issued for this directory "
      + "immediately — agents using it will start failing on their next call.";
  if (!window.confirm(confirmMsg)) return;

  button.disabled = true;
  const previous = button.textContent;
  button.textContent = "…";
  try {
    // `audience` is omitted on purpose: the gateway defaults it to the
    // canonical per-tenant issuer it already advertises via RFC 9728.
    await api(`/api/v1/idp/directories/${encodeURIComponent(directory.id)}/ema`, {
      method: "PATCH",
      body: JSON.stringify({
        enabled: turningOn,
        allowed_client_ids: directory.ema_allowed_client_ids || [],
      }),
    });
    await loadIdpDirectories();
  } catch (error) {
    button.disabled = false;
    button.textContent = previous;
    window.alert(`Could not update EMA: ${error.message || error}`);
  }
}

function renderIdpKpis(rows) {
  let entra = 0;
  let workspace = 0;
  let mostRecent = null;
  for (const d of rows) {
    if (d.kind === "entra") entra++;
    if (d.kind === "google_workspace") workspace++;
    if (d.last_sync_at) {
      const ts = Date.parse(d.last_sync_at);
      if (!Number.isNaN(ts) && (mostRecent === null || ts > mostRecent)) {
        mostRecent = ts;
      }
    }
  }
  const set = (id, v) => {
    const el = document.querySelector(`#${id}`);
    if (el) el.textContent = v;
  };
  set("idp-kpi-total", String(rows.length));
  set("idp-kpi-entra", String(entra));
  set("idp-kpi-workspace", String(workspace));
  if (mostRecent !== null) {
    set("idp-kpi-recent-scim", formatRelativeTime(new Date(mostRecent).toISOString()));
    set("idp-kpi-recent-scim-sub", "latest sync timestamp");
  } else {
    set("idp-kpi-recent-scim", "—");
    set("idp-kpi-recent-scim-sub", "no SCIM traffic yet");
  }
}

function renderIdpRow(directory) {
  const tr = document.createElement("tr");
  tr.addEventListener("click", () => openIdpDrawer(directory));

  // DIRECTORY — kind tag + display name + truncated id
  const dirCell = document.createElement("td");
  const wrap = document.createElement("div");
  wrap.className = "idp-row-directory";
  const line = document.createElement("span");
  line.className = "idp-row-directory-line";
  const kindTag = document.createElement("span");
  kindTag.className = "idp-kind-tag";
  kindTag.dataset.kind = directory.kind;
  kindTag.textContent = directory.kind === "entra" ? "Entra" : "Workspace";
  line.appendChild(kindTag);
  line.appendChild(document.createTextNode(directory.display_name));
  wrap.appendChild(line);
  const idLine = document.createElement("span");
  idLine.className = "idp-row-directory-id";
  idLine.textContent = directory.id.slice(0, 8) + "…";
  wrap.appendChild(idLine);
  dirCell.appendChild(wrap);
  tr.appendChild(dirCell);

  // PROTOCOL — OIDC / SAML
  const protoCell = document.createElement("td");
  const protoTag = document.createElement("span");
  protoTag.className = "idp-protocol-tag";
  protoTag.textContent = directory.signin_protocol.toUpperCase();
  protoCell.appendChild(protoTag);
  tr.appendChild(protoCell);

  // AGENT AUTH (EMA) — Enterprise-Managed Authorization toggle.
  // Off means the gateway ignores ID-JAG grants from this issuer, so
  // connecting a directory for SSO/SCIM never silently starts
  // authorizing agent traffic.
  const emaCell = document.createElement("td");
  const emaWrap = document.createElement("div");
  emaWrap.className = "idp-ema-cell";
  const emaBadge = document.createElement("span");
  emaBadge.className = "idp-ema-badge";
  emaBadge.dataset.on = directory.ema_enabled ? "true" : "false";
  emaBadge.textContent = directory.ema_enabled ? "enabled" : "off";
  emaWrap.appendChild(emaBadge);
  if (directory.ema_enabled && (directory.ema_allowed_client_ids || []).length) {
    const clients = document.createElement("span");
    clients.className = "idp-ema-clients";
    clients.textContent =
      `${directory.ema_allowed_client_ids.length} client(s) allowed`;
    clients.title = directory.ema_allowed_client_ids.join(", ");
    emaWrap.appendChild(clients);
  }
  const emaBtn = document.createElement("button");
  emaBtn.type = "button";
  emaBtn.className = "idp-ema-toggle";
  emaBtn.textContent = directory.ema_enabled ? "Disable" : "Enable";
  emaBtn.addEventListener("click", (event) => {
    event.stopPropagation();          // don't open the row drawer
    toggleIdpEma(directory, emaBtn);
  });
  emaWrap.appendChild(emaBtn);
  emaCell.appendChild(emaWrap);
  tr.appendChild(emaCell);

  // PROVISIONING — was "LAST SCIM", which was actively misleading for
  // Google Workspace. Workspace custom SAML apps CANNOT SCIM-push, so
  // "never" there is the expected state, not a fault — and it silently
  // means deprovisioning is manual. This cell answers the real question
  // ("is this directory actually keeping users in sync?") per kind.
  const syncCell = document.createElement("td");
  syncCell.style.fontSize = "11.5px";
  const isWorkspace = directory.kind === "google_workspace";

  if (!isWorkspace) {
    syncCell.style.color = "var(--vyuu-muted)";
    if (directory.last_sync_at) {
      syncCell.textContent = `SCIM · ${formatRelativeTime(directory.last_sync_at)}`;
      syncCell.title = new Date(directory.last_sync_at).toLocaleString();
    } else {
      syncCell.textContent = "SCIM · never";
      syncCell.title = "No SCIM push received from this directory yet.";
    }
  } else {
    const wrap = document.createElement("div");
    wrap.className = "idp-ema-cell";
    const badge = document.createElement("span");
    badge.className = "idp-ema-badge";
    badge.dataset.on = directory.workspace_polling_enabled ? "true" : "false";
    if (directory.workspace_polling_enabled) {
      badge.textContent = directory.workspace_last_polled_at
        ? `polling · ${formatRelativeTime(directory.workspace_last_polled_at)}`
        : "polling · pending";
      badge.title =
        "The gateway polls this Workspace directory and deactivates " +
        "suspended, archived or removed users automatically.";
    } else {
      badge.textContent = "manual";
      badge.title =
        "Workspace custom SAML apps cannot push SCIM, so nothing " +
        "deprovisions automatically — a terminated user keeps access " +
        "until someone disables them by hand.";
    }
    wrap.appendChild(badge);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "idp-ema-toggle";
    btn.textContent = directory.workspace_polling_enabled ? "Edit" : "Set up";
    btn.addEventListener("click", (event) => {
      event.stopPropagation();
      configureWorkspacePolling(directory, btn);
    });
    wrap.appendChild(btn);
    syncCell.appendChild(wrap);
  }
  tr.appendChild(syncCell);

  // CONNECTED — created_at relative
  const createdCell = document.createElement("td");
  createdCell.style.color = "var(--vyuu-muted)";
  createdCell.style.fontSize = "11.5px";
  createdCell.textContent = formatRelativeTime(directory.created_at);
  createdCell.title = new Date(directory.created_at).toLocaleString();
  tr.appendChild(createdCell);

  // ACTIONS — drill-in
  const actionsCell = document.createElement("td");
  const actions = document.createElement("div");
  actions.className = "users-row-actions";
  const drill = document.createElement("button");
  drill.type = "button";
  drill.textContent = "Drill in →";
  drill.addEventListener("click", (e) => {
    e.stopPropagation();
    openIdpDrawer(directory);
  });
  actions.appendChild(drill);
  actionsCell.appendChild(actions);
  tr.appendChild(actionsCell);

  return tr;
}

// ---------- IdP drawer (slide-over) -----------------------------------
const _idpDrawer = {
  el: () => document.querySelector("#idp-drawer"),
  body: () => document.querySelector("#idp-drawer-body"),
  title: () => document.querySelector("#idp-drawer-title"),
  sub: () => document.querySelector("#idp-drawer-sub"),
  current: null,
  currentTab: "endpoints",
};

function openIdpDrawer(directory) {
  _idpDrawer.current = directory;
  _idpDrawer.title().textContent = directory.display_name;
  _idpDrawer.sub().textContent =
    `${directory.kind === "entra" ? "Entra ID" : "Google Workspace"} · `
    + `${directory.signin_protocol.toUpperCase()} · connected ${formatRelativeTime(directory.created_at)}`;
  _idpDrawer.el().hidden = false;
  document.body.style.overflow = "hidden";
  switchIdpDrawerTab("endpoints");
}

function closeIdpDrawer() {
  _idpDrawer.el().hidden = true;
  _idpDrawer.body().innerHTML = "";
  document.body.style.overflow = "";
}

function switchIdpDrawerTab(tab) {
  _idpDrawer.currentTab = tab;
  for (const t of document.querySelectorAll("[data-idp-drawer-tab]")) {
    t.classList.toggle("is-active", t.dataset.idpDrawerTab === tab);
  }
  const body = _idpDrawer.body();
  body.innerHTML = "";
  const d = _idpDrawer.current;
  if (tab === "endpoints") renderIdpDrawerEndpoints(body, d);
  else if (tab === "connection") renderIdpDrawerConnection(body, d);
  else if (tab === "settings") renderIdpDrawerSettings(body, d);
}

{
  for (const el of document.querySelectorAll("[data-idp-drawer-close]")) {
    el.addEventListener("click", closeIdpDrawer);
  }
  for (const tab of document.querySelectorAll("[data-idp-drawer-tab]")) {
    tab.addEventListener("click", () => switchIdpDrawerTab(tab.dataset.idpDrawerTab));
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !_idpDrawer.el().hidden) closeIdpDrawer();
  });
}

function _idpEndpointRow(label, url) {
  const wrap = document.createElement("div");
  const lbl = document.createElement("p");
  lbl.className = "eyebrow";
  lbl.style.margin = "12px 0 4px";
  lbl.textContent = label;
  wrap.appendChild(lbl);
  const row = document.createElement("div");
  row.className = "idp-endpoint-row";
  const code = document.createElement("code");
  code.textContent = url;
  code.title = url;
  row.appendChild(code);
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "vservers-row-url-copy";
  copy.textContent = "Copy";
  copy.addEventListener("click", () => {
    navigator.clipboard.writeText(url).then(
      () => {
        copy.textContent = "Copied";
        setTimeout(() => { copy.textContent = "Copy"; }, 1200);
      },
      () => { copy.textContent = "Failed"; },
    );
  });
  row.appendChild(copy);
  wrap.appendChild(row);
  return wrap;
}

function renderIdpDrawerEndpoints(container, directory) {
  const origin = window.location.origin;
  // Workspace custom apps have no SCIM auto-provisioning path —
  // hide the SCIM endpoint URL so admins don't paste it where it
  // won't do anything. Entra still gets it (full SCIM works there).
  const isWorkspace = directory.kind === "google_workspace";
  if (!isWorkspace) {
    container.appendChild(_idpEndpointRow(
      "SCIM ENDPOINT (paste into Provisioning config)",
      directory.scim_endpoint_url
    ));
  }
  if (directory.signin_protocol === "saml") {
    container.appendChild(_idpEndpointRow(
      "SAML ACS URL (paste as Reply URL)",
      `${origin}/api/v1/auth/${directory.tenant_id}/idp/${directory.id}/saml-acs`
    ));
    container.appendChild(_idpEndpointRow(
      "START URL (paste into IdP Start URL field)",
      `${origin}/api/v1/auth/${directory.tenant_id}/idp/${directory.id}/saml-login`
    ));
    container.appendChild(_idpEndpointRow(
      "SP METADATA URL",
      `${origin}/api/v1/auth/${directory.tenant_id}/idp/${directory.id}/saml-metadata`
    ));
    container.appendChild(_idpEndpointRow(
      "SP ENTITY ID",
      `${origin}/saml/${directory.id}`
    ));
  } else {
    container.appendChild(_idpEndpointRow(
      "OIDC REDIRECT URI (paste into Redirect URIs)",
      `${origin}/api/v1/auth/${directory.tenant_id}/idp/${directory.id}/oidc-callback`
    ));
    container.appendChild(_idpEndpointRow(
      "SIGN-IN URL (link from your portal)",
      `${origin}/api/v1/auth/${directory.tenant_id}/idp/${directory.id}/oidc-start`
    ));
  }
  const note = document.createElement("p");
  note.style.margin = "16px 0 0";
  note.style.font = "400 11.5px/1.5 var(--vyuu-sans)";
  note.style.color = "var(--vyuu-muted)";
  note.textContent = isWorkspace
    ? ("Google Workspace doesn't push SCIM events for custom apps — "
      + "users JIT-provision on first sign-in via SAML. Deactivation "
      + "is manual via the Users tab until BACKLOG IDP-2 (Admin SDK "
      + "polling adapter) ships.")
    : ("The SCIM bearer is shown only at connect-time. If you've lost "
      + "it, disconnect this directory + reconnect to mint a fresh one.");
  container.appendChild(note);
}

function renderIdpDrawerConnection(container, directory) {
  const dl = document.createElement("dl");
  dl.style.display = "grid";
  dl.style.gridTemplateColumns = "max-content 1fr";
  dl.style.columnGap = "12px";
  dl.style.rowGap = "8px";
  dl.style.font = "400 12px/1.5 var(--vyuu-sans)";

  function row(label, value) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    dt.style.color = "var(--vyuu-muted)";
    dt.style.fontSize = "10.5px";
    dt.style.textTransform = "uppercase";
    dt.style.letterSpacing = "0.08em";
    dt.style.alignSelf = "start";
    dt.style.paddingTop = "2px";
    const dd = document.createElement("dd");
    dd.style.margin = "0";
    dd.textContent = value || "—";
    if (!value) dd.style.color = "var(--vyuu-muted)";
    dl.appendChild(dt);
    dl.appendChild(dd);
  }

  row("Kind", directory.kind === "entra" ? "Microsoft Entra ID" : "Google Workspace");
  row("Sign-in protocol", directory.signin_protocol.toUpperCase());
  if (directory.signin_protocol === "oidc") {
    row("OIDC issuer", directory.oidc_issuer);
    row("OIDC client_id", directory.oidc_client_id);
  } else {
    row("SAML entity_id", directory.saml_entity_id);
    row("SAML SSO URL", directory.saml_sso_url);
  }
  row("Connected at", new Date(directory.created_at).toLocaleString());
  row(
    "Last SCIM activity",
    directory.last_sync_at
      ? new Date(directory.last_sync_at).toLocaleString()
      : "never"
  );
  row("Directory ID", directory.id);
  container.appendChild(dl);
}

function renderIdpDrawerSettings(container, directory) {
  const note = document.createElement("p");
  note.style.font = "400 12.5px/1.5 var(--vyuu-sans)";
  note.style.color = "var(--vyuu-muted)";
  note.style.marginTop = "0";
  note.textContent =
    "Disconnecting removes the directory + the SCIM bearer. Existing "
    + "users provisioned by this directory survive (their idp_directory_id "
    + "is set NULL); they keep their access until you disable them "
    + "individually. The IdP can no longer push provisioning events here.";
  container.appendChild(note);

  const del = document.createElement("button");
  del.type = "button";
  del.style.padding = "8px 14px";
  del.style.border = "1px solid var(--vyuu-danger)";
  del.style.background = "var(--vyuu-danger-tint)";
  del.style.borderRadius = "var(--vyuu-r-sm)";
  del.style.color = "var(--vyuu-danger-ink)";
  del.style.font = "500 12px/1 var(--vyuu-sans)";
  del.style.cursor = "pointer";
  del.textContent = "Disconnect this directory";
  del.addEventListener("click", async () => {
    if (!confirm(
      `Disconnect "${directory.display_name}"? The IdP can no longer ` +
      `push events here. This is reversible only by re-running the ` +
      `connect wizard with fresh creds.`
    )) return;
    try {
      await api(`/api/v1/idp/directories/${encodeURIComponent(directory.id)}`,
                { method: "DELETE" });
      closeIdpDrawer();
      await loadIdpDirectories();
    } catch (error) {
      alert(String(error));
    }
  });
  container.appendChild(del);
}

// ---------- Connect-IdP modal -----------------------------------------
{
  const modal = document.querySelector("#connect-idp-modal");
  const openEntra = document.querySelector("#open-connect-entra");
  const openWorkspace = document.querySelector("#open-connect-workspace");

  function openModal(kind) {
    if (!modal) return;
    document.querySelector("#connect-idp-eyebrow").textContent =
      kind === "entra" ? "NEW DIRECTORY · ENTRA ID" : "NEW DIRECTORY · WORKSPACE";
    document.querySelector("#connect-idp-title").textContent =
      kind === "entra" ? "Connect Microsoft Entra ID" : "Connect Google Workspace";
    document.querySelector("#connect-idp-sub").textContent =
      kind === "entra"
        ? "Pick a sign-in protocol, then paste the IdP-side config. The SCIM bearer is shown once after submit."
        : "Pick a sign-in protocol, then paste the IdP-side config. Workspace runs JIT-create at first sign-in (custom-app SCIM isn't supported by Google).";
    renderConnectForm(kind);
    modal.hidden = false;
    document.body.style.overflow = "hidden";
  }

  if (openEntra && modal) openEntra.addEventListener("click", () => openModal("entra"));
  if (openWorkspace && modal) openWorkspace.addEventListener("click", () => openModal("google_workspace"));

  for (const el of document.querySelectorAll("[data-connect-idp-close]")) {
    el.addEventListener("click", () => {
      modal.hidden = true;
      document.body.style.overflow = "";
    });
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modal && !modal.hidden) {
      modal.hidden = true;
      document.body.style.overflow = "";
    }
  });
}

function renderConnectForm(kind) {
  const body = document.querySelector("#connect-idp-body");
  body.innerHTML = "";

  const form = document.createElement("form");
  form.className = "form-grid";

  // Helper for the two static stacked-label rows below — same shape
  // as `_input` further down but rendered at form-build time, not
  // inside the protocol-fields swap.
  function _stackedLabel(text) {
    const lbl = document.createElement("label");
    lbl.style.gridColumn = "1 / -1";
    lbl.style.display = "block";
    const span = document.createElement("span");
    span.textContent = text;
    span.style.display = "block";
    span.style.marginBottom = "4px";
    span.style.font = "500 12px/1.3 var(--vyuu-sans)";
    span.style.color = "var(--vyuu-ink)";
    lbl.appendChild(span);
    return lbl;
  }

  // Display name
  const nameLabel = _stackedLabel("Display name");
  const nameInput = document.createElement("input");
  nameInput.name = "display_name";
  nameInput.required = true;
  nameInput.maxLength = 255;
  nameInput.style.width = "100%";
  nameInput.placeholder = kind === "entra" ? "Acme Corp · Entra ID" : "Acme · Workspace";
  nameLabel.appendChild(nameInput);
  form.appendChild(nameLabel);

  // Protocol picker
  const protoLabel = _stackedLabel("Sign-in protocol");
  const protoSelect = document.createElement("select");
  protoSelect.name = "signin_protocol";
  protoSelect.style.width = "100%";
  for (const p of ["oidc", "saml"]) {
    const opt = document.createElement("option");
    opt.value = p;
    opt.textContent = p === "oidc" ? "OIDC (recommended)" : "SAML 2.0";
    protoSelect.appendChild(opt);
  }
  protoLabel.appendChild(protoSelect);
  form.appendChild(protoLabel);

  // Per-protocol field block — re-rendered when the picker changes.
  const fieldsWrap = document.createElement("div");
  fieldsWrap.style.gridColumn = "1 / -1";
  form.appendChild(fieldsWrap);

  function renderProtoFields() {
    fieldsWrap.innerHTML = "";
    if (protoSelect.value === "oidc") {
      fieldsWrap.appendChild(_input("oidc_issuer", "OIDC issuer URL", true,
        kind === "entra"
          ? "https://login.microsoftonline.com/{tenant}/v2.0"
          : "https://accounts.google.com"));
      fieldsWrap.appendChild(_input("oidc_client_id", "OIDC client_id", true));
      fieldsWrap.appendChild(_input("oidc_client_secret_ref",
        "OIDC client_secret_ref (NOT the literal secret — see hint below)",
        true,
        kind === "entra" ? "entra-client-secret" : "workspace-client-secret"));
      const hint = document.createElement("p");
      hint.className = "hint";
      hint.style.gridColumn = "1 / -1";
      hint.style.font = "400 11.5px/1.4 var(--vyuu-sans)";
      hint.style.color = "var(--vyuu-muted)";
      hint.textContent = "client_secret_ref points to the secret store key (Vault / Postgres). Set the actual secret via your secret-store backend before connecting.";
      fieldsWrap.appendChild(hint);
    } else {
      fieldsWrap.appendChild(_input("saml_entity_id", "SAML IdP entity_id", true));
      fieldsWrap.appendChild(_input("saml_sso_url", "SAML SSO URL", true));
      const certLabel = _stackedLabel("IdP signing certificate (PEM)");
      const cert = document.createElement("textarea");
      cert.name = "saml_idp_certificate";
      cert.required = true;
      cert.rows = 6;
      cert.style.width = "100%";
      cert.placeholder = "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----";
      cert.style.fontFamily = "var(--vyuu-mono)";
      cert.style.fontSize = "10.5px";
      certLabel.appendChild(cert);
      fieldsWrap.appendChild(certLabel);
    }
  }

  function _input(name, label, required, placeholder) {
    // Each field is a full-width stacked block: label text on top,
    // input below. The default `<label>` is inline so without these
    // overrides the text + input flow side-by-side and adjacent
    // fields visually merge in a 2-col grid.
    const lbl = document.createElement("label");
    lbl.style.gridColumn = "1 / -1";
    lbl.style.display = "block";
    const text = document.createElement("span");
    text.textContent = label;
    text.style.display = "block";
    text.style.marginBottom = "4px";
    text.style.font = "500 12px/1.3 var(--vyuu-sans)";
    text.style.color = "var(--vyuu-ink)";
    lbl.appendChild(text);
    const inp = document.createElement("input");
    inp.name = name;
    inp.style.width = "100%";
    if (required) inp.required = true;
    if (placeholder) inp.placeholder = placeholder;
    lbl.appendChild(inp);
    return lbl;
  }

  protoSelect.addEventListener("change", renderProtoFields);
  renderProtoFields();

  const submit = document.createElement("button");
  submit.type = "submit";
  submit.textContent = "Connect directory";
  form.appendChild(submit);

  const out = document.createElement("pre");
  out.className = "output";
  out.style.marginTop = "12px";
  out.textContent = "Waiting for submission.";
  form.appendChild(out);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = new FormData(form);
    const protocol = data.get("signin_protocol");
    const payload = {
      kind: kind,
      display_name: String(data.get("display_name") || "").trim(),
      signin_protocol: protocol,
    };
    if (protocol === "oidc") {
      payload.oidc = {
        issuer: String(data.get("oidc_issuer") || "").trim(),
        client_id: String(data.get("oidc_client_id") || "").trim(),
        client_secret_ref: String(data.get("oidc_client_secret_ref") || "").trim(),
      };
    } else {
      payload.saml = {
        entity_id: String(data.get("saml_entity_id") || "").trim(),
        sso_url: String(data.get("saml_sso_url") || "").trim(),
        idp_certificate: String(data.get("saml_idp_certificate") || "").trim(),
      };
    }
    try {
      const created = await api("/api/v1/idp/directories", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      _renderConnectSuccess(body, created);
      await loadIdpDirectories();
    } catch (error) {
      out.textContent = String(error.message || error);
      out.style.color = "var(--vyuu-danger-ink)";
    }
  });

  body.appendChild(form);
}

function _renderConnectSuccess(container, response) {
  container.innerHTML = "";
  const wrap = document.createElement("div");
  const headline = document.createElement("p");
  headline.style.font = "500 13px/1.4 var(--vyuu-sans)";
  headline.style.color = "var(--vyuu-ink)";
  headline.style.margin = "0 0 8px";
  headline.textContent = `✓ Directory connected: ${response.directory.display_name}`;
  wrap.appendChild(headline);

  // Workspace doesn't support custom-app SCIM auto-provisioning, so
  // the SCIM bearer + endpoint we mint behind the scenes are dormant
  // until a polling adapter ships (BACKLOG IDP-2). Hide both from the
  // success modal — surfacing them implies an integration point that
  // doesn't exist for Workspace today.
  const isWorkspace = response.directory.kind === "google_workspace";
  if (!isWorkspace) {
    // SCIM bearer reveal — shown once. (Entra only.)
    const reveal = document.createElement("div");
    reveal.className = "idp-token-reveal";
    const title = document.createElement("p");
    title.className = "idp-token-reveal-title";
    title.textContent = "SCIM Bearer · shown once";
    reveal.appendChild(title);
    const body = document.createElement("div");
    body.className = "idp-token-reveal-body";
    body.textContent = response.scim_token_plaintext;
    reveal.appendChild(body);
    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.style.marginTop = "8px";
    copyBtn.textContent = "Copy bearer";
    copyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(response.scim_token_plaintext).then(
        () => { copyBtn.textContent = "Copied"; },
        () => { copyBtn.textContent = "Copy failed"; },
      );
    });
    reveal.appendChild(copyBtn);
    wrap.appendChild(reveal);

    wrap.appendChild(_idpEndpointRow(
      "SCIM ENDPOINT (paste into IdP Provisioning config)",
      response.directory.scim_endpoint_url
    ));
  }

  const next = document.createElement("p");
  next.style.font = "400 12px/1.5 var(--vyuu-sans)";
  next.style.color = "var(--vyuu-muted)";
  next.style.marginTop = "12px";
  next.innerHTML = isWorkspace
    ? ("<strong>Note:</strong> Google Workspace doesn't support SCIM "
      + "auto-provisioning for custom apps. Users JIT-provision on "
      + "first sign-in. Deactivation is manual via the Users tab "
      + "until the Workspace polling adapter ships (BACKLOG IDP-2). "
      + "The SAML metadata + ACS / Start URLs from the drill-in "
      + "drawer are what you paste into Google's SAML app config.")
    : ("Next: paste the SCIM endpoint URL + bearer above into your "
      + "IdP's Provisioning config, then return here. The directory "
      + "shows up in the table on close.");
  wrap.appendChild(next);

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.style.marginTop = "12px";
  closeBtn.textContent = "Close";
  closeBtn.addEventListener("click", () => {
    document.querySelector("#connect-idp-modal").hidden = true;
    document.body.style.overflow = "";
  });
  wrap.appendChild(closeBtn);

  container.appendChild(wrap);
}

// =========================================================================
// Admin audit panel (IDP-1 Phase 5b)
// =========================================================================
//
// Persistent log of admin-driven mutations. Distinct from the Events
// panel which captures inbound MCP tool calls — this one captures
// what admins did to the platform. Same shape as the rest of the
// console: KPIs + pills + table + drill-in drawer.

const adminAuditOutput = document.querySelector("#admin-audit-output");
const adminAuditCount = document.querySelector("#admin-audit-count");
const adminAuditSearch = document.querySelector("#admin-audit-search");
let adminAuditCache = [];
const adminAuditPillState = { current: "all" };

if (document.querySelector("#refresh-admin-audit")) {
  document.querySelector("#refresh-admin-audit")
    .addEventListener("click", loadAdminAudit);
}
if (adminAuditSearch) {
  adminAuditSearch.addEventListener("input", () => renderAdminAudit());
}
for (const pill of document.querySelectorAll("[data-aa-pill]")) {
  pill.addEventListener("click", () => {
    adminAuditPillState.current = pill.dataset.aaPill;
    for (const p of document.querySelectorAll("[data-aa-pill]")) {
      p.classList.toggle("is-active", p === pill);
    }
    renderAdminAudit();
  });
}

async function loadAdminAudit() {
  if (!adminAuditOutput) return;
  adminAuditOutput.innerHTML =
    '<tr><td colspan="5" class="events-empty">Loading…</td></tr>';
  try {
    const page = await api("/api/v1/admin-audit?limit=200");
    adminAuditCache = page.rows || [];
    renderAdminAudit();
  } catch (error) {
    adminAuditOutput.innerHTML = "";
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "events-empty";
    td.textContent = String(error.message || error);
    tr.appendChild(td);
    adminAuditOutput.appendChild(tr);
  }
}

function renderAdminAudit() {
  if (!adminAuditOutput) return;
  renderAdminAuditKpis(adminAuditCache);

  const needle = (adminAuditSearch && adminAuditSearch.value || "").trim().toLowerCase();
  const pill = adminAuditPillState.current;
  const filtered = adminAuditCache.filter((r) => {
    if (needle) {
      const hay = `${r.action} ${r.target_display || ""} ${r.actor_display || ""}`.toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    if (pill === "operator") return r.actor_kind === "operator";
    if (pill === "scim") return r.actor_kind === "scim";
    if (pill === "system") return r.actor_kind === "system";
    if (pill === "user") return r.action.startsWith("user.") || r.action.startsWith("apikey.");
    if (pill === "vserver") return r.action.startsWith("vserver.");
    if (pill === "grant") return r.action.startsWith("grant.");
    return true;
  });

  adminAuditCount.textContent =
    filtered.length === adminAuditCache.length
      ? `${filtered.length} actions`
      : `${filtered.length} of ${adminAuditCache.length} actions`;

  adminAuditOutput.innerHTML = "";
  if (!filtered.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "events-empty";
    td.textContent = adminAuditCache.length === 0
      ? "No admin actions recorded yet — fire one (Disable user, Revoke grant, etc.) and Refresh."
      : `(0 of ${adminAuditCache.length} actions match the active filter)`;
    tr.appendChild(td);
    adminAuditOutput.appendChild(tr);
    return;
  }
  for (const r of filtered) {
    adminAuditOutput.appendChild(renderAdminAuditRow(r));
  }
}

function renderAdminAuditKpis(rows) {
  let operator = 0;
  let scim = 0;
  let system = 0;
  for (const r of rows) {
    if (r.actor_kind === "operator") operator++;
    else if (r.actor_kind === "scim") scim++;
    else if (r.actor_kind === "system") system++;
  }
  const set = (id, v) => {
    const el = document.querySelector(`#${id}`);
    if (el) el.textContent = v;
  };
  set("aa-kpi-total", String(rows.length));
  set("aa-kpi-operator", String(operator));
  set("aa-kpi-scim", String(scim));
  set("aa-kpi-system", String(system));
}

function renderAdminAuditRow(row) {
  const tr = document.createElement("tr");
  tr.dataset.actor = row.actor_kind;
  tr.addEventListener("click", () => openAdminAuditDrawer(row));

  // WHEN
  const whenCell = document.createElement("td");
  whenCell.style.color = "var(--vyuu-muted)";
  whenCell.style.fontSize = "11.5px";
  whenCell.textContent = formatRelativeTime(row.occurred_at);
  whenCell.title = new Date(row.occurred_at).toLocaleString();
  tr.appendChild(whenCell);

  // ACTOR
  const actorCell = document.createElement("td");
  const wrap = document.createElement("div");
  wrap.className = "aa-actor";
  const line = document.createElement("span");
  line.className = "aa-actor-line";
  line.textContent = row.actor_display || `(${row.actor_kind})`;
  wrap.appendChild(line);
  const kind = document.createElement("span");
  kind.className = "aa-actor-kind";
  kind.textContent = row.actor_kind;
  wrap.appendChild(kind);
  actorCell.appendChild(wrap);
  tr.appendChild(actorCell);

  // ACTION
  const actionCell = document.createElement("td");
  const tag = document.createElement("span");
  tag.className = "aa-action-tag";
  tag.textContent = row.action;
  actionCell.appendChild(tag);
  tr.appendChild(actionCell);

  // TARGET
  const targetCell = document.createElement("td");
  if (row.target_display) {
    targetCell.textContent = row.target_display;
    targetCell.style.font = "500 12px/1.3 var(--vyuu-sans)";
    targetCell.style.color = "var(--vyuu-ink)";
  } else if (row.target_kind) {
    targetCell.textContent = `(${row.target_kind})`;
    targetCell.style.color = "var(--vyuu-muted)";
  } else {
    targetCell.textContent = "—";
    targetCell.style.color = "var(--vyuu-muted)";
  }
  tr.appendChild(targetCell);

  // DETAIL — single-line JSON snippet
  const detailCell = document.createElement("td");
  const snippet = document.createElement("span");
  snippet.className = "aa-detail-snippet";
  const json = row.detail && Object.keys(row.detail).length
    ? JSON.stringify(row.detail)
    : "—";
  snippet.textContent = json.length > 80 ? json.slice(0, 78) + "…" : json;
  snippet.title = json;
  detailCell.appendChild(snippet);
  tr.appendChild(detailCell);

  return tr;
}

const _aaDrawer = {
  el: () => document.querySelector("#admin-audit-drawer"),
  body: () => document.querySelector("#admin-audit-drawer-body"),
  title: () => document.querySelector("#admin-audit-drawer-title"),
  sub: () => document.querySelector("#admin-audit-drawer-sub"),
};

function openAdminAuditDrawer(row) {
  _aaDrawer.title().textContent = row.action;
  _aaDrawer.sub().textContent =
    `${row.actor_kind} · ${row.actor_display || "—"} · ${formatRelativeTime(row.occurred_at)}`;
  const body = _aaDrawer.body();
  body.innerHTML = "";

  const dl = document.createElement("dl");
  dl.style.display = "grid";
  dl.style.gridTemplateColumns = "max-content 1fr";
  dl.style.columnGap = "12px";
  dl.style.rowGap = "8px";
  dl.style.font = "400 12px/1.5 var(--vyuu-sans)";

  function pair(label, value) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    dt.style.color = "var(--vyuu-muted)";
    dt.style.fontSize = "10.5px";
    dt.style.textTransform = "uppercase";
    dt.style.letterSpacing = "0.08em";
    dt.style.alignSelf = "start";
    dt.style.paddingTop = "2px";
    const dd = document.createElement("dd");
    dd.style.margin = "0";
    dd.textContent = value || "—";
    if (!value) dd.style.color = "var(--vyuu-muted)";
    dl.appendChild(dt);
    dl.appendChild(dd);
  }

  pair("Action", row.action);
  pair("Actor kind", row.actor_kind);
  pair("Actor", row.actor_display);
  pair("Operator id",
    row.actor_operator_id ? row.actor_operator_id : null);
  pair("Target kind", row.target_kind);
  pair("Target id", row.target_id);
  pair("Target", row.target_display);
  pair("Occurred at", new Date(row.occurred_at).toLocaleString());
  body.appendChild(dl);

  if (row.detail && Object.keys(row.detail).length) {
    const eyebrow = document.createElement("p");
    eyebrow.className = "eyebrow";
    eyebrow.style.margin = "16px 0 6px";
    eyebrow.textContent = "DETAIL";
    body.appendChild(eyebrow);
    const pre = document.createElement("pre");
    pre.className = "aa-detail-pre";
    pre.textContent = JSON.stringify(row.detail, null, 2);
    body.appendChild(pre);
  }

  _aaDrawer.el().hidden = false;
  document.body.style.overflow = "hidden";
}

function closeAdminAuditDrawer() {
  _aaDrawer.el().hidden = true;
  _aaDrawer.body().innerHTML = "";
  document.body.style.overflow = "";
}

{
  for (const el of document.querySelectorAll("[data-admin-audit-drawer-close]")) {
    el.addEventListener("click", closeAdminAuditDrawer);
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !_aaDrawer.el().hidden) closeAdminAuditDrawer();
  });
}
"""
