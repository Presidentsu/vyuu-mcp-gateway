from fastapi import APIRouter
from fastapi.responses import HTMLResponse, Response

router = APIRouter(tags=["portal-ui"])

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


@router.get("/portal", response_class=HTMLResponse)
def portal_console() -> HTMLResponse:
    return HTMLResponse(_HTML, headers=_SECURITY_HEADERS)


@router.get("/portal/app.css")
def portal_css() -> Response:
    return Response(_CSS, media_type="text/css", headers=_SECURITY_HEADERS)


@router.get("/portal/app.js")
def portal_js() -> Response:
    return Response(_JS, media_type="text/javascript", headers=_SECURITY_HEADERS)


_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Vyuu Gateway · End-User Portal</title>
    <link rel="stylesheet" href="/portal/app.css">
  </head>
  <body data-portal-active="login">

    <!-- ===================== SIGN-IN PANEL ===================== -->
    <main id="login-shell" class="login-shell">
      <header class="login-head">
        <p class="eyebrow">VYUU GATEWAY · END-USER PORTAL</p>
        <h1>Sign in</h1>
        <p class="login-sub">Use the work email and password your admin issued, or
          continue with your company's single sign-on.</p>
      </header>
      <section class="panel login-panel">
        <!-- Connected-IdP "Continue with X" buttons. Populated as the
             user types their tenant_id below — same pattern as the
             operator console's sign-in page. Buttons kick off the
             user-portal-side SAML / OIDC flows. -->
        <div id="portal-idp-buttons"
             class="idp-button-row" hidden></div>
        <form id="login-form" class="form-grid">
          <label class="login-tenant-field">
            Organisation ID
            <input name="tenant_id" id="login-tenant-id" required
                   placeholder="00000000-0000-0000-0000-000000000000">
            <span class="field-hint">Only needed when this gateway serves several
              organisations. It is in the invite your admin sent.</span>
          </label>
          <label>
            Email
            <input name="email" type="email" placeholder="you@corp.example">
          </label>
          <label>
            Password
            <input name="password" type="password" autocomplete="current-password">
          </label>
          <button type="submit" data-mode="password">Sign in with password</button>
        </form>
        <details class="advanced">
          <summary>Advanced: paste session token</summary>
          <form id="token-form" class="form-grid">
            <label>
              Session JWT
              <input id="paste-token" type="password" autocomplete="off" spellcheck="false">
            </label>
            <button type="submit">Use token</button>
          </form>
        </details>
        <pre id="login-output" class="output output-status">Not signed in.</pre>
      </section>
    </main>

    <!-- ===================== APP SHELL ===================== -->
    <div id="dashboard" class="app-shell" hidden>
      <aside class="sidebar">
        <a href="/portal" class="brand-block">
          <span class="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 48 48" width="28" height="28" fill="none">
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
          <div>
            <strong>Vyuu</strong>
            <p class="eyebrow brand-eyebrow">AI SHIELD</p>
          </div>
        </a>

        <nav class="side-nav" aria-label="Main">
          <div class="nav-group">
            <p class="nav-group-label">Get started</p>
            <button class="nav-item" data-portal-nav="home" type="button">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M3 8.5 L9 3.5 L15 8.5"/>
                  <path d="M4.5 7.5 V14.5 H13.5 V7.5"/>
                  <path d="M7.5 14.5 V10.5 H10.5 V14.5"/>
                </svg>
              </span>
              <span class="nav-item-label">Home</span>
            </button>
          </div>
          <div class="nav-group">
            <p class="nav-group-label">Discover</p>
            <button class="nav-item" data-portal-nav="catalog" type="button">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <rect x="3" y="3" width="5" height="5" rx="1"/>
                  <rect x="10" y="3" width="5" height="5" rx="1"/>
                  <rect x="3" y="10" width="5" height="5" rx="1"/>
                  <rect x="10" y="10" width="5" height="5" rx="1"/>
                </svg>
              </span>
              <span class="nav-item-label">Tool catalog</span>
            </button>
          </div>
          <div class="nav-group">
            <p class="nav-group-label">My account</p>
            <button class="nav-item" data-portal-nav="connections" type="button">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M7.5 10.5 L10.5 7.5"/>
                  <path d="M8 6 L9.5 4.5 A2.5 2.5 0 0 1 13.5 8.5 L12 10"/>
                  <path d="M10 12 L8.5 13.5 A2.5 2.5 0 0 1 4.5 9.5 L6 8"/>
                </svg>
              </span>
              <span class="nav-item-label">Connections</span>
              <span class="nav-count" id="nav-count-connections" hidden>0</span>
            </button>
            <button class="nav-item" data-portal-nav="api-keys" type="button">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="6.5" cy="7" r="3"/>
                  <path d="M8.8 9 L15 15"/>
                  <path d="M12.5 12.5 L14 11"/>
                  <path d="M11 14 L12.5 12.5"/>
                </svg>
              </span>
              <span class="nav-item-label">API keys</span>
              <span class="nav-count" id="nav-count-keys" hidden>0</span>
            </button>
            <button class="nav-item" data-portal-nav="my-requests" type="button">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <circle cx="9" cy="9" r="6"/>
                  <path d="M9 5.5 V9 L11.5 10.5"/>
                </svg>
              </span>
              <span class="nav-item-label">My requests</span>
              <span class="nav-count" id="nav-count-requests" hidden>0</span>
            </button>
            <button class="nav-item" data-portal-nav="tool-history" type="button">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M4 5 H14"/>
                  <path d="M4 9 H14"/>
                  <path d="M4 13 H11"/>
                </svg>
              </span>
              <span class="nav-item-label">Tool history</span>
            </button>
            <button class="nav-item" data-portal-nav="settings" type="button" id="tab-settings">
              <span class="nav-item-icon" aria-hidden="true">
                <svg viewBox="0 0 18 18" width="16" height="16" fill="none"
                     stroke="currentColor" stroke-width="1.6"
                     stroke-linecap="round" stroke-linejoin="round">
                  <path d="M4 5.5 H14"/>
                  <path d="M4 12.5 H14"/>
                  <circle cx="7" cy="5.5" r="1.6" fill="var(--vyuu-panel)"/>
                  <circle cx="11" cy="12.5" r="1.6" fill="var(--vyuu-panel)"/>
                </svg>
              </span>
              <span class="nav-item-label">Settings</span>
            </button>
          </div>
        </nav>

        <div class="sidebar-foot">
          <div class="user-pill" id="user-pill">
            <span class="user-pill-dot" aria-hidden="true"></span>
            <div class="user-pill-text">
              <strong id="who-email">…</strong>
              <span class="user-pill-meta" id="user-pill-meta">…</span>
            </div>
          </div>
          <button id="logout" class="logout-btn" type="button">Log out</button>
        </div>
      </aside>

      <main class="content">
        <header class="topbar">
          <nav class="breadcrumb" aria-label="Breadcrumb">
            <span>Portal</span>
            <span class="breadcrumb-sep">›</span>
            <span class="breadcrumb-section" id="breadcrumb-section">Home</span>
          </nav>
          <div class="topbar-right">
            <div class="env-pill" id="env-pill">
              <span class="env-pill-dot" aria-hidden="true"></span>
              <span id="env-pill-text">gateway · v1.0.0</span>
            </div>
          </div>
        </header>

        <!-- ===================== HOME ===================== -->
        <section data-portal-nav="home" class="panel-area">
          <div class="hero">
            <div class="hero-head">
              <p class="eyebrow">WELCOME</p>
              <h1 id="hero-title">Hi there — connect your AI tools to
                your tenant's sanctioned MCPs</h1>
              <p class="hero-sub"
                 title="Cursor, Claude Desktop, ChatGPT or your own agent.">
                   Point any MCP client at the gateway your IT team
                approved.</p>
            </div>
            <button class="btn-primary hero-cta" id="hero-cta-connect">
              Connect a new client →
            </button>
          </div>

          <div class="home-grid">
            <article class="setup-card">
              <p class="eyebrow">ONE-TIME SETUP · 2 MINUTES</p>
              <h2>Point your IDE at this URL</h2>
              <p>Any MCP-compliant client takes a single endpoint. Drop
                yours into Cursor's <code>~/.cursor/mcp.json</code> or
                Claude Desktop's <code>claude_desktop_config.json</code>.</p>
              <pre id="setup-snippet" class="setup-snippet">…</pre>
              <div class="setup-actions">
                <button type="button" id="setup-cursor">Cursor docs →</button>
                <button type="button" id="setup-claude">Claude Desktop →</button>
                <button type="button" id="setup-custom">Custom client →</button>
              </div>
            </article>

            <aside class="home-rail">
              <article class="rail-card">
                <p class="eyebrow">YOUR ACCESS</p>
                <h3>What you can use</h3>
                <ul id="home-access-list" class="rail-list">
                  <li class="rail-list-empty">Loading…</li>
                </ul>
                <button class="rail-card-cta" type="button"
                        data-portal-nav-target="catalog">
                  Browse catalog →
                </button>
              </article>

              <article class="rail-card pending-card" id="home-pending-wrap" hidden>
                <p class="eyebrow">PENDING</p>
                <h3 id="home-pending-headline">0 access requests open</h3>
                <ul id="home-pending-list" class="rail-list"></ul>
              </article>
            </aside>
          </div>

          <section class="recent-section">
            <header class="recent-section-head">
              <h2>Your last 5 tool calls</h2>
              <button type="button" class="ghost"
                      data-portal-nav-target="tool-history">
                Full history →
              </button>
            </header>
            <div id="home-recent-calls" class="recent-table">
              <p class="hint">Loading…</p>
            </div>
          </section>
        </section>

        <!-- ===================== TOOL CATALOG ===================== -->
        <section data-portal-nav="catalog" class="panel-area" hidden>
          <header class="page-head">
            <p class="eyebrow">DISCOVER · TOOL CATALOG</p>
            <h1 id="catalog-headline">What's connected</h1>
            <p class="page-sub"
               title="Connect any one to your IDE. Private bundles need a request first.">
                 Sanctioned MCP bundles.</p>
          </header>
          <div class="catalog-toolbar">
            <input id="catalog-search" type="search"
                   placeholder="Search across bundles and tools…"
                   autocomplete="off">
            <div class="filter-pills" role="tablist" aria-label="Catalog filter">
              <button class="filter-pill is-active" type="button"
                      data-catalog-filter="all">All bundles</button>
              <button class="filter-pill" type="button"
                      data-catalog-filter="open">Open to me</button>
              <button class="filter-pill" type="button"
                      data-catalog-filter="needs-request">Needs request</button>
              <button class="filter-pill" type="button"
                      data-catalog-filter="restricted">Restricted</button>
            </div>
            <span id="catalog-count" class="toolbar-meta"></span>
          </div>
          <div id="catalog-output" class="bundle-grid">Loading…</div>
        </section>

        <!-- ===================== CONNECTIONS ===================== -->
        <section data-portal-nav="connections" class="panel-area" hidden>
          <header class="page-head">
            <p class="eyebrow">MY ACCOUNT · CONNECTIONS</p>
            <h1>Linked SaaS accounts</h1>
            <p class="page-sub"
               title="Authorises only your tool calls. Disconnecting forces fresh consent.">
                 Per-user delegated access &mdash; GitHub, Notion, Drive.</p>
          </header>
          <div id="connections-output" class="connections-table">Loading…</div>
          <section class="recent-section" id="quick-connect-section" hidden>
            <header class="recent-section-head">
              <h2>Quick connect</h2>
            </header>
            <div id="quick-connect-grid" class="quick-connect-grid"></div>
          </section>
        </section>

        <!-- ===================== API KEYS ===================== -->
        <section data-portal-nav="api-keys" class="panel-area" hidden>
          <header class="page-head">
            <p class="eyebrow">MY ACCOUNT · API KEYS</p>
            <h1>Issued bearer tokens</h1>
            <p class="page-sub">For Claude Desktop, Cursor, and agents.
              Plaintext is shown <strong>once</strong> at issuance — copy
              it then. Revoke any time.</p>
            <!-- EMA-1 P3 · shown only when a connected directory has
                 Enterprise-Managed Authorization on, i.e. an AI client
                 can obtain access through company SSO and the user may
                 not need to paste a key at all. -->
            <div id="ema-notice" class="ema-notice" hidden>
              <strong>Your organisation uses single sign-on for AI tools.</strong>
              <span>
                If your AI client supports enterprise-managed
                authorization, it can sign in with your work account —
                no key to copy, and access follows your SSO account
                automatically. Issue a key below only for clients that
                don't support it.
              </span>
            </div>
          </header>
          <div class="page-card">
            <h3>Issue a new key</h3>
            <form id="issue-key-form" class="form-grid">
              <label>
                Label
                <input name="label" required maxlength="255"
                       placeholder='"MacBook Claude Desktop"'>
              </label>
              <button type="submit">Issue key</button>
            </form>
            <pre id="issued-key-output"
                 class="output output-status">No key issued in this session.</pre>
            <div id="issued-key-card" class="key-reveal" hidden></div>
          </div>

          <div class="catalog-toolbar" style="margin-top: 24px;">
            <input id="keys-search" type="search"
                   placeholder="Search by label or prefix…" autocomplete="off">
            <div class="filter-pills">
              <button class="filter-pill is-active" type="button"
                      data-keys-filter="">All keys</button>
              <button class="filter-pill" type="button"
                      data-keys-filter="active">Active</button>
              <button class="filter-pill" type="button"
                      data-keys-filter="revoked">Revoked</button>
            </div>
            <span id="keys-count" class="toolbar-meta"></span>
          </div>
          <div id="keys-output" class="bundle-grid">Loading…</div>
        </section>

        <!-- ===================== MY REQUESTS ===================== -->
        <section data-portal-nav="my-requests" class="panel-area" hidden>
          <header class="page-head">
            <p class="eyebrow">MY ACCOUNT · ACCESS REQUESTS</p>
            <h1>My requests</h1>
            <p class="page-sub">Requests you've submitted to access private
              vservers. Pending ones can be withdrawn.</p>
          </header>
          <div class="catalog-toolbar">
            <input id="requests-search" type="search"
                   placeholder="Search by note or vserver…"
                   autocomplete="off">
            <div class="filter-pills">
              <button class="filter-pill is-active" type="button"
                      data-requests-filter="">All</button>
              <button class="filter-pill" type="button"
                      data-requests-filter="pending">Pending</button>
              <button class="filter-pill" type="button"
                      data-requests-filter="approved">Approved</button>
              <button class="filter-pill" type="button"
                      data-requests-filter="declined">Declined</button>
              <button class="filter-pill" type="button"
                      data-requests-filter="withdrawn">Withdrawn</button>
            </div>
            <span id="requests-count" class="toolbar-meta"></span>
          </div>
          <div id="requests-output" class="bundle-grid">Loading…</div>
        </section>

        <!-- ===================== TOOL HISTORY ===================== -->
        <section data-portal-nav="tool-history" class="panel-area" hidden>
          <header class="page-head">
            <p class="eyebrow">MY ACCOUNT · TOOL HISTORY</p>
            <h1>Every tool call you (and your AI clients) made</h1>
            <p class="page-sub"
               title="Debug an agent&rsquo;s bad day, or prove what happened.">
                 A personal audit log.</p>
          </header>
          <div id="tool-history-kpis" class="kpi-grid">
            <article class="kpi-card" data-kpi="calls">
              <p class="eyebrow">CALLS · 7 DAYS</p>
              <h3 id="kpi-calls-value">—</h3>
            </article>
            <article class="kpi-card" data-kpi="tools">
              <p class="eyebrow">DISTINCT TOOLS</p>
              <h3 id="kpi-tools-value">—</h3>
            </article>
            <article class="kpi-card" data-kpi="blocked">
              <p class="eyebrow">BLOCKED</p>
              <h3 id="kpi-blocked-value">—</h3>
              <p id="kpi-blocked-meta" class="kpi-meta"></p>
            </article>
          </div>
          <div id="tool-history-output" class="recent-table">Loading…</div>
        </section>

        <!-- ===================== SETTINGS ===================== -->
        <section data-portal-nav="settings" class="panel-area" hidden>
          <header class="page-head">
            <p class="eyebrow">MY ACCOUNT · SETTINGS</p>
            <h1>Settings</h1>
          </header>
          <div class="page-card" id="password-panel">
            <h3>Change password</h3>
            <p class="hint"
               title="OIDC users manage their password at the IdP instead.">
                 Local-auth users only. Min 12 characters.</p>
            <form id="password-form" class="form-grid">
              <label>
                Current password
                <input name="current_password" type="password" required>
              </label>
              <label>
                New password
                <input name="new_password" type="password" required minlength="12">
              </label>
              <button type="submit">Rotate</button>
            </form>
            <pre id="password-output" class="output output-status">Not rotated.</pre>
          </div>
        </section>
      </main>
    </div>
    <script src="/portal/app.js">
// EMA-1 P3 · reveal the "SSO can authorize your AI client" notice when
// any connected directory has Enterprise-Managed Authorization on.
// Uses the same public per-tenant directory list the login page reads.
(function initEmaNotice() {
  const notice = document.querySelector("#ema-notice");
  if (!notice) return;
  const tenantId = sessionStorage.getItem("vyuu.portal.tenant");
  if (!tenantId) return;
  fetch(`/api/v1/auth/${encodeURIComponent(tenantId)}/idp-directories`)
    .then((r) => (r.ok ? r.json() : []))
    .then((dirs) => {
      if (Array.isArray(dirs) && dirs.some((d) => d && d.ema_enabled)) {
        notice.hidden = false;
      }
    })
    .catch(() => {});   // notice is an enhancement; never block the page
})();
</script>
  </body>
</html>
"""


_CSS = """
/* Vyuu Design System tokens — kept in sync with operator_ui.py.
   Same source-of-truth block; both surfaces share the cream / ink /
   orange palette + Fraunces / Inter / JetBrains Mono type stack. */
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
  --vyuu-r-sm: 6px;
  --vyuu-kpi: 600 32px/1 var(--vyuu-serif);
  --vyuu-focus: color-mix(in srgb, var(--vyuu-orange) 45%, transparent);
  --muted: var(--vyuu-muted);
  --err: var(--vyuu-danger-ink);
}

* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  color: var(--vyuu-ink);
  background: var(--vyuu-bg);
  font: var(--vyuu-body);
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}
h1, h2, h3 { margin: 0; }

.shell {
  width: min(1200px, calc(100% - 48px));
  margin: 0 auto;
  padding: 32px 0 80px;
}

/* ==================== APP SHELL (sidebar + content) ====================
   Same layout tokens the operator console uses. 248px sticky sidebar +
   fluid content; sidebar collapses to a top-bar under 880px. */
.app-shell {
  display: grid;
  grid-template-columns: 248px minmax(0, 1fr);
  min-height: 100vh;
  background: var(--vyuu-bg);
}
.sidebar {
  position: sticky;
  top: 0;
  height: 100vh;
  display: flex;
  flex-direction: column;
  padding: 18px 14px;
  border-right: 1px solid var(--vyuu-line);
  background: var(--vyuu-panel);
  overflow-y: auto;
}
.brand-block {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 6px 8px 14px;
  text-decoration: none;
  color: inherit;
  border-bottom: 1px solid var(--vyuu-line);
  margin-bottom: 14px;
}
.brand-mark {
  font-size: 26px;
  color: var(--vyuu-orange-deep);
  line-height: 1;
}
.brand-block strong {
  font: 500 17px/1.1 var(--vyuu-serif);
  color: var(--vyuu-ink);
  display: block;
}
.brand-eyebrow {
  margin: 2px 0 0;
  letter-spacing: 1.6px;
  color: var(--vyuu-muted);
}
.side-nav { flex: 1; display: flex; flex-direction: column; gap: 14px; }
.nav-group { display: flex; flex-direction: column; gap: 2px; }
.nav-group-label {
  margin: 0 0 4px 8px;
  font: var(--vyuu-eyebrow);
  letter-spacing: 1.6px;
  color: var(--vyuu-muted);
  text-transform: uppercase;
}
.nav-item {
  appearance: none;
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  padding: 7px 10px;
  border: 1px solid transparent;
  border-radius: var(--vyuu-r-md);
  background: transparent;
  color: var(--vyuu-ink);
  cursor: pointer;
  font: var(--vyuu-ui);
  min-height: auto;
  text-align: left;
}
.nav-item:hover { background: var(--vyuu-line-soft); }
.nav-item.is-active {
  background: var(--vyuu-orange-mist);
  border-color: var(--vyuu-orange-soft);
  color: var(--vyuu-orange-deep);
  font-weight: 600;
}
.nav-item-icon {
  width: 22px;
  flex-shrink: 0;
  text-align: center;
  font-size: 14px;
  color: var(--vyuu-muted);
}
.nav-item.is-active .nav-item-icon { color: var(--vyuu-orange-deep); }
.nav-item-label { flex: 1; min-width: 0; }
.nav-count {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-muted);
  background: var(--vyuu-line-soft);
  padding: 1px 7px;
  border-radius: 999px;
}
.nav-count[hidden] { display: none; }
.nav-item.is-active .nav-count {
  background: var(--vyuu-orange-soft);
  color: var(--vyuu-orange-deep);
}
.sidebar-foot {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding-top: 12px;
  border-top: 1px solid var(--vyuu-line);
  margin-top: 14px;
}
.user-pill {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border-radius: var(--vyuu-r-md);
  background: var(--vyuu-bg);
  border: 1px solid var(--vyuu-line);
}
.user-pill-dot {
  width: 8px;
  height: 8px;
  border-radius: 999px;
  background: var(--vyuu-orange-deep);
  flex-shrink: 0;
}
.user-pill-text { display: flex; flex-direction: column; min-width: 0; }
.user-pill-text strong {
  font: var(--vyuu-ui-sm);
  color: var(--vyuu-ink);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.user-pill-meta {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-muted);
}
.logout-btn {
  font: var(--vyuu-ui-sm);
  border: 1px solid var(--vyuu-line);
  background: var(--vyuu-bg);
  color: var(--vyuu-ink);
  padding: 7px 10px;
  border-radius: var(--vyuu-r-md);
  cursor: pointer;
}
.logout-btn:hover { background: var(--vyuu-line-soft); }

/* Content + topbar -------------------------------------------------- */
.content {
  padding: 24px 32px 80px;
  min-width: 0;
}
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding-bottom: 20px;
  margin-bottom: 0;
  border-bottom: 1px solid var(--vyuu-line);
}
.breadcrumb {
  display: flex;
  gap: 8px;
  align-items: center;
  font: var(--vyuu-ui);
  color: var(--vyuu-muted);
}
.breadcrumb-sep { color: var(--vyuu-subtle); }
.breadcrumb-section { color: var(--vyuu-ink); font-weight: 500; }
.topbar-right { display: flex; gap: 12px; align-items: center; }
.env-pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  border: 1px solid var(--vyuu-line);
  border-radius: 999px;
  font: var(--vyuu-mono-sm);
  background: var(--vyuu-panel);
  color: var(--vyuu-ink);
}
.env-pill-dot {
  width: 7px;
  height: 7px;
  border-radius: 999px;
  background: var(--vyuu-orange-deep);
}

/* Per-page chrome --------------------------------------------------- */
.panel-area { padding: 28px 0 32px; }
.panel-area[hidden] { display: none; }
.page-head { margin-bottom: 20px; }
.page-head h1 {
  font: 500 28px/1.15 var(--vyuu-serif);
  letter-spacing: -0.5px;
  margin: 6px 0 8px;
}
.ema-notice {
  margin-top: 12px; padding: 10px 14px; border-radius: 8px;
  background: var(--vyuu-orange-mist, #FAEDD5);
  border: 1px solid var(--vyuu-orange-soft, #F3DAB6);
  display: flex; flex-direction: column; gap: 4px;
  font-size: 12.5px; line-height: 1.5;
}
.ema-notice strong { color: var(--vyuu-orange-deep, #A85820); }
.ema-notice span { color: var(--vyuu-ink, #1F2A2E); }
.page-sub {
  font: var(--vyuu-body-lg);
  color: var(--vyuu-muted);
  max-width: 720px;
}
.page-card {
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  padding: 24px;
}

/* Hero (Home page) -------------------------------------------------- */
.hero {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 24px;
  align-items: end;
  margin: 16px 0 28px;
}
.hero-head h1 {
  font: 500 32px/1.15 var(--vyuu-serif);
  letter-spacing: -0.6px;
  margin: 6px 0 10px;
}
.hero-sub {
  font: var(--vyuu-body-lg);
  color: var(--vyuu-muted);
  max-width: 640px;
}
.btn-primary {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: var(--vyuu-orange-deep);
  color: var(--vyuu-on-primary);
  border-color: var(--vyuu-orange-deep);
  border-radius: var(--vyuu-r-md);
  padding: 10px 18px;
  font: 500 14px/1.2 var(--vyuu-sans);
  box-shadow: var(--vyuu-shadow-md);
  white-space: nowrap;
}
.btn-primary:hover { filter: brightness(0.96); }
@media (max-width: 1100px) {
  .hero { grid-template-columns: 1fr; align-items: stretch; }
  .hero-cta { justify-self: start; }
}

/* Setup card + right rail ------------------------------------------ */
.home-grid {
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(280px, 1fr);
  gap: 18px;
  margin-bottom: 32px;
}
@media (max-width: 1100px) {
  .home-grid { grid-template-columns: 1fr; }
}
.setup-card {
  background: var(--vyuu-orange-mist);
  border: 1px solid var(--vyuu-orange-soft);
  border-radius: var(--vyuu-r-xl);
  padding: 22px 24px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.setup-card h2 {
  font: 500 22px/1.2 var(--vyuu-serif);
  margin: 4px 0 4px;
}
.setup-snippet {
  margin: 12px 0 0;
  padding: 14px;
  background: var(--vyuu-code-bg);
  color: var(--vyuu-code-fg);
  border-radius: var(--vyuu-r-md);
  font: var(--vyuu-mono-sm);
  white-space: pre;
  overflow-x: auto;
  position: relative;
  border: 0;
}
.setup-snippet-copy {
  position: absolute;
  top: 8px;
  right: 8px;
  background: rgba(255,255,255,0.1);
  color: var(--vyuu-code-fg);
  border: 1px solid rgba(255,255,255,0.15);
  padding: 3px 8px;
  font: var(--vyuu-mono-sm);
  border-radius: 4px;
  cursor: pointer;
}
.setup-snippet-copy:hover { background: rgba(255,255,255,0.2); }
.setup-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-top: 6px;
}
.setup-actions button {
  background: var(--vyuu-panel);
  border-color: var(--vyuu-line);
  color: var(--vyuu-ink);
  font: var(--vyuu-ui-sm);
  padding: 7px 12px;
  min-height: auto;
}

.home-rail { display: flex; flex-direction: column; gap: 14px; }
.rail-card {
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  padding: 18px 20px;
}
.rail-card h3 {
  font: 500 18px/1.2 var(--vyuu-serif);
  margin: 4px 0 12px;
}
.rail-list {
  list-style: none;
  margin: 0 0 12px;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.rail-list li {
  display: flex;
  align-items: flex-start;
  gap: 10px;
}
.rail-list-dot {
  width: 7px;
  height: 7px;
  border-radius: 999px;
  background: var(--vyuu-orange-deep);
  margin-top: 7px;
  flex-shrink: 0;
}
.rail-list-dot.locked { background: var(--vyuu-line); }
.rail-list-text { flex: 1; min-width: 0; }
.rail-list-text strong {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-ink);
  display: block;
}
.rail-list-text small {
  font: var(--vyuu-eyebrow);
  letter-spacing: 1.4px;
  color: var(--vyuu-muted);
  text-transform: uppercase;
}
.rail-list-empty {
  color: var(--vyuu-muted);
  font: var(--vyuu-body);
}
.rail-card-cta {
  border: 1px solid var(--vyuu-line);
  background: var(--vyuu-bg);
  color: var(--vyuu-ink);
  font: var(--vyuu-ui-sm);
  padding: 8px 12px;
  width: 100%;
  border-radius: var(--vyuu-r-md);
  cursor: pointer;
  min-height: auto;
}
.pending-card {
  background: var(--vyuu-warn-tint);
  border-color: var(--vyuu-warn);
  color: var(--vyuu-warn-ink);
}
.pending-card h3 { color: var(--vyuu-warn-ink); }

/* Recent calls table (Home + Tool history) -------------------------- */
.recent-section {
  margin-top: 8px;
}
.recent-section-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin: 4px 0 14px;
}
.recent-section-head h2 {
  font: 500 22px/1.2 var(--vyuu-serif);
}
.recent-table {
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  overflow: hidden;
}

/* KPI cards row above the Tool history table — three even columns
   that wrap on narrow viewports. Number is serif + tabular numerals
   for visual weight; eyebrow above is the existing UPPERCASE label. */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
  margin: 0 0 18px;
}
@media (max-width: 720px) {
  .kpi-grid { grid-template-columns: 1fr; }
}
.kpi-card {
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  padding: 16px 18px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.kpi-card h3 {
  font: 400 32px/1.1 var(--vyuu-serif);
  font-variant-numeric: tabular-nums;
  color: var(--vyuu-ink);
  margin: 4px 0 0;
  letter-spacing: -0.5px;
}
.kpi-card[data-kpi="blocked"] h3 { color: var(--vyuu-warn-ink); }
.kpi-card[data-kpi="blocked"][data-alert="true"] {
  background: var(--vyuu-warn-tint);
  border-color: var(--vyuu-warn);
}
.kpi-meta {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-muted);
  margin: 4px 0 0;
}
.kpi-card[data-kpi="blocked"][data-alert="true"] .kpi-meta {
  color: var(--vyuu-warn-ink);
}

/* Table-styled row variant for the Tool history page (the design's
   "When / Tool / vServer / Via / Latency / Outcome" 6-column shape).
   Differs from the Home recent-table 5-col grid: adds an Outcome
   pill column on the right. */
.recent-row.recent-row-history {
  grid-template-columns:
    minmax(120px, auto) minmax(220px, 1.4fr) minmax(180px, 1.2fr)
    minmax(120px, auto) minmax(80px, auto) minmax(70px, auto);
}
.recent-row .outcome-pill {
  font: var(--vyuu-mono-sm);
  padding: 2px 9px;
  border-radius: 999px;
  text-transform: lowercase;
  white-space: nowrap;
  display: inline-block;
}
.recent-row .outcome-pill.allow {
  background: var(--vyuu-orange-soft);
  color: var(--vyuu-orange-deep);
}
.recent-row .outcome-pill.deny,
.recent-row .outcome-pill.block {
  background: var(--vyuu-danger-tint);
  color: var(--vyuu-danger-ink);
}
.recent-row .outcome-pill.error {
  background: var(--vyuu-warn-tint);
  color: var(--vyuu-warn-ink);
}
.recent-row .recent-col-latency-warn { color: var(--vyuu-danger-ink); }
.recent-row {
  display: grid;
  grid-template-columns:
    minmax(110px, auto) minmax(180px, 1fr) minmax(180px, 1fr)
    minmax(140px, auto) minmax(70px, auto);
  align-items: center;
  gap: 16px;
  padding: 12px 18px;
  border-bottom: 1px solid var(--vyuu-line);
  font: var(--vyuu-ui-sm);
}
.recent-row:last-child { border-bottom: 0; }
.recent-row .recent-col-time { color: var(--vyuu-muted); }
.recent-row .recent-col-tool { font: var(--vyuu-mono-sm); color: var(--vyuu-ink); }
.recent-row .recent-col-vserver { color: var(--vyuu-muted); }
.recent-row .recent-col-via { color: var(--vyuu-muted); }
.recent-row .recent-col-latency {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-muted);
  text-align: right;
}
.recent-empty {
  padding: 24px;
  color: var(--vyuu-muted);
  text-align: center;
  font: var(--vyuu-body);
}

/* Catalog + bundle cards ------------------------------------------- */
.catalog-toolbar {
  display: flex;
  gap: 12px;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: 18px;
}
.catalog-toolbar input[type="search"] {
  flex: 1 1 280px;
  min-height: 38px;
  padding: 8px 12px;
}
.filter-pills {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}
.filter-pill {
  appearance: none;
  background: var(--vyuu-bg);
  border: 1px solid var(--vyuu-line);
  color: var(--vyuu-muted);
  padding: 6px 14px;
  border-radius: 999px;
  font: var(--vyuu-ui-sm);
  cursor: pointer;
  min-height: auto;
}
.filter-pill:hover { color: var(--vyuu-ink); }
.filter-pill.is-active {
  background: var(--vyuu-orange-soft);
  border-color: var(--vyuu-orange-deep);
  color: var(--vyuu-orange-deep);
}

.bundle-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(420px, 1fr));
  gap: 16px;
}

/* Connections table — design has 6 columns: Account / Scope / Last
   refreshed / Expires / Status / Action. Renders the same data the
   bundle-card layout did before, but in a denser table format that
   scales when an operator has 10+ linked SaaS accounts. */
.connections-table {
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  overflow: hidden;
}
.connections-table table {
  width: 100%;
  border-collapse: collapse;
  font: var(--vyuu-body);
  font-size: 12.5px;
}
.connections-table thead th {
  text-align: left;
  padding: 12px 16px;
  background: var(--vyuu-ivory);
  border-bottom: 1px solid var(--vyuu-line);
  color: var(--vyuu-muted);
  font: var(--vyuu-eyebrow);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  white-space: nowrap;
}
.connections-table tbody td {
  padding: 12px 16px;
  border-bottom: 1px solid var(--vyuu-line);
  vertical-align: middle;
  color: var(--vyuu-ink);
}
.connections-table tbody tr:last-child td { border-bottom: 0; }
.connections-table .col-account {
  display: flex;
  align-items: center;
  gap: 10px;
  font-weight: 500;
}
.connections-table .col-scope,
.connections-table .col-refreshed,
.connections-table .col-expires {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-muted);
}
.connections-table .col-action button {
  border-color: var(--vyuu-danger);
  background: var(--vyuu-danger-tint);
  color: var(--vyuu-danger-ink);
  padding: 5px 12px;
  font: var(--vyuu-ui-sm);
  min-height: auto;
}
.connections-table-empty {
  padding: 24px 16px;
  color: var(--vyuu-muted);
  text-align: center;
  font: var(--vyuu-body);
}

/* Quick-connect grid — 4 cards (or fewer) showing MCPs the user has
   catalog access to but hasn't OAuth-authorized yet. Saffron icon
   tile + name + sub-line + Connect → CTA. Mirrors the "Clients you
   can connect from" pattern in the design mock. */
.quick-connect-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 14px;
  margin-top: 8px;
}
.quick-connect-card {
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  padding: 16px 18px;
  cursor: pointer;
  text-align: left;
  appearance: none;
  font: inherit;
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.quick-connect-card:hover {
  border-color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-mist);
}
.quick-connect-card-icon {
  width: 36px;
  height: 36px;
  border-radius: 8px;
  background: var(--vyuu-orange-soft);
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 8px;
  color: var(--vyuu-orange-deep);
  font-size: 18px;
  font-weight: 600;
}
.quick-connect-card-name {
  font: 500 15px/1.2 var(--vyuu-serif);
  color: var(--vyuu-ink);
}
.quick-connect-card-sub {
  font: var(--vyuu-eyebrow);
  letter-spacing: 1.4px;
  color: var(--vyuu-muted);
  text-transform: uppercase;
}
.bundle-card {
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  padding: 22px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.bundle-card-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}
.bundle-card-head h3 {
  font: 500 22px/1.2 var(--vyuu-serif);
  letter-spacing: -0.2px;
  font-variant: tabular-nums;
  font-family: var(--vyuu-mono);
  font-size: 17px;
  color: var(--vyuu-ink);
}
.bundle-card-desc {
  font: var(--vyuu-body);
  color: var(--vyuu-muted);
}
.bundle-card-meta {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  margin-top: auto;
}
.bundle-card-meta .pill {
  background: var(--vyuu-line-soft);
  color: var(--vyuu-muted);
  border: 0;
}
.bundle-card-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-top: 14px;
}
.bundle-card-actions .btn-primary {
  padding: 8px 18px;
  font: 500 13px/1.2 var(--vyuu-sans);
}
.bundle-status {
  align-self: flex-start;
  padding: 3px 12px;
  border-radius: 999px;
  font: var(--vyuu-ui-sm);
  letter-spacing: 0.1px;
  white-space: nowrap;
}
.bundle-status.open      { background: var(--vyuu-orange-soft); color: var(--vyuu-orange-deep); }
.bundle-status.needs     { background: var(--vyuu-warn-tint);   color: var(--vyuu-warn-ink); }
.bundle-status.restricted{ background: var(--vyuu-line-soft);   color: var(--vyuu-muted); }
/* JIT-1 · access the user holds but that is running out. Deliberately
   NOT the "open" orange: an outlined pill reads as provisional, which
   is exactly what it is. */
/* JIT-2 · per-tool elevation rows inside a granted bundle card. */
.jit-tools-box {
  margin-top: 12px;
  padding: 10px 12px;
  border-radius: 8px;
  border: 1px dashed var(--vyuu-warn-ink);
  background: var(--vyuu-warn-tint);
}
.jit-tools-head {
  margin: 0 0 6px;
  font-size: 11px;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--vyuu-warn-ink);
}
.jit-tool-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 3px 0;
  font-size: 12.5px;
}
.jit-tool-row code { font-size: 12px; }
.jit-tool-cap { color: var(--vyuu-muted); font-size: 11.5px; }
.jit-tool-row button { margin-left: auto; }

.bundle-status.temporary {
  background: transparent;
  color: var(--vyuu-warn-ink);
  border: 1px dashed var(--vyuu-warn-ink);
}

/* IdP "Continue with X" buttons (mirrors operator console) -------- */
.idp-button-row {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-bottom: 20px;
}
.idp-button-row[hidden] { display: none; }
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

/* Login standalone shell ------------------------------------------- */
.login-shell {
  width: min(640px, calc(100% - 48px));
  margin: 80px auto;
}
.login-head { text-align: center; margin-bottom: 24px; }
.login-head h1 {
  font: 500 36px/1.1 var(--vyuu-serif);
  margin: 8px 0 12px;
}
.login-panel { padding: 28px; }
body[data-portal-active="dashboard"] #login-shell { display: none; }
body[data-portal-active="login"] #dashboard { display: none; }
@media (max-width: 880px) {
  .app-shell { grid-template-columns: 1fr; }
  .sidebar { position: static; height: auto; }
  .content { padding: 18px 16px 60px; }
}

.topbar {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 24px;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--vyuu-line);
}
.eyebrow {
  margin: 0 0 6px;
  color: var(--vyuu-orange-deep);
  font: var(--vyuu-eyebrow);
  letter-spacing: 2.5px;
  text-transform: uppercase;
}
h1 { color: var(--vyuu-ink); font: var(--vyuu-h1); letter-spacing: -0.5px; }
h2 { color: var(--vyuu-ink); font: var(--vyuu-h2); letter-spacing: -0.3px; }
h3 { color: var(--vyuu-ink); font: var(--vyuu-h3); }
p, .hint { color: var(--vyuu-muted); font: var(--vyuu-body); margin: 0; }
.who { display: flex; gap: 12px; align-items: center; }
.who #who-email {
  color: var(--vyuu-ink);
  font: var(--vyuu-ui);
}

.panel {
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  background: var(--vyuu-panel);
  padding: 24px;
  margin-bottom: 16px;
}
.panel-head {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 16px;
  align-items: start;
  margin-bottom: 16px;
}
.panel-head h2 { letter-spacing: -0.3px; }
.panel-head p { margin-top: 6px; color: var(--vyuu-muted); }

/* Tab navigation matches the operator console's pill-rail look. */
.tabs {
  display: flex;
  gap: 4px;
  margin-bottom: 24px;
  padding: 4px;
  background: var(--vyuu-ivory);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  width: fit-content;
}
.tab {
  background: transparent;
  color: var(--vyuu-muted);
  border: none;
  border-radius: var(--vyuu-r-md);
  padding: 8px 16px;
  cursor: pointer;
  font: var(--vyuu-ui);
  letter-spacing: 0.1px;
  transition: background 0.15s, color 0.15s;
  min-height: 36px;
}
.tab:hover { color: var(--vyuu-ink); }
.tab[aria-selected="true"] {
  background: var(--vyuu-panel);
  color: var(--vyuu-orange-deep);
  box-shadow: var(--vyuu-shadow-md);
}

label {
  display: flex;
  flex-direction: column;
  gap: 6px;
  color: var(--vyuu-ink);
  font: var(--vyuu-label);
}

input, select, textarea {
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-md);
  background: var(--vyuu-panel);
  color: var(--vyuu-ink);
  font: var(--vyuu-ui);
}
input, select { min-height: 38px; padding: 8px 12px; }
input::placeholder { color: var(--vyuu-subtle); }

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
  cursor: pointer;
  transition: filter 0.15s, background 0.15s;
}
button:hover { filter: brightness(0.98); }
button[type="submit"], #login-form button, #token-form button,
#issue-key-form button, #password-form button {
  border-color: var(--vyuu-orange-deep);
  background: var(--vyuu-orange-deep);
  color: var(--vyuu-on-primary);
  box-shadow: var(--vyuu-shadow-md);
}
button.ghost {
  background: var(--vyuu-panel);
  color: var(--vyuu-orange-deep);
  border-color: var(--vyuu-orange-soft);
}
button.danger {
  border-color: var(--vyuu-danger);
  background: var(--vyuu-danger-tint);
  color: var(--vyuu-danger-ink);
}

.form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
  margin: 0;
}
.form-grid button { grid-column: 1 / -1; justify-self: start; }

.output {
  min-height: 60px;
  margin-top: 16px;
  padding: 14px;
  overflow: auto;
  border: 1px solid var(--vyuu-line-soft);
  border-radius: var(--vyuu-r-lg);
  background: var(--vyuu-code-bg);
  color: var(--vyuu-code-fg);
  font: var(--vyuu-mono-sm);
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 280px;
}

/* Search bar that sits above the .cards grid. */
.toolbar {
  display: flex;
  gap: 12px;
  align-items: center;
  margin-bottom: 16px;
}
.toolbar input[type="search"] {
  flex: 1;
  min-height: 38px;
  padding: 8px 12px;
  font: var(--vyuu-ui);
}
.toolbar select {
  flex: 0 0 auto;
  min-width: 160px;
}
.toolbar .toolbar-meta {
  color: var(--vyuu-muted);
  font: var(--vyuu-ui-sm);
  white-space: nowrap;
}

/* Card grid — auto-fill so cards sit side-by-side at any viewport,
   wrapping naturally at smaller widths. minmax(280px, 1fr) keeps
   each card legible on mobile but lets two-three columns appear on
   desktop. */
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 16px;
}
.card {
  display: flex;
  flex-direction: column;
  gap: 8px;
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-xl);
  background: var(--vyuu-panel);
  padding: 18px;
  min-height: 0;
}
.card-meta { display: flex; flex-direction: column; gap: 4px; flex: 1; }
.card-meta strong {
  display: block;
  color: var(--vyuu-ink);
  font: var(--vyuu-h3);
  letter-spacing: -0.2px;
}
.card-meta small {
  color: var(--vyuu-muted);
  font: var(--vyuu-mono-sm);
  overflow-wrap: anywhere;
}
.card-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-top: auto;
}

/* Pills (badges) — match operator-side semantics: meaning, not just
   colour. orange = positive/active, warn = advisory, danger = failure,
   info = categorical, neutral = standby. */
.badge, .pill {
  display: inline-flex;
  align-items: center;
  margin: 2px 4px 2px 0;
  padding: 3px 9px;
  border-radius: var(--vyuu-r-pill);
  font: 500 11px/1.3 var(--vyuu-sans);
  letter-spacing: 0.2px;
  background: var(--vyuu-orange-soft);
  color: var(--vyuu-orange-deep);
  border: none;
  text-transform: lowercase;
}
.badge.public, .badge.granted, .badge.approved {
  background: var(--vyuu-orange-soft);
  color: var(--vyuu-orange-deep);
}
.badge.private, .badge.pending {
  background: var(--vyuu-warn-tint);
  color: var(--vyuu-warn-ink);
}
.badge.locked {
  background: var(--vyuu-line-soft);
  color: var(--vyuu-muted);
}
.badge.declined, .badge.withdrawn {
  background: var(--vyuu-danger-tint);
  color: var(--vyuu-danger-ink);
}

.advanced { margin-top: 16px; }
.advanced summary {
  cursor: pointer;
  color: var(--vyuu-muted);
  font: var(--vyuu-ui-sm);
  padding: 6px 0;
}

details { margin-top: 8px; }
details summary {
  cursor: pointer;
  color: var(--vyuu-ink);
  font: var(--vyuu-label);
  padding: 6px 0;
}
details code {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-orange-deep);
}

code {
  font: var(--vyuu-mono-sm);
  color: var(--vyuu-orange-deep);
  padding: 1px 4px;
  background: var(--vyuu-orange-mist);
  border-radius: 4px;
}

/* ==== Interaction states and element defaults (production baseline) ==== */
:focus-visible { outline: 2px solid var(--vyuu-orange); outline-offset: 2px; }
button:focus-visible,
.nav-item:focus-visible,
.filter-pill:focus-visible {
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
button:active:not(:disabled) { transform: translateY(0.5px); filter: brightness(0.96); }
button:disabled, button[disabled] {
  opacity: 0.55;
  cursor: not-allowed;
  filter: none;
  box-shadow: none;
}
button.ghost, .ghost {
  background: transparent; border-color: transparent; color: var(--vyuu-muted); box-shadow: none;
}
button.ghost:hover, .ghost:hover {
  color: var(--vyuu-ink);
  background: var(--vyuu-line-soft);
  filter: none;
}
select, textarea {
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-md);
  background: var(--vyuu-panel);
  color: var(--vyuu-ink);
  font: var(--vyuu-ui);
}
input, select, textarea {
  padding: 8px 10px;
  min-height: 36px;
  transition: border-color 0.12s, box-shadow 0.12s;
}
input::placeholder, textarea::placeholder { color: var(--vyuu-subtle); }
select {
  appearance: none; -webkit-appearance: none; padding-right: 30px;
  background-image:
    linear-gradient(45deg, transparent 50%, var(--vyuu-muted) 50%),
    linear-gradient(135deg, var(--vyuu-muted) 50%, transparent 50%);
  background-position: calc(100% - 15px) 55%, calc(100% - 10px) 55%;
  background-size: 5px 5px, 5px 5px;
  background-repeat: no-repeat;
}
a { color: var(--vyuu-orange-deep); text-decoration-thickness: 1px; text-underline-offset: 2px; }
a:hover { color: var(--vyuu-ink); }
pre code { padding: 0; background: transparent; color: inherit; }
summary { cursor: pointer; color: var(--vyuu-muted); font: var(--vyuu-ui-sm); }
summary:hover { color: var(--vyuu-ink); }
details[open] > summary { margin-bottom: 8px; }
.output { min-height: 0; }
.output.output-status {
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
  border: 1px solid var(--vyuu-danger);
}
.kpi-card h3 {
  font: var(--vyuu-kpi);
  letter-spacing: -1px;
  color: var(--vyuu-ink);
  margin: 6px 0 0;
  font-feature-settings: "tnum";
}
.kpi-meta { margin: 6px 0 0; font: var(--vyuu-ui-sm); color: var(--vyuu-muted); }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    transition-duration: 0.01ms !important;
    animation-duration: 0.01ms !important;
  }
}

/* Sidebar icons are the console's 16px stroke set, not text glyphs. */
.nav-item-icon {
  display: inline-flex;
  width: 18px;
  height: 18px;
  align-items: center;
  justify-content: center;
  font-size: 0;
}
.nav-item-icon svg { width: 16px; height: 16px; }
.nav-item.is-active .nav-item-icon { color: var(--vyuu-orange-deep); }
/* Shown-once key reveal. */
.key-reveal[hidden] { display: none; }
.key-reveal {
  margin-top: 14px;
  padding: 18px 20px;
  border: 1px solid var(--vyuu-orange-soft);
  background: var(--vyuu-orange-mist);
  border-radius: var(--vyuu-r-lg);
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.key-reveal h3 { margin: 0; }
.key-reveal-row { display: flex; gap: 10px; align-items: stretch; flex-wrap: wrap; }
.key-reveal-value {
  flex: 1;
  min-width: 240px;
  padding: 10px 12px;
  background: var(--vyuu-panel);
  border: 1px solid var(--vyuu-line);
  border-radius: var(--vyuu-r-md);
  color: var(--vyuu-ink);
  font: var(--vyuu-mono-sm);
  word-break: break-all;
  user-select: all;
}
.key-reveal-warn { margin: 0; font: var(--vyuu-ui-sm); color: var(--vyuu-danger-ink); }
.key-reveal .ghost { align-self: flex-start; }
/* The same Chakravyuha mark as the operator console. */
.brand-mark { display: inline-flex; align-items: center; line-height: 0; }
.brand-mark svg { width: 28px; height: 28px; display: block; }
.login-sub { margin: 0; font: var(--vyuu-body-lg); color: var(--vyuu-muted); }
.login-panel .form-grid { grid-template-columns: 1fr; gap: 12px; }
.login-panel .form-grid button[type="submit"] { justify-self: start; }
.field-hint { font: var(--vyuu-ui-sm); font-weight: 400; color: var(--vyuu-muted); }
/* ==== Classes the portal's JS renders but nothing styled ==============
   `.pill` (bundle meta), `.outcome-pill` (tool history), the
   connections-table columns and `.card h3` were plain spans and cells.
   Same tokens as the console. */
.pill {
  display: inline-flex;
  align-items: center;
  padding: 3px 9px;
  border-radius: var(--vyuu-r-pill);
  font: 500 11px/1.3 var(--vyuu-sans);
  letter-spacing: 0.2px;
  background: var(--vyuu-orange-soft);
  color: var(--vyuu-orange-deep);
}
.outcome-pill {
  display: inline-flex;
  align-items: center;
  padding: 2px 9px;
  border-radius: var(--vyuu-r-pill);
  font: 600 10.5px/1.4 var(--vyuu-sans);
  letter-spacing: 0.04em;
  text-transform: uppercase;
  background: var(--vyuu-info-tint);
  color: var(--vyuu-info-ink);
}
.outcome-pill.deny { background: var(--vyuu-danger-tint); color: var(--vyuu-danger-ink); }
.outcome-pill.redact,
.outcome-pill.rewrite { background: var(--vyuu-warn-tint); color: var(--vyuu-warn-ink); }
.card h3 { margin: 0; font: var(--vyuu-h3); color: var(--vyuu-ink); }
.card-meta { font: var(--vyuu-ui-sm); color: var(--vyuu-muted); }
.connections-table table {
  width: 100%;
  border-collapse: collapse;
  font: 400 12.5px/1.4 var(--vyuu-sans);
}
.connections-table th {
  padding: 12px 14px;
  text-align: left;
  font: 600 10.5px/1 var(--vyuu-sans);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--vyuu-muted);
  background: var(--vyuu-ivory);
  border-bottom: 1px solid var(--vyuu-line);
}
.connections-table td {
  padding: 12px 14px;
  border-bottom: 1px solid var(--vyuu-line);
  vertical-align: middle;
}
.connections-table tbody tr:last-child td { border-bottom: 0; }
.connections-table tbody tr:hover { background: var(--vyuu-ivory); }
.col-account { display: flex; align-items: center; gap: 8px; font-weight: 500; }
.col-account .rail-list-dot { margin-top: 0; }
.col-scope, .col-refreshed, .col-expires { color: var(--vyuu-muted); font: var(--vyuu-mono-sm); }
.col-action { text-align: right; }
.col-action button { min-height: 30px; padding: 5px 10px; font: var(--vyuu-ui-sm); }
.recent-col-latency { font: var(--vyuu-mono-sm); color: var(--vyuu-muted); text-align: right; }
.recent-col-via { color: var(--vyuu-muted); }
"""


_JS = r"""
const $ = (sel) => document.querySelector(sel);
const STORAGE = sessionStorage;

// =========================================================================
// IDP-1 portal login buttons — "Continue with X" populated as the user
// types their tenant_id. Same shape as the operator console version.
//
// Also pre-fills the tenant_id input from (in order):
//   1. `?tenant=<uuid>` URL query param  — admin shares a bookmark
//      `https://gateway/portal/?tenant=<uuid>` and the user lands
//      with their directory pickers already populated.
//   2. sessionStorage from a previous successful sign-in — so a
//      returning user doesn't re-type even after closing the tab.
// Subdomain-per-tenant routing (`acme.gateway`) is the proper SaaS
// answer; tracked in BACKLOG.
// =========================================================================
{
  const buttonsContainer = document.querySelector("#portal-idp-buttons");
  const tenantIdInput = document.querySelector("#login-tenant-id");
  if (buttonsContainer && tenantIdInput) {
    // Resolution order:
    //   1. `VYUU_DEFAULT_TENANT_ID` configured server-side
    //      (single-tenant on-prem deployment) — `/api/v1/auth/default-tenant`
    //      returns it; we hide the tenant input entirely.
    //   2. `?tenant=<uuid>` URL query param — admin-shared bookmark.
    //   3. sessionStorage from a previous successful sign-in.
    // The first match wins.
    fetch("/api/v1/auth/default-tenant").then(async function(r) {
      if (r.ok) {
        const j = await r.json();
        // Server says "this gateway is bound to tenant X". Hide the
        // input, persist the value, fire the IdP-button fetch.
        tenantIdInput.value = j.tenant_id;
        const tenantLabel = document.querySelector('label[for], label');
        // Hide just the row containing the tenant_id field, not the
        // whole form. The label wraps the input.
        const wrap = tenantIdInput.closest('label');
        if (wrap) wrap.style.display = 'none';
        // Update the welcome copy so it's clear which tenant they're
        // about to sign in to. Target the descriptive subtitle, not the
        // eyebrow (which is the first <p> in .login-head).
        const subhead = document.querySelector('.login-head h1 + p');
        if (subhead) {
          subhead.textContent =
            `Sign in to ${j.display_name} with your work email + password — `
            + `or use one of the SSO buttons below.`;
        }
        sessionStorage.setItem("vyuu.portal.tenant", j.tenant_id);
        scheduleFetch();
        return;
      }
      // No default tenant — multi-tenant deployment. Fall back to
      // URL param / sessionStorage prefill.
      const urlTenant = new URLSearchParams(window.location.search).get("tenant");
      const storedTenant = sessionStorage.getItem("vyuu.portal.tenant");
      const initial = (urlTenant || storedTenant || "").trim();
      if (initial && /^[0-9a-fA-F-]{36}$/.test(initial)) {
        tenantIdInput.value = initial;
        scheduleFetch();
      }
    }).catch(function(){
      // Network error — degrade to the original "type your tenant" UX.
    });
    let lastFetchTenant = null;
    let debounceHandle = null;

    function scheduleFetch() {
      const value = tenantIdInput.value.trim();
      if (!value) {
        buttonsContainer.replaceChildren();
        buttonsContainer.hidden = true;
        lastFetchTenant = null;
        return;
      }
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
          ? '<svg width="16" height="16" viewBox="0 0 18 18" fill="none">'
            + '<rect x="2" y="2" width="6" height="6" fill="currentColor"/>'
            + '<rect x="10" y="2" width="6" height="6" fill="currentColor" opacity="0.7"/>'
            + '<rect x="2" y="10" width="6" height="6" fill="currentColor" opacity="0.7"/>'
            + '<rect x="10" y="10" width="6" height="6" fill="currentColor"/>'
            + '</svg>'
          : '<svg width="16" height="16" viewBox="0 0 18 18" fill="none" '
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
          // User-portal-side flow — mints a portal session JWT, not
          // an operator JWT. SAML uses 302 redirect; OIDC start
          // returns JSON with the IdP authorize_url.
          const base = `/api/v1/auth/${encodeURIComponent(tenantId)}`
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

const state = {
  tenant: STORAGE.getItem("vyuu.portal.tenant") || "",
  token: STORAGE.getItem("vyuu.portal.token") || "",
  user: null,
};

async function api(path, opts = {}) {
  const headers = Object.assign(
    { "content-type": "application/json" },
    opts.headers || {},
    state.token ? { Authorization: `Bearer ${state.token}` } : {},
  );
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = text; }
  return { ok: res.ok, status: res.status, body };
}

function setOutput(sel, ok, body) {
  const el = $(sel);
  el.classList.toggle("error", !ok);
  el.classList.add("has-result");
  el.textContent = typeof body === "string" ? body : JSON.stringify(body, null, 2);
}

// The one thing a user must not get wrong: the key is shown exactly
// once. A bare <pre> saying "copy this NOW" gave them a selectable
// string and nothing else. This gives them a copy button, confirmation
// that the copy happened, and the consequence of not doing it, in
// that order.
function renderIssuedKey(issued) {
  const pre = $("#issued-key-output");
  const card = $("#issued-key-card");
  if (!card) { setOutput("#issued-key-output", true, issued.plaintext); return; }
  pre.hidden = true;
  card.hidden = false;
  card.replaceChildren();
  const eyebrow = document.createElement("p");
  eyebrow.className = "eyebrow";
  eyebrow.textContent = "NEW KEY · SHOWN ONCE";
  const title = document.createElement("h3");
  title.textContent = issued.label ? `${issued.label}` : "Your new API key";
  const row = document.createElement("div");
  row.className = "key-reveal-row";
  const value = document.createElement("code");
  value.className = "key-reveal-value";
  value.textContent = issued.plaintext;
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "btn-primary";
  copy.textContent = "Copy key";
  copy.addEventListener("click", async () => {
    const ok = await copyToClipboard(issued.plaintext);
    copy.textContent = ok ? "Copied ✓" : "Copy failed — select it";
    setTimeout(() => { copy.textContent = "Copy key"; }, 2500);
  });
  row.append(value, copy);
  const warn = document.createElement("p");
  warn.className = "key-reveal-warn";
  warn.textContent = "Store it now — it cannot be shown again. If you lose it, revoke "
    + "this key and issue a new one.";
  const done = document.createElement("button");
  done.type = "button";
  done.className = "ghost";
  done.textContent = "I have saved it";
  done.addEventListener("click", () => {
    card.hidden = true;
    card.replaceChildren();
    pre.hidden = false;
    setOutput("#issued-key-output", true, "Key issued and hidden. Issue another if you need one.");
  });
  card.append(eyebrow, title, row, warn, done);
}

async function copyToClipboard(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (_) { /* fall through to the legacy path */ }
  try {
    const scratch = document.createElement("textarea");
    scratch.value = text;
    scratch.setAttribute("readonly", "");
    scratch.style.position = "fixed";
    scratch.style.opacity = "0";
    document.body.appendChild(scratch);
    scratch.select();
    const ok = document.execCommand("copy");
    scratch.remove();
    return ok;
  } catch (_) {
    return false;
  }
}

function showLogin() {
  document.body.dataset.portalActive = "login";
}

function showDashboard() {
  document.body.dataset.portalActive = "dashboard";
  paintUserPill();
  paintEnvPill();
  // OIDC users (Microsoft / Google) can't change a password; hide the
  // Settings nav item + panel entirely for them. Local-auth keeps both.
  const isLocalAuth = state.user && state.user.auth_method === "local";
  const settingsBtn = $("#tab-settings");
  if (settingsBtn) settingsBtn.hidden = !isLocalAuth;
  const passwordPanel = $("#password-panel");
  if (passwordPanel) passwordPanel.hidden = !isLocalAuth;
  // Restore last-visited nav, default to home.
  const last = STORAGE.getItem("vyuu.portal.nav") || "home";
  setActivePortalNav(last);
  refreshAll();
}

async function paintEnvPill() {
  // Surface the gateway's actual environment + version in the topbar
  // pill (was hardcoded `gateway · v1.0.0`). Reads `/api/v1/health`
  // which is unauthenticated, so this works pre-sign-in too. The
  // status dot turns red on a fetch failure (gateway down) — matches
  // the operator console's sidebar gateway-status-pill semantics.
  const text = $("#env-pill-text");
  const dot = document.querySelector("#env-pill .env-pill-dot");
  if (!text) return;
  try {
    const res = await fetch("/api/v1/health");
    if (!res.ok) throw new Error(String(res.status));
    const body = await res.json();
    const env = (body.environment || "gateway").toLowerCase();
    const version = body.version || "v?";
    // Render as "<env> · <version>". When environment === "local"
    // (the lab boot), the prefix already reads "local"; for prod
    // deploys it'll read "prod" / "staging" / etc.
    text.textContent = `${env} · ${version}`;
    if (dot) dot.style.background = "var(--vyuu-orange-deep)";
  } catch {
    text.textContent = "gateway · offline";
    if (dot) dot.style.background = "var(--vyuu-danger)";
  }
}

function paintUserPill() {
  const email = $("#who-email");
  const meta = $("#user-pill-meta");
  if (email) email.textContent = state.user ? state.user.email : "—";
  if (meta && state.user) {
    meta.textContent = `${state.user.auth_method || "local"} · `
      + (state.user.tenant_id ? state.user.tenant_id.slice(0, 8) + "…" : "");
  }
}

// Backwards-compat alias — older callers (in this file's bootstrap +
// nav handler below) still invoke selectTab; keep the symbol working.
function selectTab(name) { setActivePortalNav(name); }

function setActivePortalNav(navId) {
  if (!navId) return;
  STORAGE.setItem("vyuu.portal.nav", navId);
  // Section visibility — toggle [data-portal-nav] panels.
  for (const sec of document.querySelectorAll("[data-portal-nav]")) {
    if (sec.tagName !== "SECTION" && !sec.classList.contains("panel-area")) continue;
    sec.hidden = sec.dataset.portalNav !== navId;
  }
  // Sidebar nav active state.
  for (const item of document.querySelectorAll(".nav-item")) {
    item.classList.toggle("is-active", item.dataset.portalNav === navId);
  }
  // Topbar breadcrumb.
  const labelMap = {
    home: "Home",
    catalog: "Tool catalog",
    connections: "Connections",
    "api-keys": "API keys",
    "my-requests": "My requests",
    "tool-history": "Tool history",
    settings: "Settings",
  };
  const bc = $("#breadcrumb-section");
  if (bc) bc.textContent = labelMap[navId] || navId;
  // Auto-load the panel's data.
  const loaders = {
    home:           refreshHome,
    catalog:        refreshCatalog,
    connections:    refreshConnections,
    "api-keys":     refreshKeys,
    "my-requests":  refreshRequests,
    "tool-history": refreshToolHistory,
    settings:       () => {},  // settings is form-only
  };
  const loader = loaders[navId];
  if (typeof loader === "function") {
    try { loader(); } catch {}
  }
}

document.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  // Sidebar nav button click.
  const navBtn = target.closest("[data-portal-nav]");
  if (navBtn && navBtn.tagName === "BUTTON" && navBtn.classList.contains("nav-item")) {
    const name = navBtn.dataset.portalNav;
    if (name) setActivePortalNav(name);
    return;
  }
  // CTAs that link to a different nav target ("Browse catalog →", etc.).
  const navTargetEl = target.closest("[data-portal-nav-target]");
  if (navTargetEl) {
    const name = navTargetEl.dataset.portalNavTarget;
    if (name) setActivePortalNav(name);
  }
});

async function loadWhoami() {
  const r = await api(`/api/v1/portal/${state.tenant}/me`);
  if (!r.ok) {
    state.token = "";
    STORAGE.removeItem("vyuu.portal.token");
    return null;
  }
  return r.body;
}

async function bootstrap() {
  if (state.tenant && state.token) {
    state.user = await loadWhoami();
    if (state.user) {
      showDashboard();
      return;
    }
  }
  showLogin();
}

// --- Login forms -----------------------------------------------------------

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const tenant = f.get("tenant_id").trim();
  const email = f.get("email").trim();
  const password = f.get("password");
  if (!tenant || !email || !password) {
    setOutput("#login-output", false, "tenant, email, and password required");
    return;
  }
  const r = await fetch(`/api/v1/auth/${tenant}/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const body = await r.json();
  if (!r.ok) { setOutput("#login-output", false, body); return; }
  state.tenant = tenant;
  state.token = body.session_token;
  STORAGE.setItem("vyuu.portal.tenant", tenant);
  STORAGE.setItem("vyuu.portal.token", body.session_token);
  state.user = await loadWhoami();
  if (state.user) showDashboard();
  else setOutput("#login-output", false, "session token issued but whoami failed");
});

$("#token-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const tenant = $("#login-form").elements.tenant_id.value.trim();
  const tok = $("#paste-token").value.trim();
  if (!tenant || !tok) { setOutput("#login-output", false, "tenant and token required"); return; }
  state.tenant = tenant; state.token = tok;
  STORAGE.setItem("vyuu.portal.tenant", tenant);
  STORAGE.setItem("vyuu.portal.token", tok);
  state.user = await loadWhoami();
  if (state.user) showDashboard();
  else setOutput("#login-output", false, "token rejected");
});

$("#logout").addEventListener("click", () => {
  state.token = ""; state.user = null;
  STORAGE.removeItem("vyuu.portal.token");
  showLogin();
});

// --- Catalog ---------------------------------------------------------------

// Cached catalog rows so search/filter operate over local data without
// re-hitting the API on every keystroke.
let catalogCache = [];

async function refreshCatalog() {
  const r = await api(`/api/v1/portal/${state.tenant}/catalog`);
  if (!r.ok) { setOutput("#catalog-output", false, r.body); return; }
  catalogCache = Array.isArray(r.body) ? r.body : [];
  renderCatalog();
}

function renderCatalog() {
  const out = $("#catalog-output");
  const countEl = $("#catalog-count");
  out.innerHTML = "";
  if (!catalogCache.length) {
    out.textContent = "(no virtual servers in tenant)";
    countEl.textContent = "";
    return;
  }
  const needle = ($("#catalog-search").value || "").trim().toLowerCase();
  const accessFilter = activeFilter("catalog");  // all | open | needs-request | restricted
  const filtered = catalogCache.filter((v) => {
    if (needle) {
      const hay = `${v.name} ${v.vserver_id} ${v.description || ""}`.toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    // Visibility-based bundle filter:
    //   open           → has_access = true
    //   needs-request  → !has_access && visibility == private
    //   restricted     → !has_access && visibility != public (catch-all)
    if (accessFilter === "open" && !v.has_access) return false;
    if (accessFilter === "needs-request" && v.has_access) return false;
    if (accessFilter === "restricted" && v.has_access) return false;
    return true;
  });
  countEl.textContent = `${filtered.length} of ${catalogCache.length}`;
  if (!filtered.length) {
    out.textContent = "(no vservers match the current filters)";
    return;
  }
  for (const v of filtered) {
    out.appendChild(renderCatalogCard(v));
  }
}

// JIT-1 · request a time-boxed elevation.
//
// The policy comes from the server (`/jit-options`) rather than being
// hard-coded here: the ceiling and the preset list are the vserver's,
// and offering a duration the server will reject is a worse experience
// than offering fewer choices.
async function requestJitAccess(v) {
  const opts = await api(
    `/api/v1/portal/${state.tenant}/vservers/${v.vserver_id}/jit-options`
  );
  if (!opts.ok) { alert(JSON.stringify(opts.body)); return; }
  const policy = opts.body;
  if (!policy.jit_enabled) {
    alert("This bundle no longer offers temporary access.");
    await refreshCatalog();
    return;
  }

  const presets = policy.duration_presets_seconds || [];
  const menu = presets.map((sec, i) => `  ${i + 1}. ${formatDuration(sec)}`).join("\n");
  const answer = prompt(
    `How long do you need "${v.name}"?\n\n${menu}\n\n` +
    `Enter a number from the list, or minutes directly ` +
    `(max ${formatDuration(policy.max_duration_seconds)}).`,
    "1",
  );
  if (answer === null) return;

  const picked = Number(answer);
  if (!Number.isFinite(picked) || picked <= 0) {
    alert("Enter a number from the list, or a number of minutes.");
    return;
  }
  // A small number is a menu index; anything larger is a literal
  // minute count. Ambiguous only up to the preset count, and the menu
  // is right there.
  const seconds = picked <= presets.length
    ? presets[Math.round(picked) - 1]
    : Math.round(picked * 60);

  let justification = null;
  if (policy.require_justification) {
    justification = prompt(
      `Why do you need access to "${v.name}"?\n\n` +
      `This is recorded in the audit log and shown to your administrators.`
    );
    // Cancel aborts; an empty string would be rejected by the server
    // anyway, so catch it here with a clearer message.
    if (justification === null) return;
    if (!justification.trim()) {
      alert("A reason is required for this bundle.");
      return;
    }
  }

  const res = await api(`/api/v1/portal/${state.tenant}/jit-requests`, {
    method: "POST",
    body: JSON.stringify({
      vserver_id: v.vserver_id,
      duration_seconds: seconds,
      justification,
    }),
  });
  if (!res.ok) { alert(res.body && res.body.detail || JSON.stringify(res.body)); return; }

  if (res.body.granted) {
    alert(
      `Access granted until ${new Date(res.body.expires_at).toLocaleString()}.\n\n` +
      `It ends automatically — no need to hand it back.`
    );
    await refreshCatalog();
  } else {
    alert("Sent for approval. You'll see it under My requests.");
    refreshRequests();
  }
}

// JIT-2 · elevate into a single tool.
//
// Fetches live state first so a user who is already elevated is told so
// rather than being walked through a request that will 409 — the server
// is the authority on both the ceiling and whether they are already in.
async function requestToolElevation(v, toolName) {
  const opts = await api(
    `/api/v1/portal/${state.tenant}/vservers/${v.vserver_id}/tool-elevation-options`
  );
  if (!opts.ok) { alert(JSON.stringify(opts.body)); return; }
  const policy = opts.body;

  if (!policy.has_vserver_access) {
    alert(
      `You need access to "${v.name}" before you can elevate into one of ` +
      `its tools. A tool elevation narrows the access you have — it does ` +
      `not grant it.`
    );
    return;
  }
  const already = (policy.active_tool_elevations || {})[toolName];
  if (already) {
    alert(
      `You are already elevated into ${toolName} until ` +
      `${new Date(already).toLocaleString()}.`
    );
    return;
  }
  const ceiling = (policy.jit_tools || {})[toolName];
  if (!ceiling) {
    alert(`${toolName} no longer requires an elevation.`);
    await refreshCatalog();
    return;
  }

  const answer = prompt(
    `Elevate into ${toolName}?\n\n` +
    `How many minutes do you need? (max ${formatDuration(ceiling)})`,
    String(Math.min(15, Math.round(ceiling / 60))),
  );
  if (answer === null) return;
  const minutes = Number(answer);
  if (!Number.isFinite(minutes) || minutes <= 0) {
    alert("Enter a positive number of minutes.");
    return;
  }

  let justification = null;
  if (policy.require_justification) {
    justification = prompt(
      `Why do you need ${toolName}?\n\n` +
      `This is recorded in the audit log and shown to your administrators.`
    );
    if (justification === null) return;
    if (!justification.trim()) {
      alert("A reason is required.");
      return;
    }
  }

  const res = await api(`/api/v1/portal/${state.tenant}/tool-elevations`, {
    method: "POST",
    body: JSON.stringify({
      vserver_id: v.vserver_id,
      exposed_tool_name: toolName,
      duration_seconds: Math.round(minutes * 60),
      justification,
    }),
  });
  if (!res.ok) {
    alert(res.body && res.body.detail || JSON.stringify(res.body));
    return;
  }
  if (res.body.granted) {
    alert(
      `${toolName} is available until ` +
      `${new Date(res.body.expires_at).toLocaleString()}.\n\n` +
      `It ends automatically.`
    );
  } else {
    alert("Sent for approval. You'll see it under My requests.");
    refreshRequests();
  }
}

// "42m", "3h 10m", "2d" — same vocabulary the operator console uses.
function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d) return h ? `${d}d ${h}h` : `${d}d`;
  if (h) return m ? `${h}h ${m}m` : `${h}h`;
  return `${m || 1}m`;
}

function formatTimeLeft(isoTimestamp) {
  const ms = Date.parse(isoTimestamp) - Date.now();
  if (!Number.isFinite(ms) || ms <= 0) return "expired";
  return `${formatDuration(Math.floor(ms / 1000))} left`;
}

function renderCatalogCard(v) {
  // Bundle-card layout — matches the Claude Design mock:
  //   header row : bundle name (mono, prominent) · status pill (right)
  //   description line : short copy / fall back to "(no description)"
  //   meta pill row : "N tools" · auth mode · group / visibility
  //   action row : Connect (granted) / Request access (locked) /
  //                Show config (granted, expandable) / Reconnect/Connect
  //                per-upstream OAuth.
  const el = document.createElement("article");
  el.className = "bundle-card";

  // Per-user-auth state — drives the status pill and CTAs below.
  const required = Array.isArray(v.requires_user_auth_servers)
    ? v.requires_user_auth_servers : [];
  const oauthFullyConnected = required.length
    ? required.every((s) => s.connected)
    : true;

  const head = document.createElement("div");
  head.className = "bundle-card-head";
  const title = document.createElement("h3");
  title.textContent = v.name;
  head.appendChild(title);

  const status = document.createElement("span");
  status.className = "bundle-status";
  if (v.has_access && v.access_expires_at) {
    // JIT-1: access the user holds RIGHT NOW that will end on its own.
    // Saying "Open to you" here would be true but misleading — their
    // tools stop working when it lapses, and nobody warned them.
    status.classList.add("temporary");
    status.textContent = `Temporary · ${formatTimeLeft(v.access_expires_at)}`;
    status.title = `Access expires ${new Date(v.access_expires_at).toLocaleString()}`;
  } else if (v.has_access) {
    status.classList.add("open");
    status.textContent = oauthFullyConnected ? "Open to you" : "Connect SaaS";
  } else if (v.jit_enabled) {
    status.classList.add("needs");
    status.textContent = v.jit_auto_approve ? "Instant access" : "Needs request";
  } else if (v.visibility === "private") {
    status.classList.add("needs");
    status.textContent = "Needs request";
  } else {
    status.classList.add("restricted");
    status.textContent = "Restricted";
  }
  head.appendChild(status);
  el.appendChild(head);

  if (v.description) {
    const desc = document.createElement("p");
    desc.className = "bundle-card-desc";
    desc.textContent = v.description;
    el.appendChild(desc);
  }

  // Meta pill row — visibility + (when granted) per-upstream OAuth status.
  const metaRow = document.createElement("div");
  metaRow.className = "bundle-card-meta";
  const visPill = document.createElement("span");
  visPill.className = "pill";
  visPill.textContent = v.visibility || "private";
  metaRow.appendChild(visPill);
  if (required.length) {
    const oauthPill = document.createElement("span");
    oauthPill.className = "pill";
    const ok = required.filter((s) => s.connected).length;
    oauthPill.textContent = `OAuth ${ok}/${required.length}`;
    metaRow.appendChild(oauthPill);
  }
  el.appendChild(metaRow);

  const actions = document.createElement("div");
  actions.className = "bundle-card-actions";
  el.appendChild(actions);

  // For each wrapped upstream that needs per-user OAuth, add a Connect
  // button (or Reconnect if already connected). Click opens the IdP's
  // authorisation URL in a new tab; the gateway's /callback finishes
  // the flow.
  if (v.has_access && required.length) {
    for (const srv of required) {
      const btn = document.createElement("button");
      btn.className = srv.connected ? "ghost" : "";
      btn.textContent = srv.connected
        ? `Reconnect ${srv.server_display_name}`
        : `Connect ${srv.server_display_name}`;
      btn.onclick = async () => {
        const r = await api(
          `/api/v1/oauth-authcode/${srv.server_id}/initiate`,
          { method: "POST", body: JSON.stringify({}) },
        );
        if (!r.ok) { alert(JSON.stringify(r.body)); return; }
        // Bounce the user through the IdP. We open in the same tab so
        // the back-button returns them to the portal naturally.
        window.location.href = r.body.authorization_url;
      };
      actions.appendChild(btn);
    }
  }

  if (!v.has_access && v.jit_enabled) {
    // JIT-1 · time-boxed elevation. Distinct button from the standing
    // "Request access" below because the ask is genuinely different:
    // the user is choosing a window, not petitioning for permanence.
    const btn = document.createElement("button");
    btn.className = "btn-primary";
    btn.textContent = v.jit_auto_approve
      ? "Get temporary access →"
      : "Request temporary access →";
    btn.onclick = () => requestJitAccess(v);
    actions.appendChild(btn);
  } else if (!v.has_access) {
    const btn = document.createElement("button");
    btn.className = "btn-primary";
    btn.textContent = "Request access →";
    btn.onclick = async () => {
      const note = prompt("Why do you need access? (optional)") || "";
      const sub = await api(`/api/v1/portal/${state.tenant}/access-requests`, {
        method: "POST",
        body: JSON.stringify({ vserver_id: v.vserver_id, note }),
      });
      if (sub.ok) refreshRequests();
      else alert(JSON.stringify(sub.body));
    };
    actions.appendChild(btn);
  } else {
    // JIT-2 · elevation-gated tools. Only meaningful once the user HAS
    // bundle access — a tool elevation narrows, it never grants — so this
    // lives in the granted branch. Rendered as one row per gated tool
    // rather than a single button, because the user is choosing *which*
    // dangerous thing they need, not just "more access".
    const gatedTools = Object.keys(v.jit_tools || {});
    if (gatedTools.length) {
      const box = document.createElement("div");
      box.className = "jit-tools-box";
      const head = document.createElement("p");
      head.className = "jit-tools-head";
      head.textContent = "Tools needing temporary elevation";
      box.appendChild(head);
      for (const toolName of gatedTools.sort()) {
        const row = document.createElement("div");
        row.className = "jit-tool-row";
        const name = document.createElement("code");
        name.textContent = toolName;
        row.appendChild(name);
        const cap = document.createElement("span");
        cap.className = "jit-tool-cap";
        cap.textContent = `up to ${formatDuration(v.jit_tools[toolName])}`;
        row.appendChild(cap);
        const btn = document.createElement("button");
        btn.className = "ghost";
        btn.textContent = "Elevate →";
        btn.onclick = () => requestToolElevation(v, toolName);
        row.appendChild(btn);
        box.appendChild(row);
      }
      el.appendChild(box);
    }

    // Granted bundle — primary CTA is "Connect" (shows config snippets).
    const connectBtn = document.createElement("button");
    connectBtn.className = "btn-primary";
    connectBtn.textContent = "Connect →";
    actions.appendChild(connectBtn);

    const configBox = document.createElement("div");
    configBox.style.marginTop = "12px";
    configBox.hidden = true;
    el.appendChild(configBox);

    connectBtn.onclick = () => {
      configBox.hidden = !configBox.hidden;
      connectBtn.textContent = configBox.hidden ? "Connect →" : "Hide config";
      if (!configBox.hidden) renderConfigSnippets(configBox, v);
    };
  }
  return el;
}

function renderConfigSnippets(container, vserver) {
  const url = `${window.location.origin}/v/${state.tenant}/${vserver.name}/mcp`;
  const placeholder = "<YOUR_API_KEY>";

  const cursorConfig = JSON.stringify(
    {
      mcpServers: {
        [`${vserver.name}-via-vyuu`]: {
          url,
          type: "streamable-http",
          headers: { Authorization: `Bearer ${placeholder}` },
        },
      },
    },
    null,
    2,
  );

  const claudeConfig = JSON.stringify(
    {
      mcpServers: {
        [`${vserver.name}-via-vyuu`]: {
          command: "npx",
          args: [
            "-y",
            "mcp-remote",
            url,
            "--header",
            `Authorization:Bearer ${placeholder}`,
          ],
        },
      },
    },
    null,
    2,
  );

  container.innerHTML = `
    <p style="font-size: 0.8rem; color: var(--muted); margin: 0 0 0.5rem;">
      Replace <code>${placeholder}</code> with one of your API keys from the
      "My API keys" panel below. Issue a new key first if you don't have one.
    </p>
    <details open>
      <summary style="cursor: pointer; font-size: 0.85rem;">
        Cursor (paste into <code>~/.cursor/mcp.json</code>)
      </summary>
      <pre class="output" data-snippet="cursor"></pre>
      <button class="ghost" data-copy="cursor">Copy</button>
    </details>
    <details style="margin-top: 0.5rem;">
      <summary style="cursor: pointer; font-size: 0.85rem;">
        Claude Desktop (uses <code>mcp-remote</code> bridge — paste into
        <code>claude_desktop_config.json</code>)
      </summary>
      <pre class="output" data-snippet="claude"></pre>
      <button class="ghost" data-copy="claude">Copy</button>
    </details>
    <p style="font-size: 0.75rem; color: var(--muted); margin-top: 0.5rem;">
      Endpoint: <code>${escapeHtml(url)}</code>
    </p>`;

  container.querySelector('[data-snippet="cursor"]').textContent = cursorConfig;
  container.querySelector('[data-snippet="claude"]').textContent = claudeConfig;

  for (const btn of container.querySelectorAll("[data-copy]")) {
    btn.addEventListener("click", () => {
      const which = btn.getAttribute("data-copy");
      const snippet = container.querySelector(`[data-snippet="${which}"]`).textContent;
      navigator.clipboard.writeText(snippet).then(
        () => {
          btn.textContent = "Copied!";
          setTimeout(() => { btn.textContent = "Copy"; }, 1200);
        },
        () => { btn.textContent = "Copy failed"; },
      );
    });
  }
}

// --- My requests -----------------------------------------------------------

// Cached server-side state for the My-requests panel — keeps search /
// filter operations local once the data is fetched.
let requestsCache = [];

async function refreshRequests() {
  const r = await api(`/api/v1/portal/${state.tenant}/access-requests`);
  if (!r.ok) { setOutput("#requests-output", false, r.body); return; }
  requestsCache = Array.isArray(r.body) ? r.body : [];
  renderRequests();
}

function renderRequests() {
  const out = $("#requests-output");
  const countEl = $("#requests-count");
  out.innerHTML = "";
  if (!requestsCache.length) {
    out.textContent = "(no requests yet)";
    countEl.textContent = "";
    return;
  }
  const needle = ($("#requests-search").value || "").trim().toLowerCase();
  const status = activeFilter("requests");
  const filtered = requestsCache.filter((req) => {
    if (status && req.status !== status) return false;
    if (needle) {
      const hay = `${req.vserver_id || ""} ${req.note || ""} ${req.decision_note || ""}`
        .toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    return true;
  });
  countEl.textContent = `${filtered.length} of ${requestsCache.length}`;
  if (!filtered.length) {
    out.textContent = "(no requests match the current filters)";
    return;
  }
  for (const req of filtered) out.appendChild(renderRequestCard(req));
}

function renderRequestCard(req) {
  const el = document.createElement("div");
  el.className = "card";

  const meta = document.createElement("div");
  meta.className = "card-meta";
  const decision = req.decision_note
    ? " · decision: " + escapeHtml(req.decision_note)
    : "";
  meta.innerHTML = `
    <strong>vserver ${escapeHtml(String(req.vserver_id))}</strong>
    <div><span class="badge ${req.status}">${req.status}</span></div>
    <small>${escapeHtml(req.note || "(no note)")}</small>
    <small>submitted ${req.created_at}${decision}</small>`;
  el.appendChild(meta);

  if (req.status === "pending") {
    const actions = document.createElement("div");
    actions.className = "card-actions";
    const btn = document.createElement("button");
    btn.className = "danger";
    btn.textContent = "Withdraw";
    btn.onclick = async () => {
      await api(`/api/v1/portal/${state.tenant}/access-requests/${req.id}`,
                { method: "DELETE" });
      refreshRequests();
    };
    actions.appendChild(btn);
    el.appendChild(actions);
  }
  return el;
}

// --- API keys --------------------------------------------------------------

let keysCache = [];

async function refreshKeys() {
  const r = await api(`/api/v1/portal/${state.tenant}/api-keys`);
  if (!r.ok) { setOutput("#keys-output", false, r.body); return; }
  keysCache = Array.isArray(r.body) ? r.body : [];
  renderKeys();
}

function renderKeys() {
  const out = $("#keys-output");
  const countEl = $("#keys-count");
  out.innerHTML = "";
  if (!keysCache.length) {
    out.textContent = "(no keys issued)";
    countEl.textContent = "";
    return;
  }
  const needle = ($("#keys-search").value || "").trim().toLowerCase();
  const status = activeFilter("keys");
  const filtered = keysCache.filter((k) => {
    if (status === "active" && k.revoked_at) return false;
    if (status === "revoked" && !k.revoked_at) return false;
    if (needle) {
      const hay = `${k.label} ${k.key_prefix}`.toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    return true;
  });
  countEl.textContent = `${filtered.length} of ${keysCache.length}`;
  if (!filtered.length) {
    out.textContent = "(no keys match the current filters)";
    return;
  }
  for (const k of filtered) out.appendChild(renderKeyCard(k));
}

function renderKeyCard(k) {
  const el = document.createElement("div");
  el.className = "card";

  const meta = document.createElement("div");
  meta.className = "card-meta";
  const status = k.revoked_at
    ? '<span class="badge locked">revoked</span>'
    : '<span class="badge granted">active</span>';
  meta.innerHTML = `
    <strong>${escapeHtml(k.label)}</strong>
    <div>${status}</div>
    <small>prefix ${escapeHtml(k.key_prefix)}…</small>
    <small>created ${k.created_at}</small>
    <small>last used ${k.last_used_at || "never"}</small>`;
  el.appendChild(meta);

  if (!k.revoked_at) {
    const actions = document.createElement("div");
    actions.className = "card-actions";
    const btn = document.createElement("button");
    btn.className = "danger";
    btn.textContent = "Revoke";
    btn.onclick = async () => {
      await api(`/api/v1/portal/${state.tenant}/api-keys/${k.id}`,
                { method: "DELETE" });
      refreshKeys();
    };
    actions.appendChild(btn);
    el.appendChild(actions);
  }
  return el;
}

$("#issue-key-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const r = await api(`/api/v1/portal/${state.tenant}/api-keys`, {
    method: "POST",
    body: JSON.stringify({ label: f.get("label") }),
  });
  if (r.ok) {
    renderIssuedKey(r.body);
    e.target.reset();
    refreshKeys();
  } else {
    setOutput("#issued-key-output", false, r.body);
  }
});

// --- Connected accounts ----------------------------------------------------

let connectionsCache = [];

async function refreshConnections() {
  const r = await api(`/api/v1/oauth-authcode/connections`);
  if (!r.ok) { setOutput("#connections-output", false, r.body); return; }
  connectionsCache = Array.isArray(r.body) ? r.body : [];
  renderConnections();
}

function renderConnections() {
  paintConnectionsTable();
  paintQuickConnect();
}

function paintConnectionsTable() {
  const out = $("#connections-output");
  if (!out) return;
  out.innerHTML = "";
  if (!connectionsCache.length) {
    const empty = document.createElement("p");
    empty.className = "connections-table-empty";
    empty.textContent =
      "No SaaS accounts linked yet. Click Connect on a catalog card "
      + "or pick one below to authorise.";
    out.appendChild(empty);
    return;
  }
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  thead.innerHTML = "<tr>"
    + "<th>Account</th>"
    + "<th>Scope</th>"
    + "<th>Last refreshed</th>"
    + "<th>Expires</th>"
    + "<th></th>"
    + "</tr>";
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  for (const c of connectionsCache) {
    tbody.appendChild(renderConnectionRow(c));
  }
  table.appendChild(tbody);
  out.appendChild(table);
}

function renderConnectionRow(c) {
  // Friendly relative-time helper.
  const rel = (iso) => {
    if (!iso) return "—";
    const ms = Date.now() - new Date(iso).getTime();
    if (Number.isNaN(ms)) return "—";
    const m = Math.floor(ms / 60000);
    if (m < 1) return "just now";
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    const d = Math.floor(h / 24);
    return `${d}d ago`;
  };

  const tr = document.createElement("tr");

  const tdAccount = document.createElement("td");
  const accountWrap = document.createElement("div");
  accountWrap.className = "col-account";
  const dot = document.createElement("span");
  dot.className = "rail-list-dot";
  accountWrap.appendChild(dot);
  const name = document.createElement("span");
  name.textContent = c.server_display_name;
  accountWrap.appendChild(name);
  tdAccount.appendChild(accountWrap);
  tr.appendChild(tdAccount);

  const tdScope = document.createElement("td");
  tdScope.className = "col-scope";
  tdScope.textContent = c.scope || "(default)";
  tr.appendChild(tdScope);

  const tdRefreshed = document.createElement("td");
  tdRefreshed.className = "col-refreshed";
  tdRefreshed.textContent = rel(c.last_refreshed_at);
  tr.appendChild(tdRefreshed);

  const tdExpires = document.createElement("td");
  tdExpires.className = "col-expires";
  tdExpires.textContent = c.expires_at
    ? new Date(c.expires_at).toLocaleDateString()
    : "no expiry";
  tr.appendChild(tdExpires);

  const tdAction = document.createElement("td");
  tdAction.className = "col-action";
  const btn = document.createElement("button");
  btn.textContent = "Disconnect";
  btn.onclick = async () => {
    const msg = `Disconnect ${c.server_display_name}? Tool calls that `
              + `need this account will fail until you reconnect.`;
    if (!confirm(msg)) return;
    await api(`/api/v1/oauth-authcode/${c.server_id}/connection`,
              { method: "DELETE" });
    refreshConnections();
    refreshCatalog();
  };
  tdAction.appendChild(btn);
  tr.appendChild(tdAction);
  return tr;
}

function paintQuickConnect() {
  // MCPs the user has catalog access to that *require* per-user OAuth
  // but aren't yet connected. Surfaces a one-click path to authorise
  // alongside the existing per-bundle Connect → flow.
  const grid = $("#quick-connect-grid");
  const wrap = $("#quick-connect-section");
  if (!grid || !wrap) return;
  const candidates = (catalogCache || []).flatMap((v) =>
    (v.requires_user_auth_servers || [])
      .filter((s) => !s.connected)
      .map((s) => ({ ...s, vserver_name: v.name })),
  );
  // De-dupe by server_id (multiple vservers may wrap the same upstream).
  const seen = new Set();
  const unique = [];
  for (const c of candidates) {
    if (seen.has(c.server_id)) continue;
    seen.add(c.server_id);
    unique.push(c);
  }
  if (!unique.length) {
    wrap.hidden = true;
    return;
  }
  wrap.hidden = false;
  grid.innerHTML = "";
  for (const c of unique) {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "quick-connect-card";
    const icon = document.createElement("div");
    icon.className = "quick-connect-card-icon";
    icon.textContent = (c.server_display_name[0] || "?").toUpperCase();
    card.appendChild(icon);
    const name = document.createElement("div");
    name.className = "quick-connect-card-name";
    name.textContent = c.server_display_name;
    card.appendChild(name);
    const sub = document.createElement("div");
    sub.className = "quick-connect-card-sub";
    sub.textContent = "OAUTH · CONNECT TO AUTHORIZE";
    card.appendChild(sub);
    card.onclick = async () => {
      const r = await api(
        `/api/v1/oauth-authcode/${c.server_id}/initiate`,
        { method: "POST", body: JSON.stringify({}) },
      );
      if (!r.ok) { alert(JSON.stringify(r.body)); return; }
      window.location.href = r.body.authorization_url;
    };
    grid.appendChild(card);
  }
}

// Backcompat shim — `renderConnectionCard` was the original card-grid
// factory, now superseded by `renderConnectionRow` (table layout).
// Returns a wrapper div so any old caller that did `el.appendChild`
// against the result still works. Most callers have been migrated.
function renderConnectionCard(c) {
  const wrapper = document.createElement("div");
  wrapper.appendChild(renderConnectionRow(c));
  return wrapper;
}

// --- Password rotate -------------------------------------------------------

$("#password-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const r = await api(`/api/v1/portal/${state.tenant}/password`, {
    method: "POST",
    body: JSON.stringify({
      current_password: f.get("current_password"),
      new_password: f.get("new_password"),
    }),
  });
  setOutput("#password-output", r.ok, r.body);
  if (r.ok) e.target.reset();
});

// --- Refresh wiring --------------------------------------------------------

function refreshAll() {
  // Touch every cache once on sign-in so sidebar-count badges + the
  // Home page's "Your access" / "Pending" rails populate without a
  // visit. The setActivePortalNav() flow re-loads any specific
  // panel on demand; this is the warm-up.
  refreshCatalog();
  refreshRequests();
  refreshKeys();
  refreshConnections();
  refreshHome();
}

// =========================================================================
// Home page — greeting, IDE-config snippet, Your access rail, Pending,
// last-5 tool calls. Reuses the catalog / requests caches so it
// updates whenever those panels do.
// =========================================================================

function refreshHome() {
  paintHeroGreeting();
  paintSetupSnippet();
  paintHomeAccessList();
  paintHomePendingList();
  refreshToolHistoryHome();
}

function firstNameOf(email) {
  if (!email) return "there";
  const local = email.split("@")[0] || "";
  if (!local) return "there";
  // Heuristic: capitalize first chunk before any dot/hyphen.
  const head = local.split(/[._-]/)[0];
  return head.charAt(0).toUpperCase() + head.slice(1);
}

function paintHeroGreeting() {
  const t = $("#hero-title");
  if (!t || !state.user) return;
  t.textContent = `Hi ${firstNameOf(state.user.email)} — connect your AI `
    + `tools to your tenant's sanctioned MCPs`;
}

function paintSetupSnippet() {
  const el = $("#setup-snippet");
  if (!el) return;
  // First granted vserver = "your default endpoint" for the snippet.
  const first = (catalogCache || []).find((v) => v.has_access);
  const fallback = (catalogCache || [])[0];
  const vserver = first || fallback;
  const origin = window.location.origin;
  const url = vserver
    ? `${origin}/v/${state.tenant}/${vserver.name}/mcp`
    : `${origin}/v/${state.tenant}/<vserver-name>/mcp`;
  const config = {
    mcpServers: {
      vyuu: {
        url,
        headers: { Authorization: "Bearer vyk_•••" },
      },
    },
  };
  el.textContent = JSON.stringify(config, null, 2);
}

function paintHomeAccessList() {
  const list = $("#home-access-list");
  if (!list) return;
  list.innerHTML = "";
  const granted = (catalogCache || []).filter((v) => v.has_access);
  if (!granted.length) {
    const empty = document.createElement("li");
    empty.className = "rail-list-empty";
    empty.textContent = "No bundles granted yet. Browse the catalog "
      + "and request access to ones marked private.";
    list.appendChild(empty);
    return;
  }
  for (const v of granted.slice(0, 6)) {
    const li = document.createElement("li");
    const dot = document.createElement("span");
    dot.className = "rail-list-dot";
    li.appendChild(dot);
    const text = document.createElement("div");
    text.className = "rail-list-text";
    const name = document.createElement("strong");
    name.textContent = v.name;
    text.appendChild(name);
    const small = document.createElement("small");
    small.textContent = v.visibility === "public"
      ? "OPEN TO ALL"
      : "GRANTED";
    text.appendChild(small);
    li.appendChild(text);
    list.appendChild(li);
  }
  if (granted.length > 6) {
    const more = document.createElement("li");
    more.className = "rail-list-empty";
    more.textContent = `+${granted.length - 6} more — see catalog.`;
    list.appendChild(more);
  }
}

function paintHomePendingList() {
  const wrap = $("#home-pending-wrap");
  const list = $("#home-pending-list");
  const headline = $("#home-pending-headline");
  const navCount = $("#nav-count-requests");
  if (!list || !wrap || !headline) return;
  const pending = (requestsCache || []).filter((r) => r.status === "pending");
  if (navCount) {
    if (pending.length > 0) {
      navCount.textContent = String(pending.length);
      navCount.hidden = false;
    } else {
      navCount.hidden = true;
    }
  }
  if (!pending.length) {
    wrap.hidden = true;
    return;
  }
  wrap.hidden = false;
  headline.textContent = pending.length === 1
    ? "1 access request open"
    : `${pending.length} access requests open`;
  list.innerHTML = "";
  for (const r of pending.slice(0, 5)) {
    const li = document.createElement("li");
    const text = document.createElement("div");
    text.className = "rail-list-text";
    const strong = document.createElement("strong");
    strong.textContent = (r.vserver_id || "").slice(0, 8) + "…";
    text.appendChild(strong);
    const small = document.createElement("small");
    const when = r.created_at ? new Date(r.created_at).toLocaleDateString() : "";
    small.textContent = `submitted ${when}`;
    text.appendChild(small);
    li.appendChild(text);
    list.appendChild(li);
  }
}

// =========================================================================
// Tool history — the last N tool calls Vyuu routed for the signed-in
// user. Surfaces a thin shell over the (yet-to-ship) per-user audit
// endpoint; while that's pending, we render the empty-state copy
// rather than fabricating data.
// =========================================================================

let toolHistoryCache = [];

async function refreshToolHistoryHome() {
  const r = await fetchUserToolCalls(5);
  paintRecentRows("#home-recent-calls", r, 5);
}

async function refreshToolHistory() {
  // Two parallel fetches: rows for the table + KPI rollup for the
  // cards above it. Both backed by the in-memory ring buffer; the
  // KPI endpoint additionally counts/groups across a 7-day window.
  const [r, summary] = await Promise.all([
    fetchUserToolCalls(50),
    fetchToolHistorySummary(),
  ]);
  toolHistoryCache = r;
  paintToolHistoryKpis(summary);
  paintRecentRows("#tool-history-output", r, 50, { variant: "history" });
}

async function fetchToolHistorySummary() {
  try {
    const r = await api(
      `/api/v1/portal/${state.tenant}/tool-history-summary`,
    );
    if (!r.ok) return null;
    return r.body || null;
  } catch { return null; }
}

function paintToolHistoryKpis(summary) {
  const callsEl = $("#kpi-calls-value");
  const toolsEl = $("#kpi-tools-value");
  const blockedEl = $("#kpi-blocked-value");
  const blockedMeta = $("#kpi-blocked-meta");
  const blockedCard = document.querySelector('[data-kpi="blocked"]');
  if (!summary) {
    if (callsEl) callsEl.textContent = "—";
    if (toolsEl) toolsEl.textContent = "—";
    if (blockedEl) blockedEl.textContent = "—";
    if (blockedMeta) blockedMeta.textContent = "";
    if (blockedCard) blockedCard.removeAttribute("data-alert");
    return;
  }
  if (callsEl) callsEl.textContent = String(summary.total_calls || 0);
  if (toolsEl) toolsEl.textContent = String(summary.distinct_tools || 0);
  const blocked = summary.blocked_count || 0;
  if (blockedEl) blockedEl.textContent = String(blocked);
  if (blockedCard) {
    if (blocked > 0) blockedCard.setAttribute("data-alert", "true");
    else blockedCard.removeAttribute("data-alert");
  }
  if (blockedMeta) {
    const examples = summary.blocked_tool_examples || [];
    if (blocked > 0 && examples.length) {
      const tail = examples.length === 1 ? "" : ` (+${examples.length - 1} more)`;
      blockedMeta.textContent = `blocked: ${examples[0]}${tail}`;
    } else {
      blockedMeta.textContent = "";
    }
  }
}

async function fetchUserToolCalls(limit) {
  // Endpoint is opt-in — gateway returns 404 until shipped. The
  // empty-state path gracefully degrades.
  try {
    const r = await api(
      `/api/v1/portal/${state.tenant}/recent-tool-calls?limit=${limit}`,
    );
    if (!r.ok) return [];
    return Array.isArray(r.body) ? r.body : [];
  } catch { return []; }
}

function paintRecentRows(selector, rows, _limit, opts = {}) {
  // `variant` switches between two layouts:
  //   "home"    — 5-col (When · Tool · vServer · Via · Latency)
  //   "history" — 6-col adds an Outcome pill column on the right.
  const variant = opts.variant || "home";
  const out = $(selector);
  if (!out) return;
  out.innerHTML = "";
  if (!rows.length) {
    const empty = document.createElement("p");
    empty.className = "recent-empty";
    empty.textContent =
      "No tool calls yet. Once you connect a client to a granted "
      + "vserver, calls appear here in real time.";
    out.appendChild(empty);
    return;
  }
  for (const ev of rows) {
    const row = document.createElement("div");
    row.className = "recent-row";
    if (variant === "history") row.classList.add("recent-row-history");

    const time = document.createElement("span");
    time.className = "recent-col-time";
    time.textContent = ev.observed_at
      ? new Date(ev.observed_at).toLocaleString()
      : "";
    row.appendChild(time);

    const tool = document.createElement("span");
    tool.className = "recent-col-tool";
    tool.textContent = ev.tool || "(no tool)";
    row.appendChild(tool);

    const vserver = document.createElement("span");
    vserver.className = "recent-col-vserver";
    vserver.textContent = ev.vserver_name || "(vserver)";
    row.appendChild(vserver);

    const via = document.createElement("span");
    via.className = "recent-col-via";
    via.textContent = ev.via || "";
    row.appendChild(via);

    const latency = document.createElement("span");
    latency.className = "recent-col-latency";
    if (ev.latency_ms != null && ev.latency_ms > 1000) {
      latency.classList.add("recent-col-latency-warn");
    }
    latency.textContent = ev.latency_ms != null
      ? `${ev.latency_ms}ms` : "";
    row.appendChild(latency);

    if (variant === "history") {
      const outcome = document.createElement("span");
      const decision = (ev.decision || "").toLowerCase();
      outcome.className = "outcome-pill " + (decision || "allow");
      outcome.textContent = decision || "allow";
      row.appendChild(outcome);
    }

    out.appendChild(row);
  }
}

// Re-paint Home when catalog / requests caches refresh — keeps the
// "Your access" / "Pending" rails fresh without an extra fetch.
const _origRenderCatalog = renderCatalog;
renderCatalog = function () {
  _origRenderCatalog();
  if (typeof paintHomeAccessList === "function") paintHomeAccessList();
  if (typeof paintSetupSnippet === "function") paintSetupSnippet();
};
const _origRenderRequests = renderRequests;
renderRequests = function () {
  _origRenderRequests();
  if (typeof paintHomePendingList === "function") paintHomePendingList();
};
const _origRenderKeys = renderKeys;
renderKeys = function () {
  _origRenderKeys();
  // Sidebar count = active keys.
  const active = (keysCache || []).filter((k) => !k.revoked_at).length;
  const navCount = $("#nav-count-keys");
  if (navCount) {
    if (active > 0) { navCount.textContent = String(active); navCount.hidden = false; }
    else { navCount.hidden = true; }
  }
};
const _origRenderConnections = renderConnections;
renderConnections = function () {
  _origRenderConnections();
  // Sidebar count = total connections
  const out = $("#connections-output");
  const count = out ? out.querySelectorAll(".bundle-card, .card").length : 0;
  const navCount = $("#nav-count-connections");
  if (navCount) {
    if (count > 0) { navCount.textContent = String(count); navCount.hidden = false; }
    else { navCount.hidden = true; }
  }
};
// Local search — operates over the cached response so keystrokes don't
// fire a fetch each time. The auto-load on nav switch handles fresh
// fetches; per-filter refresh is implicit when the operator changes
// pill state.
const _bind = (id, fn) => { const el = $(id); if (el) el.addEventListener("input", fn); };
_bind("#catalog-search", renderCatalog);
_bind("#requests-search", renderRequests);
_bind("#keys-search", renderKeys);

// Filter-pill state — replaces the old <select> filters. Each pill
// group exposes one active value via `data-{group}-filter`. Reads
// happen at render time via `activeFilter(group)`.
function activeFilter(group) {
  const sel = `[data-${group}-filter].is-active`;
  const el = document.querySelector(sel);
  return el ? (el.dataset[`${group}Filter`] || "") : "";
}

document.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  for (const group of ["catalog", "requests", "keys"]) {
    const pill = target.closest(`[data-${group}-filter]`);
    if (!pill) continue;
    const groupSel = `[data-${group}-filter]`;
    for (const p of document.querySelectorAll(groupSel)) {
      p.classList.toggle("is-active", p === pill);
    }
    const renderFns = {
      catalog: renderCatalog, requests: renderRequests, keys: renderKeys,
    };
    const fn = renderFns[group];
    if (typeof fn === "function") fn();
    break;
  }
});

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

bootstrap();
"""
