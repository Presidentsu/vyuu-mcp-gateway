# Vyuu MCP Gateway — UX User Stories for UI Restructure

**Audience:** product designer restructuring the operator console (`/operator`) and the end-user portal (`/portal`).
**Goal:** give you the *who*, the *jobs they're trying to do*, and the *friction in today's UI* — enough to redesign the information architecture and flows with freedom, while staying anchored to real user needs.

The stories are deliberately **outcome-focused, not widget-prescriptive** — they say what the user must accomplish and what must be true on screen, and leave the *how* to you. Each story carries a **"Current friction → opportunity"** note grounded in the actual shipped UI (mapped in the appendix), so you know which problems to solve.

---

## How to read this doc

**Story format**
> **[ID] Title** · *Priority*
> **Story:** As a `<persona>`, I want `<goal>`, so that `<benefit>`.
> **Acceptance (UX):** what the experience must let them do / see — outcome-level.
> **States to design:** empty / loading / error / success / no-permission (as relevant).
> **On screen:** the key information that must be present.
> **Friction → opportunity:** the specific thing that's clunky today and the chance to fix it.

**Priority legend**
- **P0** — core to the persona's primary job *and* high-friction today. Fix first.
- **P1** — important; moderate friction.
- **P2** — polish / edge case / power-user.

---

## 1. Personas

### Admin / Operator side

**Priya — Platform & Security Admin** *(primary operator; role: admin)*
Owns the gateway. Connects MCP servers, wires credentials, curates the tool surface, sets visibility, watches for risk. Technical and security-minded, but time-pressured and context-switching. **Wants:** control, confidence that nothing is exposed by accident, and a fast path from "new MCP server" to "safely published." **Frustrated by:** dense multi-step forms, ambiguous fields, pasting long URLs/tokens, secrets shown once, and dashboards that look empty/untrustworthy.

**Sam — Team Lead & Access Approver** *(role: editor)*
Lives in the access-request queue and the "who can reach what" views. Rarely configures servers. **Wants:** fast, well-contextualized approve/deny decisions and a clear picture of who has access to what. **Frustrated by:** one-by-one triage, having to cross-reference UUIDs to understand a request.

**Dana — Compliance & Auditor** *(role: viewer)*
Read-only. Reviews the admin-audit trail and tool-call events, exports evidence. Never mutates. **Wants:** complete, trustworthy, filterable, exportable records; confidence that "if it happened, it's logged." **Frustrated by:** anything that feels transient or partial, raw IDs without names.

### End-user side

**Arjun — Developer / AI power user** *(primary end user)*
Wants Cursor / Claude Desktop / his own agent pointed at sanctioned tools in minutes. Comfortable editing a JSON config, but **not** a Vyuu expert and doesn't want to become one. **Wants:** the shortest path from "log in" to "my agent can call the tool." **Frustrated by:** pasting a tenant UUID, hunting for which API key to use, copy-pasting config by hand, and vserver UUIDs instead of names.

**Maya — Occasional / non-expert user**
Needs access to *one* tool for *one* task. Low Vyuu fluency. **Wants:** to be told exactly what to do next. **Frustrated by:** screens that assume she knows what an MCP, a vserver, or a bearer token is.

**"Aria" — the AI agent** *(non-human actor; not a UI user)*
Not someone who opens the portal, but its needs shape Arjun's tasks: a **stable endpoint URL**, a **valid scoped key**, and **grants that don't silently expire**. Call this out wherever a human task exists only to keep the agent working.

---

## 2. Cross-cutting UX principles (the spine of the restructure)

These themes recur across nearly every story. If the redesign nails these, most individual stories fall into place.

1. **Friendly names over UUIDs, everywhere.** Tenant, vserver, server, identity, request targets — show the human name; reveal the ID only on demand (with copy). Today UUIDs leak into My-requests, tenant cards, request targets.
2. **Foolproof "shown once" secrets.** SCIM tokens and API keys are revealed exactly once. Never a bare selectable `<pre>`. Pattern: prominent reveal → one-click copy → "copied ✓" confirmation → explicit "store it now, you can't see it again" → a clear re-issue path if missed.
3. **One-click config handoff.** The end user's core job is "point my client here." Pre-fill the *actual* vserver URL **and** a real (or freshly-issued) key into ready-to-paste Cursor / Claude blocks; link Catalog → API keys → config in one flow. Today the snippet shows `<YOUR_API_KEY>` and sends the user away to find one.
4. **Error prevention in config forms.** Auto-fill gateway-owned URLs (OAuth `redirect_uri`, callback, ACS) with a copy button rather than free-text paste (a stray slash silently broke an OAuth integration). Inline-validate JSON fields; flag a literal credential typed where a secret-*ref* belongs; mark required vs optional unambiguously.
5. **Progressive disclosure for dense flows.** The server-register wizard exposes 5 steps × 6 auth modes; show only the fields the chosen mode needs, with a plain-language one-liner per mode.
6. **Trustworthy, legible observability.** Data must feel persistent and complete (no "blank until you generate traffic"). Make risk legible: surface "who can do anything dangerous" and per-identity risk without the user assembling it.
7. **Empty states that teach the next action.** Every empty list links to the action that fills it ("No bundles yet → Browse catalog"; "No keys → Issue your first key"; "No tool calls → here's how to connect a client").
8. **Adapt to single- vs multi-tenant.** When the deployment is single-tenant, hide the tenant field entirely (already done on default). For multi-tenant, replace UUID-paste with a friendly chooser / org lookup — never ask a human to type a UUID.
9. **Status legibility.** Pair relative time with absolute on hover; warn *before* a token/cert expires; make sync freshness and **tool drift** a visible badge, not a buried field.
10. **Consistent action placement + refresh.** Decide auto-refresh vs manual and apply it consistently (today most panels are "click Refresh to load"). Put edit where users expect it (vserver grants/visibility currently hide in a drawer Settings tab).

---

## 3. Admin / Operator user stories

### EPIC EA-1 — Onboarding & sign-in

**[EA-1.1] Sign in without friction** · *P0*
**Story:** As Priya, I want to sign in to the right tenant without typing a UUID, so that I'm in the console in seconds.
**Acceptance:** single-tenant deployments show no tenant field; multi-tenant offers a named chooser / SSO, never raw UUID entry; SSO ("Continue with…") is first-class alongside password; pasting a bearer is a clearly-labeled "advanced" fallback.
**States:** logged-out, SSO-redirect, auth error, session-expired re-auth.
**On screen:** which tenant/org I'm signing into (by name), the available sign-in methods.
**Friction → opportunity:** today the operator login can require a tenant UUID and exposes "paste a bearer token" prominently — reframe bearer-paste as advanced, lead with SSO + named tenant.

**[EA-1.2] Orient on first login** · *P1*
**Story:** As a new admin, I want a clear "what is this and what do I do first" moment, so that I'm not dropped into a dense dashboard.
**Acceptance:** first-run surfaces the 3 core jobs (connect a server → publish a vserver → invite users) with progress; once configured, this recedes.
**States:** zero-config (nothing connected), partially-configured, fully-configured.
**Friction → opportunity:** the dashboard assumes prior context; there's no guided first-run.

---

### EPIC EA-2 — Connect & configure MCP servers

**[EA-2.1] Register a server without a config maze** · *P0*
**Story:** As Priya, I want to add an MCP server by answering only what's relevant to its type, so that I don't wade through fields that don't apply.
**Acceptance:** I pick a runtime (HTTP / npm / pypi / stdio / binary) and the form adapts; each auth mode (none / org-header / passthrough / OAuth-CC / OAuth-authcode / JWT-bearer) reveals only its own fields with a one-line plain-language explainer; required vs optional is obvious; I can preview discovered tools before committing.
**States:** drafting, validating, manifest-probe loading, probe-failed, submit-error, success → server appears **without a manual refresh**.
**On screen:** what type I'm adding, what auth it will use (in plain words), what tools were discovered.
**Friction → opportunity:** today it's a dense 5-step wizard; OAuth-authcode alone has 7+ fields, the DCR toggle hides fields retroactively, JSON fields validate only on submit, and after registering you must click Refresh to see the row. Big win available here.

**[EA-2.2] Handle credentials safely and by reference** · *P0*
**Story:** As Priya, I want to point at secrets by reference (not paste raw values), so that credentials never live in the gateway UI/DB.
**Acceptance:** secret-ref inputs are visibly distinct from value inputs; pasting something that looks like a literal credential is flagged before submit; gateway-owned URLs (OAuth `redirect_uri`) are **generated with a copy button**, not hand-typed.
**States:** ref valid / ref unverified / literal-credential warning.
**Friction → opportunity:** "client_id ref" etc. are repeated across modes with the "ref = secret-store key" meaning buried in hint text; a hand-typed `redirect_uri` with a stray slash silently broke an integration — auto-generate it.

**[EA-2.3] Self-healing OAuth (DCR) is understandable** · *P1*
**Story:** As Priya, I want dynamic client registration explained and its state visible, so that I trust the "it just reconnects" behavior.
**Acceptance:** the DCR toggle has a plain-language explainer of what it does and what it removes from the form; DCR status (registered / re-registered / failed) is visible on the server later.
**Friction → opportunity:** DCR is a mid-form checkbox that silently changes the form; its runtime state isn't surfaced.

---

### EPIC EA-3 — Govern the tool surface (virtual servers)

**[EA-3.1] Publish a curated, renamed tool bundle** · *P0*
**Story:** As Priya, I want to compose a virtual server from chosen tools across one or more upstreams, renaming and resolving collisions, so that users see a governed catalog — not raw upstream sprawl.
**Acceptance:** pick tools across servers; rename for clarity; name/uniqueness/tool-ref validation is inline and legible; the resulting connect URL is shown with copy.
**States:** drafting, validation-error (bad name, dup, missing tool), success.
**On screen:** which tools from which upstreams are included, the public connect URL, current visibility.
**Friction → opportunity:** creation is a light modal but **editing grants/visibility is buried** in a drawer Settings tab two clicks in; visibility is a create-time checkbox but a list-filter pill elsewhere — unify "manage exposure."

**[EA-3.2] Control who can reach a vserver** · *P0*
**Story:** As Priya/Sam, I want to set a vserver public or private and manage grants in one obvious place, so that exposure is never ambiguous.
**Acceptance:** visibility + grants (users and groups) are managed from the same surface; the effect ("who can reach this right now") is shown as a resolved list, not just rules.
**On screen:** public/private state, granted users + groups, resolved reachability.
**Friction → opportunity:** grants and visibility live in different places; there's no single "who can reach this" answer on the vserver itself.

---

### EPIC EA-4 — Keep the catalog healthy (sync, drift, health)

**[EA-4.1] See tool drift at a glance** · *P0*
**Story:** As Priya, I want to know when an upstream's tools changed or disappeared, so that my published vservers don't silently break or expose something new.
**Acceptance:** drift (new / removed / deprecated tools since last sync) is a visible badge on the server and surfaced where it affects a vserver; last-sync freshness is obvious.
**States:** in-sync, drift-detected, never-synced, sync-failed.
**On screen:** what changed, when last synced, which vservers are affected.
**Friction → opportunity:** drift is captured (`deprecated=true`) but lives as data, not a visible signal; sync freshness is a table column, not an alert.

**[EA-4.2] Trust the health view** · *P1*
**Story:** As Priya, I want a live, legible health picture of the gateway and each server, so that I can answer "is anything degraded?" instantly.
**Acceptance:** instance/uptime/latency/cert-expiry up top; per-server status, latency, call volume, last-sync; auto-refreshing (not "click to load"); cert/token expiry warns *before* it lapses.
**States:** healthy, degraded, down, stale-data.
**Friction → opportunity:** good content exists but is refresh-driven; expiry shows a date, not a proactive warning.

---

### EPIC EA-5 — Identity & access management

**[EA-5.1] Connect a corporate directory without ambiguity** · *P0*
**Story:** As Priya, I want to connect Entra / Google Workspace with fields I can't misread, so that SSO + SCIM provisioning work on the first try.
**Acceptance:** each field states exactly what to paste and from where (which value is the *IdP entity ID* vs the *SSO URL*), with examples; gateway-side values the IdP needs (ACS, callback, SCIM URL, entity ID) are presented as **labeled, copy-ready** outputs; the protocol choice (OIDC/SAML) tailors the form.
**States:** drafting, connect-error, success → SCIM token reveal.
**On screen:** clearly separated "paste these into Vyuu" vs "copy these into your IdP" groups.
**Friction → opportunity:** an operator literally asked "which input is IdP entity ID vs SSO URL" — the labels are ambiguous and the paste-here/copy-there directions are mixed together.

**[EA-5.2] Capture the SCIM token safely** · *P0*
**Story:** As Priya, I want the one-time SCIM token handed to me in a way I can't fumble, so that provisioning isn't broken by a missed copy.
**Acceptance:** prominent reveal, one-click copy with confirmation, explicit "shown once" warning, and a clear re-issue path that explains the consequence (re-sync).
**Friction → opportunity:** shown once in a modal; if missed, the only recovery is reconnecting (new token, breaks sync) — make re-issue explicit and consequence-clear.

**[EA-5.3] Triage access requests fast and in context** · *P0*
**Story:** As Sam, I want to approve/deny requests with full context and in batches, so that I clear the queue without cross-referencing.
**Acceptance:** each request shows requester (name + team), target vserver (name, not UUID), justification, and *current* access; decide inline; optional decision note; multi-select for batch decisions.
**States:** empty queue, pending, decided, error.
**On screen:** who, what (named), why, their existing access, decision note.
**Friction → opportunity:** decisions are one-by-one; full context needs a row-click; targets can appear as UUIDs.

**[EA-5.4] Manage users & groups around grants** · *P1*
**Story:** As Priya, I want to see a user/group's reach (keys, groups, vserver access) in one place, so that joiner/mover/leaver changes are safe.
**Acceptance:** per-user view shows auth method, keys, groups, and resolved vserver access + recent activity; disabling/removing shows the blast radius.
**Friction → opportunity:** the pieces exist across drawer tabs; there's no single "what can this person reach" answer.

---

### EPIC EA-6 — Observe & investigate (the flagship)

**[EA-6.1] Answer "who/what can do anything dangerous?"** · *P0*
**Story:** As Priya/Dana, I want to instantly see high-risk reach across identities (human and non-human), so that I can spot over-privilege and compromise.
**Acceptance:** a risk-first entry point lists principals by max-risk + breadth; reverse query ("who can call this dangerous tool?") is one action; human vs AI-agent vs API-key is visually distinct; AI client (Cursor/Claude/etc.) is identified.
**States:** no-traffic-yet (teaching empty state), populated, filtered.
**On screen:** principal (named), what it can reach, risk level, how it's calling in.
**Friction → opportunity:** the NHI map + identity graph exist but are refresh-to-load and require interpretation; make risk the headline, not the user's assembly job.

**[EA-6.2] Investigate an identity's activity end-to-end** · *P1*
**Story:** As Dana, I want to drill from a principal into its real calls, reach, and risk, so that I can complete an investigation in one place.
**Acceptance:** from any identity, see its tool-call timeline, the vservers/tools it touched, its grants, and risk signals — with friendly names and absolute timestamps.
**Friction → opportunity:** footprint data is shown raw (session IDs, IPs, UAs); names and a coherent narrative are missing.

**[EA-6.3] Trust that events are complete** · *P1*
**Story:** As Dana, I want the events/observability views to feel persistent and complete, so that I trust them as a record.
**Acceptance:** views are populated on load (not "generate traffic first"); time-window is explicit; deny/block/error are filterable; each event drills to detail.
**Friction → opportunity:** historically the dashboard read empty after a restart — the redesign should *feel* durable and never imply data loss.

---

### EPIC EA-7 — Audit, compliance & troubleshooting

**[EA-7.1] Read the admin-audit trail with confidence** · *P1*
**Story:** As Dana, I want a filterable, named, exportable record of every admin action, so that I can satisfy compliance without engineering help.
**Acceptance:** filter by actor kind (operator/system/SCIM), action, target, time; every row shows who (named), what, when, and before/after; export.
**On screen:** human-readable actor, action, target name, diff.
**Friction → opportunity:** good bones (actor color-coding, drawer detail); ensure names not IDs and add export.

**[EA-7.2] Get help without a UUID scavenger hunt** · *P2*
**Story:** As Priya, I want to grab a diagnostic bundle and see backend health in one place, so that support handoff is one click.
**Acceptance:** Troubleshooting groups the diagnostic-bundle download + secret-store backend health + key system status; bundle clearly states it redacts secrets.
**Friction → opportunity:** already consolidated under Settings → Troubleshooting; keep it discoverable and reassure on redaction.

---

## 4. End-user (portal) user stories

### EPIC EU-1 — Sign in & orient

**[EU-1.1] Sign in without knowing a tenant UUID** · *P0*
**Story:** As Arjun, I want to log in with my work identity, so that I don't need an internal ID handed to me.
**Acceptance:** single-tenant hides the tenant field; multi-tenant resolves the org from my email/SSO, never a UUID paste; SSO buttons lead.
**States:** logged-out, SSO redirect, error, expired-session.
**Friction → opportunity:** login copy literally says "Paste your tenant ID"; for multi-tenant users with no shared ID there's no recovery path.

**[EU-1.2] Know my first step** · *P0*
**Story:** As Maya, I want the home screen to tell me exactly what to do first, so that I'm not lost in jargon.
**Acceptance:** a single primary path ("1. Issue a key → 2. Copy your config → 3. Paste into your client") with progress; jargon (MCP, vserver, bearer) is explained in context.
**Friction → opportunity:** Home is welcoming but assumes the user knows what a vserver/PAT/MCP is and what to do next.

---

### EPIC EU-2 — Discover & request tools

**[EU-2.1] Find the tool I need and understand my access** · *P1*
**Story:** As Arjun, I want to browse sanctioned bundles and instantly see whether I can use each, so that I know what to connect vs request.
**Acceptance:** each bundle shows a clear status (open to me / connect SaaS / needs request / restricted) by **name**; search across bundles + tools; filters.
**Friction → opportunity:** status pills exist; ensure friendly names and that "what's inside this bundle" is visible.

**[EU-2.2] Request access with confidence** · *P1*
**Story:** As Maya, I want to request a private bundle and understand what happens next, so that I'm not left wondering.
**Acceptance:** request with optional justification + guidance on what approvers look for; immediate confirmation; clear status afterward; a re-request path if declined.
**States:** can-request, requested/pending, approved, declined (+reason), withdrawn.
**Friction → opportunity:** no guidance at request time; declined requests have no retry; My-requests shows the target as a UUID.

---

### EPIC EU-3 — Wire up an AI client (core JTBD)

**[EU-3.1] Get a ready-to-paste config in one flow** · *P0*
**Story:** As Arjun, I want a complete, correct config snippet — real URL, real key — that I can copy once and paste into Cursor/Claude, so that my agent works on the first try.
**Acceptance:** the snippet contains the **actual** vserver URL and a key (offer "issue a key now" inline if none); one-click copy; per-client variants (Cursor / Claude Desktop / custom); no `<placeholder>` left for the user to resolve manually.
**States:** no-key-yet (offer to issue), key-ready, copied ✓.
**On screen:** the exact endpoint, the key (handled per the "shown once" pattern), which client this is for.
**Friction → opportunity:** today the snippet shows `<YOUR_API_KEY>` and tells the user to leave for the API-keys page — collapse this into one guided handoff. **This is the portal's single most important flow.**

**[EU-3.2] Understand the endpoint I'm using** · *P2*
**Story:** As Arjun, I want the connect URL labeled by bundle name, so that I can tell my configs apart.
**Friction → opportunity:** URLs embed a cryptic vserver slug; pair it with the friendly bundle name.

---

### EPIC EU-4 — Manage API keys

**[EU-4.1] Issue a key I can actually capture** · *P0*
**Story:** As Arjun, I want to mint a named key and copy it reliably the one time it's shown, so that I don't get locked out by a missed copy.
**Acceptance:** name the key; reveal with one-click copy + "copied ✓"; explicit "shown once — store it now"; if missed, an obvious re-issue path; list shows label, prefix, created, last-used, status with revoke.
**States:** none-yet, just-issued (reveal), active, revoked.
**Friction → opportunity:** plaintext is dumped into a bare `<pre>` with no copy button; no re-reveal and no in-context re-issue guidance.

**[EU-4.2] Know which key goes where** · *P2*
**Story:** As Arjun, I want keys tied to where I use them, so that revoking one doesn't break everything.
**Friction → opportunity:** keys are just labels; consider surfacing last-used client/context to make revocation safe.

---

### EPIC EU-5 — Connect upstream SaaS (per-user OAuth)

**[EU-5.1] Connect my SaaS accounts in context** · *P1*
**Story:** As Arjun, I want to authorize the upstream accounts a bundle needs, right where I discover the need, so that my tool calls don't fail mid-task.
**Acceptance:** from a bundle that needs OAuth, connect in one click; Connections shows linked accounts, scope, freshness, and expiry with proactive "expiring soon" warnings; reconnect/disconnect are clear.
**States:** not-connected, connected, expiring-soon, expired, disconnected.
**Friction → opportunity:** the need surfaces on Catalog but the actual accounts live on Connections — two places; relative-only timestamps make staleness hard to judge.

---

### EPIC EU-6 — Activity & account

**[EU-6.1] See my own tool activity** · *P2*
**Story:** As Arjun, I want to see what my agent has done (and what got blocked), so that I can debug and trust it.
**Acceptance:** recent calls with tool, bundle (named), client, latency, outcome; blocked calls explained; time-window control.
**Friction → opportunity:** solid today; keep names friendly and explain *why* something was blocked.

**[EU-6.2] Manage my account sensibly** · *P2*
**Story:** As Maya, I want account/password actions that match how I signed in, so that I'm not shown a form I can't use.
**Acceptance:** local users get password change with strength feedback + confirmation; SSO users get a clear "managed by your IdP" with a link, not a dead form.
**Friction → opportunity:** SSO users see a disabled password form with only vague hint text.

---

## 5. Appendix — current-state IA + friction inventory

So you know exactly what you're restructuring.

### Operator console — current navigation
- **Overview:** Dashboard · NHI Map · Health & Servers
- **Catalog:** MCP Servers · Virtual Servers
- **Identity & Access:** Identities · Users · Groups · Access Requests · Admins
- **Observability:** Events · Admin Audit
- **Settings:** Identity Providers · Secret Store · Troubleshooting

### Portal — current navigation
- **Get started:** Home
- **Discover:** Tool Catalog
- **My account:** Connections · API Keys · My Requests · Tool History · Settings
- Login screen (tenant field / email+password / SSO buttons / advanced token paste)

### Consolidated friction inventory (verbatim-grounded)
**Operator:**
1. Server-register wizard is dense: 5 steps, 6 auth modes, conditional fields; DCR toggle hides fields retroactively; JSON validates only on submit.
2. After registering a server you must click **Refresh** to see it (multi-trip).
3. Secret-ref vs literal-value distinction is buried in hint text; repeated `*_ref` fields.
4. `redirect_uri` is hand-typed (a stray slash silently broke an OAuth integration) — should be generated.
5. IdP connect: ambiguous labels — "which field is IdP entity ID vs SSO URL"; paste-here vs copy-there values are mixed.
6. SCIM token shown once; recovery = reconnect (new token, breaks sync).
7. Vserver visibility + grants are split (create-modal checkbox vs drawer Settings tab vs list filter); no single "who can reach this."
8. Tool drift exists as data (`deprecated=true`) but isn't a visible signal; sync freshness is a column, not an alert.
9. NHI map / Identities / most panels are "click Refresh to load"; risk requires interpretation.
10. UUIDs appear where names should (tenant card, some targets).

**Portal:**
1. Login copy: "Paste your tenant ID…"; no friendly path for multi-tenant users without a shared ID.
2. API-key plaintext dumped in a bare `<pre>` — no copy button, no re-reveal, no re-issue guidance.
3. Config snippet shows `<YOUR_API_KEY>` and sends the user away to the API-keys page — the #1 flow is fragmented.
4. vserver UUIDs shown instead of names (My Requests, config slugs).
5. OAuth need surfaces on Catalog but accounts live on Connections — two places.
6. Relative-only timestamps make token/connection staleness hard to judge.
7. Declined requests have no retry; request-time has no guidance.
8. Empty states don't link to the action that resolves them.
9. SSO users see a dead password form on Settings.

---

*Prepared as a designer handoff. Stories are intentionally implementation-agnostic; the appendix grounds them in the shipped UI. Priorities (P0/P1/P2) reflect "core job × current friction" — a sensible build/redesign order, not a mandate.*
