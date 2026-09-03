# Features and functionality

What the gateway does, grouped by the job it does. The exhaustive
version with rationale is [`PLATFORM.md`](PLATFORM.md) (§3 "Capabilities
by domain"); the operator's how-to is [`ADMIN-GUIDE.md`](ADMIN-GUIDE.md).

## Enforcing tool calls

- **One endpoint per published bundle** — `/v/{tenant}/{vserver}/mcp`,
  Streamable HTTP, serving both the legacy `initialize` session handshake
  and the stateless 2026-07-28 protocol revision through one pipeline.
- **Identity on every call** — per-user API keys (`vyuu_user_…`) with
  admin-set lifetime policies (per user, per group, per tenant; shortest
  wins), or MCP Enterprise-Managed Authorization (ID-JAG) so an enterprise
  IdP governs which client may call what, with the gateway acting as the
  MCP resource-authorization server.
- **Authorisation** — tenant scoping, public/private bundle visibility,
  explicit grants, time-boxed **just-in-time access** to private bundles
  and **per-tool elevation** for high-risk tools, all self-service through
  access requests that admins approve.
- **Policy** — allow / deny / redact / rewrite decisions per call, from a
  built-in provider or a remote management plane; the reason lands on the
  audit row and in the client's structured error envelope.
- **Protocol governance** — multi-round tool results (sampling, roots,
  elicitation, URL elicitation) denied by default and allow-listed per
  kind and host; transit payload caps; secret-shaped strings scrubbed from
  responses; `structuredContent` preserved for SDK clients.
- **Resilience** — per-tenant in-flight gate, uvicorn back-pressure,
  upstream circuit breakers, pooled clients with credential TTL, subprocess
  limits for stdio servers.

## Building the catalog

- **Register any MCP server** — HTTP / Streamable HTTP, legacy SSE, and
  stdio via `npx`, `uvx`, or a verified binary (Sigstore).
- **Connector catalog** — one-click presets for common SaaS MCP servers
  that pre-fill the registration wizard.
- **Six outbound auth modes + mTLS** — static headers, subprocess env,
  per-user header pass-through, OAuth client-credentials, OAuth
  authorization-code with PKCE (per-user delegated tokens, with Dynamic
  Client Registration and Client ID Metadata Documents), RFC 7523
  JWT-bearer service accounts. Credentials are secret-store references,
  never values.
- **Capability sync and drift** — tools, resources and prompts pulled on
  registration and on a cadence; additions, removals and in-place edits
  surfaced as drift with risk tones; a drill-in shows the tool surface as
  a client would see it.
- **Safety at registration** — SSRF guard on URLs (and again at connect
  time), private-network allow/deny lists.

## Publishing bundles

- **Virtual servers** compose an allow-list of tools from one or more
  upstreams behind a single URL, with rename maps to resolve collisions.
- **Exposure controls** — visibility, grants for users and groups, JIT
  windows, tool elevation, and a read-only view of who can reach what.
- **Risk reduction** — the published bundle's residual risk versus its
  upstreams' inherent risk, with the findings that were eliminated and
  those still reachable.

## Identity and access

- **Operators** (admin console) with password or SSO sign-in; **end
  users** (portal) with local passwords or enterprise SSO.
- **Enterprise directories** — Microsoft Entra ID and Google Workspace:
  SCIM 2.0 provisioning (users, groups, deactivation with a grace-period
  hard delete), OIDC or SAML sign-in per directory, Workspace polling,
  JIT user creation.
- **Groups**, **access requests** with approver context, **API-key
  lifetime policies**, per-tenant subdomain routing.

## Risk intelligence

- **LLM classification of every MCP server** against the OWASP MCP Top 10
  and the MCP-in-System-of-Systems risk factors, producing scored findings
  per tool with anchored severity levels; vendor-pluggable (Anthropic,
  OpenAI, Gemini) and configured per tenant from the console.
- **Staleness detection** — a score is fingerprinted to the tool surface
  it was computed on; when sync changes a tool (even in place), the score
  is flagged out of date rather than shown as current.
- **CISO view** — tenant-wide posture: coverage, band distribution, the
  riskiest servers, what curation removed, OWASP category counts.

## Observability and audit

- **Durable audit** — every tool call and every connection-level
  rejection written synchronously to Postgres with decision, rule,
  latency, upstream status, and (only when policy opts in) payloads;
  every admin action recorded in the same transaction as the change.
- **Console views** — events with time windows, admin audit, an NHI
  (non-human identity) map of who uses what, per-identity timelines and
  dependency graphs, health with p95/p99 latency, a one-shot redacted
  diagnostic bundle for support.
- **SIEM export (Splunk HEC)** — tool calls, rejections, admin actions,
  sign-ins, per-user tool authorisation events and gateway logs, one
  sourcetype each; a deployment-level target from env plus per-tenant
  targets configured in the console with a secret-store token reference,
  test button and live delivery counters.
- **OpenTelemetry** — spans `mcp.request → policy_eval → upstream.call_tool`
  and bounded-cardinality metrics to any OTLP collector (the Splunk OTel
  Collector by default); status and a test signal in the console.
- **Retention** — opt-in prune windows for both audit tables, chunked and
  audited.

## Platform

- **Multi-tenant by construction** — `tenant_id` everywhere, Postgres
  row-level security (forced on sensitive tables), tenant-keyed secret
  resolution, envelope encryption of OAuth tokens at rest.
- **Deployable three ways** — Docker Compose appliance, Kubernetes,
  systemd on a VM; air-gap friendly (no build step, no CDN).
- **Two web apps with no framework** — operator console and end-user
  portal are single files served by the gateway under a strict CSP.
- **Security posture panel** — which controls are on, what each means,
  and the env var that flips it.
