# Vyuu MCP Gateway — Administrator's Guide

**Audience.** The person standing the gateway up for a tenant: setting up
the platform, registering upstream MCP servers, publishing virtual servers,
managing access, and onboarding end-users.

**You don't need to read this end-to-end** — pick the section that matches
the task:

- **First-time setup**: §1 → §2 → §5 (worked example)
- **Adding a new MCP server (GitHub, Notion, etc.)**: §6
- **Publishing a virtual server**: §7
- **Granting / revoking user access**: §8
- **Day-2 ops** (rotation, sync, troubleshooting): §9

For deployment / infrastructure (containerization, K8s, systemd), see
[`DEVOPS-HANDOFF.md`](./DEVOPS-HANDOFF.md). For raw architecture details,
see [`PLATFORM.md`](./PLATFORM.md).

---

## 1. Core concepts (5-minute primer)

The platform has six distinct things you'll work with. Get these straight
once and the rest of the guide makes sense.

### 1.1 Tenants

Top-level isolation boundary. Every other object (server, vserver, user,
key, audit event) belongs to exactly one tenant. Postgres row-level
security enforces this — no application-layer filter could leak.

For a single-customer install, you'll have one tenant. Multi-tenant
installs (MSPs, internal-shared-platform-team-as-customer-of-other-BUs)
have one per customer.

### 1.2 MCP servers (upstream)

The actual MCP servers that hold capabilities — GitHub Copilot MCP,
Notion MCP, an internal Datadog wrapper, a vendor-supplied Falcon MCP,
etc. The gateway holds:

- **Source spec** — how to launch / reach it (`npm`, `pypi`, `stdio`,
  `binary`, or `http` / `streamable_http`).
- **Auth config** — one of six modes, see §3.
- **Synced capabilities** — the gateway pulls `tools/list /
  resources/list / prompts/list` from the upstream and persists each
  capability with its risk classification (read / write / delete /
  admin / network / etc.).

End-users **never connect directly to MCP servers.** The gateway
brokers everything.

### 1.3 Virtual servers (vservers)

What end-users actually consume. A vserver is a curated subset of one
or more upstream MCPs' tools, with:

- A name (`github-readonly`, `falcon-mcp-soc`, `payment-ops`).
- A visibility (`public-to-tenant` or `private`).
- A tool allowlist (specific tool names from one or more upstream
  servers — you can `git/get_repo` from GitHub MCP and `tickets/create`
  from Notion MCP both inside one vserver).
- Optional rename map (rename tools to gateway-canonical names if
  upstream names are awkward — `gh_get_pull_request` → `get_pr`).

End-user MCP clients (Cursor, Claude Desktop) connect to a *vserver*,
not an upstream. URL shape: `/v/{tenant_id}/{vserver_name}/mcp`.

### 1.4 Users + groups

End-user identities. Users authenticate to the gateway with bearer
tokens (API keys: `Authorization: Bearer vyuu_user_<key>`) issued
through the portal or by an admin. Groups are sets of users for
grant assignment.

Three identity-provider modes (configurable per gateway):

| Mode | When to use |
|---|---|
| `ApiKeyIdentityProvider` (default for production) | API-key bearer tokens; password / OIDC sign-in mints them via the portal |
| `FakeIdentityProvider` (lab / dev only) | `x-vyuu-tenant-id` / `x-vyuu-principal-id` headers, no real auth |
| Custom OIDC / SAML provider | Wire your IdP through the `IdentityProvider` Protocol; out of scope for v1 |

### 1.5 Operators (admins)

The people running the gateway. Distinct from users:
- Operators authenticate via OIDC (Microsoft / Google) or local
  password to the **operator console** at `/operator`.
- Tenant-scoped: an operator from tenant A cannot see tenant B's
  data, regardless of role.
- Three roles: **owner** (everything), **admin** (most things,
  cannot delete the tenant), **operator** (read + most writes,
  cannot manage admins).

### 1.6 API keys

End-users get one or more `vyuu_user_<...>` keys via the portal.
Used in `Authorization: Bearer ...` for inbound MCP calls. Hashed
(bcrypt) at rest. Operators can revoke any key.

---

## 2. First-time setup

Assumes the gateway runtime is already running (Docker / K8s / systemd
— see [`DEVOPS-HANDOFF.md`](./DEVOPS-HANDOFF.md) for that). This
section covers what an operator does *after* the runtime is alive.

### 2.1 Create the bootstrap admin

The first time the gateway starts with empty `operators` table, set
these env vars in the runtime:

```env
VYUU_BOOTSTRAP_ADMIN_EMAIL=admin@your-corp.example
VYUU_BOOTSTRAP_ADMIN_PASSWORD=<long-random-string-rotate-immediately>
VYUU_BOOTSTRAP_TENANT_NAME=YourCorp
```

On first boot, the gateway seeds:
- A new tenant (`YourCorp`) — UUID auto-generated, surfaced in the
  operator console.
- An `owner`-role operator with the email/password you set.

Once any operator exists, these env vars are ignored on subsequent
boots. They're idempotent (no duplicate seed) but the convention is to
unset them after first launch.

### 2.2 First sign-in

Open `https://<gateway-host>/operator`. Sign in with the bootstrap
credentials. **Rotate the password immediately** — the operator
console has a "Change password" affordance under the user menu.

### 2.3 Recommended first-day actions

1. Enable an OIDC provider (Microsoft Entra / Google Workspace) so
   future operators sign in via SSO instead of local passwords.
2. Issue invitations / create operator accounts for the rest of your
   admin team.
3. Wire your secret store (Vault / AWS Secrets Manager / K8s Secrets).
   The gateway ships with `InMemorySecretStore` for dev — switch to a
   real one before storing real upstream credentials.
4. Add at least one MCP server (§6) so you have something to publish.

---

## 3. Authentication modes (which to pick)

Six outbound auth modes, each suited to a different upstream type. Pick
the row matching your upstream.

| Mode | Use when | Example | Where credentials live |
|---|---|---|---|
| `auth_org_tier` (headers) | Upstream wants a static API key in a header | Custom internal MCP with `X-Internal-Key: ...` | SecretStore (header value) |
| `auth_passthrough` | Upstream uses the calling user's credentials directly (forwards a header from the user's request) | Slack MCP that wants the user's `Slack-User-Token` | Per-user — not stored in gateway |
| `auth_oauth` (client-credentials) | Upstream supports OAuth 2.0 client_credentials grant; one gateway-owned credential serves all callers | Azure AD M2M apps | SecretStore (client_id + client_secret refs) |
| `auth_authcode` (per-user delegated) | Upstream is a SaaS the user owns ("Connect my Drive / GitHub / Notion"); per-user OAuth | GitHub Copilot MCP, Drive MCP, Notion MCP | `oauth_user_tokens` table (per-user refresh tokens) |
| `auth_jwt_bearer` (RFC 7523) | Upstream supports JWT-bearer grant; gateway impersonates a service account | Workspace SA, IAM Roles Anywhere | SecretStore (private key ref) |
| `mtls` | Upstream requires client certificate auth | Internal banking systems, defence APIs | SecretStore (cert + key refs) |

---

## 4. Where things live (admin's mental model)

The operator console (`/operator`) is split into eight sections:

| Section | Manages |
|---|---|
| **Dashboard** | 7 KPIs at the top of the page — total servers, vservers, users, tool calls today, denied calls today, capability-sync drift count, last activity |
| **MCP servers** | Register, sync, delete upstream MCPs |
| **Virtual servers** | Publish, edit, delete vservers; manage tool allowlists; assign visibility |
| **Identities** | NHI dashboard — every distinct principal seen in the audit ring buffer; click to drill into a single identity's tool-call timeline |
| **Users** | End-user CRUD — invite, password-reset, disable, view their API keys |
| **Groups** | Group membership + grant-by-group |
| **Access requests** | Per-vserver "Request access" workflow — pending requests from end-users to private vservers |
| **Admins** | Operator CRUD — invite, role-change, password-reset, disable |
| **Events** | Rolling audit-event view (last 1000 events from the in-process ring buffer) — useful for "did that call land?" debugging |
| **Secret store** | Status of the configured backend (Vault / AWS / etc.); ref-name lookups for setting up auth modes |

---

## 5. Worked example: setting up GitHub Copilot MCP

End-to-end walkthrough — registering GitHub Copilot's MCP server,
syncing capabilities, publishing a `github-readonly` vserver, granting
a developer access, and confirming the dev can call tools.

### 5.0 Shortcut: Quick add from connector catalog

Above the MCP servers table, the operator console shows a **Quick add
from catalog** card grid. Eight common SaaS connectors ship pre-
configured (display name + URL + transport + OAuth metadata):

| Card | Vendor | Default upstream |
|---|---|---|
| GitHub Copilot MCP | GitHub | `https://api.githubcopilot.com/mcp/` |
| Notion | Notion | `https://mcp.notion.com/mcp` |
| Linear | Linear | `https://mcp.linear.app/mcp` |
| Jira | Atlassian | `https://mcp.atlassian.com/v1/sse` |
| Confluence | Atlassian | `https://mcp.atlassian.com/v1/sse` |
| Slack | Slack | `@modelcontextprotocol/server-slack` (npm/stdio) |
| Microsoft 365 | Microsoft | `@softeria/ms-365-mcp-server` (npm/stdio) |
| Asana | Asana | `@cristip73/mcp-server-asana` (npm/stdio) |

Click any card → the existing register wizard opens with everything
pre-filled. You only need to fill in `client_id_ref` and
`client_secret_ref` on step 3 (Authentication) — point them at your
own secret-store entries — then walk to step 5 and Register.

After Register, the row shows a **Test connect** button (only on
auth_authcode upstreams). Click it → completes OAuth as your own
underlying portal user (resolved from your operator email), then
click **Sync** → tools discovered → click **Publish vserver** → the
inline drawer lists the discovered tools for you to pick. End users
who get granted access to that vserver run the same OAuth flow from
/portal under their own accounts.

Without **Test connect** the operator hits a chicken-and-egg: Sync
needs an OAuth token, the token requires user Connect, and Connect
in /portal only renders for users granted access to a vserver — but
publishing a vserver requires synced tools. Test connect breaks this
by letting the operator authorize once for discovery, before any
end users exist.

The catalog cards are non-destructive: every pre-filled value remains
editable. Defaults exist so you don't have to dig up vendor OAuth
URLs and scopes from per-vendor docs. Atlassian (Jira / Confluence)
both use the same OAuth client app — install Jira first, then reuse
the same `client_id_ref` / `client_secret_ref` when adding Confluence.

The four `community`-tagged connectors (Slack, Microsoft 365, Asana,
plus Microsoft 365's tenant override) point at community-maintained
npm packages because the vendor doesn't publish a hosted MCP. The
defaults are starting points — verify against current vendor docs.

To add a new connector to the catalog, append a `ConnectorTemplate`
in [`src/vyuu_gateway/upstream/connector_catalog.py`](../src/vyuu_gateway/upstream/connector_catalog.py)
and restart the gateway. The UI auto-renders new entries.

### 5.1 Register the OAuth app on GitHub's side

You need a GitHub OAuth App (NOT a personal access token). The
gateway's per-user authcode flow exchanges a user-authorised code for
a refresh token.

1. GitHub → Settings → Developer Settings → OAuth Apps → New OAuth App.
2. **Homepage URL**: `https://<gateway-host>/`
3. **Authorization callback URL**: `https://<gateway-host>/api/v1/oauth-authcode/callback`
4. Save. Copy the **Client ID** and generate a **Client Secret**.

### 5.2 Store the OAuth credentials

In your secret store (Vault example):

```bash
vault kv put secret/vyuu/<tenant>/github-mcp \
  client_id=<from step 5.1> \
  client_secret=<from step 5.1>
```

Note the secret-store paths you used (`secret/vyuu/<tenant>/github-mcp`) —
the gateway references them by name (the "ref"), not by value.

### 5.3 Register the MCP server

Operator console → MCP servers → Register. Fill the form:

| Field | Value |
|---|---|
| Display name | `github-mcp` |
| Source type | `http` |
| Source location | `https://api.githubcopilot.com/mcp/` |
| Transport | `streamable_http` |
| Auth mode | `auth_authcode` |
| OAuth `auth_url` | `https://github.com/login/oauth/authorize` |
| OAuth `token_url` | `https://github.com/login/oauth/access_token` |
| OAuth `client_id_ref` | `secret/vyuu/<tenant>/github-mcp/client_id` |
| OAuth `client_secret_ref` | `secret/vyuu/<tenant>/github-mcp/client_secret` |
| OAuth `scopes` | `read:user repo read:org` |

Click **Register**. The gateway:
1. Creates the `mcp_servers` row.
2. Auto-syncs capabilities (background task, ~10s for HTTP MCPs).
3. Schedules a health probe.

After ~10 seconds, refresh — you should see ~8-15 GitHub tools
listed under the server (`get_me`, `search_repositories`, `list_issues`,
`get_pull_request`, `search_code`, etc.).

### 5.4 Publish a virtual server

Operator console → Virtual servers → Create. Fill:

| Field | Value |
|---|---|
| Name | `github-readonly` |
| Description | Read-only GitHub access — search, list, get |
| Visibility | `private` (operators must explicitly grant access) |
| Tools (multi-select) | `get_me`, `search_repositories`, `list_issues`, `get_file_contents`, `search_code` (skip `create_*`, `delete_*`) |

Click **Save**. The vserver is now reachable at
`/v/<tenant_id>/github-readonly/mcp` but with **no users granted**.

### 5.5 Grant a developer access

Operator console → Virtual servers → `github-readonly` → Grants → Add.
Select the user (or group), confirm. The grant takes effect immediately.

### 5.6 The developer connects

The user opens `/portal`, finds `github-readonly` in the catalog, and:

1. Clicks **Connect** under the GitHub OAuth banner.
2. Browser bounces to GitHub's OAuth authorize page.
3. Approves the requested scopes.
4. Browser bounces back to the gateway's callback, which stores the
   refresh token in `oauth_user_tokens`.
5. Issues an API key under **API keys** → New key → copies it.
6. Pastes the API key into Cursor / Claude Desktop's MCP config:

```json
{
  "mcpServers": {
    "github-via-vyuu": {
      "url": "https://<gateway-host>/v/<tenant_id>/github-readonly/mcp",
      "type": "streamable-http",
      "headers": {
        "Authorization": "Bearer vyuu_user_<key>"
      }
    }
  }
}
```

7. Restart Cursor. The user can now call GitHub tools through the
   gateway, with their personal GitHub OAuth token used for upstream
   auth.

---

## 6. Adding more MCP servers — common patterns

### 6.1 Notion MCP (per-user OAuth, similar to GitHub)

Same pattern as §5, with these field changes:

| Field | Value |
|---|---|
| Source location | `https://mcp.notion.com/mcp` (or your hosted Notion MCP URL) |
| OAuth `auth_url` | `https://api.notion.com/v1/oauth/authorize` |
| OAuth `token_url` | `https://api.notion.com/v1/oauth/token` |
| OAuth `scopes` | (Notion doesn't use scopes; leave empty) |
| `extra_authorize_params` | `{"owner": "user"}` |

### 6.2 Internal MCP with static API key (auth_org_tier)

Internal services where one gateway-held API key serves every caller.

| Field | Value |
|---|---|
| Display name | `internal-datadog` |
| Source type | `http` |
| Source location | `https://datadog-mcp.internal/mcp` |
| Auth mode | `auth_org_tier` |
| Headers map | `{"X-API-Key": "secret/vyuu/<tenant>/datadog-key"}` |

The gateway resolves the secret ref on every call (cached in memory
during the request, refreshed across requests).

### 6.3 Stdio MCP from npm (e.g. drawio-mcp-server)

| Field | Value |
|---|---|
| Display name | `drawio-mcp` |
| Source type | `npm` |
| Source location | `@cherrycode/drawio-mcp-server` |
| Args | (any extra flags the package needs) |
| Auth mode | `none` |

The gateway spawns `npx -y @cherrycode/drawio-mcp-server` per pool slot,
keeps it persistent across calls (Tier-2 stdio fix), and routes
JSON-RPC over stdin/stdout.

### 6.4 Stdio MCP from PyPI (e.g. mcp-server-time)

| Field | Value |
|---|---|
| Display name | `time-pypi` |
| Source type | `pypi` |
| Source location | `mcp-server-time` |

Spawns `uvx mcp-server-time`. uvx caches the venv across pool-slot
respawns, so cold-start cost is paid once (then persistent).

### 6.5 Workspace SA / domain-wide delegation (auth_jwt_bearer)

For Google Workspace organisation-wide reads:

| Field | Value |
|---|---|
| Auth mode | `auth_jwt_bearer` |
| Issuer | `<sa>@<project>.iam.gserviceaccount.com` |
| Subject | `admin@your-corp.example` (delegate-as) |
| Audience | `https://oauth2.googleapis.com/token` |
| Token URL | `https://oauth2.googleapis.com/token` |
| Algorithm | `RS256` |
| Private key ref | `secret/vyuu/<tenant>/workspace-sa-private-key` |

Mint the SA's JSON key in GCP Console, store the private key part in
your secret store under the ref above.

### 6.6 Vendor MCP with mTLS (e.g. CrowdStrike Falcon HTTP)

| Field | Value |
|---|---|
| Auth mode | `mtls` |
| Cert ref | `secret/vyuu/<tenant>/falcon/client-cert` |
| Key ref | `secret/vyuu/<tenant>/falcon/client-key` |

The gateway loads the cert+key per pool slot, reuses across calls.
Rotation: store the new cert in the same ref, restart the pool
(or wait for the next health-check-driven reconnect).

---

## 7. Vserver patterns

### 7.1 Public-to-tenant (everyone in the tenant can use it)

Visibility: `public-to-tenant`. No grants needed. Show up in
everyone's portal catalog. Useful for: shared utility MCPs (drawio,
time, internal tickets-read).

### 7.2 Private + group grants

Visibility: `private`. Grant by group (e.g. "Engineering" group gets
`github-readonly`, "Security" group gets `falcon-mcp-soc`). Cleaner
than user-by-user grants when team membership is your access model.

### 7.3 Tool curation across multiple upstreams

A single vserver can include tools from multiple upstream MCP servers.
Example: an `incident-response` vserver could include:
- `falcon_search_detections` from CrowdStrike
- `search_issues` from GitHub
- `query_logs` from Datadog
- `create_ticket` from your internal ticket MCP

End-users see one vserver, get one URL, the gateway transparently
routes each tool to the right upstream.

### 7.4 Tool renaming

If an upstream's tool names clash (two MCPs both expose `search`), use
the rename map:

```json
{
  "rename_map": {
    "search": "github_search",
    "<server-id>:search": "datadog_search"
  }
}
```

---

## 8. Access management

### 8.1 Granting access (private vserver)

Three paths:
1. **Operator-driven**: Vservers → Edit → Grants → Add. Operator
   pre-approves a user/group.
2. **User-requested**: User clicks "Request access" in `/portal`,
   operator approves under Access requests.
3. **Group-driven**: Add the user to a group that already has the
   grant — they get access automatically.

### 8.2 Revoking access

Vservers → Edit → Grants → Remove. Takes effect on the user's next
session-init (Cursor / Claude Desktop refresh).

For immediate effect: revoke the user's API key (Users → Edit → API
keys → Revoke). Active sessions stay alive until the next call, which
401s.

### 8.3 Disabling a user entirely

Users → Edit → Disable. Sets `disabled_at`. Their API keys keep
returning 401 (the auth path checks `disabled_at`). Re-enable by
clearing the field.

---

## 9. Day-2 ops

### 9.1 Capability sync (refresh upstream tools)

If an upstream adds / removes tools, the gateway's cached
`mcp_capabilities` table goes stale. Two ways to refresh:

- **Per-server, manual**: MCP servers → click the server → **Sync**.
  Pulls fresh `tools/list` + `resources/list` + `prompts/list` from
  the upstream.
- **Periodic**: enable `VYUU_CAPABILITY_SYNC_ENABLED=true` (off by
  default — opt-in because it's a real load source). Set
  `VYUU_CAPABILITY_SYNC_INTERVAL_SECONDS=3600` for hourly.

Tools that disappear from upstream are marked `deprecated=true` —
they stop appearing in vservers, existing grants gracefully drop them.

### 9.2 Rotating an upstream credential

1. Update the secret in your secret store under the SAME ref name.
2. The gateway's `SecretStore.get_secret(...)` returns the new value
   on the next call (cached for at most a few seconds in-process).
3. For OAuth client_credentials: invalidate the cached token via
   the operator console → MCP servers → click → "Invalidate
   cached OAuth token" (forces a refresh on the next call). For
   authcode (per-user) tokens: the user re-authorises via portal.

### 9.3 Investigating "did this call work?"

1. Operator console → **Events** panel — last 1000 audit events,
   real-time. Filter by tenant / user / vserver / decision.
2. For deeper history: query your audit warehouse (ClickHouse —
   the gateway publishes to NATS, the consumer drains to
   ClickHouse, see `clickhouse_consumer.py`).

### 9.4 Common diagnostic patterns

| Symptom | Likely cause | Fix |
|---|---|---|
| User's calls return `tool_not_in_vserver` | Tool was removed from the vserver, or the vserver doesn't include it | Check vserver tool list |
| User's calls return `capabilities_not_synced` | Upstream registered but never synced | Click Sync on the server |
| All calls slow (5s+) | First call after restart — paying the persistent-pool cold-start | Wait; subsequent calls fast |
| Repeated 503s | Per-tenant inflight cap hit (one tenant is bursty) | Raise `VYUU_INBOUND_PER_TENANT_INFLIGHT_LIMIT` or tighten on the bursty tenant |
| Audit volume bigger than expected | A user's tool returns huge responses | H3 `inbound_max_response_body_bytes` should already cap; check the truncation marker |
| Users complaining about "Connect to GitHub" loop | OAuth refresh token revoked upstream | User re-clicks Connect; the authcode flow stores a new refresh token |

### 9.5 Backups

The gateway writes to one Postgres database. Standard backup procedure:
- `pg_dump` nightly.
- Replicate (Patroni / managed) for HA.
- Audit data is downstream (NATS → ClickHouse) — back up that warehouse
  separately to your standard data-protection schedule.

---

## 10. Reference

- [`PLATFORM.md`](./PLATFORM.md) — full architecture
- [`TECH-STACK.md`](./TECH-STACK.md) — packages, components, decisions
- [`DEVOPS-HANDOFF.md`](./DEVOPS-HANDOFF.md) — containerization + deployment
- [`STRESS-TESTING.md`](./STRESS-TESTING.md) — measured perf + sizing
- [`GETTING-STARTED.md`](./GETTING-STARTED.md) — first-deployment quickstart
- `deploy/README.md` — deployment-manifest specifics (Docker / systemd / K8s)
