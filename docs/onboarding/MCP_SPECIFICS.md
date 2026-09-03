# MCP_SPECIFICS — protocol oddities + design decisions

The MCP (Model Context Protocol) spec is young (2024-11 first stable
release) and the wire format leaves room for client-side variation.
This doc captures the protocol oddities that affected our implementation
so you don't re-discover them.

If you're new to MCP, the [official spec](https://modelcontextprotocol.io/)
is a good 30-minute read.

## Transports we support

MCP is transport-agnostic. We implement three:

### `streamable_http` (the modern default)

POST / GET to a single URL. The server can stream responses via SSE
(`text/event-stream`) when a tool call yields incremental output.

| Wire detail | Our handling |
|---|---|
| Session id in `mcp-session-id` header | We propagate it through the pool key + opaque-pass to the upstream |
| Server may reply with a single JSON-RPC response OR an SSE stream | The client (httpx) buffers/streams as appropriate |
| `Accept: application/json, text/event-stream` is required by spec | The drawio lab MCP rejects requests missing this header — we always send both |
| Long-lived sessions held across multiple requests | Pool keeps the httpx client warm; session id binds them |

Code: [`upstream/streamable_http_client.py`](src/vyuu_gateway/upstream/streamable_http_client.py).

### `stdio` (local subprocess)

The MCP server is spawned as a child process; JSON-RPC over stdin/stdout.
Used for npm packages (`@modelcontextprotocol/server-time`,
`@drawio/mcp`), pypi (`uvx mcp-server-time`), and binaries.

| Wire detail | Our handling |
|---|---|
| Each line on stdout is a JSON-RPC message | Newline-delimited reader |
| Subprocess crashes silently → reads return EOF | Pool detects, restarts on next request |
| Upstream env vars hold secrets (e.g., `GITHUB_PAT=...`) | Resolved from `secret_store` per-request, NOT inherited from the gateway env |
| Idle subprocesses leak memory | Pool evicts after `stdio_idle_seconds` (default 600) |

Code: [`upstream/stdio_pool.py`](src/vyuu_gateway/upstream/stdio_pool.py).

### `sse` (legacy)

Server-Sent Events for the response, separate POST for the request.
Pre-`streamable_http` MCP servers used this; we keep the client for
backward compat.

Code: [`upstream/sse_client.py`](src/vyuu_gateway/upstream/sse_client.py).

## Why we DON'T cache `tools/list`

A tempting optimisation: cache the `tools/list` response per upstream
so the gateway can answer locally without round-tripping to the upstream
on every inbound `tools/list`.

We don't. Reasons:

1. **Capability drift is real.** Upstream MCPs evolve their tool
   catalog. A cache means the inbound client sees a stale list and
   gets confused when `tools/call` for a newly-added tool succeeds
   but the AI's planner didn't see it in `tools/list`.
2. **The capability sync cron already does this.** It pulls
   `tools/list` on a cadence and writes to `mcp_capabilities`. The
   operator dashboard reads from that table for the catalog view.
3. **Gateway is a transparent proxy on the hot path.** Every byte
   the AI client sends should be reflected to the upstream and vice
   versa. The only exception is policy-driven `redact` / `rewrite`,
   which are intentional.

If a customer asks for `tools/list` caching, it should be opt-in per
vserver with an explicit TTL.

## Session-id semantics (`mcp-session-id`)

For tools that maintain state across calls (e.g., a SQL MCP that holds
a query cursor), MCP uses a session id in the `mcp-session-id` header.
The server creates it on the first request and the client echoes it
back on subsequent requests.

Our handling:

- The session id is part of the upstream pool key — separate sessions
  get separate clients to avoid cross-session bleed.
- The DELETE method on `/v/.../mcp` lets the AI client explicitly
  close a session. The gateway forwards the DELETE to the upstream.
- If the upstream returns a new session id, we update the pool key
  binding.

This is why `inbound_mcp.py` returns 400 ("Missing session ID") for
some requests that expect a session — the upstream demands it and we
don't synthesise.

## H5 raw-args / raw-response capture

By default, audit events capture **only metadata** about tool args
(`args_summary` = top-level keys + types + sizes) — NOT the values.
This is the privacy-default.

Policy decisions can opt in:

```python
PolicyDecision(
    decision=AuditDecision.ALLOW,
    capture_raw_args=True,
    capture_raw_response=False,
)
```

When opted in, the lifecycle records `raw_args` / `raw_response` on
the `AuditEvent`. Both are size-capped:

- Default cap: 10 MiB per payload (`VYUU_AUDIT_RAW_CAPTURE_BYTE_CAP`).
- Over-cap: the field is replaced with a sentinel that records the
  REAL size — `{"__truncated__": true, "total_bytes": 27000000, "stored_bytes": 0, ...}`.
- **Transit is NEVER affected by the cap.** The full payload reaches
  the upstream regardless of audit storage.

The cap is set once at startup via `configure_raw_capture_cap()` in
[`audit/events.py`](src/vyuu_gateway/audit/events.py).

## `args_summary` shape

For every tool call, even when raw capture is off, we record an
`args_summary` JSONB:

```json
{
  "top_level_keys": ["query", "limit"],
  "fields": {
    "query": {"type": "str", "size": 47},
    "limit": {"type": "int", "size": null}
  }
}
```

This gives operators useful structural info for forensics ("the
caller passed a 47-char query string with limit=10") without
recording the value.

## Why `tool` is `<connect>` for `access_attempt` events

`AuditEvent.tool` is non-nullable by design — it's the most-queried
filter. For `access_attempt` events (auth/access denials at the gate),
no specific tool was being called, so we use the sentinel `"<connect>"`.
The operator console renders this with a distinct icon.

`access_attempt` events also have `auth_failure_reason` populated —
one of `invalid_bearer`, `vserver_not_found`, `no_grant`,
`disabled_principal`. The `policy_rule_id` mirrors the failure reason
so audit consumers that group by rule_id get a clean roll-up.

## Why we don't synthesise responses on the gateway

A policy decision can DENY a call. Our response shape:

- Inbound JSON-RPC error envelope (HTTP 200 with JSON-RPC `error.code`
  set) so the AI client treats it as a tool failure, not a transport
  failure.
- The `AuditEvent.decision = DENY` is recorded with
  `upstream_status = NOT_CALLED`.

We do NOT generate a fake "successful" response on a DENY. The AI
client should know its call was rejected so it can adapt (e.g., ask
the user, try a different tool).

The same logic applies for circuit breakers — when a breaker is open,
we return a JSON-RPC error with `upstream_status = NOT_CALLED`. We
don't return cached data because we don't cache.

## OAuth-AC quirks per upstream

Some upstream MCPs (Notion, GitHub Copilot, Cloudflare) support
per-user delegated OAuth (RFC 6749 authorization code flow). Our
implementation:

- The OAuth dance happens once per user per upstream — initiated by
  the user from the Connections page in the portal.
- We store both access + refresh tokens encrypted via the secret
  store.
- On 401 from the upstream, we attempt a refresh and retry the call
  once. If refresh fails, the connection is marked invalid and the
  user sees an "Action required" link in the portal.

Code: [`upstream/oauth_authcode.py`](src/vyuu_gateway/upstream/oauth_authcode.py).

### DCR (Dynamic Client Registration)

Some upstreams require per-gateway-instance OAuth client registration
(RFC 7591). We support this via [`api/dcr_*` migrations](migrations/versions/20260503_0013_dcr_clients.py):

- On first OAuth-AC setup, we POST to the upstream's DCR endpoint
  with our metadata.
- The response gives us a (client_id, client_secret) pair we store
  in `mcp_server_dcr_clients`.
- Subsequent OAuth dances use that pair.

Some upstreams (notably enterprise Notion) gate DCR on an IAT
(Initial Access Token). The operator pastes the IAT once during
setup; we use it to authenticate the DCR POST.

## Why we record `client_metadata.user_agent`

MCP clients include a `User-Agent` (or `clientInfo` in JSON-RPC
`initialize`). We capture it on every audit event because:

- The NHI map needs it to classify "AI app" (Cursor / Claude Desktop /
  ChatGPT) vs unknown clients.
- The Identities page renders a "via Cursor 0.42" badge so operators
  see what interface drove the action.
- Forensics — "did the customer use a known-good client or did they
  curl us with a custom script?"

Pattern matching is in [`api/nhi_map.py::_classify_ai_app`](src/vyuu_gateway/api/nhi_map.py).
Adding a new known client = one regex line.

## What happens when an upstream returns a malformed JSON-RPC message

We log a warning and return a JSON-RPC parse error to the inbound
client. The audit row records `upstream_status = error` with the parse
failure in the rule_id. We don't try to "fix" the upstream response —
that's a recipe for confusing the AI.

## Why `tools/list` from a vserver isn't a 1:1 of the upstream

A vserver projects a curated subset of upstream tools. The
`virtual_server_tools` table maps `(vserver_id) → (mcp_server_id, tool_name, display_name)`.

When an inbound `tools/list` arrives:

1. Look up the vserver's tool projection.
2. For each entry, optionally rename via `display_name`.
3. Return the curated subset, NOT the upstream's full catalog.

This is how the gateway enforces the "this vserver only exposes
read-only tools" pattern — the operator picks which upstream tools
to surface.

## What's in scope for a future MCP version

- **Capabilities versioning.** MCP doesn't yet have a great answer for
  "the upstream's tool schema changed in a backwards-incompatible
  way." We rely on the capability sync cron noticing + the operator
  reviewing the diff.
- **Streaming tool calls in vservers.** Currently we forward streams
  end-to-end; vserver-level transformation of a stream isn't
  implemented (would need protocol-aware splicing).
- **Tool-call session affinity in HA.** With multi-instance HA on the
  roadmap, we'll need to route session-bound calls to the same
  gateway instance. Today: not relevant (single instance).
