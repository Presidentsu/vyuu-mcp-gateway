# SECURITY — threat model, defenses, posture

What we defend against, what we don't, and the rules engineers must
follow when adding code.

## Threat model

### Assets

- **Tenant data** — every audit row, every API key, every IdP secret,
  every user identity. Loss-of-confidentiality across tenants is the
  primary failure mode we defend against.
- **Audit integrity** — `tool_call_events` and `admin_audit_log` are
  what compliance auditors read. Tampering or loss is a control
  failure.
- **Bearer secrets** — operator JWTs, API keys, SCIM bearers, OAuth
  refresh tokens. Compromise = access to the resource the bearer
  represents.

### Attackers

- **Cross-tenant lateral movement** (highest priority) — a malicious
  end user from tenant A trying to read tenant B's data. We assume
  this is the most likely + most damaging attack.
- **Privilege escalation** — a non-admin user trying to act as an
  admin (e.g., issue grants, disable users).
- **Audit tampering** — a compromised operator trying to delete
  audit rows to cover tracks.
- **Bearer leak** — bearer captured in transit, in logs, in a
  shared diagnostic bundle, or in a screenshot.

### Defenses

| Threat | Defense |
|---|---|
| Cross-tenant data read | RLS on every tenant-scoped table; FORCE-RLS on the load-bearing ones (audit, IdP, secrets) |
| Cross-tenant write | RLS `WITH CHECK` on insert + tenant_id pinned per session, never per query |
| Audit tampering by operator | `admin_audit_log.target_id` is NOT a FK — audit rows survive even if the target row is deleted. The operator console has no "delete audit row" UI; the only path to remove rows is direct SQL. |
| Audit loss on restart | TOOL-EVENTS-1 — `tool_call_events` is a durable Postgres table, written synchronously on every emit |
| Bearer in logs | Audit pipeline never logs full bearers. Diagnostic bundle redacts every secret-named field via `_SECRET_FIELD_PATTERNS` |
| Bearer in URLs | We refuse to put bearers in URL query strings — Authorization header only. URL params are cached / logged by intermediaries. |
| Operator JWT replay | HMAC-signed against `VYUU_OPERATOR_AUTH_SIGNING_SECRET`; rotate the secret to invalidate all tokens at once |
| API key brute force | bcrypt verify (~50 ms each); the prefix narrows candidates to ~1 row, so brute force on a target key is rate-limited by network roundtrips |
| Replay of an old API key | `revoked_at` immediately blocks; bcrypt verify still passes but the lookup returns null |
| SAML assertion replay | `pysaml2` enforces NotOnOrAfter + nonce per assertion |
| OIDC ID token tampering | JWKS signature verify + iss + aud + nonce + exp |
| SCIM bearer leak | bcrypt-stored; constant-time compare; anti-enumeration 401 returns same code for "wrong directory id" and "wrong bearer" |

## What we do NOT defend against

Be honest about the boundary:

- **Gateway-host compromise.** If an attacker has shell on the gateway
  host they can read every secret in process memory + every DB
  credential in env vars. The defense for this is OS-level (SELinux /
  AppArmor / minimal container surface / read-only root fs) — not
  application-level.
- **Postgres-host compromise.** Same — RLS doesn't help against a
  superuser on the DB box. Use OS hardening + role separation; in
  production the gateway connects as a non-superuser role with only
  the grants it needs.
- **Supply chain.** A malicious dependency could exfiltrate. We pin
  every dep in `pyproject.toml` and run dependency review on PRs, but
  ultimately we trust the upstream packages we install.
- **Side-channel timing on bcrypt.** bcrypt has a constant-ish runtime
  but isn't perfectly constant. For our use case (identifying API
  keys) the timing variance is negligible relative to network noise.
- **DDoS.** The inflight gate is a per-tenant fairness mechanism, not
  a DDoS shield. Use a reverse proxy with rate limiting + cloud WAF
  in front.
- **End-to-end encryption of tool args / responses.** TLS terminates
  at the reverse proxy. Args + responses are seen in plaintext by the
  gateway because we have to inspect them to enforce policy and audit.

## Engineer rules

### Secrets handling

1. **Never log a full bearer.** When logging an auth failure, log the
   prefix (first 8 chars) at most. The plaintext lives in the request
   for ~milliseconds; don't extend its lifetime.
2. **Never include a secret in the diagnostic bundle.** The bundle
   pattern-matches field names against `_SECRET_FIELD_PATTERNS` in
   [`api/diagnostic_bundle.py`](src/vyuu_gateway/api/diagnostic_bundle.py)
   and replaces with `[REDACTED]`. If you add a new secret-named
   field, verify the pattern matches.
3. **Never put a secret in a URL.** URLs are logged by reverse proxies,
   referrer headers leak to third parties, browser history persists.
   Use the `Authorization` header.
4. **Never `print()` an `AuditEvent`.** The `raw_args` / `raw_response`
   fields can contain caller payloads that the policy opted in to
   capture. Use the structured logger.
5. **Hash before store.** Bearers (API keys, SCIM tokens, operator
   passwords) are bcrypt-hashed before persistence. Never store
   plaintext.

### Tenant boundary

1. **Always use `get_tenant_scoped_db`** for operator-API endpoints.
   Never `get_db` (untenanted).
2. **For inbound MCP**, the `get_inbound_mcp_db(tenant_id)` dep takes
   the tenant from the URL path. Don't add an alternate path that
   skips this binding.
3. **For background jobs that need cross-tenant scan**, iterate
   `tenants` (no RLS) for discovery, then open a fresh tenant-bound
   session per work unit. Failure on one tenant must not roll back
   another.
4. **Never construct a query like** `SELECT ... FROM users WHERE
   tenant_id = X` — let RLS do that. Filter by `tenant_id` only when
   you need to disambiguate within a known-correct binding (e.g.,
   when the caller passed both `operator.tenant_id` and a separate
   tenant uuid; rare).

### Auth boundary

1. **Operator JWT** authenticates ALL `/api/v1/*` routes that aren't
   under `/auth/*`, `/portal/*`, or specifically marked public. If
   you write a new operator endpoint and don't add `Depends(authenticate_operator)`,
   it's public. Verify with a curl test.
2. **Portal session JWT** authenticates `/api/v1/portal/*`.
3. **API key** authenticates `/v/{tenant_id}/{vserver_name}/mcp`.
4. **SCIM bearer** authenticates `/scim/v2/{directory_id}/*`.
5. **Don't mix bearers across surfaces.** An operator JWT is NOT
   accepted on the inbound MCP path; an API key is NOT accepted on
   the operator API. Each surface has one resolver.

### Adding a mutating operator endpoint

Every mutating action MUST emit an `admin_audit_log` row in the same
transaction. Pattern:

```python
def your_service_function(
    db: Session,
    *,
    tenant_id: UUID,
    actor: AdminAuditActor,    # operator passes this from the JWT
    ...
) -> Thing:
    # ... do the mutation ...
    db.add(thing)

    # Same-transaction audit:
    record_admin_action(
        db,
        tenant_id=tenant_id,
        actor=actor,
        action="thing.create",
        target=AdminAuditTarget("thing", thing.id, thing.name),
        detail={"some": "context"},
    )
    db.commit()  # ← commits the mutation AND the audit row atomically
    return thing
```

The `record_admin_action()` helper calls `db.add(audit_row)` but
**never** commits. The caller commits both together. If the request
rolls back, the audit row rolls back too — auditor sees exactly the
actions that happened.

### Adding a new policy / decision point

If you're extending the lifecycle to add a new decision point (a new
DENY reason, a new REDACT path), make sure:

1. The decision is recorded in the `AuditEvent.decision` +
   `policy_rule_id` so it shows up on the Events page.
2. The denial path is testable end-to-end (don't just unit-test the
   policy — test that the request returns the right HTTP shape and
   the audit row lands).
3. The metric for "this rule fired N times" is queryable from the
   `tool_call_events` table without code changes.

## Dependency policy

1. **Pin every dep** with a tilde or compatible-release constraint
   in `pyproject.toml`. Open ranges are footguns.
2. **No `git+` or `file://` deps in production.** They bypass the
   integrity check pip does for PyPI deps.
3. **Audit transitive deps quarterly** with `pip-audit` (or `uv pip
   audit`). Critical CVEs trigger an immediate patch release.
4. **System deps** that aren't installable via pip (xmlsec1, libpq):
   document them in `SETUP.md` and the Dockerfile.

Today's hard system deps:
- `xmlsec1` (pysaml2 wraps it)
- `libpq` (psycopg uses it)

## Reporting

For any suspected security issue:

1. Don't open a public issue on the repo.
2. Email the maintainer (see HANDOFF.md for current contacts).
3. Include: repro steps, observed behavior, expected behavior,
   diagnostic bundle if relevant.

## Outbound SSRF: two layers (H1)

1. **Registration** (`registry/url_security.py`) — scheme, denylist,
   allowlist, blocked hostname literals, unsafe IP literals.
2. **Connect time** (`upstream/ssrf_guard.py`) — re-resolves the hostname
   immediately before each outbound connection, rejects if **any**
   resolved address is loopback/private/link-local/reserved, and **pins**
   the connection to the address it validated.

Layer 2 exists because layer 1 cannot see where a *name* points. Pinning
exists because validate-then-reresolve is a TOCTOU race that DNS
rebinding is designed to win. TLS is unaffected: the original hostname is
carried as `Host` and `sni_hostname`, so certificate validation still
runs against the registered name.

Both layers read the same three settings, so they cannot drift:
`VYUU_HTTP_URL_ALLOW_PRIVATE_NETWORKS`, `VYUU_HTTP_URL_ALLOWLIST`,
`VYUU_HTTP_URL_DENYLIST`. Layer 2 can be disabled with
`VYUU_UPSTREAM_SSRF_GUARD_ENABLED=false`; layer 1 cannot.

**If an internal upstream stops connecting after upgrading**, that is
layer 2 doing its job on a name that resolves privately. Allowlist the
host or set `VYUU_HTTP_URL_ALLOW_PRIVATE_NETWORKS=true` — the error
message says so too.

**Not covered:** a compromised resolver. If DNS lies, we validate and pin
to the lie.

## The one deliberate hole in FORCE RLS: `app.scim_bootstrap`

`idp_directories` is ENABLE + FORCE RLS, but SCIM auth has to resolve a
directory by id *before* it knows the tenant — the directory row is what
tells us the tenant. Migration `20260825_0019` opens exactly that read
with a second PERMISSIVE, **SELECT-only** policy:

```sql
USING (
    NULLIF(current_setting('app.current_tenant_id', TRUE), '') IS NULL
    AND current_setting('app.scim_bootstrap', TRUE) = 'on'
)
```

Properties, all verified by tests and against Postgres directly:

- An unbound query that does **not** set the flag still sees nothing —
  the flag is an explicit door, not a removed wall.
- `set_config(..., is_local => true)` scopes it to one transaction, so
  the capability cannot leak into the rest of the request.
- SELECT-only by construction: it can never permit a write.
- A *bound* session that also sets the flag is unaffected — it still sees
  only its own tenant.

`scim/auth.py` is the only caller. If you need another untenanted read,
do not reuse this flag — add a separate, equally narrow one, so the
audit question "what can read this table without a tenant?" stays
answerable by grepping for policies.

Note for anyone tempted by `SECURITY DEFINER` on a FORCE-RLS table: it
does not work. FORCE subjects the table **owner** to its own policies,
and a definer function runs as the owner. Only `BYPASSRLS` escapes.

## Just-in-time access (JIT-1)

Private vservers can offer **time-boxed** elevation instead of standing
grants. Off per-vserver by default; an operator enables it with
`PATCH /api/v1/vservers/{id}/jit`.

- The grant carries `expires_at` and is enforced by the *existing* path:
  `virtual_servers/access.py` skips lapsed grants, and the inbound
  handler re-runs that check on **every request**, so an elevation that
  lapses mid-session cuts off at the next tool call. No sweeper is
  involved and none is needed.
- `granted_via` records provenance — `operator` / `jit_auto` /
  `jit_approved`. `granted_by` is NULL on `jit_auto` rows *by design*:
  no human decided it, so no human is named.
- Every elevation writes a `grant.jit_issue` row to `admin_audit_log`
  with the duration, expiry, and the user's stated reason. Turning the
  policy on or off writes `vserver.jit_enable` / `vserver.jit_disable`.
- **JIT cannot be enabled on a `public` vserver** — it needs no grant, so
  there is nothing to elevate into.
- Requests longer than the vserver's ceiling are **rejected, not
  clamped**, and an approver may grant less than was asked for but never
  more.
- `GET /api/v1/vservers/jit/elevations` answers "who has temporary access
  right now", including operator-issued time-boxed grants.

**What JIT does not do.** Disabling JIT on a vserver does not revoke
elevations already running — they expire on their own schedule. Revoke
them individually if access must stop immediately. Per-*tool* elevation
is JIT-2 in `BACKLOG.md`, not shipped.

## Audit + compliance posture

- Retention for both durable audit tables is enforced by the
  `RetentionSweeper` (`audit/retention.py`), a daily background job.
  **Both windows default to `0` = keep forever** — the module supplies
  the mechanism, the deployment supplies the policy. Nothing is deleted
  until you opt in:

  ```
  VYUU_TOOL_CALL_EVENT_RETENTION_DAYS=90     # 0 = keep forever (default)
  VYUU_ADMIN_AUDIT_RETENTION_DAYS=365        # 0 = keep forever (default)
  ```

- `tool_call_events`: 90 days suits typical compliance horizons.
- `admin_audit_log`: this is what auditors read — keep it a year or
  more. The gateway **refuses to start** if this window is shorter than
  the `tool_call_events` window, because this table holds the
  `retention.prune` rows that explain why event history disappeared;
  discarding it first would delete the explanation for a gap that is
  still visible.
- Every prune that deletes anything writes a `retention.prune` row to
  `admin_audit_log` (`actor_kind='system'`) recording the table, cutoff,
  row count, and whether the cycle hit its per-cycle cap. Rows never
  vanish without a record.
- Deletes are chunked and capped (`VYUU_AUDIT_RETENTION_BATCH_SIZE`,
  `VYUU_AUDIT_RETENTION_MAX_ROWS_PER_CYCLE`) so the first prune after
  opting in drains over several cycles instead of holding one enormous
  transaction against the live audit write path.
- Retention state — configured windows, last run, last row counts — is
  reported in the diagnostic bundle under
  `background_workers.audit_retention_sweeper`.
- Both tables can be exported to a SIEM via the audit fan-out chain
  (Kafka / NATS) for warehouse-style long-term retention. The Postgres
  tables are the live operational store.
