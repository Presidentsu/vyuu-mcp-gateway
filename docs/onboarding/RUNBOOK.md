# RUNBOOK — if X breaks, do Y

Operational firefighting. Each entry: symptom → cause → fix.

## Triage step 0: download the diagnostic bundle

Operator console → **Settings → Troubleshooting → Download diagnostic
bundle**. The JSON has every section needed for the entries below. If
you can't reach the operator console, hit the endpoint directly:

```bash
curl -H "Authorization: Bearer <operator-jwt>" \
  http://gateway/api/v1/admin/diagnostic-bundle?since_minutes=60 \
  -o bundle.json
```

Bundle structure: see `BACKEND.md` (`api/diagnostic_bundle.py`) for the
full section list.

---

## Symptom: Operator dashboard panels are blank after a restart

**Was:** before TOOL-EVENTS-1, the in-memory ring buffer reset on
every gateway restart, so the Events / NHI map / Identities pages
showed nothing until fresh traffic arrived.

**Now (post-fix):** the buffer is rehydrated from `tool_call_events`
on lifespan startup. If you still see blank panels:

1. Check the startup log for `audit_buffer_seeded events=N tenants=M`.
   If absent, warm-up failed or the panel is older than the fix.
2. Check the bundle's `audit_buffer_warmup` section:
   - `buffer_current_size` should be > 0 if `persistent_audit.total_events` > 0.
3. If buffer is empty but the table has events: look for
   `audit_buffer_warmup_failed` log line.
4. Verify RLS isn't blocking the read: the warm-up binds tenant context
   per tenant; if `bind_tenant_context` raises, you'll see it in logs.

**Workaround:** the panels query Postgres directly with a 24h window
by default. So even if warm-up failed, the data is there as soon as
you click Refresh — you just lose the live tail until traffic resumes.

---

## Symptom: Inbound MCP calls are rejected with 503

**Cause:** the per-tenant inflight gate is shedding traffic.

**Diagnose:** bundle's `inflight_gate.configured_per_tenant_cap` shows
the cap. Bundle's `audit_buffer.upstream_status_counts` shows how many
calls are in flight by recent decision pattern.

**Fix:**
- Short term: bump `VYUU_INBOUND_PER_TENANT_INFLIGHT_LIMIT` and restart.
- Long term: investigate why one tenant is generating that much traffic
  — check the Identities page filtered to that tenant for the noisy
  principal.

---

## Symptom: An upstream MCP server keeps returning 5xx

**Cause:** circuit breaker for that pool key is opening.

**Diagnose:** bundle's `circuit_breakers.open_keys` lists open pool
keys. Pool key format: `(tenant_id, server_id, principal_id)`.

**Fix:**
1. Hit Health & servers page → look at the row for that server. If
   `health_status=down` and `last_health_error` says something like
   "connection refused", the upstream is the problem.
2. If the upstream is up but slow, the breaker may be tripping on
   timeouts. Check `latency_ms_total` on recent events for that
   server in the diagnostic bundle's `persistent_audit`.
3. To force-close a breaker: restart the gateway (no per-pool reset
   API yet).

---

## Symptom: SCIM provisioning isn't pushing users

**Cause:** several possibilities; walk through each.

**Diagnose:**

```bash
# Did the IdP successfully POST to /scim/v2/{directory_id}/Users?
grep "/scim/v2" gateway.log | tail -50

# Check the directory's last_sync_at timestamp:
psql -c "SELECT display_name, kind, last_sync_at FROM idp_directories WHERE tenant_id = '...';"
```

**Fix matrix:**

| Symptom in IdP UI | Fix |
|---|---|
| "401 Unauthorized" | The SCIM bearer the IdP has is wrong / rotated. Re-issue from the IdP directory connect flow, paste the new plaintext into the IdP. |
| "404 Not Found" | The directory id in the SCIM endpoint URL is wrong. Copy the exact URL from the operator console's IdP detail page. |
| "Connection refused" | The IdP can't reach the gateway. For Entra, ensure the gateway is internet-reachable (or use Application Proxy). For Workspace, custom SAML apps don't push SCIM at all (see IDP-2 backlog item). |
| Provisioning succeeds but users don't appear | Check `users.idp_directory_id` matches the directory + look for `User.soft_deleted_at IS NOT NULL` (the user exists but is soft-deleted within the 7-day grace). |

---

## Symptom: SAML sign-in fails with "Audience does not match"

**Cause:** the IdP's configured Entity ID doesn't match the SP's
expected audience.

**Fix:**
1. The SP entity_id is per-directory:
   `https://<host>/api/v1/auth/{tenant_id}/idp/{directory_id}`.
2. In the IdP (Entra Custom App / Workspace SAML App), set the
   "Audience URI" / "Identifier" to exactly that string.
3. Re-test "Test SAML Login" from the IdP.

If it fails with "Unsolicited response":
- We set `allow_unsolicited: True` so this should work for IdP-initiated
  flows. If you see this error, you're probably running an old build.
  Check `idp/saml_provider.py` for the SP config.

---

## Symptom: Operator JWT errors flood the logs

**Cause:** `VYUU_OPERATOR_AUTH_SIGNING_SECRET` was rotated and
operators have stale tokens.

**Fix:** operators sign in again. There's no graceful overlap — by
design (see `AUTH.md`).

---

## Symptom: Database queries are slow

**Diagnose:**

```bash
# In psql, set statement_timeout for the session and look for slow queries.
psql -d vyuu_gateway -c "SELECT pid, age(clock_timestamp(), query_start), state, query
                        FROM pg_stat_activity
                        WHERE state != 'idle' ORDER BY 2 DESC LIMIT 10;"
```

**Common culprits:**

- `tool_call_events` queries without a tenant filter would full-scan.
  All endpoint queries DO scope by tenant — verify you're not running
  ad-hoc admin SQL without a filter.
- A missing index on `(tenant_id, occurred_at)` — should be present
  via the migration. Verify with `\d tool_call_events`.
- Postgres autovacuum hasn't run. Check `pg_stat_user_tables.last_autovacuum`.

**Fix:** if `tool_call_events` is large (millions of rows), partition
by month — not in current schema. File an issue if you hit this.

---

## Symptom: SCIM hard-delete sweeper isn't running

**Diagnose:** bundle's `background_workers.scim_hard_delete_sweeper`:
- `running: false` → wiring problem; check startup logs for
  `hard_delete_sweep_cycle_failed`.
- `cycles_completed: 0` after 1+ hours → the worker started but the
  first cycle is stuck.

**Fix:**
1. Restart the gateway.
2. If it persists, check Postgres for held locks on `users` from a
   stuck sweeper transaction.

---

## Symptom: A user can sign in but their MCP API key doesn't work

**Diagnose:**

```bash
# In psql:
SELECT email, disabled_at FROM users WHERE email = '...';
SELECT k.id, k.created_at, k.revoked_at FROM user_api_keys k
  JOIN users u ON k.user_id = u.id WHERE u.email = '...';
```

**Fix matrix:**

| Symptom | Cause | Fix |
|---|---|---|
| `disabled_at IS NOT NULL` | User was disabled by an admin or SCIM | Re-enable in operator console → Users |
| All keys have `revoked_at IS NOT NULL` | All keys were revoked | Issue a new key from the portal |
| Key is active but inbound MCP returns 401 | bcrypt verify failure → the bearer the client has is wrong | Issue a new key (we never store plaintext to recover) |
| 401 with `auth_failure_reason=no_grant` in audit | The vserver is `private` and this user has no `virtual_server_grants` row | Operator grants access via Virtual servers → grant |

---

## Symptom: Disk filling up

**Diagnose:**
- `tool_call_events` table size: `SELECT pg_size_pretty(pg_total_relation_size('tool_call_events'));`
- `admin_audit_log` size: same.
- `oauth_user_tokens` size (refresh tokens accumulate).

**Fix:**

- For `tool_call_events` / `admin_audit_log`: turn on retention. The
  `RetentionSweeper` runs daily but both windows default to `0` (keep
  forever), so an untouched deployment prunes nothing:

  ```
  VYUU_TOOL_CALL_EVENT_RETENTION_DAYS=90
  VYUU_ADMIN_AUDIT_RETENTION_DAYS=365     # must be >= the events window
  ```

  Restart, then confirm it is firing via the diagnostic bundle's
  `background_workers.audit_retention_sweeper` (`cycles_completed`,
  `last_run_at`, `last_rows_deleted`). The first cycle runs 60s after
  startup and daily thereafter.

  A large backlog drains over several cycles by design —
  `last_cycle_hit_cap: true` means more rows are still owed, not that
  anything failed. To drain faster, raise
  `VYUU_AUDIT_RETENTION_MAX_ROWS_PER_CYCLE`.

  Do NOT hand-run `DELETE FROM tool_call_events ...`: both tables are
  FORCE-RLS so an unbound DELETE silently matches zero rows, and a
  manual delete leaves no `retention.prune` audit row explaining the
  gap to an auditor.
- For `oauth_user_tokens`: revoke + delete tokens for disabled users.
  The hard-delete sweeper handles this if a user is hard-deleted.

---

## Symptom: "I changed code but the lab doesn't pick it up"

**Cause:** uvicorn isn't running with `--reload`.

**Fix:** restart `python examples/drawio_lab_server.py`. The lab server
is a one-shot dev process; it doesn't watch for file changes.

For an auto-reload dev loop:

```bash
uvicorn vyuu_gateway.main:create_app --factory --reload --host 127.0.0.1 --port 8000
```

---

## When to escalate

Anything that involves:
- Lost data (committed rows missing) → before doing anything,
  PG_DUMP the affected tables. Don't experiment on a damaged DB.
- A confirmed cross-tenant data leak → high-severity. Quote the exact
  query that reproduced it; check if RLS was correctly bound.
- Repeated process crashes → grab `dmesg` / `journalctl` output;
  download the diagnostic bundle from the most recent successful
  start; then file an incident.

## Where to find more help

- `BACKLOG.md` — open work + decision log; many fixes are documented
  here as the rationale for the architecture.
- `docs/PLATFORM.md` — long-form platform overview.
- `docs/TROUBLESHOOTING.md` — older troubleshooting compendium with
  more historical cases.
