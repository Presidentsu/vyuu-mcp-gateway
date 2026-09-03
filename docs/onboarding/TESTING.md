# TESTING — what's covered, how to run

## Test counts

```
952 pass with VYUU_TEST_DATABASE_URL set (real Postgres integration)
804 pass without (unit + light integration only)
```

Coverage is heavy on:
- Multi-tenant isolation (cross-tenant reads must return zero rows)
- Audit pipeline (write path + read path + persistence-across-restart)
- Auth surfaces (operator JWT, portal session, SCIM bearer, OIDC, SAML)
- Inbound MCP lifecycle (deny / allow / redact / rewrite paths)
- IDP-1 SCIM (Entra Operations[] + Workspace members[] PATCH shapes)

## Layout

```
tests/
  api/                Per-router endpoint tests
  audit/              Audit pipeline (events, recent, persistent, identity_aggregator, kafka, nats, clickhouse)
  capabilities/       Sync scheduler + upstream adapter
  db/                 Migrations + RLS helpers
  graph/              identity_graph queries
  identity/           Identity provider (api_key + fake)
  idp/                IDP-1 service + sweeper + saml_provider
  integration/        Real-Postgres + cross-component flows
  mcp/                MCP transport (sse / streamable_http / stdio)
  operator_auth/      Operator JWT + password auth
  perf/               Load tests (separate, opt-in)
  policy/             SimplePolicyProvider + ManagementPlanePolicyProvider
  registry/           users / groups / access_requests services
  scim/               SCIM server + auth
  secrets/            Secret store backends
  sessions/           In-memory + Redis registries
  tenant_isolation/   Cross-tenant proof harness
  upstream/           Pool, circuit breaker, OAuth-AC, JWT-bearer
  users/              Login endpoint, OIDC providers, JWKS
  virtual_servers/    Service + validation
```

The layout mirrors `src/`. If you add `src/vyuu_gateway/foo/bar.py`,
the test goes in `tests/foo/test_bar.py`.

## Running

```bash
# Quick — unit + light integration, no DB needed.
pytest

# Full — real Postgres integration tests opt in via this env var.
VYUU_TEST_DATABASE_URL=postgresql+psycopg://vyuu@127.0.0.1:5432/vyuu_gateway pytest

# A single file:
pytest tests/audit/test_persistent_store.py -v

# A single test:
pytest tests/audit/test_persistent_store.py::test_query_returns_persisted_events_after_restart -v

# Skip slow / perf tests (they're tagged):
pytest -m "not perf"

# Re-run only failures from last run:
pytest --lf
```

## Conventions

### DB-integration tests

All real-DB tests gate on `VYUU_TEST_DATABASE_URL`:

```python
import os
_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

# ... imports of vyuu_gateway happen AFTER ...

pgmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set",
)

@pgmark
def test_thing():
    ...
```

The early env-var swap is required because `db/session.py` builds the
`engine` at import time. Conftest at `tests/conftest.py` does the same
promotion.

### Tenant fixture pattern

DB-integration tests seed a tenant + operator + cleanup via `try/finally`:

```python
factory = _factory()
tenant_id, operator_id = _seed_tenant_and_operator(factory)
try:
    client, app, headers = _make_client(tenant_id, operator_id)
    # ... assertions ...
finally:
    _cleanup(factory, tenant_id)
```

`_cleanup` deletes the tenant; cascades drop everything tenant-scoped.

### Asserting RLS

`tests/integration/test_rls_real_postgres.py` is the canonical RLS
proof harness. It creates a non-bypassing role and verifies that
queries without `app.current_tenant_id` return zero rows from any
RLS-enabled table.

### Persistent-audit tests

`tests/audit/test_persistent_store.py` covers the load-bearing
guarantee for TOOL-EVENTS-1:
- `test_emit_persists_to_postgres` — write goes durable
- `test_query_returns_persisted_events_after_restart` — read survives restart
- `test_buffer_warmup_rehydrates_from_postgres` — startup hook works
- `test_rls_blocks_cross_tenant_reads` — RLS enforces isolation

## Writing a new test

Copy an existing test in the same area as a starting point. Patterns
to follow:

- **Don't override `get_tenant_scoped_db`** with a fake — it bypasses
  RLS and can mask bugs. Use a real DB instead.
- **Use `with TestClient(app) as client:`** so the lifespan startup
  fires (audit buffer warm-up, etc.).
- **Make events flow through the chain** with
  `app.state.recent_audit_emitter.emit_nowait(event)` — that exercises
  the full Postgres + buffer write path.
- **Always cleanup** in `finally` with `_cleanup(factory, tenant_id)`
  so tests don't leave residual rows.

## CI gotchas (when wiring to CI)

- Provision a Postgres before the test job; run `alembic upgrade head`
  to create the schema.
- Set `VYUU_TEST_DATABASE_URL` and `VYUU_OPERATOR_AUTH_SIGNING_SECRET`.
- `xmlsec1` system binary is needed at install time, not just runtime
  — pysaml2 imports xmlsec1 lazily but tests that exercise SAML code
  paths will fail without it. CI image needs `apt-get install xmlsec1`
  (or equivalent).
- Some tests run subprocesses for stdio MCP servers. The CI runner
  needs `npx`, `uvx` (or matching pinned versions). Skip these tests
  in minimal CI with `pytest -m "not stdio_subprocess"`.

## Pre-existing failures (NOT regressions)

When running with `VYUU_TEST_DATABASE_URL`, a small set of tests fail
in local-dev environments that don't have the production DB-role
hardening:

- `tests/integration/test_rls_real_postgres.py` — needs `CREATEROLE`
  on the test role.
- `tests/audit/test_admin_audit.py` — depends on the test session being
  tenant-bound; some tests use raw sessions.
- `tests/scim/test_scim_server.py` — auth setup with the lab
  configuration; runs cleanly in CI with full env.

These are setup gotchas, not real failures. See `RUNBOOK.md` for fixes.
