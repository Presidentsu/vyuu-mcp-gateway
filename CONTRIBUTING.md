# Contributing

Thanks for looking under the hood. This page is the short version of how
the codebase expects to be worked on; the long version is
[`docs/onboarding/`](docs/onboarding/README.md).

## Ground rules (from `AGENTS.md`)

- The gateway is a **data plane**, not a management plane, and never an LLM
  model gateway.
- **Tenant isolation is non-negotiable.** Every tenant-scoped table carries
  `tenant_id`; every tenant-scoped query filters on it; Postgres row-level
  security backs it up. `tests/tenant_isolation/` enforces this — adding a
  table without updating the inventory there fails the suite on purpose.
- **Never store secrets in plaintext.** Credentials live in the secret store
  and are referenced by name; the database holds references.
- **Never log** API keys, bearer tokens, OAuth tokens, full tool arguments or
  responses by default, or customer business data unless policy opted in.
- Upstream MCP servers are **untrusted**. Least privilege by default.

## Before you open a pull request

```bash
pytest                                  # unit + light integration (no database)
VYUU_TEST_DATABASE_URL=postgresql+psycopg://vyuu@127.0.0.1:5432/vyuu_gateway_test pytest
ruff check .
mypy .
```

Notes that save time:

- `pyproject.toml` already passes `-q` to pytest; adding your own `-q` hides
  the summary line entirely.
- The real-database suite creates and drops its own rows; point it at a
  disposable database that is migrated to head (`alembic upgrade head`).
- Two RLS tests assert that rows are *hidden* and therefore cannot pass on a
  superuser connection (superusers bypass RLS). Run the database suite as a
  non-superuser role, or accept those two as environmental.
- `ruff` and `mypy` carry a small known baseline of findings in files you did
  not touch; keep the count from growing and leave the rest.

## Conventions

- **Tests mirror `src/`.** `src/vyuu_gateway/foo/bar.py` → `tests/foo/test_bar.py`.
  `tests/` is not a package: do not import helpers across test modules, and
  keep test file basenames unique across directories.
- **Migrations** follow [`docs/onboarding/MIGRATIONS.md`](docs/onboarding/MIGRATIONS.md):
  one logical change per revision, filename `YYYYMMDD_NNNN_short_description.py`,
  a docstring that explains *why*, both `upgrade()` and `downgrade()`,
  `ENABLE` + `FORCE ROW LEVEL SECURITY` on tenant-scoped tables.
- **Admin actions are audited in the same transaction** via
  `record_admin_action(...)` — never commit inside it, never use a separate
  session for the audit row.
- **Module docstrings explain intent**, not mechanics. Comments answer "why",
  and are expected to be read.
- **UI** lives in two Python strings (`api/operator_ui.py`, `api/portal_ui.py`):
  no build step, strict CSP (`style-src 'self'` — set styles through CSSOM,
  never `style=` attributes), and `_JS` in the operator console is a plain
  string, so a JavaScript `\n` must be written as `\\n`.
- **Structured logging** everywhere (`logger.info("event_name", extra={...})`);
  the JSON formatter forwards `extra` keys.

## What a good pull request looks like

1. A failing test that shows the problem, then the fix.
2. The docstring or comment that will stop the next person from reintroducing it.
3. `docs/onboarding/CHANGELOG.md` entry when a migration, endpoint, or
   configuration variable changes.
4. `BACKLOG.md` updated if you closed or discovered an item.

## Reporting security issues

See [`SECURITY.md`](SECURITY.md). Please do not open public issues for
vulnerabilities.
