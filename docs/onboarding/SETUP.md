# SETUP — local dev bring-up

Goal: from a fresh machine, get the gateway running, the operator
console reachable, and the lab MCP servers callable in ~15 minutes.

## Prerequisites

- macOS or Linux (Windows works via WSL2; native Windows is not exercised)
- **Python 3.12+** (3.14 verified). Use a virtualenv.
- **PostgreSQL 16** (14+ works) running locally or reachable. We use psycopg v3.
  Note: a superuser role bypasses row-level security; fine for a lab, never for
  production (see `docs/DEPLOYMENT.md`).
- **`xmlsec1`** system binary — required by `pysaml2` for SAML signing.
  - macOS: `brew install libxmlsec1`
  - Debian/Ubuntu: `apt-get install xmlsec1 libxmlsec1-dev`
  - RHEL/Rocky: `dnf install xmlsec1 xmlsec1-openssl`
- (optional) **Redis** if you want to run the Redis-backed session
  registry instead of the in-memory default.
- (optional) **`uv`** for faster venv + dependency resolution — and **required**
  (`uvx`) if you register `pypi` stdio MCP servers.
- (optional) **Node.js 18+** — `npx` is required if you register `npm` stdio
  MCP servers, and `node` runs the console JS-syntax test in `pytest`.
- (optional) `pip install -e ".[otel]"` for OpenTelemetry export;
  `".[kafka]"` / `".[nats]"` for broker audit producers.

## 1. Get the code

```bash
cd ~/Desktop
git clone https://github.com/<your-org>/secure-mcp-gateway.git
cd secure-mcp-gateway
```

## 2. Python venv + deps

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
# pyproject.toml pins everything; this installs the gateway + dev deps.
```

## 3. Postgres

Create a database + role. The default name is `vyuu_gateway`.

```bash
# macOS Homebrew Postgres:
createuser -s vyuu          # superuser is fine for local dev
createdb -O vyuu vyuu_gateway

# Verify reach:
psql -U vyuu -d vyuu_gateway -c "select version();"
```

For production you DO NOT use a superuser — see `DEVOPS-HANDOFF.md`
section "Database role hardening" for the minimal grants.

## 4. Environment

```bash
cp .env.example .env
# Edit .env:
#   - VYUU_DATABASE_URL    → matches your local postgres
#   - VYUU_OPERATOR_AUTH_SIGNING_SECRET → 32+ random bytes
#   - VYUU_DEFAULT_TENANT_ID → keep the default for single-tenant lab mode
```

A quick way to mint a strong secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

## 5. Apply migrations

```bash
# `alembic.ini` reads the URL from VYUU_DATABASE_URL.
alembic upgrade head
# Applies every revision up to the current head (`alembic current` shows it).
```

To verify the schema landed:

```bash
psql -U vyuu -d vyuu_gateway -c "\d tool_call_events" | head -10
```

## 6. Lab bootstrap (optional but recommended)

Seed a tenant + operator + a few demo MCP servers + virtual servers
so the operator console isn't empty on first login.

```bash
python examples/lab_bootstrap.py
```

This is idempotent — re-run as many times as you want.

## 7. Run the gateway

Two options, pick one.

### Option A — drawio lab (one-shot dev server with seed data + helper output)

```bash
python examples/drawio_lab_server.py
```

This is the same entrypoint we use during development. It prints:
- The operator-console URL: <http://127.0.0.1:8000/operator>
- The portal URL: <http://127.0.0.1:8000/portal>
- A pre-minted operator bearer token you can paste into the console
- Cursor / Claude Desktop config blocks for the demo MCP servers

### Option B — uvicorn directly (closer to production)

```bash
uvicorn vyuu_gateway.main:create_app --factory --host 127.0.0.1 --port 8000
```

You'll need an operator token: either sign in with email + password
(create the first admin with the `VYUU_BOOTSTRAP_*` variables), or mint a
lab token with `vyuu_gateway.operator_auth.fake.mint_operator_test_token`
(the lab server prints one).

## 8. First sign-in

1. Open <http://127.0.0.1:8000/operator>.
2. Because `VYUU_DEFAULT_TENANT_ID` is set, the tenant input is hidden.
3. Paste the operator bearer token from the lab server's stdout into the
   "Advanced: paste a bearer token directly" disclosure → **Sign in**.
4. You should land on the Dashboard. Click **Health & servers** in the
   sidebar to see the new Health page; click **Settings → Troubleshooting**
   to download a diagnostic bundle.

For the end-user portal, sign in at <http://127.0.0.1:8000/portal/> with
a local user (the lab seeds `alice@vyuu.dev` / password
`very-strong-12+chars`). Issue an API key from the portal, then paste it
into the Cursor / Claude Desktop config from step 7.

## 9. Run the tests

```bash
# Unit + light integration (no DB needed):
pytest

# Full suite including real-Postgres integration:
VYUU_TEST_DATABASE_URL=postgresql+psycopg://vyuu@127.0.0.1:5432/vyuu_gateway pytest
```

See `TESTING.md` for the layout and current counts.

## 10. Stop / clean up

The lab server is a regular Python process — `Ctrl+C` to stop. To
nuke + re-create the lab database:

```bash
dropdb vyuu_gateway && createdb -O vyuu vyuu_gateway
alembic upgrade head
python examples/lab_bootstrap.py
```

## Common first-day snags

| Symptom | Fix |
|---|---|
| `xmlsec1: command not found` on import | Install xmlsec1 system package (step 0). It's a system binary `pysaml2` shells out to. |
| `psycopg.errors.InsufficientPrivilege` on first migration | Your DB role needs CREATE on the schema. Easiest local fix: make the role a superuser. For prod see `DEVOPS-HANDOFF.md`. |
| Operator console says "missing bearer token" | Paste the token from the lab server's stdout into the **Advanced** disclosure. The token expires when the process restarts (it's HMAC-signed against `VYUU_OPERATOR_AUTH_SIGNING_SECRET`). |
| Portal sign-in 401s | Either you're using a token from a different gateway run (signing secret changed), or the user doesn't exist. Re-run `lab_bootstrap.py`. |
| Dashboard panels are blank after restart | This used to be a known issue (in-memory ring buffer reset). Fixed in TOOL-EVENTS-1 — see `BACKLOG.md`. The buffer now warms from `tool_call_events` on lifespan startup; check the log line `audit_buffer_seeded events=N tenants=M`. |

## What's next

Read `ARCHITECTURE.md` to understand the data flow, then `KNOWLEDGE_BASE.md`
for a jump-table to specific files.
