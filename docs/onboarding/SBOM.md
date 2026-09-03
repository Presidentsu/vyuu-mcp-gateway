# SBOM — Software Bill of Materials

Every third-party package the gateway depends on, with version,
license, and what it does. Maintained as part of the source tree so
audit / security review / vendor risk-assessment is one file.

**Snapshot taken:** 2026-05-05 (re-run the regenerate command at the
bottom whenever `pyproject.toml` changes).

**Counts:** 14 direct runtime deps · 4 dev deps · 3 optional groups
(kafka / nats / perf) · 78 packages total when fully installed
(direct + transitive).

---

## Quick risk callouts

Read this first if you're doing a security / legal review:

| Concern | Affected | Notes |
|---|---|---|
| **LGPL-3.0** copyleft | `psycopg`, `psycopg-binary` | Used as a dynamically-linked Python library at runtime — LGPL allows this in proprietary software. Would only become an issue if shipping a single-binary build that statically embeds psycopg. |
| **MPL-2.0** file-level copyleft | `certifi`, `pathspec` | We don't modify these files. MPL only requires publishing modifications to the licensed FILES — not derivative works that link them. Fine for proprietary use. |
| **System binary dep** | `xmlsec1` (libxmlsec1) | Required by `pysaml2` for SAML signature ops. Apache 2.0 / GPL dual licensed at the C-library level — call it from your build, don't statically link. |
| **Native libpq dep** | `psycopg` driver | The `[binary]` extra ships precompiled wheels with libpq embedded; otherwise host needs `libpq-dev` / `libpq` system package. |

Everything else is permissive (MIT / BSD / Apache / Unlicense / ISC /
PSF). 78-package dependency tree, 0 GPL, 0 SSPL, 0 commercial lock-ins.

---

## Direct runtime dependencies

From [`pyproject.toml`](pyproject.toml) `project.dependencies`. These
are the packages our code imports directly.

| Package | Pin | License | Purpose |
|---|---|---|---|
| **alembic** | >=1.14.0 | MIT | DB migration tool for SQLAlchemy. Reads `alembic.ini`, applies `migrations/versions/`. |
| **bcrypt** | >=4.0.0 | Apache-2.0 | Password / API-key / SCIM-token hashing. Cost factor 12 by default. |
| **boto3** | >=1.35.0 | Apache-2.0 | AWS SDK. Used for an optional S3-backed audit spool + a future Vault/KMS secret-store backend. Lazy-imported. |
| **email-validator** | >=2.0.0 | Unlicense | Email format + deliverability validation; pulled in by Pydantic field validators. |
| **fastapi** | >=0.115.0 | MIT | HTTP framework. Routers, dependency injection, OpenAPI. |
| **httpx** | >=0.27.0 | BSD-3-Clause | HTTP client for upstream MCP calls, OIDC discovery, JWKS fetch, OAuth flows. |
| **jsonschema** | >=4.20.0 | MIT | JSON-schema validation for SCIM payloads + per-tool `args_summary` shape checks. |
| **mcp** | >=1.13.0 | MIT | Official MCP Python SDK — spec-compliant types + transport helpers. |
| **psycopg[binary]** | >=3.2.0 | LGPL-3.0-only | Postgres driver (v3, NOT psycopg2). The `[binary]` extra ships precompiled wheels (libpq embedded). |
| **pyjwt[crypto]** | >=2.8.0 | MIT | Operator JWT mint/verify (HMAC-SHA256), portal session JWT, OIDC ID-token verify. `[crypto]` pulls in `cryptography` for RSA + EC algorithms. |
| **pydantic-settings** | >=2.6.0 | MIT | Env-var-driven Settings class. Field aliases for `VYUU_*` env names. |
| **pysaml2** | >=7.0 | Apache-2.0 | SAML 2.0 SP for IdP-1 directories. **Wraps the `xmlsec1` system binary** for signature ops — production hosts need `apt-get install xmlsec1` / `brew install libxmlsec1`. |
| **redis** | >=5.0.0 | MIT | Redis client for the optional `RedisSessionRegistry` (multi-instance HA). In-memory default doesn't need it. |
| **sqlalchemy** | >=2.0.36 | MIT | ORM + Core. Used with the synchronous API + the `after_begin` event hook for RLS GUC binding. |
| **uvicorn[standard]** | >=0.32.0 | BSD-3-Clause | ASGI server. `[standard]` adds httptools + uvloop + websockets + watchfiles. |

## Optional dependency groups

Installed as `pip install -e ".[group]"`.

### `dev` — for development + tests

| Package | Pin | License | Purpose |
|---|---|---|---|
| **mypy** | >=1.13.0 | MIT | Type checker. Strict mode in `[tool.mypy]`. |
| **pytest** | >=8.3.0 | MIT | Test framework. Conftest at `tests/conftest.py`. |
| **ruff** | >=0.7.0 | MIT | Linter + formatter. Rules in `[tool.ruff.lint]`. |
| **types-jsonschema** | >=4.20.0 | Apache-2.0 | Type stubs for the jsonschema runtime dep. |

### `kafka` — durable audit fan-out (Kafka producer)

| Package | Pin | License | Purpose |
|---|---|---|---|
| **aiokafka** | >=0.12.0 | Apache-2.0 | Async Kafka producer. Lazy-imported by `audit/producer.py`. |

### `nats` — durable audit fan-out (NATS producer)

| Package | Pin | License | Purpose |
|---|---|---|---|
| **nats-py** | >=2.7.0 | Apache-2.0 | NATS client. Lazy-imported by `audit/producer.py`. |

### `perf` — load-test tooling

| Package | Pin | License | Purpose |
|---|---|---|---|
| **prometheus_client** | >=0.20.0 | Apache-2.0 + BSD-2-Clause | Prometheus metrics exposition for the load tests in `tests/perf/`. NOT installed in production (the gateway has no built-in `/metrics` endpoint). |

---

## Full dependency tree (direct + transitive)

Snapshot from `pip-licenses --format=csv` against a fresh
`pip install -e ".[dev,kafka,nats,perf]"` install. 78 packages.

| Package | Version | License |
|---|---|---|
| Mako                           | 1.3.12                 | MIT License |
| MarkupSafe                     | 3.0.3                  | BSD-3-Clause |
| PyJWT                          | 2.12.1                 | MIT |
| PyYAML                         | 6.0.3                  | MIT License |
| Pygments                       | 2.20.0                 | BSD-2-Clause |
| SQLAlchemy                     | 2.0.49                 | MIT |
| aiokafka                       | 0.14.0                 | Apache-2.0 |
| alembic                        | 1.18.4                 | MIT |
| annotated-doc                  | 0.0.4                  | MIT |
| annotated-types                | 0.7.0                  | MIT License |
| anyio                          | 4.13.0                 | MIT |
| async-timeout                  | 5.0.1                  | Apache Software License |
| attrs                          | 26.1.0                 | MIT |
| bcrypt                         | 5.0.0                  | Apache Software License |
| boto3                          | 1.43.0                 | Apache-2.0 |
| botocore                       | 1.43.0                 | Apache-2.0 |
| certifi                        | 2026.4.22              | MPL-2.0 |
| cffi                           | 2.0.0                  | MIT |
| charset-normalizer             | 3.4.7                  | MIT |
| click                          | 8.3.3                  | BSD-3-Clause |
| cryptography                   | 43.0.3                 | Apache-2.0 / BSD |
| defusedxml                     | 0.7.1                  | PSF |
| dnspython                      | 2.8.0                  | ISC |
| elementpath                    | 4.8.0                  | MIT License |
| email-validator                | 2.3.0                  | Unlicense |
| fastapi                        | 0.136.1                | MIT |
| flameprof                      | 0.4                    | MIT License |
| h11                            | 0.16.0                 | MIT License |
| httpcore                       | 1.0.9                  | BSD-3-Clause |
| httptools                      | 0.7.1                  | MIT |
| httpx                          | 0.28.1                 | BSD |
| httpx-sse                      | 0.4.3                  | MIT |
| idna                           | 3.13                   | BSD-3-Clause |
| iniconfig                      | 2.3.0                  | MIT |
| jmespath                       | 1.1.0                  | MIT License |
| jsonschema                     | 4.26.0                 | MIT |
| jsonschema-specifications      | 2025.9.1               | MIT |
| librt                          | 0.9.0                  | MIT |
| mcp                            | 1.27.0                 | MIT License |
| mypy                           | 1.20.2                 | MIT |
| mypy_extensions                | 1.1.0                  | MIT |
| nats-py                        | 2.14.0                 | Apache-2.0 |
| packaging                      | 26.2                   | Apache-2.0 / BSD-2-Clause |
| pathspec                       | 1.1.1                  | MPL-2.0 |
| pluggy                         | 1.6.0                  | MIT License |
| prometheus_client              | 0.25.0                 | Apache-2.0 / BSD-2-Clause |
| psycopg                        | 3.3.3                  | LGPL-3.0-only |
| psycopg-binary                 | 3.3.3                  | LGPL-3.0-only |
| py-spy                         | 0.4.2                  | MIT License |
| pyOpenSSL                      | 24.2.1                 | Apache-2.0 |
| pycparser                      | 3.0                    | BSD-3-Clause |
| pydantic                       | 2.13.3                 | MIT |
| pydantic-settings              | 2.14.0                 | MIT |
| pydantic_core                  | 2.46.3                 | MIT |
| pysaml2                        | 7.5.4                  | Apache-2.0 |
| pytest                         | 9.0.3                  | MIT |
| python-dateutil                | 2.9.0.post0            | Apache-2.0 / BSD |
| python-dotenv                  | 1.2.2                  | BSD-3-Clause |
| python-multipart               | 0.0.27                 | Apache-2.0 |
| redis                          | 7.4.0                  | MIT |
| referencing                    | 0.37.0                 | MIT |
| requests                       | 2.33.1                 | Apache-2.0 |
| rpds-py                        | 0.30.0                 | MIT |
| ruff                           | 0.15.12                | MIT |
| s3transfer                     | 0.17.0                 | Apache-2.0 |
| six                            | 1.17.0                 | MIT License |
| sse-starlette                  | 3.4.1                  | BSD-3-Clause |
| starlette                      | 1.0.0                  | BSD-3-Clause |
| types-jsonschema               | 4.26.0.20260408        | Apache-2.0 |
| typing-inspection              | 0.4.2                  | MIT |
| typing_extensions              | 4.15.0                 | PSF-2.0 |
| urllib3                        | 2.6.3                  | MIT |
| uvicorn                        | 0.46.0                 | BSD-3-Clause |
| uvloop                         | 0.22.1                 | Apache-2.0 / MIT |
| watchfiles                     | 1.1.1                  | MIT License |
| websockets                     | 16.0                   | BSD-3-Clause |
| xmlschema                      | 2.5.1                  | MIT License |
| **vyuu-mcp-gateway**           | 0.1.0                  | (proprietary, internal) |

---

## License distribution

Across the 78 third-party packages:

| License family | Count | Risk for proprietary use |
|---|---|---|
| MIT (incl. "MIT License") | 40 | None — fully permissive |
| BSD (2-Clause / 3-Clause / generic) | 12 | None |
| Apache 2.0 (incl. "Apache Software License") | 17 | None — explicit patent grant |
| MPL-2.0 | 2 | File-level copyleft only; we don't modify these |
| LGPL-3.0-only | 2 | Dynamic linking allowed (our usage); flagged in callouts above |
| Unlicense | 1 | Public-domain equivalent |
| ISC | 1 | None |
| PSF-2.0 (Python SF License) | 1 | None |
| Multi-licensed (e.g., Apache OR BSD) | 4 | None — pick the more permissive |

No GPL (v2/v3), no SSPL, no commercial lock-ins.

---

## System dependencies

Not installable via pip. Required at runtime; document in your
deployment runbook.

| Component | Why we need it | Typical install |
|---|---|---|
| **PostgreSQL 14+** | Single durable store for everything (catalog, audit, IdP, OAuth tokens). Must support Row Level Security + JSONB + `percentile_cont`. | Managed RDS / managed Cloud SQL / self-hosted Postgres 14+. |
| **xmlsec1** (libxmlsec1) | `pysaml2` shells out to it for SAML XML-DSig signature ops. Without it, SAML sign-in fails with `xmlsec1: command not found` at first SAML callback. | apt: `apt-get install xmlsec1 libxmlsec1-dev` · brew: `brew install libxmlsec1` · alpine: `apk add libxmlsec1` · RHEL: `dnf install xmlsec1 xmlsec1-openssl` |
| **libpq** | psycopg uses it. The `psycopg[binary]` extra embeds a precompiled libpq, so usually you DON'T need it as a separate system package. Without `[binary]`, install `libpq-dev`. | apt: `apt-get install libpq-dev` (only if not using the `[binary]` extra) |
| **Python 3.12+** | Type annotations + pattern matching + `StrEnum`. 3.12 is the minimum; verified against 3.14 in development. | Use the official Python image / `pyenv` / system package. |
| **Redis 6+** *(optional)* | Backs the `RedisSessionRegistry` for multi-instance HA. Single-instance on-prem uses the in-memory registry → no Redis needed. | Managed ElastiCache / managed Cloud Memorystore / self-hosted Redis. |
| **Kafka or NATS** *(optional)* | Audit fan-out for SIEM/SOC pipelines. With TOOL-EVENTS-1, Postgres is the durable audit store, so Kafka/NATS is purely a fan-out for downstream consumers. Customers without a SIEM pipeline don't need it. | Managed MSK / Confluent Cloud / Synadia Cloud / self-hosted. |
| **A reverse proxy** | Terminates TLS, handles cert renewal. The gateway does NOT terminate TLS itself. | nginx / Caddy (auto Let's Encrypt) / Traefik / your enterprise LB. |

---

## How to regenerate this SBOM

```bash
# From a fresh venv with all extras:
pip install -e ".[dev,kafka,nats,perf]" pip-licenses

# Quick freeze (just versions):
pip list --format=freeze > sbom-freeze-$(date +%Y%m%d).txt

# Curated table with licenses:
pip-licenses --format=markdown --order=name > /tmp/sbom-table.md

# Full machine-readable SBOM (CycloneDX 1.5 spec):
pip install cyclonedx-bom
cyclonedx-py environment --output-format json > sbom.cdx.json
# OR run on the project itself (resolves from pyproject.toml):
cyclonedx-py poetry --output-format json > sbom.cdx.json
```

The CycloneDX JSON is the format security-scanning tooling
(`grype`, `trivy`, `dependency-track`) consumes. Worth committing
alongside `SBOM.md` if you're feeding a vulnerability scanner.

---

## Update process

When to refresh this doc:

1. **Adding a new dep** — bump the direct-deps table + re-run the
   commands above. PR review must include the SBOM diff.
2. **Bumping a pin** — re-run the commands; if the license changed
   (rare), call it out in the PR.
3. **Removing a dep** — strike from the direct-deps table; re-run to
   confirm the transitive table reflects.
4. **Quarterly audit** — `pip-audit` for known CVEs. Critical CVEs
   trigger an immediate patch release.

```bash
# Quarterly CVE scan:
pip install pip-audit
pip-audit --requirement <(pip freeze)
```

5. **Annual license audit** — re-run `pip-licenses` and diff against
   this file. New license families that aren't in the "Quick risk
   callouts" section above get added or rejected.

---

## Vendor / customer requests

If a customer's procurement team asks for an SBOM:

- **Human-readable:** send this `SBOM.md`.
- **Machine-readable:** generate fresh CycloneDX JSON via the
  command above, send `sbom.cdx.json`. Format: CycloneDX 1.5 (the
  current de-facto standard accepted by SPDX-aware tooling).
- **License compliance attestation:** point at the "License
  distribution" table — no GPL, no SSPL, all permissive or
  dynamically-linked LGPL.

Both formats together cover the typical "Stage 4" vendor-risk
review checklist.
