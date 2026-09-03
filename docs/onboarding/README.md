# Vyuu MCP Gateway · Engineering Onboarding

Welcome. This folder is the curated doc set for an engineer picking up
the project. It assumes you can read code; it does NOT re-explain things
that are obvious from skimming `src/`. **17 markdown docs + 1 SBOM
JSON**, organised in three tiers.

## The three tiers

| Tier | Docs | When to read |
|---|---|---|
| **Core path** (1–9) | SETUP → ARCHITECTURE → BACKEND → FRONTEND → AUTH → NETWORK → TESTING → RUNBOOK → KNOWLEDGE_BASE | Day 1. Read top-to-bottom; gets you productive in a day. |
| **Depth tier** (10–11) | BACKEND_DEEP_DIVE, LOW_LEVEL_ARCH | Week 1–2. Read when debugging a specific lifecycle, designing a change that touches multiple modules, or understanding concurrency / failure modes. |
| **Reference tier** (12–17) | API_REFERENCE, MIGRATIONS, SECURITY, MCP_SPECIFICS, CHANGELOG, SBOM | Look up as needed. Skim once to know what's there. |

## Read in this order

| # | Doc | What you get out of it |
|---|---|---|
| 1 | [SETUP.md](SETUP.md) | Get the gateway running locally in ~15 minutes. Prereqs, DB, migrations, lab server, first sign-in. |
| 2 | [ARCHITECTURE.md](ARCHITECTURE.md) | The 30,000-ft picture: what flows through where, why we made the big design calls. |
| 3 | [BACKEND.md](BACKEND.md) | Per-module map of the backend. Where to look for X, what each component does, what tech each uses. |
| 4 | [FRONTEND.md](FRONTEND.md) | Operator console + end-user portal: ideology (no React, single FastAPI-served HTML), navigation model, how to add a panel. |
| 5 | [AUTH.md](AUTH.md) | Every authentication surface (operator JWT, portal session, API key, SCIM bearer, OIDC, SAML), how they relate. |
| 6 | [NETWORK.md](NETWORK.md) | Ports, routes, RLS posture, MCP transports, ingress assumptions for on-prem. |
| 7 | [TESTING.md](TESTING.md) | Test layout, what's covered, how to run, how to write new ones. |
| 8 | [RUNBOOK.md](RUNBOOK.md) | "If X breaks, do Y." Operational firefighting playbook. |
| 9 | [KNOWLEDGE_BASE.md](KNOWLEDGE_BASE.md) | Cross-reference. "Where is the X policy?" → file:line. Treat this as your jump-table. |
| 10 | [BACKEND_DEEP_DIVE.md](BACKEND_DEEP_DIVE.md) | **Depth tier.** Module dependency graph, full request lifecycles (inbound MCP, operator API + admin audit, SCIM push, IdP SSO, audit fan-out, capability sync), ERD overview, schema deep-dive column-by-column. |
| 11 | [LOW_LEVEL_ARCH.md](LOW_LEVEL_ARCH.md) | **Depth tier.** Process model, async vs sync rules, connection pooling, transaction boundaries, RLS GUC mechanics, concurrency primitives, memory budget, startup/shutdown sequence, failure-mode matrix, hot-path performance numbers. |
| 12 | [API_REFERENCE.md](API_REFERENCE.md) | **Reference.** All 105 endpoints by surface, with auth requirement (operator JWT / portal session / API key / SCIM bearer) + brief purpose. The curated companion to `/openapi.json`. |
| 13 | [MIGRATIONS.md](MIGRATIONS.md) | **Reference.** How to write a new Alembic migration with our conventions: tenant-scoped table template, when to FORCE RLS, FK semantics, indexes, enums (text + check), idempotent seeds, downgrade requirements. |
| 14 | [SECURITY.md](SECURITY.md) | **Reference.** Threat model + defenses + what we don't defend against. Engineer rules for secrets, tenant boundary, auth boundary, mutating endpoints. Dependency policy. |
| 15 | [MCP_SPECIFICS.md](MCP_SPECIFICS.md) | **Reference.** Protocol oddities that affected our implementation: streamable_http vs sse vs stdio, session-id semantics, why no `tools/list` cache, H5 raw-payload capture cap, args_summary shape, OAuth-AC + DCR. |
| 16 | [CHANGELOG.md](CHANGELOG.md) | **Reference.** Reverse-chronological landings — schema migrations, new endpoints, breaking config changes. Companion to HANDOFF.md (which goes deep on rationale). |
| 17 | [SBOM.md](SBOM.md) | **Reference.** Software Bill of Materials — every direct + transitive dependency with version, license, purpose. License-distribution audit, system-dep list, regenerate command, vendor-request playbook. Pair with [`sbom.cdx.json`](sbom.cdx.json) (CycloneDX 1.6) for machine-readable consumption by `grype` / `trivy` / `dependency-track`. |

## Existing docs you should know about

These predate the onboarding set and go deeper on specific areas:

- [`docs/PLATFORM.md`](../PLATFORM.md) — full platform overview (long, exhaustive).
- [`docs/TECH-STACK.md`](../TECH-STACK.md) — every dependency, why we picked it.
- [`docs/ADMIN-GUIDE.md`](../ADMIN-GUIDE.md) — operator-facing how-to.
- [`docs/DEVOPS-HANDOFF.md`](../DEVOPS-HANDOFF.md) — production-deploy posture.
- [`docs/STRESS-TESTING.md`](../STRESS-TESTING.md) — load test methodology + results.
- [`docs/TROUBLESHOOTING.md`](../TROUBLESHOOTING.md) — original troubleshooting compendium.
- [`BACKLOG.md`](../../BACKLOG.md) — open work + decision log. This is the source of truth for "why did we do X this way."

The onboarding set is intentionally a thin slice over those. When in
doubt, read the source code — every module has a docstring at the top
that explains intent. They're not decorative.

## Repository layout (one screen)

```
src/vyuu_gateway/
  api/             FastAPI routers (one file per surface)
  audit/           Audit pipeline (events, recent buffer, persistent store, identity aggregator)
  capabilities/    Upstream capability sync (tools/list cadence)
  risk/            LLM risk classification (OWASP MCP Top 10, MCP-in-SoS scoring, staleness)
  siem/            Splunk HEC export (events, exporter, targets, bridges)
  telemetry/       OpenTelemetry traces + metrics (optional extra)
  db/              SQLAlchemy models + Session + RLS binding
  graph/           Identity-graph queries (who-can-do, dependency_chain)
  idp/             IDP-1: Entra/Workspace SCIM + per-directory SSO
  identity/        Inbound API-key identity provider (production + fakes)
  operator_auth/   Operator JWT minting + dependency
  policy/          Policy decision providers (Simple + ManagementPlane)
  registry/        Users / groups / API keys / access requests services
  scim/            RFC 7644 server (Users + Groups, PATCH for Entra+Workspace)
  secrets/         Tenant-scoped secret store (in-memory + Postgres)
  sessions/        Session registry (in-memory + Redis)
  upstream/        Upstream MCP client pool, circuit breakers, health
  users/           OIDC providers + JWKS + login routes
  virtual_servers/ Virtual server CRUD + grants
  config.py        Settings (pydantic-settings)
  main.py          create_app + lifespan + router wiring
migrations/        Alembic versions (one per schema change)
tests/             Mirrors src/ layout
examples/          Lab server (drawio) + bootstrap scripts
docs/              All docs (this dir + the existing ones above)
```
