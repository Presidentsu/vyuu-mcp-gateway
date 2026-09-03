# Security policy

## Reporting a vulnerability

Please **do not** file public issues for security problems. Email the
maintainers (see the repository's GitHub profile) with:

- the component and version (`vyuu_gateway.__version__`, schema head from
  `alembic current`)
- a reproduction or proof of concept
- the impact as you understand it (which tenant boundary, which credential)

You will get an acknowledgement within three working days and a fix or
mitigation plan within thirty. Coordinated disclosure is appreciated; credit
is given unless you prefer otherwise.

## What this gateway defends against

The full threat model, defenses, and the rules engineers follow are in
[`docs/onboarding/SECURITY.md`](docs/onboarding/SECURITY.md). In brief:

| Threat | Defense |
|---|---|
| Cross-tenant data access | `tenant_id` on every scoped row, filtered in every query, and Postgres row-level security (`FORCE` on audit, identity, secret-bearing tables) |
| Credential exposure | Secrets live in Vault / AWS Secrets Manager / Kubernetes Secrets and are referenced by name; API responses redact credential values; OAuth tokens at rest are envelope-encrypted (local key or AWS KMS) |
| Hostile upstream MCP servers | Tool surface synced and risk-classified (OWASP MCP Top 10); SSRF guard at registration and at connect time; sigstore verification for binary upstreams; multi-round tool result (MRTR) requests denied by default; payload caps and secret redaction on responses |
| Runaway or abusive clients | Per-tenant in-flight gate, uvicorn back-pressure, upstream circuit breakers, subprocess limits in the shipped manifests |
| Unauthorised session control | Every inbound call authenticated; session termination requires the session's owner |
| Audit tampering or loss | Admin actions recorded in the same transaction as the mutation; tool calls persisted synchronously; audit rows outlive their targets; optional SIEM export |

## Supported versions

Security fixes land on `main`. Tag a release before deploying to production
and pin your image to it.
