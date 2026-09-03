# AGENTS.md

## Project

This repository implements Vyuu MCP Gateway: a server-side MCP enforcement, routing, virtual-server, audit, and observability gateway.

The master architecture spec is here:

- `docs/architecture/vyuu-gateway-spec.md`

Always read that document before implementing architectural changes.

## Product principles

- Gateway is a data plane, not the Vyuu management plane.
- Gateway enforces MCP tool policy and emits telemetry.
- Gateway must not become an LLM model gateway.
- Gateway must preserve tenant isolation.
- Gateway must treat MCP servers as untrusted.
- Gateway must default to least privilege.

## Build approach

Build ground-up. Do not fork IBM ContextForge into this repo.

ContextForge may be used only as reference architecture. Do not copy code unless a human explicitly approves license/provenance.

## MCP transport policy

Implement first-class support for:
- stdio
- Streamable HTTP

Support legacy HTTP+SSE only for backward compatibility.

Do not call SSE a current primary MCP transport.

## Security rules

Never store secrets in plaintext.

Never log:
- API keys
- bearer tokens
- OAuth tokens
- full tool arguments by default
- full tool responses by default
- customer business data unless explicitly enabled by policy

All tenant-scoped data models must include `tenant_id`.

All tenant-scoped queries must filter by `tenant_id`.

Do not add cross-tenant shared caches unless tenant keying is explicit and tested.

## Engineering rules

Prefer simple, testable modules.

Do not implement the entire gateway in one file.

Every feature must include:
- unit tests
- failure tests where relevant
- clear error handling
- structured logging
- type hints

## Testing commands

Run these before completing any task:

```bash
pytest
ruff check .
mypy .
