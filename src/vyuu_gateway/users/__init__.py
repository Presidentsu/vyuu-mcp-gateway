"""End-user identity: passwords, API keys, local-auth flow.

The companion to `operator_auth/` (admin) and `identity/` (inbound MCP
principal validation). End users sit between operators (who manage the
catalog) and the machine principals that inbound MCP calls present —
a real human who logs into the portal and issues their own API keys for
their own Claude Desktop / Cursor.

Modules:
- `passwords` — bcrypt hashing + verification + minimum-strength rule.
- `api_keys` — secret generation, format parsing, hash + verify.
- `local_auth` — verify (email, password) → User row, raise on failure.
"""
