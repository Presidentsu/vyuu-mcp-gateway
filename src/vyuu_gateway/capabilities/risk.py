"""Heuristic risk classifier for MCP tool capabilities.

The gateway records a coarse risk category alongside every capability snapshot
so that operators, audit consumers, and policy authors can reason about the
blast radius of a tool without re-reading its description. The classifier is
intentionally a name-and-description heuristic: it is fast, deterministic,
operates without an external service, and produces a conservative answer when
signals are absent. Operator-curated overrides at the policy/virtual-server
layer remain the source of truth; this is a default tag, not an enforcement
mechanism.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from vyuu_gateway.db.models import McpCapabilityKind, McpServer, RiskCategory

# Tool names commonly use snake_case / kebab-case, which means underscores and
# hyphens are word separators in this domain. Python's \b treats `_` as a word
# character, so we use explicit non-alphanumeric boundaries on both sides.
_LEFT = r"(?:^|[^a-z0-9])"
_RIGHT = r"(?=[^a-z0-9]|$)"


def _rule(*alternatives: str) -> re.Pattern[str]:
    body = "|".join(alternatives)
    return re.compile(_LEFT + r"(?:" + body + r")" + _RIGHT)


# Rules are evaluated in priority order; first match wins.
#
# Ordering rationale:
#   - CREDENTIAL_ACCESS dominates: `get_secret` must not classify as READ.
#   - ADMIN dominates DELETE / WRITE: `delete_user` is an IAM action, not a
#     generic DELETE; `update_policy` is ADMIN, not WRITE.
#   - DATA_EXPORT dominates WRITE: `send_email` is exfil, not a generic write.
#   - NETWORK uses narrow keywords because broad ones like "fetch" / "request"
#     overlap heavily with READ.
_RULES: tuple[tuple[RiskCategory, re.Pattern[str]], ...] = (
    (
        RiskCategory.CREDENTIAL_ACCESS,
        _rule(
            "secret",
            "secrets",
            "password",
            "passwords",
            "credential",
            "credentials",
            "token",
            "tokens",
            "api[_-]?key",
            "access[_-]?key",
            "private[_-]?key",
            "ssh[_-]?key",
            "vault",
            "keyring",
            "keychain",
            "oauth[_-]?token",
            "bearer[_-]?token",
            "client[_-]?secret",
        ),
    ),
    (
        RiskCategory.ADMIN,
        _rule(
            "grant[_-]?role",
            "revoke[_-]?role",
            "assign[_-]?role",
            "set[_-]?role",
            "set[_-]?policy",
            "update[_-]?policy",
            "set[_-]?permission",
            "update[_-]?permission",
            "set[_-]?acl",
            "update[_-]?acl",
            "set[_-]?iam",
            "update[_-]?iam",
            "grant[_-]?access",
            "revoke[_-]?access",
            "create[_-]?user",
            "delete[_-]?user",
            "update[_-]?user",
            "disable[_-]?user",
            "enable[_-]?user",
            "chmod",
            "chown",
            "sudo",
        ),
    ),
    (
        RiskCategory.DELETE,
        _rule(
            "delete",
            "destroy",
            "remove",
            "drop",
            "purge",
            "unlink",
            "truncate",
            "wipe",
            "erase",
            "deregister",
            "uninstall",
        ),
    ),
    (
        RiskCategory.EXECUTE,
        _rule(
            "execute",
            "exec",
            "run",
            "invoke",
            "spawn",
            "shell",
            "command",
            "cmd",
            "eval",
            "interpret",
            "repl",
            "sandbox",
        ),
    ),
    (
        RiskCategory.DATA_EXPORT,
        _rule(
            "send[_-]?email",
            "send[_-]?mail",
            "send[_-]?sms",
            "send[_-]?message",
            "post[_-]?message",
            "publish",
            "upload",
            "export",
            "webhook",
            "notify",
            "broadcast",
            "share",
        ),
    ),
    (
        RiskCategory.NETWORK,
        _rule(
            "http[_-]?request",
            "http[_-]?get",
            "http[_-]?post",
            "fetch[_-]?url",
            "download",
            "curl",
            "ping",
            "socket",
            "tcp[_-]?connect",
            "udp[_-]?send",
            "dns[_-]?lookup",
        ),
    ),
    (
        RiskCategory.WRITE,
        _rule(
            "create",
            "update",
            "write",
            "edit",
            "patch",
            "put",
            "add",
            "insert",
            "save",
            "upsert",
            "append",
            "modify",
            "rename",
            "move",
            "copy",
            "set",
        ),
    ),
    (
        RiskCategory.READ,
        _rule(
            "get",
            "list",
            "read",
            "fetch",
            "search",
            "find",
            "describe",
            "show",
            "check",
            "view",
            "query",
            "select",
            "count",
            "inspect",
            "status",
            "info",
            "head",
            "preview",
        ),
    ),
)


def classify_tool_risk(
    *,
    name: str,
    description: str | None = None,
    input_schema: Mapping[str, Any] | None = None,
    server: McpServer | None = None,
    kind: McpCapabilityKind = McpCapabilityKind.TOOL,
) -> RiskCategory:
    """Return a heuristic risk category for an MCP capability.

    Resources and prompts are not actions, so they classify as UNKNOWN; the
    category is meaningful only for tool capabilities.
    """

    if kind != McpCapabilityKind.TOOL:
        return RiskCategory.UNKNOWN

    primary = _build_haystack(name, description, _schema_property_names(input_schema))
    category = _match_rules(primary)
    if category is not RiskCategory.UNKNOWN:
        return category

    if server is not None:
        category = _match_rules((server.display_name or "").lower())
        if category is not RiskCategory.UNKNOWN:
            return category

    return RiskCategory.UNKNOWN


def _build_haystack(
    name: str,
    description: str | None,
    schema_property_names: list[str],
) -> str:
    parts = [_split_camel_case(name)]
    if description:
        parts.append(description)
    parts.extend(_split_camel_case(prop) for prop in schema_property_names)
    return " ".join(parts).lower()


_CAMEL_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")


def _split_camel_case(text: str) -> str:
    return _CAMEL_BOUNDARY.sub(r"\1 \2", text)


def _schema_property_names(input_schema: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(input_schema, Mapping):
        return []
    properties = input_schema.get("properties")
    if not isinstance(properties, Mapping):
        return []
    return [str(key) for key in properties]


def _match_rules(haystack: str) -> RiskCategory:
    if not haystack:
        return RiskCategory.UNKNOWN
    for category, pattern in _RULES:
        if pattern.search(haystack):
            return category
    return RiskCategory.UNKNOWN
