"""Consistent error envelope for tool-call failures.

Every tool-call error — whether the gateway raised it (policy denial,
malformed args, audit pipeline down), the upstream MCP server returned
it (`isError=true` with a human message), or the gateway hit a system
exception while talking to the upstream (TimeoutError, ConnectionError,
TypeError) — flows through this module so MCP clients see a consistent
shape:

    content[0].text:
        "[<source> · <category>] <human message>"

    meta["vyuu.error"]:
        {
          "source": "upstream_mcp" | "upstream_api" | "gateway"
                  | "policy" | "network",
          "category": "auth_failed" | "not_found" | "rate_limited"
                    | "needs_tool_elevation" | "upstream_input_refused"
                    | "timeout" | "denied_by_policy" | "malformed_args"
                    | "tool_not_in_vserver" | "transient" | "unknown",
          "retryable": bool,
          "correlation_id": "<uuid4>",
          "upstream_server_id": "<uuid>" | null,
          "upstream_tool_name": "<str>" | null,
        }

Why both the bracketed text prefix AND the structured meta:

- Cursor / Claude Desktop / curl users see the bracketed prefix so the
  source + category jump out at a glance even when they only render
  `content[0].text` (which is the MCP-spec-required minimum).
- Gateway-savvy agents read `meta["vyuu.error"]` to react
  programmatically (retry on `transient`, escalate on `auth_failed`,
  re-prompt the user on `malformed_args`, refresh OAuth on the right
  category, etc.).

The classifier is heuristic — it pattern-matches common phrases in
upstream error text. It's deliberately conservative: when in doubt,
returns `UNKNOWN` rather than mis-tagging. False positives on
classification are worse than `unknown` because they'd encourage
clients to take wrong recovery actions.
"""

from __future__ import annotations

import re
from enum import StrEnum
from uuid import UUID, uuid4

from mcp.types import CallToolResult, TextContent

from vyuu_gateway.mcp.sdk_compat import dump_wire


class ErrorSource(StrEnum):
    """Where the error originated.

    - `gateway` — the gateway itself rejected the call before / after
      the upstream got involved (e.g. unknown tool, audit pipeline
      down, identity validation failed).
    - `policy` — the gateway's policy engine denied the call. Distinct
      from `gateway` so clients can route policy denials to "request
      access" UX instead of "retry".
    - `upstream_mcp` — the upstream MCP server returned `isError=True`
      with a structured tool-error response. Most "the user's input
      didn't match upstream's expectations" cases live here.
    - `upstream_api` — the gateway-spawned subprocess or HTTP-bound
      upstream MCP itself called a downstream API (CrowdStrike,
      VirusTotal, GitHub) and that API returned an error. Folded into
      `upstream_mcp` for now since the upstream MCP is the layer that
      surfaces the error text — kept as a separate enum value so
      future heuristics can split them.
    - `network` — connection refused / timeout / SSL handshake — the
      gateway never got a structured response.
    """

    GATEWAY = "gateway"
    POLICY = "policy"
    UPSTREAM_MCP = "upstream_mcp"
    UPSTREAM_API = "upstream_api"
    NETWORK = "network"


class ErrorCategory(StrEnum):
    """What kind of error. Drives client-side recovery decisions."""

    AUTH_FAILED = "auth_failed"
    """Token rejected, scope missing, signature invalid. Recovery:
    re-authenticate / refresh token / reconnect OAuth."""

    NOT_FOUND = "not_found"
    """Resource the operator asked about doesn't exist. Recovery:
    fix the input."""

    RATE_LIMITED = "rate_limited"
    """Upstream temporarily refused the call. Recovery: backoff +
    retry."""

    TIMEOUT = "timeout"
    """Upstream took too long. Recovery: retry, possibly with a
    smaller payload."""

    DENIED_BY_POLICY = "denied_by_policy"
    """Gateway policy engine refused. Recovery: operator must request
    a grant from the admin (the portal's "Request access" flow)."""

    MALFORMED_ARGS = "malformed_args"
    """Args didn't match the tool's input schema. Recovery: fix the
    args."""

    TOOL_NOT_IN_VSERVER = "tool_not_in_vserver"
    """Vserver doesn't expose the requested tool. Recovery: pick a
    different tool / vserver."""

    CAPABILITIES_NOT_SYNCED = "capabilities_not_synced"
    """Vserver's mapped tools have no `mcp_capabilities` rows yet.
    Distinct from `tool_not_in_vserver`: the registration is correct,
    just missing a capability sync. Recovery: operator triggers a
    sync (operator console → MCP servers → Sync, or
    `POST /api/v1/servers/{id}/sync`). Retryable once sync completes."""

    UPSTREAM_INTERNAL = "upstream_internal"
    """Upstream returned a generic internal error. Recovery: contact
    the upstream's operator."""

    TRANSIENT = "transient"
    """Network blip / connection refused / circuit-breaker open.
    Recovery: retry."""

    NEEDS_TOOL_ELEVATION = "needs_tool_elevation"
    """The tool is published to this vserver and the caller holds
    access, but the tool is elevation-gated and no elevation is
    active. Recovery: request a time-boxed elevation in the portal
    ("Tools needing temporary elevation"), then retry. Distinct from
    `denied_by_policy`, where no self-service path exists."""

    UPSTREAM_INPUT_REFUSED = "upstream_input_refused"
    """The upstream answered with a mid-request input requirement
    (sampling / roots / elicitation) that this gateway's MRTR policy
    does not permit. Recovery: an operator must allow that kind
    explicitly via `VYUU_MRTR_ALLOWED_INPUT_KINDS` — and should first
    read WHY it was asked for, since url-elicitation in particular is
    a phishing vector. Not retryable by the caller."""

    UNKNOWN = "unknown"
    """We couldn't classify. Treat as opaque — message text still
    visible verbatim."""


# Per-category retry hints. Conservative: anything we're not sure
# about is non-retryable so clients don't loop on auth failures.
_RETRYABLE_CATEGORIES: frozenset[ErrorCategory] = frozenset(
    {
        ErrorCategory.RATE_LIMITED,
        ErrorCategory.TIMEOUT,
        ErrorCategory.TRANSIENT,
        # Operator-action-recoverable: once they trigger sync the
        # next call succeeds. Marking retryable so MCP clients show
        # "retry available" rather than "permanently failed."
        ErrorCategory.CAPABILITIES_NOT_SYNCED,
        # Same shape, user-action-recoverable: the caller elevates in
        # the portal and the identical call then succeeds. Deliberately
        # NOT alongside `upstream_input_refused`, which needs an
        # operator to widen MRTR policy after deciding it is safe.
        ErrorCategory.NEEDS_TOOL_ELEVATION,
    }
)


# Heuristic patterns. Order matters: the FIRST matching pattern wins,
# so the most specific phrases come earliest. Patterns are compiled
# case-insensitively and matched against the full upstream message.
_CLASSIFIER_PATTERNS: list[tuple[ErrorCategory, re.Pattern[str]]] = [
    (
        ErrorCategory.RATE_LIMITED,
        re.compile(
            r"\b(rate[\s-]?limit|too\s+many\s+requests|quota\s+exceeded"
            r"|429\b)",
            re.IGNORECASE,
        ),
    ),
    (
        ErrorCategory.AUTH_FAILED,
        re.compile(
            r"\b(unauthori[sz]ed|forbidden|invalid[\s_-]token|invalid"
            r"\s+credentials|token\s+expired|authentication\s+failed"
            r"|insufficient[\s_](scope|permission|privilege)|missing"
            r"[\s_]scope|401\b|403\b)",
            re.IGNORECASE,
        ),
    ),
    (
        ErrorCategory.NOT_FOUND,
        re.compile(
            r"\b(not\s+found|does\s+not\s+exist|no\s+such|could\s+not"
            r"\s+resolve|unknown\s+(repository|repo|file|hash|object)"
            r"|404\b)",
            re.IGNORECASE,
        ),
    ),
    (
        ErrorCategory.TIMEOUT,
        re.compile(
            r"\b(timed?\s+out|timeout|deadline\s+exceeded|408\b|504\b"
            r"|gateway\s+timeout)",
            re.IGNORECASE,
        ),
    ),
    (
        ErrorCategory.MALFORMED_ARGS,
        re.compile(
            r"\b(invalid\s+(input|argument|parameter|payload|request)"
            r"|missing\s+(required\s+)?(argument|parameter|field)"
            r"|validation\s+(failed|error)|schema\s+(violation|"
            r"mismatch)|400\b|422\b)",
            re.IGNORECASE,
        ),
    ),
    (
        ErrorCategory.UPSTREAM_INTERNAL,
        re.compile(
            r"\b(internal\s+(server\s+)?error|500\b|502\b|503\b"
            r"|service\s+unavailable|temporarily\s+unavailable)",
            re.IGNORECASE,
        ),
    ),
    (
        ErrorCategory.TRANSIENT,
        re.compile(
            r"\b(connection\s+(reset|refused|aborted)|circuit\s+"
            r"breaker|temporarily\s+failed|try\s+again)",
            re.IGNORECASE,
        ),
    ),
]


def classify_upstream_error_text(text: str) -> ErrorCategory:
    """Best-effort classify an arbitrary upstream error message.

    Returns `UNKNOWN` if no pattern matched — important to keep the
    false-positive rate low. Mis-classifying an `auth_failed` as
    `transient` would push a client into a retry loop on a permanent
    failure.
    """
    if not text:
        return ErrorCategory.UNKNOWN
    for category, pattern in _CLASSIFIER_PATTERNS:
        if pattern.search(text):
            return category
    return ErrorCategory.UNKNOWN


def _extract_message_from_content(
    content: list[object],
) -> str:
    """Pull the most-useful text out of a CallToolResult's content
    blocks. Concatenates `TextContent` blocks; falls back to "" when
    the response was non-text (image, audio, embedded resource)."""

    texts: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if isinstance(text, str) and text.strip():
            texts.append(text.strip())
    return "\n".join(texts)


def build_error_envelope(
    *,
    source: ErrorSource,
    category: ErrorCategory,
    message: str,
    correlation_id: UUID | None = None,
    upstream_server_id: UUID | None = None,
    upstream_tool_name: str | None = None,
    upstream_content: list[object] | None = None,
) -> CallToolResult:
    """Build a consistent error CallToolResult.

    `message` is the human-readable text. The function prefixes it
    with `[source · category]` so the source + classification show up
    in any client that just renders `content[0].text` (Cursor, curl).

    `upstream_content` (when set) is preserved verbatim as additional
    content blocks — important for upstreams that return rich error
    payloads (structured JSON, multiple text segments, etc.). The
    bracketed-prefix block is prepended; original blocks follow.

    `meta["vyuu.error"]` carries the structured fields. Spec-savvy
    clients use this for programmatic recovery (retry / re-auth /
    fix args / etc.).
    """

    cid = correlation_id or uuid4()
    prefix_text = f"[{source.value} · {category.value}] {message}".strip()
    blocks: list[TextContent | object] = [
        TextContent(type="text", text=prefix_text)
    ]
    # Preserve any structured upstream content (additional text blocks,
    # images, embedded resources). Skip duplicating a single TextContent
    # that already matches the message we've prefixed — common case
    # when classifier was run over the upstream's only text block.
    if upstream_content:
        for block in upstream_content:
            text = getattr(block, "text", None)
            if isinstance(text, str) and text.strip() == message.strip():
                continue
            blocks.append(block)

    meta = {
        "vyuu.error": {
            "source": source.value,
            "category": category.value,
            "retryable": category in _RETRYABLE_CATEGORIES,
            "correlation_id": str(cid),
            "upstream_server_id": (
                str(upstream_server_id) if upstream_server_id else None
            ),
            "upstream_tool_name": upstream_tool_name,
        }
    }

    # MCP's `CallToolResult.meta` is exposed under the JSON alias
    # `_meta` and Pydantic v2 with `populate_by_name=False` (the
    # default for MCP types) silently drops keyword args using the
    # field's Python name. `model_validate` honours both the alias
    # and the python name, so we go through that path.
    return CallToolResult.model_validate(
        {
            "content": [
                dump_wire(b, mode=None)
                if hasattr(b, "model_dump")
                else b
                for b in blocks
            ],
            "isError": True,
            "_meta": meta,
        }
    )


def envelope_from_upstream_iserror(
    response: CallToolResult,
    *,
    correlation_id: UUID | None = None,
    upstream_server_id: UUID | None = None,
    upstream_tool_name: str | None = None,
) -> CallToolResult:
    """Convert an upstream's `isError=True` CallToolResult into a
    Vyuu-shaped envelope. Preserves the upstream's text + extra
    content blocks; classifies the message; tags with source =
    `upstream_mcp`.

    Used in `inbound_mcp.py`'s reply path so VT / GitHub / Falcon /
    any future MCP get the same envelope shape on errors.
    """
    upstream_text = _extract_message_from_content(list(response.content or []))
    category = classify_upstream_error_text(upstream_text)
    return build_error_envelope(
        source=ErrorSource.UPSTREAM_MCP,
        category=category,
        message=upstream_text or "(upstream returned isError=true with no text)",
        correlation_id=correlation_id,
        upstream_server_id=upstream_server_id,
        upstream_tool_name=upstream_tool_name,
        upstream_content=list(response.content or []),
    )
