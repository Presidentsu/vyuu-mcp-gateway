"""H3 — request/response payload size limits + opt-in secret redaction.

**Distinct concern from `audit/events.py`'s capture cap.** That cap
controls what gets STORED in the audit event when an opt-in policy
captures raw payloads. This module controls what's allowed in TRANSIT
through the gateway:

- **Request body** above `Settings.inbound_max_request_body_bytes`
  fails fast with a 413 `Payload Too Large` envelope. The upstream
  is never called.
- **Response body** above `Settings.inbound_max_response_body_bytes`
  is TRUNCATED with a sentinel marker before forwarding to the client.
  The audit emit also sees the truncation. Transit completes; the
  client gets bounded data.
- **Secret redaction** (when `Settings.inbound_redact_response_secrets`
  is True or the policy decision opts in) scans response text content
  for common secret shapes (API keys, JWTs, AWS keys) and replaces
  matches with `[REDACTED:<kind>]` before forwarding + emit.

This protects two things:
- **Gateway memory** — a malicious upstream returning 1 GiB JSON
  would otherwise blow up the worker.
- **Audit pipeline cost** — ClickHouse storage scales linearly with
  response size; a single 50 MiB tool response 10×s the daily audit
  cost for that one call.

Per the security model, neither limit changes the policy decision
(allow vs deny) — that's already happened. These are post-decision
ingress / egress controls.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from mcp.types import CallToolResult, TextContent

from vyuu_gateway.mcp.sdk_compat import dump_wire, result_is_error

# ---------------------------------------------------------------------------
# Secret-redaction patterns
# ---------------------------------------------------------------------------

# Conservative library — favour false negatives over false positives.
# Each entry: (kind_label, regex). Tightening a pattern is cheap; loosening
# it can cause customer-visible data corruption, so err strict.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"\b[A-Za-z0-9/+=]{40}\b(?=[^A-Za-z0-9/+=]|$)")),
    ("github_token", re.compile(r"\bgh[posu]_[A-Za-z0-9]{36,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key_pem", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        r"[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    )),
    # JWT — three base64-url segments separated by dots. Catches
    # access tokens commonly leaked in API responses.
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
]


def redact_secrets(text: str) -> tuple[str, dict[str, int]]:
    """Replace secret-shaped substrings with `[REDACTED:<kind>]`.
    Returns (redacted_text, kind_counts). Counts are intended for
    audit metadata so operators can see "redacted 3 GitHub tokens
    in this response" without seeing the values themselves.
    """
    counts: dict[str, int] = {}
    for kind, pattern in _SECRET_PATTERNS:
        replacement = f"[REDACTED:{kind}]"
        new_text, n = pattern.subn(replacement, text)
        if n:
            counts[kind] = n
            text = new_text
    return text, counts


# ---------------------------------------------------------------------------
# Request-body size enforcement
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PayloadTooLargeError(Exception):
    """Raised when a request body exceeds `inbound_max_request_body_bytes`.
    The inbound MCP route catches this and returns a 413 with a Vyuu
    error envelope (`source=gateway, category=payload_too_large`,
    `retryable=false` — the client must shrink the payload).
    """
    actual_bytes: int
    limit_bytes: int

    def __str__(self) -> str:  # pragma: no cover
        return (
            f"request body {self.actual_bytes} bytes exceeds gateway cap "
            f"{self.limit_bytes} bytes"
        )


def assert_request_body_within_cap(body: bytes, limit_bytes: int) -> None:
    """Raise `PayloadTooLargeError` when the inbound HTTP body is too big.
    Called from the inbound MCP route immediately after reading the
    request body; before any upstream interaction."""
    if len(body) > limit_bytes:
        raise PayloadTooLargeError(
            actual_bytes=len(body), limit_bytes=limit_bytes
        )


# ---------------------------------------------------------------------------
# Response-body truncation + redaction
# ---------------------------------------------------------------------------


_TRUNCATION_TAIL = (
    "\n\n[…truncated by Vyuu gateway: payload exceeded "
    "inbound_max_response_body_bytes; full size {total_bytes} bytes]"
)


def _content_block_text(block: Any) -> str | None:
    """Extract text from a `TextContent` block; None for binary types."""
    if isinstance(block, TextContent):
        return block.text
    text = getattr(block, "text", None)
    if isinstance(text, str):
        return text
    return None


def _structured_bytes(structured: Any) -> int:
    """Approximate wire size of `structuredContent`.

    It is a sibling of `content` on the wire, so a cap that ignores it
    under-counts the response by however large the structured copy is —
    which, for a tool with an output schema, is usually the whole
    payload a second time.
    """
    if structured is None:
        return 0
    try:
        return len(json.dumps(structured, default=str).encode("utf-8"))
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return 0


def _redact_structured(value: Any, counts: dict[str, int]) -> Any:
    """Apply `redact_secrets` to every string inside `structuredContent`.

    Redacting only the text blocks would be theatre: per the MCP spec
    the structured copy carries the SAME data, so a secret scrubbed from
    the text would still ship in the structured sibling.
    """
    if isinstance(value, str):
        redacted, found = redact_secrets(value)
        for key, hits in found.items():
            counts[key] = counts.get(key, 0) + hits
        return redacted
    if isinstance(value, dict):
        return {k: _redact_structured(v, counts) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_structured(v, counts) for v in value]
    return value


def _measure_response_bytes(content: Iterable[Any]) -> int:
    """Approximate wire size of a CallToolResult content array."""
    total = 0
    for block in content:
        text = _content_block_text(block)
        if text is not None:
            total += len(text.encode("utf-8"))
        else:
            # Binary (image / audio / embedded resource) — best-effort
            # length estimate from `data` if present.
            data = getattr(block, "data", None)
            if isinstance(data, str):
                total += len(data)
            elif isinstance(data, bytes | bytearray):
                total += len(data)
    return total


def cap_call_tool_result(
    result: CallToolResult,
    *,
    limit_bytes: int,
    redact_secrets_in_text: bool = False,
) -> tuple[CallToolResult, dict[str, Any]]:
    """Apply transit caps + (optional) redaction to a `CallToolResult`.

    Returns (possibly-modified result, metadata) where metadata
    captures what changed so the caller can attach it to the audit
    event (`raw_response_truncated`, `redaction_counts`, etc.).

    Strategy is conservative:
    - If total wire size is within cap AND no redaction is requested,
      return the original unchanged.
    - If redaction is requested, scan + replace EACH text block's
      content. Counts are aggregated.
    - If size still exceeds cap after redaction, truncate the LAST
      text block to fit and append a sentinel string so the operator
      sees how much was lost.
    """
    blocks = list(result.content or [])
    structured = getattr(result, "structuredContent", None)
    # `changed` tracks whether we actually altered anything. The old
    # test for this was `blocks is result.content`, which `list(...)`
    # makes permanently False — so the "return the original unchanged"
    # fast path never fired and EVERY result was rebuilt, losing
    # `structuredContent` on every single tool call rather than only on
    # truncating ones.
    changed = False
    total = _measure_response_bytes(blocks) + _structured_bytes(structured)
    redaction_counts: dict[str, int] = {}

    # ----- Redaction (optional) -----------------------------------
    if redact_secrets_in_text and structured is not None:
        redacted_structured = _redact_structured(structured, redaction_counts)
        if redacted_structured != structured:
            structured = redacted_structured
            changed = True
    if redact_secrets_in_text and blocks:
        new_blocks: list[Any] = []
        for block in blocks:
            text = _content_block_text(block)
            if text is None:
                new_blocks.append(block)
                continue
            redacted, counts = redact_secrets(text)
            for k, v in counts.items():
                redaction_counts[k] = redaction_counts.get(k, 0) + v
            if redacted != text and isinstance(block, TextContent):
                new_blocks.append(TextContent(type="text", text=redacted))
                changed = True
            else:
                new_blocks.append(block)
        blocks = new_blocks
        total = _measure_response_bytes(blocks) + _structured_bytes(structured)

    metadata: dict[str, Any] = {
        "raw_response_total_bytes": total,
        "raw_response_truncated": False,
    }
    if redaction_counts:
        metadata["raw_response_redacted"] = redaction_counts

    # ----- Truncation (post-redaction) ----------------------------
    if total <= limit_bytes:
        if not changed:
            return result, metadata
        return _replace_content(result, blocks, structured), metadata

    # Walk blocks, keep emitting until we'd exceed the cap; truncate
    # the block we'd overflow on. Drop subsequent blocks entirely
    # (we record total so operator sees how much was lost).
    out: list[Any] = []
    used = 0
    sentinel = _TRUNCATION_TAIL.format(total_bytes=total)
    sentinel_bytes = len(sentinel.encode("utf-8"))
    effective_cap = max(0, limit_bytes - sentinel_bytes)
    for block in blocks:
        text = _content_block_text(block)
        if text is None:
            # Binary — keep verbatim if it fits.
            data = getattr(block, "data", b"")
            sz = len(data) if isinstance(data, bytes | bytearray) else (
                len(data) if isinstance(data, str) else 0
            )
            if used + sz <= effective_cap:
                out.append(block)
                used += sz
            # Otherwise drop.
            continue
        text_bytes = text.encode("utf-8")
        if used + len(text_bytes) <= effective_cap:
            out.append(block)
            used += len(text_bytes)
            continue
        # Truncate this block.
        room = max(0, effective_cap - used)
        if room > 0:
            truncated_text = text_bytes[:room].decode("utf-8", errors="replace")
            # Always emit a TextContent — non-TextContent blocks with a
            # `text` field (rare) get coerced to a fresh TextContent so
            # downstream consumers see a homogeneous shape after truncation.
            out.append(TextContent(type="text", text=truncated_text + sentinel))
            used += room + sentinel_bytes
        else:
            out.append(TextContent(type="text", text=sentinel))
        break
    metadata["raw_response_truncated"] = True
    # Drop the structured copy when truncating. Passing it through would
    # hand back in full precisely the payload the cap just withheld from
    # `content`, so the cap would bound nothing for any tool that
    # declares an output schema. Recorded so the audit event shows the
    # client got a text-only answer.
    if structured is not None:
        metadata["structured_content_dropped"] = True
    return _replace_content(result, out, None), metadata


def _replace_content(
    result: CallToolResult,
    blocks: list[Any],
    structured: Any,
) -> CallToolResult:
    """Build a new CallToolResult with replaced content, preserving meta.

    `structured` is passed explicitly rather than read off `result`
    because the truncating caller deliberately passes None.
    """
    return CallToolResult.model_validate({
        "content": [
            dump_wire(b, mode=None) if hasattr(b, "model_dump") else b
            for b in blocks
        ],
        "isError": result_is_error(result),
        # Carried through so clients built on the official MCP SDK keep
        # working: for a tool that declares an outputSchema, the SDK
        # validates `structuredContent` and raises when it is absent.
        # Dropping it made every such tool fail through this gateway
        # while working when called directly.
        **({"structuredContent": structured} if structured is not None else {}),
        **(
            {"_meta": json.loads(json.dumps(result.meta, default=str))}
            if getattr(result, "meta", None) is not None else {}
        ),
    })
