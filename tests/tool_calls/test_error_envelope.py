"""Tests for the structured tool-call error envelope.

Covers two surfaces:

1.  `classify_upstream_error_text` — the heuristic that pattern-matches
    common phrases ("File not found", "rate limit exceeded",
    "Unauthorized") into a stable `ErrorCategory` enum. Conservative
    by design: ambiguous text returns `UNKNOWN` so clients don't
    take wrong recovery actions on misclassified errors.

2.  `build_error_envelope` / `envelope_from_upstream_iserror` — the
    builders that produce a `CallToolResult` with the `[source ·
    category]` text prefix and `meta["vyuu.error"]` structured fields.
    Asserts the meta block carries the right keys + retryable flag,
    and that upstream content is preserved verbatim alongside the
    prefixed block.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from mcp.types import CallToolResult, TextContent

from vyuu_gateway.mcp.sdk_compat import sdk_field
from vyuu_gateway.tool_calls.error_envelope import (
    ErrorCategory,
    ErrorSource,
    build_error_envelope,
    classify_upstream_error_text,
    envelope_from_upstream_iserror,
)

# --- Classifier ----------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        # rate-limited
        ("API rate limit exceeded for user", ErrorCategory.RATE_LIMITED),
        ("HTTP 429 Too Many Requests", ErrorCategory.RATE_LIMITED),
        ("quota exceeded for the day", ErrorCategory.RATE_LIMITED),
        # auth-failed
        ("401 Unauthorized — invalid token", ErrorCategory.AUTH_FAILED),
        ("authentication failed: bad credentials", ErrorCategory.AUTH_FAILED),
        ("insufficient_scope: repo:write required", ErrorCategory.AUTH_FAILED),
        ("token expired", ErrorCategory.AUTH_FAILED),
        ("403 Forbidden", ErrorCategory.AUTH_FAILED),
        # not-found  (the VirusTotal case the user originally hit)
        (
            "VirusTotal API error: File 'deadbeef...' not found",
            ErrorCategory.NOT_FOUND,
        ),
        (
            "Could not resolve to a Repository with the name 'foo/bar'",
            ErrorCategory.NOT_FOUND,
        ),
        ("404: object does not exist", ErrorCategory.NOT_FOUND),
        # timeout
        ("upstream timed out after 30s", ErrorCategory.TIMEOUT),
        ("504 Gateway Timeout", ErrorCategory.TIMEOUT),
        ("deadline exceeded", ErrorCategory.TIMEOUT),
        # malformed-args
        ("Invalid input: 'hash' must be 64 chars", ErrorCategory.MALFORMED_ARGS),
        ("validation failed: missing required field 'repo'",
         ErrorCategory.MALFORMED_ARGS),
        ("400 Bad Request — schema mismatch", ErrorCategory.MALFORMED_ARGS),
        # upstream-internal
        ("500 Internal Server Error", ErrorCategory.UPSTREAM_INTERNAL),
        ("503 Service Unavailable", ErrorCategory.UPSTREAM_INTERNAL),
        # transient
        ("connection reset by peer", ErrorCategory.TRANSIENT),
        ("circuit breaker open", ErrorCategory.TRANSIENT),
        # unknown — true negatives that shouldn't classify
        ("the cake is a lie", ErrorCategory.UNKNOWN),
        ("", ErrorCategory.UNKNOWN),
        ("widget xyz123 reported state HARMONIC_DRIFT",
         ErrorCategory.UNKNOWN),
    ],
)
def test_classifier_matches_common_upstream_phrasings(
    text: str, expected: ErrorCategory
) -> None:
    """The heuristic patterns cover the phrasings real upstreams use."""
    assert classify_upstream_error_text(text) == expected


def test_classifier_priority_specific_before_generic() -> None:
    """A 401 inside a longer 'rate limit' message still classifies as
    rate-limited (the rate-limit pattern is checked first because
    that's the more actionable signal — clients should back off, not
    re-auth). Encoded by ordering of `_CLASSIFIER_PATTERNS`."""
    text = "rate limit exceeded; retry after 60s (429)"
    assert classify_upstream_error_text(text) == ErrorCategory.RATE_LIMITED

    # And the inverse — a pure auth-failed message doesn't get
    # mis-classified as rate-limited.
    assert (
        classify_upstream_error_text("401 unauthorized: bad token")
        == ErrorCategory.AUTH_FAILED
    )


# --- Envelope builder ---------------------------------------------------


def test_build_error_envelope_renders_bracketed_prefix() -> None:
    """The first content block carries `[<source> · <category>] <msg>`
    so any client that just renders `content[0].text` gets the source
    + classification at-a-glance."""
    cid = uuid4()
    server_id = uuid4()
    result = build_error_envelope(
        source=ErrorSource.UPSTREAM_MCP,
        category=ErrorCategory.NOT_FOUND,
        message="File 'deadbeef' not found",
        correlation_id=cid,
        upstream_server_id=server_id,
        upstream_tool_name="get_file_report",
    )
    assert isinstance(result, CallToolResult)
    assert sdk_field(result, "is_error") is True
    first = result.content[0]
    assert isinstance(first, TextContent)
    assert first.text == (
        "[upstream_mcp · not_found] File 'deadbeef' not found"
    )


def test_build_error_envelope_meta_carries_structured_fields() -> None:
    """`meta['vyuu.error']` exposes the structured fields clients use
    for programmatic recovery (retry / re-auth / fix-args / etc.)."""
    cid = uuid4()
    server_id = uuid4()
    result = build_error_envelope(
        source=ErrorSource.NETWORK,
        category=ErrorCategory.TIMEOUT,
        message="upstream timed out after 30s",
        correlation_id=cid,
        upstream_server_id=server_id,
        upstream_tool_name="search_repositories",
    )
    meta = (result.meta or {}).get("vyuu.error")
    assert meta is not None
    assert meta["source"] == "network"
    assert meta["category"] == "timeout"
    assert meta["retryable"] is True  # timeouts ARE retryable
    assert meta["correlation_id"] == str(cid)
    assert meta["upstream_server_id"] == str(server_id)
    assert meta["upstream_tool_name"] == "search_repositories"


@pytest.mark.parametrize(
    "category,retryable",
    [
        (ErrorCategory.RATE_LIMITED, True),
        (ErrorCategory.TIMEOUT, True),
        (ErrorCategory.TRANSIENT, True),
        (ErrorCategory.AUTH_FAILED, False),
        (ErrorCategory.NOT_FOUND, False),
        (ErrorCategory.DENIED_BY_POLICY, False),
        (ErrorCategory.MALFORMED_ARGS, False),
        (ErrorCategory.UNKNOWN, False),
    ],
)
def test_retryable_flag_per_category(
    category: ErrorCategory, retryable: bool
) -> None:
    """Conservative: only RATE_LIMITED / TIMEOUT / TRANSIENT count as
    retryable. Auth + not-found + malformed-args are explicit NO so
    clients don't loop on permanent failures."""
    result = build_error_envelope(
        source=ErrorSource.UPSTREAM_MCP,
        category=category,
        message="x",
    )
    assert (result.meta or {})["vyuu.error"]["retryable"] is retryable


def test_envelope_preserves_extra_upstream_content_blocks() -> None:
    """When upstream returns multiple content blocks (rich text +
    structured payload), the envelope keeps them — the bracketed
    prefix is prepended, the original blocks follow. Avoids losing
    upstream's full error context."""
    extra = TextContent(type="text", text="trace_id: abc123")
    same_text = TextContent(type="text", text="upstream message")
    result = build_error_envelope(
        source=ErrorSource.UPSTREAM_MCP,
        category=ErrorCategory.UPSTREAM_INTERNAL,
        message="upstream message",
        upstream_content=[same_text, extra],
    )
    # The duplicate-text block (same as `message`) is dropped to avoid
    # rendering the same text twice; the unique extra block stays.
    assert len(result.content) == 2
    first = result.content[0]
    second = result.content[1]
    assert isinstance(first, TextContent)
    assert isinstance(second, TextContent)
    assert first.text.startswith("[upstream_mcp · upstream_internal]")
    assert second.text == "trace_id: abc123"


# --- Upstream-isError adapter ------------------------------------------


def test_envelope_from_upstream_iserror_classifies_vt_not_found() -> None:
    """The VirusTotal case the user originally hit. Upstream returned
    isError=true with a 'File ... not found' message; we classify as
    not_found and tag with source=upstream_mcp."""
    upstream = CallToolResult(
        content=[
            TextContent(
                type="text",
                text=(
                    "Tool 'get_file_report' execution failed: VirusTotal "
                    "API error: File 'deadbeefdeadbeef' not found"
                ),
            )
        ],
        isError=True,
    )
    server_id = uuid4()
    result = envelope_from_upstream_iserror(
        upstream,
        upstream_server_id=server_id,
        upstream_tool_name="get_file_report",
    )
    meta = (result.meta or {})["vyuu.error"]
    assert meta["source"] == "upstream_mcp"
    assert meta["category"] == "not_found"
    assert meta["retryable"] is False
    assert meta["upstream_server_id"] == str(server_id)
    assert meta["upstream_tool_name"] == "get_file_report"
    first = result.content[0]
    assert isinstance(first, TextContent)
    assert first.text.startswith("[upstream_mcp · not_found]")
    assert "File 'deadbeefdeadbeef' not found" in first.text


def test_envelope_from_upstream_iserror_falls_back_to_unknown() -> None:
    """An upstream error message that doesn't match any pattern lands
    as `unknown` — preserves the text but doesn't lie about the
    category."""
    upstream = CallToolResult(
        content=[
            TextContent(
                type="text",
                text="HARMONIC_DRIFT detected on widget xyz123",
            )
        ],
        isError=True,
    )
    result = envelope_from_upstream_iserror(upstream)
    meta = (result.meta or {})["vyuu.error"]
    assert meta["source"] == "upstream_mcp"
    assert meta["category"] == "unknown"
    first = result.content[0]
    assert isinstance(first, TextContent)
    assert "HARMONIC_DRIFT" in first.text


def test_envelope_correlation_id_is_synthesized_when_absent() -> None:
    """If the caller doesn't pass a correlation_id we mint one (uuid4)
    so every error envelope has a unique tag for log correlation."""
    result = build_error_envelope(
        source=ErrorSource.GATEWAY,
        category=ErrorCategory.UNKNOWN,
        message="x",
    )
    cid = (result.meta or {})["vyuu.error"]["correlation_id"]
    # Validates as a UUID — would raise otherwise.
    UUID(cid)


# --- Every gateway-side failure must name a category the caller can act on ---


def test_every_error_status_maps_to_a_meaningful_category() -> None:
    """`unknown` is a fallback, not a mapping.

    Three statuses were absent from `_STATUS_TO_ENVELOPE` and therefore
    rendered as `unknown`, which told the caller nothing about a
    situation each of them can act on: a JIT elevation is self-service,
    a scope denial is not, and an MRTR refusal is an operator policy
    decision. A category that does not discriminate is the same as no
    category at all.
    """

    from vyuu_gateway.api.inbound_mcp import _STATUS_TO_ENVELOPE
    from vyuu_gateway.tool_calls.lifecycle import ToolCallStatus

    # ALLOWED is not an error, so it has nothing to map to.
    unmapped = {
        status
        for status in ToolCallStatus
        if status is not ToolCallStatus.ALLOWED and status not in _STATUS_TO_ENVELOPE
    }
    assert unmapped == set(), (
        f"these statuses fall through to `unknown`: "
        f"{sorted(s.value for s in unmapped)}"
    )


def test_the_three_previously_unknown_statuses_are_specific() -> None:
    from vyuu_gateway.api.inbound_mcp import _STATUS_TO_ENVELOPE
    from vyuu_gateway.tool_calls.lifecycle import ToolCallStatus

    _source, category = _STATUS_TO_ENVELOPE[ToolCallStatus.NO_TOOL_ELEVATION]
    assert category is ErrorCategory.NEEDS_TOOL_ELEVATION

    _source, category = _STATUS_TO_ENVELOPE[ToolCallStatus.INSUFFICIENT_SCOPE]
    assert category is ErrorCategory.DENIED_BY_POLICY

    _source, category = _STATUS_TO_ENVELOPE[ToolCallStatus.INPUT_REQUIRED_DENIED]
    assert category is ErrorCategory.UPSTREAM_INPUT_REFUSED


def test_elevation_is_retryable_but_an_mrtr_refusal_is_not() -> None:
    """The caller can fix one of these themselves and not the other.

    Elevating in the portal makes the identical call succeed, so clients
    should show "retry available". Widening MRTR policy needs an
    operator to first decide it is safe — url-elicitation in particular
    is a phishing vector — so a caller retry loop is exactly wrong.
    """

    def _retryable(category: ErrorCategory) -> bool:
        result = build_error_envelope(
            source=ErrorSource.GATEWAY, category=category, message="x"
        )
        meta = sdk_field(result, "meta") or {}
        return bool(meta["vyuu.error"]["retryable"])

    assert _retryable(ErrorCategory.NEEDS_TOOL_ELEVATION) is True
    assert _retryable(ErrorCategory.UPSTREAM_INPUT_REFUSED) is False
    # Control: a plain policy denial has no self-service path either.
    assert _retryable(ErrorCategory.DENIED_BY_POLICY) is False
