"""H3 — payload size limits + secret redaction.

Three layers covered:
1. `assert_request_body_within_cap` — pre-upstream gate; raises
   `PayloadTooLargeError` for over-cap requests.
2. `cap_call_tool_result` — response-side: truncates over-cap content,
   preserves under-cap unchanged, applies opt-in redaction.
3. `redact_secrets` — pattern library detects common secret shapes.
"""
from __future__ import annotations

import pytest
from mcp.types import CallToolResult, TextContent

from vyuu_gateway.api.payload_limits import (
    PayloadTooLargeError,
    assert_request_body_within_cap,
    cap_call_tool_result,
    redact_secrets,
)
from vyuu_gateway.mcp.sdk_compat import sdk_field

# --- Request-body cap -------------------------------------------------------


def test_request_body_under_cap_passes() -> None:
    assert_request_body_within_cap(b"x" * 1000, limit_bytes=2048)


def test_request_body_at_cap_passes() -> None:
    assert_request_body_within_cap(b"x" * 2048, limit_bytes=2048)


def test_request_body_over_cap_raises() -> None:
    with pytest.raises(PayloadTooLargeError) as exc:
        assert_request_body_within_cap(b"x" * 2049, limit_bytes=2048)
    assert exc.value.actual_bytes == 2049
    assert exc.value.limit_bytes == 2048


# --- Response-body truncation ----------------------------------------------


def _result(*texts: str) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=t) for t in texts],
        isError=False,
    )


def test_response_under_cap_returned_unchanged() -> None:
    r = _result("hello world")
    capped, meta = cap_call_tool_result(r, limit_bytes=1024)
    assert capped.content[0].text == "hello world"  # type: ignore[union-attr]
    assert meta["raw_response_truncated"] is False
    assert meta["raw_response_total_bytes"] == 11


def test_response_over_cap_is_truncated_with_marker() -> None:
    big = "abcdefghij" * 1000  # 10_000 bytes
    r = _result(big)
    capped, meta = cap_call_tool_result(r, limit_bytes=2048)
    assert meta["raw_response_truncated"] is True
    assert meta["raw_response_total_bytes"] == 10_000
    text = capped.content[0].text  # type: ignore[union-attr]
    assert "[…truncated by Vyuu gateway" in text
    # Must not exceed the cap — at most cap + small overhead from sentinel.
    # Allow up to 256 bytes of truncation-marker overhead since the
    # sentinel embeds the original byte count.
    assert len(text.encode("utf-8")) <= 2048 + 256


def test_response_truncation_keeps_is_error_flag() -> None:  # noqa: N802
    r = CallToolResult(
        content=[TextContent(type="text", text="x" * 10_000)],
        isError=True,
    )
    capped, _ = cap_call_tool_result(r, limit_bytes=1024)
    assert sdk_field(capped, "is_error") is True


# --- Secret redaction -------------------------------------------------------


def test_redact_aws_access_key() -> None:
    out, counts = redact_secrets("My key is AKIAIOSFODNN7EXAMPLE here")
    assert "[REDACTED:aws_access_key]" in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert counts == {"aws_access_key": 1}


def test_redact_github_token() -> None:
    out, counts = redact_secrets(
        "Auth: ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"
    )
    assert "[REDACTED:github_token]" in out
    assert "ghp_" not in out
    assert counts == {"github_token": 1}


def test_redact_jwt() -> None:
    jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
           "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
           "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    out, counts = redact_secrets(f"token={jwt}")
    assert "[REDACTED:jwt]" in out
    assert counts == {"jwt": 1}


def test_redact_private_key_pem() -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA…snip…\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out, counts = redact_secrets(f"creds:\n{pem}\n")
    assert "[REDACTED:private_key_pem]" in out
    assert "BEGIN RSA PRIVATE KEY" not in out
    assert counts == {"private_key_pem": 1}


def test_redact_no_match_returns_original() -> None:
    text = "just some normal output, no secrets here"
    out, counts = redact_secrets(text)
    assert out == text
    assert counts == {}


def test_redact_via_cap_call_tool_result() -> None:
    """End-to-end: redaction off by default, on when requested."""
    text_with_secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"
    r = _result(text_with_secret)

    capped, meta = cap_call_tool_result(r, limit_bytes=1024)
    assert capped.content[0].text == text_with_secret  # type: ignore[union-attr]
    assert "raw_response_redacted" not in meta

    capped2, meta2 = cap_call_tool_result(
        r, limit_bytes=1024, redact_secrets_in_text=True
    )
    assert "[REDACTED:github_token]" in capped2.content[0].text  # type: ignore[union-attr]
    assert meta2["raw_response_redacted"] == {"github_token": 1}


# --- structuredContent passthrough -----------------------------------------
#
# MCP tools that declare an `outputSchema` return their result twice: as
# human-readable `content` blocks and as a machine-readable
# `structuredContent` object. Clients built on the official SDK validate
# the latter and RAISE when it is missing, so dropping it makes such a
# tool fail through the gateway while succeeding when called directly.


def _structured_result(text: str, structured: object) -> CallToolResult:
    return CallToolResult.model_validate({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
    })


def test_structured_content_survives_under_cap() -> None:
    r = _structured_result("ok", {"rows": [1, 2, 3]})
    capped, meta = cap_call_tool_result(r, limit_bytes=1_000_000)
    assert capped.structuredContent == {"rows": [1, 2, 3]}
    assert meta["raw_response_truncated"] is False


def test_untouched_result_is_returned_by_identity() -> None:
    """The `blocks is result.content` fast path could never fire.

    `list(...)` always builds a new object, so the identity test was
    permanently False and every result was rebuilt — which is how
    `structuredContent` came to be dropped on *every* call, not just
    truncating ones.
    """
    r = _structured_result("ok", {"rows": [1]})
    capped, _meta = cap_call_tool_result(r, limit_bytes=1_000_000)
    assert capped is r


def test_structured_content_counts_toward_the_cap() -> None:
    """A cap that measured only `content` under-counted the response by
    the whole size of the structured copy."""
    r = _structured_result("ok", {"blob": "y" * 5000})
    _capped, meta = cap_call_tool_result(r, limit_bytes=1_000_000)
    assert meta["raw_response_total_bytes"] > 5000


def test_structured_content_dropped_when_truncating() -> None:
    """Otherwise the cap bounds nothing: the structured sibling would
    hand back in full exactly what was withheld from `content`."""
    r = _structured_result("x" * 5000, {"rows": ["y" * 5000]})
    capped, meta = cap_call_tool_result(r, limit_bytes=200)
    assert meta["raw_response_truncated"] is True
    assert meta["structured_content_dropped"] is True
    assert capped.structuredContent is None


def test_structured_content_is_redacted_too() -> None:
    """Scrubbing the text but shipping the structured copy verbatim
    would leak the same secret out of the sibling field."""
    token = "ghp_" + "A" * 36
    r = _structured_result(f"token {token}", {"creds": {"nested": [token]}})
    capped, meta = cap_call_tool_result(
        r, limit_bytes=1_000_000, redact_secrets_in_text=True
    )
    assert token not in str(capped.structuredContent)
    assert token not in str(capped.content)
    # Counted once for the text block, once inside the structured copy.
    assert meta["raw_response_redacted"]["github_token"] == 2
