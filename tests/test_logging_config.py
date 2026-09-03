import json
import logging
from typing import Any

import pytest

from vyuu_gateway.logging_config import configure_logging


def test_configure_logging_emits_one_line_json(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")

    logging.getLogger("tests.logging").info("health_check")

    captured = capsys.readouterr()
    payload: dict[str, Any] = json.loads(captured.out)

    assert payload["level"] == "INFO"
    assert payload["logger"] == "tests.logging"
    assert payload["message"] == "health_check"
    assert "timestamp" in payload


def test_configure_logging_preserves_caller_extra_fields(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Caller-supplied `extra={...}` keys must land in the JSON payload.

    Regression test for the architecture-review finding that the formatter
    silently dropped `extra`. Without this, structured fields like
    `session_id` / `tenant_id` on lifecycle events would be invisible in
    aggregated logs.
    """
    configure_logging("INFO")

    logging.getLogger("tests.logging").warning(
        "session_rejected",
        extra={"tenant_id": "abc", "session_id": "sess-1", "reason": "expired"},
    )

    captured = capsys.readouterr()
    payload: dict[str, Any] = json.loads(captured.out)

    assert payload["message"] == "session_rejected"
    assert payload["tenant_id"] == "abc"
    assert payload["session_id"] == "sess-1"
    assert payload["reason"] == "expired"


def test_configure_logging_does_not_emit_internal_logrecord_attrs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`pathname`, `lineno`, `process`, `thread`, etc. are bookkeeping fields
    that `logging` puts on every record. They must not bleed into the JSON
    payload — those are noise for log consumers, and several are
    deployment-specific (process id, thread id) that complicate test
    determinism."""
    configure_logging("INFO")

    logging.getLogger("tests.logging").info("plain_message")

    captured = capsys.readouterr()
    payload: dict[str, Any] = json.loads(captured.out)

    for noisy in ("pathname", "lineno", "process", "thread", "threadName", "funcName"):
        assert noisy not in payload, f"{noisy!r} leaked into the JSON payload"
