import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

# Names Python's `logging` puts on every `LogRecord` for its own bookkeeping.
# `logger.info(msg, extra={...})` writes the extra keys onto the record too;
# we want those passed through but not these built-ins (already handled or
# noise). Anything outside this set is treated as caller-supplied structured
# context and copied into the JSON payload.
_RESERVED_LOG_RECORD_ATTRS = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


def structured_fields(record: logging.LogRecord) -> dict[str, Any]:
    """The caller-supplied `extra={...}` keys on a record, nothing else.

    Shared by the stdout JSON formatter and the SIEM log bridge so a
    line shipped to Splunk carries exactly the fields the line on
    stdout does — one definition of "structured context", not two that
    drift.
    """

    out: dict[str, Any] = {}
    for key, value in record.__dict__.items():
        if key in _RESERVED_LOG_RECORD_ATTRS:
            continue
        if key in ("timestamp", "level", "logger", "message"):
            # Built-in payload fields; `extra={"level": ...}` must not
            # shadow the real one.
            continue
        out[key] = value
    return out


class JsonFormatter(logging.Formatter):
    """Minimal one-line JSON formatter for stdout log aggregation.

    Caller-supplied keys via `logger.X(msg, extra={...})` are copied into the
    JSON payload alongside the built-in fields. Reserved fields (`message`,
    `level`, etc.) cannot be shadowed by `extra` — those always reflect the
    log record itself. Anything else is passed through as-is so structured
    log consumers see every key the caller intended.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        payload.update(structured_fields(record))

        if record.exc_info is not None:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, separators=(",", ":"), default=str)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(level.upper())

    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(logger_name)
        logger.handlers = []
        logger.propagate = True
