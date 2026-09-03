"""Process-wide handle to the SIEM exporter.

Most emit sites have `app.state` in reach. The ones that do not — the
SQLAlchemy commit hook that ships admin actions, the `logging.Handler`
that ships log lines — run with no request in hand. They call `emit()`
here. It is a no-op until `create_app` installs an exporter, so every
call site is safe to leave in place when export is not configured.

Same shape as `audit.events.configure_raw_capture_cap`: a module-level
setter called once at startup, for a deployment-wide singleton.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vyuu_gateway.siem.events import SiemEvent
    from vyuu_gateway.siem.exporter import SiemExporter

_exporter: SiemExporter | None = None


def set_exporter(exporter: SiemExporter | None) -> None:
    global _exporter
    _exporter = exporter


def get_exporter() -> SiemExporter | None:
    return _exporter


def emit(event: SiemEvent) -> None:
    """Hand an event to the exporter if one is installed. Never raises:
    export is a side channel, and no request may fail because of it."""

    exporter = _exporter
    if exporter is None:
        return
    try:
        exporter.emit_nowait(event)
    except Exception:  # noqa: BLE001 - side channel must not surface
        return
