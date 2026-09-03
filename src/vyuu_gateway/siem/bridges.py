"""Hooks that turn the gateway's existing paths into SIEM events.

Three bridges, one per family that already had a path of its own:

- `SiemAuditEmitter` sits in the audit fan-out chain (`main.py`) and
  projects every `AuditEvent` — tool calls and access attempts.
- The admin-audit commit hook ships `admin_audit_log` rows at COMMIT,
  never before: `record_admin_action` stages a projected event on the
  session, `after_commit` emits it, `after_rollback` discards it. A
  SIEM row for an action that rolled back would be a phantom.
- `SiemLogHandler` forwards structured log records. A record is routed
  to a tenant only when it carries that tenant's id in `extra`; every
  record goes to the deployment target.

Logins and per-user tool authorisation had no path to bridge, so those
sites call `registry.emit(...)` directly.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from sqlalchemy import event as sa_event
from sqlalchemy.orm import Session

from vyuu_gateway.audit.emitter import AuditEmitter, EmitResult
from vyuu_gateway.audit.events import AuditEvent
from vyuu_gateway.siem import registry
from vyuu_gateway.siem.events import (
    AuthMethod,
    AuthOutcome,
    AuthSurface,
    SiemEvent,
    ToolAuthAction,
    auth_event,
    from_audit_event,
    from_log_record,
    tool_auth_event,
)

logger = logging.getLogger(__name__)

# Key under which `record_admin_action` stages events on `Session.info`.
PENDING_ADMIN_EVENTS_KEY = "siem_pending_admin_events"


class SiemAuditEmitter:
    """Audit-chain wrapper: project, hand to the exporter, delegate.

    Placed INSIDE the chain (below the Postgres store) so the durable
    write has already happened by the time an event reaches here, and
    a slow or failing SIEM cannot influence the `EmitResult` the
    lifecycle acts on — `emit_nowait` on the exporter never blocks and
    never raises, so this wrapper is invisible to its caller.
    """

    def __init__(self, inner: AuditEmitter | None = None) -> None:
        self._inner = inner

    def emit_nowait(self, audit_event: AuditEvent) -> EmitResult:
        try:
            registry.emit(from_audit_event(audit_event))
        except Exception:  # noqa: BLE001 - projection must never break audit
            logger.warning(
                "siem_audit_projection_failed",
                extra={"event_id": str(audit_event.event_id)},
                exc_info=True,
            )
        if self._inner is None:
            return EmitResult(accepted=True)
        return self._inner.emit_nowait(audit_event)


# --- admin actions: ship at commit -------------------------------------


def stage_admin_event(session: Session, event: SiemEvent) -> None:
    """Called by `record_admin_action`. Pure data, no ORM reference:
    attributes expire on commit, and `after_commit` may not issue SQL."""

    info = getattr(session, "info", None)
    if info is None:
        # A test double without `Session.info`. Nothing to stage on, and
        # nothing to ship: the commit hook only fires for real sessions.
        return
    pending = info.setdefault(PENDING_ADMIN_EVENTS_KEY, [])
    pending.append(event)


_hook_installed = False


def install_admin_audit_hook() -> None:
    """Register the class-level session listeners once per process.

    Idempotent: `create_app` is called per test, and SQLAlchemy would
    otherwise fire the listener N times per commit.
    """

    global _hook_installed
    if _hook_installed:
        return
    sa_event.listen(Session, "after_commit", _ship_pending_admin_events)
    sa_event.listen(Session, "after_rollback", _discard_pending_admin_events)
    _hook_installed = True


def _ship_pending_admin_events(session: Session) -> None:
    pending: list[SiemEvent] = session.info.pop(PENDING_ADMIN_EVENTS_KEY, [])
    for pending_event in pending:
        registry.emit(pending_event)


def _discard_pending_admin_events(session: Session) -> None:
    session.info.pop(PENDING_ADMIN_EVENTS_KEY, None)


# --- structured logs -------------------------------------------------------


class SiemLogHandler(logging.Handler):
    """Forwards log records to the exporter as `gateway_log` events.

    Attached to the root logger by `create_app` when a target could
    receive logs. Cheap when none does: the exporter's resolver filters
    by category before anything is queued.

    Records from this package are skipped — a delivery failure logs a
    warning, and shipping that warning to the failing target is a loop.
    """

    _SELF_PREFIX = "vyuu_gateway.siem"

    def __init__(self, level: int = logging.INFO) -> None:
        super().__init__(level)

    def emit(self, record: logging.LogRecord) -> None:
        if record.name.startswith(self._SELF_PREFIX):
            return
        try:
            registry.emit(from_log_record(record, _tenant_from_record(record)))
        except Exception:  # noqa: BLE001 - a log handler must never raise
            return


def _tenant_from_record(record: logging.LogRecord) -> UUID | None:
    """Only an explicit `tenant_id` in `extra` routes a line to a tenant.
    Nothing is inferred from the message."""

    raw: Any = getattr(record, "tenant_id", None)
    if isinstance(raw, UUID):
        return raw
    if isinstance(raw, str):
        try:
            return UUID(raw)
        except ValueError:
            return None
    return None


# --- logins and tool authorisation: the families that had no path ----------


def record_signin(
    http_request: Any,
    *,
    tenant_id: UUID,
    surface: AuthSurface,
    method: AuthMethod,
    outcome: AuthOutcome,
    subject: str | None,
    subject_id: UUID | None = None,
    reason: str | None = None,
    directory_id: UUID | None = None,
    directory_display: str | None = None,
) -> None:
    """One call per sign-in attempt: SIEM event + login metric.

    Takes the request so the client address and user agent ride along
    — the two fields a SOC actually pivots on. Never raises.
    """

    try:
        client_ip = None
        user_agent = None
        if http_request is not None:
            client = getattr(http_request, "client", None)
            client_ip = getattr(client, "host", None)
            headers = getattr(http_request, "headers", None)
            if headers is not None:
                user_agent = headers.get("user-agent")
        registry.emit(
            auth_event(
                tenant_id=tenant_id,
                surface=surface,
                method=method,
                outcome=outcome,
                subject=subject,
                subject_id=subject_id,
                reason=reason,
                client_ip=client_ip,
                user_agent=user_agent,
                directory_id=directory_id,
                directory_display=directory_display,
            )
        )
        telemetry = _telemetry_from(http_request)
        if telemetry is not None:
            telemetry.record_login(
                tenant_id=tenant_id,
                surface=surface.value,
                method=method.value,
                outcome=outcome.value,
            )
    except Exception:  # noqa: BLE001 - a sign-in must not fail on telemetry
        logger.warning("siem_signin_record_failed", exc_info=True)


def record_tool_auth(
    *,
    tenant_id: UUID,
    action: ToolAuthAction,
    server_id: UUID | None,
    server_display: str | None = None,
    user_id: UUID | None = None,
    mechanism: str | None = None,
    reason: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Per-user upstream authorisation lifecycle. Never raises."""

    try:
        registry.emit(
            tool_auth_event(
                tenant_id=tenant_id,
                action=action,
                server_id=server_id,
                server_display=server_display,
                user_id=user_id,
                mechanism=mechanism,
                reason=reason,
                detail=detail,
            )
        )
    except Exception:  # noqa: BLE001
        logger.warning("siem_tool_auth_record_failed", exc_info=True)


def _telemetry_from(http_request: Any) -> Any:
    app = getattr(http_request, "app", None)
    state = getattr(app, "state", None)
    return getattr(state, "telemetry", None)

