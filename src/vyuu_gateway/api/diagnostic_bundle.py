"""Gateway-wide diagnostic bundle — one-stop troubleshooting download.

When a customer hits an issue ("we're seeing 503s on the portal",
"DB seems sluggish", "tool calls are timing out for tenant X"), they
click **Download diagnostic bundle** in the operator console and
share the resulting JSON with our support team. The bundle answers
the questions an SRE would otherwise have to ssh in and grep for:

- Is the gateway alive? Uptime? Memory? FDs? CPU?
- Can it reach Postgres / Redis / NATS / the secret store?
- How many MCP servers are registered, and how many are healthy?
- How many vservers, with what visibility?
- Is the per-tenant inflight gate currently shedding traffic?
- Are any circuit breakers open?
- What do the last N audit events look like (allowed / denied / 503)?
- What's the gateway's effective settings configuration?

**Security model:**
- Operator-authenticated (same as every other `/api/v1/admin/*` route).
- Tenant-scoped — operators see only their tenant's data, not
  cross-tenant aggregates. (Multi-tenant gateways still produce
  one-bundle-per-tenant; an across-tenant view is a future "support"
  role.)
- **Secrets are NEVER in the bundle.** Settings fields whose names
  match the secret pattern (`*_secret`, `*_password`, `*_url` for
  things like `database_url`) are replaced with `[REDACTED]`. The
  bundle shows secret-store ref NAMES (so you can confirm the right
  ref is configured) but never values.
- `Cache-Control: no-store` so intermediaries don't cache.
- `Content-Disposition: attachment` so browsers download.

Wire: `GET /api/v1/admin/diagnostic-bundle?since_minutes=60`
"""
from __future__ import annotations

import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.audit.events import AuditDecision, AuditEvent
from vyuu_gateway.db.models import (
    AdminAuditLog,
    IdpDirectory,
    McpServer,
    ToolCallEvent,
    User,
    VirtualServer,
)
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"])

_BUNDLE_VERSION = "1.2"  # bumped for RETENTION-1 worker reporting
_DEFAULT_AUDIT_LIMIT = 200
_MAX_AUDIT_LIMIT = 1000
_GATEWAY_BOOT_MONOTONIC = time.monotonic()  # set on import; uptime = now - this

# Field-name patterns that indicate a secret. Settings fields matching
# any of these get their values replaced with `[REDACTED]` in the
# bundle. Conservative: better to redact a non-secret than leak one.
_SECRET_FIELD_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"_secret$", re.IGNORECASE),
    re.compile(r"_password$", re.IGNORECASE),
    re.compile(r"_token$", re.IGNORECASE),
    re.compile(r"_key$", re.IGNORECASE),
    re.compile(r"signing_secret", re.IGNORECASE),
    re.compile(r"^database_url$", re.IGNORECASE),  # contains password
    re.compile(r"^redis_url$", re.IGNORECASE),       # MAY contain password
)


def _is_secret_field(name: str) -> bool:
    return any(p.search(name) for p in _SECRET_FIELD_PATTERNS)


def _redact_url_password(url: str | None) -> str | None:
    """Strip `:password@` from a URL while keeping host/port/db visible.
    `postgres://user:secret@host:5432/db` → `postgres://user:***@host:5432/db`
    """
    if not url:
        return url
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", url)


# --- Section helpers ------------------------------------------------------


def _gateway_section(http_request: Request) -> dict[str, Any]:
    """Process-level state — uptime, memory, CPU, FDs, host info."""
    settings = http_request.app.state.settings
    pid = os.getpid()
    rss_bytes: float | None = None
    cpu_percent: float | None = None
    try:
        out = subprocess.check_output(
            ["ps", "-o", "pcpu=,rss=", "-p", str(pid)],
            stderr=subprocess.DEVNULL, timeout=1,
        ).decode().strip().split()
        if len(out) >= 2:
            cpu_percent = float(out[0])
            rss_bytes = float(out[1]) * 1024
    except Exception:  # noqa: BLE001 - best-effort
        pass
    fd_count: int | None = None
    if shutil.which("lsof"):
        try:
            fd_count = subprocess.check_output(
                ["lsof", "-p", str(pid)],
                stderr=subprocess.DEVNULL, timeout=2,
            ).decode().count("\n")
        except Exception:  # noqa: BLE001
            pass
    return {
        "name": settings.app_name,
        "version": settings.version,
        "environment": settings.environment,
        "log_level": settings.log_level,
        "python_version": sys.version.split()[0],
        "platform": f"{platform.system()}/{platform.machine()}",
        "hostname": socket.gethostname(),
        "process": {
            "pid": pid,
            "uptime_seconds": round(time.monotonic() - _GATEWAY_BOOT_MONOTONIC, 1),
            "rss_bytes": rss_bytes,
            "rss_mb": round(rss_bytes / 1024 / 1024, 1) if rss_bytes else None,
            "cpu_percent": cpu_percent,
            "fd_count": fd_count,
        },
    }


def _settings_snapshot(http_request: Request) -> dict[str, Any]:
    """Effective Settings dump with secret-shaped fields redacted.

    Pydantic's `model_dump()` would include every field; we filter and
    redact instead so support engineers see *what's configured* without
    seeing the secret values themselves. This is the bundle's biggest
    leak risk — the redaction patterns are conservative.
    """
    settings = http_request.app.state.settings
    raw = settings.model_dump()
    out: dict[str, Any] = {}
    # URL-shaped fields get partial redaction (password segment only)
    # so support engineers can still see which DB / Redis the gateway
    # is pointed at — useful for "you're hitting the wrong env"
    # diagnostics. Generic secret-field redaction comes after, so
    # *_url overrides aren't accidentally caught.
    url_fields = {"database_url", "redis_url"}
    for k, v in raw.items():
        if k in url_fields:
            out[k] = _redact_url_password(v) if isinstance(v, str) else v
        elif _is_secret_field(k):
            if isinstance(v, str) and v:
                out[k] = "[REDACTED]"
            else:
                # Leave None / empty as-is so operators see "not configured"
                out[k] = v
        elif isinstance(v, (str, int, float, bool, type(None))):
            out[k] = v
        elif isinstance(v, list | tuple):
            out[k] = list(v)
        else:
            out[k] = str(v)
    return out


def _connectivity_section(
    http_request: Request, db: Session
) -> dict[str, Any]:
    """Best-effort reachability checks for backing services."""
    settings = http_request.app.state.settings
    out: dict[str, Any] = {}

    # Postgres — already have a tenant-scoped session; cheap probe.
    try:
        version_row = db.execute(text("SHOW server_version")).first()
        active_count_row = db.execute(text(
            "SELECT count(*) FROM pg_stat_activity "
            "WHERE datname=current_database() AND state='active'"
        )).first()
        out["postgres"] = {
            "reachable": True,
            "version": version_row[0] if version_row else None,
            "active_connections": active_count_row[0] if active_count_row else None,
            "url": _redact_url_password(settings.database_url),
        }
    except Exception as exc:  # noqa: BLE001
        out["postgres"] = {
            "reachable": False,
            "error_type": exc.__class__.__name__,
            "url": _redact_url_password(settings.database_url),
        }

    # Redis — only if configured. We don't open a client here (avoid
    # adding a dep on this hot path); just report whether the URL is
    # set + whether the session registry is the Redis-backed one.
    redis_url = getattr(settings, "redis_url", None)
    session_registry_class = type(http_request.app.state.session_registry).__name__
    out["redis"] = {
        "configured": bool(redis_url),
        "url": _redact_url_password(redis_url) if redis_url else None,
        "session_registry_class": session_registry_class,
        "in_memory_fallback": "InMemorySessionRegistry" in session_registry_class,
    }

    # NATS / audit emitter — derive from the wired emitter class.
    audit_emitter = getattr(http_request.app.state, "audit_emitter", None)
    audit_class = type(audit_emitter).__name__ if audit_emitter else "None"
    inner_class = (
        type(audit_emitter._inner).__name__
        if audit_emitter and hasattr(audit_emitter, "_inner") else None
    )
    out["audit_emitter"] = {
        "class": audit_class,
        "inner_class": inner_class,
        "in_process_only": inner_class == "_LocalAuditEmitter",
    }

    # Secret store — class name + a "ping" if the backend supports one.
    secret_store = getattr(http_request.app.state, "secret_store", None)
    secret_class = type(secret_store).__name__ if secret_store else "None"
    out["secret_store"] = {"class": secret_class}

    return out


def _servers_section(
    db: Session, *, tenant_id: UUID
) -> dict[str, Any]:
    """All MCP servers in the operator's tenant — counts + health
    distribution + recently failed."""
    servers: list[McpServer] = list(db.execute(
        select(McpServer).where(McpServer.tenant_id == tenant_id)
        .order_by(McpServer.display_name)
    ).scalars())
    by_health: dict[str, int] = {}
    sync_errors: list[dict[str, Any]] = []
    health_errors: list[dict[str, Any]] = []
    for s in servers:
        h = (s.health_status.value if hasattr(s.health_status, "value")
             else str(s.health_status or "unknown"))
        by_health[h] = by_health.get(h, 0) + 1
        if s.last_health_error:
            health_errors.append({
                "id": str(s.id),
                "display_name": s.display_name,
                "error": s.last_health_error[:300],
                "checked_at": (
                    s.last_health_checked_at.isoformat()
                    if s.last_health_checked_at else None
                ),
            })
        if (
            s.last_capabilities_pulled_at is None
            and (datetime.now(UTC) - s.registered_at).total_seconds() > 300
        ):
            sync_errors.append({
                "id": str(s.id),
                "display_name": s.display_name,
                "registered_at": s.registered_at.isoformat(),
                "issue": "registered > 5min ago, never synced",
            })
    return {
        "total": len(servers),
        "by_health": by_health,
        "with_health_errors": health_errors[:20],
        "with_sync_issues": sync_errors[:20],
    }


def _vservers_section(
    db: Session, *, tenant_id: UUID
) -> dict[str, Any]:
    """All vservers in the operator's tenant — counts + visibility."""
    vservers: list[VirtualServer] = list(db.execute(
        select(VirtualServer).where(VirtualServer.tenant_id == tenant_id)
        .order_by(VirtualServer.name)
    ).scalars())
    by_visibility: dict[str, int] = {}
    for v in vservers:
        vis = (v.visibility.value if hasattr(v.visibility, "value")
               else str(v.visibility))
        by_visibility[vis] = by_visibility.get(vis, 0) + 1
    return {
        "total": len(vservers),
        "by_visibility": by_visibility,
        "names_sample": [v.name for v in vservers[:30]],
    }


def _circuit_breaker_section(http_request: Request) -> dict[str, Any]:
    """Roll-up of circuit breaker state across all upstream pool keys."""
    registry = getattr(
        http_request.app.state, "upstream_circuit_breakers", None
    )
    if registry is None:
        return {"available": False, "reason": "registry not configured"}
    breakers = getattr(registry, "_breakers", {})
    if not isinstance(breakers, dict):
        return {"available": False, "reason": "no introspection on registry"}
    by_state: dict[str, int] = {}
    open_keys: list[str] = []
    half_open_keys: list[str] = []
    for key, breaker in breakers.items():
        snap = breaker.snapshot()
        state_label = (
            snap.state.value if hasattr(snap.state, "value")
            else str(snap.state)
        )
        by_state[state_label] = by_state.get(state_label, 0) + 1
        if state_label == "open":
            open_keys.append(str(key))
        elif state_label == "half_open":
            half_open_keys.append(str(key))
    return {
        "available": True,
        "total_keys": len(breakers),
        "by_state": by_state,
        "open_keys": open_keys,
        "half_open_keys": half_open_keys,
    }


def _audit_buffer_section(
    http_request: Request,
    *,
    tenant_id: UUID,
    since_minutes: int,
    limit: int,
) -> dict[str, Any]:
    """Recent audit events from the in-memory ring buffer + summary
    counts. Production deployments query ClickHouse for full history
    via `clickhouse_consumer`'s warehouse; this section gives the
    quick "what's happening right now" picture."""
    emitter = getattr(http_request.app.state, "audit_emitter", None)
    if emitter is None or not hasattr(emitter, "query"):
        return {
            "available": False,
            "reason": "no in-memory audit ring buffer",
            "events": [],
        }
    cutoff = datetime.now(UTC) - timedelta(minutes=since_minutes)
    # Pull a generous window so we can summarise even if the recent-
    # events sample is small.
    events: list[AuditEvent] = emitter.query(
        tenant_id=tenant_id, limit=_MAX_AUDIT_LIMIT,
    )
    recent = [e for e in events if e.timestamp >= cutoff]
    decisions: dict[str, int] = {}
    upstream_statuses: dict[str, int] = {}
    by_vserver: dict[str, int] = {}
    for e in recent:
        d = (e.decision.value if hasattr(e.decision, "value")
             else str(e.decision))
        decisions[d] = decisions.get(d, 0) + 1
        u = (e.upstream_status.value if hasattr(e.upstream_status, "value")
             else str(e.upstream_status))
        upstream_statuses[u] = upstream_statuses.get(u, 0) + 1
        v = e.vserver_name or "<no-vserver>"
        by_vserver[v] = by_vserver.get(v, 0) + 1
    sample = recent[:limit]
    return {
        "available": True,
        "since_minutes": since_minutes,
        "limit": limit,
        "ring_buffer_max": getattr(emitter, "_max_events", None),
        "recent_total": len(recent),
        "decision_counts": decisions,
        "upstream_status_counts": upstream_statuses,
        "by_vserver": dict(sorted(by_vserver.items(),
                                   key=lambda kv: -kv[1])[:20]),
        "events_sample": [_audit_event_summary(e) for e in sample],
        "denial_reasons": _top_denial_reasons(recent),
    }


def _audit_event_summary(event: AuditEvent) -> dict[str, Any]:
    return {
        "event_id": str(event.event_id),
        "timestamp": event.timestamp.isoformat(),
        "principal_type": (
            event.principal.type.value if hasattr(
                event.principal.type, "value") else str(event.principal.type)
        ),
        "principal_id": event.principal.id,
        "vserver_name": event.vserver_name,
        "tool": event.tool,
        "decision": (
            event.decision.value if hasattr(event.decision, "value")
            else str(event.decision)
        ),
        "policy_rule_id": event.policy_rule_id,
        "latency_ms_total": event.latency_ms_total,
        "upstream_status": (
            event.upstream_status.value
            if hasattr(event.upstream_status, "value")
            else str(event.upstream_status)
        ),
    }


def _top_denial_reasons(events: Iterable[AuditEvent]) -> dict[str, int]:
    out: dict[str, int] = {}
    for e in events:
        if e.decision != AuditDecision.DENY:
            continue
        reason = e.policy_rule_id or "unknown"
        out[reason] = out.get(reason, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1])[:10])


def _inflight_gate_section(http_request: Request) -> dict[str, Any]:
    """Current per-tenant inflight gate state. The middleware doesn't
    expose direct introspection (intentionally — debugging shouldn't
    perturb production traffic shape), but Settings tells us the cap,
    and the audit ring buffer tells us recent 503 counts."""
    settings = http_request.app.state.settings
    out: dict[str, Any] = {
        "configured_per_tenant_cap": settings.inbound_per_tenant_inflight_limit,
        "configured_uvicorn_concurrency": settings.inbound_limit_concurrency,
        "configured_backlog": settings.inbound_backlog,
    }
    return out


def _persistent_audit_section(
    db: Session, *, tenant_id: UUID, since_minutes: int
) -> dict[str, Any]:
    """Counts and freshness checks for the durable `tool_call_events`
    table (TOOL-EVENTS-1). Distinct from `audit_buffer` above, which
    samples the in-memory hot cache. This section answers: 'is the
    durable store actually receiving writes, and how far back does our
    history go?'"""

    cutoff = datetime.now(UTC) - timedelta(minutes=since_minutes)
    total = db.execute(
        select(text("count(*)"))
        .select_from(ToolCallEvent)
        .where(ToolCallEvent.tenant_id == tenant_id)
    ).scalar() or 0
    in_window = db.execute(
        select(text("count(*)"))
        .select_from(ToolCallEvent)
        .where(
            ToolCallEvent.tenant_id == tenant_id,
            ToolCallEvent.occurred_at >= cutoff,
        )
    ).scalar() or 0
    oldest = db.execute(
        select(ToolCallEvent.occurred_at)
        .where(ToolCallEvent.tenant_id == tenant_id)
        .order_by(ToolCallEvent.occurred_at.asc())
        .limit(1)
    ).scalar()
    newest = db.execute(
        select(ToolCallEvent.occurred_at)
        .where(ToolCallEvent.tenant_id == tenant_id)
        .order_by(ToolCallEvent.occurred_at.desc())
        .limit(1)
    ).scalar()
    by_event_type = dict(
        db.execute(
            select(ToolCallEvent.event_type, text("count(*)"))
            .where(ToolCallEvent.tenant_id == tenant_id)
            .group_by(ToolCallEvent.event_type)
        ).all()
    )
    by_decision = dict(
        db.execute(
            select(ToolCallEvent.decision, text("count(*)"))
            .where(ToolCallEvent.tenant_id == tenant_id)
            .group_by(ToolCallEvent.decision)
        ).all()
    )
    return {
        "available": True,
        "total_events": int(total),
        f"events_last_{since_minutes}min": int(in_window),
        "oldest_event_at": oldest.isoformat() if oldest else None,
        "newest_event_at": newest.isoformat() if newest else None,
        "by_event_type": by_event_type,
        "by_decision": by_decision,
        "note": (
            "Source of truth for the operator-console Events / NHI map / "
            "Identities panels. Survives gateway restarts. The in-memory "
            "buffer in `audit_buffer` above is rehydrated from this table "
            "during lifespan startup."
        ),
    }


def _audit_buffer_warmup_section(http_request: Request) -> dict[str, Any]:
    """Was the in-memory ring buffer rehydrated from Postgres at startup?
    Tells operators whether the dashboard had historical context
    immediately on boot or had to wait for fresh traffic."""

    emitter = getattr(http_request.app.state, "recent_audit_emitter", None)
    if emitter is None:
        return {"available": False, "reason": "no recent_audit_emitter wired"}
    try:
        current_size = len(emitter)
    except TypeError:
        current_size = None
    return {
        "available": True,
        "buffer_current_size": current_size,
        "buffer_max_capacity": getattr(emitter._buffer, "maxlen", None)
            if hasattr(emitter, "_buffer") else None,
        "note": (
            "If buffer_current_size is 0 and total_events in the persistent "
            "section is > 0, the warm-up step skipped. Common cause: tests "
            "emit events through the chain BEFORE entering the test client "
            "context, which short-circuits warm-up. In production this "
            "shouldn't happen — check `audit_buffer_warmup_failed` log lines."
        ),
    }


def _idp_directories_section(
    db: Session, *, tenant_id: UUID
) -> dict[str, Any]:
    """All IdP directories (Entra / Workspace) connected to this tenant.
    Per-directory: last SCIM sync, signin protocol, JIT user count."""

    rows = list(db.execute(
        select(IdpDirectory).where(IdpDirectory.tenant_id == tenant_id)
        .order_by(IdpDirectory.display_name)
    ).scalars())
    directories: list[dict[str, Any]] = []
    for d in rows:
        scim_user_count = db.execute(
            select(text("count(*)"))
            .select_from(User)
            .where(
                User.tenant_id == tenant_id,
                User.idp_directory_id == d.id,
            )
        ).scalar() or 0
        directories.append({
            "id": str(d.id),
            "kind": d.kind.value if hasattr(d.kind, "value") else str(d.kind),
            "display_name": d.display_name,
            "signin_protocol": (
                d.signin_protocol.value if hasattr(d.signin_protocol, "value")
                else str(d.signin_protocol)
            ),
            "last_sync_at": (
                d.last_sync_at.isoformat() if d.last_sync_at else None
            ),
            "users_provisioned": int(scim_user_count),
            "created_at": d.created_at.isoformat(),
        })
    return {
        "total_directories": len(rows),
        "directories": directories,
    }


def _admin_audit_section(
    db: Session, *, tenant_id: UUID, since_minutes: int
) -> dict[str, Any]:
    """Recent admin-action audit rows — `user.disable`, `vserver.delete`,
    `idp.connect`, `scim.deactivate_user`, etc. Distinct from the
    inbound MCP audit above; this captures *what admins did to the
    platform*."""

    cutoff = datetime.now(UTC) - timedelta(minutes=since_minutes)
    in_window = db.execute(
        select(text("count(*)"))
        .select_from(AdminAuditLog)
        .where(
            AdminAuditLog.tenant_id == tenant_id,
            AdminAuditLog.occurred_at >= cutoff,
        )
    ).scalar() or 0
    by_actor = dict(
        db.execute(
            select(AdminAuditLog.actor_kind, text("count(*)"))
            .where(
                AdminAuditLog.tenant_id == tenant_id,
                AdminAuditLog.occurred_at >= cutoff,
            )
            .group_by(AdminAuditLog.actor_kind)
        ).all()
    )
    recent = list(db.execute(
        select(AdminAuditLog)
        .where(AdminAuditLog.tenant_id == tenant_id)
        .order_by(AdminAuditLog.occurred_at.desc())
        .limit(20)
    ).scalars())
    return {
        f"actions_last_{since_minutes}min": int(in_window),
        "by_actor_kind": by_actor,
        "recent_sample": [
            {
                "occurred_at": r.occurred_at.isoformat(),
                "actor_kind": r.actor_kind.value if hasattr(r.actor_kind, "value") else str(r.actor_kind),
                "actor_display": r.actor_display,
                "action": r.action,
                "target_kind": r.target_kind,
                "target_display": r.target_display,
            }
            for r in recent
        ],
    }


def _background_workers_section(http_request: Request) -> dict[str, Any]:
    """Status of every background async worker the gateway runs.

    Today: SCIM hard-delete sweeper (IDP-1), capability sync scheduler
    (M3), audit fan-out async producer (when wired). Operator wants to
    know 'is the cron actually firing?' — if `last_run_at` is hours
    stale, something's wedged."""

    workers: dict[str, Any] = {}

    sweeper = getattr(http_request.app.state, "hard_delete_sweeper", None)
    if sweeper is not None:
        workers["scim_hard_delete_sweeper"] = {
            "running": getattr(sweeper, "_task", None) is not None,
            "interval_seconds": getattr(sweeper, "_interval", None),
            "grace_seconds": getattr(sweeper, "_grace", None),
            "cycles_completed": getattr(sweeper, "_cycle_count", 0),
            "last_swept_count": getattr(sweeper, "_last_swept_count", 0),
        }
    else:
        workers["scim_hard_delete_sweeper"] = {"running": False, "reason": "not wired"}

    sched = getattr(http_request.app.state, "capability_sync_scheduler", None)
    if sched is not None:
        workers["capability_sync_scheduler"] = {
            "running": getattr(sched, "_task", None) is not None,
            "interval_seconds": getattr(sched, "_interval_seconds", None),
            "max_concurrent_per_tenant": getattr(
                sched, "_max_concurrent_per_tenant", None
            ),
        }
    else:
        workers["capability_sync_scheduler"] = {
            "running": False,
            "reason": "VYUU_CAPABILITY_SYNC_ENABLED not set",
        }

    # RETENTION-1. The section reports the configured windows even when
    # retention is off, because "why is this table 400 GB" and "why did
    # March disappear" are both answered by the same three numbers.
    retention = getattr(http_request.app.state, "retention_sweeper", None)
    if retention is not None:
        last = retention.last_report
        workers["audit_retention_sweeper"] = {
            "running": getattr(retention, "_task", None) is not None,
            "enabled": retention.enabled,
            "tool_call_event_retention_days": (
                retention._tool_call_event_retention_days
            ),
            "admin_audit_retention_days": retention._admin_audit_retention_days,
            "interval_seconds": retention._interval,
            "cycles_completed": retention.cycle_count,
            "last_run_at": (
                retention.last_run_at.isoformat()
                if retention.last_run_at else None
            ),
            "last_rows_deleted": dict(last.rows_deleted),
            # True means the backlog exceeded one cycle's cap and more
            # rows are still owed — not that anything failed.
            "last_cycle_hit_cap": last.capped,
        }
    else:
        workers["audit_retention_sweeper"] = {"running": False, "reason": "not wired"}

    return workers


def _stdio_subprocess_section() -> dict[str, Any]:
    """Live count of stdio MCP subprocesses spawned by this gateway.
    Best-effort via `pgrep` against known patterns; reports 'unknown'
    when pgrep isn't available."""
    if not shutil.which("pgrep"):
        return {"available": False, "reason": "pgrep unavailable"}
    patterns = ["mcp-server-time", "drawio-mcp", "falcon-mcp", "VirusTotal"]
    total = 0
    by_pattern: dict[str, int] = {}
    for pat in patterns:
        try:
            out = subprocess.check_output(
                ["pgrep", "-f", pat],
                stderr=subprocess.DEVNULL, timeout=1,
            ).decode().strip()
            n = len([line for line in out.splitlines() if line])
        except Exception:  # noqa: BLE001
            n = 0
        by_pattern[pat] = n
        total += n
    return {
        "available": True,
        "total_count": total,
        "by_pattern": by_pattern,
        "patterns_checked": list(patterns),
    }


# --- Endpoint -------------------------------------------------------------


@router.get("/diagnostic-bundle")
def diagnostic_bundle(
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
    since_minutes: int = 60,
    audit_limit: int = _DEFAULT_AUDIT_LIMIT,
) -> Response:
    """Produce a gateway-wide JSON diagnostic bundle.

    Use cases:
    - "Customer reports 503 on Cursor" → bundle shows inflight-gate
      cap, recent 503 counts, top tenants firing 503s.
    - "DB seems sluggish" → bundle shows pool size, active connection
      count, server version, hostname so you know which DB.
    - "Server X never syncs capabilities" → bundle's servers section
      flags it under `with_sync_issues`.
    - "Random tool calls fail" → bundle's circuit-breaker section
      shows which upstream pool keys are open.

    Bundle includes:
    - `gateway` — process metadata (uptime, RSS, CPU, FDs)
    - `settings_snapshot` — effective config (secrets redacted)
    - `connectivity` — Postgres / Redis / NATS / secret-store reachability
    - `servers` — all MCP servers count + health distribution + errors
    - `vservers` — all vservers count + visibility distribution
    - `circuit_breakers` — open / half-open / closed counts; open keys
    - `inflight_gate` — configured caps; recent 503s via audit buffer
    - `audit_buffer` — recent decisions + denial reasons + sample
    - `stdio_subprocesses` — live count by upstream pattern

    Security: operator-auth required, tenant-scoped, secrets redacted
    via field-name pattern. See module docstring for full posture.
    """
    if since_minutes < 1 or since_minutes > 1440:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="since_minutes must be between 1 and 1440 (24h)",
        )
    if audit_limit < 1 or audit_limit > _MAX_AUDIT_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"audit_limit must be between 1 and {_MAX_AUDIT_LIMIT}",
        )

    bundle = {
        "vyuu_diagnostic_bundle_version": _BUNDLE_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "tenant_id": str(operator.tenant_id),
        "operator_id": str(operator.operator_id),
        "since_minutes": since_minutes,
        "audit_limit": audit_limit,
        "gateway": _gateway_section(http_request),
        "settings_snapshot": _settings_snapshot(http_request),
        "connectivity": _connectivity_section(http_request, db),
        "servers": _servers_section(db, tenant_id=operator.tenant_id),
        "vservers": _vservers_section(db, tenant_id=operator.tenant_id),
        "idp_directories": _idp_directories_section(
            db, tenant_id=operator.tenant_id
        ),
        "circuit_breakers": _circuit_breaker_section(http_request),
        "inflight_gate": _inflight_gate_section(http_request),
        "background_workers": _background_workers_section(http_request),
        "stdio_subprocesses": _stdio_subprocess_section(),
        # Inbound MCP audit — both surfaces. The hot ring buffer tells
        # you what's currently live; the persistent table tells you what
        # actually survives a restart. Together they pinpoint warm-up
        # gaps and write-path failures.
        "audit_buffer": _audit_buffer_section(
            http_request,
            tenant_id=operator.tenant_id,
            since_minutes=since_minutes,
            limit=audit_limit,
        ),
        "audit_buffer_warmup": _audit_buffer_warmup_section(http_request),
        "persistent_audit": _persistent_audit_section(
            db, tenant_id=operator.tenant_id, since_minutes=since_minutes
        ),
        # Admin-action audit — what operators / SCIM / cron did to the
        # platform. Distinct retention, distinct read pattern.
        "admin_audit": _admin_audit_section(
            db, tenant_id=operator.tenant_id, since_minutes=since_minutes
        ),
    }

    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    settings = http_request.app.state.settings
    env_slug = "".join(
        ch if ch.isalnum() or ch in "-_" else "-"
        for ch in (settings.environment or "env")
    )[:24]
    filename = f"vyuu-diagnostic-{env_slug}-{ts}.json"
    body = json.dumps(bundle, indent=2, default=str).encode("utf-8")
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
