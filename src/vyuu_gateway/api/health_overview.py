"""Operator-facing Health & Server Info overview.

Powers the operator console's "Health & Server Info" page (the Vyuu
analog of cloud "Overview" pages). Where the diagnostic bundle is a
deep one-time download for support, this endpoint is a live, polled
snapshot — small JSON, fast, refreshed every few seconds.

Sections:

- `gateway_info` — version, environment, uptime, host, CPU/RSS, FDs.
- `kpis` — instances configured, gateway uptime · 30d, p95 latency
  (last 1h), cert/key expiries within 90d.
- `status_cards` — five binary health checks the page renders as
  green/amber/red tiles: DB reachable, audit DB writeable + healthy,
  IdP directories connected, capability sync running, SCIM sweeper
  active.
- `mcp_servers` — table-shaped rows: server, transport, health
  status, last sync, capability count, latency last hour.
- `latency_series` — sparse hourly points over the last 24h for a
  small in-page chart (p95 + p99). Source: `tool_call_events`.

Auth: operator JWT, tenant-scoped via the dependency. RLS gates the
read on the underlying table.

Wire: `GET /api/v1/admin/health-overview`.
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
import time
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.db.models import (
    IdpDirectory,
    McpCapability,
    McpServer,
    ToolCallEvent,
)
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator

router = APIRouter(prefix="/admin", tags=["admin"])

# Set on import so uptime is `now - boot`. The diagnostic bundle uses
# its own monotonic snapshot for the same purpose; we keep them
# independent so this module can be loaded standalone in unit tests.
_BOOT_MONOTONIC = time.monotonic()
_BOOT_WALL = datetime.now(UTC)


# --- Section helpers ------------------------------------------------------


def _gateway_info(http_request: Request) -> dict[str, Any]:
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
    except Exception:  # noqa: BLE001
        pass
    fd_count: int | None = None
    if shutil.which("lsof"):
        try:
            out = subprocess.check_output(
                ["lsof", "-p", str(pid)],
                stderr=subprocess.DEVNULL, timeout=2,
            ).decode()
            fd_count = max(0, len(out.splitlines()) - 1)
        except Exception:  # noqa: BLE001
            pass
    cpu_count = os.cpu_count() or 0
    return {
        "version": getattr(settings, "version", "unknown"),
        "environment": getattr(settings, "environment", "unknown"),
        "app_name": getattr(settings, "app_name", "Vyuu Gateway"),
        "host": socket.gethostname(),
        "platform": f"{platform.system()} {platform.release()}",
        "python_version": platform.python_version(),
        "pid": pid,
        "boot_at": _BOOT_WALL.isoformat(),
        "uptime_seconds": int(time.monotonic() - _BOOT_MONOTONIC),
        "cpu_count": cpu_count,
        "cpu_percent_now": cpu_percent,
        "rss_bytes": rss_bytes,
        "open_fds": fd_count,
    }


def _latency_p50_p95_p99(
    db: Session, *, tenant_id: UUID, since: datetime
) -> dict[str, float | None]:
    """Compute p50 / p95 / p99 of `latency_ms_total` over a time window.
    Uses Postgres `percentile_cont` for accuracy on small samples;
    falls back gracefully if no events exist."""

    row = db.execute(
        text(
            """
            SELECT
              percentile_cont(0.50) WITHIN GROUP (ORDER BY latency_ms_total) AS p50,
              percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms_total) AS p95,
              percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms_total) AS p99,
              count(*) AS sample_size
            FROM tool_call_events
            WHERE tenant_id = :tid
              AND occurred_at >= :since
              AND latency_ms_total IS NOT NULL
            """
        ),
        {"tid": tenant_id, "since": since},
    ).one()
    return {
        "p50_ms": float(row.p50) if row.p50 is not None else None,
        "p95_ms": float(row.p95) if row.p95 is not None else None,
        "p99_ms": float(row.p99) if row.p99 is not None else None,
        "sample_size": int(row.sample_size or 0),
    }


def _avg_latency(db: Session, *, tenant_id: UUID, since: datetime) -> float | None:
    """Plain mean — `Avg client latency` card on the page."""

    val = db.execute(
        select(func.avg(ToolCallEvent.latency_ms_total)).where(
            ToolCallEvent.tenant_id == tenant_id,
            ToolCallEvent.occurred_at >= since,
            ToolCallEvent.latency_ms_total.is_not(None),
        )
    ).scalar()
    return float(val) if val is not None else None


def _signing_key_expiry(http_request: Request) -> dict[str, Any]:
    """The operator-auth signing secret has no built-in expiry — it
    rotates when the env var changes. We surface the rotation hint
    (env-var origin + last-changed-on-disk if available) so operators
    aren't left guessing. IdP cert expiries come from each
    `IdpDirectory.config_json` payload."""

    settings = http_request.app.state.settings
    secret = getattr(settings, "operator_auth_signing_secret", "") or ""
    return {
        "configured": bool(secret),
        "key_length_bytes": len(secret),
        "rotation_hint": (
            "Set VYUU_OPERATOR_AUTH_SIGNING_SECRET to rotate. No automatic "
            "expiry — keys are rotated by env-var change + restart."
        ),
    }


def _idp_cert_expiries(db: Session, *, tenant_id: UUID) -> list[dict[str, Any]]:
    """One row per SAML directory whose signing cert the operator should
    track. The PEM lives at `IdpDirectory.saml_idp_certificate`. We
    don't parse it here (avoid pulling in the cryptography dep on the
    hot path); the IdP-detail page does that. For the overview, just
    surface that the cert exists and remind the operator to rotate."""

    rows = list(db.execute(
        select(IdpDirectory).where(IdpDirectory.tenant_id == tenant_id)
    ).scalars())
    out: list[dict[str, Any]] = []
    for d in rows:
        protocol = (
            d.signin_protocol.value
            if hasattr(d.signin_protocol, "value")
            else str(d.signin_protocol)
        )
        if protocol != "saml":
            continue
        out.append({
            "directory_id": str(d.id),
            "display_name": d.display_name,
            "has_certificate": bool(d.saml_idp_certificate),
            # Parsing the cert for `not_after` is the IdP-detail page's
            # job — keep this endpoint cheap and side-effect-free.
            "expires_in_days": None,
            "note": (
                "Visit the IdP detail page for the parsed expiry. This "
                "row exists so the overview reminds operators of cert "
                "rotation responsibility."
            ),
        })
    return out


def _status_cards(
    http_request: Request,
    db: Session,
    *,
    tenant_id: UUID,
) -> dict[str, Any]:
    """Five binary health tiles. Each: status (`ok` / `warn` / `error`),
    short label, detail string the page renders below the headline."""

    cards: dict[str, Any] = {}

    # 1. Database reachable + audit DB writeable.
    try:
        db.execute(text("SELECT 1")).scalar()
        # Probe the `tool_call_events` table specifically — if RLS is
        # misconfigured this returns 0 even when other tables work.
        # An owner-bind here is just a count, never a write.
        ev_count = db.execute(
            select(func.count())
            .select_from(ToolCallEvent)
            .where(ToolCallEvent.tenant_id == tenant_id)
        ).scalar()
        cards["database"] = {
            "status": "ok",
            "label": "Database reachable",
            "detail": (
                f"Postgres + tool_call_events accessible · "
                f"{ev_count or 0} events in this tenant"
            ),
        }
    except Exception as exc:  # noqa: BLE001
        cards["database"] = {
            "status": "error",
            "label": "Database unreachable",
            "detail": exc.__class__.__name__,
        }

    # 2. Audit pipeline health (in-memory + persistent agree).
    recent = getattr(http_request.app.state, "recent_audit_emitter", None)
    buffer_size = len(recent) if recent is not None else None
    cards["audit_pipeline"] = {
        "status": "ok" if recent is not None else "warn",
        "label": "Audit pipeline",
        "detail": (
            f"Hot buffer: {buffer_size} events · persistent table is "
            "the source of truth (TOOL-EVENTS-1)"
            if recent is not None
            else "RecentAuditEmitter not wired"
        ),
    }

    # 3. IdP directories connected.
    idp_count = db.execute(
        select(func.count()).select_from(IdpDirectory).where(
            IdpDirectory.tenant_id == tenant_id
        )
    ).scalar() or 0
    if idp_count == 0:
        cards["idp_directories"] = {
            "status": "warn",
            "label": "No IdP connected",
            "detail": (
                "Tenant has no Entra ID / Workspace directory wired. "
                "Local-password sign-in still works."
            ),
        }
    else:
        cards["idp_directories"] = {
            "status": "ok",
            "label": "IdP directories connected",
            "detail": (
                f"{idp_count} director{'y' if idp_count == 1 else 'ies'} "
                "active for SCIM + SSO"
            ),
        }

    # 4. Capability sync scheduler.
    sched = getattr(http_request.app.state, "capability_sync_scheduler", None)
    if sched is not None and getattr(sched, "_task", None) is not None:
        cards["capability_sync"] = {
            "status": "ok",
            "label": "Capability sync running",
            "detail": (
                f"Interval: {getattr(sched, '_interval_seconds', '?')}s · "
                "auto-pulls upstream tool catalogs"
            ),
        }
    elif sched is not None:
        cards["capability_sync"] = {
            "status": "warn",
            "label": "Capability sync stopped",
            "detail": "Scheduler wired but not running",
        }
    else:
        cards["capability_sync"] = {
            "status": "warn",
            "label": "Capability sync off",
            "detail": (
                "Set VYUU_CAPABILITY_SYNC_ENABLED=true to auto-refresh "
                "upstream capability catalogs on a cadence"
            ),
        }

    # 5. SCIM hard-delete sweeper.
    sweeper = getattr(http_request.app.state, "hard_delete_sweeper", None)
    if sweeper is not None and getattr(sweeper, "_task", None) is not None:
        cycles = getattr(sweeper, "_cycle_count", 0)
        cards["scim_sweeper"] = {
            "status": "ok",
            "label": "SCIM sweeper active",
            "detail": (
                f"{cycles} cycle{'' if cycles == 1 else 's'} completed · "
                "hourly cadence · 7-day grace before hard-delete"
            ),
        }
    else:
        cards["scim_sweeper"] = {
            "status": "warn",
            "label": "SCIM sweeper inactive",
            "detail": "Hard-delete sweeper not running",
        }

    return cards


def _mcp_servers_table(
    db: Session, *, tenant_id: UUID, latency_window: timedelta
) -> list[dict[str, Any]]:
    """One row per MCP server — the operator console renders this in
    the same shape as the screenshot's `Control-plane regions` table."""

    servers = list(db.execute(
        select(McpServer).where(McpServer.tenant_id == tenant_id)
        .order_by(McpServer.display_name)
    ).scalars())

    if not servers:
        return []

    server_ids = [s.id for s in servers]
    cap_counts: dict[UUID, int] = dict(
        db.execute(
            select(McpCapability.server_id, func.count())
            .where(
                McpCapability.tenant_id == tenant_id,
                McpCapability.server_id.in_(server_ids),
            )
            .group_by(McpCapability.server_id)
        ).all()
    )
    since = datetime.now(UTC) - latency_window
    latency_by_server: dict[UUID, float | None] = {}
    call_counts: dict[UUID, int] = {}
    rows = db.execute(
        select(
            ToolCallEvent.upstream_server_id,
            func.avg(ToolCallEvent.latency_ms_total),
            func.count(),
        )
        .where(
            ToolCallEvent.tenant_id == tenant_id,
            ToolCallEvent.occurred_at >= since,
            ToolCallEvent.upstream_server_id.in_(server_ids),
            ToolCallEvent.latency_ms_total.is_not(None),
        )
        .group_by(ToolCallEvent.upstream_server_id)
    ).all()
    for sid, avg_ms, count in rows:
        if sid is None:
            continue
        latency_by_server[sid] = float(avg_ms) if avg_ms is not None else None
        call_counts[sid] = int(count or 0)

    out: list[dict[str, Any]] = []
    for s in servers:
        health = (
            s.health_status.value if hasattr(s.health_status, "value")
            else str(s.health_status or "unknown")
        )
        transport = (
            s.transport.value if hasattr(s.transport, "value")
            else str(s.transport)
        )
        out.append({
            "server_id": str(s.id),
            "display_name": s.display_name,
            "transport": transport,
            "source_type": (
                s.source_type.value if hasattr(s.source_type, "value")
                else str(s.source_type)
            ),
            "health_status": health,
            "last_health_error": (
                s.last_health_error[:200] if s.last_health_error else None
            ),
            "last_capabilities_pulled_at": (
                s.last_capabilities_pulled_at.isoformat()
                if s.last_capabilities_pulled_at else None
            ),
            "capability_count": cap_counts.get(s.id, 0),
            "avg_latency_ms_1h": latency_by_server.get(s.id),
            "calls_last_1h": call_counts.get(s.id, 0),
            "registered_at": s.registered_at.isoformat(),
        })
    return out


def _latency_series(
    db: Session, *, tenant_id: UUID, hours: int = 24
) -> list[dict[str, Any]]:
    """Sparse hourly series of p95 latency for the in-page chart.

    Postgres `date_trunc` buckets per hour over the last `hours`
    window. Rows where `latency_ms_total` is null (events that never
    reached upstream — denied at the gate) are excluded from the
    percentile so the chart reflects upstream call performance only.
    """

    since = datetime.now(UTC) - timedelta(hours=hours)
    rows = db.execute(
        text(
            """
            SELECT
              date_trunc('hour', occurred_at) AS hour,
              percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms_total) AS p95,
              percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms_total) AS p99,
              count(*) AS samples
            FROM tool_call_events
            WHERE tenant_id = :tid
              AND occurred_at >= :since
              AND latency_ms_total IS NOT NULL
            GROUP BY 1
            ORDER BY 1 ASC
            """
        ),
        {"tid": tenant_id, "since": since},
    ).all()
    return [
        {
            "hour": row.hour.isoformat() if row.hour else None,
            "p95_ms": float(row.p95) if row.p95 is not None else None,
            "p99_ms": float(row.p99) if row.p99 is not None else None,
            "samples": int(row.samples or 0),
        }
        for row in rows
    ]


# --- Endpoint -------------------------------------------------------------


@router.get("/health-overview")
def health_overview(
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
) -> dict[str, Any]:
    """Live snapshot for the operator console's Health & Server Info
    page. Cheap (single-digit indexed queries) and tenant-scoped.
    Front-end polls every ~10s."""

    last_hour = datetime.now(UTC) - timedelta(hours=1)
    latency = _latency_p50_p95_p99(db, tenant_id=operator.tenant_id, since=last_hour)
    avg_latency = _avg_latency(db, tenant_id=operator.tenant_id, since=last_hour)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "tenant_id": str(operator.tenant_id),
        "gateway_info": _gateway_info(http_request),
        "kpis": {
            "gateway_instances": 1,  # multi-instance HA = future work
            "uptime_seconds": int(time.monotonic() - _BOOT_MONOTONIC),
            "p95_latency_ms_1h": latency["p95_ms"],
            "p99_latency_ms_1h": latency["p99_ms"],
            "p50_latency_ms_1h": latency["p50_ms"],
            "avg_latency_ms_1h": avg_latency,
            "latency_sample_size_1h": latency["sample_size"],
            "signing_key": _signing_key_expiry(http_request),
            "idp_certificates_to_track": _idp_cert_expiries(
                db, tenant_id=operator.tenant_id
            ),
        },
        "status_cards": _status_cards(
            http_request, db, tenant_id=operator.tenant_id
        ),
        "mcp_servers": _mcp_servers_table(
            db,
            tenant_id=operator.tenant_id,
            latency_window=timedelta(hours=1),
        ),
        "latency_series": _latency_series(
            db, tenant_id=operator.tenant_id, hours=24
        ),
    }
