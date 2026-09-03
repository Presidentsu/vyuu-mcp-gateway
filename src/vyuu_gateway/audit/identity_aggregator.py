"""Aggregate recent audit events by principal for the NHI dashboard.

The operator console's "Identities" panel needs to know, for every
distinct principal seen in the last N audit events: total call
volume, which vservers + upstreams they touched, when they were last
seen, and how many of their actions were high-privileged.

This module is the in-memory aggregation layer over `RecentAuditEmitter`.
It deliberately does NOT hit the DB on the hot path — the audit
ring buffer holds everything we need, and joining against
`mcp_capabilities` for per-tool risk classification is done once per
request via a small `(server_id, tool_name) -> RiskCategory` lookup
the caller hands in.

Why split this out: the same aggregation logic is reused by N2's
graph layer (`identity_graph.py`) when computing per-principal
activity summaries. Keeping it pure (no DB / no FastAPI) makes both
test paths cheap and avoids fragmentation.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from vyuu_gateway.audit.events import (
    AuditDecision,
    AuditEvent,
    AuditEventType,
    AuditPrincipalType,
)
from vyuu_gateway.db.models import RiskCategory

# The "high-privileged" buckets — actions that move data, mutate state
# at scale, or grant cross-system reach. The dashboard surfaces these
# as a separate counter so operators can spot identities that don't
# look like simple read-only readers. `UNKNOWN` is conservatively
# excluded — surfacing every unclassified tool as "high-risk" would
# train operators to ignore the signal.
_HIGH_RISK_CATEGORIES: frozenset[RiskCategory] = frozenset(
    {
        RiskCategory.DELETE,
        RiskCategory.EXECUTE,
        RiskCategory.CREDENTIAL_ACCESS,
        RiskCategory.DATA_EXPORT,
        RiskCategory.ADMIN,
    }
)


@dataclass(frozen=True)
class IdentitySummary:
    """One row in the Identities dashboard.

    `principal_id` is the natural identity (an API key id for NHIs,
    a UUID for OIDC-authed users, an opaque session id for the lab's
    fake provider). `principal_type` lets the UI render different
    icons / styling per identity flavour.

    The `latest_client_*` fields record the MCP `clientInfo` from the
    most-recent event for this principal — answering "via what
    interface did this identity make their last call?" (Cursor,
    Claude Desktop, mcp-remote, custom SDK). `distinct_clients`
    captures every unique interface seen across the window — useful
    for spotting an identity that's been driven by multiple clients.
    """

    principal_id: str
    principal_type: AuditPrincipalType
    principal_display: str
    total_calls: int
    allowed_calls: int
    denied_calls: int
    upstream_error_calls: int
    distinct_vservers: int
    distinct_upstreams: int
    distinct_tools: int
    high_risk_calls: int
    last_seen: datetime
    first_seen: datetime
    # Per-risk-category histogram. Lets the UI render a small stacked
    # bar without re-walking events.
    risk_histogram: dict[str, int] = field(default_factory=dict)
    # MCP `clientInfo.name` from the most-recent event. Falls back to
    # `None` for identities that never sent `clientInfo` (raw curl,
    # custom scripts).
    latest_client_name: str | None = None
    latest_client_version: str | None = None
    # HTTP `User-Agent` from the most-recent event. Useful when
    # `clientInfo` is missing — UA still pins down most known clients.
    latest_user_agent: str | None = None
    # Set of distinct `clientInfo.name` values seen for this identity.
    # Order is insertion-order (newest first via `[name, ...]` dedup).
    distinct_clients: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class _Mutable:
    """Working scratch state per principal during aggregation. Frozen
    to enforce that callers don't mutate it externally — internal code
    rebuilds it via `dataclasses.replace`."""

    principal_id: str
    principal_type: AuditPrincipalType
    principal_display: str
    total_calls: int
    allowed_calls: int
    denied_calls: int
    upstream_error_calls: int
    vservers: frozenset[UUID]
    upstreams: frozenset[UUID]
    tools: frozenset[str]
    high_risk_calls: int
    last_seen: datetime
    first_seen: datetime
    risk_histogram: dict[str, int]
    latest_client_name: str | None
    latest_client_version: str | None
    latest_user_agent: str | None
    distinct_clients: tuple[str, ...]


def summarize_identities(
    events: Iterable[AuditEvent],
    *,
    risk_lookup: Mapping[tuple[UUID, str], RiskCategory] | None = None,
) -> list[IdentitySummary]:
    """Group events by `principal.id`, return one summary per identity.

    Only `event_type=tool_call` events count toward the aggregation —
    `access_attempt` events (connection-level rejections) are
    surfaced separately in the dashboard's "Failed access" feed.
    Including them here would conflate a successful tool call with a
    bouncer kicking someone at the door.

    `risk_lookup` is `(upstream_server_id, tool_name) -> RiskCategory`.
    Callers build it from `mcp_capabilities` on the request. When a
    pair is missing (capability not yet synced, deleted, or different
    tenant) we treat the call as `UNKNOWN` — neither inflated to
    high-risk nor dropped entirely.
    """

    risk_lookup = risk_lookup or {}
    by_principal: dict[str, _Mutable] = {}

    for event in events:
        if event.event_type != AuditEventType.TOOL_CALL:
            continue
        pid = event.principal.id
        risk = (
            risk_lookup.get((event.upstream_server_id, event.tool))
            if event.upstream_server_id is not None
            else None
        ) or RiskCategory.UNKNOWN
        is_high = risk in _HIGH_RISK_CATEGORIES

        client_name = event.client_metadata.agent_type or None
        existing = by_principal.get(pid)
        if existing is None:
            histogram: dict[str, int] = {risk.value: 1}
            by_principal[pid] = _Mutable(
                principal_id=pid,
                principal_type=event.principal.type,
                principal_display=event.principal.display,
                total_calls=1,
                allowed_calls=1 if event.decision == AuditDecision.ALLOW else 0,
                denied_calls=1 if event.decision == AuditDecision.DENY else 0,
                upstream_error_calls=(
                    1 if _is_upstream_error(event) else 0
                ),
                vservers=frozenset(
                    {event.vserver_id} if event.vserver_id else set()
                ),
                upstreams=frozenset(
                    {event.upstream_server_id}
                    if event.upstream_server_id
                    else set()
                ),
                tools=frozenset({event.tool}),
                high_risk_calls=1 if is_high else 0,
                last_seen=event.timestamp,
                first_seen=event.timestamp,
                risk_histogram=histogram,
                latest_client_name=client_name,
                latest_client_version=event.client_metadata.client_version or None,
                latest_user_agent=event.client_metadata.user_agent or None,
                distinct_clients=(client_name,) if client_name else (),
            )
            continue

        new_histogram = dict(existing.risk_histogram)
        new_histogram[risk.value] = new_histogram.get(risk.value, 0) + 1
        new_vservers = (
            existing.vservers | {event.vserver_id}
            if event.vserver_id
            else existing.vservers
        )
        new_upstreams = (
            existing.upstreams | {event.upstream_server_id}
            if event.upstream_server_id
            else existing.upstreams
        )
        # Latest-wins for `client_*` — only overwrite when the incoming
        # event is strictly newer than what we've already recorded.
        # (Events can arrive out-of-order from the ring buffer.)
        is_newer = event.timestamp >= existing.last_seen
        latest_client_name = (
            client_name if (is_newer and client_name) else existing.latest_client_name
        )
        latest_client_version = (
            (event.client_metadata.client_version or None)
            if is_newer and event.client_metadata.client_version
            else existing.latest_client_version
        )
        latest_user_agent = (
            (event.client_metadata.user_agent or None)
            if is_newer and event.client_metadata.user_agent
            else existing.latest_user_agent
        )
        if client_name and client_name not in existing.distinct_clients:
            distinct_clients = existing.distinct_clients + (client_name,)
        else:
            distinct_clients = existing.distinct_clients
        by_principal[pid] = _Mutable(
            principal_id=existing.principal_id,
            # If a more-recent event has a richer display, prefer it —
            # API-key principals get a label after the first call only
            # in some configurations.
            principal_type=existing.principal_type,
            principal_display=(
                event.principal.display
                if event.principal.display
                else existing.principal_display
            ),
            total_calls=existing.total_calls + 1,
            allowed_calls=(
                existing.allowed_calls
                + (1 if event.decision == AuditDecision.ALLOW else 0)
            ),
            denied_calls=(
                existing.denied_calls
                + (1 if event.decision == AuditDecision.DENY else 0)
            ),
            upstream_error_calls=(
                existing.upstream_error_calls
                + (1 if _is_upstream_error(event) else 0)
            ),
            vservers=new_vservers,
            upstreams=new_upstreams,
            tools=existing.tools | {event.tool},
            high_risk_calls=existing.high_risk_calls + (1 if is_high else 0),
            # `events` may arrive in any order (the ring buffer hands
            # them newest-first). Track min/max explicitly.
            last_seen=max(existing.last_seen, event.timestamp),
            first_seen=min(existing.first_seen, event.timestamp),
            risk_histogram=new_histogram,
            latest_client_name=latest_client_name,
            latest_client_version=latest_client_version,
            latest_user_agent=latest_user_agent,
            distinct_clients=distinct_clients,
        )

    summaries = [
        IdentitySummary(
            principal_id=m.principal_id,
            principal_type=m.principal_type,
            principal_display=m.principal_display,
            total_calls=m.total_calls,
            allowed_calls=m.allowed_calls,
            denied_calls=m.denied_calls,
            upstream_error_calls=m.upstream_error_calls,
            distinct_vservers=len(m.vservers),
            distinct_upstreams=len(m.upstreams),
            distinct_tools=len(m.tools),
            high_risk_calls=m.high_risk_calls,
            last_seen=m.last_seen,
            first_seen=m.first_seen,
            risk_histogram=m.risk_histogram,
            latest_client_name=m.latest_client_name,
            latest_client_version=m.latest_client_version,
            latest_user_agent=m.latest_user_agent,
            distinct_clients=m.distinct_clients,
        )
        for m in by_principal.values()
    ]
    # Newest-active identities first — that's the most-likely thing
    # the operator wants to see.
    summaries.sort(key=lambda s: s.last_seen, reverse=True)
    return summaries


def _is_upstream_error(event: AuditEvent) -> bool:
    """An audit event with `decision=allow` but a non-`ok` upstream
    status counts as an error from the identity's perspective — the
    gateway said yes, but the upstream broke. Useful signal: an
    identity with many `upstream_error_calls` may be hitting an
    expired credential or a misconfigured upstream."""

    from vyuu_gateway.audit.events import UpstreamStatus

    return (
        event.decision == AuditDecision.ALLOW
        and event.upstream_status not in (UpstreamStatus.OK, UpstreamStatus.NOT_CALLED)
    )
