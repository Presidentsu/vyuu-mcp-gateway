"""Unit tests for the NHI identity aggregator (N1).

Pure-function tests over `summarize_identities`. No DB, no network —
just verifies the per-principal accumulators (call counts, distinct
vservers/upstreams/tools, last-seen, risk histogram) line up with
the events fed in.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from vyuu_gateway.audit.events import (
    AuditDecision,
    AuditDecisionMode,
    AuditPrincipal,
    AuditPrincipalType,
    UpstreamStatus,
    create_tool_call_audit_event,
)
from vyuu_gateway.audit.identity_aggregator import summarize_identities
from vyuu_gateway.db.models import RiskCategory


def _event(
    *,
    tenant_id: UUID,
    principal_id: str = "p-1",
    principal_type: AuditPrincipalType = AuditPrincipalType.API_KEY,
    principal_display: str = "",
    tool: str = "search",
    upstream_server_id: UUID | None = None,
    vserver_id: UUID | None = None,
    decision: AuditDecision = AuditDecision.ALLOW,
    upstream_status: UpstreamStatus = UpstreamStatus.OK,
    timestamp: datetime | None = None,
    **kw: Any,
) -> Any:
    """Helper — wraps `create_tool_call_audit_event` with our test
    defaults. Returns an `AuditEvent`."""

    event = create_tool_call_audit_event(
        tenant_id=tenant_id,
        gateway_instance_id="g",
        principal=AuditPrincipal(
            type=principal_type, id=principal_id, display=principal_display
        ),
        tool=tool,
        arguments={},
        decision=decision,
        decision_mode=AuditDecisionMode.ENFORCE,
        upstream_status=upstream_status,
        vserver_id=vserver_id,
        upstream_server_id=upstream_server_id,
        **kw,
    )
    if timestamp is not None:
        # AuditEvent is frozen; rebuild via model_copy.
        event = event.model_copy(update={"timestamp": timestamp})
    return event


def test_summarize_groups_calls_by_principal_id() -> None:
    tenant = uuid4()
    events = [
        _event(tenant_id=tenant, principal_id="alice", tool="search"),
        _event(tenant_id=tenant, principal_id="alice", tool="get"),
        _event(tenant_id=tenant, principal_id="bob", tool="search"),
    ]

    summaries = summarize_identities(events)

    by_id = {s.principal_id: s for s in summaries}
    assert by_id["alice"].total_calls == 2
    assert by_id["alice"].distinct_tools == 2
    assert by_id["bob"].total_calls == 1


def test_summarize_counts_distinct_vservers_and_upstreams() -> None:
    tenant = uuid4()
    vs_a, vs_b = uuid4(), uuid4()
    up_a, up_b = uuid4(), uuid4()
    events = [
        _event(tenant_id=tenant, vserver_id=vs_a, upstream_server_id=up_a),
        _event(tenant_id=tenant, vserver_id=vs_a, upstream_server_id=up_b),
        _event(tenant_id=tenant, vserver_id=vs_b, upstream_server_id=up_a),
    ]

    summaries = summarize_identities(events)

    assert summaries[0].distinct_vservers == 2
    assert summaries[0].distinct_upstreams == 2


def test_summarize_classifies_high_risk_actions() -> None:
    """admin / delete / credential_access / data_export / execute count
    as high-risk; read / write / network / unknown do not. The
    histogram captures every category seen so the UI can render a
    breakdown."""

    tenant = uuid4()
    server = uuid4()
    events = [
        _event(tenant_id=tenant, tool="read_file", upstream_server_id=server),
        _event(tenant_id=tenant, tool="delete_repo", upstream_server_id=server),
        _event(tenant_id=tenant, tool="export_data", upstream_server_id=server),
        _event(tenant_id=tenant, tool="grant_admin", upstream_server_id=server),
        _event(tenant_id=tenant, tool="net_call", upstream_server_id=server),
    ]
    risk_lookup = {
        (server, "read_file"): RiskCategory.READ,
        (server, "delete_repo"): RiskCategory.DELETE,
        (server, "export_data"): RiskCategory.DATA_EXPORT,
        (server, "grant_admin"): RiskCategory.ADMIN,
        (server, "net_call"): RiskCategory.NETWORK,
    }

    summaries = summarize_identities(events, risk_lookup=risk_lookup)

    assert summaries[0].high_risk_calls == 3  # delete + data_export + admin
    assert summaries[0].risk_histogram["read"] == 1
    assert summaries[0].risk_histogram["delete"] == 1
    assert summaries[0].risk_histogram["network"] == 1
    assert summaries[0].risk_histogram["admin"] == 1


def test_summarize_unknown_when_capability_not_synced() -> None:
    """A tool call whose (server_id, tool_name) isn't in the lookup
    must count as `unknown` — neither inflated to high-risk nor
    silently dropped."""

    tenant = uuid4()
    events = [
        _event(tenant_id=tenant, tool="freshly_introduced", upstream_server_id=uuid4()),
    ]

    summaries = summarize_identities(events, risk_lookup={})

    assert summaries[0].risk_histogram["unknown"] == 1
    assert summaries[0].high_risk_calls == 0


def test_summarize_first_and_last_seen_track_min_max() -> None:
    """The ring buffer hands events newest-first, but the aggregator
    must produce stable first/last seen regardless of arrival order."""

    tenant = uuid4()
    base = datetime.now(UTC)
    events = [
        _event(tenant_id=tenant, timestamp=base, principal_id="alice"),
        _event(
            tenant_id=tenant,
            timestamp=base - timedelta(minutes=10),
            principal_id="alice",
        ),
        _event(
            tenant_id=tenant,
            timestamp=base + timedelta(minutes=5),
            principal_id="alice",
        ),
    ]

    summary = summarize_identities(events)[0]

    assert summary.first_seen == base - timedelta(minutes=10)
    assert summary.last_seen == base + timedelta(minutes=5)


def test_summarize_counts_decisions_separately() -> None:
    tenant = uuid4()
    events = [
        _event(tenant_id=tenant, decision=AuditDecision.ALLOW),
        _event(tenant_id=tenant, decision=AuditDecision.ALLOW),
        _event(tenant_id=tenant, decision=AuditDecision.DENY),
    ]

    summary = summarize_identities(events)[0]

    assert summary.allowed_calls == 2
    assert summary.denied_calls == 1


def test_summarize_counts_upstream_errors_for_allowed_calls() -> None:
    """Upstream errors (200 from gateway, ERROR from upstream) are a
    distinct signal — surfaces stale credentials / broken upstreams."""

    tenant = uuid4()
    events = [
        _event(tenant_id=tenant, upstream_status=UpstreamStatus.OK),
        _event(tenant_id=tenant, upstream_status=UpstreamStatus.ERROR),
        _event(tenant_id=tenant, upstream_status=UpstreamStatus.TIMEOUT),
        # NOT_CALLED is a clean "we didn't try" — not an error.
        _event(tenant_id=tenant, upstream_status=UpstreamStatus.NOT_CALLED),
    ]

    summary = summarize_identities(events)[0]

    assert summary.upstream_error_calls == 2  # ERROR + TIMEOUT
    assert summary.total_calls == 4


def test_summarize_sorts_newest_active_first() -> None:
    """Operators want to see who's actively making calls — newest
    `last_seen` floats to the top."""

    tenant = uuid4()
    base = datetime.now(UTC)
    events = [
        _event(tenant_id=tenant, principal_id="stale", timestamp=base - timedelta(hours=1)),
        _event(tenant_id=tenant, principal_id="recent", timestamp=base),
        _event(tenant_id=tenant, principal_id="middle", timestamp=base - timedelta(minutes=15)),
    ]

    summaries = summarize_identities(events)

    assert [s.principal_id for s in summaries] == ["recent", "middle", "stale"]


def test_summarize_returns_empty_for_no_events() -> None:
    assert summarize_identities([]) == []
