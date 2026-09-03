"""Persistent tool-call events table

Revision ID: 20260505_0015
Revises: 20260504_0014
Create Date: 2026-05-05

TOOL-EVENTS-1 — make the operator-console Events / NHI map / Identities
panels survive gateway restarts. Today they read from an in-memory ring
buffer (`RecentAuditEmitter`) that resets to empty whenever the gateway
process restarts, so a deploy / upgrade / crash blanks the dashboards
until fresh traffic comes in. That fails a basic security-product bar:
operators expect to log back in after a maintenance window and still
see history.

This migration adds `tool_call_events`, the durable source of truth.
The audit pipeline writes here synchronously on every emit; the in-
memory buffer becomes a hot read-cache rehydrated from the table on
startup. Endpoints that previously queried the buffer now query the
table with proper time-window filters, paginated.

Schema notes:
- `event_id` is the PK (matches `AuditEvent.event_id` from the in-memory
  shape). Letting the audit pipeline mint it means the same id is
  visible in the buffer, the table, and any downstream Kafka/NATS sink.
- FKs to `virtual_servers` / `mcp_servers` use ON DELETE SET NULL —
  events outlive their referenced entities for forensic reasons.
  `vserver_name` is denormalised at write-time so a row stays
  human-readable after the FK target disappears.
- RLS is enabled + forced (same posture as `admin_audit_log` /
  `oauth_user_tokens`). Reads + writes both gated on
  `app.current_tenant_id`.
- Indexes cover the four hot queries: tenant feed, vserver drill-in,
  identity timeline, event-type filter — each a composite ordered by
  `occurred_at` so the planner walks the index backwards for "newest
  first" without an extra sort step.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260505_0015"
down_revision: str | None = "20260504_0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tool_call_events",
        sa.Column("event_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("gateway_instance_id", sa.Text(), nullable=False),
        sa.Column(
            "event_type",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'tool_call'"),
        ),
        # SET NULL — events outlive their referent. The vserver may be
        # deleted in the future; the audit row should still be readable
        # via `vserver_name` (denormalised below).
        sa.Column(
            "vserver_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("virtual_servers.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("vserver_name", sa.Text(), nullable=True),
        sa.Column(
            "upstream_server_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("mcp_servers.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("tool", sa.Text(), nullable=False),
        sa.Column("principal_type", sa.Text(), nullable=False),
        sa.Column("principal_id", sa.Text(), nullable=False),
        sa.Column(
            "principal_display",
            sa.Text(),
            nullable=False,
            server_default=sa.text("''"),
        ),
        sa.Column("decision", sa.Text(), nullable=False),
        sa.Column("decision_mode", sa.Text(), nullable=False),
        sa.Column(
            "policy_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
        sa.Column("policy_rule_id", sa.Text(), nullable=True),
        sa.Column("upstream_status", sa.Text(), nullable=False),
        sa.Column("latency_ms_total", sa.Float(), nullable=True),
        sa.Column("latency_ms_upstream", sa.Float(), nullable=True),
        sa.Column("response_size_bytes", sa.Integer(), nullable=True),
        sa.Column("auth_failure_reason", sa.Text(), nullable=True),
        sa.Column(
            "args_summary",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "auth_modes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "client_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "raw_args",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "raw_response",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "raw_args_truncated",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "raw_response_truncated",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.CheckConstraint(
            "event_type IN ('tool_call', 'access_attempt')",
            name="tool_call_events_event_type_check",
        ),
        sa.CheckConstraint(
            "decision IN ('allow', 'deny', 'redact', 'rewrite')",
            name="tool_call_events_decision_check",
        ),
        sa.CheckConstraint(
            "decision_mode IN ('monitor', 'enforce')",
            name="tool_call_events_decision_mode_check",
        ),
        sa.CheckConstraint(
            "upstream_status IN ('ok', 'error', 'timeout', 'not_called')",
            name="tool_call_events_upstream_status_check",
        ),
    )
    # Tenant feed — primary "show recent events" query.
    op.create_index(
        "tool_call_events_tenant_occurred_idx",
        "tool_call_events",
        ["tenant_id", "occurred_at"],
    )
    # vserver drill-in — operator clicks a vserver card.
    op.create_index(
        "tool_call_events_tenant_vserver_idx",
        "tool_call_events",
        ["tenant_id", "vserver_id", "occurred_at"],
    )
    # Per-identity timeline.
    op.create_index(
        "tool_call_events_tenant_principal_idx",
        "tool_call_events",
        ["tenant_id", "principal_id", "occurred_at"],
    )
    # event_type filter (`access_attempt` vs `tool_call`).
    op.create_index(
        "tool_call_events_tenant_event_type_idx",
        "tool_call_events",
        ["tenant_id", "event_type", "occurred_at"],
    )

    # RLS — same posture as admin_audit_log: ENABLE + FORCE so even
    # the table owner can't bypass without setting `app.current_tenant_id`.
    op.execute("ALTER TABLE tool_call_events ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tool_call_events FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY tool_call_events_tenant_isolation
        ON tool_call_events
        USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        WITH CHECK (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP POLICY IF EXISTS tool_call_events_tenant_isolation "
        "ON tool_call_events"
    )
    op.drop_index(
        "tool_call_events_tenant_event_type_idx",
        table_name="tool_call_events",
    )
    op.drop_index(
        "tool_call_events_tenant_principal_idx",
        table_name="tool_call_events",
    )
    op.drop_index(
        "tool_call_events_tenant_vserver_idx",
        table_name="tool_call_events",
    )
    op.drop_index(
        "tool_call_events_tenant_occurred_idx",
        table_name="tool_call_events",
    )
    op.drop_table("tool_call_events")
