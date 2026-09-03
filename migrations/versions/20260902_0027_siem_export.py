"""SIEM-1 · per-tenant SIEM export targets (Splunk HEC)

Revision ID: 20260902_0027
Revises: 20260828_0026
Create Date: 2026-09-02

Where a tenant's security events are shipped. One row per tenant: the
HEC endpoint, a secret-store REFERENCE to its token, and what to send.

## Why a table and not columns on `tenants`

`tenants.risk_model_*` set the precedent for four columns. This is
twelve, with its own lifecycle (enable / disable / test / clear) and
its own audit verbs, and a second SIEM vendor later would be a second
row shape rather than twelve more columns. A table with a unique
tenant index is one row per tenant today and does not paint the next
change into a corner.

## Why the token is a reference

This table is dumped, backed up and read by support. A HEC token lets
its holder WRITE events into the tenant's SIEM — forge a clean audit
trail, or bury a real one in noise — which is a worse capability than
reading it. The same reasoning that keeps `risk_model_api_key_ref` a
reference applies with more force here.

## Why delivery state is not here

Queue depth, last error, sent counts are per gateway instance, like a
circuit breaker's state. Persisting them would show one instance's
numbers as the tenant's, and would add a write per batch to a table
that otherwise changes when an admin clicks Save.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260902_0027"
down_revision = "20260828_0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenant_siem_targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("hec_url", sa.Text(), nullable=False),
        sa.Column("hec_token_ref", sa.Text(), nullable=False),
        sa.Column("index", sa.Text()),
        sa.Column("source", sa.Text(), nullable=False, server_default="vyuu-mcp-gateway"),
        sa.Column("host_override", sa.Text()),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("categories", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column(
            "include_raw_payloads", sa.Boolean(), nullable=False, server_default="false"
        ),
        sa.Column("min_log_level", sa.Text(), nullable=False, server_default="WARNING"),
        sa.Column("batch_max_events", sa.Integer(), nullable=False, server_default="100"),
        sa.Column(
            "flush_interval_seconds", sa.Float(), nullable=False, server_default="2.0"
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "tenant_siem_targets_tenant_uq", "tenant_siem_targets", ["tenant_id"], unique=True
    )
    op.execute("ALTER TABLE tenant_siem_targets ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tenant_siem_targets FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY tenant_siem_targets_tenant_isolation
        ON tenant_siem_targets
        USING (tenant_id = (NULLIF(current_setting(
            'app.current_tenant_id', TRUE), ''))::uuid)
        WITH CHECK (tenant_id = (NULLIF(current_setting(
            'app.current_tenant_id', TRUE), ''))::uuid)
        """
    )


def downgrade() -> None:
    op.drop_index("tenant_siem_targets_tenant_uq", table_name="tenant_siem_targets")
    op.drop_table("tenant_siem_targets")
