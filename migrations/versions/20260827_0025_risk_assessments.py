"""RISK-1 · LLM risk assessments for MCP servers and virtual servers

Revision ID: 20260827_0025
Revises: 20260827_0024
Create Date: 2026-08-27

Stores what the classifier concluded, so a score can be shown without
re-running a paid model call on every page load, and so "did this get
worse?" is answerable.

## History, not latest-only

Rows accumulate; the newest for a server is the current one. A single
mutable row would be cheaper and would throw away the only thing that
makes a score actionable — a capability sync that adds a `delete_*` tool
should show up as risk MOVING, and you cannot see movement against a
value that was overwritten.

## Denormalised scores

`normalised` and `band` are columns rather than being recomputed from
`findings` on read. The console sorts and filters catalogues by them,
and the alternative is deserialising every assessment's JSONB to render
one list. `findings` remains the source of truth; if the scoring changes
these are stale until re-assessment, which is why `scoring_version` is
recorded next to them.

## The vserver table stores the comparison, not a second assessment

`virtual_server_risk_assessments` is derived arithmetic over the source
servers' findings — see `risk/reduction.py` for why it must not be an
independent classification. `source_assessment_ids` records exactly
which assessments it was computed from, so a stale comparison is
detectable rather than merely suspicious.

## Model config on `tenants`

Follows the existing `slug` pattern. The API key is a **SecretStore
ref**, never the key: this table is dumped, backed up and read by
support, and an LLM vendor key buys an attacker inference spend and
whatever that account can reach.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260827_0025"
down_revision = "20260827_0024"
branch_labels = None
depends_on = None

_SCORE_COLUMNS = (
    sa.Column("exposure", sa.Float(), nullable=False),
    sa.Column("severity_profile", sa.Float(), nullable=False),
    sa.Column("overall", sa.Float(), nullable=False),
    sa.Column("normalised", sa.Float(), nullable=False),
    sa.Column("band", sa.Text(), nullable=False),
    sa.Column("finding_count", sa.Integer(), nullable=False),
)


def upgrade() -> None:
    op.create_table(
        "mcp_server_risk_assessments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "server_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("mcp_servers.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("model_id", sa.Text(), nullable=False),
        sa.Column("model_vendor", sa.Text(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("confidence", sa.Text(), nullable=False, server_default="low"),
        sa.Column(
            "findings", postgresql.JSONB, nullable=False, server_default="[]"
        ),
        *_SCORE_COLUMNS,
        # How many capabilities were in the payload. A score over 3 tools
        # and a score over 190 are not the same claim.
        sa.Column("capability_count", sa.Integer(), nullable=False, server_default="0"),
        # Whether the payload had to be truncated, and what the score is
        # actually based on. Carried per row so an old assessment cannot
        # be read under today's assumptions.
        sa.Column("truncated", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("evidence_basis", sa.Text(), nullable=False, server_default=""),
        sa.Column("scoring_version", sa.Text(), nullable=False, server_default="1"),
        sa.Column("assessed_by", postgresql.UUID(as_uuid=True)),
        sa.Column(
            "assessed_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "mcp_server_risk_latest_idx",
        "mcp_server_risk_assessments",
        ["tenant_id", "server_id", sa.text("assessed_at DESC")],
    )

    op.create_table(
        "virtual_server_risk_assessments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "vserver_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("virtual_servers.id", ondelete="CASCADE"), nullable=False,
        ),
        # Which upstream assessments this was derived from. Without it a
        # comparison computed before a re-assessment is indistinguishable
        # from a current one.
        sa.Column(
            "source_assessment_ids", postgresql.JSONB,
            nullable=False, server_default="[]",
        ),
        sa.Column("inherent_normalised", sa.Float(), nullable=False),
        sa.Column("inherent_band", sa.Text(), nullable=False),
        sa.Column("published_normalised", sa.Float(), nullable=False),
        sa.Column("published_band", sa.Text(), nullable=False),
        sa.Column("points_reduced", sa.Float(), nullable=False),
        sa.Column("percent_reduced", sa.Float(), nullable=False),
        sa.Column(
            "eliminated", postgresql.JSONB, nullable=False, server_default="[]"
        ),
        sa.Column("retained", postgresql.JSONB, nullable=False, server_default="[]"),
        sa.Column("scoring_version", sa.Text(), nullable=False, server_default="1"),
        sa.Column(
            "computed_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "virtual_server_risk_latest_idx",
        "virtual_server_risk_assessments",
        ["tenant_id", "vserver_id", sa.text("computed_at DESC")],
    )

    for table in ("mcp_server_risk_assessments", "virtual_server_risk_assessments"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_isolation
            ON {table}
            USING (tenant_id = (NULLIF(current_setting(
                'app.current_tenant_id', TRUE), ''))::uuid)
            WITH CHECK (tenant_id = (NULLIF(current_setting(
                'app.current_tenant_id', TRUE), ''))::uuid)
            """
        )

    # --- which model this tenant classifies with -------------------------
    op.add_column("tenants", sa.Column("risk_model_id", sa.Text()))
    op.add_column("tenants", sa.Column("risk_model_vendor", sa.Text()))
    # A SecretStore ref. Never the key — see the module docstring.
    op.add_column("tenants", sa.Column("risk_model_api_key_ref", sa.Text()))
    # For Azure OpenAI / Vertex / an inspecting egress proxy.
    op.add_column("tenants", sa.Column("risk_model_base_url", sa.Text()))


def downgrade() -> None:
    for column in (
        "risk_model_base_url", "risk_model_api_key_ref",
        "risk_model_vendor", "risk_model_id",
    ):
        op.drop_column("tenants", column)
    for table in ("virtual_server_risk_assessments", "mcp_server_risk_assessments"):
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_isolation ON {table}")
    op.drop_index(
        "virtual_server_risk_latest_idx", table_name="virtual_server_risk_assessments"
    )
    op.drop_table("virtual_server_risk_assessments")
    op.drop_index("mcp_server_risk_latest_idx", table_name="mcp_server_risk_assessments")
    op.drop_table("mcp_server_risk_assessments")
