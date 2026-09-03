"""create registry tables

Revision ID: 20260429_0001
Revises:
Create Date: 2026-04-29

RLS note: the policies below use `NULLIF(current_setting(...), '')::uuid`
so an unset GUC excludes rows rather than raising. `missing_ok=true` handles
the case where the setting was never defined; `NULLIF` handles the Postgres
case where it resolves to an empty string.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260429_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("tier", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint("tier IN ('shared', 'dedicated')", name="tenants_tier_check"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "operators",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint("role IN ('admin', 'editor', 'viewer')", name="operators_role_check"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("operators_tenant_id_idx", "operators", ["tenant_id"])
    op.create_index("operators_tenant_email_idx", "operators", ["tenant_id", "email"], unique=True)

    op.create_table(
        "mcp_servers",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("source_type", sa.Text(), nullable=False),
        sa.Column("source_location", sa.Text(), nullable=False),
        sa.Column("transport", sa.Text(), nullable=False),
        sa.Column("env_vars_ref", sa.Text(), nullable=True),
        sa.Column(
            "args",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
        sa.Column("registered_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "registered_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("health_status", sa.Text(), server_default="unknown", nullable=False),
        sa.Column("last_capabilities_pulled_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "source_type IN ('npm', 'http', 'stdio')",
            name="mcp_servers_source_type_check",
        ),
        sa.CheckConstraint(
            "transport IN ('stdio', 'sse', 'streamable_http')",
            name="mcp_servers_transport_check",
        ),
        sa.CheckConstraint(
            "health_status IN ('healthy', 'degraded', 'down', 'unknown')",
            name="mcp_servers_health_status_check",
        ),
        sa.ForeignKeyConstraint(["registered_by"], ["operators.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "display_name", name="mcp_servers_tenant_name_uq"),
    )
    op.create_index("mcp_servers_tenant_id_idx", "mcp_servers", ["tenant_id"])

    op.create_table(
        "mcp_capabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("server_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("schema_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("deprecated", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.CheckConstraint(
            "kind IN ('tool', 'resource', 'prompt')",
            name="mcp_capabilities_kind_check",
        ),
        sa.ForeignKeyConstraint(["server_id"], ["mcp_servers.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "mcp_capabilities_server_kind_idx",
        "mcp_capabilities",
        ["server_id", "kind"],
    )
    op.create_index(
        "mcp_capabilities_tenant_server_kind_idx",
        "mcp_capabilities",
        ["tenant_id", "server_id", "kind"],
    )

    op.execute(sa.text("ALTER TABLE operators ENABLE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            """
            CREATE POLICY operators_tenant_isolation ON operators
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            """
        )
    )
    op.execute(sa.text("ALTER TABLE mcp_servers ENABLE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            """
            CREATE POLICY mcp_servers_tenant_isolation ON mcp_servers
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            """
        )
    )
    op.execute(sa.text("ALTER TABLE mcp_capabilities ENABLE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            """
            CREATE POLICY mcp_capabilities_tenant_isolation ON mcp_capabilities
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            """
        )
    )


def downgrade() -> None:
    for table_name in ("mcp_capabilities", "mcp_servers", "operators"):
        op.execute(sa.text(f"DROP POLICY IF EXISTS {table_name}_tenant_isolation ON {table_name}"))

    op.drop_index("mcp_capabilities_tenant_server_kind_idx", table_name="mcp_capabilities")
    op.drop_index("mcp_capabilities_server_kind_idx", table_name="mcp_capabilities")
    op.drop_table("mcp_capabilities")
    op.drop_index("mcp_servers_tenant_id_idx", table_name="mcp_servers")
    op.drop_table("mcp_servers")
    op.drop_index("operators_tenant_email_idx", table_name="operators")
    op.drop_index("operators_tenant_id_idx", table_name="operators")
    op.drop_table("operators")
    op.drop_table("tenants")
