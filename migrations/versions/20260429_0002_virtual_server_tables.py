"""create virtual server tables

Revision ID: 20260429_0002
Revises: 20260429_0001
Create Date: 2026-04-29

See `20260429_0001_registry_tables.py` for the RLS GUC note. The same
`NULLIF(current_setting('app.current_tenant_id', true), '')::uuid` pattern is
used here.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260429_0002"
down_revision: str | None = "20260429_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "virtual_servers",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("policy_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "rename_map",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["created_by"], ["operators.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "name", name="virtual_servers_tenant_name_uq"),
    )
    op.create_index("virtual_servers_tenant_id_idx", "virtual_servers", ["tenant_id"])

    op.create_table(
        "virtual_server_tools",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("vserver_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("server_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tool_name", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["server_id"], ["mcp_servers.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["vserver_id"], ["virtual_servers.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("vserver_id", "server_id", "tool_name"),
    )
    op.create_index(
        "virtual_server_tools_tenant_vserver_idx",
        "virtual_server_tools",
        ["tenant_id", "vserver_id"],
    )

    op.execute(sa.text("ALTER TABLE virtual_servers ENABLE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            """
            CREATE POLICY virtual_servers_tenant_isolation ON virtual_servers
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            """
        )
    )
    op.execute(sa.text("ALTER TABLE virtual_server_tools ENABLE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            """
            CREATE POLICY virtual_server_tools_tenant_isolation ON virtual_server_tools
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            """
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "DROP POLICY IF EXISTS virtual_server_tools_tenant_isolation ON virtual_server_tools"
        )
    )
    op.execute(sa.text("DROP POLICY IF EXISTS virtual_servers_tenant_isolation ON virtual_servers"))
    op.drop_index("virtual_server_tools_tenant_vserver_idx", table_name="virtual_server_tools")
    op.drop_table("virtual_server_tools")
    op.drop_index("virtual_servers_tenant_id_idx", table_name="virtual_servers")
    op.drop_table("virtual_servers")
