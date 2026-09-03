"""DCR client credentials per MCP server (RFC 7591 dynamic registration)

Revision ID: 20260503_0013
Revises: 20260502_0012
Create Date: 2026-05-03

Adds `mcp_server_dcr_clients`: gateway-as-OAuth-client credentials
issued via Dynamic Client Registration against an MCP server's
authorization server. Used for `dcr_enabled=true` `auth_authcode`
upstreams (Notion, Linear, anything built on the official MCP SDK
auth helpers) so operators don't pre-register OAuth apps in vendor
dashboards.

Also adds `dcr_enabled` boolean to the `auth_authcode` JSONB blob —
no schema change needed there since the column is JSONB; the change
is purely Pydantic-side. Documented here for traceability.

RLS: tenant-scoped (same pattern as `oauth_user_tokens`). The
`server_id` PK is sufficient for uniqueness (one DCR client per
upstream); the row is replaced on re-registration after an
`invalid_client` from the AS.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260503_0013"
down_revision: str | None = "20260502_0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "mcp_server_dcr_clients",
        sa.Column(
            "server_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("mcp_servers.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("client_id", sa.Text(), nullable=False),
        sa.Column("client_secret", sa.Text(), nullable=True),
        sa.Column("authorization_endpoint", sa.Text(), nullable=False),
        sa.Column("token_endpoint", sa.Text(), nullable=False),
        sa.Column("registration_endpoint", sa.Text(), nullable=False),
        sa.Column(
            "registration_response",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "issued_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "mcp_server_dcr_clients_tenant_idx",
        "mcp_server_dcr_clients",
        ["tenant_id"],
    )

    # RLS: tenant scoping — same posture as oauth_user_tokens. Reads
    # filter to the bound tenant; the GUC-bound role can't see other
    # tenants' DCR clients even via direct SELECT.
    op.execute("ALTER TABLE mcp_server_dcr_clients ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE mcp_server_dcr_clients FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY mcp_server_dcr_clients_tenant_isolation
        ON mcp_server_dcr_clients
        USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        WITH CHECK (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP POLICY IF EXISTS mcp_server_dcr_clients_tenant_isolation "
        "ON mcp_server_dcr_clients"
    )
    op.drop_index("mcp_server_dcr_clients_tenant_idx", "mcp_server_dcr_clients")
    op.drop_table("mcp_server_dcr_clients")
