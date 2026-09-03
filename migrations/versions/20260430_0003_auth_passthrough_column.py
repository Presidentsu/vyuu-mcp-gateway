"""add auth_passthrough column to mcp_servers

Revision ID: 20260430_0003
Revises: 20260430_0002
Create Date: 2026-04-30

User-tier authentication: instead of the operator wiring an org-shared
secret, the server config declares which inbound headers (sent by the
end-user's MCP client) to forward to the upstream as which header name.

  auth_passthrough = {"x-vyuu-paypal-token": "Authorization"}

means: when the inbound request carries `x-vyuu-paypal-token: Bearer xyz`,
the gateway forwards `Authorization: Bearer xyz` to the upstream. The
gateway never persists the credential — each user supplies their own.

HTTP-only (stdio servers do not have inbound headers in the same shape);
the request validator rejects this on stdio transports.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260430_0003"
down_revision: str | None = "20260430_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mcp_servers",
        sa.Column(
            "auth_passthrough",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("mcp_servers", "auth_passthrough")
