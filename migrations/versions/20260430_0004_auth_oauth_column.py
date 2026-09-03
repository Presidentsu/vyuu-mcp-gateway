"""add auth_oauth column to mcp_servers

Revision ID: 20260430_0004
Revises: 20260430_0003
Create Date: 2026-04-30

OAuth 2.0 client-credentials configuration per upstream server. Carries
the token-endpoint URL plus opaque references to the client_id /
client_secret in the SecretStore — never the raw credentials. The
gateway brokers the M2M token exchange on each upstream connection and
caches the access token in memory until it expires.

Nullable: most servers don't use OAuth (org-tier static API keys via
`auth_headers` or user-tier passthrough cover the bulk of real cases).
HTTP-only — the schema validator rejects this on stdio transports.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260430_0004"
down_revision: str | None = "20260430_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mcp_servers",
        sa.Column(
            "auth_oauth",
            postgresql.JSONB,
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("mcp_servers", "auth_oauth")
