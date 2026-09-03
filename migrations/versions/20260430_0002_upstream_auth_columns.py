"""add upstream auth columns to mcp_servers

Revision ID: 20260430_0002
Revises: 20260430_0001
Create Date: 2026-04-30

`auth_headers` and `auth_env` carry per-server `{name → secret_ref}` maps
that the upstream client provider resolves through the configured
`SecretStore` before each connection. Both default to empty `{}` so existing
rows continue to work unchanged.

- `auth_headers` is honored only for HTTP / Streamable HTTP transport;
  applied as headers on every outbound request.
- `auth_env` is honored only for stdio transport (npm / pypi / raw stdio);
  injected into the spawned subprocess's environment.

Refs are opaque strings the secret store understands. The gateway never
stores raw credentials — only references.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260430_0002"
down_revision: str | None = "20260430_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mcp_servers",
        sa.Column(
            "auth_headers",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.add_column(
        "mcp_servers",
        sa.Column(
            "auth_env",
            postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("mcp_servers", "auth_env")
    op.drop_column("mcp_servers", "auth_headers")
