"""add mcp server health metadata

Revision ID: 20260429_0004
Revises: 20260429_0003
Create Date: 2026-04-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260429_0004"
down_revision: str | None = "20260429_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mcp_servers",
        sa.Column("last_health_checked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("mcp_servers", sa.Column("last_health_error", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("mcp_servers", "last_health_error")
    op.drop_column("mcp_servers", "last_health_checked_at")
