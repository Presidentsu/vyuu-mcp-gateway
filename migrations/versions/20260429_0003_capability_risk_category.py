"""add risk_category column to mcp_capabilities

Revision ID: 20260429_0003
Revises: 20260429_0002
Create Date: 2026-04-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260429_0003"
down_revision: str | None = "20260429_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_RISK_CATEGORIES = (
    "read",
    "write",
    "delete",
    "execute",
    "network",
    "credential_access",
    "data_export",
    "admin",
    "unknown",
)


def upgrade() -> None:
    op.add_column(
        "mcp_capabilities",
        sa.Column(
            "risk_category",
            sa.Text(),
            server_default="unknown",
            nullable=False,
        ),
    )
    values = ", ".join(f"'{category}'" for category in _RISK_CATEGORIES)
    op.create_check_constraint(
        "mcp_capabilities_risk_category_check",
        "mcp_capabilities",
        f"risk_category IN ({values})",
    )


def downgrade() -> None:
    op.drop_constraint(
        "mcp_capabilities_risk_category_check",
        "mcp_capabilities",
        type_="check",
    )
    op.drop_column("mcp_capabilities", "risk_category")
