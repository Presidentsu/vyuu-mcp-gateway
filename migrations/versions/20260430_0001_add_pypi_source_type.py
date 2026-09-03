"""extend mcp_servers source_type CHECK constraint with 'pypi'

Revision ID: 20260430_0001
Revises: 20260429_0004
Create Date: 2026-04-30

`pypi` source type covers MCP servers published as Python packages and
launched through `uvx <package>` (Astral's uv tool runner). Mirrors the
existing `npm` source type for the JS ecosystem.

Postgres CHECK constraints are not real enums — to extend the allowed
set we drop and recreate the constraint with the expanded values.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260430_0001"
down_revision: str | None = "20260429_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("mcp_servers_source_type_check", "mcp_servers", type_="check")
    op.create_check_constraint(
        "mcp_servers_source_type_check",
        "mcp_servers",
        "source_type IN ('npm', 'pypi', 'http', 'stdio')",
    )


def downgrade() -> None:
    op.drop_constraint("mcp_servers_source_type_check", "mcp_servers", type_="check")
    op.create_check_constraint(
        "mcp_servers_source_type_check",
        "mcp_servers",
        "source_type IN ('npm', 'http', 'stdio')",
    )
