"""extend mcp_servers source_type CHECK constraint with 'binary'

Revision ID: 20260430_0005
Revises: 20260430_0004
Create Date: 2026-04-30

`binary` source type covers MCP servers shipped as native executables
pre-installed on the gateway host (security-vendor connectors that
distribute static binaries, e.g. older CrowdStrike Falcon connectors,
some Cloudflare Rust MCPs). Launches via `StdioMcpClient` with the
absolute path as the command — no `npx` / `uvx` / interpreter wrapper.

Distinct from `stdio` source_type, which is for curated relative-name
commands (`python3`, `node`, etc.) from `StdioLaunchPolicy.allowed_commands`.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260430_0005"
down_revision: str | None = "20260430_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("mcp_servers_source_type_check", "mcp_servers", type_="check")
    op.create_check_constraint(
        "mcp_servers_source_type_check",
        "mcp_servers",
        "source_type IN ('npm', 'pypi', 'http', 'stdio', 'binary')",
    )


def downgrade() -> None:
    op.drop_constraint("mcp_servers_source_type_check", "mcp_servers", type_="check")
    op.create_check_constraint(
        "mcp_servers_source_type_check",
        "mcp_servers",
        "source_type IN ('npm', 'pypi', 'http', 'stdio')",
    )
