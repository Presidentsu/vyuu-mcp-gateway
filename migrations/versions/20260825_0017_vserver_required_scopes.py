"""EMA-1 P3 · per-tool required OAuth scope on virtual servers

Revision ID: 20260825_0017
Revises: 20260825_0016
Create Date: 2026-08-25

Adds `virtual_servers.required_scopes` — a JSONB map of
`exposed_tool_name -> required_scope`, deliberately symmetric with the
existing `rename_map` on the same row.

Why here and not on `virtual_server_tools`: the resolver's tool query
is a three-way join whose row shape is duplicated across several test
fakes, and the map is needed exactly where the `VirtualServer` row is
already loaded. Keying on the EXPOSED (post-rename) name matches what
the caller actually asks for, which is what the lifecycle compares
against.

Empty map (the default) = no tool on this vserver requires a scope, so
every existing vserver keeps behaving exactly as before.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260825_0017"
down_revision: str | None = "20260825_0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "virtual_servers",
        sa.Column(
            "required_scopes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("virtual_servers", "required_scopes")
