"""MCP-2 P3 · record which client-auth mechanism a server actually used

Revision ID: 20260826_0023
Revises: 20260826_0022
Create Date: 2026-08-26

`mcp_server_dcr_clients` was built for one mechanism, so it never had to
say which one it held. CIMD makes that ambiguous: a CIMD row and a DCR
row look alike — both carry a `client_id` and the AS endpoints — but they
mean different things and fail differently.

**`auth_mechanism`** discriminates them, and the value it carries is not
only diagnostic. The token endpoint answering `invalid_client` means
opposite things per mechanism: for DCR the registration was evicted and
re-registering fixes it, so the row is dropped and the next Connect
registers again. For CIMD there is nothing to re-register — the AS
advertised support and then refused our URL — so dropping the row and
re-probing would present the same URL to the same AS and be refused
again, forever. That is a permanent Connect failure built out of two
individually-correct behaviours.

So a rejected CIMD row is **not deleted, it is marked**
(`auth_mechanism='cimd_rejected'`). The marker is what makes the
documented fall-back to DCR actually happen instead of looping. It lives
on this row rather than on `mcp_servers` so it cascades away with the
server and stays next to the endpoints it describes.

**`registration_endpoint` becomes nullable** because CIMD has no
registration step. Leaving it NOT NULL would mean writing a placeholder
into a column whose entire job is to say where registration happened —
a value that reads as fact and is not one.

Both changes are additive to existing rows: the DEFAULT backfills every
current row as `'dcr'`, which is what they all are.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260826_0023"
down_revision = "20260826_0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "mcp_server_dcr_clients",
        sa.Column(
            "auth_mechanism",
            sa.Text(),
            nullable=False,
            server_default="dcr",
        ),
    )
    op.alter_column(
        "mcp_server_dcr_clients",
        "registration_endpoint",
        existing_type=sa.Text(),
        nullable=True,
    )


def downgrade() -> None:
    # A CIMD row has no registration_endpoint, so restoring NOT NULL
    # would fail on exactly the rows this migration introduced. Drop
    # them first: they are a cache of a discovery probe, and the next
    # Connect re-derives whatever is still true.
    op.execute("DELETE FROM mcp_server_dcr_clients WHERE auth_mechanism <> 'dcr'")
    op.execute(
        "UPDATE mcp_server_dcr_clients SET registration_endpoint = '' "
        "WHERE registration_endpoint IS NULL"
    )
    op.alter_column(
        "mcp_server_dcr_clients",
        "registration_endpoint",
        existing_type=sa.Text(),
        nullable=False,
    )
    op.drop_column("mcp_server_dcr_clients", "auth_mechanism")
