"""add per-server sync cadence + persisted last-sync drift

Revision ID: 20260502_0012
Revises: 20260501_0011
Create Date: 2026-05-02

Two new columns on `mcp_servers`:

- `sync_cadence_minutes` (INT NULL) — per-server override for the
  capability-sync cadence. NULL means "use the global default"
  (`Settings.capability_sync_interval_seconds`). 0 means "manual
  only — never auto-sync". Concrete positive values cap the
  scheduler's per-server frequency.

- `last_sync_drift` (JSONB NULL) — the most recent
  `CapabilityDrift` from `detect_capability_drift`, persisted so
  the operator UI can show a diff (added / removed / changed) on
  the server card without re-running sync. Wiped on the next
  sync run; small enough to live inline rather than in a separate
  history table.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260502_0012"
down_revision: str | None = "20260501_0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mcp_servers",
        sa.Column("sync_cadence_minutes", sa.Integer(), nullable=True),
    )
    op.add_column(
        "mcp_servers",
        sa.Column("last_sync_drift", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    # Sanity check on the cadence — refuse negative values; NULL and 0
    # are both meaningful (use-default and manual-only respectively).
    op.create_check_constraint(
        "mcp_servers_sync_cadence_nonneg",
        "mcp_servers",
        "sync_cadence_minutes IS NULL OR sync_cadence_minutes >= 0",
    )


def downgrade() -> None:
    op.drop_constraint("mcp_servers_sync_cadence_nonneg", "mcp_servers", type_="check")
    op.drop_column("mcp_servers", "last_sync_drift")
    op.drop_column("mcp_servers", "sync_cadence_minutes")
