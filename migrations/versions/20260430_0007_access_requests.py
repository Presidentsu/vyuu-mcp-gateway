"""add access_requests for end-user → admin approval workflow

Revision ID: 20260430_0007
Revises: 20260430_0006
Create Date: 2026-04-30

A3-γ: end users can self-service request access to a private vserver
they don't yet have a grant for. The admin sees a pending queue, can
approve (which creates a `virtual_server_grants` row) or decline (with
a note). Withdrawn requests are user-initiated cancellations of a
still-pending submission.

Schema notes:

- A request is owned by a user, scoped to a tenant, targeting a vserver.
  All three FKs cascade so cleaning up a tenant / user / vserver also
  cleans the request history (we don't need to preserve audit trail in
  a separate table for v1; that's an A5/A6 concern).
- `status` is one of `pending`, `approved`, `declined`, `withdrawn`.
  Check-constrained so the column always reflects a known state.
- `decided_by` + `decided_at` populate when an admin approves or declines.
  `created_grant_id` is set on approval so the user can be told which
  grant covers their request (and so an admin can trace the lineage).
- A user can only have **one pending request per vserver at a time** —
  enforced by a partial unique index on `(user_id, vserver_id) WHERE
  status = 'pending'`. Approved / declined / withdrawn requests do NOT
  block a fresh re-request. (Use case: declined for one reason, business
  context shifts, user re-requests.)
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260430_0007"
down_revision: str | None = "20260430_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "access_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "vserver_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("virtual_servers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column(
            "decided_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operators.id"),
            nullable=True,
        ),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_grant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("virtual_server_grants.id"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'declined', 'withdrawn')",
            name="access_requests_status_check",
        ),
    )
    # Per-tenant queue scan (admin "show me pending" hits this).
    op.create_index(
        "access_requests_tenant_status_idx",
        "access_requests",
        ["tenant_id", "status"],
    )
    # End-user "my requests" lookup.
    op.create_index(
        "access_requests_user_idx",
        "access_requests",
        ["user_id"],
    )
    # Vserver-side "who's asking for this" lookup (operator-UI vserver card).
    op.create_index(
        "access_requests_vserver_idx",
        "access_requests",
        ["vserver_id"],
    )
    # One pending request per (user, vserver). Other statuses don't block.
    op.create_index(
        "access_requests_one_pending_per_target",
        "access_requests",
        ["user_id", "vserver_id"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )


def downgrade() -> None:
    op.drop_table("access_requests")
