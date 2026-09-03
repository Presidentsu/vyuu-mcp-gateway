"""JIT-1 · just-in-time (time-boxed) access to private virtual servers

Revision ID: 20260825_0018
Revises: 20260825_0017
Create Date: 2026-08-25

Standing access is the thing JIT exists to remove: today a user who
needs a private vserver once gets a grant that never expires, and the
tenant accumulates permanent authority nobody revisits. JIT makes the
elevation *temporary by construction* — the grant carries an
`expires_at` and simply stops being honoured when the clock passes it.

**The enforcement path needs no change.** `virtual_servers/access.py`
already ignores grants whose `expires_at` has passed, and
`_authenticate_and_authorize` re-runs that check on *every* inbound
request (not just at session start), so an elevation that lapses
mid-session cuts off at the next call. This migration only adds the
policy that decides *how long* and *on whose say-so*.

Three tables move:

1. `virtual_servers` gains the per-vserver JIT policy. Disabled by
   default — an existing vserver behaves exactly as before until an
   operator turns it on.
2. `access_requests` gains `requested_duration_seconds`, so the
   approval queue shows *how much* access is being asked for, not just
   that access is being asked for.
3. `virtual_server_grants` gains provenance (`granted_via`) and the
   `justification` captured at request time — the two fields an auditor
   needs to answer "why did this person have access at 03:00?".

`granted_by` becomes NULLABLE. An auto-approved JIT elevation has no
operator behind it, and pointing the FK at some sentinel operator row
would put a human's name on a decision they did not make. `granted_via`
carries the provenance instead, so a NULL `granted_by` is never
ambiguous.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260825_0018"
down_revision: str | None = "20260825_0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# 4 hours. Long enough for a real debugging session, short enough that
# forgetting to revoke is not a standing grant by another name.
_DEFAULT_MAX_DURATION_SECONDS = 4 * 3600


def upgrade() -> None:
    # --- 1. Per-vserver JIT policy -------------------------------------
    op.add_column(
        "virtual_servers",
        sa.Column(
            "jit_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "virtual_servers",
        sa.Column(
            "jit_max_duration_seconds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text(str(_DEFAULT_MAX_DURATION_SECONDS)),
        ),
    )
    # Auto-approve trades the human review step for speed. Still audited,
    # still time-boxed, still justification-gated — but nobody is asked.
    # Off by default: turning it on is a deliberate decision about which
    # vservers are safe to self-serve.
    op.add_column(
        "virtual_servers",
        sa.Column(
            "jit_auto_approve",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    # On by default. A JIT grant with no stated reason is strictly worse
    # for the auditor than a standing grant, because it also lacks the
    # deliberation a standing grant implies.
    op.add_column(
        "virtual_servers",
        sa.Column(
            "jit_require_justification",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
    )
    op.create_check_constraint(
        "virtual_servers_jit_max_duration_check",
        "virtual_servers",
        "jit_max_duration_seconds > 0 AND jit_max_duration_seconds <= 604800",
    )

    # --- 2. Requested duration on the approval queue --------------------
    op.add_column(
        "access_requests",
        sa.Column("requested_duration_seconds", sa.Integer(), nullable=True),
    )
    op.create_check_constraint(
        "access_requests_requested_duration_check",
        "access_requests",
        "requested_duration_seconds IS NULL OR requested_duration_seconds > 0",
    )

    # --- 3. Grant provenance + justification ---------------------------
    op.add_column(
        "virtual_server_grants",
        sa.Column(
            "granted_via",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'operator'"),
        ),
    )
    op.add_column(
        "virtual_server_grants",
        sa.Column("justification", sa.Text(), nullable=True),
    )
    op.create_check_constraint(
        "virtual_server_grants_granted_via_check",
        "virtual_server_grants",
        "granted_via IN ('operator', 'jit_auto', 'jit_approved')",
    )
    # Auto-approved JIT has no operator behind it. See module docstring.
    op.alter_column(
        "virtual_server_grants",
        "granted_by",
        existing_type=sa.dialects.postgresql.UUID(as_uuid=True),
        nullable=True,
    )
    # "Who is elevated right now?" is the operator's live question, and
    # the expiry sweep's. Partial on non-revoked rows with an expiry —
    # standing grants (expires_at IS NULL) are the majority and never
    # belong in this index.
    op.create_index(
        "virtual_server_grants_active_expiring_idx",
        "virtual_server_grants",
        ["tenant_id", "expires_at"],
        postgresql_where=sa.text("revoked_at IS NULL AND expires_at IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "virtual_server_grants_active_expiring_idx",
        table_name="virtual_server_grants",
    )
    # Any row that relied on the nullability must be resolved before the
    # column can go back to NOT NULL. Auto-approved JIT grants have no
    # operator to attribute to, so they are dropped rather than
    # misattributed — they are, by definition, short-lived.
    op.execute(
        "DELETE FROM virtual_server_grants "
        "WHERE granted_by IS NULL"
    )
    op.alter_column(
        "virtual_server_grants",
        "granted_by",
        existing_type=sa.dialects.postgresql.UUID(as_uuid=True),
        nullable=False,
    )
    op.drop_constraint(
        "virtual_server_grants_granted_via_check",
        "virtual_server_grants",
        type_="check",
    )
    op.drop_column("virtual_server_grants", "justification")
    op.drop_column("virtual_server_grants", "granted_via")

    op.drop_constraint(
        "access_requests_requested_duration_check",
        "access_requests",
        type_="check",
    )
    op.drop_column("access_requests", "requested_duration_seconds")

    op.drop_constraint(
        "virtual_servers_jit_max_duration_check",
        "virtual_servers",
        type_="check",
    )
    op.drop_column("virtual_servers", "jit_require_justification")
    op.drop_column("virtual_servers", "jit_auto_approve")
    op.drop_column("virtual_servers", "jit_max_duration_seconds")
    op.drop_column("virtual_servers", "jit_enabled")
