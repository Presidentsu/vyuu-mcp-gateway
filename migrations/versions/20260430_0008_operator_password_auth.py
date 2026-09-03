"""add password_hash + lifecycle columns to operators

Revision ID: 20260430_0008
Revises: 20260430_0007
Create Date: 2026-04-30

Operator login was previously bearer-token-only — operators pasted a
JWT minted out-of-band into the operator console. To support a real
admin login flow + admin-management panel, operators now have:

- `password_hash`            — bcrypt, same primitives as `users`
- `last_login_at`            — observability
- `disabled_at`              — soft-disable without deletion
- `must_change_password`     — admin-issued initial credential gate

`password_hash` is nullable so existing rows + tests that mint
bearer tokens directly continue to work. Production admins go through
the new `POST /api/v1/operator-auth/login` endpoint that requires the
hash to be set.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260430_0008"
down_revision: str | None = "20260430_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "operators", sa.Column("password_hash", sa.Text(), nullable=True)
    )
    op.add_column(
        "operators",
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "operators",
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "operators",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("operators", "must_change_password")
    op.drop_column("operators", "disabled_at")
    op.drop_column("operators", "last_login_at")
    op.drop_column("operators", "password_hash")
