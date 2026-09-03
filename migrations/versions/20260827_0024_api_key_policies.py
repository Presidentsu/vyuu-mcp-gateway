"""CRED-1 · per-user / per-group API-key lifetime policy

Revision ID: 20260827_0024
Revises: 20260826_0023
Create Date: 2026-08-27

`user_api_keys.expires_at` has existed since the table was created and
is already enforced on every inbound call. Nothing ever *set* it: both
issuance paths default it to NULL, so in practice a user key lives until
somebody remembers to revoke it. A credential nobody has to renew is a
credential nobody reviews.

This table lets an admin declare a maximum lifetime and have it applied
at issuance, so expiry is the default rather than an act of vigilance.

## Why a table rather than a settings knob

The limit that suits a contractor is not the limit that suits a service
account, and a single tenant-wide number forces the strictest case on
everyone — which in practice means the number gets set loose. Three
scopes (`tenant`, `group`, `user`) let the default be short and the
exceptions be explicit and visible.

## Resolution, and why the SHORTEST group wins

Precedence is user → group → tenant → unlimited. When a user belongs to
several groups the **shortest** policy applies, never the longest: if
the longest won, joining a group would be a way to extend your own
credential lifetime, which turns group membership into a privilege
escalation. Taking the shortest means group membership can only ever
tighten.

`principal_id` holds the tenant id for `tenant` rows so the unique
constraint covers all three scopes without a nullable key column.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260827_0024"
down_revision = "20260826_0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_key_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("principal_kind", sa.Text(), nullable=False),
        sa.Column("principal_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("max_ttl_seconds", sa.Integer(), nullable=False),
        sa.Column("note", sa.Text()),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "principal_kind IN ('tenant', 'group', 'user')",
            name="api_key_policies_principal_kind_check",
        ),
        # A zero or negative ceiling would mint keys that are already
        # expired — refuse it in the schema rather than discover it when
        # somebody's agent stops working.
        sa.CheckConstraint(
            "max_ttl_seconds > 0", name="api_key_policies_ttl_positive"
        ),
        # One year. Long enough for any legitimate policy, short enough
        # that a fat-fingered value cannot mean "effectively never".
        sa.CheckConstraint(
            "max_ttl_seconds <= 31536000", name="api_key_policies_ttl_max"
        ),
    )
    op.create_unique_constraint(
        "api_key_policies_scope_uq",
        "api_key_policies",
        ["tenant_id", "principal_kind", "principal_id"],
    )
    op.create_index(
        "api_key_policies_tenant_idx", "api_key_policies", ["tenant_id"]
    )
    op.execute("ALTER TABLE api_key_policies ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE api_key_policies FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY api_key_policies_tenant_isolation
        ON api_key_policies
        USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        WITH CHECK (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP POLICY IF EXISTS api_key_policies_tenant_isolation ON api_key_policies"
    )
    op.drop_index("api_key_policies_tenant_idx", table_name="api_key_policies")
    op.drop_constraint(
        "api_key_policies_scope_uq", "api_key_policies", type_="unique"
    )
    op.drop_table("api_key_policies")
