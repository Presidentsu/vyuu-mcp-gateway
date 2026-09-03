"""add end-user identity model: users, groups, grants, user_api_keys

Revision ID: 20260430_0006
Revises: 20260430_0005
Create Date: 2026-04-30

A3-α adds end users as a first-class entity, distinct from operators.
Operators manage the catalog (admin role); users consume MCPs through
Claude Desktop, Cursor, agents (end-user role). A human can be both —
two rows, one in each table — they just have different lifecycles.

This migration adds:

- `users`           — end users; auth_method enum (local|microsoft|google)
- `groups`          — logical groupings (manually managed by admin in v1;
                       IdP-pulled is a future enhancement).
- `user_group_memberships` — many-to-many join.
- `virtual_server_grants` — explicit ACL for `private` vservers; targets
                              a user OR a group.
- `user_api_keys`   — per-user bearer tokens (for Claude Desktop, etc.).
- `virtual_servers.visibility` — public | private. Default `private`.

The `(tenant_id, email)` and `(tenant_id, name)` unique constraints
preserve the per-tenant isolation contract — a user/group/etc. is
defined within a tenant; cross-tenant references are not possible.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260430_0006"
down_revision: str | None = "20260430_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column("auth_method", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("external_subject", sa.Text(), nullable=True),
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "auth_method IN ('local', 'microsoft', 'google')",
            name="users_auth_method_check",
        ),
        sa.UniqueConstraint("tenant_id", "email", name="users_tenant_email_uq"),
    )
    op.create_index("users_tenant_id_idx", "users", ["tenant_id"])

    op.create_table(
        "groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operators.id"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("tenant_id", "name", name="groups_tenant_name_uq"),
    )
    op.create_index("groups_tenant_id_idx", "groups", ["tenant_id"])

    op.create_table(
        "user_group_memberships",
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "group_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "added_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operators.id"),
            nullable=False,
        ),
        sa.Column(
            "added_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "user_group_memberships_group_idx", "user_group_memberships", ["group_id"]
    )

    op.add_column(
        "virtual_servers",
        sa.Column(
            "visibility",
            sa.Text(),
            nullable=False,
            server_default="private",
        ),
    )
    op.create_check_constraint(
        "virtual_servers_visibility_check",
        "virtual_servers",
        "visibility IN ('public', 'private')",
    )

    op.create_table(
        "virtual_server_grants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "vserver_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("virtual_servers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("principal_kind", sa.Text(), nullable=False),
        sa.Column("principal_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "granted_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operators.id"),
            nullable=False,
        ),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "principal_kind IN ('user', 'group')",
            name="virtual_server_grants_kind_check",
        ),
    )
    op.create_index(
        "virtual_server_grants_lookup_idx",
        "virtual_server_grants",
        ["vserver_id", "principal_kind", "principal_id"],
    )
    op.create_index(
        "virtual_server_grants_tenant_idx",
        "virtual_server_grants",
        ["tenant_id"],
    )

    op.create_table(
        "user_api_keys",
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
        sa.Column("label", sa.Text(), nullable=False),
        sa.Column("key_hash", sa.Text(), nullable=False),
        # First 8 chars of the secret in plaintext, for operator-UI display
        # and log-line correlation. Not a security risk on its own — argon2
        # of the full secret is what gates auth.
        sa.Column("key_prefix", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("user_id", "label", name="user_api_keys_user_label_uq"),
    )
    op.create_index("user_api_keys_tenant_idx", "user_api_keys", ["tenant_id"])
    op.create_index("user_api_keys_user_idx", "user_api_keys", ["user_id"])


def downgrade() -> None:
    op.drop_table("user_api_keys")
    op.drop_table("virtual_server_grants")
    op.drop_constraint(
        "virtual_servers_visibility_check", "virtual_servers", type_="check"
    )
    op.drop_column("virtual_servers", "visibility")
    op.drop_table("user_group_memberships")
    op.drop_table("groups")
    op.drop_table("users")
