"""add OAuth authorization-code (phase 4) — auth_authcode column + oauth_user_tokens

Revision ID: 20260501_0009
Revises: 20260430_0008
Create Date: 2026-05-01

A1 — phase-4 OAuth: per-user delegated tokens via the authorization-code
grant (RFC 6749 §4.1). Adds two pieces of state:

1. `mcp_servers.auth_authcode` (JSONB, nullable) — per-server
   configuration: authorization URL, token URL, client_id_ref,
   client_secret_ref, scopes, redirect_uri.

2. `oauth_user_tokens` — per-(tenant, user, server) refresh + access
   tokens. Populated by the `/oauth-authcode/{server}/callback`
   endpoint after the IdP redirects back. Read on every tool call
   that hits an `auth_authcode`-using upstream.

The access_token + refresh_token are stored as plaintext. **Production
hardening (envelope encryption via KMS) is a separate slice (sized in
backlog as "AWS KMS direct integration"). For now the operator-side
hardening is: keep DB at-rest encryption on, restrict DB credentials,
audit who reads the table.

`expires_at` is the time the access_token expires (NOT the refresh
token's expiry — refresh tokens may live for months).
`last_refreshed_at` lets ops detect tokens that haven't refreshed in
ages (refresh_token may have been revoked at the IdP).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260501_0009"
down_revision: str | None = "20260430_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mcp_servers",
        sa.Column("auth_authcode", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )

    op.create_table(
        "oauth_user_tokens",
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
            "server_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("mcp_servers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("access_token", sa.Text(), nullable=False),
        sa.Column("refresh_token", sa.Text(), nullable=True),
        sa.Column("token_type", sa.Text(), nullable=False, server_default="Bearer"),
        sa.Column("scope", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_refreshed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "user_id",
            "server_id",
            name="oauth_user_tokens_unique_per_principal_server",
        ),
    )
    op.create_index(
        "oauth_user_tokens_user_idx",
        "oauth_user_tokens",
        ["user_id"],
    )
    op.create_index(
        "oauth_user_tokens_tenant_idx",
        "oauth_user_tokens",
        ["tenant_id"],
    )


def downgrade() -> None:
    op.drop_table("oauth_user_tokens")
    op.drop_column("mcp_servers", "auth_authcode")
