"""add mTLS upstream cert/key refs + enable RLS on oauth_user_tokens

Revision ID: 20260501_0010
Revises: 20260501_0009
Create Date: 2026-05-01

Two unrelated changes bundled because both are small follow-ups to the
A1 work that just landed:

1. **mTLS upstream auth** (`mcp_servers.mtls_cert_ref`,
   `mcp_servers.mtls_key_ref`) — operators registering an HTTPS MCP
   that requires client-cert auth (private corporate APIs, IRS-ish
   compliance regimes, internal-only Wiz / CrowdStrike flavours)
   provide two SecretStore refs pointing at the PEM-encoded client
   cert + private key. The provider builder resolves them and hands
   the materialised cert chain to httpx via an SSLContext at client
   construction time. Both refs must be set together (cert without
   key or key without cert is rejected at the schema level).

2. **RLS on `oauth_user_tokens`** — the table landed in 0009 without
   a policy. Tenant scoping was correctly enforced at the application
   layer (every read goes through `bind_tenant_context` + WHERE
   `tenant_id = :tid`), but the project's defence-in-depth posture
   requires RLS as the backstop on every tenant-scoped table. Adding
   the policy here avoids a "missed-RLS" incident if a future code
   path queries the table without the WHERE.

Both changes are additive + idempotent; downgrade rolls them back.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260501_0010"
down_revision: str | None = "20260501_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mcp_servers",
        sa.Column("mtls_cert_ref", sa.Text(), nullable=True),
    )
    op.add_column(
        "mcp_servers",
        sa.Column("mtls_key_ref", sa.Text(), nullable=True),
    )

    op.execute(sa.text("ALTER TABLE oauth_user_tokens ENABLE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            """
            CREATE POLICY oauth_user_tokens_tenant_isolation ON oauth_user_tokens
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            """
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "DROP POLICY IF EXISTS oauth_user_tokens_tenant_isolation ON oauth_user_tokens"
        )
    )
    op.execute(sa.text("ALTER TABLE oauth_user_tokens DISABLE ROW LEVEL SECURITY"))
    op.drop_column("mcp_servers", "mtls_key_ref")
    op.drop_column("mcp_servers", "mtls_cert_ref")
