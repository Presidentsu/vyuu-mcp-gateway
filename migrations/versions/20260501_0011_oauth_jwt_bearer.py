"""add OAuth JWT-bearer (RFC 7523) — auth_jwt_bearer column

Revision ID: 20260501_0011
Revises: 20260501_0010
Create Date: 2026-05-01

A2 — phase-5 OAuth: signed-JWT assertion grant (RFC 7523). The gateway
holds a signing key (RSA / EC), constructs a short-lived JWT, and
exchanges it at the token endpoint for an access token. Used by:

- **Google Workspace service accounts** (Drive, Calendar, Sheets) —
  the JWT's `sub` claim is the user-to-impersonate, the signing key
  is the SA's RSA private key. Gateway acts as the SA.

- **AWS IAM Roles Anywhere** — the JWT (technically X.509-derived
  CreateSession assertion) lets on-prem gateways assume an IAM role
  without long-lived AWS access keys.

- **Vendor APIs that prefer asymmetric auth over Basic auth** — some
  enterprise vendors mandate JWT-bearer for service identities.

Shape: `{token_url, algorithm, private_key_ref, issuer, subject,
audience, scope?, additional_claims?, assertion_ttl_seconds?,
key_id?}`. Stored as JSONB; refs only, never the resolved key.

Distinct from `auth_oauth` (client-credentials with shared secret) and
`auth_authcode` (per-user delegated). The three are mutually
exclusive — schema validator prevents mixing.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260501_0011"
down_revision: str | None = "20260501_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "mcp_servers",
        sa.Column("auth_jwt_bearer", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("mcp_servers", "auth_jwt_bearer")
