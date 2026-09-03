"""EMA-1 · MCP Enterprise-Managed Authorization (ID-JAG) inbound auth

Revision ID: 20260825_0016
Revises: 20260505_0015
Create Date: 2026-08-25

Two pieces of persistence for consuming the MCP Enterprise-Managed
Authorization extension (Okta "Cross App Access" et al.):

1. **`idp_directories` EMA trust config** — four columns that turn an
   already-connected directory (IDP-1) into a trusted ID-JAG issuer:

   - `ema_enabled`      — per-directory opt-in. Default false: connecting
                          a directory for SCIM/SSO does NOT silently start
                          accepting ID-JAGs from it.
   - `ema_audience`     — the audience the IdP must stamp on ID-JAGs =
                          our per-tenant resource-authorization-server
                          issuer id (e.g. `https://gw.acme.com/v/{tenant}`).
   - `ema_jwks_uri`     — optional explicit JWKS endpoint; when NULL the
                          gateway discovers it from `oidc_issuer`'s
                          `/.well-known/openid-configuration`.
   - `ema_allowed_client_ids` — JSONB array allowlist of MCP client ids
                          permitted to present ID-JAGs. Empty array =
                          accept any client the IdP already vetted (the
                          IdP's own policy gate ran at token-exchange).

   EMA is orthogonal to `signin_protocol` (which governs *human* SSO):
   a SAML-for-humans directory can still be EMA-enabled for agents.

2. **`ema_consumed_jti`** — replay cache for ID-JAG grant tokens. The
   ID-JAG is a single-use authorization grant (~300 s lifetime); the
   token endpoint records each `jti` on first redemption and rejects a
   second presentation within the grant's own `exp`. PK is
   `(tenant_id, jti)` — two tenants' IdPs could legitimately mint the
   same jti string. Rows are pruned by the hourly sweeper once
   `expires_at` passes; the table stays tiny.

RLS posture: `ema_consumed_jti` is ENABLE (not FORCE) like `users` —
the token endpoint writes under a tenant-bound session, while the
sweeper's untenanted prune scan relies on the owner exemption.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260825_0016"
down_revision: str | None = "20260505_0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- 1. idp_directories EMA trust config ---------------------------
    op.add_column(
        "idp_directories",
        sa.Column(
            "ema_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "idp_directories",
        sa.Column("ema_audience", sa.Text(), nullable=True),
    )
    op.add_column(
        "idp_directories",
        sa.Column("ema_jwks_uri", sa.Text(), nullable=True),
    )
    op.add_column(
        "idp_directories",
        sa.Column(
            "ema_allowed_client_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )

    # --- 2. ema_consumed_jti replay cache ------------------------------
    op.create_table(
        "ema_consumed_jti",
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("jti", sa.Text(), primary_key=True),
        sa.Column(
            "consumed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    # Prune scan: "delete everything whose grant lifetime has passed".
    op.create_index(
        "ema_consumed_jti_expires_idx",
        "ema_consumed_jti",
        ["expires_at"],
    )
    op.execute("ALTER TABLE ema_consumed_jti ENABLE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY ema_consumed_jti_tenant_isolation
        ON ema_consumed_jti
        USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        WITH CHECK (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP POLICY IF EXISTS ema_consumed_jti_tenant_isolation ON ema_consumed_jti"
    )
    op.drop_index("ema_consumed_jti_expires_idx", table_name="ema_consumed_jti")
    op.drop_table("ema_consumed_jti")
    for column in (
        "ema_allowed_client_ids",
        "ema_jwks_uri",
        "ema_audience",
        "ema_enabled",
    ):
        op.drop_column("idp_directories", column)
