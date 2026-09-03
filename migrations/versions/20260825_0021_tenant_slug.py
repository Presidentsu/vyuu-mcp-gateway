"""IDP-3 · per-tenant subdomain slug

Revision ID: 20260825_0021
Revises: 20260825_0020
Create Date: 2026-08-25

Today the portal sign-in page asks the user to paste a tenant UUID. The
stopgap (a `?tenant=<uuid>` link plus sessionStorage) works for returning
users on the same browser and nobody else. `tenants.slug` lets
`acme.gateway.example.com` resolve Acme without anyone typing anything.

NULLABLE, and unique only among non-NULL values: existing tenants have no
slug and keep working through the UUID path. Adopting a slug is opt-in
per tenant.

## The slug is a routing hint, never an authorization input

`Host` is attacker-controlled unless the reverse proxy pins it. Resolving
a tenant from it therefore grants **nothing** — it only decides which
login page to render. Authentication runs exactly as before, and the
issued session token carries the tenant it was minted for. A spoofed Host
shows someone the wrong login form; it cannot get them into another
tenant. Anything that later reads the slug for an access decision would
break that property, so don't.

## Why a CHECK constraint and not just app validation

The slug ends up in a hostname. A slug containing a dot would silently
extend the subdomain (`a.b` under `gateway.example.com` reads as a
different zone), and an uppercase or underscore slug is not a legal DNS
label. The database is the one place every writer passes through.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260825_0021"
down_revision: str | None = "20260825_0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("slug", sa.Text(), nullable=True))
    # Unique among non-NULLs. Postgres treats NULLs as distinct in a
    # unique index, which is exactly what we want here: many tenants with
    # no slug, at most one with any given slug.
    op.create_index(
        "tenants_slug_uq", "tenants", ["slug"], unique=True,
    )
    # A legal DNS label: lowercase alphanumerics and inner hyphens, 2..63
    # chars. No dots (would extend the subdomain), no leading/trailing
    # hyphen (illegal in DNS), no underscores.
    op.create_check_constraint(
        "tenants_slug_format_check",
        "tenants",
        "slug IS NULL OR slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'",
    )


def downgrade() -> None:
    op.drop_constraint("tenants_slug_format_check", "tenants", type_="check")
    op.drop_index("tenants_slug_uq", table_name="tenants")
    op.drop_column("tenants", "slug")
