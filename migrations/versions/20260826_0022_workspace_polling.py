"""IDP-2 · Google Workspace directory polling

Revision ID: 20260826_0022
Revises: 20260825_0021
Create Date: 2026-08-26

Google Workspace **custom SAML apps do not support SCIM
auto-provisioning** — that is reserved for apps in Google's own catalog
(Slack, Salesforce, Notion, Atlassian…), where Google built and tested a
per-app connector. An app you create yourself gets SAML SSO and nothing
else.

The consequence for us: our SCIM endpoint never receives a push from
Workspace. Workspace tenants therefore run on JIT-create at first
sign-in, and **deprovisioning is manual** — which is precisely the
property enterprises adopt directory integration to get. Somebody
terminated in HR keeps working access until an operator notices.

This adds the columns for the other direction: the gateway polls the
Admin SDK Directory API and applies what it finds through the same code
paths SCIM uses.

`workspace_service_account_ref` is a **SecretStore reference**, not the
key. Service-account JSON is the credential for domain-wide delegation —
it can read every user in the customer's directory — so it belongs
wherever the deployment already keeps secrets, not in a Postgres column
that shows up in backups and `pg_dump` output.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260826_0022"
down_revision: str | None = "20260825_0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "idp_directories",
        sa.Column(
            "workspace_polling_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    # SecretStore ref for the service-account JSON. See module docstring
    # for why the material itself is not stored here.
    op.add_column(
        "idp_directories",
        sa.Column("workspace_service_account_ref", sa.Text(), nullable=True),
    )
    # Google's customer id, or the literal `my_customer` alias. Required
    # by `users.list`; without it the API returns everything the service
    # account can see, which across a reseller account is other people's
    # directories.
    op.add_column(
        "idp_directories",
        sa.Column("workspace_customer_id", sa.Text(), nullable=True),
    )
    # The delegated admin whose authority the service account borrows.
    # Domain-wide delegation impersonates a real user; Google refuses the
    # call without one.
    op.add_column(
        "idp_directories",
        sa.Column("workspace_admin_subject", sa.Text(), nullable=True),
    )
    op.add_column(
        "idp_directories",
        sa.Column(
            "workspace_last_polled_at", sa.DateTime(timezone=True), nullable=True
        ),
    )


def downgrade() -> None:
    for column in (
        "workspace_last_polled_at",
        "workspace_admin_subject",
        "workspace_customer_id",
        "workspace_service_account_ref",
        "workspace_polling_enabled",
    ):
        op.drop_column("idp_directories", column)
