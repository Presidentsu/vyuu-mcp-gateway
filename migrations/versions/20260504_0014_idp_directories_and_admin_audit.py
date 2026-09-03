"""IdP directories (Entra / Workspace SCIM) + admin audit log

Revision ID: 20260504_0014
Revises: 20260503_0013
Create Date: 2026-05-04

IDP-1 phase 1 — schema foundation. Adds the persistence layer for:

1. **`idp_directories`** — per-tenant configuration of an Entra ID or
   Google Workspace directory. Stores the directory's display name +
   sign-in protocol choice (`oidc` or `saml`) + the SCIM bearer-token
   hash we mint when the admin connects the directory. The actual
   secrets (OIDC client_secret, SAML signing key) are routed through
   the existing `secret_store` (Vault / Postgres) via secret-ref
   pointers stored in JSONB; the table itself never holds plaintext
   long-lived credentials.

2. **`admin_audit_log`** — server-side persistent audit log of every
   admin action (user.disable, vserver.delete, grant.revoke,
   idp.connect, scim.deactivate_user, scim.hard_delete_user, etc.).
   Distinct from the in-memory `RecentAuditEmitter` ring buffer that
   captures inbound MCP tool calls — this one captures *what
   admins did to the platform*, with a long retention horizon.

3. **`users` extensions** — add `idp_directory_id` FK + `external_id`
   (the IdP's stable identifier for this user, e.g. Entra `objectId`
   or Workspace `id`). Unique `(tenant_id, idp_directory_id,
   external_id)` ensures a single user-row per IdP record. Add `'scim'`
   to the `auth_method` check constraint so SCIM-provisioned rows can
   be tagged distinctly from local / OIDC-JIT rows.

4. **`groups` extensions** — same pair of columns. SCIM pushes group
   membership; flat groups only (no nested-group expansion — that's
   parked per IDP-1 decision log).

RLS posture: both new tables are tenant-scoped and FORCE-RLS
enabled, mirroring `oauth_user_tokens` and `mcp_server_dcr_clients`.
The directory-id is sufficient for uniqueness on its own (one row
per directory); the `tenant_id` column on `idp_directories` is
required for the RLS policy + cascade cleanup when a tenant is
removed.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260504_0014"
down_revision: str | None = "20260503_0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- 1. idp_directories --------------------------------------------
    op.create_table(
        "idp_directories",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # 'entra' | 'google_workspace' — explicit kind so we can apply
        # provider-specific quirks (Entra PATCH `Operations[]`,
        # Workspace `members[]`).
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        # 'oidc' | 'saml' — the admin picks per-directory at connect
        # time. Both protocols are wired; this just controls which
        # branch handles sign-in for users provisioned by this directory.
        sa.Column("signin_protocol", sa.Text(), nullable=False),
        # SCIM bearer-token hash (argon2id). The plaintext is shown
        # once at connect-time so the admin can paste it into Entra /
        # Workspace's "Provisioning" config; we keep only the hash for
        # constant-time validation on incoming SCIM requests.
        sa.Column("scim_token_hash", sa.Text(), nullable=False),
        # OIDC config (when signin_protocol='oidc'). Stored inline since
        # issuer + client_id are not secrets; client_secret lives behind
        # `oidc_client_secret_ref` (resolved via secret_store).
        sa.Column("oidc_issuer", sa.Text(), nullable=True),
        sa.Column("oidc_client_id", sa.Text(), nullable=True),
        sa.Column("oidc_client_secret_ref", sa.Text(), nullable=True),
        # SAML config (when signin_protocol='saml').
        sa.Column("saml_entity_id", sa.Text(), nullable=True),
        sa.Column("saml_sso_url", sa.Text(), nullable=True),
        # The IdP's signing certificate (PEM). Public; safe to store inline.
        sa.Column("saml_idp_certificate", sa.Text(), nullable=True),
        # Optional metadata blob — captures provider-specific config
        # we don't promote to first-class columns (e.g., Workspace
        # customer_id, Entra app object_id).
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "last_sync_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "kind IN ('entra', 'google_workspace')",
            name="idp_directories_kind_check",
        ),
        sa.CheckConstraint(
            "signin_protocol IN ('oidc', 'saml')",
            name="idp_directories_signin_protocol_check",
        ),
        # One directory of a given kind per tenant — admins shouldn't
        # accidentally connect Entra twice in the same tenant. They
        # can still connect both Entra and Workspace simultaneously.
        sa.UniqueConstraint(
            "tenant_id", "kind", name="idp_directories_tenant_kind_uq"
        ),
    )
    op.create_index(
        "idp_directories_tenant_idx",
        "idp_directories",
        ["tenant_id"],
    )
    op.execute("ALTER TABLE idp_directories ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE idp_directories FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY idp_directories_tenant_isolation
        ON idp_directories
        USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        WITH CHECK (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        """
    )

    # --- 2. admin_audit_log --------------------------------------------
    # Persistent log of admin-driven mutations: who did what, when,
    # against which target, with optional structured detail. Sized for
    # long retention — this is the table compliance auditors read.
    op.create_table(
        "admin_audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # The acting operator. Nullable because system-driven actions
        # (SCIM sweeper, hard-delete cron) have no human author —
        # those rows record `actor_kind='system'` instead.
        sa.Column(
            "actor_operator_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operators.id", ondelete="SET NULL"),
            nullable=True,
        ),
        # 'operator' | 'system' | 'scim'. Lets the UI filter to "what
        # did Engineer X do this week" vs. "what did the SCIM sweeper
        # auto-trigger overnight".
        sa.Column("actor_kind", sa.Text(), nullable=False),
        # Free-text email captured at action time so the row stays
        # readable even if the operator account is later deleted
        # (FK is SET NULL above for the same reason).
        sa.Column("actor_display", sa.Text(), nullable=True),
        # Action verb in dotted form: "user.disable", "vserver.delete",
        # "grant.revoke", "idp.connect", "scim.deactivate_user",
        # "scim.hard_delete_user". Kept as free-text so we don't need
        # a migration every time a new admin endpoint lands.
        sa.Column("action", sa.Text(), nullable=False),
        # The thing acted upon. `target_kind` is the table-ish name
        # ('user', 'vserver', 'grant', 'idp_directory'); `target_id`
        # is its UUID; `target_display` is a human label captured at
        # action time (email / name / etc.).
        sa.Column("target_kind", sa.Text(), nullable=True),
        sa.Column(
            "target_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column("target_display", sa.Text(), nullable=True),
        # Structured detail — 'before' / 'after' for diffs, IP, UA,
        # request id, decision_note, etc. Kept as JSONB so the schema
        # can evolve without migrations.
        sa.Column(
            "detail",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "actor_kind IN ('operator', 'system', 'scim')",
            name="admin_audit_log_actor_kind_check",
        ),
    )
    # Tenant-scoped feed (the operator-console panel scans this).
    op.create_index(
        "admin_audit_log_tenant_occurred_idx",
        "admin_audit_log",
        ["tenant_id", "occurred_at"],
    )
    # Action-feed filter ("show me all `grant.revoke` events").
    op.create_index(
        "admin_audit_log_tenant_action_idx",
        "admin_audit_log",
        ["tenant_id", "action"],
    )
    # Per-target lookup ("show me everything that happened to user X").
    op.create_index(
        "admin_audit_log_target_idx",
        "admin_audit_log",
        ["tenant_id", "target_kind", "target_id"],
    )
    op.execute("ALTER TABLE admin_audit_log ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE admin_audit_log FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY admin_audit_log_tenant_isolation
        ON admin_audit_log
        USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        WITH CHECK (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        """
    )

    # --- 3. users extensions -------------------------------------------
    # The directory FK + external_id pair lets us look up "is this
    # SSO callback's `sub` claim already provisioned via SCIM?".
    op.add_column(
        "users",
        sa.Column(
            "idp_directory_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("idp_directories.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "users",
        sa.Column("external_id", sa.Text(), nullable=True),
    )
    # Unique pair per tenant — partial index because local + JIT-OIDC
    # rows have NULL external_id and we don't want them colliding.
    op.create_index(
        "users_directory_external_id_uq",
        "users",
        ["tenant_id", "idp_directory_id", "external_id"],
        unique=True,
        postgresql_where=sa.text("external_id IS NOT NULL"),
    )
    # Soft-delete grace period — set when SCIM deactivates a user.
    # The hard-delete sweeper picks rows older than 7d and removes
    # them; everything is captured in admin_audit_log.
    op.add_column(
        "users",
        sa.Column(
            "soft_deleted_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # Add 'scim' to the auth_method check.
    op.drop_constraint(
        "users_auth_method_check", "users", type_="check"
    )
    op.create_check_constraint(
        "users_auth_method_check",
        "users",
        "auth_method IN ('local', 'microsoft', 'google', 'scim')",
    )

    # --- 4. groups extensions -----------------------------------------
    op.add_column(
        "groups",
        sa.Column(
            "idp_directory_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("idp_directories.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "groups",
        sa.Column("external_id", sa.Text(), nullable=True),
    )
    op.create_index(
        "groups_directory_external_id_uq",
        "groups",
        ["tenant_id", "idp_directory_id", "external_id"],
        unique=True,
        postgresql_where=sa.text("external_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("groups_directory_external_id_uq", "groups")
    op.drop_column("groups", "external_id")
    op.drop_column("groups", "idp_directory_id")

    op.drop_constraint(
        "users_auth_method_check", "users", type_="check"
    )
    op.create_check_constraint(
        "users_auth_method_check",
        "users",
        "auth_method IN ('local', 'microsoft', 'google')",
    )
    op.drop_column("users", "soft_deleted_at")
    op.drop_index("users_directory_external_id_uq", "users")
    op.drop_column("users", "external_id")
    op.drop_column("users", "idp_directory_id")

    op.execute(
        "DROP POLICY IF EXISTS admin_audit_log_tenant_isolation "
        "ON admin_audit_log"
    )
    op.drop_index("admin_audit_log_target_idx", "admin_audit_log")
    op.drop_index("admin_audit_log_tenant_action_idx", "admin_audit_log")
    op.drop_index("admin_audit_log_tenant_occurred_idx", "admin_audit_log")
    op.drop_table("admin_audit_log")

    op.execute(
        "DROP POLICY IF EXISTS idp_directories_tenant_isolation "
        "ON idp_directories"
    )
    op.drop_index("idp_directories_tenant_idx", "idp_directories")
    op.drop_table("idp_directories")
