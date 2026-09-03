"""JIT-2 · per-tool just-in-time elevation

Revision ID: 20260825_0020
Revises: 20260825_0019
Create Date: 2026-08-25

JIT-1 elevates into a whole virtual server. The finer-grained — and more
common — ask is elevating into a *single tool*: "let me run `db.migrate`
for 20 minutes" while holding ordinary standing access to the rest of
the bundle.

## Why a separate table rather than a nullable `tool_name` on grants

`virtual_server_grants` is vserver-scoped end to end: the inbound
`access.py` check, the catalog, the identity graph and the NHI map all
read it as "may this principal reach this vserver". Adding a nullable
`exposed_tool_name` would change the meaning of every existing row and
of every query that does not filter on it — a silent widening in the
places that forgot. A parallel table means the old question keeps its old
answer, and the new question gets its own.

It also composes with where the check has to live. `tool_calls/lifecycle`
already gates on `required_scopes` immediately after tool resolution and
already knows the *exposed* (post-rename) tool name; the elevation check
belongs on that same line, so a denial is a `tool_call` event naming the
tool rather than an opaque connection-level 403.

## `virtual_servers.jit_tools` is independent of `jit_enabled`

Deliberately. The primary use case is "standing access to the bundle,
but `db.migrate` needs an elevation" — a vserver whose whole-bundle JIT
is *off*. Coupling the two would make the main case unreachable.

`jit_auto_approve` and `jit_require_justification` are shared: they
govern *how a request is decided*, which is the same question at either
granularity. `jit_tools` values are per-tool ceilings, independent of
`jit_max_duration_seconds` (which stays the whole-vserver ceiling).

## One queue

`access_requests` gains `exposed_tool_name` rather than growing a second
approval queue — same reasoning as JIT-1. The partial-unique index
becomes `(user_id, vserver_id, COALESCE(exposed_tool_name, ''))`:
`COALESCE` because NULLs compare distinct in a Postgres unique index,
which would have quietly dropped the original "one pending request per
(user, vserver)" guarantee for whole-vserver requests.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260825_0020"
down_revision: str | None = "20260825_0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- 1. Which tools are elevation-gated, and for how long ----------
    op.add_column(
        "virtual_servers",
        sa.Column(
            "jit_tools",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )

    # --- 2. The elevations themselves ----------------------------------
    op.create_table(
        "virtual_server_tool_grants",
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
        # The EXPOSED (post-rename) name, matching what the caller asks
        # for and what the lifecycle compares against. Not an FK to
        # `virtual_server_tools`: that table keys on the UPSTREAM name,
        # and re-pointing a rename must not silently transfer an
        # elevation to a different underlying tool.
        sa.Column("exposed_tool_name", sa.Text(), nullable=False),
        sa.Column("principal_kind", sa.Text(), nullable=False),
        sa.Column("principal_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "granted_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("operators.id"),
            nullable=True,
        ),
        sa.Column(
            "granted_via", sa.Text(), nullable=False, server_default=sa.text("'operator'")
        ),
        sa.Column("justification", sa.Text(), nullable=True),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        # NOT NULL, unlike the vserver-level grant. A permanent per-tool
        # grant is just an ordinary vserver grant with extra steps; if
        # someone wants standing access to a tool, they should get
        # standing access to the vserver that exposes it.
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "principal_kind IN ('user', 'group')",
            name="virtual_server_tool_grants_kind_check",
        ),
        sa.CheckConstraint(
            "granted_via IN ('operator', 'jit_auto', 'jit_approved')",
            name="virtual_server_tool_grants_via_check",
        ),
    )
    # The hot-path lookup: "does this principal hold a live elevation for
    # this tool?" — run once per gated tool call.
    op.create_index(
        "virtual_server_tool_grants_lookup_idx",
        "virtual_server_tool_grants",
        ["tenant_id", "vserver_id", "exposed_tool_name", "principal_id"],
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.create_index(
        "virtual_server_tool_grants_expiry_idx",
        "virtual_server_tool_grants",
        ["tenant_id", "expires_at"],
        postgresql_where=sa.text("revoked_at IS NULL"),
    )
    op.execute(
        "ALTER TABLE virtual_server_tool_grants ENABLE ROW LEVEL SECURITY"
    )
    op.execute(
        "ALTER TABLE virtual_server_tool_grants FORCE ROW LEVEL SECURITY"
    )
    op.execute(
        """
        CREATE POLICY virtual_server_tool_grants_tenant_isolation
        ON virtual_server_tool_grants
        USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        WITH CHECK (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        """
    )

    # --- 3. One approval queue, not two --------------------------------
    op.add_column(
        "access_requests",
        sa.Column("exposed_tool_name", sa.Text(), nullable=True),
    )
    op.drop_index(
        "access_requests_one_pending_per_target", table_name="access_requests"
    )
    # COALESCE because NULLs compare DISTINCT in a Postgres unique index:
    # without it, two whole-vserver pending requests for the same
    # (user, vserver) would both be allowed, silently dropping the
    # guarantee this index exists to provide.
    op.execute(
        """
        CREATE UNIQUE INDEX access_requests_one_pending_per_target
        ON access_requests (user_id, vserver_id, COALESCE(exposed_tool_name, ''))
        WHERE status = 'pending'
        """
    )


def downgrade() -> None:
    op.drop_index(
        "access_requests_one_pending_per_target", table_name="access_requests"
    )
    op.execute(
        """
        CREATE UNIQUE INDEX access_requests_one_pending_per_target
        ON access_requests (user_id, vserver_id)
        WHERE status = 'pending'
        """
    )
    op.drop_column("access_requests", "exposed_tool_name")

    op.execute(
        "DROP POLICY IF EXISTS virtual_server_tool_grants_tenant_isolation "
        "ON virtual_server_tool_grants"
    )
    op.drop_index(
        "virtual_server_tool_grants_expiry_idx",
        table_name="virtual_server_tool_grants",
    )
    op.drop_index(
        "virtual_server_tool_grants_lookup_idx",
        table_name="virtual_server_tool_grants",
    )
    op.drop_table("virtual_server_tool_grants")

    op.drop_column("virtual_servers", "jit_tools")
