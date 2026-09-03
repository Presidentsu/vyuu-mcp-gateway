"""BUG-SCIM-1 · let the SCIM auth step resolve a directory before it knows the tenant

Revision ID: 20260825_0019
Revises: 20260825_0018
Create Date: 2026-08-25

SCIM provisioning was returning 401 for every request, including with a
bearer the gateway itself had just minted.

Cause: `scim/auth.py` must resolve `idp_directories` by id *before* the
tenant is known — the directory row is what tells us the tenant. But
`idp_directories` is ENABLE + **FORCE** row-level security, so that
untenanted SELECT matched zero rows, the dependency read that as
"unknown directory", and returned the generic 401. Reproduced directly
against Postgres as role `vyuu` (not superuser, not BYPASSRLS, owns the
table):

    WITH GUC    -> 1 row
    WITHOUT GUC -> 0 rows

The same transaction then ran the `last_sync_at` heartbeat UPDATE, which
matched zero rows and committed silently — so the "directory is alive"
pill was dead too.

## Why a policy and not the alternatives

- **SECURITY DEFINER function**: does not help. FORCE RLS subjects the
  table *owner* to its own policies, and the function would run as that
  owner. Only a BYPASSRLS role escapes, and requiring one is a
  deployment-level privilege escalation we do not want to mandate.
- **Relax FORCE to plain ENABLE**: works, but the app connects as the
  owner, so it would exempt the *entire application* from RLS on a table
  holding SCIM token hashes and OIDC client-secret references. Tenant
  isolation there would rest solely on each query remembering its
  `tenant_id ==` predicate. That is the defense-in-depth we added FORCE
  to provide.
- **Put the tenant in the SCIM URL**: cleanest model, but changes the
  endpoint every already-configured IdP points at.

## What this does instead

A second PERMISSIVE, **SELECT-only** policy that grants the read only
when the caller has explicitly opted in for that transaction:

    app.current_tenant_id  IS NULL/empty   (no tenant bound yet)
    AND app.scim_bootstrap = 'on'          (deliberate, named capability)

`set_config(..., is_local => true)` makes the flag transaction-scoped, so
the capability cannot outlive the single lookup that needs it. An
*accidental* unbound query elsewhere still sees nothing, which is the
property that made FORCE worth having: the fix is an explicit door, not
a removed wall.

SELECT-only by construction — this policy can never permit a write.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260825_0019"
down_revision: str | None = "20260825_0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE POLICY idp_directories_scim_bootstrap
        ON idp_directories
        AS PERMISSIVE
        FOR SELECT
        USING (
            NULLIF(current_setting('app.current_tenant_id', TRUE), '') IS NULL
            AND current_setting('app.scim_bootstrap', TRUE) = 'on'
        )
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP POLICY IF EXISTS idp_directories_scim_bootstrap "
        "ON idp_directories"
    )
