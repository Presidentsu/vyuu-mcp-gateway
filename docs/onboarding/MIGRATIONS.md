# MIGRATIONS — writing new Alembic migrations

How to add a new migration without tripping over our conventions.

## Conventions

1. **One migration per logical change.** Don't bundle "add table foo" +
   "add column bar to baz" in one revision unless they're truly
   atomic. Smaller migrations are easier to revert.

2. **Filename pattern:** `YYYYMMDD_NNNN_short_description.py`.
   The `NNNN` increments per day (0001, 0002, ...). Example:
   `20260505_0015_tool_call_events.py`.

3. **Write a docstring** at the top explaining WHY, not WHAT. The
   `op.create_table(...)` is self-documenting; the rationale
   ("we needed durable persistence because the in-memory buffer
   reset on restart") isn't.

4. **`down_revision`** must point at the previous head. Find with
   `alembic history -r-1:head`.

5. **Both `upgrade()` and `downgrade()`** must be implemented. We
   don't run downgrades in production but tests rely on them and
   reviewers check both halves.

## Tenant-scoped tables

Every new tenant-scoped table needs:

1. A `tenant_id UUID NOT NULL FK to tenants(id) ON DELETE CASCADE`
2. RLS enabled (and usually `FORCE` — see below)
3. A tenant isolation policy
4. An index that starts with `tenant_id`

Template:

```python
def upgrade() -> None:
    op.create_table(
        "your_table_name",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # ... other columns ...
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "your_table_name_tenant_idx",
        "your_table_name",
        ["tenant_id"],
    )
    op.execute("ALTER TABLE your_table_name ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE your_table_name FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY your_table_name_tenant_isolation
        ON your_table_name
        USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        WITH CHECK (tenant_id = (NULLIF(current_setting('app.current_tenant_id', TRUE), ''))::uuid)
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP POLICY IF EXISTS your_table_name_tenant_isolation "
        "ON your_table_name"
    )
    op.drop_index("your_table_name_tenant_idx", table_name="your_table_name")
    op.drop_table("your_table_name")
```

## When to use FORCE RLS

Use `FORCE ROW LEVEL SECURITY` (in addition to `ENABLE`) when:

- The table holds **sensitive data** that must NEVER leak cross-tenant
  (audit, IdP config, SCIM tokens, secrets).
- A bug in app code that forgets `bind_tenant_context` should fail
  closed (zero rows) instead of leaking everything.

Use plain `ENABLE` (no FORCE) when:

- The owner role legitimately needs to scan across tenants for cron /
  background work (e.g., `users` is scanned by the SCIM sweeper).

Existing FORCE tables: `tool_call_events`, `admin_audit_log`,
`idp_directories`, `mcp_server_dcr_clients`.

## FK semantics

Pick the right `ondelete=`:

| `ondelete=` | When to use |
|---|---|
| `CASCADE` | Child rows must die with the parent (e.g., `user_api_keys → users`, anything `→ tenants`) |
| `SET NULL` | Child rows should outlive the parent (e.g., `tool_call_events.vserver_id → virtual_servers` — events outlive vservers for forensics) |
| `RESTRICT` | Block parent deletion if children exist (rarely used; usually we prefer SET NULL or CASCADE) |
| (no ondelete) | Default RESTRICT; usually a mistake. Be explicit. |

When using SET NULL, **denormalise the human-readable label** at write
time (`vserver_name`, `target_display`) so the row stays meaningful
after the FK target is gone.

## Indexes

Composite indexes always start with the highest-selectivity column
that filter queries use. For tenant-scoped tables that's
`(tenant_id, ...)` — every read query starts with `WHERE tenant_id = ?`
because of RLS.

Example pattern from `tool_call_events`:

```python
op.create_index("tool_call_events_tenant_occurred_idx",
                "tool_call_events", ["tenant_id", "occurred_at"])
op.create_index("tool_call_events_tenant_vserver_idx",
                "tool_call_events", ["tenant_id", "vserver_id", "occurred_at"])
op.create_index("tool_call_events_tenant_principal_idx",
                "tool_call_events", ["tenant_id", "principal_id", "occurred_at"])
```

Each covers a specific filter shape. Don't reuse one composite where
the column order is wrong — the planner won't be happy.

## Enums (text + check, not Postgres ENUM)

We use TEXT + CheckConstraint instead of native Postgres ENUM types:

```python
sa.CheckConstraint(
    "decision IN ('allow', 'deny', 'redact', 'rewrite')",
    name="your_table_name_decision_check",
),
```

Why: extending a native ENUM requires `ALTER TYPE ... ADD VALUE`
which can't run inside a transaction → hard to roll back. TEXT +
CHECK is a one-line migration and lets us add values trivially.

## Defaults

Use `server_default=` for column defaults that must be set during
migration backfill (existing rows). Don't rely on Python-side `default=`
for that — it only applies to new INSERTs from the ORM.

```python
sa.Column(
    "active",
    sa.Boolean(),
    nullable=False,
    server_default=sa.text("true"),
)
```

For JSONB defaults: `server_default=sa.text("'{}'::jsonb")`.

For timestamptz: `server_default=sa.func.now()`.

## Backfilling data

If you add a NOT NULL column to an existing table, backfill in the
same migration:

```python
def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("auth_method", sa.Text(), nullable=True),
    )
    op.execute("UPDATE users SET auth_method = 'local' WHERE auth_method IS NULL")
    op.alter_column("users", "auth_method", nullable=False)
```

Three-step pattern: nullable add → backfill → flip to NOT NULL. This
works on a single transaction; for large tables on prod consider
splitting into three deploys.

## Testing your migration

```bash
# Apply your migration
alembic upgrade head

# Reverse it
alembic downgrade -1

# Re-apply (proves both directions work)
alembic upgrade head

# Inspect the result
psql -d vyuu_gateway -c "\d your_table_name"
```

If you added an index, verify the planner uses it:

```sql
EXPLAIN ANALYZE SELECT * FROM your_table_name
  WHERE tenant_id = '<uuid>' AND your_filter = ...;
```

## Idempotent seeds

If you need to seed data from a migration (rare; usually do it from
`bootstrap.py` instead), use `ON CONFLICT DO NOTHING`:

```python
op.execute(
    """
    INSERT INTO your_table (id, name) VALUES
      ('00000000-...', 'seed-1'),
      ('00000000-...', 'seed-2')
    ON CONFLICT (id) DO NOTHING
    """
)
```

This is the same pattern `examples/lab_bootstrap.py` uses for the
drawio lab seed. Re-running the migration is safe.

## Don't

- ❌ Don't write a migration that requires manual operator action
  between `upgrade()` and being usable. Migrations should be
  self-contained.
- ❌ Don't use `op.execute` for things `op.*` already supports
  (`add_column`, `create_index`, etc.) — keeps the migration
  declarative and tooling-friendly.
- ❌ Don't bundle data migrations + schema migrations in the same
  revision unless they're truly atomic (an `ALTER + UPDATE` to
  backfill is fine; a "fix data quality issues" cleanup pass is not).
- ❌ Don't drop a column in the same revision that adds another
  column with the same name. Postgres handles it but it's confusing
  to review.
- ❌ Don't skip the `downgrade()` — even if you'd never run it in
  prod, tests need the round-trip and reviewers need the symmetry
  to verify intent.

## Checking + applying

```bash
# What's the current head?
alembic current

# Show the chain
alembic history

# Apply pending
alembic upgrade head

# Roll back one
alembic downgrade -1

# Roll back to a specific revision
alembic downgrade 20260504_0014

# Generate a fresh empty revision (you'll fill in upgrade/downgrade)
alembic revision -m "add foo column to bar"
```

## Where things live

- Migrations: [`migrations/versions/`](migrations/versions/)
- Alembic env config: [`migrations/env.py`](migrations/env.py) — reads
  `VYUU_DATABASE_URL`, imports `Base.metadata` from `db.models`
- Alembic CLI config: [`alembic.ini`](alembic.ini)

Most recent migration: `20260505_0015` (TOOL-EVENTS-1
`tool_call_events`).
