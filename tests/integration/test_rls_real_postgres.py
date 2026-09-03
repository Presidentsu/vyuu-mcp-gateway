"""End-to-end RLS verification against a real Postgres instance.

These tests are skipped unless the env var `VYUU_TEST_DATABASE_URL` is set to a
Postgres URL the test process can connect to as a role with privilege to
CREATE ROLE / GRANT (typically the database owner or a superuser). The role
is created fresh per module run, granted the minimum needed privileges,
exercised, and dropped on teardown.

What these tests prove:

1. The Alembic migrations themselves enable RLS on the right tables.
2. The `bind_tenant_context` + `after_begin` listener path actually issues
   `set_config('app.current_tenant_id', ...)` against real Postgres.
3. With a non-bypass role + GUC bound to tenant A, an *unfiltered* SELECT
   only returns tenant A rows. This is the regression test for "a repository
   bug forgets the tenant_id filter" — the spec mandates RLS as the
   defence-in-depth backstop.
4. With no GUC set + non-bypass role, queries return zero rows (fail closed).

These tests do real DDL and DML; do NOT point them at a production database.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

TEST_DB_URL = os.environ.get("VYUU_TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    TEST_DB_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set; skipping real-Postgres RLS integration tests",
)

# Tables we touch in this module. The order matters for cleanup (children
# before parents because of FK constraints).
_TENANT_SCOPED_TABLES = (
    "virtual_server_tools",
    "virtual_servers",
    "mcp_capabilities",
    "mcp_servers",
    "operators",
)


@pytest.fixture(scope="module")
def superuser_engine() -> Iterator[Engine]:
    """Engine connecting as the test database's owner / superuser.

    Used for setup / teardown DDL and for inserting fixture data (which
    requires bypassing RLS — owners and superusers do).
    """
    assert TEST_DB_URL is not None
    engine = create_engine(TEST_DB_URL, future=True)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module", autouse=True)
def applied_migrations(superuser_engine: Engine) -> Iterator[None]:
    """Apply Alembic migrations against the test DB before any test runs.

    Idempotent: a second run is a no-op when already at head.
    """
    # The Alembic env.py reads the URL via `get_settings().database_url`,
    # which is `lru_cache`-d. Override the env var and clear the cache so
    # migrations target the test DB without polluting global state for the
    # rest of the test session.
    from vyuu_gateway.config import get_settings

    original_url = os.environ.get("VYUU_DATABASE_URL")
    os.environ["VYUU_DATABASE_URL"] = TEST_DB_URL  # type: ignore[assignment]
    get_settings.cache_clear()

    cfg = AlembicConfig("alembic.ini")
    try:
        command.upgrade(cfg, "head")
        yield
    finally:
        if original_url is None:
            os.environ.pop("VYUU_DATABASE_URL", None)
        else:
            os.environ["VYUU_DATABASE_URL"] = original_url
        get_settings.cache_clear()


@pytest.fixture(scope="module")
def non_bypass_role(superuser_engine: Engine) -> Iterator[str]:
    """Create a role with NOBYPASSRLS for the duration of the module.

    Production gateway connections must run as a role like this. Tests use
    `SET ROLE "<role>"` from a superuser session to switch into it for the
    queries that need to be subject to RLS.
    """
    role = f"vyuu_rls_test_{uuid.uuid4().hex[:12]}"
    with superuser_engine.begin() as conn:
        conn.execute(text(f'CREATE ROLE "{role}" NOLOGIN NOBYPASSRLS'))
        # PostgreSQL 16 split role membership into ADMIN / INHERIT / SET.
        # A CREATEROLE user is still auto-granted membership in what it
        # creates, but with `set_option = false` — so `SET ROLE` below is
        # refused with "permission denied to set role", even though the
        # CREATE succeeded. Re-granting to ourselves WITH SET TRUE is
        # allowed because the auto-grant carries ADMIN OPTION.
        #
        # Guarded on the server version: `WITH SET` is a syntax error
        # before 16, where a plain membership grant already implied it.
        server_version = conn.exec_driver_sql("SHOW server_version_num").scalar()
        if int(server_version or 0) >= 160000:
            conn.execute(text(f'GRANT "{role}" TO CURRENT_USER WITH SET TRUE'))
        for table in _TENANT_SCOPED_TABLES:
            conn.execute(text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO "{role}"'))
        conn.execute(text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON tenants TO "{role}"'))
    try:
        yield role
    finally:
        with superuser_engine.begin() as conn:
            for table in (*_TENANT_SCOPED_TABLES, "tenants"):
                conn.execute(text(f'REVOKE ALL ON {table} FROM "{role}"'))
            conn.execute(text(f'DROP ROLE IF EXISTS "{role}"'))


@pytest.fixture
def two_tenant_setup(superuser_engine: Engine) -> Iterator[dict[str, dict[str, uuid.UUID]]]:
    """Insert two tenants, one operator each, one mcp_server each.

    Cleanup deletes by tenant id so two parallel runs of these tests don't
    step on each other.
    """
    tenant_a = {
        "tenant_id": uuid.uuid4(),
        "operator_id": uuid.uuid4(),
        "server_id": uuid.uuid4(),
    }
    tenant_b = {
        "tenant_id": uuid.uuid4(),
        "operator_id": uuid.uuid4(),
        "server_id": uuid.uuid4(),
    }

    for label, data in (("a", tenant_a), ("b", tenant_b)):
        _seed_tenant(superuser_engine, label=label, **data)

    try:
        yield {"a": tenant_a, "b": tenant_b}
    finally:
        _cleanup_tenants(superuser_engine, [tenant_a["tenant_id"], tenant_b["tenant_id"]])


def _seed_tenant(
    engine: Engine,
    *,
    label: str,
    tenant_id: uuid.UUID,
    operator_id: uuid.UUID,
    server_id: uuid.UUID,
) -> None:
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO tenants (id, name, tier) VALUES (:id, :name, 'shared')"),
            {"id": tenant_id, "name": f"rls-test-tenant-{label}-{tenant_id}"},
        )
        conn.execute(
            text(
                "INSERT INTO operators (id, tenant_id, email, role) "
                "VALUES (:id, :tid, :email, 'admin')"
            ),
            {
                "id": operator_id,
                "tid": tenant_id,
                "email": f"rls-test-{label}-{operator_id}@example.com",
            },
        )
        conn.execute(
            text(
                "INSERT INTO mcp_servers "
                "(id, tenant_id, display_name, source_type, source_location, "
                " transport, registered_by, args) "
                "VALUES (:id, :tid, :name, 'http', 'https://example.com/mcp', "
                "        'streamable_http', :op, '{}')"
            ),
            {
                "id": server_id,
                "tid": tenant_id,
                "name": f"rls-test-server-{label}-{server_id}",
                "op": operator_id,
            },
        )


def _cleanup_tenants(engine: Engine, tenant_ids: list[uuid.UUID]) -> None:
    with engine.begin() as conn:
        for tid in tenant_ids:
            for table in _TENANT_SCOPED_TABLES:
                conn.execute(
                    text(f"DELETE FROM {table} WHERE tenant_id = :t"),
                    {"t": tid},
                )
            conn.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": tid})


# --- Migration sanity ------------------------------------------------------------------------


def test_migrations_enable_rls_on_tenant_scoped_tables(superuser_engine: Engine) -> None:
    """Sanity check that the migrations actually turned RLS on. Without this
    the rest of the integration suite would silently pass for the wrong
    reason."""
    with superuser_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT relname, relrowsecurity FROM pg_class "
                "WHERE relname = ANY(:tables)"
            ),
            {"tables": list(_TENANT_SCOPED_TABLES)},
        ).all()

    rls_by_table: dict[str, bool] = {str(row[0]): bool(row[1]) for row in rows}
    for table in _TENANT_SCOPED_TABLES:
        assert rls_by_table.get(table) is True, f"RLS not enabled on {table}"


# --- The bind_tenant_context path runs set_config end-to-end ---------------------------------


def test_bind_tenant_context_runs_set_config_against_real_postgres(
    superuser_engine: Engine,
) -> None:
    """End-to-end: open a SessionLocal-style session, call bind_tenant_context,
    issue a query, and read back current_setting — proves the after_begin
    listener fires and set_config actually runs."""
    from vyuu_gateway.db.session import bind_tenant_context

    tenant_id = uuid.uuid4()
    session_factory = sessionmaker(bind=superuser_engine, autoflush=False, autocommit=False)

    with session_factory() as session:
        bind_tenant_context(session, tenant_id)
        observed = session.execute(
            text("SELECT current_setting('app.current_tenant_id', true)")
        ).scalar()

    assert observed == str(tenant_id)


def test_unbound_session_does_not_set_guc(superuser_engine: Engine) -> None:
    """A session that was not tenant-bound must leave the GUC unset — under a
    real RLS-enforcing role this is what makes the layer fail closed."""
    session_factory = sessionmaker(bind=superuser_engine, autoflush=False, autocommit=False)

    with session_factory() as session:
        observed = session.execute(
            text("SELECT current_setting('app.current_tenant_id', true)")
        ).scalar()

    # Postgres returns the empty string for a never-set GUC accessed via
    # current_setting(name, missing_ok=true).
    assert observed in (None, "")


# --- The "forgot tenant filter" regression -------------------------------------------------


def test_unfiltered_select_only_returns_bound_tenant_rows(
    superuser_engine: Engine,
    non_bypass_role: str,
    two_tenant_setup: dict[str, dict[str, uuid.UUID]],
) -> None:
    """Even a buggy SELECT that omits `WHERE tenant_id = ...` must not leak
    rows across tenants. RLS is the backstop."""
    tenant_a = two_tenant_setup["a"]
    tenant_b = two_tenant_setup["b"]

    with superuser_engine.connect() as conn:
        with conn.begin():
            conn.execute(text(f'SET ROLE "{non_bypass_role}"'))
            conn.execute(
                text("SELECT set_config('app.current_tenant_id', :t, true)"),
                {"t": str(tenant_a["tenant_id"])},
            )
            # Intentionally no WHERE tenant_id — simulates a repository bug.
            visible = {
                row[0]
                for row in conn.execute(
                    text("SELECT id FROM mcp_servers WHERE id IN (:a, :b)"),
                    {"a": tenant_a["server_id"], "b": tenant_b["server_id"]},
                ).all()
            }
            conn.execute(text("RESET ROLE"))

    assert tenant_a["server_id"] in visible
    assert tenant_b["server_id"] not in visible


def test_unset_guc_with_non_bypass_role_returns_zero_rows(
    superuser_engine: Engine,
    non_bypass_role: str,
    two_tenant_setup: dict[str, dict[str, uuid.UUID]],
) -> None:
    """No GUC + non-bypass role = RLS hides everything (fail closed)."""
    tenant_a = two_tenant_setup["a"]
    tenant_b = two_tenant_setup["b"]

    with superuser_engine.connect() as conn:
        with conn.begin():
            conn.execute(text(f'SET ROLE "{non_bypass_role}"'))
            visible_count = conn.execute(
                text("SELECT count(*) FROM mcp_servers WHERE id IN (:a, :b)"),
                {"a": tenant_a["server_id"], "b": tenant_b["server_id"]},
            ).scalar()
            conn.execute(text("RESET ROLE"))

    assert visible_count == 0


def test_guc_bound_to_other_tenant_hides_my_rows_even_by_id(
    superuser_engine: Engine,
    non_bypass_role: str,
    two_tenant_setup: dict[str, dict[str, uuid.UUID]],
) -> None:
    """Even a SELECT BY ID for tenant A's row, run with the GUC bound to
    tenant B, returns zero rows. Confirms RLS isn't trivially bypassable
    by knowing the row's primary key."""
    tenant_a = two_tenant_setup["a"]
    tenant_b = two_tenant_setup["b"]

    with superuser_engine.connect() as conn:
        with conn.begin():
            conn.execute(text(f'SET ROLE "{non_bypass_role}"'))
            conn.execute(
                text("SELECT set_config('app.current_tenant_id', :t, true)"),
                {"t": str(tenant_b["tenant_id"])},
            )
            row = conn.execute(
                text("SELECT id FROM mcp_servers WHERE id = :a"),
                {"a": tenant_a["server_id"]},
            ).first()
            conn.execute(text("RESET ROLE"))

    assert row is None


def test_session_local_with_bind_under_non_bypass_role_only_sees_bound_tenant(
    superuser_engine: Engine,
    non_bypass_role: str,
    two_tenant_setup: dict[str, dict[str, uuid.UUID]],
) -> None:
    """Same regression as `test_unfiltered_select_...` but exercising the full
    bind_tenant_context + Session path used by the API. Proves the production
    code path (not just hand-crafted SQL) gets RLS enforcement."""
    from vyuu_gateway.db.session import bind_tenant_context

    tenant_a = two_tenant_setup["a"]
    tenant_b = two_tenant_setup["b"]
    session_factory = sessionmaker(bind=superuser_engine, autoflush=False, autocommit=False)

    with session_factory() as session:
        bind_tenant_context(session, tenant_a["tenant_id"])
        # Switch the connection to the non-bypass role for this transaction.
        # bind_tenant_context's after_begin listener has already fired by
        # the time the next execute runs the SELECT.
        session.execute(text(f'SET ROLE "{non_bypass_role}"'))
        visible = {
            row[0]
            for row in session.execute(
                text("SELECT id FROM mcp_servers WHERE id IN (:a, :b)"),
                {"a": tenant_a["server_id"], "b": tenant_b["server_id"]},
            ).all()
        }
        session.execute(text("RESET ROLE"))

    assert tenant_a["server_id"] in visible
    assert tenant_b["server_id"] not in visible


