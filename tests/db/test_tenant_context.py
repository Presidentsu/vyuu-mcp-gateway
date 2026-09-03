"""Unit tests for the RLS tenant-context binding mechanism.

These tests do not need real Postgres — they verify the mechanism (the
`after_begin` handler and the binder) by exercising it directly with a fake
SQLAlchemy connection. The end-to-end "real RLS hides cross-tenant rows"
guarantee is covered by the env-gated integration test in
`tests/integration/test_rls_real_postgres.py`.
"""

from typing import Any
from unittest.mock import MagicMock
from uuid import uuid4

from sqlalchemy import event
from sqlalchemy.orm import Session

from vyuu_gateway.db.session import (
    _set_tenant_guc_on_transaction_begin,
    bind_tenant_context,
)


def _capture_set_config_call(connection_mock: MagicMock) -> tuple[str, dict[str, Any]]:
    assert connection_mock.execute.call_count == 1
    args = connection_mock.execute.call_args.args
    sql = str(args[0])
    params = args[1]
    return sql, params


def test_handler_runs_set_config_when_session_is_tenant_bound() -> None:
    tenant_id = uuid4()
    session = MagicMock()
    session.info = {"tenant_id": tenant_id}
    connection = MagicMock()

    _set_tenant_guc_on_transaction_begin(session, MagicMock(), connection)

    sql, params = _capture_set_config_call(connection)
    assert "set_config" in sql
    assert "app.current_tenant_id" in sql
    assert params == {"tenant_id": str(tenant_id)}


def test_handler_passes_tenant_id_as_string_in_bound_parameter() -> None:
    """The tenant id must be a bound parameter, not interpolated into the SQL."""
    tenant_id = uuid4()
    session = MagicMock()
    session.info = {"tenant_id": tenant_id}
    connection = MagicMock()

    _set_tenant_guc_on_transaction_begin(session, MagicMock(), connection)

    sql, params = _capture_set_config_call(connection)
    # The tenant id must NOT appear in the SQL text itself — only in the params.
    assert str(tenant_id) not in sql
    assert params["tenant_id"] == str(tenant_id)


def test_handler_uses_local_scope_so_guc_clears_on_commit() -> None:
    """`is_local=true` (third arg to set_config) makes the GUC transaction-
    scoped. Without it the binding would persist on the underlying connection
    after commit and leak into the next checkout from the pool — i.e., one
    tenant's request would bind the next tenant's request.
    """
    session = MagicMock()
    session.info = {"tenant_id": uuid4()}
    connection = MagicMock()

    _set_tenant_guc_on_transaction_begin(session, MagicMock(), connection)

    sql, _params = _capture_set_config_call(connection)
    assert "true" in sql


def test_handler_skips_set_config_when_session_not_bound() -> None:
    session = MagicMock()
    session.info = {}
    connection = MagicMock()

    _set_tenant_guc_on_transaction_begin(session, MagicMock(), connection)

    connection.execute.assert_not_called()


def test_bind_tenant_context_stashes_tenant_in_session_info() -> None:
    session = MagicMock()
    session.info = {}
    tenant_id = uuid4()

    bind_tenant_context(session, tenant_id)

    assert session.info["tenant_id"] == tenant_id


def test_handler_runs_set_config_after_each_transaction_begin() -> None:
    """`after_begin` is per-transaction, not per-session. Every new
    transaction on a bound session must rebind the GUC because the previous
    one was cleared by commit/rollback (is_local=true)."""
    tenant_id = uuid4()
    session = MagicMock()
    session.info = {"tenant_id": tenant_id}
    connection = MagicMock()

    for _ in range(3):
        _set_tenant_guc_on_transaction_begin(session, MagicMock(), connection)

    assert connection.execute.call_count == 3


def test_listener_is_registered_on_session_class() -> None:
    """Smoke test for the import-time `@event.listens_for(Session, "after_begin")`.

    If this assertion ever fails, the GUC binding is silently dead — every
    request would run with no tenant binding and (under a non-bypass role)
    return zero rows. Fail loud here so the regression cannot land.
    """
    assert event.contains(
        Session, "after_begin", _set_tenant_guc_on_transaction_begin
    )
