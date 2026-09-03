from collections.abc import Iterator
from uuid import UUID

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session, SessionTransaction, sessionmaker

from vyuu_gateway.config import get_settings

_settings = get_settings()
engine = create_engine(
    _settings.database_url,
    pool_pre_ping=True,
    pool_size=_settings.db_pool_size,
    max_overflow=_settings.db_pool_max_overflow,
    pool_timeout=_settings.db_pool_timeout_seconds,
    pool_recycle=_settings.db_pool_recycle_seconds,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Key under which the request's tenant id is stashed on `Session.info`. The
# `after_begin` listener below reads this on every transaction-begin to set
# the Postgres GUC that drives RLS. Centralised in one constant so it is hard
# to typo apart from the listener and the binder.
_TENANT_INFO_KEY = "tenant_id"


@event.listens_for(Session, "after_begin")
def _set_tenant_guc_on_transaction_begin(
    session: Session,
    transaction: SessionTransaction,  # noqa: ARG001 — required by the SQLAlchemy event signature
    connection: Connection,
) -> None:
    """Bind the request's tenant to every transaction this session opens.

    Why per-transaction instead of per-session: `set_config(..., is_local=true)`
    is cleared on commit/rollback, so a subsequent transaction on the same
    session would otherwise run with no GUC set. Hooking `after_begin` makes
    the binding survive multi-commit request handlers.

    Why class-level instead of instance-level: SQLAlchemy fires this once per
    session per transaction; registering on the `Session` class means we set
    up exactly one listener for the process. Per-session state is carried in
    `session.info` rather than via closures, which keeps the engine pool
    behaviour simple.

    Sessions that have not been tenant-bound (admin scripts, Alembic) are
    intentionally skipped — under a non-RLS-bypassing role this fails closed
    (queries see no rows). Admin contexts must connect as a role with
    BYPASSRLS or that owns the tenant-scoped tables.
    """

    tenant_id = session.info.get(_TENANT_INFO_KEY)
    if tenant_id is None:
        return
    connection.execute(
        text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
        {"tenant_id": str(tenant_id)},
    )


def bind_tenant_context(session: Session, tenant_id: UUID) -> None:
    """Pin every transaction this session opens to the given RLS tenant.

    Must be called before the first DB operation on the session (typically
    immediately after the session is opened by a FastAPI dependency).
    """

    session.info[_TENANT_INFO_KEY] = tenant_id


def get_db() -> Iterator[Session]:
    """Yield an unbound DB session.

    For migrations, admin scripts, and tests that do not need RLS-active
    behaviour. API request handlers must use `get_tenant_scoped_db` instead;
    an unbound session under a non-bypass role will see zero rows.
    """

    with SessionLocal() as session:
        yield session
