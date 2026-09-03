"""Composed FastAPI dependencies for the operator API.

Lives at the API layer because it composes auth (which is an API concern) and
DB (which is a data-layer concern). The `db.session` module provides the
primitives; this module wires them into request-scoped dependencies that
endpoints can declare via `Depends(...)`.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from vyuu_gateway.db.session import SessionLocal, bind_tenant_context
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator


def get_tenant_scoped_db(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
) -> Iterator[Session]:
    """Yield a DB session pinned to the authenticated operator's tenant.

    Every transaction the session opens runs `set_config('app.current_tenant_id',
    :tenant_id, true)` first (via the `after_begin` listener registered in
    `db.session`). This is the single trusted entry point for tenant-scoped
    runtime DB access — endpoints must NOT use the unbound `get_db`.

    Note: only the FastAPI dependency-cache makes the duplicate
    `Depends(authenticate_operator)` (here and on the route) safe to evaluate
    once per request. Don't disable that cache without revisiting this dep.
    """

    with SessionLocal() as session:
        bind_tenant_context(session, operator.tenant_id)
        yield session
