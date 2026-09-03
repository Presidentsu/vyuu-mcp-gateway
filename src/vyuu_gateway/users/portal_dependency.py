"""FastAPI dependency that authenticates portal-session requests.

End-user portal endpoints (γ + δ) accept the HS256 session JWT minted
by `/auth/{tenant_id}/login` (β). The dependency reads
`Settings.portal_session_signing_secret` from `app.state.settings`,
extracts the bearer via `HTTPBearer`, and returns a verified
`PortalSession` dataclass.

Cross-tenant defense: the route declares `tenant_id` as a path param;
the endpoint MUST compare `session.tenant_id == path_tenant_id` and
401/403 on mismatch. We don't fold the comparison into this dep
because it depends on the path param, which the dep can't see without
extra wiring.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated, cast

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from vyuu_gateway.config import Settings
from vyuu_gateway.db.session import SessionLocal, bind_tenant_context
from vyuu_gateway.users.sessions import (
    PortalSession,
    SessionTokenError,
    verify_portal_session,
)

_portal_bearer = HTTPBearer(auto_error=False)


def authenticate_portal_session(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(_portal_bearer),
    ],
) -> PortalSession:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    settings = cast(Settings, request.app.state.settings)
    try:
        return verify_portal_session(
            credentials.credentials,
            signing_secret=settings.portal_session_signing_secret,
        )
    except SessionTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid session token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def get_portal_scoped_db(
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
) -> Iterator[Session]:
    """Yield a DB session pinned to the authenticated portal user's
    tenant. RLS-equivalent scoping for portal endpoints."""

    with SessionLocal() as db:
        bind_tenant_context(db, session.tenant_id)
        yield db
