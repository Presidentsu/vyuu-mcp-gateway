"""FastAPI dependency that authenticates operator-API requests.

The dependency reads `app.state.operator_auth` (an `OperatorAuthProvider`),
extracts the bearer token via FastAPI's `HTTPBearer` security scheme, and
returns an `AuthenticatedOperator`. Missing token, malformed token, and
verification failure all map to HTTP 401 with `WWW-Authenticate: Bearer` so
clients get a uniform challenge surface — we deliberately do not distinguish
"no token" from "bad token" in the response, to avoid leaking which keys are
issued.
"""

from __future__ import annotations

from typing import Annotated, cast

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from vyuu_gateway.operator_auth.models import AuthenticatedOperator
from vyuu_gateway.operator_auth.provider import OperatorAuthError, OperatorAuthProvider

_bearer_scheme = HTTPBearer(auto_error=False)


def authenticate_operator(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(_bearer_scheme),
    ],
) -> AuthenticatedOperator:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    auth_provider = cast(OperatorAuthProvider, request.app.state.operator_auth)
    try:
        return auth_provider.authenticate(credentials.credentials)
    except OperatorAuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
