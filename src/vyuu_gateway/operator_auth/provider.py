"""Provider interface for operator-API authentication.

A real implementation will validate either an opaque API-key (looked up in a
key store) or an OIDC bearer token issued by the management plane. v1 ships
only `FakeOperatorAuthProvider` (HMAC-signed test tokens); production
implementations satisfy this Protocol and slot in via `create_app`.
"""

from __future__ import annotations

from typing import Protocol

from vyuu_gateway.operator_auth.models import AuthenticatedOperator


class OperatorAuthError(Exception):
    """Raised when a bearer token cannot be validated.

    Callers must map this to HTTP 401 — the message is *not* part of the
    public API and must not leak which keys exist or why validation failed.
    """


class OperatorAuthProvider(Protocol):
    def authenticate(self, token: str) -> AuthenticatedOperator:
        """Validate a bearer token and return the resolved operator.

        Raises `OperatorAuthError` for any verification failure.
        """
