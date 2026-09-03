"""Portal session JWTs.

Issued on successful login (local password OR OIDC). Carried as
`Authorization: Bearer <jwt>` on subsequent portal API calls. Distinct
from `vyuu_user_*` API keys (which are for MCP clients like Claude
Desktop, NOT browsers).

Format: HS256-signed JWT with `tenant_id`, `user_id`, `email`,
`auth_method`, `iat`, `exp`. The signing secret is
`Settings.portal_session_signing_secret` — production MUST set a long
random value (default is a dev placeholder).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import jwt


class SessionTokenError(Exception):
    """Session token failed verification (malformed / expired / signature)."""


@dataclass(frozen=True)
class PortalSession:
    """Verified portal-session claims. Returned to API handlers that
    accept session-cookie auth (the user portal endpoints in γ + δ)."""

    tenant_id: UUID
    user_id: UUID
    email: str
    auth_method: str


def issue_portal_session(
    *,
    tenant_id: UUID,
    user_id: UUID,
    email: str,
    auth_method: str,
    signing_secret: str,
    ttl_seconds: int,
    now: float | None = None,
) -> str:
    """Mint a signed session JWT. Caller stores in HTTP-only cookie OR
    returns to SPA for `Authorization: Bearer` use."""

    issued_at = int(now if now is not None else time.time())
    payload = {
        "iss": "vyuu-gateway",
        "iat": issued_at,
        "exp": issued_at + ttl_seconds,
        "tenant_id": str(tenant_id),
        "user_id": str(user_id),
        "email": email,
        "auth_method": auth_method,
    }
    return jwt.encode(payload, signing_secret, algorithm="HS256")


def verify_portal_session(token: str, *, signing_secret: str) -> PortalSession:
    """Verify a portal session JWT. Raises `SessionTokenError` on any
    failure with a sanitized class name (no claim leakage)."""

    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            signing_secret,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "iss", "tenant_id", "user_id"]},
            issuer="vyuu-gateway",
        )
    except jwt.ExpiredSignatureError as exc:
        raise SessionTokenError("session expired") from exc
    except jwt.InvalidTokenError as exc:
        raise SessionTokenError("invalid session token") from exc
    try:
        return PortalSession(
            tenant_id=UUID(claims["tenant_id"]),
            user_id=UUID(claims["user_id"]),
            email=claims.get("email", ""),
            auth_method=claims.get("auth_method", ""),
        )
    except (KeyError, ValueError) as exc:
        raise SessionTokenError("invalid session claims") from exc
