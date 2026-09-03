"""EMA-1 · hot-path `IdentityProvider` for Vyuu-issued EMA access tokens.

Verifies the short-lived HS256 access token that OUR token endpoint
(`api/ema_oauth.py`) minted after validating an enterprise IdP's ID-JAG,
then maps the token's `sub` onto a directory user. This is deliberately
the *second* stage of the EMA design:

    ID-JAG (IdP-signed, RS256, JWKS, async)  →  /oauth/token   [once]
    Vyuu access token (HS256, local secret)  →  every /mcp call [here]

Keeping the hot path on a symmetric local verify means no JWKS fetch,
no network, and no async requirement inside the synchronous
`IdentityProvider` contract — ~microseconds per call vs the API-key
provider's ~50 ms bcrypt.

Enforcement notes (the parts EMA structurally lacks, preserved here):

- The token's `dir` claim must reference a directory that is STILL
  `ema_enabled` in this tenant — flipping the toggle off revokes every
  outstanding token instantly.
- The mapped user must not be disabled — SCIM deprovisioning or an
  operator disable cuts access mid-token-lifetime.
- vserver visibility / grants / policy still run downstream exactly as
  for API-key callers; this provider only answers "who is calling".

Chain behaviour: raises `IdentityValidationError` quickly for bearers
that are not Vyuu EMA tokens (`vyuu_user_*`, non-JWT shapes) so the
`ChainedIdentityProvider` can fall through without cost.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

import jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import IdpDirectory, User
from vyuu_gateway.db.session import bind_tenant_context
from vyuu_gateway.identity.models import FederatedUserPrincipal, Principal
from vyuu_gateway.identity.provider import (
    IdentityCredentials,
    IdentityProvider,
    IdentityValidationError,
)

SessionFactory = Callable[[], Session]

# Claims our token endpoint stamps into every access token it mints.
# `require` on decode makes a token missing any of them invalid even
# if the signature checks out — defense against a mint-path bug.
_REQUIRED_CLAIMS = ["iss", "aud", "sub", "exp", "iat", "dir"]


class IdpJagIdentityProvider(IdentityProvider):
    """Validates Vyuu-minted EMA access tokens on the inbound hot path."""

    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        signing_secret: str,
        issuer_base: str,
    ) -> None:
        if not signing_secret:
            raise ValueError("ema signing secret must be non-empty")
        self._session_factory = session_factory
        self._secret = signing_secret
        # Per-tenant issuer id: f"{issuer_base}/v/{tenant_id}". Matches
        # what `api/ema_oauth.py` mints and what RFC 9728 metadata
        # advertises.
        self._issuer_base = issuer_base.rstrip("/")

    def validate_principal(
        self,
        *,
        tenant_id: UUID,
        credentials: IdentityCredentials,
    ) -> Principal:
        token = _extract_bearer(credentials.headers)
        if token is None:
            raise IdentityValidationError("missing or malformed Authorization header")
        # Cheap chain fall-through: Vyuu API keys and other non-JWT
        # bearers never look like a three-segment JWT.
        if token.startswith("vyuu_") or token.count(".") != 2:
            raise IdentityValidationError("not an EMA access token")

        try:
            claims = jwt.decode(
                token,
                key=self._secret,
                algorithms=["HS256"],
                audience=str(tenant_id),
                issuer=f"{self._issuer_base}/v/{tenant_id}",
                options={"require": _REQUIRED_CLAIMS},
            )
        except jwt.InvalidTokenError as exc:
            raise IdentityValidationError("invalid EMA access token") from exc

        subject = claims.get("sub")
        directory_raw = claims.get("dir")
        if not isinstance(subject, str) or not subject:
            raise IdentityValidationError("invalid EMA access token")
        try:
            directory_id = UUID(str(directory_raw))
        except (ValueError, TypeError) as exc:
            raise IdentityValidationError("invalid EMA access token") from exc
        client_id = claims.get("client_id")
        # OAuth `scope` is a space-delimited string (RFC 6749 §3.3).
        raw_scope = claims.get("scope")
        scopes = frozenset(raw_scope.split()) if isinstance(raw_scope, str) else frozenset()

        with self._session_factory() as session:
            bind_tenant_context(session, tenant_id)
            directory = session.scalar(
                select(IdpDirectory).where(
                    IdpDirectory.tenant_id == tenant_id,
                    IdpDirectory.id == directory_id,
                    IdpDirectory.ema_enabled.is_(True),
                )
            )
            if directory is None:
                # Directory deleted or EMA toggled off since mint —
                # instant revocation of every outstanding token.
                raise IdentityValidationError("invalid EMA access token")

            # Same matching rule as OIDC/SAML sign-in + SCIM reconcile.
            # The token endpoint JIT-created this row at mint time, so a
            # miss here means the user was hard-deleted since — reject.
            user = session.scalar(
                select(User).where(
                    User.tenant_id == tenant_id,
                    User.idp_directory_id == directory.id,
                    User.external_id == subject,
                )
            )
            if user is None or user.disabled_at is not None:
                raise IdentityValidationError("invalid EMA access token")

            user_id = user.id
            display = user.display_name or user.email

        return FederatedUserPrincipal(
            tenant_id=tenant_id,
            id=str(user_id),
            display=display,
            external_id=subject,
            client_id=client_id if isinstance(client_id, str) else None,
            directory_id=str(directory_id),
            scopes=scopes,
        )


def _extract_bearer(headers: dict[str, str]) -> str | None:
    for name, value in headers.items():
        if name.lower() != "authorization":
            continue
        if not value.startswith("Bearer "):
            return None
        return value.removeprefix("Bearer ").strip() or None
    return None
