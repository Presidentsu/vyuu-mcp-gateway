"""Production `IdentityProvider` — bearer-token-only validation.

The architectural shift vs `FakeIdentityProvider`:

The fake provider read `x-vyuu-tenant-id`, `x-vyuu-principal-id`, and
`x-vyuu-principal-display` from the request headers and trusted them.
That's correct for a lab where both sides are walked together — but
**production cannot do this**. The end-user's MCP client sets those
headers itself; trusting them means anyone who knows a `/v/{tenant}/...`
URL can claim to be any principal in any tenant.

This provider trusts ONLY the bearer token. Tenant + principal identity
are derived from the matched `user_api_keys` row. The `x-vyuu-*` headers
are ignored entirely — they're a fake-provider contract.

Hot path:
1. Pull `Authorization: Bearer ...` from credentials.headers.
2. Parse the bearer (`vyuu_user_<id>_<secret>`); reject malformed.
3. SELECT the `user_api_keys` row by id; reject if missing / revoked /
   expired.
4. bcrypt-verify the secret against `key_hash`; reject on mismatch.
5. SELECT the linked `users` row; reject if disabled / wrong tenant.
6. Return a Principal with `id=user.id` and `display=user.email`.

Updates `last_used_at` opportunistically — same transaction, so a slow
write doesn't fork a separate connection. If write fails (transient DB
issue), don't fail the whole request — auth already passed.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import User, UserApiKey
from vyuu_gateway.db.session import bind_tenant_context
from vyuu_gateway.identity.models import (
    ApiKeyPrincipal,
    Principal,
    PrincipalType,
)
from vyuu_gateway.identity.provider import (
    IdentityCredentials,
    IdentityProvider,
    IdentityValidationError,
)
from vyuu_gateway.users.api_keys import (
    MalformedApiKeyError,
    parse_bearer,
    verify_secret,
)

SessionFactory = Callable[[], Session]


class ApiKeyIdentityProvider(IdentityProvider):
    """Validates inbound MCP bearer tokens against `user_api_keys`."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def validate_principal(
        self,
        *,
        tenant_id: UUID,
        credentials: IdentityCredentials,
    ) -> Principal:
        bearer = _extract_bearer(credentials.headers)
        if bearer is None:
            raise IdentityValidationError("missing or malformed Authorization header")
        try:
            parsed = parse_bearer(bearer)
        except MalformedApiKeyError as exc:
            raise IdentityValidationError("invalid bearer token") from exc

        with self._session_factory() as session:
            bind_tenant_context(session, tenant_id)
            api_key = cast(
                UserApiKey | None,
                session.scalar(
                    select(UserApiKey).where(
                        UserApiKey.tenant_id == tenant_id,
                        UserApiKey.id == parsed.key_id,
                    )
                ),
            )
            if api_key is None:
                raise IdentityValidationError("invalid bearer token")
            if api_key.revoked_at is not None:
                raise IdentityValidationError("invalid bearer token")
            now = datetime.now(UTC)
            if api_key.expires_at is not None and api_key.expires_at <= now:
                raise IdentityValidationError("invalid bearer token")
            if not verify_secret(parsed.secret, api_key.key_hash):
                raise IdentityValidationError("invalid bearer token")

            user = cast(
                User | None,
                session.scalar(
                    select(User).where(
                        User.tenant_id == tenant_id,
                        User.id == api_key.user_id,
                    )
                ),
            )
            if user is None:
                raise IdentityValidationError("invalid bearer token")
            if user.disabled_at is not None:
                raise IdentityValidationError("invalid bearer token")

            # Snapshot fields BEFORE the commit. SQLAlchemy expires
            # instances on commit by default; subsequent attribute
            # access would trigger a refresh that we don't need.
            user_id = user.id
            user_display = user.display_name or user.email
            key_id = api_key.id

            api_key.last_used_at = now
            try:
                session.commit()
            except Exception:  # noqa: BLE001 - last_used_at is opportunistic
                session.rollback()

        return ApiKeyPrincipal(
            type=PrincipalType.API_KEY,
            tenant_id=tenant_id,
            id=str(user_id),
            display=user_display,
            key_id=str(key_id),
        )


def _extract_bearer(headers: dict[str, str]) -> str | None:
    """Return the bearer token from the `Authorization` header, or None
    if missing / malformed (handled identically to anti-enumerate)."""

    for name, value in headers.items():
        if name.lower() != "authorization":
            continue
        if not value.startswith("Bearer "):
            return None
        return value.removeprefix("Bearer ").strip() or None
    return None
