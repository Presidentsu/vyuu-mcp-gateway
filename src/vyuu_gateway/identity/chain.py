"""EMA-1 · ordered fall-through over multiple `IdentityProvider`s.

The inbound MCP endpoint holds exactly one provider on `app.state`;
this adapter lets that one slot try several credential mechanisms:

    ChainedIdentityProvider([
        ApiKeyIdentityProvider(...),   # vyuu_user_* bearers (existing)
        IdpJagIdentityProvider(...),   # Vyuu-minted EMA access tokens
    ])

Ordering contract: earlier providers are tried first, and every
provider must reject foreign credential shapes *cheaply* (the API-key
provider fails fast on non-`vyuu_user_` bearers before any DB work;
the EMA provider fails fast on non-JWT shapes before any crypto).
The chain therefore costs one string check per non-matching provider,
not one failed verification.

Error surface: the LAST provider's `IdentityValidationError` wins.
Callers convert any of them into the same opaque 401 +
`access_attempt` audit event, so which provider rejected is invisible
on the wire (anti-enumeration) while logs retain the specific reason.
"""

from __future__ import annotations

from uuid import UUID

from vyuu_gateway.identity.models import Principal
from vyuu_gateway.identity.provider import (
    IdentityCredentials,
    IdentityProvider,
    IdentityValidationError,
)


class ChainedIdentityProvider(IdentityProvider):
    def __init__(self, providers: list[IdentityProvider]) -> None:
        if not providers:
            raise ValueError("ChainedIdentityProvider requires at least one provider")
        self._providers = providers

    def validate_principal(
        self,
        *,
        tenant_id: UUID,
        credentials: IdentityCredentials,
    ) -> Principal:
        last: IdentityValidationError | None = None
        for provider in self._providers:
            try:
                return provider.validate_principal(
                    tenant_id=tenant_id, credentials=credentials
                )
            except IdentityValidationError as exc:
                last = exc
        assert last is not None  # non-empty chain ⇒ at least one raise
        raise last
