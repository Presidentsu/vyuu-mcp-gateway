from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from vyuu_gateway.identity.models import Principal


@dataclass(frozen=True)
class IdentityCredentials:
    headers: dict[str, str] = field(default_factory=dict)


class IdentityValidationError(Exception):
    """Raised when request identity cannot be validated."""


class IdentityProvider(Protocol):
    def validate_principal(
        self,
        *,
        tenant_id: UUID,
        credentials: IdentityCredentials,
    ) -> Principal:
        """Validate request credentials and return a tenant-scoped principal."""
