"""Tenant-scoped secret store Protocol + in-memory implementation."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID


class SecretNotFoundError(Exception):
    """Requested secret reference does not exist for the given tenant.

    Carries no detail about which other tenants might own the same ref —
    operators get a clean "not found" without leaking cross-tenant info.
    """


class SecretStore(Protocol):
    """Resolves opaque tenant-scoped secret references to their values.

    Implementations:
    - `InMemorySecretStore` — dev / lab; refs map directly to literal values.
    - `VaultSecretStore` (future) — `secret/data/{tenant}/{ref}` lookup.
    - `AwsSecretsManagerStore` (future) — ARN or per-tenant prefix.

    The Protocol is async because production stores are network-bound. In-
    memory is implemented async too so consumers don't have to branch.
    """

    async def get_secret(self, tenant_id: UUID, ref: str) -> str:
        """Return the secret value for `(tenant_id, ref)`.

        Raises:
            SecretNotFoundError: if the ref does not exist for this tenant.
        """


class InMemorySecretStore:
    """In-process secret store for tests, the lab, and zero-dependency dev.

    Stores tenant-scoped `{ref → value}` pairs in a dict. Production
    deployments replace this with a real KMS-backed store; the Protocol
    contract is the same.

    Tenant scoping is enforced by the lookup key being `(tenant_id, ref)` —
    even if two tenants happen to use the same ref string ("api-key"), they
    resolve to different values and cross-tenant access raises
    `SecretNotFoundError`.

    Not thread-safe; the gateway is single-process and writes happen at
    bootstrap time, not in the hot path.
    """

    def __init__(self) -> None:
        self._secrets: dict[tuple[UUID, str], str] = {}

    def put(self, tenant_id: UUID, ref: str, value: str) -> None:
        """Lab / test helper to seed a secret. Production stores pull from
        a real KMS via their own provisioning path."""

        self._secrets[(tenant_id, ref)] = value

    async def get_secret(self, tenant_id: UUID, ref: str) -> str:
        try:
            return self._secrets[(tenant_id, ref)]
        except KeyError as exc:
            raise SecretNotFoundError(
                f"secret ref not found for tenant {tenant_id}: {ref!r}"
            ) from exc
