"""Unit tests for the secret-store Protocol + in-memory implementation."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from vyuu_gateway.secrets import (
    InMemorySecretStore,
    SecretNotFoundError,
)


def test_in_memory_store_resolves_seeded_ref() -> None:
    store = InMemorySecretStore()
    tenant = uuid4()
    store.put(tenant, "paypal-bearer", "Bearer rOaSeCrEt")

    value = asyncio.run(store.get_secret(tenant, "paypal-bearer"))

    assert value == "Bearer rOaSeCrEt"


def test_in_memory_store_is_tenant_scoped() -> None:
    """Two tenants using the same opaque ref must resolve to different
    values; cross-tenant access must raise rather than leak."""
    store = InMemorySecretStore()
    tenant_a = uuid4()
    tenant_b = uuid4()
    store.put(tenant_a, "api-key", "value-a")
    store.put(tenant_b, "api-key", "value-b")

    assert asyncio.run(store.get_secret(tenant_a, "api-key")) == "value-a"
    assert asyncio.run(store.get_secret(tenant_b, "api-key")) == "value-b"


def test_in_memory_store_raises_for_unknown_ref() -> None:
    store = InMemorySecretStore()

    with pytest.raises(SecretNotFoundError):
        asyncio.run(store.get_secret(uuid4(), "nonexistent"))


def test_in_memory_store_raises_for_cross_tenant_lookup() -> None:
    """Tenant A's secret must not be visible to tenant B even with the
    same ref string — the lookup key is `(tenant_id, ref)`."""
    store = InMemorySecretStore()
    tenant_a = uuid4()
    tenant_b = uuid4()
    store.put(tenant_a, "shared-name", "tenant-a-only")

    with pytest.raises(SecretNotFoundError):
        asyncio.run(store.get_secret(tenant_b, "shared-name"))
