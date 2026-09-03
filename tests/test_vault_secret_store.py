"""Unit tests for `VaultSecretStore`.

Uses an httpx `MockTransport` to stand in for a real Vault server —
no Docker / no live Vault dependency. Exercises the full read path
including KV v2 payload parsing, 404 → SecretNotFoundError mapping,
and 5xx → VaultBackendError mapping.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import uuid4

import httpx
import pytest

from vyuu_gateway.secrets import (
    SecretNotFoundError,
    VaultBackendError,
    VaultConfigurationError,
    VaultSecretStore,
)


def _kv2_response(value: str) -> bytes:
    """Build a Vault KV v2 read-response body: data.data.<field>."""
    return json.dumps(
        {
            "request_id": "00000000-0000-0000-0000-000000000000",
            "lease_id": "",
            "renewable": False,
            "lease_duration": 0,
            "data": {"data": {"value": value, "extra": "ignored"}},
        }
    ).encode("utf-8")


def _build_store(handler: Any, *, mount: str = "secret") -> VaultSecretStore:
    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(base_url="http://vault.test", transport=transport)
    return VaultSecretStore(
        base_url="http://vault.test",
        token="dev-token",
        mount=mount,
        http_client=client,
    )


# --- Configuration -------------------------------------------------------


def test_missing_base_url_raises() -> None:
    with pytest.raises(VaultConfigurationError):
        VaultSecretStore(base_url="", token="t")


def test_missing_token_raises() -> None:
    with pytest.raises(VaultConfigurationError):
        VaultSecretStore(base_url="http://vault.test", token="")


def test_empty_mount_raises() -> None:
    with pytest.raises(VaultConfigurationError):
        VaultSecretStore(base_url="http://vault.test", token="t", mount="")


# --- Read path -----------------------------------------------------------


def test_read_returns_value_field_from_kv2_payload() -> None:
    tenant = uuid4()
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, content=_kv2_response("the-secret"))

    store = _build_store(handler)
    value = asyncio.run(store.get_secret(tenant, "paypal-bearer"))

    assert value == "the-secret"
    assert len(captured) == 1
    assert captured[0].url.path == f"/v1/secret/data/{tenant}/paypal-bearer"
    assert captured[0].headers["X-Vault-Token"] == "dev-token"


def test_read_passes_namespace_header_when_configured() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, content=_kv2_response("x"))

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(base_url="http://vault.test", transport=transport)
    store = VaultSecretStore(
        base_url="http://vault.test",
        token="t",
        namespace="acme/finance",
        http_client=client,
    )
    asyncio.run(store.get_secret(uuid4(), "ref"))

    assert captured[0].headers["X-Vault-Namespace"] == "acme/finance"


def test_404_maps_to_secret_not_found() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, content=b'{"errors": []}')

    store = _build_store(handler)
    with pytest.raises(SecretNotFoundError):
        asyncio.run(store.get_secret(uuid4(), "missing-ref"))


def test_5xx_maps_to_vault_backend_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, content=b"sealed")

    store = _build_store(handler)
    with pytest.raises(VaultBackendError):
        asyncio.run(store.get_secret(uuid4(), "ref"))


def test_403_maps_to_vault_backend_error_not_not_found() -> None:
    """A permission error must NOT silently look like missing-secret —
    that would mask ACL misconfiguration."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, content=b'{"errors": ["permission denied"]}')

    store = _build_store(handler)
    with pytest.raises(VaultBackendError):
        asyncio.run(store.get_secret(uuid4(), "ref"))


def test_malformed_payload_maps_to_vault_backend_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json")

    store = _build_store(handler)
    with pytest.raises(VaultBackendError):
        asyncio.run(store.get_secret(uuid4(), "ref"))


def test_payload_missing_value_field_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        # data.data exists but has no `value` key — wrong-shape payload.
        return httpx.Response(
            200,
            content=json.dumps({"data": {"data": {"other": "x"}}}).encode("utf-8"),
        )

    store = _build_store(handler)
    with pytest.raises(VaultBackendError, match="missing field"):
        asyncio.run(store.get_secret(uuid4(), "ref"))


def test_custom_value_field_resolves() -> None:
    """Operators with a different KV-v2 convention can override the
    JSON field name."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=json.dumps({"data": {"data": {"token": "alt"}}}).encode("utf-8"),
        )

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(base_url="http://vault.test", transport=transport)
    store = VaultSecretStore(
        base_url="http://vault.test",
        token="t",
        value_field="token",
        http_client=client,
    )
    assert asyncio.run(store.get_secret(uuid4(), "ref")) == "alt"


def test_empty_ref_raises_secret_not_found() -> None:
    """Defense-in-depth — an accidental empty string at registration
    should never accidentally read `{mount}/data/{tenant}/`."""
    store = _build_store(lambda r: httpx.Response(200, content=_kv2_response("x")))
    with pytest.raises(SecretNotFoundError):
        asyncio.run(store.get_secret(uuid4(), ""))


def test_per_tenant_path_isolation() -> None:
    """Two reads for the same ref under different tenants must hit
    different Vault paths — proves the per-tenant URL scoping that the
    docstring claims."""
    captured_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_paths.append(request.url.path)
        return httpx.Response(200, content=_kv2_response("v"))

    store = _build_store(handler)
    tenant_a = uuid4()
    tenant_b = uuid4()
    asyncio.run(store.get_secret(tenant_a, "shared"))
    asyncio.run(store.get_secret(tenant_b, "shared"))

    assert captured_paths == [
        f"/v1/secret/data/{tenant_a}/shared",
        f"/v1/secret/data/{tenant_b}/shared",
    ]
    assert tenant_a != tenant_b
