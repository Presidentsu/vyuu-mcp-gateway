"""Unit tests for `AwsSecretsManagerStore`.

Uses `botocore.stub.Stubber` — boto3's official testing primitive. No
live AWS calls; we declare the expected request shape + canned response
and the boto3 client returns that.

Why Stubber and not moto: Stubber is part of botocore (zero new deps)
and asserts the *exact* expected request — if our store fires the
wrong API call, the stub raises rather than silently returning a
default. Tighter contract, no mock framework drift.
"""

from __future__ import annotations

import asyncio
import json
from uuid import uuid4

import boto3
import pytest
from botocore.stub import Stubber

from vyuu_gateway.secrets import (
    AwsSecretsManagerBackendError,
    AwsSecretsManagerConfigurationError,
    AwsSecretsManagerStore,
    SecretNotFoundError,
)


def _stubbed_store(
    prefix: str = "vyuu", value_field: str | None = None
) -> tuple[AwsSecretsManagerStore, Stubber]:
    client = boto3.client("secretsmanager", region_name="us-east-1")
    stubber = Stubber(client)
    store = AwsSecretsManagerStore(
        prefix=prefix, value_field=value_field, client=client
    )
    return store, stubber


# --- Configuration ----------------------------------------------------------


def test_empty_prefix_raises() -> None:
    with pytest.raises(AwsSecretsManagerConfigurationError):
        AwsSecretsManagerStore(prefix="")


# --- Read path --------------------------------------------------------------


def test_read_returns_plaintext_secret_string() -> None:
    """Default value_field=None → the whole SecretString IS the value.
    This is the common case: operators paste a Bearer token directly."""
    store, stubber = _stubbed_store()
    tenant = uuid4()
    stubber.add_response(
        "get_secret_value",
        {"SecretString": "Bearer the-real-token", "Name": f"vyuu/{tenant}/paypal"},
        expected_params={"SecretId": f"vyuu/{tenant}/paypal"},
    )
    with stubber:
        value = asyncio.run(store.get_secret(tenant, "paypal"))
    assert value == "Bearer the-real-token"


def test_read_uses_configured_value_field_for_json_secret() -> None:
    """value_field set → SecretString is parsed as JSON and the field
    extracted. Mirrors the Vault store's value_field convention."""
    store, stubber = _stubbed_store(value_field="token")
    tenant = uuid4()
    body = json.dumps({"token": "abc123", "metadata": "ignored"})
    stubber.add_response(
        "get_secret_value",
        {"SecretString": body, "Name": f"vyuu/{tenant}/paypal"},
        expected_params={"SecretId": f"vyuu/{tenant}/paypal"},
    )
    with stubber:
        value = asyncio.run(store.get_secret(tenant, "paypal"))
    assert value == "abc123"


def test_resource_not_found_maps_to_secret_not_found() -> None:
    store, stubber = _stubbed_store()
    stubber.add_client_error(
        "get_secret_value",
        service_error_code="ResourceNotFoundException",
        service_message="Secrets Manager can't find the specified secret.",
        http_status_code=400,
    )
    with stubber, pytest.raises(SecretNotFoundError):
        asyncio.run(store.get_secret(uuid4(), "missing"))


def test_access_denied_does_not_silently_look_like_not_found() -> None:
    """Critical: an IAM permission error must surface as a backend
    error so operators see ACL misconfiguration. Masking it as
    not-found would let a misconfigured deployment look like
    "secret didn't exist" when the real cause is policy."""
    store, stubber = _stubbed_store()
    stubber.add_client_error(
        "get_secret_value",
        service_error_code="AccessDeniedException",
        service_message="not authorized",
        http_status_code=400,
    )
    with stubber, pytest.raises(AwsSecretsManagerBackendError):
        asyncio.run(store.get_secret(uuid4(), "paypal"))


def test_throttling_maps_to_backend_error() -> None:
    store, stubber = _stubbed_store()
    stubber.add_client_error(
        "get_secret_value",
        service_error_code="ThrottlingException",
        service_message="rate exceeded",
        http_status_code=400,
    )
    with stubber, pytest.raises(AwsSecretsManagerBackendError):
        asyncio.run(store.get_secret(uuid4(), "paypal"))


def test_secret_with_no_secret_string_raises_backend_error() -> None:
    """Binary-only secret (no `SecretString`) — we don't support it.
    The error tells the operator their secret shape is wrong rather
    than silently returning an empty string."""
    store, stubber = _stubbed_store()
    tenant = uuid4()
    stubber.add_response(
        "get_secret_value",
        {"Name": f"vyuu/{tenant}/y"},  # no SecretString
        expected_params={"SecretId": f"vyuu/{tenant}/y"},
    )
    with stubber, pytest.raises(AwsSecretsManagerBackendError, match="SecretString"):
        asyncio.run(store.get_secret(tenant, "y"))


def test_value_field_with_non_json_secret_raises() -> None:
    store, stubber = _stubbed_store(value_field="token")
    tenant = uuid4()
    stubber.add_response(
        "get_secret_value",
        {"SecretString": "not json", "Name": f"vyuu/{tenant}/y"},
        expected_params={"SecretId": f"vyuu/{tenant}/y"},
    )
    with stubber, pytest.raises(AwsSecretsManagerBackendError, match="not JSON"):
        asyncio.run(store.get_secret(tenant, "y"))


def test_value_field_missing_in_json_payload_raises() -> None:
    store, stubber = _stubbed_store(value_field="token")
    tenant = uuid4()
    body = json.dumps({"other": "field"})
    stubber.add_response(
        "get_secret_value",
        {"SecretString": body, "Name": f"vyuu/{tenant}/y"},
        expected_params={"SecretId": f"vyuu/{tenant}/y"},
    )
    with stubber, pytest.raises(AwsSecretsManagerBackendError, match="missing field"):
        asyncio.run(store.get_secret(tenant, "y"))


def test_per_tenant_prefix_isolates_paths() -> None:
    """Two tenants reading the same ref must hit different SecretIds."""
    store, stubber = _stubbed_store()
    tenant_a = uuid4()
    tenant_b = uuid4()
    stubber.add_response(
        "get_secret_value",
        {"SecretString": "a-value", "Name": f"vyuu/{tenant_a}/shared"},
        expected_params={"SecretId": f"vyuu/{tenant_a}/shared"},
    )
    stubber.add_response(
        "get_secret_value",
        {"SecretString": "b-value", "Name": f"vyuu/{tenant_b}/shared"},
        expected_params={"SecretId": f"vyuu/{tenant_b}/shared"},
    )
    with stubber:
        a = asyncio.run(store.get_secret(tenant_a, "shared"))
        b = asyncio.run(store.get_secret(tenant_b, "shared"))
    assert a == "a-value"
    assert b == "b-value"


def test_empty_ref_raises_secret_not_found() -> None:
    """Defense-in-depth: an accidental empty ref must not accidentally
    read `{prefix}/{tenant}/`."""
    store, _ = _stubbed_store()
    with pytest.raises(SecretNotFoundError):
        asyncio.run(store.get_secret(uuid4(), ""))


def test_custom_prefix_used_in_secret_id() -> None:
    """Operators with a different naming convention can override the
    prefix via VYUU_AWS_SECRETS_PREFIX."""
    store, stubber = _stubbed_store(prefix="acme/prod/vyuu")
    tenant = uuid4()
    stubber.add_response(
        "get_secret_value",
        {"SecretString": "v", "Name": f"acme/prod/vyuu/{tenant}/r"},
        expected_params={"SecretId": f"acme/prod/vyuu/{tenant}/r"},
    )
    with stubber:
        v = asyncio.run(store.get_secret(tenant, "r"))
    assert v == "v"


# --- health_check ----------------------------------------------------------


def test_health_check_ok_when_list_secrets_succeeds() -> None:
    store, stubber = _stubbed_store()
    stubber.add_response(
        "list_secrets",
        {"SecretList": []},
        expected_params={"MaxResults": 1},
    )
    with stubber:
        ok, detail = store.health_check()
    assert ok is True
    assert "reachable" in detail


def test_health_check_treats_list_secrets_access_denied_as_soft_warning() -> None:
    """Common production posture: gateway IAM has GetSecretValue but
    NOT list. We still know AWS is reachable — surface as ok-with-note."""
    store, stubber = _stubbed_store()
    stubber.add_client_error(
        "list_secrets",
        service_error_code="AccessDeniedException",
        service_message="not authorized to perform secretsmanager:ListSecrets",
        http_status_code=400,
    )
    with stubber:
        ok, detail = store.health_check()
    assert ok is True
    assert "list_secrets" in detail.lower() or "scoped" in detail.lower()


def test_health_check_returns_false_on_real_auth_failure() -> None:
    store, stubber = _stubbed_store()
    stubber.add_client_error(
        "list_secrets",
        service_error_code="UnrecognizedClientException",
        service_message="security token included in request is invalid",
        http_status_code=400,
    )
    with stubber:
        ok, detail = store.health_check()
    assert ok is False
    assert "UnrecognizedClient" in detail
