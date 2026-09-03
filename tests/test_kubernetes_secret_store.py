"""A6.y · Kubernetes Secrets `SecretStore` backend.

Third implementation of the same Protocol after Vault (A6) and AWS
(A6.x), so most of the surface is already pinned by those suites. What is
genuinely new here, and what these tests target:

- **One Secret per tenant.** `resourceNames` is the only per-object
  granularity Kubernetes RBAC offers for Secrets, so the tenant has to be
  in the object NAME. Keying by tenant inside one Secret would make every
  tenant's material reachable by anyone who can read that object, and
  RBAC could not tell them apart.
- **The token is re-read per request.** Projected service-account tokens
  are short-lived and rotated in place by kubelet; caching one means the
  gateway starts failing auth about an hour after start-up — a
  spectacularly confusing bug.
- **403 is not 404.** An outage or an RBAC gap must not be reported as
  "secret missing", which would turn a cluster problem into a silent
  authorization failure across every upstream at once.

The API server is stubbed via `httpx.MockTransport`; no cluster needed.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from vyuu_gateway.secrets.kubernetes import (
    KubernetesBackendError,
    KubernetesConfigurationError,
    KubernetesSecretStore,
    secret_name_for,
)
from vyuu_gateway.secrets.store import SecretNotFoundError

TENANT = uuid4()


def _b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


@pytest.fixture
def sa_files(tmp_path: Path) -> dict[str, Path]:
    token = tmp_path / "token"
    token.write_text("sa-token-v1")
    namespace = tmp_path / "namespace"
    namespace.write_text("vyuu-prod\n")
    return {"token": token, "namespace": namespace, "ca": tmp_path / "ca.crt"}


def _store(
    sa_files: dict[str, Path],
    handler: Any,
    **kwargs: Any,
) -> KubernetesSecretStore:
    return KubernetesSecretStore(
        token_path=sa_files["token"],
        ca_path=sa_files["ca"],
        namespace_path=sa_files["namespace"],
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="https://k8s.test"
        ),
        **kwargs,
    )


async def _get(store: KubernetesSecretStore, ref: str) -> str:
    return await store.get_secret(TENANT, ref)


# --- Per-tenant object naming -----------------------------------------------


def test_tenant_is_in_the_secret_name_not_the_key() -> None:
    """`resourceNames: ["vyuu-<tenant>"]` is the only way RBAC can scope
    Secret access per tenant."""

    assert secret_name_for(TENANT) == f"vyuu-{TENANT}".lower()
    assert secret_name_for(TENANT, "acme") == f"acme-{TENANT}".lower()


def test_read_targets_the_tenant_scoped_object(sa_files: dict[str, Path]) -> None:
    import asyncio

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, json={"data": {"api-key": _b64("s3cret")}})

    store = _store(sa_files, handler)
    assert asyncio.run(_get(store, "api-key")) == "s3cret"
    assert seen == [f"/api/v1/namespaces/vyuu-prod/secrets/vyuu-{TENANT}".lower()]


# --- Token freshness --------------------------------------------------------


def test_token_is_reread_on_every_request(sa_files: dict[str, Path]) -> None:
    """kubelet rotates projected tokens in place. A cached token starts
    failing ~an hour after start-up, long after anyone would connect the
    failure to this code."""

    import asyncio

    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["Authorization"])
        return httpx.Response(200, json={"data": {"k": _b64("v")}})

    store = _store(sa_files, handler)
    asyncio.run(_get(store, "k"))
    sa_files["token"].write_text("sa-token-v2")  # kubelet rotates it
    asyncio.run(_get(store, "k"))

    assert seen == ["Bearer sa-token-v1", "Bearer sa-token-v2"]


def test_unreadable_token_is_a_backend_error(sa_files: dict[str, Path]) -> None:
    import asyncio

    sa_files["token"].unlink()
    store = _store(sa_files, lambda r: httpx.Response(200, json={"data": {}}))
    with pytest.raises(KubernetesBackendError, match="service-account token"):
        asyncio.run(_get(store, "k"))


# --- Not-found vs broken ----------------------------------------------------


def test_missing_secret_object_is_not_found(sa_files: dict[str, Path]) -> None:
    import asyncio

    store = _store(sa_files, lambda r: httpx.Response(404, json={}))
    with pytest.raises(SecretNotFoundError):
        asyncio.run(_get(store, "k"))


def test_missing_key_inside_the_secret_is_not_found(sa_files: dict[str, Path]) -> None:
    import asyncio

    store = _store(
        sa_files, lambda r: httpx.Response(200, json={"data": {"other": _b64("v")}})
    )
    with pytest.raises(SecretNotFoundError):
        asyncio.run(_get(store, "k"))


def test_forbidden_is_a_backend_error_not_not_found(sa_files: dict[str, Path]) -> None:
    """An RBAC gap reported as "secret missing" turns a cluster
    misconfiguration into a silent authorization failure on every
    upstream simultaneously — and the operator has nothing to grep for."""

    import asyncio

    store = _store(sa_files, lambda r: httpx.Response(403, json={}))
    with pytest.raises(KubernetesBackendError, match="RBAC"):
        asyncio.run(_get(store, "k"))


def test_server_error_is_a_backend_error(sa_files: dict[str, Path]) -> None:
    import asyncio

    store = _store(sa_files, lambda r: httpx.Response(500, json={}))
    with pytest.raises(KubernetesBackendError):
        asyncio.run(_get(store, "k"))


def test_network_failure_is_a_backend_error(sa_files: dict[str, Path]) -> None:
    import asyncio

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    store = _store(sa_files, handler)
    with pytest.raises(KubernetesBackendError):
        asyncio.run(_get(store, "k"))


# --- Ref hygiene + decoding -------------------------------------------------


@pytest.mark.parametrize("bad", ["", "a/b", "../escape", "x/../y"])
def test_refs_that_could_change_the_api_path_are_refused(
    sa_files: dict[str, Path], bad: str
) -> None:
    """Refused rather than sanitised: silently rewriting a ref would read
    a *different* secret than the operator configured."""

    import asyncio

    def explode(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not reach the API server")

    store = _store(sa_files, explode)
    with pytest.raises(SecretNotFoundError):
        asyncio.run(_get(store, bad))


def test_non_base64_value_is_a_backend_error(sa_files: dict[str, Path]) -> None:
    import asyncio

    store = _store(
        sa_files, lambda r: httpx.Response(200, json={"data": {"k": "!!!not-b64!!!"}})
    )
    with pytest.raises(KubernetesBackendError, match="base64"):
        asyncio.run(_get(store, "k"))


def test_non_secret_payload_is_a_backend_error(sa_files: dict[str, Path]) -> None:
    import asyncio

    store = _store(sa_files, lambda r: httpx.Response(200, json={"kind": "Pod"}))
    with pytest.raises(KubernetesBackendError, match="not a Secret"):
        asyncio.run(_get(store, "k"))


# --- Construction -----------------------------------------------------------


def test_namespace_is_read_from_the_projected_volume(sa_files: dict[str, Path]) -> None:
    store = _store(sa_files, lambda r: httpx.Response(200, json={"data": {}}))
    assert store._namespace == "vyuu-prod"  # noqa: SLF001


def test_missing_namespace_outside_a_pod_is_refused(tmp_path: Path) -> None:
    """Running outside a cluster, there is no namespace to infer. Failing
    at construction beats failing on the first secret read, hours later,
    inside an upstream call."""

    with pytest.raises(KubernetesConfigurationError, match="VYUU_K8S_NAMESPACE"):
        KubernetesSecretStore(
            token_path=tmp_path / "nope",
            ca_path=tmp_path / "nope",
            namespace_path=tmp_path / "nope",
        )


def test_explicit_namespace_overrides_the_volume(sa_files: dict[str, Path]) -> None:
    store = _store(
        sa_files, lambda r: httpx.Response(200, json={"data": {}}), namespace="other"
    )
    assert store._namespace == "other"  # noqa: SLF001


def test_health_check_reports_the_api_version(sa_files: dict[str, Path]) -> None:
    import asyncio

    store = _store(
        sa_files, lambda r: httpx.Response(200, json={"gitVersion": "v1.31.2"})
    )
    ok, detail = asyncio.run(store.health_check())
    assert ok is True
    assert "v1.31.2" in detail


# --- TLS ---------------------------------------------------------------------
#
# These build the client for real (no injected transport), because that
# is the only path where `verify` is decided — and an unverified
# connection to the API server would expose every tenant's secrets to
# anyone able to intercept in-cluster traffic.


def test_cluster_ca_is_used_to_verify_the_api_server(
    sa_files: dict[str, Path], tmp_path: Path
) -> None:
    ca = tmp_path / "ca.crt"
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    store = KubernetesSecretStore(
        token_path=sa_files["token"],
        ca_path=ca,
        namespace_path=sa_files["namespace"],
    )
    assert store.verify_target() == str(ca)


def test_missing_ca_falls_back_to_the_system_trust_store_not_to_no_tls(
    sa_files: dict[str, Path], tmp_path: Path
) -> None:
    """A missing CA file is a misconfiguration, not a reason to stop
    checking. `verify=False` here would be a silent downgrade that
    exposes every tenant's secrets to in-cluster interception."""

    store = KubernetesSecretStore(
        token_path=sa_files["token"],
        ca_path=tmp_path / "definitely-absent.crt",
        namespace_path=sa_files["namespace"],
    )
    assert store.verify_target() is True


def test_verification_is_never_disabled(
    sa_files: dict[str, Path], tmp_path: Path
) -> None:
    """The property that must hold however the CA path is configured."""

    for ca in (tmp_path / "absent.crt", sa_files["namespace"]):
        store = KubernetesSecretStore(
            token_path=sa_files["token"],
            ca_path=ca,
            namespace_path=sa_files["namespace"],
        )
        assert store.verify_target() is not False
