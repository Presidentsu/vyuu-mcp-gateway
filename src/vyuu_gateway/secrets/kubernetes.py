"""A6.y · Kubernetes Secrets SecretStore.

Third implementation of the same `SecretStore` Protocol, after Vault
(A6) and AWS Secrets Manager (A6.x). For deployments already running in
Kubernetes that would rather not stand up a separate KMS.

## Why the API and not a mounted volume

A projected volume mount is simpler and, for most deployments, better —
kubelet handles refresh, nothing needs RBAC, and the gateway just reads
files. This backend exists for the case a mount does not cover: reading a
`Secret` the pod does not mount, either because it is provisioned after
start-up or because the set is not known at deploy time (a multi-tenant
gateway onboarding tenants without a pod restart).

Deployments that *can* mount should mount.

## Path convention, and why the tenant id is in the NAME

    namespace/<namespace>  ·  secret name: vyuu-<tenant_id>  ·  key: <ref>

Putting the tenant in the Secret name rather than the key means a
Kubernetes RBAC rule can scope access per tenant with
`resourceNames: ["vyuu-<tenant_id>"]` — which is the only granularity
RBAC offers for Secrets. Keying by tenant *inside* one Secret would make
every tenant's material reachable by anyone who can read that one object,
and RBAC could not tell them apart.

## Auth

In-cluster service-account token from the standard projected path, with
the cluster CA for TLS. No kubeconfig parsing, no client library: one
authenticated HTTPS GET against the API server is the whole protocol,
and pulling in `kubernetes` (a very large dependency) to make it would
be a poor trade.

The token is re-read from disk on every request rather than cached.
Projected service-account tokens are short-lived and rotated in place by
kubelet — caching one means the gateway starts failing authentication
roughly an hour after start-up, which is a genuinely miserable bug to
diagnose.
"""

from __future__ import annotations

import base64
import binascii
import logging
from pathlib import Path
from uuid import UUID

import httpx

from vyuu_gateway.secrets.store import SecretNotFoundError

logger = logging.getLogger(__name__)

# Where kubelet projects the pod's service-account credentials. Fixed by
# Kubernetes, not by us.
_SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
_TOKEN_PATH = _SA_DIR / "token"
_CA_PATH = _SA_DIR / "ca.crt"
_NAMESPACE_PATH = _SA_DIR / "namespace"


class KubernetesConfigurationError(Exception):
    """Constructed with invalid or missing configuration."""


class KubernetesBackendError(Exception):
    """The API server returned an unexpected error.

    Distinct from `SecretNotFoundError` on purpose, and for the same
    reason as the Vault backend: treating an outage as "secret missing"
    would turn a cluster problem into a silent authorization failure on
    every upstream at once.
    """


def secret_name_for(tenant_id: UUID, prefix: str = "vyuu") -> str:
    """The `Secret` object holding one tenant's material.

    Lowercased because Kubernetes object names must be RFC 1123 labels
    and a UUID's canonical form is already lowercase hex — but callers
    can pass a prefix, so normalise rather than assume.
    """

    return f"{prefix}-{tenant_id}".lower()


class KubernetesSecretStore:
    """Reads `Secret` resources via the Kubernetes API.

    Cheap to construct — no I/O, same as the other two backends, so
    importing this module in a test that never reads costs nothing.
    """

    def __init__(
        self,
        *,
        namespace: str | None = None,
        api_server: str = "https://kubernetes.default.svc",
        secret_name_prefix: str = "vyuu",
        timeout_seconds: float = 5.0,
        token_path: Path = _TOKEN_PATH,
        ca_path: Path = _CA_PATH,
        namespace_path: Path = _NAMESPACE_PATH,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._api_server = api_server.rstrip("/")
        self._prefix = secret_name_prefix
        self._timeout = timeout_seconds
        self._token_path = token_path
        self._ca_path = ca_path
        self._namespace = namespace or self._read_namespace(namespace_path)
        if not self._namespace:
            raise KubernetesConfigurationError(
                "namespace is required and could not be read from "
                f"{namespace_path} — set VYUU_K8S_NAMESPACE when running "
                "outside a pod"
            )
        self._injected_client = http_client
        self._client: httpx.AsyncClient | None = http_client

    @staticmethod
    def _read_namespace(path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8").strip() or None
        except OSError:
            return None

    def _read_token(self) -> str:
        """Read the service-account token fresh on every call.

        NOT cached: projected tokens are short-lived and rotated in place
        by kubelet. A cached token starts failing ~an hour after start-up,
        long after anyone would connect it to this code.
        """

        try:
            token = self._token_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise KubernetesBackendError(
                f"could not read service-account token at {self._token_path}: "
                f"{exc.__class__.__name__}"
            ) from exc
        if not token:
            raise KubernetesBackendError(
                f"service-account token at {self._token_path} is empty"
            )
        return token

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        self._client = httpx.AsyncClient(
            base_url=self._api_server, verify=self.verify_target()
        )
        return self._client

    def verify_target(self) -> str | bool:
        """What to hand httpx as `verify`.

        The cluster CA when it is present; otherwise the system trust
        store — **never** `False`. A missing CA file is a
        misconfiguration, not a reason to stop checking, and an
        unverified connection to the API server would expose every
        tenant's secrets to anyone able to intercept in-cluster traffic.

        Split out from client construction so the decision is testable
        without generating a certificate: what matters is the choice, and
        httpx's handling of a valid CA path is httpx's business.
        """

        return str(self._ca_path) if self._ca_path.is_file() else True

    async def aclose(self) -> None:
        if self._client is not None and self._injected_client is None:
            await self._client.aclose()
            self._client = None

    async def health_check(self) -> tuple[bool, str]:
        """Connectivity probe for the operator-UI secret-store panel."""

        client = self._ensure_client()
        try:
            response = await client.get(
                "/version",
                headers={"Authorization": f"Bearer {self._read_token()}"},
                timeout=self._timeout,
            )
        except KubernetesBackendError as exc:
            return False, str(exc)
        except httpx.HTTPError as exc:
            return False, f"network error: {exc.__class__.__name__}"
        if response.status_code == 200:
            try:
                version = response.json().get("gitVersion", "unknown")
            except ValueError:
                version = "unknown"
            return True, f"kubernetes api reachable ({version})"
        return False, f"kubernetes /version returned HTTP {response.status_code}"

    async def get_secret(self, tenant_id: UUID, ref: str) -> str:
        if not ref:
            raise SecretNotFoundError("empty secret ref")
        # A ref becomes a key inside a Secret, and a `/` would change
        # which API path we hit. Refuse rather than sanitise: silently
        # rewriting a ref would read a *different* secret than the
        # operator configured.
        if "/" in ref or ".." in ref:
            raise SecretNotFoundError(f"invalid secret ref: {ref!r}")

        name = secret_name_for(tenant_id, self._prefix)
        client = self._ensure_client()
        path = f"/api/v1/namespaces/{self._namespace}/secrets/{name}"
        try:
            response = await client.get(
                path,
                headers={"Authorization": f"Bearer {self._read_token()}"},
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise KubernetesBackendError(
                f"kubernetes read failed for ref {ref!r}: {exc.__class__.__name__}"
            ) from exc

        if response.status_code == 404:
            raise SecretNotFoundError(
                f"secret ref not found for tenant {tenant_id}: {ref!r}"
            )
        if response.status_code == 403:
            # Distinguished from 404 in the LOG but not in the raised
            # error: an operator debugging RBAC needs to know, while the
            # caller must not be able to probe which tenants exist.
            logger.warning(
                "kubernetes_secret_forbidden",
                extra={"secret": name, "namespace": self._namespace},
            )
            raise KubernetesBackendError(
                f"kubernetes denied access to secret {name!r} — check the "
                "service account's RBAC for this namespace"
            )
        if response.status_code >= 400:
            raise KubernetesBackendError(
                f"kubernetes returned {response.status_code} reading ref {ref!r}"
            )

        try:
            data = response.json()["data"]
        except (ValueError, KeyError, TypeError) as exc:
            raise KubernetesBackendError(
                f"kubernetes payload for ref {ref!r} was not a Secret"
            ) from exc
        if not isinstance(data, dict) or ref not in data:
            raise SecretNotFoundError(
                f"secret ref not found for tenant {tenant_id}: {ref!r}"
            )

        # Secret values are always base64 in the API representation.
        try:
            return base64.b64decode(data[ref], validate=True).decode("utf-8")
        except (binascii.Error, TypeError, ValueError, UnicodeDecodeError) as exc:
            raise KubernetesBackendError(
                f"secret ref {ref!r} is not valid base64-encoded UTF-8"
            ) from exc
