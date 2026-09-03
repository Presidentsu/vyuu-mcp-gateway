"""HashiCorp Vault SecretStore — KV v2 backend.

Resolves `(tenant_id, ref)` to a secret value via Vault's HTTP API.
Path convention:

    {mount}/data/{tenant_id}/{ref}

The KV v2 secret payload is `{"data": {"data": {"value": "<secret>"}}}`.
We pull `data.data.value` by default; the JSON key inside the secret is
configurable via `value_field` if your provisioning convention differs.

Auth: the simplest production-viable mode — static Vault token via
`VYUU_VAULT_TOKEN`. AppRole / k8s auth / agent sidecar are real-world
options but each is its own infra story; defer to a follow-up. The
Protocol is unchanged either way — only this module's `__init__` would
grow new auth modes.

Why per-tenant path prefix: Vault's namespacing + ACL templates can
trivially gate `{mount}/data/{tenant_id}/*` by tenant identity, so a
multi-tenant deployment can hand each tenant its own write-scoped token
without cross-tenant leakage. The gateway always passes `tenant_id` on
every read, so even a misconfigured ACL gets defense-in-depth.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

import httpx

from vyuu_gateway.secrets.store import SecretNotFoundError

logger = logging.getLogger(__name__)


class VaultConfigurationError(Exception):
    """The Vault SecretStore was constructed with invalid / missing config."""


class VaultBackendError(Exception):
    """Vault returned an unexpected error (network, 5xx, malformed body).

    Distinct from `SecretNotFoundError`. Operators see this as 502 from
    the upstream-call wrapper that already exists for `auth_headers`/
    `auth_env` resolution; backend errors should not be silently treated
    as missing-secret because that would mask outages.
    """


class VaultSecretStore:
    """Read-only Vault KV v2 client. Implements the `SecretStore` Protocol.

    Cheap to construct — no I/O. The httpx client is created lazily on
    first read to avoid penalising tests that import this module but
    never make a request.
    """

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        mount: str = "secret",
        namespace: str | None = None,
        value_field: str = "value",
        timeout_seconds: float = 5.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if not base_url:
            raise VaultConfigurationError("VYUU_VAULT_ADDR / base_url is required")
        if not token:
            raise VaultConfigurationError("VYUU_VAULT_TOKEN / token is required")
        if not mount:
            raise VaultConfigurationError("Vault mount must be a non-empty string")
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._mount = mount.strip("/")
        self._namespace = namespace
        self._value_field = value_field
        self._timeout = timeout_seconds
        # Tests / advanced wiring can inject a pre-built client (e.g. with
        # a transport mock). Production builds one lazily so we never make
        # an unnecessary network handle.
        self._injected_client = http_client
        self._client: httpx.AsyncClient | None = http_client

    async def aclose(self) -> None:
        # Only close clients we built ourselves — never the injected one.
        if self._client is not None and self._injected_client is None:
            await self._client.aclose()
            self._client = None

    async def health_check(self) -> tuple[bool, str]:
        """Connectivity probe used by the operator-UI panel.

        Returns `(ok, detail)`. Hits Vault's standard `/v1/sys/health`
        endpoint (auth-free, returns the seal status). Reports `ok=True`
        on 200 (initialized + unsealed + active) or 429 (standby —
        active node elsewhere, our reads will follow active). Anything
        else flips ok to False with the status code in the detail."""

        client = self._ensure_client()
        try:
            response = await client.get("/v1/sys/health", timeout=self._timeout)
        except httpx.HTTPError as exc:
            return False, f"network error: {exc.__class__.__name__}"
        # Vault uses non-standard codes: 200 active, 429 standby,
        # 472 disaster-recovery secondary, 473 perf-standby, 501 not init,
        # 503 sealed. Treat 200 + 429 as healthy for read traffic.
        if response.status_code in (200, 429):
            try:
                body = response.json()
                version = body.get("version", "unknown")
                sealed = body.get("sealed", False)
                if sealed:
                    return False, f"vault is sealed (v{version})"
                return True, f"vault reachable (v{version})"
            except ValueError:
                return True, "vault reachable (non-JSON health body)"
        return False, f"vault health returned HTTP {response.status_code}"

    async def get_secret(self, tenant_id: UUID, ref: str) -> str:
        if not ref:
            raise SecretNotFoundError("empty secret ref")
        client = self._ensure_client()
        path = f"/v1/{self._mount}/data/{tenant_id}/{ref}"
        headers = {"X-Vault-Token": self._token}
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace
        try:
            response = await client.get(path, headers=headers, timeout=self._timeout)
        except httpx.HTTPError as exc:
            raise VaultBackendError(
                f"Vault read failed for ref {ref!r}: {exc.__class__.__name__}"
            ) from exc

        if response.status_code == 404:
            # Vault returns 404 for missing path — map to the Protocol's
            # standard not-found error, no detail leak.
            raise SecretNotFoundError(
                f"secret ref not found for tenant {tenant_id}: {ref!r}"
            )
        if response.status_code >= 400:
            raise VaultBackendError(
                f"Vault returned {response.status_code} reading ref {ref!r}"
            )

        body = self._parse_body(response, ref)
        try:
            value = body["data"]["data"][self._value_field]
        except (KeyError, TypeError) as exc:
            raise VaultBackendError(
                f"Vault payload missing field {self._value_field!r} for ref {ref!r}"
            ) from exc
        if not isinstance(value, str):
            raise VaultBackendError(
                f"Vault field {self._value_field!r} for ref {ref!r} is not a string"
            )
        return value

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        self._client = httpx.AsyncClient(base_url=self._base_url)
        return self._client

    def _parse_body(self, response: httpx.Response, ref: str) -> dict[str, Any]:
        try:
            body = response.json()
        except ValueError as exc:
            raise VaultBackendError(
                f"Vault payload for ref {ref!r} was not JSON"
            ) from exc
        if not isinstance(body, dict):
            raise VaultBackendError(
                f"Vault payload for ref {ref!r} is not a JSON object"
            )
        return body
