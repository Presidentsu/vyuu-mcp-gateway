"""AWS Secrets Manager SecretStore.

Same Protocol contract as `VaultSecretStore` — drop-in replacement for
deployments standardised on AWS. Resolves `(tenant_id, ref)` to a value
from AWS Secrets Manager.

Path layout:

    {prefix}/{tenant_id}/{ref}     (default prefix = "vyuu")

Example: `vyuu/cafdc8bf-.../paypal-bearer`. Per-tenant prefix gives
clean IAM scoping — operators can attach a policy with
`Resource: "arn:aws:secretsmanager:*:*:secret:vyuu/{tenant_id}/*"` per
tenant if they want, on top of the gateway-side `tenant_id` parameter
(defense-in-depth).

Auth: relies on the boto3 default credential chain. Production on-prem
deployments should use **IAM Roles Anywhere** (X.509-cert-based session
credentials) rather than long-lived access keys. AWS-resident
deployments use the EC2 instance profile / ECS task role / EKS pod
identity automatically. The gateway code doesn't care which — boto3
figures it out.

Latency: AWS API calls take ~50-200ms from on-prem. Not a hot-path
concern because secrets are resolved at upstream-client construction
time (and cached in the httpx pool), not per request.

Secret value shape: AWS Secrets Manager stores either a plaintext
`SecretString` or binary. We read `SecretString`. By default we treat
the entire string as the value (most common — operators store the raw
header / token there). When the string is JSON, the `value_field`
config selects a specific JSON field; this matches the Vault store's
convention so an operator migrating from one to the other doesn't have
to re-think the layout.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

import boto3
import botocore.exceptions

from vyuu_gateway.secrets.store import SecretNotFoundError

logger = logging.getLogger(__name__)


class AwsSecretsManagerConfigurationError(Exception):
    """Construction-time misconfiguration."""


class AwsSecretsManagerBackendError(Exception):
    """AWS API returned an unexpected error (access denied, throttling,
    network, malformed JSON, etc.). Distinct from `SecretNotFoundError`
    so a permission error doesn't silently look like a missing secret."""


class AwsSecretsManagerStore:
    """boto3-backed SecretStore. Implements the `SecretStore` Protocol.

    Cheap to construct — no AWS API call until first `get_secret`.
    Tests inject `client` directly; production builds via `boto3.client`
    using the default credential chain.
    """

    def __init__(
        self,
        *,
        region_name: str | None = None,
        prefix: str = "vyuu",
        value_field: str | None = None,
        client: Any = None,
    ) -> None:
        if not prefix:
            raise AwsSecretsManagerConfigurationError(
                "AWS Secrets Manager prefix must be a non-empty string"
            )
        # Treat empty value_field as None (whole string is the value).
        self._region_name = region_name
        self._prefix = prefix.strip("/")
        self._value_field = value_field or None
        self._injected_client = client
        self._client = client

    def aclose(self) -> None:
        # boto3 clients don't need explicit close, but keep the symmetry
        # with VaultSecretStore so wiring doesn't have to branch.
        return None

    async def get_secret(self, tenant_id: UUID, ref: str) -> str:
        if not ref:
            raise SecretNotFoundError("empty secret ref")
        client = self._ensure_client()
        secret_id = f"{self._prefix}/{tenant_id}/{ref}"
        try:
            # boto3 is sync; the gateway's secret-resolution call sites
            # already buffer the await, so a sync call here is fine. If
            # this becomes hot-path (it shouldn't — see latency note in
            # the module docstring), wrap in `asyncio.to_thread`.
            response = client.get_secret_value(SecretId=secret_id)
        except client.exceptions.ResourceNotFoundException as exc:
            # Map AWS-specific not-found to the Protocol-standard error.
            raise SecretNotFoundError(
                f"secret ref not found for tenant {tenant_id}: {ref!r}"
            ) from exc
        except botocore.exceptions.ClientError as exc:
            # Includes AccessDeniedException, ThrottlingException,
            # InternalServiceError. NEVER mask as not-found — masking a
            # permission error as missing-secret would hide IAM
            # misconfiguration.
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            raise AwsSecretsManagerBackendError(
                f"AWS Secrets Manager error {code} reading ref {ref!r}"
            ) from exc
        except botocore.exceptions.BotoCoreError as exc:
            # Network errors, endpoint errors, etc.
            raise AwsSecretsManagerBackendError(
                f"AWS Secrets Manager network error reading ref {ref!r}: "
                f"{exc.__class__.__name__}"
            ) from exc

        return self._extract_value(response, ref)

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        kwargs: dict[str, Any] = {}
        if self._region_name:
            kwargs["region_name"] = self._region_name
        self._client = boto3.client("secretsmanager", **kwargs)
        return self._client

    def _extract_value(self, response: dict[str, Any], ref: str) -> str:
        secret_string = response.get("SecretString")
        if not isinstance(secret_string, str) or not secret_string:
            raise AwsSecretsManagerBackendError(
                f"AWS Secrets Manager payload for ref {ref!r} has no SecretString"
            )
        if self._value_field is None:
            return secret_string
        # JSON-shaped secret: pull the configured field, mirroring the
        # Vault store's default of `data.data.value`.
        try:
            parsed = json.loads(secret_string)
        except ValueError as exc:
            raise AwsSecretsManagerBackendError(
                f"value_field={self._value_field!r} configured but secret"
                f" {ref!r} is not JSON"
            ) from exc
        if not isinstance(parsed, dict):
            raise AwsSecretsManagerBackendError(
                f"AWS Secrets Manager payload for ref {ref!r} is not a JSON object"
            )
        try:
            value = parsed[self._value_field]
        except KeyError as exc:
            raise AwsSecretsManagerBackendError(
                f"AWS Secrets Manager payload missing field {self._value_field!r}"
                f" for ref {ref!r}"
            ) from exc
        if not isinstance(value, str):
            raise AwsSecretsManagerBackendError(
                f"AWS Secrets Manager field {self._value_field!r} for ref {ref!r}"
                " is not a string"
            )
        return value

    def health_check(self) -> tuple[bool, str]:
        """Quick connectivity probe used by the operator-UI panel.

        Returns `(ok, detail_message)`. Does NOT raise — intentionally
        designed to be safe to call from the hot UI path. Builds the
        boto3 client (to surface credential-chain failures clearly)
        and calls `list_secrets(MaxResults=1)` — cheap, doesn't depend
        on any specific secret being present.
        """

        try:
            client = self._ensure_client()
        except botocore.exceptions.NoCredentialsError as exc:
            return False, f"no AWS credentials: {exc!s}"
        except Exception as exc:  # noqa: BLE001
            return False, f"client construction failed: {exc.__class__.__name__}"
        try:
            client.list_secrets(MaxResults=1)
        except botocore.exceptions.ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            # AccessDeniedException on list_secrets is OK if the IAM
            # policy is scoped to GetSecretValue only — we still know
            # we can talk to AWS. Surface as a soft warning rather than
            # a hard failure.
            if code == "AccessDeniedException":
                return (
                    True,
                    "credentials valid (list_secrets denied —"
                    " fine if IAM is scoped narrowly)",
                )
            return False, f"{code}: {exc!s}"
        except botocore.exceptions.BotoCoreError as exc:
            return False, f"network error: {exc.__class__.__name__}"
        return True, "credentials valid; AWS Secrets Manager reachable"
