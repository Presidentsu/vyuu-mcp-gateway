"""Tenant-scoped secret resolution for upstream MCP authentication.

Upstream MCP servers — CrowdStrike Falcon, Palo Alto Cortex, PayPal,
Wiz, Snyk, Datadog and friends — all require API keys, OAuth client
credentials, or static bearer tokens to talk to. The gateway never
stores raw credentials in the registry; instead `mcp_servers.auth_headers`
and `mcp_servers.auth_env` carry **opaque references** that resolve to
secret values through a `SecretStore`.

Production wires `VaultSecretStore` / `AwsSecretsManagerStore` /
`KubernetesSecretStore`. The dev / lab path uses `InMemorySecretStore`
so iteration stays zero-dependency.

The Protocol takes the tenant id explicitly so a tenant cannot read
another tenant's refs even if they happen to share an opaque ref string —
defense in depth on top of whatever isolation the underlying store
already provides.
"""

from vyuu_gateway.secrets.aws_secrets_manager import (
    AwsSecretsManagerBackendError,
    AwsSecretsManagerConfigurationError,
    AwsSecretsManagerStore,
)
from vyuu_gateway.secrets.kubernetes import (
    KubernetesBackendError,
    KubernetesConfigurationError,
    KubernetesSecretStore,
)
from vyuu_gateway.secrets.store import (
    InMemorySecretStore,
    SecretNotFoundError,
    SecretStore,
)
from vyuu_gateway.secrets.vault import (
    VaultBackendError,
    VaultConfigurationError,
    VaultSecretStore,
)

__all__ = [
    "KubernetesBackendError",
    "KubernetesConfigurationError",
    "KubernetesSecretStore",
    "AwsSecretsManagerBackendError",
    "AwsSecretsManagerConfigurationError",
    "AwsSecretsManagerStore",
    "InMemorySecretStore",
    "SecretNotFoundError",
    "SecretStore",
    "VaultBackendError",
    "VaultConfigurationError",
    "VaultSecretStore",
]
