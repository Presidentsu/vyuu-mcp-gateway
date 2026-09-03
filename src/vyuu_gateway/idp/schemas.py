"""Pydantic schemas for the operator-side IdP-directory CRUD.

The shape mirrors `idp_directories` (see `db/models.IdpDirectory`)
but splits OIDC + SAML config into nested objects so the admin
console wizard can validate one block at a time. The `signin_protocol`
field on the parent picks which block is required.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from vyuu_gateway.db.models import IdpDirectoryKind, IdpSigninProtocol


class OidcConfig(BaseModel):
    """OIDC sign-in config. Required when `signin_protocol = 'oidc'`."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    issuer: str = Field(min_length=1, max_length=512)
    client_id: str = Field(min_length=1, max_length=512)
    # secret-store key (NOT the literal client_secret). Same convention
    # as the upstream `client_secret_ref` fields elsewhere — admins
    # paste the secret into Vault / Postgres-backed secret store and
    # reference it by name here.
    client_secret_ref: str = Field(min_length=1, max_length=255)


class SamlConfig(BaseModel):
    """SAML sign-in config. Required when `signin_protocol = 'saml'`."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    entity_id: str = Field(min_length=1, max_length=512)
    sso_url: str = Field(min_length=1, max_length=512)
    # PEM-encoded IdP signing certificate. Public; safe inline.
    idp_certificate: str = Field(min_length=1, max_length=10_000)


class ConnectIdpDirectoryRequest(BaseModel):
    """Admin connects a new directory.

    Either `oidc` or `saml` (matching `signin_protocol`) must be
    populated; the other must be omitted. Mutual exclusion is
    enforced by `_check_signin_block_present`.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    kind: IdpDirectoryKind
    display_name: str = Field(min_length=1, max_length=255)
    signin_protocol: IdpSigninProtocol
    oidc: OidcConfig | None = None
    saml: SamlConfig | None = None
    # Optional provider-specific extras (Workspace customer_id, Entra
    # app object_id, etc.). JSONB on the DB.
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_signin_block_present(self) -> ConnectIdpDirectoryRequest:
        if self.signin_protocol == IdpSigninProtocol.OIDC:
            if self.oidc is None:
                raise ValueError("oidc config required when signin_protocol=oidc")
            if self.saml is not None:
                raise ValueError("saml config must be omitted when signin_protocol=oidc")
        else:
            if self.saml is None:
                raise ValueError("saml config required when signin_protocol=saml")
            if self.oidc is not None:
                raise ValueError("oidc config must be omitted when signin_protocol=saml")
        return self


class ConfigureEmaRequest(BaseModel):
    """EMA-1 P3 · turn Enterprise-Managed Authorization on/off for a
    directory. `audience` is what the IdP must stamp as the ID-JAG
    audience — the gateway's per-tenant resource-authorization-server
    issuer. `allowed_client_ids` empty means "any MCP client the IdP
    itself vetted"; listing ids narrows further, gateway-side."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    enabled: bool
    audience: str = Field(default="", max_length=2048)
    jwks_uri: str | None = Field(default=None, max_length=2048)
    allowed_client_ids: list[str] = Field(default_factory=list, max_length=50)


class ConfigureWorkspacePollingRequest(BaseModel):
    """IDP-2 · turn Workspace directory polling on/off for one directory.

    Omitted fields keep their stored value, so an operator can flip the
    toggle without restating the service-account ref.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    enabled: bool
    # Google's customer id, or the `my_customer` alias.
    customer_id: str | None = Field(default=None, max_length=200)
    # The delegated admin domain-wide delegation impersonates.
    admin_subject: str | None = Field(default=None, max_length=320)
    # SecretStore REFERENCE to the service-account JSON — never the JSON.
    service_account_ref: str | None = Field(default=None, max_length=400)


class IdpDirectoryResponse(BaseModel):
    """Public view of a connected directory.

    The SCIM bearer hash is NEVER included here — the plaintext is
    surfaced exactly once at connect-time via
    `IdpDirectoryConnectedResponse`, and the hash itself is an
    implementation detail.
    """

    model_config = ConfigDict(from_attributes=False)

    id: UUID
    tenant_id: UUID
    kind: IdpDirectoryKind
    display_name: str
    signin_protocol: IdpSigninProtocol
    oidc_issuer: str | None
    oidc_client_id: str | None
    saml_entity_id: str | None
    saml_sso_url: str | None
    metadata: dict[str, Any]
    last_sync_at: datetime | None
    created_at: datetime
    # EMA-1 P3 · surfaced so the operator console can render the toggle
    # state without a second call. Never includes secrets.
    ema_enabled: bool = False
    # IDP-2 · Workspace polling. Surfaced so an operator can see WHY a
    # Workspace directory is or is not deprovisioning — the single most
    # confusing thing about Workspace, since custom SAML apps cannot
    # SCIM-push and the absence is silent.
    workspace_polling_enabled: bool = False
    workspace_customer_id: str | None = None
    workspace_admin_subject: str | None = None
    # Reference only — never the service-account JSON itself.
    workspace_service_account_ref: str | None = None
    workspace_last_polled_at: datetime | None = None
    ema_audience: str | None = None
    ema_jwks_uri: str | None = None
    ema_allowed_client_ids: list[str] = []
    # The SCIM endpoint URL the admin pastes into the IdP. Built
    # server-side from `request.base_url` + the directory id; surfacing
    # it here saves the admin from constructing it manually.
    scim_endpoint_url: str


class IdpDirectoryConnectedResponse(BaseModel):
    """Returned exactly once from `POST /idp/directories`. Carries the
    plaintext SCIM bearer the admin pastes into Entra / Workspace —
    we never re-show this. The directory itself is reachable via the
    list / get endpoints from this point forward."""

    model_config = ConfigDict(from_attributes=False)

    directory: IdpDirectoryResponse
    scim_token_plaintext: str
