from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from vyuu_gateway.audit.events import AuditPrincipal, AuditPrincipalType


class PrincipalType(StrEnum):
    ENDPOINT_SESSION = "endpoint_session"
    SERVER_AGENT = "server_agent"
    API_KEY = "api_key"
    # EMA-1 · caller authenticated via an enterprise-IdP-rooted EMA
    # access token (ID-JAG exchange) rather than a Vyuu-minted API key.
    FEDERATED_USER = "federated_user"


class Principal(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: PrincipalType
    tenant_id: UUID
    id: str = Field(min_length=1)
    display: str = ""

    def to_audit_principal(self) -> AuditPrincipal:
        return AuditPrincipal(
            type=AuditPrincipalType(self.type.value),
            id=self.id,
            display=self.display,
        )


class EndpointSessionPrincipal(Principal):
    type: Literal[PrincipalType.ENDPOINT_SESSION] = PrincipalType.ENDPOINT_SESSION
    endpoint_session_id: str = Field(min_length=1)


class ServerAgentPrincipal(Principal):
    type: Literal[PrincipalType.SERVER_AGENT] = PrincipalType.SERVER_AGENT
    agent_id: str = Field(min_length=1)


class ApiKeyPrincipal(Principal):
    type: Literal[PrincipalType.API_KEY] = PrincipalType.API_KEY
    key_id: str = Field(min_length=1)


class FederatedUserPrincipal(Principal):
    """EMA-1 · principal established from an EMA access token.

    `id` is the Vyuu `users.id` (the ID-JAG `sub` is JIT-mapped onto a
    directory user, so grants / groups / NHI treat federated callers
    exactly like SCIM-provisioned ones). `external_id` preserves the
    IdP's stable subject; `client_id` names the MCP client application
    the enterprise IdP authorized — the NHI map's AI-app column reads
    it directly instead of sniffing user agents.
    """

    type: Literal[PrincipalType.FEDERATED_USER] = PrincipalType.FEDERATED_USER
    external_id: str = Field(min_length=1)
    client_id: str | None = None
    directory_id: str | None = None
    # EMA-1 P3 · scopes the enterprise IdP authorized on the ID-JAG,
    # carried through the minted access token. Drives per-tool scope
    # gating (`virtual_servers.required_scopes`). Frozen so the
    # principal stays hashable/immutable like its siblings.
    scopes: frozenset[str] = frozenset()


def principal_from_type(
    *,
    principal_type: PrincipalType,
    tenant_id: UUID,
    principal_id: str,
    display: str = "",
) -> Principal:
    if principal_type == PrincipalType.ENDPOINT_SESSION:
        return EndpointSessionPrincipal(
            tenant_id=tenant_id,
            id=principal_id,
            endpoint_session_id=principal_id,
            display=display,
        )
    if principal_type == PrincipalType.SERVER_AGENT:
        return ServerAgentPrincipal(
            tenant_id=tenant_id,
            id=principal_id,
            agent_id=principal_id,
            display=display,
        )
    if principal_type == PrincipalType.FEDERATED_USER:
        return FederatedUserPrincipal(
            tenant_id=tenant_id,
            id=principal_id,
            external_id=principal_id,
            display=display,
        )
    return ApiKeyPrincipal(
        tenant_id=tenant_id,
        id=principal_id,
        key_id=principal_id,
        display=display,
    )
