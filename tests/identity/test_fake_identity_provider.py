from uuid import uuid4

import pytest

from vyuu_gateway.identity.fake import FakeIdentityProvider, sign_test_token
from vyuu_gateway.identity.models import (
    ApiKeyPrincipal,
    EndpointSessionPrincipal,
    PrincipalType,
    ServerAgentPrincipal,
)
from vyuu_gateway.identity.provider import IdentityCredentials, IdentityValidationError


def test_fake_identity_provider_validates_endpoint_session_mock_headers() -> None:
    tenant_id = uuid4()
    principal = FakeIdentityProvider().validate_principal(
        tenant_id=tenant_id,
        credentials=IdentityCredentials(
            headers={
                "x-vyuu-tenant-id": str(tenant_id),
                "x-vyuu-principal-type": "endpoint_session",
                "x-vyuu-principal-id": "endpoint-session-1",
                "x-vyuu-principal-display": "Endpoint Session 1",
            }
        ),
    )

    assert isinstance(principal, EndpointSessionPrincipal)
    assert principal.tenant_id == tenant_id
    assert principal.id == "endpoint-session-1"
    assert principal.endpoint_session_id == "endpoint-session-1"
    assert principal.display == "Endpoint Session 1"
    assert principal.to_audit_principal().type == "endpoint_session"


def test_fake_identity_provider_validates_server_agent_mock_headers() -> None:
    tenant_id = uuid4()
    principal = FakeIdentityProvider().validate_principal(
        tenant_id=tenant_id,
        credentials=IdentityCredentials(
            headers={
                "x-vyuu-principal-type": "server_agent",
                "x-vyuu-principal-id": "agent-1",
            }
        ),
    )

    assert isinstance(principal, ServerAgentPrincipal)
    assert principal.agent_id == "agent-1"


def test_fake_identity_provider_validates_signed_api_key_test_token() -> None:
    tenant_id = uuid4()
    token = sign_test_token(
        tenant_id=tenant_id,
        principal_type=PrincipalType.API_KEY,
        principal_id="key-1",
        display="CI key",
    )

    principal = FakeIdentityProvider(allow_mock_headers=False).validate_principal(
        tenant_id=tenant_id,
        credentials=IdentityCredentials(headers={"authorization": f"Bearer {token}"}),
    )

    assert isinstance(principal, ApiKeyPrincipal)
    assert principal.key_id == "key-1"
    assert principal.display == "CI key"


def test_fake_identity_provider_rejects_wrong_token_signature() -> None:
    tenant_id = uuid4()
    token = sign_test_token(
        tenant_id=tenant_id,
        principal_type=PrincipalType.API_KEY,
        principal_id="key-1",
    )

    with pytest.raises(IdentityValidationError):
        FakeIdentityProvider(signing_secret="different").validate_principal(
            tenant_id=tenant_id,
            credentials=IdentityCredentials(headers={"authorization": f"Bearer {token}"}),
        )


def test_fake_identity_provider_rejects_tenant_mismatch() -> None:
    token = sign_test_token(
        tenant_id=uuid4(),
        principal_type=PrincipalType.API_KEY,
        principal_id="key-1",
    )

    with pytest.raises(IdentityValidationError):
        FakeIdentityProvider().validate_principal(
            tenant_id=uuid4(),
            credentials=IdentityCredentials(headers={"authorization": f"Bearer {token}"}),
        )


def test_fake_identity_provider_rejects_missing_credentials() -> None:
    with pytest.raises(IdentityValidationError):
        FakeIdentityProvider().validate_principal(
            tenant_id=uuid4(),
            credentials=IdentityCredentials(headers={}),
        )
