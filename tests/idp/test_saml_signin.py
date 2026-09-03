"""Tests for the per-directory SAML sign-in flow.

Real SAML round-trips need a working IdP (or a mock that signs
responses with the directory's cert). These tests cover the
NEW pieces — directory-scoped routing, RelayState validation,
SP metadata output, malformed-response rejection — without trying
to forge a signed response.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import UUID, uuid4

import pytest

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ.setdefault("VYUU_DATABASE_URL", _DATABASE_URL)

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.config import Settings  # noqa: E402
from vyuu_gateway.db.models import (  # noqa: E402
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
)
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.operator_auth.fake import mint_operator_test_token  # noqa: E402

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set; skipping SAML sign-in integration",
)

_TEST_SIGNING_SECRET = "test-operator-auth-secret-α8"

# A real X.509 PEM, just expired/self-signed. Generated for test fixtures
# only — pysaml2 needs a syntactically-valid cert to bring up the
# Saml2Client; signature validation against a real IdP isn't exercised
# by these tests, just the route plumbing.
_TEST_PEM = """-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUcUXEpXpHt1nZJtYFdOe45ZmywNAwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzEwMjcyMTU1MzlaFw0zMzEw
MjQyMTU1MzlaMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDByzCQ86SdcpO9LaVNNNXjQ0xPshj8s0DDp0Wt12Kw
Mfvur1PMYpvDhXRoFxoY3+iuObc3l8YuLFsGgrdiTkR+P9h1ftgXk3w/Ti2fHDXo
A2g/gMPGOwgLXeUGcPa/bcWeQrUsM5WNNFhGUEQHVx9Ab/kjxK8eJFrtWpJjMlGZ
GMTFsXkRmlUmBPKZ2CFMVOWO2j7qJRPsJUjPNRbZZbm9ifw4xLJcOMC3afSqIRzM
B0BkMIO5ZtW5kCrRpWJQE2vw1GPDVpY6uy3PQCaZRrV2V8Tva3nLaWfFn6QmkM37
CvVMN8KqzC4zbfa9CVApbJxEUrW3DlTTL/fGXF/pSIDvAgMBAAGjUzBRMB0GA1Ud
DgQWBBQAEz0Jnxm99yoF1d7gTQfwZsQ/HzAfBgNVHSMEGDAWgBQAEz0Jnxm99yoF
1d7gTQfwZsQ/HzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAY
AsmO7gFtUAZxqH80WjHmJJqW7uohx8gwxcINq6jnEJ0eaoHF1iCvHTXc4Dm3qLwq
1x3zT4Fnxuhe1jfVi7LBoHvUWW74W8HYy8FzCRY4MpxqPAOyPsOgoNQAfIrhPq2t
cfxnj6vIoAIFXsdPj5nEW+mYJlWAcmvP9k4G7kZYoxmCVkPK5YBoIowCqTxIMR5b
2JiUdgvbgdAmZUuiHbKDkPsm2/wlcDRJ5bBy2cSUW6NMZyW1k5L8BnE3UqgNu3W6
G2A8X5tgDhKj0i8pIJxAqGPIu5+oh/Bz/TWdJpQpmTZbbhX8UMoJ2YaTC3VLVHRo
uXqUWyUNAVPCKMa3M+lH
-----END CERTIFICATE-----"""


def _build_factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(create_engine(_DATABASE_URL, future=True), autoflush=False, future=True)


def _seed_tenant_and_operator() -> tuple[UUID, UUID, str]:
    Session = _build_factory()
    tenant_id = uuid4()
    operator_id = uuid4()
    with Session() as session:
        session.add(Tenant(id=tenant_id, name=f"saml-test-{tenant_id}", tier=TenantTier.SHARED))
        session.add(
            Operator(
                id=operator_id,
                tenant_id=tenant_id,
                email=f"admin-{operator_id}@example.com",
                role=OperatorRole.ADMIN,
                password_hash=None,
                must_change_password=False,
            )
        )
        session.commit()
    bearer = mint_operator_test_token(
        tenant_id=tenant_id,
        operator_id=operator_id,
        signing_secret=_TEST_SIGNING_SECRET,
        display="saml-test-admin",
    )
    return tenant_id, operator_id, bearer


def _cleanup_tenant(tenant_id: UUID) -> None:
    Session = _build_factory()
    with Session() as session:
        session.execute(text("DELETE FROM tenants WHERE id = :tid"), {"tid": str(tenant_id)})
        session.commit()


def _build_client() -> TestClient:
    return TestClient(
        create_app(
            Settings(
                app_name="vyuu-test",
                environment="test",
                log_level="CRITICAL",
                version="test",
                operator_auth_signing_secret=_TEST_SIGNING_SECRET,
            )
        )
    )


def _connect_saml_directory(client: TestClient, operator_bearer: str) -> str:
    resp = client.post(
        "/api/v1/idp/directories",
        headers={"Authorization": f"Bearer {operator_bearer}"},
        json={
            "kind": "entra",
            "display_name": "Acme Corp · Entra (SAML)",
            "signin_protocol": "saml",
            "saml": {
                "entity_id": "https://login.microsoftonline.com/contoso/saml2",
                "sso_url": "https://login.microsoftonline.com/contoso/saml2",
                "idp_certificate": _TEST_PEM,
            },
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["directory"]["id"]


def test_saml_login_redirects_to_idp_sso_url() -> None:
    """`/saml-login` must 302 to the directory's stored SSO URL with a
    `SAMLRequest` query param + a `RelayState` we can validate on the
    callback."""

    tenant_id, _, operator_bearer = _seed_tenant_and_operator()
    try:
        client = _build_client()
        directory_id = _connect_saml_directory(client, operator_bearer)

        resp = client.get(
            f"/api/v1/auth/{tenant_id}/idp/{directory_id}/saml-login",
            follow_redirects=False,
        )
        assert resp.status_code == 302
        location = resp.headers["location"]
        parsed = urlparse(location)
        assert parsed.netloc == "login.microsoftonline.com"
        assert parsed.path == "/contoso/saml2"
        qs = parse_qs(parsed.query)
        assert "SAMLRequest" in qs
        relay = qs["RelayState"][0]
        # State MUST start with the (tenant, directory) tuple from
        # the path so the ACS can reject mismatched callbacks.
        assert relay.startswith(f"{tenant_id}.{directory_id}.")
    finally:
        _cleanup_tenant(tenant_id)


def test_saml_login_400_when_directory_is_oidc() -> None:
    """An OIDC-configured directory must reject the SAML login route."""

    tenant_id, _, operator_bearer = _seed_tenant_and_operator()
    try:
        client = _build_client()
        connect = client.post(
            "/api/v1/idp/directories",
            headers={"Authorization": f"Bearer {operator_bearer}"},
            json={
                "kind": "google_workspace",
                "display_name": "Acme · Workspace (OIDC)",
                "signin_protocol": "oidc",
                "oidc": {
                    "issuer": "https://accounts.google.com",
                    "client_id": "fake-id",
                    "client_secret_ref": "fake-ref",
                },
            },
        )
        directory_id = connect.json()["directory"]["id"]

        resp = client.get(
            f"/api/v1/auth/{tenant_id}/idp/{directory_id}/saml-login",
            follow_redirects=False,
        )
        assert resp.status_code == 400
        assert "SAML" in resp.text
    finally:
        _cleanup_tenant(tenant_id)


def test_saml_acs_accepts_any_relay_state() -> None:
    """ACS doesn't gate on RelayState — pysaml2's signed-Audience
    check on the response is the actual cross-directory-replay
    defense. We must accept absent RelayState (IdP-initiated /
    Google's "Test SAML Login" button), our own prefix (SP-initiated
    browser flow), and IdP-internal values (Google app launcher)
    alike, falling through to the parse path on each. Garbage
    SAMLResponse surfaces as 401 from the parse step in every case.
    """

    tenant_id, _, operator_bearer = _seed_tenant_and_operator()
    try:
        client = _build_client()
        directory_id = _connect_saml_directory(client, operator_bearer)

        # IdP-initiated — no RelayState
        no_relay = client.post(
            f"/api/v1/auth/{tenant_id}/idp/{directory_id}/saml-acs",
            data={"SAMLResponse": "garbage"},
        )
        assert no_relay.status_code == 401

        # Google "Test SAML Login" — IdP-internal RelayState (not our prefix)
        idp_internal = client.post(
            f"/api/v1/auth/{tenant_id}/idp/{directory_id}/saml-acs",
            data={
                "SAMLResponse": "garbage",
                "RelayState": "google-internal-test-state-1234",
            },
        )
        assert idp_internal.status_code == 401

        # SP-initiated — our prefix
        sp_initiated = client.post(
            f"/api/v1/auth/{tenant_id}/idp/{directory_id}/saml-acs",
            data={
                "SAMLResponse": "garbage",
                "RelayState": f"{tenant_id}.{directory_id}.nonce",
            },
        )
        assert sp_initiated.status_code == 401
    finally:
        _cleanup_tenant(tenant_id)


def test_saml_acs_rejects_malformed_response_with_401() -> None:
    """A garbage `SAMLResponse` must surface as 401 — we never disclose
    which sub-check (signature, NotOnOrAfter, NameID format) failed."""

    tenant_id, _, operator_bearer = _seed_tenant_and_operator()
    try:
        client = _build_client()
        directory_id = _connect_saml_directory(client, operator_bearer)

        resp = client.post(
            f"/api/v1/auth/{tenant_id}/idp/{directory_id}/saml-acs",
            data={
                "SAMLResponse": "definitely-not-a-real-saml-response",
                "RelayState": f"{tenant_id}.{directory_id}.abc",
            },
        )
        assert resp.status_code == 401
    finally:
        _cleanup_tenant(tenant_id)


def test_saml_metadata_returns_sp_entity_descriptor() -> None:
    """The SP metadata route must serve XML the IdP can ingest."""

    tenant_id, _, operator_bearer = _seed_tenant_and_operator()
    try:
        client = _build_client()
        directory_id = _connect_saml_directory(client, operator_bearer)

        resp = client.get(
            f"/api/v1/auth/{tenant_id}/idp/{directory_id}/saml-metadata"
        )
        assert resp.status_code == 200
        assert "samlmetadata+xml" in resp.headers["content-type"]
        body = resp.text
        # The metadata must mention the SP entity id (path-derived) and
        # the ACS URL the IdP will POST to. These two strings being
        # present is sufficient — we rely on pysaml2 for full schema
        # compliance.
        assert f"/saml/{directory_id}" in body
        assert "/saml-acs" in body
    finally:
        _cleanup_tenant(tenant_id)
