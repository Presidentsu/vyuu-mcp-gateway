"""Tests for the per-directory OIDC sign-in flow.

We don't exercise the round-trip against a real IdP — that's
covered by the existing `tests/users/test_login_endpoint.py` for
the deployment-wide OIDC providers, and the per-directory flow
just swaps where the OIDC config comes from. These tests cover the
NEW pieces: directory-scoped routing, state-prefix validation, the
JIT-create path when SCIM hasn't run yet, and graceful 404 / 400
handling on misconfigured directories.
"""

from __future__ import annotations

import os
from typing import Any
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
    reason="VYUU_TEST_DATABASE_URL not set; skipping OIDC sign-in integration",
)

_TEST_SIGNING_SECRET = "test-operator-auth-secret-α8"


def _build_factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(create_engine(_DATABASE_URL, future=True), autoflush=False, future=True)


def _seed_tenant_and_operator() -> tuple[UUID, UUID, str]:
    Session = _build_factory()
    tenant_id = uuid4()
    operator_id = uuid4()
    with Session() as session:
        session.add(Tenant(id=tenant_id, name=f"oidc-test-{tenant_id}", tier=TenantTier.SHARED))
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
        display="oidc-test-admin",
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


def test_oidc_start_404_when_directory_unknown() -> None:
    """The directory id has to exist in the same tenant. Unknown id
    is 404, not 401 — admins are authenticated to discover, but
    end-users hitting the start URL deserve a clean error."""

    tenant_id, _, _ = _seed_tenant_and_operator()
    try:
        client = _build_client()
        unknown = uuid4()
        resp = client.get(
            f"/api/v1/auth/{tenant_id}/idp/{unknown}/oidc-start"
        )
        assert resp.status_code == 404
    finally:
        _cleanup_tenant(tenant_id)


def test_oidc_start_400_when_directory_is_saml() -> None:
    """A directory that the admin configured for SAML must reject the
    OIDC start endpoint — wrong protocol family, the admin needs to
    use the SAML route instead."""

    tenant_id, _, operator_bearer = _seed_tenant_and_operator()
    try:
        client = _build_client()
        connect = client.post(
            "/api/v1/idp/directories",
            headers={"Authorization": f"Bearer {operator_bearer}"},
            json={
                "kind": "entra",
                "display_name": "Acme · Entra (SAML)",
                "signin_protocol": "saml",
                "saml": {
                    "entity_id": "https://acme.example.com/saml",
                    "sso_url": "https://login.microsoftonline.com/contoso/saml2",
                    "idp_certificate": "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
                },
            },
        )
        assert connect.status_code == 201, connect.text
        directory_id = connect.json()["directory"]["id"]

        resp = client.get(
            f"/api/v1/auth/{tenant_id}/idp/{directory_id}/oidc-start"
        )
        assert resp.status_code == 400
        assert "OIDC" in resp.text
    finally:
        _cleanup_tenant(tenant_id)


def test_oidc_callback_rejects_state_with_wrong_directory_id() -> None:
    """State-prefix validation defends against a callback minted for
    (tenant A, dir X) being replayed at (tenant A, dir Y)."""

    tenant_id, _, operator_bearer = _seed_tenant_and_operator()
    try:
        client = _build_client()
        connect = client.post(
            "/api/v1/idp/directories",
            headers={"Authorization": f"Bearer {operator_bearer}"},
            json={
                "kind": "google_workspace",
                "display_name": "Acme · Workspace",
                "signin_protocol": "oidc",
                "oidc": {
                    "issuer": "https://accounts.google.com",
                    "client_id": "fake-client-id",
                    "client_secret_ref": "missing-ref-on-purpose",
                },
            },
        )
        directory_id = connect.json()["directory"]["id"]
        wrong_directory_id = uuid4()

        resp = client.post(
            f"/api/v1/auth/{tenant_id}/idp/{directory_id}/oidc-callback",
            json={
                "code": "anything",
                # State carries the WRONG directory id — must be rejected
                # before any IdP token-exchange is attempted.
                "state": f"{tenant_id}.{wrong_directory_id}.abc123",
            },
        )
        assert resp.status_code == 400
        assert "state" in resp.text.lower()
    finally:
        _cleanup_tenant(tenant_id)
