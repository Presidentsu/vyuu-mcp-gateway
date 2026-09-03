"""IDP-2 · HTTP surface for Workspace polling configuration.

Exists because the service-layer tests did **not** catch a 500 on this
endpoint: `_to_response()` takes a `Request` the handler never passed, so
every successful call raised `TypeError` *after* committing — the change
applied, the operator saw a failure. Only driving the real route through
FastAPI's dependency injection finds that, which is the argument for an
API-level test per endpoint rather than per service function.

Runs against real Postgres (skipped without `VYUU_TEST_DATABASE_URL`).
"""

from __future__ import annotations

import os

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

from typing import Any  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, select, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.config import Settings  # noqa: E402
from vyuu_gateway.db.models import (  # noqa: E402
    AdminAuditLog,
    IdpDirectory,
    IdpDirectoryKind,
    IdpSigninProtocol,
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
)
from vyuu_gateway.db.session import bind_tenant_context  # noqa: E402
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.operator_auth.fake import mint_operator_test_token  # noqa: E402

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None, reason="VYUU_TEST_DATABASE_URL not set"
)

SECRET = "workspace-api-secret"


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(
        create_engine(_DATABASE_URL, future=True), autoflush=False, future=True
    )


def _seed(factory: Any) -> tuple[UUID, UUID, UUID]:
    tenant_id, operator_id, directory_id = uuid4(), uuid4(), uuid4()
    # Tenant committed first: `idp_directories` FKs it, and combining the
    # inserts into one flush produced a FK violation.
    with factory() as s:
        s.add(Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED))
        s.commit()
    with factory() as s:
        bind_tenant_context(s, tenant_id)
        s.add(Operator(id=operator_id, tenant_id=tenant_id,
                       email=f"op-{operator_id.hex[:6]}@test", role=OperatorRole.ADMIN))
        s.add(IdpDirectory(
            id=directory_id, tenant_id=tenant_id,
            kind=IdpDirectoryKind.GOOGLE_WORKSPACE,
            display_name="Acme · Workspace",
            signin_protocol=IdpSigninProtocol.SAML,
            scim_token_hash="x" * 60,
        ))
        s.commit()
    return tenant_id, operator_id, directory_id


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as s:
        for table in ("admin_audit_log", "idp_directories", "operators"):
            s.execute(text(f"DELETE FROM {table} WHERE tenant_id = :i"), {"i": tenant_id})
        s.execute(text("DELETE FROM tenants WHERE id = :i"), {"i": tenant_id})
        s.commit()


def _client() -> TestClient:
    return TestClient(create_app(Settings(
        app_name="ws-api", environment="test", log_level="CRITICAL", version="t",
        operator_auth_signing_secret=SECRET,
    )))


def _auth(tenant_id: UUID, operator_id: UUID) -> dict[str, str]:
    return {"Authorization": f"Bearer {mint_operator_test_token(
        tenant_id=tenant_id, operator_id=operator_id, signing_secret=SECRET)}"}


def test_enabling_returns_200_and_the_updated_directory() -> None:
    """The regression this file exists for: a handler that commits and
    then raises leaves the operator seeing a failure for a change that
    applied."""

    factory = _factory()
    tenant_id, operator_id, directory_id = _seed(factory)
    try:
        response = _client().patch(
            f"/api/v1/idp/directories/{directory_id}/workspace-polling",
            headers=_auth(tenant_id, operator_id),
            json={
                "enabled": True,
                "customer_id": "my_customer",
                "admin_subject": "admin@acme.example",
                "service_account_ref": "workspace-sa-json",
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["workspace_polling_enabled"] is True
        assert body["workspace_customer_id"] == "my_customer"
        assert body["workspace_admin_subject"] == "admin@acme.example"
        assert body["workspace_service_account_ref"] == "workspace-sa-json"
    finally:
        _cleanup(factory, tenant_id)


def test_enabling_without_the_required_fields_is_refused() -> None:
    """A poller that silently never runs looks exactly like a directory
    with nothing to sync — and Workspace's absence of deprovisioning is
    already silent enough."""

    factory = _factory()
    tenant_id, operator_id, directory_id = _seed(factory)
    try:
        response = _client().patch(
            f"/api/v1/idp/directories/{directory_id}/workspace-polling",
            headers=_auth(tenant_id, operator_id),
            json={"enabled": True},
        )
        assert response.status_code == 400
        detail = response.json()["detail"]
        for field in ("customer_id", "admin_subject", "service_account_ref"):
            assert field in detail
    finally:
        _cleanup(factory, tenant_id)


def test_toggle_off_keeps_the_stored_settings() -> None:
    """So re-enabling does not make an operator retype the service-account
    ref they set months ago."""

    factory = _factory()
    tenant_id, operator_id, directory_id = _seed(factory)
    try:
        client = _client()
        headers = _auth(tenant_id, operator_id)
        url = f"/api/v1/idp/directories/{directory_id}/workspace-polling"
        client.patch(url, headers=headers, json={
            "enabled": True, "customer_id": "my_customer",
            "admin_subject": "a@x.test", "service_account_ref": "ref-1",
        })
        off = client.patch(url, headers=headers, json={"enabled": False})
        assert off.status_code == 200
        assert off.json()["workspace_polling_enabled"] is False
        assert off.json()["workspace_service_account_ref"] == "ref-1"

        back_on = client.patch(url, headers=headers, json={"enabled": True})
        assert back_on.status_code == 200
        assert back_on.json()["workspace_polling_enabled"] is True
    finally:
        _cleanup(factory, tenant_id)


def test_both_directions_are_audited_with_the_deprovisioning_consequence() -> None:
    factory = _factory()
    tenant_id, operator_id, directory_id = _seed(factory)
    try:
        client = _client()
        headers = _auth(tenant_id, operator_id)
        url = f"/api/v1/idp/directories/{directory_id}/workspace-polling"
        client.patch(url, headers=headers, json={
            "enabled": True, "customer_id": "my_customer",
            "admin_subject": "a@x.test", "service_account_ref": "ref-1",
        })
        client.patch(url, headers=headers, json={"enabled": False})

        with factory() as s:
            bind_tenant_context(s, tenant_id)
            rows = list(s.scalars(select(AdminAuditLog).where(
                AdminAuditLog.tenant_id == tenant_id)).all())
        actions = {r.action for r in rows}
        assert "idp.workspace_polling_enable" in actions
        assert "idp.workspace_polling_disable" in actions
        disabled = next(r for r in rows if r.action.endswith("disable"))
        assert "MANUAL" in disabled.detail["deprovisioning"]
        # The REF is recorded; the service-account JSON never is.
        assert disabled.detail["service_account_ref"] == "ref-1"


    finally:
        _cleanup(factory, tenant_id)


def test_requires_operator_auth() -> None:
    factory = _factory()
    tenant_id, _op, directory_id = _seed(factory)
    try:
        response = _client().patch(
            f"/api/v1/idp/directories/{directory_id}/workspace-polling",
            json={"enabled": False},
        )
        assert response.status_code in (401, 403)
    finally:
        _cleanup(factory, tenant_id)


def test_unknown_directory_is_404() -> None:
    factory = _factory()
    tenant_id, operator_id, _dir = _seed(factory)
    try:
        response = _client().patch(
            f"/api/v1/idp/directories/{uuid4()}/workspace-polling",
            headers=_auth(tenant_id, operator_id),
            json={"enabled": False},
        )
        assert response.status_code == 404
    finally:
        _cleanup(factory, tenant_id)
