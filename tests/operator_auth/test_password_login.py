"""End-to-end tests for the operator login + admin-management surface."""

from __future__ import annotations

import os

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

from typing import Any  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import pytest  # noqa: E402
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
from vyuu_gateway.users.passwords import hash_password  # noqa: E402

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set",
)

_OP_SECRET = "operator-login-test-secret"
_PORTAL_SECRET = "operator-login-test-portal"


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(create_engine(_DATABASE_URL, future=True), autoflush=False, future=True)


def _seed_operator_with_password(
    factory: Any,
    *,
    email: str,
    password: str,
    disabled: bool = False,
    must_change_password: bool = False,
) -> tuple[UUID, UUID]:
    """Seed a tenant + operator with a bcrypt password. Returns
    (tenant_id, operator_id)."""
    from datetime import UTC, datetime

    tenant_id = uuid4()
    operator_id = uuid4()
    with factory() as session:
        session.add(Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED))
        session.add(
            Operator(
                id=operator_id,
                tenant_id=tenant_id,
                email=email,
                role=OperatorRole.ADMIN,
                password_hash=hash_password(password),
                must_change_password=must_change_password,
                disabled_at=datetime.now(UTC) if disabled else None,
            )
        )
        session.commit()
    return tenant_id, operator_id


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as session:
        for table in (
            "access_requests",
            "user_group_memberships",
            "virtual_server_grants",
            "user_api_keys",
            "groups",
            "users",
            "virtual_server_tools",
            "virtual_servers",
            "operators",
        ):
            if table == "user_group_memberships":
                session.execute(
                    text(
                        "DELETE FROM user_group_memberships WHERE user_id IN "
                        "(SELECT id FROM users WHERE tenant_id = :id)"
                    ),
                    {"id": tenant_id},
                )
            else:
                session.execute(
                    text(f"DELETE FROM {table} WHERE tenant_id = :id"),
                    {"id": tenant_id},
                )
        session.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        session.commit()


def _make_client() -> TestClient:
    return TestClient(
        create_app(
            Settings(
                app_name="op-auth-test",
                environment="test",
                log_level="CRITICAL",
                operator_auth_signing_secret=_OP_SECRET,
                portal_session_signing_secret=_PORTAL_SECRET,
            )
        )
    )


# --- Login -----------------------------------------------------------------


def test_login_returns_bearer_token_on_correct_password() -> None:
    factory = _factory()
    tenant_id, operator_id = _seed_operator_with_password(
        factory, email="admin@corp.example", password="very-strong-12+chars"
    )
    try:
        with _make_client() as client:
            r = client.post(
                "/api/v1/operator-auth/login",
                json={
                    "tenant_id": str(tenant_id),
                    "email": "admin@corp.example",
                    "password": "very-strong-12+chars",
                },
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["operator_id"] == str(operator_id)
        assert body["bearer_token"]
        # Token should be usable against the existing dependency.
        with _make_client() as client:
            r2 = client.get(
                "/api/v1/admins",
                headers={"Authorization": f"Bearer {body['bearer_token']}"},
            )
        assert r2.status_code == 200
    finally:
        _cleanup(factory, tenant_id)


def test_login_rejects_wrong_password_with_401() -> None:
    factory = _factory()
    tenant_id, _ = _seed_operator_with_password(
        factory, email="admin@corp.example", password="very-strong-12+chars"
    )
    try:
        with _make_client() as client:
            r = client.post(
                "/api/v1/operator-auth/login",
                json={
                    "tenant_id": str(tenant_id),
                    "email": "admin@corp.example",
                    "password": "wrong-password",
                },
            )
        assert r.status_code == 401
    finally:
        _cleanup(factory, tenant_id)


def test_login_rejects_unknown_email_with_401_anti_enumeration() -> None:
    factory = _factory()
    tenant_id, _ = _seed_operator_with_password(
        factory, email="known@corp.example", password="very-strong-12+chars"
    )
    try:
        with _make_client() as client:
            r = client.post(
                "/api/v1/operator-auth/login",
                json={
                    "tenant_id": str(tenant_id),
                    "email": "unknown@corp.example",
                    "password": "anything",
                },
            )
        # Same generic 401 as wrong-password — no enumeration.
        assert r.status_code == 401
    finally:
        _cleanup(factory, tenant_id)


def test_login_rejects_disabled_operator() -> None:
    factory = _factory()
    tenant_id, _ = _seed_operator_with_password(
        factory,
        email="admin@corp.example",
        password="very-strong-12+chars",
        disabled=True,
    )
    try:
        with _make_client() as client:
            r = client.post(
                "/api/v1/operator-auth/login",
                json={
                    "tenant_id": str(tenant_id),
                    "email": "admin@corp.example",
                    "password": "very-strong-12+chars",
                },
            )
        assert r.status_code == 401
    finally:
        _cleanup(factory, tenant_id)


def test_login_rejects_legacy_operator_without_password() -> None:
    """An operator row without a password (lab/legacy) cannot use the
    login endpoint. Only bearer-token mint paths work."""
    factory = _factory()
    tenant_id = uuid4()
    operator_id = uuid4()
    with factory() as session:
        session.add(Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED))
        session.add(
            Operator(
                id=operator_id,
                tenant_id=tenant_id,
                email="legacy@corp.example",
                role=OperatorRole.ADMIN,
                password_hash=None,
            )
        )
        session.commit()
    try:
        with _make_client() as client:
            r = client.post(
                "/api/v1/operator-auth/login",
                json={
                    "tenant_id": str(tenant_id),
                    "email": "legacy@corp.example",
                    "password": "any-password",
                },
            )
        assert r.status_code == 401
    finally:
        _cleanup(factory, tenant_id)


# --- Admin management -----------------------------------------------------


def _admin_headers(tenant_id: UUID, operator_id: UUID) -> dict[str, str]:
    token = mint_operator_test_token(
        tenant_id=tenant_id, operator_id=operator_id, signing_secret=_OP_SECRET
    )
    return {"Authorization": f"Bearer {token}"}


def test_list_admins_returns_only_callers_tenant() -> None:
    factory = _factory()
    tenant_a, op_a = _seed_operator_with_password(
        factory, email="admin-a@corp.example", password="very-strong-12+chars"
    )
    tenant_b, _ = _seed_operator_with_password(
        factory, email="admin-b@corp.example", password="very-strong-12+chars"
    )
    try:
        with _make_client() as client:
            r = client.get("/api/v1/admins", headers=_admin_headers(tenant_a, op_a))
        assert r.status_code == 200
        emails = [row["email"] for row in r.json()]
        assert "admin-a@corp.example" in emails
        assert "admin-b@corp.example" not in emails
    finally:
        _cleanup(factory, tenant_a)
        _cleanup(factory, tenant_b)


def test_create_admin_then_login_with_new_credential() -> None:
    """Full flow: existing admin creates a new admin via POST /admins,
    then the new admin logs in via POST /operator-auth/login."""
    factory = _factory()
    tenant_id, op_id = _seed_operator_with_password(
        factory, email="admin@corp.example", password="very-strong-12+chars"
    )
    try:
        with _make_client() as client:
            r = client.post(
                "/api/v1/admins",
                json={
                    "email": "new-admin@corp.example",
                    "role": "admin",
                    "password": "another-strong-12+chars",
                    "must_change_password": True,
                },
                headers=_admin_headers(tenant_id, op_id),
            )
            assert r.status_code == 201, r.text
            body = r.json()
            assert body["email"] == "new-admin@corp.example"
            assert body["must_change_password"] is True
            new_op_id = body["id"]

            login = client.post(
                "/api/v1/operator-auth/login",
                json={
                    "tenant_id": str(tenant_id),
                    "email": "new-admin@corp.example",
                    "password": "another-strong-12+chars",
                },
            )
        assert login.status_code == 200
        assert login.json()["operator_id"] == new_op_id
        assert login.json()["must_change_password"] is True
    finally:
        _cleanup(factory, tenant_id)


def test_create_admin_with_weak_password_returns_422() -> None:
    factory = _factory()
    tenant_id, op_id = _seed_operator_with_password(
        factory, email="admin@corp.example", password="very-strong-12+chars"
    )
    try:
        with _make_client() as client:
            r = client.post(
                "/api/v1/admins",
                json={
                    "email": "weak@corp.example",
                    "role": "admin",
                    "password": "short",
                },
                headers=_admin_headers(tenant_id, op_id),
            )
        assert r.status_code == 422
    finally:
        _cleanup(factory, tenant_id)


def test_create_admin_with_duplicate_email_returns_409() -> None:
    factory = _factory()
    tenant_id, op_id = _seed_operator_with_password(
        factory, email="admin@corp.example", password="very-strong-12+chars"
    )
    try:
        with _make_client() as client:
            r = client.post(
                "/api/v1/admins",
                json={
                    "email": "admin@corp.example",  # already exists
                    "role": "admin",
                    "password": "very-strong-12+chars",
                },
                headers=_admin_headers(tenant_id, op_id),
            )
        assert r.status_code == 409
    finally:
        _cleanup(factory, tenant_id)


def test_disable_self_returns_400() -> None:
    """Critical safety: an admin disabling themselves would lock the
    tenant out. Endpoint must reject."""
    factory = _factory()
    tenant_id, op_id = _seed_operator_with_password(
        factory, email="admin@corp.example", password="very-strong-12+chars"
    )
    try:
        with _make_client() as client:
            r = client.delete(
                f"/api/v1/admins/{op_id}",
                headers=_admin_headers(tenant_id, op_id),
            )
        assert r.status_code == 400
    finally:
        _cleanup(factory, tenant_id)


def test_disable_other_admin_then_their_login_fails() -> None:
    factory = _factory()
    tenant_id, op_id = _seed_operator_with_password(
        factory, email="admin@corp.example", password="very-strong-12+chars"
    )
    try:
        with _make_client() as client:
            create = client.post(
                "/api/v1/admins",
                json={
                    "email": "doomed@corp.example",
                    "role": "admin",
                    "password": "very-strong-12+chars",
                    "must_change_password": False,
                },
                headers=_admin_headers(tenant_id, op_id),
            )
            target_id = create.json()["id"]
            r = client.delete(
                f"/api/v1/admins/{target_id}",
                headers=_admin_headers(tenant_id, op_id),
            )
            assert r.status_code == 200
            assert r.json()["disabled_at"] is not None
            login = client.post(
                "/api/v1/operator-auth/login",
                json={
                    "tenant_id": str(tenant_id),
                    "email": "doomed@corp.example",
                    "password": "very-strong-12+chars",
                },
            )
        assert login.status_code == 401
    finally:
        _cleanup(factory, tenant_id)


def test_self_rotate_requires_correct_current_password() -> None:
    factory = _factory()
    tenant_id, op_id = _seed_operator_with_password(
        factory,
        email="admin@corp.example",
        password="very-strong-12+chars",
        must_change_password=True,
    )
    try:
        with _make_client() as client:
            r = client.post(
                "/api/v1/operator-auth/password",
                json={
                    "current_password": "wrong",
                    "new_password": "even-stronger-22+chars",
                },
                headers=_admin_headers(tenant_id, op_id),
            )
            assert r.status_code == 401
            r2 = client.post(
                "/api/v1/operator-auth/password",
                json={
                    "current_password": "very-strong-12+chars",
                    "new_password": "even-stronger-22+chars",
                },
                headers=_admin_headers(tenant_id, op_id),
            )
        assert r2.status_code == 200
        assert r2.json()["must_change_password"] is False
    finally:
        _cleanup(factory, tenant_id)


def test_admin_endpoints_require_operator_jwt() -> None:
    with _make_client() as client:
        r = client.get("/api/v1/admins")
    assert r.status_code == 401
