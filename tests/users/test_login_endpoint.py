"""End-to-end tests for the local-password login endpoint.

Same shape as `test_users_api.py` — env-gated on `VYUU_TEST_DATABASE_URL`,
seeds a tenant + local user via the factory, hits `/auth/{tenant}/login`
through `TestClient`, asserts the session JWT round-trips.

OIDC callback tests are deferred to a real-Keycloak integration test
(env-gated on `VYUU_TEST_KEYCLOAK_URL`) — out of scope for this batch
since standing up Keycloak in CI is its own infrastructure piece.
The `users/test_oidc.py` unit tests cover the core JWKS+JWT path with
generated RSA keys, which is the meaningful security check.
"""

from __future__ import annotations

import os

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

from datetime import UTC, datetime  # noqa: E402
from typing import Any  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.config import Settings  # noqa: E402
from vyuu_gateway.db.models import (  # noqa: E402
    Tenant,
    TenantTier,
    User,
    UserAuthMethod,
)
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.users.passwords import hash_password  # noqa: E402
from vyuu_gateway.users.sessions import verify_portal_session  # noqa: E402

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set",
)

_TEST_SIGNING_SECRET = "test-portal-session-secret"


def _build_factory() -> Any:
    assert _DATABASE_URL is not None
    engine = create_engine(_DATABASE_URL, future=True)
    return sessionmaker(engine, autoflush=False, future=True)


def _seed_local_user(
    factory: Any,
    *,
    email: str,
    password: str,
    disabled: bool = False,
) -> tuple[UUID, UUID]:
    tenant_id = uuid4()
    user_id = uuid4()
    with factory() as session:
        session.add(Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED))
        session.add(
            User(
                id=user_id,
                tenant_id=tenant_id,
                email=email,
                auth_method=UserAuthMethod.LOCAL,
                password_hash=hash_password(password),
                disabled_at=datetime.now(UTC) if disabled else None,
            )
        )
        session.commit()
    return tenant_id, user_id


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as session:
        for table in ("user_api_keys", "users", "operators"):
            session.execute(
                text(f"DELETE FROM {table} WHERE tenant_id = :id"), {"id": tenant_id}
            )
        session.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        session.commit()


def _make_client() -> TestClient:
    return TestClient(
        create_app(
            Settings(
                app_name="auth-test",
                environment="test",
                log_level="CRITICAL",
                operator_auth_signing_secret="ignored",
                portal_session_signing_secret=_TEST_SIGNING_SECRET,
            )
        )
    )


def test_local_login_returns_session_jwt_on_correct_password() -> None:
    factory = _build_factory()
    tenant_id, user_id = _seed_local_user(
        factory, email="alice@corp.example", password="very-strong-12+chars"
    )
    try:
        with _make_client() as client:
            r = client.post(
                f"/api/v1/auth/{tenant_id}/login",
                json={
                    "email": "alice@corp.example",
                    "password": "very-strong-12+chars",
                },
            )
        assert r.status_code == 200
        body = r.json()
        assert body["user_id"] == str(user_id)
        assert body["auth_method"] == "local"
        # Round-trip the session JWT.
        sess = verify_portal_session(
            body["session_token"], signing_secret=_TEST_SIGNING_SECRET
        )
        assert sess.tenant_id == tenant_id
        assert sess.user_id == user_id
    finally:
        _cleanup(factory, tenant_id)


def test_local_login_rejects_wrong_password_with_401() -> None:
    factory = _build_factory()
    tenant_id, _ = _seed_local_user(
        factory, email="bob@corp.example", password="very-strong-12+chars"
    )
    try:
        with _make_client() as client:
            r = client.post(
                f"/api/v1/auth/{tenant_id}/login",
                json={"email": "bob@corp.example", "password": "wrong-password"},
            )
        assert r.status_code == 401
    finally:
        _cleanup(factory, tenant_id)


def test_local_login_rejects_unknown_email_with_401_anti_enumeration() -> None:
    """Same generic 401 as wrong-password — attacker can't probe which
    emails exist by comparing response shapes."""
    factory = _build_factory()
    # Seed a tenant but NO user with the queried email.
    tenant_id, _ = _seed_local_user(
        factory, email="known@corp.example", password="very-strong-12+chars"
    )
    try:
        with _make_client() as client:
            r = client.post(
                f"/api/v1/auth/{tenant_id}/login",
                json={"email": "unknown@corp.example", "password": "anything"},
            )
        assert r.status_code == 401
    finally:
        _cleanup(factory, tenant_id)


def test_local_login_rejects_disabled_user() -> None:
    factory = _build_factory()
    tenant_id, _ = _seed_local_user(
        factory,
        email="disabled@corp.example",
        password="very-strong-12+chars",
        disabled=True,
    )
    try:
        with _make_client() as client:
            r = client.post(
                f"/api/v1/auth/{tenant_id}/login",
                json={
                    "email": "disabled@corp.example",
                    "password": "very-strong-12+chars",
                },
            )
        assert r.status_code == 401
    finally:
        _cleanup(factory, tenant_id)


def test_oidc_initiate_returns_404_when_provider_not_configured() -> None:
    """Default Settings has no OIDC providers wired — `/auth/.../oidc/microsoft`
    should 404 rather than crash."""
    tenant_id = uuid4()
    with _make_client() as client:
        r = client.get(f"/api/v1/auth/{tenant_id}/oidc/microsoft")
    assert r.status_code == 404
