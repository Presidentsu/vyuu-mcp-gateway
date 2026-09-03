"""End-to-end test: ApiKeyIdentityProvider against real Postgres.

Verifies the bearer-only validation path: no `x-vyuu-*` headers
are honored; the gateway derives `(tenant_id, user_id)` from the
matched `user_api_keys` row alone.

Env-gated on `VYUU_TEST_DATABASE_URL` (same gating as the existing
real-Postgres RLS tests). Skipped in the default suite; runs in the
no-skip pass.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from vyuu_gateway.db.models import (
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
    User,
    UserApiKey,
    UserAuthMethod,
)
from vyuu_gateway.identity.api_key_provider import ApiKeyIdentityProvider
from vyuu_gateway.identity.provider import (
    IdentityCredentials,
    IdentityValidationError,
)
from vyuu_gateway.users.api_keys import issue_new_key

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set; skipping real-Postgres integration",
)


def _build_session() -> Any:
    """Dedicated engine + session_factory bound to the test database."""
    assert _DATABASE_URL is not None
    engine = create_engine(_DATABASE_URL, future=True)
    return sessionmaker(engine, autoflush=False, future=True)


def _seed_user_with_key(
    session_factory: Any,
    *,
    expires_in: timedelta | None = None,
    revoked: bool = False,
    disabled: bool = False,
) -> tuple[UUID, UUID, UUID, str]:
    """Insert a tenant + operator + user + api_key. Returns the issued
    plaintext + ids the test needs."""
    with session_factory() as session:
        tenant_id = uuid4()
        operator_id = uuid4()
        user_id = uuid4()
        key_id = uuid4()
        issued = issue_new_key(key_id=key_id)
        now = datetime.now(UTC)

        session.add(Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED))
        session.add(
            Operator(
                id=operator_id,
                tenant_id=tenant_id,
                email=f"op-{operator_id.hex[:6]}@test",
                role=OperatorRole.ADMIN,
            )
        )
        session.add(
            User(
                id=user_id,
                tenant_id=tenant_id,
                email=f"u-{user_id.hex[:6]}@test",
                display_name="Test User",
                auth_method=UserAuthMethod.LOCAL,
                password_hash="$2b$12$placeholder",
                disabled_at=now if disabled else None,
            )
        )
        session.add(
            UserApiKey(
                id=key_id,
                tenant_id=tenant_id,
                user_id=user_id,
                label="test-key",
                key_hash=issued.key_hash,
                key_prefix=issued.key_prefix,
                expires_at=now + expires_in if expires_in else None,
                revoked_at=now if revoked else None,
            )
        )
        session.commit()
        return tenant_id, user_id, key_id, issued.plaintext


def _cleanup(session_factory: Any, tenant_id: UUID) -> None:
    with session_factory() as session:
        session.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        session.commit()


def test_valid_bearer_returns_principal_keyed_on_user_id() -> None:
    factory = _build_session()
    tenant_id, user_id, _, plaintext = _seed_user_with_key(factory)
    try:
        provider = ApiKeyIdentityProvider(factory)
        principal = provider.validate_principal(
            tenant_id=tenant_id,
            credentials=IdentityCredentials(
                headers={"Authorization": f"Bearer {plaintext}"}
            ),
        )
        # Per the architectural shift documented in api_key_provider.py:
        # principal.id is the USER UUID, not a free-form header value.
        assert principal.id == str(user_id)
        assert principal.tenant_id == tenant_id
    finally:
        _cleanup(factory, tenant_id)


def test_revoked_key_rejected() -> None:
    factory = _build_session()
    tenant_id, _, _, plaintext = _seed_user_with_key(factory, revoked=True)
    try:
        provider = ApiKeyIdentityProvider(factory)
        with pytest.raises(IdentityValidationError):
            provider.validate_principal(
                tenant_id=tenant_id,
                credentials=IdentityCredentials(
                    headers={"Authorization": f"Bearer {plaintext}"}
                ),
            )
    finally:
        _cleanup(factory, tenant_id)


def test_expired_key_rejected() -> None:
    factory = _build_session()
    tenant_id, _, _, plaintext = _seed_user_with_key(
        factory, expires_in=timedelta(seconds=-1)
    )
    try:
        provider = ApiKeyIdentityProvider(factory)
        with pytest.raises(IdentityValidationError):
            provider.validate_principal(
                tenant_id=tenant_id,
                credentials=IdentityCredentials(
                    headers={"Authorization": f"Bearer {plaintext}"}
                ),
            )
    finally:
        _cleanup(factory, tenant_id)


def test_disabled_user_rejected() -> None:
    factory = _build_session()
    tenant_id, _, _, plaintext = _seed_user_with_key(factory, disabled=True)
    try:
        provider = ApiKeyIdentityProvider(factory)
        with pytest.raises(IdentityValidationError):
            provider.validate_principal(
                tenant_id=tenant_id,
                credentials=IdentityCredentials(
                    headers={"Authorization": f"Bearer {plaintext}"}
                ),
            )
    finally:
        _cleanup(factory, tenant_id)


def test_cross_tenant_bearer_rejected() -> None:
    """A key issued in tenant A cannot be used to claim identity in tenant B."""
    factory = _build_session()
    tenant_a, _, _, plaintext = _seed_user_with_key(factory)
    other_tenant = uuid4()
    try:
        provider = ApiKeyIdentityProvider(factory)
        with pytest.raises(IdentityValidationError):
            provider.validate_principal(
                tenant_id=other_tenant,  # NOT the bearer's home tenant
                credentials=IdentityCredentials(
                    headers={"Authorization": f"Bearer {plaintext}"}
                ),
            )
    finally:
        _cleanup(factory, tenant_a)


def test_garbled_bearer_rejected() -> None:
    factory = _build_session()
    tenant_id, _, _, _ = _seed_user_with_key(factory)
    try:
        provider = ApiKeyIdentityProvider(factory)
        with pytest.raises(IdentityValidationError):
            provider.validate_principal(
                tenant_id=tenant_id,
                credentials=IdentityCredentials(
                    headers={"Authorization": "Bearer not-a-valid-key"}
                ),
            )
    finally:
        _cleanup(factory, tenant_id)


def test_xyu_legacy_headers_are_ignored() -> None:
    """The architectural shift: even if the request carries the old
    `x-vyuu-*` headers (which the FAKE provider trusted), the real
    provider ignores them entirely and validates ONLY the bearer."""
    factory = _build_session()
    tenant_id, user_id, _, plaintext = _seed_user_with_key(factory)
    try:
        provider = ApiKeyIdentityProvider(factory)
        principal = provider.validate_principal(
            tenant_id=tenant_id,
            credentials=IdentityCredentials(
                headers={
                    "Authorization": f"Bearer {plaintext}",
                    "x-vyuu-tenant-id": str(uuid4()),  # try to claim a different tenant
                    "x-vyuu-principal-id": "spoofed-id",
                    "x-vyuu-principal-display": "spoofed-display",
                }
            ),
        )
        # All the spoofing failed: principal still keyed on the bearer's
        # actual user_id, and tenant matches the request path.
        assert principal.id == str(user_id)
        assert principal.tenant_id == tenant_id
    finally:
        _cleanup(factory, tenant_id)
