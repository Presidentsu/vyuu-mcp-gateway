"""End-to-end tests for the operator-side admin endpoints (users,
groups, API keys, grants, vserver visibility).

Exercises the routes through `TestClient` against a real test Postgres,
so RLS-bound sessions + the actual ORM cascade behavior are honored.
Skipped when `VYUU_TEST_DATABASE_URL` is unset.

Implementation note: we bind `SessionLocal` to the test DB by pointing
`VYUU_DATABASE_URL` at it BEFORE any vyuu_gateway imports. Same pattern
the existing real-Postgres RLS integration tests use — see
`tests/integration/test_rls_real_postgres.py`.
"""

from __future__ import annotations

import os

# Must come BEFORE any `vyuu_gateway` imports — `SessionLocal` is built
# at module import time using `get_settings().database_url`, and that
# `Settings` object reads `VYUU_DATABASE_URL` from env exactly once.
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
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
    VirtualServer,
    VirtualServerVisibility,
)
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.operator_auth.fake import mint_operator_test_token  # noqa: E402

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set; skipping integration",
)

_TEST_SIGNING_SECRET = "test-operator-auth-secret-α8"


def _build_engine_and_factory() -> tuple[Any, Any]:
    assert _DATABASE_URL is not None
    engine = create_engine(_DATABASE_URL, future=True)
    return engine, sessionmaker(engine, autoflush=False, future=True)


def _make_tenant_and_operator() -> tuple[UUID, UUID, dict[str, str], Any]:
    """Insert a fresh tenant + operator row directly. Returns ids + headers."""
    engine, factory = _build_engine_and_factory()
    tenant_id = uuid4()
    operator_id = uuid4()
    with factory() as session:
        session.add(Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED))
        session.add(
            Operator(
                id=operator_id,
                tenant_id=tenant_id,
                email=f"op-{operator_id.hex[:6]}@test",
                role=OperatorRole.ADMIN,
            )
        )
        session.commit()
    token = mint_operator_test_token(
        tenant_id=tenant_id,
        operator_id=operator_id,
        signing_secret=_TEST_SIGNING_SECRET,
    )
    return tenant_id, operator_id, {"Authorization": f"Bearer {token}"}, factory


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    """Wipe a test tenant. Done in dependency order because some FK
    constraints (membership.added_by → operators) are RESTRICT, not
    CASCADE — production never deletes operators or tenants this way,
    so the production semantics are fine; tests just need the explicit
    order."""
    with factory() as session:
        for table in (
            "user_group_memberships",
            "virtual_server_grants",
            "user_api_keys",
            "groups",
            "users",
            "virtual_server_tools",
            "virtual_servers",
        ):
            session.execute(text(f"DELETE FROM {table} WHERE tenant_id = :id")
                            if table != "user_group_memberships"
                            else text(
                                "DELETE FROM user_group_memberships WHERE user_id IN "
                                "(SELECT id FROM users WHERE tenant_id = :id)"
                            ), {"id": tenant_id})
        session.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        session.commit()


def _make_client() -> TestClient:
    """Build a TestClient. `SessionLocal` is already pointed at the
    test DB via the env-var nudge at the top of the module."""

    return TestClient(
        create_app(
            Settings(
                app_name="users-api-test",
                environment="test",
                log_level="CRITICAL",
                operator_auth_signing_secret=_TEST_SIGNING_SECRET,
            )
        )
    )


def test_create_local_user_persists_with_bcrypted_password() -> None:
    tenant_id, _, headers, factory = _make_tenant_and_operator()
    try:
        with _make_client() as client:
            response = client.post(
                "/api/v1/users",
                json={
                    "email": "alice@corp.example",
                    "password": "very-strong-12+chars",
                    "display_name": "Alice",
                },
                headers=headers,
            )
        assert response.status_code == 201
        body = response.json()
        assert body["email"] == "alice@corp.example"
        assert body["auth_method"] == "local"
        assert body["must_change_password"] is True
        assert UUID(body["id"])
    finally:
        _cleanup(factory, tenant_id)


def test_create_user_rejects_weak_password() -> None:
    tenant_id, _, headers, factory = _make_tenant_and_operator()
    try:
        with _make_client() as client:
            response = client.post(
                "/api/v1/users",
                json={"email": "bob@corp.example", "password": "short"},
                headers=headers,
            )
        assert response.status_code == 422
    finally:
        _cleanup(factory, tenant_id)


def test_duplicate_email_rejected_409() -> None:
    tenant_id, _, headers, factory = _make_tenant_and_operator()
    try:
        with _make_client() as client:
            client.post(
                "/api/v1/users",
                json={"email": "dup@corp.example", "password": "very-strong-12+chars"},
                headers=headers,
            )
            response = client.post(
                "/api/v1/users",
                json={"email": "dup@corp.example", "password": "another-strong-pw"},
                headers=headers,
            )
        assert response.status_code == 409
    finally:
        _cleanup(factory, tenant_id)


def test_issue_api_key_returns_plaintext_only_once() -> None:
    tenant_id, _, headers, factory = _make_tenant_and_operator()
    try:
        with _make_client() as client:
            user_response = client.post(
                "/api/v1/users",
                json={
                    "email": "carol@corp.example",
                    "password": "very-strong-12+chars",
                },
                headers=headers,
            )
            user_id = user_response.json()["id"]

            # Issue a key.
            issue_response = client.post(
                f"/api/v1/users/{user_id}/api-keys",
                json={"label": "Carol's Claude Desktop"},
                headers=headers,
            )
            assert issue_response.status_code == 201
            issued = issue_response.json()
            plaintext = issued["plaintext"]
            assert plaintext.startswith("vyuu_user_")
            key_id = issued["id"]

            # Listing returns metadata but NEVER the plaintext.
            list_response = client.get(
                f"/api/v1/users/{user_id}/api-keys", headers=headers
            )
        assert list_response.status_code == 200
        rows = list_response.json()
        assert len(rows) == 1
        assert "plaintext" not in rows[0]
        assert rows[0]["id"] == key_id
        assert rows[0]["key_prefix"] == issued["key_prefix"]
    finally:
        _cleanup(factory, tenant_id)


def test_revoke_api_key_marks_revoked_at() -> None:
    tenant_id, _, headers, factory = _make_tenant_and_operator()
    try:
        with _make_client() as client:
            user_response = client.post(
                "/api/v1/users",
                json={"email": "dave@corp.example", "password": "very-strong-12+chars"},
                headers=headers,
            )
            user_id = user_response.json()["id"]
            issue_response = client.post(
                f"/api/v1/users/{user_id}/api-keys",
                json={"label": "rev-test"},
                headers=headers,
            )
            key_id = issue_response.json()["id"]

            revoke = client.delete(
                f"/api/v1/users/{user_id}/api-keys/{key_id}", headers=headers
            )
        assert revoke.status_code == 200
        assert revoke.json()["revoked_at"] is not None
    finally:
        _cleanup(factory, tenant_id)


def test_create_group_and_add_member() -> None:
    tenant_id, _, headers, factory = _make_tenant_and_operator()
    try:
        with _make_client() as client:
            user_response = client.post(
                "/api/v1/users",
                json={"email": "eve@corp.example", "password": "very-strong-12+chars"},
                headers=headers,
            )
            user_id = user_response.json()["id"]

            group_response = client.post(
                "/api/v1/groups",
                json={"name": "engineering"},
                headers=headers,
            )
            assert group_response.status_code == 201
            group_id = group_response.json()["id"]

            add = client.post(
                f"/api/v1/groups/{group_id}/members",
                json={"user_id": user_id},
                headers=headers,
            )
            assert add.status_code == 204

            # GET /groups/{id}/members — backs the operator console's
            # inline group editor (chip list of current members).
            members = client.get(
                f"/api/v1/groups/{group_id}/members", headers=headers
            )
            assert members.status_code == 200
            payload = members.json()
            assert isinstance(payload, list)
            assert len(payload) == 1
            assert payload[0]["id"] == user_id
            assert payload[0]["email"] == "eve@corp.example"

            # 404 for a group_id that doesn't exist in this tenant.
            from uuid import uuid4
            bogus = client.get(
                f"/api/v1/groups/{uuid4()}/members", headers=headers
            )
            assert bogus.status_code == 404

            # After remove, list returns empty.
            remove = client.delete(
                f"/api/v1/groups/{group_id}/members/{user_id}",
                headers=headers,
            )
            assert remove.status_code == 204
            members_after = client.get(
                f"/api/v1/groups/{group_id}/members", headers=headers
            )
            assert members_after.status_code == 200
            assert members_after.json() == []
    finally:
        _cleanup(factory, tenant_id)


def test_set_vserver_visibility_and_issue_grant_for_user() -> None:
    """End-to-end: vserver flips public→private, user gets a direct
    grant, list/revoke through the API."""
    tenant_id, operator_id, headers, factory = _make_tenant_and_operator()
    # Insert a fresh vserver row directly (bypassing the public registry
    # API since that's covered elsewhere; we just need a vserver to grant on).
    vserver_id = uuid4()
    with factory() as session:
        session.add(
            VirtualServer(
                id=vserver_id,
                tenant_id=tenant_id,
                name="sensitive-vserver",
                rename_map={},
                visibility=VirtualServerVisibility.PUBLIC,
                created_by=operator_id,
                created_at=datetime.now(UTC),
            )
        )
        session.commit()
    try:
        with _make_client() as client:
            user_response = client.post(
                "/api/v1/users",
                json={"email": "frank@corp.example", "password": "very-strong-12+chars"},
                headers=headers,
            )
            user_id = user_response.json()["id"]

            # Flip to private.
            visibility = client.patch(
                f"/api/v1/vservers/{vserver_id}/visibility",
                json={"visibility": "private"},
                headers=headers,
            )
            assert visibility.status_code == 200
            assert visibility.json()["visibility"] == "private"

            # Issue a direct user grant.
            grant_response = client.post(
                f"/api/v1/vservers/{vserver_id}/grants",
                json={"principal_kind": "user", "principal_id": user_id},
                headers=headers,
            )
            assert grant_response.status_code == 201
            grant_id = grant_response.json()["id"]

            # List shows the grant.
            list_response = client.get(
                f"/api/v1/vservers/{vserver_id}/grants", headers=headers
            )
            assert list_response.status_code == 200
            grants = list_response.json()
            assert len(grants) == 1
            assert grants[0]["id"] == grant_id

            # Revoke.
            revoke = client.delete(
                f"/api/v1/vservers/{vserver_id}/grants/{grant_id}", headers=headers
            )
        assert revoke.status_code == 200
        assert revoke.json()["revoked_at"] is not None
    finally:
        _cleanup(factory, tenant_id)


def test_endpoints_require_operator_auth() -> None:
    """All admin endpoints are operator-auth-gated. Spot-check the most
    sensitive ones return 401 without a valid bearer."""
    with _make_client() as client:
        for path in (
            "/api/v1/users",
            "/api/v1/groups",
        ):
            r = client.get(path)
            assert r.status_code == 401, path

        # Mutations
        r = client.post(
            "/api/v1/users", json={"email": "x@x.com", "password": "very-strong-12+chars"}
        )
        assert r.status_code == 401
