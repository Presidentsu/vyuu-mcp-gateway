"""End-to-end tests for the A3-γ access-request endpoints.

Covers:
- Portal (end-user) routes under `/api/v1/portal/{tenant_id}/access-requests`
- Admin routes under `/api/v1/access-requests`

Same env-gating as the other admin-API tests (`VYUU_TEST_DATABASE_URL`).
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
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.config import Settings  # noqa: E402
from vyuu_gateway.db.models import (  # noqa: E402
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
    User,
    UserAuthMethod,
    VirtualServer,
    VirtualServerVisibility,
)
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.operator_auth.fake import mint_operator_test_token  # noqa: E402
from vyuu_gateway.users.sessions import issue_portal_session  # noqa: E402

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set",
)

_OPERATOR_SECRET = "test-operator-secret-A3γ"
_PORTAL_SECRET = "test-portal-secret-A3γ"


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(create_engine(_DATABASE_URL, future=True), autoflush=False, future=True)


def _seed_world(
    factory: Any,
    *,
    visibility: VirtualServerVisibility = VirtualServerVisibility.PRIVATE,
) -> tuple[UUID, UUID, UUID, UUID]:
    tenant_id = uuid4()
    operator_id = uuid4()
    user_id = uuid4()
    vserver_id = uuid4()
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
        session.add(
            User(
                id=user_id,
                tenant_id=tenant_id,
                email=f"u-{user_id.hex[:6]}@test",
                auth_method=UserAuthMethod.LOCAL,
                password_hash="x" * 60,
            )
        )
        session.add(
            VirtualServer(
                id=vserver_id,
                tenant_id=tenant_id,
                name=f"vs-{vserver_id.hex[:6]}",
                visibility=visibility,
                created_by=operator_id,
            )
        )
        session.commit()
    return tenant_id, operator_id, user_id, vserver_id


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
                app_name="ar-api-test",
                environment="test",
                log_level="CRITICAL",
                operator_auth_signing_secret=_OPERATOR_SECRET,
                portal_session_signing_secret=_PORTAL_SECRET,
            )
        )
    )


def _operator_headers(tenant_id: UUID, operator_id: UUID) -> dict[str, str]:
    token = mint_operator_test_token(
        tenant_id=tenant_id,
        operator_id=operator_id,
        signing_secret=_OPERATOR_SECRET,
    )
    return {"Authorization": f"Bearer {token}"}


def _portal_headers(tenant_id: UUID, user_id: UUID) -> dict[str, str]:
    token = issue_portal_session(
        tenant_id=tenant_id,
        user_id=user_id,
        email="end-user@test",
        auth_method="local",
        signing_secret=_PORTAL_SECRET,
        ttl_seconds=300,
    )
    return {"Authorization": f"Bearer {token}"}


# --- Portal endpoints ------------------------------------------------------


def test_portal_submit_creates_pending_request() -> None:
    factory = _factory()
    tenant_id, _, user_id, vserver_id = _seed_world(factory)
    try:
        with _make_client() as client:
            r = client.post(
                f"/api/v1/portal/{tenant_id}/access-requests",
                json={"vserver_id": str(vserver_id), "note": "let me in"},
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["status"] == "pending"
        assert body["note"] == "let me in"
        assert body["user_id"] == str(user_id)
    finally:
        _cleanup(factory, tenant_id)


def test_portal_submit_for_public_vserver_rejected_409() -> None:
    factory = _factory()
    tenant_id, _, user_id, vserver_id = _seed_world(
        factory, visibility=VirtualServerVisibility.PUBLIC
    )
    try:
        with _make_client() as client:
            r = client.post(
                f"/api/v1/portal/{tenant_id}/access-requests",
                json={"vserver_id": str(vserver_id)},
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 409
    finally:
        _cleanup(factory, tenant_id)


def test_portal_submit_cross_tenant_token_rejected_403() -> None:
    """Token signed for tenant A used at tenant B's URL → 403."""
    factory = _factory()
    tenant_id, _, user_id, vserver_id = _seed_world(factory)
    try:
        wrong_tenant = uuid4()
        with _make_client() as client:
            r = client.post(
                f"/api/v1/portal/{wrong_tenant}/access-requests",
                json={"vserver_id": str(vserver_id)},
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 403
    finally:
        _cleanup(factory, tenant_id)


def test_portal_submit_without_token_returns_401() -> None:
    factory = _factory()
    tenant_id, _, _, vserver_id = _seed_world(factory)
    try:
        with _make_client() as client:
            r = client.post(
                f"/api/v1/portal/{tenant_id}/access-requests",
                json={"vserver_id": str(vserver_id)},
            )
        assert r.status_code == 401
    finally:
        _cleanup(factory, tenant_id)


def test_portal_list_mine_returns_only_users_own() -> None:
    factory = _factory()
    tenant_id, _, user_id, vserver_id = _seed_world(factory)
    try:
        with _make_client() as client:
            client.post(
                f"/api/v1/portal/{tenant_id}/access-requests",
                json={"vserver_id": str(vserver_id), "note": "mine"},
                headers=_portal_headers(tenant_id, user_id),
            )
            # A different user requests the same vserver — shouldn't
            # appear in the first user's list.
            other_user_id = uuid4()
            with factory() as session:
                session.add(
                    User(
                        id=other_user_id,
                        tenant_id=tenant_id,
                        email=f"other-{other_user_id.hex[:6]}@test",
                        auth_method=UserAuthMethod.LOCAL,
                        password_hash="y" * 60,
                    )
                )
                session.commit()
            client.post(
                f"/api/v1/portal/{tenant_id}/access-requests",
                json={"vserver_id": str(vserver_id), "note": "theirs"},
                headers=_portal_headers(tenant_id, other_user_id),
            )
            r = client.get(
                f"/api/v1/portal/{tenant_id}/access-requests",
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 200
        body = r.json()
        assert len(body) == 1
        assert body[0]["note"] == "mine"
    finally:
        _cleanup(factory, tenant_id)


def test_portal_withdraw_pending_succeeds() -> None:
    factory = _factory()
    tenant_id, _, user_id, vserver_id = _seed_world(factory)
    try:
        with _make_client() as client:
            create = client.post(
                f"/api/v1/portal/{tenant_id}/access-requests",
                json={"vserver_id": str(vserver_id)},
                headers=_portal_headers(tenant_id, user_id),
            )
            request_id = create.json()["id"]
            r = client.delete(
                f"/api/v1/portal/{tenant_id}/access-requests/{request_id}",
                headers=_portal_headers(tenant_id, user_id),
            )
        assert r.status_code == 200
        assert r.json()["status"] == "withdrawn"
    finally:
        _cleanup(factory, tenant_id)


# --- Admin endpoints -------------------------------------------------------


def test_admin_list_pending_queue() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(factory)
    try:
        with _make_client() as client:
            client.post(
                f"/api/v1/portal/{tenant_id}/access-requests",
                json={"vserver_id": str(vserver_id)},
                headers=_portal_headers(tenant_id, user_id),
            )
            r = client.get(
                "/api/v1/access-requests?status_filter=pending",
                headers=_operator_headers(tenant_id, operator_id),
            )
        assert r.status_code == 200
        body = r.json()
        assert len(body) == 1
        assert body[0]["status"] == "pending"
    finally:
        _cleanup(factory, tenant_id)


def test_admin_approve_creates_grant_and_marks_request() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(factory)
    try:
        with _make_client() as client:
            create = client.post(
                f"/api/v1/portal/{tenant_id}/access-requests",
                json={"vserver_id": str(vserver_id), "note": "please"},
                headers=_portal_headers(tenant_id, user_id),
            )
            request_id = create.json()["id"]
            r = client.post(
                f"/api/v1/access-requests/{request_id}/approve",
                headers=_operator_headers(tenant_id, operator_id),
            )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "approved"
        assert body["created_grant_id"] is not None
    finally:
        _cleanup(factory, tenant_id)


def test_admin_decline_records_note() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(factory)
    try:
        with _make_client() as client:
            create = client.post(
                f"/api/v1/portal/{tenant_id}/access-requests",
                json={"vserver_id": str(vserver_id)},
                headers=_portal_headers(tenant_id, user_id),
            )
            request_id = create.json()["id"]
            r = client.post(
                f"/api/v1/access-requests/{request_id}/decline",
                json={"decision_note": "needs more business context"},
                headers=_operator_headers(tenant_id, operator_id),
            )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "declined"
        assert body["decision_note"] == "needs more business context"
        assert body["created_grant_id"] is None
    finally:
        _cleanup(factory, tenant_id)


def test_admin_approve_already_approved_returns_409() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed_world(factory)
    try:
        with _make_client() as client:
            create = client.post(
                f"/api/v1/portal/{tenant_id}/access-requests",
                json={"vserver_id": str(vserver_id)},
                headers=_portal_headers(tenant_id, user_id),
            )
            request_id = create.json()["id"]
            client.post(
                f"/api/v1/access-requests/{request_id}/approve",
                headers=_operator_headers(tenant_id, operator_id),
            )
            r = client.post(
                f"/api/v1/access-requests/{request_id}/approve",
                headers=_operator_headers(tenant_id, operator_id),
            )
        assert r.status_code == 409
    finally:
        _cleanup(factory, tenant_id)
