"""JIT-1 · HTTP-level tests for the just-in-time access endpoints.

The service tests (`test_jit_access.py`) cover the logic; these cover the
wiring — routing, auth, status codes, and the shape the two UIs consume.
The end-to-end walk is the important one: an operator turns JIT on, a
user self-serves an elevation, and it shows up on the operator's live
list. If any link in that chain is mis-wired the feature is unusable
however correct the service layer is.
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

_OPERATOR_SECRET = "test-operator-secret-jit"
_PORTAL_SECRET = "test-portal-secret-jit"


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(
        create_engine(_DATABASE_URL, future=True), autoflush=False, future=True
    )


def _seed(
    factory: Any,
    *,
    visibility: VirtualServerVisibility = VirtualServerVisibility.PRIVATE,
) -> tuple[UUID, UUID, UUID, UUID]:
    tenant_id, operator_id, user_id, vserver_id = (
        uuid4(), uuid4(), uuid4(), uuid4()
    )
    with factory() as s:
        s.add(Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED))
        s.add(Operator(
            id=operator_id, tenant_id=tenant_id,
            email=f"op-{operator_id.hex[:6]}@test", role=OperatorRole.ADMIN,
        ))
        s.add(User(
            id=user_id, tenant_id=tenant_id, email=f"u-{user_id.hex[:6]}@test",
            auth_method=UserAuthMethod.LOCAL, password_hash="x" * 60,
        ))
        s.add(VirtualServer(
            id=vserver_id, tenant_id=tenant_id, name=f"vs-{vserver_id.hex[:6]}",
            visibility=visibility, created_by=operator_id,
        ))
        s.commit()
    return tenant_id, operator_id, user_id, vserver_id


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as s:
        for table in (
            "access_requests", "admin_audit_log", "virtual_server_grants",
            "user_api_keys", "users", "virtual_server_tools",
            "virtual_servers", "operators",
        ):
            s.execute(
                text(f"DELETE FROM {table} WHERE tenant_id = :id"),
                {"id": tenant_id},
            )
        s.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        s.commit()


def _client() -> TestClient:
    return TestClient(create_app(Settings(
        app_name="jit-api-test", environment="test", log_level="CRITICAL",
        operator_auth_signing_secret=_OPERATOR_SECRET,
        portal_session_signing_secret=_PORTAL_SECRET,
    )))


def _op(tenant_id: UUID, operator_id: UUID) -> dict[str, str]:
    return {"Authorization": f"Bearer {mint_operator_test_token(
        tenant_id=tenant_id, operator_id=operator_id,
        signing_secret=_OPERATOR_SECRET)}"}


def _portal(tenant_id: UUID, user_id: UUID) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_portal_session(
        tenant_id=tenant_id, user_id=user_id, email='end-user@test',
        auth_method='local', signing_secret=_PORTAL_SECRET, ttl_seconds=300)}"}


# --- The end-to-end walk ---------------------------------------------------


def test_operator_enables_jit_then_user_self_serves_an_elevation() -> None:
    """The whole feature in one pass: configure → request → live list.
    A break anywhere in this chain makes JIT unusable regardless of how
    correct the service layer is."""

    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed(factory)
    try:
        client = _client()

        cfg = client.patch(
            f"/api/v1/vservers/{vserver_id}/jit",
            headers=_op(tenant_id, operator_id),
            json={
                "enabled": True, "max_duration_seconds": 7200,
                "auto_approve": True, "require_justification": True,
            },
        )
        assert cfg.status_code == 200, cfg.text
        assert cfg.json()["jit_enabled"] is True
        assert cfg.json()["jit_max_duration_seconds"] == 7200

        # The portal learns the policy from the server, not a hard-coded list.
        opts = client.get(
            f"/api/v1/portal/{tenant_id}/vservers/{vserver_id}/jit-options",
            headers=_portal(tenant_id, user_id),
        )
        assert opts.status_code == 200, opts.text
        body = opts.json()
        assert body["jit_enabled"] is True
        assert body["auto_approve"] is True
        assert body["require_justification"] is True
        # Presets above the ceiling are filtered out server-side.
        assert body["duration_presets_seconds"]
        assert max(body["duration_presets_seconds"]) <= 7200

        got = client.post(
            f"/api/v1/portal/{tenant_id}/jit-requests",
            headers=_portal(tenant_id, user_id),
            json={
                "vserver_id": str(vserver_id), "duration_seconds": 3600,
                "justification": "prod incident 91",
            },
        )
        assert got.status_code == 201, got.text
        assert got.json()["granted"] is True
        assert got.json()["expires_at"]
        assert got.json()["request_id"] is None

        live = client.get(
            "/api/v1/vservers/jit/elevations",
            headers=_op(tenant_id, operator_id),
        )
        assert live.status_code == 200, live.text
        rows = live.json()
        assert len(rows) == 1
        assert rows[0]["user_id"] == str(user_id)
        assert rows[0]["granted_via"] == "jit_auto"
        assert rows[0]["justification"] == "prod incident 91"
        assert 3500 < rows[0]["seconds_remaining"] <= 3600

        # And the catalog now reports the access as temporary, so the
        # user is not surprised when it lapses.
        cat = client.get(
            f"/api/v1/portal/{tenant_id}/catalog",
            headers=_portal(tenant_id, user_id),
        )
        assert cat.status_code == 200, cat.text
        entry = next(c for c in cat.json() if c["vserver_id"] == str(vserver_id))
        assert entry["has_access"] is True
        assert entry["access_expires_at"] is not None
    finally:
        _cleanup(factory, tenant_id)


def test_queued_request_carries_the_duration_to_the_operator_queue() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed(factory)
    try:
        client = _client()
        client.patch(
            f"/api/v1/vservers/{vserver_id}/jit",
            headers=_op(tenant_id, operator_id),
            json={"enabled": True, "auto_approve": False},
        )
        res = client.post(
            f"/api/v1/portal/{tenant_id}/jit-requests",
            headers=_portal(tenant_id, user_id),
            json={
                "vserver_id": str(vserver_id), "duration_seconds": 1800,
                "justification": "quarterly close",
            },
        )
        assert res.status_code == 201, res.text
        assert res.json()["granted"] is False
        assert res.json()["request_id"]

        queue = client.get(
            "/api/v1/access-requests", headers=_op(tenant_id, operator_id)
        )
        assert queue.status_code == 200
        row = next(r for r in queue.json() if r["id"] == res.json()["request_id"])
        # The reviewer needs "how much", not just "who wants what".
        assert row["requested_duration_seconds"] == 1800
        assert row["note"] == "quarterly close"

        approved = client.post(
            f"/api/v1/access-requests/{row['id']}/approve",
            headers=_op(tenant_id, operator_id),
            json={"duration_seconds": 900},
        )
        assert approved.status_code == 200, approved.text

        live = client.get(
            "/api/v1/vservers/jit/elevations",
            headers=_op(tenant_id, operator_id),
        )
        rows = live.json()
        assert len(rows) == 1
        assert rows[0]["granted_via"] == "jit_approved"
        assert 800 < rows[0]["seconds_remaining"] <= 900
    finally:
        _cleanup(factory, tenant_id)


# --- Rejections ------------------------------------------------------------


def test_over_ceiling_request_is_400_with_the_ceiling_in_the_message() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed(factory)
    try:
        client = _client()
        client.patch(
            f"/api/v1/vservers/{vserver_id}/jit",
            headers=_op(tenant_id, operator_id),
            json={"enabled": True, "max_duration_seconds": 3600,
                  "auto_approve": True, "require_justification": False},
        )
        res = client.post(
            f"/api/v1/portal/{tenant_id}/jit-requests",
            headers=_portal(tenant_id, user_id),
            json={"vserver_id": str(vserver_id), "duration_seconds": 8 * 3600},
        )
        assert res.status_code == 400
        # The caller can retry correctly instead of bisecting.
        assert "3600" in res.json()["detail"]
    finally:
        _cleanup(factory, tenant_id)


def test_missing_justification_is_400_when_the_vserver_requires_one() -> None:
    factory = _factory()
    tenant_id, operator_id, user_id, vserver_id = _seed(factory)
    try:
        client = _client()
        client.patch(
            f"/api/v1/vservers/{vserver_id}/jit",
            headers=_op(tenant_id, operator_id),
            json={"enabled": True, "auto_approve": True,
                  "require_justification": True},
        )
        res = client.post(
            f"/api/v1/portal/{tenant_id}/jit-requests",
            headers=_portal(tenant_id, user_id),
            json={"vserver_id": str(vserver_id), "duration_seconds": 600},
        )
        assert res.status_code == 400
        assert "reason" in res.json()["detail"].lower()
    finally:
        _cleanup(factory, tenant_id)


def test_jit_on_a_public_vserver_is_refused() -> None:
    factory = _factory()
    tenant_id, operator_id, _user, vserver_id = _seed(
        factory, visibility=VirtualServerVisibility.PUBLIC
    )
    try:
        client = _client()
        res = client.patch(
            f"/api/v1/vservers/{vserver_id}/jit",
            headers=_op(tenant_id, operator_id),
            json={"enabled": True},
        )
        assert res.status_code == 400
        assert "public" in res.json()["detail"].lower()
    finally:
        _cleanup(factory, tenant_id)


def test_jit_endpoints_require_their_own_auth() -> None:
    """A portal session must not drive the operator policy endpoint, and
    an unauthenticated caller must not read who is elevated."""

    factory = _factory()
    tenant_id, _op_id, user_id, vserver_id = _seed(factory)
    try:
        client = _client()
        assert client.get("/api/v1/vservers/jit/elevations").status_code in (401, 403)
        assert client.patch(
            f"/api/v1/vservers/{vserver_id}/jit", json={"enabled": True}
        ).status_code in (401, 403)
        # A portal bearer is not an operator bearer.
        assert client.patch(
            f"/api/v1/vservers/{vserver_id}/jit",
            headers=_portal(tenant_id, user_id),
            json={"enabled": True},
        ).status_code in (401, 403)
        assert client.post(
            f"/api/v1/portal/{tenant_id}/jit-requests",
            json={"vserver_id": str(vserver_id), "duration_seconds": 600},
        ).status_code in (401, 403)
    finally:
        _cleanup(factory, tenant_id)
