"""End-to-end tests for the SCIM 2.0 server.

Real-Postgres integration tests — skipped when
`VYUU_TEST_DATABASE_URL` is unset. The point is to exercise the
full SCIM lifecycle (connect directory → POST User → PATCH active=
false → DELETE) against a live DB and confirm the audit log
captures every step with `actor_kind='scim'`.
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
    reason="VYUU_TEST_DATABASE_URL not set; skipping SCIM integration",
)

_TEST_SIGNING_SECRET = "test-operator-auth-secret-α8"


def _build_engine_and_factory() -> tuple[Any, Any]:
    assert _DATABASE_URL is not None
    engine = create_engine(_DATABASE_URL, future=True)
    return engine, sessionmaker(engine, autoflush=False, future=True)


def _seed_tenant_and_operator() -> tuple[UUID, UUID, str]:
    """Insert a fresh tenant + operator. Returns (tenant_id, operator_id, bearer)."""

    _, Session = _build_engine_and_factory()
    tenant_id = uuid4()
    operator_id = uuid4()
    with Session() as setup:
        setup.add(Tenant(id=tenant_id, name=f"scim-test-{tenant_id}", tier=TenantTier.SHARED))
        setup.add(
            Operator(
                id=operator_id,
                tenant_id=tenant_id,
                email=f"admin-{operator_id}@example.com",
                role=OperatorRole.ADMIN,
                password_hash=None,
                must_change_password=False,
            )
        )
        setup.commit()
    bearer = mint_operator_test_token(
        tenant_id=tenant_id,
        operator_id=operator_id,
        signing_secret=_TEST_SIGNING_SECRET,
        display="scim-test-admin",
    )
    return tenant_id, operator_id, bearer


def _cleanup_tenant(tenant_id: UUID) -> None:
    _, Session = _build_engine_and_factory()
    with Session() as cleanup:
        # FK cascades from `tenants.id` handle the rest.
        cleanup.execute(text("DELETE FROM tenants WHERE id = :tid"), {"tid": str(tenant_id)})
        cleanup.commit()


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


def test_scim_full_user_lifecycle() -> None:
    """Connect directory → POST User → GET User → PATCH active=false →
    DELETE. Confirms each step writes the expected admin_audit_log
    row with `actor_kind='scim'`."""

    tenant_id, _operator_id, operator_bearer = _seed_tenant_and_operator()
    try:
        client = _build_client()

        # 1. Operator connects an Entra directory via the admin endpoint.
        connect_resp = client.post(
            "/api/v1/idp/directories",
            headers={"Authorization": f"Bearer {operator_bearer}"},
            json={
                "kind": "entra",
                "display_name": "Acme Corp · Entra ID",
                "signin_protocol": "oidc",
                "oidc": {
                    "issuer": "https://login.microsoftonline.com/contoso/v2.0",
                    "client_id": "00000000-0000-0000-0000-000000000001",
                    "client_secret_ref": "entra-client-secret",
                },
            },
        )
        assert connect_resp.status_code == 201, connect_resp.text
        connected = connect_resp.json()
        directory_id = connected["directory"]["id"]
        scim_bearer = connected["scim_token_plaintext"]
        assert scim_bearer.startswith("vyuu_scim_")

        scim_path = f"/scim/v2/{directory_id}"
        scim_headers = {"Authorization": f"Bearer {scim_bearer}"}

        # 2. SCIM ServiceProviderConfig (the IdP probes this first).
        cfg = client.get(f"{scim_path}/ServiceProviderConfig", headers=scim_headers)
        assert cfg.status_code == 200
        body = cfg.json()
        assert body["patch"]["supported"] is True
        assert body["filter"]["supported"] is True

        # 3. POST a new user.
        external_id = "entra-objectid-7777"
        create_resp = client.post(
            f"{scim_path}/Users",
            headers=scim_headers,
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "alice@acme.com",
                "name": {"givenName": "Alice", "familyName": "Anderson"},
                "emails": [{"value": "alice@acme.com", "primary": True}],
                "active": True,
                "externalId": external_id,
            },
        )
        assert create_resp.status_code == 201, create_resp.text
        user = create_resp.json()
        user_id = user["id"]
        assert user["userName"] == "alice@acme.com"
        assert user["active"] is True
        assert user["displayName"] == "Alice Anderson"
        assert user["externalId"] == external_id

        # 4. GET by id.
        get_resp = client.get(f"{scim_path}/Users/{user_id}", headers=scim_headers)
        assert get_resp.status_code == 200
        assert get_resp.json()["userName"] == "alice@acme.com"

        # 5. List with filter.
        filter_resp = client.get(
            f"{scim_path}/Users",
            headers=scim_headers,
            params={"filter": 'userName eq "alice@acme.com"'},
        )
        assert filter_resp.status_code == 200
        listing = filter_resp.json()
        assert listing["totalResults"] == 1
        assert listing["Resources"][0]["id"] == user_id

        # 6. PATCH active=false (the deactivation case).
        patch_resp = client.patch(
            f"{scim_path}/Users/{user_id}",
            headers=scim_headers,
            json={
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "replace", "path": "active", "value": False}
                ],
            },
        )
        assert patch_resp.status_code == 200, patch_resp.text
        assert patch_resp.json()["active"] is False

        # 7. DELETE.
        del_resp = client.delete(f"{scim_path}/Users/{user_id}", headers=scim_headers)
        assert del_resp.status_code == 204

        # 8. Confirm admin_audit_log carries scim-actor rows for every step.
        _, Session = _build_engine_and_factory()
        with Session() as session:
            session.execute(
                text("SELECT set_config('app.current_tenant_id', :tid, false)"),
                {"tid": str(tenant_id)},
            )
            audit_rows = session.scalars(
                # Most recent first
                text(
                    "SELECT action FROM admin_audit_log "
                    "WHERE tenant_id = :tid ORDER BY occurred_at DESC"
                ),
                params={"tid": str(tenant_id)},
            ).all()
            assert "idp.connect" in audit_rows
            assert "scim.create_user" in audit_rows
            assert "scim.deactivate_user" in audit_rows  # both PATCH and DELETE
            # And every SCIM-driven row carries the scim actor kind.
            scim_count = session.scalar(
                text(
                    "SELECT count(*) FROM admin_audit_log "
                    "WHERE tenant_id = :tid AND actor_kind = 'scim'"
                ),
                {"tid": str(tenant_id)},
            )
            assert scim_count >= 2  # create + deactivate (PATCH + DELETE both fire deactivate)
    finally:
        _cleanup_tenant(tenant_id)


def test_scim_unauthorized_returns_401_with_no_detail() -> None:
    """Bad bearer + unknown directory id both collapse to 401 with no
    differentiating detail — anti-enumeration."""

    tenant_id, _operator_id, _ = _seed_tenant_and_operator()
    try:
        client = _build_client()

        # Unknown directory id
        unknown_id = uuid4()
        resp = client.get(
            f"/scim/v2/{unknown_id}/ServiceProviderConfig",
            headers={"Authorization": "Bearer vyuu_scim_anything"},
        )
        assert resp.status_code == 401

        # Missing Authorization header
        resp = client.get(f"/scim/v2/{unknown_id}/ServiceProviderConfig")
        assert resp.status_code == 401

        # Both must be opaque — IdP shouldn't be able to fingerprint
        # which step failed.
        assert "directory" not in resp.text.lower()
        assert "token" not in resp.text.lower()
    finally:
        _cleanup_tenant(tenant_id)


def test_scim_user_create_conflict_returns_409_uniqueness() -> None:
    """Spec-compliant uniqueness violation — IdPs use this to dedup
    on retry."""

    tenant_id, _operator_id, operator_bearer = _seed_tenant_and_operator()
    try:
        client = _build_client()
        connect_resp = client.post(
            "/api/v1/idp/directories",
            headers={"Authorization": f"Bearer {operator_bearer}"},
            json={
                "kind": "google_workspace",
                "display_name": "Acme · Workspace",
                "signin_protocol": "oidc",
                "oidc": {
                    "issuer": "https://accounts.google.com",
                    "client_id": "ws-client-1",
                    "client_secret_ref": "ws-client-secret",
                },
            },
        )
        directory_id = connect_resp.json()["directory"]["id"]
        scim_bearer = connect_resp.json()["scim_token_plaintext"]
        scim_path = f"/scim/v2/{directory_id}"
        scim_headers = {"Authorization": f"Bearer {scim_bearer}"}

        body = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "duplicate@acme.com",
            "active": True,
            "externalId": "dup-1",
        }
        first = client.post(f"{scim_path}/Users", headers=scim_headers, json=body)
        assert first.status_code == 201
        second = client.post(f"{scim_path}/Users", headers=scim_headers, json=body)
        assert second.status_code == 409
        err = second.json()
        assert err["schemas"] == [
            "urn:ietf:params:scim:api:messages:2.0:Error"
        ]
        assert err["scimType"] == "uniqueness"
    finally:
        _cleanup_tenant(tenant_id)


# --- BUG-SCIM-1 regression guards ------------------------------------------


def test_scim_request_stamps_the_directory_heartbeat() -> None:
    """`last_sync_at` drives the operator console's "directory is alive"
    pill, and it is the canary for the *second* half of BUG-SCIM-1.

    The auth dependency's bootstrap read runs untenanted. If it does not
    end that transaction before binding the tenant, the heartbeat UPDATE
    executes with no `app.current_tenant_id` set, FORCE-RLS matches zero
    rows, and it commits silently — a broken heartbeat that looks exactly
    like a healthy one. Nothing else in the suite notices, because the
    SCIM request itself still succeeds.
    """

    _, Session = _build_engine_and_factory()
    tenant_id, _operator_id, operator_bearer = _seed_tenant_and_operator()
    try:
        client = _build_client()
        connect = client.post(
            "/api/v1/idp/directories",
            headers={"Authorization": f"Bearer {operator_bearer}"},
            json={
                "kind": "entra",
                "display_name": "Heartbeat Co",
                "signin_protocol": "oidc",
                "oidc": {
                    "issuer": "https://login.microsoftonline.com/hb/v2.0",
                    "client_id": "00000000-0000-0000-0000-0000000000hb".replace("hb", "01"),
                    "client_secret_ref": "hb-secret",
                },
            },
        )
        assert connect.status_code == 201, connect.text
        directory_id = connect.json()["directory"]["id"]
        scim_bearer = connect.json()["scim_token_plaintext"]

        with Session() as s:
            s.execute(
                text("SELECT set_config('app.current_tenant_id', :t, false)"),
                {"t": str(tenant_id)},
            )
            before = s.execute(
                text("SELECT last_sync_at FROM idp_directories WHERE id = :d"),
                {"d": directory_id},
            ).scalar()

        probe = client.get(
            f"/scim/v2/{directory_id}/ServiceProviderConfig",
            headers={"Authorization": f"Bearer {scim_bearer}"},
        )
        assert probe.status_code == 200, probe.text

        with Session() as s:
            s.execute(
                text("SELECT set_config('app.current_tenant_id', :t, false)"),
                {"t": str(tenant_id)},
            )
            after = s.execute(
                text("SELECT last_sync_at FROM idp_directories WHERE id = :d"),
                {"d": directory_id},
            ).scalar()

        assert after is not None, (
            "heartbeat never landed — the auth dependency's UPDATE ran "
            "outside a tenant-bound transaction and RLS discarded it"
        )
        assert before != after
    finally:
        _cleanup_tenant(tenant_id)


def test_untenanted_directory_read_stays_blocked_without_the_capability() -> None:
    """The BUG-SCIM-1 fix opens ONE door, deliberately narrow: an
    untenanted read of `idp_directories` succeeds only for a caller that
    sets `app.scim_bootstrap` for that transaction.

    This is the wall the fix must not have removed. If someone later
    "simplifies" the policy to allow any unbound read, or relaxes the
    table from FORCE to plain ENABLE, this fails.
    """

    _, Session = _build_engine_and_factory()
    tenant_id, _operator_id, operator_bearer = _seed_tenant_and_operator()
    try:
        client = _build_client()
        connect = client.post(
            "/api/v1/idp/directories",
            headers={"Authorization": f"Bearer {operator_bearer}"},
            json={
                "kind": "entra",
                "display_name": "Walled Co",
                "signin_protocol": "oidc",
                "oidc": {
                    "issuer": "https://login.microsoftonline.com/wall/v2.0",
                    "client_id": "00000000-0000-0000-0000-000000000002",
                    "client_secret_ref": "wall-secret",
                },
            },
        )
        assert connect.status_code == 201, connect.text
        directory_id = connect.json()["directory"]["id"]

        with Session() as s:
            blocked = s.execute(
                text("SELECT count(*) FROM idp_directories WHERE id = :d"),
                {"d": directory_id},
            ).scalar()
        assert blocked == 0, (
            "an unbound session read idp_directories without asking for "
            "the scim_bootstrap capability — FORCE RLS is not doing its job"
        )

        # ...and the door itself still opens, for a caller that asks.
        with Session() as s:
            s.execute(text("SELECT set_config('app.scim_bootstrap', 'on', true)"))
            allowed = s.execute(
                text("SELECT count(*) FROM idp_directories WHERE id = :d"),
                {"d": directory_id},
            ).scalar()
        assert allowed == 1

        # The capability must not grant writes.
        with Session() as s:
            s.execute(text("SELECT set_config('app.scim_bootstrap', 'on', true)"))
            result = s.execute(
                text(
                    "UPDATE idp_directories SET display_name = 'tampered' "
                    "WHERE id = :d"
                ),
                {"d": directory_id},
            )
            s.commit()
        assert result.rowcount == 0, (
            "the scim_bootstrap policy is SELECT-only; a write got through"
        )
    finally:
        _cleanup_tenant(tenant_id)
