"""HTTP-level integration tests for the N2 graph endpoints.

The deep behaviour of the query layer is already covered in
`tests/graph/test_identity_graph.py`. These tests just verify the
HTTP wire shape, status codes, and tenant scoping.

Skipped unless `VYUU_TEST_DATABASE_URL` is set.
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
    GrantPrincipalKind,
    McpCapability,
    McpCapabilityKind,
    McpServer,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
    Operator,
    OperatorRole,
    RiskCategory,
    Tenant,
    TenantTier,
    User,
    UserAuthMethod,
    VirtualServer,
    VirtualServerGrant,
    VirtualServerTool,
    VirtualServerVisibility,
)
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.operator_auth.fake import mint_operator_test_token  # noqa: E402
from vyuu_gateway.users.passwords import hash_password  # noqa: E402

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set",
)

_SECRET = "graph-endpoints-test-secret"


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(
        create_engine(_DATABASE_URL, future=True),
        autoflush=False,
        future=True,
    )


def _seed(factory: Any) -> dict[str, UUID]:
    """Minimal seed: tenant, operator, alice, 1 mcp_server with a
    delete tool, 1 private vserver granting alice access."""

    ids = {
        "tenant": uuid4(),
        "operator": uuid4(),
        "alice": uuid4(),
        "server": uuid4(),
        "vserver": uuid4(),
    }
    with factory() as s:
        s.add(Tenant(id=ids["tenant"], name=f"t-{ids['tenant'].hex[:6]}", tier=TenantTier.SHARED))
        s.commit()
    with factory() as s:
        s.add(
            Operator(
                id=ids["operator"],
                tenant_id=ids["tenant"],
                email=f"op-{ids['operator'].hex[:6]}@test",
                role=OperatorRole.ADMIN,
            )
        )
        s.add(
            User(
                id=ids["alice"],
                tenant_id=ids["tenant"],
                email=f"alice-{ids['alice'].hex[:6]}@test",
                auth_method=UserAuthMethod.LOCAL,
                password_hash=hash_password("very-strong-12+chars"),
            )
        )
        s.commit()
    with factory() as s:
        s.add(
            McpServer(
                id=ids["server"],
                tenant_id=ids["tenant"],
                display_name="github-mock",
                source_type=McpServerSourceType.HTTP,
                source_location="https://github.example/mcp",
                transport=McpTransport.STREAMABLE_HTTP,
                args=[],
                registered_by=ids["operator"],
                health_status=McpServerHealthStatus.UNKNOWN,
            )
        )
        s.add(
            McpCapability(
                id=uuid4(),
                tenant_id=ids["tenant"],
                server_id=ids["server"],
                kind=McpCapabilityKind.TOOL,
                name="delete_repo",
                schema_json={},
                risk_category=RiskCategory.DELETE,
            )
        )
        s.add(
            VirtualServer(
                id=ids["vserver"],
                tenant_id=ids["tenant"],
                name="alice-vs",
                visibility=VirtualServerVisibility.PRIVATE,
                created_by=ids["operator"],
            )
        )
        s.commit()
    with factory() as s:
        s.add(
            VirtualServerTool(
                tenant_id=ids["tenant"],
                vserver_id=ids["vserver"],
                server_id=ids["server"],
                tool_name="delete_repo",
            )
        )
        s.add(
            VirtualServerGrant(
                id=uuid4(),
                tenant_id=ids["tenant"],
                vserver_id=ids["vserver"],
                principal_kind=GrantPrincipalKind.USER,
                principal_id=ids["alice"],
                granted_by=ids["operator"],
            )
        )
        s.commit()
    return ids


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as s:
        for table in (
            "oauth_user_tokens",
            "user_group_memberships",
            "virtual_server_grants",
            "virtual_server_tools",
            "virtual_servers",
            "mcp_capabilities",
            "mcp_servers",
            "user_api_keys",
            "groups",
            "users",
            "operators",
        ):
            if table == "user_group_memberships":
                s.execute(
                    text(
                        "DELETE FROM user_group_memberships WHERE user_id IN "
                        "(SELECT id FROM users WHERE tenant_id = :id)"
                    ),
                    {"id": tenant_id},
                )
            else:
                s.execute(
                    text(f"DELETE FROM {table} WHERE tenant_id = :id"),
                    {"id": tenant_id},
                )
        s.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        s.commit()


def _client_and_headers(tenant_id: UUID) -> tuple[TestClient, dict[str, str]]:
    app = create_app(
        Settings(
            app_name="graph-endpoints-test",
            environment="test",
            log_level="CRITICAL",
            operator_auth_signing_secret=_SECRET,
        )
    )
    token = mint_operator_test_token(
        tenant_id=tenant_id, operator_id=uuid4(), signing_secret=_SECRET
    )
    return TestClient(app), {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------


def test_summary_endpoint_returns_full_picture() -> None:
    factory = _factory()
    ids = _seed(factory)
    try:
        client, headers = _client_and_headers(ids["tenant"])
        with client:
            r = client.get(
                f"/api/v1/identities/{ids['alice']}/summary", headers=headers
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["principal_id"] == str(ids["alice"])
        assert body["display"].startswith("alice-")
        assert body["max_risk_category"] == "delete"
        assert body["risk_score"] >= 50  # max severity 5 * 10
        # alice-vs is the only granted vserver.
        assert {v["name"] for v in body["granted_vservers"]} == {"alice-vs"}
        assert {v["grant_path"] for v in body["granted_vservers"]} == {"direct"}
    finally:
        _cleanup(factory, ids["tenant"])


def test_summary_endpoint_returns_404_for_unknown_user() -> None:
    factory = _factory()
    ids = _seed(factory)
    try:
        client, headers = _client_and_headers(ids["tenant"])
        with client:
            r = client.get(
                f"/api/v1/identities/{uuid4()}/summary", headers=headers
            )
        assert r.status_code == 404
    finally:
        _cleanup(factory, ids["tenant"])


def test_graph_endpoint_returns_node_and_edge_arrays() -> None:
    factory = _factory()
    ids = _seed(factory)
    try:
        client, headers = _client_and_headers(ids["tenant"])
        with client:
            r = client.get(
                f"/api/v1/identities/{ids['alice']}/graph", headers=headers
            )
        assert r.status_code == 200
        body = r.json()
        kinds = {n["kind"] for n in body["nodes"]}
        # Every layer must show up.
        assert kinds == {"principal", "vserver", "tool", "upstream"}
        # All edges have both ends in the node set.
        node_ids = {n["id"] for n in body["nodes"]}
        for e in body["edges"]:
            assert e["source"] in node_ids
            assert e["target"] in node_ids
    finally:
        _cleanup(factory, ids["tenant"])


def test_who_can_do_endpoint_returns_principals_and_filters_by_risk_floor() -> None:
    factory = _factory()
    ids = _seed(factory)
    try:
        client, headers = _client_and_headers(ids["tenant"])
        with client:
            # Tool exists, alice has direct grant — should appear.
            r_all = client.get(
                "/api/v1/who-can-do?tool_name=delete_repo", headers=headers
            )
            # delete_repo's risk = DELETE; floor=ADMIN excludes it.
            r_admin = client.get(
                "/api/v1/who-can-do?tool_name=delete_repo&risk_floor=admin",
                headers=headers,
            )
        assert r_all.status_code == 200
        rows = r_all.json()
        assert {row["principal_id"] for row in rows} == {str(ids["alice"])}
        assert all(row["grant_path"] == "direct" for row in rows)
        # Floor filter: ADMIN excludes DELETE.
        assert r_admin.status_code == 200
        assert r_admin.json() == []
    finally:
        _cleanup(factory, ids["tenant"])


def test_who_can_do_unauthenticated_returns_401() -> None:
    factory = _factory()
    ids = _seed(factory)
    try:
        client, _ = _client_and_headers(ids["tenant"])
        with client:
            r = client.get("/api/v1/who-can-do?tool_name=delete_repo")
        assert r.status_code == 401
    finally:
        _cleanup(factory, ids["tenant"])
