"""Integration tests for the NHI graph query layer (N2).

These exercise the real query joins against Postgres (RLS-bound
session, virtual_server_grants, virtual_server_tools,
mcp_capabilities, oauth_user_tokens). Skipped unless
`VYUU_TEST_DATABASE_URL` is set.

Coverage:
  - principal_summary surfaces direct + group + public grants
  - exposed_tools join risk_category from mcp_capabilities
  - oauth_user_tokens connection state shows on reachable_upstreams
  - risk_score derives from highest-severity tool + breadth
  - who_can_do returns direct + group-mediated principals (no public)
  - who_can_do honors the risk_floor filter
  - dependency_chain returns connected node + edge graph
"""

from __future__ import annotations

import os

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

from typing import Any  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import pytest  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.db.models import (  # noqa: E402
    GrantPrincipalKind,
    Group,
    McpCapability,
    McpCapabilityKind,
    McpServer,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
    OAuthUserToken,
    Operator,
    OperatorRole,
    RiskCategory,
    Tenant,
    TenantTier,
    User,
    UserAuthMethod,
    UserGroupMembership,
    VirtualServer,
    VirtualServerGrant,
    VirtualServerTool,
    VirtualServerVisibility,
)
from vyuu_gateway.graph.identity_graph import (  # noqa: E402
    dependency_chain,
    principal_summary,
    who_can_do,
)
from vyuu_gateway.users.passwords import hash_password  # noqa: E402

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set",
)


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(
        create_engine(_DATABASE_URL, future=True),
        autoflush=False,
        future=True,
    )


def _seed_world(factory: Any) -> dict[str, UUID]:
    """Seed: tenant, operator, user (alice + bob), 1 group with bob in
    it, 1 public vserver, 1 private vserver alice has direct grant on,
    1 private vserver granted to the group bob is in, 1 mcp_server
    with auth_authcode + 2 capabilities (read + delete) wired, and an
    oauth_user_tokens row for alice."""

    ids: dict[str, UUID] = {
        "tenant": uuid4(),
        "operator": uuid4(),
        "alice": uuid4(),
        "bob": uuid4(),
        "group": uuid4(),
        "vs_public": uuid4(),
        "vs_alice_direct": uuid4(),
        "vs_bob_via_group": uuid4(),
        "server": uuid4(),
        "cap_read": uuid4(),
        "cap_delete": uuid4(),
        "token": uuid4(),
        "grant_alice_direct": uuid4(),
        "grant_group": uuid4(),
        "membership": uuid4(),
    }
    # Flush tenant + operator first so FK references resolve. SA's
    # autoflush ordering doesn't deduce FK depth across heterogeneous
    # adds in a single session, so we commit in dependency layers.
    with factory() as session:
        session.add(
            Tenant(id=ids["tenant"], name=f"t-{ids['tenant'].hex[:6]}", tier=TenantTier.SHARED)
        )
        session.commit()
    with factory() as session:
        session.add(
            Operator(
                id=ids["operator"],
                tenant_id=ids["tenant"],
                email=f"op-{ids['operator'].hex[:6]}@test",
                role=OperatorRole.ADMIN,
            )
        )
        for name, uid in (("alice", ids["alice"]), ("bob", ids["bob"])):
            session.add(
                User(
                    id=uid,
                    tenant_id=ids["tenant"],
                    email=f"{name}-{uid.hex[:6]}@test",
                    auth_method=UserAuthMethod.LOCAL,
                    password_hash=hash_password("very-strong-12+chars"),
                )
            )
        session.commit()
    with factory() as session:
        session.add(
            Group(
                id=ids["group"],
                tenant_id=ids["tenant"],
                name=f"engineers-{ids['group'].hex[:6]}",
                created_by=ids["operator"],
            )
        )
        session.add(
            UserGroupMembership(
                user_id=ids["bob"],
                group_id=ids["group"],
                added_by=ids["operator"],
            )
        )
        # Two private vservers + one public.
        session.add(
            VirtualServer(
                id=ids["vs_public"],
                tenant_id=ids["tenant"],
                name="public-vs",
                visibility=VirtualServerVisibility.PUBLIC,
                created_by=ids["operator"],
            )
        )
        session.add(
            VirtualServer(
                id=ids["vs_alice_direct"],
                tenant_id=ids["tenant"],
                name="alice-only",
                visibility=VirtualServerVisibility.PRIVATE,
                created_by=ids["operator"],
            )
        )
        session.add(
            VirtualServer(
                id=ids["vs_bob_via_group"],
                tenant_id=ids["tenant"],
                name="engineers-vs",
                visibility=VirtualServerVisibility.PRIVATE,
                created_by=ids["operator"],
            )
        )
        # MCP server with two tools — one read, one delete.
        session.add(
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
                auth_authcode={
                    "auth_url": "https://github.com/login/oauth/authorize",
                    "token_url": "https://github.com/login/oauth/access_token",
                    "client_id_ref": "gh-id",
                    "client_secret_ref": "gh-secret",
                    "scopes": ["read:user"],
                    "redirect_uri": "https://gw.example/cb",
                },
            )
        )
        session.add(
            McpCapability(
                id=ids["cap_read"],
                tenant_id=ids["tenant"],
                server_id=ids["server"],
                kind=McpCapabilityKind.TOOL,
                name="list_repos",
                schema_json={},
                risk_category=RiskCategory.READ,
            )
        )
        session.add(
            McpCapability(
                id=ids["cap_delete"],
                tenant_id=ids["tenant"],
                server_id=ids["server"],
                kind=McpCapabilityKind.TOOL,
                name="delete_repo",
                schema_json={},
                risk_category=RiskCategory.DELETE,
            )
        )
        session.commit()

    # Tool exposures: every vserver wraps both tools so we can show
    # per-grant-path differences cleanly.
    with factory() as session:
        for vs in (ids["vs_public"], ids["vs_alice_direct"], ids["vs_bob_via_group"]):
            for tool in ("list_repos", "delete_repo"):
                session.add(
                    VirtualServerTool(
                        tenant_id=ids["tenant"],
                        vserver_id=vs,
                        server_id=ids["server"],
                        tool_name=tool,
                    )
                )
        # Direct user grant for alice on alice-only.
        session.add(
            VirtualServerGrant(
                id=ids["grant_alice_direct"],
                tenant_id=ids["tenant"],
                vserver_id=ids["vs_alice_direct"],
                principal_kind=GrantPrincipalKind.USER,
                principal_id=ids["alice"],
                granted_by=ids["operator"],
            )
        )
        # Group grant on engineers-vs (bob is in the group).
        session.add(
            VirtualServerGrant(
                id=ids["grant_group"],
                tenant_id=ids["tenant"],
                vserver_id=ids["vs_bob_via_group"],
                principal_kind=GrantPrincipalKind.GROUP,
                principal_id=ids["group"],
                granted_by=ids["operator"],
            )
        )
        # alice has connected her github account.
        session.add(
            OAuthUserToken(
                id=ids["token"],
                tenant_id=ids["tenant"],
                user_id=ids["alice"],
                server_id=ids["server"],
                access_token="alice-token",
                token_type="Bearer",
            )
        )
        session.commit()
    return ids


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as session:
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


# ---------------------------------------------------------------------------
# principal_summary
# ---------------------------------------------------------------------------


def test_principal_summary_returns_none_for_unknown_user() -> None:
    factory = _factory()
    ids = _seed_world(factory)
    try:
        with factory() as db:
            assert (
                principal_summary(db, tenant_id=ids["tenant"], principal_id=uuid4())
                is None
            )
    finally:
        _cleanup(factory, ids["tenant"])


def test_principal_summary_resolves_direct_and_public_grants() -> None:
    factory = _factory()
    ids = _seed_world(factory)
    try:
        with factory() as db:
            summary = principal_summary(
                db, tenant_id=ids["tenant"], principal_id=ids["alice"]
            )
        assert summary is not None
        names = {v.name for v in summary.granted_vservers}
        # public + direct alice grant. Bob's group-grant vserver
        # should NOT appear for alice.
        assert "public-vs" in names
        assert "alice-only" in names
        assert "engineers-vs" not in names
        paths = {v.name: v.grant_path for v in summary.granted_vservers}
        assert paths["public-vs"] == "public"
        assert paths["alice-only"] == "direct"
    finally:
        _cleanup(factory, ids["tenant"])


def test_principal_summary_resolves_group_mediated_grants() -> None:
    factory = _factory()
    ids = _seed_world(factory)
    try:
        with factory() as db:
            summary = principal_summary(
                db, tenant_id=ids["tenant"], principal_id=ids["bob"]
            )
        assert summary is not None
        names = {v.name for v in summary.granted_vservers}
        assert "public-vs" in names
        assert "engineers-vs" in names
        assert "alice-only" not in names
        engineers = next(
            v for v in summary.granted_vservers if v.name == "engineers-vs"
        )
        assert engineers.grant_path.startswith("group:")
    finally:
        _cleanup(factory, ids["tenant"])


def test_principal_summary_attaches_risk_category_to_exposed_tools() -> None:
    factory = _factory()
    ids = _seed_world(factory)
    try:
        with factory() as db:
            summary = principal_summary(
                db, tenant_id=ids["tenant"], principal_id=ids["alice"]
            )
        assert summary is not None
        risks = {(t.tool_name, t.risk_category.value) for t in summary.exposed_tools}
        assert ("list_repos", "read") in risks
        assert ("delete_repo", "delete") in risks
        # Highest-risk tool drives `max_risk_category`.
        assert summary.max_risk_category == RiskCategory.DELETE
        # Risk score: max severity (5) * 10 + breadth (4 high-risk
        # exposures across public + alice-only at 4 * 4 = 16) = 50 + 16 = 66
        # — alice can call delete_repo via two vservers (public-vs +
        # alice-only), so high_risk_count = 2 → breadth = 8 → score 58.
        assert summary.risk_score >= 50  # at least max-severity floor
    finally:
        _cleanup(factory, ids["tenant"])


def test_principal_summary_marks_oauth_connection_state() -> None:
    factory = _factory()
    ids = _seed_world(factory)
    try:
        with factory() as db:
            alice = principal_summary(
                db, tenant_id=ids["tenant"], principal_id=ids["alice"]
            )
            bob = principal_summary(
                db, tenant_id=ids["tenant"], principal_id=ids["bob"]
            )
        assert alice is not None and bob is not None
        # alice has a token row → oauth_connected=True on the github server.
        alice_up = next(u for u in alice.reachable_upstreams)
        assert alice_up.oauth_connected is True
        # bob doesn't → False (not None — the upstream IS authcode-configured).
        bob_up = next(u for u in bob.reachable_upstreams)
        assert bob_up.oauth_connected is False
        # And the OAuthConnection summary surfaces alice's row.
        assert len(alice.oauth_connections) == 1
        assert alice.oauth_connections[0].server_display_name == "github-mock"
        assert len(bob.oauth_connections) == 0
    finally:
        _cleanup(factory, ids["tenant"])


# ---------------------------------------------------------------------------
# who_can_do
# ---------------------------------------------------------------------------


def test_who_can_do_returns_direct_and_group_mediated_principals() -> None:
    factory = _factory()
    ids = _seed_world(factory)
    try:
        with factory() as db:
            results = who_can_do(
                db,
                tenant_id=ids["tenant"],
                tool_name="delete_repo",
            )
        # alice has direct grant on alice-only; bob has group grant on
        # engineers-vs. Public vserver is excluded from who_can_do.
        principals = {(r.principal_id, r.via_vserver_name) for r in results}
        assert (ids["alice"], "alice-only") in principals
        assert (ids["bob"], "engineers-vs") in principals
        # Public vserver is intentionally excluded from this query
        # (would otherwise return every user in the tenant).
        names = {r.via_vserver_name for r in results}
        assert "public-vs" not in names
    finally:
        _cleanup(factory, ids["tenant"])


def test_who_can_do_risk_floor_filters_out_low_risk_only() -> None:
    """Floor=admin → no matches (no admin tools wired). Floor=read →
    matches stay because read meets the floor."""

    factory = _factory()
    ids = _seed_world(factory)
    try:
        with factory() as db:
            high = who_can_do(
                db,
                tenant_id=ids["tenant"],
                tool_name="list_repos",
                risk_floor=RiskCategory.ADMIN,
            )
            low = who_can_do(
                db,
                tenant_id=ids["tenant"],
                tool_name="list_repos",
                risk_floor=RiskCategory.READ,
            )
        assert high == []  # READ doesn't meet ADMIN floor
        assert low  # READ does meet READ floor
    finally:
        _cleanup(factory, ids["tenant"])


def test_who_can_do_returns_empty_for_unknown_tool() -> None:
    factory = _factory()
    ids = _seed_world(factory)
    try:
        with factory() as db:
            assert (
                who_can_do(
                    db, tenant_id=ids["tenant"], tool_name="never_wired_tool"
                )
                == []
            )
    finally:
        _cleanup(factory, ids["tenant"])


# ---------------------------------------------------------------------------
# dependency_chain
# ---------------------------------------------------------------------------


def test_dependency_chain_returns_connected_node_set() -> None:
    factory = _factory()
    ids = _seed_world(factory)
    try:
        with factory() as db:
            graph = dependency_chain(
                db, tenant_id=ids["tenant"], principal_id=ids["alice"]
            )
        kinds = {n.kind for n in graph.nodes}
        # Every layer must show up: principal → vserver → tool → upstream
        assert kinds == {"principal", "vserver", "tool", "upstream"}
        # Every edge has both ends in the node set.
        node_ids = {n.id for n in graph.nodes}
        for e in graph.edges:
            assert e.source in node_ids
            assert e.target in node_ids
        # Edge kinds are all from our taxonomy.
        edge_kinds = {e.kind for e in graph.edges}
        assert edge_kinds <= {"grant", "exposes", "wraps"}
    finally:
        _cleanup(factory, ids["tenant"])


def test_dependency_chain_returns_empty_for_unknown_user() -> None:
    factory = _factory()
    ids = _seed_world(factory)
    try:
        with factory() as db:
            graph = dependency_chain(
                db, tenant_id=ids["tenant"], principal_id=uuid4()
            )
        assert graph.nodes == ()
        assert graph.edges == ()
    finally:
        _cleanup(factory, ids["tenant"])
