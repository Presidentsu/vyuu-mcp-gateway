"""Unit + integration tests for `GET /api/v1/nhi-map`.

The classification helpers (`_classify_ai_app`, `_is_likely_agent`)
are pure functions — tested directly. The full endpoint goes through
the recent-emitter ring buffer and the user / mcp_server label
joins, so it gets an integration test against real Postgres when
`VYUU_TEST_DATABASE_URL` is set.
"""

from __future__ import annotations

import os

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

from typing import Any  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.api.nhi_map import _classify_ai_app, _is_likely_agent  # noqa: E402
from vyuu_gateway.audit.events import (  # noqa: E402
    AuditClientMetadata,
    AuditDecision,
    AuditDecisionMode,
    AuditPrincipal,
    AuditPrincipalType,
    UpstreamStatus,
    create_tool_call_audit_event,
)
from vyuu_gateway.config import Settings  # noqa: E402
from vyuu_gateway.db.models import (  # noqa: E402
    McpServer,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
    User,
    UserAuthMethod,
)
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.operator_auth.fake import mint_operator_test_token  # noqa: E402
from vyuu_gateway.users.passwords import hash_password  # noqa: E402

_SECRET = "nhi-map-test-secret"


# ---------------------------------------------------------------------------
# Pure-function tests — no DB needed
# ---------------------------------------------------------------------------


def test_classify_ai_app_recognises_known_clients() -> None:
    """The known-clients allowlist matches user-agent substrings
    case-insensitively. Anything outside it is unsanctioned."""

    cases = [
        ("Cursor/0.42 (Mac)",          "app:cursor",         "Cursor",         True),
        ("claude-desktop/1.5",         "app:claude desktop", "Claude Desktop", True),
        ("ChatGPT-iOS/2.1",            "app:chatgpt",        "ChatGPT",        True),
        ("openai-ai/internal",         "app:chatgpt",        "ChatGPT",        True),
        ("MyHomegrownAgent/0.1",       None,                 None,             False),
        ("",                           "unknown:none",       "Unknown / no UA", False),
        (None,                         "unknown:none",       "Unknown / no UA", False),
    ]
    for ua, expected_id, expected_label, expected_sanc in cases:
        node_id, label, sanc = _classify_ai_app(ua)
        assert sanc is expected_sanc, ua
        if expected_id is not None:
            assert node_id == expected_id, ua
        if expected_label is not None:
            assert label == expected_label, ua


def test_is_likely_agent_picks_up_automated_caller_hints() -> None:
    assert _is_likely_agent("nightly-bot", "p-1") is True
    assert _is_likely_agent("automation-runner", "p-2") is True
    assert _is_likely_agent("alice@corp.example", "p-3") is False
    assert _is_likely_agent("Aamir Khan", "service-account-x") is True


# ---------------------------------------------------------------------------
# Endpoint integration — real Postgres so user/mcp label joins resolve
# ---------------------------------------------------------------------------


pgmark = pytest.mark.skipif(
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


def _seed(factory: Any) -> dict[str, UUID]:
    ids: dict[str, UUID] = {
        "tenant": uuid4(),
        "operator": uuid4(),
        "alice": uuid4(),
        "bob": uuid4(),
        "server": uuid4(),
    }
    with factory() as s:
        s.add(Tenant(id=ids["tenant"], name=f"t-{ids['tenant'].hex[:6]}", tier=TenantTier.SHARED))
        s.commit()
    with factory() as s:
        s.add(
            Operator(
                id=ids["operator"],
                tenant_id=ids["tenant"],
                email="op@test",
                role=OperatorRole.ADMIN,
            )
        )
        for name, uid in (("alice", ids["alice"]), ("bob", ids["bob"])):
            s.add(
                User(
                    id=uid,
                    tenant_id=ids["tenant"],
                    email=f"{name}@corp.example",
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


def _client_and_headers(tenant_id: UUID) -> tuple[TestClient, FastAPI, dict[str, str]]:
    app = create_app(
        Settings(
            app_name="nhi-map-test",
            environment="test",
            log_level="CRITICAL",
            operator_auth_signing_secret=_SECRET,
        )
    )
    token = mint_operator_test_token(
        tenant_id=tenant_id, operator_id=uuid4(), signing_secret=_SECRET
    )
    return TestClient(app), app, {"Authorization": f"Bearer {token}"}


def _emit(
    app: FastAPI,
    *,
    tenant_id: UUID,
    principal_id: str,
    user_agent: str | None,
    upstream_server_id: UUID | None = None,
    tool: str = "t",
    principal_display: str = "",
) -> None:
    metadata = AuditClientMetadata(user_agent=user_agent) if user_agent else None
    app.state.recent_audit_emitter.emit_nowait(
        create_tool_call_audit_event(
            tenant_id=tenant_id,
            gateway_instance_id="g",
            principal=AuditPrincipal(
                type=AuditPrincipalType.API_KEY,
                id=principal_id,
                display=principal_display,
            ),
            tool=tool,
            arguments={},
            decision=AuditDecision.ALLOW,
            decision_mode=AuditDecisionMode.ENFORCE,
            upstream_status=UpstreamStatus.OK,
            upstream_server_id=upstream_server_id,
            client_metadata=metadata,
        )
    )


@pgmark
def test_nhi_map_returns_4_columns_and_resolves_labels() -> None:
    factory = _factory()
    ids = _seed(factory)
    try:
        client, app, headers = _client_and_headers(ids["tenant"])
        # Alice via Cursor → github MCP
        _emit(
            app,
            tenant_id=ids["tenant"],
            principal_id=str(ids["alice"]),
            user_agent="Cursor/0.42",
            upstream_server_id=ids["server"],
        )
        # Bob via Claude Desktop → github MCP
        _emit(
            app,
            tenant_id=ids["tenant"],
            principal_id=str(ids["bob"]),
            user_agent="claude-desktop/1.5",
            upstream_server_id=ids["server"],
        )
        # An automated caller (display includes "bot") via unsanctioned UA
        _emit(
            app,
            tenant_id=ids["tenant"],
            principal_id="nightly-bot-1",
            principal_display="nightly-bot",
            user_agent="my-homegrown-script/0.1",
            upstream_server_id=ids["server"],
        )
        with client:
            r = client.get("/api/v1/nhi-map", headers=headers)
        assert r.status_code == 200
        body = r.json()
        cols = {n["column"] for n in body["nodes"]}
        # `agent` shows up because the bot principal got classified as agent.
        assert {"user", "ai_app", "mcp_server", "agent"} <= cols
        # Alice's user node label was joined to her email.
        alice_node = next(
            n for n in body["nodes"] if n["id"] == f"user:{ids['alice']}"
        )
        assert alice_node["label"] == "alice@corp.example"
        # MCP server label was joined to display_name.
        mcp_node = next(
            n for n in body["nodes"] if n["id"].startswith("mcp:")
        )
        assert mcp_node["label"] == "github-mock"
        assert mcp_node["sanctioned"] is True
        # The unknown UA is unsanctioned (dashed in the UI).
        unsanc = [n for n in body["nodes"] if not n["sanctioned"]]
        assert any("homegrown" in n["label"].lower() for n in unsanc)
    finally:
        _cleanup(factory, ids["tenant"])


@pgmark
def test_nhi_map_sanctioned_only_drops_unknown_clients() -> None:
    factory = _factory()
    ids = _seed(factory)
    try:
        client, app, headers = _client_and_headers(ids["tenant"])
        _emit(
            app,
            tenant_id=ids["tenant"],
            principal_id=str(ids["alice"]),
            user_agent="Cursor/0.42",
            upstream_server_id=ids["server"],
        )
        _emit(
            app,
            tenant_id=ids["tenant"],
            principal_id="someone-else",
            user_agent="my-totally-unknown-client/1",
            upstream_server_id=ids["server"],
        )
        with client:
            r = client.get(
                "/api/v1/nhi-map?sanctioned_only=true", headers=headers
            )
        body = r.json()
        unsanc = [n for n in body["nodes"] if not n["sanctioned"]]
        assert unsanc == []
    finally:
        _cleanup(factory, ids["tenant"])


@pgmark
def test_nhi_map_empty_when_no_events() -> None:
    factory = _factory()
    ids = _seed(factory)
    try:
        client, _, headers = _client_and_headers(ids["tenant"])
        with client:
            r = client.get("/api/v1/nhi-map", headers=headers)
        assert r.status_code == 200
        body = r.json()
        assert body["nodes"] == []
        assert body["edges"] == []
        assert body["sample_size"] == 0
    finally:
        _cleanup(factory, ids["tenant"])


@pgmark
def test_nhi_map_unauthenticated_returns_401() -> None:
    factory = _factory()
    ids = _seed(factory)
    try:
        client, _, _ = _client_and_headers(ids["tenant"])
        with client:
            r = client.get("/api/v1/nhi-map")
        assert r.status_code == 401
    finally:
        _cleanup(factory, ids["tenant"])
