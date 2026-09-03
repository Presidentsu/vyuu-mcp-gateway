"""The MCP servers table's TOOLS column.

The console read `server._tool_count`, which nothing in the codebase
ever assigned — so the column rendered "—" on every row in every
deployment, including a CrowdStrike server exposing 190 tools. Found by
looking at the screen during functionality testing; no test could have
caught it, because no test asked the API for the number.

Real Postgres: the count is a grouped query over `mcp_capabilities`.
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
    McpCapability,
    McpCapabilityKind,
    McpServer,
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
)
from vyuu_gateway.db.session import bind_tenant_context  # noqa: E402
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.operator_auth.fake import mint_operator_test_token  # noqa: E402

pytestmark = pytest.mark.skipif(
    _DATABASE_URL is None, reason="VYUU_TEST_DATABASE_URL not set"
)

SECRET = "tool-count-operator-secret-0123456789abcdef"


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(
        create_engine(_DATABASE_URL, future=True), autoflush=False, future=True
    )


def _seed(factory: Any) -> tuple[UUID, UUID]:
    tenant_id, operator_id = uuid4(), uuid4()
    with factory() as s:
        s.add(Tenant(id=tenant_id, name=f"t-{tenant_id.hex[:6]}", tier=TenantTier.SHARED))
        s.commit()
    with factory() as s:
        bind_tenant_context(s, tenant_id)
        s.add(Operator(id=operator_id, tenant_id=tenant_id,
                       email=f"op-{operator_id.hex[:6]}@test", role=OperatorRole.ADMIN))
        s.commit()
    return tenant_id, operator_id


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as s:
        for table in ("mcp_capabilities", "mcp_servers", "operators"):
            s.execute(text(f"DELETE FROM {table} WHERE tenant_id = :i"), {"i": tenant_id})
        s.execute(text("DELETE FROM tenants WHERE id = :i"), {"i": tenant_id})
        s.commit()


def _client() -> TestClient:
    return TestClient(create_app(Settings(
        app_name="tool-count", environment="test", log_level="CRITICAL",
        version="t", operator_auth_signing_secret=SECRET,
    )))


def _headers(tenant_id: UUID, operator_id: UUID) -> dict[str, str]:
    return {"Authorization": f"Bearer {mint_operator_test_token(
        tenant_id=tenant_id, operator_id=operator_id, signing_secret=SECRET)}"}


def _add_server(factory: Any, tenant_id: UUID, operator_id: UUID, *, synced: bool) -> UUID:
    server_id = uuid4()
    with factory() as s:
        bind_tenant_context(s, tenant_id)
        s.add(McpServer(
            id=server_id, tenant_id=tenant_id, display_name=f"srv-{server_id.hex[:6]}",
            source_type="npm", source_location="@acme/probe", transport="stdio",
            args=[], registered_by=operator_id,
            last_capabilities_pulled_at=datetime.now(UTC) if synced else None,
        ))
        s.commit()
    return server_id


def _add_capability(
    factory: Any, tenant_id: UUID, server_id: UUID, *,
    name: str, kind: McpCapabilityKind, deprecated: bool = False,
) -> None:
    with factory() as s:
        bind_tenant_context(s, tenant_id)
        s.add(McpCapability(
            id=uuid4(), tenant_id=tenant_id, server_id=server_id, kind=kind,
            name=name, schema_json={}, deprecated=deprecated,
        ))
        s.commit()


def _row_for(client: TestClient, headers: dict[str, str], server_id: UUID) -> dict:
    listed = client.get("/api/v1/servers", headers=headers).json()
    return next(s for s in listed if s["id"] == str(server_id))


def test_never_synced_is_null_not_zero() -> None:
    """These are different statements. "Synced and exposes nothing" is a
    finished answer; "never synced" means the operator still has work to
    do, and a column that renders both as 0 hides that."""

    factory = _factory()
    tenant_id, operator_id = _seed(factory)
    try:
        server_id = _add_server(factory, tenant_id, operator_id, synced=False)
        row = _row_for(_client(), _headers(tenant_id, operator_id), server_id)
        assert row["tool_count"] is None
    finally:
        _cleanup(factory, tenant_id)


def test_synced_with_no_tools_is_zero() -> None:
    factory = _factory()
    tenant_id, operator_id = _seed(factory)
    try:
        server_id = _add_server(factory, tenant_id, operator_id, synced=True)
        row = _row_for(_client(), _headers(tenant_id, operator_id), server_id)
        assert row["tool_count"] == 0
    finally:
        _cleanup(factory, tenant_id)


def test_counts_only_live_tools() -> None:
    """Deprecated rows are history — every sync keeps the previous
    snapshot, so counting them would double the number on the second
    sync and grow forever. Resources are not tools."""

    factory = _factory()
    tenant_id, operator_id = _seed(factory)
    try:
        server_id = _add_server(factory, tenant_id, operator_id, synced=True)
        for name in ("alpha", "beta", "gamma"):
            _add_capability(factory, tenant_id, server_id,
                            name=name, kind=McpCapabilityKind.TOOL)
        _add_capability(factory, tenant_id, server_id, name="alpha",
                        kind=McpCapabilityKind.TOOL, deprecated=True)
        _add_capability(factory, tenant_id, server_id, name="res://x",
                        kind=McpCapabilityKind.RESOURCE)

        row = _row_for(_client(), _headers(tenant_id, operator_id), server_id)
        assert row["tool_count"] == 3
    finally:
        _cleanup(factory, tenant_id)


def test_counts_do_not_leak_across_servers() -> None:
    """The grouped query must key by server, not sum the tenant."""

    factory = _factory()
    tenant_id, operator_id = _seed(factory)
    try:
        a = _add_server(factory, tenant_id, operator_id, synced=True)
        b = _add_server(factory, tenant_id, operator_id, synced=True)
        for name in ("one", "two"):
            _add_capability(factory, tenant_id, a, name=name, kind=McpCapabilityKind.TOOL)
        _add_capability(factory, tenant_id, b, name="solo", kind=McpCapabilityKind.TOOL)

        client, headers = _client(), _headers(tenant_id, operator_id)
        assert _row_for(client, headers, a)["tool_count"] == 2
        assert _row_for(client, headers, b)["tool_count"] == 1
    finally:
        _cleanup(factory, tenant_id)
