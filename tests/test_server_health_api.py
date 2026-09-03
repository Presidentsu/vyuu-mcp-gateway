from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.config import Settings
from vyuu_gateway.db.models import (
    McpServer,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
)
from vyuu_gateway.main import create_app
from vyuu_gateway.operator_auth.fake import mint_operator_test_token
from vyuu_gateway.upstream.health import (
    ServerHealthSnapshot,
    UpstreamHealthServerNotFoundError,
)

TEST_SIGNING_SECRET = "test-operator-auth-secret"


class _FakeSession:
    def __init__(self, server: McpServer | None) -> None:
        self.server = server
        self.statements: list[Any] = []

    def scalar(self, statement: Any) -> McpServer | None:
        self.statements.append(statement)
        return self.server


class _FakeHealthChecker:
    def __init__(self, snapshot: ServerHealthSnapshot | None) -> None:
        self.snapshot = snapshot
        self.calls: list[tuple[UUID, UUID]] = []

    async def check_server(self, tenant_id: UUID, server_id: UUID) -> ServerHealthSnapshot:
        self.calls.append((tenant_id, server_id))
        if self.snapshot is None:
            raise UpstreamHealthServerNotFoundError
        return self.snapshot


def _server(*, tenant_id: UUID | None = None) -> McpServer:
    return McpServer(
        id=uuid4(),
        tenant_id=tenant_id or uuid4(),
        display_name="upstream",
        source_type=McpServerSourceType.HTTP,
        source_location="https://upstream.example/mcp",
        transport=McpTransport.STREAMABLE_HTTP,
        args=[],
        registered_by=uuid4(),
        registered_at=datetime.now(UTC),
        health_status=McpServerHealthStatus.HEALTHY,
        last_health_checked_at=datetime.now(UTC),
        last_health_error=None,
    )


def _auth_headers(tenant_id: UUID, operator_id: UUID | None = None) -> dict[str, str]:
    token = mint_operator_test_token(
        tenant_id=tenant_id,
        operator_id=operator_id or uuid4(),
        signing_secret=TEST_SIGNING_SECRET,
    )
    return {"Authorization": f"Bearer {token}"}


def _client(
    fake_session: _FakeSession,
    *,
    health_checker: _FakeHealthChecker | None = None,
) -> TestClient:
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
            operator_auth_signing_secret=TEST_SIGNING_SECRET,
        ),
        upstream_health_checker=health_checker,
    )

    def override_get_tenant_scoped_db() -> Iterator[_FakeSession]:
        yield fake_session

    app.dependency_overrides[get_tenant_scoped_db] = override_get_tenant_scoped_db
    return TestClient(app)


def test_get_server_health_returns_tenant_scoped_status() -> None:
    server = _server()
    fake_session = _FakeSession(server)
    client = _client(fake_session)

    response = client.get(
        f"/api/v1/servers/{server.id}/health",
        headers=_auth_headers(server.tenant_id),
    )

    assert response.status_code == 200
    body = response.json()
    assert UUID(body["id"]) == server.id
    assert UUID(body["tenant_id"]) == server.tenant_id
    assert body["health_status"] == "healthy"
    assert body["last_health_checked_at"] is not None
    assert body["last_health_error"] is None
    sql = str(fake_session.statements[0])
    assert "mcp_servers.tenant_id" in sql
    assert "mcp_servers.id" in sql


def test_get_server_health_returns_404_for_missing_server() -> None:
    fake_session = _FakeSession(None)
    client = _client(fake_session)

    response = client.get(
        f"/api/v1/servers/{uuid4()}/health",
        headers=_auth_headers(uuid4()),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "server not found"


def test_post_health_check_uses_authenticated_operator_tenant() -> None:
    tenant_id = uuid4()
    server_id = uuid4()
    snapshot = ServerHealthSnapshot(
        id=server_id,
        tenant_id=tenant_id,
        health_status=McpServerHealthStatus.DOWN,
        last_health_checked_at=datetime.now(UTC),
        last_health_error="timeout",
        last_capabilities_pulled_at=None,
    )
    checker = _FakeHealthChecker(snapshot)
    client = _client(_FakeSession(None), health_checker=checker)

    response = client.post(
        f"/api/v1/servers/{server_id}/health/check",
        headers=_auth_headers(tenant_id),
    )

    assert response.status_code == 200
    assert checker.calls == [(tenant_id, server_id)]
    assert response.json()["health_status"] == "down"
    assert response.json()["last_health_error"] == "timeout"


def test_post_health_check_returns_404_for_missing_server() -> None:
    checker = _FakeHealthChecker(None)
    client = _client(_FakeSession(None), health_checker=checker)

    response = client.post(
        f"/api/v1/servers/{uuid4()}/health/check",
        headers=_auth_headers(uuid4()),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "server not found"


def test_server_health_requires_authentication() -> None:
    client = _client(_FakeSession(_server()))

    response = client.get(f"/api/v1/servers/{uuid4()}/health")

    assert response.status_code == 401
