from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import (
    McpServer,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
)
from vyuu_gateway.upstream.health import (
    UpstreamHealthChecker,
    UpstreamHealthServerNotFoundError,
    get_server_health,
)


class _FakeSession:
    def __init__(self, server: McpServer | None) -> None:
        self.server = server
        self.info: dict[str, Any] = {}
        self.scalar_calls: list[Any] = []
        self.committed = False
        self.refreshed: McpServer | None = None

    def __enter__(self) -> _FakeSession:
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def scalar(self, statement: Any) -> McpServer | None:
        self.scalar_calls.append(statement)
        return self.server

    def commit(self) -> None:
        self.committed = True

    def refresh(self, server: McpServer) -> None:
        self.refreshed = server


class _FakeHealthClient:
    def __init__(self, *, exc: Exception | None = None, sleep_seconds: float = 0) -> None:
        self.exc = exc
        self.sleep_seconds = sleep_seconds
        self.initialized = False

    async def initialize(self) -> object:
        if self.sleep_seconds:
            await asyncio.sleep(self.sleep_seconds)
        if self.exc is not None:
            raise self.exc
        self.initialized = True
        return object()


class _FakeHealthProvider:
    def __init__(self, client: _FakeHealthClient) -> None:
        self.client = client
        self.calls: list[tuple[Any, Any]] = []

    def get_client(self, tenant_id: Any, server_id: Any) -> _FakeHealthClient:
        self.calls.append((tenant_id, server_id))
        return self.client


def _server() -> McpServer:
    return McpServer(
        id=uuid4(),
        tenant_id=uuid4(),
        display_name="upstream",
        source_type=McpServerSourceType.HTTP,
        source_location="https://upstream.example/mcp",
        transport=McpTransport.STREAMABLE_HTTP,
        args=[],
        registered_by=uuid4(),
        registered_at=datetime.now(UTC),
        health_status=McpServerHealthStatus.UNKNOWN,
    )


def _checker(
    session: _FakeSession,
    provider: _FakeHealthProvider,
    *,
    timeout_seconds: float | None = 5.0,
) -> UpstreamHealthChecker:
    def factory() -> Any:
        return session

    return UpstreamHealthChecker(factory, provider, timeout_seconds=timeout_seconds)


def test_health_check_marks_server_healthy_and_clears_previous_error() -> None:
    async def run() -> None:
        server = _server()
        server.health_status = McpServerHealthStatus.DOWN
        server.last_health_error = "RuntimeError"
        session = _FakeSession(server)
        provider = _FakeHealthProvider(_FakeHealthClient())

        snapshot = await _checker(session, provider).check_server(server.tenant_id, server.id)

        assert snapshot.health_status == McpServerHealthStatus.HEALTHY
        assert snapshot.last_health_error is None
        assert snapshot.last_health_checked_at is not None
        assert session.committed
        assert session.refreshed is server
        assert provider.calls == [(server.tenant_id, server.id)]

    asyncio.run(run())


def test_health_check_marks_down_on_upstream_error_without_storing_raw_message() -> None:
    async def run() -> None:
        server = _server()
        session = _FakeSession(server)
        provider = _FakeHealthProvider(_FakeHealthClient(exc=RuntimeError("secret-token=abc")))

        snapshot = await _checker(session, provider).check_server(server.tenant_id, server.id)

        assert snapshot.health_status == McpServerHealthStatus.DOWN
        assert snapshot.last_health_error == "RuntimeError"
        assert "secret" not in snapshot.last_health_error
        assert session.committed

    asyncio.run(run())


def test_health_check_marks_down_on_timeout() -> None:
    async def run() -> None:
        server = _server()
        session = _FakeSession(server)
        provider = _FakeHealthProvider(_FakeHealthClient(sleep_seconds=0.05))

        snapshot = await _checker(
            session,
            provider,
            timeout_seconds=0.001,
        ).check_server(server.tenant_id, server.id)

        assert snapshot.health_status == McpServerHealthStatus.DOWN
        assert snapshot.last_health_error == "timeout"
        assert session.committed

    asyncio.run(run())


def test_health_check_requires_tenant_scoped_server() -> None:
    async def run() -> None:
        session = _FakeSession(None)
        provider = _FakeHealthProvider(_FakeHealthClient())

        with pytest.raises(UpstreamHealthServerNotFoundError):
            await _checker(session, provider).check_server(uuid4(), uuid4())

        assert not session.committed
        assert provider.calls == []

    asyncio.run(run())


def test_health_check_binds_and_filters_tenant_context() -> None:
    async def run() -> None:
        server = _server()
        session = _FakeSession(server)
        provider = _FakeHealthProvider(_FakeHealthClient())

        await _checker(session, provider).check_server(server.tenant_id, server.id)

        assert session.info["tenant_id"] == server.tenant_id
        sql = str(session.scalar_calls[0])
        assert "mcp_servers.tenant_id" in sql
        assert "mcp_servers.id" in sql

    asyncio.run(run())


def test_get_server_health_returns_snapshot_for_tenant_scoped_row() -> None:
    server = _server()
    session = _FakeSession(server)

    snapshot = get_server_health(
        cast(Session, session),
        tenant_id=server.tenant_id,
        server_id=server.id,
    )

    assert snapshot.id == server.id
    assert snapshot.tenant_id == server.tenant_id
    assert snapshot.health_status == McpServerHealthStatus.UNKNOWN
    sql = str(session.scalar_calls[0])
    assert "mcp_servers.tenant_id" in sql
    assert "mcp_servers.id" in sql
