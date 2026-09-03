"""Tenant-scoped upstream health checks."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import McpServer, McpServerHealthStatus
from vyuu_gateway.db.session import bind_tenant_context

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], Session]


class UpstreamHealthClient(Protocol):
    async def initialize(self) -> object:
        """Initialize or probe the upstream MCP server."""


class UpstreamHealthClientProvider(Protocol):
    def get_client(self, tenant_id: UUID, server_id: UUID) -> UpstreamHealthClient:
        """Return a tenant-scoped upstream client."""


class UpstreamHealthServerNotFoundError(Exception):
    """The requested server is not registered in the tenant."""


@dataclass(frozen=True)
class ServerHealthSnapshot:
    id: UUID
    tenant_id: UUID
    health_status: McpServerHealthStatus
    last_health_checked_at: datetime | None
    last_health_error: str | None
    last_capabilities_pulled_at: datetime | None

    @classmethod
    def from_server(cls, server: McpServer) -> ServerHealthSnapshot:
        return cls(
            id=server.id,
            tenant_id=server.tenant_id,
            health_status=server.health_status,
            last_health_checked_at=server.last_health_checked_at,
            last_health_error=server.last_health_error,
            last_capabilities_pulled_at=server.last_capabilities_pulled_at,
        )


class UpstreamHealthChecker:
    """Probes upstream connectivity and persists safe health metadata."""

    def __init__(
        self,
        session_factory: SessionFactory,
        upstream_clients: UpstreamHealthClientProvider,
        *,
        timeout_seconds: float | None = 5.0,
    ) -> None:
        self._session_factory = session_factory
        self._upstream_clients = upstream_clients
        self._timeout_seconds = timeout_seconds

    async def check_server(self, tenant_id: UUID, server_id: UUID) -> ServerHealthSnapshot:
        with self._session_factory() as session:
            bind_tenant_context(session, tenant_id)
            server = _lookup_server(session, tenant_id, server_id)
            checked_at = datetime.now(UTC)

            try:
                await self._initialize_upstream(tenant_id, server_id)
            except TimeoutError:
                self._mark_down(server, checked_at, "timeout")
                logger.warning(
                    "upstream_health_check_timeout",
                    extra={"tenant_id": str(tenant_id), "server_id": str(server_id)},
                )
            except BaseExceptionGroup as exc:
                # anyio task groups wrap the real cause; drill into it so the
                # persisted `last_health_error` is operator-actionable
                # (e.g. `McpError`, `ConnectionRefusedError`).
                inner = _innermost_exception(exc)
                error_type = inner.__class__.__name__
                self._mark_down(server, checked_at, error_type)
                logger.warning(
                    "upstream_health_check_failed",
                    extra={
                        "tenant_id": str(tenant_id),
                        "server_id": str(server_id),
                        "error_type": error_type,
                    },
                )
            except Exception as exc:
                error_type = exc.__class__.__name__
                self._mark_down(server, checked_at, error_type)
                logger.warning(
                    "upstream_health_check_failed",
                    extra={
                        "tenant_id": str(tenant_id),
                        "server_id": str(server_id),
                        "error_type": error_type,
                    },
                )
            else:
                server.health_status = McpServerHealthStatus.HEALTHY
                server.last_health_checked_at = checked_at
                server.last_health_error = None

            session.commit()
            session.refresh(server)
            return ServerHealthSnapshot.from_server(server)

    async def _initialize_upstream(self, tenant_id: UUID, server_id: UUID) -> None:
        client = self._upstream_clients.get_client(tenant_id, server_id)
        initialize = client.initialize()
        if self._timeout_seconds is None:
            await initialize
            return
        await asyncio.wait_for(initialize, timeout=self._timeout_seconds)

    @staticmethod
    def _mark_down(server: McpServer, checked_at: datetime, error: str) -> None:
        server.health_status = McpServerHealthStatus.DOWN
        server.last_health_checked_at = checked_at
        server.last_health_error = error


def get_server_health(
    session: Session,
    *,
    tenant_id: UUID,
    server_id: UUID,
) -> ServerHealthSnapshot:
    server = _lookup_server(session, tenant_id, server_id)
    return ServerHealthSnapshot.from_server(server)


def _innermost_exception(exc: BaseException) -> BaseException:
    """Drill into anyio task-group `BaseExceptionGroup` to the real cause."""

    while isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) >= 1:
        exc = exc.exceptions[0]
    return exc


def _lookup_server(session: Session, tenant_id: UUID, server_id: UUID) -> McpServer:
    server = cast(
        McpServer | None,
        session.scalar(
            select(McpServer).where(
                McpServer.tenant_id == tenant_id,
                McpServer.id == server_id,
            )
        ),
    )
    if server is None:
        raise UpstreamHealthServerNotFoundError
    return server
