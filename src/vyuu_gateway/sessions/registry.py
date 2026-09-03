"""Gateway session model and registry interface.

A `GatewaySession` represents one MCP client's connection to a virtual server.
It is created on `initialize`, looked up on every subsequent `tools/list` /
`tools/call`, and torn down by the client (DELETE) or by expiry.

The `SessionRegistry` Protocol shapes both the in-memory dev impl shipped here
and the Redis-backed impl in `sessions/redis_registry.py`. The lifecycle only
ever calls `get_session`; `create_session` / `delete_session` live on the same
Protocol because storage is centralised — keeping reads and writes on one
interface keeps the test matrix tight (one fake to maintain instead of two).

Methods are async because the production impl (Redis) does network I/O and
sync calls inside an async request handler would block the event loop. The
in-memory impl returns immediately but matches the async signature so call
sites and the Protocol stay consistent.

Owned by this module rather than `tool_calls/lifecycle.py` because the inbound
MCP transport needs write access to the registry, which would otherwise
introduce a circular import: lifecycle would own `GatewaySession`, but the
inbound transport that creates sessions also imports lifecycle for tool-call
handling.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from vyuu_gateway.audit.events import AuditClientMetadata, AuditPrincipal


@dataclass(frozen=True)
class GatewaySession:
    session_id: str
    tenant_id: UUID
    vserver_name: str
    principal: AuditPrincipal
    expires_at: datetime
    client_metadata: AuditClientMetadata = field(default_factory=AuditClientMetadata)
    vserver_id: UUID | None = None
    policy_id: UUID | None = None

    def is_expired(self, *, at: datetime | None = None) -> bool:
        now = at if at is not None else datetime.now(UTC)
        return self.expires_at <= now


class SessionRegistry(Protocol):
    async def create_session(self, session: GatewaySession) -> None:
        """Persist a newly-initialized session."""

    async def get_session(self, tenant_id: UUID, session_id: str) -> GatewaySession | None:
        """Return a tenant-scoped session by id, or None if missing or expired."""

    async def delete_session(self, tenant_id: UUID, session_id: str) -> None:
        """Drop a session — used on client-initiated DELETE and on expiry sweeps."""


class InMemorySessionRegistry(SessionRegistry):
    """Process-local session registry for single-instance deployments.

    Suitable for v1 dev / single-process deployments and unit tests. The
    Redis-backed impl replaces this for multi-instance gateway clusters;
    both satisfy the same `SessionRegistry` Protocol so call sites and the
    rest of the lifecycle do not change.
    """

    def __init__(self) -> None:
        # Keyed on `(tenant_id, session_id)` so a session id can never be
        # looked up under the wrong tenant — the test for cross-tenant
        # session rejection exercises this directly.
        self._sessions: dict[tuple[UUID, str], GatewaySession] = {}

    async def create_session(self, session: GatewaySession) -> None:
        self._sessions[(session.tenant_id, session.session_id)] = session

    async def get_session(self, tenant_id: UUID, session_id: str) -> GatewaySession | None:
        session = self._sessions.get((tenant_id, session_id))
        if session is None:
            return None
        if session.is_expired():
            # Drop expired entries lazily on lookup; a separate sweep can be
            # added when memory pressure becomes a real concern.
            del self._sessions[(tenant_id, session_id)]
            return None
        return session

    async def delete_session(self, tenant_id: UUID, session_id: str) -> None:
        self._sessions.pop((tenant_id, session_id), None)


def default_expiry(*, ttl_seconds: int, now: datetime | None = None) -> datetime:
    """Compute an expiry timestamp for a freshly-created session."""
    base = now if now is not None else datetime.now(UTC)
    return base + timedelta(seconds=ttl_seconds)
