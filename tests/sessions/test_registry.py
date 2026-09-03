import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from vyuu_gateway.audit.events import AuditPrincipal, AuditPrincipalType
from vyuu_gateway.sessions.registry import (
    GatewaySession,
    InMemorySessionRegistry,
    default_expiry,
)


def _make_session(
    *,
    tenant_id: UUID | None = None,
    session_id: str = "session-1",
    vserver_name: str = "finance-readonly",
    expires_at: datetime | None = None,
) -> GatewaySession:
    return GatewaySession(
        session_id=session_id,
        tenant_id=tenant_id if tenant_id is not None else uuid4(),
        vserver_name=vserver_name,
        principal=AuditPrincipal(type=AuditPrincipalType.API_KEY, id="api-key-1"),
        expires_at=expires_at if expires_at is not None else _far_future(),
    )


def _far_future() -> datetime:
    return datetime.now(UTC) + timedelta(hours=1)


def _just_past() -> datetime:
    return datetime.now(UTC) - timedelta(seconds=1)


def test_create_and_lookup_round_trip() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        registry = InMemorySessionRegistry()
        session = _make_session(tenant_id=tenant_id)
        await registry.create_session(session)

        found = await registry.get_session(tenant_id, session.session_id)

        assert found is session

    asyncio.run(run())


def test_lookup_returns_none_for_unknown_session_id() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        registry = InMemorySessionRegistry()

        assert await registry.get_session(tenant_id, "missing") is None

    asyncio.run(run())


def test_expired_session_is_not_returned_and_is_evicted() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        registry = InMemorySessionRegistry()
        expired = _make_session(tenant_id=tenant_id, expires_at=_just_past())
        await registry.create_session(expired)

        assert await registry.get_session(tenant_id, expired.session_id) is None
        # Subsequent lookups should also miss — eviction happened on first read.
        assert await registry.get_session(tenant_id, expired.session_id) is None

    asyncio.run(run())


def test_session_expiry_is_lazy_until_lookup() -> None:
    """The registry doesn't sweep proactively; lookup is the eviction point.

    Tested explicitly because the in-memory impl's eviction strategy matters
    for memory-pressure planning (when one is added) and behaviour parity
    with the Redis backend (which uses TTL-based eviction).
    """

    async def run() -> None:
        tenant_id = uuid4()
        registry = InMemorySessionRegistry()
        expired = _make_session(tenant_id=tenant_id, expires_at=_just_past())
        await registry.create_session(expired)

        # Internal dict still has the entry until lookup observes the expiry.
        assert (tenant_id, expired.session_id) in registry._sessions  # noqa: SLF001
        await registry.get_session(tenant_id, expired.session_id)
        assert (tenant_id, expired.session_id) not in registry._sessions  # noqa: SLF001

    asyncio.run(run())


def test_delete_session_removes_entry() -> None:
    async def run() -> None:
        tenant_id = uuid4()
        registry = InMemorySessionRegistry()
        session = _make_session(tenant_id=tenant_id)
        await registry.create_session(session)

        await registry.delete_session(tenant_id, session.session_id)

        assert await registry.get_session(tenant_id, session.session_id) is None

    asyncio.run(run())


def test_delete_nonexistent_session_is_a_no_op() -> None:
    """Idempotent delete — a duplicate DELETE / cleanup sweep must not raise."""

    async def run() -> None:
        registry = InMemorySessionRegistry()
        await registry.delete_session(uuid4(), "missing")  # no exception

    asyncio.run(run())


def test_session_lookup_is_keyed_on_tenant_id_not_just_session_id() -> None:
    """Cross-tenant rejection: a session id minted under tenant A must not
    resolve under tenant B even if the session id collides — this is the
    isolation property the registry must guarantee on top of any other
    tenant filter."""

    async def run() -> None:
        tenant_a = uuid4()
        tenant_b = uuid4()
        registry = InMemorySessionRegistry()
        shared_session_id = "session-shared"

        session_a = _make_session(tenant_id=tenant_a, session_id=shared_session_id)
        await registry.create_session(session_a)

        assert await registry.get_session(tenant_a, shared_session_id) is session_a
        assert await registry.get_session(tenant_b, shared_session_id) is None

    asyncio.run(run())


def test_two_sessions_with_same_id_in_different_tenants_coexist() -> None:
    async def run() -> None:
        tenant_a = uuid4()
        tenant_b = uuid4()
        registry = InMemorySessionRegistry()

        session_a = _make_session(tenant_id=tenant_a, session_id="dup")
        session_b = _make_session(tenant_id=tenant_b, session_id="dup")
        await registry.create_session(session_a)
        await registry.create_session(session_b)

        found_a = await registry.get_session(tenant_a, "dup")
        found_b = await registry.get_session(tenant_b, "dup")

        assert found_a is session_a
        assert found_b is session_b

    asyncio.run(run())


def test_delete_does_not_affect_other_tenant_session_with_same_id() -> None:
    async def run() -> None:
        tenant_a = uuid4()
        tenant_b = uuid4()
        registry = InMemorySessionRegistry()
        await registry.create_session(_make_session(tenant_id=tenant_a, session_id="dup"))
        session_b = _make_session(tenant_id=tenant_b, session_id="dup")
        await registry.create_session(session_b)

        await registry.delete_session(tenant_a, "dup")

        assert await registry.get_session(tenant_b, "dup") is session_b

    asyncio.run(run())


def test_default_expiry_is_in_the_future_by_ttl() -> None:
    base = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)
    expiry = default_expiry(ttl_seconds=600, now=base)
    assert expiry == base + timedelta(seconds=600)


def test_is_expired_returns_true_at_or_after_expires_at() -> None:
    boundary = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)
    session = _make_session(expires_at=boundary)
    assert session.is_expired(at=boundary) is True
    assert session.is_expired(at=boundary + timedelta(seconds=1)) is True
    assert session.is_expired(at=boundary - timedelta(seconds=1)) is False
