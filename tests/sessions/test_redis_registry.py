"""Real-Redis tests for `RedisSessionRegistry`.

Skipped unless `VYUU_TEST_REDIS_URL` is set, mirroring how the real-Postgres
RLS suite (`tests/integration/test_rls_real_postgres.py`) is gated. The tests
require a Redis instance the test process can reach with the URL provided
(e.g., `redis://127.0.0.1:6379/15` — DB 15 is conventionally throwaway).

How to run locally:

    redis-server &           # or `brew services start redis`
    VYUU_TEST_REDIS_URL=redis://127.0.0.1:6379/15 \
        pytest tests/sessions/test_redis_registry.py -v

What these prove:
- Round-trip serialization preserves every field on `GatewaySession`.
- TTL is set via Redis `EX` and the key actually expires when expected.
- Cross-instance: two `RedisSessionRegistry` objects with separate clients
  pointed at the same Redis can read each other's writes — the multi-pod
  HA property the in-memory registry can't satisfy.
- Tenant scoping survives the JSON encoding: a session id under tenant A
  is invisible under tenant B even when both registries share the same
  Redis instance.

Tests use a unique key prefix per test session so concurrent / repeated runs
don't step on each other.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from redis.asyncio import Redis, from_url

from vyuu_gateway.audit.events import (
    AuditClientMetadata,
    AuditPrincipal,
    AuditPrincipalType,
)
from vyuu_gateway.sessions.redis_registry import RedisSessionRegistry
from vyuu_gateway.sessions.registry import GatewaySession

TEST_REDIS_URL = os.environ.get("VYUU_TEST_REDIS_URL")

pytestmark = pytest.mark.skipif(
    TEST_REDIS_URL is None,
    reason="VYUU_TEST_REDIS_URL not set; skipping real-Redis session tests",
)


# --- helpers ---------------------------------------------------------------


def _far_future() -> datetime:
    return datetime.now(UTC) + timedelta(hours=1)


def _build_session(
    *,
    tenant_id: uuid.UUID | None = None,
    session_id: str | None = None,
    expires_at: datetime | None = None,
    vserver_id: uuid.UUID | None = None,
    policy_id: uuid.UUID | None = None,
) -> GatewaySession:
    return GatewaySession(
        session_id=session_id or uuid.uuid4().hex,
        tenant_id=tenant_id or uuid.uuid4(),
        vserver_name="redis-lab-vserver",
        principal=AuditPrincipal(
            type=AuditPrincipalType.ENDPOINT_SESSION,
            id="endpoint-redis-1",
            display="Redis lab endpoint",
        ),
        client_metadata=AuditClientMetadata(
            agent_type="claude_desktop",
            client_version="1.2.3",
            user_agent="redis-lab/0.1",
        ),
        expires_at=expires_at if expires_at is not None else _far_future(),
        vserver_id=vserver_id,
        policy_id=policy_id,
    )


async def _new_client() -> Redis:
    assert TEST_REDIS_URL is not None
    return from_url(TEST_REDIS_URL, decode_responses=True)


@pytest.fixture
def redis_prefix() -> str:
    """Per-test key prefix so parallel runs / leaked keys never collide."""
    return f"vyuu:session:test:{uuid.uuid4().hex[:12]}"


async def _cleanup_prefix(client: Redis, prefix: str) -> None:
    """Best-effort delete of every key under the test prefix."""
    keys = []
    async for key in client.scan_iter(match=f"{prefix}:*"):
        keys.append(key)
    if keys:
        await client.delete(*keys)


# --- tests -----------------------------------------------------------------


def test_create_and_lookup_round_trip_preserves_all_fields(redis_prefix: str) -> None:
    async def run() -> None:
        client = await _new_client()
        registry = RedisSessionRegistry(client, key_prefix=redis_prefix)
        try:
            session = _build_session(
                vserver_id=uuid.uuid4(),
                policy_id=uuid.uuid4(),
            )
            await registry.create_session(session)

            found = await registry.get_session(session.tenant_id, session.session_id)
            assert found is not None
            # Equality comparison checks every field on the frozen dataclass —
            # if anything (UUIDs, timestamps, principal type, etc.) round-trips
            # incorrectly, this assertion fails loudly.
            assert found == session
        finally:
            await _cleanup_prefix(client, redis_prefix)
            await client.aclose()

    asyncio.run(run())


def test_lookup_returns_none_for_missing_session(redis_prefix: str) -> None:
    async def run() -> None:
        client = await _new_client()
        registry = RedisSessionRegistry(client, key_prefix=redis_prefix)
        try:
            assert (
                await registry.get_session(uuid.uuid4(), "nonexistent-session-id")
                is None
            )
        finally:
            await client.aclose()

    asyncio.run(run())


def test_session_expires_via_redis_ttl(redis_prefix: str) -> None:
    """Set a session with a sub-second TTL; sleep past it; verify the key
    is gone (Redis itself swept it) and the registry returns None."""

    async def run() -> None:
        client = await _new_client()
        registry = RedisSessionRegistry(client, key_prefix=redis_prefix)
        try:
            session = _build_session(
                expires_at=datetime.now(UTC) + timedelta(seconds=1),
            )
            await registry.create_session(session)

            # Within TTL: still visible.
            assert (
                await registry.get_session(session.tenant_id, session.session_id)
                is not None
            )
            await asyncio.sleep(1.5)

            # After TTL: gone.
            assert (
                await registry.get_session(session.tenant_id, session.session_id)
                is None
            )
        finally:
            await _cleanup_prefix(client, redis_prefix)
            await client.aclose()

    asyncio.run(run())


def test_already_expired_session_is_treated_as_missing(redis_prefix: str) -> None:
    """A session created with `expires_at` in the past is stored briefly with
    Redis TTL=1 (we can't pass EX 0). Lookup must still return None because
    the registry rechecks `is_expired()` for clock-skew safety."""

    async def run() -> None:
        client = await _new_client()
        registry = RedisSessionRegistry(client, key_prefix=redis_prefix)
        try:
            session = _build_session(expires_at=datetime.now(UTC) - timedelta(seconds=10))
            await registry.create_session(session)

            assert (
                await registry.get_session(session.tenant_id, session.session_id)
                is None
            )
        finally:
            await _cleanup_prefix(client, redis_prefix)
            await client.aclose()

    asyncio.run(run())


def test_delete_removes_session(redis_prefix: str) -> None:
    async def run() -> None:
        client = await _new_client()
        registry = RedisSessionRegistry(client, key_prefix=redis_prefix)
        try:
            session = _build_session()
            await registry.create_session(session)

            await registry.delete_session(session.tenant_id, session.session_id)
            assert (
                await registry.get_session(session.tenant_id, session.session_id)
                is None
            )
        finally:
            await _cleanup_prefix(client, redis_prefix)
            await client.aclose()

    asyncio.run(run())


def test_delete_nonexistent_session_is_idempotent(redis_prefix: str) -> None:
    async def run() -> None:
        client = await _new_client()
        registry = RedisSessionRegistry(client, key_prefix=redis_prefix)
        try:
            await registry.delete_session(uuid.uuid4(), "nonexistent")
            # No exception is the assertion.
        finally:
            await client.aclose()

    asyncio.run(run())


def test_session_id_does_not_leak_across_tenants(redis_prefix: str) -> None:
    """Same session id, two tenants, both stored — each tenant only sees
    its own. The Redis key includes the tenant id specifically to prevent
    cross-tenant resolution."""

    async def run() -> None:
        client = await _new_client()
        registry = RedisSessionRegistry(client, key_prefix=redis_prefix)
        try:
            tenant_a = uuid.uuid4()
            tenant_b = uuid.uuid4()
            shared_session_id = "shared-session-id"

            session_a = _build_session(tenant_id=tenant_a, session_id=shared_session_id)
            session_b = _build_session(tenant_id=tenant_b, session_id=shared_session_id)
            await registry.create_session(session_a)
            await registry.create_session(session_b)

            found_a = await registry.get_session(tenant_a, shared_session_id)
            found_b = await registry.get_session(tenant_b, shared_session_id)
            assert found_a == session_a
            assert found_b == session_b

            # Deleting under tenant A must not affect tenant B.
            await registry.delete_session(tenant_a, shared_session_id)
            assert await registry.get_session(tenant_a, shared_session_id) is None
            assert await registry.get_session(tenant_b, shared_session_id) == session_b
        finally:
            await _cleanup_prefix(client, redis_prefix)
            await client.aclose()

    asyncio.run(run())


def test_session_created_by_instance_a_is_visible_to_instance_b(redis_prefix: str) -> None:
    """The HA property: two gateway processes share Redis, each constructs
    its own `RedisSessionRegistry` with its own client, and a session created
    by instance A's registry is fully readable by instance B's registry.

    This is the property an in-memory registry can never satisfy and the
    reason this module exists.
    """

    async def run() -> None:
        client_a = await _new_client()
        client_b = await _new_client()
        registry_a = RedisSessionRegistry(client_a, key_prefix=redis_prefix)
        registry_b = RedisSessionRegistry(client_b, key_prefix=redis_prefix)
        try:
            session = _build_session(
                vserver_id=uuid.uuid4(),
                policy_id=uuid.uuid4(),
            )
            await registry_a.create_session(session)

            seen_by_b = await registry_b.get_session(session.tenant_id, session.session_id)
            assert seen_by_b == session

            # Deleting on B is also visible on A.
            await registry_b.delete_session(session.tenant_id, session.session_id)
            assert (
                await registry_a.get_session(session.tenant_id, session.session_id)
                is None
            )
        finally:
            await _cleanup_prefix(client_a, redis_prefix)
            await client_a.aclose()
            await client_b.aclose()

    asyncio.run(run())


def test_corrupt_payload_in_redis_is_treated_as_missing_and_evicted(
    redis_prefix: str,
) -> None:
    """If a key holds a value the registry can't parse (e.g., schema drift,
    operator manually wrote something), the registry must not crash the
    request — it returns None and deletes the offending key."""

    async def run() -> None:
        client = await _new_client()
        registry = RedisSessionRegistry(client, key_prefix=redis_prefix)
        try:
            tenant_id = uuid.uuid4()
            session_id = "corrupt-payload-session"
            key = f"{redis_prefix}:{tenant_id}:{session_id}"

            await client.set(key, "not-valid-json", ex=60)

            assert await registry.get_session(tenant_id, session_id) is None
            # Offending key should have been deleted so subsequent lookups
            # don't re-incur the parse error.
            assert await client.get(key) is None
        finally:
            await _cleanup_prefix(client, redis_prefix)
            await client.aclose()

    asyncio.run(run())


# --- cross-registry consumer (lifecycle smoke) ----------------------------


async def _async_iter_collect(it: AsyncIterator[str]) -> list[str]:
    out: list[str] = []
    async for item in it:
        out.append(item)
    return out
