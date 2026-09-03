"""P2 · pooled-client credential freshness.

Org-tier `auth_headers` are resolved from the SecretStore **once**, in
the pool factory, and then baked into the transport client. Without a
bound on how long that client may be reused, a rotated secret only takes
effect when the connection happens to drop or a circuit breaker opens —
so a tenant rotating a *leaked* credential can keep serving traffic with
it for hours. That is the opposite of what rotating it was for, which is
why this is a correctness concern rather than a performance one.

The load-bearing test is
`test_a_rotated_credential_takes_effect_within_the_ttl`: it drives the
real pool with a factory whose secret changes underneath it, and asserts
the new value is actually used.
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import uuid4

import pytest

from vyuu_gateway.db.models import McpTransport
from vyuu_gateway.upstream.pool import UpstreamClientPool, UpstreamPoolKey

KEY = UpstreamPoolKey(
    tenant_id=uuid4(), server_id=uuid4(), transport=McpTransport.STREAMABLE_HTTP
)


class _FakeClient:
    """Stands in for a transport client that baked a credential in at
    construction — which is exactly what the real ones do."""

    def __init__(self, credential: str) -> None:
        self.credential = credential
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _pool(clock: _Clock, *, max_age: float | None = 60.0) -> UpstreamClientPool:
    return UpstreamClientPool(
        max_clients_per_upstream=2, client_max_age_seconds=max_age, clock=clock
    )


async def _use(pool: UpstreamClientPool, factory: Any) -> _FakeClient:
    async with pool.acquire(KEY, factory) as client:
        return client  # type: ignore[return-value]


# --- The point --------------------------------------------------------------


def test_a_rotated_credential_takes_effect_within_the_ttl() -> None:
    clock = _Clock()
    pool = _pool(clock, max_age=60.0)
    secret = {"value": "original"}

    async def factory() -> _FakeClient:
        return _FakeClient(secret["value"])

    async def scenario() -> None:
        first = await _use(pool, factory)
        assert first.credential == "original"

        # Reused inside the window — still the old client, by design.
        assert (await _use(pool, factory)) is first

        # The operator rotates the secret because it leaked.
        secret["value"] = "rotated"

        # Still inside the window: the pooled client is untouched. This
        # is the exposure the TTL bounds, and it is real.
        assert (await _use(pool, factory)).credential == "original"

        clock.advance(61.0)
        after = await _use(pool, factory)
        assert after.credential == "rotated", (
            "a client past its max age must be rebuilt, or a rotated "
            "credential never takes effect on a stable connection"
        )
        assert first.closed is True

    asyncio.run(scenario())


def test_without_a_ttl_the_stale_credential_persists_indefinitely() -> None:
    """Documents what `upstream_client_max_age_seconds=0` actually costs,
    so disabling it is an informed choice rather than an assumption that
    something else will catch it."""

    clock = _Clock()
    pool = _pool(clock, max_age=None)
    secret = {"value": "original"}

    async def factory() -> _FakeClient:
        return _FakeClient(secret["value"])

    async def scenario() -> None:
        await _use(pool, factory)
        secret["value"] = "rotated"
        clock.advance(10_000.0)
        assert (await _use(pool, factory)).credential == "original"

    asyncio.run(scenario())


# --- Mechanics --------------------------------------------------------------


def test_age_is_measured_from_build_not_from_release() -> None:
    """A continuously-busy connection must still age out. If the stamp
    were refreshed on release, the stable-connection case — the exact one
    this exists for — would stay "fresh" forever."""

    clock = _Clock()
    pool = _pool(clock, max_age=60.0)
    built: list[_FakeClient] = []

    async def factory() -> _FakeClient:
        client = _FakeClient(f"cred-{len(built)}")
        built.append(client)
        return client

    async def scenario() -> None:
        await _use(pool, factory)
        # Six acquire/release cycles spread across 90s. Each one returns
        # the client to the pool; none of them should reset its age.
        for _ in range(6):
            clock.advance(15.0)
            await _use(pool, factory)
        assert len(built) >= 2, "client was kept alive past its max age"

    asyncio.run(scenario())


def test_fresh_clients_are_not_retired() -> None:
    clock = _Clock()
    pool = _pool(clock, max_age=600.0)
    built: list[_FakeClient] = []

    async def factory() -> _FakeClient:
        client = _FakeClient("c")
        built.append(client)
        return client

    async def scenario() -> None:
        first = await _use(pool, factory)
        clock.advance(30.0)
        assert (await _use(pool, factory)) is first
        assert len(built) == 1
        assert first.closed is False

    asyncio.run(scenario())


def test_retired_clients_are_closed_not_leaked() -> None:
    clock = _Clock()
    pool = _pool(clock, max_age=10.0)
    built: list[_FakeClient] = []

    async def factory() -> _FakeClient:
        client = _FakeClient("c")
        built.append(client)
        return client

    async def scenario() -> None:
        await _use(pool, factory)
        clock.advance(11.0)
        await _use(pool, factory)
        assert built[0].closed is True

    asyncio.run(scenario())


def test_a_client_whose_close_fails_does_not_break_acquire() -> None:
    """A client being discarded *because* it is stale is exactly the one
    most likely to fail on close."""

    clock = _Clock()
    pool = _pool(clock, max_age=10.0)

    class _BadClose(_FakeClient):
        async def aclose(self) -> None:
            raise RuntimeError("teardown exploded")

    async def factory() -> _FakeClient:
        return _BadClose("c")

    async def scenario() -> None:
        await _use(pool, factory)
        clock.advance(11.0)
        assert (await _use(pool, factory)) is not None

    asyncio.run(scenario())


def test_capacity_is_returned_when_clients_are_retired() -> None:
    """Retiring must free the slot it occupied, or the pool leaks
    capacity and eventually blocks forever."""

    clock = _Clock()
    pool = _pool(clock, max_age=10.0)

    async def factory() -> _FakeClient:
        return _FakeClient("c")

    async def scenario() -> None:
        for _ in range(6):
            await _use(pool, factory)
            clock.advance(11.0)
        state = pool._states[KEY]  # noqa: SLF001
        assert state.total <= pool.max_clients_per_upstream

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


def test_negative_max_age_is_refused_at_construction() -> None:
    with pytest.raises(ValueError, match="positive or None"):
        UpstreamClientPool(client_max_age_seconds=0)
