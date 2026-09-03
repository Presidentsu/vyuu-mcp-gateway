from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from vyuu_gateway.db.models import McpTransport
from vyuu_gateway.upstream.circuit_breaker import (
    CircuitBreakerConfig,
    CircuitBreakerKey,
    CircuitBreakerOpenError,
    CircuitBreakerState,
    UpstreamCircuitBreakerRegistry,
)


class _Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _key() -> CircuitBreakerKey:
    return CircuitBreakerKey(
        tenant_id=uuid4(),
        server_id=uuid4(),
        transport=McpTransport.STREAMABLE_HTTP,
    )


def test_circuit_opens_after_configured_consecutive_failures() -> None:
    async def run() -> None:
        clock = _Clock()
        registry = UpstreamCircuitBreakerRegistry(
            config=CircuitBreakerConfig(failure_threshold=2, recovery_timeout_seconds=10),
            clock=clock,
        )
        key = _key()
        breaker = registry.breaker_for(key)

        await breaker.before_call()
        await breaker.record_failure()
        assert registry.snapshot(key).state == CircuitBreakerState.CLOSED

        await breaker.before_call()
        await breaker.record_failure()

        snapshot = registry.snapshot(key)
        assert snapshot.state == CircuitBreakerState.OPEN
        assert snapshot.consecutive_failures == 2
        with pytest.raises(CircuitBreakerOpenError):
            await breaker.before_call()

    asyncio.run(run())


def test_circuit_transitions_half_open_after_recovery_timeout_and_closes_on_success() -> None:
    async def run() -> None:
        clock = _Clock()
        registry = UpstreamCircuitBreakerRegistry(
            config=CircuitBreakerConfig(failure_threshold=1, recovery_timeout_seconds=10),
            clock=clock,
        )
        key = _key()
        breaker = registry.breaker_for(key)

        await breaker.record_failure()
        clock.advance(9.9)
        with pytest.raises(CircuitBreakerOpenError):
            await breaker.before_call()

        clock.advance(0.2)
        await breaker.before_call()
        assert registry.snapshot(key).state == CircuitBreakerState.HALF_OPEN

        await breaker.record_success()

        snapshot = registry.snapshot(key)
        assert snapshot.state == CircuitBreakerState.CLOSED
        assert snapshot.consecutive_failures == 0
        assert snapshot.opened_at_monotonic is None

    asyncio.run(run())


def test_half_open_allows_only_one_probe_until_result() -> None:
    async def run() -> None:
        clock = _Clock()
        registry = UpstreamCircuitBreakerRegistry(
            config=CircuitBreakerConfig(failure_threshold=1, recovery_timeout_seconds=1),
            clock=clock,
        )
        breaker = registry.breaker_for(_key())

        await breaker.record_failure()
        clock.advance(1.1)
        await breaker.before_call()

        with pytest.raises(CircuitBreakerOpenError):
            await breaker.before_call()

    asyncio.run(run())


def test_half_open_failure_reopens_circuit() -> None:
    async def run() -> None:
        clock = _Clock()
        registry = UpstreamCircuitBreakerRegistry(
            config=CircuitBreakerConfig(failure_threshold=1, recovery_timeout_seconds=1),
            clock=clock,
        )
        key = _key()
        breaker = registry.breaker_for(key)

        await breaker.record_failure()
        clock.advance(1.1)
        await breaker.before_call()
        await breaker.record_failure()

        assert registry.snapshot(key).state == CircuitBreakerState.OPEN
        with pytest.raises(CircuitBreakerOpenError):
            await breaker.before_call()

    asyncio.run(run())


def test_circuit_breaker_keys_are_tenant_scoped() -> None:
    async def run() -> None:
        server_id = uuid4()
        registry = UpstreamCircuitBreakerRegistry(
            config=CircuitBreakerConfig(failure_threshold=1, recovery_timeout_seconds=10)
        )
        tenant_a = CircuitBreakerKey(uuid4(), server_id, McpTransport.STREAMABLE_HTTP)
        tenant_b = CircuitBreakerKey(uuid4(), server_id, McpTransport.STREAMABLE_HTTP)

        await registry.breaker_for(tenant_a).record_failure()

        assert registry.snapshot(tenant_a).state == CircuitBreakerState.OPEN
        assert registry.snapshot(tenant_b).state == CircuitBreakerState.CLOSED

    asyncio.run(run())
