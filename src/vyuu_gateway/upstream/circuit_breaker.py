"""Per-upstream circuit breakers for outbound MCP calls."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from vyuu_gateway.db.models import McpTransport


class CircuitBreakerState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpenError(Exception):
    """The upstream circuit is open and calls are temporarily rejected."""


class CircuitBreaker(Protocol):
    async def before_call(self) -> None:
        """Raise when the call should be rejected by the breaker."""

    async def record_success(self) -> None:
        """Record a successful upstream operation."""

    async def record_failure(self) -> None:
        """Record a failed upstream operation."""

    def snapshot(self) -> CircuitBreakerSnapshot:
        """Return current breaker state."""


@dataclass(frozen=True)
class CircuitBreakerConfig:
    failure_threshold: int = 5
    recovery_timeout_seconds: float = 30.0
    half_open_success_threshold: int = 1

    def __post_init__(self) -> None:
        if self.failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if self.recovery_timeout_seconds <= 0:
            raise ValueError("recovery_timeout_seconds must be > 0")
        if self.half_open_success_threshold < 1:
            raise ValueError("half_open_success_threshold must be >= 1")


@dataclass(frozen=True)
class CircuitBreakerKey:
    tenant_id: UUID
    server_id: UUID
    transport: McpTransport


@dataclass(frozen=True)
class CircuitBreakerSnapshot:
    key: CircuitBreakerKey
    state: CircuitBreakerState
    consecutive_failures: int
    opened_at_monotonic: float | None


class UpstreamCircuitBreakerRegistry:
    """Owns circuit breakers keyed by tenant-scoped upstream identity."""

    def __init__(
        self,
        *,
        config: CircuitBreakerConfig | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config or CircuitBreakerConfig()
        self._clock = clock
        self._breakers: dict[CircuitBreakerKey, _CircuitBreaker] = {}

    def breaker_for(self, key: CircuitBreakerKey) -> CircuitBreaker:
        breaker = self._breakers.get(key)
        if breaker is None:
            breaker = _CircuitBreaker(key=key, config=self._config, clock=self._clock)
            self._breakers[key] = breaker
        return breaker

    def snapshot(self, key: CircuitBreakerKey) -> CircuitBreakerSnapshot:
        return self.breaker_for(key).snapshot()


class _CircuitBreaker:
    def __init__(
        self,
        *,
        key: CircuitBreakerKey,
        config: CircuitBreakerConfig,
        clock: Callable[[], float],
    ) -> None:
        self._key = key
        self._config = config
        self._clock = clock
        self._state = CircuitBreakerState.CLOSED
        self._consecutive_failures = 0
        self._half_open_successes = 0
        self._half_open_probe_in_flight = False
        self._opened_at: float | None = None
        self._lock = asyncio.Lock()

    async def before_call(self) -> None:
        async with self._lock:
            if self._state == CircuitBreakerState.CLOSED:
                return

            if self._state == CircuitBreakerState.OPEN:
                assert self._opened_at is not None
                if self._clock() - self._opened_at < self._config.recovery_timeout_seconds:
                    raise CircuitBreakerOpenError("upstream circuit breaker is open")
                self._state = CircuitBreakerState.HALF_OPEN
                self._half_open_successes = 0
                self._half_open_probe_in_flight = False

            if self._state == CircuitBreakerState.HALF_OPEN:
                if self._half_open_probe_in_flight:
                    raise CircuitBreakerOpenError("upstream circuit breaker is half-open")
                self._half_open_probe_in_flight = True

    async def record_success(self) -> None:
        async with self._lock:
            if self._state == CircuitBreakerState.HALF_OPEN:
                self._half_open_probe_in_flight = False
                self._half_open_successes += 1
                if self._half_open_successes >= self._config.half_open_success_threshold:
                    self._close()
                return

            if self._state == CircuitBreakerState.CLOSED:
                self._consecutive_failures = 0

    async def record_failure(self) -> None:
        async with self._lock:
            if self._state == CircuitBreakerState.HALF_OPEN:
                self._open()
                return

            if self._state == CircuitBreakerState.CLOSED:
                self._consecutive_failures += 1
                if self._consecutive_failures >= self._config.failure_threshold:
                    self._open()

    def snapshot(self) -> CircuitBreakerSnapshot:
        return CircuitBreakerSnapshot(
            key=self._key,
            state=self._state,
            consecutive_failures=self._consecutive_failures,
            opened_at_monotonic=self._opened_at,
        )

    def _open(self) -> None:
        self._state = CircuitBreakerState.OPEN
        self._opened_at = self._clock()
        self._half_open_successes = 0
        self._half_open_probe_in_flight = False

    def _close(self) -> None:
        self._state = CircuitBreakerState.CLOSED
        self._consecutive_failures = 0
        self._half_open_successes = 0
        self._half_open_probe_in_flight = False
        self._opened_at = None
