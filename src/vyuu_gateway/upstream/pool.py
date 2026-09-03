"""Bounded upstream MCP client pool.

The pool is tenant-aware by construction: callers must include tenant_id in
the pool key. A pooled client is discarded after operation failures so broken
transport state is not returned to the idle set.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, TypeVar
from uuid import UUID

from mcp.types import CallToolResult, InitializeResult, Prompt, Resource, Tool

from vyuu_gateway.capabilities.client import CapabilityDescriptor
from vyuu_gateway.db.models import McpTransport
from vyuu_gateway.mcp.outbound import OutboundMcpClient
from vyuu_gateway.upstream.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerKey,
    UpstreamCircuitBreakerRegistry,
)

logger = logging.getLogger(__name__)

# Where a pooled client remembers when it was built, for the P2
# credential-freshness TTL. On the instance rather than in a pool-side
# map so it cannot outlive the client it describes.
_BUILT_AT_ATTR = "_vyuu_pool_built_at"

T = TypeVar("T")
# Async so the factory can resolve tenant-scoped secrets from a `SecretStore`
# (which is network-bound for Vault / AWS / k8s) before constructing the
# transport client. The pool calls it under the same async context as the
# upstream operation, so this never blocks the lifecycle.
ClientFactory = Callable[[], Awaitable[OutboundMcpClient]]
ClientOperation = Callable[[OutboundMcpClient], Awaitable[T]]


class UpstreamPoolClosedError(Exception):
    """Requested upstream pool key is closing and cannot lease new clients."""


@dataclass(frozen=True)
class UpstreamPoolKey:
    """Tenant-scoped upstream identity for pooling."""

    tenant_id: UUID
    server_id: UUID
    transport: McpTransport


@dataclass
class _PoolState:
    # P2 · each idle entry carries the monotonic time its client was
    # BUILT, not when it was returned to the pool. Credential freshness
    # is about when the secret was read, and the secret is read once, in
    # the factory. Refreshing the timestamp on release would let a
    # continuously-busy connection stay "fresh" forever — which is
    # exactly the stable-connection case the TTL exists for.
    idle: list[tuple[OutboundMcpClient, float]] = field(default_factory=list)
    total: int = 0
    closing: bool = False
    condition: asyncio.Condition = field(default_factory=asyncio.Condition)


class UpstreamClientPool:
    """Async-safe bounded pool for outbound MCP clients."""

    def __init__(
        self,
        *,
        max_clients_per_upstream: int = 4,
        client_max_age_seconds: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """`client_max_age_seconds` bounds how long a pooled client may
        carry the credential it was built with (P2).

        Org-tier `auth_headers` are resolved from the SecretStore once,
        in the factory, and then baked into the transport client. Without
        a TTL a rotated secret only takes effect when the connection
        happens to drop or a circuit breaker opens — so a tenant that
        rotates a **leaked** credential can keep serving traffic with it
        for hours, which is the opposite of what rotating it was for.

        `None` disables the TTL and restores the previous behaviour.
        """

        if max_clients_per_upstream < 1:
            raise ValueError("max_clients_per_upstream must be >= 1")
        if client_max_age_seconds is not None and client_max_age_seconds <= 0:
            raise ValueError("client_max_age_seconds must be positive or None")
        self._max_clients_per_upstream = max_clients_per_upstream
        self._client_max_age_seconds = client_max_age_seconds
        self._clock = clock
        self._states: dict[UpstreamPoolKey, _PoolState] = {}

    @property
    def max_clients_per_upstream(self) -> int:
        return self._max_clients_per_upstream

    @asynccontextmanager
    async def acquire(
        self,
        key: UpstreamPoolKey,
        factory: ClientFactory,
    ) -> AsyncIterator[OutboundMcpClient]:
        client = await self._acquire(key, factory)
        discard = False
        try:
            yield client
        except (Exception, asyncio.CancelledError):
            discard = True
            raise
        finally:
            await self.release(key, client, discard=discard)

    async def release(
        self,
        key: UpstreamPoolKey,
        client: OutboundMcpClient,
        *,
        discard: bool = False,
    ) -> None:
        close_client = False
        state = self._states.get(key)
        if state is None:
            close_client = True
        else:
            async with state.condition:
                if discard or state.closing:
                    state.total -= 1
                    close_client = True
                    if state.closing and state.total == 0:
                        self._states.pop(key, None)
                else:
                    # Age is measured from BUILD, not from release —
                    # see `_PoolState.idle`. The pool never sees the
                    # factory call, so the stamp is carried on the client
                    # and set the first time it is released.
                    created_at = getattr(client, _BUILT_AT_ATTR, None)
                    if created_at is None:
                        created_at = self._clock()
                        try:
                            setattr(client, _BUILT_AT_ATTR, created_at)
                        except (AttributeError, TypeError):
                            # A client that refuses attributes (a slotted
                            # or frozen test fake) simply never ages out.
                            # Preferable to failing the release path.
                            pass
                    state.idle.append((client, created_at))
                state.condition.notify()

        if close_client:
            await _close_client(client)

    async def close_key(self, key: UpstreamPoolKey) -> None:
        state = self._states.get(key)
        if state is None:
            return

        async with state.condition:
            state.closing = True
            # `idle` entries are now `(client, built_at)` — unwrap for
            # the closer, which only needs the client.
            idle = [client for client, _built_at in state.idle]
            state.idle.clear()
            state.total -= len(idle)
            if state.total == 0:
                self._states.pop(key, None)
            state.condition.notify_all()

        await _close_many(idle)

    async def close_all(self) -> None:
        keys = list(self._states)
        for key in keys:
            await self.close_key(key)

    async def _acquire(
        self,
        key: UpstreamPoolKey,
        factory: ClientFactory,
    ) -> OutboundMcpClient:
        state = self._state_for(key)
        while True:
            # `expired` is collected under the lock but CLOSED outside it:
            # `aclose()` can be slow (a stdio subprocess teardown), and
            # holding the pool lock across it would stall every other
            # caller for this upstream.
            expired: list[OutboundMcpClient] = []
            reuse: OutboundMcpClient | None = None
            build = False

            async with state.condition:
                if state.closing:
                    raise UpstreamPoolClosedError("upstream pool key is closing")
                # P2 · retire aged-out clients before reusing one. Checked
                # on ACQUIRE rather than on a timer: an idle pool nobody
                # is using holds no stale credential in practice, and a
                # sweeper would need its own task, failure mode and tests
                # to close a window that only exists at the moment of use.
                expired = self._take_expired(state)
                if expired:
                    state.total -= len(expired)
                if state.idle:
                    reuse = state.idle.pop()[0]
                elif state.total < self._max_clients_per_upstream:
                    state.total += 1
                    build = True
                if expired:
                    # Slots freed — wake anyone blocked on capacity.
                    state.condition.notify(len(expired))
                if reuse is None and not build:
                    await state.condition.wait()

            for client in expired:
                await _safe_close(client)

            if reuse is not None:
                return reuse
            if build:
                break
            # Neither reused nor authorised to build: we were woken by a
            # release or an expiry. Re-enter and re-evaluate.

        try:
            return await factory()
        except (Exception, asyncio.CancelledError):
            async with state.condition:
                state.total -= 1
                if state.closing and state.total == 0:
                    self._states.pop(key, None)
                state.condition.notify()
            raise

    def _take_expired(self, state: _PoolState) -> list[OutboundMcpClient]:
        """Remove and return idle clients past `client_max_age_seconds`.

        Only IDLE clients are considered — a leased client is mid-call and
        is not ours to close. It gets checked the next time it is
        acquired, which is the first moment its credential could matter
        again.
        """

        if self._client_max_age_seconds is None or not state.idle:
            return []
        cutoff = self._clock() - self._client_max_age_seconds
        fresh: list[tuple[OutboundMcpClient, float]] = []
        stale: list[OutboundMcpClient] = []
        for client, created_at in state.idle:
            (stale.append(client) if created_at <= cutoff else fresh.append((client, created_at)))
        if stale:
            logger.info(
                "upstream_pool_client_retired_for_age",
                extra={"retired": len(stale), "max_age_s": self._client_max_age_seconds},
            )
        state.idle = fresh
        return stale

    def _state_for(self, key: UpstreamPoolKey) -> _PoolState:
        state = self._states.get(key)
        if state is None:
            state = _PoolState()
            self._states[key] = state
        return state


class PooledOutboundMcpClient:
    """Outbound MCP client proxy backed by `UpstreamClientPool`."""

    def __init__(
        self,
        *,
        key: UpstreamPoolKey,
        pool: UpstreamClientPool,
        factory: ClientFactory,
        circuit_breakers: UpstreamCircuitBreakerRegistry | None = None,
    ) -> None:
        self.key = key
        self._pool = pool
        self._factory = factory
        self._circuit_breakers = circuit_breakers

    async def initialize(self) -> InitializeResult:
        return await self._with_client(lambda client: client.initialize())

    async def list_tools(self) -> list[Tool]:
        return await self._with_client(lambda client: client.list_tools())

    async def list_resources(self) -> list[Resource]:
        return await self._with_client(lambda client: client.list_resources())

    async def list_prompts(self) -> list[Prompt]:
        return await self._with_client(lambda client: client.list_prompts())

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        inbound_headers: dict[str, str] | None = None,
        principal_id: UUID | None = None,
    ) -> CallToolResult:
        return await self._with_client(
            lambda client: client.call_tool(
                tool_name,
                arguments,
                inbound_headers=inbound_headers,
                principal_id=principal_id,
            )
        )

    async def list_capabilities(
        self,
        *,
        principal_id: UUID | None = None,
    ) -> list[CapabilityDescriptor]:
        return await self._with_client(
            lambda client: client.list_capabilities(principal_id=principal_id)
        )

    async def _with_client(self, operation: ClientOperation[T]) -> T:
        breaker = self._breaker()
        if breaker is not None:
            await breaker.before_call()

        try:
            async with self._pool.acquire(self.key, self._factory) as client:
                result = await operation(client)
        except Exception:
            if breaker is not None:
                await breaker.record_failure()
            raise

        if breaker is not None:
            await breaker.record_success()
        return result

    def _breaker(self) -> CircuitBreaker | None:
        if self._circuit_breakers is None:
            return None
        return self._circuit_breakers.breaker_for(
            CircuitBreakerKey(
                tenant_id=self.key.tenant_id,
                server_id=self.key.server_id,
                transport=self.key.transport,
            )
        )


async def _close_many(clients: list[OutboundMcpClient]) -> None:
    for client in clients:
        await _close_client(client)


async def _close_client(client: OutboundMcpClient) -> None:
    aclose = getattr(client, "aclose", None)
    if callable(aclose):
        try:
            result = aclose()
            if inspect.isawaitable(result):
                await result
        except Exception:
            logger.warning("upstream_client_close_failed", exc_info=True)
        return

    close = getattr(client, "close", None)
    if callable(close):
        try:
            result = close()
            if inspect.isawaitable(result):
                await result
        except Exception:
            logger.warning("upstream_client_close_failed", exc_info=True)


async def _safe_close(client: OutboundMcpClient) -> None:
    """Close a retired client without letting its teardown break the
    acquire path. A client we are discarding *because* it is stale is
    exactly the one most likely to fail on close."""

    aclose = getattr(client, "aclose", None)
    if aclose is None:
        return
    try:
        await aclose()
    except Exception:  # noqa: BLE001
        logger.warning("upstream_pool_retired_client_close_failed", exc_info=True)
