from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID, uuid4

import pytest
from mcp.types import CallToolResult, InitializeResult, Prompt, Resource, Tool

from vyuu_gateway.capabilities.client import CapabilityDescriptor
from vyuu_gateway.db.models import McpTransport
from vyuu_gateway.mcp.sdk_compat import sdk_field
from vyuu_gateway.upstream.circuit_breaker import (
    CircuitBreakerConfig,
    CircuitBreakerKey,
    CircuitBreakerOpenError,
    CircuitBreakerState,
    UpstreamCircuitBreakerRegistry,
)
from vyuu_gateway.upstream.pool import (
    PooledOutboundMcpClient,
    UpstreamClientPool,
    UpstreamPoolKey,
)


class _FakeOutboundClient:
    def __init__(self, *, fail_call: bool = False) -> None:
        self.fail_call = fail_call
        self.closed = False
        self.calls = 0

    async def initialize(self) -> InitializeResult:
        raise NotImplementedError

    async def list_tools(self) -> list[Tool]:
        return []

    async def list_resources(self) -> list[Resource]:
        return []

    async def list_prompts(self) -> list[Prompt]:
        return []

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        inbound_headers: dict[str, str] | None = None,  # noqa: ARG002
        principal_id: object = None,  # noqa: ARG002
    ) -> CallToolResult:
        self.calls += 1
        if self.fail_call:
            raise RuntimeError("upstream failed")
        return CallToolResult(content=[], isError=False)

    async def list_capabilities(
        self, *, principal_id: UUID | None = None
    ) -> list[CapabilityDescriptor]:
        del principal_id  # Stdio fakes ignore the per-user OAuth bearer.
        return []

    async def aclose(self) -> None:
        self.closed = True


def _async_returning(client: _FakeOutboundClient) -> Any:
    """Helper: wrap a sync `client` value as an async factory for the pool."""

    async def _factory() -> _FakeOutboundClient:
        return client

    return _factory


def _key() -> UpstreamPoolKey:
    return UpstreamPoolKey(
        tenant_id=uuid4(),
        server_id=uuid4(),
        transport=McpTransport.STREAMABLE_HTTP,
    )


def test_pool_reuses_released_client_for_same_key() -> None:
    async def run() -> None:
        pool = UpstreamClientPool(max_clients_per_upstream=1)
        key = _key()
        created: list[_FakeOutboundClient] = []

        async def factory() -> _FakeOutboundClient:
            client = _FakeOutboundClient()
            created.append(client)
            return client

        async with pool.acquire(key, factory) as first:
            assert first is created[0]
        async with pool.acquire(key, factory) as second:
            assert second is created[0]

        assert len(created) == 1
        await pool.close_all()

    asyncio.run(run())


def test_pool_is_tenant_keyed_even_for_same_server_id() -> None:
    async def run() -> None:
        pool = UpstreamClientPool(max_clients_per_upstream=1)
        server_id = uuid4()
        tenant_a_key = UpstreamPoolKey(uuid4(), server_id, McpTransport.STREAMABLE_HTTP)
        tenant_b_key = UpstreamPoolKey(uuid4(), server_id, McpTransport.STREAMABLE_HTTP)
        created: list[_FakeOutboundClient] = []

        async def factory() -> _FakeOutboundClient:
            client = _FakeOutboundClient()
            created.append(client)
            return client

        async with pool.acquire(tenant_a_key, factory) as client_a:
            async with pool.acquire(tenant_b_key, factory) as client_b:
                assert client_a is not client_b

        assert len(created) == 2
        await pool.close_all()

    asyncio.run(run())


def test_pool_waits_when_per_upstream_capacity_is_exhausted() -> None:
    async def run() -> None:
        pool = UpstreamClientPool(max_clients_per_upstream=1)
        key = _key()

        async def factory() -> _FakeOutboundClient:
            return _FakeOutboundClient()

        async def second_acquire() -> None:
            async with pool.acquire(key, factory):
                return

        async with pool.acquire(key, factory):
            task = asyncio.create_task(second_acquire())
            await asyncio.sleep(0)
            assert not task.done()

        await asyncio.wait_for(task, timeout=1.0)
        await pool.close_all()

    asyncio.run(run())


def test_factory_failure_does_not_leak_pool_capacity() -> None:
    async def run() -> None:
        pool = UpstreamClientPool(max_clients_per_upstream=1)
        key = _key()
        attempts = 0

        async def factory() -> _FakeOutboundClient:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("cannot connect")
            return _FakeOutboundClient()

        with pytest.raises(RuntimeError, match="cannot connect"):
            async with pool.acquire(key, factory):
                pass

        async with pool.acquire(key, factory) as client:
            assert isinstance(client, _FakeOutboundClient)
        assert attempts == 2
        await pool.close_all()

    asyncio.run(run())


def test_pooled_client_discards_and_closes_client_after_operation_error() -> None:
    async def run() -> None:
        pool = UpstreamClientPool(max_clients_per_upstream=1)
        key = _key()
        failing = _FakeOutboundClient(fail_call=True)
        succeeding = _FakeOutboundClient()
        clients = [failing, succeeding]

        async def factory() -> _FakeOutboundClient:
            return clients.pop(0)

        pooled = PooledOutboundMcpClient(key=key, pool=pool, factory=factory)

        with pytest.raises(RuntimeError, match="upstream failed"):
            await pooled.call_tool("echo", {})
        assert failing.closed

        result = await pooled.call_tool("echo", {})
        assert not sdk_field(result, "is_error")
        assert succeeding.calls == 1
        await pool.close_all()
        assert succeeding.closed

    asyncio.run(run())


def test_close_all_closes_idle_clients() -> None:
    async def run() -> None:
        pool = UpstreamClientPool(max_clients_per_upstream=1)
        key = _key()
        client = _FakeOutboundClient()

        async with pool.acquire(key, _async_returning(client)):
            pass

        await pool.close_all()

        assert client.closed

    asyncio.run(run())


def test_pooled_client_opens_circuit_after_consecutive_operation_failures() -> None:
    async def run() -> None:
        pool = UpstreamClientPool(max_clients_per_upstream=1)
        key = _key()
        circuit_breakers = UpstreamCircuitBreakerRegistry(
            config=CircuitBreakerConfig(failure_threshold=1, recovery_timeout_seconds=30)
        )
        failing = _FakeOutboundClient(fail_call=True)
        pooled = PooledOutboundMcpClient(
            key=key,
            pool=pool,
            factory=_async_returning(failing),
            circuit_breakers=circuit_breakers,
        )

        with pytest.raises(RuntimeError, match="upstream failed"):
            await pooled.call_tool("echo", {})
        assert circuit_breakers.snapshot(_breaker_key(key)).state == CircuitBreakerState.OPEN

        with pytest.raises(CircuitBreakerOpenError):
            await pooled.call_tool("echo", {})
        assert failing.calls == 1

    asyncio.run(run())


def test_pooled_client_resets_circuit_after_successful_operation() -> None:
    async def run() -> None:
        pool = UpstreamClientPool(max_clients_per_upstream=1)
        key = _key()
        circuit_breakers = UpstreamCircuitBreakerRegistry(
            config=CircuitBreakerConfig(failure_threshold=2, recovery_timeout_seconds=30)
        )
        client = _FakeOutboundClient()
        pooled = PooledOutboundMcpClient(
            key=key,
            pool=pool,
            factory=_async_returning(client),
            circuit_breakers=circuit_breakers,
        )
        breaker_key = _breaker_key(key)

        await circuit_breakers.breaker_for(breaker_key).record_failure()
        result = await pooled.call_tool("echo", {})

        assert not sdk_field(result, "is_error")
        assert circuit_breakers.snapshot(breaker_key).consecutive_failures == 0
        await pool.close_all()

    asyncio.run(run())


def _breaker_key(key: UpstreamPoolKey) -> CircuitBreakerKey:
    return CircuitBreakerKey(
        tenant_id=key.tenant_id,
        server_id=key.server_id,
        transport=key.transport,
    )


# --- Provider-level teardown ------------------------------------------------


@pytest.mark.anyio
async def test_forget_server_closes_the_pooled_client() -> None:
    """`forget_server` must actually close the client, not just drop the
    memo — for stdio that close IS the subprocess kill."""
    from vyuu_gateway.upstream.provider import DatabaseBackedUpstreamClientProvider

    tenant_id, server_id = uuid4(), uuid4()
    key = UpstreamPoolKey(
        tenant_id=tenant_id,
        server_id=server_id,
        transport=McpTransport.STDIO,
    )
    pool = UpstreamClientPool(max_clients_per_upstream=1)
    upstream = _FakeOutboundClient()

    async def factory() -> _FakeOutboundClient:
        return upstream

    provider = DatabaseBackedUpstreamClientProvider.__new__(
        DatabaseBackedUpstreamClientProvider
    )
    provider._pool = pool
    provider._oauth_providers = {}
    provider._clients_by_lookup_key = {
        (tenant_id, server_id): PooledOutboundMcpClient(
            key=key, pool=pool, factory=factory
        )
    }

    # Put a live client in the pool, as a real call would: acquire
    # then release leaves it idle and reusable.
    async with pool.acquire(key, factory):
        pass
    assert upstream.closed is False

    await provider.forget_server(tenant_id, server_id)

    assert upstream.closed is True
    assert provider._clients_by_lookup_key == {}


@pytest.mark.anyio
async def test_forget_server_is_a_noop_for_a_server_never_connected_to() -> None:
    """Deleting a registered-but-never-used server must not raise."""
    from vyuu_gateway.upstream.provider import DatabaseBackedUpstreamClientProvider

    provider = DatabaseBackedUpstreamClientProvider.__new__(
        DatabaseBackedUpstreamClientProvider
    )
    provider._pool = UpstreamClientPool(max_clients_per_upstream=1)
    provider._oauth_providers = {}
    provider._clients_by_lookup_key = {}

    await provider.forget_server(uuid4(), uuid4())  # must not raise
