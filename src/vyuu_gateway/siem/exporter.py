"""The SIEM exporter — non-blocking, batching, per-target delivery.

## Hot-path contract

`emit_nowait()` is called from the audit chain on a request thread, from
a SQLAlchemy commit hook, and from a `logging.Handler` that may fire on
any thread. So it must be thread-safe, must never block, and must never
raise. It resolves which targets accept the event, appends to each
target's bounded in-memory queue under a lock, and pokes that target's
worker. That is all. No I/O, no secret lookups, no serialisation.

## Why one worker per target, not one queue for all

A tenant whose Splunk is down must not delay another tenant's delivery,
and a deployment target with a slow link must not back up tenant
queues. Each target has its own queue, worker, retry state and stats,
so a failure is contained to the target it belongs to.

## Loss is bounded and visible, never silent

The queue is bounded. When a target cannot keep up the newest events
are dropped, counted, and the target is flagged degraded — visible on
the console's status panel. Retries use exponential backoff on
retryable failures only; a non-retryable failure (bad token, wrong
index) drops the batch at once and records Splunk's own message, so the
operator reads "Invalid token" rather than a queue-depth graph.

The durable copy of tool calls is still Postgres. This channel adds
reach, not durability; it deliberately has no disk spool.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from vyuu_gateway.siem.events import SiemEvent, heartbeat_event
from vyuu_gateway.siem.hec import HecDeliveryError, HecTarget, SplunkHecClient
from vyuu_gateway.siem.targets import DEPLOYMENT_KEY, TargetConfig, TargetResolver
from vyuu_gateway.telemetry import Telemetry

logger = logging.getLogger(__name__)


class SecretResolver:
    """The slice of `SecretStore` the exporter needs."""

    async def get_secret(self, tenant_id: UUID, ref: str) -> str:  # pragma: no cover
        raise NotImplementedError


@dataclass
class TargetStats:
    key: str
    sent_events: int = 0
    sent_batches: int = 0
    failed_batches: int = 0
    retried_batches: int = 0
    dropped_events: int = 0
    queue_depth: int = 0
    degraded: bool = False
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    last_error: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "sent_events": self.sent_events,
            "sent_batches": self.sent_batches,
            "failed_batches": self.failed_batches,
            "retried_batches": self.retried_batches,
            "dropped_events": self.dropped_events,
            "queue_depth": self.queue_depth,
            "degraded": self.degraded,
            "last_success_at": (
                self.last_success_at.isoformat() if self.last_success_at else None
            ),
            "last_failure_at": (
                self.last_failure_at.isoformat() if self.last_failure_at else None
            ),
            "last_error": self.last_error,
        }


@dataclass
class _TargetQueue:
    config: TargetConfig
    max_size: int
    items: deque[SiemEvent] = field(default_factory=deque)
    lock: threading.Lock = field(default_factory=threading.Lock)
    stats: TargetStats = field(init=False)
    wake: asyncio.Event | None = None
    task: asyncio.Task[None] | None = None
    # Events drained from the queue but not yet acknowledged by the
    # collector. `flush()` waits on this too, so "flushed" means
    # delivered or dropped, not merely dequeued.
    in_flight: int = 0

    def __post_init__(self) -> None:
        self.stats = TargetStats(key=self.config.key)

    def push(self, event: SiemEvent) -> bool:
        with self.lock:
            if len(self.items) >= self.max_size:
                self.stats.dropped_events += 1
                self.stats.degraded = True
                self.stats.queue_depth = len(self.items)
                return False
            self.items.append(event)
            self.stats.queue_depth = len(self.items)
            return True

    def drain(self, limit: int) -> list[SiemEvent]:
        with self.lock:
            batch = [self.items.popleft() for _ in range(min(limit, len(self.items)))]
            self.stats.queue_depth = len(self.items)
            return batch

    def __len__(self) -> int:
        with self.lock:
            return len(self.items)


class SiemExporter:
    def __init__(
        self,
        *,
        client: SplunkHecClient,
        resolver: TargetResolver,
        secret_store: SecretResolver | Any,
        gateway_instance_id: str,
        telemetry: Telemetry | None = None,
        max_queue_size: int = 5000,
        max_attempts: int = 5,
        backoff_base_seconds: float = 1.0,
        backoff_cap_seconds: float = 30.0,
        token_ttl_seconds: float = 300.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._client = client
        self._resolver = resolver
        self._secret_store = secret_store
        self._gateway_instance_id = gateway_instance_id
        self._telemetry = telemetry or Telemetry()
        self._max_queue_size = max_queue_size
        self._max_attempts = max(1, max_attempts)
        self._backoff_base = backoff_base_seconds
        self._backoff_cap = backoff_cap_seconds
        self._token_ttl = token_ttl_seconds
        self._clock = clock
        self._sleep = sleep
        self._queues: dict[str, _TargetQueue] = {}
        self._queues_lock = threading.Lock()
        self._tokens: dict[tuple[UUID | None, str], tuple[float, str]] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._running = False

    # --- hot path -------------------------------------------------------

    def emit_nowait(self, event: SiemEvent) -> None:
        for config in self._resolver.targets_for(event.tenant_id):
            if not config.accepts(event):
                continue
            queue = self._queue_for(config)
            queue.push(event)
            self._wake(queue)

    def _queue_for(self, config: TargetConfig) -> _TargetQueue:
        with self._queues_lock:
            queue = self._queues.get(config.key)
            if queue is None:
                queue = _TargetQueue(config=config, max_size=self._max_queue_size)
                self._queues[config.key] = queue
            elif queue.config != config:
                # Settings changed under us: keep the queue and its
                # stats, deliver with the new config from here on.
                queue.config = config
        if self._running and queue.task is None:
            self._schedule(self._ensure_worker, queue)
        return queue

    def _wake(self, queue: _TargetQueue) -> None:
        wake = queue.wake
        if wake is None:
            return
        self._schedule(wake.set)

    def _schedule(self, fn: Callable[..., Any], *args: Any) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            loop.call_soon_threadsafe(fn, *args)
        except RuntimeError:
            # Loop shut down between the check and the call.
            return

    # --- lifecycle ------------------------------------------------------

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._running = True
        with self._queues_lock:
            queues = list(self._queues.values())
        for queue in queues:
            self._ensure_worker(queue)

    def _ensure_worker(self, queue: _TargetQueue) -> None:
        if not self._running or queue.task is not None:
            return
        queue.wake = asyncio.Event()
        queue.task = asyncio.create_task(
            self._run(queue), name=f"siem-export:{queue.config.key}"
        )
        # Anything queued before the worker existed.
        queue.wake.set()

    async def stop(self) -> None:
        self._running = False
        with self._queues_lock:
            queues = list(self._queues.values())
        for queue in queues:
            task = queue.task
            queue.task = None
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        await self._client.aclose()

    async def aclose(self) -> None:
        await self.stop()

    async def flush(self, timeout_seconds: float = 5.0) -> bool:
        """Wait for every queue to drain. Tests, and graceful shutdown."""

        deadline = self._clock() + timeout_seconds
        while self._clock() < deadline:
            with self._queues_lock:
                queues = list(self._queues.values())
            for queue in queues:
                self._wake(queue)
            if all(len(q) == 0 and q.in_flight == 0 for q in queues):
                return True
            await asyncio.sleep(0.02)
        return False

    async def _run(self, queue: _TargetQueue) -> None:
        assert queue.wake is not None
        while self._running:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(
                    queue.wake.wait(), timeout=queue.config.flush_interval_seconds
                )
            queue.wake.clear()
            while True:
                batch = queue.drain(queue.config.batch_max_events)
                if not batch:
                    break
                queue.in_flight = len(batch)
                try:
                    await self._deliver(queue, batch)
                finally:
                    queue.in_flight = 0

    # --- delivery -------------------------------------------------------

    async def _deliver(self, queue: _TargetQueue, batch: list[SiemEvent]) -> None:
        config = queue.config
        stats = queue.stats
        try:
            target = await self._hec_target(config)
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            self._record_failure(queue, batch, f"token unavailable: {exc}")
            return

        for attempt in range(1, self._max_attempts + 1):
            try:
                sent = await self._client.send_batch(
                    target,
                    batch,
                    include_raw=config.include_raw_payloads,
                    gateway_instance_id=self._gateway_instance_id,
                )
            except HecDeliveryError as exc:
                if exc.retryable and attempt < self._max_attempts:
                    stats.retried_batches += 1
                    await self._sleep(
                        min(self._backoff_cap, self._backoff_base * (2 ** (attempt - 1)))
                    )
                    continue
                self._record_failure(queue, batch, exc.detail)
                return
            except Exception as exc:  # noqa: BLE001 - reported, not raised
                self._record_failure(queue, batch, f"{exc.__class__.__name__}: {exc}")
                return
            stats.sent_events += sent
            stats.sent_batches += 1
            stats.degraded = False
            stats.last_success_at = datetime.now(UTC)
            stats.last_error = None
            self._telemetry.record_siem_delivery(target=config.key, sent=sent, failed=0)
            return

    def _record_failure(self, queue: _TargetQueue, batch: list[SiemEvent], detail: str) -> None:
        stats = queue.stats
        stats.failed_batches += 1
        stats.dropped_events += len(batch)
        stats.degraded = True
        stats.last_failure_at = datetime.now(UTC)
        stats.last_error = detail[:300]
        self._telemetry.record_siem_delivery(
            target=queue.config.key, sent=0, failed=len(batch)
        )
        logger.warning(
            "siem_batch_dropped",
            extra={
                "target": queue.config.key,
                "events": len(batch),
                "detail": detail[:300],
            },
        )

    async def _hec_target(self, config: TargetConfig) -> HecTarget:
        if config.token_literal is not None:
            token = config.token_literal
        else:
            token = await self._token(config)
        return HecTarget(
            url=config.hec_url,
            token=token,
            index=config.index,
            source=config.source,
            host=config.host,
            verify_tls=config.verify_tls,
        )

    async def _token(self, config: TargetConfig) -> str:
        if config.token_ref is None or config.tenant_id is None:
            raise RuntimeError("target has neither a token nor a token reference")
        cache_key = (config.tenant_id, config.token_ref)
        cached = self._tokens.get(cache_key)
        now = self._clock()
        if cached is not None and cached[0] > now:
            return cached[1]
        token = await self._secret_store.get_secret(config.tenant_id, config.token_ref)
        if not token:
            raise RuntimeError(f"secret {config.token_ref!r} is empty")
        self._tokens[cache_key] = (now + self._token_ttl, token)
        return token

    # --- operator-facing ------------------------------------------------

    def invalidate(self, tenant_id: UUID | None) -> None:
        """A settings change: forget cached config and token."""

        self._resolver.invalidate(tenant_id)
        for key in [k for k in self._tokens if k[0] == tenant_id]:
            self._tokens.pop(key, None)

    def stats(self) -> dict[str, TargetStats]:
        with self._queues_lock:
            return {key: q.stats for key, q in self._queues.items()}

    def stats_for(self, tenant_id: UUID | None) -> TargetStats | None:
        key = DEPLOYMENT_KEY if tenant_id is None else str(tenant_id)
        return self.stats().get(key)

    def deployment_target_configured(self) -> bool:
        return any(t.tenant_id is None for t in self._resolver.targets_for(None))

    async def send_test(self, tenant_id: UUID | None) -> tuple[bool, str]:
        """Deliver one heartbeat to the tenant's (or deployment's) target
        right now, bypassing the queue. What the console's Test button
        calls; the answer is Splunk's own."""

        key = DEPLOYMENT_KEY if tenant_id is None else str(tenant_id)
        self.invalidate(tenant_id)
        configs = [c for c in self._resolver.targets_for(tenant_id) if c.key == key]
        if not configs:
            return False, "no enabled SIEM target is configured"
        config = configs[0]
        try:
            target = await self._hec_target(config)
        except Exception as exc:  # noqa: BLE001 - shown to the operator
            return False, f"token unavailable: {exc}"
        event = heartbeat_event(tenant_id, gateway_instance_id=self._gateway_instance_id)
        try:
            await self._client.send_batch(
                target, [event], include_raw=False,
                gateway_instance_id=self._gateway_instance_id,
            )
        except HecDeliveryError as exc:
            return False, exc.detail
        except Exception as exc:  # noqa: BLE001 - shown to the operator
            return False, f"{exc.__class__.__name__}: {exc}"
        return True, f"delivered one heartbeat event to {config.hec_url}"
