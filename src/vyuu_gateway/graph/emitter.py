"""Non-blocking emitter for NHI graph events.

Mirrors the audit emitter pattern: the lifecycle calls `emit_nowait` and never
awaits a downstream publish. The default is a no-op (graph telemetry off);
production wires `AsyncGraphEventEmitter` over a `KafkaGraphProducer` /
`NatsGraphProducer` for a real graph-ingestion pipeline.

Why no disk-spool fallback (unlike audit): graph events are derivable from
audit events (same `correlation_id`), so durability rides on the audit
pipeline. Producer failure here marks degraded + drops. Operator replays
graph events offline by re-running the graph builder over the audit log.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Protocol

from vyuu_gateway.graph.events import GraphEvent
from vyuu_gateway.graph.producer import GraphEventProducer

logger = logging.getLogger(__name__)


class GraphEventEmitter(Protocol):
    def emit_nowait(self, event: GraphEvent) -> None:
        """Hand off a graph event without blocking the request hot path."""


class NoOpGraphEventEmitter:
    """Default emitter — discards events.

    Used when graph telemetry is disabled or ingestion is not yet wired up.
    """

    def emit_nowait(self, event: GraphEvent) -> None:
        return None


class InMemoryGraphEventEmitter:
    """Test emitter that records every event."""

    def __init__(self) -> None:
        self.events: list[GraphEvent] = []

    def emit_nowait(self, event: GraphEvent) -> None:
        self.events.append(event)


class AsyncGraphEventEmitter:
    """Non-blocking graph emitter backed by an async queue + producer worker.

    Same hot-path shape as `AsyncAuditEmitter`: `emit_nowait` enqueues; a
    single background task drains the queue and awaits `producer.produce`.
    On producer failure, the worker sets `degraded=True` and drops the
    event (no disk spool — see module docstring).

    Backpressure: when the queue is full, `emit_nowait` drops + flags
    degraded. Graph events are best-effort; we will never let them block
    a tool call.
    """

    def __init__(
        self,
        producer: GraphEventProducer,
        *,
        max_queue_size: int = 1000,
    ) -> None:
        self._producer = producer
        self._queue: asyncio.Queue[GraphEvent] = asyncio.Queue(maxsize=max_queue_size)
        self._worker: asyncio.Task[None] | None = None
        self._degraded = False
        self._dropped_count = 0

    async def start(self) -> None:
        if self._worker is None or self._worker.done():
            self._worker = asyncio.create_task(self._run())

    async def stop(self) -> None:
        await self._queue.join()
        if self._worker is not None:
            self._worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._worker
            self._worker = None

    async def aclose(self) -> None:
        """Lifespan integration — `_close_if_supported` calls aclose."""

        await self.stop()

    def emit_nowait(self, event: GraphEvent) -> None:
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self._degraded = True
            self._dropped_count += 1

    async def flush(self) -> None:
        await self._queue.join()

    @property
    def degraded(self) -> bool:
        return self._degraded

    @property
    def dropped_count(self) -> int:
        return self._dropped_count

    async def _run(self) -> None:
        while True:
            event = await self._queue.get()
            try:
                await self._producer.produce(event)
                self._degraded = False
            except Exception:
                # Producer-level failure: mark degraded, drop. Audit
                # pipeline carries the correlation_id; offline rebuild
                # is the recovery path.
                self._degraded = True
                logger.warning(
                    "graph_event_drop_on_producer_error",
                    extra={"event_kind": event.__class__.__name__},
                )
            finally:
                self._queue.task_done()
