import asyncio
import contextlib
import logging
from dataclasses import dataclass
from typing import Protocol

from vyuu_gateway.audit.events import AuditEvent
from vyuu_gateway.audit.producer import AuditProducer
from vyuu_gateway.audit.spool import AuditSpoolFullError, DiskSpool

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EmitResult:
    accepted: bool
    spooled: bool = False
    durable: bool = False
    degraded: bool = False
    reason: str | None = None


class AuditEmitter(Protocol):
    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        """Accept an audit event without blocking the request hot path."""


class AsyncAuditEmitter:
    """Non-blocking audit emitter backed by an async queue and producer worker."""

    def __init__(
        self,
        producer: AuditProducer,
        *,
        max_queue_size: int = 1000,
        overflow_spool: DiskSpool | None = None,
    ) -> None:
        self._producer = producer
        self._queue: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=max_queue_size)
        self._overflow_spool = overflow_spool
        self._worker: asyncio.Task[None] | None = None
        self._degraded = False

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

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        try:
            self._queue.put_nowait(event)
            return EmitResult(accepted=True, degraded=self._degraded)
        except asyncio.QueueFull:
            if self._overflow_spool is not None:
                try:
                    self._overflow_spool.append(event)
                except AuditSpoolFullError as exc:
                    self._degraded = True
                    return EmitResult(
                        accepted=False,
                        degraded=True,
                        reason=exc.__class__.__name__,
                    )
                self._degraded = True
                return EmitResult(accepted=True, spooled=True, durable=True, degraded=True)
            self._degraded = True
            return EmitResult(accepted=False, degraded=True, reason="queue_full")

    async def flush(self) -> None:
        await self._queue.join()

    def can_durably_accept_now(self) -> bool:
        return self._overflow_spool is not None

    @property
    def degraded(self) -> bool:
        return self._degraded

    async def _run(self) -> None:
        while True:
            event = await self._queue.get()
            try:
                await self._producer.produce(event)
                self._degraded = False
            except Exception:
                if self._overflow_spool is not None:
                    try:
                        self._overflow_spool.append(event)
                    except AuditSpoolFullError:
                        logger.critical("audit_spool_full")
                    finally:
                        self._degraded = True
                else:
                    self._degraded = True
            finally:
                self._queue.task_done()


class DiskSpoolAuditEmitter:
    """Durable local audit emitter for strict-mode local development deployments."""

    def __init__(self, spool: DiskSpool) -> None:
        self._spool = spool

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        try:
            self._spool.append(event)
        except AuditSpoolFullError as exc:
            return EmitResult(accepted=False, degraded=True, reason=exc.__class__.__name__)
        return EmitResult(accepted=True, spooled=True, durable=True)

    def can_durably_accept_now(self) -> bool:
        if self._spool.max_bytes is None:
            return True
        current_size = self._spool.path.stat().st_size if self._spool.path.exists() else 0
        return current_size < self._spool.max_bytes
