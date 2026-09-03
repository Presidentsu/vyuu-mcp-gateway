import asyncio
from pathlib import Path
from uuid import uuid4

from vyuu_gateway.audit.emitter import AsyncAuditEmitter
from vyuu_gateway.audit.events import (
    AuditDecision,
    AuditEvent,
    AuditPrincipal,
    AuditPrincipalType,
    create_tool_call_audit_event,
)
from vyuu_gateway.audit.producer import AuditProducer, TestAuditProducer
from vyuu_gateway.audit.spool import DiskSpool, SpoolingAuditProducer


class FailingAuditProducer(AuditProducer):
    async def produce(self, event: AuditEvent) -> None:
        raise RuntimeError("producer unavailable")


class BlockingAuditProducer(AuditProducer):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def produce(self, event: AuditEvent) -> None:
        self.started.set()
        await self.release.wait()


def make_event(tool: str = "query") -> AuditEvent:
    return create_tool_call_audit_event(
        tenant_id=uuid4(),
        gateway_instance_id="gateway-1",
        principal=AuditPrincipal(type=AuditPrincipalType.API_KEY, id="key-1"),
        tool=tool,
        arguments={"sql": "select 1"},
        decision=AuditDecision.ALLOW,
    )


def test_async_audit_emitter_delivers_events_to_test_producer() -> None:
    async def run() -> None:
        producer = TestAuditProducer()
        emitter = AsyncAuditEmitter(producer)
        await emitter.start()

        result = emitter.emit_nowait(make_event())
        await emitter.flush()
        await emitter.stop()

        assert result.accepted
        assert len(producer.events) == 1
        assert producer.events[0].tool == "query"

    asyncio.run(run())


def test_emit_nowait_does_not_wait_for_blocked_producer() -> None:
    async def run() -> None:
        producer = BlockingAuditProducer()
        emitter = AsyncAuditEmitter(producer)
        await emitter.start()

        result = emitter.emit_nowait(make_event())
        await asyncio.wait_for(producer.started.wait(), timeout=1)

        assert result.accepted
        producer.release.set()
        await emitter.flush()
        await emitter.stop()

    asyncio.run(run())


def test_spooling_producer_writes_failed_events_to_disk(tmp_path: Path) -> None:
    async def run() -> None:
        spool = DiskSpool(tmp_path / "audit-spool.jsonl")
        producer = SpoolingAuditProducer(FailingAuditProducer(), spool)

        await producer.produce(make_event())

        spooled_events = spool.read_events()
        assert len(spooled_events) == 1
        assert spooled_events[0].tool == "query"

    asyncio.run(run())


def test_emitter_spools_when_queue_is_full(tmp_path: Path) -> None:
    async def run() -> None:
        producer = BlockingAuditProducer()
        spool = DiskSpool(tmp_path / "overflow.jsonl")
        emitter = AsyncAuditEmitter(producer, max_queue_size=1, overflow_spool=spool)

        first = emitter.emit_nowait(make_event("first"))
        second = emitter.emit_nowait(make_event("second"))

        assert first.accepted
        assert second.accepted
        assert second.spooled
        assert [event.tool for event in spool.read_events()] == ["second"]

    asyncio.run(run())


def test_emitter_spools_producer_failures_without_stopping_worker(tmp_path: Path) -> None:
    async def run() -> None:
        producer = FailingAuditProducer()
        spool = DiskSpool(tmp_path / "producer-failures.jsonl")
        emitter = AsyncAuditEmitter(producer, overflow_spool=spool)
        await emitter.start()

        first = emitter.emit_nowait(make_event("first"))
        second = emitter.emit_nowait(make_event("second"))
        await emitter.flush()
        await emitter.stop()

        assert first.accepted
        assert second.accepted
        assert [event.tool for event in spool.read_events()] == ["first", "second"]

    asyncio.run(run())
