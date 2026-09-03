import asyncio
from pathlib import Path
from uuid import uuid4

from vyuu_gateway.audit.emitter import AsyncAuditEmitter, DiskSpoolAuditEmitter
from vyuu_gateway.audit.events import (
    AuditDecision,
    AuditEvent,
    AuditPrincipal,
    AuditPrincipalType,
    create_tool_call_audit_event,
)
from vyuu_gateway.audit.producer import AuditProducer, TestAuditProducer
from vyuu_gateway.audit.spool import AuditSpoolFullError, DiskSpool


class FailingAuditProducer(AuditProducer):
    async def produce(self, event: AuditEvent) -> None:
        raise RuntimeError("producer unavailable")


def make_event(tool: str = "query") -> AuditEvent:
    return create_tool_call_audit_event(
        tenant_id=uuid4(),
        gateway_instance_id="gateway-1",
        principal=AuditPrincipal(type=AuditPrincipalType.API_KEY, id="key-1"),
        tool=tool,
        arguments={"sql": "select 1"},
        decision=AuditDecision.ALLOW,
    )


def test_audit_producer_down_spools_failed_events(tmp_path: Path) -> None:
    async def run() -> None:
        spool = DiskSpool(tmp_path / "producer-down.jsonl")
        emitter = AsyncAuditEmitter(FailingAuditProducer(), overflow_spool=spool)
        await emitter.start()

        result = emitter.emit_nowait(make_event())
        await emitter.flush()
        await emitter.stop()

        assert result.accepted
        assert emitter.degraded
        assert [event.tool for event in spool.read_events()] == ["query"]

    asyncio.run(run())


def test_disk_spool_available_returns_durable_emit_result(tmp_path: Path) -> None:
    spool = DiskSpool(tmp_path / "strict-spool.jsonl")
    emitter = DiskSpoolAuditEmitter(spool)

    result = emitter.emit_nowait(make_event())

    assert result.accepted
    assert result.durable
    assert result.spooled
    assert [event.tool for event in spool.read_events()] == ["query"]


def test_disk_spool_full_rejects_events(tmp_path: Path) -> None:
    spool = DiskSpool(tmp_path / "full.jsonl", max_bytes=0)
    emitter = DiskSpoolAuditEmitter(spool)

    result = emitter.emit_nowait(make_event())

    assert not result.accepted
    assert result.degraded
    assert result.reason == "AuditSpoolFullError"
    assert spool.read_events() == []


def test_disk_spool_raises_when_full(tmp_path: Path) -> None:
    spool = DiskSpool(tmp_path / "full-direct.jsonl", max_bytes=0)

    try:
        spool.append(make_event())
    except AuditSpoolFullError:
        pass
    else:
        raise AssertionError("expected full spool to reject append")


def test_recovery_replays_spooled_events_and_clears_spool(tmp_path: Path) -> None:
    async def run() -> None:
        spool = DiskSpool(tmp_path / "replay.jsonl")
        spool.append(make_event("first"))
        spool.append(make_event("second"))
        producer = TestAuditProducer()

        replayed = await spool.replay_to(producer)

        assert replayed == 2
        assert [event.tool for event in producer.events] == ["first", "second"]
        assert spool.read_events() == []

    asyncio.run(run())
