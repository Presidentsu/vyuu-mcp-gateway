"""Unit tests for `AsyncGraphEventEmitter` and the Kafka / NATS graph producers.

The audit emitter has analogous tests under `tests/audit/`. These exercise
the parallel pieces — async queue + worker, drop-on-producer-failure
behavior, and the per-broker wire format.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any
from uuid import uuid4

import pytest

from vyuu_gateway.graph.emitter import AsyncGraphEventEmitter
from vyuu_gateway.graph.events import (
    GraphEdge,
    GraphEdgeType,
    GraphEvent,
    GraphNode,
    GraphNodeType,
)
from vyuu_gateway.graph.kafka_producer import KafkaGraphProducer
from vyuu_gateway.graph.nats_producer import NatsGraphProducer


def _event() -> GraphEvent:
    return GraphEvent(
        tenant_id=uuid4(),
        correlation_id=uuid4(),
        edges=(
            GraphEdge(
                type=GraphEdgeType.PRINCIPAL_CALLED_TOOL,
                source=GraphNode(type=GraphNodeType.PRINCIPAL, id="api-key-1"),
                target=GraphNode(type=GraphNodeType.TOOL, id="query"),
            ),
        ),
    )


# --- AsyncGraphEventEmitter ------------------------------------------------


class _RecordingProducer:
    """In-memory producer with optional fault injection."""

    def __init__(self, *, raise_for_first_n: int = 0) -> None:
        self.events: list[GraphEvent] = []
        self._raise_for = raise_for_first_n
        self._call_count = 0

    async def produce(self, event: GraphEvent) -> None:
        self._call_count += 1
        if self._call_count <= self._raise_for:
            raise ConnectionError("simulated broker failure")
        self.events.append(event)


def test_async_emitter_drains_queue_to_producer() -> None:
    """Hot-path `emit_nowait` puts on a queue; worker drains to producer.
    The lifecycle never awaits this; the emit is non-blocking."""

    async def run() -> None:
        producer = _RecordingProducer()
        emitter = AsyncGraphEventEmitter(producer)
        await emitter.start()

        event = _event()
        emitter.emit_nowait(event)
        await emitter.flush()

        assert producer.events == [event]
        assert emitter.degraded is False
        await emitter.stop()

    asyncio.run(run())


def test_async_emitter_marks_degraded_on_producer_failure_and_drops() -> None:
    """Unlike audit, graph events are NOT spooled on producer failure —
    they're recoverable from the audit log via the same correlation_id.
    Worker must mark degraded and continue, not crash."""

    async def run() -> None:
        producer = _RecordingProducer(raise_for_first_n=1)
        emitter = AsyncGraphEventEmitter(producer)
        await emitter.start()

        emitter.emit_nowait(_event())  # this one will fail
        emitter.emit_nowait(_event())  # this one should succeed
        await emitter.flush()

        assert len(producer.events) == 1  # first dropped on broker failure
        # The next successful produce flips degraded back to False.
        assert emitter.degraded is False
        await emitter.stop()

    asyncio.run(run())


def test_async_emitter_drops_on_full_queue_and_flags_degraded() -> None:
    """Backpressure: if the queue fills (worker can't keep up), drop +
    flag. Graph events are best-effort; we never block the request hot
    path waiting for queue space."""

    async def run() -> None:
        # Slow producer + tiny queue → forced overflow.
        async def slow_produce(_event: GraphEvent) -> None:
            await asyncio.sleep(0.5)

        producer = type("Slow", (), {"produce": staticmethod(slow_produce)})()
        emitter = AsyncGraphEventEmitter(producer, max_queue_size=1)
        await emitter.start()

        # Fill the queue: one in flight (worker processing), one queued,
        # one drops.
        emitter.emit_nowait(_event())
        emitter.emit_nowait(_event())
        emitter.emit_nowait(_event())  # should drop
        emitter.emit_nowait(_event())  # should drop

        assert emitter.dropped_count >= 1
        assert emitter.degraded is True
        # Don't flush — the slow producer would block the test.
        if emitter._worker is not None:  # noqa: SLF001
            emitter._worker.cancel()  # noqa: SLF001

    asyncio.run(run())


# --- KafkaGraphProducer ----------------------------------------------------


class _FakeKafka:
    def __init__(self, *, raise_on_send: BaseException | None = None) -> None:
        self.sent: list[dict[str, Any]] = []
        self._raise_on_send = raise_on_send

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def send_and_wait(
        self,
        topic: str,
        *,
        value: bytes,
        key: bytes,
        headers: list[tuple[str, bytes]],
    ) -> None:
        if self._raise_on_send:
            raise self._raise_on_send
        self.sent.append({"topic": topic, "value": value, "key": key, "headers": headers})


def test_kafka_graph_producer_emits_correlation_id_header() -> None:
    """Graph consumers join with audit via `correlation_id` — must be
    a header so consumers don't have to parse the body."""

    fake = _FakeKafka()
    producer = KafkaGraphProducer(bootstrap_servers="localhost:9092", producer=fake)
    event = _event()

    asyncio.run(producer.produce(event))

    headers = dict(fake.sent[0]["headers"])
    assert headers["correlation_id"] == str(event.correlation_id).encode("utf-8")
    assert headers["tenant_id"] == str(event.tenant_id).encode("utf-8")


def test_kafka_graph_producer_uses_separate_topic_from_audit() -> None:
    """Audit and graph default to different topics so consumers can
    have separate retention / consumer groups / SLAs."""

    fake = _FakeKafka()
    producer = KafkaGraphProducer(bootstrap_servers="localhost:9092", producer=fake)
    asyncio.run(producer.produce(_event()))

    assert fake.sent[0]["topic"] == "vyuu.graph.events"


def test_kafka_graph_producer_propagates_broker_errors() -> None:
    fake = _FakeKafka(raise_on_send=ConnectionError("broker down"))
    producer = KafkaGraphProducer(bootstrap_servers="localhost:9092", producer=fake)

    with pytest.raises(ConnectionError, match="broker down"):
        asyncio.run(producer.produce(_event()))


# --- NatsGraphProducer -----------------------------------------------------


class _FakeJetStream:
    def __init__(self, *, raise_on_publish: BaseException | None = None) -> None:
        self.published: list[dict[str, Any]] = []
        self._raise = raise_on_publish

    async def publish(
        self,
        subject: str,
        *,
        payload: bytes,
        headers: dict[str, str],
    ) -> None:
        if self._raise:
            raise self._raise
        self.published.append({"subject": subject, "payload": payload, "headers": headers})


def test_nats_graph_producer_emits_to_per_tenant_subject() -> None:
    js = _FakeJetStream()
    producer = NatsGraphProducer(
        servers="nats://localhost:4222",
        connection=object(),
        jetstream=js,
    )
    event = _event()

    asyncio.run(producer.produce(event))

    assert js.published[0]["subject"] == f"vyuu.graph.events.{event.tenant_id}"
    headers = js.published[0]["headers"]
    assert headers["Vyuu-Correlation-Id"] == str(event.correlation_id)
    body = json.loads(js.published[0]["payload"].decode("utf-8"))
    assert body["correlation_id"] == str(event.correlation_id)


def test_nats_graph_producer_propagates_broker_errors() -> None:
    js = _FakeJetStream(raise_on_publish=ConnectionError("nats unreachable"))
    producer = NatsGraphProducer(
        servers="nats://localhost:4222",
        connection=object(),
        jetstream=js,
    )

    with pytest.raises(ConnectionError):
        asyncio.run(producer.produce(_event()))


# --- Integration test gated on real NATS -----------------------------------


_NATS_URL = os.environ.get("VYUU_TEST_NATS_URL")


@pytest.mark.skipif(
    _NATS_URL is None,
    reason="VYUU_TEST_NATS_URL not set; skipping real-NATS graph integration test",
)
def test_real_nats_graph_round_trip() -> None:
    """End-to-end: NatsGraphProducer publishes to a real JetStream stream;
    we consume back and assert the wire format includes the correlation_id
    header (which is the durable join key with the audit pipeline)."""

    import nats
    from nats.js.api import StreamConfig

    assert _NATS_URL is not None
    nats_url: str = _NATS_URL

    async def run() -> None:
        nc = await nats.connect(servers=nats_url)
        js = nc.jetstream()
        stream_name = f"vyuu_graph_test_{uuid4().hex[:8]}"
        try:
            await js.add_stream(
                StreamConfig(
                    name=stream_name,
                    subjects=[f"vyuu.graph.test.{stream_name}.>"],
                )
            )
            producer = NatsGraphProducer(
                servers=nats_url,
                subject_prefix=f"vyuu.graph.test.{stream_name}",
                connection=nc,
                jetstream=js,
            )
            event = _event()
            await producer.produce(event)

            psub = await js.pull_subscribe(
                f"vyuu.graph.test.{stream_name}.{event.tenant_id}",
                durable="vyuu-graph-test",
            )
            msgs = await psub.fetch(1, timeout=5)
            assert len(msgs) == 1
            received_headers = msgs[0].headers
            assert received_headers is not None
            assert received_headers["Vyuu-Correlation-Id"] == str(event.correlation_id)
            body = json.loads(msgs[0].data.decode("utf-8"))
            assert body["correlation_id"] == str(event.correlation_id)
            await msgs[0].ack()
        finally:
            try:
                await js.delete_stream(stream_name)
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
            await nc.drain()

    asyncio.run(run())
