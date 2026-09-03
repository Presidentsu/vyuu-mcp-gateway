"""Unit tests for the Kafka durable audit producer.

These tests inject a fake `aiokafka`-shaped client so they don't need a
real broker. The integration test that runs against a real cluster lives
behind `VYUU_TEST_KAFKA_BOOTSTRAP_SERVERS` and is skipped by default.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import uuid4

import pytest

from vyuu_gateway.audit.events import (
    AuditDecision,
    AuditDecisionMode,
    AuditPrincipal,
    AuditPrincipalType,
    UpstreamStatus,
    create_tool_call_audit_event,
)
from vyuu_gateway.audit.kafka_producer import KafkaAuditProducer


class _FakeKafkaProducer:
    """Stand-in for `aiokafka.AIOKafkaProducer` exposing only the methods
    `KafkaAuditProducer` calls. Records sent messages so tests can assert
    topic / key / value / headers without a real broker."""

    def __init__(self, *, raise_on_send: BaseException | None = None) -> None:
        self.started = False
        self.stopped = False
        self.sent: list[dict[str, Any]] = []
        self._raise_on_send = raise_on_send

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    async def send_and_wait(
        self,
        topic: str,
        *,
        value: bytes,
        key: bytes,
        headers: list[tuple[str, bytes]],
    ) -> None:
        if self._raise_on_send is not None:
            raise self._raise_on_send
        self.sent.append(
            {"topic": topic, "value": value, "key": key, "headers": headers}
        )


def _event() -> Any:
    return create_tool_call_audit_event(
        tenant_id=uuid4(),
        gateway_instance_id="gw-1",
        principal=AuditPrincipal(type=AuditPrincipalType.API_KEY, id="api-1"),
        tool="query",
        arguments={"sql": "select 1"},
        decision=AuditDecision.ALLOW,
        decision_mode=AuditDecisionMode.ENFORCE,
        upstream_status=UpstreamStatus.OK,
    )


def test_produce_writes_event_with_tenant_keyed_message() -> None:
    """The wire format must put tenant_id on the Kafka message *key* so
    consumers get per-tenant ordering on the same partition. Random
    partitioning would let a tenant's events arrive out of order."""

    fake = _FakeKafkaProducer()
    producer = KafkaAuditProducer(
        bootstrap_servers="localhost:9092",
        topic="vyuu.audit.events",
        producer=fake,
    )
    event = _event()

    asyncio.run(producer.produce(event))

    assert len(fake.sent) == 1
    sent = fake.sent[0]
    assert sent["topic"] == "vyuu.audit.events"
    assert sent["key"] == str(event.tenant_id).encode("utf-8")
    body = json.loads(sent["value"].decode("utf-8"))
    assert body["event_id"] == str(event.event_id)
    assert body["tenant_id"] == str(event.tenant_id)
    assert body["decision"] == "allow"


def test_produce_attaches_routing_headers() -> None:
    """Headers let consumers route without parsing the JSON body."""

    fake = _FakeKafkaProducer()
    producer = KafkaAuditProducer(bootstrap_servers="localhost:9092", producer=fake)
    event = _event()

    asyncio.run(producer.produce(event))

    headers = dict(fake.sent[0]["headers"])
    assert headers["event_id"] == str(event.event_id).encode("utf-8")
    assert headers["decision"] == b"allow"
    assert headers["tenant_id"] == str(event.tenant_id).encode("utf-8")


def test_produce_starts_producer_lazily_on_first_call() -> None:
    """Lifecycle: `start()` may not have been called explicitly. The
    first `produce()` should initialize the underlying client."""

    fake = _FakeKafkaProducer()
    producer = KafkaAuditProducer(bootstrap_servers="localhost:9092", producer=fake)
    event = _event()

    # Caller-injected producer: gateway does NOT call `start()` on it
    # (that's the caller's responsibility — they own the lifecycle).
    asyncio.run(producer.produce(event))
    assert fake.started is False  # caller-injected — we don't manage it
    assert len(fake.sent) == 1


def test_produce_propagates_broker_errors_to_caller() -> None:
    """Broker failures must propagate so `AsyncAuditEmitter` can fall
    back to the disk spool. Swallowing here would silently drop audit
    events — exactly the behavior `AsyncAuditEmitter._run` is designed
    to catch with `except Exception:` + spool fallback."""

    fake = _FakeKafkaProducer(raise_on_send=ConnectionError("broker down"))
    producer = KafkaAuditProducer(bootstrap_servers="localhost:9092", producer=fake)

    with pytest.raises(ConnectionError, match="broker down"):
        asyncio.run(producer.produce(_event()))


def test_aclose_stops_owned_producer() -> None:
    """When the producer wasn't injected, the gateway must own the
    lifecycle and stop the underlying client on shutdown."""

    fake = _FakeKafkaProducer()
    producer = KafkaAuditProducer(bootstrap_servers="localhost:9092")
    # Bypass real `aiokafka` import — pretend we built it.
    producer._producer = fake  # noqa: SLF001
    producer._owns_producer = True  # noqa: SLF001
    producer._started = True  # noqa: SLF001

    asyncio.run(producer.aclose())

    assert fake.stopped is True
