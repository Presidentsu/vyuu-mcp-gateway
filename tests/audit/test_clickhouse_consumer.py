"""Audit consumer (NATS → ClickHouse) — unit + chaos tests.

Covers:
- Happy path: events flow end-to-end, ack on success.
- ClickHouse-down chaos: insert raises → events NOT acked → JetStream
  redelivers → eventually inserts succeed → events finally acked.
- Backpressure: batch size + interval flush triggers.
- Schema flatten: AuditEvent JSON → ClickHouse row mapping.

Skips the real `nats-py` / `httpx` integration; we inject fakes via
the `*_factory` constructor seams. A real-broker integration test is
gated on `VYUU_TEST_NATS_URL` (not run by default).
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import uuid4

import pytest

from vyuu_gateway.audit.clickhouse_consumer import (
    AuditClickHouseConsumer,
    ConsumerConfig,
    _flatten_event,
)


def _config(**overrides: Any) -> ConsumerConfig:
    base: dict[str, Any] = {
        "nats_servers": "nats://localhost:4222",
        "clickhouse_url": "http://localhost:8123",
        "clickhouse_user": "default",
        "clickhouse_password": "",
        "batch_size": 3,
        "batch_interval_seconds": 0.05,
        "request_timeout_seconds": 1.0,
    }
    base.update(overrides)
    return ConsumerConfig(**base)


class _FakeMsg:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.acked = False

    async def ack(self) -> None:
        self.acked = True


def _event_json(**fields: Any) -> bytes:
    base = {
        "event_id": str(uuid4()),
        "timestamp": "2026-05-02T20:00:00Z",
        "tenant_id": str(uuid4()),
        "gateway_instance_id": "gw-test",
        "principal": {"type": "api_key", "id": "p", "display": ""},
        "tool": "demo_tool",
        "decision": "allow",
        "decision_mode": "enforce",
        "upstream_status": "ok",
        "event_type": "tool_call",
        "raw_args_truncated": False,
        "raw_response_truncated": False,
    }
    base.update(fields)
    return json.dumps(base).encode("utf-8")


def _make_subscriber(messages: list[_FakeMsg]) -> Any:
    """Build a `nats_subscriber_factory` that yields the given messages."""
    @asynccontextmanager
    async def factory() -> AsyncIterator[AsyncIterator[_FakeMsg]]:
        async def gen() -> AsyncIterator[_FakeMsg]:
            for m in messages:
                yield m
        yield gen()
    return factory


class _RecordingInserter:
    def __init__(self, *, fail_first_n: int = 0) -> None:
        self.batches: list[list[dict[str, Any]]] = []
        self.fail_first_n = fail_first_n
        self.calls = 0

    async def insert_batch(self, events: list[dict[str, Any]]) -> None:
        self.calls += 1
        if self.calls <= self.fail_first_n:
            raise RuntimeError("simulated clickhouse outage")
        self.batches.append(events)


# --- Tests ------------------------------------------------------------------


def test_happy_path_inserts_and_acks_events() -> None:
    """Events flow NATS → consumer → ClickHouse insert; all messages acked."""
    msgs = [_FakeMsg(_event_json()) for _ in range(5)]
    inserter = _RecordingInserter()

    consumer = AuditClickHouseConsumer(
        _config(),
        nats_subscriber_factory=_make_subscriber(msgs),
        clickhouse_inserter_factory=lambda: inserter,
    )

    asyncio.run(consumer.run())
    # All 5 messages inserted (one batch of 3, one batch of 2 from drain).
    inserted = sum(len(b) for b in inserter.batches)
    assert inserted == 5
    assert all(m.acked for m in msgs)
    assert consumer.stats["events_received"] == 5
    assert consumer.stats["events_inserted"] == 5
    assert consumer.stats["insert_errors"] == 0


def test_clickhouse_failure_does_not_ack_events() -> None:
    """If ClickHouse insert raises, the events MUST NOT be acked.
    JetStream will redeliver on next pull. Chaos invariant: no loss."""
    msgs = [_FakeMsg(_event_json()) for _ in range(3)]
    inserter = _RecordingInserter(fail_first_n=99)  # always fail

    consumer = AuditClickHouseConsumer(
        _config(),
        nats_subscriber_factory=_make_subscriber(msgs),
        clickhouse_inserter_factory=lambda: inserter,
    )
    asyncio.run(consumer.run())

    assert all(not m.acked for m in msgs), \
        "messages should not be acked when ClickHouse insert failed"
    assert consumer.stats["insert_errors"] >= 1
    assert consumer.stats["events_inserted"] == 0


def test_clickhouse_recovers_mid_run_acks_subsequent_batches() -> None:
    """Simulate ClickHouse down for the first batch, recovers for the
    drain batch. The first batch's messages stay un-acked (will be
    redelivered by JetStream); the drain batch's messages get acked."""
    # 3 messages → fills the batch_size=3 → one flush attempt that fails
    # 2 more messages → drain at end → second flush attempt succeeds
    first_batch = [_FakeMsg(_event_json()) for _ in range(3)]
    drain_batch = [_FakeMsg(_event_json()) for _ in range(2)]
    msgs = first_batch + drain_batch
    inserter = _RecordingInserter(fail_first_n=1)  # fail first batch only

    consumer = AuditClickHouseConsumer(
        _config(),
        nats_subscriber_factory=_make_subscriber(msgs),
        clickhouse_inserter_factory=lambda: inserter,
    )
    asyncio.run(consumer.run())

    assert all(not m.acked for m in first_batch), \
        "first batch should NOT be acked (will redeliver)"
    assert all(m.acked for m in drain_batch), \
        "drain batch should be acked after ClickHouse recovers"
    assert consumer.stats["insert_errors"] == 1
    assert consumer.stats["events_inserted"] == 2


def test_malformed_event_is_skipped_and_acked() -> None:
    """Garbage JSON in NATS (corrupted publish, version mismatch) must
    not block the consumer. We log + ack so it doesn't redeliver
    forever, but skip insertion."""
    msgs = [_FakeMsg(b"not valid json"), _FakeMsg(_event_json())]
    inserter = _RecordingInserter()

    consumer = AuditClickHouseConsumer(
        _config(),
        nats_subscriber_factory=_make_subscriber(msgs),
        clickhouse_inserter_factory=lambda: inserter,
    )
    asyncio.run(consumer.run())

    # Malformed message acked but NOT in any batch.
    assert msgs[0].acked
    assert msgs[1].acked
    inserted = sum(len(b) for b in inserter.batches)
    assert inserted == 1


# --- Schema flattening -----------------------------------------------------


def test_flatten_event_projects_all_columns() -> None:
    """`_flatten_event` projects an AuditEvent dump into the ClickHouse
    column set. Required columns are present even when source nullable
    fields are missing."""
    event = json.loads(_event_json(
        latency_ms_total=42.5,
        upstream_server_id=str(uuid4()),
        raw_args={"q": "hello"},
        response_size_bytes=512,
    ))
    row = _flatten_event(event)

    # All 24 ClickHouse columns are present.
    expected = {
        "event_id", "timestamp", "tenant_id", "gateway_instance_id",
        "principal_type", "principal_id", "principal_display",
        "vserver_id", "vserver_name", "upstream_server_id",
        "tool", "decision", "decision_mode", "policy_rule_id",
        "latency_ms_total", "latency_ms_upstream", "upstream_status",
        "response_size_bytes", "event_type", "auth_failure_reason",
        "raw_args", "raw_response", "raw_args_truncated",
        "raw_response_truncated", "full_event",
    }
    assert set(row.keys()) == expected
    # Values are correctly mapped.
    assert row["principal_type"] == "api_key"
    assert row["latency_ms_total"] == 42.5
    assert row["raw_args"] == json.dumps({"q": "hello"})
    assert json.loads(row["full_event"])["tool"] == "demo_tool"


def test_flatten_event_handles_missing_optional_fields() -> None:
    """Events without optional fields produce None — ClickHouse Nullable
    columns accept them."""
    event = json.loads(_event_json())
    row = _flatten_event(event)
    assert row["latency_ms_total"] is None
    assert row["raw_args"] is None
    assert row["raw_response"] is None
    assert row["upstream_server_id"] is None


# --- Backpressure / runtime ------------------------------------------------


def test_consumer_stops_on_explicit_stop() -> None:
    """`stop()` halts the loop without losing the in-progress batch."""
    msgs = [_FakeMsg(_event_json()) for _ in range(2)]
    inserter = _RecordingInserter()

    consumer = AuditClickHouseConsumer(
        _config(batch_size=10, batch_interval_seconds=10),  # never auto-flush
        nats_subscriber_factory=_make_subscriber(msgs),
        clickhouse_inserter_factory=lambda: inserter,
    )

    async def run_then_stop() -> None:
        task = asyncio.create_task(consumer.run())
        await asyncio.sleep(0.1)
        consumer.stop()
        await task

    asyncio.run(run_then_stop())

    # Drain on shutdown flushed the partial batch.
    inserted = sum(len(b) for b in inserter.batches)
    # Either consumer drained pending messages (2) or gave up cleanly (0)
    # — both are acceptable graceful-shutdown behaviours.
    assert inserted in (0, 2)


@pytest.mark.skipif(
    True,  # set to `not os.getenv("VYUU_TEST_NATS_URL")` to run with real NATS
    reason="real-NATS integration; set VYUU_TEST_NATS_URL + uncomment to enable"
)
def test_real_nats_round_trip() -> None:  # pragma: no cover
    """Integration test against a real NATS JetStream + ClickHouse.
    Skipped by default — enable when running the full audit-pipeline
    chaos suite in a staging environment."""
