"""Unit tests for the NATS JetStream durable audit producer.

Unit tests use an injected fake JetStream context. The integration test
that runs against a real `nats-server` lives behind `VYUU_TEST_NATS_URL`
and is skipped when the env var is not set.
"""

from __future__ import annotations

import asyncio
import json
import os
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
from vyuu_gateway.audit.nats_producer import NatsAuditProducer


class _FakeJetStream:
    """Records `publish()` calls so tests can assert subject + payload."""

    def __init__(self, *, raise_on_publish: BaseException | None = None) -> None:
        self.published: list[dict[str, Any]] = []
        self._raise_on_publish = raise_on_publish

    async def publish(
        self,
        subject: str,
        *,
        payload: bytes,
        headers: dict[str, str],
    ) -> None:
        if self._raise_on_publish is not None:
            raise self._raise_on_publish
        self.published.append(
            {"subject": subject, "payload": payload, "headers": headers}
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


def test_produce_publishes_to_per_tenant_subject() -> None:
    """Subject pattern `vyuu.audit.events.<tenant_id>` lets consumers
    subscribe per-tenant or with `vyuu.audit.events.*` for fan-out."""

    js = _FakeJetStream()
    producer = NatsAuditProducer(
        servers="nats://localhost:4222",
        jetstream=js,
        connection=object(),  # bypass real connect
    )
    event = _event()

    asyncio.run(producer.produce(event))

    assert len(js.published) == 1
    msg = js.published[0]
    assert msg["subject"] == f"vyuu.audit.events.{event.tenant_id}"
    body = json.loads(msg["payload"].decode("utf-8"))
    assert body["event_id"] == str(event.event_id)
    assert body["decision"] == "allow"


def test_produce_attaches_routing_headers() -> None:
    js = _FakeJetStream()
    producer = NatsAuditProducer(
        servers="nats://localhost:4222",
        jetstream=js,
        connection=object(),
    )
    event = _event()

    asyncio.run(producer.produce(event))

    headers = js.published[0]["headers"]
    assert headers["Vyuu-Event-Id"] == str(event.event_id)
    assert headers["Vyuu-Decision"] == "allow"
    assert headers["Vyuu-Tenant-Id"] == str(event.tenant_id)


def test_produce_propagates_broker_errors_to_caller() -> None:
    js = _FakeJetStream(raise_on_publish=ConnectionError("nats unreachable"))
    producer = NatsAuditProducer(
        servers="nats://localhost:4222",
        jetstream=js,
        connection=object(),
    )

    with pytest.raises(ConnectionError, match="unreachable"):
        asyncio.run(producer.produce(_event()))


def test_subject_prefix_is_configurable() -> None:
    """Operators with a separate stream per environment use a custom prefix."""

    js = _FakeJetStream()
    producer = NatsAuditProducer(
        servers="nats://localhost:4222",
        subject_prefix="prod.vyuu.audit",
        jetstream=js,
        connection=object(),
    )
    event = _event()

    asyncio.run(producer.produce(event))

    assert js.published[0]["subject"] == f"prod.vyuu.audit.{event.tenant_id}"


# --- Integration test gated on a real NATS server ---------------------------

_NATS_URL = os.environ.get("VYUU_TEST_NATS_URL")


@pytest.mark.skipif(
    _NATS_URL is None,
    reason="VYUU_TEST_NATS_URL not set; skipping real-NATS integration test",
)
def test_real_nats_jetstream_round_trip() -> None:
    """End-to-end against a real `nats-server` with JetStream enabled.

    Requires:
      nats-server -js
      export VYUU_TEST_NATS_URL=nats://127.0.0.1:4222

    The test creates an ephemeral stream, publishes one audit event,
    consumes it back, and asserts the wire format. The stream is torn
    down afterward.
    """

    import nats
    from nats.js.api import StreamConfig

    assert _NATS_URL is not None  # narrowed for mypy after skipif guard
    nats_url: str = _NATS_URL

    async def run() -> None:
        nc = await nats.connect(servers=nats_url)
        js = nc.jetstream()
        stream_name = f"vyuu_audit_test_{uuid4().hex[:8]}"
        try:
            await js.add_stream(
                StreamConfig(
                    name=stream_name,
                    subjects=[f"vyuu.audit.test.{stream_name}.>"],
                )
            )
            producer = NatsAuditProducer(
                servers=nats_url,
                subject_prefix=f"vyuu.audit.test.{stream_name}",
                connection=nc,
                jetstream=js,
            )
            event = _event()
            await producer.produce(event)

            # Pull one message back from the stream.
            psub = await js.pull_subscribe(
                f"vyuu.audit.test.{stream_name}.{event.tenant_id}",
                durable="vyuu-audit-test",
            )
            msgs = await psub.fetch(1, timeout=5)
            assert len(msgs) == 1
            body = json.loads(msgs[0].data.decode("utf-8"))
            assert body["event_id"] == str(event.event_id)
            await msgs[0].ack()
        finally:
            try:
                await js.delete_stream(stream_name)
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
            await nc.drain()

    asyncio.run(run())
