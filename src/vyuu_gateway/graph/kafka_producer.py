"""Kafka-backed graph event producer.

Mirrors `audit.kafka_producer.KafkaAuditProducer`. Lazy-imports `aiokafka`
so the base install stays light. See that module's docstring for the
wire-format rationale; the only differences here are:

- Topic defaults to `vyuu.graph.events` so audit + graph live on
  separate topics with separate retention / consumer groups.
- Event body is `GraphEvent.model_dump_json(...)`.
- Routing headers carry `event_id`, `correlation_id`, `tenant_id`. The
  `correlation_id` is the most useful here — joins to the audit event
  for the same tool call.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from vyuu_gateway.graph.events import GraphEvent

if TYPE_CHECKING:
    from aiokafka import AIOKafkaProducer  # pragma: no cover


class KafkaGraphProducer:
    """Durable graph event producer backed by an `AIOKafkaProducer`."""

    def __init__(
        self,
        *,
        bootstrap_servers: str,
        topic: str = "vyuu.graph.events",
        client_id: str = "vyuu-gateway",
        acks: str | int = "all",
        producer: Any | None = None,
    ) -> None:
        self._bootstrap_servers = bootstrap_servers
        self._topic = topic
        self._client_id = client_id
        self._acks = acks
        self._producer: AIOKafkaProducer | Any | None = producer
        self._owns_producer = producer is None
        self._started = False

    async def start(self) -> None:
        if self._started:
            return
        if self._producer is None:
            try:
                from aiokafka import AIOKafkaProducer
            except ImportError as exc:  # pragma: no cover - exercised manually
                raise ImportError(
                    "KafkaGraphProducer requires the `kafka` extra: "
                    "`pip install vyuu-mcp-gateway[kafka]`"
                ) from exc
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap_servers,
                client_id=self._client_id,
                acks=self._acks,
                enable_idempotence=True,
            )
        if self._owns_producer:
            await self._producer.start()
        self._started = True

    async def stop(self) -> None:
        if not self._started:
            return
        if self._owns_producer and self._producer is not None:
            await self._producer.stop()
        self._started = False

    async def aclose(self) -> None:
        await self.stop()

    async def produce(self, event: GraphEvent) -> None:
        if not self._started:
            await self.start()
        assert self._producer is not None
        payload = event.model_dump_json(exclude_none=True).encode("utf-8")
        key = str(event.tenant_id).encode("utf-8")
        headers = [
            ("event_id", str(event.event_id).encode("utf-8")),
            ("correlation_id", str(event.correlation_id).encode("utf-8")),
            ("tenant_id", key),
        ]
        await self._producer.send_and_wait(
            self._topic,
            value=payload,
            key=key,
            headers=headers,
        )
