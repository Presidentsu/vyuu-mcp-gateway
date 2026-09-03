"""Kafka-backed durable audit producer.

Implements the `AuditProducer` Protocol for `AsyncAuditEmitter`. Hot path
is unchanged — the emitter queues and a single worker awaits `produce()`.
This module only handles the broker round-trip.

Lazy-imports `aiokafka` so the base gateway install doesn't pull it.
Operators who deploy Kafka install via `pip install
vyuu-mcp-gateway[kafka]`.

Wire format
-----------
- **Topic** (default `vyuu.audit.events`): single topic for all tenants.
  Lets a single Kafka consumer fan out to per-tenant SIEMs based on the
  message key. Operators can override per deployment.
- **Key**: tenant_id as UTF-8 bytes — guarantees per-tenant ordering on
  the same partition.
- **Value**: `AuditEvent.model_dump_json(...)` — a single line of JSON,
  schema-versioned via `event.event_version`.
- **Headers**: `event_id`, `decision` (allow / deny / etc.), `tenant_id`
  (mirror of key for consumers that route by header without parsing
  the body).

Acknowledgement
---------------
Defaults to `acks='all'` so the producer waits for all in-sync replicas
before considering the message durable. The `produce()` await returns
only after the broker has confirmed. If the broker is unreachable, the
underlying client raises and `AsyncAuditEmitter` falls back to the disk
spool — the existing failure-mode contract.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from vyuu_gateway.audit.events import AuditEvent

if TYPE_CHECKING:
    from aiokafka import AIOKafkaProducer  # pragma: no cover


class KafkaAuditProducer:
    """Durable audit producer backed by an `AIOKafkaProducer`."""

    def __init__(
        self,
        *,
        bootstrap_servers: str,
        topic: str = "vyuu.audit.events",
        client_id: str = "vyuu-gateway",
        acks: str | int = "all",
        producer: Any | None = None,
    ) -> None:
        """Build a Kafka audit producer.

        `producer` is an injection seam for unit tests — pass a fake/mock
        with the same `start()` / `stop()` / `send_and_wait()` shape and
        the real `aiokafka` import is never touched.
        """

        self._bootstrap_servers = bootstrap_servers
        self._topic = topic
        self._client_id = client_id
        self._acks = acks
        self._producer: AIOKafkaProducer | Any | None = producer
        self._owns_producer = producer is None
        self._started = False

    async def start(self) -> None:
        """Lazily construct + start the underlying client.

        Called from the gateway lifespan startup; safe to call again
        idempotently. Raises a clear ImportError if the optional
        `aiokafka` dependency isn't installed.
        """

        if self._started:
            return
        if self._producer is None:
            try:
                from aiokafka import AIOKafkaProducer
            except ImportError as exc:  # pragma: no cover - exercised manually
                raise ImportError(
                    "KafkaAuditProducer requires the `kafka` extra: "
                    "`pip install vyuu-mcp-gateway[kafka]`"
                ) from exc
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap_servers,
                client_id=self._client_id,
                acks=self._acks,
                # JSON values, no compression by default — operators
                # opt in via a separate Settings extension later.
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
        """Lifespan integration — `_close_if_supported` calls aclose."""

        await self.stop()

    async def produce(self, event: AuditEvent) -> None:
        """Publish one event. Blocks until the broker acks (acks=all)."""

        if not self._started:
            await self.start()
        assert self._producer is not None
        payload = event.model_dump_json(exclude_none=True).encode("utf-8")
        key = str(event.tenant_id).encode("utf-8")
        headers = [
            ("event_id", str(event.event_id).encode("utf-8")),
            ("decision", event.decision.value.encode("utf-8")),
            ("tenant_id", key),
        ]
        await self._producer.send_and_wait(
            self._topic,
            value=payload,
            key=key,
            headers=headers,
        )
