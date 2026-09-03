"""NATS JetStream-backed durable audit producer.

Implements the `AuditProducer` Protocol. Like the Kafka producer, the
gateway's hot-path queue + worker + disk-spool fallback is unchanged —
this module just handles the broker round-trip.

Why JetStream and not core NATS? Core NATS is fire-and-forget — if no
consumer is connected when the message is published, it's gone. Audit
telemetry needs durability, so JetStream is the only sensible choice for
this surface. Operators who want at-most-once for some reason can swap
in a custom `AuditProducer` impl.

Wire format
-----------
- **Subject** (default `vyuu.audit.events.<tenant_id>`): per-tenant
  subject under a shared stream. Lets consumers subscribe with wildcard
  filters (`vyuu.audit.events.*`) or per-tenant precision.
- **Body**: `AuditEvent.model_dump_json(...)` — single line of JSON,
  schema-versioned via `event.event_version`.
- **Headers**: `Vyuu-Event-Id`, `Vyuu-Decision`, `Vyuu-Tenant-Id`
  (consumers can route on these without parsing the body).

The stream itself (storage class, retention policy, replicas) must be
configured outside the gateway — typically via `nats stream add` at
deployment time. This producer does NOT auto-create the stream; if it
doesn't exist, `produce()` raises and the disk-spool fallback kicks in.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from vyuu_gateway.audit.events import AuditEvent

if TYPE_CHECKING:
    from nats.aio.client import Client as NatsClient  # pragma: no cover
    from nats.js import JetStreamContext  # pragma: no cover


class NatsAuditProducer:
    """Durable audit producer publishing to a NATS JetStream subject."""

    def __init__(
        self,
        *,
        servers: str | list[str],
        subject_prefix: str = "vyuu.audit.events",
        client_name: str = "vyuu-gateway",
        connection: Any | None = None,
        jetstream: Any | None = None,
    ) -> None:
        """Build a NATS audit producer.

        `connection` and `jetstream` are injection seams for unit tests.
        Pass a fake with the same `publish()` shape and the real `nats`
        import is never touched.
        """

        self._servers = servers
        self._subject_prefix = subject_prefix.rstrip(".")
        self._client_name = client_name
        self._connection: NatsClient | Any | None = connection
        self._jetstream: JetStreamContext | Any | None = jetstream
        self._owns_connection = connection is None
        self._started = False

    async def start(self) -> None:
        if self._started:
            return
        if self._connection is None:
            try:
                import nats
            except ImportError as exc:  # pragma: no cover - exercised manually
                raise ImportError(
                    "NatsAuditProducer requires the `nats` extra: "
                    "`pip install vyuu-mcp-gateway[nats]`"
                ) from exc
            self._connection = await nats.connect(
                servers=self._servers,
                name=self._client_name,
            )
        if self._jetstream is None:
            self._jetstream = self._connection.jetstream()
        self._started = True

    async def stop(self) -> None:
        if not self._started:
            return
        if self._owns_connection and self._connection is not None:
            await self._connection.drain()
        self._started = False

    async def aclose(self) -> None:
        await self.stop()

    async def produce(self, event: AuditEvent) -> None:
        if not self._started:
            await self.start()
        assert self._jetstream is not None
        subject = f"{self._subject_prefix}.{event.tenant_id}"
        payload = event.model_dump_json(exclude_none=True).encode("utf-8")
        headers = {
            "Vyuu-Event-Id": str(event.event_id),
            "Vyuu-Decision": event.decision.value,
            "Vyuu-Tenant-Id": str(event.tenant_id),
        }
        await self._jetstream.publish(
            subject,
            payload=payload,
            headers=headers,
        )
