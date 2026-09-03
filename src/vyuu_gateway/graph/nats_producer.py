"""NATS JetStream graph event producer.

Mirrors `audit.nats_producer.NatsAuditProducer`. See that module's
docstring for stream-management notes; the only differences here are:

- Subject prefix defaults to `vyuu.graph.events` (audit + graph stay on
  separate streams with separate retention).
- Headers carry `Vyuu-Event-Id`, `Vyuu-Correlation-Id`, `Vyuu-Tenant-Id`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from vyuu_gateway.graph.events import GraphEvent

if TYPE_CHECKING:
    from nats.aio.client import Client as NatsClient  # pragma: no cover
    from nats.js import JetStreamContext  # pragma: no cover


class NatsGraphProducer:
    """Durable graph producer publishing to a NATS JetStream subject."""

    def __init__(
        self,
        *,
        servers: str | list[str],
        subject_prefix: str = "vyuu.graph.events",
        client_name: str = "vyuu-gateway",
        connection: Any | None = None,
        jetstream: Any | None = None,
    ) -> None:
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
                    "NatsGraphProducer requires the `nats` extra: "
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

    async def produce(self, event: GraphEvent) -> None:
        if not self._started:
            await self.start()
        assert self._jetstream is not None
        subject = f"{self._subject_prefix}.{event.tenant_id}"
        payload = event.model_dump_json(exclude_none=True).encode("utf-8")
        headers = {
            "Vyuu-Event-Id": str(event.event_id),
            "Vyuu-Correlation-Id": str(event.correlation_id),
            "Vyuu-Tenant-Id": str(event.tenant_id),
        }
        await self._jetstream.publish(
            subject,
            payload=payload,
            headers=headers,
        )
