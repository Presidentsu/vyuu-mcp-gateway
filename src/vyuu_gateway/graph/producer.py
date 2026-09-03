"""Producer protocol for NHI graph events.

A producer is the durable backend (Kafka/NATS in production, in-memory list in
tests). The lifecycle does not call producers directly; it calls an emitter
which decouples the request hot path from delivery. This protocol exists so a
future Kafka adapter can be slotted in without touching call sites.
"""

from __future__ import annotations

from typing import Protocol

from vyuu_gateway.graph.events import GraphEvent


class GraphEventProducer(Protocol):
    async def produce(self, event: GraphEvent) -> None:
        """Durably publish a graph event downstream."""


class TestGraphEventProducer:
    """In-memory producer for tests."""

    __test__ = False

    def __init__(self) -> None:
        self.events: list[GraphEvent] = []

    async def produce(self, event: GraphEvent) -> None:
        self.events.append(event)
