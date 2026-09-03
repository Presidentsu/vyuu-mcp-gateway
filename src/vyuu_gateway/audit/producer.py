from typing import Protocol

from vyuu_gateway.audit.events import AuditEvent


class AuditProducer(Protocol):
    async def produce(self, event: AuditEvent) -> None:
        """Durably publish an audit event."""


class TestAuditProducer(AuditProducer):
    __test__ = False

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def produce(self, event: AuditEvent) -> None:
        self.events.append(event)
