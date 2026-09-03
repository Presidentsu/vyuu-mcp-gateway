from pathlib import Path

from vyuu_gateway.audit.events import AuditEvent
from vyuu_gateway.audit.producer import AuditProducer


class AuditSpoolFullError(Exception):
    """Raised when the local audit spool cannot accept another event."""


class DiskSpool:
    """Append-only local JSONL spool for failed audit delivery."""

    def __init__(self, path: Path, *, max_bytes: int | None = None) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: AuditEvent) -> None:
        serialized = event.model_dump_json() + "\n"
        if self.max_bytes is not None:
            current_size = self.path.stat().st_size if self.path.exists() else 0
            if current_size + len(serialized.encode("utf-8")) > self.max_bytes:
                raise AuditSpoolFullError("audit spool is full")

        with self.path.open("a", encoding="utf-8") as spool_file:
            spool_file.write(serialized)

    def read_events(self) -> list[AuditEvent]:
        if not self.path.exists():
            return []
        return [
            AuditEvent.model_validate_json(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line
        ]

    async def replay_to(self, producer: AuditProducer) -> int:
        events = self.read_events()
        replayed = 0

        for index, event in enumerate(events):
            try:
                await producer.produce(event)
            except Exception:
                self._replace(events[index:])
                raise
            replayed += 1

        self._replace([])
        return replayed

    def _replace(self, events: list[AuditEvent]) -> None:
        if not events:
            self.path.write_text("", encoding="utf-8")
            return

        payload = "".join(event.model_dump_json() + "\n" for event in events)
        self.path.write_text(payload, encoding="utf-8")


class SpoolingAuditProducer(AuditProducer):
    """Producer wrapper that falls back to disk when the primary producer fails."""

    def __init__(self, primary: AuditProducer, spool: DiskSpool) -> None:
        self._primary = primary
        self._spool = spool

    async def produce(self, event: AuditEvent) -> None:
        try:
            await self._primary.produce(event)
        except Exception:
            self._spool.append(event)
