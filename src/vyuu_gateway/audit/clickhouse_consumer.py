"""NATS JetStream → ClickHouse audit consumer.

Standalone process that subscribes to the gateway's audit subject and
batches events into a ClickHouse `audit_events` table. Designed to run
alongside the gateway (separate pod / container / systemd unit), not in
the gateway process itself — that keeps the audit pipeline independently
scalable and lets ClickHouse outages not affect the gateway hot path.

Run:
    python -m vyuu_gateway.audit.clickhouse_consumer \\
        --nats nats://nats.internal:4222 \\
        --clickhouse-url http://clickhouse.internal:8123 \\
        --clickhouse-user vyuu \\
        --clickhouse-password "$CH_PW" \\
        --batch-size 1000 --batch-interval 1.0

ClickHouse schema (run once at deployment time):

    CREATE TABLE audit_events (
        event_id UUID,
        timestamp DateTime64(3, 'UTC'),
        tenant_id UUID,
        gateway_instance_id String,
        principal_type LowCardinality(String),
        principal_id String,
        principal_display String,
        vserver_id Nullable(UUID),
        vserver_name Nullable(String),
        upstream_server_id Nullable(UUID),
        tool LowCardinality(String),
        decision LowCardinality(String),
        decision_mode LowCardinality(String),
        policy_rule_id Nullable(String),
        latency_ms_total Nullable(Float64),
        latency_ms_upstream Nullable(Float64),
        upstream_status LowCardinality(String),
        response_size_bytes Nullable(UInt64),
        event_type LowCardinality(String),
        auth_failure_reason Nullable(String),
        raw_args Nullable(String),
        raw_response Nullable(String),
        raw_args_truncated Bool,
        raw_response_truncated Bool,
        full_event String,  -- canonical JSON for forensic queries
        ingested_at DateTime64(3, 'UTC') DEFAULT now64(3)
    ) ENGINE = MergeTree
    PARTITION BY toYYYYMMDD(timestamp)
    ORDER BY (tenant_id, timestamp, event_id)
    TTL toDateTime(timestamp) + INTERVAL 90 DAY DELETE;

Backpressure model:
- NATS JetStream tracks consumer pending count. We pull in batches of
  1000 events (or 1s timeout, whichever first), insert into ClickHouse
  in one HTTP request, then ack the batch.
- If ClickHouse is down: don't ack. JetStream redelivers when we come
  back. Gateway's DiskSpoolAuditEmitter handles the producer side
  staying up while broker is down.

Chaos test (`tests/audit/test_clickhouse_consumer_chaos.py`):
- Kill ClickHouse mid-batch → consumer logs + retries → events
  eventually land when ClickHouse recovers (no loss).
- Kill NATS mid-run → consumer reconnects → no duplicate events
  (JetStream tracks acks).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("vyuu.audit.consumer")


@dataclass(frozen=True)
class ConsumerConfig:
    nats_servers: str | list[str]
    clickhouse_url: str
    clickhouse_user: str
    clickhouse_password: str
    clickhouse_database: str = "default"
    clickhouse_table: str = "audit_events"
    nats_subject_filter: str = "vyuu.audit.events.>"
    nats_stream: str = "VYUU_AUDIT"
    nats_durable_consumer: str = "vyuu-clickhouse-consumer"
    batch_size: int = 1000
    batch_interval_seconds: float = 1.0
    request_timeout_seconds: float = 10.0
    # Disk spool for ClickHouse-down windows. Producer-side spool is
    # in the gateway; this is the consumer-side spool for events that
    # arrived from NATS but couldn't be inserted yet.
    disk_spool_dir: str | None = None


class AuditClickHouseConsumer:
    """Pulls audit events from NATS JetStream, batches into ClickHouse."""

    def __init__(
        self,
        config: ConsumerConfig,
        *,
        # Injection seams for chaos tests.
        nats_subscriber_factory: Any | None = None,
        clickhouse_inserter_factory: Any | None = None,
    ) -> None:
        self._config = config
        self._nats_subscriber_factory = nats_subscriber_factory
        self._clickhouse_inserter_factory = clickhouse_inserter_factory
        self._running = False
        self._stats = {
            "events_received": 0,
            "events_inserted": 0,
            "batches_inserted": 0,
            "insert_errors": 0,
            "nats_reconnects": 0,
        }

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    async def run(self) -> None:
        """Main loop. Runs until SIGINT / SIGTERM or `stop()`."""
        self._running = True
        logger.info("audit_consumer_starting", extra={
            "nats": self._config.nats_servers,
            "clickhouse": self._config.clickhouse_url,
            "batch_size": self._config.batch_size,
        })
        async with self._subscribe() as messages:
            inserter = await self._build_inserter()
            buffer: list[dict[str, Any]] = []
            ack_callbacks: list[Any] = []
            last_flush = asyncio.get_event_loop().time()

            async for message in messages:
                if not self._running:
                    break
                self._stats["events_received"] += 1
                try:
                    event = json.loads(message.body)
                except (ValueError, TypeError):
                    logger.warning("audit_consumer_skipping_malformed_event")
                    await message.ack()
                    continue
                buffer.append(event)
                ack_callbacks.append(message.ack)

                now = asyncio.get_event_loop().time()
                if (len(buffer) >= self._config.batch_size
                        or now - last_flush >= self._config.batch_interval_seconds):
                    await self._flush(inserter, buffer, ack_callbacks)
                    buffer = []
                    ack_callbacks = []
                    last_flush = now

            # Drain on shutdown.
            if buffer:
                await self._flush(inserter, buffer, ack_callbacks)
        logger.info("audit_consumer_stopped", extra=self.stats)

    def stop(self) -> None:
        self._running = False

    async def _flush(
        self,
        inserter: Any,
        buffer: list[dict[str, Any]],
        ack_callbacks: list[Any],
    ) -> None:
        if not buffer:
            return
        try:
            await inserter.insert_batch(buffer)
        except Exception as exc:  # noqa: BLE001
            self._stats["insert_errors"] += 1
            logger.warning(
                "audit_consumer_clickhouse_insert_failed",
                extra={"batch_size": len(buffer), "error": exc.__class__.__name__},
            )
            # Don't ack — JetStream will redeliver on next pull.
            return
        # Insert succeeded; ack everything.
        self._stats["events_inserted"] += len(buffer)
        self._stats["batches_inserted"] += 1
        for ack in ack_callbacks:
            try:
                await ack()
            except Exception:  # noqa: BLE001
                logger.warning("audit_consumer_ack_failed", exc_info=True)

    @asynccontextmanager
    async def _subscribe(self) -> AsyncIterator[Any]:
        if self._nats_subscriber_factory is not None:
            async with self._nats_subscriber_factory() as messages:
                yield messages
            return
        # Real NATS path — lazy import so unit tests don't need nats-py.
        from nats.aio.client import Client as NatsClient  # noqa: I001

        nc = NatsClient()
        await nc.connect(servers=self._config.nats_servers)
        try:
            js = nc.jetstream()
            sub = await js.pull_subscribe(
                self._config.nats_subject_filter,
                durable=self._config.nats_durable_consumer,
                stream=self._config.nats_stream,
            )

            async def _gen() -> AsyncIterator[Any]:
                while self._running:
                    try:
                        msgs = await sub.fetch(
                            batch=min(self._config.batch_size, 100),
                            timeout=self._config.batch_interval_seconds,
                        )
                    except TimeoutError:
                        continue
                    for m in msgs:
                        yield _NatsMessage(m)

            yield _gen()
        finally:
            await nc.drain()

    async def _build_inserter(self) -> Any:
        if self._clickhouse_inserter_factory is not None:
            return self._clickhouse_inserter_factory()
        return _ClickHouseHttpInserter(self._config)


class _NatsMessage:
    """Adapt nats-py's `Msg` to the simple shape the consumer loop uses."""

    def __init__(self, msg: Any) -> None:
        self._msg = msg

    @property
    def body(self) -> bytes:
        data = self._msg.data
        return data if isinstance(data, bytes) else bytes(data)

    async def ack(self) -> None:
        await self._msg.ack()


class _ClickHouseHttpInserter:
    """Bulk-insert events into ClickHouse via the HTTP interface.

    Wire format: JSONEachRow over POST /?query=INSERT+INTO+...
    Each row is one canonical JSON line; ClickHouse parses on the
    server side. Avoids row-by-row insert overhead.
    """

    def __init__(self, config: ConsumerConfig) -> None:
        self._config = config
        self._url = config.clickhouse_url.rstrip("/")
        self._auth = (config.clickhouse_user, config.clickhouse_password)

    async def insert_batch(self, events: list[dict[str, Any]]) -> None:
        # Lazy import so the gateway base install doesn't pull httpx
        # for the consumer surface specifically.
        import httpx  # noqa: I001

        rows = "\n".join(json.dumps(_flatten_event(e)) for e in events) + "\n"
        params = {
            "query": (
                f"INSERT INTO {self._config.clickhouse_database}."
                f"{self._config.clickhouse_table} FORMAT JSONEachRow"
            ),
        }
        async with httpx.AsyncClient(timeout=self._config.request_timeout_seconds) as c:
            r = await c.post(
                self._url,
                params=params,
                content=rows.encode("utf-8"),
                auth=self._auth,
            )
        if r.status_code != 200:
            raise RuntimeError(
                f"clickhouse insert failed: HTTP {r.status_code} — {r.text[:200]}"
            )


def _flatten_event(event: dict[str, Any]) -> dict[str, Any]:
    """Project an `AuditEvent` dump into the ClickHouse columns.
    Preserves the full event JSON in `full_event` for forensic queries."""
    p = event.get("principal") or {}
    return {
        "event_id": event.get("event_id"),
        "timestamp": event.get("timestamp"),
        "tenant_id": event.get("tenant_id"),
        "gateway_instance_id": event.get("gateway_instance_id"),
        "principal_type": p.get("type"),
        "principal_id": p.get("id"),
        "principal_display": p.get("display") or "",
        "vserver_id": event.get("vserver_id"),
        "vserver_name": event.get("vserver_name"),
        "upstream_server_id": event.get("upstream_server_id"),
        "tool": event.get("tool"),
        "decision": event.get("decision"),
        "decision_mode": event.get("decision_mode"),
        "policy_rule_id": event.get("policy_rule_id"),
        "latency_ms_total": event.get("latency_ms_total"),
        "latency_ms_upstream": event.get("latency_ms_upstream"),
        "upstream_status": event.get("upstream_status"),
        "response_size_bytes": event.get("response_size_bytes"),
        "event_type": event.get("event_type"),
        "auth_failure_reason": event.get("auth_failure_reason"),
        "raw_args": (
            json.dumps(event["raw_args"]) if event.get("raw_args") is not None else None
        ),
        "raw_response": (
            json.dumps(event["raw_response"])
            if event.get("raw_response") is not None else None
        ),
        "raw_args_truncated": bool(event.get("raw_args_truncated")),
        "raw_response_truncated": bool(event.get("raw_response_truncated")),
        "full_event": json.dumps(event, default=str),
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Vyuu MCP Gateway audit consumer (NATS → ClickHouse)"
    )
    parser.add_argument("--nats", required=True,
                        help="NATS server URL(s), e.g. nats://nats.internal:4222")
    parser.add_argument("--clickhouse-url", required=True,
                        help="ClickHouse HTTP URL, e.g. http://ch.internal:8123")
    parser.add_argument("--clickhouse-user", default="default")
    parser.add_argument("--clickhouse-password", default="")
    parser.add_argument("--clickhouse-database", default="default")
    parser.add_argument("--clickhouse-table", default="audit_events")
    parser.add_argument("--subject-filter", default="vyuu.audit.events.>")
    parser.add_argument("--stream", default="VYUU_AUDIT")
    parser.add_argument("--durable", default="vyuu-clickhouse-consumer")
    parser.add_argument("--batch-size", type=int, default=1000)
    parser.add_argument("--batch-interval", type=float, default=1.0)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")

    config = ConsumerConfig(
        nats_servers=args.nats,
        clickhouse_url=args.clickhouse_url,
        clickhouse_user=args.clickhouse_user,
        clickhouse_password=args.clickhouse_password,
        clickhouse_database=args.clickhouse_database,
        clickhouse_table=args.clickhouse_table,
        nats_subject_filter=args.subject_filter,
        nats_stream=args.stream,
        nats_durable_consumer=args.durable,
        batch_size=args.batch_size,
        batch_interval_seconds=args.batch_interval,
    )
    consumer = AuditClickHouseConsumer(config)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _stop(*_: Any) -> None:
        consumer.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _stop)

    try:
        loop.run_until_complete(consumer.run())
    finally:
        loop.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
