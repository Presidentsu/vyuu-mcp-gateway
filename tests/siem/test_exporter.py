"""SIEM-1 · the exporter: routing, batching, retry, loss accounting."""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Sequence
from typing import Any
from uuid import UUID, uuid4

from vyuu_gateway.siem.events import DEFAULT_CATEGORIES, SiemCategory, SiemEvent
from vyuu_gateway.siem.exporter import SiemExporter
from vyuu_gateway.siem.hec import HecDeliveryError, HecTarget
from vyuu_gateway.siem.targets import StaticTargetResolver, TargetConfig


class _FakeClient:
    """Records batches; can be scripted to fail."""

    def __init__(self, failures: list[HecDeliveryError] | None = None) -> None:
        self.batches: list[dict[str, Any]] = []
        self._failures = list(failures or [])
        self.closed = False

    async def send_batch(
        self,
        target: HecTarget,
        events: Sequence[SiemEvent],
        *,
        include_raw: bool,
        gateway_instance_id: str,
    ) -> int:
        if self._failures:
            raise self._failures.pop(0)
        self.batches.append(
            {
                "target": target,
                "events": list(events),
                "include_raw": include_raw,
                "gateway_instance_id": gateway_instance_id,
            }
        )
        return len(events)

    async def aclose(self) -> None:
        self.closed = True


class _FakeSecrets:
    def __init__(self, secrets: dict[tuple[UUID, str], str]) -> None:
        self._secrets = secrets
        self.lookups = 0

    async def get_secret(self, tenant_id: UUID, ref: str) -> str:
        self.lookups += 1
        try:
            return self._secrets[(tenant_id, ref)]
        except KeyError:
            raise LookupError(f"no secret {ref!r}") from None


def _deployment(**overrides: Any) -> TargetConfig:
    kwargs: dict[str, Any] = {
        "key": "deployment", "tenant_id": None, "hec_url": "https://ops:8088", "token_ref": None,
        "token_literal": "ops-token", "index": None, "source": "vyuu-mcp-gateway", "host": None,
        "verify_tls": True, "categories": DEFAULT_CATEGORIES, "include_raw_payloads": False,
        "min_log_level": logging.WARNING, "batch_max_events": 100, "flush_interval_seconds": 0.05,
    }
    kwargs.update(overrides)
    return TargetConfig(**kwargs)


def _tenant_target(tenant_id: UUID, **overrides: Any) -> TargetConfig:
    kwargs: dict[str, Any] = {
        "key": str(tenant_id), "tenant_id": tenant_id, "hec_url": "https://acme:8088",
        "token_ref": "hec-token", "token_literal": None, "index": "acme",
            "source": "vyuu-mcp-gateway",
        "host": None, "verify_tls": True, "categories": DEFAULT_CATEGORIES,
        "include_raw_payloads": True, "min_log_level": logging.WARNING,
        "batch_max_events": 100, "flush_interval_seconds": 0.05,
    }
    kwargs.update(overrides)
    return TargetConfig(**kwargs)


def _event(tenant_id: UUID | None, category: SiemCategory = SiemCategory.TOOL_CALL,
           *, level: int = 0) -> SiemEvent:
    return SiemEvent(category=category, tenant_id=tenant_id, body={"n": 1}, log_level=level)


async def _no_sleep(_: float) -> None:
    return None


def _exporter(
    targets: list[TargetConfig],
    *,
    client: _FakeClient | None = None,
    secrets: _FakeSecrets | None = None,
    **kwargs: Any,
) -> tuple[SiemExporter, _FakeClient]:
    client = client or _FakeClient()
    exporter = SiemExporter(
        client=client,  # type: ignore[arg-type]
        resolver=StaticTargetResolver(targets),
        secret_store=secrets or _FakeSecrets({}),
        gateway_instance_id="gw-1",
        sleep=_no_sleep,
        **kwargs,
    )
    return exporter, client


def test_tenant_events_reach_the_deployment_and_their_own_target_only() -> None:
    acme, globex = uuid4(), uuid4()
    secrets = _FakeSecrets({(acme, "hec-token"): "acme-token", (globex, "hec-token"): "g-token"})
    exporter, client = _exporter(
        [_deployment(), _tenant_target(acme), _tenant_target(globex)], secrets=secrets
    )

    async def run() -> None:
        await exporter.start()
        exporter.emit_nowait(_event(acme))
        exporter.emit_nowait(_event(None))  # a gateway-wide event
        assert await exporter.flush()
        await exporter.stop()

    asyncio.run(run())
    by_target = {b["target"].url: b for b in client.batches}
    assert set(by_target) == {"https://ops:8088", "https://acme:8088"}
    assert len(by_target["https://ops:8088"]["events"]) == 2
    assert len(by_target["https://acme:8088"]["events"]) == 1
    # Token resolved from the store for the tenant, literal for ops.
    assert by_target["https://acme:8088"]["target"].token == "acme-token"
    assert by_target["https://ops:8088"]["target"].token == "ops-token"
    # Raw-payload policy travels with the target, not the event.
    assert by_target["https://acme:8088"]["include_raw"] is True
    assert by_target["https://ops:8088"]["include_raw"] is False
    assert client.closed


def test_category_and_log_level_filters_apply_per_target() -> None:
    acme = uuid4()
    only_auth = _tenant_target(
        acme, categories=frozenset({SiemCategory.AUTH, SiemCategory.GATEWAY_LOG}),
        min_log_level=logging.ERROR,
    )
    exporter, client = _exporter(
        [only_auth], secrets=_FakeSecrets({(acme, "hec-token"): "t"})
    )

    async def run() -> None:
        await exporter.start()
        exporter.emit_nowait(_event(acme, SiemCategory.TOOL_CALL))
        exporter.emit_nowait(_event(acme, SiemCategory.AUTH))
        exporter.emit_nowait(_event(acme, SiemCategory.GATEWAY_LOG, level=logging.WARNING))
        exporter.emit_nowait(_event(acme, SiemCategory.GATEWAY_LOG, level=logging.ERROR))
        await exporter.flush()
        await exporter.stop()

    asyncio.run(run())
    delivered = [e.category for b in client.batches for e in b["events"]]
    assert sorted(delivered) == sorted([SiemCategory.AUTH, SiemCategory.GATEWAY_LOG])


def test_events_emitted_before_start_are_delivered_after_it() -> None:
    exporter, client = _exporter([_deployment()])
    exporter.emit_nowait(_event(None))

    async def run() -> None:
        await exporter.start()
        await exporter.flush()
        await exporter.stop()

    asyncio.run(run())
    assert len(client.batches) == 1


def test_retryable_failure_is_retried_then_succeeds() -> None:
    client = _FakeClient(failures=[HecDeliveryError("busy", status_code=503, retryable=True)])
    exporter, _ = _exporter([_deployment()], client=client)

    async def run() -> None:
        await exporter.start()
        exporter.emit_nowait(_event(None))
        await exporter.flush()
        await exporter.stop()

    asyncio.run(run())
    stats = exporter.stats()["deployment"]
    assert len(client.batches) == 1
    assert stats.retried_batches == 1
    assert stats.sent_batches == 1 and stats.sent_events == 1
    assert stats.failed_batches == 0 and stats.degraded is False
    assert stats.last_error is None


def test_non_retryable_failure_drops_the_batch_and_says_why() -> None:
    client = _FakeClient(
        failures=[HecDeliveryError("HTTP 403: Invalid token (code 4)", status_code=403,
            retryable=False)]
    )
    exporter, _ = _exporter([_deployment()], client=client)

    async def run() -> None:
        await exporter.start()
        exporter.emit_nowait(_event(None))
        exporter.emit_nowait(_event(None))
        await exporter.flush()
        await exporter.stop()

    asyncio.run(run())
    stats = exporter.stats()["deployment"]
    assert client.batches == []
    assert stats.failed_batches == 1
    assert stats.dropped_events == 2
    assert stats.degraded is True
    assert stats.last_error is not None and "Invalid token" in stats.last_error
    assert stats.retried_batches == 0


def test_retries_give_up_after_max_attempts() -> None:
    client = _FakeClient(
        failures=[HecDeliveryError("busy", status_code=503, retryable=True)] * 10
    )
    exporter, _ = _exporter([_deployment()], client=client, max_attempts=3)

    async def run() -> None:
        await exporter.start()
        exporter.emit_nowait(_event(None))
        await exporter.flush()
        await exporter.stop()

    asyncio.run(run())
    stats = exporter.stats()["deployment"]
    assert stats.retried_batches == 2
    assert stats.failed_batches == 1 and stats.dropped_events == 1


def test_queue_overflow_drops_newest_and_counts_it() -> None:
    exporter, client = _exporter([_deployment()], max_queue_size=3)
    for _ in range(5):
        exporter.emit_nowait(_event(None))
    stats = exporter.stats()["deployment"]
    assert stats.dropped_events == 2
    assert stats.queue_depth == 3
    assert stats.degraded is True

    async def run() -> None:
        await exporter.start()
        await exporter.flush()
        await exporter.stop()

    asyncio.run(run())
    assert sum(len(b["events"]) for b in client.batches) == 3


def test_missing_tenant_token_is_reported_not_raised() -> None:
    acme = uuid4()
    exporter, client = _exporter([_tenant_target(acme)], secrets=_FakeSecrets({}))

    async def run() -> None:
        await exporter.start()
        exporter.emit_nowait(_event(acme))
        await exporter.flush()
        await exporter.stop()

    asyncio.run(run())
    stats = exporter.stats()[str(acme)]
    assert client.batches == []
    assert stats.last_error is not None and "token unavailable" in stats.last_error
    assert stats.dropped_events == 1


def test_tenant_token_is_cached_and_invalidation_forgets_it() -> None:
    acme = uuid4()
    secrets = _FakeSecrets({(acme, "hec-token"): "t"})
    exporter, _ = _exporter([_tenant_target(acme, batch_max_events=1)], secrets=secrets)

    async def run() -> None:
        await exporter.start()
        exporter.emit_nowait(_event(acme))
        exporter.emit_nowait(_event(acme))
        await exporter.flush()
        assert secrets.lookups == 1
        exporter.invalidate(acme)
        exporter.emit_nowait(_event(acme))
        await exporter.flush()
        assert secrets.lookups == 2
        await exporter.stop()

    asyncio.run(run())


def test_batches_respect_the_target_batch_size() -> None:
    exporter, client = _exporter([_deployment(batch_max_events=2)])

    async def run() -> None:
        exporter.emit_nowait(_event(None))
        exporter.emit_nowait(_event(None))
        exporter.emit_nowait(_event(None))
        await exporter.start()
        await exporter.flush()
        await exporter.stop()

    asyncio.run(run())
    assert sorted(len(b["events"]) for b in client.batches) == [1, 2]


def test_emit_is_safe_from_another_thread_while_the_loop_runs() -> None:
    exporter, client = _exporter([_deployment()])

    async def run() -> None:
        await exporter.start()
        def _emit_many() -> None:
            for _ in range(20):
                exporter.emit_nowait(_event(None))

        worker = threading.Thread(target=_emit_many)
        worker.start()
        worker.join()
        await exporter.flush()
        await exporter.stop()

    asyncio.run(run())
    assert sum(len(b["events"]) for b in client.batches) == 20


def test_send_test_reports_splunks_answer() -> None:
    acme = uuid4()
    client = _FakeClient(
        failures=[HecDeliveryError("HTTP 403: Invalid token (code 4)", status_code=403,
            retryable=False)]
    )
    exporter, _ = _exporter(
        [_deployment(), _tenant_target(acme)], client=client,
        secrets=_FakeSecrets({(acme, "hec-token"): "t"}),
    )

    async def run() -> tuple[tuple[bool, str], tuple[bool, str], tuple[bool, str]]:
        first = await exporter.send_test(acme)      # scripted failure
        second = await exporter.send_test(acme)     # then success
        third = await exporter.send_test(uuid4())   # nothing configured
        return first, second, third

    first, second, third = asyncio.run(run())
    assert first == (False, "HTTP 403: Invalid token (code 4)")
    assert second[0] is True and "https://acme:8088" in second[1]
    assert third[0] is False and "no enabled SIEM target" in third[1]
    # The heartbeat bypassed the queue: nothing counted against delivery stats.
    assert exporter.stats() == {} or all(s.sent_events == 0 for s in exporter.stats().values())
    assert client.batches[0]["events"][0].category == SiemCategory.HEARTBEAT


def test_deployment_target_configured_reflects_the_resolver() -> None:
    with_ops, _ = _exporter([_deployment()])
    without, _ = _exporter([_tenant_target(uuid4())])
    assert with_ops.deployment_target_configured() is True
    assert without.deployment_target_configured() is False
