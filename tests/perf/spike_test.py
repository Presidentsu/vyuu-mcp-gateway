"""Spike test — synchronized 0→N in-flight burst.

Cron-boundary autonomous agents (CI bots, security scanners,
midnight-batch jobs) wake up *together*, not in a gradual ramp. This
test simulates that traffic shape: N drivers all park at a barrier,
then fire their first call simultaneously when the barrier releases.

Three spikes back-to-back validates recovery between bursts (the
warm path stays warm; the gateway returns to baseline RPS quickly
between spikes). The 60s gap between spikes lets the inflight gate
clear and Python's GC catch up.

Pre-warm phase ensures we measure GATEWAY behavior under the spike,
not stdio uvx subprocess cold-spawn — the persistent pool's 4 slots
are warm before the first spike fires.

Output: time-to-first-success, time-to-50%-completion, time-to-99%-
completion, 503 count, healthz uptime during the spike, post-spike
recovery time. Captured via Prometheus during the run; this script
emits a structured JSON summary.
"""
from __future__ import annotations

import asyncio
import json
import statistics
import time
from dataclasses import dataclass, field

import httpx

URL = "http://127.0.0.1:8000/v/11111111-1111-1111-1111-111111111111/time-pypi/mcp"
HEALTHZ = "http://127.0.0.1:8000/healthz"
H = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "x-vyuu-tenant-id": "11111111-1111-1111-1111-111111111111",
    "x-vyuu-principal-type": "endpoint_session",
    "x-vyuu-principal-display": "spike",
}


@dataclass
class CallResult:
    fired_at: float
    completed_at: float
    status: int
    is_error: bool


@dataclass
class SpikeStats:
    spike_n: int
    burst_size: int
    barrier_released_at: float
    calls: list[CallResult] = field(default_factory=list)
    healthz_samples: list[tuple[float, int, float]] = field(default_factory=list)


async def init_session(c: httpx.AsyncClient, pid: str) -> dict[str, str] | None:
    h = {**H, "x-vyuu-principal-id": pid}
    r = await c.post(URL, headers=h, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "spike", "version": "1.0"}}})
    sid = r.headers.get("mcp-session-id")
    if not sid:
        return None
    h2 = {**h, "Mcp-Session-Id": sid}
    await c.post(URL, headers=h2, json={
        "jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    return h2


async def spike_driver(
    c: httpx.AsyncClient,
    headers: dict[str, str],
    barrier: asyncio.Event,
    stats: SpikeStats,
) -> None:
    """One spike driver — park at barrier, fire one call when released,
    record outcome."""
    await barrier.wait()
    fired_at = time.perf_counter()
    rid = int(fired_at * 1000) & 0x7FFFFFFF
    try:
        r = await c.post(URL, headers=headers, json={
            "jsonrpc": "2.0", "id": rid, "method": "tools/call",
            "params": {"name": "get_current_time",
                       "arguments": {"timezone": "UTC"}}}, timeout=20)
        stats.calls.append(CallResult(
            fired_at=fired_at,
            completed_at=time.perf_counter(),
            status=r.status_code,
            is_error=(r.status_code != 200) or ('"isError":true' in r.text),
        ))
    except Exception:
        stats.calls.append(CallResult(
            fired_at=fired_at,
            completed_at=time.perf_counter(),
            status=0,
            is_error=True,
        ))


async def healthz_pinger(deadline: float, stats: SpikeStats) -> None:
    """Independent healthz pinger throughout the spike window — proves
    /healthz survives the burst (the whole point of the gate-bypass)."""
    async with httpx.AsyncClient(timeout=2.0) as hc:
        while time.perf_counter() < deadline:
            t0 = time.perf_counter()
            try:
                r = await hc.get(HEALTHZ)
                stats.healthz_samples.append(
                    (t0, r.status_code, (time.perf_counter() - t0) * 1000)
                )
            except Exception:
                stats.healthz_samples.append(
                    (t0, 0, (time.perf_counter() - t0) * 1000)
                )
            await asyncio.sleep(0.25)


async def run_one_spike(
    spike_n: int,
    burst_size: int,
    sids: list[dict[str, str]],
    drivers_client: httpx.AsyncClient,
) -> SpikeStats:
    stats = SpikeStats(spike_n=spike_n, burst_size=burst_size,
                       barrier_released_at=0.0)
    barrier = asyncio.Event()
    drivers = [
        asyncio.create_task(
            spike_driver(drivers_client, sids[i % len(sids)], barrier, stats)
        )
        for i in range(burst_size)
    ]
    # Healthz pinger runs slightly past the expected last-call completion
    # so we capture recovery as well.
    hz_task = asyncio.create_task(
        healthz_pinger(time.perf_counter() + 30, stats)
    )
    # Hold for 200ms to ensure all drivers parked at the barrier, then fire.
    await asyncio.sleep(0.2)
    stats.barrier_released_at = time.perf_counter()
    barrier.set()
    await asyncio.gather(*drivers, return_exceptions=True)
    await hz_task
    return stats


def summarize(stats: SpikeStats) -> dict:
    relative_calls = [
        {
            "fired_offset_ms": round((c.fired_at - stats.barrier_released_at) * 1000, 1),
            "completed_offset_ms": round((c.completed_at - stats.barrier_released_at) * 1000, 1),
            "duration_ms": round((c.completed_at - c.fired_at) * 1000, 1),
            "status": c.status,
            "is_error": c.is_error,
        }
        for c in sorted(stats.calls, key=lambda c: c.completed_at)
    ]
    successes = [c for c in relative_calls if not c["is_error"]]
    errors = [c for c in relative_calls if c["is_error"]]
    completion_offsets = [c["completed_offset_ms"] for c in successes]
    durations = [c["duration_ms"] for c in successes]
    status_counts: dict[int, int] = {}
    for c in relative_calls:
        status_counts[c["status"]] = status_counts.get(c["status"], 0) + 1

    healthz_ok = sum(1 for _, status, _ in stats.healthz_samples if status == 200)
    healthz_total = len(stats.healthz_samples)
    healthz_latencies = [ms for _, status, ms in stats.healthz_samples if status == 200]

    return {
        "spike_n": stats.spike_n,
        "burst_size": stats.burst_size,
        "successes": len(successes),
        "errors": len(errors),
        "status_counts": status_counts,
        "time_to_first_success_ms": min(completion_offsets) if completion_offsets else None,
        "time_to_50pct_complete_ms": (
            sorted(completion_offsets)[len(completion_offsets)//2]
            if completion_offsets else None
        ),
        "time_to_99pct_complete_ms": (
            sorted(completion_offsets)[int(0.99 * len(completion_offsets))]
            if len(completion_offsets) >= 100 else (
                max(completion_offsets) if completion_offsets else None
            )
        ),
        "time_to_100pct_complete_ms": (
            max(completion_offsets) if completion_offsets else None
        ),
        "duration_p50_ms": (
            round(statistics.median(durations), 1) if durations else None
        ),
        "duration_p99_ms": (
            round(sorted(durations)[int(0.99 * len(durations))], 1)
            if len(durations) >= 100 else None
        ),
        "duration_max_ms": round(max(durations), 1) if durations else None,
        "healthz_ok": healthz_ok,
        "healthz_total": healthz_total,
        "healthz_uptime_pct": (
            round(100 * healthz_ok / healthz_total, 1) if healthz_total else None
        ),
        "healthz_max_latency_ms": (
            round(max(healthz_latencies), 1) if healthz_latencies else None
        ),
    }


async def main() -> None:
    # Two passes:
    #   Pass A — under-cap burst (100). Tests gateway behavior under
    #            a clean cron-boundary burst; everything should
    #            succeed.
    #   Pass B — over-cap burst (150). Tests fast-503 behavior past
    #            the per-tenant cap; should see ~22 clean 503s.
    passes = [
        {"label": "under-cap", "burst_size": 100, "expected_503s": 0},
        {"label": "over-cap",  "burst_size": 150, "expected_503s": 22},
    ]
    num_spikes_per_pass = 3
    gap_between_spikes_s = 20
    pre_warm_calls = 50

    print("# Spike test — synchronized burst, 2 passes × 3 spikes each")
    print(f"# Pre-warm: {pre_warm_calls} sequential calls to warm stdio pool")
    print("# Per-tenant inflight cap: 128")
    print()

    all_summaries = []
    for pass_cfg in passes:
        burst_size = pass_cfg["burst_size"]
        label = pass_cfg["label"]
        expected_503s = pass_cfg["expected_503s"]
        print(f"\n{'#' * 60}")
        print(f"# Pass: {label} — burst_size={burst_size}, expected_503s={expected_503s}")
        print(f"{'#' * 60}\n")

        limits = httpx.Limits(
            max_connections=burst_size + 8,
            max_keepalive_connections=burst_size + 8,
        )
        async with httpx.AsyncClient(limits=limits, timeout=30.0) as drivers_client:
            # 32 sessions reused across drivers (one HTTP/1.1 conn per session,
            # multiple drivers can share via httpx's pool with serialization
            # at the connection layer; for high-concurrency we'd want HTTP/2
            # multiplexing or one connection per driver).
            sids: list[dict[str, str]] = []
            for i in range(32):
                try:
                    h = await init_session(drivers_client, f"spike-{label}-{i}")
                    if h:
                        sids.append(h)
                except Exception:
                    pass
            print(f"# {len(sids)} sessions initialized")
            if not sids:
                print("ERROR: no sessions initialized")
                continue

            # Pre-warm the persistent stdio pool.
            print(f"# Warming pool with {pre_warm_calls} sequential calls...")
            warmup_start = time.perf_counter()
            for i in range(pre_warm_calls):
                try:
                    await drivers_client.post(URL, headers=sids[i % len(sids)], json={
                        "jsonrpc": "2.0", "id": 9000 + i, "method": "tools/call",
                        "params": {"name": "get_current_time",
                                   "arguments": {"timezone": "UTC"}}}, timeout=10)
                except Exception:
                    pass
            print(f"# Warmup done in {time.perf_counter() - warmup_start:.1f}s")
            print()

            for n in range(1, num_spikes_per_pass + 1):
                print(f"=== Pass {label}, Spike {n}/{num_spikes_per_pass} "
                      f"({burst_size} synchronized) ===")
                stats = await run_one_spike(n, burst_size, sids, drivers_client)
                summary = summarize(stats)
                summary["pass"] = label
                all_summaries.append(summary)
                print(f"  successes  : {summary['successes']}/{burst_size}")
                print(f"  errors     : {summary['errors']}")
                print(f"  status     : {summary['status_counts']}")
                first_ok = summary['time_to_first_success_ms']
                p50_done = summary['time_to_50pct_complete_ms']
                p99_done = summary['time_to_99pct_complete_ms']
                p100_done = summary['time_to_100pct_complete_ms']
                p50_dur = summary['duration_p50_ms']
                max_dur = summary['duration_max_ms']
                print(f"  first ok   : "
                      f"{f'{first_ok:.1f} ms' if first_ok is not None else '—'}")
                print(f"  50% done   : "
                      f"{f'{p50_done:.1f} ms' if p50_done is not None else '—'}")
                print(f"  99% done   : "
                      f"{f'{p99_done:.1f} ms' if p99_done is not None else '—'}")
                print(f"  100% done  : "
                      f"{f'{p100_done:.1f} ms' if p100_done is not None else '—'}")
                print(f"  duration   : p50={p50_dur} max={max_dur} ms")
                print(f"  healthz    : {summary['healthz_ok']}/{summary['healthz_total']} "
                      f"ok ({summary['healthz_uptime_pct']}%) "
                      f"max latency {summary['healthz_max_latency_ms']} ms")
                print()
                if n < num_spikes_per_pass:
                    print(f"# Cooldown {gap_between_spikes_s}s...")
                    await asyncio.sleep(gap_between_spikes_s)

    print("=== JSON summary ===")
    print(json.dumps(all_summaries, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
