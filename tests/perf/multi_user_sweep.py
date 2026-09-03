"""Multi-user concurrent-load sweep against the lab gateway.

For each tier in `--tiers`, spins up N concurrent async sessions
(each one user with their own real bcrypt-verified API key from
`provision_users.py`), each driver firing tool calls round-robin
across 5 tools on 3 vservers for `--duration` seconds. Captures
per-tier latency percentiles, throughput, error rates, and
gateway resource samples (CPU / RSS / FDs / stdio subprocess
count / DB pool active).

The point is to find the scaling knee — the tier at which DB
pool / stdio pool / event loop saturates and tail latency
explodes. That's the data; we don't pretend it's a victory lap.

Usage:
    # 0. Provision 500 users (one-shot, ~2 min)
    python tests/perf/provision_users.py --count 500 --label sweep

    # 1. Run sweep
    python tests/perf/multi_user_sweep.py \\
        --keys-file tests/perf/results/perf-users-sweep.json \\
        --tiers 10 50 100 200 500 \\
        --duration 60

    # 2. Cleanup
    python tests/perf/provision_users.py --cleanup --label sweep
"""
from __future__ import annotations

import argparse
import asyncio
import json
import random
import statistics
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

import httpx

TENANT = "11111111-1111-1111-1111-111111111111"
URL_TPL = f"http://127.0.0.1:8000/v/{TENANT}/{{vserver}}/mcp"
HEALTHZ = "http://127.0.0.1:8000/healthz"

# Tool mix — three lab vservers + five tools. drawio-stdio + time-pypi
# are stdio-pool backed; drawio-http is HTTP. Keeps representative
# variety without being a stdio-pool stress test.
TOOL_MIX = [
    ("time-pypi", "get_current_time", {"timezone": "UTC"}),
    ("time-pypi", "convert_time",
     {"source_timezone": "UTC", "time": "12:00", "target_timezone": "Asia/Kolkata"}),
    ("drawio-stdio", "open_drawio_mermaid",
     {"content": "graph TD; A-->B; B-->C"}),
    ("drawio-http", "search_shapes", {"query": "rectangle"}),
    ("drawio-http", "create_diagram",
     {"title": "perf", "content": "graph TD; X-->Y"}),
]


@dataclass
class TierStats:
    tier_users: int
    duration_s: float = 0.0
    ok: int = 0
    other_status: dict[int, int] = field(default_factory=dict)
    transport_errors: dict[str, int] = field(default_factory=dict)
    latencies_ms: list[float] = field(default_factory=list)
    healthz_ok: int = 0
    healthz_fail: int = 0
    healthz_latencies_ms: list[float] = field(default_factory=list)
    resource_samples: list[dict] = field(default_factory=list)


def percentile(xs: list[float], q: float) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    return s[int(round((q / 100) * (len(s) - 1)))]


async def _user_driver(
    *,
    user_id: UUID,
    api_key: str,
    deadline: float,
    stats: TierStats,
) -> None:
    """One async session per provisioned user. Keep-alive httpx client
    so we measure the gateway's hot path, not TLS / TCP setup."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    sessions: dict[str, dict[str, str]] = {}

    async with httpx.AsyncClient(timeout=20.0) as client:
        # Initialize one session per vserver for this user (mirrors
        # how Cursor / Claude Desktop hold persistent MCP sessions).
        for vserver, _, _ in TOOL_MIX:
            if vserver in sessions:
                continue
            try:
                r = await client.post(
                    URL_TPL.format(vserver=vserver),
                    headers=headers,
                    json={
                        "jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {
                                "name": "perf-sweep", "version": "1.0",
                            },
                        },
                    },
                )
                sid = r.headers.get("mcp-session-id") or r.headers.get("Mcp-Session-Id")
                if r.status_code == 200 and sid:
                    sessions[vserver] = {**headers, "Mcp-Session-Id": sid}
                    await client.post(
                        URL_TPL.format(vserver=vserver),
                        headers=sessions[vserver],
                        json={
                            "jsonrpc": "2.0",
                            "method": "notifications/initialized",
                            "params": {},
                        },
                    )
            except Exception as e:
                stats.transport_errors[type(e).__name__] = (
                    stats.transport_errors.get(type(e).__name__, 0) + 1
                )

        if not sessions:
            return  # this user can't reach any vserver — skip.

        rid = 100
        while time.perf_counter() < deadline:
            vserver, tool, args = random.choice(TOOL_MIX)
            if vserver not in sessions:
                continue
            rid += 1
            t0 = time.perf_counter()
            try:
                r = await client.post(
                    URL_TPL.format(vserver=vserver),
                    headers=sessions[vserver],
                    json={
                        "jsonrpc": "2.0", "id": rid, "method": "tools/call",
                        "params": {"name": tool, "arguments": args},
                    },
                )
                dt = (time.perf_counter() - t0) * 1000
                if r.status_code == 200:
                    if '"result"' in r.text:
                        stats.ok += 1
                        stats.latencies_ms.append(dt)
                    else:
                        stats.other_status[200] = stats.other_status.get(200, 0) + 1
                else:
                    stats.other_status[r.status_code] = (
                        stats.other_status.get(r.status_code, 0) + 1
                    )
            except Exception as e:
                stats.transport_errors[type(e).__name__] = (
                    stats.transport_errors.get(type(e).__name__, 0) + 1
                )


async def _healthz_pinger(deadline: float, stats: TierStats) -> None:
    """Independent client — proves /healthz stays green even when
    the per-tenant gate or stdio pool is saturated."""
    async with httpx.AsyncClient(timeout=2.0) as hc:
        while time.perf_counter() < deadline:
            t0 = time.perf_counter()
            try:
                r = await hc.get(HEALTHZ)
                dt = (time.perf_counter() - t0) * 1000
                stats.healthz_latencies_ms.append(dt)
                if r.status_code == 200:
                    stats.healthz_ok += 1
                else:
                    stats.healthz_fail += 1
            except Exception:
                stats.healthz_fail += 1
            await asyncio.sleep(0.5)


async def _resource_sampler(
    deadline: float, stats: TierStats, lab_pid: int | None
) -> None:
    """Once per second: gateway CPU%, RSS_MB, FD count, stdio
    subprocess count, Postgres active connections."""
    while time.perf_counter() < deadline:
        sample: dict[str, float] = {}
        if lab_pid is not None:
            try:
                out = subprocess.check_output(
                    ["ps", "-o", "pcpu=,rss=", "-p", str(lab_pid)],
                    stderr=subprocess.DEVNULL, timeout=1,
                ).decode().strip().split()
                sample["gw_cpu_pct"] = float(out[0])
                sample["gw_rss_mb"] = float(out[1]) / 1024
            except Exception:
                pass
            try:
                fds = subprocess.check_output(
                    ["lsof", "-p", str(lab_pid)],
                    stderr=subprocess.DEVNULL, timeout=2,
                ).decode().count("\n")
                sample["gw_fds"] = fds
            except Exception:
                pass
        try:
            n = subprocess.check_output(
                "pgrep -fl 'mcp-server-time|drawio-mcp' | wc -l",
                shell=True, stderr=subprocess.DEVNULL, timeout=1,
            ).decode().strip()
            sample["stdio_subprocesses"] = int(n)
        except Exception:
            pass
        try:
            pg = subprocess.check_output(
                "psql -h 127.0.0.1 -U vyuu -d vyuu_gateway -tAc "
                '"SELECT count(*) FROM pg_stat_activity '
                "WHERE datname='vyuu_gateway' AND state='active';\"",
                shell=True, stderr=subprocess.DEVNULL, timeout=2,
            ).decode().strip()
            sample["pg_active_conns"] = int(pg)
        except Exception:
            pass
        sample["t"] = round(time.perf_counter(), 2)
        if sample:
            stats.resource_samples.append(sample)
        await asyncio.sleep(1.0)


def _summary(stats: TierStats) -> dict[str, object]:
    lat = stats.latencies_ms
    res = stats.resource_samples
    res_summary: dict[str, float] = {}
    for k in ("gw_cpu_pct", "gw_rss_mb", "gw_fds", "stdio_subprocesses",
              "pg_active_conns"):
        vals = [s[k] for s in res if k in s]
        if vals:
            res_summary[f"{k}_max"] = max(vals)
            res_summary[f"{k}_avg"] = round(statistics.mean(vals), 1)
    healthz_total = stats.healthz_ok + stats.healthz_fail
    return {
        "tier_users": stats.tier_users,
        "duration_s": round(stats.duration_s, 2),
        "ok": stats.ok,
        "rps_ok": round(stats.ok / stats.duration_s, 1) if stats.duration_s else 0,
        "other_status": dict(stats.other_status),
        "transport_errors": dict(stats.transport_errors),
        "p50_ms": round(percentile(lat, 50), 1),
        "p95_ms": round(percentile(lat, 95), 1),
        "p99_ms": round(percentile(lat, 99), 1),
        "p99_9_ms": round(percentile(lat, 99.9), 1),
        "max_ms": round(max(lat), 1) if lat else 0.0,
        "healthz_total": healthz_total,
        "healthz_ok": stats.healthz_ok,
        "healthz_uptime_pct": round(100 * stats.healthz_ok / healthz_total, 2)
            if healthz_total else 0.0,
        "healthz_max_ms": round(max(stats.healthz_latencies_ms), 1)
            if stats.healthz_latencies_ms else 0.0,
        "resources": res_summary,
    }


async def _run_tier(
    *,
    keys: list[dict],
    tier_users: int,
    duration_s: float,
    lab_pid: int | None,
) -> dict[str, object]:
    if tier_users > len(keys):
        raise ValueError(
            f"tier wants {tier_users} users but only {len(keys)} keys provisioned"
        )
    chosen = keys[:tier_users]
    stats = TierStats(tier_users=tier_users)
    deadline = time.perf_counter() + duration_s
    t0 = time.perf_counter()

    drivers = [
        asyncio.create_task(_user_driver(
            user_id=UUID(k["user_id"]),
            api_key=k["api_key"],
            deadline=deadline,
            stats=stats,
        ))
        for k in chosen
    ]
    hz = asyncio.create_task(_healthz_pinger(deadline, stats))
    sampler = asyncio.create_task(_resource_sampler(deadline, stats, lab_pid))

    await asyncio.gather(*drivers, return_exceptions=True)
    stats.duration_s = time.perf_counter() - t0
    hz.cancel()
    sampler.cancel()
    for t in (hz, sampler):
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass

    return _summary(stats)


async def main_async(args: argparse.Namespace) -> None:
    keys = json.loads(Path(args.keys_file).read_text())
    print(f"# loaded {len(keys)} provisioned keys from {args.keys_file}")
    print(f"# tiers={args.tiers} duration={args.duration}s lab_pid={args.lab_pid}")

    results = []
    for tier in args.tiers:
        print(f"\n=== Tier: {tier} concurrent users ===", flush=True)
        # Cooldown between tiers — let stdio pool drain + breakers reset.
        if results:
            print("  cooldown 30s before tier...", flush=True)
            await asyncio.sleep(30.0)
        summary = await _run_tier(
            keys=keys,
            tier_users=tier,
            duration_s=args.duration,
            lab_pid=args.lab_pid,
        )
        results.append(summary)
        print(json.dumps(summary, indent=2), flush=True)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"\n# wrote {out}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keys-file", required=True)
    ap.add_argument("--tiers", nargs="+", type=int, default=[10, 50, 100, 200, 500])
    ap.add_argument("--duration", type=float, default=60.0)
    ap.add_argument("--lab-pid", type=int, default=None)
    ap.add_argument("--out", default="tests/perf/results/multi-user-sweep.json")
    args = ap.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
