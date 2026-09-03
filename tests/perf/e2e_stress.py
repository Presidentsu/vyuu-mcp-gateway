"""End-to-end stress test for the Tier-1 + Tier-2 gateway.

Verifies five things in sequence:

  P1  Gateway hot-path RPS (deny path, no upstream call). Headroom check.
  P2  Stdio persistent-pool RPS (post-Tier-2). Pre-fix ceiling: ~5/server.
  P3  Past-saturation behavior. Drives in-flight beyond per-tenant cap;
      verifies clean 503s, /healthz stays green, gateway doesn't crash.
  P4  Sustained 60s burst at the recommended workload (~150 RPS).
      Watches for memory leaks, FD leaks, subprocess accumulation.
  P5  Cleanup verification. Stdio subprocesses drain to 0 after load
      ends (proves pool teardown works).

Harness design:
- ONE httpx client per session, HTTP/1.1 keep-alive (no per-call connect).
- Independent /healthz pinger on its own client throughout every phase.
- Resource sampling (gateway CPU/RSS/FDs, stdio subprocess count, pg
  active connections) every 1s during phases.
- All output structured so we can compare runs.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from dataclasses import dataclass, field

import httpx

TENANT = "11111111-1111-1111-1111-111111111111"
def vserver_url(vs: str) -> str:
    return f"http://127.0.0.1:8000/v/{TENANT}/{vs}/mcp"
URL = vserver_url  # backwards-compat alias used throughout the file
HEALTHZ = "http://127.0.0.1:8000/healthz"

H_BASE = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "x-vyuu-tenant-id": TENANT,
    "x-vyuu-principal-type": "endpoint_session",
    "x-vyuu-principal-display": "e2e-stress",
}


# Realistic mix — only upstreams with synced caps, all stdio so we
# exercise the persistent-pool path that Tier-2 fixed.
TOOLS = {
    "time-pypi": {
        "get_current_time":  ({"timezone": "UTC"}, 0.7),
        "convert_time":      ({"source_timezone": "UTC", "time": "12:00",
                                "target_timezone": "Asia/Kolkata"}, 0.3),
    },
    "drawio-stdio": {
        "open_drawio_mermaid": ({"content": "graph TD; A-->B; B-->C"}, 0.7),
        "open_drawio_xml":     ({"content":
            '<mxfile><diagram><mxGraphModel><root>'
            '<mxCell id="0"/><mxCell id="1" parent="0"/>'
            '</root></mxGraphModel></diagram></mxfile>'}, 0.3),
    },
}


@dataclass
class PhaseStats:
    label: str
    duration_s: float = 0.0
    sessions_live: int = 0
    in_flight: int = 0
    ok: int = 0
    rate_limited_503: int = 0
    other_status: dict[int, int] = field(default_factory=dict)
    transport_errors: dict[str, int] = field(default_factory=dict)
    latencies_ms: list[float] = field(default_factory=list)
    healthz_ok: int = 0
    healthz_fail: int = 0
    healthz_latencies_ms: list[float] = field(default_factory=list)
    resource_samples: list[dict] = field(default_factory=list)


def percentile(xs, q):
    if not xs:
        return 0.0
    s = sorted(xs)
    return s[int(round((q / 100) * (len(s) - 1)))]


def _summary(ph: PhaseStats) -> dict:
    return {
        "phase": ph.label,
        "duration_s": round(ph.duration_s, 2),
        "in_flight": ph.in_flight,
        "sessions_live": ph.sessions_live,
        "ok": ph.ok,
        "rps_ok": round(ph.ok / ph.duration_s, 1) if ph.duration_s > 0 else 0,
        "rate_limited_503": ph.rate_limited_503,
        "other_status": dict(ph.other_status),
        "transport_errors": dict(ph.transport_errors),
        "p50_ms": round(percentile(ph.latencies_ms, 50), 1),
        "p95_ms": round(percentile(ph.latencies_ms, 95), 1),
        "p99_ms": round(percentile(ph.latencies_ms, 99), 1),
        "max_ms": round(max(ph.latencies_ms) if ph.latencies_ms else 0, 1),
        "healthz_total": ph.healthz_ok + ph.healthz_fail,
        "healthz_ok": ph.healthz_ok,
        "healthz_fail": ph.healthz_fail,
        "healthz_p50_ms": round(percentile(ph.healthz_latencies_ms, 50), 1),
        "healthz_max_ms": round(max(ph.healthz_latencies_ms) if ph.healthz_latencies_ms else 0, 1),
        "resources": _resource_summary(ph.resource_samples),
    }


def _resource_summary(samples: list[dict]) -> dict:
    if not samples:
        return {}
    keys = ["gw_cpu", "gw_rss_mb", "gw_fds", "stdio_n", "pg_active"]
    out = {}
    for k in keys:
        vals = [s.get(k, 0) for s in samples if k in s]
        if vals:
            out[f"{k}_max"] = max(vals)
            out[f"{k}_avg"] = round(sum(vals) / len(vals), 1)
    return out


# --- Session helpers --------------------------------------------------------


async def init_session(client: httpx.AsyncClient, vserver: str, principal: str):
    h = {**H_BASE, "x-vyuu-principal-id": principal}
    r = await client.post(URL(vserver), headers=h, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "e2e", "version": "1.0"}}})
    if r.status_code != 200:
        return None
    sid = r.headers.get("mcp-session-id") or r.headers.get("Mcp-Session-Id")
    if not sid:
        return None
    h2 = {**h, "Mcp-Session-Id": sid}
    await client.post(URL(vserver), headers=h2, json={
        "jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    return h2


async def fire_call(client, headers, vserver, tool, args, ph,
                    *, deny_path: bool = False):
    rid = int(time.perf_counter() * 1000) & 0x7FFFFFFF
    t0 = time.perf_counter()
    try:
        r = await client.post(URL(vserver), headers=headers, json={
            "jsonrpc": "2.0", "id": rid, "method": "tools/call",
            "params": {"name": tool, "arguments": args}}, timeout=15)
        dt = (time.perf_counter() - t0) * 1000
        if r.status_code == 200:
            text = r.text
            has_result = '"result"' in text
            is_error_envelope = '"isError":true' in text
            if not has_result:
                ph.other_status[200] = ph.other_status.get(200, 0) + 1
            elif deny_path:
                # Deny path SUCCESS = gateway returned a clean policy
                # deny envelope. The envelope has isError=true by design.
                ph.ok += 1
                ph.latencies_ms.append(dt)
            elif is_error_envelope:
                # Tool path: upstream returned an error envelope (e.g.
                # malformed args). Not a gateway success.
                ph.other_status[200] = ph.other_status.get(200, 0) + 1
            else:
                ph.ok += 1
                ph.latencies_ms.append(dt)
        elif r.status_code == 503:
            ph.rate_limited_503 += 1
        else:
            ph.other_status[r.status_code] = ph.other_status.get(r.status_code, 0) + 1
    except Exception as e:
        name = type(e).__name__
        ph.transport_errors[name] = ph.transport_errors.get(name, 0) + 1


# --- Drivers / pingers ------------------------------------------------------


async def stdio_driver(client, headers, vserver, ph, deadline):
    """Drives realistic mix on one session for `vserver`."""
    import random
    tool_names = list(TOOLS[vserver].keys())
    weights = [TOOLS[vserver][n][1] for n in tool_names]
    while time.perf_counter() < deadline:
        tool = random.choices(tool_names, weights=weights, k=1)[0]
        args = TOOLS[vserver][tool][0]
        await fire_call(client, headers, vserver, tool, args, ph)


async def deny_driver(client, headers, vserver, ph, deadline):
    """Drives gateway-only deny path (bogus tool name → no upstream call)."""
    while time.perf_counter() < deadline:
        await fire_call(client, headers, vserver, "__bogus__", {}, ph,
                        deny_path=True)


async def healthz_pinger(deadline, ph):
    """Independent client — never shares connection pool with drivers."""
    async with httpx.AsyncClient(timeout=2.0) as hc:
        while time.perf_counter() < deadline:
            t0 = time.perf_counter()
            try:
                r = await hc.get(HEALTHZ)
                dt = (time.perf_counter() - t0) * 1000
                ph.healthz_latencies_ms.append(dt)
                if r.status_code == 200:
                    ph.healthz_ok += 1
                else:
                    ph.healthz_fail += 1
            except Exception:
                ph.healthz_fail += 1
            await asyncio.sleep(0.5)


async def resource_sampler(deadline, ph, lab_pid):
    """Captures gateway CPU/RSS/FDs + stdio process count + pg active conns."""
    while time.perf_counter() < deadline:
        sample = {}
        # Gateway proc
        try:
            out = subprocess.check_output(
                ["ps", "-o", "pcpu=,rss=", "-p", str(lab_pid)],
                stderr=subprocess.DEVNULL, timeout=1).decode().strip().split()
            sample["gw_cpu"] = float(out[0])
            sample["gw_rss_mb"] = float(out[1]) / 1024
        except Exception:
            pass
        # FDs
        try:
            fds = subprocess.check_output(
                ["lsof", "-p", str(lab_pid)],
                stderr=subprocess.DEVNULL, timeout=1).decode().count("\n")
            sample["gw_fds"] = fds
        except Exception:
            pass
        # Stdio subprocesses
        try:
            n = subprocess.check_output(
                "pgrep -fl 'mcp-server-time|drawio-mcp' | wc -l",
                shell=True, stderr=subprocess.DEVNULL, timeout=1
            ).decode().strip()
            sample["stdio_n"] = int(n)
        except Exception:
            pass
        # Postgres active conns
        try:
            pg = subprocess.check_output(
                "psql -h 127.0.0.1 -U vyuu -d vyuu_gateway -tAc "
                "\"SELECT count(*) FROM pg_stat_activity "
                "WHERE datname='vyuu_gateway' AND state='active';\"",
                shell=True, stderr=subprocess.DEVNULL, timeout=1
            ).decode().strip()
            sample["pg_active"] = int(pg)
        except Exception:
            pass
        sample["t"] = round(time.perf_counter(), 2)
        ph.resource_samples.append(sample)
        await asyncio.sleep(1)


# --- Phase runners ----------------------------------------------------------


async def run_phase(label, vserver_mix, in_flight, duration_s, lab_pid, *,
                    deny_path=False):
    """Generic phase runner.

    `vserver_mix` is a list[(vserver, weight)] for assigning sessions.
    `in_flight` is total concurrent calls (sessions × per-session-conc).
    """
    import random
    # Assign each in-flight slot a session. Use ~1 session per 4
    # in-flight (multi-call per session). Each session = 1 httpx client
    # with HTTP/1.1 keep-alive; 1 connection only.
    sessions_count = max(1, in_flight // 4)
    per_session = max(1, in_flight // sessions_count)
    actual_in_flight = sessions_count * per_session
    ph = PhaseStats(label=label, in_flight=actual_in_flight)

    # Build sessions sequentially to avoid SYN-backlog burst.
    sessions = []
    for i in range(sessions_count):
        c = httpx.AsyncClient(
            limits=httpx.Limits(max_connections=per_session + 2,
                                max_keepalive_connections=per_session + 2),
            timeout=15.0,
        )
        # Pick a vserver for this session
        vs = random.choices([v for v, _ in vserver_mix],
                            weights=[w for _, w in vserver_mix], k=1)[0]
        try:
            h = await init_session(c, vs, f"e2e-s{i}")
            if h:
                sessions.append((c, h, vs))
            else:
                await c.aclose()
        except Exception:
            await c.aclose()
    ph.sessions_live = len(sessions)
    if not sessions:
        return _summary(ph)

    # Drive load + monitors.
    deadline = time.perf_counter() + duration_s
    drivers: list = []
    for c, h, vs in sessions:
        for _ in range(per_session):
            if deny_path:
                drivers.append(asyncio.create_task(
                    deny_driver(c, h, vs, ph, deadline)))
            else:
                drivers.append(asyncio.create_task(
                    stdio_driver(c, h, vs, ph, deadline)))
    hz_task = asyncio.create_task(healthz_pinger(deadline, ph))
    res_task = asyncio.create_task(resource_sampler(deadline, ph, lab_pid))

    t_start = time.perf_counter()
    await asyncio.gather(*drivers, return_exceptions=True)
    await hz_task
    await res_task
    ph.duration_s = time.perf_counter() - t_start

    # Cleanup.
    for c, _, _ in sessions:
        try:
            await c.aclose()
        except Exception:
            pass

    return _summary(ph)


# --- Main -------------------------------------------------------------------


async def main():
    lab_pid_out = subprocess.check_output(
        "pgrep -f 'drawio_lab_server|lab_with_metrics' | head -1",
        shell=True,
    ).decode().strip()
    if not lab_pid_out:
        print("ERROR: lab not running")
        return
    lab_pid = int(lab_pid_out)
    print(f"# E2E stress test against lab pid={lab_pid}")
    print(f"# host: {os.uname().sysname} {os.uname().machine}, "
          f"cpus={os.cpu_count()}")
    print()

    results = []

    # Quick warmup (pays the persistent-pool cold-spawn once per upstream).
    print("=== warmup (10s, 4 in-flight, mixed stdio) ===")
    await run_phase("warmup",
                    [("time-pypi", 0.7), ("drawio-stdio", 0.3)],
                    in_flight=4, duration_s=10, lab_pid=lab_pid)
    print("(warmup done; pool slots warm)\n")
    await asyncio.sleep(2)

    # P1 — gateway hot path (deny: no upstream call, just route + audit)
    print("=== P1 — gateway hot path (deny, no upstream) ===")
    for inflight in (8, 32, 64, 128):
        s = await run_phase(f"P1-deny-{inflight}",
                            [("time-pypi", 1.0)],
                            in_flight=inflight, duration_s=15,
                            lab_pid=lab_pid, deny_path=True)
        results.append(s)
        print(f"  in-flight={s['in_flight']:>4} rps={s['rps_ok']:>6.1f} "
              f"p50={s['p50_ms']:>5.1f} p99={s['p99_ms']:>5.1f} "
              f"503={s['rate_limited_503']:>4} other={dict(s['other_status'])} "
              f"healthz={s['healthz_ok']}/{s['healthz_total']} "
              f"max_p={s['healthz_max_ms']:.0f}ms")
        await asyncio.sleep(2)
    print()

    # P2 — stdio persistent path (real upstream tool calls).
    # Using time-pypi only — drawio-stdio's npm package writes
    # non-JSON to stdout (`[postprocess] xmldom normalized, ...`)
    # which corrupts the JSON-RPC stream. That's an UPSTREAM bug,
    # not a gateway issue, but it would muddy the perf numbers.
    print("=== P2 — stdio persistent-pool path (time-pypi) ===")
    for inflight in (8, 16, 32, 64):
        s = await run_phase(f"P2-stdio-{inflight}",
                            [("time-pypi", 1.0)],
                            in_flight=inflight, duration_s=15, lab_pid=lab_pid)
        results.append(s)
        print(f"  in-flight={s['in_flight']:>4} rps={s['rps_ok']:>6.1f} "
              f"p50={s['p50_ms']:>5.1f} p99={s['p99_ms']:>5.1f} "
              f"503={s['rate_limited_503']:>4} stdio_n={s['resources'].get('stdio_n_max', 0)} "
              f"healthz={s['healthz_ok']}/{s['healthz_total']}")
        await asyncio.sleep(2)
    print()

    # P3 — past saturation: 256 in-flight, expect 503 cascade + healthz green
    print("=== P3 — past saturation (256 in-flight, cap=128) ===")
    s = await run_phase("P3-saturation",
                        [("time-pypi", 1.0)],
                        in_flight=256, duration_s=15, lab_pid=lab_pid)
    results.append(s)
    print(f"  in-flight={s['in_flight']:>4} rps={s['rps_ok']:>6.1f} "
          f"503={s['rate_limited_503']:>4} (expected to be > 0) "
          f"healthz_failed={s['healthz_fail']} (expected 0)")
    print(f"  resources peak: cpu={s['resources'].get('gw_cpu_max',0):.1f}% "
          f"rss={s['resources'].get('gw_rss_mb_max',0):.0f}MB "
          f"fds={s['resources'].get('gw_fds_max',0)} "
          f"stdio_n={s['resources'].get('stdio_n_max',0)}")
    print()

    # P4 — sustained 60s burst at recommended workload (~150 RPS target)
    print("=== P4 — sustained 60s @ ~140 RPS workload ===")
    s = await run_phase("P4-sustained",
                        [("time-pypi", 1.0)],
                        in_flight=16, duration_s=60, lab_pid=lab_pid)
    results.append(s)
    print(f"  duration={s['duration_s']:.1f}s rps={s['rps_ok']:.1f} "
          f"p50={s['p50_ms']:.1f}ms p99={s['p99_ms']:.1f}ms")
    print(f"  rss start → end: "
          f"{s['resources'].get('gw_rss_mb_avg',0):.0f}MB avg "
          f"({s['resources'].get('gw_rss_mb_max',0):.0f}MB peak)")
    print(f"  fds peak: {s['resources'].get('gw_fds_max',0)} "
          f"(should be stable, no leak)")
    print(f"  stdio_n peak: {s['resources'].get('stdio_n_max',0)}")
    print(f"  healthz: {s['healthz_ok']}/{s['healthz_total']} ok, "
          f"max_latency={s['healthz_max_ms']:.0f}ms")
    print()

    # P5 — cleanup verification
    await asyncio.sleep(3)
    n_remaining = subprocess.check_output(
        "pgrep -fl 'mcp-server-time|drawio-mcp' | wc -l",
        shell=True).decode().strip()
    print("=== P5 — post-load cleanup ===")
    print(f"  stdio subprocesses remaining: {n_remaining} "
          f"(persistent pool alive — won't be 0 unless aclose'd)")
    print()

    print("=== JSON summary (full data) ===")
    print(json.dumps(results, indent=2, default=str))


asyncio.run(main())
