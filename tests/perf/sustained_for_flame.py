"""Drive sustained mid-saturation load for flame-graph capture.

Pairs with py-spy attached to the gateway PID. Runs 32 in-flight calls
across 8 sessions × 4 concurrent each for a configurable duration. Mirrors
the P2 stdio-persistent-pool path from e2e_stress so the flame graph
samples real upstream tool calls.
"""
from __future__ import annotations

import argparse
import asyncio
import time

import httpx

TENANT = "11111111-1111-1111-1111-111111111111"
VSERVER = "time-pypi"
URL = f"http://127.0.0.1:8000/v/{TENANT}/{VSERVER}/mcp"

H_BASE = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "x-vyuu-tenant-id": TENANT,
    "x-vyuu-principal-type": "endpoint_session",
    "x-vyuu-principal-display": "flame",
}


async def init_session(client: httpx.AsyncClient, principal: str) -> dict | None:
    h = {**H_BASE, "x-vyuu-principal-id": principal}
    r = await client.post(URL, headers=h, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "flame", "version": "1.0"}}})
    if r.status_code != 200:
        return None
    sid = r.headers.get("mcp-session-id") or r.headers.get("Mcp-Session-Id")
    if not sid:
        return None
    h2 = {**h, "Mcp-Session-Id": sid}
    await client.post(URL, headers=h2, json={
        "jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    return h2


async def driver(client: httpx.AsyncClient, headers: dict, deadline: float,
                 stats: dict) -> None:
    while time.perf_counter() < deadline:
        rid = int(time.perf_counter() * 1000) & 0x7FFFFFFF
        try:
            r = await client.post(URL, headers=headers, json={
                "jsonrpc": "2.0", "id": rid, "method": "tools/call",
                "params": {"name": "get_current_time",
                           "arguments": {"timezone": "UTC"}}}, timeout=15)
            if r.status_code == 200 and '"result"' in r.text:
                stats["ok"] += 1
            elif r.status_code == 503:
                stats["rate_limited"] += 1
            else:
                stats["other"] += 1
        except Exception:
            stats["transport_err"] += 1


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--sessions", type=int, default=8)
    ap.add_argument("--per-session", type=int, default=4)
    args = ap.parse_args()

    in_flight = args.sessions * args.per_session
    print(f"# Sustained load: {in_flight} in-flight ({args.sessions} "
          f"sessions × {args.per_session}), duration={args.duration}s")

    limits = httpx.Limits(max_connections=in_flight * 2,
                          max_keepalive_connections=in_flight * 2)
    client = httpx.AsyncClient(timeout=15.0, limits=limits)
    try:
        headers_list = []
        for i in range(args.sessions):
            h = await init_session(client, f"flame-{i}")
            if h is None:
                print(f"# session {i} init failed — skipping")
                continue
            headers_list.append(h)
        print(f"# {len(headers_list)} sessions initialized")

        stats = {"ok": 0, "rate_limited": 0, "other": 0, "transport_err": 0}
        deadline = time.perf_counter() + args.duration
        t0 = time.perf_counter()
        tasks = [
            asyncio.create_task(driver(client, h, deadline, stats))
            for h in headers_list
            for _ in range(args.per_session)
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        dt = time.perf_counter() - t0
        rps = stats["ok"] / dt if dt > 0 else 0
        print(f"# done in {dt:.1f}s — ok={stats['ok']} "
              f"rate_limited={stats['rate_limited']} "
              f"other={stats['other']} transport_err={stats['transport_err']} "
              f"rps_ok={rps:.1f}")
    finally:
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(main())
