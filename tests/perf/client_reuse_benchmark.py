"""P1 / P3 · does one-shot httpx client construction actually cost us?

Both `P1 · Per-passthrough connection pool` and `P3 · single shared httpx
client for token refreshes` are recorded in `BACKLOG.md` with the same
blocker: *"hold off until measurement shows it matters"*. This is that
measurement. It is deliberately NOT part of the test suite — timing
assertions are flaky, and the output here is a number for a human to
read, not a pass/fail.

## What it measures

Two shapes the gateway actually uses today:

- **one-shot** — `async with httpx.AsyncClient() as c: await c.post(...)`,
  which is what `CachedOAuthTokenProvider._refresh` (P3) and the
  passthrough path (P1) do. A fresh connection, and on https a fresh TLS
  handshake, per call.
- **reused** — one client for the whole run, which is what both items
  propose.

## Read the https numbers, not the http ones

Over plain http the difference is a TCP handshake on loopback:
microseconds, and misleadingly small. The cost these items are really
about is the **TLS handshake**, which is where the asymmetric crypto is.
Against a remote auth server it is also a round-trip that loopback
cannot simulate at all — so treat the local https delta as a *floor*,
not an estimate.

## How to read the result

The deciding question is not "is reuse faster" — it always is. It is
whether the saving is material at the gateway's actual call rate. Token
refreshes happen once per token lifetime (minutes to hours), so even a
large per-call delta may be worth nothing; passthrough tool calls can be
per-request, where the same delta matters. The script prints per-call
cost so you can multiply by your own rate.

Usage:

    python3 tests/perf/client_reuse_benchmark.py            # http + https
    python3 tests/perf/client_reuse_benchmark.py --calls 200
"""

from __future__ import annotations

import argparse
import asyncio
import ssl
import statistics
import time
from typing import Any

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route


def _app() -> Starlette:
    async def token(request: Any) -> JSONResponse:
        # Shaped like a real token response so the JSON parse is not
        # trivially smaller than production's.
        return JSONResponse(
            {"access_token": "a" * 512, "token_type": "Bearer", "expires_in": 3600}
        )

    return Starlette(routes=[Route("/token", token, methods=["POST"])])


async def _one_shot(url: str, calls: int, verify: Any) -> list[float]:
    """A fresh client per call — today's behaviour."""
    samples: list[float] = []
    for _ in range(calls):
        started = time.perf_counter()
        async with httpx.AsyncClient(verify=verify) as client:
            await client.post(url, data={"grant_type": "client_credentials"})
        samples.append(time.perf_counter() - started)
    return samples


async def _reused(url: str, calls: int, verify: Any) -> list[float]:
    """One client for the whole run — what P1 / P3 propose."""
    samples: list[float] = []
    async with httpx.AsyncClient(verify=verify) as client:
        for _ in range(calls):
            started = time.perf_counter()
            await client.post(url, data={"grant_type": "client_credentials"})
            samples.append(time.perf_counter() - started)
    return samples


def _summarise(label: str, samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    stats = {
        "mean_ms": statistics.fmean(samples) * 1000,
        "p50_ms": ordered[len(ordered) // 2] * 1000,
        "p95_ms": ordered[int(len(ordered) * 0.95)] * 1000,
    }
    print(
        f"  {label:<10} mean {stats['mean_ms']:7.3f} ms   "
        f"p50 {stats['p50_ms']:7.3f} ms   p95 {stats['p95_ms']:7.3f} ms"
    )
    return stats


async def _run_scheme(scheme: str, port: int, calls: int, verify: Any) -> None:
    url = f"{scheme}://127.0.0.1:{port}/token"
    print(f"\n{scheme.upper()}  ({calls} calls)")
    # Warm up so the first-call import/JIT cost lands in neither column.
    await _reused(url, 5, verify)
    one_shot = _summarise("one-shot", await _one_shot(url, calls, verify))
    reused = _summarise("reused", await _reused(url, calls, verify))
    delta = one_shot["mean_ms"] - reused["mean_ms"]
    print(f"  → reuse saves {delta:.3f} ms per call ({delta / one_shot['mean_ms']:.0%})")
    print(
        f"    at 1 call/s that is {delta:.1f} ms/s; "
        f"at 100 calls/s, {delta * 100 / 1000:.2f} s/s of wall clock"
    )


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--calls", type=int, default=100)
    parser.add_argument("--port", type=int, default=8899)
    args = parser.parse_args()

    config = uvicorn.Config(
        _app(), host="127.0.0.1", port=args.port, log_level="error"
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.02)
    try:
        await _run_scheme("http", args.port, args.calls, verify=False)
        print(
            "\nNOTE: the http numbers are a TCP handshake on loopback and are "
            "\nmisleadingly small. The cost P1/P3 are about is the TLS "
            "\nhandshake and the network round-trip to a REMOTE auth server, "
            "\nneither of which loopback reproduces. Treat any local delta as "
            "\na floor."
        )
    finally:
        server.should_exit = True
        await task


if __name__ == "__main__":
    ssl  # noqa: B018 — imported for the https note above
    asyncio.run(main())
