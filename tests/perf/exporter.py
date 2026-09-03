"""Standalone Prometheus exporter for gateway-adjacent system metrics.

**Test/perf-only.** Polls things the in-process middleware can't see:
the gateway's host process metrics (CPU/RSS/FDs), stdio MCP subprocess
counts, Postgres active connection count.

Run alongside `lab_with_metrics.py` (which provides the in-process
metrics on `:8000/metrics`):

    python tests/perf/exporter.py --gateway-pid 12345 --port 9100

The local `docker-compose.yml` Prometheus is configured to scrape
both endpoints. Tear down: SIGINT.
"""
from __future__ import annotations

import argparse
import logging
import shutil
import subprocess
import sys
import time

from prometheus_client import Gauge, start_http_server

logger = logging.getLogger("vyuu-exporter")


def _run(cmd: list[str], timeout: float = 1.0) -> str:
    """Run a subprocess and return its stdout (stripped). Empty string on failure."""
    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=timeout
        )
        return out.decode("utf-8", errors="replace").strip()
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return ""


def _gateway_cpu_rss(pid: int) -> tuple[float, float]:
    """Return (cpu_percent, rss_bytes). 0,0 on failure."""
    out = _run(["ps", "-o", "pcpu=,rss=", "-p", str(pid)])
    parts = out.split()
    if len(parts) >= 2:
        try:
            return float(parts[0]), float(parts[1]) * 1024  # rss in KiB → bytes
        except ValueError:
            pass
    return 0.0, 0.0


def _gateway_fds(pid: int) -> int:
    """Open file descriptor count. Uses lsof; 0 if unavailable."""
    if not shutil.which("lsof"):
        return 0
    out = _run(["lsof", "-p", str(pid)], timeout=2.0)
    if not out:
        return 0
    return out.count("\n")


def _stdio_count_and_rss(patterns: list[str]) -> tuple[int, float]:
    """Sum subprocess count + RSS for stdio MCPs matching `patterns`."""
    if not shutil.which("pgrep"):
        return 0, 0.0
    total_count = 0
    total_rss_bytes = 0.0
    for pat in patterns:
        pids = _run(["pgrep", "-f", pat])
        if not pids:
            continue
        for pid in pids.splitlines():
            total_count += 1
            out = _run(["ps", "-o", "rss=", "-p", pid.strip()])
            try:
                total_rss_bytes += float(out) * 1024
            except ValueError:
                pass
    return total_count, total_rss_bytes


def _pg_active_conns(database_url: str | None, db_name: str) -> int:
    if not shutil.which("psql"):
        return 0
    cmd = [
        "psql",
        *(["-d", database_url] if database_url else ["-h", "127.0.0.1",
                                                       "-U", "vyuu",
                                                       "-d", db_name]),
        "-tAc",
        "SELECT count(*) FROM pg_stat_activity "
        f"WHERE datname='{db_name}' AND state='active'",
    ]
    out = _run(cmd, timeout=2.0)
    try:
        return int(out)
    except ValueError:
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Vyuu gateway perf exporter — system-side metrics"
    )
    parser.add_argument("--gateway-pid", type=int, required=True,
                        help="PID of the gateway process to observe")
    parser.add_argument("--port", type=int, default=9100,
                        help="Prometheus exposition port (default 9100)")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Poll interval in seconds (default 1.0)")
    parser.add_argument("--db-name", default="vyuu_gateway",
                        help="Postgres database name to count connections in")
    parser.add_argument("--database-url", default=None,
                        help="Optional Postgres connection URL for psql")
    parser.add_argument("--stdio-pattern",
                        action="append",
                        default=None,
                        help="Patterns to match stdio MCP subprocesses "
                             "(default: mcp-server-time, drawio-mcp, "
                             "falcon-mcp). May be passed multiple times.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    patterns = args.stdio_pattern or [
        "mcp-server-time", "drawio-mcp", "falcon-mcp"
    ]

    # Metrics. All test-only; not shipped in the gateway codebase.
    g_cpu = Gauge("vyuu_proc_cpu_percent", "Gateway process CPU%")
    g_rss = Gauge("vyuu_proc_rss_bytes", "Gateway process RSS bytes")
    g_fds = Gauge("vyuu_proc_fds", "Gateway process open file descriptors")
    g_stdio_n = Gauge(
        "vyuu_stdio_subprocess_count",
        "Live stdio MCP subprocesses spawned by the gateway",
    )
    g_stdio_rss = Gauge(
        "vyuu_stdio_subprocess_rss_bytes",
        "Combined RSS of all stdio MCP subprocesses",
    )
    g_pg = Gauge(
        "vyuu_postgres_active_connections",
        "Active Postgres connections held by the gateway",
    )
    g_alive = Gauge("vyuu_proc_alive",
                    "1 if the gateway PID is alive, 0 otherwise")

    start_http_server(args.port)
    logger.info("exporter_started pid=%d port=%d interval=%.1fs patterns=%s",
                args.gateway_pid, args.port, args.interval, patterns)
    logger.info("exposition_url=http://127.0.0.1:%d/metrics", args.port)

    try:
        while True:
            cpu, rss = _gateway_cpu_rss(args.gateway_pid)
            g_alive.set(1 if rss > 0 else 0)
            g_cpu.set(cpu)
            g_rss.set(rss)
            g_fds.set(_gateway_fds(args.gateway_pid))
            n, total_rss = _stdio_count_and_rss(patterns)
            g_stdio_n.set(n)
            g_stdio_rss.set(total_rss)
            g_pg.set(_pg_active_conns(args.database_url, args.db_name))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        logger.info("exporter_stopped")
        return 0


if __name__ == "__main__":
    sys.exit(main())
