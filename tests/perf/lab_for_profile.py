"""Boot the lab inside cProfile, dumping a .prof on SIGTERM/SIGINT.

Pairs with `sustained_for_flame.py` for flame-graph capture WITHOUT
requiring root (which py-spy needs on macOS due to SIP).

Usage:
    # T1
    python tests/perf/lab_for_profile.py            # writes /tmp/flame/lab.prof on shutdown
    # T2 (after lab is up)
    python tests/perf/sustained_for_flame.py --duration 60
    # then SIGINT lab — cProfile flushes /tmp/flame/lab.prof
    # then: flameprof /tmp/flame/lab.prof > /tmp/flame/lab.svg

Caveats: cProfile is deterministic, not sampling — it inflates wall time
and slightly distorts hot-path ranking compared to py-spy. Useful for
spotting top callees by cumulative time, which is what we need here.
"""
from __future__ import annotations

import atexit
import cProfile
import logging
import os
import sys
from pathlib import Path

import uvicorn

EXAMPLES_DIR = Path(__file__).parent.parent.parent / "examples"
sys.path.insert(0, str(EXAMPLES_DIR))
from drawio_lab_server import (  # noqa: E402
    LAB_HOST,
    LAB_PORT,
    _build_lab_app,
    _print_banner,
    _print_footer,
    _print_operator_token,
)

PERF_DIR = Path(__file__).parent
sys.path.insert(0, str(PERF_DIR.parent.parent))
from tests.perf.metrics_middleware import attach_metrics  # noqa: E402

PROF_OUT = Path(os.environ.get("FLAME_PROF_OUT", "/tmp/flame/lab.prof"))


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = _build_lab_app()
    attach_metrics(app)
    settings = app.state.settings

    _print_banner()
    _print_operator_token()
    _print_footer()
    print("=" * 78)
    print(f"PROFILED LAB — output: {PROF_OUT}")
    print(f"PID: {os.getpid()}  (kill with SIGINT to flush profile)")
    print("=" * 78)

    PROF_OUT.parent.mkdir(parents=True, exist_ok=True)
    profiler = cProfile.Profile()

    def _flush() -> None:
        try:
            profiler.disable()
            profiler.dump_stats(str(PROF_OUT))
            print(f"\n[profile] stats written to {PROF_OUT}", flush=True)
        except Exception as e:
            print(f"\n[profile] failed to dump stats: {e}", flush=True)

    atexit.register(_flush)

    profiler.enable()
    try:
        uvicorn.run(
            app,
            host=LAB_HOST,
            port=LAB_PORT,
            log_level="info",
            limit_concurrency=settings.inbound_limit_concurrency,
            limit_max_requests=(
                settings.inbound_limit_max_requests
                if settings.inbound_limit_max_requests > 0 else None
            ),
            backlog=settings.inbound_backlog,
            timeout_keep_alive=settings.inbound_keep_alive_seconds,
        )
    finally:
        _flush()


if __name__ == "__main__":
    main()
