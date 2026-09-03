"""Boot the drawio lab with the test-only metrics middleware attached.

**Test/perf-only.** Production deployments use `examples/drawio_lab_server.py`
or the manifests in `deploy/`; neither imports this module. The
metrics middleware is appended at the OUTSIDE of the FastAPI app's
middleware stack (so it sees raw inbound requests + final responses,
including 503s from the per-tenant inflight gate).

Run:
    python tests/perf/lab_with_metrics.py

What you get on the host:
    http://127.0.0.1:8000/      — gateway (operator console / portal / MCP)
    http://127.0.0.1:8000/healthz — liveness (bypasses metrics + gate)
    http://127.0.0.1:8000/metrics — Prometheus exposition (in-process)

Pair with `exporter.py --gateway-pid <pid>` for system-side metrics
on `:9100`, and `docker-compose up -d` for the Prometheus + Grafana stack.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import uvicorn

# Boot the drawio lab the same way `examples/drawio_lab_server.py` does,
# then attach the metrics middleware. Reusing the existing module keeps
# drift to a minimum — anything `_build_lab_app()` knows about (env-var
# secret seeding, identity provider toggle, oauth-authcode etc.) shows
# up here automatically.
EXAMPLES_DIR = Path(__file__).parent.parent.parent / "examples"
sys.path.insert(0, str(EXAMPLES_DIR))
from drawio_lab_server import (  # noqa: E402
    LAB_HOST,
    LAB_PORT,
    _build_lab_app,
    _print_banner,
    _print_claude_desktop_config,
    _print_cursor_config,
    _print_footer,
    _print_operator_token,
)

# Local import — kept after the lab import so `tests/perf/` files can
# share it without circular concerns. The middleware is opt-in, NOT
# imported by anything under `src/vyuu_gateway/`.
PERF_DIR = Path(__file__).parent
sys.path.insert(0, str(PERF_DIR.parent.parent))
from tests.perf.metrics_middleware import attach_metrics  # noqa: E402


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = _build_lab_app()
    attach_metrics(app)
    settings = app.state.settings

    _print_banner()
    _print_operator_token()
    _print_cursor_config()
    _print_claude_desktop_config()
    _print_footer()
    print("=" * 78)
    print(f"Test-only metrics middleware attached. /metrics exposed on "
          f"http://{LAB_HOST}:{LAB_PORT}/metrics")
    print(f"PID: {os.getpid()}  (pass to exporter.py via --gateway-pid)")
    print("=" * 78)
    print()

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


if __name__ == "__main__":
    main()
