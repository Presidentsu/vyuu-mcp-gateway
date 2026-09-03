"""Regression test for the operator-console + portal JavaScript.

Why this exists: the operator UI ships HTML/CSS/JS as Python triple-
quoted string constants in `vyuu_gateway/api/operator_ui.py` (and the
sibling `portal_ui.py`). It's easy to write `"\n"` in those strings
expecting the JS string-literal `\n`, but Python interprets it as a
literal newline — which silently breaks the JS at the browser when
served. Symptom: page loads, every form handler is missing because
the inline script halts at the unterminated string, and submitting
any form does a default browser navigation that wipes the auth state
and the panel renders.

This test catches that class of bug at CI time by running `node
--check` over the served JS bytes. Skipped automatically when node is
not on PATH so it doesn't gate CI on an extra runtime dependency, but
locally + in any CI image with node it's a hard parse-time check.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from vyuu_gateway.api.operator_ui import _JS as OPERATOR_JS
from vyuu_gateway.api.portal_ui import _JS as PORTAL_JS

NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None, reason="node not on PATH")
def test_operator_js_parses_under_node_check() -> None:
    _assert_js_parses(OPERATOR_JS, label="operator_ui")


@pytest.mark.skipif(NODE is None, reason="node not on PATH")
def test_portal_js_parses_under_node_check() -> None:
    _assert_js_parses(PORTAL_JS, label="portal_ui")


def _assert_js_parses(source: str, *, label: str) -> None:
    """Write the served JS to a temp file and run `node --check` over it.

    Same parser the browser uses (V8); catches every syntax error a
    real client would hit, including the `"\\n"`-leaks-as-newline bug
    that motivated this test.
    """

    assert NODE is not None  # narrowed for mypy
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
        fh.write(source)
        path = Path(fh.name)
    try:
        result = subprocess.run(
            [NODE, "--check", str(path)],
            capture_output=True,
            timeout=10,
        )
    finally:
        path.unlink(missing_ok=True)
    assert result.returncode == 0, (
        f"{label} JS failed `node --check`:\n"
        f"stdout: {result.stdout.decode(errors='replace')}\n"
        f"stderr: {result.stderr.decode(errors='replace')}"
    )
