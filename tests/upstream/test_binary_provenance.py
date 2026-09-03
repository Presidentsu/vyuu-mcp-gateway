"""S1.b · Sigstore/cosign provenance for `binary` upstreams.

S1 shipped path validation — absolute, no traversal, exists, executable,
optionally allowlisted. All of that answers "is this a sane path?".
**None of it answers "is this the file the vendor shipped?"**, and
`binary` is the one source type where the gateway executes code it did
not fetch. An attacker with write access to the connector directory gets
code execution inside the gateway process tree while every S1 check still
passes.

The tests that carry the most weight are the ones asserting failure is
*loud*:

- `test_missing_cosign_is_a_hard_failure_not_a_skip` — a deployment that
  configured a key has said "only signed binaries run". "We could not
  check" does not satisfy that, and a skip here would silently revert the
  control while leaving the config in place looking effective.
- `test_timeout_kills_and_reaps_the_subprocess` — a hung cosign must not
  wedge upstream builds *or* leave a zombie for the life of the process.

`cosign` itself is stubbed: these must be deterministic and must not
require the binary to be installed.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from vyuu_gateway.upstream import binary_provenance
from vyuu_gateway.upstream.binary_provenance import (
    BinaryProvenanceError,
    CosignPolicy,
    signature_path_for,
    verify_binary,
)


class _FakeProcess:
    def __init__(self, returncode: int, stderr: bytes = b"", hang: bool = False) -> None:
        self.returncode = returncode
        self._stderr = stderr
        self._hang = hang
        self.killed = False
        self.waited = False

    async def communicate(self) -> tuple[bytes, bytes]:
        if self._hang:
            await asyncio.sleep(3600)
        return b"", self._stderr

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        self.waited = True
        return -9


def _stub(monkeypatch: pytest.MonkeyPatch, process: _FakeProcess) -> list[list[str]]:
    """Replace cosign discovery + spawn. Returns the captured argv list."""

    calls: list[list[str]] = []

    async def fake_exec(*argv: str, **kw: Any) -> _FakeProcess:
        calls.append(list(argv))
        return process

    monkeypatch.setattr(binary_provenance.shutil, "which", lambda _n: "/usr/bin/cosign")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    return calls


@pytest.fixture
def signed_binary(tmp_path: Path) -> str:
    binary = tmp_path / "falcon-mcp"
    binary.write_bytes(b"#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    (tmp_path / "falcon-mcp.sig").write_text("SIGNATURE")
    return str(binary)


ENABLED = CosignPolicy(verification_key_path="/keys/vendor.pub")


# --- Disabled by default ----------------------------------------------------


def test_no_key_configured_is_a_no_op(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pre-S1.b behaviour is preserved exactly: no key, no verification,
    no cosign requirement."""

    def explode(*a: Any, **k: Any) -> Any:
        raise AssertionError("cosign must not be consulted when disabled")

    monkeypatch.setattr(binary_provenance.shutil, "which", explode)
    asyncio.run(verify_binary("/opt/whatever", CosignPolicy()))


def test_policy_enabled_flag_tracks_the_key() -> None:
    assert CosignPolicy().enabled is False
    assert ENABLED.enabled is True


# --- Failure must be loud ---------------------------------------------------


def test_missing_cosign_is_a_hard_failure_not_a_skip(
    monkeypatch: pytest.MonkeyPatch, signed_binary: str
) -> None:
    """A configured key is a statement about what may run. Skipping when
    the tool is absent would revert the control while leaving the config
    in place looking effective — the worst of both."""

    monkeypatch.setattr(binary_provenance.shutil, "which", lambda _n: None)
    with pytest.raises(BinaryProvenanceError, match="not on PATH"):
        asyncio.run(verify_binary(signed_binary, ENABLED))


def test_missing_signature_file_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = tmp_path / "unsigned"
    binary.write_bytes(b"x")
    _stub(monkeypatch, _FakeProcess(0))
    with pytest.raises(BinaryProvenanceError, match="no signature found"):
        asyncio.run(verify_binary(str(binary), ENABLED))


def test_bad_signature_is_refused_and_reports_cosign_stderr(
    monkeypatch: pytest.MonkeyPatch, signed_binary: str
) -> None:
    _stub(monkeypatch, _FakeProcess(1, stderr=b"Error: signature mismatch"))
    with pytest.raises(BinaryProvenanceError) as exc:
        asyncio.run(verify_binary(signed_binary, ENABLED))
    assert "signature mismatch" in str(exc.value)


def test_cosign_stderr_is_bounded_and_flattened(
    monkeypatch: pytest.MonkeyPatch, signed_binary: str
) -> None:
    """stderr is subprocess output acting on operator-supplied paths. It
    must not be able to flood the log or forge structure in it."""

    noisy = (b"line\n" * 500) + b"tail"
    _stub(monkeypatch, _FakeProcess(1, stderr=noisy))
    with pytest.raises(BinaryProvenanceError) as exc:
        asyncio.run(verify_binary(signed_binary, ENABLED))
    message = str(exc.value)
    assert "\n" not in message
    assert len(message) < 500


def test_timeout_kills_and_reaps_the_subprocess(
    monkeypatch: pytest.MonkeyPatch, signed_binary: str
) -> None:
    """A hung cosign (e.g. reaching for a transparency log on an isolated
    host) must not wedge upstream builds — and must not leave a zombie
    for the life of the gateway."""

    process = _FakeProcess(0, hang=True)
    _stub(monkeypatch, process)
    monkeypatch.setattr(binary_provenance, "_COSIGN_TIMEOUT_SECONDS", 0.05)
    with pytest.raises(BinaryProvenanceError, match="timed out"):
        asyncio.run(verify_binary(signed_binary, ENABLED))
    assert process.killed is True
    assert process.waited is True, "killed subprocess was never reaped"


def test_spawn_failure_is_refused(
    monkeypatch: pytest.MonkeyPatch, signed_binary: str
) -> None:
    async def boom(*a: Any, **k: Any) -> Any:
        raise OSError("exec format error")

    monkeypatch.setattr(binary_provenance.shutil, "which", lambda _n: "/usr/bin/cosign")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", boom)
    with pytest.raises(BinaryProvenanceError, match="could not run cosign"):
        asyncio.run(verify_binary(signed_binary, ENABLED))


# --- Success path + argv ----------------------------------------------------


def test_valid_signature_passes(
    monkeypatch: pytest.MonkeyPatch, signed_binary: str
) -> None:
    _stub(monkeypatch, _FakeProcess(0))
    asyncio.run(verify_binary(signed_binary, ENABLED))


def test_argv_passes_key_signature_and_binary(
    monkeypatch: pytest.MonkeyPatch, signed_binary: str
) -> None:
    calls = _stub(monkeypatch, _FakeProcess(0))
    asyncio.run(verify_binary(signed_binary, ENABLED))
    argv = calls[0]
    assert argv[1] == "verify-blob"
    assert "--key" in argv and "/keys/vendor.pub" in argv
    assert "--signature" in argv
    assert signature_path_for(signed_binary, ENABLED).name in " ".join(argv)
    # The binary itself is the final positional — cosign's contract.
    assert argv[-1] == signed_binary


def test_keyless_identity_constraints_are_passed_through(
    monkeypatch: pytest.MonkeyPatch, signed_binary: str
) -> None:
    """The operator's signer policy belongs in one place; cosign is the
    thing that actually evaluates it."""

    policy = CosignPolicy(
        verification_key_path="/keys/vendor.pub",
        certificate_identity="release@vendor.example",
        certificate_oidc_issuer="https://token.actions.githubusercontent.com",
    )
    calls = _stub(monkeypatch, _FakeProcess(0))
    asyncio.run(verify_binary(signed_binary, policy))
    argv = calls[0]
    assert "--certificate-identity" in argv
    assert "release@vendor.example" in argv
    assert "--certificate-oidc-issuer" in argv


def test_signature_suffix_is_configurable(tmp_path: Path) -> None:
    policy = CosignPolicy(verification_key_path="/k", signature_suffix=".cosign.sig")
    assert signature_path_for("/opt/x", policy) == Path("/opt/x.cosign.sig")
