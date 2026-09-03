"""S1.b · Cosign / Sigstore signature verification for `binary` upstreams.

S1 shipped *path* validation: absolute, no traversal, no metacharacters,
exists, executable, optionally allowlisted. All of that answers "is this
a sane path?" — none of it answers **"is this the file the vendor
shipped?"**

That gap matters because `binary` is the one source type where the
gateway executes code it did not fetch. An npm or pypi upstream at least
came from a registry with its own integrity story; a binary is whatever
is on disk at that path when we spawn it. An attacker with write access
to the connector directory — or a botched deploy that half-replaced a
file — gets arbitrary code execution inside the gateway process tree,
and every path check above still passes.

## Verify at launch, not only at registration

Registration-time verification proves the file was good *once*. The whole
threat is the file changing afterwards, so verification runs on every
client build — which is once per pooled connection, not per tool call.

## Shelling out to `cosign`

Deliberate, over binding a Python Sigstore library:

- `cosign` is what the vendor's release pipeline produced the signature
  with, so it is the implementation whose semantics match the artifact.
- Verification is a *build-time-ish* operation on a cold path; a
  subprocess costs milliseconds we are already spending spawning the
  upstream itself.
- It keeps a security-critical crypto dependency out of our import graph.

The cost is that `cosign` must be present. That is why verification is
**opt-in per deployment**: a gateway with no key configured behaves
exactly as it did before S1.b. But once a key IS configured, a missing
`cosign` binary is a hard failure, not a skip — "we could not check" must
never silently mean "it is fine".
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# Verification is a cold-path operation, but a hung `cosign` (say, one
# that tries to reach a transparency log on a network-isolated host)
# must not wedge the upstream build forever.
_COSIGN_TIMEOUT_SECONDS = 20.0


class BinaryProvenanceError(Exception):
    """A binary failed signature verification, or could not be verified.

    Both cases raise. A deployment that configured a verification key has
    said "only run signed binaries", and "we were unable to check" does
    not satisfy that.
    """


@dataclass(frozen=True)
class CosignPolicy:
    """Per-deployment Sigstore verification settings.

    `verification_key_path` is the switch: unset means no verification,
    which is the pre-S1.b behaviour and the lab default.
    """

    verification_key_path: str | None = None
    # Optional expected signer identity, for keyless/OIDC signatures.
    # Checked by cosign itself; passed through so the operator's policy
    # lives in one place.
    certificate_identity: str | None = None
    certificate_oidc_issuer: str | None = None
    # Where to find the detached signature. `None` means "alongside the
    # binary, with a .sig suffix", which is what `cosign sign-blob
    # --output-signature` produces by default.
    signature_suffix: str = ".sig"

    @property
    def enabled(self) -> bool:
        return bool(self.verification_key_path)


def signature_path_for(binary_path: str, policy: CosignPolicy) -> Path:
    return Path(f"{binary_path}{policy.signature_suffix}")


async def verify_binary(binary_path: str, policy: CosignPolicy) -> None:
    """Verify a binary's detached Sigstore signature.

    No-op when the policy is disabled. Raises `BinaryProvenanceError` on
    any outcome that is not a clean pass — including cosign being absent,
    the signature file being missing, and the subprocess timing out.
    """

    if not policy.enabled:
        return

    cosign = shutil.which("cosign")
    if cosign is None:
        # Hard failure, not a skip. See the module docstring: a
        # configured key is a statement about what may run.
        raise BinaryProvenanceError(
            "signature verification is enabled but `cosign` is not on PATH; "
            "install cosign or unset the verification key"
        )

    signature = signature_path_for(binary_path, policy)
    if not signature.is_file():
        raise BinaryProvenanceError(
            f"no signature found at {signature} for binary {binary_path}"
        )

    argv = [
        cosign,
        "verify-blob",
        "--key",
        str(policy.verification_key_path),
        "--signature",
        str(signature),
    ]
    if policy.certificate_identity:
        argv += ["--certificate-identity", policy.certificate_identity]
    if policy.certificate_oidc_issuer:
        argv += ["--certificate-oidc-issuer", policy.certificate_oidc_issuer]
    argv.append(binary_path)

    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        raise BinaryProvenanceError(
            f"could not run cosign: {exc.__class__.__name__}"
        ) from exc

    try:
        _stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=_COSIGN_TIMEOUT_SECONDS
        )
    except TimeoutError as exc:
        process.kill()
        # Reap, so a killed cosign does not become a zombie for the life
        # of the gateway process.
        await process.wait()
        raise BinaryProvenanceError(
            f"cosign timed out after {_COSIGN_TIMEOUT_SECONDS}s verifying "
            f"{binary_path}"
        ) from exc

    if process.returncode != 0:
        # cosign's stderr is the useful diagnostic, but it is output from
        # a subprocess acting on operator-supplied paths — bounded and
        # newline-flattened so it cannot flood or forge log structure.
        detail = (stderr or b"").decode("utf-8", "replace").strip()
        detail = " ".join(detail.split())[:300]
        logger.warning(
            "binary_signature_verification_failed",
            extra={"binary_path": binary_path, "cosign_stderr": detail},
        )
        raise BinaryProvenanceError(
            f"signature verification failed for {binary_path}: {detail}"
        )

    logger.info("binary_signature_verified", extra={"binary_path": binary_path})
