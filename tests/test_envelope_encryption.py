"""AWS-KMS-1 · envelope encryption for data the gateway stores itself.

The row this exists for is `oauth_user_tokens`. Its own model docstring
said the quiet part out loud: *"Tokens are stored as plaintext (DB
at-rest encryption is the operator's responsibility for v1)."*

A refresh token is durable delegated access to a user's GitHub, Google
Drive, Slack or Notion. Plaintext means a database dump, a backup, a read
replica, or a `pg_dump` pasted into a support ticket hands over every
user's connected accounts at once — and unlike a leaked password, nobody
can tell it happened and nothing rotates. Postgres-level at-rest
encryption does not help: it defends against disk theft, not against
anything that can already run a SELECT.

The tests that carry the weight:

- `test_a_ciphertext_moved_between_rows_fails_to_open` — the attack
  available to anyone with write-but-not-read access. AAD binds each
  value to its row so this fails authentication instead of quietly
  granting one user another's token.
- `test_existing_plaintext_rows_keep_working` — the property that makes
  enabling encryption a no-downtime change rather than a flag day, which
  is the difference between a control that gets enabled and one that
  doesn't.
- `test_disabling_encryption_refuses_to_read_sealed_rows` — turning it
  off must not silently feed ciphertext to an upstream, which surfaces as
  a baffling 401 rather than "your key is missing".
"""

from __future__ import annotations

import base64
import os
from uuid import uuid4

import pytest

from vyuu_gateway.crypto import (
    ENVELOPE_PREFIX,
    EnvelopeCipher,
    EnvelopeDecryptError,
    LocalMasterKeyProvider,
    NullEnvelopeCipher,
    is_envelope,
    seal_token,
    token_aad,
    unseal_token,
)

TENANT, USER, SERVER = uuid4(), uuid4(), uuid4()


def _cipher() -> EnvelopeCipher:
    return EnvelopeCipher(LocalMasterKeyProvider(os.urandom(32)))


def _row_kwargs(**overrides: object) -> dict:
    kwargs = {
        "tenant_id": TENANT,
        "user_id": USER,
        "server_id": SERVER,
        "field": "refresh_token",
    }
    kwargs.update(overrides)
    return kwargs


# --- Core round trip --------------------------------------------------------


def test_round_trip() -> None:
    cipher = _cipher()
    sealed = seal_token(cipher, "rt-secret", **_row_kwargs())
    assert sealed is not None and sealed.startswith(ENVELOPE_PREFIX)
    assert "rt-secret" not in sealed
    assert unseal_token(cipher, sealed, **_row_kwargs()) == "rt-secret"


def _segments(sealed: str) -> tuple[str, str, str]:
    wrapped, nonce, ciphertext = sealed[len(ENVELOPE_PREFIX):].split(":")
    return wrapped, nonce, ciphertext


def test_each_value_gets_a_fresh_data_key_and_nonce() -> None:
    """AES-GCM is catastrophic under nonce reuse. A per-value data key
    makes reuse structurally impossible rather than something a later
    edit could get wrong.

    Compares the NONCE and CIPHERTEXT segments specifically, not the
    whole envelope string: the wrapped-key segment randomises on its own
    (the master-key wrap uses its own nonce), so comparing full strings
    passes even with a hard-coded data key and nonce. Which it did.
    """

    cipher = _cipher()
    first = seal_token(cipher, "same", **_row_kwargs())
    second = seal_token(cipher, "same", **_row_kwargs())
    assert first is not None and second is not None

    _w1, nonce1, ct1 = _segments(first)
    _w2, nonce2, ct2 = _segments(second)
    assert nonce1 != nonce2, "nonce reused across two seals"
    assert ct1 != ct2, "identical ciphertext — the data key was reused"

    assert unseal_token(cipher, first, **_row_kwargs()) == "same"
    assert unseal_token(cipher, second, **_row_kwargs()) == "same"


@pytest.mark.parametrize("empty", [None, ""])
def test_empty_values_pass_through(empty: str | None) -> None:
    """An unset credential is not a secret, and enveloping it would break
    every `if not row.refresh_token` check in the codebase."""

    cipher = _cipher()
    assert seal_token(cipher, empty, **_row_kwargs()) == empty


# --- AAD: binding a value to its row ----------------------------------------


def test_a_ciphertext_moved_between_rows_fails_to_open() -> None:
    """The attack available to someone with write-but-not-read access on
    the database: copy a privileged user's `refresh_token` ciphertext
    into your own row and let the gateway decrypt it for you."""

    cipher = _cipher()
    sealed = seal_token(cipher, "victim-token", **_row_kwargs())
    with pytest.raises(EnvelopeDecryptError, match="moved from a different row"):
        unseal_token(cipher, sealed, **_row_kwargs(user_id=uuid4()))


def test_a_ciphertext_moved_between_tenants_fails_to_open() -> None:
    cipher = _cipher()
    sealed = seal_token(cipher, "victim-token", **_row_kwargs())
    with pytest.raises(EnvelopeDecryptError):
        unseal_token(cipher, sealed, **_row_kwargs(tenant_id=uuid4()))


def test_access_and_refresh_tokens_cannot_be_swapped() -> None:
    """Swapping them would present a short-lived token where a durable
    one is expected, or hand a refresh token to an upstream as a bearer."""

    cipher = _cipher()
    sealed = seal_token(cipher, "rt", **_row_kwargs(field="refresh_token"))
    with pytest.raises(EnvelopeDecryptError):
        unseal_token(cipher, sealed, **_row_kwargs(field="access_token"))


def test_aad_names_the_row_and_the_column() -> None:
    aad = token_aad(tenant_id=TENANT, user_id=USER, server_id=SERVER, field="x")
    for part in (str(TENANT), str(USER), str(SERVER), "x"):
        assert part in aad


# --- Tamper + wrong key -----------------------------------------------------


def test_tampered_ciphertext_fails_to_open() -> None:
    cipher = _cipher()
    sealed = seal_token(cipher, "rt", **_row_kwargs())
    assert sealed is not None
    body = sealed[len(ENVELOPE_PREFIX):].split(":")
    # Flip a byte in the ciphertext segment.
    raw = bytearray(base64.b64decode(body[2]))
    raw[0] ^= 0xFF
    tampered = ENVELOPE_PREFIX + ":".join(
        [body[0], body[1], base64.b64encode(bytes(raw)).decode()]
    )
    with pytest.raises(EnvelopeDecryptError):
        unseal_token(cipher, tampered, **_row_kwargs())


def test_a_different_master_key_cannot_open_it() -> None:
    sealed = seal_token(_cipher(), "rt", **_row_kwargs())
    with pytest.raises(EnvelopeDecryptError, match="wrong master key"):
        unseal_token(_cipher(), sealed, **_row_kwargs())


@pytest.mark.parametrize(
    "malformed",
    [ENVELOPE_PREFIX + "onlyonepart", ENVELOPE_PREFIX + "a:b", ENVELOPE_PREFIX + "!!:!!:!!"],
)
def test_malformed_envelopes_are_refused_not_returned(malformed: str) -> None:
    """Returning the raw string would send a ciphertext to an upstream as
    a bearer token."""

    with pytest.raises(EnvelopeDecryptError):
        unseal_token(_cipher(), malformed, **_row_kwargs())


def test_master_key_must_be_exactly_32_bytes() -> None:
    with pytest.raises(ValueError, match="openssl rand"):
        LocalMasterKeyProvider(os.urandom(16))


# --- Migration story: no backfill, no flag day ------------------------------


def test_existing_plaintext_rows_keep_working() -> None:
    """What makes enabling encryption a no-downtime change instead of an
    outage-shaped event — which is how a security control ends up never
    being enabled."""

    cipher = _cipher()
    assert unseal_token(cipher, "legacy-plaintext-token", **_row_kwargs()) == (
        "legacy-plaintext-token"
    )
    assert is_envelope("legacy-plaintext-token") is False


def test_a_plaintext_row_is_sealed_on_its_next_write() -> None:
    cipher = _cipher()
    legacy = "legacy-plaintext-token"
    resealed = seal_token(cipher, unseal_token(cipher, legacy, **_row_kwargs()), **_row_kwargs())
    assert is_envelope(resealed)
    assert unseal_token(cipher, resealed, **_row_kwargs()) == legacy


# --- Encryption disabled ----------------------------------------------------


def test_null_cipher_is_a_passthrough_for_plaintext() -> None:
    cipher = NullEnvelopeCipher()
    assert cipher.enabled is False
    assert seal_token(cipher, "rt", **_row_kwargs()) == "rt"
    assert unseal_token(cipher, "rt", **_row_kwargs()) == "rt"


def test_disabling_encryption_refuses_to_read_sealed_rows() -> None:
    """Turning encryption off after rows were sealed must NOT hand the
    ciphertext to an upstream as a bearer — that surfaces as a baffling
    401 instead of "your key is missing"."""

    sealed = seal_token(_cipher(), "rt", **_row_kwargs())
    with pytest.raises(EnvelopeDecryptError, match="no encryption key is configured"):
        unseal_token(NullEnvelopeCipher(), sealed, **_row_kwargs())


# --- Startup wiring ---------------------------------------------------------


def test_backend_selection_and_validation() -> None:
    from vyuu_gateway.config import Settings
    from vyuu_gateway.main import _build_envelope_cipher

    def _settings(**kw: object) -> Settings:
        return Settings(
            app_name="V", environment="test", log_level="CRITICAL", version="v", **kw
        )

    assert isinstance(_build_envelope_cipher(_settings()), NullEnvelopeCipher)
    good = _settings(
        envelope_encryption_backend="local",
        envelope_master_key=base64.b64encode(os.urandom(32)).decode(),
    )
    assert isinstance(_build_envelope_cipher(good), EnvelopeCipher)

    with pytest.raises(RuntimeError, match="VYUU_ENVELOPE_MASTER_KEY"):
        _build_envelope_cipher(_settings(envelope_encryption_backend="local"))
    with pytest.raises(RuntimeError, match="valid base64"):
        _build_envelope_cipher(
            _settings(
                envelope_encryption_backend="local", envelope_master_key="!!!not-b64"
            )
        )
    with pytest.raises(RuntimeError, match="VYUU_ENVELOPE_KMS_KEY_ID"):
        _build_envelope_cipher(_settings(envelope_encryption_backend="aws_kms"))
    with pytest.raises(RuntimeError, match="must be 'none'"):
        _build_envelope_cipher(_settings(envelope_encryption_backend="rot13"))


def test_kms_provider_wraps_and_unwraps_via_the_client() -> None:
    """`GenerateDataKey` would let KMS mint the key, but minting locally
    and calling `Encrypt` keeps this provider interchangeable with the
    local one behind a single Protocol."""

    from vyuu_gateway.crypto import AwsKmsKeyProvider

    class _FakeKms:
        def encrypt(self, *, KeyId: str, Plaintext: bytes) -> dict:  # noqa: N803
            return {"CiphertextBlob": b"wrapped:" + Plaintext}

        def decrypt(self, *, KeyId: str, CiphertextBlob: bytes) -> dict:  # noqa: N803
            return {"Plaintext": CiphertextBlob.removeprefix(b"wrapped:")}

    provider = AwsKmsKeyProvider(key_id="arn:aws:kms:...", client=_FakeKms())
    cipher = EnvelopeCipher(provider)
    sealed = seal_token(cipher, "rt", **_row_kwargs())
    assert unseal_token(cipher, sealed, **_row_kwargs()) == "rt"


def test_kms_failures_surface_as_decrypt_errors() -> None:
    from vyuu_gateway.crypto import AwsKmsKeyProvider

    class _BrokenKms:
        def encrypt(self, **kw: object) -> dict:
            return {"CiphertextBlob": b"x"}

        def decrypt(self, **kw: object) -> dict:
            raise RuntimeError("AccessDeniedException")

    provider = AwsKmsKeyProvider(key_id="k", client=_BrokenKms())
    with pytest.raises(EnvelopeDecryptError, match="KMS decrypt failed"):
        provider.unwrap(b"anything")
