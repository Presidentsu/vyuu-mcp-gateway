"""Envelope encryption for at-rest data the gateway stores itself.

Distinct from `secrets/` — that resolves references to secrets somebody
*else* holds (Vault, AWS Secrets Manager, Kubernetes). This protects rows
in **our** database.

## The row this exists for

`oauth_user_tokens` holds per-user OAuth access and refresh tokens for
every connected SaaS — GitHub, Google Drive, Slack, Notion. Its own model
docstring said the quiet part out loud: *"Tokens are stored as plaintext
(DB at-rest encryption is the operator's responsibility for v1)."*

A refresh token is durable delegated access. Plaintext means a database
dump, a backup, a read replica, or a `pg_dump` pasted into a support
ticket hands over every user's connected accounts at once — and unlike a
password, nobody can tell it happened and no rotation is triggered.
Postgres-level at-rest encryption does not help here, because it protects
against disk theft, not against anything that can already run a SELECT.

## Envelope, not direct encryption

A fresh 256-bit data key per value, used once with AES-GCM, and itself
wrapped by a master key that never leaves the KMS. Three reasons this
beats encrypting rows directly with a KMS key:

1. **No plaintext round-trip to the KMS.** Only the data key crosses the
   wire, never the token.
2. **Rotating the master key does not rewrite the table.** Old rows stay
   readable via their wrapped keys.
3. **One key, one value.** AES-GCM is catastrophic under nonce reuse, and
   a per-value key makes reuse structurally impossible rather than
   something a future edit could get wrong.

## Self-describing values, so no migration and no flag day

An encrypted value is a string:

    vyuu:v1:<b64 wrapped_key>:<b64 nonce>:<b64 ciphertext>

`decrypt()` passes anything without that prefix straight through. So an
existing plaintext row keeps working, gets re-encrypted the next time it
is written, and a deployment can turn encryption on without a backfill or
turn it off without stranding data it can no longer read. The alternative
— a boolean column plus a migration — makes enabling it an outage-shaped
event, which is how a security control ends up not being enabled.

## AAD binds a value to its row

Every value is encrypted with associated data naming the row it belongs
to. Moving a ciphertext from one user's row to another's — the obvious
attack for anyone with write access but not read access — fails
authentication instead of silently granting that user someone else's
token.
"""

from __future__ import annotations

import base64
import logging
import os
from typing import Any, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

# Marks a value as enveloped. Versioned so a future format change is a
# new prefix rather than an ambiguous parse.
ENVELOPE_PREFIX = "vyuu:v1:"

_DATA_KEY_BYTES = 32  # AES-256
_NONCE_BYTES = 12     # GCM standard; 96 bits is the only size with a proof


class EnvelopeDecryptError(Exception):
    """A value could not be decrypted.

    Raised rather than returning None or the ciphertext: a caller that
    silently proceeds with an unreadable credential produces a confusing
    upstream 401 instead of the real error, which is that the key is
    wrong or the value was tampered with.
    """


def is_envelope(value: str | None) -> bool:
    return bool(value) and str(value).startswith(ENVELOPE_PREFIX)


class MasterKeyProvider(Protocol):
    """Wraps and unwraps data keys. The master key never leaves it."""

    def wrap(self, data_key: bytes) -> bytes:
        """Encrypt a data key with the master key."""

    def unwrap(self, wrapped: bytes) -> bytes:
        """Recover a data key."""


class LocalMasterKeyProvider:
    """Master key held in gateway config.

    For on-prem deployments with no KMS, and for dev. Honest about what
    it is: the key sits in the process's environment, so it protects
    against database exposure — the threat this module exists for — and
    **not** against host compromise. A deployment that needs the latter
    wants `AwsKmsKeyProvider`.
    """

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != _DATA_KEY_BYTES:
            raise ValueError(
                f"master key must be exactly {_DATA_KEY_BYTES} bytes "
                f"(got {len(master_key)}); generate one with "
                "`openssl rand -base64 32`"
            )
        self._aes = AESGCM(master_key)

    def wrap(self, data_key: bytes) -> bytes:
        nonce = os.urandom(_NONCE_BYTES)
        return nonce + self._aes.encrypt(nonce, data_key, b"vyuu-data-key")

    def unwrap(self, wrapped: bytes) -> bytes:
        nonce, ciphertext = wrapped[:_NONCE_BYTES], wrapped[_NONCE_BYTES:]
        try:
            return self._aes.decrypt(nonce, ciphertext, b"vyuu-data-key")
        except InvalidTag as exc:
            raise EnvelopeDecryptError(
                "data key could not be unwrapped — wrong master key, or the "
                "stored value was modified"
            ) from exc


class AwsKmsKeyProvider:
    """Master key in AWS KMS; only data keys cross the wire.

    `GenerateDataKey` would let KMS mint the key for us, but we mint it
    locally and call `Encrypt` instead: it keeps this provider
    interchangeable with `LocalMasterKeyProvider` behind one Protocol,
    and a 32-byte payload to `Encrypt` is well within the 4KB limit.
    """

    def __init__(self, *, key_id: str, region_name: str | None = None,
                 client: Any | None = None) -> None:
        if not key_id:
            raise ValueError("KMS key id / ARN is required")
        self._key_id = key_id
        self._region_name = region_name
        self._client = client

    def _kms(self) -> Any:
        if self._client is None:
            import boto3  # local import — keeps boto3 off the import path

            self._client = boto3.client("kms", region_name=self._region_name)
        return self._client

    def wrap(self, data_key: bytes) -> bytes:
        response = self._kms().encrypt(KeyId=self._key_id, Plaintext=data_key)
        return bytes(response["CiphertextBlob"])

    def unwrap(self, wrapped: bytes) -> bytes:
        try:
            response = self._kms().decrypt(
                KeyId=self._key_id, CiphertextBlob=wrapped
            )
        except Exception as exc:  # noqa: BLE001 — botocore raises many shapes
            raise EnvelopeDecryptError(
                f"KMS decrypt failed: {exc.__class__.__name__}"
            ) from exc
        return bytes(response["Plaintext"])


class EnvelopeCipher:
    """Encrypts and decrypts individual field values."""

    def __init__(self, provider: MasterKeyProvider) -> None:
        self._provider = provider

    @property
    def enabled(self) -> bool:
        return True

    def encrypt(self, plaintext: str | None, *, aad: str) -> str | None:
        """Encrypt one value. `None` and `""` pass through unchanged —
        an empty credential is not a secret, and enveloping it would just
        make "is this set?" checks stop working."""

        if not plaintext:
            return plaintext
        data_key = os.urandom(_DATA_KEY_BYTES)
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = AESGCM(data_key).encrypt(
            nonce, plaintext.encode("utf-8"), aad.encode("utf-8")
        )
        return ENVELOPE_PREFIX + ":".join(
            base64.b64encode(part).decode("ascii")
            for part in (self._provider.wrap(data_key), nonce, ciphertext)
        )

    def decrypt(self, stored: str | None, *, aad: str) -> str | None:
        """Decrypt, or pass through a value that was never encrypted.

        The pass-through is what makes enabling encryption a no-downtime
        change: existing plaintext rows keep working and are re-encrypted
        on their next write.
        """

        if not stored or not is_envelope(stored):
            return stored
        body = stored[len(ENVELOPE_PREFIX):]
        parts = body.split(":")
        if len(parts) != 3:
            raise EnvelopeDecryptError("malformed envelope: expected 3 segments")
        try:
            wrapped, nonce, ciphertext = (base64.b64decode(p, validate=True) for p in parts)
        except (ValueError, TypeError) as exc:
            raise EnvelopeDecryptError("malformed envelope: bad base64") from exc

        data_key = self._provider.unwrap(wrapped)
        try:
            return AESGCM(data_key).decrypt(
                nonce, ciphertext, aad.encode("utf-8")
            ).decode("utf-8")
        except InvalidTag as exc:
            # AAD binds a value to its row, so this also fires when a
            # ciphertext is moved between rows — which is the point.
            raise EnvelopeDecryptError(
                "value failed authentication — it was modified, or moved "
                "from a different row"
            ) from exc
        except UnicodeDecodeError as exc:
            raise EnvelopeDecryptError("decrypted value was not UTF-8") from exc


class NullEnvelopeCipher:
    """No-op cipher: the default, and what an un-configured deployment
    gets.

    Still *decrypts* — so turning encryption off leaves previously
    encrypted rows unreadable, which is a real trap. `decrypt` therefore
    raises a clear error on an enveloped value rather than returning the
    ciphertext as if it were a token, which would surface as a baffling
    upstream 401.
    """

    @property
    def enabled(self) -> bool:
        return False

    def encrypt(self, plaintext: str | None, *, aad: str) -> str | None:
        return plaintext

    def decrypt(self, stored: str | None, *, aad: str) -> str | None:
        if is_envelope(stored):
            raise EnvelopeDecryptError(
                "this row is encrypted but no encryption key is configured; "
                "restore VYUU_ENVELOPE_MASTER_KEY (or the KMS key id) to read it"
            )
        return stored
