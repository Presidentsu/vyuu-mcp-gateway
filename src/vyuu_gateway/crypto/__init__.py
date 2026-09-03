"""Envelope encryption for data the gateway stores itself."""

from vyuu_gateway.crypto.envelope import (
    ENVELOPE_PREFIX,
    AwsKmsKeyProvider,
    EnvelopeCipher,
    EnvelopeDecryptError,
    LocalMasterKeyProvider,
    MasterKeyProvider,
    NullEnvelopeCipher,
    is_envelope,
)
from vyuu_gateway.crypto.oauth_tokens import seal_token, token_aad, unseal_token

__all__ = [
    "ENVELOPE_PREFIX",
    "AwsKmsKeyProvider",
    "EnvelopeCipher",
    "EnvelopeDecryptError",
    "LocalMasterKeyProvider",
    "MasterKeyProvider",
    "NullEnvelopeCipher",
    "is_envelope",
    "seal_token",
    "token_aad",
    "configure_envelope_cipher",
    "get_envelope_cipher",
    "unseal_token",
]


# --- Process-wide cipher ----------------------------------------------------
#
# Set once by `create_app`. A module-level singleton rather than an
# injected dependency because the encrypt/decrypt call sites are inside
# persistence code reached from four different entry points (the OAuth
# callback, the refresh path, and both of their tests) — threading a
# cipher through all of them would put a crypto parameter in signatures
# that have no other reason to know about crypto.
#
# Mirrors the existing `audit.events.configure_raw_capture_cap` pattern.

_cipher: object = NullEnvelopeCipher()


def configure_envelope_cipher(cipher: object) -> None:
    """Install the process-wide cipher. Called by `create_app`."""

    global _cipher
    _cipher = cipher


def get_envelope_cipher() -> object:
    """The configured cipher, or a no-op one when encryption is off."""

    return _cipher
