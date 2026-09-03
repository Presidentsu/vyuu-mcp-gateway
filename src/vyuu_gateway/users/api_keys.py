"""Per-user API keys: format, generation, parsing, hash + verify.

Wire format:

    vyuu_user_<id-base32>_<secret-b64>

- `vyuu_user_` prefix lets the gateway route the bearer to the
  ApiKeyIdentityProvider before any DB hit. Future: `vyuu_op_` for
  operator API keys, `vyuu_svc_` for service-to-service.
- `<id-base32>` is the `user_api_keys.id` UUID encoded as 26 chars of
  lowercase base32. Lets the gateway do a single SQL `WHERE id = ?`
  lookup — no scan, no full-key index.
- `<secret-b64>` is 32 random bytes urlsafe-base64'd (~43 chars). Hashed
  with bcrypt at issuance; the plaintext is shown to the user once and
  never persisted.

Total length ~80 chars. Looks like:
  `vyuu_user_a1b2c3d4e5f6g7h8i9j0k1l2m3_AbCdEfGh...`

The `key_prefix` column on `user_api_keys` carries the first 8 chars of
the secret (plain) for operator-UI display + log correlation. Knowing
the prefix is not a security risk — bcrypt of the FULL secret gates
auth.
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from uuid import UUID

import bcrypt

KEY_SCOPE = "user"
KEY_PREFIX_PUBLIC_LEN = 8  # chars of secret retained as `key_prefix` in DB

_BEARER_PREFIX = f"vyuu_{KEY_SCOPE}_"
_SECRET_BYTES = 32


class MalformedApiKeyError(ValueError):
    """Bearer token did not parse as a Vyuu user API key.

    Carries no detail — the auth path treats this identically to
    "key not found" so an attacker can't fingerprint which part of
    the format is being rejected.
    """


@dataclass(frozen=True)
class IssuedApiKey:
    """Result of issuing a new API key — plaintext returned exactly once."""

    key_id: UUID
    plaintext: str         # show to user, then forget
    key_hash: str          # persist this
    key_prefix: str        # persist this for display


@dataclass(frozen=True)
class ParsedApiKey:
    """Successfully-parsed bearer; `key_id` to look up the row, `secret`
    for the hash compare."""

    key_id: UUID
    secret: str


def issue_new_key(*, key_id: UUID) -> IssuedApiKey:
    """Mint a new API key for the given pre-allocated `key_id`.

    Caller is responsible for inserting the resulting `key_hash` /
    `key_prefix` into `user_api_keys` — keeping the DB-write decision
    in the caller lets the registry service control transactions and
    uniqueness violations on `(user_id, label)` cleanly.
    """

    secret_bytes = secrets.token_bytes(_SECRET_BYTES)
    secret = base64.urlsafe_b64encode(secret_bytes).decode("ascii").rstrip("=")
    plaintext = _format_bearer(key_id, secret)
    return IssuedApiKey(
        key_id=key_id,
        plaintext=plaintext,
        key_hash=_hash_secret(secret),
        key_prefix=secret[:KEY_PREFIX_PUBLIC_LEN],
    )


def parse_bearer(bearer: str) -> ParsedApiKey:
    """Parse a `vyuu_user_<id-b32>_<secret>` bearer.

    Raises `MalformedApiKeyError` on any shape failure. Successful
    parse does NOT validate the secret — the caller still needs to
    hash-compare against the DB row's `key_hash`.
    """

    if not bearer or not bearer.startswith(_BEARER_PREFIX):
        raise MalformedApiKeyError
    body = bearer[len(_BEARER_PREFIX):]
    sep = body.find("_")
    if sep <= 0 or sep == len(body) - 1:
        raise MalformedApiKeyError
    id_b32 = body[:sep]
    secret = body[sep + 1:]
    try:
        key_id = _decode_id(id_b32)
    except ValueError as exc:
        raise MalformedApiKeyError from exc
    return ParsedApiKey(key_id=key_id, secret=secret)


def verify_secret(secret: str, key_hash: str) -> bool:
    """Constant-time compare `secret` against the stored bcrypt hash."""

    if not secret or not key_hash:
        return False
    try:
        return bcrypt.checkpw(secret.encode("utf-8"), key_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _format_bearer(key_id: UUID, secret: str) -> str:
    return f"{_BEARER_PREFIX}{_encode_id(key_id)}_{secret}"


def _encode_id(key_id: UUID) -> str:
    """UUID → 26 chars of lowercase base32 (no padding)."""

    return base64.b32encode(key_id.bytes).decode("ascii").rstrip("=").lower()


def _decode_id(id_b32: str) -> UUID:
    """Inverse of `_encode_id`. Raises `ValueError` on shape failure."""

    if not id_b32 or len(id_b32) != 26:
        raise ValueError("id segment is the wrong length")
    padded = id_b32.upper() + "=" * 6  # base32 needs padding to multiples of 8
    decoded = base64.b32decode(padded)
    if len(decoded) != 16:
        raise ValueError("id segment did not decode to 16 bytes")
    return UUID(bytes=decoded)


def _hash_secret(secret: str) -> str:
    """Hash a per-key secret. Bcrypt rounds=10 (faster than the password
    floor of 12 because the input is 32 random bytes — high entropy
    makes brute-force infeasible regardless of work factor; we pay the
    cost on every inbound MCP request, so ~90ms vs ~250ms matters)."""

    salt = bcrypt.gensalt(rounds=10)
    return bcrypt.hashpw(secret.encode("utf-8"), salt).decode("utf-8")
