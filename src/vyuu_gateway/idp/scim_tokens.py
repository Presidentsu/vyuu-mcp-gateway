"""Mint + verify the SCIM bearer for one IdP directory.

When the admin connects a directory in the operator console we
generate a single 256-bit secret, bcrypt-hash it, and stash the hash
on `idp_directories.scim_token_hash`. The plaintext is shown ONCE in
the create response — the admin pastes it into Entra/Workspace's
"Provisioning" config. We never persist the plaintext.

On every inbound `/scim/v2/{directory_id}/...` request, the SCIM
auth dependency:

1. Reads `Authorization: Bearer <plaintext>` off the request.
2. Loads the directory by the `directory_id` in the URL path.
3. bcrypt-compares the plaintext against the stored hash.

Generic errors only — the failure modes (bad directory id, bad
token, disabled directory) all collapse to 401 with no detail, same
anti-enumeration posture as the inbound API-key validation path.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

import bcrypt

# `vyuu_scim_` prefix makes the bearer visually distinct from the
# `vyuu_user_` keys that drive inbound MCP traffic — when an admin
# pastes the wrong one into the wrong place, the prefix gives them
# an immediate "this isn't a SCIM token" hint at the IdP side.
_BEARER_PREFIX = "vyuu_scim_"
_SECRET_BYTES = 32  # 256-bit


@dataclass(frozen=True)
class IssuedScimToken:
    """Result of minting a fresh SCIM bearer.

    `plaintext` is shown to the admin once at directory-connect time
    and never persisted. `token_hash` goes into
    `idp_directories.scim_token_hash`. The verifier never sees the
    plaintext beyond the inbound HTTP request.
    """

    plaintext: str
    token_hash: str


def issue_scim_token() -> IssuedScimToken:
    """Mint a fresh SCIM bearer + bcrypt hash."""

    secret = secrets.token_urlsafe(_SECRET_BYTES)
    plaintext = f"{_BEARER_PREFIX}{secret}"
    return IssuedScimToken(
        plaintext=plaintext,
        token_hash=_hash(plaintext),
    )


def verify_scim_token(presented: str, stored_hash: str) -> bool:
    """Constant-time compare of a presented bearer against the stored
    hash. Returns False for any malformed input — generic, no detail
    leaks back to the caller."""

    if not presented or not stored_hash:
        return False
    if not presented.startswith(_BEARER_PREFIX):
        return False
    try:
        return bcrypt.checkpw(
            presented.encode("utf-8"), stored_hash.encode("utf-8")
        )
    except (ValueError, TypeError):
        return False


def _hash(plaintext: str) -> str:
    return bcrypt.hashpw(
        plaintext.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")
