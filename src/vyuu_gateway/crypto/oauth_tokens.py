"""Envelope encryption applied to `oauth_user_tokens`.

Thin, deliberate wrapper over `crypto/envelope.py` that fixes one thing:
**the associated data**. Every stored token is bound to the exact row it
belongs to, so a ciphertext moved between rows fails authentication
instead of silently granting one user another user's access.

## Why not a SQLAlchemy `TypeDecorator`

That would be less code and fully transparent — and it cannot see the
row. A `TypeDecorator` binds one column value at a time, with no access
to `tenant_id` / `user_id` / `server_id`, so the best AAD it could
construct is a per-column constant. That stops a value being moved
between *columns* and does nothing about the attack that matters: an
actor with write-but-not-read access copying `refresh_token` from a
privileged user's row into their own.

Four explicit call sites is a fair price for making that attack fail
closed.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

__all__ = ["seal_token", "token_aad", "unseal_token"]


def token_aad(
    *, tenant_id: UUID, user_id: UUID, server_id: UUID, field: str
) -> str:
    """Associated data binding a value to (row, column).

    Includes the field name as well as the row, so `access_token` and
    `refresh_token` cannot be swapped for each other either — a swap
    would otherwise present a short-lived token where a durable one is
    expected, or vice versa.
    """

    return f"oauth_user_tokens|{tenant_id}|{user_id}|{server_id}|{field}"


def seal_token(
    cipher: Any,
    value: str | None,
    *,
    tenant_id: UUID,
    user_id: UUID,
    server_id: UUID,
    field: str,
) -> str | None:
    return cipher.encrypt(
        value,
        aad=token_aad(
            tenant_id=tenant_id, user_id=user_id, server_id=server_id, field=field
        ),
    )


def unseal_token(
    cipher: Any,
    stored: str | None,
    *,
    tenant_id: UUID,
    user_id: UUID,
    server_id: UUID,
    field: str,
) -> str | None:
    return cipher.decrypt(
        stored,
        aad=token_aad(
            tenant_id=tenant_id, user_id=user_id, server_id=server_id, field=field
        ),
    )
