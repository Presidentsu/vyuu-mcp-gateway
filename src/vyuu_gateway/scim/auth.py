"""SCIM bearer-auth dependency.

Mounts at `/scim/v2/{directory_id}/...`. The IdP presents the
plaintext bearer the admin pasted into Provisioning config; we
look up the directory by id (untenanted, since the tenant context
isn't known yet), verify the bearer against the stored bcrypt
hash, then bind the session's tenant context for the rest of the
request so RLS guards every subsequent query.

That untenanted first read needs an explicit escape hatch, because
`idp_directories` is FORCE-RLS — see `authenticate_scim` and
migration `20260825_0019`.

Anti-enumeration posture: every failure mode (unknown id, bad
bearer, malformed header, missing header) returns 401 with no
detail. The IdP retries 401s; we don't disclose which step failed.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import Header, HTTPException, Path, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import IdpDirectory
from vyuu_gateway.db.session import SessionLocal, bind_tenant_context
from vyuu_gateway.idp.scim_tokens import verify_scim_token
from vyuu_gateway.idp.service import (
    get_idp_directory_for_scim,
    stamp_last_sync,
)


@dataclass(frozen=True)
class ScimContext:
    """Resolved SCIM session context. Both `directory` and `db` are
    valid for the lifetime of one HTTP request — the dependency
    closes the session on exit.

    `directory.tenant_id` is the canonical tenant for everything that
    happens during this request; the session is already bound to it
    via `bind_tenant_context`."""

    directory: IdpDirectory
    db: Session


def _generic_401() -> HTTPException:
    """Single error path for every auth-failure mode. No detail back
    to the IdP."""

    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="authentication required",
        headers={"WWW-Authenticate": 'Bearer realm="scim"'},
    )


def authenticate_scim(
    directory_id: UUID = Path(...),
    authorization: Annotated[str | None, Header()] = None,
) -> Iterator[ScimContext]:
    """SCIM auth dependency.

    Yields a `ScimContext` carrying the directory + an open
    tenant-bound DB session. The session lives for the lifetime
    of the request and is closed on dependency teardown.
    """

    if not authorization or not authorization.lower().startswith("bearer "):
        raise _generic_401()
    presented = authorization.split(" ", 1)[1].strip()
    if not presented:
        raise _generic_401()

    # The tenant is unknown until we have the directory row, and the
    # directory row is what tells us the tenant — so this first lookup
    # cannot be tenant-scoped. `idp_directories` is FORCE-RLS, which
    # means an untenanted SELECT matches zero rows (BUG-SCIM-1: this
    # silently 401'd every SCIM request, including with bearers we had
    # just minted). Migration `20260825_0019` adds a SELECT-only policy
    # that opens exactly this read, and only for a caller that asks for
    # it by name.
    session = SessionLocal()
    try:
        # `is_local => true` scopes the capability to this transaction,
        # so it cannot leak into the request body's queries below. An
        # accidental unbound query elsewhere still sees nothing.
        session.execute(
            text("SELECT set_config('app.scim_bootstrap', 'on', true)")
        )
        directory = get_idp_directory_for_scim(
            session, directory_id=directory_id
        )
        if directory is None:
            raise _generic_401()
        if not verify_scim_token(presented, directory.scim_token_hash):
            raise _generic_401()

        # Bearer checks out. Copy what we need before ending the
        # bootstrap transaction — `rollback()` expires every ORM
        # instance attached to this session.
        tenant_id = directory.tenant_id

        # End the bootstrap transaction. Two reasons, both load-bearing:
        #   1. It drops the `app.scim_bootstrap` capability.
        #   2. `bind_tenant_context` only takes effect via the
        #      `after_begin` listener, which fires on the NEXT
        #      transaction. Without this the tenant GUC would never be
        #      set for the rest of the request — which is why the
        #      `last_sync_at` heartbeat below was also silently
        #      updating zero rows.
        # Rollback rather than commit: nothing was written, and a
        # rollback cannot accidentally persist one.
        session.rollback()
        bind_tenant_context(session, tenant_id)

        # Re-read under RLS. The row is the same one we just
        # authenticated against; loading it inside the tenant-bound
        # transaction means every attribute the request handler touches
        # comes from a properly-scoped read, not from the bootstrap one.
        directory = get_idp_directory_for_scim(
            session, directory_id=directory_id
        )
        if directory is None:
            # Only reachable if the directory was deleted between the
            # two statements. Same opaque 401 as every other failure.
            raise _generic_401()

        # Heartbeat — last_sync_at gives the operator console a
        # "directory is alive" pill. Cheap UPDATE, runs in its own
        # transaction so the SCIM body doesn't have to commit it.
        try:
            stamp_last_sync(
                session,
                tenant_id=directory.tenant_id,
                directory_id=directory.id,
                when=datetime.now(UTC),
            )
        except Exception:
            # Heartbeat failure should never block a real SCIM
            # operation. Swallow + continue; the operator-side
            # console will show the staleness for free if it persists.
            session.rollback()

        yield ScimContext(directory=directory, db=session)
    finally:
        session.close()
