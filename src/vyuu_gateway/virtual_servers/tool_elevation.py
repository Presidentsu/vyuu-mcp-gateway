"""JIT-2 · database-backed `ToolElevationChecker` for the inbound hot path.

Answers one question, once per elevation-gated tool call: does this
principal hold a live elevation for this exposed tool?

## Why it opens its own session

The lifecycle runs inside the inbound request but is deliberately
DB-agnostic — every collaborator is injected, which is what lets the
whole orchestration be tested without Postgres. Rather than thread a
session through it, this checker takes the same `SessionLocal` factory
the other hot-path providers use and binds the tenant itself.

`virtual_server_tool_grants` is ENABLE + FORCE RLS, so the binding is
not optional: an unbound query returns zero rows, which this class would
report as "no elevation" — a fail-closed answer, but for the wrong
reason and impossible to debug from the outside.

## Group elevations

Supported the same way vserver grants are: a `group` elevation applies to
every member. The lookup unions the direct and via-group legs in one
statement rather than two round-trips, since this is per-tool-call.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import (
    GrantPrincipalKind,
    UserGroupMembership,
    VirtualServerToolGrant,
)
from vyuu_gateway.db.session import bind_tenant_context

SessionFactory = Callable[[], Session]


class DatabaseToolElevationChecker:
    """Looks up live per-tool elevations. Satisfies
    `tool_calls.lifecycle.ToolElevationChecker`."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def has_active_tool_elevation(
        self,
        *,
        tenant_id: UUID,
        vserver_id: UUID,
        exposed_tool_name: str,
        principal_id: str,
    ) -> bool:
        try:
            user_id = UUID(principal_id)
        except (ValueError, TypeError):
            # Only principals resolving to a real `users.id` can hold an
            # elevation, same rule as vserver grants.
            return False

        now = datetime.now(UTC)
        with self._session_factory() as session:
            bind_tenant_context(session, tenant_id)

            direct = select(VirtualServerToolGrant.id).where(
                VirtualServerToolGrant.tenant_id == tenant_id,
                VirtualServerToolGrant.vserver_id == vserver_id,
                VirtualServerToolGrant.exposed_tool_name == exposed_tool_name,
                VirtualServerToolGrant.principal_kind == GrantPrincipalKind.USER,
                VirtualServerToolGrant.principal_id == user_id,
                VirtualServerToolGrant.revoked_at.is_(None),
                VirtualServerToolGrant.expires_at > now,
            )
            via_group = (
                select(VirtualServerToolGrant.id)
                .join(
                    UserGroupMembership,
                    UserGroupMembership.group_id
                    == VirtualServerToolGrant.principal_id,
                )
                .where(
                    VirtualServerToolGrant.tenant_id == tenant_id,
                    VirtualServerToolGrant.vserver_id == vserver_id,
                    VirtualServerToolGrant.exposed_tool_name == exposed_tool_name,
                    VirtualServerToolGrant.principal_kind
                    == GrantPrincipalKind.GROUP,
                    VirtualServerToolGrant.revoked_at.is_(None),
                    VirtualServerToolGrant.expires_at > now,
                    UserGroupMembership.user_id == user_id,
                )
            )
            # `.first()` rather than a count: we only need existence, and
            # this runs on every gated tool call.
            return (
                session.execute(direct.union_all(via_group).limit(1)).first()
                is not None
            )
