"""Server-side admin audit log — records every admin action.

**Distinct from `RecentAuditEmitter`**, which is the in-memory ring buffer
of inbound MCP tool calls. This module persists *what admins did to the
platform* — disable a user, revoke a grant, delete a vserver, connect an
IdP, deactivate a SCIM user, etc. The auditor's table.

## The synchronous-same-transaction guarantee

Every retrofit follows the same pattern:

```python
def disable_user_endpoint(...):
    user = disable_user(db, tenant_id=..., user_id=...)   # mutation
    record_admin_action(                                  # audit row
        db,
        tenant_id=...,
        actor=AdminAuditActor.operator(operator),
        action="user.disable",
        target=AdminAuditTarget(kind="user", id=user.id, display=user.email),
        detail={"reason": "..."},
    )
    db.commit()                                           # both or nothing
```

`record_admin_action` only calls `db.add()` — it deliberately does not
commit. The mutation and the audit row share the caller's transaction,
so they commit atomically. **If the audit insert fails, the mutation
is rolled back along with it.** That's the only way to give the
auditor the guarantee they need ("if the action happened, there is a
log row for it"). Fire-and-forget logging would let an audit hiccup
silently drop the row.

Never use a separate session for the audit row. Never commit inside
this function. The whole point is sharing the caller's transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from vyuu_gateway.db.models import AdminAuditActorKind, AdminAuditLog
from vyuu_gateway.siem.bridges import stage_admin_event
from vyuu_gateway.siem.events import from_admin_action

if TYPE_CHECKING:
    from vyuu_gateway.operator_auth.models import AuthenticatedOperator


@dataclass(frozen=True)
class AdminAuditActor:
    """Who triggered the action.

    Three constructor patterns. Use `operator(...)` for human-driven
    actions (the operator JWT off the request), `system(...)` for cron /
    sweeper / startup migrations, `scim(...)` for IdP-pushed lifecycle
    events.
    """

    kind: AdminAuditActorKind
    operator_id: UUID | None
    # Captured at action time so the row stays readable if the operator
    # is later deleted (FK is SET NULL, not CASCADE).
    display: str | None

    @classmethod
    def operator(cls, op: AuthenticatedOperator) -> AdminAuditActor:
        return cls(
            kind=AdminAuditActorKind.OPERATOR,
            operator_id=op.operator_id,
            display=op.display or None,
        )

    @classmethod
    def system(cls, label: str) -> AdminAuditActor:
        """For cron-loop actors. `label` is what shows up in the UI as
        the actor name — pass the loop name (`"hard_delete_sweeper"`,
        `"startup_migration"`)."""
        return cls(
            kind=AdminAuditActorKind.SYSTEM,
            operator_id=None,
            display=label,
        )

    @classmethod
    def scim(cls, directory_display: str) -> AdminAuditActor:
        """For SCIM-driven actions. `directory_display` is the IdP
        directory's display name (`"Acme Corp · Entra ID"`) so the audit
        log reads as "Acme Corp · Entra ID deactivated user X"."""
        return cls(
            kind=AdminAuditActorKind.SCIM,
            operator_id=None,
            display=directory_display,
        )


@dataclass(frozen=True)
class AdminAuditTarget:
    """The thing acted upon.

    `display` is captured at action time so the row stays human-readable
    after the target is deleted. We're not foreign-keying `target_id`
    deliberately — the audit log outlives its targets.
    """

    kind: str
    id: UUID | None
    display: str | None


def record_admin_action(
    db: Session,
    *,
    tenant_id: UUID,
    actor: AdminAuditActor,
    action: str,
    target: AdminAuditTarget | None = None,
    detail: dict[str, Any] | None = None,
) -> AdminAuditLog:
    """Append one admin-audit row to the caller's open transaction.

    Does NOT commit — the caller's `db.commit()` covers both the
    mutation and this audit row. Atomic by construction: if the
    transaction rolls back (constraint violation, raised exception,
    explicit rollback), the audit row goes with it.

    `action` is a free-text dotted verb so we don't migrate every
    time a new admin endpoint lands. Conventional namespaces:
    `user.*`, `vserver.*`, `grant.*`, `group.*`, `admin.*` (for
    operator-management actions), `apikey.*`, `access_request.*`,
    `idp.*`, `scim.*`, `secret.*`.
    """

    row = AdminAuditLog(
        id=uuid4(),
        tenant_id=tenant_id,
        actor_operator_id=actor.operator_id,
        actor_kind=actor.kind,
        actor_display=actor.display,
        action=action,
        target_kind=(target.kind if target is not None else None),
        target_id=(target.id if target is not None else None),
        target_display=(target.display if target is not None else None),
        detail=detail or {},
        occurred_at=datetime.now(UTC),
    )
    db.add(row)
    # SIEM-1 · stage the projection now, ship it at commit. Projected
    # here rather than in the commit hook because the row's attributes
    # expire on commit and the hook may not issue SQL to reload them.
    # Rollback discards it, so the SIEM never sees an action that did
    # not happen — the same guarantee the auditor's table has.
    stage_admin_event(
        db,
        from_admin_action(
            tenant_id=tenant_id,
            row_id=row.id,
            actor_kind=actor.kind.value,
            actor_operator_id=actor.operator_id,
            actor_display=actor.display,
            action=action,
            target_kind=row.target_kind,
            target_id=row.target_id,
            target_display=row.target_display,
            detail=dict(row.detail or {}),
            occurred_at=row.occurred_at,
        ),
    )
    return row
