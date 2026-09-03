"""Read-only endpoint over the persistent `admin_audit_log` table.

The Operator Console's admin-audit panel calls this to render the
"who did what to the platform, when" feed. Distinct from
`/api/v1/audit-events` which exposes the in-memory ring buffer of
inbound MCP tool calls.

Tenant scoping comes from the operator JWT — the table itself is
RLS-bound, but we filter explicitly at the query layer for
defence-in-depth.

Pagination is offset-based with a hard cap. The table is bounded by
the tenant's lifetime admin actions (typically thousands, not
millions), so offset works fine; we'll move to keyset if a tenant's
volume crosses the threshold.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.db.models import AdminAuditActorKind, AdminAuditLog
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator

router = APIRouter(tags=["admin-audit"])


class AdminAuditRowResponse(BaseModel):
    """Wire shape — mirrors `AdminAuditLog` but uses the StrEnum value
    for `actor_kind` so JSON consumers don't have to handle it as a
    Python enum."""

    model_config = ConfigDict(from_attributes=False)

    id: UUID
    actor_operator_id: UUID | None
    actor_kind: AdminAuditActorKind
    actor_display: str | None
    action: str
    target_kind: str | None
    target_id: UUID | None
    target_display: str | None
    detail: dict[str, Any]
    occurred_at: datetime


class AdminAuditPage(BaseModel):
    """Paged response. `total_estimate` is `None` past the first page
    so we don't recompute the count on every scroll — the UI just
    renders "more available" when `len(rows) == limit`."""

    model_config = ConfigDict(from_attributes=False)

    rows: list[AdminAuditRowResponse]
    total_estimate: int | None = None
    next_offset: int | None = None


@router.get("/admin-audit", response_model=AdminAuditPage)
def list_admin_audit_endpoint(
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
    db: Annotated[Session, Depends(get_tenant_scoped_db)],
    actor_kind: Annotated[AdminAuditActorKind | None, Query()] = None,
    action_prefix: Annotated[str | None, Query(max_length=64)] = None,
    target_kind: Annotated[str | None, Query(max_length=64)] = None,
    since: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AdminAuditPage:
    """List admin-audit rows for this tenant, newest first.

    Filters are AND-composed. `action_prefix` is a starts-with match
    on the dotted verb (`user.`, `vserver.delete`, `scim.`) — handles
    the operator-console's "show me everything that touched users" use
    case without requiring a full enum.
    """

    stmt = select(AdminAuditLog).where(
        AdminAuditLog.tenant_id == operator.tenant_id
    )
    if actor_kind is not None:
        stmt = stmt.where(AdminAuditLog.actor_kind == actor_kind)
    if action_prefix:
        stmt = stmt.where(AdminAuditLog.action.like(f"{action_prefix}%"))
    if target_kind:
        stmt = stmt.where(AdminAuditLog.target_kind == target_kind)
    if since is not None:
        stmt = stmt.where(AdminAuditLog.occurred_at >= since)

    stmt = stmt.order_by(AdminAuditLog.occurred_at.desc()).offset(offset).limit(limit)
    rows = list(db.scalars(stmt).all())

    # Total estimate only on the first page — saves a count query on
    # subsequent pages where the UI just keeps rendering until rows
    # run out.
    total_estimate: int | None = None
    if offset == 0:
        count_stmt = select(func.count()).select_from(AdminAuditLog).where(
            AdminAuditLog.tenant_id == operator.tenant_id
        )
        if actor_kind is not None:
            count_stmt = count_stmt.where(AdminAuditLog.actor_kind == actor_kind)
        if action_prefix:
            count_stmt = count_stmt.where(
                AdminAuditLog.action.like(f"{action_prefix}%")
            )
        if target_kind:
            count_stmt = count_stmt.where(AdminAuditLog.target_kind == target_kind)
        if since is not None:
            count_stmt = count_stmt.where(AdminAuditLog.occurred_at >= since)
        total_estimate = int(db.scalar(count_stmt) or 0)

    next_offset = offset + len(rows) if len(rows) == limit else None

    return AdminAuditPage(
        rows=[
            AdminAuditRowResponse(
                id=row.id,
                actor_operator_id=row.actor_operator_id,
                actor_kind=row.actor_kind,
                actor_display=row.actor_display,
                action=row.action,
                target_kind=row.target_kind,
                target_id=row.target_id,
                target_display=row.target_display,
                detail=row.detail,
                occurred_at=row.occurred_at,
            )
            for row in rows
        ],
        total_estimate=total_estimate,
        next_offset=next_offset,
    )
