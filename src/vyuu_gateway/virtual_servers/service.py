from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, cast
from uuid import UUID, uuid4

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vyuu_gateway.audit.admin_audit import (
    AdminAuditActor,
    AdminAuditTarget,
    record_admin_action,
)
from vyuu_gateway.db.models import (
    McpServer,
    Operator,
    VirtualServer,
    VirtualServerGrant,
    VirtualServerTool,
    VirtualServerVisibility,
)
from vyuu_gateway.virtual_servers.schemas import (
    AllowlistedTool,
    CreateVirtualServerRequest,
    UpdateVirtualServerRequest,
)


class VirtualServerError(Exception):
    """Base error for virtual server service failures."""


class VirtualServerCreatorNotFoundError(VirtualServerError):
    """Raised when the creating operator is not in the requested tenant."""


class DuplicateVirtualServerNameError(VirtualServerError):
    """Raised when a tenant already has a virtual server with the requested name."""


class VirtualServerNotFoundError(VirtualServerError):
    """Raised when a virtual server is not found in the requested tenant."""


class UpstreamServerNotFoundError(VirtualServerError):
    """Raised when an allowlisted upstream server is not in the requested tenant."""


class CapabilitiesNotSyncedError(VirtualServerError):
    """Raised when a vserver has `virtual_server_tools` rows pointing
    at upstream servers whose `mcp_capabilities` table is empty (or
    has no active rows for the referenced tools).

    Distinct from `VirtualServerNotFoundError` and the policy-engine
    `tool_not_in_virtual_server` deny: this is the specific case
    where the operator registered the server, mapped its tools to a
    vserver, but never triggered (or never successfully completed) a
    capability sync. Tool calls return a confusing
    `tool_not_in_vserver` until sync runs.

    Surfaced separately so the error envelope can tag the failure
    correctly (`category=capabilities_not_synced, retryable=true`)
    and operators see the real root cause in the audit + UI surfaces.
    """

    def __init__(self, vserver_id: UUID, server_ids: list[UUID]) -> None:
        super().__init__(
            f"vserver {vserver_id} maps tools from {len(server_ids)} "
            f"upstream server(s) but no active capabilities are synced "
            f"for those servers; trigger a capability sync to enable "
            f"tool calls"
        )
        self.vserver_id = vserver_id
        self.server_ids = server_ids


class VirtualServerSession(Protocol):
    def scalar(self, statement: Any) -> Any:
        """Return one scalar ORM result."""

    def scalars(self, statement: Any) -> Any:
        """Return scalar ORM rows."""

    def execute(self, statement: Any) -> Any:
        """Execute a SQL statement (used for bulk DELETE in update)."""

    def add(self, instance: object) -> None:
        """Stage an ORM instance for persistence."""

    def delete(self, instance: object) -> None:
        """Stage an ORM instance for deletion."""

    def commit(self) -> None:
        """Commit staged changes."""

    def rollback(self) -> None:
        """Roll back staged changes."""

    def refresh(self, instance: object) -> None:
        """Refresh an ORM instance."""


# Mirrors the `server_default` on `virtual_servers.jit_max_duration_seconds`
# and the ceiling the migration's check constraint allows. 4 hours: long
# enough for a real debugging session, short enough that forgetting to
# revoke is not a standing grant by another name.
DEFAULT_JIT_MAX_DURATION_SECONDS = 4 * 3600

def create_virtual_server(
    db: VirtualServerSession | Session,
    *,
    request: CreateVirtualServerRequest,
    tenant_id: UUID,
    created_by: UUID,
    actor: AdminAuditActor | None = None,
) -> VirtualServer:
    """Create a new virtual server under the given tenant + operator.

    `tenant_id` and `created_by` MUST come from a trusted authentication
    context (the operator-API bearer token), never from the request body.
    Same defence-in-depth pattern as `register_mcp_server`.
    """

    _ensure_operator_in_tenant(db, tenant_id, created_by)
    _ensure_unique_name(db, tenant_id, request.name)
    _ensure_servers_in_tenant(db, tenant_id, [tool.server_id for tool in request.tools])

    virtual_server = VirtualServer(
        id=uuid4(),
        tenant_id=tenant_id,
        name=request.name,
        policy_id=request.policy_id,
        rename_map=dict(request.rename_map),
        # Python-level fallback for `visibility`. The column has both a
        # `default=` and a `server_default=` (see models.VirtualServer),
        # but neither populates the instance attribute on plain
        # `VirtualServer(...)` construction — only on flush. Tests using a
        # fake DB session never flush, and the response schema validates
        # the in-memory instance, so we set this explicitly to keep the
        # Python and DB views in sync.
        visibility=VirtualServerVisibility.PRIVATE,
        # JIT-1 · same reasoning as `visibility` above, and the same
        # explicitness is worth having on its own terms: "a new vserver
        # starts with just-in-time access OFF" is a policy decision, and
        # this is where a reader looks for it — not a `server_default` two
        # files away.
        jit_enabled=False,
        jit_max_duration_seconds=DEFAULT_JIT_MAX_DURATION_SECONDS,
        jit_auto_approve=False,
        jit_require_justification=True,
        # Empty = no tool on this vserver is elevation-gated.
        jit_tools={},
        created_by=created_by,
        created_at=datetime.now(UTC),
    )
    deduped_tools = list(_deduplicate_tools(request.tools))
    for tool in deduped_tools:
        virtual_server.tools.append(
            VirtualServerTool(
                tenant_id=tenant_id,
                vserver_id=virtual_server.id,
                server_id=tool.server_id,
                tool_name=tool.tool_name,
            )
        )

    try:
        db.add(virtual_server)
        if actor is not None:
            record_admin_action(
                db,
                tenant_id=tenant_id,
                actor=actor,
                action="vserver.create",
                target=AdminAuditTarget(
                    kind="vserver",
                    id=virtual_server.id,
                    display=virtual_server.name,
                ),
                detail={
                    "tool_count": len(deduped_tools),
                    "rename_map_size": len(request.rename_map),
                    "policy_id": (
                        str(request.policy_id) if request.policy_id else None
                    ),
                },
            )
        db.commit()
        db.refresh(virtual_server)
    except IntegrityError as exc:
        db.rollback()
        raise DuplicateVirtualServerNameError from exc

    return virtual_server


def add_allowlisted_tools(
    db: VirtualServerSession | Session,
    *,
    tenant_id: UUID,
    vserver_id: UUID,
    tools: list[AllowlistedTool],
) -> list[VirtualServerTool]:
    virtual_server = cast(
        VirtualServer | None,
        db.scalar(
            select(VirtualServer).where(
                VirtualServer.tenant_id == tenant_id,
                VirtualServer.id == vserver_id,
            )
        ),
    )
    if virtual_server is None:
        raise VirtualServerNotFoundError

    _ensure_servers_in_tenant(db, tenant_id, [tool.server_id for tool in tools])

    created_tools = [
        VirtualServerTool(
            tenant_id=tenant_id,
            vserver_id=vserver_id,
            server_id=tool.server_id,
            tool_name=tool.tool_name,
        )
        for tool in _deduplicate_tools(tools)
    ]
    for tool in created_tools:
        db.add(tool)

    db.commit()
    return created_tools


def list_virtual_servers(
    db: VirtualServerSession | Session,
    *,
    tenant_id: UUID,
) -> list[VirtualServer]:
    """List virtual servers visible to one tenant, newest first.

    Tenant filter is explicit on the SQL so the boundary holds even where
    RLS is dormant (see HANDOFF "RLS role separation" follow-up).
    """

    return list(
        db.scalars(
            select(VirtualServer)
            .where(VirtualServer.tenant_id == tenant_id)
            .order_by(VirtualServer.created_at.desc(), VirtualServer.name.asc())
        ).all()
    )


@dataclass(frozen=True)
class VirtualServerListItem:
    """One row in the operator-console Virtual Servers table — a
    `VirtualServer` plus per-vserver aggregates the table renders
    (tool count + grant count). The route layer maps this to
    `VirtualServerListItemResponse`."""

    virtual_server: VirtualServer
    tool_count: int
    grant_count: int


def list_virtual_servers_with_aggregates(
    db: Session,
    *,
    tenant_id: UUID,
) -> list[VirtualServerListItem]:
    """One-trip list for the admin Virtual Servers table.

    Computes `tool_count` (allowlisted tools per vserver) and
    `grant_count` (grants targeting this vserver — both user- and
    group-targeted) via two LEFT-JOINed aggregate subqueries.
    Bounded by the tenant's vserver count, no N+1.
    """

    tools_subq = (
        select(
            VirtualServerTool.vserver_id.label("vserver_id"),
            func.count().label("cnt"),
        )
        .group_by(VirtualServerTool.vserver_id)
        .subquery()
    )
    grants_subq = (
        select(
            VirtualServerGrant.vserver_id.label("vserver_id"),
            func.count().label("cnt"),
        )
        .group_by(VirtualServerGrant.vserver_id)
        .subquery()
    )
    rows = db.execute(
        select(
            VirtualServer,
            func.coalesce(tools_subq.c.cnt, 0).label("tool_count"),
            func.coalesce(grants_subq.c.cnt, 0).label("grant_count"),
        )
        .outerjoin(tools_subq, tools_subq.c.vserver_id == VirtualServer.id)
        .outerjoin(grants_subq, grants_subq.c.vserver_id == VirtualServer.id)
        .where(VirtualServer.tenant_id == tenant_id)
        .order_by(VirtualServer.created_at.desc(), VirtualServer.name.asc())
    ).all()
    return [
        VirtualServerListItem(
            virtual_server=vserver,
            tool_count=int(tool_count or 0),
            grant_count=int(grant_count or 0),
        )
        for vserver, tool_count, grant_count in rows
    ]


def get_virtual_server(
    db: VirtualServerSession | Session,
    *,
    tenant_id: UUID,
    vserver_id: UUID,
) -> VirtualServer:
    """Fetch one virtual server, raising `VirtualServerNotFoundError` on miss."""
    virtual_server = cast(
        VirtualServer | None,
        db.scalar(
            select(VirtualServer).where(
                VirtualServer.tenant_id == tenant_id,
                VirtualServer.id == vserver_id,
            )
        ),
    )
    if virtual_server is None:
        raise VirtualServerNotFoundError
    return virtual_server


def list_virtual_server_tools(
    db: VirtualServerSession | Session,
    *,
    tenant_id: UUID,
    vserver_id: UUID,
) -> list[VirtualServerTool]:
    """Return the allowlisted tools currently bound to a virtual server."""

    # Confirm the virtual server exists in this tenant first so the caller
    # gets a 404 (not an empty list) when the id is wrong.
    get_virtual_server(db, tenant_id=tenant_id, vserver_id=vserver_id)
    return list(
        db.scalars(
            select(VirtualServerTool)
            .where(
                VirtualServerTool.tenant_id == tenant_id,
                VirtualServerTool.vserver_id == vserver_id,
            )
            .order_by(VirtualServerTool.tool_name.asc())
        ).all()
    )


def update_virtual_server(
    db: VirtualServerSession | Session,
    *,
    tenant_id: UUID,
    vserver_id: UUID,
    request: UpdateVirtualServerRequest,
    actor: AdminAuditActor | None = None,
) -> VirtualServer:
    """Update mutable fields and (optionally) replace the tool allowlist.

    The allowlist replace is all-or-nothing: when `request.tools` is set, the
    existing rows for this vserver are deleted and re-inserted from the
    request. This is simpler than a diff/merge and matches the "operator
    edits the published tool list" UI shape — we don't need to preserve
    insertion order because the resolver synthesizes its own ordering.
    """

    virtual_server = get_virtual_server(
        db, tenant_id=tenant_id, vserver_id=vserver_id
    )

    changed_fields: list[str] = []

    if request.name is not None and request.name != virtual_server.name:
        existing_id = db.scalar(
            select(VirtualServer.id).where(
                VirtualServer.tenant_id == tenant_id,
                VirtualServer.name == request.name,
                VirtualServer.id != vserver_id,
            )
        )
        if existing_id is not None:
            raise DuplicateVirtualServerNameError
        virtual_server.name = request.name
        changed_fields.append("name")

    if request.policy_id is not None:
        virtual_server.policy_id = request.policy_id
        changed_fields.append("policy_id")

    if request.rename_map is not None:
        virtual_server.rename_map = dict(request.rename_map)
        changed_fields.append("rename_map")

    if request.tools is not None:
        _ensure_servers_in_tenant(db, tenant_id, [tool.server_id for tool in request.tools])
        # Replace the allowlist atomically. The cascade FK on
        # virtual_server_tools.vserver_id handles cleanup if the parent row
        # is dropped, but for an *update* we delete by primary-key columns.
        db.execute(
            delete(VirtualServerTool).where(
                VirtualServerTool.tenant_id == tenant_id,
                VirtualServerTool.vserver_id == vserver_id,
            )
        )
        for tool in _deduplicate_tools(request.tools):
            db.add(
                VirtualServerTool(
                    tenant_id=tenant_id,
                    vserver_id=vserver_id,
                    server_id=tool.server_id,
                    tool_name=tool.tool_name,
                )
            )
        changed_fields.append("tools")

    if actor is not None and changed_fields:
        record_admin_action(
            db,
            tenant_id=tenant_id,
            actor=actor,
            action="vserver.update",
            target=AdminAuditTarget(
                kind="vserver",
                id=virtual_server.id,
                display=virtual_server.name,
            ),
            detail={"fields": changed_fields},
        )

    try:
        db.commit()
        db.refresh(virtual_server)
    except IntegrityError as exc:
        db.rollback()
        raise DuplicateVirtualServerNameError from exc

    return virtual_server


def delete_virtual_server(
    db: VirtualServerSession | Session,
    *,
    tenant_id: UUID,
    vserver_id: UUID,
    actor: AdminAuditActor | None = None,
) -> None:
    """Drop a virtual server and its tool allowlist (FK CASCADE handles tools)."""
    virtual_server = get_virtual_server(
        db, tenant_id=tenant_id, vserver_id=vserver_id
    )
    # Capture display BEFORE delete (the row is gone after).
    deleted_name = virtual_server.name
    db.delete(virtual_server)
    if actor is not None:
        record_admin_action(
            db,
            tenant_id=tenant_id,
            actor=actor,
            action="vserver.delete",
            target=AdminAuditTarget(
                kind="vserver", id=vserver_id, display=deleted_name
            ),
        )
    db.commit()


def _ensure_operator_in_tenant(
    db: VirtualServerSession | Session,
    tenant_id: UUID,
    operator_id: UUID,
) -> None:
    existing_operator_id = db.scalar(
        select(Operator.id).where(
            Operator.tenant_id == tenant_id,
            Operator.id == operator_id,
        )
    )
    if existing_operator_id is None:
        raise VirtualServerCreatorNotFoundError


def _ensure_unique_name(
    db: VirtualServerSession | Session,
    tenant_id: UUID,
    name: str,
) -> None:
    existing_vserver_id = db.scalar(
        select(VirtualServer.id).where(
            VirtualServer.tenant_id == tenant_id,
            VirtualServer.name == name,
        )
    )
    if existing_vserver_id is not None:
        raise DuplicateVirtualServerNameError


def _ensure_servers_in_tenant(
    db: VirtualServerSession | Session,
    tenant_id: UUID,
    server_ids: list[UUID],
) -> None:
    unique_server_ids = set(server_ids)
    if not unique_server_ids:
        return

    found_server_ids = set(
        db.scalars(
            select(McpServer.id).where(
                McpServer.tenant_id == tenant_id,
                McpServer.id.in_(unique_server_ids),
            )
        )
    )
    if found_server_ids != unique_server_ids:
        raise UpstreamServerNotFoundError


def _deduplicate_tools(tools: list[AllowlistedTool]) -> list[AllowlistedTool]:
    return list({(tool.server_id, tool.tool_name): tool for tool in tools}.values())
