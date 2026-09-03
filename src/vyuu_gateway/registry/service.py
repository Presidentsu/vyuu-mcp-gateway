from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import (
    McpServer,
    McpServerHealthStatus,
    Operator,
)
from vyuu_gateway.registry.schemas import ServerRegistrationRequest


class RegistryError(Exception):
    """Base error for registry service failures."""


class OperatorNotFoundError(RegistryError):
    """Raised when the registering operator is not in the requested tenant."""


class DuplicateServerNameError(RegistryError):
    """Raised when a tenant already has a server with the requested display name."""


def register_mcp_server(
    db: Session,
    *,
    request: ServerRegistrationRequest,
    tenant_id: UUID,
    registered_by: UUID,
) -> McpServer:
    """Persist an MCP server under the given tenant and operator.

    `tenant_id` and `registered_by` MUST come from a trusted authentication
    context (e.g., the operator-API bearer-token dependency), never from the
    request body. The defense-in-depth check below re-verifies the operator
    actually exists in the claimed tenant in the operators table — if a
    bearer token's claims and the operators table disagree, we reject rather
    than persist a row keyed on the auth-provider claim alone.
    """

    operator_id = db.scalar(
        select(Operator.id).where(
            Operator.tenant_id == tenant_id,
            Operator.id == registered_by,
        )
    )
    if operator_id is None:
        raise OperatorNotFoundError

    existing_server_id = db.scalar(
        select(McpServer.id).where(
            McpServer.tenant_id == tenant_id,
            McpServer.display_name == request.display_name,
        )
    )
    if existing_server_id is not None:
        raise DuplicateServerNameError

    server = McpServer(
        id=uuid4(),
        tenant_id=tenant_id,
        display_name=request.display_name,
        source_type=request.source_type,
        source_location=request.source_location,
        transport=request.transport,
        env_vars_ref=request.env_vars_ref,
        args=request.args,
        auth_headers=dict(request.auth_headers),
        auth_env=dict(request.auth_env),
        auth_passthrough=dict(request.auth_passthrough),
        auth_oauth=(
            request.auth_oauth.model_dump(exclude_none=True)
            if request.auth_oauth is not None
            else None
        ),
        auth_authcode=(
            request.auth_authcode.model_dump(exclude_none=True)
            if request.auth_authcode is not None
            else None
        ),
        auth_jwt_bearer=(
            request.auth_jwt_bearer.model_dump(exclude_none=True)
            if request.auth_jwt_bearer is not None
            else None
        ),
        mtls_cert_ref=request.mtls_cert_ref,
        mtls_key_ref=request.mtls_key_ref,
        sync_cadence_minutes=request.sync_cadence_minutes,
        registered_by=registered_by,
        registered_at=datetime.now(UTC),
        health_status=McpServerHealthStatus.UNKNOWN,
    )

    try:
        db.add(server)
        db.commit()
        db.refresh(server)
    except IntegrityError as exc:
        db.rollback()
        raise DuplicateServerNameError from exc

    return server


def list_mcp_servers(db: Session, *, tenant_id: UUID) -> list[McpServer]:
    """List MCP servers visible to one tenant.

    The caller must pass tenant context explicitly. The SQL filter is kept even
    when the session is RLS-bound so tests can verify the tenant boundary and
    future non-RLS stores keep the same isolation contract.
    """

    return list(
        db.scalars(
            select(McpServer)
            .where(McpServer.tenant_id == tenant_id)
            .order_by(McpServer.registered_at.desc(), McpServer.display_name.asc())
        ).all()
    )


class ServerNotFoundError(Exception):
    """Raised when a server lookup misses for the operator's tenant."""


def delete_mcp_server(
    db: Session,
    *,
    tenant_id: UUID,
    server_id: UUID,
) -> dict[str, int]:
    """Delete an MCP server + cascade its dependents.

    All FK refs to `mcp_servers.id` are `ondelete=CASCADE`, so the
    Postgres-level cascade reaps:
      - `mcp_capabilities` rows for this server
      - `virtual_server_tools` rows referencing this server
      - `oauth_user_tokens` rows for this (tenant, user, server)

    Vservers that *only* wrap this server end up with an empty tool
    allowlist (still queryable, but `tools/list` returns []). We don't
    delete those vservers — the operator may want to keep them as
    placeholders. Returns a small summary so the operator UI can
    surface a confirmation toast.

    Tenant-scoped: a server_id from a different tenant raises
    `ServerNotFoundError` (anti-enumeration; same response shape as
    "doesn't exist").
    """
    from sqlalchemy import delete as sa_delete
    from sqlalchemy import func as sa_func

    from vyuu_gateway.db.models import (
        McpCapability,
        OAuthUserToken,
        VirtualServerTool,
    )

    server = db.scalar(
        select(McpServer).where(
            McpServer.tenant_id == tenant_id,
            McpServer.id == server_id,
        )
    )
    if server is None:
        raise ServerNotFoundError

    # Count dependents BEFORE the delete so the response is meaningful.
    cap_count = db.scalar(
        select(sa_func.count(McpCapability.id)).where(
            McpCapability.server_id == server_id,
            McpCapability.tenant_id == tenant_id,
        )
    ) or 0
    tool_exposure_count = db.scalar(
        select(sa_func.count(VirtualServerTool.tool_name)).where(
            VirtualServerTool.server_id == server_id,
        )
    ) or 0
    token_count = db.scalar(
        select(sa_func.count(OAuthUserToken.id)).where(
            OAuthUserToken.server_id == server_id,
            OAuthUserToken.tenant_id == tenant_id,
        )
    ) or 0

    db.execute(
        sa_delete(McpServer).where(
            McpServer.tenant_id == tenant_id,
            McpServer.id == server_id,
        )
    )
    db.commit()

    return {
        "capabilities_deleted": int(cap_count),
        "vserver_tool_exposures_removed": int(tool_exposure_count),
        "oauth_user_tokens_revoked": int(token_count),
    }


def update_sync_cadence(
    db: Session,
    *,
    tenant_id: UUID,
    server_id: UUID,
    sync_cadence_minutes: int | None,
) -> McpServer:
    """Update a server's per-server sync cadence.

    NULL means "use the global default", 0 means "manual only — never
    auto-sync", positive int caps the per-server frequency at every N
    minutes. The CHECK constraint at the schema level rejects negative
    values; the Pydantic schema also bounds at 30 days.
    """

    server = db.scalar(
        select(McpServer).where(
            McpServer.tenant_id == tenant_id,
            McpServer.id == server_id,
        )
    )
    if server is None:
        raise ServerNotFoundError
    server.sync_cadence_minutes = sync_cadence_minutes
    db.commit()
    db.refresh(server)
    return server
