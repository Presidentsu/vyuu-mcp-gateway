import asyncio
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from inspect import Parameter, signature
from typing import Any, cast
from uuid import UUID, uuid4

import pytest

from vyuu_gateway.audit.emitter import EmitResult
from vyuu_gateway.audit.events import (
    AuditEvent,
    AuditPrincipal,
    AuditPrincipalType,
    AuthModeFlags,
)
from vyuu_gateway.capabilities.client import CapabilityDescriptor
from vyuu_gateway.capabilities.sync import DatabaseCapabilitySyncService, McpServerNotFoundError
from vyuu_gateway.db.base import Base
from vyuu_gateway.db.models import McpCapability
from vyuu_gateway.identity.fake import FakeIdentityProvider
from vyuu_gateway.identity.models import PrincipalType
from vyuu_gateway.identity.provider import IdentityCredentials
from vyuu_gateway.policy.simple import SimplePolicyProvider
from vyuu_gateway.registry.schemas import ServerRegistrationRequest
from vyuu_gateway.registry.service import list_mcp_servers, register_mcp_server
from vyuu_gateway.sessions.registry import GatewaySession
from vyuu_gateway.tool_calls.lifecycle import (
    ToolCallLifecycle,
    ToolCallRequest,
    ToolCallStatus,
)
from vyuu_gateway.virtual_servers.resolver import VirtualServerResolver
from vyuu_gateway.virtual_servers.schemas import CreateVirtualServerRequest
from vyuu_gateway.virtual_servers.service import (
    VirtualServerNotFoundError,
    add_allowlisted_tools,
    create_virtual_server,
)


class MissingVirtualServerSession:
    def __init__(self) -> None:
        self.scalar_statements: list[object] = []
        self.execute_called = False

    def scalar(self, statement: Any) -> None:
        self.scalar_statements.append(statement)
        return None

    def execute(self, statement: Any) -> list[tuple[object, ...]]:
        self.execute_called = True
        raise AssertionError("tenant-mismatched virtual server should stop before tool lookup")


class MissingServerSession:
    def __init__(self) -> None:
        self.scalar_statements: list[object] = []
        self.scalars_called = False
        self.committed = False

    def scalar(self, statement: Any) -> None:
        self.scalar_statements.append(statement)
        return None

    def scalars(self, statement: Any) -> Iterable[McpCapability]:
        self.scalars_called = True
        return ()

    def add(self, instance: object) -> None:
        raise AssertionError("tenant-mismatched capability sync should not persist rows")

    def commit(self) -> None:
        self.committed = True


class FailingCapabilityClient:
    def __init__(self) -> None:
        self.called = False

    async def list_capabilities(
        self, server: object, *, principal_id: object = None
    ) -> list[CapabilityDescriptor]:
        del server, principal_id
        self.called = True
        raise AssertionError("tenant-mismatched server should not be probed")


class ServerListSession:
    def __init__(self) -> None:
        self.statements: list[object] = []

    def scalars(self, statement: object) -> "_EmptyScalarResult":
        self.statements.append(statement)
        return _EmptyScalarResult()


class _EmptyScalarResult:
    def all(self) -> list[object]:
        return []


def test_tenant_a_cannot_list_tenant_b_servers() -> None:
    session = ServerListSession()

    servers = list_mcp_servers(cast(Any, session), tenant_id=uuid4())

    assert servers == []
    assert "mcp_servers.tenant_id" in str(session.statements[0])


def test_tenant_a_cannot_access_tenant_b_virtual_servers() -> None:
    tenant_a_id = uuid4()
    session = MissingVirtualServerSession()

    with pytest.raises(VirtualServerNotFoundError):
        VirtualServerResolver(session).resolve_tools(tenant_a_id, "tenant-b-vserver")

    assert "virtual_servers.tenant_id" in str(session.scalar_statements[0])
    assert not session.execute_called


def test_tenant_a_cannot_see_tenant_b_capabilities() -> None:
    session = MissingServerSession()
    client = FailingCapabilityClient()

    with pytest.raises(McpServerNotFoundError):
        asyncio.run(
            DatabaseCapabilitySyncService(session, client).sync_server_capabilities(
                uuid4(), uuid4()
            )
        )

    assert "mcp_servers.tenant_id" in str(session.scalar_statements[0])
    assert not session.scalars_called
    assert not session.committed
    assert not client.called


class _StaticSessionRegistry:
    """Test registry that returns a single pre-built `GatewaySession`."""

    def __init__(self, session: GatewaySession) -> None:
        self._session = session

    async def create_session(self, session: GatewaySession) -> None:
        self._session = session

    async def get_session(self, tenant_id: UUID, session_id: str) -> GatewaySession | None:
        if (tenant_id, session_id) != (self._session.tenant_id, self._session.session_id):
            return None
        return self._session

    async def delete_session(self, tenant_id: UUID, session_id: str) -> None:
        return None


class _RecordingAuditEmitter:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        self.events.append(event)
        return EmitResult(accepted=True)


class _AssertingUpstreamProvider:
    """Provider whose `get_client` should never run for a tenant-mismatched call."""

    def get_client(self, tenant_id: UUID, server_id: UUID) -> Any:
        raise AssertionError(
            "tenant-mismatched virtual server should be rejected before upstream resolution"
        )

    def get_auth_mode_flags(
        self, tenant_id: UUID, server_id: UUID
    ) -> AuthModeFlags:
        return AuthModeFlags()


def test_tenant_a_cannot_call_tools_from_tenant_b_vserver() -> None:
    """Crossing the tool-call entry point with a virtual server name that does
    not exist in tenant A's tenant must surface as `TOOL_NOT_IN_VIRTUAL_SERVER`,
    not leak across tenants. Resolver-level filtering is covered by
    `test_tenant_a_cannot_access_tenant_b_virtual_servers` — this verifies the
    full lifecycle correctly translates the resolver's failure to a deny without
    reaching upstream."""
    tenant_a_id = uuid4()
    db_session = MissingVirtualServerSession()
    gateway_session = GatewaySession(
        session_id="session-1",
        tenant_id=tenant_a_id,
        vserver_name="tenant-b-vserver",
        principal=AuditPrincipal(type=AuditPrincipalType.API_KEY, id="api-key-1"),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    audit_emitter = _RecordingAuditEmitter()
    lifecycle = ToolCallLifecycle(
        sessions=_StaticSessionRegistry(gateway_session),
        resolver=VirtualServerResolver(db_session),
        identity_provider=FakeIdentityProvider(),
        policy_provider=SimplePolicyProvider(),
        upstream_clients=_AssertingUpstreamProvider(),
        audit_emitter=audit_emitter,
        gateway_instance_id="gateway-1",
    )

    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=tenant_a_id,
                session_id="session-1",
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=IdentityCredentials(
                    headers={
                        "x-vyuu-tenant-id": str(tenant_a_id),
                        "x-vyuu-principal-type": PrincipalType.ENDPOINT_SESSION.value,
                        "x-vyuu-principal-id": "endpoint-session-1",
                    }
                ),
            )
        )
    )

    assert result.status == ToolCallStatus.TOOL_NOT_IN_VIRTUAL_SERVER
    assert "virtual_servers.tenant_id" in str(db_session.scalar_statements[0])
    assert not db_session.execute_called
    assert len(audit_emitter.events) == 1
    assert audit_emitter.events[0].decision == "deny"


def test_tenant_id_is_required_on_all_tenant_scoped_db_rows() -> None:
    tenant_scoped_tables = set(Base.metadata.tables) - {"tenants"}

    assert tenant_scoped_tables == {
        "access_requests",
        "admin_audit_log",
        "api_key_policies",
        "ema_consumed_jti",
        "groups",
        "idp_directories",
        "mcp_capabilities",
        "mcp_server_dcr_clients",
        "mcp_server_risk_assessments",
        "mcp_servers",
        "oauth_user_tokens",
        "operators",
        "tenant_siem_targets",
        "tool_call_events",
        "user_api_keys",
        "user_group_memberships",
        "users",
        "virtual_server_grants",
        "virtual_server_risk_assessments",
        "virtual_server_tool_grants",
        "virtual_server_tools",
        "virtual_servers",
    }

    # `user_group_memberships` is the only join table — its tenant
    # scoping is enforced via FKs to `users.tenant_id` and
    # `groups.tenant_id`, so it doesn't need its own column.
    tables_without_tenant_id_column = {"user_group_memberships"}
    for table_name in tenant_scoped_tables - tables_without_tenant_id_column:
        table = Base.metadata.tables[table_name]
        tenant_id_column = table.columns.get("tenant_id")

        assert tenant_id_column is not None, table_name
        assert not tenant_id_column.nullable, table_name


def test_all_repository_and_service_methods_require_tenant_context() -> None:
    tenant_scoped_methods: Iterable[Callable[..., object]] = (
        register_mcp_server,
        list_mcp_servers,
        DatabaseCapabilitySyncService.sync_server_capabilities,
        VirtualServerResolver.resolve_tools,
        VirtualServerResolver.synthesize_tools_list,
        create_virtual_server,
        add_allowlisted_tools,
        ToolCallLifecycle.handle_tool_call,
    )

    for method in tenant_scoped_methods:
        assert _requires_tenant_context(method), method.__qualname__


def _requires_tenant_context(method: Callable[..., object]) -> bool:
    parameters = signature(method).parameters

    tenant_id = parameters.get("tenant_id")
    if tenant_id is not None and tenant_id.default is Parameter.empty:
        return True

    request = parameters.get("request")
    if request is None or request.default is not Parameter.empty:
        return False

    return _request_model_requires_tenant_id(request.annotation)


def _request_model_requires_tenant_id(annotation: object) -> bool:
    if annotation is ServerRegistrationRequest:
        return "tenant_id" in ServerRegistrationRequest.model_fields
    if annotation is CreateVirtualServerRequest:
        return "tenant_id" in CreateVirtualServerRequest.model_fields
    if annotation is ToolCallRequest:
        return "tenant_id" in ToolCallRequest.__dataclass_fields__
    return False
