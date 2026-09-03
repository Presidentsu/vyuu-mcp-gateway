"""EMA-1 P3 · per-tool OAuth scope gating in the tool-call lifecycle.

No DB: a fake resolver hands the lifecycle a `ResolvedToolsList`
carrying `required_scopes`, and a fake identity provider supplies the
principal under test. That isolates the gate itself from vserver
persistence, which the real-Postgres EMA suite already covers.

The property under test is the "AND-combine" decision: scope narrows,
never widens. Grants/visibility have already said the principal may
reach the vserver; the gate asks the further question "did the
principal's issuer authorize THIS tool?".
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from vyuu_gateway.audit.emitter import EmitResult
from vyuu_gateway.audit.events import AuditEvent, AuditPrincipal, AuditPrincipalType
from vyuu_gateway.identity.models import (
    ApiKeyPrincipal,
    FederatedUserPrincipal,
    Principal,
)
from vyuu_gateway.mcp.sdk_compat import make_tool
from vyuu_gateway.policy.interfaces import PolicyDenyReason
from vyuu_gateway.policy.simple import SimplePolicyProvider
from vyuu_gateway.sessions.registry import GatewaySession
from vyuu_gateway.tool_calls.lifecycle import (
    ToolCallLifecycle,
    ToolCallRequest,
    ToolCallStatus,
)
from vyuu_gateway.virtual_servers.resolver import ResolvedTool, ResolvedToolsList

_TENANT = uuid4()
_SERVER = uuid4()
_TOOL = "delete_repo"


class _Resolver:
    def __init__(self, required_scopes: dict[str, str]) -> None:
        self._required = required_scopes

    def resolve_tools(self, tenant_id: UUID, vserver_name: str) -> ResolvedToolsList:
        return ResolvedToolsList(
            tools=[
                ResolvedTool(
                    exposed_name=_TOOL,
                    upstream_server_id=_SERVER,
                    upstream_tool_name=_TOOL,
                    tool=make_tool(
                        name=_TOOL,
                        input_schema={"type": "object", "properties": {}},
                    ),
                )
            ],
            required_scopes=self._required,
        )


class _StaticIdentity:
    def __init__(self, principal: Principal) -> None:
        self._principal = principal

    def validate_principal(self, *, tenant_id: UUID, credentials: Any) -> Principal:
        return self._principal


class _Registry:
    def __init__(self, session: GatewaySession) -> None:
        self._session = session

    async def create_session(self, session: GatewaySession) -> None: ...
    async def delete_session(self, tenant_id: UUID, session_id: str) -> None: ...
    async def get_session(self, tenant_id: UUID, session_id: str) -> GatewaySession:
        return self._session


class _Audit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        self.events.append(event)
        return EmitResult(accepted=True)


class _UpstreamProbe:
    """Records whether the call got past the gate.

    Reaching `get_client` is the observable signal that the scope gate
    allowed the call through; it then raises so no real upstream work
    happens (the lifecycle turns that into `upstream_error`, which is
    irrelevant to what these tests assert).
    """

    def __init__(self) -> None:
        self.reached = False

    def get_client(self, tenant_id: UUID, server_id: UUID) -> Any:
        self.reached = True
        raise RuntimeError("probe: no real upstream in this test")

    def get_auth_mode_flags(self, tenant_id: UUID, server_id: UUID) -> Any:
        from vyuu_gateway.audit.events import AuthModeFlags

        return AuthModeFlags()


def _run(principal: Principal, required_scopes: dict[str, str]) -> Any:
    session = GatewaySession(
        session_id="s-1",
        tenant_id=_TENANT,
        vserver_name="finance",
        principal=AuditPrincipal(type=AuditPrincipalType.API_KEY, id="p"),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    audit = _Audit()
    upstream = _UpstreamProbe()
    lifecycle = ToolCallLifecycle(
        sessions=_Registry(session),
        resolver=_Resolver(required_scopes),
        identity_provider=_StaticIdentity(principal),
        policy_provider=SimplePolicyProvider(),
        upstream_clients=upstream,
        audit_emitter=audit,
        gateway_instance_id="gw",
    )
    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=_TENANT,
                session_id="s-1",
                tool_name=_TOOL,
                arguments={},
                session=session,
            )
        )
    )
    return result, audit, upstream


def _federated(scopes: frozenset[str]) -> FederatedUserPrincipal:
    return FederatedUserPrincipal(
        tenant_id=_TENANT,
        id=str(uuid4()),
        display="priya@corp.example",
        external_id="okta-sub",
        client_id="cursor-app",
        scopes=scopes,
    )


def test_federated_principal_holding_the_scope_is_allowed_through_the_gate() -> None:
    result, _audit, upstream = _run(
        _federated(frozenset({"repo.delete"})), {_TOOL: "repo.delete"}
    )
    assert result.status is not ToolCallStatus.INSUFFICIENT_SCOPE
    # Positive proof the gate opened, rather than merely "not denied".
    assert upstream.reached


def test_federated_principal_missing_the_scope_is_denied() -> None:
    result, audit, upstream = _run(
        _federated(frozenset({"repo.read"})), {_TOOL: "repo.delete"}
    )
    assert result.status is ToolCallStatus.INSUFFICIENT_SCOPE
    assert not result.allowed
    # Denied BEFORE any upstream contact — no side effect escapes.
    assert not upstream.reached
    assert result.decision.reason is PolicyDenyReason.INSUFFICIENT_SCOPE
    # The denial is auditable and names the tool, so it lands in the
    # Events panel as a tool_call deny rather than a bare 401.
    assert audit.events, "scope denial must be audited"
    ev = audit.events[-1]
    assert ev.tool == _TOOL
    assert ev.decision.value == "deny"
    assert ev.policy_rule_id == "insufficient_scope"


def test_api_key_principal_fails_closed_on_a_scope_gated_tool() -> None:
    """An API key carries no scopes at all, so it cannot demonstrate the
    required authority. Documented, deliberate: scope gating fails
    closed."""

    principal = ApiKeyPrincipal(
        tenant_id=_TENANT, id=str(uuid4()), display="svc", key_id=str(uuid4())
    )
    result, _audit, upstream = _run(principal, {_TOOL: "repo.delete"})
    assert result.status is ToolCallStatus.INSUFFICIENT_SCOPE
    assert not upstream.reached


def test_ungated_tool_is_untouched_by_the_feature() -> None:
    """Regression guard: an empty `required_scopes` map — every existing
    vserver — must behave exactly as before for every principal type."""

    for principal in (
        _federated(frozenset()),
        ApiKeyPrincipal(
            tenant_id=_TENANT, id=str(uuid4()), display="svc", key_id=str(uuid4())
        ),
    ):
        result, _audit, upstream = _run(principal, {})
        assert result.status is not ToolCallStatus.INSUFFICIENT_SCOPE
        assert upstream.reached


def test_gate_only_applies_to_the_named_tool() -> None:
    result, _audit, upstream = _run(_federated(frozenset()), {"some_other_tool": "x.y"})
    assert result.status is not ToolCallStatus.INSUFFICIENT_SCOPE
    assert upstream.reached
