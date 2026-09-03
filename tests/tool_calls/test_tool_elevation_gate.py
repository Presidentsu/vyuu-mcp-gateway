"""JIT-2 · per-tool just-in-time elevation gate in the tool-call lifecycle.

No DB: a fake resolver hands the lifecycle a `ResolvedToolsList` carrying
`jit_tools`, and a fake checker answers the elevation question. That
isolates the *gate* from persistence, which the real-Postgres suite in
`tests/users/test_jit_tool_elevation.py` covers separately.

The properties under test:

- An elevation-gated tool is denied without a live elevation, and the
  denial is a `tool_call` event **naming the tool** — not an opaque
  connection-level 403 — so the operator can see what was refused.
- It **fails closed** on every "can't tell": no checker wired, a
  non-user principal, or a checker that raises. A gate that opens when
  it cannot establish authority is not a gate.
- Ungated tools are untouched, so `jit_tools` being empty by default
  means no existing deployment changes behaviour.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from vyuu_gateway.audit.emitter import EmitResult
from vyuu_gateway.audit.events import AuditEvent, AuditPrincipal, AuditPrincipalType
from vyuu_gateway.identity.models import ApiKeyPrincipal, Principal
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
_VSERVER = uuid4()
_TOOL = "db_migrate"
_UNGATED = "db_select"


class _Resolver:
    def __init__(self, jit_tools: dict[str, int]) -> None:
        self._jit_tools = jit_tools

    def resolve_tools(self, tenant_id: UUID, vserver_name: str) -> ResolvedToolsList:
        return ResolvedToolsList(
            tools=[
                ResolvedTool(
                    exposed_name=name,
                    upstream_server_id=_SERVER,
                    upstream_tool_name=name,
                    tool=make_tool(
                        name=name, input_schema={"type": "object", "properties": {}}
                    ),
                )
                for name in (_TOOL, _UNGATED)
            ],
            jit_tools=self._jit_tools,
            vserver_id=_VSERVER,
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
    """Reaching `get_client` is the observable proof the gate OPENED —
    "not denied" is a weaker claim than "actually got through"."""

    def __init__(self) -> None:
        self.reached = False

    def get_client(self, tenant_id: UUID, server_id: UUID) -> Any:
        self.reached = True
        raise RuntimeError("probe: no real upstream in this test")

    def get_auth_mode_flags(self, tenant_id: UUID, server_id: UUID) -> Any:
        from vyuu_gateway.audit.events import AuthModeFlags

        return AuthModeFlags()


class _Checker:
    """Records the query it was asked, so tests can assert the gate looks
    up the *exposed* name and the right vserver."""

    def __init__(self, *, answer: bool = True, raises: bool = False) -> None:
        self._answer = answer
        self._raises = raises
        self.calls: list[dict[str, Any]] = []

    def has_active_tool_elevation(self, **kwargs: Any) -> bool:
        self.calls.append(kwargs)
        if self._raises:
            raise RuntimeError("boom: elevation lookup exploded")
        return self._answer


def _run(
    *,
    jit_tools: dict[str, int],
    checker: Any,
    principal: Principal | None = None,
    tool_name: str = _TOOL,
) -> Any:
    session = GatewaySession(
        session_id="s-1",
        tenant_id=_TENANT,
        vserver_name="platform",
        principal=AuditPrincipal(type=AuditPrincipalType.API_KEY, id="p"),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    audit = _Audit()
    upstream = _UpstreamProbe()
    lifecycle = ToolCallLifecycle(
        sessions=_Registry(session),
        resolver=_Resolver(jit_tools),
        identity_provider=_StaticIdentity(principal or _user_principal()),
        policy_provider=SimplePolicyProvider(),
        upstream_clients=upstream,
        audit_emitter=audit,
        gateway_instance_id="gw",
        tool_elevation_checker=checker,
    )
    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=_TENANT,
                session_id="s-1",
                tool_name=tool_name,
                arguments={},
                session=session,
            )
        )
    )
    return result, audit, upstream


def _user_principal(user_id: str | None = None) -> ApiKeyPrincipal:
    return ApiKeyPrincipal(
        tenant_id=_TENANT,
        id=user_id or str(uuid4()),
        display="dana@corp.example",
        key_id=str(uuid4()),
    )


# --- The gate ---------------------------------------------------------------


def test_gated_tool_with_a_live_elevation_is_allowed_through() -> None:
    checker = _Checker(answer=True)
    result, _audit, upstream = _run(jit_tools={_TOOL: 1200}, checker=checker)

    assert result.status is not ToolCallStatus.NO_TOOL_ELEVATION
    # Positive proof the gate opened, not merely "wasn't denied".
    assert upstream.reached
    # And it asked the right question.
    assert checker.calls == [
        {
            "tenant_id": _TENANT,
            "vserver_id": _VSERVER,
            "exposed_tool_name": _TOOL,
            "principal_id": checker.calls[0]["principal_id"],
        }
    ]


def test_gated_tool_without_an_elevation_is_denied_naming_the_tool() -> None:
    """The denial must be a `tool_call` event carrying the tool name —
    that is the whole reason the gate lives in the lifecycle rather than
    in the connection-level access check."""

    result, audit, upstream = _run(
        jit_tools={_TOOL: 1200}, checker=_Checker(answer=False)
    )

    assert result.status is ToolCallStatus.NO_TOOL_ELEVATION
    assert result.decision.allowed is False
    assert not upstream.reached

    assert len(audit.events) == 1
    event = audit.events[0]
    assert event.tool == _TOOL
    assert event.policy_rule_id == PolicyDenyReason.NO_TOOL_ELEVATION.value


def test_ungated_tool_is_untouched_by_the_gate() -> None:
    """`jit_tools` is opt-in per tool: a tool absent from the map must
    never be asked about, let alone denied."""

    checker = _Checker(answer=False)
    _result, _audit, upstream = _run(
        jit_tools={_TOOL: 1200}, checker=checker, tool_name=_UNGATED
    )
    assert upstream.reached
    assert checker.calls == [], "ungated tool should not consult the checker"


def test_empty_jit_tools_changes_nothing() -> None:
    checker = _Checker(answer=False)
    _result, _audit, upstream = _run(jit_tools={}, checker=checker)
    assert upstream.reached
    assert checker.calls == []


# --- Fails closed -----------------------------------------------------------


def test_no_checker_wired_denies_a_gated_tool() -> None:
    """A deployment that gates a tool but never wires the lookup must not
    silently allow it. Fail closed."""

    result, _audit, upstream = _run(jit_tools={_TOOL: 1200}, checker=None)
    assert result.status is ToolCallStatus.NO_TOOL_ELEVATION
    assert not upstream.reached


def test_checker_raising_denies_rather_than_allows() -> None:
    """A gate that opens when the lookup errors is not a gate."""

    result, _audit, upstream = _run(
        jit_tools={_TOOL: 1200}, checker=_Checker(raises=True)
    )
    assert result.status is ToolCallStatus.NO_TOOL_ELEVATION
    assert not upstream.reached


def test_non_user_principal_is_denied_without_consulting_the_checker() -> None:
    """Only principals resolving to a real `users.id` can hold an
    elevation — same rule as vserver grants. A principal whose id is not
    a UUID is denied before the lookup, not after it."""

    checker = _Checker(answer=True)
    result, _audit, upstream = _run(
        jit_tools={_TOOL: 1200},
        checker=checker,
        principal=_user_principal(user_id="endpoint-session-1"),
    )
    assert result.status is ToolCallStatus.NO_TOOL_ELEVATION
    assert not upstream.reached
    assert checker.calls == []
