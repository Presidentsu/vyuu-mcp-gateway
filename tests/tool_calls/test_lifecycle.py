import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from mcp.types import CallToolResult, TextContent

from vyuu_gateway.audit.emitter import DiskSpoolAuditEmitter, EmitResult
from vyuu_gateway.audit.events import (
    AuditEvent,
    AuditPrincipal,
    AuditPrincipalType,
    AuthModeFlags,
    UpstreamStatus,
)
from vyuu_gateway.audit.failure import AuditFailureMode
from vyuu_gateway.audit.spool import DiskSpool
from vyuu_gateway.identity.fake import FakeIdentityProvider
from vyuu_gateway.identity.models import PrincipalType
from vyuu_gateway.identity.provider import IdentityCredentials
from vyuu_gateway.policy.interfaces import (
    PolicyDecision,
    PolicyDenyReason,
    PolicyProvider,
    ToolCallPolicyContext,
)
from vyuu_gateway.policy.simple import SimplePolicyProvider
from vyuu_gateway.sessions.registry import GatewaySession
from vyuu_gateway.tool_calls import lifecycle as lifecycle_module
from vyuu_gateway.tool_calls.lifecycle import (
    ToolCallLifecycle,
    ToolCallLifecycleResult,
    ToolCallRequest,
    ToolCallStatus,
    UpstreamToolClientProvider,
)
from vyuu_gateway.upstream.circuit_breaker import CircuitBreakerOpenError
from vyuu_gateway.virtual_servers.resolver import (
    ResolvedToolsList,
    VirtualServerToolCapability,
    synthesize_tools,
)


def _far_future() -> datetime:
    return datetime.now(UTC) + timedelta(hours=1)


class FakeSessionRegistry:
    def __init__(self, session: GatewaySession | None) -> None:
        self.session = session
        self.calls: list[tuple[UUID, str]] = []

    async def create_session(self, session: GatewaySession) -> None:
        self.session = session

    async def get_session(self, tenant_id: UUID, session_id: str) -> GatewaySession | None:
        self.calls.append((tenant_id, session_id))
        if self.session is None:
            return None
        if self.session.tenant_id != tenant_id or self.session.session_id != session_id:
            return None
        return self.session

    async def delete_session(self, tenant_id: UUID, session_id: str) -> None:
        if self.session is not None and (
            self.session.tenant_id == tenant_id
            and self.session.session_id == session_id
        ):
            self.session = None


class FakeResolver:
    def __init__(self, resolved_tools: ResolvedToolsList) -> None:
        self.resolved_tools = resolved_tools
        self.calls: list[tuple[UUID, str]] = []

    def resolve_tools(self, tenant_id: UUID, vserver_name: str) -> ResolvedToolsList:
        self.calls.append((tenant_id, vserver_name))
        return self.resolved_tools


class FakeAuditEmitter:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        self.events.append(event)
        return EmitResult(accepted=True)


class RejectingAuditEmitter:
    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        return EmitResult(accepted=False, degraded=True, reason="producer_down")

    def can_durably_accept_now(self) -> bool:
        return False


class RaisingPolicyProvider:
    def __init__(self) -> None:
        self.calls = 0

    def evaluate_tool_call(self, context: ToolCallPolicyContext) -> PolicyDecision:
        self.calls += 1
        raise RuntimeError("policy unavailable")


class UnexpectedPolicyProvider:
    def evaluate_tool_call(self, context: ToolCallPolicyContext) -> PolicyDecision:
        raise AssertionError("malformed args should fail before policy evaluation")


class RuleDenyPolicyProvider:
    def evaluate_tool_call(self, context: ToolCallPolicyContext) -> PolicyDecision:
        return PolicyDecision.deny(
            PolicyDenyReason.TOOL_DENIED,
            "denied by rule",
            rule_id="mgmt-rule-1",
        )


class FakeUpstreamClient:
    def __init__(
        self,
        *,
        response: CallToolResult | None = None,
        exception: Exception | None = None,
    ) -> None:
        self.response = response or make_response("ok")
        self.exception = exception
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        inbound_headers: dict[str, str] | None = None,
        principal_id: object = None,
    ) -> CallToolResult:
        self.calls.append((tool_name, arguments))
        self.last_inbound_headers = inbound_headers
        self.last_principal_id = principal_id
        if self.exception is not None:
            raise self.exception
        return self.response


class FakeUpstreamClientProvider:
    def __init__(self, client: FakeUpstreamClient) -> None:
        self.client = client
        self.calls: list[tuple[UUID, UUID]] = []

    def get_client(self, tenant_id: UUID, server_id: UUID) -> FakeUpstreamClient:
        self.calls.append((tenant_id, server_id))
        return self.client

    def get_auth_mode_flags(
        self, tenant_id: UUID, server_id: UUID
    ) -> AuthModeFlags:
        return AuthModeFlags()


class OpenCircuitUpstreamClientProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[UUID, UUID]] = []

    def get_client(self, tenant_id: UUID, server_id: UUID) -> FakeUpstreamClient:
        self.calls.append((tenant_id, server_id))
        raise CircuitBreakerOpenError("open")

    def get_auth_mode_flags(
        self, tenant_id: UUID, server_id: UUID
    ) -> AuthModeFlags:
        return AuthModeFlags()


@dataclass(frozen=True)
class LifecycleFixture:
    tenant_id: UUID
    session: GatewaySession
    resolver: FakeResolver
    upstream_client: FakeUpstreamClient
    upstream_provider: FakeUpstreamClientProvider
    audit_emitter: FakeAuditEmitter


def test_lifecycle_allows_valid_call_invokes_upstream_and_emits_audit() -> None:
    fixture = make_fixture()

    result = run_lifecycle(fixture)

    assert result.status == ToolCallStatus.ALLOWED
    assert result.allowed
    assert result.response is not None
    assert fixture.resolver.calls == [(fixture.tenant_id, "finance-readonly")]
    assert fixture.upstream_provider.calls == [
        (fixture.tenant_id, fixture.resolver.resolved_tools.tools[0].upstream_server_id)
    ]
    assert fixture.upstream_client.calls == [("query_select", {"sql": "select 1"})]
    event = only_event(fixture.audit_emitter)
    assert event.decision == "allow"
    assert event.principal.type == AuditPrincipalType.ENDPOINT_SESSION
    assert event.principal.id == "endpoint-session-1"
    assert event.upstream_status == UpstreamStatus.OK
    assert event.response_size_bytes is not None
    assert event.latency_ms_total is not None
    assert event.latency_ms_upstream is not None
    assert "select 1" not in str(event.args_summary)


def test_lifecycle_threads_principal_uuid_to_upstream_call() -> None:
    """A1: when the inbound principal carries a UUID-shaped id (the
    ApiKeyIdentityProvider sets `principal.id` to the user's UUID),
    the lifecycle must forward that as `principal_id=<UUID>` so the
    auth_authcode token provider can look up the right user's row.

    Non-UUID principal ids (the lab's FakeIdentityProvider sets
    free-form strings) collapse to None. Phase-3 / phase-2 token
    providers ignore the field; phase-4 raises a clean
    OAuthTokenError when None — covered in
    `tests/upstream/test_oauth_authcode.py::test_principal_id_required`."""

    user_uuid = uuid4()
    fixture = make_fixture()

    lifecycle = ToolCallLifecycle(
        sessions=FakeSessionRegistry(fixture.session),
        resolver=fixture.resolver,
        identity_provider=FakeIdentityProvider(),
        policy_provider=SimplePolicyProvider(),
        upstream_clients=fixture.upstream_provider,
        audit_emitter=fixture.audit_emitter,
        gateway_instance_id="gateway-1",
    )
    creds = IdentityCredentials(
        headers={
            "x-vyuu-tenant-id": str(fixture.tenant_id),
            "x-vyuu-principal-type": PrincipalType.ENDPOINT_SESSION.value,
            # The id IS a UUID — that's what the api-key provider would
            # produce in production.
            "x-vyuu-principal-id": str(user_uuid),
            "x-vyuu-principal-display": "End user",
        }
    )
    asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=fixture.tenant_id,
                session_id=fixture.session.session_id,
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=creds,
                inbound_headers={},
            )
        )
    )

    assert fixture.upstream_client.last_principal_id == user_uuid


def test_lifecycle_collapses_non_uuid_principal_id_to_none() -> None:
    """The lab's FakeIdentityProvider sets free-form ids like
    "endpoint-session-1". The lifecycle must NOT pass that through as a
    string — phase-3 token providers ignore None safely, but a stray
    string would surface as a downstream parse error in the phase-4
    provider. Cast/parse failure → None is the safe default."""

    fixture = make_fixture()
    # Default make_identity_credentials sends `endpoint-session-1`.
    run_lifecycle(fixture)
    assert fixture.upstream_client.last_principal_id is None





def test_lifecycle_threads_inbound_headers_to_upstream_call() -> None:
    """User-tier auth: the lifecycle must hand the inbound request's
    headers to the upstream client unchanged. The upstream client (real
    StreamableHttpMcpClient) does the per-server filtering through its
    `auth_passthrough_map`. Lifecycle just plumbs."""
    fixture = make_fixture()

    inbound = {
        "x-vyuu-paypal-token": "Bearer alice-personal-pat",
        "x-random": "should-still-be-passed-along-and-filtered-downstream",
    }
    result = run_lifecycle(fixture, inbound_headers=inbound)

    assert result.status == ToolCallStatus.ALLOWED
    # Upstream client received the inbound headers verbatim — filtering
    # happens inside the StreamableHttpMcpClient, not in the lifecycle.
    assert fixture.upstream_client.last_inbound_headers == inbound


def test_lifecycle_denies_policy_blocked_call_and_emits_audit() -> None:
    fixture = make_fixture()

    result = run_lifecycle(
        fixture,
        policy_provider=SimplePolicyProvider(denied_tools={"query"}),
    )

    assert result.status == ToolCallStatus.DENIED
    assert not result.allowed
    assert fixture.upstream_client.calls == []
    event = only_event(fixture.audit_emitter)
    assert event.decision == "deny"
    assert event.upstream_status == UpstreamStatus.NOT_CALLED
    assert event.policy_rule_id == "tool_denied"


def test_lifecycle_uses_policy_decision_rule_id_in_audit() -> None:
    fixture = make_fixture()

    result = run_lifecycle(fixture, policy_provider=RuleDenyPolicyProvider())

    assert result.status == ToolCallStatus.DENIED
    assert fixture.upstream_client.calls == []
    event = only_event(fixture.audit_emitter)
    assert event.policy_rule_id == "mgmt-rule-1"


def test_lifecycle_denies_malformed_args_before_policy_or_upstream_and_emits_audit() -> None:
    fixture = make_fixture()

    result = run_lifecycle(
        fixture,
        request_args={"sql": 10},
        policy_provider=UnexpectedPolicyProvider(),
    )

    assert result.status == ToolCallStatus.MALFORMED_ARGS
    assert not result.allowed
    assert fixture.upstream_client.calls == []
    event = only_event(fixture.audit_emitter)
    assert event.decision == "deny"
    assert event.upstream_status == UpstreamStatus.NOT_CALLED
    assert event.policy_rule_id == "malformed_args"


def test_lifecycle_records_upstream_timeout_audit() -> None:
    fixture = make_fixture(upstream_client=FakeUpstreamClient(exception=TimeoutError()))

    result = run_lifecycle(fixture)

    assert result.status == ToolCallStatus.UPSTREAM_TIMEOUT
    assert result.decision.allowed
    event = only_event(fixture.audit_emitter)
    assert event.decision == "allow"
    assert event.upstream_status == UpstreamStatus.TIMEOUT
    assert event.latency_ms_upstream is not None


def test_lifecycle_records_upstream_error_audit() -> None:
    fixture = make_fixture(upstream_client=FakeUpstreamClient(exception=RuntimeError("boom")))

    result = run_lifecycle(fixture)

    assert result.status == ToolCallStatus.UPSTREAM_ERROR
    assert result.decision.allowed
    event = only_event(fixture.audit_emitter)
    assert event.decision == "allow"
    assert event.upstream_status == UpstreamStatus.ERROR
    assert event.latency_ms_upstream is not None


def test_lifecycle_records_open_circuit_as_upstream_error_audit() -> None:
    fixture = make_fixture()
    upstream_provider = OpenCircuitUpstreamClientProvider()

    result = run_lifecycle(fixture, upstream_provider=upstream_provider)

    assert result.status == ToolCallStatus.UPSTREAM_ERROR
    # Hotfix #1's verbose-error change: `error_message` now embeds
    # both the exception class AND its repr, so operators see actual
    # detail like "TypeError: foo missing 1 required arg" instead of
    # bare "TypeError". The class-name prefix stays stable.
    assert result.error_message is not None
    assert result.error_message.startswith("CircuitBreakerOpenError")
    event = only_event(fixture.audit_emitter)
    assert event.decision == "allow"
    assert event.upstream_status == UpstreamStatus.ERROR
    assert fixture.upstream_client.calls == []


def test_lifecycle_records_policy_engine_error_audit_without_upstream_call() -> None:
    fixture = make_fixture()
    policy_provider = RaisingPolicyProvider()

    result = run_lifecycle(fixture, policy_provider=policy_provider)

    assert result.status == ToolCallStatus.POLICY_ENGINE_ERROR
    assert not result.allowed
    assert result.decision.reason is not None
    assert result.decision.reason.value == "policy_engine_error"
    assert policy_provider.calls == 1
    assert fixture.upstream_client.calls == []
    event = only_event(fixture.audit_emitter)
    assert event.decision == "deny"
    assert event.upstream_status == UpstreamStatus.NOT_CALLED
    assert event.policy_rule_id == "policy_engine_error"


def test_lifecycle_records_missing_session_audit_without_resolution_or_upstream() -> None:
    fixture = make_fixture()
    sessions = FakeSessionRegistry(session=None)
    lifecycle = ToolCallLifecycle(
        sessions=sessions,
        resolver=fixture.resolver,
        identity_provider=FakeIdentityProvider(),
        policy_provider=SimplePolicyProvider(),
        upstream_clients=fixture.upstream_provider,
        audit_emitter=fixture.audit_emitter,
        gateway_instance_id="gateway-1",
    )

    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=fixture.tenant_id,
                session_id="missing",
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=make_identity_credentials(fixture.tenant_id),
            )
        )
    )

    assert result.status == ToolCallStatus.SESSION_NOT_FOUND
    assert fixture.resolver.calls == []
    assert fixture.upstream_client.calls == []
    event = only_event(fixture.audit_emitter)
    assert event.decision == "deny"
    assert event.upstream_status == UpstreamStatus.NOT_CALLED
    assert event.policy_rule_id == "session_not_found"


def test_lifecycle_rejects_invalid_identity_before_policy_or_upstream() -> None:
    fixture = make_fixture()
    policy_provider = UnexpectedPolicyProvider()
    lifecycle = ToolCallLifecycle(
        sessions=FakeSessionRegistry(fixture.session),
        resolver=fixture.resolver,
        identity_provider=FakeIdentityProvider(),
        policy_provider=policy_provider,
        upstream_clients=fixture.upstream_provider,
        audit_emitter=fixture.audit_emitter,
        gateway_instance_id="gateway-1",
    )

    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=fixture.tenant_id,
                session_id=fixture.session.session_id,
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=IdentityCredentials(headers={}),
            )
        )
    )

    assert result.status == ToolCallStatus.IDENTITY_INVALID
    assert not result.allowed
    assert fixture.resolver.calls == []
    assert fixture.upstream_client.calls == []
    event = only_event(fixture.audit_emitter)
    assert event.decision == "deny"
    assert event.policy_rule_id == "identity_invalid"


def test_strict_audit_mode_blocks_when_audit_cannot_be_durably_queued() -> None:
    fixture = make_fixture()
    lifecycle = ToolCallLifecycle(
        sessions=FakeSessionRegistry(fixture.session),
        resolver=fixture.resolver,
        identity_provider=FakeIdentityProvider(),
        policy_provider=SimplePolicyProvider(),
        upstream_clients=fixture.upstream_provider,
        audit_emitter=RejectingAuditEmitter(),
        gateway_instance_id="gateway-1",
        audit_failure_mode=AuditFailureMode.STRICT,
    )

    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=fixture.tenant_id,
                session_id=fixture.session.session_id,
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=make_identity_credentials(fixture.tenant_id),
            )
        )
    )

    assert result.status == ToolCallStatus.AUDIT_UNAVAILABLE
    assert not result.allowed
    assert fixture.upstream_client.calls == []


def test_strict_audit_mode_allows_when_disk_spool_is_available(tmp_path: Path) -> None:
    fixture = make_fixture()
    lifecycle = ToolCallLifecycle(
        sessions=FakeSessionRegistry(fixture.session),
        resolver=fixture.resolver,
        identity_provider=FakeIdentityProvider(),
        policy_provider=SimplePolicyProvider(),
        upstream_clients=fixture.upstream_provider,
        audit_emitter=DiskSpoolAuditEmitter(DiskSpool(tmp_path / "strict.jsonl")),
        gateway_instance_id="gateway-1",
        audit_failure_mode=AuditFailureMode.STRICT,
    )

    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=fixture.tenant_id,
                session_id=fixture.session.session_id,
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=make_identity_credentials(fixture.tenant_id),
            )
        )
    )

    assert result.status == ToolCallStatus.ALLOWED
    assert result.audit_emit_result is not None
    assert result.audit_emit_result.durable
    assert fixture.upstream_client.calls == [("query_select", {"sql": "select 1"})]


def test_strict_audit_mode_blocks_when_disk_spool_is_full(tmp_path: Path) -> None:
    fixture = make_fixture()
    lifecycle = ToolCallLifecycle(
        sessions=FakeSessionRegistry(fixture.session),
        resolver=fixture.resolver,
        identity_provider=FakeIdentityProvider(),
        policy_provider=SimplePolicyProvider(),
        upstream_clients=fixture.upstream_provider,
        audit_emitter=DiskSpoolAuditEmitter(DiskSpool(tmp_path / "full.jsonl", max_bytes=0)),
        gateway_instance_id="gateway-1",
        audit_failure_mode=AuditFailureMode.STRICT,
    )

    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=fixture.tenant_id,
                session_id=fixture.session.session_id,
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=make_identity_credentials(fixture.tenant_id),
            )
        )
    )

    assert result.status == ToolCallStatus.AUDIT_UNAVAILABLE
    assert fixture.upstream_client.calls == []


def test_continuity_audit_mode_allows_and_logs_critical_when_audit_rejects(
    monkeypatch: Any,
) -> None:
    fixture = make_fixture()
    critical_logs: list[str] = []

    def record_critical(message: str, *args: object, **kwargs: object) -> None:
        critical_logs.append(message)

    monkeypatch.setattr(lifecycle_module.logger, "critical", record_critical)
    lifecycle = ToolCallLifecycle(
        sessions=FakeSessionRegistry(fixture.session),
        resolver=fixture.resolver,
        identity_provider=FakeIdentityProvider(),
        policy_provider=SimplePolicyProvider(),
        upstream_clients=fixture.upstream_provider,
        audit_emitter=RejectingAuditEmitter(),
        gateway_instance_id="gateway-1",
        audit_failure_mode=AuditFailureMode.CONTINUITY,
    )

    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=fixture.tenant_id,
                session_id=fixture.session.session_id,
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=make_identity_credentials(fixture.tenant_id),
            )
        )
    )

    assert result.status == ToolCallStatus.ALLOWED
    assert fixture.upstream_client.calls == [("query_select", {"sql": "select 1"})]
    assert critical_logs == ["audit_delivery_degraded"]


def test_monitor_audit_mode_allows_best_effort_when_audit_rejects() -> None:
    fixture = make_fixture()
    lifecycle = ToolCallLifecycle(
        sessions=FakeSessionRegistry(fixture.session),
        resolver=fixture.resolver,
        identity_provider=FakeIdentityProvider(),
        policy_provider=SimplePolicyProvider(),
        upstream_clients=fixture.upstream_provider,
        audit_emitter=RejectingAuditEmitter(),
        gateway_instance_id="gateway-1",
        audit_failure_mode=AuditFailureMode.MONITOR,
    )

    result = asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=fixture.tenant_id,
                session_id=fixture.session.session_id,
                tool_name="query",
                arguments={"sql": "select 1"},
                identity_credentials=make_identity_credentials(fixture.tenant_id),
            )
        )
    )

    assert result.status == ToolCallStatus.ALLOWED
    assert fixture.upstream_client.calls == [("query_select", {"sql": "select 1"})]


def run_lifecycle(
    fixture: LifecycleFixture,
    *,
    request_args: dict[str, Any] | None = None,
    policy_provider: PolicyProvider | None = None,
    upstream_provider: UpstreamToolClientProvider | None = None,
    inbound_headers: dict[str, str] | None = None,
) -> ToolCallLifecycleResult:
    lifecycle = ToolCallLifecycle(
        sessions=FakeSessionRegistry(fixture.session),
        resolver=fixture.resolver,
        identity_provider=FakeIdentityProvider(),
        policy_provider=policy_provider or SimplePolicyProvider(),
        upstream_clients=upstream_provider or fixture.upstream_provider,
        audit_emitter=fixture.audit_emitter,
        gateway_instance_id="gateway-1",
    )
    return asyncio.run(
        lifecycle.handle_tool_call(
            ToolCallRequest(
                tenant_id=fixture.tenant_id,
                session_id=fixture.session.session_id,
                tool_name="query",
                arguments=request_args or {"sql": "select 1"},
                identity_credentials=make_identity_credentials(fixture.tenant_id),
                inbound_headers=inbound_headers or {},
            )
        )
    )


def make_fixture(
    *,
    upstream_client: FakeUpstreamClient | None = None,
) -> LifecycleFixture:
    tenant_id = uuid4()
    session = GatewaySession(
        session_id="session-1",
        tenant_id=tenant_id,
        vserver_name="finance-readonly",
        principal=AuditPrincipal(type=AuditPrincipalType.API_KEY, id="api-key-1"),
        expires_at=_far_future(),
    )
    resolved_tools = synthesize_tools(
        [
            VirtualServerToolCapability(
                server_id=uuid4(),
                server_display_name="Postgres",
                tool_name="query_select",
                schema_json={
                    "inputSchema": {
                        "type": "object",
                        "properties": {"sql": {"type": "string"}},
                        "required": ["sql"],
                    }
                },
            )
        ],
        {"query_select": "query"},
    )
    client = upstream_client or FakeUpstreamClient()
    provider = FakeUpstreamClientProvider(client)
    return LifecycleFixture(
        tenant_id=tenant_id,
        session=session,
        resolver=FakeResolver(resolved_tools),
        upstream_client=client,
        upstream_provider=provider,
        audit_emitter=FakeAuditEmitter(),
    )


def make_response(text: str, *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        isError=is_error,
    )


def make_identity_credentials(tenant_id: UUID) -> IdentityCredentials:
    return IdentityCredentials(
        headers={
            "x-vyuu-tenant-id": str(tenant_id),
            "x-vyuu-principal-type": PrincipalType.ENDPOINT_SESSION.value,
            "x-vyuu-principal-id": "endpoint-session-1",
            "x-vyuu-principal-display": "Endpoint Session 1",
        }
    )


def only_event(audit_emitter: FakeAuditEmitter) -> AuditEvent:
    assert len(audit_emitter.events) == 1
    return audit_emitter.events[0]


def test_tool_call_audit_events_carry_the_vserver_name() -> None:
    """Not just the id.

    `access_attempt` rows already carried the name, so an operator
    filtering `tool_call_events` by the name they know got a silent
    subset — every allow and every deny was missing, because only the
    access-attempt path populated it. A partial answer that looks
    complete is worse than an empty one, and it cost a wrong conclusion
    during functionality testing before the query was redone by id.
    """

    fixture = make_fixture()
    result = run_lifecycle(fixture)
    assert result.status == ToolCallStatus.ALLOWED

    event = only_event(fixture.audit_emitter)
    assert event.vserver_name == "finance-readonly"
    # The name is denormalised alongside the id, not in place of it —
    # both come from the session, so they cannot disagree.
    assert event.vserver_id == fixture.session.vserver_id


def test_denied_tool_call_events_also_carry_the_vserver_name() -> None:
    """Denials are the rows an operator filters for most."""

    fixture = make_fixture()
    result = run_lifecycle(
        fixture,
        policy_provider=SimplePolicyProvider(denied_tools={"query"}),
    )

    assert result.status == ToolCallStatus.DENIED
    event = only_event(fixture.audit_emitter)
    assert event.decision == "deny"
    assert event.vserver_name == "finance-readonly"
