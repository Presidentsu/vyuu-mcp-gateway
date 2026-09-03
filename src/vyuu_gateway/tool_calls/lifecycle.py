import logging
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol
from uuid import UUID, uuid4

from jsonschema import ValidationError
from jsonschema.validators import Draft202012Validator
from mcp.types import CallToolResult

from vyuu_gateway.audit.emitter import AuditEmitter, EmitResult
from vyuu_gateway.audit.events import (
    AuditDecision,
    AuditDecisionMode,
    AuditPrincipal,
    AuditPrincipalType,
    AuthModeFlags,
    UpstreamStatus,
    create_tool_call_audit_event,
)
from vyuu_gateway.audit.failure import AuditFailureMode
from vyuu_gateway.graph.build import build_tool_call_graph_event
from vyuu_gateway.graph.emitter import GraphEventEmitter, NoOpGraphEventEmitter
from vyuu_gateway.identity.models import Principal
from vyuu_gateway.identity.provider import (
    IdentityCredentials,
    IdentityProvider,
    IdentityValidationError,
)
from vyuu_gateway.mcp.mrtr import (
    MrtrPolicy,
    evaluate_input_requests,
    is_input_required,
)
from vyuu_gateway.mcp.sdk_compat import (
    dump_wire,
    result_is_error,
    tool_input_schema,
)
from vyuu_gateway.policy.interfaces import (
    PolicyDecision,
    PolicyDenyReason,
    PolicyProvider,
    ToolCallPolicyContext,
)
from vyuu_gateway.sessions.registry import GatewaySession, SessionRegistry
from vyuu_gateway.telemetry import Telemetry
from vyuu_gateway.virtual_servers.resolver import ResolvedTool, ResolvedToolsList
from vyuu_gateway.virtual_servers.service import (
    CapabilitiesNotSyncedError,
    VirtualServerNotFoundError,
)

logger = logging.getLogger(__name__)


class ToolCallStatus(StrEnum):
    AUDIT_UNAVAILABLE = "audit_unavailable"
    ALLOWED = "allowed"
    CAPABILITIES_NOT_SYNCED = "capabilities_not_synced"
    DENIED = "denied"
    IDENTITY_INVALID = "identity_invalid"
    INSUFFICIENT_SCOPE = "insufficient_scope"
    NO_TOOL_ELEVATION = "no_tool_elevation"
    INPUT_REQUIRED_DENIED = "input_required_denied"
    MALFORMED_ARGS = "malformed_args"
    POLICY_ENGINE_ERROR = "policy_engine_error"
    SESSION_NOT_FOUND = "session_not_found"
    TOOL_NOT_IN_VIRTUAL_SERVER = "tool_not_in_virtual_server"
    UPSTREAM_ERROR = "upstream_error"
    UPSTREAM_TIMEOUT = "upstream_timeout"


@dataclass(frozen=True)
class ToolCallRequest:
    tenant_id: UUID
    session_id: str
    tool_name: str
    arguments: dict[str, Any]
    identity_credentials: IdentityCredentials = field(default_factory=IdentityCredentials)
    # Raw inbound headers from the end user's MCP client. Forwarded
    # opaquely to the upstream client; the StreamableHttpMcpClient filters
    # them through its `auth_passthrough_map` before sending. Empty/{} when
    # the inbound route doesn't supply any (tests, internal callers).
    inbound_headers: dict[str, str] = field(default_factory=dict)
    # MCP-2 P1 · pre-resolved session context. When set, the lifecycle
    # skips the registry lookup entirely: the legacy route passes the
    # session it already fetched during dispatch (saving a duplicate
    # lookup), and the modern stateless path passes an ephemeral
    # never-registered session (the 2026-07-28 revision has no protocol
    # sessions, so there is nothing to look up). Tenant agreement is
    # still enforced below either way.
    session: GatewaySession | None = None


@dataclass(frozen=True)
class ToolCallLifecycleResult:
    status: ToolCallStatus
    decision: PolicyDecision
    response: CallToolResult | None = None
    upstream_server_id: UUID | None = None
    upstream_tool_name: str | None = None
    audit_emit_result: EmitResult | None = None
    error_message: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision.allowed and self.status == ToolCallStatus.ALLOWED


class ToolResolver(Protocol):
    def resolve_tools(self, tenant_id: UUID, vserver_name: str) -> ResolvedToolsList:
        """Resolve tools exposed by a tenant-scoped virtual server."""


class ToolElevationChecker(Protocol):
    """JIT-2 · "does this principal hold a live elevation for this tool?"

    A Protocol rather than a DB call inline, because `ToolCallLifecycle`
    has no database knowledge and is better for it — every collaborator
    here is injected, which is what lets the tests drive the whole
    orchestration without Postgres.

    Optional: when no checker is wired the gate is skipped entirely, so a
    deployment (or a test) that never configures `jit_tools` behaves
    exactly as it did before JIT-2.
    """

    def has_active_tool_elevation(
        self,
        *,
        tenant_id: UUID,
        vserver_id: UUID,
        exposed_tool_name: str,
        principal_id: str,
    ) -> bool:
        """True iff a non-revoked, non-expired elevation exists."""


class UpstreamToolClient(Protocol):
    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        inbound_headers: dict[str, str] | None = None,
        principal_id: UUID | None = None,
    ) -> CallToolResult:
        """Call an upstream MCP tool.

        `inbound_headers` carries the end user's request headers; the
        outbound implementation filters them through its server-row
        `auth_passthrough` map and forwards matching entries to the
        upstream. Implementations that don't support pass-through
        (stdio) ignore this parameter — the registration validator
        already rejects auth_passthrough on stdio transports.

        `principal_id` is threaded through for phase-4 OAuth
        (per-user delegated tokens). Phase-3 OAuth + non-OAuth
        upstreams ignore it.
        """


class UpstreamToolClientProvider(Protocol):
    def get_client(self, tenant_id: UUID, server_id: UUID) -> UpstreamToolClient:
        """Return an upstream client for a tenant-scoped MCP server."""

    def get_auth_mode_flags(
        self, tenant_id: UUID, server_id: UUID
    ) -> AuthModeFlags:
        """Return which outbound-auth modes are configured for this server.
        Soft-fails to all-False if the server can't be looked up — auditing
        must not break the request when the server row is gone."""


class ToolCallLifecycle:
    """Full tool-call orchestration from session lookup through audit emission."""

    def __init__(
        self,
        *,
        sessions: SessionRegistry,
        resolver: ToolResolver,
        identity_provider: IdentityProvider,
        policy_provider: PolicyProvider,
        upstream_clients: UpstreamToolClientProvider,
        audit_emitter: AuditEmitter,
        gateway_instance_id: str = "unknown",
        audit_failure_mode: AuditFailureMode = AuditFailureMode.MONITOR,
        graph_event_emitter: GraphEventEmitter | None = None,
        tool_elevation_checker: ToolElevationChecker | None = None,
        mrtr_policy: MrtrPolicy | None = None,
        telemetry: Telemetry | None = None,
    ) -> None:
        self._sessions = sessions
        self._resolver = resolver
        self._identity_provider = identity_provider
        self._policy_provider = policy_provider
        self._upstream_clients = upstream_clients
        self._audit_emitter = audit_emitter
        self._gateway_instance_id = gateway_instance_id
        self._audit_failure_mode = audit_failure_mode
        self._tool_elevation_checker = tool_elevation_checker
        # MCP-2 P3 · default denies every input-request kind, matching
        # the SDK's own `allow_input_required=False`.
        self._mrtr_policy = mrtr_policy or MrtrPolicy()
        # OTEL-1 · spans around policy evaluation and the upstream call,
        # plus the bounded-cardinality tool-call metrics. No-op by default.
        self._telemetry: Telemetry = telemetry if telemetry is not None else Telemetry()
        self._graph_event_emitter: GraphEventEmitter = (
            graph_event_emitter if graph_event_emitter is not None else NoOpGraphEventEmitter()
        )

    def _holds_tool_elevation(
        self,
        *,
        tenant_id: UUID,
        vserver_id: UUID | None,
        exposed_tool_name: str,
        principal: Principal,
    ) -> bool:
        """JIT-2 · fail-closed elevation lookup.

        Every "can't tell" answer is False. A gate that opens when it
        cannot establish authority is not a gate — and each of these
        cases is a misconfiguration worth surfacing as a denial the
        operator can see in the Events panel, rather than a silent
        allow nobody notices.
        """

        checker = self._tool_elevation_checker
        if checker is None or vserver_id is None:
            return False
        # Only principals that resolve to a real `users.id` can hold an
        # elevation — same rule as vserver grants in `access.py`.
        try:
            UUID(principal.id)
        except (ValueError, TypeError):
            return False
        try:
            return bool(
                checker.has_active_tool_elevation(
                    tenant_id=tenant_id,
                    vserver_id=vserver_id,
                    exposed_tool_name=exposed_tool_name,
                    principal_id=principal.id,
                )
            )
        except Exception:  # noqa: BLE001 — deny on lookup failure
            logger.warning(
                "tool_elevation_check_failed tool=%s vserver=%s",
                exposed_tool_name,
                vserver_id,
                exc_info=True,
            )
            return False

    async def handle_tool_call(self, request: ToolCallRequest) -> ToolCallLifecycleResult:
        correlation_id = uuid4()
        started_at = time.perf_counter()
        session = (
            request.session
            if request.session is not None
            else await self._sessions.get_session(request.tenant_id, request.session_id)
        )
        if session is None or session.tenant_id != request.tenant_id:
            decision = PolicyDecision.deny(
                PolicyDenyReason.TOOL_NOT_IN_VIRTUAL_SERVER,
                "session was not found in tenant",
            )
            return self._denied_result(
                status=ToolCallStatus.SESSION_NOT_FOUND,
                request=request,
                decision=decision,
                session=None,
                started_at=started_at,
                policy_rule_id=ToolCallStatus.SESSION_NOT_FOUND.value,
                correlation_id=correlation_id,
            )

        try:
            principal = self._identity_provider.validate_principal(
                tenant_id=session.tenant_id,
                credentials=request.identity_credentials,
            )
        except IdentityValidationError as exc:
            decision = PolicyDecision.deny(
                PolicyDenyReason.IDENTITY_INVALID,
                "identity validation failed",
            )
            return self._denied_result(
                status=ToolCallStatus.IDENTITY_INVALID,
                request=request,
                decision=decision,
                session=session,
                started_at=started_at,
                policy_rule_id=PolicyDenyReason.IDENTITY_INVALID.value,
                error_message=exc.__class__.__name__,
                correlation_id=correlation_id,
            )

        try:
            resolved_tools = self._resolver.resolve_tools(session.tenant_id, session.vserver_name)
        except VirtualServerNotFoundError:
            decision = PolicyDecision.deny(
                PolicyDenyReason.TOOL_NOT_IN_VIRTUAL_SERVER,
                "virtual server was not found in tenant",
            )
            return self._denied_result(
                status=ToolCallStatus.TOOL_NOT_IN_VIRTUAL_SERVER,
                request=request,
                decision=decision,
                session=session,
                principal=principal,
                started_at=started_at,
                policy_rule_id=PolicyDenyReason.TOOL_NOT_IN_VIRTUAL_SERVER.value,
                correlation_id=correlation_id,
            )
        except CapabilitiesNotSyncedError as exc:
            # Tier-1 stress-test fix: distinguish "operator hasn't run
            # capability sync yet" from "tool actually not registered."
            # Without this branch the same `tool_not_in_vserver` was
            # returned for both, sending operators down the wrong
            # debugging path.
            decision = PolicyDecision.deny(
                PolicyDenyReason.CAPABILITIES_NOT_SYNCED,
                str(exc),
            )
            return self._denied_result(
                status=ToolCallStatus.CAPABILITIES_NOT_SYNCED,
                request=request,
                decision=decision,
                session=session,
                principal=principal,
                started_at=started_at,
                policy_rule_id=PolicyDenyReason.CAPABILITIES_NOT_SYNCED.value,
                error_message=str(exc),
                correlation_id=correlation_id,
            )
        resolved_tool = next(
            (tool for tool in resolved_tools.tools if tool.exposed_name == request.tool_name),
            None,
        )
        if resolved_tool is None:
            decision = PolicyDecision.deny(
                PolicyDenyReason.TOOL_NOT_IN_VIRTUAL_SERVER,
                "tool is not exposed by virtual server",
            )
            return self._denied_result(
                status=ToolCallStatus.TOOL_NOT_IN_VIRTUAL_SERVER,
                request=request,
                decision=decision,
                session=session,
                principal=principal,
                started_at=started_at,
                policy_rule_id=PolicyDenyReason.TOOL_NOT_IN_VIRTUAL_SERVER.value,
                correlation_id=correlation_id,
            )

        # EMA-1 P3 · per-tool scope gate. AND-combined with everything
        # else: visibility + grants already said "this principal may
        # reach this vserver"; this asks the narrower question "did the
        # principal's issuer authorize THIS tool?". It can only narrow.
        #
        # Fails closed on purpose. A principal carrying no scopes at all
        # (an API key — scopes are an EMA/ID-JAG concept) cannot
        # demonstrate the required authority, so a scope-gated tool is
        # denied for it. Operators opt in per tool via
        # `virtual_servers.required_scopes`, which is empty by default,
        # so no existing deployment changes behaviour.
        required_scope = resolved_tools.required_scopes.get(resolved_tool.exposed_name)
        if required_scope is not None:
            held = getattr(principal, "scopes", frozenset())
            if required_scope not in held:
                decision = PolicyDecision.deny(
                    PolicyDenyReason.INSUFFICIENT_SCOPE,
                    f"tool requires scope {required_scope!r}",
                )
                return self._denied_result(
                    status=ToolCallStatus.INSUFFICIENT_SCOPE,
                    request=request,
                    decision=decision,
                    session=session,
                    principal=principal,
                    started_at=started_at,
                    resolved_tool=resolved_tool,
                    policy_rule_id=PolicyDenyReason.INSUFFICIENT_SCOPE.value,
                    correlation_id=correlation_id,
                )

        # JIT-2 · per-tool elevation gate. Sits immediately after the
        # scope gate and before policy, so a denial is a `tool_call` event
        # naming the tool (`policy_rule_id=no_tool_elevation`) rather than
        # an opaque connection-level 403 — the operator sees WHICH tool
        # was refused and to whom.
        #
        # Like the scope gate, it can only narrow: the caller has already
        # cleared visibility + grants for the vserver. `jit_tools` is
        # empty by default, so no existing deployment changes behaviour.
        #
        # Fails closed. If a tool is elevation-gated and we cannot
        # establish an elevation — no checker wired, principal is not a
        # user, lookup raises — the call is denied. An elevation gate
        # that opens on error is not a gate.
        jit_ceiling = resolved_tools.jit_tools.get(resolved_tool.exposed_name)
        if jit_ceiling is not None:
            if not self._holds_tool_elevation(
                tenant_id=session.tenant_id,
                vserver_id=resolved_tools.vserver_id,
                exposed_tool_name=resolved_tool.exposed_name,
                principal=principal,
            ):
                decision = PolicyDecision.deny(
                    PolicyDenyReason.NO_TOOL_ELEVATION,
                    "tool requires an active just-in-time elevation",
                )
                return self._denied_result(
                    status=ToolCallStatus.NO_TOOL_ELEVATION,
                    request=request,
                    decision=decision,
                    session=session,
                    principal=principal,
                    started_at=started_at,
                    resolved_tool=resolved_tool,
                    policy_rule_id=PolicyDenyReason.NO_TOOL_ELEVATION.value,
                    correlation_id=correlation_id,
                )

        malformed_reason = _validate_tool_arguments(resolved_tool, request.arguments)
        if malformed_reason is not None:
            decision = PolicyDecision.deny(PolicyDenyReason.MALFORMED_ARGS, malformed_reason)
            return self._denied_result(
                status=ToolCallStatus.MALFORMED_ARGS,
                request=request,
                decision=decision,
                session=session,
                principal=principal,
                started_at=started_at,
                resolved_tool=resolved_tool,
                policy_rule_id=PolicyDenyReason.MALFORMED_ARGS.value,
                correlation_id=correlation_id,
            )

        try:
            with self._telemetry.span(
                "vyuu.policy_eval",
                tenant_id=session.tenant_id,
                vserver=session.vserver_name,
                tool=request.tool_name,
            ):
                decision = self._policy_provider.evaluate_tool_call(
                    ToolCallPolicyContext(
                        tenant_id=session.tenant_id,
                        vserver_name=session.vserver_name,
                        tool=resolved_tool,
                        arguments=request.arguments,
                        policy_id=session.policy_id,
                    )
                )
        except Exception as exc:
            decision = PolicyDecision.deny(
                PolicyDenyReason.POLICY_ENGINE_ERROR,
                "policy engine error",
            )
            return self._denied_result(
                status=ToolCallStatus.POLICY_ENGINE_ERROR,
                request=request,
                decision=decision,
                session=session,
                principal=principal,
                started_at=started_at,
                resolved_tool=resolved_tool,
                policy_rule_id=ToolCallStatus.POLICY_ENGINE_ERROR.value,
                error_message=exc.__class__.__name__,
                correlation_id=correlation_id,
            )

        if not decision.allowed:
            return self._denied_result(
                status=ToolCallStatus.DENIED,
                request=request,
                decision=decision,
                session=session,
                principal=principal,
                started_at=started_at,
                resolved_tool=resolved_tool,
                policy_rule_id=(
                    decision.rule_id
                    or (decision.reason.value if decision.reason is not None else None)
                ),
                correlation_id=correlation_id,
            )

        audit_preflight_failure = self._strict_audit_preflight_failure(
            request=request,
            session=session,
            principal=principal,
            upstream_server_id=resolved_tool.upstream_server_id,
        )
        if audit_preflight_failure is not None:
            return audit_preflight_failure

        upstream_started_at = time.perf_counter()
        try:
            # `principal_id` is threaded into call_tool for phase-4 OAuth
            # (per-user delegated tokens). Phase-3 token providers ignore
            # it. ApiKey principals' `id` IS the user's UUID (the
            # ApiKeyIdentityProvider sets it that way); for FakeIdentity
            # principals (lab) it's a free-form string and the
            # auth_authcode token provider would reject the request with
            # OAuthTokenError if no token row exists for that string.
            principal_uuid = _principal_user_uuid(principal)
            with self._telemetry.span(
                "vyuu.upstream.call_tool",
                tenant_id=session.tenant_id,
                vserver=session.vserver_name,
                upstream_server_id=resolved_tool.upstream_server_id,
                tool=resolved_tool.upstream_tool_name,
            ):
                response = await self._upstream_clients.get_client(
                    session.tenant_id,
                    resolved_tool.upstream_server_id,
                ).call_tool(
                    resolved_tool.upstream_tool_name,
                    request.arguments,
                    inbound_headers=request.inbound_headers or None,
                    principal_id=principal_uuid,
                )
        except TimeoutError as exc:
            return self._upstream_failure_result(
                status=ToolCallStatus.UPSTREAM_TIMEOUT,
                request=request,
                session=session,
                principal=principal,
                resolved_tool=resolved_tool,
                started_at=started_at,
                upstream_started_at=upstream_started_at,
                upstream_status=UpstreamStatus.TIMEOUT,
                error_message=exc.__class__.__name__,
                correlation_id=correlation_id,
            )
        except Exception as exc:
            # Log the full traceback so operators can see WHY the
            # upstream call exploded (vs. just the exception class
            # name). The user-facing audit message stays terse to
            # avoid leaking implementation detail to MCP clients.
            logger.warning(
                "upstream_call_failed",
                extra={
                    "tenant_id": str(session.tenant_id),
                    "vserver_id": str(session.vserver_id),
                    "upstream_server_id": str(resolved_tool.upstream_server_id),
                    "tool_name": request.tool_name,
                    "exc_type": exc.__class__.__name__,
                    "exc_str": str(exc),
                },
                exc_info=exc,
            )
            return self._upstream_failure_result(
                status=ToolCallStatus.UPSTREAM_ERROR,
                request=request,
                session=session,
                principal=principal,
                resolved_tool=resolved_tool,
                started_at=started_at,
                upstream_started_at=upstream_started_at,
                upstream_status=UpstreamStatus.ERROR,
                error_message=f"{exc.__class__.__name__}: {exc!s}"[:200],
                correlation_id=correlation_id,
            )

        # MCP-2 P3 · MRTR. The upstream may answer with
        # `InputRequiredResult` instead of a result — asking the CALLER'S
        # side for capability, not data: drive their LLM (`sampling`),
        # enumerate their filesystem roots, prompt their human, or send
        # that human to a URL of the upstream's choosing.
        #
        # Checked here rather than at the serialization boundary because
        # a refusal has to become a `tool_call` audit event carrying the
        # kinds and the destination URL. "An upstream tried to send your
        # user to not-really-okta.example" is the finding; a 400 with no
        # event is not.
        #
        # Default policy denies every kind, which reproduces the SDK's own
        # `allow_input_required=False` — so this is not a new restriction,
        # only a visible one.
        if is_input_required(response):
            mrtr = evaluate_input_requests(response, self._mrtr_policy)
            if not mrtr.allowed:
                decision = PolicyDecision.deny(
                    PolicyDenyReason.INPUT_REQUIRED_DENIED,
                    "; ".join(mrtr.denied_reasons)[:300]
                    or "input-required round refused",
                )
                return self._upstream_failure_result(
                    status=ToolCallStatus.INPUT_REQUIRED_DENIED,
                    request=request,
                    session=session,
                    principal=principal,
                    resolved_tool=resolved_tool,
                    started_at=started_at,
                    upstream_started_at=upstream_started_at,
                    upstream_status=UpstreamStatus.ERROR,
                    error_message=(
                        "upstream requested additional input that policy "
                        f"does not permit: {', '.join(mrtr.kinds)}"
                    )[:200],
                    correlation_id=correlation_id,
                    decision=decision,
                    policy_rule_id=PolicyDenyReason.INPUT_REQUIRED_DENIED.value,
                )
            logger.info(
                "mrtr_input_required_allowed",
                extra={"detail": mrtr.audit_detail(), "tool": request.tool_name},
            )

        upstream_status = (
            UpstreamStatus.ERROR if result_is_error(response) else UpstreamStatus.OK
        )
        result_status = ToolCallStatus.ALLOWED
        if upstream_status == UpstreamStatus.ERROR:
            result_status = ToolCallStatus.UPSTREAM_ERROR
        # H5 · raw-arg / raw-response capture is opt-in via the policy
        # decision. Default off (PolicyDecision fields default to False),
        # so existing policies keep the metadata-only privacy posture.
        # Only the success path captures responses; failure paths emit
        # only the args (and only if opted-in).
        raw_args = request.arguments if decision.capture_raw_args else None
        raw_response = (
            _serialise_call_result(response)
            if decision.capture_raw_response
            else None
        )
        audit_emit_result = self._emit_audit(
            session=session,
            principal=principal,
            tool_name=request.tool_name,
            arguments=request.arguments,
            decision=decision,
            audit_decision=AuditDecision.ALLOW,
            upstream_status=upstream_status,
            upstream_server_id=resolved_tool.upstream_server_id,
            policy_rule_id=decision.rule_id,
            started_at=started_at,
            upstream_started_at=upstream_started_at,
            response_size_bytes=_response_size_bytes(response),
            correlation_id=correlation_id,
            raw_args=raw_args,
            raw_response=raw_response,
        )
        self._emit_graph_event(
            correlation_id=correlation_id,
            session=session,
            principal=principal,
            resolved_tool=resolved_tool,
            upstream_status=upstream_status,
        )
        audit_failure = self._audit_failure_result(
            result=audit_emit_result,
            upstream_server_id=resolved_tool.upstream_server_id,
            upstream_tool_name=resolved_tool.upstream_tool_name,
        )
        if audit_failure is not None:
            return audit_failure
        return ToolCallLifecycleResult(
            status=result_status,
            decision=decision,
            response=response,
            upstream_server_id=resolved_tool.upstream_server_id,
            upstream_tool_name=resolved_tool.upstream_tool_name,
            audit_emit_result=audit_emit_result,
            error_message=(
                "upstream returned an MCP tool error"
                if result_is_error(response)
                else None
            ),
        )

    def _denied_result(
        self,
        *,
        status: ToolCallStatus,
        request: ToolCallRequest,
        decision: PolicyDecision,
        session: GatewaySession | None,
        started_at: float,
        policy_rule_id: str | None,
        correlation_id: UUID,
        principal: Principal | None = None,
        resolved_tool: ResolvedTool | None = None,
        upstream_server_id: UUID | None = None,
        error_message: str | None = None,
    ) -> ToolCallLifecycleResult:
        effective_upstream_server_id = upstream_server_id
        if effective_upstream_server_id is None and resolved_tool is not None:
            effective_upstream_server_id = resolved_tool.upstream_server_id
        audit_emit_result = self._emit_audit(
            session=session,
            principal=principal,
            fallback_tenant_id=request.tenant_id,
            tool_name=request.tool_name,
            arguments=request.arguments,
            decision=decision,
            audit_decision=AuditDecision.DENY,
            upstream_status=UpstreamStatus.NOT_CALLED,
            upstream_server_id=effective_upstream_server_id,
            started_at=started_at,
            policy_rule_id=policy_rule_id,
            correlation_id=correlation_id,
        )
        self._emit_graph_event(
            correlation_id=correlation_id,
            session=session,
            principal=principal,
            resolved_tool=resolved_tool,
            upstream_status=UpstreamStatus.NOT_CALLED,
        )
        audit_failure = self._audit_failure_result(
            result=audit_emit_result,
            upstream_server_id=effective_upstream_server_id,
        )
        if audit_failure is not None:
            return audit_failure
        return ToolCallLifecycleResult(
            status=status,
            decision=decision,
            upstream_server_id=effective_upstream_server_id,
            audit_emit_result=audit_emit_result,
            error_message=error_message or decision.message,
        )

    def _upstream_failure_result(
        self,
        *,
        status: ToolCallStatus,
        request: ToolCallRequest,
        session: GatewaySession,
        principal: Principal,
        resolved_tool: ResolvedTool,
        started_at: float,
        upstream_started_at: float,
        upstream_status: UpstreamStatus,
        error_message: str,
        correlation_id: UUID,
        decision: PolicyDecision | None = None,
        policy_rule_id: str | None = None,
    ) -> ToolCallLifecycleResult:
        # Timeouts and upstream errors record as ALLOW: the gateway did
        # permit the call, and the upstream is what failed. But a refusal
        # the GATEWAY made about the upstream's response (MCP-2 P3's MRTR
        # gate) has to record as a DENY — otherwise it is invisible to
        # every operator filtering the Events panel for denials, which is
        # exactly who needs to see it.
        effective_decision = decision or PolicyDecision.allow()
        audit_emit_result = self._emit_audit(
            session=session,
            principal=principal,
            tool_name=request.tool_name,
            arguments=request.arguments,
            decision=effective_decision,
            audit_decision=(
                AuditDecision.ALLOW
                if effective_decision.allowed
                else AuditDecision.DENY
            ),
            upstream_status=upstream_status,
            upstream_server_id=resolved_tool.upstream_server_id,
            started_at=started_at,
            upstream_started_at=upstream_started_at,
            correlation_id=correlation_id,
            policy_rule_id=policy_rule_id,
        )
        self._emit_graph_event(
            correlation_id=correlation_id,
            session=session,
            principal=principal,
            resolved_tool=resolved_tool,
            upstream_status=upstream_status,
        )
        audit_failure = self._audit_failure_result(
            result=audit_emit_result,
            upstream_server_id=resolved_tool.upstream_server_id,
            upstream_tool_name=resolved_tool.upstream_tool_name,
        )
        if audit_failure is not None:
            return audit_failure
        return ToolCallLifecycleResult(
            status=status,
            decision=effective_decision,
            upstream_server_id=resolved_tool.upstream_server_id,
            upstream_tool_name=resolved_tool.upstream_tool_name,
            audit_emit_result=audit_emit_result,
            error_message=error_message,
        )

    def _strict_audit_preflight_failure(
        self,
        *,
        request: ToolCallRequest,
        session: GatewaySession,
        principal: Principal,
        upstream_server_id: UUID,
    ) -> ToolCallLifecycleResult | None:
        if self._audit_failure_mode != AuditFailureMode.STRICT:
            return None

        can_durably_accept_now = getattr(self._audit_emitter, "can_durably_accept_now", None)
        if callable(can_durably_accept_now) and can_durably_accept_now():
            return None

        if can_durably_accept_now is None:
            reason = "audit emitter does not expose durable queue availability"
        else:
            reason = "audit emitter cannot durably queue events"

        return ToolCallLifecycleResult(
            status=ToolCallStatus.AUDIT_UNAVAILABLE,
            decision=PolicyDecision.deny(PolicyDenyReason.AUDIT_UNAVAILABLE, reason),
            upstream_server_id=upstream_server_id,
            audit_emit_result=EmitResult(accepted=False, degraded=True, reason=reason),
            error_message=reason,
        )

    def _audit_failure_result(
        self,
        *,
        result: EmitResult,
        upstream_server_id: UUID | None,
        upstream_tool_name: str | None = None,
    ) -> ToolCallLifecycleResult | None:
        if self._audit_failure_mode == AuditFailureMode.MONITOR:
            return None

        audit_durable = result.accepted and result.durable
        audit_degraded = result.degraded or result.spooled or not audit_durable
        if self._audit_failure_mode == AuditFailureMode.CONTINUITY:
            if audit_degraded:
                logger.critical(
                    "audit_delivery_degraded",
                    extra={
                        "audit_failure_mode": self._audit_failure_mode.value,
                        "audit_emit_accepted": result.accepted,
                        "audit_emit_durable": result.durable,
                        "audit_emit_spooled": result.spooled,
                    },
                )
            return None

        if audit_durable:
            return None

        return ToolCallLifecycleResult(
            status=ToolCallStatus.AUDIT_UNAVAILABLE,
            decision=PolicyDecision.deny(
                PolicyDenyReason.AUDIT_UNAVAILABLE,
                "audit event could not be durably queued",
            ),
            upstream_server_id=upstream_server_id,
            upstream_tool_name=upstream_tool_name,
            audit_emit_result=result,
            error_message=result.reason or "audit event could not be durably queued",
        )

    def _emit_audit(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        decision: PolicyDecision,
        audit_decision: AuditDecision,
        upstream_status: UpstreamStatus,
        started_at: float,
        correlation_id: UUID,
        session: GatewaySession | None = None,
        principal: Principal | None = None,
        fallback_tenant_id: UUID | None = None,
        upstream_server_id: UUID | None = None,
        policy_rule_id: str | None = None,
        upstream_started_at: float | None = None,
        response_size_bytes: int | None = None,
        auth_modes: AuthModeFlags | None = None,
        raw_args: dict[str, Any] | None = None,
        raw_response: dict[str, Any] | None = None,
    ) -> EmitResult:
        now = time.perf_counter()
        tenant_id = session.tenant_id if session is not None else fallback_tenant_id
        if tenant_id is None:
            raise ValueError("tenant_id is required to emit tool-call audit events")

        audit_principal = (
            principal.to_audit_principal()
            if principal is not None
            else (
                session.principal
                if session is not None
                else AuditPrincipal(type=AuditPrincipalType.API_KEY, id="unknown", display="")
            )
        )
        # If we know the upstream server but no explicit auth_modes were
        # passed, ask the provider — keeps the call sites short while still
        # giving honest data on every event that reaches the upstream.
        resolved_auth_modes = auth_modes
        if resolved_auth_modes is None and upstream_server_id is not None:
            resolved_auth_modes = self._upstream_clients.get_auth_mode_flags(
                tenant_id, upstream_server_id
            )
        event = create_tool_call_audit_event(
            tenant_id=tenant_id,
            gateway_instance_id=self._gateway_instance_id,
            principal=audit_principal,
            vserver_id=session.vserver_id if session is not None else None,
            vserver_name=session.vserver_name if session is not None else None,
            upstream_server_id=upstream_server_id,
            tool=tool_name,
            arguments=arguments,
            decision=audit_decision,
            decision_mode=AuditDecisionMode.ENFORCE,
            upstream_status=upstream_status,
            policy_id=session.policy_id if session is not None else None,
            policy_rule_id=policy_rule_id
            or (decision.reason.value if decision.reason is not None else None),
            latency_ms_total=_elapsed_ms(started_at, now),
            latency_ms_upstream=_elapsed_ms(upstream_started_at, now)
            if upstream_started_at is not None
            else None,
            response_size_bytes=response_size_bytes,
            client_metadata=session.client_metadata if session is not None else None,
            auth_modes=resolved_auth_modes,
            raw_args=raw_args,
            raw_response=raw_response,
            event_id=correlation_id,
        )
        self._telemetry.record_tool_call(
            tenant_id=event.tenant_id,
            vserver=event.vserver_name,
            decision=event.decision.value,
            upstream_status=event.upstream_status.value,
            duration_ms=event.latency_ms_total,
            upstream_ms=event.latency_ms_upstream,
            upstream_server_id=event.upstream_server_id,
        )
        emit_result = self._audit_emitter.emit_nowait(event)
        if not emit_result.accepted:
            # The counter `security-issues.md` asked for: an audit event
            # the pipeline could not take is a page, not a log line.
            self._telemetry.record_audit_emit_failure(tenant_id=event.tenant_id)
        return emit_result

    def _emit_graph_event(
        self,
        *,
        correlation_id: UUID,
        session: GatewaySession | None,
        principal: Principal | None,
        resolved_tool: ResolvedTool | None,
        upstream_status: UpstreamStatus,
    ) -> None:
        if session is None or principal is None:
            # We need both an existing session and a validated principal to
            # construct identity-rooted edges. Session-not-found and
            # identity-invalid paths intentionally do not produce graph events.
            return
        audit_principal = principal.to_audit_principal()
        event = build_tool_call_graph_event(
            tenant_id=session.tenant_id,
            correlation_id=correlation_id,
            principal=audit_principal,
            session_id=session.session_id,
            vserver_name=session.vserver_name,
            vserver_id=session.vserver_id,
            client_display=session.client_metadata.agent_type,
            resolved_exposed_name=(
                resolved_tool.exposed_name if resolved_tool is not None else None
            ),
            resolved_upstream_server_id=(
                resolved_tool.upstream_server_id if resolved_tool is not None else None
            ),
            resolved_upstream_tool_name=(
                resolved_tool.upstream_tool_name if resolved_tool is not None else None
            ),
            upstream_status=upstream_status,
        )
        self._graph_event_emitter.emit_nowait(event)


def _validate_tool_arguments(tool: ResolvedTool, arguments: dict[str, Any]) -> str | None:
    try:
        Draft202012Validator(tool_input_schema(tool.tool)).validate(arguments)
    except ValidationError as exc:
        return exc.message
    return None


def _response_size_bytes(response: CallToolResult) -> int:
    return len(response.model_dump_json(exclude_none=True).encode("utf-8"))


def _serialise_call_result(response: CallToolResult) -> dict[str, Any]:
    """Render an MCP `CallToolResult` to a dict suitable for H5 raw
    audit capture. Pydantic's `model_dump(mode="json")` gives us a
    JSON-roundtrippable shape with enums + datetimes already coerced.
    The downstream `truncate_for_audit_capture` enforces the size cap."""

    return dump_wire(response)


def _elapsed_ms(started_at: float | None, ended_at: float) -> float | None:
    if started_at is None:
        return None
    return (ended_at - started_at) * 1000


def _principal_user_uuid(principal: Principal) -> UUID | None:
    """Extract the principal's user UUID for phase-4 OAuth lookups.

    `ApiKeyIdentityProvider` sets `principal.id` to the user's UUID.
    `FakeIdentityProvider` sets it to a free-form string. We try to
    parse it as a UUID and return None on failure — phase-4 will then
    raise OAuthTokenError because no oauth_user_tokens row will match
    a None principal, surfacing as a clear "user must connect" error
    rather than a silent no-op.
    """

    try:
        return UUID(principal.id)
    except (ValueError, AttributeError):
        return None
