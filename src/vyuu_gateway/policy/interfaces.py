from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol
from uuid import UUID

from vyuu_gateway.virtual_servers.resolver import ResolvedTool


class PolicyDecisionValue(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class PolicyDenyReason(StrEnum):
    AUDIT_UNAVAILABLE = "audit_unavailable"
    CAPABILITIES_NOT_SYNCED = "capabilities_not_synced"
    IDENTITY_INVALID = "identity_invalid"
    # EMA-1 P3 · caller lacks the OAuth scope the tool requires.
    INSUFFICIENT_SCOPE = "insufficient_scope"
    MALFORMED_ARGS = "malformed_args"
    # JIT-2 · the tool is elevation-gated and the caller holds no live
    # elevation for it.
    NO_TOOL_ELEVATION = "no_tool_elevation"
    # MCP-2 P3 · the upstream asked the caller's side for capability
    # (sampling / roots / elicitation) that policy does not permit.
    INPUT_REQUIRED_DENIED = "input_required_denied"
    POLICY_ENGINE_ERROR = "policy_engine_error"
    TOOL_DENIED = "tool_denied"
    TOOL_NOT_IN_VIRTUAL_SERVER = "tool_not_in_virtual_server"


@dataclass(frozen=True)
class ToolCallPolicyContext:
    tenant_id: UUID
    vserver_name: str
    tool: ResolvedTool
    arguments: dict[str, Any]
    policy_id: UUID | None = None


@dataclass(frozen=True)
class PolicyDecision:
    decision: PolicyDecisionValue
    reason: PolicyDenyReason | None = None
    message: str | None = None
    rule_id: str | None = None
    # H5 · explicit opt-in for raw-arg / raw-response capture in the
    # audit event. Default off. Policy engines that need compliance-
    # grade audit (raw values, not just metadata) flip these per rule.
    # Both default to False so existing policies stay metadata-only —
    # the privacy default per spec §3.3.
    capture_raw_args: bool = False
    capture_raw_response: bool = False

    @classmethod
    def allow(
        cls,
        *,
        rule_id: str | None = None,
        capture_raw_args: bool = False,
        capture_raw_response: bool = False,
    ) -> "PolicyDecision":
        return cls(
            decision=PolicyDecisionValue.ALLOW,
            rule_id=rule_id,
            capture_raw_args=capture_raw_args,
            capture_raw_response=capture_raw_response,
        )

    @classmethod
    def deny(
        cls,
        reason: PolicyDenyReason,
        message: str | None = None,
        *,
        rule_id: str | None = None,
    ) -> "PolicyDecision":
        return cls(
            decision=PolicyDecisionValue.DENY,
            reason=reason,
            message=message,
            rule_id=rule_id,
        )

    @property
    def allowed(self) -> bool:
        return self.decision == PolicyDecisionValue.ALLOW


class PolicyProvider(Protocol):
    """Replaceable policy provider interface.

    The Vyuu agent policy engine should eventually implement this protocol.
    """

    def evaluate_tool_call(self, context: ToolCallPolicyContext) -> PolicyDecision:
        """Evaluate a resolved tool call before it reaches an upstream MCP server."""
