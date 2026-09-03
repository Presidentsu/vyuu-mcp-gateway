from collections.abc import Iterable

from jsonschema import ValidationError
from jsonschema.validators import Draft202012Validator

from vyuu_gateway.mcp.sdk_compat import tool_input_schema
from vyuu_gateway.policy.interfaces import (
    PolicyDecision,
    PolicyDenyReason,
    PolicyProvider,
    ToolCallPolicyContext,
)


class SimplePolicyProvider(PolicyProvider):
    """Temporary policy provider for the gateway data-plane skeleton.

    `capture_raw_audit` toggles H5 raw-args / raw-response audit capture
    on every allow-decision. Default `False` preserves the privacy-by-
    default posture per spec §3.3 — production policies stay metadata-
    only unless they explicitly opt in. Dev / lab / POC deployments set
    `VYUU_AUDIT_CAPTURE_RAW_DEFAULT=true` so the operator-console
    "Events" panel renders full request + response bodies for every
    call without per-rule policy authoring. Operators see the audit-
    panel footer that explains the opt-in is on.
    """

    def __init__(
        self,
        *,
        allowed_tools: Iterable[str] | None = None,
        denied_tools: Iterable[str] = (),
        capture_raw_audit: bool = False,
    ) -> None:
        self._allowed_tools = set(allowed_tools) if allowed_tools is not None else None
        self._denied_tools = set(denied_tools)
        self._capture_raw_audit = capture_raw_audit

    def evaluate_tool_call(self, context: ToolCallPolicyContext) -> PolicyDecision:
        tool_name = context.tool.exposed_name
        if tool_name in self._denied_tools:
            return PolicyDecision.deny(PolicyDenyReason.TOOL_DENIED, "tool is denied by policy")

        if self._allowed_tools is not None and tool_name not in self._allowed_tools:
            return PolicyDecision.deny(
                PolicyDenyReason.TOOL_DENIED,
                "tool is not allowed by policy",
            )

        input_schema = tool_input_schema(context.tool.tool)
        try:
            Draft202012Validator(input_schema).validate(context.arguments)
        except ValidationError as exc:
            return PolicyDecision.deny(PolicyDenyReason.MALFORMED_ARGS, exc.message)

        return PolicyDecision.allow(
            capture_raw_args=self._capture_raw_audit,
            capture_raw_response=self._capture_raw_audit,
        )
