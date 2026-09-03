from uuid import uuid4

from vyuu_gateway.policy.interfaces import (
    PolicyDenyReason,
    ToolCallPolicyContext,
)
from vyuu_gateway.policy.simple import SimplePolicyProvider
from vyuu_gateway.virtual_servers.resolver import VirtualServerToolCapability, synthesize_tools


def make_context(
    *,
    exposed_name: str = "search",
    arguments: dict[str, object] | None = None,
) -> ToolCallPolicyContext:
    resolved_tool = synthesize_tools(
        [
            VirtualServerToolCapability(
                server_id=uuid4(),
                server_display_name="GitHub",
                tool_name="search",
                schema_json={
                    "inputSchema": {
                        "type": "object",
                        "properties": {"q": {"type": "string"}},
                        "required": ["q"],
                        "additionalProperties": False,
                    }
                },
            )
        ],
        {"search": exposed_name},
    ).tools[0]
    return ToolCallPolicyContext(
        tenant_id=uuid4(),
        vserver_name="engineering",
        tool=resolved_tool,
        arguments=arguments or {"q": "mcp"},
    )


def test_simple_policy_allows_valid_tool_call() -> None:
    decision = SimplePolicyProvider().evaluate_tool_call(make_context())

    assert decision.allowed
    assert decision.reason is None


def test_simple_policy_denies_explicitly_denied_tool() -> None:
    decision = SimplePolicyProvider(denied_tools={"search"}).evaluate_tool_call(make_context())

    assert not decision.allowed
    assert decision.reason == PolicyDenyReason.TOOL_DENIED


def test_simple_policy_denies_tool_not_in_allowed_set() -> None:
    decision = SimplePolicyProvider(allowed_tools={"read"}).evaluate_tool_call(make_context())

    assert not decision.allowed
    assert decision.reason == PolicyDenyReason.TOOL_DENIED


def test_simple_policy_denies_malformed_args() -> None:
    decision = SimplePolicyProvider().evaluate_tool_call(make_context(arguments={"q": 42}))

    assert not decision.allowed
    assert decision.reason == PolicyDenyReason.MALFORMED_ARGS
    assert decision.message is not None
