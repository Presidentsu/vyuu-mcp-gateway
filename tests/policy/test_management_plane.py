from __future__ import annotations

from typing import cast
from uuid import UUID, uuid4

import httpx
import pytest

from vyuu_gateway.policy.interfaces import PolicyDenyReason, ToolCallPolicyContext
from vyuu_gateway.policy.management_plane import (
    ManagementPlanePolicyError,
    ManagementPlanePolicyProvider,
)
from vyuu_gateway.virtual_servers.resolver import VirtualServerToolCapability, synthesize_tools

_MISSING = object()


class _Clock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _context(
    *,
    tenant_id: UUID | None = None,
    policy_id: UUID | None | object = _MISSING,
    exposed_name: str = "search",
    upstream_tool_name: str = "search_repos",
) -> ToolCallPolicyContext:
    if policy_id is _MISSING:
        resolved_policy_id: UUID | None = uuid4()
    else:
        resolved_policy_id = cast(UUID | None, policy_id)

    resolved_tool = synthesize_tools(
        [
            VirtualServerToolCapability(
                server_id=uuid4(),
                server_display_name="GitHub",
                tool_name=upstream_tool_name,
                schema_json={
                    "inputSchema": {
                        "type": "object",
                        "properties": {"q": {"type": "string"}},
                        "required": ["q"],
                    }
                },
            )
        ],
        {upstream_tool_name: exposed_name},
    ).tools[0]
    return ToolCallPolicyContext(
        tenant_id=tenant_id or uuid4(),
        vserver_name="engineering",
        tool=resolved_tool,
        arguments={"q": "secret-query"},
        policy_id=resolved_policy_id,
    )


def _policy(policy_id: UUID | None, **overrides: object) -> dict[str, object]:
    assert policy_id is not None
    payload: dict[str, object] = {
        "policy_id": str(policy_id),
        "version": "v1",
        "default_decision": "deny",
        "rules": [],
    }
    payload.update(overrides)
    return payload


def test_management_policy_provider_pulls_and_evaluates_deny_rule() -> None:
    context = _context()
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json=_policy(
                context.policy_id,
                rules=[{"id": "deny-search", "effect": "deny", "tools": ["search"]}],
            ),
        )

    provider = ManagementPlanePolicyProvider(
        base_url="https://mgmt.example",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    decision = provider.evaluate_tool_call(context)

    assert not decision.allowed
    assert decision.reason == PolicyDenyReason.TOOL_DENIED
    assert decision.rule_id == "deny-search"
    assert requests[0].method == "GET"
    assert requests[0].content == b""
    assert b"secret-query" not in requests[0].content


def test_management_policy_provider_caches_policy_until_ttl_expires() -> None:
    clock = _Clock()
    context = _context()
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_policy(context.policy_id, default_decision="allow"))

    provider = ManagementPlanePolicyProvider(
        base_url="https://mgmt.example",
        ttl_seconds=60,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=clock,
    )

    assert provider.evaluate_tool_call(context).allowed
    clock.advance(59)
    assert provider.evaluate_tool_call(context).allowed
    assert calls == 1

    clock.advance(2)
    assert provider.evaluate_tool_call(context).allowed
    assert calls == 2


def test_management_policy_provider_cache_is_tenant_scoped() -> None:
    policy_id = uuid4()
    tenant_a = uuid4()
    tenant_b = uuid4()
    seen_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        return httpx.Response(200, json=_policy(policy_id, default_decision="allow"))

    provider = ManagementPlanePolicyProvider(
        base_url="https://mgmt.example",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    assert provider.evaluate_tool_call(_context(tenant_id=tenant_a, policy_id=policy_id)).allowed
    assert provider.evaluate_tool_call(_context(tenant_id=tenant_b, policy_id=policy_id)).allowed

    assert len(seen_paths) == 2
    assert str(tenant_a) in seen_paths[0]
    assert str(tenant_b) in seen_paths[1]


def test_management_policy_provider_allows_first_matching_allow_rule() -> None:
    context = _context(exposed_name="safe_search")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_policy(
                context.policy_id,
                rules=[
                    {"id": "allow-safe", "effect": "allow", "tools": ["safe_search"]},
                    {"id": "deny-all", "effect": "deny"},
                ],
            ),
        )

    provider = ManagementPlanePolicyProvider(
        base_url="https://mgmt.example",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    decision = provider.evaluate_tool_call(context)

    assert decision.allowed
    assert decision.rule_id == "allow-safe"


def test_management_policy_provider_denies_when_policy_id_missing() -> None:
    provider = ManagementPlanePolicyProvider(
        base_url="https://mgmt.example",
        http_client=httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(500))
        ),
    )

    decision = provider.evaluate_tool_call(_context(policy_id=None))

    assert not decision.allowed
    assert decision.reason == PolicyDenyReason.TOOL_DENIED
    assert decision.rule_id == "missing_policy_id"


def test_management_policy_provider_fetch_failure_raises_policy_error() -> None:
    context = _context()
    provider = ManagementPlanePolicyProvider(
        base_url="https://mgmt.example",
        http_client=httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(503, text="secret body"))
        ),
    )

    with pytest.raises(ManagementPlanePolicyError, match="HTTPStatusError"):
        provider.evaluate_tool_call(context)


def test_management_policy_provider_rejects_policy_id_mismatch() -> None:
    context = _context()
    provider = ManagementPlanePolicyProvider(
        base_url="https://mgmt.example",
        http_client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json=_policy(uuid4(), default_decision="allow"))
            )
        ),
    )

    with pytest.raises(ManagementPlanePolicyError, match="policy_id_mismatch"):
        provider.evaluate_tool_call(context)


def test_management_policy_provider_sends_authorization_header_when_configured() -> None:
    context = _context()
    authorization_headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        authorization_headers.append(request.headers.get("authorization"))
        return httpx.Response(200, json=_policy(context.policy_id, default_decision="allow"))

    provider = ManagementPlanePolicyProvider(
        base_url="https://mgmt.example",
        bearer_token="test-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    assert provider.evaluate_tool_call(context).allowed
    assert authorization_headers == ["Bearer test-token"]
