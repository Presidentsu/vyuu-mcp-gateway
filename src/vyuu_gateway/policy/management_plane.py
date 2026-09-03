"""Management-plane backed policy provider.

Policy bodies are pulled on a TTL and evaluated locally. The hot path never
sends tool arguments or tool responses to the management plane.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vyuu_gateway.policy.interfaces import (
    PolicyDecision,
    PolicyDenyReason,
    PolicyProvider,
    ToolCallPolicyContext,
)


class ManagementPlanePolicyError(Exception):
    """Policy could not be pulled or parsed from the management plane."""


class ManagementPolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=255)
    effect: Literal["allow", "deny"]
    tools: list[str] | None = None
    upstream_tools: list[str] | None = None
    upstream_server_ids: list[UUID] | None = None


class ManagementPolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: UUID
    version: str = Field(min_length=1, max_length=255)
    default_decision: Literal["allow", "deny"] = "deny"
    rules: list[ManagementPolicyRule] = Field(default_factory=list)


@dataclass(frozen=True)
class _CacheEntry:
    policy: ManagementPolicyDocument
    expires_at: float


class ManagementPlanePolicyProvider(PolicyProvider):
    """Pull-through cached policy provider for Vyuu management plane."""

    def __init__(
        self,
        *,
        base_url: str,
        ttl_seconds: float = 60.0,
        http_client: httpx.Client | None = None,
        bearer_token: str | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self._base_url = base_url.rstrip("/")
        self._ttl_seconds = ttl_seconds
        self._http_client = http_client or httpx.Client(timeout=5.0)
        self._owns_http_client = http_client is None
        self._bearer_token = bearer_token
        self._clock = clock
        self._cache: dict[tuple[UUID, UUID], _CacheEntry] = {}

    def evaluate_tool_call(self, context: ToolCallPolicyContext) -> PolicyDecision:
        if context.policy_id is None:
            return PolicyDecision.deny(
                PolicyDenyReason.TOOL_DENIED,
                "virtual server has no policy attached",
                rule_id="missing_policy_id",
            )

        policy = self._get_policy(context.tenant_id, context.policy_id)
        rule = _first_matching_rule(policy, context)
        if rule is not None:
            if rule.effect == "allow":
                return PolicyDecision.allow(rule_id=rule.id)
            return PolicyDecision.deny(
                PolicyDenyReason.TOOL_DENIED,
                "tool is denied by management-plane policy",
                rule_id=rule.id,
            )

        if policy.default_decision == "allow":
            return PolicyDecision.allow(rule_id="default_allow")
        return PolicyDecision.deny(
            PolicyDenyReason.TOOL_DENIED,
            "tool is denied by management-plane policy default",
            rule_id="default_deny",
        )

    def close(self) -> None:
        if self._owns_http_client:
            self._http_client.close()

    def _get_policy(self, tenant_id: UUID, policy_id: UUID) -> ManagementPolicyDocument:
        cache_key = (tenant_id, policy_id)
        now = self._clock()
        cached = self._cache.get(cache_key)
        if cached is not None and cached.expires_at > now:
            return cached.policy

        policy = self._fetch_policy(tenant_id, policy_id)
        self._cache[cache_key] = _CacheEntry(policy=policy, expires_at=now + self._ttl_seconds)
        return policy

    def _fetch_policy(self, tenant_id: UUID, policy_id: UUID) -> ManagementPolicyDocument:
        headers: dict[str, str] = {}
        if self._bearer_token is not None:
            headers["Authorization"] = f"Bearer {self._bearer_token}"

        try:
            response = self._http_client.get(
                f"{self._base_url}/api/v1/tenants/{tenant_id}/policies/{policy_id}",
                headers=headers,
            )
            response.raise_for_status()
            payload = response.json()
            policy = ManagementPolicyDocument.model_validate(payload)
        except (httpx.HTTPError, ValueError, ValidationError) as exc:
            raise ManagementPlanePolicyError(exc.__class__.__name__) from exc

        if policy.policy_id != policy_id:
            raise ManagementPlanePolicyError("policy_id_mismatch")
        return policy


def _first_matching_rule(
    policy: ManagementPolicyDocument,
    context: ToolCallPolicyContext,
) -> ManagementPolicyRule | None:
    for rule in policy.rules:
        if _matches_rule(rule, context):
            return rule
    return None


def _matches_rule(rule: ManagementPolicyRule, context: ToolCallPolicyContext) -> bool:
    if rule.tools is not None and context.tool.exposed_name not in rule.tools:
        return False
    if (
        rule.upstream_tools is not None
        and context.tool.upstream_tool_name not in rule.upstream_tools
    ):
        return False
    if (
        rule.upstream_server_ids is not None
        and context.tool.upstream_server_id not in rule.upstream_server_ids
    ):
        return False
    return True
