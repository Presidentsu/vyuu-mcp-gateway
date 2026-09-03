"""Redis-backed `SessionRegistry` implementation.

Multi-instance deployments share session state via Redis: instance A creates
a session on `initialize`, instance B (behind the same load balancer) looks
it up on the next `tools/call`. The cross-instance round-trip is the property
that makes a Redis-backed registry an HA prerequisite — verified directly by
`tests/sessions/test_redis_registry.py`.

Storage shape:
- Key:   `{key_prefix}:{tenant_id}:{session_id}` (UUIDs serialized as strings).
  The tenant prefix in the key matches `(tenant_id, session_id)` keying in
  `InMemorySessionRegistry` — a session id minted under tenant A is *not*
  reachable under tenant B even via direct Redis access.
- Value: a JSON object with `session_id`, `tenant_id`, `vserver_name`,
  `vserver_id`, `principal`, `client_metadata`, `expires_at`, `policy_id`.
  Pydantic-shaped sub-objects round-trip through `model_dump`/`model_validate`.
- TTL:   set via Redis `EX` to `expires_at - now` so Redis itself drops the
  key on expiry. Lookups also re-check `is_expired()` for clock-skew safety.

Failure modes that are tested:
- Lookup of a missing/expired key → `None`.
- Corrupt or partial JSON in Redis (e.g., from a schema migration mistake) →
  treated as "missing", logged at warning, and the offending key is deleted
  so subsequent lookups don't retry the parse forever.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from redis.asyncio import Redis

from vyuu_gateway.audit.events import AuditClientMetadata, AuditPrincipal
from vyuu_gateway.sessions.registry import GatewaySession, SessionRegistry

logger = logging.getLogger(__name__)

DEFAULT_KEY_PREFIX = "vyuu:session"


class RedisSessionRegistry(SessionRegistry):
    """`SessionRegistry` backed by an async Redis client.

    The Redis client is injected (not constructed) so callers control its
    lifecycle, connection pooling, TLS settings, and authentication.
    `vyuu_gateway.main.create_app` builds one from `Settings.redis_url` for
    the standard production wiring.
    """

    def __init__(self, client: Redis, *, key_prefix: str = DEFAULT_KEY_PREFIX) -> None:
        self._client = client
        self._key_prefix = key_prefix

    async def create_session(self, session: GatewaySession) -> None:
        ttl_seconds = self._ttl_seconds(session.expires_at)
        # Redis `EX 0` is invalid; clamp at 1 so an already-expired session
        # is stored briefly then GC'd. Lookups re-check `is_expired()` so
        # callers never observe such a session even if Redis hasn't swept yet.
        ttl_seconds = max(1, ttl_seconds)
        payload = json.dumps(_to_dict(session))
        await self._client.set(
            self._key(session.tenant_id, session.session_id),
            payload,
            ex=ttl_seconds,
        )

    async def get_session(
        self,
        tenant_id: UUID,
        session_id: str,
    ) -> GatewaySession | None:
        key = self._key(tenant_id, session_id)
        raw = await self._client.get(key)
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            session = _from_dict(data)
        except (ValueError, KeyError, TypeError) as exc:
            # A corrupt entry is dangerous to leave around — every future
            # lookup would retry the parse. Drop it and log so we notice.
            logger.warning(
                "redis_session_payload_unreadable",
                extra={
                    "tenant_id": str(tenant_id),
                    "session_id": session_id,
                    "error": exc.__class__.__name__,
                },
            )
            await self._client.delete(key)
            return None
        if session.is_expired():
            await self._client.delete(key)
            return None
        return session

    async def delete_session(self, tenant_id: UUID, session_id: str) -> None:
        await self._client.delete(self._key(tenant_id, session_id))

    def _key(self, tenant_id: UUID, session_id: str) -> str:
        return f"{self._key_prefix}:{tenant_id}:{session_id}"

    @staticmethod
    def _ttl_seconds(expires_at: datetime) -> int:
        delta = expires_at - datetime.now(UTC)
        return int(delta.total_seconds())


def _to_dict(session: GatewaySession) -> dict[str, Any]:
    return {
        "session_id": session.session_id,
        "tenant_id": str(session.tenant_id),
        "vserver_name": session.vserver_name,
        "vserver_id": str(session.vserver_id) if session.vserver_id is not None else None,
        "principal": session.principal.model_dump(mode="json"),
        "client_metadata": session.client_metadata.model_dump(
            mode="json",
            exclude_none=True,
        ),
        "expires_at": session.expires_at.isoformat(),
        "policy_id": str(session.policy_id) if session.policy_id is not None else None,
    }


def _from_dict(data: dict[str, Any]) -> GatewaySession:
    expires_at = datetime.fromisoformat(data["expires_at"])
    if expires_at.tzinfo is None:
        # We always serialize tz-aware UTC, but defend against an entry
        # written by an older or misconfigured writer.
        expires_at = expires_at.replace(tzinfo=UTC)

    vserver_id_raw = data.get("vserver_id")
    policy_id_raw = data.get("policy_id")

    return GatewaySession(
        session_id=data["session_id"],
        tenant_id=UUID(data["tenant_id"]),
        vserver_name=data["vserver_name"],
        principal=AuditPrincipal.model_validate(data["principal"]),
        client_metadata=AuditClientMetadata.model_validate(data.get("client_metadata") or {}),
        expires_at=expires_at,
        vserver_id=UUID(vserver_id_raw) if vserver_id_raw is not None else None,
        policy_id=UUID(policy_id_raw) if policy_id_raw is not None else None,
    )
