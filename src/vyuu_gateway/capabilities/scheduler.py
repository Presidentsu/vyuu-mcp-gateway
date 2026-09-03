"""Periodic capability-sync worker.

Runs `DatabaseCapabilitySyncService.sync_server_capabilities` on a cadence
across every registered upstream. Optional — off by default per
`Settings.capability_sync_enabled`. When enabled, the gateway lifespan
spawns one worker task; on each tick, it walks `mcp_servers` and runs
syncs grouped by tenant with a per-tenant concurrency cap.

Why per-tenant concurrency rather than global: a single tenant with
many servers (think a security org that has registered 200 MCPs)
should not get all of its upstreams probed simultaneously — that's a
synthetic spike on every vendor's API at the same wall-clock minute.
The cap throttles inside a tenant; tenants run in parallel.

Failure model:
- Per-call timeout caps each sync at `per_call_timeout_seconds`.
- Individual sync failures (upstream down, no creds, etc.) are caught
  and logged; the worker continues with the next server.
- Worker loop never raises — operator sees nothing in logs other than
  per-server warnings.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import defaultdict
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.capabilities.client import McpCapabilityClient
from vyuu_gateway.capabilities.sync import DatabaseCapabilitySyncService
from vyuu_gateway.db.models import McpServer, OAuthUserToken
from vyuu_gateway.db.session import bind_tenant_context

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], Session]

# Sentinel returned by `_resolve_authcode_principal` when the server
# requires per-user OAuth but no user has Connected yet — caller logs
# + skips this cycle. Distinct from `None` (which means "not
# authcode; pass through with no principal_id").
_SKIP_AUTHCODE_NO_TOKEN: object = object()


class _SyncSubject(Protocol):
    """Just the row fields the worker reads — keeps the worker testable
    against a list of fakes without standing up a real DB."""

    @property
    def tenant_id(self) -> UUID: ...

    @property
    def id(self) -> UUID: ...


class PeriodicCapabilitySyncScheduler:
    """Spawns one async task that syncs all registered upstreams on a tick."""

    def __init__(
        self,
        *,
        session_factory: SessionFactory,
        capability_client: McpCapabilityClient,
        interval_seconds: float = 3600.0,
        max_concurrent_per_tenant: int = 4,
        per_call_timeout_seconds: float = 30.0,
    ) -> None:
        self._session_factory = session_factory
        self._capability_client = capability_client
        self._interval = max(1.0, float(interval_seconds))
        self._max_concurrent_per_tenant = max(1, int(max_concurrent_per_tenant))
        self._per_call_timeout = max(1.0, float(per_call_timeout_seconds))
        self._task: asyncio.Task[None] | None = None
        self._cycle_count = 0

    @property
    def cycle_count(self) -> int:
        """Number of completed cycles. Useful in tests."""

        return self._cycle_count

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def aclose(self) -> None:
        await self.stop()

    async def run_one_cycle(self) -> None:
        """Single sync pass across all registered servers. Exposed
        primarily so tests can drive deterministic cycles without
        waiting on `asyncio.sleep`."""

        servers = self._fetch_registered_servers()
        by_tenant: dict[UUID, list[_SyncSubject]] = defaultdict(list)
        for server in servers:
            by_tenant[server.tenant_id].append(server)

        # Run tenants in parallel; within a tenant, throttle via semaphore.
        await asyncio.gather(
            *(self._sync_tenant(tenant_id, group) for tenant_id, group in by_tenant.items()),
            return_exceptions=False,
        )
        self._cycle_count += 1

    async def _run(self) -> None:
        while True:
            try:
                await self.run_one_cycle()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - never crash the worker loop
                logger.warning("capability_sync_cycle_failed")
            await asyncio.sleep(self._interval)

    async def _sync_tenant(
        self, tenant_id: UUID, servers: Iterable[_SyncSubject]
    ) -> None:
        semaphore = asyncio.Semaphore(self._max_concurrent_per_tenant)

        async def _one(server: _SyncSubject) -> None:
            async with semaphore:
                await self._sync_one(tenant_id, server.id)

        await asyncio.gather(*(_one(s) for s in servers), return_exceptions=False)

    async def _sync_one(self, tenant_id: UUID, server_id: UUID) -> None:
        try:
            with self._session_factory() as session:
                bind_tenant_context(session, tenant_id)
                # U7 — for `auth_authcode` upstreams, the upstream
                # probe needs a per-user OAuth token. The scheduler
                # has no inbound user context, so resolve any user
                # who has authorised this server (most-recently-
                # refreshed wins — that's the freshest token, lowest
                # chance of expiry between resolution and probe). If
                # nobody has Connected yet, log + skip; the next
                # /initiate (operator Test connect or portal Connect)
                # naturally re-authorises and the next scheduler
                # tick succeeds.
                resolved = self._resolve_authcode_principal(
                    session, tenant_id, server_id
                )
                if resolved is _SKIP_AUTHCODE_NO_TOKEN:
                    logger.info(
                        "capability_sync_skipped_no_authcode_token",
                        extra={
                            "tenant_id": str(tenant_id),
                            "server_id": str(server_id),
                        },
                    )
                    return
                # Narrow `UUID | object | None` → `UUID | None` for the
                # downstream signature; the sentinel was filtered above.
                principal_id: UUID | None = (
                    resolved if isinstance(resolved, UUID) else None
                )
                service = DatabaseCapabilitySyncService(
                    session, self._capability_client
                )
                await asyncio.wait_for(
                    service.sync_server_capabilities(
                        tenant_id, server_id, principal_id=principal_id
                    ),
                    timeout=self._per_call_timeout,
                )
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            logger.warning(
                "capability_sync_per_call_timeout",
                extra={"tenant_id": str(tenant_id), "server_id": str(server_id)},
            )
        except Exception as exc:  # noqa: BLE001 - per-server failure swallowed
            # Drill into anyio task-group wrappers (same pattern as the
            # health checker) so the recorded error is operator-actionable.
            inner: BaseException = exc
            while isinstance(inner, BaseExceptionGroup) and len(inner.exceptions) >= 1:
                inner = inner.exceptions[0]
            logger.warning(
                "capability_sync_per_server_failed",
                extra={
                    "tenant_id": str(tenant_id),
                    "server_id": str(server_id),
                    "error_type": inner.__class__.__name__,
                },
            )

    def _resolve_authcode_principal(
        self, session: Session, tenant_id: UUID, server_id: UUID
    ) -> UUID | object | None:
        """For an `auth_authcode` upstream, return a `user_id` whose
        stored token the scheduler should use to authenticate the
        capability probe. For non-authcode upstreams, return None
        (caller passes through; the upstream provider ignores it).

        Returns the `_SKIP_AUTHCODE_NO_TOKEN` sentinel when the
        server IS authcode but no `oauth_user_tokens` row exists yet
        — caller logs + skips. Authcode servers without any user
        having Connected are unscheduled-syncable by definition, and
        the existing `_only_authcode` skip in the manual sync
        endpoint already handles the operator-side equivalent.
        """
        server = session.get(McpServer, server_id)
        if server is None:
            return None
        # Match the schema's mutual-exclusion rule (auth_oauth /
        # auth_authcode / auth_jwt_bearer are exclusive). Only the
        # authcode case needs a per-user principal.
        if not server.auth_authcode:
            return None
        # Pick the most recently refreshed token's user — that's the
        # one least likely to be expired by the time the probe runs.
        token = session.scalar(
            select(OAuthUserToken)
            .where(
                OAuthUserToken.tenant_id == tenant_id,
                OAuthUserToken.server_id == server_id,
            )
            .order_by(OAuthUserToken.last_refreshed_at.desc())
            .limit(1)
        )
        if token is None:
            return _SKIP_AUTHCODE_NO_TOKEN
        return token.user_id

    def _fetch_registered_servers(self) -> list[McpServer]:
        # Open a fresh session per cycle (not bound to any tenant — this
        # is the cross-tenant scan; the per-server sync below opens its
        # own tenant-bound session for RLS). Filters out servers whose
        # per-server `sync_cadence_minutes` says we're not due yet (or
        # is 0, meaning "manual only — scheduler skip").
        now = datetime.now(UTC)
        with self._session_factory() as session:
            result = session.scalars(select(McpServer))
            # Real `Session.scalars` returns a `ScalarResult` with `.all()`;
            # test fakes may return a plain iterable. Tolerate both.
            rows = list(result.all() if hasattr(result, "all") else result)
        return [s for s in rows if _is_due_for_sync(s, now)]


def _is_due_for_sync(server: McpServer, now: datetime) -> bool:
    """Honors the per-server `sync_cadence_minutes` override.

    Semantics:
        cadence is None → use the global default (every scheduler tick
            counts as due — the global interval already throttles).
        cadence == 0    → manual only; scheduler skips this server
            (operator clicks Sync capabilities by hand).
        cadence > 0     → run no more often than every N minutes; we're
            due iff `last_capabilities_pulled_at` is None or N minutes
            have elapsed since it.
    """
    cadence = server.sync_cadence_minutes
    if cadence == 0:
        return False
    if server.last_capabilities_pulled_at is None:
        return True
    if cadence is None:
        return True
    last = server.last_capabilities_pulled_at
    if last.tzinfo is None:
        # Postgres returns aware datetimes, but defensive against test
        # fakes that pass naïve ones.
        last = last.replace(tzinfo=UTC)
    elapsed_seconds = (now - last).total_seconds()
    return elapsed_seconds >= cadence * 60
