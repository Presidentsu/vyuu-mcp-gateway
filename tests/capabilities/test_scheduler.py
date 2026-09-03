"""Unit tests for the periodic capability-sync scheduler.

Tests drive deterministic cycles via `run_one_cycle()` rather than
waiting on `asyncio.sleep`, so they're fast and predictable. The
end-to-end `start()` + sleep loop is covered by an integration smoke
test that uses a tiny interval.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest

from vyuu_gateway.capabilities.client import CapabilityDescriptor, McpCapabilityClient
from vyuu_gateway.capabilities.scheduler import (
    PeriodicCapabilitySyncScheduler,
    _is_due_for_sync,
)
from vyuu_gateway.db.models import (
    McpServer,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
)


def _server(*, tenant_id: UUID, server_id: UUID | None = None) -> McpServer:
    return McpServer(
        id=server_id or uuid4(),
        tenant_id=tenant_id,
        display_name=f"server-{(server_id or uuid4()).hex[:6]}",
        source_type=McpServerSourceType.HTTP,
        source_location="https://upstream.example/mcp",
        transport=McpTransport.STREAMABLE_HTTP,
        args=[],
        registered_by=uuid4(),
        health_status=McpServerHealthStatus.UNKNOWN,
    )


class _RecordingCapabilityClient(McpCapabilityClient):
    """Records list_capabilities calls; `delay` lets tests force overlap
    with the per-tenant concurrency cap."""

    def __init__(self, *, delay: float = 0.0) -> None:
        self.calls: list[UUID] = []
        self.principal_ids: list[UUID | None] = []
        self._delay = delay
        self.in_flight = 0
        self.peak_in_flight = 0

    async def list_capabilities(
        self,
        server: McpServer,
        *,
        principal_id: UUID | None = None,
    ) -> list[CapabilityDescriptor]:
        # U7 — record principal_id alongside the call so the
        # authcode-resolves-from-tokens test can assert the right
        # user was picked. Stdio/M2M servers send None.
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        try:
            self.calls.append(server.id)
            self.principal_ids.append(principal_id)
            if self._delay > 0:
                await asyncio.sleep(self._delay)
            return []
        finally:
            self.in_flight -= 1


class _FakeSession:
    """In-memory `Session` stand-in. `scalar` filters by the requested
    server_id parameter so concurrent per-server syncs in the scheduler
    receive distinct rows (otherwise every concurrent `_sync_one` would
    re-process the same first server and the sync test couldn't tell
    whether all rows were visited)."""

    def __init__(
        self,
        servers: Iterable[McpServer],
        *,
        oauth_tokens: list[Any] | None = None,
    ) -> None:
        self._servers = list(servers)
        self._added: list[Any] = []
        self.info: dict[str, Any] = {}
        # U7 — `OAuthUserToken`-shaped objects keyed by server_id, used
        # by `_resolve_authcode_principal` when scheduling sync for an
        # `auth_authcode` upstream. SimpleNamespace works because the
        # scheduler only reads `user_id` + `last_refreshed_at`.
        self._oauth_tokens = list(oauth_tokens or [])

    def __enter__(self) -> _FakeSession:
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def scalar(self, statement: Any) -> Any:
        # U7 — token lookup query: `select(OAuthUserToken).where(
        # server_id==X).order_by(last_refreshed_at desc).limit(1)`.
        # When the SQL mentions oauth_user_tokens, return the matching
        # SimpleNamespace token (most-recently-refreshed wins).
        sql = str(statement).lower()
        if "oauth_user_tokens" in sql:
            params = self._compiled_params(statement)
            wanted_server = params.get("server_id_1") or params.get("server_id")
            matching = [
                t for t in self._oauth_tokens if t.server_id == wanted_server
            ]
            if not matching:
                return None
            return max(matching, key=lambda t: t.last_refreshed_at)
        # Default McpServer lookup path.
        params = self._compiled_params(statement)
        wanted_id = params.get("id_1") or params.get("id")
        if wanted_id is None:
            # Fallback for shapes we haven't accounted for — return the
            # first server (legacy behavior for non-McpServer queries).
            return self._servers[0] if self._servers else None
        for server in self._servers:
            if server.id == wanted_id:
                return server
        return None

    def get(self, model: Any, ident: Any) -> Any:
        # U7 — `_resolve_authcode_principal` uses `session.get(McpServer,
        # server_id)` to read the server's auth_authcode column without
        # building a full `select`. Return the matching row.
        from vyuu_gateway.db.models import McpServer as _McpServer
        if model is _McpServer:
            for server in self._servers:
                if server.id == ident:
                    return server
        return None

    def scalars(self, statement: Any) -> list[Any]:
        # Two callsites: cross-tenant scan returns all rows; per-tenant
        # sync calls scalars with the prior-capabilities query.
        sql = str(statement)
        if "mcp_capabilities" in sql:
            return []
        return list(self._servers)

    def add(self, _instance: Any) -> None:
        self._added.append(_instance)

    def commit(self) -> None:
        return None

    def refresh(self, _server: Any) -> None:
        return None

    @staticmethod
    def _compiled_params(statement: Any) -> dict[str, Any]:
        try:
            compiled = statement.compile(compile_kwargs={"literal_binds": False})
        except Exception:  # noqa: BLE001 - non-SQL statements (None, etc.)
            return {}
        return dict(compiled.params or {})


def _build_scheduler(
    *,
    servers: list[McpServer],
    capability_client: _RecordingCapabilityClient,
    max_concurrent_per_tenant: int = 4,
    per_call_timeout_seconds: float = 30.0,
    oauth_tokens: list[Any] | None = None,
) -> PeriodicCapabilitySyncScheduler:
    def factory() -> _FakeSession:
        return _FakeSession(servers, oauth_tokens=oauth_tokens)

    return PeriodicCapabilitySyncScheduler(
        session_factory=factory,  # type: ignore[arg-type]
        capability_client=capability_client,
        interval_seconds=3600.0,  # not used in run_one_cycle tests
        max_concurrent_per_tenant=max_concurrent_per_tenant,
        per_call_timeout_seconds=per_call_timeout_seconds,
    )


def test_one_cycle_syncs_every_registered_server() -> None:
    tenant = uuid4()
    servers = [_server(tenant_id=tenant) for _ in range(3)]
    client = _RecordingCapabilityClient()
    scheduler = _build_scheduler(servers=servers, capability_client=client)

    asyncio.run(scheduler.run_one_cycle())

    assert sorted(client.calls) == sorted(s.id for s in servers)
    assert scheduler.cycle_count == 1


def test_per_tenant_concurrency_cap_throttles_within_a_tenant() -> None:
    """A tenant with N servers should never have more than `cap` syncs
    in flight at once. Use a slow client to force overlap."""
    tenant = uuid4()
    servers = [_server(tenant_id=tenant) for _ in range(8)]
    client = _RecordingCapabilityClient(delay=0.05)
    scheduler = _build_scheduler(
        servers=servers,
        capability_client=client,
        max_concurrent_per_tenant=2,
    )

    asyncio.run(scheduler.run_one_cycle())

    assert client.peak_in_flight <= 2
    assert len(client.calls) == 8


def test_separate_tenants_run_in_parallel_not_throttled_together() -> None:
    """Two tenants with 4 servers each + cap=2 → up to 4 in flight
    (2 per tenant × 2 tenants). The cap is per-tenant, not global."""
    tenant_a = uuid4()
    tenant_b = uuid4()
    servers = [_server(tenant_id=tenant_a) for _ in range(4)] + [
        _server(tenant_id=tenant_b) for _ in range(4)
    ]
    client = _RecordingCapabilityClient(delay=0.05)
    scheduler = _build_scheduler(
        servers=servers,
        capability_client=client,
        max_concurrent_per_tenant=2,
    )

    asyncio.run(scheduler.run_one_cycle())

    # Up to 2 per tenant × 2 tenants = 4 concurrent. Allow 3-4 to
    # account for scheduler scheduling jitter.
    assert client.peak_in_flight <= 4
    assert client.peak_in_flight >= 2


def test_per_call_timeout_does_not_abort_cycle() -> None:
    """A slow upstream that exceeds `per_call_timeout` must not block
    other servers. The cycle keeps going; the slow one is logged as
    timed out and the rest sync normally."""
    tenant = uuid4()
    fast = _server(tenant_id=tenant)
    slow = _server(tenant_id=tenant)

    class _MixedClient(McpCapabilityClient):
        def __init__(self) -> None:
            self.calls: list[UUID] = []

        async def list_capabilities(
            self,
            server: McpServer,
            *,
            principal_id: UUID | None = None,
        ) -> list[CapabilityDescriptor]:
            del principal_id
            if server.id == slow.id:
                await asyncio.sleep(5)  # past timeout
            self.calls.append(server.id)
            return []

    client = _MixedClient()
    scheduler = PeriodicCapabilitySyncScheduler(
        session_factory=lambda: _FakeSession([fast, slow]),  # type: ignore[arg-type, return-value]
        capability_client=client,
        per_call_timeout_seconds=0.3,
        max_concurrent_per_tenant=2,
    )

    asyncio.run(scheduler.run_one_cycle())

    # Only the fast server got recorded; slow was timed out before
    # appending.
    assert fast.id in client.calls
    assert slow.id not in client.calls


def test_per_server_failure_does_not_abort_cycle() -> None:
    """Individual sync failure logs + continues. Cycle still completes."""

    tenant = uuid4()
    failing = _server(tenant_id=tenant)
    succeeding = _server(tenant_id=tenant)

    class _PartialFailingClient(McpCapabilityClient):
        def __init__(self) -> None:
            self.calls: list[UUID] = []

        async def list_capabilities(
            self,
            server: McpServer,
            *,
            principal_id: UUID | None = None,
        ) -> list[CapabilityDescriptor]:
            del principal_id
            if server.id == failing.id:
                raise RuntimeError("simulated upstream failure")
            self.calls.append(server.id)
            return []

    client = _PartialFailingClient()
    scheduler = PeriodicCapabilitySyncScheduler(
        session_factory=lambda: _FakeSession([failing, succeeding]),  # type: ignore[arg-type, return-value]
        capability_client=client,
        per_call_timeout_seconds=5.0,
        max_concurrent_per_tenant=2,
    )

    asyncio.run(scheduler.run_one_cycle())

    assert succeeding.id in client.calls
    assert failing.id not in client.calls
    assert scheduler.cycle_count == 1


def test_start_and_stop_lifecycle_does_not_leak_tasks() -> None:
    """Start spawns the worker; stop cancels cleanly. No orphan tasks."""

    tenant = uuid4()
    servers = [_server(tenant_id=tenant)]
    client = _RecordingCapabilityClient()
    scheduler = PeriodicCapabilitySyncScheduler(
        session_factory=lambda: _FakeSession(servers),  # type: ignore[arg-type, return-value]
        capability_client=client,
        # Tiny interval so a cycle actually runs before we stop.
        interval_seconds=1.0,
        max_concurrent_per_tenant=2,
        per_call_timeout_seconds=5.0,
    )

    async def run() -> None:
        await scheduler.start()
        # Yield long enough for one cycle.
        await asyncio.sleep(0.1)
        await scheduler.stop()
        # Idempotent — calling stop twice is fine.
        await scheduler.stop()

    asyncio.run(run())

    assert scheduler.cycle_count >= 1


def test_disabled_scheduler_is_not_present_in_app_state() -> None:
    """`Settings.capability_sync_enabled=False` (default) → no scheduler
    is constructed. Confirms the opt-in default."""
    from vyuu_gateway.config import Settings
    from vyuu_gateway.main import create_app

    app = create_app(
        Settings(
            app_name="t",
            environment="test",
            log_level="CRITICAL",
            operator_auth_signing_secret="x",
        )
    )

    assert app.state.capability_sync_scheduler is None


def test_enabled_scheduler_lands_in_app_state() -> None:
    from vyuu_gateway.config import Settings
    from vyuu_gateway.main import create_app

    app = create_app(
        Settings(
            app_name="t",
            environment="test",
            log_level="CRITICAL",
            operator_auth_signing_secret="x",
            capability_sync_enabled=True,
        )
    )

    assert isinstance(
        app.state.capability_sync_scheduler, PeriodicCapabilitySyncScheduler
    )


@pytest.mark.parametrize("interval", [0.0, -1.0, 0.5])
def test_interval_below_minimum_is_clamped(interval: float) -> None:
    """Tiny / zero / negative intervals would spin the worker — clamp
    to a 1s floor as defense in depth (operators can override but not
    accidentally DoS themselves)."""
    scheduler = PeriodicCapabilitySyncScheduler(
        session_factory=lambda: _FakeSession([]),  # type: ignore[arg-type, return-value]
        capability_client=_RecordingCapabilityClient(),
        interval_seconds=interval,
        max_concurrent_per_tenant=2,
        per_call_timeout_seconds=5.0,
    )
    assert scheduler._interval >= 1.0  # noqa: SLF001


# --- Per-server sync_cadence_minutes filter -------------------------------

class _IsDueDescribeIt:
    """Group the `_is_due_for_sync` matrix in one place for readability."""

    @staticmethod
    def _make(*, cadence: int | None, last_synced_minutes_ago: int | None) -> McpServer:
        s = _server(tenant_id=uuid4())
        s.sync_cadence_minutes = cadence
        if last_synced_minutes_ago is None:
            s.last_capabilities_pulled_at = None
        else:
            s.last_capabilities_pulled_at = (
                datetime.now(UTC) - timedelta(minutes=last_synced_minutes_ago)
            )
        return s


def test_is_due_for_sync_skips_manual_only_servers() -> None:
    """cadence=0 means the operator wants to sync this server by hand;
    the scheduler should never pick it up regardless of stale-ness."""

    server = _IsDueDescribeIt._make(cadence=0, last_synced_minutes_ago=99999)
    assert _is_due_for_sync(server, datetime.now(UTC)) is False


def test_is_due_for_sync_returns_true_for_never_synced() -> None:
    """Any positive cadence + no prior sync → always due."""

    server = _IsDueDescribeIt._make(cadence=60, last_synced_minutes_ago=None)
    assert _is_due_for_sync(server, datetime.now(UTC)) is True


def test_is_due_for_sync_throttles_by_cadence() -> None:
    """cadence=60 + last sync 30 min ago → not due. 90 min ago → due."""

    too_recent = _IsDueDescribeIt._make(cadence=60, last_synced_minutes_ago=30)
    assert _is_due_for_sync(too_recent, datetime.now(UTC)) is False

    overdue = _IsDueDescribeIt._make(cadence=60, last_synced_minutes_ago=90)
    assert _is_due_for_sync(overdue, datetime.now(UTC)) is True


def test_is_due_for_sync_treats_none_as_use_global_default() -> None:
    """cadence=None → defer to the global tick; every cycle is due."""

    just_synced = _IsDueDescribeIt._make(cadence=None, last_synced_minutes_ago=1)
    assert _is_due_for_sync(just_synced, datetime.now(UTC)) is True


# ---------------------------------------------------------------------------
# U7 — scheduler resolves principal_id for authcode upstreams
# ---------------------------------------------------------------------------


def _authcode_server(*, tenant_id: UUID, server_id: UUID | None = None) -> McpServer:
    """Variant of `_server` with an `auth_authcode` blob set so the
    scheduler routes through the principal resolution path."""
    s = _server(tenant_id=tenant_id, server_id=server_id)
    s.auth_authcode = {
        "auth_url": "https://idp.example/authorize",
        "token_url": "https://idp.example/token",
        "client_id_ref": "demo",
        "client_secret_ref": "demo-secret",
        "redirect_uri": "https://gw.example/callback",
        "scopes": [],
    }
    return s


def _token(
    *, server_id: UUID, user_id: UUID, last_refreshed_at: datetime
) -> Any:
    """Minimal `OAuthUserToken`-shaped row for the FakeSession.
    The scheduler reads only `user_id` + `last_refreshed_at`."""
    from types import SimpleNamespace
    return SimpleNamespace(
        server_id=server_id,
        user_id=user_id,
        last_refreshed_at=last_refreshed_at,
    )


def test_authcode_server_resolves_most_recently_refreshed_user_token() -> None:
    """When the scheduler hits an `auth_authcode` upstream, it must
    pick the user_id whose token is most recently refreshed (lowest
    chance of being expired by the time the probe runs) and pass that
    as `principal_id` to the upstream client."""
    tenant = uuid4()
    server = _authcode_server(tenant_id=tenant)
    older_user = uuid4()
    fresher_user = uuid4()
    now = datetime.now(UTC)
    tokens = [
        _token(
            server_id=server.id,
            user_id=older_user,
            last_refreshed_at=now - timedelta(hours=2),
        ),
        _token(
            server_id=server.id,
            user_id=fresher_user,
            last_refreshed_at=now - timedelta(minutes=5),
        ),
    ]

    client = _RecordingCapabilityClient()
    scheduler = _build_scheduler(
        servers=[server], capability_client=client, oauth_tokens=tokens
    )

    asyncio.run(scheduler.run_one_cycle())

    assert client.calls == [server.id]
    assert client.principal_ids == [fresher_user], (
        f"expected fresher token's user_id; got {client.principal_ids}"
    )


def test_authcode_server_with_no_user_tokens_is_skipped_with_log() -> None:
    """An authcode upstream that nobody has Connected yet has no
    `oauth_user_tokens` row to lend a principal_id. The scheduler
    must skip it (rather than calling sync with `principal_id=None`,
    which would 401 silently). The next /initiate (operator Test
    connect or portal Connect) re-authorises and the next tick
    succeeds."""
    tenant = uuid4()
    server = _authcode_server(tenant_id=tenant)
    client = _RecordingCapabilityClient()
    scheduler = _build_scheduler(
        servers=[server], capability_client=client, oauth_tokens=[]
    )

    asyncio.run(scheduler.run_one_cycle())

    assert client.calls == [], (
        "scheduler must skip authcode servers with no stored user tokens"
    )


def test_non_authcode_server_passes_principal_id_none() -> None:
    """The scheduler must NOT change behavior for non-authcode
    upstreams (M2M, env, mTLS, no-auth, stdio, etc.) — they keep
    their existing path with `principal_id=None`. Tests that the
    new code path is targeted at `auth_authcode` and doesn't leak
    sentinel/skip behavior elsewhere."""
    tenant = uuid4()
    # `_server` (not `_authcode_server`) → no auth_authcode set.
    server = _server(tenant_id=tenant)
    client = _RecordingCapabilityClient()
    scheduler = _build_scheduler(servers=[server], capability_client=client)

    asyncio.run(scheduler.run_one_cycle())

    assert client.calls == [server.id]
    assert client.principal_ids == [None]
