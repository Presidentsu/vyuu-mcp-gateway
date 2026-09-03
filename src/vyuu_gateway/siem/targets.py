"""Where a SIEM target's configuration comes from.

Two tiers, one shape:

- The **deployment** target is built once from `VYUU_SIEM_*` settings.
  It belongs to whoever runs the gateway and receives everything —
  including gateway-wide log lines that carry no tenant.
- A **tenant** target is a `tenant_siem_targets` row that tenant's
  admins manage in the console. It receives only events carrying that
  tenant's id.

`TargetConfig` deliberately carries a secret *reference*, not the token:
`targets_for()` runs on the hot path (inside the audit chain, on a
request thread) where nothing may block on a secret backend. The
exporter's async worker resolves the ref when it builds a batch.

## Caching

`DatabaseTargetResolver` caches per tenant with a TTL, negative results
included — most tenants will have no target, and "no row" must be as
cheap as "a row". A settings change calls `invalidate()` so the console
does not have to tell operators to wait a minute.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import TenantSiemTarget
from vyuu_gateway.db.session import bind_tenant_context
from vyuu_gateway.siem.events import DEFAULT_CATEGORIES, SiemCategory, SiemEvent

logger = logging.getLogger(__name__)

DEPLOYMENT_KEY = "deployment"


@dataclass(frozen=True, slots=True)
class TargetConfig:
    key: str
    tenant_id: UUID | None
    hec_url: str
    # Exactly one of these is set. Tenant targets reference the secret
    # store; the deployment target's token arrives via env like every
    # other deployment credential (`vault_token`, OIDC client secrets).
    token_ref: str | None
    token_literal: str | None
    index: str | None
    source: str
    host: str | None
    verify_tls: bool
    categories: frozenset[SiemCategory]
    include_raw_payloads: bool
    min_log_level: int
    batch_max_events: int = 100
    flush_interval_seconds: float = 2.0

    def accepts(self, event: SiemEvent) -> bool:
        if event.category == SiemCategory.HEARTBEAT:
            return True
        if event.category not in self.categories:
            return False
        if event.category == SiemCategory.GATEWAY_LOG:
            return event.log_level >= self.min_log_level
        return True


class TargetResolver(Protocol):
    def targets_for(self, tenant_id: UUID | None) -> Sequence[TargetConfig]:
        """Every target that may receive an event carrying `tenant_id`.
        Must not block: called on the request path."""

    def invalidate(self, tenant_id: UUID | None) -> None:
        """Forget what is cached for one tenant (None = deployment)."""


class StaticTargetResolver:
    """Fixed list — tests, and deployments with no tenant targets."""

    def __init__(self, targets: Sequence[TargetConfig]) -> None:
        self._targets = list(targets)

    def targets_for(self, tenant_id: UUID | None) -> Sequence[TargetConfig]:
        return [
            t for t in self._targets
            if t.tenant_id is None or t.tenant_id == tenant_id
        ]

    def invalidate(self, tenant_id: UUID | None) -> None:
        return None


def parse_log_level(name: str | None, default: int = logging.WARNING) -> int:
    if not name:
        return default
    level = logging.getLevelNamesMapping().get(name.strip().upper())
    return level if level is not None else default


def parse_categories(names: Sequence[str] | None) -> frozenset[SiemCategory]:
    """Unknown names are dropped rather than failing the whole target —
    a category added in a later release must not disable an existing
    export when the row is read by an older gateway."""

    if names is None:
        return DEFAULT_CATEGORIES
    out: set[SiemCategory] = set()
    for name in names:
        try:
            category = SiemCategory(str(name))
        except ValueError:
            continue
        if category != SiemCategory.HEARTBEAT:
            out.add(category)
    return frozenset(out)


def config_from_row(row: TenantSiemTarget) -> TargetConfig | None:
    """`None` when the row exists but is switched off."""

    if not row.enabled:
        return None
    return TargetConfig(
        key=str(row.tenant_id),
        tenant_id=row.tenant_id,
        hec_url=row.hec_url,
        token_ref=row.hec_token_ref,
        token_literal=None,
        index=row.index or None,
        source=row.source or "vyuu-mcp-gateway",
        host=row.host_override or None,
        verify_tls=bool(row.verify_tls),
        categories=parse_categories(list(row.categories or [])),
        include_raw_payloads=bool(row.include_raw_payloads),
        min_log_level=parse_log_level(row.min_log_level),
        batch_max_events=max(1, int(row.batch_max_events or 100)),
        flush_interval_seconds=max(0.2, float(row.flush_interval_seconds or 2.0)),
    )


class DatabaseTargetResolver:
    """Tenant targets from `tenant_siem_targets`, plus the deployment one."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        *,
        deployment: TargetConfig | None,
        ttl_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._session_factory = session_factory
        self._deployment = deployment
        self._ttl = ttl_seconds
        self._clock = clock
        self._cache: dict[UUID, tuple[float, TargetConfig | None]] = {}
        self._lock = threading.Lock()

    @property
    def deployment(self) -> TargetConfig | None:
        return self._deployment

    def targets_for(self, tenant_id: UUID | None) -> Sequence[TargetConfig]:
        out: list[TargetConfig] = []
        if self._deployment is not None:
            out.append(self._deployment)
        if tenant_id is not None:
            tenant_target = self._tenant_target(tenant_id)
            if tenant_target is not None:
                out.append(tenant_target)
        return out

    def invalidate(self, tenant_id: UUID | None) -> None:
        if tenant_id is None:
            return
        with self._lock:
            self._cache.pop(tenant_id, None)

    def _tenant_target(self, tenant_id: UUID) -> TargetConfig | None:
        now = self._clock()
        with self._lock:
            cached = self._cache.get(tenant_id)
            if cached is not None and cached[0] > now:
                return cached[1]
        config = self._load(tenant_id)
        with self._lock:
            self._cache[tenant_id] = (now + self._ttl, config)
        return config

    def _load(self, tenant_id: UUID) -> TargetConfig | None:
        try:
            with self._session_factory() as session:
                bind_tenant_context(session, tenant_id)
                row = session.scalar(
                    select(TenantSiemTarget).where(
                        TenantSiemTarget.tenant_id == tenant_id
                    )
                )
                return config_from_row(row) if row is not None else None
        except Exception:  # noqa: BLE001 - never let a lookup break emit
            logger.warning(
                "siem_target_lookup_failed",
                extra={"tenant_id": str(tenant_id)},
                exc_info=True,
            )
            return None
