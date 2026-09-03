"""SIEM-1 · target configuration: parsing, acceptance, caching."""

from __future__ import annotations

import logging
from typing import Any, cast
from uuid import uuid4

from vyuu_gateway.db.models import TenantSiemTarget
from vyuu_gateway.siem.events import DEFAULT_CATEGORIES, SiemCategory, SiemEvent
from vyuu_gateway.siem.targets import (
    DatabaseTargetResolver,
    StaticTargetResolver,
    TargetConfig,
    config_from_row,
    parse_categories,
    parse_log_level,
)


def _config(**overrides: Any) -> TargetConfig:
    kwargs: dict[str, Any] = {
        "key": "t",
        "tenant_id": uuid4(),
        "hec_url": "https://s:8088",
        "token_ref": "ref",
        "token_literal": None,
        "index": None,
        "source": "vyuu-mcp-gateway",
        "host": None,
        "verify_tls": True,
        "categories": DEFAULT_CATEGORIES,
        "include_raw_payloads": False,
        "min_log_level": logging.WARNING,
    }
    kwargs.update(overrides)
    return TargetConfig(**kwargs)


def _event(category: SiemCategory, *, level: int = 0) -> SiemEvent:
    return SiemEvent(category=category, tenant_id=uuid4(), body={}, log_level=level)


def test_parse_categories_drops_unknown_and_heartbeat() -> None:
    out = parse_categories(["tool_call", "bogus", "heartbeat", "auth"])
    assert out == frozenset({SiemCategory.TOOL_CALL, SiemCategory.AUTH})


def test_parse_categories_none_means_the_defaults() -> None:
    assert parse_categories(None) == DEFAULT_CATEGORIES
    assert SiemCategory.GATEWAY_LOG not in DEFAULT_CATEGORIES


def test_parse_log_level_is_case_insensitive_with_a_default() -> None:
    assert parse_log_level("error") == logging.ERROR
    assert parse_log_level("nonsense") == logging.WARNING
    assert parse_log_level(None, default=logging.INFO) == logging.INFO


def test_accepts_filters_by_category_and_log_level() -> None:
    config = _config(
        categories=frozenset({SiemCategory.TOOL_CALL, SiemCategory.GATEWAY_LOG}),
        min_log_level=logging.WARNING,
    )
    assert config.accepts(_event(SiemCategory.TOOL_CALL))
    assert not config.accepts(_event(SiemCategory.AUTH))
    assert config.accepts(_event(SiemCategory.GATEWAY_LOG, level=logging.ERROR))
    assert not config.accepts(_event(SiemCategory.GATEWAY_LOG, level=logging.INFO))
    # The test button must always get through.
    assert config.accepts(_event(SiemCategory.HEARTBEAT))


def test_config_from_row_is_none_when_disabled() -> None:
    row = TenantSiemTarget(
        id=uuid4(), tenant_id=uuid4(), enabled=False, hec_url="https://s:8088",
        hec_token_ref="ref", categories=["tool_call"],
    )
    assert config_from_row(row) is None


def test_config_from_row_reads_every_field() -> None:
    tenant = uuid4()
    row = TenantSiemTarget(
        id=uuid4(), tenant_id=tenant, enabled=True, hec_url="https://s:8088",
        hec_token_ref="ref", index="sec", source="gw", host_override="h",
        verify_tls=False, categories=["tool_call", "gateway_log"],
        include_raw_payloads=True, min_log_level="ERROR",
        batch_max_events=7, flush_interval_seconds=0.5,
    )
    config = config_from_row(row)
    assert config is not None
    assert config.key == str(tenant)
    assert config.token_ref == "ref" and config.token_literal is None
    assert config.index == "sec" and config.host == "h" and config.verify_tls is False
    assert config.categories == frozenset({SiemCategory.TOOL_CALL, SiemCategory.GATEWAY_LOG})
    assert config.include_raw_payloads is True
    assert config.min_log_level == logging.ERROR
    assert config.batch_max_events == 7 and config.flush_interval_seconds == 0.5


def test_static_resolver_returns_deployment_plus_matching_tenant_only() -> None:
    tenant_a, tenant_b = uuid4(), uuid4()
    deployment = _config(key="deployment", tenant_id=None, token_ref=None, token_literal="t")
    a = _config(key=str(tenant_a), tenant_id=tenant_a)
    b = _config(key=str(tenant_b), tenant_id=tenant_b)
    resolver = StaticTargetResolver([deployment, a, b])
    assert [t.key for t in resolver.targets_for(tenant_a)] == ["deployment", str(tenant_a)]
    assert [t.key for t in resolver.targets_for(None)] == ["deployment"]


# --- database resolver -------------------------------------------------------


class _FakeSession:
    def __init__(self, row: Any, *, raise_: bool = False) -> None:
        self._row = row
        self._raise = raise_
        self.info: dict[str, Any] = {}
        self.queries = 0

    def __enter__(self) -> _FakeSession:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def scalar(self, statement: Any) -> Any:
        self.queries += 1
        if self._raise:
            raise RuntimeError("db down")
        return self._row


def test_database_resolver_caches_hits_and_misses_until_invalidated() -> None:
    tenant = uuid4()
    row = TenantSiemTarget(
        id=uuid4(), tenant_id=tenant, enabled=True, hec_url="https://s:8088",
        hec_token_ref="ref", categories=["tool_call"],
    )
    session = _FakeSession(row)
    now = [100.0]
    resolver = DatabaseTargetResolver(
        cast(Any, lambda: session), deployment=None, ttl_seconds=60.0, clock=lambda: now[0]
    )
    assert [t.key for t in resolver.targets_for(tenant)] == [str(tenant)]
    resolver.targets_for(tenant)
    assert session.queries == 1  # cached
    now[0] += 61
    resolver.targets_for(tenant)
    assert session.queries == 2  # ttl expired
    resolver.invalidate(tenant)
    resolver.targets_for(tenant)
    assert session.queries == 3  # explicit invalidation

    # A tenant with no row is cached as a miss too.
    empty = _FakeSession(None)
    resolver2 = DatabaseTargetResolver(cast(Any, lambda: empty), deployment=None, ttl_seconds=60.0)
    other = uuid4()
    assert resolver2.targets_for(other) == []
    resolver2.targets_for(other)
    assert empty.queries == 1


def test_database_resolver_survives_a_lookup_failure() -> None:
    session = _FakeSession(None, raise_=True)
    deployment = _config(key="deployment", tenant_id=None, token_ref=None, token_literal="t")
    resolver = DatabaseTargetResolver(cast(Any, lambda: session), deployment=deployment)
    assert [t.key for t in resolver.targets_for(uuid4())] == ["deployment"]
