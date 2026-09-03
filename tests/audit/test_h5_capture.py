"""H5 — raw-args / raw-response capture under explicit policy opt-in.

Three layers covered here:
1. `truncate_for_audit_capture` — whole-or-sentinel size cap. Transit
   is never blocked by the cap; only audit-storage size is bounded.
2. `create_tool_call_audit_event(raw_args=..., raw_response=...)` —
   factory threads payloads through the truncator and records the
   `raw_*_truncated` flags.
3. `PolicyDecision.allow(capture_raw_args=...)` — the opt-in surface.
"""

from __future__ import annotations

from collections.abc import Iterator
from uuid import uuid4

import pytest

from vyuu_gateway.audit.events import (
    AuditDecision,
    AuditPrincipal,
    AuditPrincipalType,
    UpstreamStatus,
    configure_raw_capture_cap,
    create_tool_call_audit_event,
    truncate_for_audit_capture,
)
from vyuu_gateway.policy.interfaces import PolicyDecision

# Default cap for the module is 10 MiB (production-realistic). Test
# fixtures lower it so we don't have to allocate big payloads to
# exercise the sentinel path. Restored on teardown so tests stay
# isolated.
_TEST_CAP = 16 * 1024  # 16 KiB
_DEFAULT_CAP = 10 * 1024 * 1024  # matches `_AUDIT_RAW_CAPTURE_BYTE_CAP`


@pytest.fixture(autouse=True)
def _small_cap_for_tests() -> Iterator[None]:
    configure_raw_capture_cap(_TEST_CAP)
    try:
        yield
    finally:
        configure_raw_capture_cap(_DEFAULT_CAP)


# --- truncate_for_audit_capture --------------------------------------------


def test_truncate_returns_none_unchanged_for_none() -> None:
    out, truncated = truncate_for_audit_capture(None)
    assert out is None
    assert truncated is False


def test_truncate_returns_payload_unchanged_when_under_cap() -> None:
    payload = {"foo": "bar", "n": 42}
    out, truncated = truncate_for_audit_capture(payload)
    assert out == payload
    assert truncated is False


def test_truncate_returns_sentinel_when_over_cap() -> None:
    """Payload above the cap → no body stored, sentinel records the
    real `total_bytes`. Transit through the gateway is unaffected."""
    payload = {"big": "x" * 64_000}  # ~64 KB > 16 KB test cap
    out, truncated = truncate_for_audit_capture(payload)
    assert truncated is True
    assert isinstance(out, dict)
    assert out["__truncated__"] is True
    # Operator must see how much actually flowed through.
    assert out["total_bytes"] > 64_000
    assert out["stored_bytes"] == 0
    assert out["cap_bytes"] == _TEST_CAP
    assert "transit unaffected" in out["reason"]
    # Original payload field is gone — that's the whole-or-sentinel
    # contract; partial fragments aren't useful.
    assert "big" not in out


def test_truncate_returns_payload_unchanged_at_default_10mib_cap() -> None:
    """Confirm production default of 10 MiB — a 64 KB payload should
    pass through unchanged at default cap."""
    configure_raw_capture_cap(_DEFAULT_CAP)
    try:
        payload = {"big": "x" * 64_000}
        out, truncated = truncate_for_audit_capture(payload)
        assert out == payload
        assert truncated is False
    finally:
        configure_raw_capture_cap(_TEST_CAP)


def test_configure_raw_capture_cap_rejects_too_small() -> None:
    """Refuse caps under 1 KiB — those would sentinel essentially
    every realistic payload and obscure the audit-storage intent."""
    with pytest.raises(ValueError):
        configure_raw_capture_cap(512)


def test_truncate_returns_safe_sentinel_for_non_serialisable() -> None:
    """Pydantic / dataclass / arbitrary object — not JSON-roundtrippable.
    Must not raise; returns a clear sentinel."""

    class _Opaque:
        pass

    payload = {"weird": _Opaque()}
    out, truncated = truncate_for_audit_capture(payload)
    # Either captured-with-default-str-coercion (safe) or sentinel-replaced.
    # In both cases truncation flag must NOT be False if we lose info.
    assert isinstance(out, dict)
    if "__non_serialisable__" in out:
        assert truncated is True


# --- create_tool_call_audit_event raw-fields ------------------------------


def _principal() -> AuditPrincipal:
    return AuditPrincipal(type=AuditPrincipalType.API_KEY, id="p")


def test_event_default_has_raw_fields_none() -> None:
    """No raw_* args passed → fields default to None (privacy default)."""
    event = create_tool_call_audit_event(
        tenant_id=uuid4(),
        gateway_instance_id="g",
        principal=_principal(),
        tool="t",
        arguments={"a": 1},
        decision=AuditDecision.ALLOW,
        upstream_status=UpstreamStatus.OK,
    )
    assert event.raw_args is None
    assert event.raw_response is None
    assert event.raw_args_truncated is False
    assert event.raw_response_truncated is False


def test_event_records_raw_args_when_passed() -> None:
    payload = {"query": "SELECT *", "limit": 10}
    event = create_tool_call_audit_event(
        tenant_id=uuid4(),
        gateway_instance_id="g",
        principal=_principal(),
        tool="run_query",
        arguments=payload,
        decision=AuditDecision.ALLOW,
        upstream_status=UpstreamStatus.OK,
        raw_args=payload,
    )
    assert event.raw_args == payload
    assert event.raw_args_truncated is False


def test_event_marks_raw_args_truncated_when_oversized() -> None:
    huge = {"blob": "x" * 64_000}  # > 16 KiB test cap
    event = create_tool_call_audit_event(
        tenant_id=uuid4(),
        gateway_instance_id="g",
        principal=_principal(),
        tool="t",
        arguments=huge,
        decision=AuditDecision.ALLOW,
        upstream_status=UpstreamStatus.OK,
        raw_args=huge,
    )
    assert event.raw_args_truncated is True
    # New whole-or-sentinel contract: raw_args holds the sentinel,
    # not a partial fragment, and records the original total size.
    assert event.raw_args is not None
    assert event.raw_args["__truncated__"] is True
    assert event.raw_args["total_bytes"] > 64_000
    assert event.raw_args["stored_bytes"] == 0


# --- PolicyDecision opt-in surface ----------------------------------------


def test_policy_decision_allow_defaults_capture_off() -> None:
    decision = PolicyDecision.allow()
    assert decision.capture_raw_args is False
    assert decision.capture_raw_response is False


def test_policy_decision_allow_can_opt_in_to_capture() -> None:
    decision = PolicyDecision.allow(
        capture_raw_args=True,
        capture_raw_response=True,
    )
    assert decision.capture_raw_args is True
    assert decision.capture_raw_response is True


def test_policy_decision_deny_path_does_not_carry_capture_flags() -> None:
    """Deny decisions never carry capture flags — there's no upstream
    response to capture and the args are already in args_summary."""
    from vyuu_gateway.policy.interfaces import PolicyDenyReason

    decision = PolicyDecision.deny(PolicyDenyReason.TOOL_DENIED)
    assert decision.capture_raw_args is False
    assert decision.capture_raw_response is False
