"""Operator-facing security-posture panel.

Several gateway protections default to **off** deliberately — the safe
default for an irreversible control is to make the operator choose. That
is only defensible if turning them on is discoverable, which is what this
endpoint is for.

The property these tests actually protect is that each row reports the
**consequence of its current state**, not a boolean. "Retention: off"
means nothing to most readers; "tool-call history grows without limit" is
the sentence that gets it enabled. A row whose consequence text does not
change with its state would be decoration.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from vyuu_gateway.api.security_posture import build_posture
from vyuu_gateway.config import Settings
from vyuu_gateway.main import create_app
from vyuu_gateway.operator_auth.fake import mint_operator_test_token

SECRET = "posture-test-secret"


def _settings(**kw: object) -> Settings:
    return Settings(
        app_name="Vyuu", environment="test", log_level="CRITICAL",
        version="t", operator_auth_signing_secret=SECRET, **kw,
    )


def _controls(**kw: object) -> dict:
    return {c.key: c for c in build_posture(_settings(**kw)).controls}


# --- The property that matters ----------------------------------------------


def test_every_control_states_a_consequence_not_just_a_flag() -> None:
    for control in build_posture(_settings()).controls:
        assert control.consequence, f"{control.key} has no consequence text"
        assert len(control.consequence) > 40, (
            f"{control.key}'s consequence is too terse to be useful: "
            f"{control.consequence!r}"
        )
        assert control.label and control.detail


@pytest.mark.parametrize(
    ("key", "on_kwargs"),
    [
        (
            "envelope_encryption",
            {"envelope_encryption_backend": "local", "envelope_master_key": "x" * 44},
        ),
        ("audit_retention", {"tool_call_event_retention_days": 90}),
        ("binary_provenance", {"binary_cosign_verification_key_path": "/k.pub"}),
        ("secret_store", {"secret_store_backend": "vault"}),
        ("tenant_subdomains", {"portal_base_domain": "gw.example.com"}),
        ("cimd_inbound", {"ema_cimd_resolution_enabled": True}),
    ],
)
def test_consequence_changes_with_state(key: str, on_kwargs: dict) -> None:
    """A consequence identical in both states is decoration, not
    information."""

    off = _controls()[key]
    on = _controls(**on_kwargs)[key]
    assert off.enabled is False and on.enabled is True
    assert off.consequence != on.consequence


# --- The states an operator most needs to see -------------------------------


def test_plaintext_tokens_are_flagged_as_a_warning() -> None:
    """The default. It must not read as neutral — a database dump exposes
    every user's connected SaaS accounts."""

    control = _controls()["envelope_encryption"]
    assert control.severity == "warn"
    assert "PLAINTEXT" in control.consequence


def test_encryption_on_clears_the_warning() -> None:
    control = _controls(
        envelope_encryption_backend="local", envelope_master_key="x" * 44
    )["envelope_encryption"]
    assert control.severity == "good"
    assert control.detail == "local master key"


def test_mrtr_deny_all_is_good_not_a_warning() -> None:
    """Deny-all is the SAFE state here, unlike the other controls. A
    panel that flagged it amber would train operators to ignore amber."""

    control = _controls()["mrtr"]
    assert control.enabled is False
    assert control.severity == "good"


def test_unrestricted_url_elicitation_is_the_mrtr_warning() -> None:
    """Enabling url elicitation with no host allowlist lets an upstream
    send your users anywhere. That is the state worth flagging."""

    control = _controls(mrtr_allowed_input_kinds=["elicit_url"])["mrtr"]
    assert control.severity == "warn"
    assert "ANY address" in control.consequence

    restricted = _controls(
        mrtr_allowed_input_kinds=["elicit_url"],
        mrtr_allowed_elicit_url_hosts=["okta.com"],
    )["mrtr"]
    assert restricted.severity == "good"


def test_unbounded_credential_age_is_a_warning() -> None:
    control = _controls(upstream_client_max_age_seconds=0)["credential_freshness"]
    assert control.severity == "warn"
    assert "revoked credential" in control.consequence


def test_credential_age_is_rendered_readably() -> None:
    assert _controls(upstream_client_max_age_seconds=900)[
        "credential_freshness"
    ].detail == "15m"
    assert _controls(upstream_client_max_age_seconds=86400)[
        "credential_freshness"
    ].detail == "1d"


def test_every_control_names_the_env_var_that_changes_it() -> None:
    """Read-only panel — its whole job is to tell the operator what to
    put in their deployment."""

    for control in build_posture(_settings()).controls:
        assert control.env_vars, f"{control.key} names no env var"
        assert all(v.startswith("VYUU_") for v in control.env_vars)


# --- CIMD -------------------------------------------------------------------


def test_cimd_client_id_is_offered_over_https() -> None:
    posture = build_posture(_settings(public_base_url="https://gw.example.com"))
    assert posture.cimd_client_id == (
        "https://gw.example.com/.well-known/oauth-client"
    )


def test_cimd_client_id_is_withheld_over_http() -> None:
    """CIMD's trust model is "whoever controls this URL is the client".
    Over http that is whoever controls the network, so the panel must not
    offer an id the gateway should not be presenting."""

    assert build_posture(_settings(public_base_url="http://127.0.0.1:8000")).cimd_client_id is None


# --- Endpoint ---------------------------------------------------------------


def test_blind_to_cimd_revocation_is_info_not_a_warning() -> None:
    """String matching is the behaviour this gateway has always had, and
    it is not unsafe — only blind to revocation. Enabling resolution
    makes a third party's uptime part of this auth path, which is a real
    trade to make deliberately rather than be nagged into."""

    off = _controls()["cimd_inbound"]
    assert off.severity == "info"
    assert "decommissioned" in off.consequence
    on = _controls(ema_cimd_resolution_enabled=True)["cimd_inbound"]
    assert on.severity == "good"
    # The window is stated, because "revocation works" without a number
    # is not something an operator can plan around.
    assert "15 minutes" in on.consequence


def test_endpoint_requires_operator_auth() -> None:
    client = TestClient(create_app(_settings()))
    assert client.get("/api/v1/admin/security-posture").status_code in (401, 403)


def test_endpoint_returns_the_posture() -> None:
    client = TestClient(create_app(_settings()))
    token = mint_operator_test_token(
        tenant_id=uuid4(), operator_id=uuid4(), signing_secret=SECRET
    )
    response = client.get(
        "/api/v1/admin/security-posture",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    keys = {c["key"] for c in response.json()["controls"]}
    # Every feature shipped this week has a row. A control with no row is
    # a control nobody can verify.
    assert keys >= {
        "envelope_encryption",
        "audit_retention",
        "ssrf_guard",
        "mrtr",
        "binary_provenance",
        "credential_freshness",
        "secret_store",
        "tenant_subdomains",
    }
