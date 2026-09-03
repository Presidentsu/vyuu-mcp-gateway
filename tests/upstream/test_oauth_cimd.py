"""MCP-2 P3 · CIMD (Client ID Metadata Document).

Two halves, both covered here:

- **The document we serve** (`api/cimd.py`). Under CIMD the client_id
  *is* this URL, so the document has to self-identify with it, and the
  redirect URI it publishes is the only thing standing between us and
  anyone who can reach the URL. Those are the properties tested.
- **The per-AS decision** (`upstream/oauth_cimd.py`) — whether to present
  the document or fall back to the DCR path we already ship.

The decision deliberately falls **back**, not closed. That inverts the
rule used elsewhere in the gateway, and the justification is that the two
paths grant *identical* authority: same redirect URI, same scopes, same
eventual token. Choosing between them is a mechanism decision, not a
trust decision.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from vyuu_gateway.api.cimd import CIMD_PATH, build_client_metadata, client_id_url
from vyuu_gateway.config import Settings
from vyuu_gateway.main import create_app
from vyuu_gateway.upstream.oauth_cimd import (
    CIMD_SUPPORT_KEY,
    plan_from_as_metadata,
)

BASE = "https://gw.example.com"
CLIENT_ID = f"{BASE}{CIMD_PATH}"


def _client(base: str = BASE) -> TestClient:
    return TestClient(
        create_app(
            Settings(
                app_name="Vyuu MCP Gateway",
                environment="test",
                log_level="CRITICAL",
                version="t",
                public_base_url=base,
            )
        )
    )


def _as_metadata(**overrides: object) -> dict:
    doc = {
        CIMD_SUPPORT_KEY: True,
        "issuer": "https://as.example.com",
        "authorization_endpoint": "https://as.example.com/authorize",
        "token_endpoint": "https://as.example.com/token",
    }
    doc.update(overrides)
    return doc


# --- The document we serve --------------------------------------------------


def test_document_self_identifies_with_its_own_url() -> None:
    """CIMD requires it, and it is what stops the document being copied
    to another host and used to borrow our identity — an AS compares
    `client_id` against the URL it actually fetched."""

    resp = _client().get(CIMD_PATH)
    assert resp.status_code == 200
    assert resp.json()["client_id"] == CLIENT_ID
    assert client_id_url(BASE) == CLIENT_ID


def test_document_publishes_exactly_the_gateway_callback() -> None:
    """The redirect URI list is the security boundary of the whole
    scheme: an AS refuses to redirect anywhere not listed. One entry,
    ours, derived from configuration — never from a request."""

    body = _client().get(CIMD_PATH).json()
    assert body["redirect_uris"] == [
        f"{BASE}/api/v1/oauth-authcode/callback"
    ]
    assert not any("*" in uri for uri in body["redirect_uris"])


def test_document_declares_no_client_secret() -> None:
    """Control of the URL is the proof under CIMD. Saying so explicitly
    stops an AS issuing a secret it then expects us to hold."""

    assert _client().get(CIMD_PATH).json()["token_endpoint_auth_method"] == "none"


def test_document_is_public_and_carries_nothing_tenant_specific() -> None:
    """It must be fetchable by an AS with no credential of ours, so it
    must contain only what a DCR registration would have sent anyway.
    This test exists to fail loudly if someone adds a field that is not
    already public."""

    resp = _client().get(CIMD_PATH)
    assert resp.status_code == 200  # no auth header supplied
    assert set(resp.json()) == {
        "client_id",
        "client_name",
        "client_uri",
        "redirect_uris",
        "grant_types",
        "response_types",
        "token_endpoint_auth_method",
        "application_type",
    }


def test_document_is_cacheable_but_not_forever() -> None:
    """An AS may cache it; adding a redirect URI should still take effect
    the same day."""

    cache = _client().get(CIMD_PATH).headers["cache-control"]
    assert "public" in cache
    assert "max-age=3600" in cache


def test_document_is_not_behind_the_api_version_prefix() -> None:
    """The URL *is* the client_id. Anything a version bump could move is
    the wrong place for it."""

    client = _client()
    assert client.get(CIMD_PATH).status_code == 200
    assert client.get(f"/api/v1{CIMD_PATH}").status_code == 404


def test_metadata_builder_is_pure() -> None:
    doc = build_client_metadata(
        public_base_url="https://x.test/", app_name="N", redirect_uris=["https://x.test/cb"]
    )
    assert doc["client_id"] == f"https://x.test{CIMD_PATH}"
    assert doc["client_uri"] == "https://x.test"


# --- The per-AS decision ----------------------------------------------------


def test_cimd_is_used_when_the_as_advertises_it() -> None:
    plan = plan_from_as_metadata(_as_metadata(), client_id=CLIENT_ID)
    assert plan.use_cimd is True
    assert plan.client_id == CLIENT_ID
    assert plan.authorization_endpoint == "https://as.example.com/authorize"
    assert plan.token_endpoint == "https://as.example.com/token"


def test_falls_back_to_dcr_when_unadvertised() -> None:
    for metadata in (
        _as_metadata(**{CIMD_SUPPORT_KEY: False}),
        {k: v for k, v in _as_metadata().items() if k != CIMD_SUPPORT_KEY},
    ):
        plan = plan_from_as_metadata(metadata, client_id=CLIENT_ID)
        assert plan.use_cimd is False
        assert CIMD_SUPPORT_KEY in plan.reason


@pytest.mark.parametrize("missing", ["authorization_endpoint", "token_endpoint"])
def test_as_claiming_cimd_with_incomplete_metadata_falls_back(missing: str) -> None:
    """Malformed metadata is not a reason to guess at endpoints — and the
    DCR path is the one with the error reporting an operator needs."""

    metadata = {k: v for k, v in _as_metadata().items() if k != missing}
    plan = plan_from_as_metadata(metadata, client_id=CLIENT_ID)
    assert plan.use_cimd is False
    assert "missing" in plan.reason


@pytest.mark.parametrize(
    "client_id",
    ["http://gw.example.com/.well-known/oauth-client", "gw.example.com", ""],
)
def test_non_https_client_id_refuses_cimd(client_id: str) -> None:
    """CIMD's trust model is "whoever controls this URL is the client".
    Over http, that is whoever controls the network."""

    plan = plan_from_as_metadata(_as_metadata(), client_id=client_id)
    assert plan.use_cimd is False
    assert "https" in plan.reason


def test_the_reason_is_always_populated() -> None:
    """"Why did this upstream use CIMD and that one use DCR?" is asked
    during a connect failure, and the answer lives in the AS's metadata
    where the operator cannot see it."""

    for metadata in (_as_metadata(), _as_metadata(**{CIMD_SUPPORT_KEY: False})):
        assert plan_from_as_metadata(metadata, client_id=CLIENT_ID).reason
