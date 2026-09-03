"""MCP-2 P3 · the call site that chooses CIMD over DCR.

`tests/upstream/test_oauth_dcr.py` covers the decision itself against a
stub authorization server. This covers the wiring around it: which
`cimd_client_id` the resolver hands to discovery, and — the part with
teeth — what happens after an AS has advertised CIMD and then refused
our document.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import pytest

from vyuu_gateway.api import oauth_authcode
from vyuu_gateway.api.oauth_authcode import (
    _cimd_client_id_for,
    _resolve_client_id_and_auth_url,
)
from vyuu_gateway.db.models import McpServerDcrClient

OUR_CIMD = "https://gateway.example/.well-known/oauth-client"


@dataclass
class _Settings:
    public_base_url: str = "https://gateway.example"


class _Server:
    def __init__(self) -> None:
        self.id = uuid4()
        self.source_location = "https://upstream.example/mcp"


class _FakeDb:
    """Just enough Session for the resolver: one row, by model."""

    def __init__(self, row: Any = None) -> None:
        self.row = row
        self.added: list[Any] = []
        self.deleted: list[Any] = []
        self.commits = 0

    def get(self, model: Any, _key: Any) -> Any:
        return self.row if model is McpServerDcrClient else None

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    def delete(self, obj: Any) -> None:
        self.deleted.append(obj)
        self.row = None

    def flush(self) -> None:
        pass

    def commit(self) -> None:
        self.commits += 1


def _row(mechanism: str) -> McpServerDcrClient:
    return McpServerDcrClient(
        server_id=uuid4(),
        tenant_id=uuid4(),
        client_id="existing-client-id",
        client_secret=None,
        authorization_endpoint="https://as.example/authorize",
        token_endpoint="https://as.example/token",
        registration_endpoint=None,
        registration_response={},
        auth_mechanism=mechanism,
    )


@dataclass
class _Result:
    client_id: str = "issued-id"
    client_secret: str | None = None
    authorization_endpoint: str = "https://as.example/authorize"
    token_endpoint: str = "https://as.example/token"
    registration_endpoint: str | None = None
    registration_response: dict[str, Any] | None = None
    auth_mechanism: str = "dcr"
    mechanism_reason: str = ""


def _resolve(
    monkeypatch: pytest.MonkeyPatch,
    *,
    db: _FakeDb,
    settings: Any,
) -> tuple[Any, dict[str, Any]]:
    """Run the resolver, capturing what discovery was asked for."""

    seen: dict[str, Any] = {}

    async def _fake_discover(**kwargs: Any) -> _Result:
        seen.update(kwargs)
        return _Result(registration_response={})

    monkeypatch.setattr(oauth_authcode, "discover_and_register", _fake_discover)

    async def go() -> Any:
        return await _resolve_client_id_and_auth_url(
            server=_Server(),
            spec={"dcr_enabled": True, "redirect_uri": "https://gateway.example/cb"},
            tenant_id=uuid4(),
            secret_store=None,
            db=db,
            settings=settings,
        )

    return asyncio.run(go()), seen


# --- which client_id is offered -------------------------------------------


def test_an_https_deployment_offers_its_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = _FakeDb()
    _result, seen = _resolve(monkeypatch, db=db, settings=_Settings())
    assert seen["cimd_client_id"] == OUR_CIMD


def test_an_http_deployment_offers_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dev gateway on http keeps the DCR path it already works with,
    rather than presenting a client_id every AS will reject."""

    db = _FakeDb()
    _result, seen = _resolve(
        monkeypatch, db=db, settings=_Settings(public_base_url="http://localhost:8000")
    )
    assert seen["cimd_client_id"] is None


def test_client_id_helper_requires_https() -> None:
    assert _cimd_client_id_for(_Settings()) == OUR_CIMD
    assert _cimd_client_id_for(_Settings(public_base_url="http://x")) is None
    assert _cimd_client_id_for(_Settings(public_base_url="")) is None


# --- the anti-loop property ------------------------------------------------


def test_a_rejected_cimd_row_forces_the_dcr_branch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The failure this guards against is built from two individually
    correct behaviours: `invalid_client` drops the row, and a fresh probe
    reads the AS's (unchanged) CIMD advertisement. Together they present
    the same refused URL forever. The tombstone is what breaks the cycle,
    so discovery must be asked for DCR explicitly."""

    db = _FakeDb(_row("cimd_rejected"))
    _result, seen = _resolve(monkeypatch, db=db, settings=_Settings())
    assert seen["cimd_client_id"] is None
    # The tombstone is cleared so the DCR result can take its place.
    assert len(db.deleted) == 1
    assert len(db.added) == 1


def test_a_working_cimd_row_is_reused_without_probing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negative control for the test above: an ordinary CIMD row must
    NOT be deleted, or every Connect would re-run discovery."""

    db = _FakeDb(_row("cimd"))
    (client_id, authorize_url), seen = _resolve(
        monkeypatch, db=db, settings=_Settings()
    )
    assert client_id == "existing-client-id"
    assert authorize_url == "https://as.example/authorize"
    assert seen == {}  # discovery never ran
    assert db.deleted == []


def test_the_mechanism_is_persisted_on_the_new_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Set explicitly at construction, because a column `default=` fires
    at INSERT — a hand-built instance reads None until then, and the
    tombstone branch would misread a CIMD row as DCR."""

    seen: dict[str, Any] = {}

    async def _fake_discover(**kwargs: Any) -> _Result:
        seen.update(kwargs)
        return _Result(
            client_id=OUR_CIMD,
            auth_mechanism="cimd",
            registration_response={},
            mechanism_reason="authorization server advertises CIMD support",
        )

    monkeypatch.setattr(oauth_authcode, "discover_and_register", _fake_discover)
    db = _FakeDb()

    async def go() -> Any:
        return await _resolve_client_id_and_auth_url(
            server=_Server(),
            spec={"dcr_enabled": True, "redirect_uri": "https://gateway.example/cb"},
            tenant_id=uuid4(),
            secret_store=None,
            db=db,
            settings=_Settings(),
        )

    client_id, _authorize_url = asyncio.run(go())
    assert client_id == OUR_CIMD
    assert db.added[0].auth_mechanism == "cimd"


def test_a_missing_settings_object_disables_cimd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The parameter defaults to None so no existing caller changes
    behaviour by omission — it just does not offer a document."""

    db = _FakeDb()
    _result, seen = _resolve(monkeypatch, db=db, settings=None)
    assert seen["cimd_client_id"] is None
