"""HTTP-level tests for `GET /api/v1/admin/diagnostic-bundle`.

Covers the gateway-wide troubleshooting bundle:
- Happy path: all sections present + correct shape.
- **Secret-redaction guarantee** — no secret VALUES leak from Settings,
  database_url password, or any field-name-pattern match.
- since_minutes / audit_limit validation.
- Operator-auth required.
- Filename header includes environment slug.

The fakes mirror `tests/api/test_capability_sync_and_vservers.py`'s
shape so the same `_build_app` / auth helpers work without
needing a real Postgres.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.api.diagnostic_bundle import _BUNDLE_VERSION
from vyuu_gateway.config import Settings
from vyuu_gateway.db.models import (
    McpServer,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
    VirtualServer,
    VirtualServerVisibility,
)
from vyuu_gateway.main import create_app
from vyuu_gateway.operator_auth.fake import mint_operator_test_token

TEST_SIGNING_SECRET = "diag-bundle-test-secret"

_SECRET_CANARY = "DO-NOT-LEAK-ME-9999-SECRET-CANARY"


# --- Fakes -----------------------------------------------------------------


class _Result:
    """Stands in for a SQLAlchemy `Result`, covering the read surface the
    bundle actually uses: `.first()`, `.all()`, `.scalars()`, `.scalar()`."""

    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows

    def __iter__(self) -> Iterator[Any]:
        return iter(self._rows)

    def scalars(self) -> list[Any]:
        return list(self._rows)

    def first(self) -> Any:
        return self._rows[0] if self._rows else None

    def scalar(self) -> Any:
        """First column of the first row, `None` when there are no rows —
        matching `Result.scalar()`. The bundle's `count(*)` queries lean on
        the `None` (they spell it `.scalar() or 0`), so an unscripted table
        must read as empty rather than raise."""
        if not self._rows:
            return None
        row = self._rows[0]
        if isinstance(row, tuple | list):
            return row[0] if row else None
        return row


class _FakeDb:
    """Minimal DB fake that dispatches on the statement's target table.

    Deliberately NOT a positional script. The endpoint issues a growing
    number of queries and reorders them whenever a section is added, and a
    positional fake answers by *arrival order* — so a new section querying
    ahead of `servers` silently hands the servers section someone else's
    rows, and the assertions keep passing against the wrong data. Matching
    on the compiled SQL means a query we haven't scripted gets an empty
    result instead of another section's.

    Only the tables these tests assert on are scripted; `idp_directories`,
    `tool_call_events` and `admin_audit_log` intentionally read as empty
    (those sections have their own tests against a real Postgres).
    """

    def __init__(
        self,
        *,
        servers: list[McpServer],
        vservers: list[VirtualServer],
        pg_version: str = "16.2",
        pg_active_count: int = 3,
    ) -> None:
        self._servers = servers
        self._vservers = vservers
        self._pg_version = pg_version
        self._pg_active_count = pg_active_count

    def execute(self, statement: Any) -> _Result:
        sql = str(statement).lower()
        if "show server_version" in sql:
            return _Result([(self._pg_version,)])
        if "pg_stat_activity" in sql:
            return _Result([(self._pg_active_count,)])
        if "from mcp_servers" in sql:
            return _Result(list(self._servers))
        if "from virtual_servers" in sql:
            return _Result(list(self._vservers))
        return _Result([])

    def scalar(self, statement: Any) -> Any:
        return self.execute(statement).scalar()


def _auth(tenant_id: UUID) -> dict[str, str]:
    operator_id = uuid4()
    token = mint_operator_test_token(
        tenant_id=tenant_id,
        operator_id=operator_id,
        signing_secret=TEST_SIGNING_SECRET,
    )
    return {"Authorization": f"Bearer {token}"}


def _make_server(*, tenant_id: UUID,
                 health: McpServerHealthStatus = McpServerHealthStatus.HEALTHY,
                 health_error: str | None = None) -> McpServer:
    return McpServer(
        id=uuid4(),
        tenant_id=tenant_id,
        display_name=f"server-{uuid4().hex[:8]}",
        source_type=McpServerSourceType.HTTP,
        source_location="https://upstream.example/mcp",
        transport=McpTransport.STREAMABLE_HTTP,
        args=[],
        registered_by=uuid4(),
        registered_at=datetime.now(UTC),
        health_status=health,
        last_health_error=health_error,
        last_health_checked_at=datetime.now(UTC),
        last_capabilities_pulled_at=datetime.now(UTC),
        auth_headers={},
        auth_env={},
        auth_oauth=None,
        auth_authcode=None,
        auth_passthrough=None,
        mtls_cert_ref=None,
        mtls_key_ref=None,
    )


def _make_vserver(*, tenant_id: UUID,
                   visibility: VirtualServerVisibility =
                       VirtualServerVisibility.PUBLIC) -> VirtualServer:
    return VirtualServer(
        id=uuid4(),
        tenant_id=tenant_id,
        name=f"vs-{uuid4().hex[:8]}",
        visibility=visibility,
        rename_map={},
        created_by=uuid4(),
        created_at=datetime.now(UTC),
    )


def _build_app(db: _FakeDb,
               *,
               canary_in_signing_secret: bool = False) -> TestClient:
    """Build app with a Settings whose secret-shaped fields contain
    the canary, so we can verify redaction works."""
    signing = (
        _SECRET_CANARY if canary_in_signing_secret else TEST_SIGNING_SECRET
    )
    # Use a database_url with a password to test URL-redaction.
    db_url = f"postgresql+psycopg://test:{_SECRET_CANARY}@localhost:5432/x"
    app = create_app(
        Settings(
            app_name="Vyuu Gateway (diagnostic test)",
            environment="test",
            log_level="CRITICAL",
            version="diag-test",
            operator_auth_signing_secret=signing,
            portal_session_signing_secret=_SECRET_CANARY,
            database_url=db_url,
        ),
    )

    def override_db() -> Iterator[_FakeDb]:
        yield db

    app.dependency_overrides[get_tenant_scoped_db] = override_db
    return TestClient(app)


# --- Tests -----------------------------------------------------------------


def test_diagnostic_bundle_happy_path_has_all_sections() -> None:
    tenant_id = uuid4()
    servers = [
        _make_server(tenant_id=tenant_id, health=McpServerHealthStatus.HEALTHY),
        _make_server(tenant_id=tenant_id, health=McpServerHealthStatus.DOWN,
                     health_error="connection refused"),
        _make_server(tenant_id=tenant_id, health=McpServerHealthStatus.UNKNOWN),
    ]
    vservers = [
        _make_vserver(tenant_id=tenant_id,
                       visibility=VirtualServerVisibility.PUBLIC),
        _make_vserver(tenant_id=tenant_id,
                       visibility=VirtualServerVisibility.PRIVATE),
    ]
    db = _FakeDb(servers=servers, vservers=vservers)
    client = _build_app(db)

    resp = client.get(
        "/api/v1/admin/diagnostic-bundle",
        headers=_auth(tenant_id),
    )
    assert resp.status_code == 200, resp.text
    bundle = resp.json()

    # Top-level shape.
    # Every section the endpoint advertises. Kept exhaustive on purpose:
    # a section that silently stops being emitted is a support-visible
    # regression, and this is the only test that would catch it.
    for key in (
        "vyuu_diagnostic_bundle_version", "generated_at", "tenant_id",
        "operator_id", "since_minutes", "audit_limit",
        "gateway", "settings_snapshot", "connectivity",
        "servers", "vservers", "idp_directories",
        "circuit_breakers", "inflight_gate", "background_workers",
        "stdio_subprocesses", "audit_buffer", "audit_buffer_warmup",
        "persistent_audit", "admin_audit",
    ):
        assert key in bundle, f"missing top-level key: {key}"
    # Against the constant, not a literal: the version is bumped every time
    # a section is added, and a hand-maintained literal here just breaks the
    # suite on an otherwise-correct change. What matters is that the field is
    # emitted and matches what the endpoint declares.
    assert bundle["vyuu_diagnostic_bundle_version"] == _BUNDLE_VERSION
    assert bundle["tenant_id"] == str(tenant_id)

    # Gateway section: process metadata + version.
    g = bundle["gateway"]
    assert g["version"] == "diag-test"
    assert g["environment"] == "test"
    assert g["process"]["pid"] > 0
    assert g["process"]["uptime_seconds"] >= 0

    # Connectivity: postgres reachable per the fake's scripted result.
    assert bundle["connectivity"]["postgres"]["reachable"] is True
    assert bundle["connectivity"]["postgres"]["version"] == "16.2"
    assert bundle["connectivity"]["postgres"]["active_connections"] == 3

    # Servers section: total + by_health distribution.
    s = bundle["servers"]
    assert s["total"] == 3
    assert s["by_health"].get("healthy") == 1
    assert s["by_health"].get("down") == 1
    assert s["by_health"].get("unknown") == 1
    # The DOWN server's error should surface.
    assert any("connection refused" in e["error"]
               for e in s["with_health_errors"])

    # Vservers section: total + visibility distribution.
    v = bundle["vservers"]
    assert v["total"] == 2
    assert v["by_visibility"].get("public") == 1
    assert v["by_visibility"].get("private") == 1


def test_diagnostic_bundle_redacts_signing_secret() -> None:
    """The canary planted in `operator_auth_signing_secret` MUST NOT
    appear anywhere in the response body. The settings-snapshot
    section should show `[REDACTED]` for that field."""
    tenant_id = uuid4()
    operator_id = uuid4()
    db = _FakeDb(servers=[], vservers=[])
    client = _build_app(db, canary_in_signing_secret=True)

    # Mint the auth token with the SAME signing secret the app was
    # built with — otherwise auth would 401 before the redaction
    # path ever runs.
    token = mint_operator_test_token(
        tenant_id=tenant_id,
        operator_id=operator_id,
        signing_secret=_SECRET_CANARY,
    )
    resp = client.get(
        "/api/v1/admin/diagnostic-bundle",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.text
    assert _SECRET_CANARY not in body, (
        "BUG: diagnostic bundle leaked a secret value via "
        "settings_snapshot. Field-name redaction patterns failed."
    )
    bundle = resp.json()
    snap = bundle["settings_snapshot"]
    assert snap["operator_auth_signing_secret"] == "[REDACTED]"
    assert snap["portal_session_signing_secret"] == "[REDACTED]"


def test_diagnostic_bundle_redacts_database_url_password() -> None:
    """`database_url` is `postgresql://user:password@host/db` — the
    password segment must be replaced with `***`. Visible parts
    (user, host, port, db) are intentionally preserved so support
    can confirm the customer is pointed at the right DB."""
    tenant_id = uuid4()
    db = _FakeDb(servers=[], vservers=[])
    client = _build_app(db)  # canary is in the URL by default

    resp = client.get(
        "/api/v1/admin/diagnostic-bundle",
        headers=_auth(tenant_id),
    )
    assert resp.status_code == 200
    bundle = resp.json()
    db_url = bundle["settings_snapshot"]["database_url"]
    assert _SECRET_CANARY not in db_url
    assert "***" in db_url
    # Visible parts retained — user, host, port, db.
    assert "test:***@localhost:5432/x" in db_url


def test_diagnostic_bundle_filename_includes_environment_slug() -> None:
    tenant_id = uuid4()
    db = _FakeDb(servers=[], vservers=[])
    client = _build_app(db)

    resp = client.get(
        "/api/v1/admin/diagnostic-bundle",
        headers=_auth(tenant_id),
    )
    assert resp.status_code == 200
    cd = resp.headers["content-disposition"]
    assert cd.startswith("attachment;")
    assert "vyuu-diagnostic-test" in cd
    assert ".json" in cd


def test_diagnostic_bundle_rejects_out_of_range_since_minutes() -> None:
    tenant_id = uuid4()
    db = _FakeDb(servers=[], vservers=[])
    client = _build_app(db)

    resp = client.get(
        "/api/v1/admin/diagnostic-bundle?since_minutes=0",
        headers=_auth(tenant_id),
    )
    assert resp.status_code == 400

    resp = client.get(
        "/api/v1/admin/diagnostic-bundle?since_minutes=2000",
        headers=_auth(tenant_id),
    )
    assert resp.status_code == 400


def test_diagnostic_bundle_rejects_out_of_range_audit_limit() -> None:
    tenant_id = uuid4()
    db = _FakeDb(servers=[], vservers=[])
    client = _build_app(db)

    resp = client.get(
        "/api/v1/admin/diagnostic-bundle?audit_limit=0",
        headers=_auth(tenant_id),
    )
    assert resp.status_code == 400

    resp = client.get(
        "/api/v1/admin/diagnostic-bundle?audit_limit=99999",
        headers=_auth(tenant_id),
    )
    assert resp.status_code == 400


def test_diagnostic_bundle_requires_operator_auth() -> None:
    db = _FakeDb(servers=[], vservers=[])
    client = _build_app(db)

    # No Authorization header.
    resp = client.get("/api/v1/admin/diagnostic-bundle")
    assert resp.status_code in (401, 403)


def test_diagnostic_bundle_response_is_valid_json() -> None:
    tenant_id = uuid4()
    db = _FakeDb(servers=[], vservers=[])
    client = _build_app(db)

    resp = client.get(
        "/api/v1/admin/diagnostic-bundle",
        headers=_auth(tenant_id),
    )
    assert resp.status_code == 200
    parsed = json.loads(resp.content)
    assert parsed["vyuu_diagnostic_bundle_version"] == _BUNDLE_VERSION


def test_diagnostic_bundle_circuit_breaker_section_is_available() -> None:
    """The circuit-breaker registry is wired by `create_app`; the
    section should report `available=True` even when no breakers
    have been triggered yet."""
    tenant_id = uuid4()
    db = _FakeDb(servers=[], vservers=[])
    client = _build_app(db)

    resp = client.get(
        "/api/v1/admin/diagnostic-bundle",
        headers=_auth(tenant_id),
    )
    assert resp.status_code == 200
    cb = resp.json()["circuit_breakers"]
    assert cb["available"] is True
    assert "total_keys" in cb
    assert "by_state" in cb


def test_diagnostic_bundle_inflight_gate_section_reports_caps() -> None:
    """The inflight-gate section reports configured caps so support
    can see if a tenant is being shed because the cap is too tight."""
    tenant_id = uuid4()
    db = _FakeDb(servers=[], vservers=[])
    client = _build_app(db)

    resp = client.get(
        "/api/v1/admin/diagnostic-bundle",
        headers=_auth(tenant_id),
    )
    assert resp.status_code == 200
    g = resp.json()["inflight_gate"]
    assert "configured_per_tenant_cap" in g
    assert "configured_uvicorn_concurrency" in g
    assert "configured_backlog" in g
