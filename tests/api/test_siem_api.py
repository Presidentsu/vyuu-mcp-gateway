"""SIEM-1 · the tenant-scoped SIEM export API.

Two layers, like the tenant-settings tests:

1. Validation + audit contract against a scripted fake session (no
   Postgres): the shapes the console relies on, the refusals that keep
   a live token out of the tenants table, the admin-audit rows.
2. A real-DB round trip (gated on `VYUU_TEST_DATABASE_URL`) for the
   upsert / read / clear cycle under RLS.
"""

from __future__ import annotations

import os

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ.setdefault("VYUU_DATABASE_URL", _DATABASE_URL)

import asyncio  # noqa: E402
from collections.abc import Iterator  # noqa: E402
from datetime import UTC, datetime  # noqa: E402
from typing import Any  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from vyuu_gateway.api.dependencies import get_tenant_scoped_db  # noqa: E402
from vyuu_gateway.config import Settings  # noqa: E402
from vyuu_gateway.db.models import AdminAuditLog, TenantSiemTarget  # noqa: E402
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.operator_auth.fake import mint_operator_test_token  # noqa: E402
from vyuu_gateway.secrets.store import InMemorySecretStore  # noqa: E402

TEST_SIGNING_SECRET = "siem-test-signing-secret"


def _auth_context() -> tuple[UUID, UUID, dict[str, str]]:
    tenant_id, operator_id = uuid4(), uuid4()
    token = mint_operator_test_token(
        tenant_id=tenant_id, operator_id=operator_id, signing_secret=TEST_SIGNING_SECRET
    )
    return tenant_id, operator_id, {"Authorization": f"Bearer {token}"}


class FakeDbSession:
    """Scripted `scalar()` results; records what the endpoint did.
    Deliberately has no `info` attribute, like the registry fakes."""

    def __init__(self, *, scalar_results: list[Any] | None = None) -> None:
        self._scalar_queue = list(scalar_results or [])
        self.added: list[Any] = []
        self.deleted: list[Any] = []
        self.committed = False

    def scalar(self, statement: object) -> Any:
        return self._scalar_queue.pop(0) if self._scalar_queue else None

    def add(self, instance: Any) -> None:
        self.added.append(instance)

    def delete(self, instance: Any) -> None:
        self.deleted.append(instance)

    def commit(self) -> None:
        self.committed = True

    def refresh(self, instance: Any) -> None:
        return None


class _FakeExporter:
    def __init__(self, *, deployment: bool = False) -> None:
        self.invalidated: list[UUID | None] = []
        self._deployment = deployment
        self.test_result: tuple[bool, str] = (True, "delivered one heartbeat event to https://s")

    def invalidate(self, tenant_id: UUID | None) -> None:
        self.invalidated.append(tenant_id)

    def deployment_target_configured(self) -> bool:
        return self._deployment

    def stats_for(self, tenant_id: UUID | None) -> Any:
        return None

    async def send_test(self, tenant_id: UUID | None) -> tuple[bool, str]:
        return self.test_result


def _build(
    db: FakeDbSession, *, exporter: _FakeExporter | None = None, store: Any = None
) -> tuple[TestClient, Any]:
    app = create_app(
        Settings(
            app_name="siem-test", environment="test", log_level="CRITICAL",
            version="t", operator_auth_signing_secret=TEST_SIGNING_SECRET,
        ),
        secret_store=store or InMemorySecretStore(),
    )

    def override_db() -> Iterator[FakeDbSession]:
        yield db

    app.dependency_overrides[get_tenant_scoped_db] = override_db
    if exporter is not None:
        app.state.siem_exporter = exporter
    return TestClient(app), app


def _row(tenant_id: UUID, **overrides: Any) -> TenantSiemTarget:
    kwargs: dict[str, Any] = {
        "id": uuid4(), "tenant_id": tenant_id, "enabled": True,
        "hec_url": "https://splunk.corp:8088", "hec_token_ref": "splunk-hec",
        "index": "sec", "source": "vyuu-mcp-gateway", "host_override": None,
        "verify_tls": True, "categories": ["tool_call", "auth"],
        "include_raw_payloads": False, "min_log_level": "WARNING",
        "batch_max_events": 100, "flush_interval_seconds": 2.0,
        "created_at": datetime.now(UTC), "updated_at": datetime.now(UTC),
    }
    kwargs.update(overrides)
    return TenantSiemTarget(**kwargs)


def _valid_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "hec_url": "https://splunk.corp:8088/services/collector/event",
        "hec_token_ref": "splunk-hec",
        "index": "sec",
        "categories": ["tool_call", "access_attempt", "admin_action"],
    }
    body.update(overrides)
    return body


# --- 1. contract, no database ------------------------------------------------


def test_unconfigured_tenant_reads_defaults_and_options() -> None:
    _, _, headers = _auth_context()
    client, _ = _build(
        FakeDbSession(scalar_results=[None]), exporter=_FakeExporter(deployment=True)
    )
    response = client.get("/api/v1/admin/siem/config", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is False and body["enabled"] is False
    assert body["token_present"] is False
    assert body["secret_backend"] == "InMemorySecretStore" and body["secret_writable"] is True
    assert body["deployment_target_configured"] is True
    ids = [o["id"] for o in body["options"]]
    assert ids == [
        "tool_call", "access_attempt", "admin_action", "auth", "tool_auth", "gateway_log",
    ]
    assert [o["default"] for o in body["options"]][-1] is False  # logs are opt-in
    assert body["log_levels"] == ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def test_put_creates_the_target_normalises_the_url_and_audits() -> None:
    tenant_id, _, headers = _auth_context()
    db = FakeDbSession(scalar_results=[None])
    exporter = _FakeExporter()
    client, _ = _build(db, exporter=exporter)

    response = client.put("/api/v1/admin/siem/config", headers=headers, json=_valid_body())

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["configured"] is True and body["enabled"] is True
    # The pasted collector path is gone; the origin is what is stored.
    assert body["hec_url"] == "https://splunk.corp:8088"
    assert body["categories"] == ["access_attempt", "admin_action", "tool_call"]
    assert body["token_present"] is False  # a ref, no token yet

    rows = [a for a in db.added if isinstance(a, TenantSiemTarget)]
    assert len(rows) == 1 and rows[0].tenant_id == tenant_id
    audits = [a for a in db.added if isinstance(a, AdminAuditLog)]
    assert [a.action for a in audits] == ["siem.config_set"]
    assert audits[0].detail["before"] is None
    assert audits[0].detail["after"]["hec_url"] == "https://splunk.corp:8088"
    assert db.committed
    assert exporter.invalidated == [tenant_id]


@pytest.mark.parametrize(
    ("field", "value", "fragment"),
    [
        ("hec_url", "http://splunk.corp:8088", "https"),
        ("hec_url", "https://splunk.corp:8088?token=x", "query"),
        ("hec_url", "http://169.254.169.254", "link-local"),
        ("hec_token_ref", "0b8d3c1e-6f2a-4b1e-9c3d-1a2b3c4d5e6f", "looks like a HEC token"),
        ("hec_token_ref", "Splunk abc123", "Authorization header"),
        ("categories", ["tool_call", "bogus"], "unknown categories"),
        ("min_log_level", "LOUD", "min_log_level"),
        ("batch_max_events", 0, "greater than or equal"),
    ],
)
def test_put_refuses_bad_input_with_a_reason(field: str, value: Any, fragment: str) -> None:
    _, _, headers = _auth_context()
    client, _ = _build(FakeDbSession(scalar_results=[None]))
    response = client.put(
        "/api/v1/admin/siem/config", headers=headers, json=_valid_body(**{field: value})
    )
    assert response.status_code == 422
    assert fragment.lower() in response.text.lower()


def test_put_replaces_an_existing_target_and_records_before_after() -> None:
    tenant_id, _, headers = _auth_context()
    existing = _row(tenant_id, enabled=True, index="old")
    db = FakeDbSession(scalar_results=[existing])
    client, _ = _build(db)

    response = client.put(
        "/api/v1/admin/siem/config", headers=headers,
        json=_valid_body(enabled=False, index="new"),
    )
    assert response.status_code == 200, response.text
    assert response.json()["enabled"] is False and response.json()["index"] == "new"
    assert not [a for a in db.added if isinstance(a, TenantSiemTarget)]  # updated in place
    audit = next(a for a in db.added if isinstance(a, AdminAuditLog))
    assert audit.detail["before"]["index"] == "old" and audit.detail["after"]["index"] == "new"


def test_token_is_written_to_the_secret_store_never_the_row() -> None:
    tenant_id, _, headers = _auth_context()
    row = _row(tenant_id)
    db = FakeDbSession(scalar_results=[row, row])
    client, app = _build(db, exporter=_FakeExporter())

    response = client.post(
        "/api/v1/admin/siem/token", headers=headers, json={"hec_token": "abcd-1234-efgh-5678"}
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "stored": True, "ref": "splunk-hec", "backend": "InMemorySecretStore",
    }
    store = app.state.secret_store
    assert asyncio.run(store.get_secret(tenant_id, "splunk-hec")) == "abcd-1234-efgh-5678"
    audit = next(a for a in db.added if isinstance(a, AdminAuditLog))
    assert audit.action == "siem.token_stored"
    assert "abcd-1234" not in str(audit.detail)
    assert row.hec_token_ref == "splunk-hec"


def test_token_needs_a_target_first() -> None:
    _, _, headers = _auth_context()
    client, _ = _build(FakeDbSession(scalar_results=[None]))
    response = client.post(
        "/api/v1/admin/siem/token", headers=headers, json={"hec_token": "abcdefgh"}
    )
    assert response.status_code == 400
    assert "reference first" in response.json()["detail"]


def test_token_write_is_refused_on_a_read_only_backend() -> None:
    tenant_id, _, headers = _auth_context()

    class _ReadOnlyStore:
        async def get_secret(self, tenant_id: UUID, ref: str) -> str:
            raise LookupError(ref)

    client, _ = _build(FakeDbSession(scalar_results=[_row(tenant_id)]), store=_ReadOnlyStore())
    response = client.post(
        "/api/v1/admin/siem/token", headers=headers, json={"hec_token": "abcdefgh"}
    )
    assert response.status_code == 400
    assert "read-only" in response.json()["detail"]
    assert "splunk-hec" in response.json()["detail"]


def test_delete_clears_and_audits() -> None:
    tenant_id, _, headers = _auth_context()
    row = _row(tenant_id)
    db = FakeDbSession(scalar_results=[row])
    exporter = _FakeExporter()
    client, _ = _build(db, exporter=exporter)

    response = client.delete("/api/v1/admin/siem/config", headers=headers)
    assert response.status_code == 204
    assert db.deleted == [row]
    audit = next(a for a in db.added if isinstance(a, AdminAuditLog))
    assert audit.action == "siem.config_cleared"
    assert exporter.invalidated == [tenant_id]


def test_test_endpoint_relays_the_exporters_answer() -> None:
    _, _, headers = _auth_context()
    exporter = _FakeExporter()
    exporter.test_result = (False, "HTTP 403: Invalid token (code 4)")
    client, _ = _build(FakeDbSession(), exporter=exporter)
    response = client.post("/api/v1/admin/siem/test", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"ok": False, "detail": "HTTP 403: Invalid token (code 4)"}


def test_status_reports_configuration_and_exporter_presence() -> None:
    tenant_id, _, headers = _auth_context()
    client, _ = _build(
        FakeDbSession(scalar_results=[_row(tenant_id)]), exporter=_FakeExporter()
    )
    response = client.get("/api/v1/admin/siem/status", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is True and body["enabled"] is True
    assert body["exporter_installed"] is True and body["stats"] is None


def test_endpoints_require_an_operator() -> None:
    client, _ = _build(FakeDbSession())
    assert client.get("/api/v1/admin/siem/config").status_code in (401, 403)
    assert client.put("/api/v1/admin/siem/config", json=_valid_body()).status_code in (401, 403)
    assert client.post("/api/v1/admin/siem/test").status_code in (401, 403)


# --- 2. real database round trip ----------------------------------------------


@pytest.mark.skipif(_DATABASE_URL is None, reason="VYUU_TEST_DATABASE_URL not set")
def test_round_trip_under_rls() -> None:
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from vyuu_gateway.db.models import Operator, OperatorRole, Tenant, TenantTier

    assert _DATABASE_URL is not None
    factory = sessionmaker(
        create_engine(_DATABASE_URL, future=True), autoflush=False, future=True
    )
    tenant_id, operator_id = uuid4(), uuid4()
    other_tenant, other_operator = uuid4(), uuid4()
    with factory() as s:
        for tid, oid in ((tenant_id, operator_id), (other_tenant, other_operator)):
            s.add(Tenant(id=tid, name=f"t-{tid.hex[:6]}", tier=TenantTier.SHARED))
            s.add(Operator(id=oid, tenant_id=tid, email=f"op-{oid.hex[:6]}@test",
                           role=OperatorRole.ADMIN))
        s.commit()
    app = create_app(Settings(
        app_name="siem-db-test", environment="test", log_level="CRITICAL", version="t",
        operator_auth_signing_secret=TEST_SIGNING_SECRET,
    ), secret_store=InMemorySecretStore())

    def headers(tid: UUID, oid: UUID) -> dict[str, str]:
        token = mint_operator_test_token(
            tenant_id=tid, operator_id=oid, signing_secret=TEST_SIGNING_SECRET
        )
        return {"Authorization": f"Bearer {token}"}

    try:
        with TestClient(app) as client:
            mine = headers(tenant_id, operator_id)
            created = client.put("/api/v1/admin/siem/config", headers=mine, json=_valid_body())
            assert created.status_code == 200, created.text
            read = client.get("/api/v1/admin/siem/config", headers=mine).json()
            assert read["configured"] and read["hec_url"] == "https://splunk.corp:8088"

            stored = client.post(
                "/api/v1/admin/siem/token", headers=mine, json={"hec_token": "hec-token-value"}
            )
            assert stored.status_code == 200
            assert client.get("/api/v1/admin/siem/config", headers=mine).json()["token_present"]

            # Another tenant sees nothing of it.
            theirs = headers(other_tenant, other_operator)
            theirs_view = client.get("/api/v1/admin/siem/config", headers=theirs).json()
            assert theirs_view["configured"] is False

            assert client.delete("/api/v1/admin/siem/config", headers=mine).status_code == 204
            after = client.get("/api/v1/admin/siem/config", headers=mine).json()
            assert after["configured"] is False
    finally:
        with factory() as s:
            for tid in (tenant_id, other_tenant):
                for table in ("admin_audit_log", "tenant_siem_targets", "operators"):
                    s.execute(text(f"DELETE FROM {table} WHERE tenant_id = :i"), {"i": tid})
                s.execute(text("DELETE FROM tenants WHERE id = :i"), {"i": tid})
            s.commit()
