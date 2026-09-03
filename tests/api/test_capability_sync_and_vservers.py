"""HTTP-level tests for capability sync + virtual-server CRUD endpoints.

These cover the operator-console workflow:
  1. POST /api/v1/servers/{id}/sync     — discover tools on a registered upstream
  2. GET  /api/v1/servers/{id}/capabilities  — show synced tools for picking
  3. POST /api/v1/vservers               — publish a chosen subset
  4. GET  /api/v1/vservers               — list published bundles
  5. GET  /api/v1/vservers/{id}          — fetch one
  6. GET  /api/v1/vservers/{id}/tools    — current allowlist
  7. PATCH /api/v1/vservers/{id}         — rename / update tools / policy_id
  8. DELETE /api/v1/vservers/{id}        — remove

DB and capability-sync clients are faked at the FastAPI dep-override level so
the routes run end-to-end (auth + schema + business logic) without needing
real Postgres or a real MCP upstream.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.capabilities.client import CapabilityDescriptor
from vyuu_gateway.capabilities.fake_client import FakeInMemoryMcpClient
from vyuu_gateway.config import Settings
from vyuu_gateway.db.models import (
    McpCapability,
    McpCapabilityKind,
    McpServer,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
    RiskCategory,
    VirtualServer,
    VirtualServerTool,
    VirtualServerVisibility,
)
from vyuu_gateway.main import create_app
from vyuu_gateway.mcp.sdk_compat import McpError
from vyuu_gateway.operator_auth.fake import mint_operator_test_token

TEST_SIGNING_SECRET = "vservers-test-secret"


# --- Fakes -------------------------------------------------------------------


class _ScalarResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows

    def __iter__(self) -> Iterator[Any]:
        return iter(self._rows)


class _ExecuteResult:
    """Test stand-in for SQLAlchemy's `Result` — the multi-column
    cousin of `_ScalarResult`. The `execute()`-based queries
    (`list_virtual_servers_with_aggregates`, etc.) iterate the result
    or call `.all()`, both of which return a list of tuples."""

    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[Any, ...]]:
        return self._rows

    def __iter__(self) -> Iterator[tuple[Any, ...]]:
        return iter(self._rows)


class FakeDbSession:
    """Test DB session shaped for both the registry and vserver service paths.

    Returns scripted scalar results in order, so each test sets the queue to
    match the SQL its endpoint will execute. Tracks `added` / `deleted` /
    `committed` for assertions.
    """

    def __init__(
        self,
        *,
        scalar_results: list[Any] | None = None,
        scalars_results: list[list[Any]] | None = None,
        execute_results: list[list[tuple[Any, ...]]] | None = None,
    ) -> None:
        self._scalar_queue: list[Any] = list(scalar_results or [])
        self._scalars_queue: list[list[Any]] = list(scalars_results or [])
        self._execute_queue: list[list[tuple[Any, ...]]] = list(execute_results or [])
        self.scalar_statements: list[object] = []
        self.scalars_statements: list[object] = []
        self.execute_statements: list[object] = []
        self.added: list[Any] = []
        self.deleted: list[Any] = []
        self.committed = False
        self.rolled_back = False
        self.raise_integrity_error_on_commit = False

    def scalar(self, statement: object) -> Any:
        self.scalar_statements.append(statement)
        if not self._scalar_queue:
            return None
        return self._scalar_queue.pop(0)

    def scalars(self, statement: object) -> _ScalarResult:
        self.scalars_statements.append(statement)
        if not self._scalars_queue:
            return _ScalarResult([])
        return _ScalarResult(self._scalars_queue.pop(0))

    def execute(self, statement: object) -> _ExecuteResult:
        self.execute_statements.append(statement)
        if not self._execute_queue:
            return _ExecuteResult([])
        return _ExecuteResult(self._execute_queue.pop(0))

    def add(self, instance: Any) -> None:
        self.added.append(instance)

    def delete(self, instance: Any) -> None:
        self.deleted.append(instance)

    def commit(self) -> None:
        if self.raise_integrity_error_on_commit:
            raise IntegrityError("duplicate", {}, Exception("duplicate"))
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def refresh(self, instance: Any) -> None:
        return None


# --- Helpers -----------------------------------------------------------------


def _auth_context() -> tuple[UUID, UUID, dict[str, str]]:
    tenant_id = uuid4()
    operator_id = uuid4()
    token = mint_operator_test_token(
        tenant_id=tenant_id,
        operator_id=operator_id,
        signing_secret=TEST_SIGNING_SECRET,
    )
    return tenant_id, operator_id, {"Authorization": f"Bearer {token}"}


def _build_app(
    db: FakeDbSession,
    *,
    capability_client: FakeInMemoryMcpClient | None = None,
    upstream_clients: object | None = None,
) -> TestClient:
    app = create_app(
        Settings(
            app_name="Vyuu Gateway (vservers test)",
            environment="test",
            log_level="CRITICAL",
            version="vservers-test",
            operator_auth_signing_secret=TEST_SIGNING_SECRET,
        ),
        capability_sync_client=capability_client,
        upstream_clients=upstream_clients,
    )

    def override_db() -> Iterator[FakeDbSession]:
        yield db

    app.dependency_overrides[get_tenant_scoped_db] = override_db
    return TestClient(app)


def _make_server(*, tenant_id: UUID, server_id: UUID | None = None) -> McpServer:
    return McpServer(
        id=server_id or uuid4(),
        tenant_id=tenant_id,
        display_name="upstream-x",
        source_type=McpServerSourceType.HTTP,
        source_location="https://upstream.example/mcp",
        transport=McpTransport.STREAMABLE_HTTP,
        args=[],
        registered_by=uuid4(),
        registered_at=datetime.now(UTC),
        health_status=McpServerHealthStatus.UNKNOWN,
    )


def _make_capability(
    *,
    tenant_id: UUID,
    server_id: UUID,
    name: str,
    kind: McpCapabilityKind = McpCapabilityKind.TOOL,
    risk_category: RiskCategory = RiskCategory.READ,
) -> McpCapability:
    return McpCapability(
        id=uuid4(),
        tenant_id=tenant_id,
        server_id=server_id,
        kind=kind,
        name=name,
        schema_json={"description": f"{name} description", "inputSchema": {"type": "object"}},
        risk_category=risk_category,
        observed_at=datetime.now(UTC),
        deprecated=False,
    )


def _make_vserver(*, tenant_id: UUID, name: str = "finance-readonly") -> VirtualServer:
    # Every NOT NULL column has to be stated explicitly: this instance is
    # transient, so SQLAlchemy's column defaults (which fire at INSERT)
    # have not run and the attributes would read as None. Same reason
    # `rename_map` is set below rather than left to its default.
    return VirtualServer(
        id=uuid4(),
        tenant_id=tenant_id,
        name=name,
        rename_map={},
        policy_id=None,
        visibility=VirtualServerVisibility.PRIVATE,
        jit_enabled=False,
        jit_max_duration_seconds=4 * 3600,
        jit_auto_approve=False,
        jit_require_justification=True,
        jit_tools={},
        created_by=uuid4(),
        created_at=datetime.now(UTC),
    )


# --- Capability sync tests ---------------------------------------------------


def test_sync_endpoint_drives_capability_discovery_through_provider() -> None:
    tenant_id, _operator_id, headers = _auth_context()
    server_id = uuid4()
    server = _make_server(tenant_id=tenant_id, server_id=server_id)

    fake_client = FakeInMemoryMcpClient()
    fake_client.set_capabilities(
        server_id,
        [
            CapabilityDescriptor(
                kind=McpCapabilityKind.TOOL,
                name="list_repos",
                schema_json={"inputSchema": {"type": "object"}},
            ),
            CapabilityDescriptor(
                kind=McpCapabilityKind.TOOL,
                name="delete_file",
                schema_json={"inputSchema": {"type": "object"}},
            ),
        ],
    )

    db = FakeDbSession(
        # First scalar: McpServer lookup; second: not used (sync calls scalars
        # for previous capabilities).
        scalar_results=[server],
        scalars_results=[[]],  # no prior capabilities
    )
    client = _build_app(db, capability_client=fake_client)

    response = client.post(f"/api/v1/servers/{server_id}/sync", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["server_id"] == str(server_id)
    assert body["capability_count"] == 2
    assert {c["name"] for c in body["added"]} == {"list_repos", "delete_file"}
    assert body["removed"] == []
    assert body["changed"] == []

    # Two new capability rows persisted; the sync ran through the real
    # service even though the upstream client is faked.
    persisted_caps = [a for a in db.added if isinstance(a, McpCapability)]
    assert len(persisted_caps) == 2
    assert db.committed

    # `last_sync_drift` is persisted on the server row so the operator
    # console can show "what changed" without re-syncing. Both tools
    # were new (no prior caps), so they appear under `added`.
    drift_json = server.last_sync_drift
    assert isinstance(drift_json, dict)
    assert drift_json["has_changes"] is True
    assert {entry["name"] for entry in drift_json["added"]} == {
        "list_repos",
        "delete_file",
    }
    assert drift_json["removed"] == []
    assert drift_json["changed"] == []
    # Each `added` entry carries a resolved risk_category so the UI
    # can tone the diff (e.g. delete_file should classify as "delete").
    by_name = {e["name"]: e for e in drift_json["added"]}
    assert by_name["delete_file"]["risk_category"] == "delete"


def test_seed_endpoint_persists_capabilities_without_upstream_probe() -> None:
    """Manual capability seeding for credential-gated MCPs (CrowdStrike,
    air-gapped deployments, pre-procurement evaluation). No upstream
    probe — the operator pastes the catalog directly."""

    tenant_id, _operator_id, headers = _auth_context()
    server_id = uuid4()
    server = _make_server(tenant_id=tenant_id, server_id=server_id)
    db = FakeDbSession(scalar_results=[server], scalars_results=[[]])
    client = _build_app(db, capability_client=FakeInMemoryMcpClient())

    response = client.post(
        f"/api/v1/servers/{server_id}/capabilities",
        headers=headers,
        json={
            "capabilities": [
                {
                    "kind": "tool",
                    "name": "list_detections",
                    "schema_json": {
                        "description": "List Falcon detections",
                        "inputSchema": {"type": "object"},
                    },
                },
                {
                    "kind": "tool",
                    "name": "delete_indicator",
                    "schema_json": {"inputSchema": {"type": "object"}},
                    "risk_category": "delete",  # operator override
                },
            ]
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["capability_count"] == 2
    assert {c["name"] for c in body["added"]} == {
        "list_detections",
        "delete_indicator",
    }
    persisted = [a for a in db.added if isinstance(a, McpCapability)]
    assert len(persisted) == 2
    by_name = {c.name: c for c in persisted}
    assert by_name["delete_indicator"].risk_category == RiskCategory.DELETE
    assert db.committed
    # `last_capabilities_pulled_at` must NOT be set — manual seed is not
    # a verified-against-upstream snapshot.
    assert server.last_capabilities_pulled_at is None


def test_seed_endpoint_returns_404_for_unknown_server() -> None:
    _tenant_id, _operator_id, headers = _auth_context()
    db = FakeDbSession(scalar_results=[None])
    client = _build_app(db, capability_client=FakeInMemoryMcpClient())

    response = client.post(
        f"/api/v1/servers/{uuid4()}/capabilities",
        headers=headers,
        json={"capabilities": []},
    )

    assert response.status_code == 404


def test_seed_endpoint_requires_operator_auth() -> None:
    db = FakeDbSession()
    client = _build_app(db, capability_client=FakeInMemoryMcpClient())

    response = client.post(
        f"/api/v1/servers/{uuid4()}/capabilities",
        json={"capabilities": []},
    )

    assert response.status_code == 401


def test_seed_endpoint_marks_previous_capabilities_deprecated() -> None:
    """Seeding REPLACES the active snapshot — old capabilities flip to
    deprecated, new ones land. Same drift contract as upstream sync."""

    tenant_id, _operator_id, headers = _auth_context()
    server_id = uuid4()
    server = _make_server(tenant_id=tenant_id, server_id=server_id)
    old_cap = _make_capability(
        tenant_id=tenant_id, server_id=server_id, name="old_tool"
    )
    db = FakeDbSession(scalar_results=[server], scalars_results=[[old_cap]])
    client = _build_app(db, capability_client=FakeInMemoryMcpClient())

    response = client.post(
        f"/api/v1/servers/{server_id}/capabilities",
        headers=headers,
        json={
            "capabilities": [
                {
                    "kind": "tool",
                    "name": "new_tool",
                    "schema_json": {"inputSchema": {"type": "object"}},
                }
            ]
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert {c["name"] for c in body["added"]} == {"new_tool"}
    assert {c["name"] for c in body["removed"]} == {"old_tool"}
    # The old capability row got flipped to deprecated.
    assert old_cap.deprecated is True


def test_patch_sync_cadence_updates_server_row() -> None:
    """`PATCH /servers/{id}/sync-cadence` flips the per-server
    `sync_cadence_minutes`. NULL = use the global default; 0 = manual
    only (scheduler skips); positive = throttle to N minutes."""

    tenant_id, _operator_id, headers = _auth_context()
    server_id = uuid4()
    server = _make_server(tenant_id=tenant_id, server_id=server_id)
    db = FakeDbSession(scalar_results=[server, server, server])
    client = _build_app(db, capability_client=FakeInMemoryMcpClient())

    # Set to 30 minutes
    response = client.patch(
        f"/api/v1/servers/{server_id}/sync-cadence",
        headers=headers,
        json={"sync_cadence_minutes": 30},
    )
    assert response.status_code == 200
    assert response.json()["sync_cadence_minutes"] == 30
    assert server.sync_cadence_minutes == 30

    # Flip to manual-only
    response = client.patch(
        f"/api/v1/servers/{server_id}/sync-cadence",
        headers=headers,
        json={"sync_cadence_minutes": 0},
    )
    assert response.status_code == 200
    assert response.json()["sync_cadence_minutes"] == 0

    # Reset to global default (NULL)
    response = client.patch(
        f"/api/v1/servers/{server_id}/sync-cadence",
        headers=headers,
        json={"sync_cadence_minutes": None},
    )
    assert response.status_code == 200
    assert response.json()["sync_cadence_minutes"] is None


def test_patch_sync_cadence_rejects_negative_and_overlong() -> None:
    """Schema bounds: ge=0 (no negatives) and le=43200 (30 days)."""

    tenant_id, _operator_id, headers = _auth_context()
    server_id = uuid4()
    server = _make_server(tenant_id=tenant_id, server_id=server_id)
    db = FakeDbSession(scalar_results=[server])
    client = _build_app(db, capability_client=FakeInMemoryMcpClient())

    bad_negative = client.patch(
        f"/api/v1/servers/{server_id}/sync-cadence",
        headers=headers,
        json={"sync_cadence_minutes": -1},
    )
    assert bad_negative.status_code == 422

    bad_overlong = client.patch(
        f"/api/v1/servers/{server_id}/sync-cadence",
        headers=headers,
        json={"sync_cadence_minutes": 999_999},
    )
    assert bad_overlong.status_code == 422


def test_patch_sync_cadence_returns_404_for_unknown_server() -> None:
    _tenant_id, _operator_id, headers = _auth_context()
    db = FakeDbSession(scalar_results=[None])
    client = _build_app(db, capability_client=FakeInMemoryMcpClient())

    response = client.patch(
        f"/api/v1/servers/{uuid4()}/sync-cadence",
        headers=headers,
        json={"sync_cadence_minutes": 60},
    )
    assert response.status_code == 404


def test_delete_server_cascades_dependents_and_returns_summary() -> None:
    """`DELETE /servers/{id}` cascade-deletes capabilities + tool
    exposures + OAuth tokens (FK CASCADE) and returns a per-table
    count summary. Anti-enumeration: 404 for cross-tenant id."""
    tenant_id, _operator_id, headers = _auth_context()
    server_id = uuid4()
    server = _make_server(tenant_id=tenant_id, server_id=server_id)
    # Scalar queue order matches `delete_mcp_server`:
    #   1. server lookup
    #   2. capability count
    #   3. vserver_tools count
    #   4. oauth_user_tokens count
    db = FakeDbSession(scalar_results=[server, 5, 3, 1])
    client = _build_app(db, capability_client=FakeInMemoryMcpClient())

    response = client.delete(
        f"/api/v1/servers/{server_id}", headers=headers
    )

    assert response.status_code == 200
    body = response.json()
    assert body["capabilities_deleted"] == 5
    assert body["vserver_tool_exposures_removed"] == 3
    assert body["oauth_user_tokens_revoked"] == 1
    # The actual DELETE statement was executed.
    # (`any(...)` would call `bool()` on each SQLAlchemy Delete,
    # which raises — assert on the list length instead.)
    assert len(db.execute_statements) >= 1
    assert db.committed


def test_delete_server_returns_404_for_unknown_id() -> None:
    _tenant_id, _operator_id, headers = _auth_context()
    db = FakeDbSession(scalar_results=[None])
    client = _build_app(db, capability_client=FakeInMemoryMcpClient())

    response = client.delete(
        f"/api/v1/servers/{uuid4()}", headers=headers
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "server not found"


def test_sync_endpoint_returns_404_for_unknown_server() -> None:
    tenant_id, _operator_id, headers = _auth_context()
    db = FakeDbSession(scalar_results=[None])
    client = _build_app(db, capability_client=FakeInMemoryMcpClient())

    response = client.post(f"/api/v1/servers/{uuid4()}/sync", headers=headers)

    assert response.status_code == 404
    assert response.json()["detail"] == "server not found"
    assert not db.committed


def test_sync_endpoint_returns_502_when_upstream_initialize_fails() -> None:
    """A registered-but-unreachable upstream (e.g. PayPal MCP without an
    API key) must surface as a clean 502 with the sanitized error class
    name, not as a 500 with a leaked traceback.
    """

    class _UpstreamFailingClient(FakeInMemoryMcpClient):
        async def list_capabilities(
            self,
            server: McpServer,
            *,
            principal_id: UUID | None = None,
        ) -> list[CapabilityDescriptor]:
            from vyuu_gateway.mcp.sdk_compat import make_mcp_error

            del principal_id
            raise make_mcp_error(-32000, "Connection closed")

    tenant_id, _operator_id, headers = _auth_context()
    server_id = uuid4()
    server = _make_server(tenant_id=tenant_id, server_id=server_id)
    db = FakeDbSession(scalar_results=[server], scalars_results=[[]])
    client = _build_app(db, capability_client=_UpstreamFailingClient())

    response = client.post(f"/api/v1/servers/{server_id}/sync", headers=headers)

    assert response.status_code == 502
    detail = response.json()["detail"]
    # Sanitized: error CLASS name only, never the raw upstream message.
    # The message carries the exception CLASS name, which the SDK
    # renamed (McpError -> MCPError) in v2. Assert against the class
    # the shim resolved rather than either literal.
    assert detail == f"upstream sync failed: {McpError.__name__}"
    assert "Connection closed" not in detail


def test_sync_endpoint_unwraps_exception_group_to_innermost_cause() -> None:
    """anyio task groups wrap upstream failures in nested ExceptionGroups.
    The 502 detail must surface the innermost class (e.g. `McpError`),
    not the wrapper.
    """

    class _TaskGroupWrappedClient(FakeInMemoryMcpClient):
        async def list_capabilities(
            self,
            server: McpServer,
            *,
            principal_id: UUID | None = None,
        ) -> list[CapabilityDescriptor]:
            from vyuu_gateway.mcp.sdk_compat import make_mcp_error

            del principal_id
            inner = make_mcp_error(-32000, "Connection closed")
            raise ExceptionGroup("outer", [ExceptionGroup("inner", [inner])])

    tenant_id, _operator_id, headers = _auth_context()
    server_id = uuid4()
    server = _make_server(tenant_id=tenant_id, server_id=server_id)
    db = FakeDbSession(scalar_results=[server], scalars_results=[[]])
    client = _build_app(db, capability_client=_TaskGroupWrappedClient())

    response = client.post(f"/api/v1/servers/{server_id}/sync", headers=headers)

    assert response.status_code == 502
    # Class name, which the SDK renamed (McpError -> MCPError) in v2.
    assert response.json()["detail"] == (
        f"upstream sync failed: {McpError.__name__}"
    )


def test_sync_endpoint_requires_operator_auth() -> None:
    db = FakeDbSession()
    client = _build_app(db, capability_client=FakeInMemoryMcpClient())

    response = client.post(f"/api/v1/servers/{uuid4()}/sync")

    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"


def test_capabilities_endpoint_lists_synced_rows_with_redacted_alias() -> None:
    tenant_id, _operator_id, headers = _auth_context()
    server_id = uuid4()
    cap1 = _make_capability(
        tenant_id=tenant_id,
        server_id=server_id,
        name="list_repos",
        risk_category=RiskCategory.READ,
    )
    cap2 = _make_capability(
        tenant_id=tenant_id,
        server_id=server_id,
        name="delete_file",
        risk_category=RiskCategory.DELETE,
    )

    db = FakeDbSession(scalars_results=[[cap1, cap2]])
    client = _build_app(db)

    response = client.get(f"/api/v1/servers/{server_id}/capabilities", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    names = sorted(c["name"] for c in body)
    assert names == ["delete_file", "list_repos"]
    # `schema_json` is the wire alias; the model attr is `schema_payload`,
    # not visible in the JSON.
    for entry in body:
        assert "schema_json" in entry
        assert "schema_payload" not in entry


def test_capabilities_endpoint_filters_by_tenant_in_sql() -> None:
    tenant_id, _operator_id, headers = _auth_context()
    server_id = uuid4()
    db = FakeDbSession(scalars_results=[[]])
    client = _build_app(db)

    client.get(f"/api/v1/servers/{server_id}/capabilities", headers=headers)

    sql = str(db.scalars_statements[0])
    assert "mcp_capabilities.tenant_id" in sql
    assert "mcp_capabilities.server_id" in sql
    # Excludes deprecated rows.
    assert "mcp_capabilities.deprecated" in sql


# --- Virtual server CRUD tests ----------------------------------------------


def test_create_vserver_persists_with_auth_context_tenant_and_creator() -> None:
    tenant_id, operator_id, headers = _auth_context()
    server_id = uuid4()

    db = FakeDbSession(
        scalar_results=[
            uuid4(),  # operator-in-tenant exists
            None,  # vserver name is not duplicate
        ],
        scalars_results=[[server_id]],  # allowlisted server is in tenant
    )
    client = _build_app(db)

    payload = {
        "name": "finance-readonly",
        "tools": [{"server_id": str(server_id), "tool_name": "query"}],
    }

    response = client.post("/api/v1/vservers", json=payload, headers=headers)

    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "finance-readonly"
    assert UUID(body["tenant_id"]) == tenant_id
    assert UUID(body["created_by"]) == operator_id

    # Persisted vserver has correct tenant + creator from auth context, not
    # from any client-supplied body field.
    persisted_vservers = [a for a in db.added if isinstance(a, VirtualServer)]
    assert len(persisted_vservers) == 1
    assert persisted_vservers[0].tenant_id == tenant_id
    assert persisted_vservers[0].created_by == operator_id


def test_create_vserver_rejects_body_supplied_tenant_id() -> None:
    """`extra="forbid"` on the request schema must reject any client
    attempt to supply tenant_id / created_by in the body."""
    _tenant_id, _operator_id, headers = _auth_context()
    db = FakeDbSession()
    client = _build_app(db)

    response = client.post(
        "/api/v1/vservers",
        json={
            "name": "should-fail",
            "tenant_id": str(uuid4()),  # forbidden
            "created_by": str(uuid4()),  # forbidden
            "tools": [],
        },
        headers=headers,
    )

    assert response.status_code == 422
    assert db.added == []


def test_create_vserver_rejects_unknown_upstream_server_in_tools() -> None:
    _tenant_id, _operator_id, headers = _auth_context()
    server_id = uuid4()

    db = FakeDbSession(
        scalar_results=[
            uuid4(),  # operator exists
            None,  # name not duplicate
        ],
        # The allowlisted server isn't returned, simulating "not in tenant"
        scalars_results=[[]],
    )
    client = _build_app(db)

    response = client.post(
        "/api/v1/vservers",
        json={
            "name": "x",
            "tools": [{"server_id": str(server_id), "tool_name": "y"}],
        },
        headers=headers,
    )

    assert response.status_code == 400
    assert "do not exist" in response.json()["detail"]


def test_create_vserver_rejects_duplicate_name_with_409() -> None:
    _tenant_id, _operator_id, headers = _auth_context()

    db = FakeDbSession(
        scalar_results=[
            uuid4(),  # operator exists
            uuid4(),  # name IS duplicate
        ],
    )
    client = _build_app(db)

    response = client.post("/api/v1/vservers", json={"name": "dup"}, headers=headers)

    assert response.status_code == 409


def test_list_vservers_returns_only_tenant_rows_via_sql_filter() -> None:
    tenant_id, _operator_id, headers = _auth_context()
    # The endpoint now joins per-vserver aggregates (tool_count,
    # grant_count) — the fake has to script the multi-column row.
    finance_vserver = _make_vserver(tenant_id=tenant_id, name="finance")
    db = FakeDbSession(
        execute_results=[[(finance_vserver, 5, 2)]],
    )
    client = _build_app(db)

    response = client.get("/api/v1/vservers", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert [row["name"] for row in body] == ["finance"]
    assert body[0]["tool_count"] == 5
    assert body[0]["grant_count"] == 2
    assert "virtual_servers.tenant_id" in str(db.execute_statements[0])


def test_get_vserver_returns_one() -> None:
    tenant_id, _operator_id, headers = _auth_context()
    vserver = _make_vserver(tenant_id=tenant_id)
    db = FakeDbSession(scalar_results=[vserver])
    client = _build_app(db)

    response = client.get(f"/api/v1/vservers/{vserver.id}", headers=headers)

    assert response.status_code == 200
    assert response.json()["name"] == vserver.name


def test_get_vserver_returns_404_for_unknown_id() -> None:
    _tenant_id, _operator_id, headers = _auth_context()
    db = FakeDbSession(scalar_results=[None])
    client = _build_app(db)

    response = client.get(f"/api/v1/vservers/{uuid4()}", headers=headers)

    assert response.status_code == 404


def test_list_vserver_tools_returns_allowlist() -> None:
    tenant_id, _operator_id, headers = _auth_context()
    vserver = _make_vserver(tenant_id=tenant_id)
    server_id = uuid4()
    tool = VirtualServerTool(
        tenant_id=tenant_id,
        vserver_id=vserver.id,
        server_id=server_id,
        tool_name="query_select",
    )
    db = FakeDbSession(
        scalar_results=[vserver],
        scalars_results=[[tool]],
    )
    client = _build_app(db)

    response = client.get(f"/api/v1/vservers/{vserver.id}/tools", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body == [{"server_id": str(server_id), "tool_name": "query_select"}]


def test_update_vserver_replaces_tool_allowlist() -> None:
    tenant_id, _operator_id, headers = _auth_context()
    vserver = _make_vserver(tenant_id=tenant_id)
    new_server_id = uuid4()

    db = FakeDbSession(
        scalar_results=[
            vserver,  # get_virtual_server lookup
        ],
        scalars_results=[
            [new_server_id],  # _ensure_servers_in_tenant returns matching id
        ],
    )
    client = _build_app(db)

    response = client.patch(
        f"/api/v1/vservers/{vserver.id}",
        json={
            "tools": [{"server_id": str(new_server_id), "tool_name": "new_tool"}]
        },
        headers=headers,
    )

    assert response.status_code == 200
    # The bulk-DELETE statement was issued (allowlist replace is not
    # incremental).
    assert any("DELETE FROM virtual_server_tools" in str(s) for s in db.execute_statements)
    # New tool added.
    new_tools = [a for a in db.added if isinstance(a, VirtualServerTool)]
    assert len(new_tools) == 1
    assert new_tools[0].tool_name == "new_tool"


def test_update_vserver_can_rename() -> None:
    tenant_id, _operator_id, headers = _auth_context()
    vserver = _make_vserver(tenant_id=tenant_id, name="old-name")

    db = FakeDbSession(
        scalar_results=[
            vserver,  # get_virtual_server
            None,  # uniqueness check passes
        ],
    )
    client = _build_app(db)

    response = client.patch(
        f"/api/v1/vservers/{vserver.id}",
        json={"name": "new-name"},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["name"] == "new-name"


def test_delete_vserver_removes_row() -> None:
    tenant_id, _operator_id, headers = _auth_context()
    vserver = _make_vserver(tenant_id=tenant_id)
    db = FakeDbSession(scalar_results=[vserver])
    client = _build_app(db)

    response = client.delete(f"/api/v1/vservers/{vserver.id}", headers=headers)

    assert response.status_code == 204
    assert db.deleted == [vserver]
    assert db.committed


def test_delete_vserver_returns_404_for_unknown() -> None:
    _tenant_id, _operator_id, headers = _auth_context()
    db = FakeDbSession(scalar_results=[None])
    client = _build_app(db)

    response = client.delete(f"/api/v1/vservers/{uuid4()}", headers=headers)

    assert response.status_code == 404


def test_vserver_endpoints_all_require_operator_auth() -> None:
    db = FakeDbSession()
    client = _build_app(db)

    for method, path in [
        ("POST", "/api/v1/vservers"),
        ("GET", "/api/v1/vservers"),
        ("GET", f"/api/v1/vservers/{uuid4()}"),
        ("GET", f"/api/v1/vservers/{uuid4()}/tools"),
        ("PATCH", f"/api/v1/vservers/{uuid4()}"),
        ("DELETE", f"/api/v1/vservers/{uuid4()}"),
    ]:
        response = client.request(method, path, json={"name": "x"} if method == "POST" else None)
        assert response.status_code == 401, f"{method} {path}: {response.status_code}"
        assert response.headers.get("www-authenticate") == "Bearer"



# --- Upstream teardown on delete -------------------------------------------


class _RecordingUpstreamProvider:
    """Records `forget_server` calls; optionally raises."""

    def __init__(self, *, fail: bool = False) -> None:
        self.forgotten: list[tuple[UUID, UUID]] = []
        self._fail = fail

    async def forget_server(self, tenant_id: UUID, server_id: UUID) -> None:
        self.forgotten.append((tenant_id, server_id))
        if self._fail:
            raise RuntimeError("upstream teardown blew up")

    async def aclose(self) -> None:
        return None


def test_delete_server_tears_down_the_upstream_connection() -> None:
    """Deleting an stdio server must kill its subprocess.

    The row was deleted but nothing told the connection pool, so a
    spawned `uvx` / `npx` child kept running — holding the credentials
    it was started with — until the gateway process itself exited.
    """
    tenant_id, _operator_id, headers = _auth_context()
    server_id = uuid4()
    server = _make_server(tenant_id=tenant_id, server_id=server_id)
    db = FakeDbSession(scalar_results=[server, 0, 0, 0])
    provider = _RecordingUpstreamProvider()
    client = _build_app(
        db,
        capability_client=FakeInMemoryMcpClient(),
        upstream_clients=provider,
    )

    response = client.delete(f"/api/v1/servers/{server_id}", headers=headers)

    assert response.status_code == 200
    assert provider.forgotten == [(tenant_id, server_id)]


def test_delete_server_still_succeeds_if_teardown_fails() -> None:
    """The row is already gone by then. Raising would report failure for
    work that did happen, and the retry cannot succeed twice."""
    tenant_id, _operator_id, headers = _auth_context()
    server_id = uuid4()
    server = _make_server(tenant_id=tenant_id, server_id=server_id)
    db = FakeDbSession(scalar_results=[server, 0, 0, 0])
    provider = _RecordingUpstreamProvider(fail=True)
    client = _build_app(
        db,
        capability_client=FakeInMemoryMcpClient(),
        upstream_clients=provider,
    )

    response = client.delete(f"/api/v1/servers/{server_id}", headers=headers)

    assert response.status_code == 200
    assert provider.forgotten == [(tenant_id, server_id)]


def test_delete_server_404_does_not_tear_down_anything() -> None:
    """A cross-tenant / unknown id must not be able to close a live
    connection — that would make the anti-enumeration 404 into a
    denial-of-service primitive."""
    _tenant_id, _operator_id, headers = _auth_context()
    provider = _RecordingUpstreamProvider()
    db = FakeDbSession(scalar_results=[None])
    client = _build_app(
        db,
        capability_client=FakeInMemoryMcpClient(),
        upstream_clients=provider,
    )

    response = client.delete(f"/api/v1/servers/{uuid4()}", headers=headers)

    assert response.status_code == 404
    assert provider.forgotten == []
