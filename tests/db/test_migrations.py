from pathlib import Path

MIGRATION = Path("migrations/versions/20260429_0001_registry_tables.py")
VIRTUAL_SERVER_MIGRATION = Path("migrations/versions/20260429_0002_virtual_server_tables.py")
RISK_CATEGORY_MIGRATION = Path(
    "migrations/versions/20260429_0003_capability_risk_category.py"
)
HEALTH_METADATA_MIGRATION = Path(
    "migrations/versions/20260429_0004_mcp_server_health_metadata.py"
)


def test_initial_registry_migration_creates_expected_tables() -> None:
    migration_source = MIGRATION.read_text()

    for table_name in ("tenants", "operators", "mcp_servers", "mcp_capabilities"):
        assert f'"{table_name}"' in migration_source


def test_initial_registry_migration_enables_tenant_rls() -> None:
    migration_source = MIGRATION.read_text()

    for table_name in ("operators", "mcp_servers", "mcp_capabilities"):
        assert f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY" in migration_source
        assert f"CREATE POLICY {table_name}_tenant_isolation" in migration_source


def test_initial_registry_migration_keeps_capabilities_tenant_scoped() -> None:
    migration_source = MIGRATION.read_text()

    assert '"tenant_id", postgresql.UUID(as_uuid=True), nullable=False' in migration_source
    assert "mcp_capabilities_tenant_server_kind_idx" in migration_source


def test_virtual_server_migration_creates_expected_tables() -> None:
    migration_source = VIRTUAL_SERVER_MIGRATION.read_text()

    assert '"virtual_servers"' in migration_source
    assert '"virtual_server_tools"' in migration_source
    assert "virtual_servers_tenant_name_uq" in migration_source


def test_virtual_server_migration_keeps_tool_allowlist_tenant_scoped() -> None:
    migration_source = VIRTUAL_SERVER_MIGRATION.read_text()

    assert '"tenant_id", postgresql.UUID(as_uuid=True), nullable=False' in migration_source
    assert "virtual_server_tools_tenant_vserver_idx" in migration_source
    assert "ALTER TABLE virtual_servers ENABLE ROW LEVEL SECURITY" in migration_source
    assert "ALTER TABLE virtual_server_tools ENABLE ROW LEVEL SECURITY" in migration_source


def test_risk_category_migration_adds_column_with_default_and_check() -> None:
    migration_source = RISK_CATEGORY_MIGRATION.read_text()

    assert 'down_revision: str | None = "20260429_0002"' in migration_source
    assert 'add_column(\n        "mcp_capabilities"' in migration_source
    assert '"risk_category"' in migration_source
    assert 'server_default="unknown"' in migration_source
    assert "mcp_capabilities_risk_category_check" in migration_source
    for category in (
        "read",
        "write",
        "delete",
        "execute",
        "network",
        "credential_access",
        "data_export",
        "admin",
        "unknown",
    ):
        assert f'"{category}"' in migration_source


def test_health_metadata_migration_adds_safe_status_fields() -> None:
    migration_source = HEALTH_METADATA_MIGRATION.read_text()

    assert 'down_revision: str | None = "20260429_0003"' in migration_source
    assert 'add_column(\n        "mcp_servers"' in migration_source
    assert '"last_health_checked_at"' in migration_source
    assert '"last_health_error"' in migration_source
