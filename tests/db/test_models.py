from typing import cast

from sqlalchemy import CheckConstraint, Table, UniqueConstraint
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from vyuu_gateway.db.base import Base
from vyuu_gateway.db.models import (
    McpCapability,
    McpServer,
    Operator,
    Tenant,
    VirtualServer,
    VirtualServerTool,
)


def test_registry_tables_are_registered() -> None:
    assert set(Base.metadata.tables) >= {
        "tenants",
        "operators",
        "mcp_servers",
        "mcp_capabilities",
        "virtual_servers",
        "virtual_server_tools",
    }


def test_tenant_scoped_tables_have_non_nullable_tenant_id() -> None:
    for model in (Operator, McpServer, McpCapability, VirtualServer, VirtualServerTool):
        table = cast(Table, model.__table__)
        tenant_id = table.columns["tenant_id"]

        assert not tenant_id.nullable


def test_mcp_servers_has_tenant_scoped_display_name_uniqueness() -> None:
    table = cast(Table, McpServer.__table__)
    constraints = {
        constraint.name: constraint
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    constraint = constraints["mcp_servers_tenant_name_uq"]

    assert [column.name for column in constraint.columns] == ["tenant_id", "display_name"]


def test_virtual_servers_has_tenant_scoped_name_uniqueness() -> None:
    table = cast(Table, VirtualServer.__table__)
    constraints = {
        constraint.name: constraint
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    constraint = constraints["virtual_servers_tenant_name_uq"]

    assert [column.name for column in constraint.columns] == ["tenant_id", "name"]


def test_registry_models_include_spec_check_constraints() -> None:
    tables = (
        cast(Table, Tenant.__table__),
        cast(Table, Operator.__table__),
        cast(Table, McpServer.__table__),
        cast(Table, McpCapability.__table__),
    )
    check_constraint_names = {
        constraint.name
        for table in tables
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }

    assert check_constraint_names >= {
        "tenants_tier_check",
        "operators_role_check",
        "mcp_servers_source_type_check",
        "mcp_servers_transport_check",
        "mcp_servers_health_status_check",
        "mcp_capabilities_kind_check",
    }


def test_mcp_server_args_uses_postgresql_text_array() -> None:
    table = cast(Table, McpServer.__table__)
    ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))  # type: ignore[no-untyped-call]

    assert "args TEXT[] NOT NULL" in ddl


def test_mcp_server_includes_health_metadata_columns() -> None:
    table = cast(Table, McpServer.__table__)

    assert "last_health_checked_at" in table.columns
    assert "last_health_error" in table.columns
    assert table.columns["last_health_checked_at"].nullable
    assert table.columns["last_health_error"].nullable


def test_mcp_capability_schema_uses_postgresql_jsonb() -> None:
    table = cast(Table, McpCapability.__table__)
    ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))  # type: ignore[no-untyped-call]

    assert "schema_json JSONB NOT NULL" in ddl
