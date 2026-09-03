"""Idempotently seed the local Postgres for `examples/drawio_lab_server.py`.

The lab now uses the real production code path end-to-end (no more fake
resolver / hand-wired upstream dispatcher). To make the pre-baked drawio
URLs work AND let the operator console register new servers, the database
needs:

  - a tenant whose id matches the lab bearer token
  - an operator whose id matches the lab bearer token
  - the two drawio MCP servers registered with FIXED ids so the printed
    Cursor / Claude Desktop URLs stay stable across runs
  - two virtual servers (`drawio-http`, `drawio-stdio`) bundling each
    upstream's tools, so the inbound MCP route resolves them

This script runs Alembic migrations and INSERTs everything with `ON
CONFLICT DO NOTHING`, so running it twice is a no-op and re-running after
the lab evolves only adds new rows. Capability rows are NOT seeded — run
`POST /api/v1/servers/{id}/sync` from the operator console (or curl) to
populate them; that exercises the real sync code path.

Usage:

    # 1. start Postgres locally (one-time)
    /opt/homebrew/opt/postgresql@16/bin/pg_ctl \\
        -D /opt/homebrew/var/postgresql@16 -l /tmp/pg_lab.log start
    /opt/homebrew/opt/postgresql@16/bin/createdb -h 127.0.0.1 vyuu_gateway -O vyuu

    # 2. bootstrap (idempotent)
    python examples/lab_bootstrap.py

    # 3. start the lab
    python examples/drawio_lab_server.py
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import UTC, datetime
from uuid import UUID

from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.config import get_settings
from vyuu_gateway.db.models import (
    McpServer,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
    VirtualServer,
    VirtualServerTool,
    VirtualServerVisibility,
)
from vyuu_gateway.db.session import SessionLocal

# These IDs MUST match the constants in `examples/drawio_lab_server.py` so the
# printed Cursor / Claude Desktop URLs and the lab bearer token resolve to
# the same rows after a bootstrap.
LAB_TENANT_ID = UUID("11111111-1111-1111-1111-111111111111")
LAB_OPERATOR_ID = UUID("44444444-4444-4444-4444-444444444444")
LAB_HTTP_SERVER_ID = UUID("22222222-2222-2222-2222-222222222222")
LAB_STDIO_SERVER_ID = UUID("22222222-2222-2222-2222-222222222233")
LAB_PYPI_SERVER_ID = UUID("22222222-2222-2222-2222-222222222244")
LAB_HTTP_VSERVER_ID = UUID("33333333-3333-3333-3333-333333333333")
LAB_STDIO_VSERVER_ID = UUID("33333333-3333-3333-3333-333333333344")
LAB_PYPI_VSERVER_ID = UUID("33333333-3333-3333-3333-333333333355")

LAB_HTTP_VSERVER_NAME = "drawio-http"
LAB_STDIO_VSERVER_NAME = "drawio-stdio"
LAB_PYPI_VSERVER_NAME = "time-pypi"
DRAWIO_HTTP_UPSTREAM_URL = "https://mcp.draw.io/mcp"
DRAWIO_NPM_PACKAGE = "@drawio/mcp"
TIME_PYPI_PACKAGE = "mcp-server-time"

logger = logging.getLogger(__name__)


def run_migrations() -> None:
    """Apply Alembic migrations to whatever DATABASE_URL the gateway uses."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg = AlembicConfig(os.path.join(repo_root, "alembic.ini"))
    # Alembic resolves the URL via env.py → get_settings(); no override needed.
    command.upgrade(cfg, "head")


def seed(session: Session) -> None:
    """Idempotently seed lab tenant + operator + drawio servers + vservers."""

    if session.scalar(select(Tenant).where(Tenant.id == LAB_TENANT_ID)) is None:
        session.add(
            Tenant(
                id=LAB_TENANT_ID,
                name="lab-tenant",
                tier=TenantTier.SHARED,
            )
        )
        print(f"  seeded tenant   {LAB_TENANT_ID}")
    else:
        print(f"  tenant already exists  {LAB_TENANT_ID}")

    if session.scalar(select(Operator).where(Operator.id == LAB_OPERATOR_ID)) is None:
        session.add(
            Operator(
                id=LAB_OPERATOR_ID,
                tenant_id=LAB_TENANT_ID,
                email="lab-operator@example.com",
                role=OperatorRole.ADMIN,
            )
        )
        print(f"  seeded operator {LAB_OPERATOR_ID}")
    else:
        print(f"  operator already exists  {LAB_OPERATOR_ID}")

    _seed_server(
        session,
        server_id=LAB_HTTP_SERVER_ID,
        display_name=LAB_HTTP_VSERVER_NAME,
        source_type=McpServerSourceType.HTTP,
        source_location=DRAWIO_HTTP_UPSTREAM_URL,
        transport=McpTransport.STREAMABLE_HTTP,
    )
    _seed_server(
        session,
        server_id=LAB_STDIO_SERVER_ID,
        display_name=LAB_STDIO_VSERVER_NAME,
        source_type=McpServerSourceType.NPM,
        source_location=DRAWIO_NPM_PACKAGE,
        transport=McpTransport.STDIO,
    )
    # PyPI / uvx upstream — `mcp-server-time` is Anthropic's reference time
    # MCP server, free, no API key. Same launch shape any enterprise PyPI
    # MCP (CrowdStrike, Palo Alto, Wiz, Snyk, Datadog) would use.
    _seed_server(
        session,
        server_id=LAB_PYPI_SERVER_ID,
        display_name=LAB_PYPI_VSERVER_NAME,
        source_type=McpServerSourceType.PYPI,
        source_location=TIME_PYPI_PACKAGE,
        transport=McpTransport.STDIO,
    )

    _seed_vserver(
        session,
        vserver_id=LAB_HTTP_VSERVER_ID,
        name=LAB_HTTP_VSERVER_NAME,
        upstream_server_id=LAB_HTTP_SERVER_ID,
        tool_names=("create_diagram", "search_shapes"),
    )
    _seed_vserver(
        session,
        vserver_id=LAB_STDIO_VSERVER_ID,
        name=LAB_STDIO_VSERVER_NAME,
        upstream_server_id=LAB_STDIO_SERVER_ID,
        tool_names=("open_drawio_xml", "open_drawio_csv", "open_drawio_mermaid"),
    )
    _seed_vserver(
        session,
        vserver_id=LAB_PYPI_VSERVER_ID,
        name=LAB_PYPI_VSERVER_NAME,
        upstream_server_id=LAB_PYPI_SERVER_ID,
        tool_names=("get_current_time", "convert_time"),
    )

    session.commit()


def _seed_server(
    session: Session,
    *,
    server_id: UUID,
    display_name: str,
    source_type: McpServerSourceType,
    source_location: str,
    transport: McpTransport,
) -> None:
    if session.scalar(select(McpServer).where(McpServer.id == server_id)) is not None:
        print(f"  mcp_server already exists  {display_name:<14}  {server_id}")
        return
    session.add(
        McpServer(
            id=server_id,
            tenant_id=LAB_TENANT_ID,
            display_name=display_name,
            source_type=source_type,
            source_location=source_location,
            transport=transport,
            args=[],
            registered_by=LAB_OPERATOR_ID,
            registered_at=datetime.now(UTC),
            health_status=McpServerHealthStatus.UNKNOWN,
        )
    )
    print(f"  seeded mcp_server          {display_name:<14}  {server_id}")


def _seed_vserver(
    session: Session,
    *,
    vserver_id: UUID,
    name: str,
    upstream_server_id: UUID,
    tool_names: tuple[str, ...],
) -> None:
    if session.scalar(select(VirtualServer).where(VirtualServer.id == vserver_id)) is not None:
        print(f"  vserver already exists     {name:<14}  {vserver_id}")
        return
    session.add(
        VirtualServer(
            id=vserver_id,
            tenant_id=LAB_TENANT_ID,
            name=name,
            policy_id=None,
            rename_map={},
            # The lab seeds open demo vservers — operator UI lets you flip
            # to private + grant from there. Production registrations
            # default to private (operator opt-in to public).
            visibility=VirtualServerVisibility.PUBLIC,
            created_by=LAB_OPERATOR_ID,
            created_at=datetime.now(UTC),
        )
    )
    for tool_name in tool_names:
        session.add(
            VirtualServerTool(
                tenant_id=LAB_TENANT_ID,
                vserver_id=vserver_id,
                server_id=upstream_server_id,
                tool_name=tool_name,
            )
        )
    print(
        f"  seeded vserver             {name:<14}  {vserver_id}"
        f"  ({len(tool_names)} tools)"
    )


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    settings = get_settings()
    print()
    print("=" * 72)
    print(f"Lab bootstrap — DATABASE_URL = {settings.database_url}")
    print("=" * 72)
    print()
    print("Applying migrations...")
    run_migrations()
    print()
    print("Seeding lab tenant + operator + drawio servers + virtual servers...")
    with SessionLocal() as session:
        seed(session)
    print()
    print("Done. Next:")
    print("  python examples/drawio_lab_server.py")
    print()
    print("Then in the operator console you can register new servers; the lab")
    print("token already authenticates as the seeded operator under this tenant.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
