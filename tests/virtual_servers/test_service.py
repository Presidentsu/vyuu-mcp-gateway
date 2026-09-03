from uuid import uuid4

import pytest

from vyuu_gateway.db.models import VirtualServer, VirtualServerTool
from vyuu_gateway.virtual_servers.schemas import AllowlistedTool, CreateVirtualServerRequest
from vyuu_gateway.virtual_servers.service import (
    DuplicateVirtualServerNameError,
    UpstreamServerNotFoundError,
    VirtualServerCreatorNotFoundError,
    add_allowlisted_tools,
    create_virtual_server,
)


class FakeServiceSession:
    def __init__(
        self,
        *,
        operator_exists: bool = True,
        duplicate_vserver: bool = False,
        found_server_ids: set[object] | None = None,
        virtual_server: VirtualServer | None = None,
    ) -> None:
        self.scalar_results: list[object | None] = [
            uuid4() if operator_exists else None,
            uuid4() if duplicate_vserver else None,
        ]
        if virtual_server is not None:
            self.scalar_results = [virtual_server]
        self.found_server_ids = found_server_ids or set()
        self.added: list[object] = []
        self.committed = False
        self.rolled_back = False
        self.scalar_statements: list[object] = []
        self.scalars_statements: list[object] = []

    def scalar(self, statement: object) -> object | None:
        self.scalar_statements.append(statement)
        return self.scalar_results.pop(0)

    def scalars(self, statement: object) -> set[object]:
        self.scalars_statements.append(statement)
        return self.found_server_ids

    def add(self, instance: object) -> None:
        self.added.append(instance)

    def execute(self, statement: object) -> None:
        # The legacy create_virtual_server tests don't exercise UPDATE flows,
        # so the bulk DELETE inside `update_virtual_server` is irrelevant
        # here. Stubbed so the fake satisfies the Protocol.
        return None

    def delete(self, instance: object) -> None:
        return None

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def refresh(self, instance: object) -> None:
        return None


def test_create_virtual_server_persists_allowlisted_tools_and_rename_map() -> None:
    tenant_id = uuid4()
    creator_id = uuid4()
    server_id = uuid4()
    session = FakeServiceSession(found_server_ids={server_id})

    virtual_server = create_virtual_server(
        session,
        request=CreateVirtualServerRequest(
            name="finance-readonly",
            rename_map={"query_select": "query"},
            tools=[AllowlistedTool(server_id=server_id, tool_name="query_select")],
        ),
        tenant_id=tenant_id,
        created_by=creator_id,
    )

    assert virtual_server.tenant_id == tenant_id
    assert virtual_server.name == "finance-readonly"
    assert virtual_server.rename_map == {"query_select": "query"}
    assert [(tool.server_id, tool.tool_name) for tool in virtual_server.tools] == [
        (server_id, "query_select")
    ]
    assert session.added == [virtual_server]
    assert session.committed


def test_create_virtual_server_raises_when_creator_not_in_tenant() -> None:
    session = FakeServiceSession(operator_exists=False)

    with pytest.raises(VirtualServerCreatorNotFoundError):
        create_virtual_server(
            session,
            request=CreateVirtualServerRequest(name="finance-readonly"),
            tenant_id=uuid4(),
            created_by=uuid4(),
        )


def test_create_virtual_server_raises_for_duplicate_name_in_tenant() -> None:
    session = FakeServiceSession(duplicate_vserver=True)

    with pytest.raises(DuplicateVirtualServerNameError):
        create_virtual_server(
            session,
            request=CreateVirtualServerRequest(name="finance-readonly"),
            tenant_id=uuid4(),
            created_by=uuid4(),
        )


def test_create_virtual_server_raises_when_allowlisted_server_is_outside_tenant() -> None:
    server_id = uuid4()
    session = FakeServiceSession(found_server_ids=set())

    with pytest.raises(UpstreamServerNotFoundError):
        create_virtual_server(
            session,
            request=CreateVirtualServerRequest(
                name="finance-readonly",
                tools=[AllowlistedTool(server_id=server_id, tool_name="query")],
            ),
            tenant_id=uuid4(),
            created_by=uuid4(),
        )


def test_add_allowlisted_tools_persists_tools_for_existing_virtual_server() -> None:
    tenant_id = uuid4()
    vserver_id = uuid4()
    server_id = uuid4()
    session = FakeServiceSession(
        found_server_ids={server_id},
        virtual_server=VirtualServer(
            id=vserver_id,
            tenant_id=tenant_id,
            name="finance-readonly",
            created_by=uuid4(),
        ),
    )

    created_tools = add_allowlisted_tools(
        session,
        tenant_id=tenant_id,
        vserver_id=vserver_id,
        tools=[AllowlistedTool(server_id=server_id, tool_name="query")],
    )

    assert len(created_tools) == 1
    assert isinstance(created_tools[0], VirtualServerTool)
    assert created_tools[0].tenant_id == tenant_id
    assert created_tools[0].vserver_id == vserver_id
    assert created_tools[0].server_id == server_id
    assert created_tools[0].tool_name == "query"
    assert session.added == created_tools
    assert session.committed


def test_virtual_server_service_queries_are_tenant_filtered() -> None:
    tenant_id = uuid4()
    server_id = uuid4()
    session = FakeServiceSession(found_server_ids={server_id})

    create_virtual_server(
        session,
        request=CreateVirtualServerRequest(
            name="finance-readonly",
            tools=[AllowlistedTool(server_id=server_id, tool_name="query")],
        ),
        tenant_id=tenant_id,
        created_by=uuid4(),
    )

    assert "operators.tenant_id" in str(session.scalar_statements[0])
    assert "virtual_servers.tenant_id" in str(session.scalar_statements[1])
    assert "mcp_servers.tenant_id" in str(session.scalars_statements[0])
