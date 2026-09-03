"""MCP-2 P2 · the SDK v1/v2 compatibility layer.

These run on whichever SDK is installed and must pass on both. That is
the point: they encode the invariants the shim exists to hold, so the
day `pyproject.toml` moves to `mcp>=2` the suite tells us whether the
move is safe rather than production doing it.

The one that earns its keep is
`test_wire_dump_uses_camelcase_aliases_on_either_sdk`. v2 snake_cased the
Python attributes but kept the camelCase wire aliases, so a bare
`model_dump()` — correct on v1 — silently emits `is_error` / `input_schema`
on v2. Nothing errors: the gateway returns 200, the JSON looks plausible,
and every MCP client just stops seeing the fields. That is the kind of
break that ships.
"""

from __future__ import annotations

from datetime import timedelta

from mcp.types import CallToolResult, TextContent

from vyuu_gateway.mcp.sdk_compat import (
    MCP_SDK_MAJOR,
    McpError,
    dump_wire,
    http_client_module,
    is_v2,
    make_tool,
    read_timeout_arg,
    result_is_error,
    set_result_is_error,
    tool_input_schema,
)

# --- The wire contract ------------------------------------------------------


def test_wire_dump_uses_camelcase_aliases_on_either_sdk() -> None:
    """The MCP wire format is camelCase in BOTH SDK versions. Only the
    Python attribute names changed."""

    result = CallToolResult(
        content=[TextContent(type="text", text="hi")],
        **({"is_error": True} if is_v2() else {"isError": True}),
    )
    wire = dump_wire(result)
    assert wire["isError"] is True, (
        "serialized without `by_alias=True` — an MCP client would not see "
        "isError at all"
    )
    assert "is_error" not in wire


def test_wire_dump_keeps_tool_schema_camelcase() -> None:
    tool = make_tool(name="query", input_schema={"type": "object"})
    wire = dump_wire(tool)
    assert wire["inputSchema"] == {"type": "object"}
    assert "input_schema" not in wire


def test_bare_model_dump_is_the_trap_this_module_exists_for() -> None:
    """Documents the hazard directly. On v1 a bare dump happens to be
    correct; on v2 it is not — which is exactly why call sites must not
    make that choice individually."""

    tool = make_tool(name="query", input_schema={"type": "object"})
    bare = tool.model_dump(exclude_none=True)
    if is_v2():
        assert "input_schema" in bare and "inputSchema" not in bare, (
            "v2 bare dump should emit snake_case — if this changed, the "
            "shim's premise needs rechecking"
        )
    else:
        assert "inputSchema" in bare
    # Either way, the wire helper is right.
    assert "inputSchema" in dump_wire(tool)


# --- Accessors --------------------------------------------------------------


def test_tool_input_schema_reads_either_field_name() -> None:
    tool = make_tool(name="t", input_schema={"type": "object", "properties": {}})
    assert tool_input_schema(tool) == {"type": "object", "properties": {}}


def test_tool_input_schema_returns_empty_not_none() -> None:
    """Callers feed this straight to a JSON-Schema validator: `{}` means
    "no constraints", `None` means "crash"."""

    class _NoSchema:
        pass

    assert tool_input_schema(_NoSchema()) == {}


def test_result_is_error_round_trips() -> None:
    result = CallToolResult(content=[TextContent(type="text", text="x")])
    assert result_is_error(result) is False
    set_result_is_error(result, True)
    assert result_is_error(result) is True


def test_result_is_error_defaults_false_when_unreadable() -> None:
    """An unreadable flag must not turn a successful call into a failed
    one — that would convert an SDK mismatch into fabricated upstream
    errors in the audit log."""

    class _Opaque:
        pass

    assert result_is_error(_Opaque()) is False


def test_make_tool_accepts_output_schema_too() -> None:
    tool = make_tool(
        name="t", input_schema={"type": "object"}, output_schema={"type": "string"}
    )
    assert dump_wire(tool)["outputSchema"] == {"type": "string"}


# --- Version-conditional plumbing -------------------------------------------


def test_read_timeout_matches_the_sdk_signature() -> None:
    """v1 wants a `timedelta`, v2 a `float`. Passing a float to v1 does
    not raise — it silently means "no timeout" — so this is exactly the
    kind of difference worth centralising."""

    value = read_timeout_arg(30.0)
    if is_v2():
        assert value == 30.0 and isinstance(value, float)
    else:
        assert value == timedelta(seconds=30)
    assert read_timeout_arg(None) is None


def test_http_client_module_matches_the_sdk_transport() -> None:
    """v2 transports take `httpx2` clients. Mixing flavours fails deep in
    the connection pool with an error that never mentions versions."""

    module = http_client_module()
    assert module.__name__ == ("httpx2" if is_v2() else "httpx")
    assert hasattr(module, "AsyncClient")


def test_mcp_error_is_importable_and_is_an_exception() -> None:
    assert isinstance(McpError, type) and issubclass(McpError, Exception)


def test_version_detection_agrees_with_the_installed_package() -> None:
    import importlib.metadata as md

    assert MCP_SDK_MAJOR == int(md.version("mcp").split(".", 1)[0])
    assert is_v2() == (MCP_SDK_MAJOR >= 2)


def test_wire_dump_strips_modern_only_result_fields() -> None:
    """SDK v2 models default `result_type="complete"`, which serializes as
    `resultType` — a field the 2026-07-28 revision introduced. Leaking it
    into a LEGACY response tells a 2025-era client we speak a revision we
    are not speaking on that connection.

    The dual-era handler adds it back explicitly on the modern path, so
    stripping here makes that path the only source of it.
    """

    from mcp.types import ListToolsResult

    from vyuu_gateway.mcp.sdk_compat import MODERN_ONLY_RESULT_FIELDS

    wire = dump_wire(ListToolsResult(tools=[]))
    assert not (MODERN_ONLY_RESULT_FIELDS & set(wire)), (
        f"modern-era fields leaked into a plain dump: {wire}"
    )
    assert "tools" in wire
