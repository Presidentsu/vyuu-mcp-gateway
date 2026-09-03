"""MCP-2 P2 · one place that knows whether we are on MCP SDK v1 or v2.

The v2 rewrite (2026-07-28) is smaller than its release notes suggest —
`ClientSession`, `streamable_http_client`, `sse_client` and
`stdio_client` all survive. What actually breaks us is four things:

| v1                                   | v2                                  |
|--------------------------------------|-------------------------------------|
| `mcp.shared.exceptions.McpError`     | `mcp.MCPError`                      |
| `Tool.inputSchema`                   | `Tool.input_schema`                 |
| `CallToolResult.isError`             | `.is_error`                         |
| `read_timeout_seconds: timedelta`    | `read_timeout_seconds: float`       |
| transport takes an `httpx.AsyncClient`| takes an `httpx2.AsyncClient`      |

(Server-side, `FastMCP` became `mcp.server.mcpserver.MCPServer`. Only our
tests build servers, so that rename is handled there.)

## Why a shim rather than a cutover

Two reasons, both concrete:

1. **We cannot branch.** This tree is not a git repo, and the SDK is
   installed editable into an environment shared with another team's
   checkout. A hard cutover would break their tree the moment `mcp` is
   upgraded, and ours the moment it is not.
2. **v1.x is still maintained** (critical + security fixes). A shim lets
   a deployment upgrade the SDK on its own schedule instead of ours, and
   lets us verify against v2 *before* committing every consumer to it.

The shim is scaffolding, not architecture. When `pyproject.toml` moves to
`mcp>=2`, every `if _V2` here collapses and the module can be inlined
away. Keep it small enough that doing so stays easy — resist adding
anything that is not a genuine v1/v2 difference.

## Accessors, not `getattr` sprinkled everywhere

Call sites use `tool_input_schema(tool)` rather than
`getattr(tool, "input_schema", None) or tool.inputSchema`. The difference
matters: a typo'd attribute in the scattered form silently reads `None`
and a tool's schema quietly becomes empty, which is a validation bypass.
Here it is one function with one test.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from mcp.client.streamable_http import streamable_http_client

__all__ = [
    "MCP_SDK_MAJOR",
    "MODERN_ONLY_RESULT_FIELDS",
    "dump_wire",
    "open_streamable_http",
    "sdk_field",
    "make_mcp_server",
    "server_sse_app",
    "server_streamable_http_app",
    "McpError",
    "make_mcp_error",
    "http_client_module",
    "is_v2",
    "make_tool",
    "read_timeout_arg",
    "result_is_error",
    "set_result_is_error",
    "tool_input_schema",
]


def _detect_major() -> int:
    try:
        return int(version("mcp").split(".", 1)[0])
    except (PackageNotFoundError, ValueError):  # pragma: no cover
        # Unknown install shape: assume v1, which is what `pyproject.toml`
        # pins. Guessing v2 would fail at import; guessing v1 fails at the
        # first attribute access with a readable AttributeError.
        return 1


MCP_SDK_MAJOR: int = _detect_major()


def is_v2() -> bool:
    return MCP_SDK_MAJOR >= 2


# --- Exceptions -------------------------------------------------------------

if MCP_SDK_MAJOR >= 2:
    from mcp import MCPError as McpError  # type: ignore[attr-defined]
else:  # pragma: no cover — exercised on the v1 line, which is the default
    from mcp.shared.exceptions import McpError  # type: ignore[no-redef]


def make_mcp_error(code: int, message: str, data: Any = None) -> Exception:
    """Construct an SDK protocol error on either version.

    v1 takes a single `ErrorData` model; v2 takes the fields directly.
    Neither shape raises anything readable when given the other — v2
    reports a missing positional argument, which does not hint at a
    version mismatch at all.
    """

    if MCP_SDK_MAJOR >= 2:
        return McpError(code=code, message=message, data=data)
    from mcp.types import ErrorData

    return McpError(ErrorData(code=code, message=message, data=data))


# --- Transport HTTP client --------------------------------------------------


def http_client_module() -> Any:
    """The httpx flavour this SDK's transports expect.

    v2 moved to `httpx2`. Passing a v1 `httpx.AsyncClient` into a v2
    transport fails deep inside the connection pool with an error that
    does not mention versions at all, so the two must not be mixed.
    """

    if MCP_SDK_MAJOR >= 2:
        import httpx2  # type: ignore[import-not-found]

        return httpx2
    import httpx

    return httpx


# --- Tool schema ------------------------------------------------------------


def tool_input_schema(tool: Any) -> dict[str, Any]:
    """The tool's JSON-Schema for arguments, on either SDK.

    Returns `{}` rather than None when absent: every caller here feeds it
    to a validator, and `{}` means "no constraints" while `None` means
    "crash".
    """

    schema = getattr(tool, "input_schema", None)
    if schema is None:
        schema = getattr(tool, "inputSchema", None)
    return schema or {}


# v2 snake_cased the schema fields. Written as a map so adding the next
# renamed field is one line and cannot be half-done.
_TOOL_FIELD_V2 = {"input_schema": "input_schema", "output_schema": "output_schema"}
_TOOL_FIELD_V1 = {"input_schema": "inputSchema", "output_schema": "outputSchema"}


def sdk_field(obj: Any, snake_name: str) -> Any:
    """Read a field that v2 snake_cased and v1 spelled in camelCase.

    Call sites always pass the v2 (snake_case) spelling; this finds it
    under either name.

    **Raises `AttributeError` when neither exists**, rather than returning
    None. That is deliberate and is the difference between this and a
    scattered `getattr(o, "a", None) or getattr(o, "b", None)`: a typo in
    the fallback form silently yields None, and a tool schema quietly
    becoming empty is a validation bypass, not a test failure.
    """

    if hasattr(obj, snake_name):
        return getattr(obj, snake_name)
    head, *rest = snake_name.split("_")
    camel = head + "".join(part.title() for part in rest)
    if hasattr(obj, camel):
        return getattr(obj, camel)
    raise AttributeError(
        f"{type(obj).__name__} has neither {snake_name!r} nor {camel!r} "
        f"(MCP SDK major {MCP_SDK_MAJOR})"
    )


def make_tool(
    *,
    name: str,
    input_schema: dict[str, Any],
    output_schema: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Any:
    """Build a `Tool` using this SDK's field names.

    Callers pass snake_case (the v2 spelling) regardless of the installed
    SDK, so call sites read the same either way and only this function
    knows about the rename.
    """

    from mcp.types import Tool

    names = _TOOL_FIELD_V2 if MCP_SDK_MAJOR >= 2 else _TOOL_FIELD_V1
    fields: dict[str, Any] = {names["input_schema"]: input_schema}
    if output_schema is not None:
        fields[names["output_schema"]] = output_schema
    return Tool(name=name, **fields, **kwargs)


# --- Call results -----------------------------------------------------------


def result_is_error(result: Any) -> bool:
    """Did the upstream flag this tool result as an error?

    Defaults to False when neither attribute exists — an unreadable flag
    must not turn a successful call into a failed one. A genuinely
    malformed result surfaces through the envelope path instead.
    """

    flag = getattr(result, "is_error", None)
    if flag is None:
        flag = getattr(result, "isError", None)
    return bool(flag)


def set_result_is_error(result: Any, value: bool) -> None:
    """Set the error flag using whichever field this SDK defines."""

    if hasattr(result, "is_error"):
        result.is_error = value
    else:
        result.isError = value


# --- Timeouts ---------------------------------------------------------------


def read_timeout_arg(seconds: float | None) -> Any:
    """`ClientSession(read_timeout_seconds=...)` takes a `timedelta` on
    v1 and a plain `float` on v2. Passing the wrong one is not a type
    error at call time — v1 silently treats a float as no timeout — so
    this is the kind of difference worth centralising."""

    if seconds is None:
        return None
    if MCP_SDK_MAJOR >= 2:
        return float(seconds)
    return timedelta(seconds=seconds)


# --- Wire serialization -----------------------------------------------------


# Result fields the 2026-07-28 revision introduced. SDK v2 models carry
# them with defaults (`result_type="complete"`), so a plain serialization
# leaks them into LEGACY responses too — telling a 2025-era client we
# speak a revision we are not speaking on that connection.
#
# The dual-era handler adds these back explicitly on the modern path, so
# stripping them at the serialization seam makes that path the ONLY
# source of them. Which is the property worth having: era-specific
# fields should come from era-specific code, not from whatever defaults
# a dependency happens to ship.
MODERN_ONLY_RESULT_FIELDS = frozenset({"resultType", "ttlMs", "cacheScope"})


def dump_wire(model: Any, **kwargs: Any) -> dict[str, Any]:
    """Serialize an SDK model for the JSON-RPC wire.

    **The single most dangerous v1→v2 difference, and the quietest.** v2
    snake_cased the Python attributes but kept the camelCase *wire*
    aliases (`is_error` serializes as `isError`, `input_schema` as
    `inputSchema`). So `model_dump()` — which was correct on v1, where the
    field names already were the wire names — now emits `is_error` and
    `input_schema`, and every MCP client on the far side silently fails to
    see the fields it needs.

    Nothing about that is loud. The gateway returns 200, the JSON looks
    plausible, and a client just behaves as if `isError` were absent.

    `by_alias=True` is the fix and is a **no-op on v1** (verified: the v1
    field names are already the alias values), so this is safe to use
    unconditionally at every wire boundary.

    Use this — never bare `model_dump()` — for anything that reaches an
    MCP client. Our own Pydantic models are unaffected either way, since a
    field with no alias serializes under its own name.
    """

    kwargs.setdefault("mode", "json")
    kwargs.setdefault("exclude_none", True)
    dumped = dict(model.model_dump(by_alias=True, **kwargs))
    # See MODERN_ONLY_RESULT_FIELDS. Callers that genuinely want these
    # (the 2026-07-28 handlers) add them explicitly.
    for field_name in MODERN_ONLY_RESULT_FIELDS:
        dumped.pop(field_name, None)
    return dumped


# --- Transport streams ------------------------------------------------------


@asynccontextmanager
async def open_streamable_http(
    url: str, *, http_client: Any
) -> AsyncIterator[tuple[Any, Any]]:
    """Open a streamable-HTTP transport, yielding `(read, write)`.

    v1 yields a THIRD value — a `get_session_id` callable — which v2
    dropped, because the 2026-07-28 protocol is stateless and has no
    session id to hand back. We never used it, but the arity difference
    is a hard `ValueError: not enough values to unpack` at the call site
    rather than anything that degrades gracefully.

    Normalising here means the two call sites in `outbound.py` stop
    caring, and the day we drop v1 this collapses to a re-export.
    """

    async with streamable_http_client(url, http_client=http_client) as streams:
        yield streams[0], streams[1]


# --- Server side (test fakes only) ------------------------------------------
#
# The gateway never runs an MCP *server* library — it speaks the protocol
# directly in `api/inbound_mcp.py`. Only our tests spin up fake upstreams.
# These two helpers live here anyway, because "which SDK am I on" should
# have exactly one answer in this codebase, and duplicating the branch
# across six test modules is how the answer stops being one.
#
# v2 renamed `FastMCP` to `MCPServer` AND moved `stateless_http` /
# `transport_security` off the constructor onto `streamable_http_app()`.
# The second half is the easy one to miss: constructing succeeds, the
# kwargs are silently accepted as something else or rejected late.


# Transport options that v2 moved from the constructor onto
# `streamable_http_app()`. Accepting them in either place and routing
# them correctly keeps every call site version-agnostic — which is the
# whole job of this module.
_TRANSPORT_KWARGS = ("stateless_http", "transport_security", "json_response")

# Where a v1 server stashes them (its `settings` object) so we can read
# them back when the app is built.
_STASH = "_vyuu_transport_kwargs"


def make_mcp_server(name: str, **kwargs: Any) -> Any:
    """Build the SDK's batteries-included server.

    Transport options may be passed here (the v1 shape) or to
    `server_streamable_http_app` (the v2 shape); this routes them to
    whichever the installed SDK actually wants. Passing them to the wrong
    one is the easy mistake — v2 constructs fine and then ignores them,
    so a test meant to run stateless quietly runs stateful.
    """

    transport = {k: kwargs.pop(k) for k in _TRANSPORT_KWARGS if k in kwargs}
    if MCP_SDK_MAJOR >= 2:
        from mcp.server.mcpserver import MCPServer

        server = MCPServer(name, **kwargs)
    else:
        from mcp.server.fastmcp import FastMCP

        server = FastMCP(name, **transport, **kwargs)
    # Remember them either way: on v2 they are needed at app-build time,
    # and on v1 keeping them lets both call shapes work identically.
    setattr(server, _STASH, transport)
    return server


def server_streamable_http_app(server: Any, **kwargs: Any) -> Any:
    """Build the Starlette app, with transport options wherever this SDK
    expects them. Options given to `make_mcp_server` are carried through."""

    stashed = dict(getattr(server, _STASH, {}))
    stashed.update(kwargs)
    if MCP_SDK_MAJOR >= 2:
        return server.streamable_http_app(**stashed)
    # v1 took them on the constructor. Anything passed only here still
    # has to land, so mirror onto the settings object it exposes.
    settings = getattr(server, "settings", None)
    if settings is not None:
        for key, value in stashed.items():
            if hasattr(settings, key):
                setattr(settings, key, value)
    return server.streamable_http_app()


def server_sse_app(server: Any) -> Any:
    """SSE variant. Present on both SDKs with the same call shape; here
    for symmetry so tests never import the server object's methods
    directly and thus never re-acquire a version dependency."""

    return server.sse_app()
