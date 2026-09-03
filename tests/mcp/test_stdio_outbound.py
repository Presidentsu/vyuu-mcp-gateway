import asyncio
import sys
from pathlib import Path

from vyuu_gateway.db.models import McpCapabilityKind
from vyuu_gateway.mcp.outbound import StdioMcpClient

FAKE_STDIO_SERVER = Path(__file__).with_name("fake_stdio_server.py")


def make_client() -> StdioMcpClient:
    return StdioMcpClient(
        command=sys.executable,
        args=[str(FAKE_STDIO_SERVER)],
        read_timeout_seconds=5.0,
    )


def test_stdio_client_initializes_against_fake_server() -> None:
    async def run() -> None:
        result = await make_client().initialize()

        assert sdk_field(result, "server_info").name == "fake-stdio-server"
        assert sdk_field(result, "protocol_version")

    asyncio.run(run())


def test_stdio_client_lists_tools_resources_and_prompts() -> None:
    async def run() -> None:
        client = make_client()

        tools = await client.list_tools()
        resources = await client.list_resources()
        prompts = await client.list_prompts()

        assert [tool.name for tool in tools] == ["echo"]
        assert sdk_field(tools[0], "input_schema")["properties"]["message"]["type"] == "string"
        assert [str(resource.uri) for resource in resources] == ["config://stdio"]
        assert [prompt.name for prompt in prompts] == ["greet"]

    asyncio.run(run())


def test_stdio_client_calls_tool() -> None:
    async def run() -> None:
        result = await make_client().call_tool("echo", {"message": "hello"})

        assert not sdk_field(result, "is_error")
        assert result.content[0].type == "text"
        assert result.content[0].text == "hello"

    asyncio.run(run())


def test_stdio_client_returns_capability_descriptors() -> None:
    async def run() -> None:
        capabilities = await make_client().list_capabilities()

        assert [(capability.kind, capability.name) for capability in capabilities] == [
            (McpCapabilityKind.TOOL, "echo"),
            (McpCapabilityKind.RESOURCE, "config://stdio"),
            (McpCapabilityKind.PROMPT, "greet"),
        ]
        assert capabilities[0].schema_json["inputSchema"]["properties"]["message"]["type"] == (
            "string"
        )

    asyncio.run(run())


# --- U4: bounded stderr capture on stdio startup failure -------------------


def test_stdio_startup_failure_surfaces_stderr_diagnostic() -> None:
    """A stdio upstream that exits during initialize with a clear stderr
    message (e.g. `falcon-mcp` saying 'Configuration error: API
    credentials not provided') must reach the operator. The default
    /dev/null redirection swallowed it; U4 captures a bounded slice."""
    import pytest

    from vyuu_gateway.mcp.outbound import UpstreamStartupDiagnosticError

    # One-liner Python that mimics a credential-gated upstream: emit a
    # config-error message on stderr, then exit non-zero before any
    # MCP handshake.
    failing = StdioMcpClient(
        command=sys.executable,
        args=[
            "-c",
            (
                "import sys; "
                "sys.stderr.write("
                "'Configuration error: Falcon API credentials not provided. "
                "Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET.\\n'); "
                "sys.exit(1)"
            ),
        ],
        read_timeout_seconds=5.0,
    )

    async def run() -> None:
        with pytest.raises(UpstreamStartupDiagnosticError) as exc_info:
            await failing.initialize()
        diagnostic = exc_info.value
        # The original error class is preserved so operators can still
        # see WHAT kind of failure (McpError / TimeoutError / etc.).
        assert diagnostic.original_error_class
        # The captured stderr is the message the upstream actually wrote.
        assert "Configuration error" in diagnostic.stderr
        assert "FALCON_CLIENT_ID" in diagnostic.stderr
        # Bounded: capped at the buffer's max even if upstream wrote
        # gigabytes. (Trivially satisfied here; cap is enforced by the
        # buffer regardless of how much arrives.)
        assert len(diagnostic.stderr) <= 1024

    asyncio.run(run())


def test_stdio_startup_succeeds_does_not_emit_diagnostic() -> None:
    """The fake stdio server starts cleanly — no diagnostic raised, no
    stderr surfaced. Confirms the capture only fires on failure."""

    async def run() -> None:
        # Healthy server; should NOT raise.
        result = await make_client().initialize()
        assert sdk_field(result, "server_info").name == "fake-stdio-server"

    asyncio.run(run())


def test_sanitize_stderr_caps_at_max_bytes() -> None:
    """Defense against a hostile upstream that writes gigabytes to
    stderr — the sanitizer must cap output regardless of input size."""

    from vyuu_gateway.mcp.outbound import _sanitize_stderr_capture

    assert _sanitize_stderr_capture("a" * 10_000, max_bytes=64) == "a" * 64


def test_sanitize_stderr_strips_ansi_and_control_chars() -> None:
    from vyuu_gateway.mcp.outbound import _sanitize_stderr_capture

    # Realistic CLI output: ANSI red + bell + null byte mixed in.
    raw = "\x1b[31mERROR:\x1b[0m bad config\x07\x00"
    assert _sanitize_stderr_capture(raw) == "ERROR: bad config"


def test_sanitize_stderr_refuses_json_shaped_payload() -> None:
    """If the upstream emitted what looks like a JSON-RPC message on
    stderr (rare but possible — some stdio servers mis-route logs),
    we refuse to surface it. Could leak protocol payload + confuse
    operators about what's tool output vs error."""
    from vyuu_gateway.mcp.outbound import _sanitize_stderr_capture

    assert _sanitize_stderr_capture(
        '{"jsonrpc":"2.0","id":1,"result":{"some":"data"}}'
    ) == ""
    assert _sanitize_stderr_capture("[hello]") == ""


def test_sanitize_stderr_handles_empty_input() -> None:
    """Healthy upstream wrote nothing — sanitizer returns empty (caller
    won't raise UpstreamStartupDiagnosticError)."""
    from vyuu_gateway.mcp.outbound import _sanitize_stderr_capture

    assert _sanitize_stderr_capture("") == ""


# =========================================================================
# Tier-2 stress-test fix: persistent stdio subprocess
# =========================================================================
#
# The previous (cold-spawn) implementation forked a new uvx/npx
# subprocess per `call_tool` — capping per-server RPS at ~5. The
# rewrite holds the subprocess + ClientSession across calls. These
# tests verify the public-API contract AND the persistence invariant:
# subprocess count stays at 1 across many calls, concurrent calls
# multiplex correctly, subprocess death is detected, aclose() actually
# terminates the process.


def _supervisor_task_count() -> int:
    """Count `stdio-supervisor:*` tasks. Used to confirm one process
    per StdioMcpClient instance (vs the prior N-process-per-N-calls)."""
    return sum(
        1 for t in asyncio.all_tasks()
        if (t.get_name() or "").startswith("stdio-supervisor:")
    )


def test_stdio_client_persists_subprocess_across_many_calls() -> None:
    """Make 50 sequential tool calls; the supervisor task (and thus
    the subprocess it owns) must be the SAME instance throughout —
    no per-call spawn/teardown."""
    async def run() -> None:
        client = make_client()
        # First call triggers connect.
        await client.call_tool("echo", {"message": "warm-1"})
        assert _supervisor_task_count() == 1
        first_supervisor = client._supervisor
        first_session = client._session
        # Subsequent calls reuse the same session.
        for i in range(49):
            result = await client.call_tool("echo", {"message": f"call-{i}"})
            assert not sdk_field(result, "is_error")
            block = result.content[0]
            assert getattr(block, "text", None) == f"call-{i}"
        # Supervisor + session unchanged across all 50 calls.
        assert client._supervisor is first_supervisor
        assert client._session is first_session
        await client.aclose()
        assert _supervisor_task_count() == 0

    asyncio.run(run())


def test_stdio_client_concurrent_calls_multiplex_one_subprocess() -> None:
    """Many concurrent `call_tool` invocations on one client must all
    succeed using the same persistent subprocess. The MCP SDK's session
    demuxes responses by JSON-RPC id — we just need to verify the
    gateway-side wrapper doesn't serialize them artificially."""
    async def run() -> None:
        client = make_client()
        # Connect explicitly so we know the supervisor exists by the
        # time we fan out concurrent calls.
        await client.connect()
        assert _supervisor_task_count() == 1

        async def call(i: int) -> str:
            result = await client.call_tool("echo", {"message": f"msg-{i}"})
            assert not sdk_field(result, "is_error")
            block = result.content[0]
            text = getattr(block, "text", None)
            assert isinstance(text, str)
            return text

        # 20 concurrent calls. With cold-spawn this would have spawned
        # 20 subprocesses; with persistence, still 1.
        results = await asyncio.gather(*(call(i) for i in range(20)))
        assert sorted(results) == sorted(f"msg-{i}" for i in range(20))
        assert _supervisor_task_count() == 1  # still just the one
        await client.aclose()

    asyncio.run(run())


def test_stdio_client_aclose_terminates_subprocess() -> None:
    """`aclose()` must actually kill the subprocess (the prior
    implementation's docstring described it as a no-op). After
    aclose(), supervisor task is gone and any further call raises."""
    import pytest

    from vyuu_gateway.mcp.outbound import UpstreamClientBrokenError

    async def run() -> None:
        client = make_client()
        await client.connect()
        assert _supervisor_task_count() == 1

        await client.aclose()
        # Supervisor task has exited (cleanly).
        assert _supervisor_task_count() == 0
        # Idempotent — second aclose is a no-op.
        await client.aclose()
        # Further use raises so the pool's discard path constructs
        # a fresh client.
        with pytest.raises(UpstreamClientBrokenError):
            await client.call_tool("echo", {"message": "x"})

    asyncio.run(run())


def test_stdio_client_recovers_via_pool_after_subprocess_death() -> None:
    """If the subprocess dies mid-session (host kill, OOM, upstream
    crash), the next call surfaces the underlying exception and the
    client marks itself broken. The pool's release-with-discard
    flow then closes the client; a fresh client gets constructed
    on the next acquire (cold-spawn paid once, then back to warm).

    We simulate subprocess death by cancelling the supervisor task
    directly — anyio unwinds the stdio_client context which sends
    SIGTERM to the subprocess.
    """
    import pytest

    async def run() -> None:
        client = make_client()
        # Healthy call.
        result = await client.call_tool("echo", {"message": "alive"})
        assert not sdk_field(result, "is_error")
        # Simulate subprocess death by cancelling the supervisor.
        # Real-world equivalent: subprocess SIGSEGV, host OOM-kill,
        # uvx package version mismatch causing exit, etc.
        supervisor = client._supervisor
        assert supervisor is not None
        supervisor.cancel()
        try:
            await supervisor
        except (asyncio.CancelledError, Exception):
            pass
        # Next call should fail (broken client). The exact exception
        # depends on the SDK's stream-closed handling — accept any
        # raised Exception, the gateway pool catches BaseException.
        with pytest.raises(Exception):  # noqa: B017 — see comment above
            await client.call_tool("echo", {"message": "after-death"})
        # Client is now closed (broken).
        assert client._closed is True
        # Cleanup is idempotent.
        await client.aclose()

    asyncio.run(run())


def test_stdio_client_initialize_caches_after_first_connect() -> None:
    """`initialize()` historically cold-spawned a fresh subprocess to
    do the handshake. With persistence, calling `initialize()` after
    the supervisor is up returns the cached InitializeResult without
    spawning a new process — single source of truth for server info."""
    async def run() -> None:
        client = make_client()
        first = await client.initialize()
        second = await client.initialize()
        third = await client.connect()  # alias for initialize
        # All three return the same logical result (cached). Exact
        # object identity not guaranteed (SDK may construct fresh
        # InitializeResult per session) but server name + protocol
        # version must match.
        assert sdk_field(first, "server_info").name == "fake-stdio-server"
        assert sdk_field(second, "server_info").name == sdk_field(first, "server_info").name
        assert sdk_field(third, "server_info").name == sdk_field(first, "server_info").name
        # Still only one supervisor / subprocess.
        assert _supervisor_task_count() == 1
        await client.aclose()

    asyncio.run(run())


def test_stdio_client_list_capabilities_warms_session_once() -> None:
    """Capability sync calls `list_capabilities()` which internally
    runs three list_* calls. With persistence all three multiplex
    through one session — no per-call subprocess spawn."""
    async def run() -> None:
        client = make_client()
        caps = await client.list_capabilities()
        # Same shape as the existing capability test.
        names = [(c.kind, c.name) for c in caps]
        assert (McpCapabilityKind.TOOL, "echo") in names
        # One supervisor, one subprocess.
        assert _supervisor_task_count() == 1
        # Second call reuses the session.
        caps2 = await client.list_capabilities()
        assert [(c.kind, c.name) for c in caps2] == names
        assert _supervisor_task_count() == 1
        await client.aclose()

    asyncio.run(run())


# Re-import to expose to the new tests above without polluting the top
# of the file.
from vyuu_gateway.db.models import McpCapabilityKind  # noqa: E402, F811
from vyuu_gateway.mcp.sdk_compat import sdk_field  # noqa: E402
