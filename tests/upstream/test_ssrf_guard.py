"""H1 · DNS-time SSRF backstop (`upstream/ssrf_guard.py`).

`registry/url_security.py` checks the URL at registration and cannot see
what a hostname resolves to at call time. These tests cover the gap it
leaves: a name that passes registration because it is not an IP literal,
then resolves to something internal when the gateway dials it.

The two that matter most:

- `test_hostname_resolving_to_metadata_ip_is_blocked` — the actual attack
  (`mcp.evil.test` → `169.254.169.254`), which registration lets through.
- `test_connection_is_pinned_to_the_validated_address` — resolve-then-let-
  httpx-resolve-again is a TOCTOU race, and DNS rebinding exists to win
  it. This proves the socket goes to the address we checked, with the
  original hostname preserved for `Host` and TLS SNI.

DNS is stubbed rather than relying on a real resolver: these must be
deterministic and must not need network access.
"""

from __future__ import annotations

import socket
from typing import Any

import anyio
import httpx
import pytest

from vyuu_gateway.registry.url_security import UrlSecurityPolicy
from vyuu_gateway.upstream.ssrf_guard import (
    SsrfGuardTransport,
    UpstreamAddressBlockedError,
    resolve_and_validate,
)

DEFAULT = UrlSecurityPolicy()


def _stub_dns(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, list[str]]) -> None:
    """Replace getaddrinfo with a fixed table, in getaddrinfo's own
    5-tuple shape so the code under test is exercised as written."""

    def fake(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        if host not in mapping:
            raise OSError(f"nodename nor servname provided: {host}")
        return [
            (
                socket.AF_INET6 if ":" in addr else socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (addr, port),
            )
            for addr in mapping[host]
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake)


def _resolve(host: str, port: int, policy: UrlSecurityPolicy) -> str:
    """`anyio.run` forwards positional args only, so keyword-only
    `policy` needs a closure."""
    return anyio.run(lambda: resolve_and_validate(host, port, policy=policy))


# --- The gap registration leaves ------------------------------------------


def test_hostname_resolving_to_metadata_ip_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`mcp.evil.test` is not an IP literal and not in BLOCKED_HOSTNAMES,
    so `validate_http_source_url` accepts it at registration. This is the
    only layer that sees where it actually points."""

    from vyuu_gateway.registry.url_security import validate_http_source_url

    # Precondition: registration really does let this through.
    validate_http_source_url("https://mcp.evil.test/mcp", DEFAULT)

    _stub_dns(monkeypatch, {"mcp.evil.test": ["169.254.169.254"]})
    with pytest.raises(UpstreamAddressBlockedError) as exc:
        _resolve("mcp.evil.test", 443, DEFAULT)
    assert "169.254.169.254" in str(exc.value)
    # Every rejection names the escape hatch.
    assert "VYUU_HTTP_URL_ALLOW_PRIVATE_NETWORKS" in str(exc.value)


@pytest.mark.parametrize(
    "addr",
    ["127.0.0.1", "10.1.2.3", "192.168.1.5", "172.16.0.9", "169.254.169.254",
     "0.0.0.0", "::1", "fd00::1"],
)
def test_private_and_loopback_answers_are_blocked(
    monkeypatch: pytest.MonkeyPatch, addr: str
) -> None:
    _stub_dns(monkeypatch, {"h.test": [addr]})
    with pytest.raises(UpstreamAddressBlockedError):
        _resolve("h.test", 443, DEFAULT)


def test_any_unsafe_answer_rejects_the_whole_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A name resolving to one public and one private address must be
    rejected. Taking the first answer would let an attacker win by
    controlling record order."""

    _stub_dns(monkeypatch, {"mixed.test": ["93.184.216.34", "127.0.0.1"]})
    with pytest.raises(UpstreamAddressBlockedError):
        _resolve("mixed.test", 443, DEFAULT)

    # ...and the reverse order, so this is not an artefact of ordering.
    _stub_dns(monkeypatch, {"mixed.test": ["127.0.0.1", "93.184.216.34"]})
    with pytest.raises(UpstreamAddressBlockedError):
        _resolve("mixed.test", 443, DEFAULT)


def test_public_address_is_allowed_and_returned_for_pinning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_dns(monkeypatch, {"good.test": ["93.184.216.34"]})
    out = _resolve("good.test", 443, DEFAULT)
    assert out == "93.184.216.34"


# --- Policy is shared with registration ------------------------------------


def test_allowlisted_host_skips_resolution_entirely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An allowlisted host is a deliberate operator decision — including,
    legitimately, an internal one. Re-litigating it here would make the
    allowlist mean something different at connect time than at
    registration time."""

    def explode(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("allowlisted host must not be resolved")

    monkeypatch.setattr(socket, "getaddrinfo", explode)
    policy = UrlSecurityPolicy(allowlist=("internal.corp",))
    assert _resolve("internal.corp", 443, policy) == "internal.corp"


def test_denylist_wins_over_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = UrlSecurityPolicy(
        allowlist=("*.corp",), denylist=("secret.corp",)
    )
    with pytest.raises(UpstreamAddressBlockedError):
        _resolve("secret.corp", 443, policy)


def test_allow_private_networks_permits_internal_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_dns(monkeypatch, {"internal.test": ["10.0.0.5"]})
    policy = UrlSecurityPolicy(allow_private_networks=True)
    assert _resolve("internal.test", 443, policy) == "10.0.0.5"


def test_unresolvable_host_is_blocked_not_passed_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail closed. A resolution failure must not fall through to letting
    httpx try its own lookup."""

    _stub_dns(monkeypatch, {})
    with pytest.raises(UpstreamAddressBlockedError):
        _resolve("nx.test", 443, DEFAULT)


def test_safe_ip_literal_needs_no_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("IP literal must not be resolved")

    monkeypatch.setattr(socket, "getaddrinfo", explode)
    assert _resolve("93.184.216.34", 443, DEFAULT) == "93.184.216.34"


def test_unsafe_ip_literal_is_blocked_at_connect_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Belt and braces with registration: a row already in the DB from
    before the check existed still cannot be dialled."""

    with pytest.raises(UpstreamAddressBlockedError):
        _resolve("127.0.0.1", 443, DEFAULT)


# --- The transport: pinning --------------------------------------------------


class _RecordingTransport(httpx.AsyncBaseTransport):
    """Captures the request as it would hit the socket."""

    def __init__(self) -> None:
        self.seen: httpx.Request | None = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.seen = request
        return httpx.Response(200, text="ok")


def test_connection_is_pinned_to_the_validated_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validate-then-reresolve is a TOCTOU race. The request that reaches
    the socket must target the address we checked — while keeping the
    original hostname for `Host` and TLS SNI, so certificate validation
    still runs against the real name and not a bare IP."""

    _stub_dns(monkeypatch, {"good.test": ["93.184.216.34"]})
    inner = _RecordingTransport()
    guard = SsrfGuardTransport(inner, policy=DEFAULT)

    async def go() -> httpx.Response:
        async with httpx.AsyncClient(transport=guard) as client:
            return await client.get("https://good.test/mcp")

    resp = anyio.run(go)
    assert resp.status_code == 200
    assert inner.seen is not None
    # Socket goes to the checked address...
    assert inner.seen.url.host == "93.184.216.34"
    # ...while the origin server and the TLS stack still see the name.
    assert inner.seen.headers["Host"] == "good.test"
    assert inner.seen.extensions.get("sni_hostname") == "good.test"
    assert inner.seen.url.path == "/mcp"


def test_transport_blocks_before_the_socket_is_opened(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_dns(monkeypatch, {"evil.test": ["169.254.169.254"]})
    inner = _RecordingTransport()
    guard = SsrfGuardTransport(inner, policy=DEFAULT)

    async def go() -> None:
        async with httpx.AsyncClient(transport=guard) as client:
            await client.get("https://evil.test/mcp")

    with pytest.raises(UpstreamAddressBlockedError):
        anyio.run(go)
    assert inner.seen is None, "request reached the inner transport"


def test_blocked_error_is_an_httpx_transport_error() -> None:
    """So it travels the existing upstream-failure path — error envelope,
    circuit breaker, audit event — without any of them needing to know
    about SSRF specifically."""

    assert issubclass(UpstreamAddressBlockedError, httpx.TransportError)


def test_ipv6_answer_is_pinned_with_correct_bracketing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real hosts do resolve to IPv6 (the lab's own `mcp.draw.io` does).
    A bare `2606:...` in a URL is ambiguous with the port separator, so
    the literal has to end up bracketed — otherwise the request silently
    targets a mangled host."""

    _stub_dns(monkeypatch, {"v6.test": ["2606:4700::1111"]})
    inner = _RecordingTransport()
    guard = SsrfGuardTransport(inner, policy=DEFAULT)

    async def go() -> httpx.Response:
        async with httpx.AsyncClient(transport=guard) as client:
            return await client.get("https://v6.test:8443/mcp")

    assert anyio.run(go).status_code == 200
    assert inner.seen is not None
    assert inner.seen.url.host == "2606:4700::1111"
    # httpx brackets IPv6 hosts when rendering the URL.
    assert "[2606:4700::1111]:8443" in str(inner.seen.url)
    # Host header keeps the original name + non-default port.
    assert inner.seen.headers["Host"] == "v6.test:8443"
    assert inner.seen.extensions.get("sni_hostname") == "v6.test"
