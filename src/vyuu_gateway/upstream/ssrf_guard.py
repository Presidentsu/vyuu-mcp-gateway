"""H1 · DNS-time SSRF backstop for outbound upstream connections.

`registry/url_security.py` checks a URL at **registration**: scheme,
denylist/allowlist, blocked hostname literals, and unsafe IP literals.
That stops the obvious cases, but it cannot stop the interesting one — a
hostname that passes registration because it is not an IP literal, and
then *resolves* to a private address at call time. `mcp.evil.test`
pointing at `169.254.169.254` sails through registration untouched.

This module closes that at the moment it matters: immediately before the
socket is opened.

## Resolve, validate, and PIN

Checking DNS and then letting httpx resolve again is not a fix — it is a
TOCTOU race, and DNS rebinding exists precisely to win it. An attacker
answers the first lookup with a public address and the second with
`127.0.0.1`.

So `SsrfGuardTransport` resolves once, validates **every** address the
resolver returned, then rewrites the request to connect to the address it
validated. TLS still works and still verifies the real certificate: the
original hostname rides along as the `Host` header and as httpx's
`sni_hostname` extension, which httpcore uses as `server_hostname` for
both SNI and certificate validation. The connection therefore goes to an
address we checked, while the certificate is checked against the name the
operator registered.

## Every address, not the first

If a hostname resolves to one public and one private address, taking the
first would let an attacker win by ordering. Any unsafe address in the
answer rejects the whole name.

## Policy is shared with registration

The same `UrlSecurityPolicy` governs both, so a deployment that allows
private networks (or allowlists a host) at registration behaves
identically here. There is deliberately no second, connect-time-only set
of knobs to keep in sync.

## Known limits

- **Not a defence against a compromised resolver.** If DNS itself lies,
  we validate and pin to the lie. Pinning bounds the damage to one
  answer rather than two, but the answer is still the resolver's.
- **Redirects are re-checked** only because httpx issues each hop as a
  fresh request through this transport. If you replace the transport
  stack, that property has to be preserved.
- **Adds one `getaddrinfo` per connection attempt.** It runs on a worker
  thread so it never blocks the event loop, and in practice hits the OS
  resolver cache.
"""

from __future__ import annotations

import logging
import socket
from ipaddress import IPv4Address, IPv6Address, ip_address

import anyio.to_thread
import httpx

from vyuu_gateway.registry.url_security import (
    BLOCKED_HOSTNAMES,
    UrlSecurityPolicy,
    _is_unsafe_ip,
    _matches_any,
)

logger = logging.getLogger(__name__)


class UpstreamAddressBlockedError(httpx.TransportError):
    """The upstream host resolved to an address we refuse to connect to.

    Subclasses `httpx.TransportError` so it travels the same path as any
    other connection failure — the MCP client's error envelope, the
    circuit breaker, and the audit event all treat it as an upstream
    error without needing to know about SSRF specifically.
    """


def _remedy(host: str) -> str:
    """Every rejection says what to do about it. An operator whose
    internal MCP server just stopped connecting after an upgrade should
    not have to read the source to find the escape hatch."""

    return (
        f"If {host!r} is a legitimate internal upstream, allow it explicitly: "
        f"set VYUU_HTTP_URL_ALLOWLIST to include it, or "
        f"VYUU_HTTP_URL_ALLOW_PRIVATE_NETWORKS=true to permit private ranges."
    )


async def resolve_and_validate(
    host: str,
    port: int,
    *,
    policy: UrlSecurityPolicy,
) -> str:
    """Resolve `host` and return one validated address literal to connect to.

    Raises `UpstreamAddressBlockedError` if the host is denied outright or
    if **any** resolved address is loopback / private / link-local /
    metadata. Returns the host unchanged when it is already a safe IP
    literal or is allowlisted (nothing to pin, nothing to check).
    """

    lowered = host.lower()

    # Denylist wins over everything, exactly as at registration.
    if _matches_any(lowered, policy.denylist):
        raise UpstreamAddressBlockedError(
            f"upstream host {host!r} is denied by configuration"
        )

    # An allowlisted host is a deliberate operator decision — including,
    # legitimately, an internal one. Skip resolution entirely rather than
    # re-litigating it here; that is what the allowlist is for.
    if _matches_any(lowered, policy.allowlist):
        return host

    if lowered in BLOCKED_HOSTNAMES:
        raise UpstreamAddressBlockedError(
            f"upstream host {host!r} is a local or cloud-metadata service"
        )

    literal = _as_ip_literal(lowered)
    if literal is not None:
        if _is_unsafe_ip(literal) and not policy.allow_private_networks:
            raise UpstreamAddressBlockedError(
                f"upstream address {host!r} is loopback, private, link-local, "
                f"or reserved. {_remedy(host)}"
            )
        return host

    try:
        # On a worker thread: getaddrinfo is blocking and can take
        # seconds on a slow resolver.
        infos = await anyio.to_thread.run_sync(
            lambda: socket.getaddrinfo(lowered, port, proto=socket.IPPROTO_TCP)
        )
    except OSError as exc:
        raise UpstreamAddressBlockedError(
            f"could not resolve upstream host {host!r}: {exc}"
        ) from exc

    resolved: list[IPv4Address | IPv6Address] = []
    for info in infos:
        sockaddr = info[4]
        try:
            resolved.append(ip_address(sockaddr[0]))
        except ValueError:  # pragma: no cover — getaddrinfo returns literals
            continue
    if not resolved:
        raise UpstreamAddressBlockedError(
            f"upstream host {host!r} resolved to no usable address"
        )

    if not policy.allow_private_networks:
        # ANY unsafe answer rejects the whole name — see module docstring.
        for candidate in resolved:
            if _is_unsafe_ip(candidate):
                logger.warning(
                    "upstream_ssrf_blocked host=%s resolved=%s",
                    host,
                    candidate,
                )
                raise UpstreamAddressBlockedError(
                    f"upstream host {host!r} resolves to {candidate}, which is "
                    f"loopback, private, link-local, or reserved. {_remedy(host)}"
                )

    return str(resolved[0])


def _as_ip_literal(host: str) -> IPv4Address | IPv6Address | None:
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        return ip_address(candidate)
    except ValueError:
        return None


class SsrfGuardTransport(httpx.AsyncBaseTransport):
    """Wraps another transport, validating and pinning the destination.

    Composes rather than subclasses `AsyncHTTPTransport` so it can sit in
    front of whatever transport the caller already configured — including
    the mTLS-configured one, and including `ASGITransport` in tests
    (where it is a no-op passthrough for the in-process host).
    """

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport,
        *,
        policy: UrlSecurityPolicy,
    ) -> None:
        self._inner = inner
        self._policy = policy

    async def handle_async_request(
        self, request: httpx.Request
    ) -> httpx.Response:
        host = request.url.host
        if not host:
            return await self._inner.handle_async_request(request)

        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        validated = await resolve_and_validate(host, port, policy=self._policy)

        if validated != host:
            # Pin to the address we just checked. `Host` keeps the origin
            # server routing correctly (name-based vhosts), and
            # `sni_hostname` keeps TLS SNI + certificate validation on the
            # real name rather than the bare IP.
            original_host_header = request.headers.get("host") or _host_header(
                host, request.url.port
            )
            request.url = request.url.copy_with(host=validated)
            request.headers["Host"] = original_host_header
            request.extensions = {**request.extensions, "sni_hostname": host}

        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


def _host_header(host: str, port: int | None) -> str:
    """RFC 9110 Host: bracket IPv6 literals, omit the default port."""
    bracketed = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{bracketed}:{port}" if port is not None else bracketed
