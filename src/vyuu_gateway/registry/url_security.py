"""URL security checks for HTTP MCP server registration.

Registration accepts operator-supplied URLs that the gateway will later open
outbound connections to. Without guardrails, an operator (or a compromised
operator account) could register URLs pointing at the gateway's own loopback,
internal RFC1918 addresses, link-local cloud metadata services, or non-HTTP
schemes the upstream MCP client could be coerced into dereferencing. These
checks reject those targets before they enter the registry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from ipaddress import IPv4Address, IPv6Address, ip_address
from urllib.parse import urlparse

ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

# Hostname literals that resolve to local or cloud-metadata services. Covered
# in addition to IP-literal checks because an operator could pass a name rather
# than an IP and we do not perform DNS resolution at registration time.
BLOCKED_HOSTNAMES: frozenset[str] = frozenset(
    {
        "localhost",
        "ip6-localhost",
        "ip6-loopback",
        # AWS / Azure / GCP / OCI / Alibaba metadata service hostnames.
        "metadata.google.internal",
        "metadata.goog",
        "metadata.azure.com",
        "metadata.oraclecloud.com",
        "100.100.100.200",
    }
)


class HttpUrlSecurityError(ValueError):
    """Base error raised when an HTTP source URL is rejected."""


class UnsafeUrlSchemeError(HttpUrlSecurityError):
    """URL uses a scheme other than http or https."""


class MalformedUrlError(HttpUrlSecurityError):
    """URL parse failed or has no host component."""


class BlockedHostError(HttpUrlSecurityError):
    """URL host resolves to a loopback, private, link-local, or metadata target."""


class HostDeniedByConfigError(HttpUrlSecurityError):
    """URL host matches the operator-configured denylist."""


@dataclass(frozen=True)
class UrlSecurityPolicy:
    """Operator-configured URL policy applied at registration time."""

    allow_private_networks: bool = False
    allowlist: tuple[str, ...] = field(default_factory=tuple)
    denylist: tuple[str, ...] = field(default_factory=tuple)


def validate_http_source_url(url: str, policy: UrlSecurityPolicy) -> None:
    """Raise HttpUrlSecurityError if the URL is unsafe under the given policy.

    Order: scheme check, denylist (always wins), allowlist (bypasses
    private-network block), hostname literal block, IP literal block.
    """

    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeUrlSchemeError(
            f"url scheme {parsed.scheme!r} is not allowed; use http or https"
        )

    host = parsed.hostname
    if not host:
        raise MalformedUrlError("url has no host component")
    host = host.lower()

    if _matches_any(host, policy.denylist):
        raise HostDeniedByConfigError(f"host {host!r} is denied by configuration")

    allowlisted = _matches_any(host, policy.allowlist)
    if allowlisted:
        return

    if host in BLOCKED_HOSTNAMES:
        raise BlockedHostError(f"host {host!r} resolves to a local or metadata service")

    ip = _parse_ip_literal(host)
    if ip is not None and _is_unsafe_ip(ip) and not policy.allow_private_networks:
        raise BlockedHostError(
            f"host {host!r} is in a loopback, private, or link-local range"
        )


def _matches_any(host: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatchcase(host, pattern.lower()) for pattern in patterns)


def _parse_ip_literal(host: str) -> IPv4Address | IPv6Address | None:
    candidate = host
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return ip_address(candidate)
    except ValueError:
        return None


def _is_unsafe_ip(ip: IPv4Address | IPv6Address) -> bool:
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        return _is_unsafe_ip(ip.ipv4_mapped)
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
    )
