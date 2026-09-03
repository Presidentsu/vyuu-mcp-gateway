import pytest

from vyuu_gateway.registry.url_security import (
    BlockedHostError,
    HostDeniedByConfigError,
    MalformedUrlError,
    UnsafeUrlSchemeError,
    UrlSecurityPolicy,
    validate_http_source_url,
)

DEFAULT_POLICY = UrlSecurityPolicy()


def test_public_https_url_is_allowed() -> None:
    validate_http_source_url("https://mcp.example.com/mcp", DEFAULT_POLICY)


def test_public_http_url_is_allowed() -> None:
    validate_http_source_url("http://mcp.example.com:8080/sse", DEFAULT_POLICY)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://internal.example/",
        "ftp://files.example.com/",
        "ws://socket.example.com/",
        "data:text/plain,hello",
        "javascript:alert(1)",
    ],
)
def test_non_http_schemes_are_rejected(url: str) -> None:
    with pytest.raises(UnsafeUrlSchemeError):
        validate_http_source_url(url, DEFAULT_POLICY)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/mcp",
        "http://LOCALHOST/mcp",
        "http://localhost:9000/mcp",
        "http://ip6-localhost/mcp",
        "http://ip6-loopback/mcp",
    ],
)
def test_localhost_hostnames_are_blocked(url: str) -> None:
    with pytest.raises(BlockedHostError):
        validate_http_source_url(url, DEFAULT_POLICY)


@pytest.mark.parametrize(
    "url",
    [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.goog/",
        "http://metadata.azure.com/",
        "http://metadata.oraclecloud.com/",
        "http://100.100.100.200/latest/meta-data/",
    ],
)
def test_cloud_metadata_hostnames_are_blocked(url: str) -> None:
    with pytest.raises(BlockedHostError):
        validate_http_source_url(url, DEFAULT_POLICY)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/mcp",
        "http://127.0.0.1:8080/mcp",
        "http://127.5.6.7/mcp",
    ],
)
def test_ipv4_loopback_is_blocked(url: str) -> None:
    with pytest.raises(BlockedHostError):
        validate_http_source_url(url, DEFAULT_POLICY)


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.0.1/mcp",
        "http://10.255.255.254/mcp",
        "http://172.16.0.1/mcp",
        "http://172.31.255.254/mcp",
        "http://192.168.0.1/mcp",
        "http://192.168.1.100/mcp",
    ],
)
def test_rfc1918_private_ranges_are_blocked(url: str) -> None:
    with pytest.raises(BlockedHostError):
        validate_http_source_url(url, DEFAULT_POLICY)


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.0.1/mcp",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.255.254/mcp",
    ],
)
def test_ipv4_link_local_and_aws_metadata_are_blocked(url: str) -> None:
    with pytest.raises(BlockedHostError):
        validate_http_source_url(url, DEFAULT_POLICY)


def test_unspecified_ipv4_is_blocked() -> None:
    with pytest.raises(BlockedHostError):
        validate_http_source_url("http://0.0.0.0/mcp", DEFAULT_POLICY)


@pytest.mark.parametrize(
    "url",
    [
        "http://[::1]/mcp",
        "http://[::1]:9000/mcp",
    ],
)
def test_ipv6_loopback_is_blocked(url: str) -> None:
    with pytest.raises(BlockedHostError):
        validate_http_source_url(url, DEFAULT_POLICY)


@pytest.mark.parametrize(
    "url",
    [
        "http://[fe80::1]/mcp",
        "http://[fe80::abcd:1234]/mcp",
    ],
)
def test_ipv6_link_local_is_blocked(url: str) -> None:
    with pytest.raises(BlockedHostError):
        validate_http_source_url(url, DEFAULT_POLICY)


@pytest.mark.parametrize(
    "url",
    [
        "http://[fc00::1]/mcp",
        "http://[fd00::1]/mcp",
    ],
)
def test_ipv6_unique_local_is_blocked(url: str) -> None:
    with pytest.raises(BlockedHostError):
        validate_http_source_url(url, DEFAULT_POLICY)


def test_ipv4_mapped_ipv6_loopback_is_blocked() -> None:
    with pytest.raises(BlockedHostError):
        validate_http_source_url("http://[::ffff:127.0.0.1]/mcp", DEFAULT_POLICY)


def test_ipv4_mapped_ipv6_rfc1918_is_blocked() -> None:
    with pytest.raises(BlockedHostError):
        validate_http_source_url("http://[::ffff:10.0.0.1]/mcp", DEFAULT_POLICY)


def test_url_without_host_is_rejected() -> None:
    with pytest.raises(MalformedUrlError):
        validate_http_source_url("http:///path-only", DEFAULT_POLICY)


def test_allow_private_networks_permits_loopback() -> None:
    policy = UrlSecurityPolicy(allow_private_networks=True)
    validate_http_source_url("http://127.0.0.1/mcp", policy)


def test_allow_private_networks_permits_rfc1918() -> None:
    policy = UrlSecurityPolicy(allow_private_networks=True)
    validate_http_source_url("http://10.0.0.5/mcp", policy)


def test_allow_private_networks_does_not_bypass_metadata_hostname() -> None:
    policy = UrlSecurityPolicy(allow_private_networks=True)
    with pytest.raises(BlockedHostError):
        validate_http_source_url(
            "http://metadata.google.internal/computeMetadata/v1/",
            policy,
        )


def test_allow_private_networks_does_not_bypass_localhost_hostname() -> None:
    policy = UrlSecurityPolicy(allow_private_networks=True)
    with pytest.raises(BlockedHostError):
        validate_http_source_url("http://localhost/mcp", policy)


def test_allowlist_overrides_private_network_block() -> None:
    policy = UrlSecurityPolicy(allowlist=("internal-mcp.lan",))
    validate_http_source_url("http://internal-mcp.lan/mcp", policy)


def test_allowlist_overrides_localhost_block() -> None:
    policy = UrlSecurityPolicy(allowlist=("localhost",))
    validate_http_source_url("http://localhost:9000/mcp", policy)


def test_allowlist_glob_pattern_matches_subdomains() -> None:
    policy = UrlSecurityPolicy(allowlist=("*.internal.example",))
    validate_http_source_url("http://mcp-1.internal.example/mcp", policy)


def test_denylist_blocks_otherwise_public_url() -> None:
    policy = UrlSecurityPolicy(denylist=("evil.example.com",))
    with pytest.raises(HostDeniedByConfigError):
        validate_http_source_url("https://evil.example.com/mcp", policy)


def test_denylist_glob_pattern_matches_subdomains() -> None:
    policy = UrlSecurityPolicy(denylist=("*.evil.example.com",))
    with pytest.raises(HostDeniedByConfigError):
        validate_http_source_url("https://api.evil.example.com/mcp", policy)


def test_denylist_takes_precedence_over_allowlist() -> None:
    policy = UrlSecurityPolicy(
        allowlist=("evil.example.com",),
        denylist=("evil.example.com",),
    )
    with pytest.raises(HostDeniedByConfigError):
        validate_http_source_url("https://evil.example.com/mcp", policy)


def test_allowlist_does_not_relax_scheme_check() -> None:
    policy = UrlSecurityPolicy(allowlist=("internal.example",))
    with pytest.raises(UnsafeUrlSchemeError):
        validate_http_source_url("file://internal.example/etc/passwd", policy)
