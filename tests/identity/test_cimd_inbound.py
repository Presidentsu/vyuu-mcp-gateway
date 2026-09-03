"""MCP-2 P3 · inbound CIMD resolution.

The module under test performs a server-side fetch of a URL that arrives
in a request, so most of these tests are about the *bounds* on that fetch
rather than the happy path: the SSRF guard being unskippable, redirects
refused, the size cap applied before the body is buffered, and answers
cached so the endpoint cannot be used to amplify traffic at a third
party.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from vyuu_gateway.identity.cimd_inbound import (
    CimdResolutionError,
    InboundCimdResolver,
    is_cimd_client_id,
)
from vyuu_gateway.registry.url_security import UrlSecurityPolicy

CLIENT_ID = "https://client.example/.well-known/oauth-client"

# `client.example` does not resolve, and the SSRF guard runs on every
# fetch by construction. Allowlisting it is how a test reaches the mock
# transport at all — which is itself evidence the guard is not optional.
POLICY = UrlSecurityPolicy(allowlist=("client.example",))


def _document(**overrides: object) -> dict[str, object]:
    doc: dict[str, object] = {
        "client_id": CLIENT_ID,
        "client_name": "Acme Desktop",
        "client_uri": "https://client.example",
        "redirect_uris": ["https://client.example/callback"],
    }
    doc.update(overrides)
    return doc


def _transport(
    handler: object = None, *, calls: list[httpx.Request] | None = None
) -> httpx.MockTransport:
    def _default(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_document())

    inner = handler or _default

    def _record(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        return inner(request)  # type: ignore[operator]

    return httpx.MockTransport(_record)


# --- what counts as a CIMD client_id --------------------------------------


def test_only_https_urls_are_cimd_client_ids() -> None:
    assert is_cimd_client_id(CLIENT_ID) is True
    # http is excluded rather than upgraded: control of an http URL is
    # control of the network, which is not the client.
    assert is_cimd_client_id("http://client.example/.well-known/oauth-client") is False
    assert is_cimd_client_id("acme-desktop") is False
    assert is_cimd_client_id("https://") is False


# --- the happy path -------------------------------------------------------


def test_resolves_a_document_and_returns_the_client_name() -> None:
    resolver = InboundCimdResolver(policy=POLICY, transport=_transport())
    identity = asyncio.run(resolver.resolve(CLIENT_ID))
    assert identity.client_id == CLIENT_ID
    # The whole point of the fetch for audit purposes: an operator reading
    # an event sees a name, not a URL.
    assert identity.client_name == "Acme Desktop"
    assert identity.client_uri == "https://client.example"


# --- self-identification --------------------------------------------------


def test_document_naming_a_different_client_id_is_refused() -> None:
    """The impostor case: a document copied from the real client and
    served somewhere else still names the original's client_id."""

    transport = _transport(
        lambda request: httpx.Response(
            200, json=_document(client_id="https://someone-else.example/doc")
        )
    )
    resolver = InboundCimdResolver(policy=POLICY, transport=transport)
    with pytest.raises(CimdResolutionError) as excinfo:
        asyncio.run(resolver.resolve(CLIENT_ID))
    assert "self-identify" in excinfo.value.reason


def test_document_with_no_client_id_at_all_is_refused() -> None:
    transport = _transport(
        lambda request: httpx.Response(200, json={"client_name": "Acme"})
    )
    resolver = InboundCimdResolver(policy=POLICY, transport=transport)
    with pytest.raises(CimdResolutionError):
        asyncio.run(resolver.resolve(CLIENT_ID))


# --- revocation -----------------------------------------------------------


def test_document_that_stopped_being_served_is_refused() -> None:
    """CIMD's stated revocation mechanism is 'stop serving the document'.
    A 404 therefore has to mean rejected, not 'carry on as before'."""

    transport = _transport(lambda request: httpx.Response(404))
    resolver = InboundCimdResolver(policy=POLICY, transport=transport)
    with pytest.raises(CimdResolutionError) as excinfo:
        asyncio.run(resolver.resolve(CLIENT_ID))
    assert "404" in excinfo.value.reason


# --- redirects ------------------------------------------------------------


def test_redirect_is_refused_rather_than_followed() -> None:
    """Following would move the fetch to a host the operator never
    allowlisted, and would make the self-identification check compare
    against the wrong URL."""

    hops: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hops.append(request)
        return httpx.Response(302, headers={"Location": "https://evil.example/doc"})

    resolver = InboundCimdResolver(
        policy=POLICY, transport=_transport(handler)
    )
    with pytest.raises(CimdResolutionError) as excinfo:
        asyncio.run(resolver.resolve(CLIENT_ID))
    assert "redirect" in excinfo.value.reason
    # Negative control: exactly one hop. If redirects were followed this
    # would be two, and the second would be to a host nobody vetted.
    assert len(hops) == 1


# --- size cap -------------------------------------------------------------


def test_oversized_document_is_refused() -> None:
    transport = _transport(
        lambda request: httpx.Response(200, content=b"x" * 5000)
    )
    resolver = InboundCimdResolver(
        policy=POLICY, transport=transport, max_document_bytes=1024
    )
    with pytest.raises(CimdResolutionError) as excinfo:
        asyncio.run(resolver.resolve(CLIENT_ID))
    assert "exceeds" in excinfo.value.reason


def test_a_document_just_under_the_cap_still_resolves() -> None:
    """Negative control for the test above — proves the cap rejects on
    size and not merely on the payload being unusual."""

    padded = _document(client_name="A" * 400)
    body = json.dumps(padded).encode()
    resolver = InboundCimdResolver(
        policy=POLICY,
        transport=_transport(lambda request: httpx.Response(200, content=body)),
        max_document_bytes=len(body) + 1,
    )
    identity = asyncio.run(resolver.resolve(CLIENT_ID))
    assert identity.client_name == "A" * 400


# --- malformed ------------------------------------------------------------


def test_non_json_is_refused() -> None:
    resolver = InboundCimdResolver(
        policy=POLICY,
        transport=_transport(lambda request: httpx.Response(200, content=b"<html>")),
    )
    with pytest.raises(CimdResolutionError):
        asyncio.run(resolver.resolve(CLIENT_ID))


def test_json_that_is_not_an_object_is_refused() -> None:
    resolver = InboundCimdResolver(
        policy=POLICY,
        transport=_transport(lambda request: httpx.Response(200, json=[1, 2, 3])),
    )
    with pytest.raises(CimdResolutionError):
        asyncio.run(resolver.resolve(CLIENT_ID))


# --- the SSRF guard is not optional ---------------------------------------


def test_a_client_id_resolving_to_loopback_is_refused() -> None:
    """The transport is injected, yet the guard still runs — that is the
    property. `localhost` is NOT in this policy's allowlist, so the guard
    resolves it, sees loopback, and refuses before the mock is reached."""

    reached: list[httpx.Request] = []
    resolver = InboundCimdResolver(
        policy=UrlSecurityPolicy(allowlist=("client.example",)),
        transport=_transport(calls=reached),
    )
    with pytest.raises(CimdResolutionError) as excinfo:
        asyncio.run(
            resolver.resolve("https://localhost/.well-known/oauth-client")
        )
    assert "unreachable" in excinfo.value.reason
    # The request never got as far as the transport.
    assert reached == []


# --- caching --------------------------------------------------------------


def test_a_resolved_document_is_cached() -> None:
    calls: list[httpx.Request] = []
    resolver = InboundCimdResolver(policy=POLICY, transport=_transport(calls=calls))

    async def run() -> None:
        await resolver.resolve(CLIENT_ID)
        await resolver.resolve(CLIENT_ID)
        await resolver.resolve(CLIENT_ID)

    asyncio.run(run())
    # Without this, every token request is a fetch at the client's server
    # — which is the amplification the allowlist gate exists to prevent.
    assert len(calls) == 1


def test_failures_are_cached_too() -> None:
    calls: list[httpx.Request] = []
    resolver = InboundCimdResolver(
        policy=POLICY,
        transport=_transport(lambda request: httpx.Response(500), calls=calls),
    )

    async def run() -> None:
        for _ in range(3):
            with pytest.raises(CimdResolutionError):
                await resolver.resolve(CLIENT_ID)

    asyncio.run(run())
    assert len(calls) == 1


def test_cache_expires_and_refetches() -> None:
    """Negative control for the caching tests: proves they assert a TTL
    and not merely that the resolver fetches once ever."""

    now = [1000.0]
    calls: list[httpx.Request] = []
    resolver = InboundCimdResolver(
        policy=POLICY,
        transport=_transport(calls=calls),
        ttl_seconds=100,
        clock=lambda: now[0],
    )
    asyncio.run(resolver.resolve(CLIENT_ID))
    now[0] += 50
    asyncio.run(resolver.resolve(CLIENT_ID))
    assert len(calls) == 1
    now[0] += 51
    asyncio.run(resolver.resolve(CLIENT_ID))
    assert len(calls) == 2


def test_a_failure_is_retried_sooner_than_a_success_is_refetched() -> None:
    """A resolved document is a stable fact; a failure is usually a blip
    someone is already fixing. Caching both for 15 minutes would turn a
    brief outage at the client into a long one here."""

    now = [1000.0]
    calls: list[httpx.Request] = []
    resolver = InboundCimdResolver(
        policy=POLICY,
        transport=_transport(lambda request: httpx.Response(503), calls=calls),
        ttl_seconds=900,
        negative_ttl_seconds=60,
        clock=lambda: now[0],
    )
    with pytest.raises(CimdResolutionError):
        asyncio.run(resolver.resolve(CLIENT_ID))
    now[0] += 61  # past the negative TTL, far short of the positive one
    with pytest.raises(CimdResolutionError):
        asyncio.run(resolver.resolve(CLIENT_ID))
    assert len(calls) == 2


def test_a_burst_for_one_uncached_client_produces_one_fetch() -> None:
    """Without the per-key lock, N concurrent grants for one client mean
    N simultaneous requests at that client's server."""

    calls: list[httpx.Request] = []

    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.01)
        calls.append(request)
        return httpx.Response(200, json=_document())

    resolver = InboundCimdResolver(
        policy=POLICY, transport=httpx.MockTransport(slow)
    )

    async def run() -> list[object]:
        return await asyncio.gather(*(resolver.resolve(CLIENT_ID) for _ in range(10)))

    results = asyncio.run(run())
    assert len(results) == 10
    assert len(calls) == 1


def test_invalidate_forces_a_refetch() -> None:
    calls: list[httpx.Request] = []
    resolver = InboundCimdResolver(policy=POLICY, transport=_transport(calls=calls))
    asyncio.run(resolver.resolve(CLIENT_ID))
    resolver.invalidate(CLIENT_ID)
    asyncio.run(resolver.resolve(CLIENT_ID))
    assert len(calls) == 2


def test_a_non_url_client_id_is_never_fetched() -> None:
    calls: list[httpx.Request] = []
    resolver = InboundCimdResolver(policy=POLICY, transport=_transport(calls=calls))
    with pytest.raises(CimdResolutionError):
        asyncio.run(resolver.resolve("acme-desktop"))
    assert calls == []
