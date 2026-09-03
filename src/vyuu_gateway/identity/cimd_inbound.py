"""MCP-2 P3 · consuming an inbound client's Client ID Metadata Document.

`api/cimd.py` serves *our* document so upstream authorization servers can
identify us. This is the mirror image: we are the authorization server,
an inbound MCP client presents a `client_id` that is an https URL, and
the document at that URL says who it claims to be.

## Why fetch at all

An allowlist of URL strings can be enforced by string comparison; no
network call is required to decide whether `client_id` is in a list. The
fetch buys two things string comparison cannot:

- **Revocation.** CIMD's revocation story — ours included, stated in
  `api/cimd.py` — is "stop serving the document". A gateway that never
  fetches can never observe that, so an allowlisted client stays
  allowlisted forever, including after its operator has decommissioned
  it. Honouring revocation requires asking.
- **Identity in the audit trail.** `client_id=https://…/.well-known/
  oauth-client` in an event tells an operator nothing. The document
  carries `client_name`, which is what they are actually looking for
  when they ask which client redeemed a grant.

## Why this is dangerous, and what bounds it

This is a **server-side fetch of a URL that arrives in a request**, which
is the definition of SSRF. Four things bound it, and all four are load-
bearing:

1. **Only allowlisted client_ids are ever resolved.** This is a
   precondition of `resolve()`, not a suggestion — the caller checks
   membership *first*. It means the set of URLs this code can be made to
   fetch is chosen by an operator, never by a request. Without it, an
   unauthenticated caller could name any URL and use the gateway as a
   probe of its internal network, or point thousands of requests at one
   victim and use us as an amplifier.
2. **Every fetch goes through `SsrfGuardTransport`.** Defence in depth
   behind (1): an operator can allowlist a URL whose *name* later starts
   resolving somewhere private, and the DNS-time guard catches that at
   the moment the socket opens.
3. **Redirects are not followed.** A redirect would defeat both the
   self-identification check below and the operator's choice of URL: the
   allowlisted host would hand us off to one nobody vetted. A client_id
   that redirects is not a client_id that self-identifies.
4. **Answers are cached, negatives included.** Without a cache, every
   token request is a fetch, which reintroduces the amplification (1)
   removes and makes the allowlisted client's availability a hard
   dependency of ours.

## Self-identification

CIMD requires the document to carry the URL it is served from. We check
`document["client_id"] == the URL we fetched`, exactly. A document that
names a different client_id was copied from somewhere else, which is
precisely how an impostor borrows an identity it does not control.

## Failing closed — the opposite of the outbound half

`upstream/oauth_cimd.py` falls *back* to DCR on failure, and documents
why: the two mechanisms grant identical authority, so choosing between
them is a mechanism decision. Nothing of the sort is true here. Here the
document is how we learn **who the caller is**, and there is no second
mechanism that establishes the same fact. An unresolvable document is an
unidentified client, so `resolve()` raises and the caller rejects the
grant. Treating "the fetch failed" as "identity confirmed" would make
the check worse than not having it.

Off by default (`VYUU_EMA_CIMD_RESOLUTION_ENABLED`): switching it on
makes an allowlisted client's document availability part of this
gateway's auth path, and that is an operator's decision to make
knowingly.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import anyio
import httpx

from vyuu_gateway.registry.url_security import UrlSecurityPolicy
from vyuu_gateway.upstream.ssrf_guard import SsrfGuardTransport

logger = logging.getLogger(__name__)

# A CIMD document is client metadata: a handful of short strings and a
# list of redirect URIs. Anything approaching this size is either broken
# or is trying to make us hold it in memory.
DEFAULT_MAX_DOCUMENT_BYTES = 64 * 1024

# A resolved document is a stable fact about a client, so it can be held
# a while. A *failure* usually is not — it is a deploy, a blip, an expired
# certificate someone is already fixing — and caching one for as long as
# a success would turn a transient outage into a long one.
DEFAULT_TTL_SECONDS = 900
DEFAULT_NEGATIVE_TTL_SECONDS = 60


class CimdResolutionError(Exception):
    """The client_id could not be resolved to a document we trust.

    `reason` is for operators and logs. It is deliberately NOT surfaced
    to the caller: the EMA token endpoint answers every failure with the
    same opaque `invalid_grant`, and leaking which step failed would let
    a caller probe the allowlist.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class InboundClientIdentity:
    """Who an inbound client says it is, having proved it controls the URL."""

    client_id: str
    client_name: str | None
    client_uri: str | None
    document: dict[str, Any]


def is_cimd_client_id(client_id: str) -> bool:
    """True when this client_id is an https URL, i.e. a CIMD identifier.

    Anything else — an opaque string, an http URL — is a conventional
    client_id and is matched literally against the allowlist, exactly as
    before. http is excluded rather than upgraded: CIMD's trust model is
    "whoever controls this URL is the client", and over http that is
    whoever controls the network.
    """

    if not isinstance(client_id, str):
        return False
    parsed = urlparse(client_id)
    return parsed.scheme == "https" and bool(parsed.netloc)


@dataclass
class _CacheEntry:
    expires_at: float
    identity: InboundClientIdentity | None
    error: str | None


class InboundCimdResolver:
    """Resolves inbound CIMD client_ids, with caching and an SSRF guard.

    One instance per app; it holds the cache. Construct it with the same
    `UrlSecurityPolicy` the rest of the gateway uses so "allowed to
    connect to" cannot mean two different things in two places.
    """

    def __init__(
        self,
        *,
        policy: UrlSecurityPolicy,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        negative_ttl_seconds: int = DEFAULT_NEGATIVE_TTL_SECONDS,
        max_document_bytes: int = DEFAULT_MAX_DOCUMENT_BYTES,
        timeout_seconds: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._policy = policy
        self._ttl = ttl_seconds
        self._negative_ttl = negative_ttl_seconds
        self._max_bytes = max_document_bytes
        self._timeout = timeout_seconds
        self._clock = clock
        self._cache: dict[str, _CacheEntry] = {}
        # Per-key so a slow document does not stall resolution of every
        # other client, and so a burst of requests for one uncached
        # client produces one fetch rather than one per request.
        self._locks: dict[str, anyio.Lock] = {}
        # A transport, not a client: the SSRF guard wraps whatever is
        # injected, so a test (or a custom stack) cannot accidentally
        # opt out of the one control that makes this module safe to run.
        self._inner_transport = transport

    async def resolve(self, client_id: str) -> InboundClientIdentity:
        """Resolve an **already-allowlisted** CIMD client_id.

        The caller MUST have confirmed allowlist membership first — see
        bound (1) in the module docstring. Raises `CimdResolutionError`
        on any failure; there is no fall-back.
        """

        if not is_cimd_client_id(client_id):
            raise CimdResolutionError("client_id is not an https URL")

        cached = self._cache.get(client_id)
        now = self._clock()
        if cached is not None and cached.expires_at > now:
            if cached.identity is not None:
                return cached.identity
            raise CimdResolutionError(cached.error or "cached failure")

        lock = self._locks.setdefault(client_id, anyio.Lock())
        async with lock:
            # Re-check: another task may have filled the entry while we
            # waited, and the point of the lock is that only one fetch
            # happens per miss.
            cached = self._cache.get(client_id)
            now = self._clock()
            if cached is not None and cached.expires_at > now:
                if cached.identity is not None:
                    return cached.identity
                raise CimdResolutionError(cached.error or "cached failure")

            try:
                identity = await self._fetch(client_id)
            except CimdResolutionError as exc:
                self._cache[client_id] = _CacheEntry(
                    expires_at=self._clock() + self._negative_ttl,
                    identity=None,
                    error=exc.reason,
                )
                logger.warning(
                    "inbound_cimd_resolution_failed",
                    extra={"client_id": client_id[:200], "reason": exc.reason},
                )
                raise
            self._cache[client_id] = _CacheEntry(
                expires_at=self._clock() + self._ttl, identity=identity, error=None
            )
            return identity

    async def _fetch(self, client_id: str) -> InboundClientIdentity:
        # A client per fetch. Fetches are cached, so this happens once
        # per client per TTL — not often enough for connection reuse to
        # be worth an object whose lifecycle nothing would close.
        async with httpx.AsyncClient(
            timeout=self._timeout,
            # See bound (3): a redirect would both defeat the
            # self-identification check and move the fetch to a host the
            # operator never allowlisted.
            follow_redirects=False,
            transport=SsrfGuardTransport(
                self._inner_transport or httpx.AsyncHTTPTransport(),
                policy=self._policy,
            ),
        ) as http:
            try:
                # Streamed, so an oversized body is abandoned mid-flight
                # rather than buffered and then measured. Reading first
                # and checking after would let a hostile document cost us
                # its full length regardless of the cap.
                async with http.stream(
                    "GET", client_id, headers={"Accept": "application/json"}
                ) as response:
                    if response.is_redirect:
                        raise CimdResolutionError(
                            "document responded with a redirect; a client_id "
                            "must serve its own metadata"
                        )
                    if response.status_code != 200:
                        # The revocation signal: a client whose operator
                        # took the document down stops resolving, and
                        # therefore stops being accepted.
                        raise CimdResolutionError(
                            f"document returned HTTP {response.status_code}"
                        )
                    chunks: list[bytes] = []
                    total = 0
                    async for chunk in response.aiter_bytes():
                        total += len(chunk)
                        if total > self._max_bytes:
                            raise CimdResolutionError(
                                f"document exceeds {self._max_bytes} bytes"
                            )
                        chunks.append(chunk)
            except httpx.HTTPError as exc:
                # Includes the SSRF guard's rejection, which subclasses
                # `httpx.TransportError` precisely so it travels as an
                # ordinary connection failure.
                raise CimdResolutionError(
                    f"document unreachable ({exc.__class__.__name__})"
                ) from exc

        try:
            document = json.loads(b"".join(chunks))
        except ValueError as exc:
            raise CimdResolutionError("document is not JSON") from exc

        if not isinstance(document, dict):
            raise CimdResolutionError("document is not a JSON object")

        # Self-identification — see the module docstring. Exact match:
        # a document naming a different client_id was copied from
        # elsewhere and does not establish control of THIS URL.
        declared = document.get("client_id")
        if declared != client_id:
            raise CimdResolutionError(
                "document does not self-identify with the URL it was fetched from"
            )

        return InboundClientIdentity(
            client_id=client_id,
            client_name=_optional_str(document.get("client_name")),
            client_uri=_optional_str(document.get("client_uri")),
            document=document,
        )

    def invalidate(self, client_id: str) -> None:
        """Drop a cached answer — for an operator forcing a re-check
        after fixing a client, without restarting the gateway."""

        self._cache.pop(client_id, None)


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None
