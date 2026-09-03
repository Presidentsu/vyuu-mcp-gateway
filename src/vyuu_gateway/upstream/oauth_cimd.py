"""MCP-2 P3 · use CIMD instead of Dynamic Client Registration when we can.

`api/cimd.py` serves our document; this decides, per authorization
server, whether to present it.

## The decision

An AS advertises support in its RFC 8414 metadata as
`client_id_metadata_document_supported: true`. When it does, we skip
registration entirely and pass our document's URL as `client_id`. When it
does not, we fall back to the DCR path we already ship.

Preferring CIMD is not merely modern-for-its-own-sake. Every DCR
registration is a credential pair that both sides now have to store, keep
in sync and eventually rotate — and `U10 · DCR auto-recovery on
invalid_client` exists because that drifts in production. CIMD has
nothing to drift: no secret, no stored registration, and revocation is
"stop serving the document".

## Fail *back*, not closed

An AS that advertises CIMD but then rejects our URL leaves us with a
working alternative, so a CIMD failure falls back to DCR rather than
failing the user's connect. This is the opposite of the fail-closed rule
used elsewhere in the gateway, and deliberately: the two paths grant
**identical** authority — the same redirect URI, the same scopes, the
same eventual token. Choosing between them is a mechanism decision, not a
trust decision, so falling back costs no security. (A fail-closed rule
here would just mean users cannot connect to a server whose AS misreports
its own capabilities.)

## What is NOT here

Consuming *someone else's* CIMD — fetching a URL an inbound client
supplies as its `client_id` — is the inbound half and lives in
`identity/cimd_inbound.py`. It is a server-side fetch of a URL that
arrives in a request, so it is bounded very differently from this module:
it goes through `upstream/ssrf_guard.py`, refuses redirects, caches, and
**fails closed** rather than falling back. Read that module's docstring
for why the two halves take opposite rules on failure.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# RFC 8414 metadata key an AS uses to advertise CIMD support.
CIMD_SUPPORT_KEY = "client_id_metadata_document_supported"


@dataclass(frozen=True)
class CimdPlan:
    """Whether to use CIMD for one authorization server, and why.

    `reason` is carried even on success because "why did this upstream
    use CIMD and that one use DCR?" is a question an operator will ask
    while debugging a connect failure, and the answer lives in the AS's
    metadata rather than anywhere they can see.
    """

    use_cimd: bool
    reason: str
    client_id: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None


def plan_from_as_metadata(
    as_metadata: dict[str, Any], *, client_id: str
) -> CimdPlan:
    """Decide from an already-fetched RFC 8414 document.

    Split from any network call so the decision is testable on its own —
    it is pure policy over a dict.
    """

    if not as_metadata.get(CIMD_SUPPORT_KEY):
        return CimdPlan(
            use_cimd=False,
            reason=f"authorization server does not advertise {CIMD_SUPPORT_KEY}",
        )
    authorization_endpoint = as_metadata.get("authorization_endpoint")
    token_endpoint = as_metadata.get("token_endpoint")
    if not authorization_endpoint or not token_endpoint:
        # An AS claiming CIMD but omitting its own endpoints is
        # malformed. Falling back to DCR is not going to help, but it is
        # the DCR path that has the error reporting an operator needs.
        return CimdPlan(
            use_cimd=False,
            reason=(
                "authorization server advertises CIMD but its metadata is "
                "missing authorization_endpoint or token_endpoint"
            ),
        )
    if not str(client_id).lower().startswith("https://"):
        # Our own client_id must be an https URL — CIMD's entire trust
        # model is "whoever controls this URL is the client", and http
        # means whoever controls the network does.
        return CimdPlan(
            use_cimd=False,
            reason="gateway public_base_url is not https; CIMD requires it",
        )
    return CimdPlan(
        use_cimd=True,
        reason="authorization server advertises CIMD support",
        client_id=client_id,
        authorization_endpoint=authorization_endpoint,
        token_endpoint=token_endpoint,
    )


async def fetch_as_metadata(
    issuer_or_metadata_url: str, *, http: httpx.AsyncClient
) -> dict[str, Any] | None:
    """Fetch an RFC 8414 authorization-server metadata document.

    Returns None on any failure — the caller falls back to DCR, which
    does its own discovery with its own error reporting. Swallowing here
    keeps this function a pure "can we use CIMD?" probe rather than a
    second, competing discovery implementation.
    """

    url = issuer_or_metadata_url
    if not url.rstrip("/").endswith("/.well-known/oauth-authorization-server"):
        url = f"{url.rstrip('/')}/.well-known/oauth-authorization-server"
    try:
        response = await http.get(url, headers={"Accept": "application/json"})
        if response.status_code != 200:
            return None
        document = response.json()
    except Exception:  # noqa: BLE001 — probe only; DCR reports real errors
        logger.info("cimd_as_metadata_probe_failed", extra={"url": url})
        return None
    return document if isinstance(document, dict) else None
