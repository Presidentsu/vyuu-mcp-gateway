"""MCP-2 P3 · Client ID Metadata Document (CIMD).

The 2026-07-28 revision prefers CIMD over RFC 7591 Dynamic Client
Registration, and the reason is structural rather than stylistic.

**DCR is stateful in the worst place.** Registering produces a
`client_id` and often a `client_secret` that both sides must now store,
keep in sync, and eventually rotate. We persist them in
`mcp_server_dcr_clients`; the authorization server persists its own copy.
Every upstream we front is another registration that can be revoked,
expire, or silently drift — and a registration that fails halfway leaves
credentials on one side only. `U10 · DCR auto-recovery on invalid_client`
exists precisely because that goes wrong in practice.

**CIMD removes the registration entirely.** The client's `client_id`
*is* an https URL, and that URL serves the client's metadata. An
authorization server that sees `client_id=https://gateway.example/...`
fetches the document and learns the redirect URIs, name and scopes
directly. Nothing is stored on either side; nothing can drift; there is
no secret to rotate. Revocation is "stop serving the document".

## What this module does

Serves *our* document, so the gateway can present itself as a CIMD client
to upstream authorization servers. `upstream/oauth_cimd.py` decides
per-AS whether to use it.

## Why the document is served unauthenticated

It has to be: an authorization server fetches it server-to-server, with
no credential of ours. That is fine because the document is public by
construction — it contains only what we would have sent in a DCR
registration request, which the AS was going to learn anyway. **It must
therefore never grow a field that is not already public.** If a future
change wants to put anything tenant-specific here, that is the signal
the design has gone wrong.

## The redirect URI is the security boundary

CIMD moves trust onto "whoever controls this URL is the client". That
means the *only* thing protecting us is that the document names our
redirect URI and nothing else — an AS will refuse to redirect anywhere
that is not listed. Serving a document with a wildcard or an
attacker-influenceable redirect would hand over the whole flow, so the
value comes from `Settings.public_base_url` and is never taken from a
request.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(tags=["oauth-cimd"])

# The path our client_id points at. Stable by contract: an authorization
# server may cache the document, and any deployment that has handed this
# URL to an upstream cannot move it without breaking that upstream.
CIMD_PATH = "/.well-known/oauth-client"

# How long an AS may cache the document. Short enough that adding a
# redirect URI takes effect the same day, long enough that a busy AS is
# not refetching per authorization.
_CACHE_MAX_AGE_SECONDS = 3600


def client_id_url(public_base_url: str) -> str:
    """Our `client_id` — which under CIMD *is* the document's URL."""

    return f"{public_base_url.rstrip('/')}{CIMD_PATH}"


def build_client_metadata(
    *, public_base_url: str, app_name: str, redirect_uris: list[str]
) -> dict[str, Any]:
    """The document itself.

    Field names are RFC 7591 client metadata — CIMD reuses the same
    vocabulary, so an AS that already parses DCR registrations needs no
    new code to read this.
    """

    base = public_base_url.rstrip("/")
    return {
        # Per CIMD the document MUST self-identify with the URL it is
        # served from. An AS compares this against the URL it fetched;
        # a mismatch means the document was copied from somewhere else,
        # which is how an impostor would try to borrow our identity.
        "client_id": client_id_url(base),
        "client_name": app_name,
        "client_uri": base,
        "redirect_uris": list(redirect_uris),
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        # No secret exists under CIMD — control of the URL is the proof.
        # Saying so explicitly stops an AS from falling back to issuing
        # one and expecting us to keep it.
        "token_endpoint_auth_method": "none",
        # RFC 7591 §2, same reasoning as the DCR path: some AS relax
        # redirect_uri rules for `native` clients, and an omitted field
        # can be inferred as native.
        "application_type": "web",
    }


@router.get(CIMD_PATH)
def client_id_metadata_document(request: Request) -> JSONResponse:
    """Serve this gateway's CIMD.

    Unauthenticated by necessity — see the module docstring. Contains
    only values already destined for the authorization server.
    """

    settings = request.app.state.settings
    from vyuu_gateway.api.oauth_authcode import GATEWAY_REDIRECT_PATH

    base = settings.public_base_url.rstrip("/")
    document = build_client_metadata(
        public_base_url=base,
        app_name=settings.app_name,
        redirect_uris=[f"{base}{GATEWAY_REDIRECT_PATH}"],
    )
    return JSONResponse(
        document,
        headers={
            "Cache-Control": f"public, max-age={_CACHE_MAX_AGE_SECONDS}",
            # The document is the client's identity; a proxy serving a
            # stale or substituted copy is a client-impersonation vector.
            "Content-Type": "application/json",
        },
    )
