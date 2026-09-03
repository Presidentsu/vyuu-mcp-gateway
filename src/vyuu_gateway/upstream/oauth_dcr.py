"""OAuth 2.1 Dynamic Client Registration (DCR) for `auth_authcode`
upstreams that follow the MCP-Auth spec.

Three RFCs cooperate:

- **RFC 9728** — OAuth 2.0 Protected Resource Metadata. The MCP server
  responds to unauthenticated requests with a `WWW-Authenticate: Bearer
  resource_metadata="..."` header. That URL serves a JSON document
  pointing at the authorization server(s).
- **RFC 8414** — OAuth 2.0 Authorization Server Metadata. Each AS
  exposes `/.well-known/oauth-authorization-server` with the
  authorization, token, and registration endpoints.
- **RFC 7591** — OAuth 2.0 Dynamic Client Registration. POST our
  client metadata to the registration endpoint; receive `client_id`
  (+ optional `client_secret`).

For Notion, Linear, and any vendor built on the official MCP SDK auth
helpers, this entire dance happens automatically — the operator clicks
"Register from catalog" and the gateway provisions itself as an OAuth
client without any vendor-dashboard setup.

Threat model. The discovery URLs are HTTPS-only (we reject HTTP), so a
MITM cannot redirect us to a hostile registration endpoint. We
register without an Initial Access Token (RFC 7591 §3) — most public
SaaS MCPs allow this; enterprise IdPs that require an IAT need a
different path (backlogged as the per-vendor adapter case).

Persistence: results land in `mcp_server_dcr_clients` (one row per
`mcp_servers.id`). Re-registration replaces the row on PK collision.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from vyuu_gateway.upstream.oauth_cimd import plan_from_as_metadata

logger = logging.getLogger(__name__)

# Default client metadata sent at registration. All fields are
# overridable per-call so tests can swap names + the catalog can
# eventually customize per-connector.
_DEFAULT_CLIENT_NAME = "Vyuu MCP Gateway"
_DEFAULT_GRANT_TYPES = ("authorization_code", "refresh_token")
_DEFAULT_RESPONSE_TYPES = ("code",)


class DcrError(Exception):
    """DCR flow failed at some step. Carries the step + a sanitized
    detail string suitable for surfacing to operators (no upstream
    response bodies — those may contain credentials or PII)."""

    def __init__(self, step: str, detail: str) -> None:
        super().__init__(f"[{step}] {detail}")
        self.step = step
        self.detail = detail


@dataclass(frozen=True)
class DcrResult:
    """Output of a successful client-identity acquisition. The caller
    persists this to `mcp_server_dcr_clients`.

    Despite the name this is no longer always a *registration*: when the
    AS advertises CIMD there is nothing to register, and the result
    carries our document URL as the `client_id` with no secret and no
    registration endpoint. `auth_mechanism` says which happened, because
    the two fail in opposite ways — see the model's column comment.
    """

    client_id: str
    client_secret: str | None
    authorization_endpoint: str
    token_endpoint: str
    # None under CIMD: there is no registration endpoint to record.
    registration_endpoint: str | None
    registration_response: dict[str, Any]
    auth_mechanism: str = "dcr"
    # Why this mechanism and not the other. Carried even on success:
    # "why did this upstream use CIMD and that one use DCR?" is asked
    # while debugging a connect failure, and the answer otherwise lives
    # only in an AS metadata document nobody can see.
    mechanism_reason: str = ""


def _require_https(url: str, *, step: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise DcrError(
            step,
            "discovery URL must be HTTPS — refusing plaintext (MITM defense)",
        )


async def discover_and_register(
    *,
    upstream_url: str,
    redirect_uri: str,
    client_name: str = _DEFAULT_CLIENT_NAME,
    scopes: list[str] | None = None,
    initial_access_token: str | None = None,
    cimd_client_id: str | None = None,
    http: httpx.AsyncClient | None = None,
) -> DcrResult:
    """Run the full RFC 9728 → 8414 → 7591 discovery + registration
    flow against an MCP server URL.

    `upstream_url` is the MCP server's MCP endpoint (e.g.
    `https://mcp.notion.com/mcp`). The discovery probe POSTs
    unauthenticated to that URL and reads the WWW-Authenticate hint.

    `redirect_uri` is the gateway's callback URL — the same value
    eventually passed to /authorize in the authcode flow. Must match
    exactly (the AS validates it as registered).

    `scopes` are the scopes the gateway will eventually request. We
    pass them to registration so the AS can pre-authorize them; some
    AS implementations (Notion) ignore the field, others narrow the
    grant. Optional.

    `initial_access_token` (RFC 7591 §3) — required by some enterprise
    OAuth servers (Okta, certain Auth0 tenants, private B2B IdPs) that
    gate the registration endpoint behind a Bearer token. Sent as
    `Authorization: Bearer <iat>` on the registration POST when
    provided. Public SaaS DCR servers (Notion, Linear, Cloudflare,
    Sentry, etc.) accept unauthenticated registration and don't need
    one.

    `cimd_client_id` (MCP-2 P3) — our own Client ID Metadata Document
    URL. When supplied *and* the AS advertises CIMD support, discovery
    stops at step 3 and returns that URL as the client_id: no
    registration request is sent and no credential is created on either
    side. When the AS does not advertise it, registration proceeds
    exactly as before and the result records why CIMD was not used.
    Passing None disables the check entirely.

    Returns `DcrResult` with the issued credentials + cached endpoint
    URLs. Raises `DcrError` with a step name on any failure.
    """

    own_client = http is None
    if http is None:
        http = httpx.AsyncClient(timeout=15.0)
    try:
        # Step 1: probe the MCP server to get the resource metadata URL.
        # We expect a 401 with `WWW-Authenticate: Bearer
        # resource_metadata="..."`. Spec-compliant servers use that
        # exact format. If the WWW-Authenticate is missing the hint, we
        # fall back to the conventional `/.well-known/oauth-protected-
        # resource` path on the same origin.
        try:
            probe = await http.post(
                upstream_url,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": client_name, "version": "1.0"},
                    },
                },
            )
        except httpx.HTTPError as exc:
            raise DcrError(
                "probe",
                f"upstream MCP unreachable ({exc.__class__.__name__})",
            ) from exc

        resource_metadata_url = _extract_resource_metadata_url(
            probe.headers.get("www-authenticate", ""),
            upstream_url=upstream_url,
        )
        _require_https(resource_metadata_url, step="probe")

        # Step 2: GET the resource metadata document (RFC 9728).
        try:
            resource_resp = await http.get(resource_metadata_url)
        except httpx.HTTPError as exc:
            raise DcrError(
                "resource_metadata",
                f"resource metadata unreachable ({exc.__class__.__name__})",
            ) from exc
        if resource_resp.status_code != 200:
            raise DcrError(
                "resource_metadata",
                f"resource metadata returned HTTP {resource_resp.status_code}",
            )
        try:
            resource_doc = resource_resp.json()
        except ValueError as exc:
            raise DcrError(
                "resource_metadata", "resource metadata is not JSON"
            ) from exc
        as_urls = resource_doc.get("authorization_servers") or []
        if not as_urls or not isinstance(as_urls, list):
            raise DcrError(
                "resource_metadata",
                "resource metadata missing `authorization_servers`",
            )
        as_url = as_urls[0]  # Try the first AS; spec allows multiple
        if not isinstance(as_url, str):
            raise DcrError("resource_metadata", "AS URL not a string")
        _require_https(as_url, step="resource_metadata")

        # Step 3: GET the AS metadata (RFC 8414). The well-known
        # path lives at the AS issuer's root.
        as_metadata_url = as_url.rstrip("/") + "/.well-known/oauth-authorization-server"
        try:
            as_resp = await http.get(as_metadata_url)
        except httpx.HTTPError as exc:
            raise DcrError(
                "as_metadata",
                f"AS metadata unreachable ({exc.__class__.__name__})",
            ) from exc
        if as_resp.status_code != 200:
            raise DcrError(
                "as_metadata", f"AS metadata returned HTTP {as_resp.status_code}"
            )
        try:
            as_doc = as_resp.json()
        except ValueError as exc:
            raise DcrError("as_metadata", "AS metadata is not JSON") from exc
        # MCP-2 P3 — the CIMD decision happens HERE, before the
        # DCR-specific requirements below, because an AS that supports
        # CIMD has no reason to offer a `registration_endpoint` and
        # demanding one would reject the very servers CIMD is for.
        cimd_reason = "gateway did not offer a client_id metadata document"
        if cimd_client_id is not None:
            plan = plan_from_as_metadata(as_doc, client_id=cimd_client_id)
            cimd_reason = plan.reason
            if plan.use_cimd:
                assert plan.authorization_endpoint and plan.token_endpoint
                _require_https(plan.authorization_endpoint, step="as_metadata")
                _require_https(plan.token_endpoint, step="as_metadata")
                logger.info(
                    "cimd_selected_over_dcr",
                    extra={"as_url": as_url, "client_id": cimd_client_id},
                )
                return DcrResult(
                    client_id=cimd_client_id,
                    # No secret exists under CIMD — control of the URL is
                    # the proof. The callback treats a secretless client
                    # as public and sends client_id in the form body.
                    client_secret=None,
                    authorization_endpoint=plan.authorization_endpoint,
                    token_endpoint=plan.token_endpoint,
                    registration_endpoint=None,
                    # Nothing was registered, so there is no registration
                    # response. Keep the AS document instead — it is what
                    # the decision was actually made from.
                    registration_response={"as_metadata": as_doc},
                    auth_mechanism="cimd",
                    mechanism_reason=plan.reason,
                )

        for required in (
            "authorization_endpoint",
            "token_endpoint",
            "registration_endpoint",
        ):
            if not as_doc.get(required):
                raise DcrError(
                    "as_metadata",
                    f"AS metadata missing `{required}` — vendor does not "
                    f"support DCR; use static credentials",
                )
        for endpoint_key in (
            "authorization_endpoint",
            "token_endpoint",
            "registration_endpoint",
        ):
            _require_https(as_doc[endpoint_key], step="as_metadata")

        # Optional sanity check: spec-compliant DCR servers MUST
        # advertise PKCE S256 (per OAuth 2.1). If they don't, we
        # accept the registration anyway but log a warning — our
        # /initiate sends `code_challenge_method=S256` regardless,
        # and an AS that doesn't support it will reject at /authorize.
        pkce_methods = as_doc.get("code_challenge_methods_supported") or []
        if "S256" not in pkce_methods:
            logger.warning(
                "dcr_as_does_not_advertise_s256",
                extra={"as_url": as_url, "advertised": pkce_methods},
            )

        # Step 4: POST to the registration endpoint with our client
        # metadata (RFC 7591). All fields below are spec-defined.
        client_metadata: dict[str, Any] = {
            "client_name": client_name,
            "redirect_uris": [redirect_uri],
            "grant_types": list(_DEFAULT_GRANT_TYPES),
            "response_types": list(_DEFAULT_RESPONSE_TYPES),
            # `client_secret_basic` is the most widely supported.
            # Spec-compliant AS that issue secrets accept it; pure
            # PKCE-only AS will return `client_secret=None` regardless.
            "token_endpoint_auth_method": "client_secret_basic",
            # RFC 7591 §2 / MCP-2 P3. `web` is the accurate answer and
            # not merely the default: our redirect_uri is an https URL on
            # the gateway, and the client secret lives in a secret store
            # server-side. Declaring it matters because some AS apply
            # *stricter* redirect_uri rules to `native` clients (allowing
            # loopback and custom schemes) — an AS that infers `native`
            # from an omitted field can silently relax the check that
            # protects our callback.
            "application_type": "web",
        }
        if scopes:
            client_metadata["scope"] = " ".join(scopes)

        registration_headers: dict[str, str] = {"Accept": "application/json"}
        if initial_access_token:
            # RFC 7591 §3: when an Initial Access Token is required by
            # the AS, the client sends it as a Bearer credential on the
            # registration request itself. Public SaaS DCR servers
            # ignore this header; gated enterprise IdPs require it.
            registration_headers["Authorization"] = f"Bearer {initial_access_token}"
        try:
            reg_resp = await http.post(
                as_doc["registration_endpoint"],
                json=client_metadata,
                headers=registration_headers,
            )
        except httpx.HTTPError as exc:
            raise DcrError(
                "registration",
                f"registration endpoint unreachable ({exc.__class__.__name__})",
            ) from exc
        # RFC 7591: 201 Created on success. 200 also seen in the wild.
        if reg_resp.status_code not in (200, 201):
            raise DcrError(
                "registration",
                f"registration returned HTTP {reg_resp.status_code} — "
                f"vendor may require an Initial Access Token (RFC 7591 §3) "
                f"or a software statement; not currently supported",
            )
        try:
            reg_body = reg_resp.json()
        except ValueError as exc:
            raise DcrError(
                "registration", "registration response is not JSON"
            ) from exc
        client_id = reg_body.get("client_id")
        if not client_id or not isinstance(client_id, str):
            raise DcrError(
                "registration", "registration response missing client_id"
            )
        client_secret = reg_body.get("client_secret")
        if client_secret is not None and not isinstance(client_secret, str):
            raise DcrError(
                "registration", "registration client_secret is not a string"
            )

        return DcrResult(
            client_id=client_id,
            client_secret=client_secret,
            authorization_endpoint=as_doc["authorization_endpoint"],
            token_endpoint=as_doc["token_endpoint"],
            registration_endpoint=as_doc["registration_endpoint"],
            registration_response=reg_body,
            auth_mechanism="dcr",
            mechanism_reason=cimd_reason,
        )
    finally:
        if own_client:
            await http.aclose()


def _extract_resource_metadata_url(
    www_authenticate: str, *, upstream_url: str
) -> str:
    """Parse `WWW-Authenticate: Bearer ... resource_metadata="..."`.

    The header is comma + space separated key=value pairs after the
    scheme name. Spec-compliant servers (Notion, Linear) include a
    `resource_metadata` parameter pointing at the RFC 9728 document.
    Falls back to the conventional `<origin>/.well-known/oauth-
    protected-resource` path if the header is missing or malformed —
    that's the universal default.
    """
    if www_authenticate:
        # Look for resource_metadata="..."
        marker = "resource_metadata="
        idx = www_authenticate.find(marker)
        if idx >= 0:
            value = www_authenticate[idx + len(marker):]
            # Strip optional quoting + take up to the next comma.
            if value.startswith('"'):
                end = value.find('"', 1)
                if end > 0:
                    return value[1:end]
            else:
                end = value.find(",")
                return value[:end] if end > 0 else value
    # Fallback: default well-known URL on the upstream's origin.
    parsed = urlparse(upstream_url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}/.well-known/oauth-protected-resource"
    raise DcrError(
        "probe",
        "no WWW-Authenticate hint and upstream URL has no host",
    )
