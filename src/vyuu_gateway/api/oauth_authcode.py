"""OAuth authorization-code (phase 4 / A1) — initiate + callback +
list/disconnect endpoints for the per-user delegated token flow.

Three end-user-facing endpoints (portal-session JWT auth):

- `POST /api/v1/oauth-authcode/{server_id}/initiate` — returns the
  IdP's authorization URL with a signed state token. The portal
  redirects the browser to this URL.
- `GET  /api/v1/oauth-authcode/callback?code=...&state=...` — IdP
  redirects the browser here after consent. Validates state, exchanges
  code for tokens, persists to `oauth_user_tokens`. NO auth required —
  the state token is the auth (CSRF + carrier of tenant/user/server).
- `GET  /api/v1/oauth-authcode/connections` — list servers this user
  has authorised, with metadata (last refresh, scope, etc.).
- `DELETE /api/v1/oauth-authcode/{server_id}/connection` — user
  disconnects their account; deletes the `oauth_user_tokens` row.
  (Best practice: also revoke at the IdP — left as TODO since not
  every IdP supports the revocation endpoint.)

One operator-facing endpoint (operator-bearer auth):

- `POST /api/v1/oauth-authcode/{server_id}/operator-initiate` —
  same flow as `/initiate` but for operators testing a freshly
  registered upstream BEFORE any portal user has connected. Resolves
  the operator's email to the matching `users` row in the same
  tenant (the bootstrap path explicitly maps operator email →
  user email 1:1; per-PLATFORM.md §3.1) and mints the state token
  carrying that user_id. After OAuth completes, the standard
  /callback writes a token row keyed by that user. This breaks
  the chicken-and-egg where Sync needs a token, Token needs Connect,
  Connect needs vserver-access, vserver-access needs Sync.

State token format: HS256 JWT signed with
`Settings.portal_session_signing_secret`. Carries
`(tenant_id, user_id, server_id, nonce, exp)`. 10-minute lifetime —
plenty for the IdP redirect round trip but short enough that a
captured state token can't be replayed days later.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import html
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import urlencode, urlparse
from uuid import UUID, uuid4

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy import update as sa_update
from sqlalchemy.orm import Session

from vyuu_gateway.crypto import get_envelope_cipher, seal_token
from vyuu_gateway.db.models import (
    McpServer,
    McpServerDcrClient,
    OAuthUserToken,
    Operator,
    User,
)
from vyuu_gateway.db.session import SessionLocal, bind_tenant_context
from vyuu_gateway.operator_auth.dependency import authenticate_operator
from vyuu_gateway.operator_auth.models import AuthenticatedOperator
from vyuu_gateway.siem.bridges import record_tool_auth
from vyuu_gateway.siem.events import ToolAuthAction
from vyuu_gateway.upstream.oauth_dcr import DcrError, discover_and_register
from vyuu_gateway.users.portal_dependency import (
    authenticate_portal_session,
    get_portal_scoped_db,
)
from vyuu_gateway.users.sessions import PortalSession

logger = logging.getLogger(__name__)
router = APIRouter(tags=["oauth-authcode"])

# The gateway's OAuth callback, relative to `public_base_url`. Named
# here rather than spelled out in each caller because CIMD publishes it
# as our registered redirect URI — the document and the route must be
# the same string or every authorization will be rejected.
GATEWAY_REDIRECT_PATH = "/api/v1/oauth-authcode/callback"

_STATE_TTL_SECONDS = 600  # 10 minutes — long enough for the IdP round trip
_STATE_ISSUER = "vyuu-gateway-oauth-state"


# --- State token helpers ---------------------------------------------------


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE (RFC 7636) code_verifier + code_challenge pair.

    OAuth 2.1 mandates PKCE for all authorization-code flows. Even with
    a confidential client (we send client_secret), PKCE blocks code
    interception attacks where an attacker who steals the redirect's
    `?code=...` can't exchange it without the verifier. Required by
    DCR-spec-compliant servers (Notion, Linear) and recommended for
    static OAuth apps.

    `code_verifier`: 43-128 chars from RFC 3986 unreserved set (we use
    `secrets.token_urlsafe(64)` which gives ~86 chars of [A-Za-z0-9_-]).
    `code_challenge` = base64url(SHA256(code_verifier)) for S256.
    """
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return code_verifier, code_challenge


def _expected_issuer(authorize_url: str) -> str | None:
    """MCP-2 P3 · the issuer we expect to see back in the authorization
    response, per RFC 9207.

    Derived from the authorization endpoint's ORIGIN. That is a
    deliberate approximation: an AS's issuer identifier is whatever its
    metadata says, and for most providers that is the origin — but not
    all (some publish `https://host/tenant`). Getting it slightly wrong
    is safe in the direction that matters, because validation only ever
    *rejects on mismatch of origin*, and the mix-up attack this defends
    against necessarily involves a different origin: the whole attack is
    that the code came from an authorization server the client did not
    send the user to.

    A same-origin issuer path difference produces a false reject, which
    is loud and fixable. A cross-origin one produces the true reject.
    Returns None for an unparseable URL, which downgrades to "cannot
    validate" rather than "reject everything".
    """

    try:
        parsed = urlparse(authorize_url)
    except ValueError:
        return None
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _issuer_origin(issuer: str) -> str | None:
    try:
        parsed = urlparse(issuer)
    except ValueError:
        return None
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


class Rfc9207ViolationError(Exception):
    """The authorization response failed RFC 9207 issuer validation.

    Carries a message safe to render to the operator — it names origins,
    never codes or tokens.
    """


def validate_authorization_response_issuer(
    *, received_iss: str | None, expected_iss: str | None
) -> None:
    """RFC 9207 · Authorization Server Issuer Identification.

    The attack: a client that talks to more than one authorization
    server can be induced to send a code it received from a *malicious*
    AS to an *honest* AS's token endpoint — or vice versa. The code, the
    state and PKCE all validate individually; nothing in the response
    says which AS produced it. RFC 9207 closes that by having the AS
    echo its own issuer, and the client check it.

    Rules, in order:

    - `iss` present and it does not match what we expect → **reject**.
      This is the attack signature and there is no benign reading of it.
    - `iss` absent but we expected one → accept with a warning. The spec
      lets a client demand `iss` only when the AS *advertised* support
      (`authorization_response_iss_parameter_supported`); most static
      OAuth apps we front do not publish metadata at all, so rejecting
      here would break every legacy provider for no security gain
      against an attacker who can simply omit the parameter.
    - We have no expectation → accept. Nothing to compare against.
    """

    if received_iss is None:
        if expected_iss is not None:
            logger.info(
                "oauth_authcode_no_iss_in_response",
                extra={"expected_iss": expected_iss},
            )
        return
    if expected_iss is None:
        logger.info(
            "oauth_authcode_iss_present_but_unverifiable",
            extra={"received_iss": received_iss},
        )
        return

    received_origin = _issuer_origin(received_iss)
    if received_origin is None or received_origin != expected_iss:
        logger.warning(
            "oauth_authcode_issuer_mismatch",
            extra={"received_iss": received_iss, "expected_iss": expected_iss},
        )
        raise Rfc9207ViolationError(
            "The identity provider that answered is not the one we sent you "
            "to. This is the signature of an OAuth mix-up attack, so the "
            "connection was refused."
        )


def _mint_state_token(
    *,
    tenant_id: UUID,
    user_id: UUID,
    server_id: UUID,
    code_verifier: str,
    signing_secret: str,
    expected_iss: str | None = None,
) -> str:
    """Sign a state token tying the IdP redirect to the originating user.

    HS256 JWT with `(tenant_id, user_id, server_id, code_verifier,
    nonce, iat, exp)`. The nonce is opaque — there so two concurrent
    initiate calls from the same user produce different states.
    `code_verifier` is the PKCE secret that the callback echoes back to
    the token endpoint. Embedding it in the state JWT (signed) keeps
    the gateway stateless — no session storage needed for the in-flight
    flow.
    """

    now = int(datetime.now(UTC).timestamp())
    return jwt.encode(
        {
            "iss": _STATE_ISSUER,
            "iat": now,
            "exp": now + _STATE_TTL_SECONDS,
            "tenant_id": str(tenant_id),
            "user_id": str(user_id),
            "server_id": str(server_id),
            "code_verifier": code_verifier,
            # RFC 9207. Signed into the state rather than re-derived at
            # callback time: the state is what ties the response to THIS
            # request, so the expectation must be captured when the
            # request is made, not reconstructed afterwards from data an
            # attacker may since have influenced.
            "expected_iss": expected_iss,
            "nonce": secrets.token_urlsafe(16),
        },
        signing_secret,
        algorithm="HS256",
    )


class _StateClaims(BaseModel):
    tenant_id: UUID
    user_id: UUID
    server_id: UUID
    # `None` for tokens minted before PKCE was added — graceful
    # backwards-compat for any in-flight legacy state at deploy time.
    # New mints always carry the verifier.
    code_verifier: str | None = None
    # RFC 9207. `None` on legacy in-flight state, and on any flow whose
    # authorization URL we could not parse — both downgrade to "cannot
    # validate", never to "reject".
    expected_iss: str | None = None


def _verify_state_token(token: str, *, signing_secret: str) -> _StateClaims:
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            signing_secret,
            algorithms=["HS256"],
            issuer=_STATE_ISSUER,
            options={"require": ["exp", "iat", "iss", "tenant_id", "user_id", "server_id"]},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid or expired oauth-authcode state",
        ) from exc
    try:
        return _StateClaims(
            tenant_id=UUID(claims["tenant_id"]),
            user_id=UUID(claims["user_id"]),
            server_id=UUID(claims["server_id"]),
            code_verifier=claims.get("code_verifier"),
            expected_iss=claims.get("expected_iss"),
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="malformed oauth-authcode state",
        ) from exc


# --- Shared credential + endpoint resolver --------------------------------


def _cimd_client_id_for(settings: Any) -> str | None:
    """Our CIMD client_id, or None if this deployment cannot use CIMD.

    Gated on https because CIMD's entire trust model is "whoever controls
    this URL is the client" — over http that is whoever controls the
    network. Returning None here (rather than letting the AS reject an
    http URL later) keeps a dev deployment on the DCR path it already
    works with, instead of failing every Connect with an AS-side error
    nobody can act on.
    """

    base = getattr(settings, "public_base_url", "") or ""
    if not base.lower().startswith("https://"):
        return None
    from vyuu_gateway.api.cimd import client_id_url

    return client_id_url(base)




async def _resolve_client_id_and_auth_url(
    *,
    server: McpServer,
    spec: dict[str, Any],
    tenant_id: UUID,
    secret_store: Any,
    db: Session,
    settings: Any = None,
) -> tuple[str, str]:
    """Return `(client_id, authorization_endpoint)` for the OAuth
    authorize URL — abstracts over static-creds, CIMD and DCR.

    Static mode: SecretStore lookup for `client_id`, `spec["auth_url"]`
    for the authorize endpoint (operator pre-configured).

    DCR mode: look up cached `mcp_server_dcr_clients` row. If absent
    (first Connect for this server), run the full RFC 9728 → 8414 →
    7591 discovery + registration dance against `server.source_location`,
    persist the result, and return the issued client_id +
    auto-discovered authorization_endpoint. Subsequent users reuse the
    cached row — DCR runs at most once per server.

    CIMD mode (MCP-2 P3) is not a separate branch the operator picks —
    it is chosen inside the same discovery, when the AS advertises
    support. The row that lands in `mcp_server_dcr_clients` then records
    a client_id that is our own document URL, with no secret and nothing
    registered anywhere.

    Raises 502 on DCR failure with the step name surfaced (operators
    see e.g. "DCR failed at registration: vendor may require an Initial
    Access Token").
    """
    if spec.get("dcr_enabled"):
        dcr_row = db.get(McpServerDcrClient, server.id)
        if dcr_row is not None and dcr_row.auth_mechanism == "cimd_rejected":
            # A tombstone, not a usable row: this AS advertised CIMD and
            # then refused our client_id. Re-probing would read the same
            # advertisement and present the same refused URL, so the
            # documented fall-back to DCR only happens if we ignore the
            # advertisement from here on. Dropping it lets registration
            # run below and overwrite the tombstone.
            db.delete(dcr_row)
            db.flush()
            dcr_row = None
            cimd_client_id = None
        else:
            cimd_client_id = _cimd_client_id_for(settings)
        if dcr_row is None:
            # U11 — if the operator configured an Initial Access Token
            # ref (for enterprise IdPs that gate /register behind a
            # Bearer token), resolve it via the SecretStore and pass
            # it to the DCR client. Public SaaS vendors leave this
            # blank; we send no Authorization header in that case.
            iat: str | None = None
            iat_ref = spec.get("initial_access_token_ref") or ""
            if iat_ref:
                try:
                    iat = await secret_store.get_secret(tenant_id, iat_ref)
                except Exception as exc:  # noqa: BLE001
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=(
                            f"DCR failed: initial_access_token_ref "
                            f"{iat_ref!r} could not be resolved from "
                            f"the SecretStore ({exc.__class__.__name__})"
                        ),
                    ) from exc
            try:
                result = await discover_and_register(
                    upstream_url=server.source_location,
                    redirect_uri=spec["redirect_uri"],
                    scopes=list(spec.get("scopes") or []),
                    initial_access_token=iat,
                    cimd_client_id=cimd_client_id,
                )
            except DcrError as exc:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"DCR failed at {exc.step}: {exc.detail}",
                ) from exc
            dcr_row = McpServerDcrClient(
                server_id=server.id,
                tenant_id=tenant_id,
                client_id=result.client_id,
                client_secret=result.client_secret,
                authorization_endpoint=result.authorization_endpoint,
                token_endpoint=result.token_endpoint,
                registration_endpoint=result.registration_endpoint,
                registration_response=result.registration_response,
                # Set explicitly rather than relying on the column
                # default: a column `default=` fires at INSERT, so the
                # attribute reads None on this in-memory instance and
                # the branch below would misread a CIMD row as DCR.
                auth_mechanism=result.auth_mechanism,
            )
            db.add(dcr_row)
            db.commit()
            logger.info(
                "oauth_client_identity_resolved",
                extra={
                    "server_id": str(server.id),
                    "mechanism": result.auth_mechanism,
                    "reason": result.mechanism_reason,
                },
            )
            record_tool_auth(
                tenant_id=tenant_id,
                action=ToolAuthAction.CLIENT_IDENTITY_RESOLVED,
                server_id=server.id,
                # `getattr`: the wiring tests drive this with a bare
                # server stand-in, and a display name is a nicety here.
                server_display=getattr(server, "display_name", None),
                mechanism=result.auth_mechanism,
                reason=result.mechanism_reason,
            )
        return dcr_row.client_id, dcr_row.authorization_endpoint

    # Static-creds path (existing behavior unchanged).
    client_id = await secret_store.get_secret(tenant_id, spec["client_id_ref"])
    return client_id, spec["auth_url"]


# --- Schemas ---------------------------------------------------------------


class InitiateRequest(BaseModel):
    """Payload for POST /initiate. Body is empty for now — server_id is
    in the URL path, principal is from the portal session JWT. Reserved
    for future flags (e.g. force_consent, additional_scopes)."""

    model_config = ConfigDict(extra="forbid")


class InitiateResponse(BaseModel):
    """Returned to the SPA. Browser follows `authorization_url`; the
    state token is opaque to the SPA but must round-trip back."""

    model_config = ConfigDict(extra="forbid")

    authorization_url: str
    state: str
    expires_in_seconds: int


class ConnectionView(BaseModel):
    """One row of the user's connected-account list."""

    model_config = ConfigDict(from_attributes=True)

    server_id: UUID
    server_display_name: str
    scope: str | None
    last_refreshed_at: datetime
    expires_at: datetime | None


# --- Endpoints -------------------------------------------------------------


@router.post(
    "/oauth-authcode/{server_id}/initiate",
    response_model=InitiateResponse,
)
async def oauth_authcode_initiate_endpoint(
    server_id: UUID,
    http_request: Request,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
) -> InitiateResponse:
    """Start the authorization-code flow. Returns the IdP URL the SPA
    should redirect the browser to.

    For DCR-enabled servers, runs RFC 9728 → 8414 → 7591 discovery +
    registration on the FIRST call (per server, not per user) and
    caches the issued credentials in `mcp_server_dcr_clients`.
    """

    settings = http_request.app.state.settings
    secret_store = http_request.app.state.secret_store
    with SessionLocal() as db:
        bind_tenant_context(db, session.tenant_id)
        server = db.scalar(
            select(McpServer).where(
                McpServer.tenant_id == session.tenant_id,
                McpServer.id == server_id,
            )
        )
        if server is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="upstream server not found in tenant",
            )
        spec = server.auth_authcode
        if not spec:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="server is not configured for OAuth authorization-code",
            )

        client_id, authorize_url = await _resolve_client_id_and_auth_url(
            server=server,
            spec=spec,
            tenant_id=session.tenant_id,
            secret_store=secret_store,
            db=db,
            settings=settings,
        )
        spec_snapshot = dict(spec)

    code_verifier, code_challenge = _generate_pkce_pair()
    state = _mint_state_token(
        tenant_id=session.tenant_id,
        user_id=session.user_id,
        server_id=server_id,
        code_verifier=code_verifier,
        signing_secret=settings.portal_session_signing_secret,
        # RFC 9207: capture WHO we are about to send the user to, so the
        # callback can check that the same party answered.
        expected_iss=_expected_issuer(authorize_url),
    )

    query: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": spec_snapshot["redirect_uri"],
        "state": state,
        # PKCE (RFC 7636 S256). OAuth 2.1 mandates this even for
        # confidential clients. Spec-compliant DCR servers (Notion,
        # Linear) require it; static OAuth servers (GitHub, Google)
        # accept it as defense-in-depth without complaint.
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    scopes = spec_snapshot.get("scopes") or []
    if scopes:
        query["scope"] = " ".join(scopes)
    # Provider-specific authorize-URL params (e.g. Google needs
    # access_type=offline + prompt=consent to issue a refresh token).
    # Schema validation already rejects overrides of the reserved
    # params, so we can merge unconditionally.
    extras = spec_snapshot.get("extra_authorize_params") or {}
    for k, v in extras.items():
        query[k] = v

    sep = "&" if "?" in authorize_url else "?"
    auth_url = f"{authorize_url}{sep}{urlencode(query)}"

    return InitiateResponse(
        authorization_url=auth_url,
        state=state,
        expires_in_seconds=_STATE_TTL_SECONDS,
    )


@router.post(
    "/oauth-authcode/{server_id}/operator-initiate",
    response_model=InitiateResponse,
)
async def oauth_authcode_operator_initiate_endpoint(
    server_id: UUID,
    http_request: Request,
    operator: Annotated[AuthenticatedOperator, Depends(authenticate_operator)],
) -> InitiateResponse:
    """Operator-side counterpart to `/initiate`.

    Lets an operator personally authorize a freshly-registered
    auth_authcode upstream BEFORE any portal user has access to a
    vserver wrapping it. Resolves the operator's email to the matching
    `users` row in the same tenant (PLATFORM.md §3.1: bootstrap maps
    operator → user 1:1 by email) and mints a state token carrying
    that user_id. After OAuth completes, the standard /callback writes
    the token row keyed by that user — Sync then succeeds, Publish
    vserver becomes possible.

    Errors:
    - 404 if server doesn't exist in tenant
    - 400 if server has no auth_authcode configured
    - 412 if the operator's email is not registered as a portal user
      (operator must sign into /portal once to provision their user
      record, OR an admin must create the user)
    """

    settings = http_request.app.state.settings
    with SessionLocal() as db:
        bind_tenant_context(db, operator.tenant_id)

        # Resolve operator → user via shared email. The bootstrap path
        # creates this 1:1 mapping; for operators provisioned later an
        # admin needs to also create the matching /portal user. Skip
        # any disabled accounts so a stale row doesn't silently get
        # OAuth tokens written under it.
        operator_row = db.scalar(
            select(Operator).where(Operator.id == operator.operator_id)
        )
        if operator_row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="operator not found",
            )
        user = db.scalar(
            select(User).where(
                User.tenant_id == operator.tenant_id,
                User.email == operator_row.email,
                User.disabled_at.is_(None),
            )
        )
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail=(
                    "Operator email is not registered as a portal user. "
                    "Sign into /portal once with the same email to "
                    "provision your user record, then click Test connect "
                    "again."
                ),
            )

        server = db.scalar(
            select(McpServer).where(
                McpServer.tenant_id == operator.tenant_id,
                McpServer.id == server_id,
            )
        )
        if server is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="upstream server not found in tenant",
            )
        spec = server.auth_authcode
        if not spec:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="server is not configured for OAuth authorization-code",
            )

        secret_store = http_request.app.state.secret_store
        client_id, authorize_url = await _resolve_client_id_and_auth_url(
            server=server,
            spec=spec,
            tenant_id=operator.tenant_id,
            secret_store=secret_store,
            db=db,
            settings=http_request.app.state.settings,
        )
        spec_snapshot = dict(spec)
        user_id = user.id

    code_verifier, code_challenge = _generate_pkce_pair()
    state = _mint_state_token(
        tenant_id=operator.tenant_id,
        user_id=user_id,
        server_id=server_id,
        code_verifier=code_verifier,
        signing_secret=settings.portal_session_signing_secret,
        # RFC 9207 — same capture on the operator "Test connect" path.
        # Both entry points must carry it, or one of them silently loses
        # mix-up protection while the other has it.
        expected_iss=_expected_issuer(authorize_url),
    )

    query: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": spec_snapshot["redirect_uri"],
        "state": state,
        # PKCE (RFC 7636) — see notes on the portal /initiate endpoint.
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    scopes = spec_snapshot.get("scopes") or []
    if scopes:
        query["scope"] = " ".join(scopes)
    extras = spec_snapshot.get("extra_authorize_params") or {}
    for k, v in extras.items():
        query[k] = v

    sep = "&" if "?" in authorize_url else "?"
    auth_url = f"{authorize_url}{sep}{urlencode(query)}"

    return InitiateResponse(
        authorization_url=auth_url,
        state=state,
        expires_in_seconds=_STATE_TTL_SECONDS,
    )


_CALLBACK_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Vyuu Gateway · Connection {status}</title>
  <style>
    body {{
      font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
      background: #F7F4ED; color: #1F2A2E;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; margin: 0;
    }}
    .card {{
      background: #FFFEFB; border: 1px solid #E4DED1;
      border-radius: 12px; padding: 32px 28px; max-width: 460px;
      box-shadow: 0 2px 8px rgba(168, 88, 32, 0.18);
    }}
    h1 {{ font: 500 22px/1.2 Georgia, serif; margin: 0 0 12px;
         letter-spacing: -0.3px; }}
    p  {{ color: #6B7A7D; font: 400 14px/1.55 ui-sans-serif, system-ui;
         margin: 0 0 16px; }}
    a  {{ color: #A85820; text-decoration: none; font-weight: 500; }}
    .err {{ color: #8A4A34; }}
    code {{
      font: 12px ui-monospace, SFMono-Regular, monospace;
      background: #FAEDD5; color: #A85820;
      padding: 1px 5px; border-radius: 4px;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1{cls}>{heading}</h1>
    <p>{message}</p>
    <p><a href="/portal">Return to portal</a></p>
  </div>
</body>
</html>
"""


def _render_callback_html(
    *, status: str, heading: str, message: str, is_error: bool = False
) -> str:
    return _CALLBACK_HTML_TEMPLATE.format(
        status=status,
        cls=' class="err"' if is_error else "",
        heading=heading,
        message=message,
    )


@router.get("/oauth-authcode/callback", response_class=HTMLResponse)
async def oauth_authcode_callback_endpoint(
    http_request: Request,
    code: str | None = None,
    state: str | None = None,
    # RFC 9207 · the authorization server's own issuer identifier. Named
    # `iss` on the wire by the spec.
    iss: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> HTMLResponse:
    """IdP redirects the user's browser here after consent.

    No auth header — the **state token** IS the auth (signed,
    short-lived, carries the originating tenant/user/server).

    On success: persists tokens to `oauth_user_tokens`, returns a small
    HTML page the user sees in their browser. On failure: returns the
    IdP's error description (NEVER any code/token data) in an HTML
    page so operators can debug.
    """

    # Filled in as the callback learns who this is for, so a failure
    # event names the tenant / server / user when it can.
    known: dict[str, Any] = {}

    def _err(http_status: int, heading: str, message: str) -> HTMLResponse:
        if known.get("tenant_id") is not None:
            record_tool_auth(
                tenant_id=known["tenant_id"],
                action=ToolAuthAction.EXCHANGE_FAILED,
                server_id=known.get("server_id"),
                server_display=known.get("server_display"),
                user_id=known.get("user_id"),
                # The heading is ours; the message may quote the IdP
                # (escaped for HTML). Neither ever carries a token.
                reason=f"{heading}: {html.unescape(message)}"[:300],
            )
        return HTMLResponse(
            _render_callback_html(
                status="failed",
                heading=heading,
                message=message,
                is_error=True,
            ),
            status_code=http_status,
        )

    if error:
        # IdP rejected the request (user denied consent, scope error,
        # client_id mismatch, etc.). Surface the description so the
        # operator can debug — never contains tokens.
        # html.escape() defends against an IdP returning attacker-
        # controlled markup in the redirect query string.
        return _err(
            status.HTTP_400_BAD_REQUEST,
            "Connection failed",
            f"OAuth error from IdP: <code>{html.escape(error)}</code> "
            f"{html.escape(error_description or '')}",
        )
    if not code or not state:
        return _err(
            status.HTTP_400_BAD_REQUEST,
            "Connection failed",
            "Missing <code>code</code> or <code>state</code> parameter "
            "in the IdP redirect.",
        )

    settings = http_request.app.state.settings
    try:
        claims = _verify_state_token(
            state, signing_secret=settings.portal_session_signing_secret
        )
    except HTTPException as exc:
        return _err(exc.status_code, "Connection failed", str(exc.detail))
    known.update(
        tenant_id=claims.tenant_id, server_id=claims.server_id, user_id=claims.user_id
    )

    # RFC 9207, checked BEFORE the code is exchanged. The whole point is
    # to avoid handing a code from one authorization server to another's
    # token endpoint, so validating after the exchange would be too late.
    try:
        validate_authorization_response_issuer(
            received_iss=iss, expected_iss=claims.expected_iss
        )
    except Rfc9207ViolationError as exc:
        return _err(status.HTTP_400_BAD_REQUEST, "Connection refused", str(exc))

    with SessionLocal() as db:
        bind_tenant_context(db, claims.tenant_id)
        server = db.scalar(
            select(McpServer).where(
                McpServer.tenant_id == claims.tenant_id,
                McpServer.id == claims.server_id,
            )
        )
        if server is None or not server.auth_authcode:
            return _err(
                status.HTTP_404_NOT_FOUND,
                "Connection failed",
                "Server not found or no longer configured for OAuth.",
            )
        spec = server.auth_authcode
        redirect_uri = spec["redirect_uri"]
        server_id = server.id
        server_display_name = server.display_name
        known["server_display"] = server_display_name

        # Credential resolution: DCR mode pulls cached client_id /
        # client_secret / token_endpoint from `mcp_server_dcr_clients`
        # (the row was provisioned at /initiate time). Static-creds
        # mode goes through the SecretStore + spec["token_url"].
        if spec.get("dcr_enabled"):
            dcr_row = db.get(McpServerDcrClient, server.id)
            if dcr_row is None:
                return _err(
                    status.HTTP_409_CONFLICT,
                    "Connection failed",
                    "DCR client not registered. Restart the Connect flow.",
                )
            client_id = dcr_row.client_id
            client_secret = dcr_row.client_secret  # may be None for public clients
            token_url = dcr_row.token_endpoint
            # Read now, while the row is loaded: the recovery below runs
            # in a fresh session after this one is gone.
            dcr_mechanism = dcr_row.auth_mechanism
        else:
            client_id_ref = spec["client_id_ref"]
            client_secret_ref = spec["client_secret_ref"]
            token_url = spec["token_url"]
            secret_store = http_request.app.state.secret_store
            client_id = await secret_store.get_secret(claims.tenant_id, client_id_ref)
            client_secret = await secret_store.get_secret(claims.tenant_id, client_secret_ref)

    body = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }
    # PKCE (RFC 7636) — echo the verifier back to the token endpoint
    # so it can hash + compare against the challenge sent at /authorize.
    # Required by OAuth 2.1 / DCR-spec servers (Notion, Linear);
    # ignored by static OAuth servers without PKCE support. The state
    # JWT is the carrier — embedding the verifier in a signed token
    # keeps the gateway stateless across the redirect round trip.
    if claims.code_verifier:
        body["code_verifier"] = claims.code_verifier

    # Confidential clients (most static OAuth + Notion/Linear DCR)
    # use HTTP Basic auth. Public clients (PKCE-only DCR with no
    # secret) send `client_id` in the form body per RFC 6749 §3.2.1.
    request_kwargs: dict[str, Any] = {
        "data": body,
        # `Accept: application/json` is REQUIRED for GitHub — without
        # it GitHub's token endpoint returns form-urlencoded
        # `access_token=...&scope=...&...`, which our `response.json()`
        # parse rejects. Other IdPs return JSON regardless; sending
        # Accept costs nothing and fixes GitHub.
        "headers": {"Accept": "application/json"},
        "timeout": 10.0,
    }
    if client_secret:
        request_kwargs["auth"] = (client_id, client_secret)
    else:
        body["client_id"] = client_id

    async with httpx.AsyncClient() as http:
        try:
            response = await http.post(token_url, **request_kwargs)
        except httpx.HTTPError as exc:
            return _err(
                status.HTTP_502_BAD_GATEWAY,
                "Connection failed",
                f"Token endpoint unreachable: <code>{exc.__class__.__name__}</code>",
            )

    if response.status_code != 200:
        # RFC 6749 §5.2 — `invalid_client` from the token endpoint
        # means the AS no longer recognizes our client credentials.
        # For DCR upstreams this happens when the gateway-issued
        # client gets evicted between authorize and token exchange
        # (rare race). Drop the stale dcr_clients row so the next
        # /initiate triggers fresh registration. The user must re-
        # Connect because the authcode they have is bound to the
        # dead client_id and can't be reused.
        from vyuu_gateway.upstream.oauth_authcode import (
            _looks_like_invalid_client,
        )
        if spec.get("dcr_enabled") and _looks_like_invalid_client(response):
            # `invalid_client` means opposite things per mechanism.
            #
            # DCR: the registration was evicted. Dropping the row makes
            # the next Connect register again, which fixes it.
            #
            # CIMD: nothing was ever registered. The AS advertised
            # support and then refused our document URL, so dropping the
            # row would re-probe, read the same advertisement, present
            # the same refused URL and fail identically — a permanent
            # Connect failure assembled from two correct behaviours. The
            # row is marked instead, and that marker is what makes the
            # documented fall-back to DCR actually happen.
            cimd_refused = dcr_mechanism == "cimd"
            with SessionLocal() as cleanup_db:
                bind_tenant_context(cleanup_db, claims.tenant_id)
                if cimd_refused:
                    cleanup_db.execute(
                        sa_update(McpServerDcrClient)
                        .where(McpServerDcrClient.server_id == claims.server_id)
                        .values(auth_mechanism="cimd_rejected")
                    )
                else:
                    cleanup_db.execute(
                        sa_delete(McpServerDcrClient).where(
                            McpServerDcrClient.server_id == claims.server_id
                        )
                    )
                cleanup_db.execute(
                    sa_delete(OAuthUserToken).where(
                        OAuthUserToken.tenant_id == claims.tenant_id,
                        OAuthUserToken.server_id == claims.server_id,
                    )
                )
                cleanup_db.commit()
            if cimd_refused:
                logger.warning(
                    "cimd_refused_by_as_falling_back_to_dcr",
                    extra={"server_id": str(claims.server_id)},
                )
                return _err(
                    status.HTTP_409_CONFLICT,
                    "Reconnect required",
                    "The upstream authorization server advertises "
                    "client-ID-metadata-document support but rejected "
                    "this gateway's document. The gateway has recorded "
                    "that and will register conventionally instead. "
                    "Click Connect again.",
                )
            return _err(
                status.HTTP_409_CONFLICT,
                "Reconnect required",
                "The upstream OAuth client credentials were revoked "
                "between authorize and token exchange. The gateway "
                "has dropped the stale registration. Click Connect "
                "again — the next attempt will provision fresh "
                "credentials automatically.",
            )
        return _err(
            status.HTTP_502_BAD_GATEWAY,
            "Connection failed",
            f"Token endpoint returned status <code>{response.status_code}</code>.",
        )

    try:
        payload: dict[str, Any] = response.json()
    except ValueError:
        return _err(
            status.HTTP_502_BAD_GATEWAY,
            "Connection failed",
            "Token endpoint returned non-JSON response.",
        )

    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        return _err(
            status.HTTP_502_BAD_GATEWAY,
            "Connection failed",
            "Token response missing <code>access_token</code>.",
        )
    refresh_token = payload.get("refresh_token")
    if refresh_token is not None and not isinstance(refresh_token, str):
        refresh_token = None
    token_type = payload.get("token_type") or "Bearer"
    if not isinstance(token_type, str):
        token_type = "Bearer"
    scope = payload.get("scope")
    if not isinstance(scope, str):
        scope = None
    expires_in = payload.get("expires_in")
    expires_at = (
        datetime.now(UTC) + timedelta(seconds=float(expires_in))
        if isinstance(expires_in, (int, float)) and expires_in > 0
        else None
    )

    # Upsert: if the user reconnects a server they're already connected
    # to, replace the row in-place rather than fail on the unique
    # constraint.
    with SessionLocal() as db:
        bind_tenant_context(db, claims.tenant_id)
        existing = db.scalar(
            select(OAuthUserToken).where(
                OAuthUserToken.tenant_id == claims.tenant_id,
                OAuthUserToken.user_id == claims.user_id,
                OAuthUserToken.server_id == server_id,
            )
        )
        # AWS-KMS-1 · seal before persisting. A refresh token is durable
        # delegated access to the user's SaaS account; plaintext in
        # Postgres means a dump, a backup or a read replica hands over
        # every connected account at once, silently.
        cipher = get_envelope_cipher()
        _seal = functools.partial(
            seal_token,
            cipher,
            tenant_id=claims.tenant_id,
            user_id=claims.user_id,
            server_id=server_id,
        )
        if existing is not None:
            existing.access_token = _seal(access_token, field="access_token")
            existing.refresh_token = _seal(refresh_token, field="refresh_token")
            existing.token_type = token_type
            existing.scope = scope
            existing.expires_at = expires_at
            existing.last_refreshed_at = datetime.now(UTC)
        else:
            db.add(
                OAuthUserToken(
                    id=uuid4(),
                    tenant_id=claims.tenant_id,
                    user_id=claims.user_id,
                    server_id=server_id,
                    access_token=_seal(access_token, field="access_token"),
                    refresh_token=_seal(refresh_token, field="refresh_token"),
                    token_type=token_type,
                    scope=scope,
                    expires_at=expires_at,
                )
            )
        db.commit()
    record_tool_auth(
        tenant_id=claims.tenant_id,
        action=ToolAuthAction.CONNECTED,
        server_id=server_id,
        server_display=server_display_name,
        user_id=claims.user_id,
        detail={"scope": scope, "token_type": token_type},
    )

    return HTMLResponse(
        _render_callback_html(
            status="ok",
            heading=f"Connected to {html.escape(server_display_name)}",
            message=(
                "Your account is linked. You can close this tab and return "
                "to the portal — tool calls that need this connection will "
                "now work as you."
            ),
        )
    )


@router.get(
    "/oauth-authcode/connections",
    response_model=list[ConnectionView],
)
def oauth_authcode_list_connections_endpoint(
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
) -> list[ConnectionView]:
    """List the calling user's connected accounts. Joined against
    `mcp_servers` so the SPA can render display names without a
    second round trip."""

    rows = db.execute(
        select(OAuthUserToken, McpServer).join(
            McpServer, McpServer.id == OAuthUserToken.server_id
        ).where(
            OAuthUserToken.tenant_id == session.tenant_id,
            OAuthUserToken.user_id == session.user_id,
        )
    ).all()
    return [
        ConnectionView(
            server_id=token.server_id,
            server_display_name=server.display_name,
            scope=token.scope,
            last_refreshed_at=token.last_refreshed_at,
            expires_at=token.expires_at,
        )
        for token, server in rows
    ]


@router.delete(
    "/oauth-authcode/{server_id}/connection",
    status_code=status.HTTP_204_NO_CONTENT,
)
def oauth_authcode_disconnect_endpoint(
    server_id: UUID,
    session: Annotated[PortalSession, Depends(authenticate_portal_session)],
    db: Annotated[Session, Depends(get_portal_scoped_db)],
) -> None:
    """User disconnects their account. Deletes the row in
    `oauth_user_tokens`. Does NOT call the IdP's revocation endpoint
    (not every IdP exposes one) — operators with strict revocation
    requirements can do that out-of-band."""

    db.execute(
        sa_delete(OAuthUserToken).where(
            OAuthUserToken.tenant_id == session.tenant_id,
            OAuthUserToken.user_id == session.user_id,
            OAuthUserToken.server_id == server_id,
        )
    )
    db.commit()
    record_tool_auth(
        tenant_id=session.tenant_id,
        action=ToolAuthAction.DISCONNECTED,
        server_id=server_id,
        user_id=session.user_id,
    )
