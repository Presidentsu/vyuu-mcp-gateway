"""Per-directory sign-in routes (Phase 4 of IDP-1).

Unlike the existing `/auth/{tenant}/oidc/{provider}` routes — which
use a single deployment-wide `microsoft` / `google` OIDC config out
of env vars — these routes resolve the OIDC provider from the
directory's `idp_directories` row, so each tenant's connected Entra
or Workspace gets its own client_id / client_secret / issuer.

Two routes:

- `GET  /auth/{tenant_id}/idp/{directory_id}/oidc-start` — build the
  IdP's `/authorize` URL.
- `POST /auth/{tenant_id}/idp/{directory_id}/oidc-callback` — exchange
  the code, look up the user by `(directory_id, external_id=sub)`,
  mint a portal session.

The lookup matches users provisioned via SCIM: SCIM stamps
`(idp_directory_id, external_id)` on `users` when the IdP creates
the row, and OIDC's `sub` claim is the same external id Entra/
Workspace sent. So sign-in is a clean "find by directory + sub"
rather than the old email-keyed JIT path.

If SCIM hasn't run yet (the user is signing in before the IdP has
pushed their provisioning event), we **JIT-create** a placeholder
user row with `auth_method=scim` + `idp_directory_id` set + the
external_id from the OIDC `sub`. The next SCIM sync flips the row
into the canonical state by matching on `(directory_id, external_id)`.

SAML support (Phase 4b) ships in a follow-up; this file is OIDC only.
"""

from __future__ import annotations

import json
import logging
import secrets
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from vyuu_gateway.audit.admin_audit import (
    AdminAuditActor,
    AdminAuditTarget,
    record_admin_action,
)
from vyuu_gateway.db.models import (
    IdpDirectory,
    IdpSigninProtocol,
    User,
)
from vyuu_gateway.db.session import SessionLocal, bind_tenant_context
from vyuu_gateway.idp.saml_provider import (
    SamlLoginResult,
    SamlProvider,
    SamlValidationError,
)
from vyuu_gateway.idp.service import (
    IdpDirectoryNotFoundError,
    find_or_jit_create_directory_user,
    get_idp_directory,
)
from vyuu_gateway.secrets.store import SecretNotFoundError, SecretStore
from vyuu_gateway.siem.bridges import record_signin
from vyuu_gateway.siem.events import AuthMethod, AuthOutcome, AuthSurface
from vyuu_gateway.users.oidc import (
    JwksCache,
    OidcConfig,
    OidcValidationError,
)
from vyuu_gateway.users.oidc_providers import OidcLoginResult, OidcProvider
from vyuu_gateway.users.sessions import issue_portal_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])


# --- Default-tenant resolution (single-tenant on-prem deployments) -------


class _DefaultTenantResponse(BaseModel):
    """Minimal payload — login pages just need the tenant_id to bind
    sessionStorage + the display_name to put on the welcome card."""

    model_config = ConfigDict(from_attributes=False)

    tenant_id: UUID
    display_name: str


@router.get(
    "/default-tenant",
    response_model=_DefaultTenantResponse,
)
def default_tenant_endpoint(request: Request) -> _DefaultTenantResponse:
    """Returns the deployment's bound tenant when this is a single-
    tenant on-prem install. 404 in multi-tenant SaaS deployments where
    the user must specify a tenant.

    Public (no auth) by design — login pages call this BEFORE any
    user has a session. The only thing leaked is "this gateway is
    bound to tenant X with display name Y", which any user of that
    deployment already knows.
    """

    settings = request.app.state.settings

    # IDP-3 · a tenant subdomain wins over the deployment default, so a
    # multi-tenant SaaS build resolves per-request from `Host` while an
    # on-prem build keeps using `default_tenant_id`. Extending THIS
    # endpoint rather than adding a dispatcher is deliberate: both login
    # pages already call it and already auto-fill from the answer, so
    # subdomain routing lands with no change to either page.
    #
    # `Host` is client-supplied. This grants nothing — it only selects
    # which login page renders. See `api/tenant_routing.py`.
    from vyuu_gateway.api.tenant_routing import tenant_from_host

    base_domain = getattr(settings, "portal_base_domain", None)
    if base_domain:
        with SessionLocal() as session:
            host_tenant = tenant_from_host(
                session,
                host=request.headers.get("host"),
                base_domain=base_domain,
            )
            if host_tenant is not None:
                return _DefaultTenantResponse(
                    tenant_id=host_tenant.id,
                    display_name=host_tenant.name,
                )

    default_tenant_id = getattr(settings, "default_tenant_id", None)
    if default_tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no default tenant configured (multi-tenant deployment)",
        )

    # Look up the display name from `tenants` so the login page can
    # show "Sign in to <Tenant Display Name>" instead of just a UUID.
    # Untenanted SELECT — single-tenant deployments by definition can
    # see this row.
    from vyuu_gateway.db.models import Tenant  # local import — avoids cycle

    with SessionLocal() as session:
        tenant = session.scalar(
            select(Tenant).where(Tenant.id == default_tenant_id)
        )
        if tenant is None:
            # Misconfig — env points at a tenant that doesn't exist.
            # Don't surface the UUID; just say it's not configured.
            logger.warning(
                "default_tenant_id_misconfig",
                extra={"tenant_id": str(default_tenant_id)},
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="default tenant not found",
            )
        return _DefaultTenantResponse(
            tenant_id=tenant.id,
            display_name=tenant.name,
        )


def _portal_landing_html(
    *, tenant_id: UUID, session_token: str, email: str
) -> HTMLResponse:
    """Tiny landing page returned at the end of the user-portal SSO
    redirect chain. The browser is sitting on our SAML/OIDC callback
    URL — we want to land them in the portal app shell with the
    session already persisted, NOT show them raw JSON.

    Approach: render HTML that runs JS to set sessionStorage (the
    same keys the portal frontend reads from) and `replace()` the
    URL with `/portal/`. `replace()` keeps the browser back-button
    sane — back doesn't go to "your callback URL" mid-flow.

    Same security posture as the existing portal — sessionStorage is
    XSS-readable, not HttpOnly. We're not regressing here; the portal
    has always stored the JWT this way.
    """

    # JSON-encode each value so quotes / non-ASCII land cleanly inside
    # the inline <script>. Belt-and-suspenders against an admin who
    # pastes a directory display name with a quote in it.
    token_lit = json.dumps(session_token)
    tenant_lit = json.dumps(str(tenant_id))
    email_lit = json.dumps(email)
    body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Signing in&hellip;</title>
  <style>
    body {{
      font: 400 14px/1.5 -apple-system, system-ui, sans-serif;
      color: #1F2A2E;
      background: #F7F4ED;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
    }}
    .card {{
      background: #FFFEFB;
      border: 1px solid #E4DED1;
      border-radius: 8px;
      padding: 24px 32px;
      text-align: center;
    }}
    .card p {{ margin: 0; color: #6B7A7D; }}
  </style>
</head>
<body>
  <div class="card">
    <p>Signing you in&hellip;</p>
  </div>
  <script>
    sessionStorage.setItem("vyuu.portal.tenant", {tenant_lit});
    sessionStorage.setItem("vyuu.portal.token", {token_lit});
    sessionStorage.setItem("vyuu.portal.email", {email_lit});
    window.location.replace("/portal/");
  </script>
</body>
</html>"""
    return HTMLResponse(body)


# Public — no operator auth — list of connected directories for one
# tenant, filtered to the bits the login pages need to render
# "Continue with X" buttons. No bearer hashes, no client_secret_refs,
# no SAML certs — just enough to build the per-directory start URL.
class _PublicIdpDirectorySummary(BaseModel):
    model_config = ConfigDict(from_attributes=False)

    id: UUID
    kind: str
    display_name: str
    signin_protocol: str
    # EMA-1 P3 · whether agents can obtain a gateway token via this
    # directory's IdP. Safe to disclose — it says "SSO can authorize
    # your AI client here", the same class of fact as the directory's
    # existence, and lets the portal tell users they may not need to
    # mint an API key at all.
    ema_enabled: bool = False


@router.get(
    "/{tenant_id}/idp-directories",
    response_model=list[_PublicIdpDirectorySummary],
)
def list_public_idp_directories_endpoint(
    tenant_id: UUID,
) -> list[_PublicIdpDirectorySummary]:
    """Unauthenticated lookup so the operator-console + portal login
    pages can enumerate connected directories and render
    "Continue with X" buttons. Only safe-to-disclose fields are
    returned — anything operator-only (cert, secret refs, SCIM
    token hash) is filtered server-side.

    The list is per-tenant so a sign-in page bound to tenant A
    doesn't leak directory names from tenant B.
    """

    with SessionLocal() as session:
        bind_tenant_context(session, tenant_id)
        rows = session.scalars(
            select(IdpDirectory).where(IdpDirectory.tenant_id == tenant_id)
        ).all()
        return [
            _PublicIdpDirectorySummary(
                id=d.id,
                kind=(d.kind.value if hasattr(d.kind, "value") else str(d.kind)),
                display_name=d.display_name,
                signin_protocol=(
                    d.signin_protocol.value
                    if hasattr(d.signin_protocol, "value")
                    else str(d.signin_protocol)
                ),
                ema_enabled=bool(getattr(d, "ema_enabled", False)),
            )
            for d in rows
        ]

# Single process-wide JWKS cache. Keyed internally by issuer URL, so
# multiple directories pointing at the same issuer (e.g., two tenants
# each with their own Entra app under contoso.onmicrosoft.com) reuse
# JWKS fetches.
_JWKS_CACHE = JwksCache()


# --- Request / response shapes -------------------------------------------


class IdpOidcStartResponse(BaseModel):
    model_config = ConfigDict(from_attributes=False)

    authorization_url: str
    state: str


class IdpOidcCallbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    code: str
    state: str


class IdpSigninResponse(BaseModel):
    model_config = ConfigDict(from_attributes=False)

    session_token: str
    user_id: UUID
    email: str
    auth_method: str
    # Populated true when the user row didn't exist before this sign-in
    # (race: user opens the portal before SCIM has pushed them). The
    # next SCIM sync will reconcile the placeholder.
    jit_created: bool


# --- Routes --------------------------------------------------------------


@router.get(
    "/{tenant_id}/idp/{directory_id}/oidc-start",
    response_model=IdpOidcStartResponse,
)
async def oidc_start_endpoint(
    tenant_id: UUID,
    directory_id: UUID,
    request: Request,
) -> IdpOidcStartResponse:
    directory = _load_directory(tenant_id, directory_id)
    if directory.signin_protocol != IdpSigninProtocol.OIDC:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="directory is not OIDC-configured",
        )

    provider = await _build_provider(request, directory)
    state = f"{tenant_id}.{directory_id}.{secrets.token_urlsafe(24)}"
    nonce = secrets.token_urlsafe(16)
    return IdpOidcStartResponse(
        authorization_url=provider.authorization_url(state=state, nonce=nonce),
        state=state,
    )


@router.post(
    "/{tenant_id}/idp/{directory_id}/oidc-callback",
    response_model=IdpSigninResponse,
)
async def oidc_callback_endpoint(
    tenant_id: UUID,
    directory_id: UUID,
    body: IdpOidcCallbackRequest,
    request: Request,
) -> IdpSigninResponse:
    """Programmatic callback — frontend exchanges code+state via POST
    JSON. Returns the session token as JSON. Used by SDK callers /
    automated tests."""

    return await _do_user_oidc_exchange(
        request=request,
        tenant_id=tenant_id,
        directory_id=directory_id,
        code=body.code,
        state=body.state,
        as_html=False,
    )


@router.get(
    "/{tenant_id}/idp/{directory_id}/oidc-callback",
)
async def oidc_callback_browser_endpoint(
    tenant_id: UUID,
    directory_id: UUID,
    request: Request,
    code: str,
    state: str,
) -> HTMLResponse:
    """Browser-redirect callback — the IdP sends the user here with
    `?code=…&state=…` in query. We exchange synchronously, mint the
    session, and render an HTML page that persists it to
    sessionStorage + replaces the URL with `/portal/` so the user
    lands signed-in instead of staring at JSON.

    This is what the IdP's app registration's "redirect URI" should
    point at — same path as the POST callback, GET method."""

    return await _do_user_oidc_exchange(  # type: ignore[return-value]
        request=request,
        tenant_id=tenant_id,
        directory_id=directory_id,
        code=code,
        state=state,
        as_html=True,
    )


async def _do_user_oidc_exchange(
    *,
    request: Request,
    tenant_id: UUID,
    directory_id: UUID,
    code: str,
    state: str,
    as_html: bool,
) -> IdpSigninResponse | HTMLResponse:
    """Shared core for both the JSON-POST and browser-GET OIDC
    callbacks. Validates state prefix, exchanges the code, looks up
    or JIT-creates the user, mints a portal session. Returns the
    session-bearing JSON in `as_html=False` mode, an HTML
    landing-page in `as_html=True` mode."""

    directory = _load_directory(tenant_id, directory_id)
    if directory.signin_protocol != IdpSigninProtocol.OIDC:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="directory is not OIDC-configured",
        )
    expected_prefix = f"{tenant_id}.{directory_id}."
    if not state.startswith(expected_prefix):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="state does not match path",
        )

    provider = await _build_provider(request, directory)
    try:
        result = await provider.exchange_code_for_id_token(code=code)
    except OidcValidationError as exc:
        record_signin(
            request, tenant_id=tenant_id, surface=AuthSurface.PORTAL,
            method=AuthMethod.OIDC, outcome=AuthOutcome.FAILURE, subject=None,
            reason="oidc validation failed",
            directory_id=directory.id, directory_display=directory.display_name,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OIDC validation failed",
        ) from exc

    settings = request.app.state.settings
    with SessionLocal() as session:
        bind_tenant_context(session, tenant_id)
        user, jit_created = _find_or_jit_create_user(
            session, directory=directory, oidc_result=result
        )
        user.last_login_at = datetime.now(UTC)
        record_signin(
            request, tenant_id=tenant_id, surface=AuthSurface.PORTAL,
            method=AuthMethod.OIDC, outcome=AuthOutcome.SUCCESS,
            subject=user.email, subject_id=user.id,
            directory_id=directory.id, directory_display=directory.display_name,
        )
        if jit_created:
            record_admin_action(
                session,
                tenant_id=tenant_id,
                actor=AdminAuditActor.scim(directory.display_name),
                action="scim.jit_create_user",
                target=AdminAuditTarget(
                    kind="user", id=user.id, display=user.email
                ),
                detail={
                    "directory_id": str(directory_id),
                    "external_id": result.subject,
                    "reason": "oidc_signin_before_scim_provisioned",
                },
            )
        session.commit()
        session.refresh(user)

        token = issue_portal_session(
            tenant_id=tenant_id,
            user_id=user.id,
            email=user.email,
            auth_method=user.auth_method.value
            if hasattr(user.auth_method, "value")
            else str(user.auth_method),
            signing_secret=settings.portal_session_signing_secret,
            ttl_seconds=settings.portal_session_ttl_seconds,
        )
        if as_html:
            return _portal_landing_html(
                tenant_id=tenant_id,
                session_token=token,
                email=user.email,
            )
        return IdpSigninResponse(
            session_token=token,
            user_id=user.id,
            email=user.email,
            auth_method=(
                user.auth_method.value
                if hasattr(user.auth_method, "value")
                else str(user.auth_method)
            ),
            jit_created=jit_created,
        )


# --- Helpers --------------------------------------------------------------


def _load_directory(tenant_id: UUID, directory_id: UUID) -> IdpDirectory:
    with SessionLocal() as session:
        bind_tenant_context(session, tenant_id)
        try:
            return get_idp_directory(
                session, tenant_id=tenant_id, directory_id=directory_id
            )
        except IdpDirectoryNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="directory not found",
            ) from exc


async def _build_provider(
    request: Request, directory: IdpDirectory
) -> OidcProvider:
    """Construct an OidcProvider from the directory's stored config.

    `client_secret_ref` resolves through the deployment's secret_store.
    The redirect_uri is computed from the request base URL — the same
    URL the admin pasted into the IdP's app registration.
    """

    if (
        not directory.oidc_issuer
        or not directory.oidc_client_id
        or not directory.oidc_client_secret_ref
    ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC config incomplete on directory",
        )

    secret_store: SecretStore | None = getattr(
        request.app.state, "secret_store", None
    )
    if secret_store is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="secret store not configured",
        )

    try:
        client_secret = await secret_store.get_secret(
            directory.tenant_id, directory.oidc_client_secret_ref
        )
    except SecretNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="oidc_client_secret_ref does not resolve",
        ) from exc

    base = str(request.base_url).rstrip("/")
    redirect_uri = (
        f"{base}/api/v1/auth/{directory.tenant_id}/idp/{directory.id}/oidc-callback"
    )

    return OidcProvider(
        config=OidcConfig(
            issuer_url=directory.oidc_issuer,
            audience=directory.oidc_client_id,
            email_claim="email",
            # `sub` is the universal OIDC stable subject claim. For
            # Entra it's the user's `oid` (we tell admins to wire that
            # mapping at app-registration time); for Google it's the
            # native `sub`. We'll honour whichever the IdP sends.
            subject_claim="sub",
        ),
        client_id=directory.oidc_client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        jwks_cache=_JWKS_CACHE,
    )


def _find_or_jit_create_user(
    db,
    *,
    directory: IdpDirectory,
    oidc_result: OidcLoginResult,
) -> tuple[User, bool]:
    """Locate the user row provisioned for this OIDC subject under
    this directory. JIT-create a placeholder row if SCIM hasn't run
    yet — the next SCIM sync reconciles by `(directory_id,
    external_id)` and back-fills metadata.
    """

    # Shared with SAML sign-in + EMA-1's token exchange — one matching
    # rule, one placeholder shape (see idp/service.py).
    return find_or_jit_create_directory_user(
        db,
        directory=directory,
        subject=oidc_result.subject,
        email=oidc_result.email,
        display_name=oidc_result.display_name,
    )


# =========================================================================
# SAML sign-in (Phase 4b)
# =========================================================================
#
# Same shape as OIDC, different transport. Three routes:
#
# - `GET  /auth/{tenant_id}/idp/{directory_id}/saml-login` — build the
#   IdP redirect (HTTP-Redirect binding). Browser follows the 302 to
#   the IdP's SSO URL with our `SAMLRequest` + `RelayState=state`.
#
# - `POST /auth/{tenant_id}/idp/{directory_id}/saml-acs` — Assertion
#   Consumer Service. The IdP form-POSTs `SAMLResponse` + `RelayState`
#   here. We validate the signature against the directory's stored
#   cert, extract the NameID + email, find/JIT-create the user, mint
#   a portal session, and (for now) return the session token in JSON.
#
# - `GET  /auth/{tenant_id}/idp/{directory_id}/saml-metadata` — SP
#   metadata XML for the admin to paste into Entra / Workspace's
#   "SAML application" config.


@router.get(
    "/{tenant_id}/idp/{directory_id}/saml-login",
)
async def saml_login_endpoint(
    tenant_id: UUID,
    directory_id: UUID,
    request: Request,
) -> RedirectResponse:
    directory = _load_directory(tenant_id, directory_id)
    if directory.signin_protocol != IdpSigninProtocol.SAML:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="directory is not SAML-configured",
        )

    provider = _build_saml_provider(request, directory)
    state = f"{tenant_id}.{directory_id}.{secrets.token_urlsafe(24)}"
    try:
        target = provider.prepare_login(state=state)
    except SamlValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to build SAML AuthnRequest",
        ) from exc
    return RedirectResponse(target, status_code=status.HTTP_302_FOUND)


@router.post("/{tenant_id}/idp/{directory_id}/saml-acs")
async def saml_acs_endpoint(
    tenant_id: UUID,
    directory_id: UUID,
    request: Request,
    SAMLResponse: Annotated[str, Form()],
    RelayState: Annotated[str | None, Form()] = None,
) -> HTMLResponse:
    """Browser-form-POSTed by the IdP at the end of SAML SSO. We
    validate, mint a portal session, and render an HTML page that
    persists the session into sessionStorage + redirects to /portal/.
    The user lands signed-in in the portal app shell — they never see
    raw JSON.
    """

    directory = _load_directory(tenant_id, directory_id)
    if directory.signin_protocol != IdpSigninProtocol.SAML:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="directory is not SAML-configured",
        )

    # RelayState is purely an SP-initiated session-continuity hint —
    # cross-directory replay defence comes from pysaml2 validating the
    # signed `<Audience>` element against our directory-keyed SP
    # entity_id. Accept whatever the IdP sends.
    del RelayState  # noqa: F821 — kept for the FastAPI form binding

    provider = _build_saml_provider(request, directory)
    try:
        result = provider.parse_response(SAMLResponse)
    except SamlValidationError as exc:
        # Generic 401 — we don't disclose whether the signature, the
        # NotOnOrAfter window, or a missing attribute was at fault.
        record_signin(
            request, tenant_id=tenant_id, surface=AuthSurface.PORTAL,
            method=AuthMethod.SAML, outcome=AuthOutcome.FAILURE, subject=None,
            reason="saml validation failed",
            directory_id=directory.id, directory_display=directory.display_name,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SAML validation failed",
        ) from exc

    settings = request.app.state.settings
    with SessionLocal() as session:
        bind_tenant_context(session, tenant_id)
        user, jit_created = _find_or_jit_create_saml_user(
            session, directory=directory, saml_result=result
        )
        user.last_login_at = datetime.now(UTC)
        record_signin(
            request, tenant_id=tenant_id, surface=AuthSurface.PORTAL,
            method=AuthMethod.SAML, outcome=AuthOutcome.SUCCESS,
            subject=user.email, subject_id=user.id,
            directory_id=directory.id, directory_display=directory.display_name,
        )
        if jit_created:
            record_admin_action(
                session,
                tenant_id=tenant_id,
                actor=AdminAuditActor.scim(directory.display_name),
                action="scim.jit_create_user",
                target=AdminAuditTarget(
                    kind="user", id=user.id, display=user.email
                ),
                detail={
                    "directory_id": str(directory_id),
                    "external_id": result.name_id,
                    "reason": "saml_signin_before_scim_provisioned",
                },
            )
        session.commit()
        session.refresh(user)

        token = issue_portal_session(
            tenant_id=tenant_id,
            user_id=user.id,
            email=user.email,
            auth_method=user.auth_method.value
            if hasattr(user.auth_method, "value")
            else str(user.auth_method),
            signing_secret=settings.portal_session_signing_secret,
            ttl_seconds=settings.portal_session_ttl_seconds,
        )
        return _portal_landing_html(
            tenant_id=tenant_id, session_token=token, email=user.email
        )


@router.get(
    "/{tenant_id}/idp/{directory_id}/saml-metadata",
)
async def saml_metadata_endpoint(
    tenant_id: UUID,
    directory_id: UUID,
    request: Request,
) -> Response:
    """SP metadata XML the admin pastes into Entra / Workspace.

    Mounted as a public-readable endpoint so the IdP can also fetch
    it directly via metadata-URL — the metadata carries no secrets;
    just our entity id, ACS URL, and supported NameID format.
    """

    directory = _load_directory(tenant_id, directory_id)
    if directory.signin_protocol != IdpSigninProtocol.SAML:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="directory is not SAML-configured",
        )
    provider = _build_saml_provider(request, directory)
    return Response(
        content=provider.metadata_xml(),
        media_type="application/samlmetadata+xml",
    )


def _build_saml_provider(
    request: Request, directory: IdpDirectory
) -> SamlProvider:
    """Construct a SamlProvider from the directory's stored config."""

    if (
        not directory.saml_entity_id
        or not directory.saml_sso_url
        or not directory.saml_idp_certificate
    ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SAML config incomplete on directory",
        )

    base = str(request.base_url).rstrip("/")
    sp_entity_id = f"{base}/saml/{directory.id}"
    sp_acs_url = (
        f"{base}/api/v1/auth/{directory.tenant_id}/idp/{directory.id}/saml-acs"
    )
    return SamlProvider(
        sp_entity_id=sp_entity_id,
        sp_acs_url=sp_acs_url,
        idp_entity_id=directory.saml_entity_id,
        idp_sso_url=directory.saml_sso_url,
        idp_certificate_pem=directory.saml_idp_certificate,
    )


def _find_or_jit_create_saml_user(
    db,
    *,
    directory: IdpDirectory,
    saml_result: SamlLoginResult,
) -> tuple[User, bool]:
    """SAML equivalent of `_find_or_jit_create_user` — match on
    `(directory_id, external_id=NameID)`, JIT-create if SCIM hasn't
    pushed the user yet."""

    return find_or_jit_create_directory_user(
        db,
        directory=directory,
        subject=saml_result.name_id,
        email=saml_result.email,
        display_name=saml_result.display_name,
    )


# =========================================================================
# Operator-side IdP sign-in
# =========================================================================
#
# Same OIDC + SAML plumbing as the user-portal flow above, but the
# callback mints an OPERATOR JWT instead of a portal session — and
# the lookup is by email against the `operators` table, not by
# (directory_id, external_id) against `users`.
#
# This is what powers the "Continue with Google / Microsoft" buttons
# on the operator console login page. The operator must already exist
# in the `operators` table for the tenant — we don't auto-create
# operators (that'd be a privilege-escalation surface). Unknown
# emails get 403 with a clear message.

from vyuu_gateway.db.models import Operator  # noqa: E402
from vyuu_gateway.operator_auth.fake import (  # noqa: E402
    mint_operator_test_token,
)


class OperatorIdpSigninResponse(BaseModel):
    model_config = ConfigDict(from_attributes=False)

    operator_token: str
    operator_id: UUID
    email: str
    role: str


operator_idp_router = APIRouter(tags=["operator-auth"])


@operator_idp_router.get(
    "/{tenant_id}/idp/{directory_id}/oidc-start",
    response_model=IdpOidcStartResponse,
)
async def operator_oidc_start_endpoint(
    tenant_id: UUID,
    directory_id: UUID,
    request: Request,
) -> IdpOidcStartResponse:
    """Identical to the user-portal `oidc-start` except for the
    redirect_uri — which the operator-side `_build_provider` builds
    against the operator-callback URL so the IdP returns the user
    to the operator-side handler."""

    directory = _load_directory(tenant_id, directory_id)
    if directory.signin_protocol != IdpSigninProtocol.OIDC:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="directory is not OIDC-configured",
        )
    provider = await _build_provider_for_operator(request, directory)
    state = f"op.{tenant_id}.{directory_id}.{secrets.token_urlsafe(24)}"
    nonce = secrets.token_urlsafe(16)
    return IdpOidcStartResponse(
        authorization_url=provider.authorization_url(state=state, nonce=nonce),
        state=state,
    )


@operator_idp_router.post(
    "/{tenant_id}/idp/{directory_id}/oidc-callback",
    response_model=OperatorIdpSigninResponse,
)
async def operator_oidc_callback_endpoint(
    tenant_id: UUID,
    directory_id: UUID,
    body: IdpOidcCallbackRequest,
    request: Request,
) -> OperatorIdpSigninResponse:
    directory = _load_directory(tenant_id, directory_id)
    if directory.signin_protocol != IdpSigninProtocol.OIDC:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="directory is not OIDC-configured",
        )
    expected_prefix = f"op.{tenant_id}.{directory_id}."
    if not body.state.startswith(expected_prefix):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="state does not match path",
        )
    provider = await _build_provider_for_operator(request, directory)
    try:
        result = await provider.exchange_code_for_id_token(code=body.code)
    except OidcValidationError as exc:
        record_signin(
            request, tenant_id=tenant_id, surface=AuthSurface.OPERATOR,
            method=AuthMethod.OIDC, outcome=AuthOutcome.FAILURE, subject=None,
            reason="oidc validation failed",
            directory_id=directory.id, directory_display=directory.display_name,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OIDC validation failed",
        ) from exc

    return _mint_operator_response(
        request=request, tenant_id=tenant_id, email=result.email,
        method=AuthMethod.OIDC, directory=directory,
    )


@operator_idp_router.get(
    "/{tenant_id}/idp/{directory_id}/saml-login",
)
async def operator_saml_login_endpoint(
    tenant_id: UUID,
    directory_id: UUID,
    request: Request,
) -> RedirectResponse:
    directory = _load_directory(tenant_id, directory_id)
    if directory.signin_protocol != IdpSigninProtocol.SAML:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="directory is not SAML-configured",
        )
    provider = _build_saml_provider_for_operator(request, directory)
    state = f"op.{tenant_id}.{directory_id}.{secrets.token_urlsafe(24)}"
    try:
        target = provider.prepare_login(state=state)
    except SamlValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to build SAML AuthnRequest",
        ) from exc
    return RedirectResponse(target, status_code=status.HTTP_302_FOUND)


@operator_idp_router.post(
    "/{tenant_id}/idp/{directory_id}/saml-acs",
    response_model=OperatorIdpSigninResponse,
)
async def operator_saml_acs_endpoint(
    tenant_id: UUID,
    directory_id: UUID,
    request: Request,
    SAMLResponse: Annotated[str, Form()],
    RelayState: Annotated[str | None, Form()] = None,
) -> OperatorIdpSigninResponse:
    directory = _load_directory(tenant_id, directory_id)
    if directory.signin_protocol != IdpSigninProtocol.SAML:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="directory is not SAML-configured",
        )
    del RelayState  # purely an SP-side hint, audience check is the defence
    provider = _build_saml_provider_for_operator(request, directory)
    try:
        result = provider.parse_response(SAMLResponse)
    except SamlValidationError as exc:
        record_signin(
            request, tenant_id=tenant_id, surface=AuthSurface.OPERATOR,
            method=AuthMethod.SAML, outcome=AuthOutcome.FAILURE, subject=None,
            reason="saml validation failed",
            directory_id=directory.id, directory_display=directory.display_name,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SAML validation failed",
        ) from exc
    return _mint_operator_response(
        request=request, tenant_id=tenant_id, email=result.email,
        method=AuthMethod.SAML, directory=directory,
    )


# --- Operator-side helpers ---------------------------------------------


def _mint_operator_response(
    *,
    request: Request,
    tenant_id: UUID,
    email: str,
    method: AuthMethod,
    directory: IdpDirectory,
) -> OperatorIdpSigninResponse:
    """Look up the operator by `(tenant_id, email)`. If not present —
    or disabled — return 403. We do NOT auto-create operators from
    SSO; admin privileges have to be pre-issued via the operator
    console (or the bootstrap path)."""

    settings = request.app.state.settings
    normalized = email.strip().lower()
    with SessionLocal() as session:
        bind_tenant_context(session, tenant_id)
        operator = session.scalar(
            select(Operator).where(
                Operator.tenant_id == tenant_id,
                Operator.email == normalized,
            )
        )
        if operator is None:
            record_signin(
                request, tenant_id=tenant_id, surface=AuthSurface.OPERATOR,
                method=method, outcome=AuthOutcome.FAILURE, subject=normalized,
                reason="not registered as an operator",
                directory_id=directory.id, directory_display=directory.display_name,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "your email is not registered as an operator in this "
                    "tenant — ask an existing admin to invite you"
                ),
            )
        if operator.disabled_at is not None:
            record_signin(
                request, tenant_id=tenant_id, surface=AuthSurface.OPERATOR,
                method=method, outcome=AuthOutcome.FAILURE, subject=normalized,
                subject_id=operator.id, reason="operator is disabled",
                directory_id=directory.id, directory_display=directory.display_name,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="operator is disabled",
            )
        operator.last_login_at = datetime.now(UTC)
        session.commit()
        record_signin(
            request, tenant_id=tenant_id, surface=AuthSurface.OPERATOR,
            method=method, outcome=AuthOutcome.SUCCESS, subject=operator.email,
            subject_id=operator.id,
            directory_id=directory.id, directory_display=directory.display_name,
        )
        token = mint_operator_test_token(
            tenant_id=tenant_id,
            operator_id=operator.id,
            display=operator.email,
            signing_secret=settings.operator_auth_signing_secret,
        )
        role_value = (
            operator.role.value
            if hasattr(operator.role, "value")
            else str(operator.role)
        )
        return OperatorIdpSigninResponse(
            operator_token=token,
            operator_id=operator.id,
            email=operator.email,
            role=role_value,
        )


async def _build_provider_for_operator(
    request: Request, directory: IdpDirectory
) -> OidcProvider:
    """Same as `_build_provider` but the redirect_uri points at the
    operator-side callback so the IdP returns the user back to a route
    that mints an operator JWT, not a portal session."""

    if (
        not directory.oidc_issuer
        or not directory.oidc_client_id
        or not directory.oidc_client_secret_ref
    ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC config incomplete on directory",
        )
    secret_store: SecretStore | None = getattr(
        request.app.state, "secret_store", None
    )
    if secret_store is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="secret store not configured",
        )
    try:
        client_secret = await secret_store.get_secret(
            directory.tenant_id, directory.oidc_client_secret_ref
        )
    except SecretNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="oidc_client_secret_ref does not resolve",
        ) from exc

    base = str(request.base_url).rstrip("/")
    redirect_uri = (
        f"{base}/api/v1/operator-auth/{directory.tenant_id}/idp/"
        f"{directory.id}/oidc-callback"
    )
    return OidcProvider(
        config=OidcConfig(
            issuer_url=directory.oidc_issuer,
            audience=directory.oidc_client_id,
            email_claim="email",
            subject_claim="sub",
        ),
        client_id=directory.oidc_client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        jwks_cache=_JWKS_CACHE,
    )


def _build_saml_provider_for_operator(
    request: Request, directory: IdpDirectory
) -> SamlProvider:
    """SAML SP wrapper aimed at the operator-side ACS URL. Same SP
    entity_id as the user-portal flow — the SAML response's signed
    Audience pins it to this directory regardless of which side
    consumes it."""

    if (
        not directory.saml_entity_id
        or not directory.saml_sso_url
        or not directory.saml_idp_certificate
    ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SAML config incomplete on directory",
        )
    base = str(request.base_url).rstrip("/")
    sp_entity_id = f"{base}/saml/{directory.id}"
    sp_acs_url = (
        f"{base}/api/v1/operator-auth/{directory.tenant_id}/idp/"
        f"{directory.id}/saml-acs"
    )
    return SamlProvider(
        sp_entity_id=sp_entity_id,
        sp_acs_url=sp_acs_url,
        idp_entity_id=directory.saml_entity_id,
        idp_sso_url=directory.saml_sso_url,
        idp_certificate_pem=directory.saml_idp_certificate,
    )
