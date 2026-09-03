"""EMA-1 · Vyuu as MCP Resource Authorization Server (ID-JAG exchange).

Implements the server half of MCP Enterprise-Managed Authorization:
the enterprise IdP (Okta "Cross App Access", Entra, …) mints an
**ID-JAG** — a short-lived identity-assertion authorization grant —
and the MCP client redeems it HERE for a Vyuu-signed access token:

    POST /v/{tenant_id}/oauth/token
        grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
        assertion=<ID-JAG JWT>
        [client_id=<mcp client id>]

Validation order (each step's failure → RFC 6749 `invalid_grant`,
same opaque shape — anti-enumeration):

    1. unverified `iss` → EMA-enabled `idp_directories` row in tenant
    2. signature vs the directory's JWKS (explicit `ema_jwks_uri` or
       OIDC discovery), `aud` == `directory.ema_audience`, exp/iat
    3. `resource` (when present) resolves to a vserver in this tenant
    4. `client_id` ∈ `ema_allowed_client_ids` (when list non-empty),
       then — only for an allowlisted https client_id, and only when
       `VYUU_EMA_CIMD_RESOLUTION_ENABLED` — its CIMD document resolves
       and self-identifies (MCP-2 P3; makes revocation observable)
    5. `jti` never redeemed before (replay cache, same-tx as JIT user)

On success the `sub` is JIT-mapped onto a directory user (same
matching rule as OIDC/SAML sign-in + SCIM reconcile) and a short-lived
**HS256** access token is minted. Every subsequent `/mcp` call verifies
that token locally (`identity/jwt_bearer_provider.py`) — the JWKS
round-trip happens once per grant, never on the hot path.

Discovery: RFC 9728 protected-resource metadata is served at the
path-insertion form clients compute
(`/.well-known/oauth-protected-resource/v/{tenant}/{vserver}/mcp`)
and advertised via `resource_metadata` on inbound 401s.

Bundled upstream-spec note (2026-07-28): authorization servers SHOULD
send RFC 9207 `iss` on authorization responses. The ID-JAG flow has no
authorization response leg (token-exchange only), so it does not apply
here; it applies to our OAuth-AC client in `upstream/oauth_authcode.py`
(MCP-2 P3).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

import httpx
import jwt
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from vyuu_gateway.api.inbound_mcp import get_inbound_mcp_db
from vyuu_gateway.db.models import EmaConsumedJti, IdpDirectory, VirtualServer
from vyuu_gateway.identity.cimd_inbound import (
    CimdResolutionError,
    is_cimd_client_id,
)
from vyuu_gateway.idp.service import find_or_jit_create_directory_user

logger = logging.getLogger(__name__)

# JSON-RPC-free plain OAuth surface — mounted WITHOUT the /api/v1 prefix.
router = APIRouter(tags=["ema-oauth"])
wellknown_router = APIRouter(tags=["ema-oauth"])

_JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
# Asymmetric algorithms enterprise IdPs actually sign ID-JAGs with.
# HS* is deliberately absent: an attacker must never be able to force
# symmetric verification against a public JWKS value.
_IDJAG_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384")
_IDJAG_REQUIRED_CLAIMS = ["iss", "aud", "sub", "exp", "iat", "jti"]
# Grace on top of the ID-JAG's own exp when reserving the jti — covers
# clock skew between us and the IdP so a replay right at the boundary
# still hits the reservation.
_JTI_RETENTION_SKEW = timedelta(minutes=5)


# --- JWKS fetching ----------------------------------------------------------


class EmaJwksError(Exception):
    """Signing-key material could not be obtained / matched."""


class EmaJwksFetcher:
    """Tiny async JWKS fetcher with per-source TTL caching.

    Sources, in order: the directory's explicit `ema_jwks_uri`, else
    the issuer's `/.well-known/openid-configuration` → `jwks_uri`.
    Deliberately separate from `users.oidc.JwksCache`: that class both
    fetches AND decodes with OIDC-specific claim rules; the ID-JAG
    needs different required-claims + audience semantics, so here the
    fetcher only resolves keys and `_decode_id_jag` owns validation.
    `http_client_factory` is injectable so tests can serve JWKS from
    an in-process ASGI transport.
    """

    _TTL_SECONDS = 300.0
    _FETCH_TIMEOUT = 10.0

    def __init__(
        self,
        *,
        http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._http_factory = http_client_factory or (lambda: httpx.AsyncClient())
        self._clock = clock
        # source url -> (fetched_at, {kid: jwk_dict})
        self._cache: dict[str, tuple[float, dict[str, dict[str, Any]]]] = {}

    async def signing_key(
        self, *, issuer: str, jwks_uri: str | None, kid: str
    ) -> dict[str, Any]:
        source = jwks_uri or issuer
        cached = self._cache.get(source)
        now = self._clock()
        if cached and (now - cached[0]) <= self._TTL_SECONDS:
            key = cached[1].get(kid)
            if key is not None:
                return key
        keys = await self._fetch(issuer=issuer, jwks_uri=jwks_uri)
        self._cache[source] = (self._clock(), keys)
        key = keys.get(kid)
        if key is None:
            raise EmaJwksError("signing key not found in issuer JWKS")
        return key

    async def _fetch(
        self, *, issuer: str, jwks_uri: str | None
    ) -> dict[str, dict[str, Any]]:
        async with self._http_factory() as http:
            try:
                if jwks_uri is None:
                    discovery_url = (
                        issuer.rstrip("/") + "/.well-known/openid-configuration"
                    )
                    discovery = await http.get(
                        discovery_url, timeout=self._FETCH_TIMEOUT
                    )
                    discovery.raise_for_status()
                    jwks_uri = discovery.json().get("jwks_uri")
                    if not isinstance(jwks_uri, str) or not jwks_uri:
                        raise EmaJwksError("discovery doc missing jwks_uri")
                jwks = await http.get(jwks_uri, timeout=self._FETCH_TIMEOUT)
                jwks.raise_for_status()
                keys = jwks.json().get("keys", [])
            except EmaJwksError:
                raise
            except Exception as exc:  # noqa: BLE001 — network / JSON / HTTP
                raise EmaJwksError(
                    f"JWKS fetch failed: {exc.__class__.__name__}"
                ) from exc
        out: dict[str, dict[str, Any]] = {}
        for key in keys:
            if isinstance(key, dict) and isinstance(key.get("kid"), str):
                out[key["kid"]] = key
        return out


_DEFAULT_FETCHER = EmaJwksFetcher()


def _fetcher_for(request: Request) -> EmaJwksFetcher:
    override = getattr(request.app.state, "ema_jwks_fetcher", None)
    return override if isinstance(override, EmaJwksFetcher) else _DEFAULT_FETCHER


# --- helpers ----------------------------------------------------------------


def _oauth_error(error: str, description: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {"error": error}
    if description:
        body["error_description"] = description
    return JSONResponse(
        body,
        status_code=400,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _issuer_for_tenant(settings: Any, tenant_id: UUID) -> str:
    return f"{settings.public_base_url.rstrip('/')}/v/{tenant_id}"


def resource_metadata_payload(
    settings: Any, tenant_id: UUID, vserver_name: str
) -> dict[str, Any]:
    base = settings.public_base_url.rstrip("/")
    return {
        "resource": f"{base}/v/{tenant_id}/{vserver_name}/mcp",
        "authorization_servers": [_issuer_for_tenant(settings, tenant_id)],
        "authorization_grant_profiles_supported": [
            "urn:ietf:params:oauth:grant-profile:id-jag"
        ],
        "bearer_methods_supported": ["header"],
    }


# --- RFC 9728 protected-resource metadata -----------------------------------


@wellknown_router.get(
    "/.well-known/oauth-protected-resource/v/{tenant_id}/{vserver_name}/mcp"
)
def protected_resource_metadata(
    tenant_id: UUID,
    vserver_name: str,
    request: Request,
) -> JSONResponse:
    """RFC 9728 §3 path-insertion form — what spec-compliant clients
    compute from the resource URL. Public by design (it names WHERE to
    authorize, nothing tenant-secret); 404s when EMA is off so the
    surface doesn't advertise a token endpoint that would reject
    everything."""

    settings = request.app.state.settings
    if not settings.ema_enabled:
        return JSONResponse({"detail": "Not found"}, status_code=404)
    return JSONResponse(
        resource_metadata_payload(settings, tenant_id, vserver_name),
        headers={"Cache-Control": "public, max-age=3600"},
    )


# --- token endpoint ----------------------------------------------------------


@router.post("/v/{tenant_id}/oauth/token")
async def ema_token_endpoint(
    tenant_id: UUID,
    request: Request,
    db: Annotated[Session, Depends(get_inbound_mcp_db)],
) -> JSONResponse:
    settings = request.app.state.settings
    if not settings.ema_enabled:
        return JSONResponse({"detail": "Not found"}, status_code=404)

    form = await request.form()
    if form.get("grant_type") != _JWT_BEARER_GRANT:
        return _oauth_error("unsupported_grant_type")
    assertion = form.get("assertion")
    if not isinstance(assertion, str) or not assertion:
        return _oauth_error("invalid_request", "assertion is required")
    form_client_id = form.get("client_id")

    # 1. Unverified iss/kid → which tenant directory claims this issuer.
    #    (Signature is checked in step 2 against THAT directory's JWKS —
    #    the unverified read only selects the trust anchor, it grants
    #    nothing.)
    try:
        unverified_header = jwt.get_unverified_header(assertion)
        unverified_claims = jwt.decode(
            assertion, options={"verify_signature": False}
        )
    except jwt.InvalidTokenError:
        return _oauth_error("invalid_grant")
    issuer = unverified_claims.get("iss")
    kid = unverified_header.get("kid")
    if not isinstance(issuer, str) or not issuer or not isinstance(kid, str):
        return _oauth_error("invalid_grant")

    directory = db.scalar(
        select(IdpDirectory).where(
            IdpDirectory.tenant_id == tenant_id,
            IdpDirectory.oidc_issuer == issuer,
            IdpDirectory.ema_enabled.is_(True),
        )
    )
    if directory is None or not directory.ema_audience:
        return _oauth_error("invalid_grant")

    # 2. Real validation: signature + iss + aud + exp/iat.
    try:
        signing_jwk = await _fetcher_for(request).signing_key(
            issuer=issuer, jwks_uri=directory.ema_jwks_uri, kid=kid
        )
        claims = jwt.decode(
            assertion,
            key=jwt.PyJWK(signing_jwk).key,
            algorithms=list(_IDJAG_ALGORITHMS),
            audience=directory.ema_audience,
            issuer=issuer,
            options={"require": _IDJAG_REQUIRED_CLAIMS},
            leeway=60,
        )
    except (EmaJwksError, jwt.InvalidTokenError) as exc:
        logger.info(
            "ema_id_jag_rejected",
            extra={
                "tenant_id": str(tenant_id),
                "directory_id": str(directory.id),
                "reason": exc.__class__.__name__,
            },
        )
        return _oauth_error("invalid_grant")

    subject = claims.get("sub")
    email = claims.get("email")
    if not isinstance(subject, str) or not subject:
        return _oauth_error("invalid_grant")
    if not isinstance(email, str) or not email:
        # A user row needs an email; enterprise IdPs include it on
        # ID-JAGs (it's in the spec's own example). Reject rather than
        # fabricate an address SCIM could never reconcile.
        return _oauth_error("invalid_grant", "assertion missing email claim")

    # 3. resource (optional) must be a vserver in THIS tenant.
    resource = claims.get("resource")
    if resource is not None:
        if not isinstance(resource, str):
            return _oauth_error("invalid_grant")
        vserver_name = _vserver_name_from_resource(
            resource, settings=settings, tenant_id=tenant_id
        )
        if vserver_name is None:
            return _oauth_error("invalid_grant")
        known = db.scalar(
            select(VirtualServer.id).where(
                VirtualServer.tenant_id == tenant_id,
                VirtualServer.name == vserver_name,
            )
        )
        if known is None:
            return _oauth_error("invalid_grant")

    # 4. client allowlist (empty list = IdP policy already vetted it).
    client_id = form_client_id if isinstance(form_client_id, str) else None
    client_id = client_id or (
        claims.get("client_id") if isinstance(claims.get("client_id"), str) else None
    )
    allowlist = directory.ema_allowed_client_ids or []
    if allowlist and client_id not in allowlist:
        return _oauth_error("invalid_grant")

    # 4b. MCP-2 P3 · resolve a CIMD client_id to its document.
    #
    # The ORDER is the security property, not a detail. Resolution runs
    # only after membership in `allowlist` has been confirmed above,
    # which is what keeps the set of fetchable URLs an operator's list
    # rather than anything a caller can name. The `allowlist and` term
    # below is the same guarantee restated: an EMPTY allowlist means no
    # membership check happened, so there is nothing vouching for this
    # URL and we must not fetch it. Removing that term would turn an
    # unauthenticated endpoint into a probe of the gateway's network.
    #
    # Failure rejects. See `identity/cimd_inbound.py` for why this
    # inverts the outbound half's fall-back rule.
    client_name: str | None = None
    resolver = getattr(request.app.state, "inbound_cimd_resolver", None)
    if (
        resolver is not None
        and allowlist
        and client_id is not None
        and is_cimd_client_id(client_id)
    ):
        try:
            identity = await resolver.resolve(client_id)
        except CimdResolutionError as exc:
            logger.warning(
                "ema_cimd_client_rejected",
                extra={
                    "tenant_id": str(tenant_id),
                    "client_id": client_id[:200],
                    "reason": exc.reason,
                },
            )
            return _oauth_error("invalid_grant")
        client_name = identity.client_name

    # 5. Single-use jti + JIT user, atomically. The PK insert doubles as
    #    the race guard: two concurrent redemptions of one grant → one
    #    IntegrityError → one clean replay rejection.
    exp_dt = datetime.fromtimestamp(int(claims["exp"]), tz=UTC)
    db.add(
        EmaConsumedJti(
            tenant_id=tenant_id,
            jti=str(claims["jti"]),
            expires_at=exp_dt + _JTI_RETENTION_SKEW,
        )
    )
    user, jit_created = find_or_jit_create_directory_user(
        db,
        directory=directory,
        subject=subject,
        email=email,
        display_name=claims.get("name") if isinstance(claims.get("name"), str) else None,
    )
    if user.disabled_at is not None:
        db.rollback()
        return _oauth_error("invalid_grant")
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        logger.warning(
            "ema_id_jag_replayed",
            extra={"tenant_id": str(tenant_id), "jti": str(claims["jti"])[:64]},
        )
        return _oauth_error("invalid_grant")

    # 6. Mint the Vyuu access token (HS256 — hot path verifies locally).
    now = datetime.now(UTC)
    ttl = int(settings.ema_access_token_ttl_seconds)
    scope = claims.get("scope") if isinstance(claims.get("scope"), str) else ""
    access_token = jwt.encode(
        {
            "iss": _issuer_for_tenant(settings, tenant_id),
            "aud": str(tenant_id),
            "sub": subject,
            "email": email,
            "client_id": client_id,
            "dir": str(directory.id),
            "scope": scope,
            "iat": now,
            "exp": now + timedelta(seconds=ttl),
        },
        settings.ema_signing_secret,
        algorithm="HS256",
    )
    logger.info(
        "ema_access_token_minted",
        extra={
            "tenant_id": str(tenant_id),
            "directory_id": str(directory.id),
            "client_id": client_id,
            # None unless CIMD resolution ran. An opaque URL in this log
            # is the thing the document was fetched to fix.
            "client_name": client_name,
            "jit_created": jit_created,
        },
    )
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ttl,
            "scope": scope,
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _vserver_name_from_resource(
    resource: str, *, settings: Any, tenant_id: UUID
) -> str | None:
    """`{public_base_url}/v/{tenant_id}/{vserver_name}/mcp` → name.

    Exact-prefix + exact-suffix match; anything else (other tenant,
    other origin, trailing junk) is None → invalid_grant.
    """

    prefix = f"{settings.public_base_url.rstrip('/')}/v/{tenant_id}/"
    if not resource.startswith(prefix):
        return None
    remainder = resource.removeprefix(prefix)
    if not remainder.endswith("/mcp"):
        return None
    name = remainder.removesuffix("/mcp")
    if not name or "/" in name:
        return None
    return name
