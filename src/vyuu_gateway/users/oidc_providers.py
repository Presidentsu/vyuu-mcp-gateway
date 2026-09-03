"""Microsoft Entra ID and Google Workspace OIDC providers.

Both go through `JwksCache.validate_token`. The differences are:

- **Issuer URL.**
  - Microsoft: per-tenant, `https://login.microsoftonline.com/{tenant_id}/v2.0`.
  - Google: global, `https://accounts.google.com`.
- **Email + subject claims.**
  - Microsoft: `email` (or `preferred_username`) + `oid` (object id, stable
    across renames + re-creates within a tenant).
  - Google: `email` + `sub`.
- **Hosted-domain pin.**
  - Google: `hd` claim, optional but typical for Workspace.
  - Microsoft: tenant-pin is in the issuer URL itself, no extra claim.
- **Authorization endpoint.** Provider-specific URL the gateway redirects
  to on `/auth/oidc/{provider}`. Token exchange uses the discovery doc's
  `token_endpoint`.

Per the design (Q1 OIDC: keep it simple), v1 supports exactly these
two providers; per-tenant routing of the same provider is deferred.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx

from vyuu_gateway.users.oidc import JwksCache, OidcConfig, OidcValidationError


@dataclass(frozen=True)
class OidcLoginInitiation:
    """Payload returned by `/auth/oidc/{provider}` — the URL to redirect
    the user's browser to + a `state` token the callback validates."""

    authorization_url: str
    state: str


@dataclass(frozen=True)
class OidcLoginResult:
    """Validated identity claims from a successful OIDC callback."""

    email: str
    subject: str
    display_name: str | None
    raw_claims: dict[str, Any]


class OidcProvider:
    """Base for Microsoft + Google. Subclasses set `name` + `config`."""

    name: str = ""

    def __init__(
        self,
        *,
        config: OidcConfig,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        jwks_cache: JwksCache,
    ) -> None:
        self.config = config
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._jwks = jwks_cache

    def authorization_url(self, *, state: str, nonce: str) -> str:
        """Build the IdP's `/authorize` URL. Subclass overrides if its
        path differs from the default OIDC discovery convention."""

        params = {
            "client_id": self._client_id,
            "response_type": "code",
            "redirect_uri": self._redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
        }
        return f"{self._authorize_endpoint()}?{urlencode(params)}"

    def _authorize_endpoint(self) -> str:
        # Default — Microsoft + Google both follow this convention.
        return self.config.issuer_url.rstrip("/") + "/oauth2/v2.0/authorize"

    async def exchange_code_for_id_token(self, *, code: str) -> OidcLoginResult:
        """Exchange the OAuth `code` for an ID token, validate it,
        return the canonical claims for JIT user provisioning."""

        async with httpx.AsyncClient() as http:
            try:
                response = await http.post(
                    self._token_endpoint(),
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": self._redirect_uri,
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                    },
                    timeout=10.0,
                )
            except httpx.HTTPError as exc:
                raise OidcValidationError(
                    f"token exchange failed: {exc.__class__.__name__}"
                ) from exc
        if response.status_code != 200:
            raise OidcValidationError(f"token endpoint returned {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise OidcValidationError("token endpoint returned non-JSON") from exc
        id_token = payload.get("id_token")
        if not isinstance(id_token, str):
            raise OidcValidationError("token response missing id_token")

        claims = await self._jwks.validate_token(id_token, config=self.config)
        email = claims.get(self.config.email_claim)
        subject = claims.get(self.config.subject_claim)
        if not isinstance(email, str) or not email:
            raise OidcValidationError("id_token missing email claim")
        if not isinstance(subject, str) or not subject:
            raise OidcValidationError("id_token missing subject claim")

        return OidcLoginResult(
            email=email.lower().strip(),
            subject=subject,
            display_name=(
                claims.get("name") if isinstance(claims.get("name"), str) else None
            ),
            raw_claims=claims,
        )

    def _token_endpoint(self) -> str:
        return self.config.issuer_url.rstrip("/") + "/oauth2/v2.0/token"


class MicrosoftEntraIdProvider(OidcProvider):
    """Microsoft Entra ID (Azure AD). Per-tenant — operator configures
    one tenant per gateway. `oid` is the stable subject claim
    (`sub` rotates per app registration in Microsoft's model)."""

    name = "microsoft"

    @classmethod
    def build(
        cls,
        *,
        microsoft_tenant_id: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        jwks_cache: JwksCache,
    ) -> MicrosoftEntraIdProvider:
        issuer = f"https://login.microsoftonline.com/{microsoft_tenant_id}/v2.0"
        return cls(
            config=OidcConfig(
                issuer_url=issuer,
                audience=client_id,
                email_claim="email",
                subject_claim="oid",
            ),
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            jwks_cache=jwks_cache,
        )


class GoogleWorkspaceProvider(OidcProvider):
    """Google Workspace via Google's OIDC. `hd` claim pins to a single
    Workspace domain (operator-configured) — without this, any Google
    user can sign in. Production should always set `hosted_domain`."""

    name = "google"

    def _authorize_endpoint(self) -> str:
        return "https://accounts.google.com/o/oauth2/v2/auth"

    def _token_endpoint(self) -> str:
        return "https://oauth2.googleapis.com/token"

    @classmethod
    def build(
        cls,
        *,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        jwks_cache: JwksCache,
        hosted_domain: str | None = None,
    ) -> GoogleWorkspaceProvider:
        return cls(
            config=OidcConfig(
                issuer_url="https://accounts.google.com",
                audience=client_id,
                email_claim="email",
                subject_claim="sub",
                hosted_domain=hosted_domain,
            ),
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            jwks_cache=jwks_cache,
        )
