"""OIDC core: JWKS cache + JWT validator. Shared by Microsoft + Google.

Per-provider config carries `issuer_url`, expected `audience` (the
gateway's client_id), and a few claim-mapping knobs. The actual
provider classes (`MicrosoftEntraIdProvider`, `GoogleWorkspaceProvider`)
in `users/oidc_providers.py` instantiate this with their specifics.

JWKS strategy:
- In-memory cache keyed by issuer.
- Refresh on `kid` miss (token signed by a rotated key).
- Single-flight: an `asyncio.Lock` per issuer so a hot key rotation
  doesn't trigger N concurrent JWKS fetches.
- TTL fallback (~5min) to bound cache staleness.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt


class OidcConfigurationError(Exception):
    """Provider config or discovery document is malformed."""


class OidcValidationError(Exception):
    """The presented JWT failed validation."""


@dataclass(frozen=True)
class OidcConfig:
    """Provider config — populated from `Settings` per-provider.

    `issuer_url` is the OIDC issuer (e.g. `https://accounts.google.com`).
    `audience` is the gateway's client_id at the IdP. `email_claim` and
    `subject_claim` say which claim names carry the email + stable
    identity per provider — Microsoft uses `oid`, Google uses `sub`.
    """

    issuer_url: str
    audience: str
    email_claim: str = "email"
    subject_claim: str = "sub"
    # Optional Google-Workspace-style domain pin. When set, JWTs whose
    # `hd` claim doesn't match are rejected. Microsoft's tenant-pin is
    # already enforced via `iss` matching the per-tenant issuer URL.
    hosted_domain: str | None = None


@dataclass
class _JwksCacheEntry:
    """Per-issuer JWKS state. Updated by `JwksCache.refresh`."""

    keys_by_kid: dict[str, dict[str, Any]] = field(default_factory=dict)
    fetched_at: float = 0.0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class JwksCache:
    """In-memory JWKS cache with single-flight refresh + TTL fallback.

    `validate_token` is the only public method — provider classes call
    it directly. The cache is keyed on `(issuer_url, kid)` because the
    same `kid` can mean different keys across issuers.
    """

    # 5-minute TTL — refreshed lazily on next validation if exceeded.
    _DEFAULT_TTL_SECONDS = 300.0
    # Hard timeout on the JWKS HTTP fetch.
    _FETCH_TIMEOUT_SECONDS = 10.0

    def __init__(
        self,
        *,
        ttl_seconds: float = _DEFAULT_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
    ) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        self._http_factory = http_client_factory or (lambda: httpx.AsyncClient())
        self._entries: dict[str, _JwksCacheEntry] = {}

    async def validate_token(self, token: str, *, config: OidcConfig) -> dict[str, Any]:
        """Decode + verify a JWT against the configured issuer's JWKS.

        Returns the validated claims dict on success. Raises
        `OidcValidationError` for any signature / exp / iss / aud /
        hosted_domain failure with a sanitized class-name reason.
        """

        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise OidcValidationError("malformed JWT") from exc
        kid = unverified_header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise OidcValidationError("JWT missing kid header")

        signing_key_jwk = await self._signing_key(config.issuer_url, kid)
        try:
            algorithms = [unverified_header.get("alg", "RS256")]
            signing_key = jwt.PyJWK(signing_key_jwk).key
            claims = jwt.decode(
                token,
                key=signing_key,
                algorithms=algorithms,
                audience=config.audience,
                issuer=config.issuer_url,
                options={"require": ["exp", "iat", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise OidcValidationError("JWT expired") from exc
        except jwt.InvalidIssuerError as exc:
            raise OidcValidationError("issuer mismatch") from exc
        except jwt.InvalidAudienceError as exc:
            raise OidcValidationError("audience mismatch") from exc
        except jwt.InvalidTokenError as exc:
            raise OidcValidationError("invalid JWT") from exc

        if config.hosted_domain is not None:
            hd = claims.get("hd")
            if hd != config.hosted_domain:
                raise OidcValidationError("hosted_domain mismatch")

        return dict(claims)

    async def _signing_key(self, issuer: str, kid: str) -> dict[str, Any]:
        """Return the JWK dict matching `kid` for `issuer`. Refresh on miss."""

        entry = self._entries.setdefault(issuer, _JwksCacheEntry())
        key = entry.keys_by_kid.get(kid)
        now = self._clock()
        cache_stale = (now - entry.fetched_at) > self._ttl
        if key is not None and not cache_stale:
            return key

        # Refresh under the per-issuer lock — single-flight.
        async with entry.lock:
            # Re-check under lock — a concurrent caller may have refreshed.
            key = entry.keys_by_kid.get(kid)
            now = self._clock()
            if key is not None and (now - entry.fetched_at) <= self._ttl:
                return key
            await self._refresh(entry, issuer)
            key = entry.keys_by_kid.get(kid)
            if key is None:
                raise OidcValidationError("signing key not found in issuer JWKS")
            return key

    async def _refresh(self, entry: _JwksCacheEntry, issuer: str) -> None:
        """Fetch the issuer's discovery doc → JWKS endpoint → keys."""

        async with self._http_factory() as http:
            try:
                discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
                discovery = await http.get(
                    discovery_url, timeout=self._FETCH_TIMEOUT_SECONDS
                )
                discovery.raise_for_status()
                jwks_uri = discovery.json().get("jwks_uri")
                if not isinstance(jwks_uri, str) or not jwks_uri:
                    raise OidcConfigurationError("discovery doc missing jwks_uri")
                jwks = await http.get(jwks_uri, timeout=self._FETCH_TIMEOUT_SECONDS)
                jwks.raise_for_status()
                keys = jwks.json().get("keys", [])
            except httpx.HTTPError as exc:
                raise OidcValidationError(
                    f"JWKS fetch failed: {exc.__class__.__name__}"
                ) from exc

        if not isinstance(keys, list):
            raise OidcConfigurationError("JWKS response shape invalid")
        entry.keys_by_kid = {
            k["kid"]: k for k in keys if isinstance(k, dict) and "kid" in k
        }
        entry.fetched_at = self._clock()
