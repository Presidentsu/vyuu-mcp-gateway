from datetime import datetime
from typing import Annotated, Any, Self
from urllib.parse import urlparse
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from vyuu_gateway.db.models import (
    McpCapabilityKind,
    McpServerHealthStatus,
    McpServerSourceType,
    McpTransport,
    RiskCategory,
)

ServerArg = Annotated[str, Field(min_length=1, max_length=1024)]


# Placeholder returned in place of any stored credential value. A fixed
# string with no length or prefix information — a masked prefix would
# still hand an attacker the first characters of a live key.
REDACTED_SECRET = "••••••••"

class OAuthClientCredentialsSpec(BaseModel):
    """OAuth 2.0 client-credentials grant spec.

    `client_id_ref` and `client_secret_ref` are SecretStore references —
    the gateway never sees the raw credentials at registration time.
    `token_url` MUST be HTTPS so the client_id / client_secret aren't
    exposed in plaintext during the M2M exchange. Optional `scope` and
    `audience` ride on the token request as documented by RFC 6749 / 8693.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    token_url: str = Field(min_length=1, max_length=2048)
    client_id_ref: str = Field(min_length=1, max_length=1024)
    client_secret_ref: str = Field(min_length=1, max_length=1024)
    scope: str | None = Field(default=None, max_length=1024)
    audience: str | None = Field(default=None, max_length=1024)

    @model_validator(mode="after")
    def validate_token_url(self) -> Self:
        parsed = urlparse(self.token_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("OAuth token_url must be an https URL")
        return self


_JWT_BEARER_ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "PS256")


class OAuthJwtBearerSpec(BaseModel):
    """OAuth 2.0 JWT-bearer assertion grant spec (A2 / phase 5).

    Per RFC 7523, the gateway signs a short-lived assertion JWT with a
    private key, POSTs it to `token_url` with
    `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<jwt>`,
    and receives a bearer access token in return. The access token then
    rides on every upstream call.

    `private_key_ref` is a SecretStore ref to a PEM-encoded RSA / EC
    private key. The gateway never logs the key material; only the
    assertion hash + claims surface in audit (and never the signing
    bytes). Symmetric algorithms (HS256) are intentionally not
    supported — JWT-bearer's whole value is asymmetric trust between
    gateway-as-issuer and the auth server-as-verifier.

    `issuer` / `subject` / `audience` populate the assertion's `iss`,
    `sub`, `aud` claims respectively. For Google Workspace SAs:
    issuer=subject=service-account-email when not impersonating;
    subject=user-email when impersonating; audience=token URL.
    `additional_claims` carries auth-server-specific extensions (e.g.
    Google requires a `scope` claim in the assertion itself, AWS IRA
    needs none).

    `assertion_ttl_seconds` is the JWT's lifetime in seconds; capped at
    600 per RFC 7523 §3 recommendations (most servers enforce 300).

    `scope` (optional) is the body-form `scope` parameter, separate
    from any `scope` claim inside the assertion."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    token_url: str = Field(min_length=1, max_length=2048)
    algorithm: str = Field(min_length=1, max_length=10)
    private_key_ref: str = Field(min_length=1, max_length=1024)
    issuer: str = Field(min_length=1, max_length=512)
    subject: str = Field(min_length=1, max_length=512)
    audience: str = Field(min_length=1, max_length=2048)
    scope: str | None = Field(default=None, max_length=1024)
    additional_claims: dict[str, Any] = Field(default_factory=dict)
    assertion_ttl_seconds: int = Field(default=60, ge=30, le=600)
    key_id: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def validate_spec(self) -> Self:
        parsed = urlparse(self.token_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("OAuth JWT-bearer token_url must be an https URL")
        if self.algorithm not in _JWT_BEARER_ALLOWED_ALGORITHMS:
            raise ValueError(
                f"OAuth JWT-bearer algorithm must be one of "
                f"{_JWT_BEARER_ALLOWED_ALGORITHMS} (got {self.algorithm!r}); "
                "symmetric / 'none' algorithms are rejected"
            )
        # `additional_claims` cannot redefine the structural claims —
        # those are owned by the spec fields. Preventing override here
        # avoids a class of misconfigurations where the operator adds
        # `iss` to additional_claims and the gateway silently uses the
        # spec's issuer instead.
        reserved = {"iss", "sub", "aud", "exp", "iat", "nbf", "jti"}
        overlap = reserved & set(self.additional_claims)
        if overlap:
            raise ValueError(
                f"additional_claims cannot redefine reserved JWT claims: "
                f"{sorted(overlap)} — set them via the spec fields instead"
            )
        return self


class OAuthAuthCodeSpec(BaseModel):
    """OAuth 2.0 authorization-code grant spec (A1 / phase 4).

    Per-user delegated tokens. The gateway redirects the user's browser
    through the IdP's `auth_url`, receives an authorization code at
    `redirect_uri`, exchanges it at `token_url` for access + refresh
    tokens, and persists per-(tenant, user, server) in
    `oauth_user_tokens`.

    Both `auth_url` and `token_url` MUST be HTTPS — anything less
    exposes the auth code (which is bearer-equivalent for the brief
    exchange window) and the client_secret (used as Basic auth on the
    token exchange) over plaintext.

    `redirect_uri` must be an HTTPS URL on the gateway itself
    (typically `https://<gateway-host>/api/v1/oauth-authcode/callback`).
    The same exact value MUST be configured in the IdP's app settings —
    a mismatch surfaces as 400 from the IdP at the redirect step.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    # Dynamic Client Registration mode (RFC 7591). When True, the
    # gateway discovers the AS metadata at the upstream's MCP URL and
    # POSTs to `registration_endpoint` to mint its own client_id /
    # client_secret on first use. The fields below become optional in
    # that mode — `auth_url` / `token_url` / scopes are auto-discovered
    # from `/.well-known/oauth-authorization-server` if blank;
    # `client_id_ref` / `client_secret_ref` are persisted to
    # `mcp_server_dcr_clients` rather than looked up in the SecretStore.
    # Used by Notion, Linear, and any spec-compliant MCP-Auth vendor
    # so operators don't pre-create OAuth apps in vendor dashboards.
    dcr_enabled: bool = False
    # Initial Access Token ref (RFC 7591 §3). Some enterprise OAuth
    # servers (Okta tenants, certain Auth0 configurations, private B2B
    # IdPs) gate the registration endpoint behind a Bearer IAT — a
    # token only issued via the vendor dashboard. When provided, the
    # DCR client resolves this ref through the SecretStore and sends
    # `Authorization: Bearer <iat>` on the registration POST. Only
    # consulted when `dcr_enabled=True`. Most public SaaS DCR servers
    # (Notion, Linear, Cloudflare, Sentry, etc.) accept unauthenticated
    # registration and don't need this.
    initial_access_token_ref: str = Field(default="", max_length=1024)
    # In DCR mode `auth_url` is auto-discovered. Keep the field present
    # but optional (empty string allowed) so existing static-cred rows
    # don't change shape and so operators can override the AS endpoint
    # if discovery returns the wrong issuer (rare).
    auth_url: str = Field(default="", max_length=2048)
    token_url: str = Field(default="", max_length=2048)
    # In DCR mode the gateway-issued credentials live in
    # `mcp_server_dcr_clients`; the ref names are unused but accepted
    # as empty strings for forward-compat.
    client_id_ref: str = Field(default="", max_length=1024)
    client_secret_ref: str = Field(default="", max_length=1024)
    scopes: list[str] = Field(default_factory=list, max_length=50)
    redirect_uri: str = Field(min_length=1, max_length=2048)
    # Provider-specific extras stamped onto the authorize URL. Most
    # IdPs (GitHub, Slack, Notion, Atlassian, Linear, Salesforce) need
    # nothing here; a few require operator-supplied flags:
    #   - Google: {"access_type": "offline", "prompt": "consent"} —
    #     without these Google ISSUES NO REFRESH TOKEN, and access
    #     tokens expire after 1 hour
    #   - Microsoft Entra: {"prompt": "select_account"} sometimes
    #   - Okta: {"prompt": "login"} for forced re-auth
    # The four keys we own (`response_type`, `client_id`,
    # `redirect_uri`, `state`, `scope`) are reserved — providing them
    # in `extra_authorize_params` is a configuration error and is
    # rejected.
    extra_authorize_params: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_urls(self) -> Self:
        # `auth_url` and `token_url` are talking to the IdP — these MUST
        # be HTTPS when provided. In DCR mode (`dcr_enabled=True`) the
        # gateway discovers them from the AS metadata at runtime, so
        # they may be left blank at registration time; the discovery
        # client only accepts HTTPS endpoints (defense in depth).
        for field_name in ("auth_url", "token_url"):
            url = getattr(self, field_name)
            if not url:
                if self.dcr_enabled:
                    continue
                raise ValueError(
                    f"OAuth {field_name} is required (or set dcr_enabled=true "
                    f"to discover it from the upstream AS metadata)"
                )
            parsed = urlparse(url)
            if parsed.scheme != "https" or not parsed.netloc:
                raise ValueError(f"OAuth {field_name} must be an https URL")
        # In static-creds mode (default), client_id_ref and
        # client_secret_ref are required — the SecretStore can't look
        # up empty refs. In DCR mode they're persisted to
        # `mcp_server_dcr_clients` instead, so accepting empty strings
        # is correct.
        if not self.dcr_enabled:
            if not self.client_id_ref:
                raise ValueError(
                    "OAuth client_id_ref is required (or set dcr_enabled=true)"
                )
            if not self.client_secret_ref:
                raise ValueError(
                    "OAuth client_secret_ref is required (or set dcr_enabled=true)"
                )
        # `redirect_uri` is on the gateway itself, hit by the user's
        # browser. HTTPS is the right default for production; localhost
        # / 127.0.0.1 development hosts are explicitly permitted on
        # plain HTTP because that's the only way local-dev OAuth
        # iterations work (Google's documented exception, GitHub
        # accepts it too). Any other host MUST be HTTPS.
        #
        # Normalise duplicate slashes in the path BEFORE the upstream
        # AS sees this URL. Common copy-paste mistake: paste a host
        # with a trailing `/` (e.g. `https://gateway.example.com/`)
        # then add `/api/v1/oauth-authcode/callback` → end up with
        # `https://gateway.example.com//api/v1/...`. RFC 7591 DCR
        # echoes the exact string back as the registered redirect_uri,
        # then the upstream AS redirects users to a path that doesn't
        # match our routes → 404 → OAuth dance silently breaks for
        # that server. The user sees "DCR / publish nothing works."
        # Strip here so the operator can't trip on it. We deliberately
        # don't touch the scheme separator (`://`).
        if self.redirect_uri:
            scheme, sep, rest = self.redirect_uri.partition("://")
            if sep:
                netloc, slash, path = rest.partition("/")
                if slash:
                    # Collapse runs of `/` first, then strip any leading
                    # `/` so the reassembly's own `/` separator doesn't
                    # produce a double when the original started with
                    # `//path`. Without `lstrip` the input
                    # `https://host//api/x` would partition to path=
                    # `/api/x` (single `/` survives the split) and
                    # collapse leaves it untouched.
                    while "//" in path:
                        path = path.replace("//", "/")
                    path = path.lstrip("/")
                    self.redirect_uri = f"{scheme}://{netloc}/{path}"
        ru = urlparse(self.redirect_uri)
        if not ru.netloc:
            raise ValueError("OAuth redirect_uri must be a valid URL")
        host = ru.hostname or ""
        is_localhost = host in {"localhost", "127.0.0.1", "::1"}
        if ru.scheme != "https" and not (ru.scheme == "http" and is_localhost):
            raise ValueError(
                "OAuth redirect_uri must be an https URL "
                "(http allowed only for localhost / 127.0.0.1 dev hosts)"
            )
        # Reserved authorize-URL params are owned by the gateway. An
        # operator stuffing `client_id` here would silently shadow the
        # ref-resolved client_id; reject up front.
        reserved = {"response_type", "client_id", "redirect_uri", "state", "scope"}
        overlap = reserved & set(self.extra_authorize_params)
        if overlap:
            raise ValueError(
                f"extra_authorize_params cannot redefine reserved authorize "
                f"URL params: {sorted(overlap)}"
            )
        for k, v in self.extra_authorize_params.items():
            if not k or any(ch < " " or ch == "\x7f" for ch in k):
                raise ValueError(
                    "extra_authorize_params keys must be non-empty + free "
                    "of control characters"
                )
            if any(ch < " " or ch == "\x7f" for ch in v):
                raise ValueError(
                    "extra_authorize_params values cannot contain control characters"
                )
        # Scopes can't have spaces (the OAuth wire format is
        # space-delimited; an embedded space would split a scope).
        for scope in self.scopes:
            if not scope or " " in scope or any(c < " " for c in scope):
                raise ValueError(
                    f"OAuth scope {scope!r} cannot be empty or contain "
                    "whitespace / control characters"
                )
        return self


class ServerRegistrationRequest(BaseModel):
    """Public request schema for `POST /api/v1/servers`.

    Tenant and operator identity come from the authenticated bearer token,
    not from the request body. `extra="forbid"` ensures any client that tries
    to slip a `tenant_id` or `registered_by` field into the body gets a 422 —
    a body-supplied tenant must never silently override the auth context.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    display_name: str = Field(min_length=1, max_length=255)
    source_type: McpServerSourceType
    source_location: str = Field(min_length=1, max_length=2048)
    transport: McpTransport | None = None
    env_vars_ref: str | None = Field(default=None, min_length=1, max_length=1024)
    args: list[ServerArg] = Field(default_factory=list, max_length=100)
    # Per-request header injection for HTTP transports. Maps `header_name`
    # to a `secret_ref` understood by the configured `SecretStore`. The
    # gateway never sees the raw credential at registration time — only
    # the opaque ref.
    auth_headers: dict[str, str] = Field(default_factory=dict)
    # Per-process env injection for stdio transports.
    auth_env: dict[str, str] = Field(default_factory=dict)
    # User-tier auth: `{inbound_header_name → upstream_header_name}`. When
    # the inbound MCP request carries `inbound_header_name`, the gateway
    # forwards its value to the upstream as `upstream_header_name`. The
    # gateway never persists the credential — each user brings their own
    # (e.g. their personal GitHub PAT, PayPal sandbox token). HTTP-only.
    auth_passthrough: dict[str, str] = Field(default_factory=dict)
    # OAuth 2.0 client-credentials configuration. The gateway brokers the
    # M2M token exchange and rides the access token as Authorization:
    # Bearer on every upstream call. HTTP-only. Cannot coexist with an
    # explicit Authorization in `auth_headers` or `auth_passthrough` —
    # the operator must pick one model for the Authorization header.
    auth_oauth: OAuthClientCredentialsSpec | None = None
    # OAuth 2.0 authorization-code (phase 4). Per-user delegated tokens
    # — each user grants the gateway access to their own account at the
    # IdP, the gateway stores the resulting refresh token and rides the
    # access token as Authorization: Bearer per call. HTTP-only. Cannot
    # coexist with `auth_oauth` (different grant types per server) and
    # cannot coexist with explicit Authorization in `auth_headers` /
    # `auth_passthrough`.
    auth_authcode: OAuthAuthCodeSpec | None = None
    # OAuth 2.0 JWT-bearer assertion grant (RFC 7523 — A2). Mutually
    # exclusive with `auth_oauth` and `auth_authcode`. HTTP-only.
    auth_jwt_bearer: OAuthJwtBearerSpec | None = None
    # mTLS upstream auth — when both refs are set, the gateway resolves
    # them through the SecretStore at provider-build time and configures
    # httpx with the resulting client cert chain. Both must be set
    # together (cert without key or key without cert is a configuration
    # bug). HTTP transports only — stdio MCPs don't have a TLS layer.
    # Coexists freely with header / OAuth auth modes — mTLS is a
    # transport-layer credential, separate from the application-layer
    # Authorization header.
    mtls_cert_ref: str | None = Field(default=None, min_length=1, max_length=1024)
    mtls_key_ref: str | None = Field(default=None, min_length=1, max_length=1024)
    # Per-server capability-sync cadence override.
    #   None  → use the global default (Settings.capability_sync_interval_seconds)
    #   0     → manual only — scheduler skips this server
    #   N>0   → run no more often than every N minutes
    # Capped at 30 days (43200 min) so a typo doesn't park a server
    # for years; lift the cap only if a real customer asks.
    sync_cadence_minutes: int | None = Field(default=None, ge=0, le=43200)

    @model_validator(mode="after")
    def validate_source_shape(self) -> Self:
        if self.source_type == McpServerSourceType.HTTP:
            self._validate_http_source()
        else:
            if self.transport is None:
                self.transport = McpTransport.STDIO

            if self.transport != McpTransport.STDIO:
                raise ValueError(
                    "npm, pypi, stdio, and binary sources must use stdio transport"
                )

            if self.source_type == McpServerSourceType.BINARY:
                # Schema-level path-shape check; the launch policy does
                # the existence + permission checks at register-time.
                if not self.source_location.startswith("/"):
                    raise ValueError(
                        "binary source_location must be an absolute path "
                        "(starting with /)"
                    )

        self._validate_auth()
        return self

    def _validate_http_source(self) -> None:
        parsed = urlparse(self.source_location)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("http source_location must be an http or https URL")

        if self.transport is None:
            raise ValueError("http sources must declare sse or streamable_http transport")

        if self.transport == McpTransport.STDIO:
            raise ValueError("http sources cannot use stdio transport")

        if self.args:
            raise ValueError(
                "args are only supported for npm, pypi, stdio, and binary sources"
            )

    def _validate_auth(self) -> None:
        """Per-transport sanity checks on the auth maps.

        - `auth_headers` only makes sense on HTTP transports — stdio
          subprocesses don't speak HTTP. Reject up front so operators
          notice the mistake at registration, not at sync time.
        - `auth_env` is the mirror — only honored for stdio transports.
        - Names must be non-empty and not contain control characters
          (defense in depth against header / env injection via the name
          itself, separate from the secret value).
        - Refs must be non-empty so an empty-string ref doesn't silently
          translate to "no secret to resolve".
        """

        if self.auth_headers and self.transport == McpTransport.STDIO:
            raise ValueError("auth_headers are only honored for HTTP transports")

        if self.auth_env and self.transport != McpTransport.STDIO:
            raise ValueError("auth_env is only honored for stdio transports")

        if self.auth_passthrough and self.transport == McpTransport.STDIO:
            raise ValueError("auth_passthrough is only honored for HTTP transports")

        if self.auth_oauth is not None and self.transport == McpTransport.STDIO:
            raise ValueError("auth_oauth is only honored for HTTP transports")

        if self.auth_authcode is not None and self.transport == McpTransport.STDIO:
            raise ValueError("auth_authcode is only honored for HTTP transports")

        if self.auth_jwt_bearer is not None and self.transport == McpTransport.STDIO:
            raise ValueError("auth_jwt_bearer is only honored for HTTP transports")

        # mTLS: both refs must be set together (cert+key are useless
        # in isolation), and HTTP-only (stdio has no TLS layer).
        cert_set = self.mtls_cert_ref is not None
        key_set = self.mtls_key_ref is not None
        if cert_set != key_set:
            raise ValueError(
                "mtls_cert_ref and mtls_key_ref must both be set or both unset"
            )
        if cert_set and self.transport == McpTransport.STDIO:
            raise ValueError(
                "mtls_cert_ref / mtls_key_ref are only honored for HTTP transports"
            )

        # auth_oauth (M2M client_credentials), auth_authcode (per-user
        # delegated), and auth_jwt_bearer (RFC 7523 service-account)
        # all target the same Authorization header. Pick exactly one
        # OAuth grant type per server — anything else is ambiguous at
        # runtime.
        oauth_modes_set = sum(
            1
            for m in (self.auth_oauth, self.auth_authcode, self.auth_jwt_bearer)
            if m is not None
        )
        if oauth_modes_set > 1:
            raise ValueError(
                "auth_oauth, auth_authcode, and auth_jwt_bearer are "
                "mutually exclusive — pick one OAuth grant type"
            )

        # A header name can't be both org-tier (auth_headers) AND user-tier
        # (auth_passthrough) — the operator must pick one model per name.
        # Otherwise resolution order would silently shadow whichever lost.
        header_overlap = set(self.auth_headers).intersection(self.auth_passthrough.values())
        if header_overlap:
            raise ValueError(
                f"auth_headers and auth_passthrough collide on upstream header(s): "
                f"{sorted(header_overlap)}"
            )

        # OAuth always sets Authorization: Bearer <token>. So if `auth_oauth`
        # is configured, no other model may also target Authorization.
        if self.auth_oauth is not None:
            ah_lower = {k.lower() for k in self.auth_headers}
            ap_lower = {v.lower() for v in self.auth_passthrough.values()}
            if "authorization" in ah_lower or "authorization" in ap_lower:
                raise ValueError(
                    "auth_oauth sets Authorization; cannot also set it via "
                    "auth_headers or auth_passthrough"
                )

        # Same Authorization-header collision check for auth_authcode.
        if self.auth_authcode is not None:
            ah_lower = {k.lower() for k in self.auth_headers}
            ap_lower = {v.lower() for v in self.auth_passthrough.values()}
            if "authorization" in ah_lower or "authorization" in ap_lower:
                raise ValueError(
                    "auth_authcode sets Authorization; cannot also set it via "
                    "auth_headers or auth_passthrough"
                )

        # Same Authorization-header collision check for auth_jwt_bearer.
        if self.auth_jwt_bearer is not None:
            ah_lower = {k.lower() for k in self.auth_headers}
            ap_lower = {v.lower() for v in self.auth_passthrough.values()}
            if "authorization" in ah_lower or "authorization" in ap_lower:
                raise ValueError(
                    "auth_jwt_bearer sets Authorization; cannot also set it "
                    "via auth_headers or auth_passthrough"
                )

        for name, ref in self.auth_headers.items():
            _validate_auth_entry(name, ref, kind="header")
        for name, ref in self.auth_env.items():
            _validate_auth_entry(name, ref, kind="env")
        for inbound, upstream in self.auth_passthrough.items():
            _validate_auth_entry(inbound, upstream, kind="passthrough")


def _validate_auth_entry(name: str, ref: str, *, kind: str) -> None:
    """Sanity-check a single `{name: secret_ref}` entry from auth_headers
    or auth_env. Refs are opaque to the gateway, but the *name* and *ref*
    must both be non-empty and free of control characters so they cannot
    be used to smuggle a CRLF into an HTTP header or a NUL into an env var.
    """

    if not name or not name.strip():
        raise ValueError(f"auth_{kind} name must be non-empty")
    if any(ch < " " or ch == "\x7f" for ch in name):
        raise ValueError(f"auth_{kind} name contains control characters")
    if not ref or not ref.strip():
        raise ValueError(f"auth_{kind} secret ref must be non-empty for {name!r}")


class CapabilitySeedEntry(BaseModel):
    """One manually-seeded capability — kind, name, schema, optional risk."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    kind: McpCapabilityKind
    name: str = Field(min_length=1, max_length=255)
    schema_payload: dict[str, Any] = Field(
        alias="schema_json", serialization_alias="schema_json"
    )
    risk_category: RiskCategory | None = None


class CapabilitySeedRequest(BaseModel):
    """Request body for `POST /api/v1/servers/{id}/capabilities`.

    Operator pastes a catalog (from vendor docs / a static manifest /
    an export of an existing tenant) and the gateway writes it as the
    active capability snapshot for the server, bypassing the upstream
    probe. Useful for credential-gated upstreams (CrowdStrike Falcon),
    air-gapped deployments, and pre-procurement evaluation.
    """

    model_config = ConfigDict(extra="forbid")

    capabilities: list[CapabilitySeedEntry] = Field(min_length=0, max_length=2000)


class ServerSyncCadenceUpdateRequest(BaseModel):
    """Request body for `PATCH /api/v1/servers/{id}/sync-cadence`.

    Standalone endpoint so cadence changes are an atomic, low-risk
    operation — operators don't need to round-trip the full server
    registration just to flip auto-sync from hourly to daily.
    """

    model_config = ConfigDict(extra="forbid")

    sync_cadence_minutes: int | None = Field(default=None, ge=0, le=43200)


class ServerRegistrationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    display_name: str
    source_type: McpServerSourceType
    source_location: str
    transport: McpTransport
    env_vars_ref: str | None
    args: list[str]
    # Auth maps surface in the response so operators can see what's
    # wired. `auth_headers` / `auth_env` VALUES are redacted on the way
    # out — see `_redact_auth_values` below.
    # Older fake fixtures may pass `None`; treat that as "no auth".
    auth_headers: dict[str, str] = Field(default_factory=dict)
    auth_env: dict[str, str] = Field(default_factory=dict)
    # NOT redacted: passthrough maps an inbound header NAME to an
    # outbound header NAME ({"x-vyuu-paypal-token": "Authorization"}).
    # No credential ever lands here, and operators need to read the
    # mapping to debug per-user forwarding.
    auth_passthrough: dict[str, str] = Field(default_factory=dict)
    # OAuth shape echoes back the **refs**, never the resolved client_id /
    # client_secret. `None` when not configured.
    auth_oauth: OAuthClientCredentialsSpec | None = None
    # auth_authcode echoes back the spec — refs only, never resolved.
    auth_authcode: OAuthAuthCodeSpec | None = None
    # auth_jwt_bearer echoes back the spec — private_key_ref only,
    # never the resolved PEM key.
    auth_jwt_bearer: OAuthJwtBearerSpec | None = None
    # mTLS refs echo back so operators can see the wiring; resolved
    # PEM blobs are NEVER returned — those live in the SecretStore.
    mtls_cert_ref: str | None = None
    mtls_key_ref: str | None = None

    @field_validator("auth_headers", "auth_env", "auth_passthrough", mode="before")
    @classmethod
    def _coerce_none_to_empty(cls, value: object) -> object:
        if value is None:
            return {}
        return value

    @field_serializer("auth_headers", "auth_env", when_used="always")
    def _redact_auth_values(self, value: dict[str, str]) -> dict[str, str]:
        """Return the KEYS wired, never the values.

        These are documented as opaque secret refs, and on that reading
        echoing them is harmless. Nothing enforces it: the registration
        API accepts whatever string an operator types, so an operator
        who pastes an API key directly gets that key stored verbatim and
        handed back by `GET /servers` to anyone who can list servers —
        which is a far weaker permission than "may read this tenant's
        upstream credentials". That is exactly what a security review of
        this gateway found in the CrowdStrike registration.

        Redacting here fixes the class rather than the instance: it does
        not matter whether the stored string is a ref or a live key,
        because neither leaves the process. Operators keep everything
        they actually consume — the console reads only
        `Object.keys(...)` to label a server "Org env" / "Org headers" —
        and the gateway itself resolves values from the ORM model, never
        from this response.
        """
        return dict.fromkeys(value, REDACTED_SECRET)

    registered_by: UUID
    registered_at: datetime
    health_status: McpServerHealthStatus
    last_health_checked_at: datetime | None
    last_health_error: str | None
    last_capabilities_pulled_at: datetime | None
    # NULL = use the global default cadence; 0 = manual-only (skip
    # auto-sync); positive int = run no more often than every N
    # minutes. Surfaced so the operator console can render a
    # per-server "Sync every…" dropdown.
    sync_cadence_minutes: int | None = None
    # Most recent capability-sync drift (added / removed / changed).
    # Wiped on each sync run; small enough to inline. Lets the
    # operator console show "what changed last sync" on the server
    # row without re-syncing.
    last_sync_drift: dict[str, Any] | None = None
    # Live (non-deprecated) tool capabilities on this server. The
    # operator console has always had a TOOLS column for this and could
    # never fill it — nothing computed the number, so every row read
    # "—" regardless of how many tools the server actually exposed.
    # Served from one grouped query rather than a per-row fetch from the
    # browser, which would be an N+1 across the whole catalog.
    tool_count: int | None = None


class ServerHealthResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    health_status: McpServerHealthStatus
    last_health_checked_at: datetime | None
    last_health_error: str | None
    last_capabilities_pulled_at: datetime | None


class CapabilityResponse(BaseModel):
    """A single tool / resource / prompt entry in a server's snapshot.

    Python attr is `schema_payload` — the field is aliased to/from the
    `schema_json` ORM column and serialized as `schema_json` over the wire.
    Avoiding the literal name `schema_json` on a Pydantic class side-steps
    a v2 deprecation warning where `schema_json` shadows BaseModel's legacy
    method.
    """

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: UUID
    server_id: UUID
    tenant_id: UUID
    kind: McpCapabilityKind
    name: str
    risk_category: RiskCategory
    schema_payload: dict[str, Any] = Field(
        alias="schema_json",
        serialization_alias="schema_json",
    )
    observed_at: datetime
    deprecated: bool


class CapabilityChangeResponse(BaseModel):
    kind: McpCapabilityKind
    name: str


class CapabilitySyncResponse(BaseModel):
    """Result of `POST /api/v1/servers/{id}/sync`."""

    model_config = ConfigDict(from_attributes=True)

    tenant_id: UUID
    server_id: UUID
    synced_at: datetime
    capability_count: int
    added: list[CapabilityChangeResponse]
    removed: list[CapabilityChangeResponse]
    changed: list[CapabilityChangeResponse]
    unchanged: list[CapabilityChangeResponse]
