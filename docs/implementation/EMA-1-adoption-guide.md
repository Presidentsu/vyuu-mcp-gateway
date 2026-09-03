# EMA-1 — Adopting MCP Enterprise-Managed Authorization (ID-JAG) as an inbound auth mechanism

**Status:** proposed / ready to implement
**Owner:** (assign)
**Spec:** [Enterprise-Managed Authorization](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization) · [ext-auth repo](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization.mdx)
**Underlying IETF drafts:** ID-JAG (`draft-ietf-oauth-identity-assertion-authz-grant`), Token Exchange (RFC 8693), JWT-Bearer grant (RFC 7523), Protected Resource Metadata (RFC 9728)

> This guide is for the engineer implementing the feature. It gives the architecture, the exact integration seams in our codebase, schema + code changes file-by-file, a security checklist, a test plan, and a phased rollout. Code blocks are **accurate skeletons** — real class/function names and signatures, but you'll fill in bodies and error handling.

---

## 0. TL;DR — the one rule

**Adopting EMA is one new `IdentityProvider`. Nothing downstream changes.**

EMA only changes *how the inbound principal is established*. The entire downstream lifecycle — tenant bind (RLS) → vserver + grant authz → policy (allow/deny/redact/rewrite) → upstream credential brokering → audit/NHI — is untouched. We are adding a second way to answer "who is calling," alongside `vyuu_user_*` API keys.

```
POST /v/{tenant}/{vserver}/mcp
   │
   ▼  app.state.identity_provider.validate_principal(tenant_id=…, credentials=…)   ← inbound_mcp.py:300
   │
   │   ChainedIdentityProvider:
   │     1. ApiKeyIdentityProvider    (vyuu_user_*  → Principal)        [exists]
   │     2. IdpJagIdentityProvider    (EMA JWT      → Principal)        [NEW]
   │
   ▼  Principal  (now carries a real corporate `sub`, email, and client_id)
   │
   └─► tenant bind → vserver+grant authz → policy → upstream+cred broker → audit → NHI   [UNCHANGED]
```

The integration seam is a single call site (`src/vyuu_gateway/api/inbound_mcp.py:300`). Everything in this guide funnels into producing a `Principal` from an EMA token at that seam, plus (Phase 2) a small standalone OAuth token endpoint.

---

## 1. Background — what we're consuming, and the two roles we play

In EMA, the enterprise IdP (Okta first, via "Cross App Access"; Entra/others will follow) is the policy point **at token-issuance time**. The MCP client:

1. Authenticates the user at the IdP (OIDC/SAML).
2. Token-exchanges (RFC 8693) at the IdP for an **ID-JAG** — a short-lived (≈300s) JWT *grant*, signed by the IdP, with `aud` = the **Resource Authorization Server** issuer and `resource` = the MCP server's resource id, carrying `sub`, `email`, `client_id`, `scope`.
3. Presents the ID-JAG to the **Resource Authorization Server** (RFC 7523 jwt-bearer grant) → receives an **audience-restricted access token**.
4. Calls the MCP server (the **Resource Server**) with that access token.

Our `/v/{tenant}/{vserver}/mcp` endpoint **is** the MCP server from the client's perspective, so Vyuu can occupy two EMA roles:

| EMA role | What Vyuu does | Phase |
|---|---|---|
| **Resource Server** | Accept + validate the access token on `/mcp`, map to a `Principal`. | P1 |
| **Resource Authorization Server** | Also advertise RFC 9728 metadata + expose a token endpoint that accepts the **ID-JAG** and mints **our own** access token. | P2 |

**Why P2 (being the Resource Authorization Server) is the strategic spine, not just P1:**
- The enterprise admin configures Okta/Entra with **Vyuu** as the resource authorization server → centralized MCP governance in their IdP, while Vyuu stays the enforcement + observability point.
- **The upstream MCP servers never need to implement EMA.** Vyuu presents the EMA-compliant face for the long tail. No IdP can occupy this position.
- It keeps **JWKS validation off the hot path** (see §3.2): the IdP-signed ID-JAG is validated **once** at the (async) token endpoint; every subsequent `/mcp` call validates a **Vyuu-signed** token with a cheap synchronous HMAC verify.

> **Recommendation:** build P2 as the primary path. Implement P1 ("consume an externally-issued access token directly on `/mcp`") only if a customer runs their own resource authorization server — it requires a synchronous JWKS verifier on the hot path (§3.3).

---

## 2. Scope & phases

| Phase | Deliverable | Rough effort |
|---|---|---|
| **P1** | `IdpJagIdentityProvider` + `ChainedIdentityProvider`; validate an EMA access token on `/mcp`; map `sub` → `Principal` (JIT user); access-attempt audit on failure. | 2–3 d |
| **P2** | RFC 9728 protected-resource metadata per vserver + `/oauth/token` (jwt-bearer grant): validate ID-JAG against the tenant directory's JWKS → mint a Vyuu-signed access token. Hot path verifies the Vyuu token. | 3–5 d |
| **P3** | Governance + UX: scope→tool gating (AND-combined with grants), per-vserver `client_id` allowlist, operator-console enable toggle + EMA identities in NHI, portal "no key needed" messaging. | 3–4 d |

All phases are **additive and feature-flagged**. Existing `vyuu_user_*` keys keep working unchanged.

---

## 3. End-to-end flows

### 3.1 Phase 2 (recommended) — Vyuu as Resource Authorization Server + Resource Server

```
 MCP client            Enterprise IdP (Okta)          Vyuu AS (/oauth/token)        Vyuu RS (/v/.../mcp)
     │                        │                              │                            │
     │ 1. user SSO + token-exchange (RFC 8693)               │                            │
     │───────────────────────►│  issues ID-JAG (JWT)         │                            │
     │   aud=<vyuu-as-issuer>  │  signed by IdP              │                            │
     │   resource=<vserver-id> │                            │                            │
     │◄───────────────────────│                            │                            │
     │                                                      │                            │
     │ 2. POST grant_type=jwt-bearer & assertion=<ID-JAG>   │                            │
     │─────────────────────────────────────────────────────►│                            │
     │     Vyuu: validate ID-JAG sig vs IdP JWKS (async),    │                            │
     │     check iss∈tenant directory, aud==our issuer,      │                            │
     │     resource→vserver in tenant, client_id allowed,    │                            │
     │     jti not replayed → MINT Vyuu access token (HS256) │                            │
     │◄─────────────────────────────────────────────────────│  {access_token, exp, scope}│
     │                                                                                    │
     │ 3. POST /v/{tenant}/{vserver}/mcp   Authorization: Bearer <vyuu access token>      │
     │───────────────────────────────────────────────────────────────────────────────────►│
     │    IdpJagIdentityProvider: sync HMAC-verify Vyuu token → sub→User(JIT) → Principal  │
     │    then UNCHANGED: tenant bind → vserver+grant authz → policy → upstream → audit/NHI│
     │◄───────────────────────────────────────────────────────────────────────────────────│
```

Key property: **step 2 (JWKS, network, async) happens once per session; step 3 (every call) is a local HMAC verify.**

### 3.2 Phase 1 (variant) — Vyuu consumes an externally-issued access token

If the enterprise runs its own resource authorization server, the client gets the access token there and presents it straight to `/mcp`. Vyuu then must verify an **IdP/AS-signed** token on the hot path → needs a **synchronous JWKS verifier** (§3.3). Same `sub→Principal` mapping.

### 3.3 The async/sync JWKS gotcha (read before coding)

`IdentityProvider.validate_principal(...)` is **synchronous** (see `identity/api_key_provider.py`). Our existing `users/oidc.py::JwksCache.validate_token(...)` is **async** and is only called from the async OIDC sign-in path. Therefore:

- **P2 hot path:** the token is **Vyuu-signed (HS256)** → verify with a synchronous `jwt.decode(token, key=settings.ema_signing_secret, algorithms=["HS256"], audience=…, issuer=…)`. **No JWKS, no async, no network.** ✔ preferred.
- **P2 token endpoint:** validating the IdP-signed **ID-JAG** *is* async (JWKS) — and that endpoint is an `async def` FastAPI route, so reuse `JwksCache.validate_token(...)` directly. ✔
- **P1 hot path (variant only):** to verify an IdP-signed access token synchronously, add a small `SyncJwksCache` (sync `httpx.Client`, same TTL/single-flight shape as `JwksCache`) **or** refresh JWKS in a background task and keep a sync-readable key dict. Do **not** call the async cache from the sync provider.

---

## 4. Data model changes

### 4.1 `idp_directories` — EMA trust config

We already store the OIDC issuer + client per directory. EMA reuses `oidc_issuer` as the **trusted ID-JAG issuer** and adds a few columns. New Alembic migration (next revision after `20260505_0015`):

```python
# migrations/versions/20260620_0016_ema_idp_jag.py
"""EMA / ID-JAG inbound auth — per-directory trust config

Revision ID: 20260620_0016
Revises: 20260505_0015
"""
def upgrade() -> None:
    op.add_column("idp_directories", sa.Column(
        "ema_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    # The audience the IdP must set on the ID-JAG = our resource-AS issuer id
    # for this tenant (e.g. https://gw.acme.com/v/{tenant}). Null until enabled.
    op.add_column("idp_directories", sa.Column("ema_audience", sa.Text(), nullable=True))
    # Optional explicit JWKS URI; if null we discover from oidc_issuer.
    op.add_column("idp_directories", sa.Column("ema_jwks_uri", sa.Text(), nullable=True))
    # Allowlist of MCP client_ids permitted to present ID-JAGs (empty = allow any
    # client the IdP already vetted). JSONB array of strings.
    op.add_column("idp_directories", sa.Column(
        "ema_allowed_client_ids",
        postgresql.JSONB(astext_type=sa.Text()),
        nullable=False, server_default=sa.text("'[]'::jsonb")))

def downgrade() -> None:
    for c in ("ema_allowed_client_ids", "ema_jwks_uri", "ema_audience", "ema_enabled"):
        op.drop_column("idp_directories", c)
```

ORM (`src/vyuu_gateway/db/models.py`, `IdpDirectory`):

```python
    ema_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    ema_audience: Mapped[str | None] = mapped_column(Text)
    ema_jwks_uri: Mapped[str | None] = mapped_column(Text)
    ema_allowed_client_ids: Mapped[list[str]] = mapped_column(
        postgresql.JSONB(astext_type=Text()), nullable=False,
        default=list, server_default=text("'[]'::jsonb"))
```

> EMA is **orthogonal to `signin_protocol`** (which governs *human* SSO). A directory can be SAML-for-SSO and still be EMA-enabled for agent traffic. Don't overload `signin_protocol`.

### 4.2 Virtual server resource identifier

EMA's `resource` claim must map to a vserver. Use a deterministic resource id rather than a new column:

```
resource id = f"{settings.public_base_url}/v/{tenant_id}/{vserver_name}/mcp"
```

This is already the canonical connect URL, so no schema change is required. (If you prefer an opaque stable id, add `virtual_servers.resource_id UUID` — optional.)

### 4.3 Replay cache for ID-JAG `jti` (P2 token endpoint)

ID-JAGs are single-use grants. Prevent replay within their short lifetime. Lightweight options:
- **Redis** (preferred if the deployment already runs the Redis session registry): `SETNX ema:jti:{jti} EX <exp-now>`.
- **Postgres** table `ema_consumed_jti(jti PK, tenant_id, consumed_at, expires_at)` with a periodic prune (reuse the sweeper cadence).

Skip only if you accept replay-within-300s as tolerable (you shouldn't for a security product).

---

## 5. Code changes — file by file

### 5.1 `identity/models.py` — a federated-user principal (clean NHI classification)

Add a principal type so EMA traffic is distinguishable from API-key traffic in NHI/audit. `tool_call_events.principal_type` is free `Text` (no CHECK), so this is a **code-only** change — just extend the two StrEnums.

```python
# identity/models.py
class PrincipalType(StrEnum):
    ENDPOINT_SESSION = "endpoint_session"
    SERVER_AGENT = "server_agent"
    API_KEY = "api_key"
    FEDERATED_USER = "federated_user"     # NEW — EMA / ID-JAG

class FederatedUserPrincipal(Principal):
    type: Literal[PrincipalType.FEDERATED_USER] = PrincipalType.FEDERATED_USER
    external_id: str = Field(min_length=1)   # the IdP `sub`
    client_id: str | None = None             # the MCP client app id (for NHI AI-app)
    directory_id: str | None = None
```

And mirror in `audit/events.py::AuditPrincipalType` (also free StrEnum):

```python
class AuditPrincipalType(StrEnum):
    ENDPOINT_SESSION = "endpoint_session"
    SERVER_AGENT = "server_agent"
    API_KEY = "api_key"
    FEDERATED_USER = "federated_user"     # NEW
```

> **Zero-change fallback:** if you want to ship P1 without touching enums, reuse `ApiKeyPrincipal` with `id=str(user.id)`. You lose the clean NHI distinction but everything else works. Recommended path is the new type — it's two enum lines.

### 5.2 `identity/jwt_bearer_provider.py` (NEW) — the EMA `IdentityProvider`

Implements the same `IdentityProvider` contract as `ApiKeyIdentityProvider`. Hot path verifies a **Vyuu-signed** access token (P2). It then resolves `sub` → `User` via the **existing JIT-create machinery**.

```python
# identity/jwt_bearer_provider.py  (skeleton)
from __future__ import annotations
import jwt
from datetime import UTC, datetime
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.orm import Session

from vyuu_gateway.db.models import IdpDirectory, User
from vyuu_gateway.db.session import bind_tenant_context
from vyuu_gateway.identity.models import FederatedUserPrincipal, Principal, PrincipalType
from vyuu_gateway.identity.provider import (
    IdentityCredentials, IdentityProvider, IdentityValidationError)

class IdpJagIdentityProvider(IdentityProvider):
    """Validates Vyuu-issued EMA access tokens (P2) and maps sub → User."""

    def __init__(self, session_factory, *, signing_secret: str, issuer: str) -> None:
        self._session_factory = session_factory
        self._secret = signing_secret
        self._issuer = issuer  # our resource-AS issuer id

    def validate_principal(self, *, tenant_id: UUID, credentials: IdentityCredentials) -> Principal:
        token = _extract_bearer(credentials.headers)          # reuse helper shape from api_key_provider
        if token is None or token.startswith("vyuu_user_"):    # not ours → let the chain fall through
            raise IdentityValidationError("not an EMA token")
        try:
            claims = jwt.decode(
                token, key=self._secret, algorithms=["HS256"],
                audience=str(tenant_id),                       # we set aud=tenant on mint
                issuer=self._issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.InvalidTokenError as exc:
            raise IdentityValidationError("invalid EMA token") from exc

        sub = claims["sub"]
        directory_id = claims.get("dir")
        client_id = claims.get("client_id")
        with self._session_factory() as session:
            bind_tenant_context(session, tenant_id)
            directory = session.scalar(select(IdpDirectory).where(
                IdpDirectory.tenant_id == tenant_id,
                IdpDirectory.id == directory_id,
                IdpDirectory.ema_enabled.is_(True)))
            if directory is None:
                raise IdentityValidationError("EMA not enabled for directory")
            # Reuse the IDP-1 JIT pattern: match (tenant, directory, external_id=sub)
            user = session.scalar(select(User).where(
                User.tenant_id == tenant_id,
                User.idp_directory_id == directory.id,
                User.external_id == sub))
            if user is None:
                user = _jit_create_federated_user(session, directory=directory, claims=claims)
            if user.disabled_at is not None:
                raise IdentityValidationError("principal disabled")   # kill-switch still bites
            user_id, display = user.id, (user.display_name or user.email)

        return FederatedUserPrincipal(
            type=PrincipalType.FEDERATED_USER, tenant_id=tenant_id,
            id=str(user_id), display=display,
            external_id=sub, client_id=client_id, directory_id=str(directory.id))
```

`_jit_create_federated_user` is the same shape as `api/idp_signin.py::_find_or_jit_create_user` (match on `(directory_id, external_id)`, create `User(auth_method=SCIM, external_id=sub, …)`, `db.add` + `db.flush`). **Refactor that existing function into `idp/service.py` and import it from both places** rather than duplicating.

### 5.3 `identity/chain.py` (NEW) — try API key, then EMA

```python
# identity/chain.py
class ChainedIdentityProvider(IdentityProvider):
    def __init__(self, providers: list[IdentityProvider]) -> None:
        self._providers = providers
    def validate_principal(self, *, tenant_id, credentials) -> Principal:
        last: Exception | None = None
        for p in self._providers:
            try:
                return p.validate_principal(tenant_id=tenant_id, credentials=credentials)
            except IdentityValidationError as exc:
                last = exc
        raise last or IdentityValidationError("no identity provider matched")
```

Order: **ApiKey first** (cheap prefix check, no surprises), **EMA second**. The EMA provider must cheaply reject non-EMA bearers (it does: `vyuu_user_*` prefix → raise immediately).

### 5.4 `api/ema_oauth.py` (NEW, P2) — Resource AS endpoints

```python
# api/ema_oauth.py  (skeleton)
router = APIRouter(tags=["ema-oauth"])

# RFC 9728 — advertised so EMA clients discover our AS + grant profile
@router.get("/v/{tenant_id}/{vserver_name}/.well-known/oauth-protected-resource")
def protected_resource_metadata(tenant_id: UUID, vserver_name: str, request: Request):
    base = request.app.state.settings.public_base_url
    issuer = f"{base}/v/{tenant_id}"
    return {
        "resource": f"{base}/v/{tenant_id}/{vserver_name}/mcp",
        "authorization_servers": [issuer],
        "authorization_grant_profiles_supported": [
            "urn:ietf:params:oauth:grant-profile:id-jag"],
    }

@router.post("/v/{tenant_id}/oauth/token")
async def token(tenant_id: UUID, request: Request, db = Depends(get_inbound_mcp_db_factory(tenant_id))):
    form = await request.form()
    if form.get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer":
        return _oauth_error("unsupported_grant_type")
    id_jag = form["assertion"]; client_id = form.get("client_id")

    # 1. unverified iss → find the tenant directory whose oidc_issuer matches + ema_enabled
    iss = jwt.get_unverified_claims(id_jag)["iss"]   # or decode header→claims carefully
    directory = db.scalar(select(IdpDirectory).where(
        IdpDirectory.tenant_id == tenant_id,
        IdpDirectory.oidc_issuer == iss,
        IdpDirectory.ema_enabled.is_(True)))
    if directory is None:
        return _oauth_error("invalid_grant")

    # 2. validate ID-JAG signature vs IdP JWKS (async — reuse users/oidc.py JwksCache)
    cfg = OidcConfig(issuer_url=directory.oidc_issuer, audience=directory.ema_audience)
    claims = await request.app.state.jwks_cache.validate_token(id_jag, config=cfg)

    # 3. checks: aud==our issuer, resource→vserver in tenant, client_id ∈ allowlist, jti not replayed
    _assert_resource_maps_to_tenant_vserver(claims["resource"], tenant_id, db)
    _assert_client_allowed(client_id or claims.get("client_id"), directory)
    _assert_jti_unused(claims["jti"], tenant_id, exp=claims["exp"])   # §4.3

    # 4. mint a short-lived Vyuu access token (HS256) — sync-verifiable on the hot path
    now = datetime.now(UTC)
    access = jwt.encode({
        "iss": f"{base}/v/{tenant_id}", "aud": str(tenant_id),
        "sub": claims["sub"], "email": claims.get("email"),
        "client_id": client_id, "dir": str(directory.id),
        "scope": claims.get("scope", ""),
        "iat": now, "exp": now + timedelta(seconds=settings.ema_access_token_ttl_seconds),
    }, settings.ema_signing_secret, algorithm="HS256")
    return {"access_token": access, "token_type": "Bearer",
            "expires_in": settings.ema_access_token_ttl_seconds, "scope": claims.get("scope", "")}
```

Wire in `main.py`: `app.include_router(ema_oauth_router)` (no `/api/v1` prefix — these are well-known + token endpoints under `/v/...`), and stash `app.state.jwks_cache = JwksCache()` if not already present.

### 5.5 `main.py` — build the chain when EMA is enabled

In `_build_default_identity_provider(settings)`:

```python
def _build_default_identity_provider(settings):
    api_key = ApiKeyIdentityProvider(SessionLocal)
    if not settings.ema_enabled:
        return api_key
    ema = IdpJagIdentityProvider(
        SessionLocal,
        signing_secret=settings.ema_signing_secret,
        issuer_template=settings.public_base_url)      # builds per-tenant issuer
    return ChainedIdentityProvider([api_key, ema])
```

(The lab’s `VYUU_LAB_USE_API_KEY_IDENTITY` branch is unchanged; EMA only augments the production provider.)

### 5.6 `config.py` — settings

```python
ema_enabled: bool = Field(default=False, validation_alias=AliasChoices("ema_enabled", "VYUU_EMA_ENABLED"))
ema_signing_secret: str = Field(default="", validation_alias=AliasChoices("ema_signing_secret", "VYUU_EMA_SIGNING_SECRET"))
ema_access_token_ttl_seconds: int = Field(default=900, validation_alias=AliasChoices(..., "VYUU_EMA_ACCESS_TOKEN_TTL_SECONDS"))
public_base_url: str = Field(default="http://127.0.0.1:8000", validation_alias=AliasChoices("public_base_url", "VYUU_PUBLIC_BASE_URL"))
```

`ema_signing_secret` must be ≥32 random bytes in prod (validate like `operator_auth_signing_secret`).

### 5.7 Scope ↔ tool gating (P3) — AND-combined with grants

The Vyuu access token carries `scope` (e.g. `chat.read chat.history`). Add a check **after** the existing vserver+grant authz, **before** policy, in `inbound_mcp.py`'s lifecycle (or inside the policy provider). Semantics: a call must satisfy **both** the token scope **and** the Vyuu grant/policy (defense in depth). Map scope→tool via a simple per-vserver mapping (config or a `virtual_server_tools.required_scope` column). If the token lacks the scope a tool requires → deny with a new `AuthFailureReason.INSUFFICIENT_SCOPE` (extend the enum) and emit an `access_attempt`.

### 5.8 NHI / audit enrichment (mostly free)

Because the `Principal` now carries `external_id` (real corporate `sub`) and `client_id` (the MCP app), audit rows and the NHI map get richer automatically. One small enhancement in `api/nhi_map.py::_classify_ai_app`: also key off `client_id` (not just `user_agent`) so the AI-app column is populated for EMA traffic.

---

## 6. Security checklist (must all hold)

- [ ] **Signature:** ID-JAG verified against the directory's JWKS (RS256/ES256); Vyuu access token verified HS256 with `ema_signing_secret`.
- [ ] **Issuer allowlist:** `iss` must match a `ema_enabled` `IdpDirectory.oidc_issuer` *in this tenant* (no cross-tenant issuer trust).
- [ ] **Audience pinning:** ID-JAG `aud` == `directory.ema_audience` (our AS issuer); Vyuu token `aud` == tenant id.
- [ ] **Resource pinning:** ID-JAG `resource` must resolve to a vserver in this tenant; the minted token is scoped to it.
- [ ] **Client allowlist:** `client_id` ∈ `directory.ema_allowed_client_ids` when the list is non-empty.
- [ ] **Replay:** ID-JAG `jti` consumed once within its `exp` (§4.3).
- [ ] **Expiry + skew:** require `exp`/`iat`; allow ≤60s clock skew; keep Vyuu access-token TTL short (≤15 min).
- [ ] **Key rotation:** JWKS TTL (existing cache = 300s) picks up IdP key rollover automatically.
- [ ] **No header trust:** identity comes only from the validated token — never from `x-vyuu-*` headers (same rule as `ApiKeyIdentityProvider`).
- [ ] **Tenant isolation:** every DB read in the provider is `bind_tenant_context`-bound; directory lookup is tenant-scoped.
- [ ] **Kill-switch preserved:** disabled user / revoked grant / policy deny still block at call time even with a valid token (this is the value EMA structurally lacks).
- [ ] **Anti-enumeration:** all validation failures surface as the same opaque "Authentication failed" 401 + an `access_attempt` audit event (mirror the existing `INVALID_BEARER` path).

---

## 7. Test plan

Mirror the existing patterns (`tests/identity/`, `tests/api/`, real-Postgres gated on `VYUU_TEST_DATABASE_URL`, the tenant-seed `try/finally` cleanup).

**Unit — `tests/identity/test_idp_jag_provider.py`**
- valid Vyuu token → `FederatedUserPrincipal` with right `id`/`external_id`/`client_id`
- expired token → `IdentityValidationError`
- wrong `aud` / wrong `iss` → reject
- `vyuu_user_*` bearer → provider raises immediately (chain falls through to ApiKey)
- disabled user → reject (kill-switch)
- EMA disabled on directory → reject

**Unit — token endpoint validation** (`tests/api/test_ema_oauth.py`)
- valid ID-JAG (mock JWKS) → mints token with correct claims
- bad signature / unknown issuer / wrong audience → `invalid_grant`
- `resource` not in tenant → reject
- `client_id` not allowlisted → reject
- replayed `jti` → reject second use

**Integration (real Postgres)** — seed tenant + EMA directory + vserver + grant:
- end-to-end: POST `/oauth/token` with a test ID-JAG → use returned token on `/v/.../mcp` → 200, and a `tool_call_events` row exists with `principal_type=federated_user`, the right `external_id`, and `client_id`
- no-grant on a private vserver → 403 + `access_attempt` (proves downstream authz still applies to EMA principals)
- chain: same client can use a `vyuu_user_*` key OR an EMA token interchangeably

**RLS** — an EMA token minted for tenant A cannot resolve a principal under tenant B (issuer + directory lookups are tenant-scoped).

---

## 8. Rollout & backward-compat

- **Additive + flagged:** `VYUU_EMA_ENABLED=false` by default → zero behavior change; `vyuu_user_*` keys untouched.
- **Per-directory opt-in:** EMA only active for directories with `ema_enabled=true`.
- **Sequencing:** ship P1 provider + P2 token endpoint together (they're co-dependent for the recommended Vyuu-signed hot path), then P3 governance/UX.
- **Docs:** update `docs/onboarding/AUTH.md` (new inbound surface), `API_REFERENCE.md` (the `/oauth/token` + `.well-known` routes), `MCP_SPECIFICS.md` (EMA notes), and the SBOM if any new dep is added (none expected — PyJWT + httpx already present).

---

## 9. Open decisions (with recommendations)

| Decision | Recommendation |
|---|---|
| P1-only vs through P2 | **Through P2** — keeps JWKS off the hot path and delivers the long-tail bridge. |
| Principal model | **New `FEDERATED_USER` type** (2 enum lines) for clean NHI; reuse JIT-to-User so grants/groups/audit work. |
| Scope semantics | **AND-combine** token scope with Vyuu grant/policy (defense in depth). |
| Replay cache | **Redis if present, else Postgres `ema_consumed_jti`** with sweeper prune. |
| Vyuu token format | **HS256 JWT** signed with `ema_signing_secret` (sync verify, stateless). |
| Resource id scheme | **Derive from connect URL** (no schema change); add `resource_id` only if an opaque id is needed. |

---

## 10. Effort summary

- P1 provider + chain + enum + JIT refactor: **2–3 days**
- P2 token endpoint + RFC 9728 + mint + trust config + migration: **3–5 days**
- P3 scope gating + client allowlist + operator/portal UX: **3–4 days**
- Tests across all: folded into the above; budget ~1.5 days of the total for the integration suite.

**Total: ~8–12 engineering days** for the full bridge, test-covered.

---

## References

- MCP EMA spec — https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization
- ext-auth spec source — https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization.mdx
- Integration seams in this repo: `identity/provider.py` (contract), `identity/api_key_provider.py` (reference impl), `api/inbound_mcp.py:300` (call site), `users/oidc.py::JwksCache` (JWKS), `api/idp_signin.py::_find_or_jit_create_user` (JIT), `db/models.py::IdpDirectory` (trust config), `config.py` (Settings), `main.py::_build_default_identity_provider` (wiring).
