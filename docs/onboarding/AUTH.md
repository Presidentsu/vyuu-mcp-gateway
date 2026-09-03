# AUTH — every authentication surface

The gateway has multiple auth surfaces because it serves multiple
audiences. This doc walks each one.

## Surface map

| Surface | Who | Bearer format | Verifier | Stored where |
|---|---|---|---|---|
| Operator console | admins | HMAC JWT (`eyJ...`) | `OperatorAuthProvider` | nowhere — JWT-signed against `VYUU_OPERATOR_AUTH_SIGNING_SECRET` |
| End-user portal session | users | Portal JWT | `authenticate_portal_session` | nowhere — JWT-signed |
| Inbound MCP (Cursor / Claude) | users (their AI client) | `vyuu_user_*` API key | `ApiKeyIdentityProvider` | `user_api_keys` (bcrypt hashed) |
| SCIM (IdP → us) | Entra / Workspace | `vyuu_scim_*` bearer | `authenticate_scim` | `idp_directories.scim_token_hash` (bcrypt) |
| Per-directory SSO (us ← IdP) | users | OIDC ID token / SAML assertion | `idp_signin.py` | not stored — exchanged for portal session JWT |
| Outbound to upstream MCP | gateway acting as user | various (header / bearer / OAuth-AC / JWT-bearer / mTLS) | `upstream/oauth_*.py` | `oauth_user_tokens` (per-user) + `secret_store` (per-tenant) |

## 1. Operator JWT

**Use case:** admin signs in to the operator console.

**Wire format:**

```
Authorization: Bearer eyJ0ZW5hbnRfaWQiOiI...<payload>.<HMAC-SHA256 signature>
                      ^------ base64url payload ------^.^----- HMAC-SHA256 sig -----^
```

Payload (the lab-style format):

```json
{
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "operator_id": "44444444-4444-4444-4444-444444444444",
  "display": "Lab Operator"
}
```

**Verifier:** `OperatorAuthProvider.authenticate(bearer)` — concrete
impl is `FakeOperatorAuthProvider` for the lab (HMAC-signed against
`VYUU_OPERATOR_AUTH_SIGNING_SECRET`). Production replaces with an
OIDC-backed provider that maps an IdP JWT claim to a row in `operators`.

**Code:** `src/vyuu_gateway/operator_auth/`.

**Rotation:** change `VYUU_OPERATOR_AUTH_SIGNING_SECRET` and restart.
All previous tokens become invalid. There's no automatic expiry — JWTs
without `exp` rely on the signing secret being the rotation lever.

## 2. Portal session JWT

**Use case:** end user signs in to the portal.

**How it's minted:**
- Local password sign-in → bcrypt verify → mint JWT.
- IdP SSO (OIDC or SAML) → callback resolves user → mint JWT.

**Stored:** `sessionStorage["vyuu.portal.token"]` — survives tab
reloads, cleared on browser close.

**Code:** `src/vyuu_gateway/api/portal.py` (verifier),
`src/vyuu_gateway/users/login_endpoint.py` (mint via password),
`src/vyuu_gateway/api/idp_signin.py` (mint via SSO).

## 3. User API key (`vyuu_user_*`)

**Use case:** an AI client (Cursor, Claude Desktop) calls the gateway
on behalf of a user.

**Format:**

```
vyuu_user_<32-byte-url-safe-random>
```

**Issuance:** user clicks "Issue API key" in the portal → server
generates random secret → stores bcrypt hash in `user_api_keys.secret_hash`
→ returns the plaintext **once** in the API response. We never store
plaintext.

**Verification (hot path):**

1. `ApiKeyIdentityProvider.identify(bearer)` is called from
   `inbound_mcp.py`.
2. We split `vyuu_user_<random>` and look up by the deterministic
   PREFIX (first ~8 chars) for an indexed query — the prefix is stored
   alongside the hash so we can find candidate rows fast.
3. bcrypt verify against `secret_hash`. Constant-time.
4. Return `Principal(type=API_KEY, id=user_api_key.id, display=...)`.

**Code:** `src/vyuu_gateway/identity/api_key.py`,
`src/vyuu_gateway/registry/users_service.py` (issue / revoke).

## 4. SCIM bearer (`vyuu_scim_*`)

**Use case:** Entra ID or Google Workspace pushes user/group
provisioning events.

**Issuance:** admin connects an IdP directory → server mints a
`vyuu_scim_<32-byte>` bearer → stores bcrypt hash on
`idp_directories.scim_token_hash` → returns plaintext once. The admin
pastes it into the IdP's "Provisioning" settings.

**Verification:** `authenticate_scim` dependency. Looks up directory
by URL path (`/scim/v2/{directory_id}`), bcrypt-verifies the bearer
against the stored hash, binds tenant context.

**Anti-enumeration:** unknown directory id returns 401 (same as wrong
bearer), so an attacker can't probe for valid IDs.

**Code:** `src/vyuu_gateway/scim/auth.py`,
`src/vyuu_gateway/idp/scim_tokens.py`.

## 5. Per-directory SSO (OIDC + SAML)

**Use case:** user signs in to the portal (or operator console) using
their corporate IdP that's connected via IDP-1.

**OIDC flow** (Entra ID + Google Workspace + generic):

1. User clicks "Continue with X" → POST `/api/v1/auth/{tenant_id}/idp/{directory_id}/oidc-start`.
2. We build an authorize URL with `state` + `nonce`, return it.
3. User authenticates at the IdP, redirects back to
   `/api/v1/auth/{tenant_id}/idp/{directory_id}/oidc-callback?code=...&state=...`.
4. We exchange the code for tokens, verify the ID token's signature
   against the directory's JWKS, validate `iss` / `aud` / `nonce`.
5. Look up (or JIT-create) the user by `(directory_id, external_id)`
   where `external_id = id_token.sub`.
6. Mint portal session JWT, set in `sessionStorage`, redirect to `/portal/`.

**SAML flow** (Entra ID Custom App + Google Workspace SAML App):

1. User clicks "Continue with X" → GET `/api/v1/auth/{tenant_id}/idp/{directory_id}/saml-login`.
2. We build a SAML AuthnRequest, redirect user to IdP.
3. User authenticates, IdP POSTs SAML Response to
   `/api/v1/auth/{tenant_id}/idp/{directory_id}/saml-acs`.
4. `pysaml2` validates: signature, audience, NotOnOrAfter, replay nonce.
5. Same JIT-create + JWT mint as OIDC.

**Audience pinning:** the SP's `entity_id` is per-directory:
`https://<host>/api/v1/auth/{tenant_id}/idp/{directory_id}`. Cross-tenant
relay-state attacks fail because the audience won't match.

**Code:** `src/vyuu_gateway/api/idp_signin.py`,
`src/vyuu_gateway/idp/saml_provider.py`.

## 6. Outbound auth to upstream MCPs

The gateway calls upstream MCP servers on the user's behalf. Several
auth modes — pick what the upstream supports:

| Mode | When to use | Code |
|---|---|---|
| `auth_org_tier` (static header) | Single shared API key for the whole tenant | `mcp_servers.outbound_auth_*` columns + `secret_store` |
| `auth_user_tier_passthrough` | The user's own bearer is forwarded as-is | `inbound_mcp.py` request handlers |
| `auth_oauth_client_credentials` | Service-to-service OAuth (no user) | `secret_store` + `httpx` token request |
| `auth_oauth_authcode` | Per-user delegated OAuth (RFC 6749 authorization code) | `upstream/oauth_authcode.py` + `oauth_user_tokens` |
| `auth_oauth_jwt_bearer` | RFC 7523 JWT-bearer for service accounts | `upstream/oauth_jwt_bearer.py` |
| `auth_mtls` | Transport-layer cert auth | `upstream/pool.py` cert wiring |

**Per-user OAuth tokens (`oauth_user_tokens`):** stored encrypted via
the secret store. Refresh on 401. Revoke when the user is disabled.
RLS-enforced per tenant.

## 7. Identity provider chain

Inbound bearer → `Principal` resolution is pluggable via
`IdentityProvider` Protocol. Production uses `ApiKeyIdentityProvider`.
Future: a chain that tries multiple resolvers (api_key, mTLS cert,
JWT) in order.

## Common questions

**Q: How do I rotate the operator JWT secret?**
A: Update `VYUU_OPERATOR_AUTH_SIGNING_SECRET`, restart. All operators
re-sign in. There's no graceful overlap — by design (rotation is
infrequent + manual).

**Q: Can a user share their API key with another user?**
A: Yes, mechanically — but the audit log records every call against
that key, and the operator console attributes calls to the key's
owner. So sharing breaks accountability without breaking auth.

**Q: Why bcrypt for API keys instead of HMAC or Argon2?**
A: bcrypt is well-supported, has a clear cost-factor knob, and the
verify cost (~50ms) is acceptable on the hot path because we cache
the result for the request lifetime.

**Q: What happens if both an OIDC user and a local user share an email?**
A: They're separate rows in `users` because `(tenant_id, idp_directory_id,
external_id)` is unique — local user has `idp_directory_id=NULL`. Sign-in
disambiguates by which surface the user used.

**Q: Can SCIM provision an admin (operator)?**
A: No. SCIM provisions `users` (end-user portal). Operators are a
different table; they're created by the bootstrap or by an existing
operator via the Admins page.
