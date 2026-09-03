"""EMA-1 · real-Postgres tests for the ID-JAG token endpoint + chain e2e.

Drives the full bridge exactly as an enterprise deployment would:

    RSA-signed ID-JAG (fake Okta, JWKS over MockTransport)
        → POST /v/{tenant}/oauth/token          (mint Vyuu HS256 token)
            → POST /v/{tenant}/{vserver}/mcp    (chain: Fake→EMA leg)

Needs real Postgres (JIT user rows, directory trust config, jti replay
PK, grants) — gated on `VYUU_TEST_DATABASE_URL`. Point it at the
dedicated `vyuu_gateway_os_test` DB; the shared lab DB has prod-repo
schema drift.
"""

from __future__ import annotations

import os

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

import json  # noqa: E402
from collections.abc import AsyncIterator  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402
from datetime import UTC, datetime, timedelta  # noqa: E402
from typing import Any  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import anyio  # noqa: E402
import httpx  # noqa: E402
import jwt  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from sqlalchemy import create_engine, select, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.api.ema_oauth import EmaJwksFetcher  # noqa: E402
from vyuu_gateway.audit.emitter import EmitResult  # noqa: E402
from vyuu_gateway.audit.events import AuditEvent, AuthFailureReason  # noqa: E402
from vyuu_gateway.config import Settings  # noqa: E402
from vyuu_gateway.db.models import (  # noqa: E402
    EmaConsumedJti,
    GrantPrincipalKind,
    IdpDirectory,
    IdpDirectoryKind,
    IdpSigninProtocol,
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
    User,
    VirtualServer,
    VirtualServerGrant,
    VirtualServerVisibility,
)
from vyuu_gateway.identity.cimd_inbound import InboundCimdResolver  # noqa: E402
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.operator_auth.fake import mint_operator_test_token  # noqa: E402
from vyuu_gateway.registry.url_security import UrlSecurityPolicy  # noqa: E402

pgmark = pytest.mark.skipif(
    _DATABASE_URL is None,
    reason="VYUU_TEST_DATABASE_URL not set",
)
pytestmark = pgmark

_BASE = "http://gateway"
_ISSUER = "https://idp.test"
_KID = "ema-test-kid"
_EMA_SECRET = "ema-test-signing-secret-0123456789abcdef-XYZ"
_OP_SECRET = "operator-signing-secret-for-ema-p3-tests-0123"

# One RSA keypair per module — 2048-bit generation is ~100 ms; no need
# to pay it per test.
_IDP_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_IDP_JWK: dict[str, Any] = json.loads(
    jwt.algorithms.RSAAlgorithm.to_jwk(_IDP_KEY.public_key())
)
_IDP_JWK.update({"kid": _KID, "use": "sig", "alg": "RS256"})
# A second key whose signatures must NOT verify against the JWKS above.
_WRONG_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(
        create_engine(_DATABASE_URL, future=True), autoflush=False, future=True
    )


def _fake_idp_transport() -> httpx.MockTransport:
    """Serves the fake IdP's discovery doc + JWKS in-process."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"jwks_uri": f"{_ISSUER}/jwks"})
        if request.url.path.endswith("/jwks"):
            return httpx.Response(200, json={"keys": [_IDP_JWK]})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _id_jag(
    tenant_id: UUID,
    *,
    sub: str = "okta-user-7",
    email: str | None = "priya@corp.example",
    audience: str | None = None,
    resource: str | None = None,
    client_id: str | None = "cursor-app-id",
    jti: str | None = None,
    key: Any = None,
    kid: str = _KID,
    exp_delta: timedelta = timedelta(minutes=5),
) -> str:
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "iss": _ISSUER,
        "aud": audience or f"{_BASE}/v/{tenant_id}",
        "sub": sub,
        "jti": jti or uuid4().hex,
        "iat": now,
        "exp": now + exp_delta,
        "scope": "tools.read tools.call",
        "name": "Priya Sharma",
    }
    if email is not None:
        claims["email"] = email
    if resource is not None:
        claims["resource"] = resource
    if client_id is not None:
        claims["client_id"] = client_id
    return jwt.encode(
        claims, key or _IDP_KEY, algorithm="RS256", headers={"kid": kid}
    )


def _seed(
    factory: Any,
    *,
    visibility: VirtualServerVisibility = VirtualServerVisibility.PUBLIC,
    allowed_client_ids: list[str] | None = None,
    ema_enabled: bool = True,
) -> dict[str, Any]:
    ids: dict[str, Any] = {"tenant": uuid4(), "operator": uuid4(), "directory": uuid4()}
    with factory() as s:
        s.add(Tenant(id=ids["tenant"], name=f"t-{ids['tenant'].hex[:6]}", tier=TenantTier.SHARED))
        s.commit()
    with factory() as s:
        # idp_directories is FORCE-RLS — bind tenant context before insert.
        s.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, false)"),
            {"tid": str(ids["tenant"])},
        )
        s.add(
            Operator(
                id=ids["operator"],
                tenant_id=ids["tenant"],
                email=f"op-{ids['operator'].hex[:6]}@test",
                role=OperatorRole.ADMIN,
            )
        )
        s.add(
            IdpDirectory(
                id=ids["directory"],
                tenant_id=ids["tenant"],
                kind=IdpDirectoryKind.ENTRA,
                display_name="Fake Okta",
                signin_protocol=IdpSigninProtocol.OIDC,
                scim_token_hash="unused-in-this-test",
                oidc_issuer=_ISSUER,
                ema_enabled=ema_enabled,
                ema_audience=f"{_BASE}/v/{ids['tenant']}",
                ema_allowed_client_ids=allowed_client_ids or [],
            )
        )
        vs = VirtualServer(
            tenant_id=ids["tenant"],
            name="finance-readonly",
            visibility=visibility,
            created_by=ids["operator"],
        )
        s.add(vs)
        s.flush()
        ids["vserver"] = vs.id
        s.commit()
    return ids


def _cleanup(factory: Any, tenant_id: UUID) -> None:
    with factory() as s:
        s.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        s.commit()


class RecordingAuditEmitter:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit_nowait(self, event: AuditEvent) -> EmitResult:
        self.events.append(event)
        return EmitResult(accepted=True)


@asynccontextmanager
async def _gateway() -> AsyncIterator[tuple[httpx.AsyncClient, RecordingAuditEmitter, Any]]:
    audit = RecordingAuditEmitter()
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
            operator_auth_signing_secret=_OP_SECRET,
            ema_enabled=True,
            ema_signing_secret=_EMA_SECRET,
            public_base_url=_BASE,
        ),
        audit_emitter=audit,
    )
    # Inject the fake IdP's JWKS transport.
    app.state.ema_jwks_fetcher = EmaJwksFetcher(
        http_client_factory=lambda: httpx.AsyncClient(transport=_fake_idp_transport())
    )
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url=_BASE) as http:
            yield http, audit, app


async def _mint(
    http: httpx.AsyncClient,
    tenant_id: UUID,
    assertion: str,
    *,
    client_id: str | None = "cursor-app-id",
) -> httpx.Response:
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": assertion,
    }
    if client_id is not None:
        data["client_id"] = client_id
    return await http.post(f"/v/{tenant_id}/oauth/token", data=data)


# --- token endpoint ----------------------------------------------------------


def test_mint_happy_path_creates_jit_user_and_valid_token() -> None:
    async def run() -> None:
        factory = _factory()
        ids = _seed(factory)
        tenant = ids["tenant"]
        try:
            async with _gateway() as (http, _audit, _app):
                r = await _mint(http, tenant, _id_jag(tenant))
                assert r.status_code == 200, r.text
                body = r.json()
                assert body["token_type"] == "Bearer"
                assert body["expires_in"] == 900
                assert body["scope"] == "tools.read tools.call"
                claims = jwt.decode(
                    body["access_token"],
                    _EMA_SECRET,
                    algorithms=["HS256"],
                    audience=str(tenant),
                    issuer=f"{_BASE}/v/{tenant}",
                )
                assert claims["sub"] == "okta-user-7"
                assert claims["dir"] == str(ids["directory"])
                assert claims["client_id"] == "cursor-app-id"

                # JIT user landed with the shared (directory, external_id) rule.
                with factory() as s:
                    user = s.scalar(
                        select(User).where(
                            User.tenant_id == tenant,
                            User.external_id == "okta-user-7",
                        )
                    )
                    assert user is not None
                    assert user.email == "priya@corp.example"
                    assert user.idp_directory_id == ids["directory"]
                    jti_rows = s.execute(
                        select(EmaConsumedJti).where(EmaConsumedJti.tenant_id == tenant)
                    ).scalars().all()
                    assert len(jti_rows) == 1
        finally:
            _cleanup(factory, tenant)

    anyio.run(run)


def test_mint_rejections() -> None:
    """One seeded world, the full rejection matrix — each case must
    surface as the same opaque `invalid_grant` (anti-enumeration)."""

    async def run() -> None:
        factory = _factory()
        ids = _seed(factory, allowed_client_ids=["cursor-app-id"])
        tenant = ids["tenant"]
        try:
            async with _gateway() as (http, _audit, _app):
                # wrong grant_type
                r = await http.post(
                    f"/v/{tenant}/oauth/token",
                    data={"grant_type": "authorization_code", "assertion": "x"},
                )
                assert r.json()["error"] == "unsupported_grant_type"

                # unknown issuer (valid JWT, issuer not registered)
                bad_iss = jwt.encode(
                    {
                        "iss": "https://not-registered.example",
                        "aud": f"{_BASE}/v/{tenant}",
                        "sub": "s", "jti": uuid4().hex,
                        "iat": datetime.now(UTC),
                        "exp": datetime.now(UTC) + timedelta(minutes=5),
                    },
                    _IDP_KEY, algorithm="RS256", headers={"kid": _KID},
                )
                r = await _mint(http, tenant, bad_iss)
                assert r.json()["error"] == "invalid_grant"

                # bad signature (right issuer/kid, wrong key)
                r = await _mint(http, tenant, _id_jag(tenant, key=_WRONG_KEY))
                assert r.json()["error"] == "invalid_grant"

                # wrong audience
                r = await _mint(http, tenant, _id_jag(tenant, audience="https://other.example"))
                assert r.json()["error"] == "invalid_grant"

                # expired
                r = await _mint(http, tenant, _id_jag(tenant, exp_delta=timedelta(minutes=-10)))
                assert r.json()["error"] == "invalid_grant"

                # missing email claim
                r = await _mint(http, tenant, _id_jag(tenant, email=None))
                assert r.json()["error"] == "invalid_grant"

                # resource outside this tenant's vservers
                r = await _mint(
                    http, tenant,
                    _id_jag(tenant, resource=f"{_BASE}/v/{tenant}/not-a-vserver/mcp"),
                )
                assert r.json()["error"] == "invalid_grant"

                # resource for ANOTHER tenant entirely
                r = await _mint(
                    http, tenant,
                    _id_jag(tenant, resource=f"{_BASE}/v/{uuid4()}/finance-readonly/mcp"),
                )
                assert r.json()["error"] == "invalid_grant"

                # client not on the allowlist
                r = await _mint(
                    http, tenant, _id_jag(tenant, client_id="rogue-app"), client_id="rogue-app"
                )
                assert r.json()["error"] == "invalid_grant"

                # valid resource + allowlisted client still mints
                r = await _mint(
                    http, tenant,
                    _id_jag(tenant, resource=f"{_BASE}/v/{tenant}/finance-readonly/mcp"),
                )
                assert r.status_code == 200, r.text
        finally:
            _cleanup(factory, tenant)

    anyio.run(run)


def test_jti_replay_is_rejected_second_time() -> None:
    async def run() -> None:
        factory = _factory()
        ids = _seed(factory)
        tenant = ids["tenant"]
        try:
            async with _gateway() as (http, _audit, _app):
                assertion = _id_jag(tenant, jti="grant-jti-once")
                first = await _mint(http, tenant, assertion)
                assert first.status_code == 200, first.text
                second = await _mint(http, tenant, assertion)
                assert second.status_code == 400
                assert second.json()["error"] == "invalid_grant"
        finally:
            _cleanup(factory, tenant)

    anyio.run(run)


def test_directory_toggle_and_master_switch() -> None:
    async def run() -> None:
        factory = _factory()
        ids = _seed(factory, ema_enabled=False)
        tenant = ids["tenant"]
        try:
            # Directory not EMA-enabled → invalid_grant.
            async with _gateway() as (http, _audit, _app):
                r = await _mint(http, tenant, _id_jag(tenant))
                assert r.json()["error"] == "invalid_grant"

            # Master switch off → whole surface 404s (endpoint + metadata).
            app = create_app(
                Settings(
                    app_name="Vyuu MCP Gateway",
                    environment="test",
                    log_level="CRITICAL",
                    version="test-version",
                    operator_auth_signing_secret="ignored-here",
                    ema_enabled=False,
                    public_base_url=_BASE,
                )
            )
            async with app.router.lifespan_context(app):
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url=_BASE) as http:
                    r = await _mint(http, tenant, _id_jag(tenant))
                    assert r.status_code == 404
                    meta = await http.get(
                        f"/.well-known/oauth-protected-resource/v/{tenant}/finance-readonly/mcp"
                    )
                    assert meta.status_code == 404
        finally:
            _cleanup(factory, tenant)

    anyio.run(run)


def test_protected_resource_metadata_shape() -> None:
    async def run() -> None:
        factory = _factory()
        ids = _seed(factory)
        tenant = ids["tenant"]
        try:
            async with _gateway() as (http, _audit, _app):
                r = await http.get(
                    f"/.well-known/oauth-protected-resource/v/{tenant}/finance-readonly/mcp"
                )
                assert r.status_code == 200
                body = r.json()
                assert body["resource"] == f"{_BASE}/v/{tenant}/finance-readonly/mcp"
                assert body["authorization_servers"] == [f"{_BASE}/v/{tenant}"]
                assert body["authorization_grant_profiles_supported"] == [
                    "urn:ietf:params:oauth:grant-profile:id-jag"
                ]
        finally:
            _cleanup(factory, tenant)

    anyio.run(run)


# --- chain e2e: minted token → /mcp ------------------------------------------


def test_chain_e2e_grant_enforcement_and_kill_switch() -> None:
    """The moat proof: an IdP-blessed token still passes through Vyuu's
    per-call enforcement — private-vserver grants gate access, and
    disabling the user revokes mid-token-lifetime."""

    async def run() -> None:
        factory = _factory()
        ids = _seed(factory, visibility=VirtualServerVisibility.PRIVATE)
        tenant = ids["tenant"]
        try:
            async with _gateway() as (http, audit, _app):
                minted = await _mint(http, tenant, _id_jag(tenant))
                assert minted.status_code == 200, minted.text
                token = minted.json()["access_token"]
                mcp_url = f"/v/{tenant}/finance-readonly/mcp"
                discover = {
                    "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                    "params": {"_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28"
                    }},
                }
                headers = {"Authorization": f"Bearer {token}"}

                # 1. Private vserver, no grant → 403 + access_attempt.
                r = await http.post(mcp_url, json=discover, headers=headers)
                assert r.status_code == 403
                attempts = [
                    e for e in audit.events
                    if e.auth_failure_reason == AuthFailureReason.NO_GRANT
                ]
                assert attempts, "expected NO_GRANT access_attempt"
                assert attempts[-1].principal.type.value == "federated_user"

                # 2. Grant the JIT user → same token now passes.
                with factory() as s:
                    user = s.scalar(
                        select(User).where(
                            User.tenant_id == tenant,
                            User.external_id == "okta-user-7",
                        )
                    )
                    assert user is not None
                    user_id = user.id
                    s.add(
                        VirtualServerGrant(
                            tenant_id=tenant,
                            vserver_id=ids["vserver"],
                            principal_kind=GrantPrincipalKind.USER,
                            principal_id=user_id,
                            granted_by=ids["operator"],
                        )
                    )
                    s.commit()
                r = await http.post(mcp_url, json=discover, headers=headers)
                assert r.status_code == 200, r.text
                assert r.json()["result"]["supportedVersions"] == ["2026-07-28"]

                # 3. Kill-switch: disable the user → the STILL-VALID token
                #    is rejected on the very next call.
                with factory() as s:
                    s.execute(
                        text("UPDATE users SET disabled_at = now() WHERE id = :id"),
                        {"id": user_id},
                    )
                    s.commit()
                r = await http.post(mcp_url, json=discover, headers=headers)
                assert r.status_code == 401

                # 4. Legacy fake-header identity still authenticates via
                #    the chain's first leg (order regression guard).
                r = await http.post(
                    mcp_url,
                    json=discover,
                    headers={
                        "x-vyuu-tenant-id": str(tenant),
                        "x-vyuu-principal-type": "endpoint_session",
                        "x-vyuu-principal-id": "ep-1",
                    },
                )
                # endpoint_session principal has no grant on the private
                # vserver → 403 (not 401) proves identity resolved via leg 1.
                assert r.status_code == 403
        finally:
            _cleanup(factory, tenant)

    anyio.run(run)


# --- EMA-1 P3 · operator configuration endpoint ------------------------------


def _op_headers(tenant_id: UUID, operator_id: UUID) -> dict[str, str]:
    token = mint_operator_test_token(
        tenant_id=tenant_id, operator_id=operator_id, signing_secret=_OP_SECRET
    )
    return {"Authorization": f"Bearer {token}"}


def test_ema_config_endpoint_enables_disables_and_revokes() -> None:
    """Disabling EMA on a directory must revoke tokens already in the
    wild — the hot path re-checks the flag on every call. That is the
    per-call kill-switch EMA itself cannot offer."""

    async def run() -> None:
        factory = _factory()
        ids = _seed(factory, ema_enabled=False)
        tenant, operator = ids["tenant"], ids["operator"]
        try:
            async with _gateway() as (http, _audit, _app):
                hdrs = _op_headers(tenant, operator)
                url = f"/api/v1/idp/directories/{ids['directory']}/ema"

                # Omitting the audience defaults it to the canonical
                # per-tenant issuer — the same value our RFC 9728
                # metadata advertises — so it cannot drift by typo.
                r = await http.patch(url, json={"enabled": True}, headers=hdrs)
                assert r.status_code == 200, r.text
                assert r.json()["ema_audience"] == f"{_BASE}/v/{tenant}"

                # Explicit config (adds a client allowlist).
                r = await http.patch(
                    url,
                    json={
                        "enabled": True,
                        "audience": f"{_BASE}/v/{tenant}",
                        "allowed_client_ids": ["cursor-app-id"],
                    },
                    headers=hdrs,
                )
                assert r.status_code == 200, r.text
                body = r.json()
                assert body["ema_enabled"] is True
                assert body["ema_allowed_client_ids"] == ["cursor-app-id"]

                # A token can now be minted and used.
                minted = await _mint(http, tenant, _id_jag(tenant))
                assert minted.status_code == 200, minted.text
                token = minted.json()["access_token"]
                mcp_url = f"/v/{tenant}/finance-readonly/mcp"
                discover = {
                    "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                    "params": {"_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28"
                    }},
                }
                auth = {"Authorization": f"Bearer {token}"}
                assert (await http.post(mcp_url, json=discover, headers=auth)).status_code == 200

                # Disable → the SAME still-unexpired token is dead.
                r = await http.patch(
                    url, json={"enabled": False, "audience": ""}, headers=hdrs
                )
                assert r.status_code == 200
                assert r.json()["ema_enabled"] is False
                assert (await http.post(mcp_url, json=discover, headers=auth)).status_code == 401

                # ...and no new token can be minted either.
                assert (await _mint(http, tenant, _id_jag(tenant))).status_code == 400

                # Both transitions are in the admin audit trail.
                with factory() as sdb:
                    sdb.execute(
                        text("SELECT set_config('app.current_tenant_id', :t, false)"),
                        {"t": str(tenant)},
                    )
                    actions = sdb.execute(
                        text("SELECT action FROM admin_audit_log WHERE tenant_id = :t"),
                        {"t": str(tenant)},
                    ).scalars().all()
                assert "idp.ema_enable" in actions
                assert "idp.ema_disable" in actions
        finally:
            _cleanup(factory, tenant)

    anyio.run(run)


def test_ema_cannot_be_enabled_without_an_issuer_to_anchor_trust() -> None:
    async def run() -> None:
        factory = _factory()
        ids = _seed(factory, ema_enabled=False)
        tenant, operator = ids["tenant"], ids["operator"]
        try:
            with factory() as sdb:
                sdb.execute(
                    text("SELECT set_config('app.current_tenant_id', :t, false)"),
                    {"t": str(tenant)},
                )
                sdb.execute(
                    text("UPDATE idp_directories SET oidc_issuer = NULL WHERE id = :d"),
                    {"d": str(ids["directory"])},
                )
                sdb.commit()
            async with _gateway() as (http, _audit, _app):
                r = await http.patch(
                    f"/api/v1/idp/directories/{ids['directory']}/ema",
                    json={"enabled": True, "audience": f"{_BASE}/v/{tenant}"},
                    headers=_op_headers(tenant, operator),
                )
                assert r.status_code == 400
                assert "issuer" in r.json()["detail"]
        finally:
            _cleanup(factory, tenant)

    anyio.run(run)


# --- MCP-2 P3 · inbound CIMD ------------------------------------------------

_CIMD_ID = "https://acme-client.example/.well-known/oauth-client"
_CIMD_POLICY = UrlSecurityPolicy(allowlist=("acme-client.example",))


def _cimd_resolver(
    calls: list[httpx.Request], *, status_code: int = 200
) -> InboundCimdResolver:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if status_code != 200:
            return httpx.Response(status_code)
        return httpx.Response(
            200, json={"client_id": _CIMD_ID, "client_name": "Acme Desktop"}
        )

    return InboundCimdResolver(
        policy=_CIMD_POLICY, transport=httpx.MockTransport(handler)
    )


def test_cimd_client_id_resolves_and_mints() -> None:
    factory = _factory()
    ids = _seed(factory, allowed_client_ids=[_CIMD_ID])
    calls: list[httpx.Request] = []

    async def run() -> None:
        async with _gateway() as (http, _audit, app):
            app.state.inbound_cimd_resolver = _cimd_resolver(calls)
            response = await _mint(
                http, ids["tenant"], _id_jag(ids["tenant"]), client_id=_CIMD_ID
            )
            assert response.status_code == 200, response.text

    try:
        anyio.run(run)
        assert len(calls) == 1
    finally:
        _cleanup(factory, ids["tenant"])


def test_a_cimd_client_whose_document_is_gone_is_refused() -> None:
    """CIMD revocation is "stop serving the document". An allowlist alone
    cannot observe that — the entry stays in the list forever — so this
    is the behaviour the whole inbound half exists to buy."""

    factory = _factory()
    ids = _seed(factory, allowed_client_ids=[_CIMD_ID])
    calls: list[httpx.Request] = []

    async def run() -> None:
        async with _gateway() as (http, _audit, app):
            app.state.inbound_cimd_resolver = _cimd_resolver(calls, status_code=404)
            response = await _mint(
                http, ids["tenant"], _id_jag(ids["tenant"]), client_id=_CIMD_ID
            )
            assert response.status_code == 400
            assert response.json()["error"] == "invalid_grant"

    try:
        anyio.run(run)
        assert len(calls) == 1
    finally:
        _cleanup(factory, ids["tenant"])


def test_an_empty_allowlist_never_triggers_a_fetch() -> None:
    """The SSRF bound, asserted directly.

    An empty allowlist means no membership check ran, so nothing has
    vouched for the URL the caller supplied. Resolving it anyway would
    let anyone holding a valid ID-JAG point this gateway at any address
    it can reach — an internal port scan, or a flood aimed at a third
    party. The mint must succeed (empty list = IdP policy already vetted
    the client) with **zero** outbound requests.
    """

    factory = _factory()
    ids = _seed(factory, allowed_client_ids=[])
    calls: list[httpx.Request] = []

    async def run() -> None:
        async with _gateway() as (http, _audit, app):
            app.state.inbound_cimd_resolver = _cimd_resolver(calls)
            response = await _mint(
                http,
                ids["tenant"],
                _id_jag(ids["tenant"]),
                client_id="https://attacker-chosen.example/doc",
            )
            assert response.status_code == 200, response.text

    try:
        anyio.run(run)
        assert calls == []
    finally:
        _cleanup(factory, ids["tenant"])


def test_a_url_client_id_not_on_the_allowlist_is_refused_before_any_fetch() -> None:
    """Ordering: the allowlist check runs first, so a rejected client_id
    costs no outbound request at all."""

    factory = _factory()
    ids = _seed(factory, allowed_client_ids=[_CIMD_ID])
    calls: list[httpx.Request] = []

    async def run() -> None:
        async with _gateway() as (http, _audit, app):
            app.state.inbound_cimd_resolver = _cimd_resolver(calls)
            response = await _mint(
                http,
                ids["tenant"],
                _id_jag(ids["tenant"]),
                client_id="https://attacker-chosen.example/doc",
            )
            assert response.status_code == 400
            assert response.json()["error"] == "invalid_grant"

    try:
        anyio.run(run)
        assert calls == []
    finally:
        _cleanup(factory, ids["tenant"])


def test_resolution_is_off_unless_configured() -> None:
    """Default-off: an allowlisted CIMD client_id still mints without a
    resolver, exactly as before P3. Negative control for the tests above
    — they must be asserting the feature, not the allowlist."""

    factory = _factory()
    ids = _seed(factory, allowed_client_ids=[_CIMD_ID])

    async def run() -> None:
        async with _gateway() as (http, _audit, app):
            assert app.state.inbound_cimd_resolver is None
            response = await _mint(
                http, ids["tenant"], _id_jag(ids["tenant"]), client_id=_CIMD_ID
            )
            assert response.status_code == 200, response.text

    try:
        anyio.run(run)
    finally:
        _cleanup(factory, ids["tenant"])


def test_an_opaque_client_id_is_never_fetched_even_when_allowlisted() -> None:
    """Only https client_ids are CIMD identifiers; a conventional opaque
    id keeps literal matching and costs no request."""

    factory = _factory()
    ids = _seed(factory, allowed_client_ids=["cursor-app-id"])
    calls: list[httpx.Request] = []

    async def run() -> None:
        async with _gateway() as (http, _audit, app):
            app.state.inbound_cimd_resolver = _cimd_resolver(calls)
            response = await _mint(
                http, ids["tenant"], _id_jag(ids["tenant"]), client_id="cursor-app-id"
            )
            assert response.status_code == 200, response.text

    try:
        anyio.run(run)
        assert calls == []
    finally:
        _cleanup(factory, ids["tenant"])
