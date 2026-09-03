"""Tests for the DCR client (RFC 9728 → 8414 → 7591 discovery + register).

Uses an in-process ASGI stub patched into `httpx.AsyncClient` so the
flow is fully deterministic — no network, no flakes. Mirrors the
shape of real Notion / Linear responses captured during the design
spike.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest

from vyuu_gateway.upstream.oauth_dcr import (
    DcrError,
    _extract_resource_metadata_url,
    discover_and_register,
)


class _StubMcpAndAsServer:
    """One ASGI app that pretends to be both the MCP server and the
    OAuth AS at the same hostname. The DCR flow hits four URLs in
    sequence; this stub serves all four off path matching."""

    def __init__(
        self,
        *,
        host: str = "fake-mcp.example",
        omit_resource_metadata_hint: bool = False,
        registration_status: int = 201,
        omit_registration_endpoint: bool = False,
        public_client: bool = False,
        require_iat: str | None = None,
        cimd_supported: bool = False,
    ) -> None:
        self._host = host
        self._omit_resource_metadata_hint = omit_resource_metadata_hint
        self._registration_status = registration_status
        self._omit_registration_endpoint = omit_registration_endpoint
        self._public_client = public_client
        # MCP-2 P3 — RFC 8414 key by which an AS advertises that it will
        # accept a client_id metadata document URL instead of a
        # registration.
        self._cimd_supported = cimd_supported
        # U11 — when set, registration POSTs without
        # `Authorization: Bearer <require_iat>` are rejected with 401
        # to mimic enterprise IdPs that gate /register behind an IAT.
        self._require_iat = require_iat
        self.calls: list[str] = []
        self.last_registration_body: dict[str, Any] | None = None
        self.last_registration_auth_header: str | None = None

    async def __call__(
        self, scope: dict[str, Any], receive: Any, send: Any
    ) -> None:
        if scope["type"] != "http":
            return
        path = scope["path"]
        method = scope["method"]
        self.calls.append(f"{method} {path}")

        # Drain the request body
        body = b""
        more = True
        while more:
            event = await receive()
            body += event.get("body", b"")
            more = event.get("more_body", False)

        # 1. MCP probe → 401 with WWW-Authenticate hint
        if path == "/mcp" and method == "POST":
            headers = [(b"content-type", b"application/json")]
            if not self._omit_resource_metadata_hint:
                headers.append((
                    b"www-authenticate",
                    f'Bearer realm="OAuth", resource_metadata="https://{self._host}/.well-known/oauth-protected-resource"'.encode(),
                ))
            await send({"type": "http.response.start", "status": 401, "headers": headers})
            await send({
                "type": "http.response.body",
                "body": b'{"error":"invalid_token"}',
            })
            return

        # 2. Resource metadata (RFC 9728)
        if path == "/.well-known/oauth-protected-resource" and method == "GET":
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({
                "type": "http.response.body",
                "body": json.dumps({
                    "resource": f"https://{self._host}",
                    "authorization_servers": [f"https://{self._host}"],
                }).encode(),
            })
            return

        # 3. AS metadata (RFC 8414)
        if path == "/.well-known/oauth-authorization-server" and method == "GET":
            doc: dict[str, Any] = {
                "issuer": f"https://{self._host}",
                "authorization_endpoint": f"https://{self._host}/authorize",
                "token_endpoint": f"https://{self._host}/token",
                "code_challenge_methods_supported": ["plain", "S256"],
            }
            if not self._omit_registration_endpoint:
                doc["registration_endpoint"] = f"https://{self._host}/register"
            if self._cimd_supported:
                doc["client_id_metadata_document_supported"] = True
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({
                "type": "http.response.body",
                "body": json.dumps(doc).encode(),
            })
            return

        # 4. DCR registration (RFC 7591)
        if path == "/register" and method == "POST":
            # Capture the inbound Authorization header so the IAT test
            # can assert it was attached. ASGI scope headers are
            # bytes; lowercase them for the lookup.
            auth_header_value = None
            for k, v in scope.get("headers", []):
                if k.decode("latin-1").lower() == "authorization":
                    auth_header_value = v.decode("latin-1")
                    break
            self.last_registration_auth_header = auth_header_value
            # Enforce IAT requirement when configured: the AS only
            # honors registration POSTs that carry a matching Bearer.
            if self._require_iat is not None:
                expected = f"Bearer {self._require_iat}"
                if auth_header_value != expected:
                    await send({
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [(b"content-type", b"application/json")],
                    })
                    await send({
                        "type": "http.response.body",
                        "body": b'{"error":"invalid_token"}',
                    })
                    return
            try:
                self.last_registration_body = json.loads(body)
            except ValueError:
                self.last_registration_body = None
            response_body: dict[str, Any] = {
                "client_id": "stub-client-id-XYZ",
                "client_id_issued_at": 1700000000,
            }
            if not self._public_client:
                response_body["client_secret"] = "stub-client-secret"
                response_body["client_secret_expires_at"] = 0
            await send({
                "type": "http.response.start",
                "status": self._registration_status,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({
                "type": "http.response.body",
                "body": json.dumps(response_body).encode(),
            })
            return

        # Unknown path
        await send({
            "type": "http.response.start",
            "status": 404,
            "headers": [(b"content-type", b"text/plain")],
        })
        await send({"type": "http.response.body", "body": b"not found"})


def _patched_client(stub: _StubMcpAndAsServer) -> httpx.AsyncClient:
    # mypy: stub IS callable (`__call__` matches the ASGI3 protocol)
    # but doesn't structurally inherit from the typed ASGIApp alias.
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=stub),  # type: ignore[arg-type]
        base_url="https://fake-mcp.example",
    )


# ----------------------------------------------------------------------
# Header parsing
# ----------------------------------------------------------------------


def test_extract_resource_metadata_url_from_quoted_value() -> None:
    h = (
        'Bearer realm="OAuth", '
        'resource_metadata="https://x.example/.well-known/oauth-protected-resource", '
        'error="invalid_token"'
    )
    assert _extract_resource_metadata_url(
        h, upstream_url="https://x.example/mcp"
    ) == "https://x.example/.well-known/oauth-protected-resource"


def test_extract_resource_metadata_url_falls_back_to_well_known() -> None:
    """No hint in WWW-Authenticate → use the conventional well-known
    path on the upstream's origin."""
    assert _extract_resource_metadata_url(
        "", upstream_url="https://x.example/mcp"
    ) == "https://x.example/.well-known/oauth-protected-resource"


# ----------------------------------------------------------------------
# Full DCR flow
# ----------------------------------------------------------------------


def test_discover_and_register_happy_path_confidential_client() -> None:
    """Notion-shape: spec-compliant server with WWW-Authenticate hint,
    full AS metadata, registration returns confidential client."""
    stub = _StubMcpAndAsServer()

    async def run() -> None:
        async with _patched_client(stub) as http:
            result = await discover_and_register(
                upstream_url="https://fake-mcp.example/mcp",
                redirect_uri="https://gw.example/callback",
                scopes=["read", "write"],
                http=http,
            )

        assert result.client_id == "stub-client-id-XYZ"
        assert result.client_secret == "stub-client-secret"
        assert result.authorization_endpoint == "https://fake-mcp.example/authorize"
        assert result.token_endpoint == "https://fake-mcp.example/token"
        assert result.registration_endpoint == "https://fake-mcp.example/register"
        # All four steps were hit in order.
        assert stub.calls == [
            "POST /mcp",
            "GET /.well-known/oauth-protected-resource",
            "GET /.well-known/oauth-authorization-server",
            "POST /register",
        ]
        # Registration sent the right RFC 7591 payload.
        assert stub.last_registration_body is not None
        assert stub.last_registration_body["redirect_uris"] == [
            "https://gw.example/callback"
        ]
        assert stub.last_registration_body["scope"] == "read write"
        assert "authorization_code" in stub.last_registration_body["grant_types"]
        assert "refresh_token" in stub.last_registration_body["grant_types"]

    asyncio.run(run())


def test_discover_and_register_public_client_no_secret() -> None:
    """Some PKCE-only AS implementations return no client_secret. The
    DcrResult propagates `client_secret=None` rather than rejecting."""
    stub = _StubMcpAndAsServer(public_client=True)

    async def run() -> None:
        async with _patched_client(stub) as http:
            result = await discover_and_register(
                upstream_url="https://fake-mcp.example/mcp",
                redirect_uri="https://gw.example/callback",
                http=http,
            )
        assert result.client_id == "stub-client-id-XYZ"
        assert result.client_secret is None

    asyncio.run(run())


def test_discover_and_register_falls_back_when_hint_missing() -> None:
    """Server returns 401 without `resource_metadata=...` in WWW-
    Authenticate. We fall back to `/.well-known/oauth-protected-resource`
    on the same origin."""
    stub = _StubMcpAndAsServer(omit_resource_metadata_hint=True)

    async def run() -> None:
        async with _patched_client(stub) as http:
            result = await discover_and_register(
                upstream_url="https://fake-mcp.example/mcp",
                redirect_uri="https://gw.example/callback",
                http=http,
            )
        assert result.client_id == "stub-client-id-XYZ"

    asyncio.run(run())


def test_discover_and_register_400_when_no_registration_endpoint() -> None:
    """Vendor exposes AS metadata but no `registration_endpoint` —
    DCR is not supported. Surfaces a clear error so operators know to
    fall back to static-creds."""
    stub = _StubMcpAndAsServer(omit_registration_endpoint=True)

    async def run() -> None:
        async with _patched_client(stub) as http:
            with pytest.raises(DcrError) as exc_info:
                await discover_and_register(
                    upstream_url="https://fake-mcp.example/mcp",
                    redirect_uri="https://gw.example/callback",
                    http=http,
                )
        assert exc_info.value.step == "as_metadata"
        assert "registration_endpoint" in exc_info.value.detail

    asyncio.run(run())


def test_discover_and_register_rejects_non_https_endpoints() -> None:
    """Defense in depth: refuse to follow plaintext discovery URLs
    even if a (compromised) MCP server points at them."""

    class _PlaintextStub(_StubMcpAndAsServer):
        async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
            if scope["type"] == "http" and scope["path"] == "/mcp":
                # Drain
                more = True
                while more:
                    e = await receive()
                    more = e.get("more_body", False)
                await send({
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (
                            b"www-authenticate",
                            b'Bearer realm="OAuth", resource_metadata="http://insecure.example/meta"',
                        ),
                    ],
                })
                await send({"type": "http.response.body", "body": b"{}"})
                return
            await super().__call__(scope, receive, send)

    stub = _PlaintextStub()

    async def run() -> None:
        async with _patched_client(stub) as http:
            with pytest.raises(DcrError) as exc_info:
                await discover_and_register(
                    upstream_url="https://fake-mcp.example/mcp",
                    redirect_uri="https://gw.example/callback",
                    http=http,
                )
        assert exc_info.value.step == "probe"
        assert "HTTPS" in exc_info.value.detail

    asyncio.run(run())


def test_discover_and_register_surfaces_iat_required_hint() -> None:
    """Some enterprise IdPs (Okta, certain Auth0 tenants) require an
    Initial Access Token at /register — they return 401/403. We
    surface the failure with a hint so operators know which path to
    take instead."""
    stub = _StubMcpAndAsServer(registration_status=401)

    async def run() -> None:
        async with _patched_client(stub) as http:
            with pytest.raises(DcrError) as exc_info:
                await discover_and_register(
                    upstream_url="https://fake-mcp.example/mcp",
                    redirect_uri="https://gw.example/callback",
                    http=http,
                )
        assert exc_info.value.step == "registration"
        assert "Initial Access Token" in exc_info.value.detail

    asyncio.run(run())


# ---------------------------------------------------------------------------
# U11 — Initial Access Token (RFC 7591 §3) for enterprise IdPs
# ---------------------------------------------------------------------------


def test_discover_and_register_attaches_iat_bearer_when_provided() -> None:
    """U11 — when the operator configured an IAT (for an Okta /
    Auth0 tenant that gates /register), the DCR client sends
    `Authorization: Bearer <iat>` on the registration POST. Public
    SaaS DCR servers (Notion etc.) ignore the header; gated IdPs
    require it."""
    stub = _StubMcpAndAsServer(require_iat="enterprise-iat-secret-XYZ")

    async def run() -> None:
        async with _patched_client(stub) as http:
            result = await discover_and_register(
                upstream_url="https://fake-mcp.example/mcp",
                redirect_uri="https://gw.example/callback",
                initial_access_token="enterprise-iat-secret-XYZ",
                http=http,
            )
        assert result.client_id == "stub-client-id-XYZ"
        assert stub.last_registration_auth_header == (
            "Bearer enterprise-iat-secret-XYZ"
        )

    asyncio.run(run())


def test_discover_and_register_without_iat_fails_against_gated_as() -> None:
    """When the AS requires an IAT and the caller didn't provide
    one, registration must fail (the stub returns 401). Confirms
    the IAT-required path is the right code-flow trigger; the
    pre-existing `surfaces_iat_required_hint` test covers the
    operator-facing error message."""
    stub = _StubMcpAndAsServer(require_iat="needed-iat")

    async def run() -> None:
        async with _patched_client(stub) as http:
            with pytest.raises(DcrError) as exc_info:
                await discover_and_register(
                    upstream_url="https://fake-mcp.example/mcp",
                    redirect_uri="https://gw.example/callback",
                    http=http,
                )
        assert exc_info.value.step == "registration"
        assert stub.last_registration_auth_header is None

    asyncio.run(run())


def test_discover_and_register_no_iat_sends_no_authorization_header() -> None:
    """Public SaaS DCR servers (Notion, Linear, etc.) never get an
    Authorization header from us — confirms the IAT branch is
    opt-in, not always-on."""
    stub = _StubMcpAndAsServer()

    async def run() -> None:
        async with _patched_client(stub) as http:
            await discover_and_register(
                upstream_url="https://fake-mcp.example/mcp",
                redirect_uri="https://gw.example/callback",
                http=http,
            )
        assert stub.last_registration_auth_header is None

    asyncio.run(run())


# ----------------------------------------------------------------------
# MCP-2 P3 · CIMD instead of registration
# ----------------------------------------------------------------------

_OUR_CIMD = "https://gateway.example/.well-known/oauth-client"


def _run(stub: _StubMcpAndAsServer, **kwargs: Any) -> Any:
    async def go() -> Any:
        async with _patched_client(stub) as http:
            return await discover_and_register(
                upstream_url="https://fake-mcp.example/mcp",
                redirect_uri="https://gateway.example/cb",
                http=http,
                **kwargs,
            )

    return asyncio.run(go())


def test_cimd_is_used_and_nothing_is_registered() -> None:
    """The point of CIMD: no credential is created on either side. If a
    registration POST happens anyway we have gained nothing and still
    own a client_secret somebody must rotate."""

    stub = _StubMcpAndAsServer(cimd_supported=True)
    result = _run(stub, cimd_client_id=_OUR_CIMD)

    assert result.auth_mechanism == "cimd"
    assert result.client_id == _OUR_CIMD
    # No secret exists under CIMD — control of the URL is the proof.
    assert result.client_secret is None
    assert result.registration_endpoint is None
    assert result.authorization_endpoint == "https://fake-mcp.example/authorize"
    assert result.token_endpoint == "https://fake-mcp.example/token"
    assert not any(call.startswith("POST /register") for call in stub.calls)


def test_cimd_works_when_the_as_offers_no_registration_endpoint() -> None:
    """An AS that supports CIMD has no reason to run a registration
    endpoint. Requiring one would reject exactly the servers CIMD is
    for — and before P3 this combination raised at as_metadata."""

    stub = _StubMcpAndAsServer(cimd_supported=True, omit_registration_endpoint=True)
    result = _run(stub, cimd_client_id=_OUR_CIMD)
    assert result.auth_mechanism == "cimd"


def test_an_as_without_cimd_support_still_registers() -> None:
    stub = _StubMcpAndAsServer(cimd_supported=False)
    result = _run(stub, cimd_client_id=_OUR_CIMD)
    assert result.auth_mechanism == "dcr"
    assert result.client_id == "stub-client-id-XYZ"
    assert any(call.startswith("POST /register") for call in stub.calls)
    # The reason is carried on success so an operator debugging "why did
    # this one register and that one not?" has an answer.
    assert "does not advertise" in result.mechanism_reason


def test_not_offering_a_document_keeps_the_old_path_exactly() -> None:
    """Negative control: the AS advertises CIMD, but a gateway that
    cannot serve a document (no https base URL) must still register."""

    stub = _StubMcpAndAsServer(cimd_supported=True)
    result = _run(stub, cimd_client_id=None)
    assert result.auth_mechanism == "dcr"
    assert any(call.startswith("POST /register") for call in stub.calls)


def test_an_http_client_id_is_refused_and_falls_back() -> None:
    """CIMD's trust model is "whoever controls this URL is the client".
    Over http that is whoever controls the network."""

    stub = _StubMcpAndAsServer(cimd_supported=True)
    result = _run(stub, cimd_client_id="http://gateway.example/.well-known/oauth-client")
    assert result.auth_mechanism == "dcr"
    assert "https" in result.mechanism_reason
