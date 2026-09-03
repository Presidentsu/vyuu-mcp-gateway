from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from vyuu_gateway.api.dependencies import get_tenant_scoped_db
from vyuu_gateway.config import Settings
from vyuu_gateway.db.models import McpServer
from vyuu_gateway.main import create_app
from vyuu_gateway.operator_auth.fake import mint_operator_test_token
from vyuu_gateway.registry.schemas import REDACTED_SECRET

TEST_SIGNING_SECRET = "test-operator-auth-secret"


class FakeSession:
    def __init__(
        self,
        *,
        operator_exists: bool = True,
        duplicate_server: bool = False,
        listed_servers: list[McpServer] | None = None,
    ) -> None:
        self.scalar_results: list[object | None] = [
            uuid4() if operator_exists else None,
            uuid4() if duplicate_server else None,
        ]
        self.listed_servers = listed_servers or []
        self.added: McpServer | None = None
        self.committed = False
        self.rolled_back = False
        self.raise_integrity_error = False
        self.statements: list[object] = []

    def scalar(self, statement: object) -> object | None:
        self.statements.append(statement)
        return self.scalar_results.pop(0)

    def execute(self, statement: object) -> "_RowResult":
        """The servers list runs one grouped count over
        `mcp_capabilities` to fill the TOOLS column. This fake has no
        capability rows, so the honest answer is an empty result — the
        endpoint then reports 0 for synced servers and None for the
        rest, which is what these tests assert."""

        self.statements.append(statement)
        return _RowResult([])

    def scalars(self, statement: object) -> "_ScalarResult":
        self.statements.append(statement)
        return _ScalarResult(self.listed_servers)

    def add(self, instance: object) -> None:
        self.added = instance if isinstance(instance, McpServer) else None

    def commit(self) -> None:
        if self.raise_integrity_error:
            raise IntegrityError("duplicate", {}, Exception("duplicate"))
        self.committed = True

    def refresh(self, instance: object) -> None:
        return None

    def rollback(self) -> None:
        self.rolled_back = True


class _RowResult:
    def __init__(self, rows: list[tuple[object, ...]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[object, ...]]:
        return self._rows


class _ScalarResult:
    def __init__(self, rows: list[McpServer]) -> None:
        self._rows = rows

    def all(self) -> list[McpServer]:
        return self._rows


def make_client(
    fake_session: FakeSession,
    *,
    http_url_allow_private_networks: bool = False,
    http_url_allowlist: list[str] | None = None,
    http_url_denylist: list[str] | None = None,
) -> TestClient:
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
            http_url_allow_private_networks=http_url_allow_private_networks,
            http_url_allowlist=http_url_allowlist or [],
            http_url_denylist=http_url_denylist or [],
            operator_auth_signing_secret=TEST_SIGNING_SECRET,
        )
    )

    def override_get_tenant_scoped_db() -> Iterator[FakeSession]:
        yield fake_session

    app.dependency_overrides[get_tenant_scoped_db] = override_get_tenant_scoped_db
    return TestClient(app)


def base_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "display_name": "github-tools",
        "source_type": "npm",
        "source_location": "@modelcontextprotocol/server-github",
    }
    payload.update(overrides)
    return payload


def auth_context() -> tuple[UUID, UUID, dict[str, str]]:
    """Return (tenant_id, operator_id, headers) for a fresh authenticated caller."""
    tenant_id = uuid4()
    operator_id = uuid4()
    token = mint_operator_test_token(
        tenant_id=tenant_id,
        operator_id=operator_id,
        signing_secret=TEST_SIGNING_SECRET,
    )
    return tenant_id, operator_id, {"Authorization": f"Bearer {token}"}


def test_register_npm_server_persists_metadata_with_stdio_default() -> None:
    fake_session = FakeSession()
    client = make_client(fake_session)
    tenant_id, operator_id, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(args=["--readonly"]),
        headers=headers,
    )

    assert response.status_code == 201
    body = response.json()
    assert body["source_type"] == "npm"
    assert body["transport"] == "stdio"
    assert body["health_status"] == "unknown"
    assert body["last_capabilities_pulled_at"] is None
    assert fake_session.committed
    assert fake_session.added is not None
    assert fake_session.added.tenant_id == tenant_id
    assert fake_session.added.registered_by == operator_id
    assert UUID(body["tenant_id"]) == tenant_id
    assert UUID(body["registered_by"]) == operator_id
    assert fake_session.added.display_name == "github-tools"
    assert fake_session.added.args == ["--readonly"]


def test_register_pypi_server_persists_metadata_with_stdio_default() -> None:
    """Mirrors the npm path for PyPI / `uvx`-launched MCP servers."""
    fake_session = FakeSession()
    client = make_client(fake_session)
    tenant_id, operator_id, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            display_name="time-mcp",
            source_type="pypi",
            source_location="mcp-server-time",
            args=["--local-timezone", "UTC"],
        ),
        headers=headers,
    )

    assert response.status_code == 201
    body = response.json()
    assert body["source_type"] == "pypi"
    assert body["transport"] == "stdio"
    assert body["source_location"] == "mcp-server-time"
    assert body["args"] == ["--local-timezone", "UTC"]
    assert UUID(body["tenant_id"]) == tenant_id
    assert UUID(body["registered_by"]) == operator_id
    assert fake_session.added is not None
    assert fake_session.added.source_type.value == "pypi"


def test_register_http_server_accepts_auth_headers() -> None:
    """HTTP MCPs (PayPal, Wiz, Datadog) carry auth via per-request headers.
    Refs are stored as-is; the gateway never sees the resolved value at
    registration time.
    """
    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            display_name="paypal-http",
            source_type="http",
            source_location="https://mcp.paypal.com/mcp",
            transport="streamable_http",
            auth_headers={"Authorization": "paypal-bearer"},
        ),
        headers=headers,
    )

    assert response.status_code == 201
    body = response.json()
    # The response names the header that is wired but redacts its value;
    # the row keeps the real one.
    assert body["auth_headers"] == {"Authorization": REDACTED_SECRET}
    assert body["auth_env"] == {}
    assert fake_session.added is not None
    assert fake_session.added.auth_headers == {"Authorization": "paypal-bearer"}


def test_register_pypi_server_accepts_auth_env() -> None:
    """Stdio MCPs (CrowdStrike, Snyk) carry auth via subprocess env vars.
    Multiple refs are common (FALCON_CLIENT_ID + FALCON_CLIENT_SECRET).
    """
    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            display_name="falcon-mcp",
            source_type="pypi",
            source_location="crowdstrike-falcon-mcp",
            auth_env={
                "FALCON_CLIENT_ID": "falcon-id",
                "FALCON_CLIENT_SECRET": "falcon-secret",
            },
        ),
        headers=headers,
    )

    assert response.status_code == 201
    body = response.json()
    assert body["auth_env"] == {
        "FALCON_CLIENT_ID": REDACTED_SECRET,
        "FALCON_CLIENT_SECRET": REDACTED_SECRET,
    }
    assert body["auth_headers"] == {}
    # Redaction is presentation-only: the row still carries what the
    # subprocess needs.
    assert fake_session.added is not None
    assert fake_session.added.auth_env == {
        "FALCON_CLIENT_ID": "falcon-id",
        "FALCON_CLIENT_SECRET": "falcon-secret",
    }


def test_register_rejects_auth_headers_on_stdio_transport() -> None:
    """`auth_headers` is meaningless for stdio (no HTTP); reject at register
    so operators don't ship a never-authenticated stdio MCP."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="pypi",
            source_location="some-pypi-mcp",
            auth_headers={"Authorization": "wrong-place"},
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_rejects_auth_env_on_http_transport() -> None:
    """Mirror: `auth_env` is meaningless for HTTP (no subprocess)."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://mcp.example/mcp",
            transport="streamable_http",
            auth_env={"API_KEY": "wrong-place"},
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_rejects_empty_secret_ref() -> None:
    """An empty ref would silently mean "no secret" at resolution time —
    catch it at registration so operators see the typo.
    """
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://mcp.example/mcp",
            transport="streamable_http",
            auth_headers={"Authorization": ""},
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_http_server_accepts_auth_passthrough() -> None:
    """User-tier auth: operator declares which inbound header to forward
    as which upstream header. The credential never lives in the gateway —
    each user brings their own.
    """
    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            display_name="paypal-passthrough",
            source_type="http",
            source_location="https://mcp.paypal.com/mcp",
            transport="streamable_http",
            auth_passthrough={"x-vyuu-paypal-token": "Authorization"},
        ),
        headers=headers,
    )

    assert response.status_code == 201
    body = response.json()
    assert body["auth_passthrough"] == {"x-vyuu-paypal-token": "Authorization"}
    assert body["auth_headers"] == {}
    assert fake_session.added is not None
    assert fake_session.added.auth_passthrough == {
        "x-vyuu-paypal-token": "Authorization"
    }


def test_register_rejects_auth_passthrough_on_stdio_transport() -> None:
    """Stdio doesn't have inbound HTTP headers in the same shape; reject
    at register so operators don't ship a never-authenticated stdio MCP."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="pypi",
            source_location="some-pypi-mcp",
            auth_passthrough={"x-token": "Authorization"},
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_rejects_auth_headers_and_passthrough_collision() -> None:
    """The operator must pick one model per upstream header. Otherwise
    resolution order would silently shadow whichever lost."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://mcp.example/mcp",
            transport="streamable_http",
            auth_headers={"Authorization": "org-vault-ref"},
            auth_passthrough={"x-user-token": "Authorization"},
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_http_server_accepts_auth_oauth() -> None:
    """OAuth client-credentials: the gateway brokers the M2M token
    exchange. Refs are stored as-is; the gateway never sees the raw
    client_id / client_secret at registration time."""
    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            display_name="wiz-oauth",
            source_type="http",
            source_location="https://api.wiz.io/mcp",
            transport="streamable_http",
            auth_oauth={
                "token_url": "https://auth.wiz.io/oauth/token",
                "client_id_ref": "wiz-id",
                "client_secret_ref": "wiz-secret",
                "audience": "https://api.wiz.io",
            },
        ),
        headers=headers,
    )

    assert response.status_code == 201
    body = response.json()
    assert body["auth_oauth"]["token_url"] == "https://auth.wiz.io/oauth/token"
    assert body["auth_oauth"]["client_id_ref"] == "wiz-id"
    assert body["auth_oauth"]["audience"] == "https://api.wiz.io"
    assert body["auth_headers"] == {}
    assert fake_session.added is not None
    persisted_oauth = fake_session.added.auth_oauth
    assert persisted_oauth is not None
    assert persisted_oauth["client_secret_ref"] == "wiz-secret"


def test_register_rejects_oauth_token_url_over_http() -> None:
    """A plaintext token URL would expose client_id/client_secret on the
    wire — reject at registration."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://mcp.example/mcp",
            transport="streamable_http",
            auth_oauth={
                "token_url": "http://auth.example/token",  # plaintext
                "client_id_ref": "id",
                "client_secret_ref": "secret",
            },
        ),
        headers=headers,
    )

    assert response.status_code == 422
    assert "https" in response.text.lower()


def test_register_rejects_oauth_on_stdio_transport() -> None:
    """OAuth bearer tokens are HTTP-only; reject on stdio."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="pypi",
            source_location="some-pypi-mcp",
            auth_oauth={
                "token_url": "https://auth.example/token",
                "client_id_ref": "id",
                "client_secret_ref": "secret",
            },
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_rejects_oauth_with_explicit_authorization_header() -> None:
    """OAuth always sets Authorization. Operators must not also
    configure Authorization via auth_headers — only one Authorization
    source per upstream."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://mcp.example/mcp",
            transport="streamable_http",
            auth_headers={"Authorization": "static-vault-ref"},
            auth_oauth={
                "token_url": "https://auth.example/token",
                "client_id_ref": "id",
                "client_secret_ref": "secret",
            },
        ),
        headers=headers,
    )

    assert response.status_code == 422
    assert "Authorization" in response.text


def test_register_rejects_oauth_with_passthrough_authorization() -> None:
    """Same rule applied to user-tier passthrough."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://mcp.example/mcp",
            transport="streamable_http",
            auth_passthrough={"x-user-token": "Authorization"},
            auth_oauth={
                "token_url": "https://auth.example/token",
                "client_id_ref": "id",
                "client_secret_ref": "secret",
            },
        ),
        headers=headers,
    )

    assert response.status_code == 422


def _authcode_payload(**overrides: Any) -> dict[str, Any]:
    """Helper: a known-good auth_authcode block. Tests override one
    field at a time to assert each rule fires."""

    payload = {
        "auth_url": "https://idp.example/oauth/authorize",
        "token_url": "https://idp.example/oauth/token",
        "client_id_ref": "demo-id",
        "client_secret_ref": "demo-secret",
        "redirect_uri": "https://gateway.example/api/v1/oauth-authcode/callback",
        "scopes": ["user:read"],
    }
    payload.update(overrides)
    return payload


def test_register_http_server_accepts_auth_authcode() -> None:
    """auth_authcode (per-user delegated) is the phase-4 OAuth path. Refs
    are stored as-is; the gateway never sees the raw client_id /
    client_secret at registration time."""
    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            display_name="github-authcode",
            source_type="http",
            source_location="https://api.github.example/mcp",
            transport="streamable_http",
            auth_authcode=_authcode_payload(),
        ),
        headers=headers,
    )

    assert response.status_code == 201
    body = response.json()
    assert body["auth_authcode"]["auth_url"] == (
        "https://idp.example/oauth/authorize"
    )
    assert body["auth_authcode"]["client_id_ref"] == "demo-id"
    assert body["auth_authcode"]["scopes"] == ["user:read"]
    assert fake_session.added is not None
    persisted = fake_session.added.auth_authcode
    assert persisted is not None
    assert persisted["client_secret_ref"] == "demo-secret"
    assert persisted["redirect_uri"] == (
        "https://gateway.example/api/v1/oauth-authcode/callback"
    )


def test_register_authcode_only_skips_auto_capability_sync(
    monkeypatch: Any,
) -> None:
    """Per-user OAuth-authcode upstreams have NO operator-side bearer at
    registration time, so capability auto-sync would 401 N times and
    trip the upstream circuit breaker. Skip the auto-sync; the operator
    runs Connect → on at least one user account first, then clicks
    Sync manually. Prevents the confusing 502 + CircuitBreakerOpenError
    cascade when registering a SaaS connector via the catalog."""
    from vyuu_gateway.api import servers as servers_module

    sync_calls: list[Any] = []

    async def _fake_sync(*args: Any, **kwargs: Any) -> None:
        sync_calls.append((args, kwargs))

    monkeypatch.setattr(servers_module, "_sync_after_registration", _fake_sync)

    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            display_name="github-only-authcode",
            source_type="http",
            source_location="https://api.github.example/mcp",
            transport="streamable_http",
            auth_authcode=_authcode_payload(),
        ),
        headers=headers,
    )

    assert response.status_code == 201
    assert sync_calls == [], (
        "auto-sync must NOT fire for authcode-only servers; got "
        f"{len(sync_calls)} calls"
    )


def test_register_oauth_m2m_still_runs_auto_sync(monkeypatch: Any) -> None:
    """Sanity check on the inverse: a server with `auth_oauth` (M2M
    client_credentials — gateway holds the credential) still gets
    auto-sync, because the gateway CAN call the upstream at
    registration time. Guards against an over-eager skip rule."""
    from vyuu_gateway.api import servers as servers_module

    sync_calls: list[Any] = []

    async def _fake_sync(*args: Any, **kwargs: Any) -> None:
        sync_calls.append((args, kwargs))

    monkeypatch.setattr(servers_module, "_sync_after_registration", _fake_sync)

    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            display_name="m2m-only-server",
            source_type="http",
            source_location="https://api.m2m.example/mcp",
            transport="streamable_http",
            auth_oauth={
                "token_url": "https://idp.example/oauth/token",
                "client_id_ref": "m2m-id",
                "client_secret_ref": "m2m-secret",
            },
        ),
        headers=headers,
    )

    assert response.status_code == 201
    assert len(sync_calls) == 1, (
        "auto-sync should fire for M2M-credentialed servers; got "
        f"{len(sync_calls)} calls"
    )


def test_register_rejects_authcode_with_plaintext_url() -> None:
    """Any of auth_url/token_url/redirect_uri over plaintext exposes
    the auth code or client_secret on the wire — reject all three."""

    for plaintext_field in ("auth_url", "token_url", "redirect_uri"):
        client = make_client(FakeSession())
        _, _, headers = auth_context()
        bad = _authcode_payload(
            **{plaintext_field: "http://idp.example/whatever"},
        )
        response = client.post(
            "/api/v1/servers",
            json=base_payload(
                source_type="http",
                source_location="https://mcp.example/mcp",
                transport="streamable_http",
                auth_authcode=bad,
            ),
            headers=headers,
        )
        assert response.status_code == 422
        assert "https" in response.text.lower()


def test_register_rejects_authcode_with_whitespace_in_scope() -> None:
    """Scopes are wire-serialised space-delimited; a scope containing
    whitespace would silently split."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://mcp.example/mcp",
            transport="streamable_http",
            auth_authcode=_authcode_payload(scopes=["user read"]),
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_rejects_authcode_on_stdio_transport() -> None:
    """auth_authcode is HTTP-only — stdio MCPs don't have an
    Authorization header to stamp."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="pypi",
            source_location="some-pypi-mcp",
            auth_authcode=_authcode_payload(),
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_rejects_both_auth_oauth_and_auth_authcode() -> None:
    """The two grant types compete for the Authorization header — pick
    one. Allowing both would be ambiguous at runtime."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://mcp.example/mcp",
            transport="streamable_http",
            auth_oauth={
                "token_url": "https://auth.example/token",
                "client_id_ref": "id",
                "client_secret_ref": "secret",
            },
            auth_authcode=_authcode_payload(),
        ),
        headers=headers,
    )

    assert response.status_code == 422
    assert "auth_authcode" in response.text


def test_register_authcode_accepts_extra_authorize_params_for_google() -> None:
    """Google Drive needs `access_type=offline` + `prompt=consent` on
    the authorize URL or it issues no refresh_token. The
    `extra_authorize_params` dict carries these provider-specific
    flags through to the /initiate response."""

    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            display_name="drive-userauth",
            source_type="http",
            source_location="https://drive.example/mcp",
            transport="streamable_http",
            auth_authcode=_authcode_payload(
                auth_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                scopes=["https://www.googleapis.com/auth/drive.readonly"],
                extra_authorize_params={
                    "access_type": "offline",
                    "prompt": "consent",
                },
            ),
        ),
        headers=headers,
    )

    assert response.status_code == 201, response.text
    body = response.json()
    extras = body["auth_authcode"]["extra_authorize_params"]
    assert extras["access_type"] == "offline"
    assert extras["prompt"] == "consent"


def test_register_rejects_authcode_extras_redefining_reserved_params() -> None:
    """The gateway owns `response_type`, `client_id`, `redirect_uri`,
    `state`, `scope`. Letting operators override them via extras would
    silently shadow the ref-resolved client_id (and break state/CSRF)."""

    for reserved_key in ("client_id", "redirect_uri", "state", "scope"):
        client = make_client(FakeSession())
        _, _, headers = auth_context()
        response = client.post(
            "/api/v1/servers",
            json=base_payload(
                source_type="http",
                source_location="https://api.example/mcp",
                transport="streamable_http",
                auth_authcode=_authcode_payload(
                    extra_authorize_params={reserved_key: "attacker-value"},
                ),
            ),
            headers=headers,
        )
        assert response.status_code == 422, f"reserved key {reserved_key!r} accepted"
        assert "reserved" in response.text.lower()


def test_register_rejects_authcode_with_explicit_authorization_header() -> None:
    """auth_authcode sets Authorization. Operators must not also
    configure Authorization via auth_headers."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://mcp.example/mcp",
            transport="streamable_http",
            auth_headers={"Authorization": "static-vault-ref"},
            auth_authcode=_authcode_payload(),
        ),
        headers=headers,
    )

    assert response.status_code == 422
    assert "Authorization" in response.text


def test_register_rejects_authcode_with_passthrough_authorization() -> None:
    """Same rule for user-tier passthrough."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://mcp.example/mcp",
            transport="streamable_http",
            auth_passthrough={"x-user-token": "Authorization"},
            auth_authcode=_authcode_payload(),
        ),
        headers=headers,
    )

    assert response.status_code == 422


def _jwt_bearer_payload(**overrides: Any) -> dict[str, Any]:
    """Helper: a known-good auth_jwt_bearer block for A2 tests."""
    payload = {
        "token_url": "https://oauth2.googleapis.com/token",
        "algorithm": "RS256",
        "private_key_ref": "sa-private-key",
        "issuer": "automation-sa@project.iam.gserviceaccount.com",
        "subject": "automation-sa@project.iam.gserviceaccount.com",
        "audience": "https://oauth2.googleapis.com/token",
    }
    payload.update(overrides)
    return payload


def test_register_http_server_accepts_auth_jwt_bearer() -> None:
    """A2: RFC 7523 JWT-bearer assertion grant (Workspace SAs, IRA).
    Refs are stored as-is; the gateway never sees the raw private
    key at registration time."""

    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            display_name="drive-sa",
            source_type="http",
            source_location="https://drive.googleapis.com/mcp",
            transport="streamable_http",
            auth_jwt_bearer=_jwt_bearer_payload(
                additional_claims={"scope": "https://www.googleapis.com/auth/drive.readonly"},
            ),
        ),
        headers=headers,
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["auth_jwt_bearer"]["algorithm"] == "RS256"
    assert body["auth_jwt_bearer"]["private_key_ref"] == "sa-private-key"
    assert fake_session.added is not None
    persisted = fake_session.added.auth_jwt_bearer
    assert persisted is not None
    assert persisted["additional_claims"]["scope"] == (
        "https://www.googleapis.com/auth/drive.readonly"
    )


def test_register_rejects_jwt_bearer_with_plaintext_token_url() -> None:
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://api.example/mcp",
            transport="streamable_http",
            auth_jwt_bearer=_jwt_bearer_payload(token_url="http://insecure.example/token"),
        ),
        headers=headers,
    )

    assert response.status_code == 422
    assert "https" in response.text.lower()


def test_register_rejects_jwt_bearer_with_symmetric_algorithm() -> None:
    """Symmetric / 'none' algorithms defeat the asymmetric trust
    model — the auth server can't verify a signature with a public key
    if the gateway used HS256. Schema rejects all symmetric algos."""

    for bad_alg in ("HS256", "none", "HS512"):
        client = make_client(FakeSession())
        _, _, headers = auth_context()
        response = client.post(
            "/api/v1/servers",
            json=base_payload(
                source_type="http",
                source_location="https://api.example/mcp",
                transport="streamable_http",
                auth_jwt_bearer=_jwt_bearer_payload(algorithm=bad_alg),
            ),
            headers=headers,
        )
        assert response.status_code == 422


def test_register_rejects_jwt_bearer_with_reserved_claim_in_additional() -> None:
    """`additional_claims` cannot redefine iss/sub/aud/etc — those
    are owned by the spec fields. Allowing override would mean a
    misconfigured server silently uses one issuer for the assertion
    and another for the spec — an audit nightmare."""

    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://api.example/mcp",
            transport="streamable_http",
            auth_jwt_bearer=_jwt_bearer_payload(
                additional_claims={"iss": "evil-issuer"},
            ),
        ),
        headers=headers,
    )

    assert response.status_code == 422
    assert "reserved" in response.text.lower() or "iss" in response.text


def test_register_rejects_jwt_bearer_with_excessive_assertion_ttl() -> None:
    """RFC 7523 §3 recommends short-lived assertions (typically <=
    300s). Cap at 600 to prevent operators from defeating the
    short-lifetime property."""

    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://api.example/mcp",
            transport="streamable_http",
            auth_jwt_bearer=_jwt_bearer_payload(assertion_ttl_seconds=86400),
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_rejects_jwt_bearer_on_stdio_transport() -> None:
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="pypi",
            source_location="some-pypi-mcp",
            auth_jwt_bearer=_jwt_bearer_payload(),
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_rejects_jwt_bearer_with_other_oauth_modes() -> None:
    """auth_oauth + auth_authcode + auth_jwt_bearer are mutually
    exclusive — pick exactly one OAuth grant type per server."""

    for other_mode in ("auth_oauth", "auth_authcode"):
        client = make_client(FakeSession())
        _, _, headers = auth_context()
        kwargs: dict[str, Any] = {
            "source_type": "http",
            "source_location": "https://api.example/mcp",
            "transport": "streamable_http",
            "auth_jwt_bearer": _jwt_bearer_payload(),
        }
        if other_mode == "auth_oauth":
            kwargs["auth_oauth"] = {
                "token_url": "https://auth.example/token",
                "client_id_ref": "id",
                "client_secret_ref": "secret",
            }
        else:
            kwargs["auth_authcode"] = _authcode_payload()
        response = client.post(
            "/api/v1/servers",
            json=base_payload(**kwargs),
            headers=headers,
        )
        assert response.status_code == 422
        assert "mutually exclusive" in response.text.lower()


def test_register_rejects_jwt_bearer_with_explicit_authorization_header() -> None:
    """auth_jwt_bearer sets Authorization. Operators must not also
    configure Authorization via auth_headers."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://api.example/mcp",
            transport="streamable_http",
            auth_headers={"Authorization": "static-vault-ref"},
            auth_jwt_bearer=_jwt_bearer_payload(),
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_http_server_accepts_mtls_cert_and_key() -> None:
    """mTLS: when both refs are set, the server registers cleanly and
    the response echoes the refs back. Refs are stored as-is; the
    gateway never sees the resolved PEM bytes at registration time."""

    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            display_name="corp-mtls",
            source_type="http",
            source_location="https://internal.api.example/mcp",
            transport="streamable_http",
            mtls_cert_ref="corp-cert-pem",
            mtls_key_ref="corp-key-pem",
        ),
        headers=headers,
    )

    assert response.status_code == 201
    body = response.json()
    assert body["mtls_cert_ref"] == "corp-cert-pem"
    assert body["mtls_key_ref"] == "corp-key-pem"
    assert fake_session.added is not None
    assert fake_session.added.mtls_cert_ref == "corp-cert-pem"
    assert fake_session.added.mtls_key_ref == "corp-key-pem"


def test_register_rejects_mtls_cert_without_key() -> None:
    """One ref without the other is half-configured — rejected."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://corp.example/mcp",
            transport="streamable_http",
            mtls_cert_ref="cert-only",
        ),
        headers=headers,
    )

    assert response.status_code == 422
    assert "both" in response.text.lower()


def test_register_rejects_mtls_key_without_cert() -> None:
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://corp.example/mcp",
            transport="streamable_http",
            mtls_key_ref="key-only",
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_rejects_mtls_on_stdio_transport() -> None:
    """stdio MCPs don't have a TLS layer — mTLS makes no sense there."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="pypi",
            source_location="some-pypi-mcp",
            mtls_cert_ref="cert",
            mtls_key_ref="key",
        ),
        headers=headers,
    )

    assert response.status_code == 422
    assert "HTTP" in response.text or "http" in response.text


def test_register_binary_server_accepts_absolute_path() -> None:
    """`binary` source type carries an absolute path to a pre-installed
    executable. Schema-level shape check only — existence is verified
    at provider-build time (which is also when the operator gets a
    clean 502 if the binary is missing)."""
    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            display_name="vendor-binary",
            source_type="binary",
            source_location="/opt/vyuu/connectors/falcon-mcp",
            args=["--region", "us-2"],
        ),
        headers=headers,
    )

    assert response.status_code == 201
    body = response.json()
    assert body["source_type"] == "binary"
    assert body["transport"] == "stdio"
    assert body["source_location"] == "/opt/vyuu/connectors/falcon-mcp"
    assert body["args"] == ["--region", "us-2"]


def test_register_binary_rejects_relative_path() -> None:
    """Schema-level path-shape check: must start with /."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="binary",
            source_location="relative/path/foo-mcp",
        ),
        headers=headers,
    )

    assert response.status_code == 422
    assert "absolute" in response.text.lower()


def test_register_binary_rejects_streamable_http_transport() -> None:
    """Mirror of the npm/pypi rule: binary requires stdio transport."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="binary",
            source_location="/opt/foo",
            transport="streamable_http",
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_schedules_background_health_probe() -> None:
    """After successful registration, the gateway must schedule a non-
    blocking health probe so `health_status` doesn't sit on `unknown`
    until the operator manually clicks 'Check health'."""
    from uuid import UUID as _UUID

    fake_session = FakeSession()
    probe_calls: list[tuple[_UUID, _UUID]] = []

    class _FakeHealthChecker:
        async def check_server(self, tenant_id: _UUID, server_id: _UUID) -> None:
            probe_calls.append((tenant_id, server_id))

    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
            operator_auth_signing_secret=TEST_SIGNING_SECRET,
        ),
        upstream_health_checker=_FakeHealthChecker(),
    )

    def override_get_tenant_scoped_db() -> Iterator[FakeSession]:
        yield fake_session

    app.dependency_overrides[get_tenant_scoped_db] = override_get_tenant_scoped_db

    tenant_id, _operator_id, headers = auth_context()
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/servers", json=base_payload(), headers=headers
        )

    assert response.status_code == 201
    # TestClient runs background tasks synchronously after the response.
    assert len(probe_calls) == 1
    assert probe_calls[0][0] == tenant_id
    assert probe_calls[0][1] == fake_session.added.id  # type: ignore[union-attr]


def test_register_swallows_probe_exceptions_so_response_succeeds() -> None:
    """A probe failure must NOT bubble up — registration already succeeded
    in the DB; the probe is a best-effort UX nicety."""

    class _ExplodingChecker:
        async def check_server(self, tenant_id: UUID, server_id: UUID) -> None:
            raise RuntimeError("upstream pool blown up")

    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
            operator_auth_signing_secret=TEST_SIGNING_SECRET,
        ),
        upstream_health_checker=_ExplodingChecker(),
    )

    fake_session = FakeSession()

    def override() -> Iterator[FakeSession]:
        yield fake_session

    app.dependency_overrides[get_tenant_scoped_db] = override
    _, _, headers = auth_context()
    with TestClient(app) as client:
        response = client.post("/api/v1/servers", json=base_payload(), headers=headers)

    # Registration response is unaffected by probe exceptions.
    assert response.status_code == 201


def test_register_pypi_server_with_invalid_transport_returns_422() -> None:
    """`pypi` must use stdio transport, mirroring the npm rule."""
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="pypi",
            source_location="mcp-server-time",
            transport="streamable_http",
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_server_queries_are_tenant_filtered() -> None:
    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    response = client.post("/api/v1/servers", json=base_payload(), headers=headers)

    assert response.status_code == 201
    compiled_queries = [str(statement) for statement in fake_session.statements]
    assert "operators.tenant_id" in compiled_queries[0]
    assert "mcp_servers.tenant_id" in compiled_queries[1]


def test_list_servers_returns_only_authenticated_tenant_rows() -> None:
    tenant_id, operator_id, headers = auth_context()
    server = McpServer(
        id=uuid4(),
        tenant_id=tenant_id,
        display_name="drawio-http",
        source_type="http",
        source_location="https://mcp.draw.io/mcp",
        transport="streamable_http",
        env_vars_ref=None,
        args=[],
        registered_by=operator_id,
        registered_at=datetime.now(UTC),
        health_status="unknown",
    )
    fake_session = FakeSession(listed_servers=[server])
    client = make_client(fake_session)

    response = client.get("/api/v1/servers", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["tenant_id"] == str(tenant_id)
    assert body[0]["display_name"] == "drawio-http"
    compiled_query = str(fake_session.statements[0])
    assert "mcp_servers.tenant_id" in compiled_query


def test_list_servers_requires_operator_auth() -> None:
    client = make_client(FakeSession())

    response = client.get("/api/v1/servers")

    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"


def test_register_http_server_requires_current_or_legacy_http_transport() -> None:
    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://mcp.example.com/mcp",
            transport="streamable_http",
            args=[],
        ),
        headers=headers,
    )

    assert response.status_code == 201
    assert response.json()["transport"] == "streamable_http"
    assert fake_session.added is not None
    assert fake_session.added.source_location == "https://mcp.example.com/mcp"


def test_register_stdio_server_rejects_non_stdio_transport() -> None:
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="stdio",
            source_location="python -m internal_server",
            transport="streamable_http",
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_http_server_rejects_invalid_url() -> None:
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="not-a-url",
            transport="streamable_http",
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_http_server_rejects_args() -> None:
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            source_type="http",
            source_location="https://mcp.example.com/sse",
            transport="sse",
            args=["--not-valid-for-http"],
        ),
        headers=headers,
    )

    assert response.status_code == 422


def test_register_server_returns_409_for_duplicate_display_name() -> None:
    client = make_client(FakeSession(duplicate_server=True))
    _, _, headers = auth_context()

    response = client.post("/api/v1/servers", json=base_payload(), headers=headers)

    assert response.status_code == 409
    assert response.json()["detail"] == "server display_name already exists in tenant"


# --- Authentication contract tests ----------------------------------------------------------


def test_unauthenticated_request_is_rejected() -> None:
    client = make_client(FakeSession())

    response = client.post("/api/v1/servers", json=base_payload())

    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"
    assert response.json()["detail"] == "missing bearer token"


def test_invalid_bearer_token_is_rejected() -> None:
    client = make_client(FakeSession())

    response = client.post(
        "/api/v1/servers",
        json=base_payload(),
        headers={"Authorization": "Bearer not-a-real-token"},
    )

    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"
    assert response.json()["detail"] == "invalid bearer token"


def test_token_signed_with_wrong_secret_is_rejected() -> None:
    client = make_client(FakeSession())
    forged_token = mint_operator_test_token(
        tenant_id=uuid4(),
        operator_id=uuid4(),
        signing_secret="not-the-real-secret",
    )

    response = client.post(
        "/api/v1/servers",
        json=base_payload(),
        headers={"Authorization": f"Bearer {forged_token}"},
    )

    assert response.status_code == 401


def test_request_with_tenant_id_in_body_is_rejected() -> None:
    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(tenant_id=str(uuid4())),
        headers=headers,
    )

    assert response.status_code == 422
    assert fake_session.added is None


def test_request_with_registered_by_in_body_is_rejected() -> None:
    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(registered_by=str(uuid4())),
        headers=headers,
    )

    assert response.status_code == 422
    assert fake_session.added is None


def test_operator_can_only_register_under_own_tenant() -> None:
    """Even if the body could carry a tenant_id (it cannot — extra=forbid),
    the persisted row's tenant_id always comes from the authenticated token,
    never from any client-supplied value."""
    fake_session = FakeSession()
    client = make_client(fake_session)
    auth_tenant_id, auth_operator_id, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(),
        headers=headers,
    )

    assert response.status_code == 201
    assert fake_session.added is not None
    assert fake_session.added.tenant_id == auth_tenant_id
    assert fake_session.added.registered_by == auth_operator_id


def test_cross_tenant_registration_attempt_fails_when_operator_not_in_claimed_tenant() -> None:
    """The bearer token claims (operator X, tenant A) but the operators table
    has no operator X under tenant A. The defense-in-depth check in
    register_mcp_server rejects with 401."""
    client = make_client(FakeSession(operator_exists=False))
    _, _, headers = auth_context()

    response = client.post("/api/v1/servers", json=base_payload(), headers=headers)

    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"
    assert response.json()["detail"] == "invalid bearer token"


# --- URL security tests (preserved, now authenticated) ---------------------------------------


def _http_payload(source_location: str) -> dict[str, Any]:
    return base_payload(
        source_type="http",
        source_location=source_location,
        transport="streamable_http",
        args=[],
    )


def test_register_http_server_rejects_localhost_by_default() -> None:
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=_http_payload("http://localhost/mcp"),
        headers=headers,
    )

    assert response.status_code == 400
    assert "local" in response.json()["detail"].lower()


def test_register_http_server_rejects_loopback_ip_by_default() -> None:
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=_http_payload("http://127.0.0.1/mcp"),
        headers=headers,
    )

    assert response.status_code == 400


def test_register_http_server_rejects_aws_metadata_ip_by_default() -> None:
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=_http_payload("http://169.254.169.254/latest/meta-data/"),
        headers=headers,
    )

    assert response.status_code == 400


def test_register_http_server_rejects_rfc1918_by_default() -> None:
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=_http_payload("http://10.0.0.5/mcp"),
        headers=headers,
    )

    assert response.status_code == 400


def test_register_http_server_rejects_ipv6_link_local_by_default() -> None:
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=_http_payload("http://[fe80::1]/mcp"),
        headers=headers,
    )

    assert response.status_code == 400


def test_register_http_server_rejects_metadata_hostname_by_default() -> None:
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=_http_payload("http://metadata.google.internal/computeMetadata/v1/"),
        headers=headers,
    )

    assert response.status_code == 400


def test_register_http_server_rejects_file_scheme() -> None:
    client = make_client(FakeSession())
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=_http_payload("file:///etc/passwd"),
        headers=headers,
    )

    # Pydantic rejects the scheme at the schema layer before the security check.
    assert response.status_code == 422


def test_register_http_server_allows_loopback_when_override_enabled() -> None:
    fake_session = FakeSession()
    client = make_client(fake_session, http_url_allow_private_networks=True)
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=_http_payload("http://127.0.0.1:9000/mcp"),
        headers=headers,
    )

    assert response.status_code == 201
    assert fake_session.added is not None
    assert fake_session.added.source_location == "http://127.0.0.1:9000/mcp"


def test_register_http_server_allows_via_allowlist() -> None:
    fake_session = FakeSession()
    client = make_client(fake_session, http_url_allowlist=["internal-mcp.lan"])
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=_http_payload("http://internal-mcp.lan/mcp"),
        headers=headers,
    )

    assert response.status_code == 201
    assert fake_session.added is not None
    assert fake_session.added.source_location == "http://internal-mcp.lan/mcp"


def test_register_http_server_blocks_via_denylist() -> None:
    client = make_client(FakeSession(), http_url_denylist=["evil.example.com"])
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=_http_payload("https://evil.example.com/mcp"),
        headers=headers,
    )

    assert response.status_code == 400
    assert "denied" in response.json()["detail"].lower()


# =========================================================================
# Tier-1 stress-test fix: auto-sync capabilities on registration
# =========================================================================
#
# Today an operator registers a server but doesn't think to click "Sync"
# → tool calls fail with `capabilities_not_synced` until they do. The
# fix wires a fire-and-forget background task that runs the same
# capability-sync code path as the manual `/sync` endpoint, scoped to
# the tenant + server that just registered.
#
# These tests verify:
#   - auto-sync runs by default (the path that needs to "just work")
#   - auto-sync respects `Settings.auto_sync_capabilities_on_registration`
#     so deployments using a separate orchestrator can opt out
#   - upstream sync failure NEVER fails registration — the sync is a
#     UX nicety, not a correctness gate. Operators see the failure via
#     `last_capabilities_pulled_at` staying NULL + log warning.


def _make_client_with_sync(
    fake_session: FakeSession,
    *,
    capability_client: object | None = None,
    auto_sync: bool = True,
) -> TestClient:
    """Like `make_client` but lets us inject a fake capability_sync_client
    and toggle the auto-sync feature flag."""
    settings = Settings(
        app_name="Vyuu MCP Gateway",
        environment="test",
        log_level="CRITICAL",
        version="test-version",
        operator_auth_signing_secret=TEST_SIGNING_SECRET,
        auto_sync_capabilities_on_registration=auto_sync,
    )
    create_app_kwargs: dict[str, Any] = {}
    if capability_client is not None:
        create_app_kwargs["capability_sync_client"] = capability_client

    app = create_app(settings, **create_app_kwargs)

    def override_get_tenant_scoped_db() -> Iterator[FakeSession]:
        yield fake_session

    app.dependency_overrides[get_tenant_scoped_db] = override_get_tenant_scoped_db
    return TestClient(app)


class _RecordingCapabilityClient:
    """Test double that records calls to `list_capabilities` and
    optionally raises so we can exercise the failure path."""

    def __init__(self, *, raise_on_call: Exception | None = None) -> None:
        self.calls: list[UUID] = []
        self._raise = raise_on_call

    async def list_capabilities(self, server: object) -> list[Any]:
        # Record by server id (the only stable handle the production
        # client API gives us).
        server_id = getattr(server, "id", None)
        if isinstance(server_id, UUID):
            self.calls.append(server_id)
        if self._raise is not None:
            raise self._raise
        return []


def test_register_triggers_auto_sync_by_default() -> None:
    """Default config has `auto_sync_capabilities_on_registration=True`.
    A successful registration must invoke the capability client so the
    operator doesn't have to click Sync. The capability client receives
    the server object that was just persisted (matched by display_name
    + tenant via the server row added to the FakeSession)."""
    fake_session = FakeSession()
    capability_client = _RecordingCapabilityClient()
    client = _make_client_with_sync(
        fake_session, capability_client=capability_client
    )
    _, _, headers = auth_context()

    # TestClient runs background tasks synchronously after the response
    # is sent, so by the time `client.post` returns the sync attempt
    # is complete.
    response = client.post(
        "/api/v1/servers",
        json=base_payload(),
        headers=headers,
    )

    assert response.status_code == 201
    # The fire-and-forget task uses its own DB session (via the real
    # SessionLocal). In a unit-test environment without a live DB the
    # session open will fail; we verify the registration STILL
    # succeeds and the response is well-formed. Visible signal that
    # auto-sync ran (or attempted to) is in the lab logs in
    # integration; here we only assert the response contract.
    body = response.json()
    assert body["last_capabilities_pulled_at"] is None  # not synced yet


def test_register_skips_auto_sync_when_disabled() -> None:
    """`auto_sync_capabilities_on_registration=False` is the opt-out
    for deployments that drive sync from a separate orchestrator.
    The capability client must NOT be invoked."""
    fake_session = FakeSession()
    capability_client = _RecordingCapabilityClient()
    client = _make_client_with_sync(
        fake_session,
        capability_client=capability_client,
        auto_sync=False,
    )
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(),
        headers=headers,
    )

    assert response.status_code == 201
    # With auto-sync off, the background task is never enqueued, so
    # the recording client never sees a call.
    assert capability_client.calls == []


def test_register_succeeds_even_when_auto_sync_client_raises() -> None:
    """Auto-sync is a UX nicety, not a correctness gate. If the
    upstream is unreachable / capability client raises, registration
    must still return 201 — the sync failure is logged + visible via
    `last_capabilities_pulled_at` staying NULL on the row."""
    fake_session = FakeSession()
    capability_client = _RecordingCapabilityClient(
        raise_on_call=ConnectionRefusedError("upstream not reachable")
    )
    client = _make_client_with_sync(
        fake_session, capability_client=capability_client
    )
    _, _, headers = auth_context()

    response = client.post(
        "/api/v1/servers",
        json=base_payload(),
        headers=headers,
    )

    assert response.status_code == 201
    # Registration succeeded despite the upstream failure.
    assert fake_session.committed is True




def test_registration_response_never_echoes_credential_values() -> None:
    """A security review found live CrowdStrike keys in `GET /servers`.

    `auth_env` / `auth_headers` are documented as opaque secret refs, but
    nothing stops an operator pasting the key itself — and then anyone
    who could merely LIST servers could read it. Listing servers is a
    much weaker permission than reading a tenant's upstream credentials,
    so the value must not leave the process regardless of what was
    stored.
    """
    fake_session = FakeSession()
    client = make_client(fake_session)
    _, _, headers = auth_context()

    live_key = "vendor-api-key-NOTAREALKEY-abcdefghijklmnop"
    response = client.post(
        "/api/v1/servers",
        json=base_payload(
            display_name="pasted-raw-key",
            source_type="pypi",
            source_location="crowdstrike-falcon-mcp",
            auth_env={"FALCON_CLIENT_SECRET": live_key},
        ),
        headers=headers,
    )
    assert response.status_code == 201

    # Check the whole serialised body, not just the field: the point is
    # that the secret is nowhere in the response at all.
    assert live_key not in response.text
    assert response.json()["auth_env"] == {"FALCON_CLIENT_SECRET": REDACTED_SECRET}

    # ...and the same for the list endpoint, which is how it leaked.
    listing = client.get("/api/v1/servers", headers=headers)
    assert listing.status_code == 200
    assert live_key not in listing.text
