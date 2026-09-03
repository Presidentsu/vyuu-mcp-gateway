"""S8 — manifest parsing + fetch tests.

Three layers:
1. `parse_manifest(payload)` — deterministic field extraction across
   the realistic shape variations we expect from upstream `mcp.json`
   conventions.
2. `fetch_manifest(url)` via httpx MockTransport — covers the network
   error / non-2xx / non-JSON cases without an HTTP server.
3. `POST /api/v1/servers/from-manifest` endpoint via `TestClient` —
   round-trips a manifest into a `ManifestPreviewResponse`.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from vyuu_gateway.config import Settings
from vyuu_gateway.main import create_app
from vyuu_gateway.operator_auth.fake import mint_operator_test_token
from vyuu_gateway.registry.manifest import (
    ManifestFetchError,
    ManifestParseError,
    fetch_manifest,
    parse_manifest,
)

_OP_SECRET = "manifest-test-op-secret"


# --- parse_manifest -------------------------------------------------------


def test_parse_recognises_streamable_http_endpoint() -> None:
    out = parse_manifest(
        {
            "name": "drawio",
            "description": "Draw.io diagrams",
            "transport": "streamable-http",
            "endpoint": "https://mcp.draw.io/mcp",
        }
    )
    assert out.display_name == "drawio"
    assert out.description == "Draw.io diagrams"
    assert out.transport == "streamable_http"
    assert out.source_type == "http"
    assert out.source_location == "https://mcp.draw.io/mcp"


def test_parse_npm_command_with_args_extracts_package() -> None:
    out = parse_manifest(
        {
            "name": "drawio-stdio",
            "command": "npx",
            "args": ["-y", "@drawio/mcp"],
        }
    )
    assert out.source_type == "npm"
    assert out.source_location == "@drawio/mcp"
    assert out.transport == "stdio"
    assert out.args == ["-y", "@drawio/mcp"]


def test_parse_uvx_command_picks_first_arg_as_package() -> None:
    out = parse_manifest(
        {"command": "uvx", "args": ["mcp-server-time", "--utc"]}
    )
    assert out.source_type == "pypi"
    assert out.source_location == "mcp-server-time"
    assert out.transport == "stdio"


def test_parse_unknown_command_falls_back_to_stdio() -> None:
    out = parse_manifest(
        {"command": "/opt/vendor/foo-mcp", "args": ["--port", "9000"]}
    )
    assert out.source_type == "stdio"
    assert out.source_location == "/opt/vendor/foo-mcp"
    assert out.args == ["--port", "9000"]


def test_parse_extracts_auth_hint() -> None:
    out = parse_manifest(
        {
            "name": "wiz",
            "endpoint": "https://api.wiz.io/mcp",
            "auth": {"scheme": "oauth"},
        }
    )
    assert out.auth_hint == "oauth"


def test_parse_returns_partial_when_fields_missing() -> None:
    """The whole point of this module: best-effort, no exceptions on
    sparse input. Operators see what wasn't auto-detected and fill in."""
    out = parse_manifest({"name": "mystery"})
    assert out.display_name == "mystery"
    assert out.transport is None
    assert out.source_type is None
    assert out.source_location is None
    # Raw payload is round-tripped so the operator can eyeball it.
    assert out.raw == {"name": "mystery"}


def test_parse_rejects_non_object_payload() -> None:
    with pytest.raises(ManifestParseError):
        parse_manifest("not a dict")  # type: ignore[arg-type]


def test_parse_alternative_field_names() -> None:
    """Same data, different keys — `title`/`url` aliases.
    Upstream conventions diverge; we accept both."""
    out = parse_manifest(
        {
            "title": "snyk",
            "summary": "Snyk MCP",
            "type": "http",
            "url": "https://api.snyk.io/mcp",
        }
    )
    assert out.display_name == "snyk"
    assert out.description == "Snyk MCP"
    assert out.source_type == "http"
    assert out.source_location == "https://api.snyk.io/mcp"


# --- fetch_manifest ------------------------------------------------------


def _fetch(url: str, handler: Any, *, allow_http: bool = True) -> dict[str, Any]:
    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    return asyncio.run(
        fetch_manifest(url, allow_http=allow_http, http_client=client)
    )


def test_fetch_returns_parsed_json_body() -> None:
    payload = {"name": "x"}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(payload).encode("utf-8"))

    body = _fetch("http://example.com/mcp.json", handler)
    assert body == payload


def test_fetch_rejects_http_when_allow_http_false() -> None:
    with pytest.raises(ManifestFetchError, match="HTTPS"):
        asyncio.run(
            fetch_manifest("http://example.com/mcp.json", allow_http=False)
        )


def test_fetch_rejects_unsupported_scheme() -> None:
    with pytest.raises(ManifestFetchError, match="scheme"):
        asyncio.run(fetch_manifest("file:///etc/passwd"))


def test_fetch_maps_4xx_to_fetch_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, content=b"nope")

    with pytest.raises(ManifestFetchError):
        _fetch("http://example.com/missing.json", handler)


def test_fetch_maps_non_json_body_to_parse_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>not json</html>")

    with pytest.raises(ManifestParseError):
        _fetch("http://example.com/mcp.json", handler)


def test_fetch_rejects_non_object_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'["array", "not", "object"]')

    with pytest.raises(ManifestParseError):
        _fetch("http://example.com/mcp.json", handler)


# --- /servers/from-manifest endpoint -------------------------------------


def _make_client_and_token() -> tuple[TestClient, dict[str, str]]:
    app = create_app(
        Settings(
            app_name="manifest-test",
            environment="test",
            log_level="CRITICAL",
            operator_auth_signing_secret=_OP_SECRET,
        )
    )
    client = TestClient(app)
    token = mint_operator_test_token(
        tenant_id=uuid4(),
        operator_id=uuid4(),
        signing_secret=_OP_SECRET,
    )
    return client, {"Authorization": f"Bearer {token}"}


def test_endpoint_rejects_missing_token() -> None:
    client, _ = _make_client_and_token()
    with client:
        r = client.post(
            "/api/v1/servers/from-manifest",
            json={"manifest_url": "https://example.com/mcp.json"},
        )
    assert r.status_code == 401


def test_endpoint_rejects_invalid_scheme() -> None:
    client, headers = _make_client_and_token()
    with client:
        r = client.post(
            "/api/v1/servers/from-manifest",
            json={"manifest_url": "file:///etc/passwd"},
            headers=headers,
        )
    assert r.status_code == 400


def test_endpoint_rejects_plain_http_by_default() -> None:
    client, headers = _make_client_and_token()
    with client:
        r = client.post(
            "/api/v1/servers/from-manifest",
            json={"manifest_url": "http://example.com/mcp.json"},
            headers=headers,
        )
    assert r.status_code == 400
