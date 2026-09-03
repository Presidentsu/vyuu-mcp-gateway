"""Unit tests for the OAuth 2.0 client-credentials token provider."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any
from uuid import uuid4

import httpx
import pytest

from vyuu_gateway.secrets import InMemorySecretStore
from vyuu_gateway.upstream.oauth import (
    CachedOAuthTokenProvider,
    OAuthClientCredentialsConfig,
    OAuthTokenError,
)


def _config(**overrides: Any) -> OAuthClientCredentialsConfig:
    return OAuthClientCredentialsConfig(
        token_url=overrides.pop("token_url", "https://auth.example/token"),
        client_id_ref=overrides.pop("client_id_ref", "client-id-ref"),
        client_secret_ref=overrides.pop("client_secret_ref", "client-secret-ref"),
        scope=overrides.pop("scope", None),
        audience=overrides.pop("audience", None),
    )


class _MockClock:
    """Manual clock for deterministic TTL testing — `monotonic()` is too jittery."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _RecordingTokenIssuer:
    """ASGI app that issues tokens and records request count + body.

    Used as the OAuth auth server in tests. `expires_in` and `access_token`
    are configurable so we can drive caching / expiry behavior.
    """

    def __init__(
        self,
        *,
        access_token: str = "abc.def.ghi",
        expires_in: int | None = 3600,
        status_code: int = 200,
        body_override: dict[str, Any] | None = None,
        latency_seconds: float = 0.0,
    ) -> None:
        self.access_token = access_token
        self.expires_in = expires_in
        self.status_code = status_code
        self.body_override = body_override
        self.latency_seconds = latency_seconds
        self.requests: list[dict[str, str]] = []

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        # Drain the request body.
        body_bytes = b""
        more_body = True
        while more_body:
            event = await receive()
            body_bytes += event.get("body", b"")
            more_body = event.get("more_body", False)
        # Record the form fields and the auth header.
        form_fields = dict(
            field.split("=", 1) for field in body_bytes.decode().split("&") if "=" in field
        )
        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
        self.requests.append({**form_fields, "_authorization": headers.get("authorization", "")})

        if self.latency_seconds > 0:
            await asyncio.sleep(self.latency_seconds)

        if self.body_override is not None:
            payload: dict[str, Any] = self.body_override
        else:
            payload = {
                "access_token": self.access_token,
                "token_type": "Bearer",
            }
            if self.expires_in is not None:
                payload["expires_in"] = self.expires_in

        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": json.dumps(payload).encode()})


def _provider_with_issuer(
    issuer: _RecordingTokenIssuer,
    *,
    config: OAuthClientCredentialsConfig | None = None,
    secret_store: InMemorySecretStore | None = None,
    tenant_id: Any = None,
    clock: Callable[[], float] | None = None,
) -> CachedOAuthTokenProvider:
    cfg = config or _config()
    tid = tenant_id or uuid4()
    store = secret_store or InMemorySecretStore()
    if not store._secrets:  # noqa: SLF001
        store.put(tid, cfg.client_id_ref, "lab-client-id")
        store.put(tid, cfg.client_secret_ref, "lab-client-secret")

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=issuer))  # type: ignore[arg-type]

    return CachedOAuthTokenProvider(
        config=cfg,
        tenant_id=tid,
        secret_store=store,
        clock=clock or _MockClock(),
        http_client_factory=factory,
    )


def test_fetches_and_returns_access_token() -> None:
    issuer = _RecordingTokenIssuer(access_token="t1", expires_in=3600)
    provider = _provider_with_issuer(issuer)

    token = asyncio.run(provider.fetch_token())

    assert token == "t1"
    assert len(issuer.requests) == 1
    assert issuer.requests[0]["grant_type"] == "client_credentials"
    # Basic auth ridden via httpx — base64('lab-client-id:lab-client-secret').
    assert issuer.requests[0]["_authorization"].startswith("Basic ")


def test_caches_token_until_expiry_minus_safety_buffer() -> None:
    issuer = _RecordingTokenIssuer(access_token="cached", expires_in=3600)
    clock = _MockClock()
    provider = _provider_with_issuer(issuer, clock=clock)

    # First call: cache miss, fetches.
    asyncio.run(provider.fetch_token())
    # Second call within the cache window: no new HTTP request.
    clock.advance(60)
    asyncio.run(provider.fetch_token())
    assert len(issuer.requests) == 1
    # Advance past expiry minus safety buffer (3600 - 60 = 3540s).
    clock.advance(3500)  # total 3560 — past 3540 cutoff.
    asyncio.run(provider.fetch_token())
    assert len(issuer.requests) == 2


def test_includes_scope_and_audience_when_configured() -> None:
    issuer = _RecordingTokenIssuer()
    provider = _provider_with_issuer(
        issuer,
        config=_config(scope="wiz:read", audience="https://api.wiz.io"),
    )

    asyncio.run(provider.fetch_token())

    body = issuer.requests[0]
    assert body["scope"] == "wiz%3Aread"
    assert body["audience"] == "https%3A%2F%2Fapi.wiz.io"


def test_raises_when_token_endpoint_returns_non_2xx() -> None:
    issuer = _RecordingTokenIssuer(status_code=401)
    provider = _provider_with_issuer(issuer)

    with pytest.raises(OAuthTokenError, match="401"):
        asyncio.run(provider.fetch_token())


def test_raises_when_response_missing_access_token() -> None:
    issuer = _RecordingTokenIssuer(body_override={"token_type": "Bearer"})
    provider = _provider_with_issuer(issuer)

    with pytest.raises(OAuthTokenError, match="missing access_token"):
        asyncio.run(provider.fetch_token())


def test_concurrent_callers_share_a_single_refresh() -> None:
    """The async lock must serialize the refresh — a hot upstream
    triggering N parallel calls during a token refresh must NOT issue
    N token requests to the auth server."""

    issuer = _RecordingTokenIssuer(access_token="shared", latency_seconds=0.05)
    provider = _provider_with_issuer(issuer)

    async def run() -> None:
        results = await asyncio.gather(*(provider.fetch_token() for _ in range(8)))
        assert all(r == "shared" for r in results)

    asyncio.run(run())
    assert len(issuer.requests) == 1


def test_default_expires_in_used_when_response_omits_it() -> None:
    """RFC 6749 §5.1: expires_in is RECOMMENDED but optional. Conservative
    default (1h) avoids holding a potentially-expired token forever."""

    issuer = _RecordingTokenIssuer(expires_in=None)
    clock = _MockClock()
    provider = _provider_with_issuer(issuer, clock=clock)

    asyncio.run(provider.fetch_token())
    # Within 1h - safety buffer: still cached.
    clock.advance(3500)
    asyncio.run(provider.fetch_token())
    assert len(issuer.requests) == 1
