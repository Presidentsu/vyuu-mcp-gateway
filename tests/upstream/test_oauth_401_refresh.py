"""A4 — 401-driven OAuth refresh.

Two sets of tests:
- Provider invalidation API works (each of the 3 providers).
- The HTTP MCP client `_looks_like_unauthorized` detects the common
  exception shapes that surface a 401 from the upstream.
"""
from __future__ import annotations

from uuid import UUID, uuid4

from vyuu_gateway.mcp.outbound import _looks_like_unauthorized

# --- Heuristic detection ---------------------------------------------------


class _Resp:
    status_code = 401


class _StatusErr(Exception):  # noqa: N818 — fake httpx-style error for test
    response = _Resp()


def test_looks_like_unauthorized_detects_response_status_code() -> None:
    """httpx.HTTPStatusError carries `.response.status_code = 401`."""
    assert _looks_like_unauthorized(_StatusErr("nope")) is True


def test_looks_like_unauthorized_detects_message_containing_401() -> None:
    assert _looks_like_unauthorized(Exception("HTTP 401 Unauthorized")) is True


def test_looks_like_unauthorized_detects_invalid_token_phrase() -> None:
    assert _looks_like_unauthorized(Exception(
        'OAuth error: {"error": "invalid_token"}'
    )) is True


def test_looks_like_unauthorized_drills_through_exception_group() -> None:
    """anyio wraps task-group failures in BaseExceptionGroup; the
    real cause sits inside."""
    inner = Exception("401 Unauthorized")
    group = BaseExceptionGroup("upstream", [inner])
    assert _looks_like_unauthorized(group) is True


def test_looks_like_unauthorized_returns_false_for_other_errors() -> None:
    assert _looks_like_unauthorized(Exception("503 Service Unavailable")) is False
    assert _looks_like_unauthorized(Exception("connection refused")) is False
    assert _looks_like_unauthorized(TimeoutError()) is False


# --- Provider invalidation -------------------------------------------------


def test_cached_oauth_provider_invalidate_clears_cached_token() -> None:
    """Phase-3 (client-credentials) provider drops its single token."""
    import asyncio

    from vyuu_gateway.upstream.oauth import (
        CachedOAuthTokenProvider,
        OAuthClientCredentialsConfig,
    )

    config = OAuthClientCredentialsConfig(
        token_url="https://example.invalid/token",
        client_id_ref="cid",
        client_secret_ref="csec",
    )

    class _StubStore:
        async def get_secret(self, tenant_id: UUID, ref: str) -> str:
            return "stub"

    provider = CachedOAuthTokenProvider(
        config=config,
        tenant_id=uuid4(),
        secret_store=_StubStore(),
    )
    # Inject a cached token directly.
    provider._access_token = "cached-token-value"
    provider._expires_at = float("inf")

    async def run() -> None:
        # Pre-invalidate: cached token returned.
        assert await provider.fetch_token() == "cached-token-value"
        await provider.invalidate()
        # Post-invalidate: internal state cleared.
        assert provider._access_token is None
        assert provider._expires_at == 0.0

    asyncio.run(run())


def test_jwt_bearer_provider_invalidate_clears_cached_token() -> None:
    """Phase-5 (JWT-bearer service-account) provider drops its token."""
    import asyncio

    from vyuu_gateway.upstream.oauth_jwt_bearer import (
        OAuthJwtBearerConfig,
        OAuthJwtBearerTokenProvider,
    )

    config = OAuthJwtBearerConfig(
        token_url="https://example.invalid/token",
        issuer="iss",
        subject="sub",
        audience="aud",
        private_key_ref="pk",
        algorithm="RS256",
    )

    class _StubStore:
        async def get_secret(self, tenant_id: UUID, ref: str) -> str:
            return "stub"

    provider = OAuthJwtBearerTokenProvider(
        config=config,
        tenant_id=uuid4(),
        secret_store=_StubStore(),
    )
    provider._access_token = "cached"
    provider._expires_at = float("inf")

    async def run() -> None:
        await provider.invalidate()
        assert provider._access_token is None
        assert provider._expires_at == 0.0

    asyncio.run(run())


def test_authcode_provider_invalidate_marks_only_specified_principal() -> None:
    """Phase-4 invalidation is per-principal — other users' caches stay live."""
    import asyncio

    from vyuu_gateway.upstream.oauth_authcode import (
        OAuthAuthCodeConfig,
        OAuthAuthCodeTokenProvider,
    )

    user_a = uuid4()
    user_b = uuid4()

    config = OAuthAuthCodeConfig(
        auth_url="https://example.invalid/authorize",
        token_url="https://example.invalid/token",
        client_id_ref="cid",
        client_secret_ref="csec",
        redirect_uri="https://gateway/callback",
        scopes=("read",),
    )
    provider = OAuthAuthCodeTokenProvider(
        config=config,
        tenant_id=uuid4(),
        server_id=uuid4(),
        secret_store=None,  # type: ignore[arg-type]
        db_session_factory=None,
    )

    async def run() -> None:
        # Invalidate user A only.
        await provider.invalidate(principal_id=user_a)
        assert user_a in provider._invalidated
        assert user_b not in provider._invalidated
        # Idempotent — second call doesn't blow up.
        await provider.invalidate(principal_id=user_a)
        # No-op for None.
        await provider.invalidate(principal_id=None)
        assert user_b not in provider._invalidated

    asyncio.run(run())
