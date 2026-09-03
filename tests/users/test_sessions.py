"""Unit tests for portal session JWT issuance + verification."""

from __future__ import annotations

import time
from uuid import uuid4

import pytest

from vyuu_gateway.users.sessions import (
    SessionTokenError,
    issue_portal_session,
    verify_portal_session,
)


def test_round_trip() -> None:
    tenant_id = uuid4()
    user_id = uuid4()
    token = issue_portal_session(
        tenant_id=tenant_id,
        user_id=user_id,
        email="alice@corp",
        auth_method="local",
        signing_secret="s" * 32,
        ttl_seconds=3600,
    )
    sess = verify_portal_session(token, signing_secret="s" * 32)
    assert sess.tenant_id == tenant_id
    assert sess.user_id == user_id
    assert sess.email == "alice@corp"
    assert sess.auth_method == "local"


def test_expired_token_rejected() -> None:
    """Force-expired token (negative ttl) — verify must fail."""
    token = issue_portal_session(
        tenant_id=uuid4(),
        user_id=uuid4(),
        email="x@x",
        auth_method="local",
        signing_secret="s" * 32,
        ttl_seconds=-1,
        now=time.time() - 10,
    )
    with pytest.raises(SessionTokenError, match="expired"):
        verify_portal_session(token, signing_secret="s" * 32)


def test_wrong_signing_secret_rejected() -> None:
    token = issue_portal_session(
        tenant_id=uuid4(),
        user_id=uuid4(),
        email="x@x",
        auth_method="local",
        signing_secret="aaa" * 16,
        ttl_seconds=3600,
    )
    with pytest.raises(SessionTokenError):
        verify_portal_session(token, signing_secret="bbb" * 16)


def test_garbled_token_rejected() -> None:
    with pytest.raises(SessionTokenError):
        verify_portal_session("not-a-jwt", signing_secret="s" * 32)
