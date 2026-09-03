"""EMA-1 · pure-unit tests for `IdpJagIdentityProvider`.

Everything here fails BEFORE any DB work (bearer-shape fast-reject and
JWT decode both precede the session), so the tests run without
Postgres and prove the no-DB property with a session factory that
explodes if touched. The DB-dependent halves (directory toggle, JIT
user mapping, disabled-user kill-switch) live in the real-Postgres
suite `tests/api/test_ema_oauth.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest

from vyuu_gateway.identity.jwt_bearer_provider import IdpJagIdentityProvider
from vyuu_gateway.identity.provider import (
    IdentityCredentials,
    IdentityValidationError,
)

_SECRET = "unit-test-ema-signing-secret-0123456789abcdef"
_BASE = "http://gateway"


def _forbidden_session_factory() -> None:
    raise AssertionError("provider must not touch the DB before token validation")


def _provider() -> IdpJagIdentityProvider:
    return IdpJagIdentityProvider(
        _forbidden_session_factory,  # type: ignore[arg-type]
        signing_secret=_SECRET,
        issuer_base=_BASE,
    )


def _token(
    tenant_id,
    *,
    secret: str = _SECRET,
    issuer: str | None = None,
    aud: str | None = None,
    exp_delta: timedelta = timedelta(minutes=10),
    drop: tuple[str, ...] = (),
) -> str:
    now = datetime.now(UTC)
    claims = {
        "iss": issuer or f"{_BASE}/v/{tenant_id}",
        "aud": aud or str(tenant_id),
        "sub": "okta-sub-1",
        "email": "user@corp.example",
        "dir": str(uuid4()),
        "iat": now,
        "exp": now + exp_delta,
    }
    for key in drop:
        claims.pop(key, None)
    return jwt.encode(claims, secret, algorithm="HS256")


def _creds(bearer: str) -> IdentityCredentials:
    return IdentityCredentials(headers={"Authorization": f"Bearer {bearer}"})


def test_rejects_missing_authorization_header() -> None:
    with pytest.raises(IdentityValidationError):
        _provider().validate_principal(
            tenant_id=uuid4(), credentials=IdentityCredentials(headers={})
        )


def test_fast_rejects_vyuu_api_key_bearers_without_crypto_or_db() -> None:
    """Chain contract: foreign bearer shapes must be rejected on a
    string check alone so the fall-through costs nothing."""

    with pytest.raises(IdentityValidationError, match="not an EMA"):
        _provider().validate_principal(
            tenant_id=uuid4(),
            credentials=_creds("vyuu_user_abc123_secretsecret"),
        )


def test_fast_rejects_non_jwt_shapes() -> None:
    with pytest.raises(IdentityValidationError, match="not an EMA"):
        _provider().validate_principal(
            tenant_id=uuid4(), credentials=_creds("just-an-opaque-string")
        )


def test_rejects_expired_token() -> None:
    tenant_id = uuid4()
    token = _token(tenant_id, exp_delta=timedelta(minutes=-5))
    with pytest.raises(IdentityValidationError, match="invalid EMA"):
        _provider().validate_principal(tenant_id=tenant_id, credentials=_creds(token))


def test_rejects_wrong_audience() -> None:
    tenant_id = uuid4()
    token = _token(tenant_id, aud=str(uuid4()))  # some other tenant
    with pytest.raises(IdentityValidationError, match="invalid EMA"):
        _provider().validate_principal(tenant_id=tenant_id, credentials=_creds(token))


def test_rejects_wrong_issuer() -> None:
    tenant_id = uuid4()
    token = _token(tenant_id, issuer=f"{_BASE}/v/{uuid4()}")
    with pytest.raises(IdentityValidationError, match="invalid EMA"):
        _provider().validate_principal(tenant_id=tenant_id, credentials=_creds(token))


def test_rejects_wrong_signing_secret() -> None:
    tenant_id = uuid4()
    token = _token(tenant_id, secret="a-completely-different-signing-secret!!")
    with pytest.raises(IdentityValidationError, match="invalid EMA"):
        _provider().validate_principal(tenant_id=tenant_id, credentials=_creds(token))


def test_rejects_token_missing_required_claim() -> None:
    tenant_id = uuid4()
    token = _token(tenant_id, drop=("dir",))
    with pytest.raises(IdentityValidationError, match="invalid EMA"):
        _provider().validate_principal(tenant_id=tenant_id, credentials=_creds(token))


def test_constructor_refuses_empty_secret() -> None:
    with pytest.raises(ValueError):
        IdpJagIdentityProvider(
            _forbidden_session_factory,  # type: ignore[arg-type]
            signing_secret="",
            issuer_base=_BASE,
        )
