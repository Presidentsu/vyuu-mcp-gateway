"""First-run bootstrap: env-driven seeding of tenant + operator + user."""

from __future__ import annotations

from uuid import UUID

import pytest

from vyuu_gateway.bootstrap import maybe_bootstrap_admin
from vyuu_gateway.db.models import Operator, Tenant, User

_ENV = {
    "VYUU_BOOTSTRAP_TENANT_NAME": "Acme Corp",
    "VYUU_BOOTSTRAP_ADMIN_EMAIL": "Admin@Acme.Example",
    "VYUU_BOOTSTRAP_ADMIN_PASSWORD": "initial-password-that-is-long",
}


class _FakeSession:
    """Empty database: no operators, no tenants."""

    def __init__(self) -> None:
        self.added: list[object] = []
        self.committed = False

    def scalar(self, _stmt):  # noqa: ANN001 - SQLAlchemy Select
        return None

    def get(self, _model, _pk):  # noqa: ANN001
        return None

    def add(self, obj: object) -> None:
        self.added.append(obj)

    def commit(self) -> None:
        self.committed = True


def _seed(monkeypatch: pytest.MonkeyPatch, **extra: str) -> _FakeSession:
    for key in ("VYUU_BOOTSTRAP_TENANT_ID",):
        monkeypatch.delenv(key, raising=False)
    for key, value in {**_ENV, **extra}.items():
        monkeypatch.setenv(key, value)
    session = _FakeSession()
    maybe_bootstrap_admin(session)
    return session


def _by_type(session: _FakeSession, model: type) -> object:
    matches = [obj for obj in session.added if isinstance(obj, model)]
    assert len(matches) == 1, f"expected exactly one {model.__name__}, got {matches}"
    return matches[0]


def test_seeds_tenant_operator_and_user_with_matching_ids(monkeypatch):
    session = _seed(monkeypatch)

    tenant = _by_type(session, Tenant)
    operator = _by_type(session, Operator)
    user = _by_type(session, User)
    assert session.committed
    assert operator.tenant_id == tenant.id == user.tenant_id
    assert operator.email == "admin@acme.example" == user.email
    assert operator.must_change_password and user.must_change_password


def test_pinned_tenant_id_is_honoured(monkeypatch):
    pinned = "3f0c6c1e-9d4b-4a2e-8f77-0d5a1b2c3d4e"
    session = _seed(monkeypatch, VYUU_BOOTSTRAP_TENANT_ID=pinned)

    tenant = _by_type(session, Tenant)
    assert tenant.id == UUID(pinned)
    assert _by_type(session, Operator).tenant_id == UUID(pinned)


def test_invalid_pinned_tenant_id_skips_the_seed(monkeypatch):
    session = _seed(monkeypatch, VYUU_BOOTSTRAP_TENANT_ID="not-a-uuid")

    assert session.added == []
    assert not session.committed


def test_missing_env_is_a_noop(monkeypatch):
    for key in _ENV:
        monkeypatch.delenv(key, raising=False)
    session = _FakeSession()
    maybe_bootstrap_admin(session)
    assert session.added == [] and not session.committed
