"""IDP-3 · per-tenant subdomain routing.

The parsing half needs no database and is where the security-relevant
cases live: `Host` is client-supplied, so `slug_from_host` is the
function an attacker gets to poke at. Suffix confusion
(`acme.gateway.example.com.evil.com`) is the one that actually matters —
a naive `in` or `split(".")[0]` gets it wrong.

The resolution half runs against Postgres, including the property that
matters most: **resolving a tenant from `Host` grants nothing.** It picks
which login page renders. If that ever stops being true this becomes a
tenant-confusion vulnerability.
"""

from __future__ import annotations

import os

_DATABASE_URL = os.environ.get("VYUU_TEST_DATABASE_URL")
if _DATABASE_URL is not None:
    os.environ["VYUU_DATABASE_URL"] = _DATABASE_URL

from typing import Any  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from vyuu_gateway.api.tenant_routing import (  # noqa: E402
    RESERVED_SLUGS,
    InvalidTenantSlugError,
    normalize_slug,
    set_tenant_slug,
    slug_from_host,
    tenant_from_host,
)
from vyuu_gateway.config import Settings  # noqa: E402
from vyuu_gateway.db.models import (  # noqa: E402
    Operator,
    OperatorRole,
    Tenant,
    TenantTier,
)
from vyuu_gateway.main import create_app  # noqa: E402
from vyuu_gateway.operator_auth.fake import mint_operator_test_token  # noqa: E402

BASE = "gateway.example.com"
_SECRET = "idp3-operator-secret"

pgmark = pytest.mark.skipif(
    _DATABASE_URL is None, reason="VYUU_TEST_DATABASE_URL not set"
)


# --- Host parsing (no DB) ---------------------------------------------------


def test_plain_subdomain_resolves() -> None:
    assert slug_from_host("acme.gateway.example.com", base_domain=BASE) == "acme"


def test_port_and_case_are_normalised() -> None:
    assert slug_from_host("ACME.Gateway.Example.Com:8443", base_domain=BASE) == "acme"
    # A trailing dot is a legal FQDN and must not change the answer.
    assert slug_from_host("acme.gateway.example.com.", base_domain=BASE) == "acme"


@pytest.mark.parametrize(
    "host",
    [
        # THE case. A naive `endswith(base)` without the dot, or a
        # `split(".")[0]`, hands `acme` to a host the attacker owns.
        "acme.gateway.example.com.evil.com",
        "evil-gateway.example.com",
        "gateway.example.com.evil.com",
        "evil.com",
        # The bare base domain is not a tenant.
        "gateway.example.com",
        # Multi-label: `a.b` is not a slug any tenant can hold, and
        # accepting it would make the answer depend on dot count.
        "a.b.gateway.example.com",
        # Not a legal DNS label.
        "-lead.gateway.example.com",
        "trail-.gateway.example.com",
        "UPPER_SCORE.gateway.example.com",
        "",
    ],
)
def test_hosts_that_must_not_resolve(host: str) -> None:
    assert slug_from_host(host, base_domain=BASE) is None


def test_no_base_domain_disables_resolution_entirely() -> None:
    """An unconfigured deployment must never resolve from Host — that is
    what keeps this feature opt-in."""
    assert slug_from_host("acme.gateway.example.com", base_domain=None) is None
    assert slug_from_host("acme.gateway.example.com", base_domain="") is None


def test_reserved_labels_do_not_resolve() -> None:
    for label in ("www", "api", "admin", "portal", "operator"):
        assert slug_from_host(f"{label}.{BASE}", base_domain=BASE) is None


# --- Slug validation --------------------------------------------------------


def test_normalize_accepts_legal_dns_labels() -> None:
    assert normalize_slug("  Acme  ") == "acme"
    assert normalize_slug("acme-corp-2") == "acme-corp-2"


@pytest.mark.parametrize(
    "bad",
    ["", "a", "-acme", "acme-", "ACME_CORP", "acme.corp", "acme corp", "x" * 64],
)
def test_normalize_rejects_illegal_slugs(bad: str) -> None:
    with pytest.raises(InvalidTenantSlugError):
        normalize_slug(bad)


def test_normalize_rejects_reserved() -> None:
    for label in sorted(RESERVED_SLUGS)[:5]:
        with pytest.raises(InvalidTenantSlugError):
            normalize_slug(label)


def test_normalize_rejects_rather_than_slugifies() -> None:
    """A silently-transformed slug is a hostname the operator did not
    choose and will not predict. "Acme Corp" must fail, not become
    "acme-corp"."""
    with pytest.raises(InvalidTenantSlugError):
        normalize_slug("Acme Corp")


# --- Against Postgres -------------------------------------------------------


def _factory() -> Any:
    assert _DATABASE_URL is not None
    return sessionmaker(
        create_engine(_DATABASE_URL, future=True), autoflush=False, future=True
    )


def _seed(factory: Any, *, slug: str | None = None) -> tuple[UUID, UUID]:
    tenant_id, operator_id = uuid4(), uuid4()
    with factory() as s:
        s.add(Tenant(id=tenant_id, name=f"Tenant {tenant_id.hex[:6]}",
                     tier=TenantTier.SHARED, slug=slug))
        s.add(Operator(id=operator_id, tenant_id=tenant_id,
                       email=f"op-{operator_id.hex[:6]}@test",
                       role=OperatorRole.ADMIN))
        s.commit()
    return tenant_id, operator_id


def _cleanup(factory: Any, *tenant_ids: UUID) -> None:
    with factory() as s:
        for tid in tenant_ids:
            s.execute(text("DELETE FROM admin_audit_log WHERE tenant_id = :i"), {"i": tid})
            s.execute(text("DELETE FROM operators WHERE tenant_id = :i"), {"i": tid})
            s.execute(text("DELETE FROM tenants WHERE id = :i"), {"i": tid})
        s.commit()


def _client(base_domain: str | None = BASE) -> TestClient:
    return TestClient(create_app(Settings(
        app_name="idp3-test", environment="test", log_level="CRITICAL",
        version="t", operator_auth_signing_secret=_SECRET,
        portal_base_domain=base_domain,
    )))


def _op(tenant_id: UUID, operator_id: UUID) -> dict[str, str]:
    return {"Authorization": f"Bearer {mint_operator_test_token(
        tenant_id=tenant_id, operator_id=operator_id, signing_secret=_SECRET)}"}


@pgmark
def test_tenant_resolves_from_host_end_to_end() -> None:
    factory = _factory()
    tenant_id, _op_id = _seed(factory, slug="acme")
    try:
        client = _client()
        resp = client.get(
            "/api/v1/auth/default-tenant",
            headers={"Host": "acme.gateway.example.com"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["tenant_id"] == str(tenant_id)
    finally:
        _cleanup(factory, tenant_id)


@pgmark
def test_unknown_and_spoofed_hosts_do_not_resolve() -> None:
    factory = _factory()
    tenant_id, _op_id = _seed(factory, slug="acme")
    try:
        client = _client()
        for host in (
            "nosuchtenant.gateway.example.com",
            "acme.gateway.example.com.evil.com",
            "evil.com",
        ):
            resp = client.get(
                "/api/v1/auth/default-tenant", headers={"Host": host}
            )
            assert resp.status_code == 404, f"{host} resolved: {resp.text}"
    finally:
        _cleanup(factory, tenant_id)


@pgmark
def test_host_resolution_grants_nothing() -> None:
    """The load-bearing security property. A forged `Host` picks a login
    page — it must not authenticate anyone or reach tenant data. If this
    ever fails, subdomain routing has become tenant confusion."""

    factory = _factory()
    tenant_id, operator_id = _seed(factory, slug="acme")
    other_id, _other_op = _seed(factory, slug="beta")
    try:
        client = _client()
        host = {"Host": "acme.gateway.example.com"}

        # No credentials + the right Host is still unauthenticated.
        assert client.get("/api/v1/vservers", headers=host).status_code in (401, 403)
        assert client.get("/api/v1/tenant/settings", headers=host).status_code in (401, 403)

        # And an operator authenticated for ANOTHER tenant is not
        # re-pointed at Acme by the Host header — the token wins.
        resp = client.get(
            "/api/v1/tenant/settings",
            headers={**_op(other_id, _other_op), **host},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["tenant_id"] == str(other_id)
        assert resp.json()["slug"] == "beta"
    finally:
        _cleanup(factory, tenant_id, other_id)


@pgmark
def test_default_tenant_id_still_works_and_host_wins_over_it() -> None:
    factory = _factory()
    host_tenant, _o1 = _seed(factory, slug="acme")
    default_tenant, _o2 = _seed(factory)
    try:
        app = create_app(Settings(
            app_name="idp3-test", environment="test", log_level="CRITICAL",
            version="t", operator_auth_signing_secret=_SECRET,
            portal_base_domain=BASE, default_tenant_id=default_tenant,
        ))
        client = TestClient(app)

        # No matching subdomain → the on-prem default, exactly as before.
        plain = client.get("/api/v1/auth/default-tenant",
                           headers={"Host": "gateway.example.com"})
        assert plain.status_code == 200
        assert plain.json()["tenant_id"] == str(default_tenant)

        # A matching subdomain wins.
        sub = client.get("/api/v1/auth/default-tenant",
                         headers={"Host": "acme.gateway.example.com"})
        assert sub.status_code == 200
        assert sub.json()["tenant_id"] == str(host_tenant)
    finally:
        _cleanup(factory, host_tenant, default_tenant)


@pgmark
def test_slug_is_unique_across_tenants() -> None:
    factory = _factory()
    first, _o1 = _seed(factory, slug="taken")
    second, _o2 = _seed(factory)
    try:
        with factory() as s, pytest.raises(InvalidTenantSlugError, match="already in use"):
            set_tenant_slug(s, tenant_id=second, slug="taken")
    finally:
        _cleanup(factory, first, second)


@pgmark
def test_operator_can_claim_change_and_clear_a_slug() -> None:
    factory = _factory()
    tenant_id, operator_id = _seed(factory)
    try:
        client = _client()
        headers = _op(tenant_id, operator_id)

        claimed = client.patch("/api/v1/tenant/settings/slug",
                               headers=headers, json={"slug": "Acme"})
        assert claimed.status_code == 200, claimed.text
        assert claimed.json()["slug"] == "acme"
        # The URL is served, not assembled client-side, so the console
        # cannot show a hostname the gateway would not honour.
        assert claimed.json()["portal_url"] == "https://acme.gateway.example.com/portal/"

        reserved = client.patch("/api/v1/tenant/settings/slug",
                                headers=headers, json={"slug": "api"})
        assert reserved.status_code == 400
        assert "reserved" in reserved.json()["detail"]

        cleared = client.patch("/api/v1/tenant/settings/slug",
                               headers=headers, json={"slug": None})
        assert cleared.status_code == 200
        assert cleared.json()["slug"] is None
        assert cleared.json()["portal_url"] is None
    finally:
        _cleanup(factory, tenant_id)


@pgmark
def test_db_check_constraint_backstops_a_bad_slug() -> None:
    """App validation can be bypassed by a direct write; the constraint
    cannot. A slug with a dot would silently extend the subdomain."""

    factory = _factory()
    tenant_id, _op_id = _seed(factory)
    try:
        with factory() as s:
            with pytest.raises(Exception) as exc:
                s.execute(
                    text("UPDATE tenants SET slug = 'bad.slug' WHERE id = :i"),
                    {"i": tenant_id},
                )
                s.commit()
            assert "tenants_slug_format_check" in str(exc.value)
            s.rollback()
    finally:
        _cleanup(factory, tenant_id)


@pgmark
def test_tenant_from_host_reads_the_row() -> None:
    factory = _factory()
    tenant_id, _op_id = _seed(factory, slug="acme")
    try:
        with factory() as s:
            found = tenant_from_host(
                s, host="acme.gateway.example.com:443", base_domain=BASE
            )
            assert found is not None and found.id == tenant_id
            assert tenant_from_host(s, host="nope." + BASE, base_domain=BASE) is None
    finally:
        _cleanup(factory, tenant_id)
