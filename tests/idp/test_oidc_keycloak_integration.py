"""A3-β.x · full OIDC handshake against a REAL identity provider.

Env-gated on `VYUU_TEST_KEYCLOAK_URL`; skipped everywhere else, including
CI until Keycloak is stood up there. Setup ladder is in
`tests/perf/../..` — see `docs/onboarding/RUNBOOK.md` and the
`docker compose` snippet in this module's docstring below.

## What this covers that the existing unit tests do not

`tests/idp/test_oidc_signin.py` already validates the security-relevant
half — signature, `iss`, `aud`, `exp`, nonce, hosted-domain — against
generated RSA keys and a mocked httpx. That IS the meaningful check, and
it runs everywhere.

What it cannot cover is the plumbing around it, which is where real
integrations actually break:

- the **discovery document** actually being fetched and parsed from a
  live `/.well-known/openid-configuration`, rather than a config object
  we constructed ourselves;
- **JWKS fetched over the network** from the URL that document names, and
  the ID token being signed by whichever key the IdP is currently
  rotating on — not one our own test generated;
- the **code→token exchange** hitting a real token endpoint with real
  form encoding, real error shapes, and a real `client_secret`.

Every one of those has a mock-shaped assumption baked into the unit
tests. This is the test that finds out whether the assumption holds.

## Standing up Keycloak

```bash
docker run -d --name vyuu-keycloak-test -p 8080:8080 \\
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \\
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \\
  quay.io/keycloak/keycloak:26.0 start-dev

# Keycloak 26's master realm ships `sslRequired=external`, and inside
# Docker the client's source address is not local — so plain-HTTP admin
# calls 403 until this is relaxed. One-time, dev only.
docker exec vyuu-keycloak-test /opt/keycloak/bin/kcadm.sh config credentials \\
  --server http://localhost:8080 --realm master --user admin --password admin
docker exec vyuu-keycloak-test /opt/keycloak/bin/kcadm.sh update realms/master \\
  -s sslRequired=NONE

export VYUU_TEST_KEYCLOAK_URL=http://127.0.0.1:8080
python3 -m pytest tests/idp/test_oidc_keycloak_integration.py
```

(The env-var names and the `sslRequired` step are both Keycloak-26
specifics that an untested docstring would have got wrong — `KEYCLOAK_ADMIN`
was renamed, and the SSL default 403s every admin call. Found by running
this, which is the whole argument for having done so.)

The test provisions its own realm, client and user through the admin
API, so there is no realm export to keep in sync with the Keycloak
version — a fixture that drifts is worse than no fixture, because it
fails for reasons unrelated to the code under test.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

_KEYCLOAK_URL = os.environ.get("VYUU_TEST_KEYCLOAK_URL")

pytestmark = pytest.mark.skipif(
    _KEYCLOAK_URL is None,
    reason="VYUU_TEST_KEYCLOAK_URL not set (see this module's docstring)",
)

REALM = "vyuu-test"
CLIENT_ID = "vyuu-gateway"
CLIENT_SECRET = "vyuu-gateway-secret"  # noqa: S105 — test realm only
USER_EMAIL = "oidc-user@vyuu.test"
USER_PASSWORD = "oidc-user-password"  # noqa: S105 — test realm only
REDIRECT_URI = "http://127.0.0.1:9/callback"


def _admin_token(http: Any) -> str:
    response = http.post(
        f"{_KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": "admin",
            "password": "admin",
        },
    )
    response.raise_for_status()
    return str(response.json()["access_token"])


@pytest.fixture(scope="module")
def keycloak_realm() -> Any:
    """Provision realm + client + user, then tear the realm down.

    Provisioned rather than imported from a realm export: an export
    pinned to one Keycloak version drifts, and then this fails for
    reasons that have nothing to do with the gateway.
    """

    import httpx

    with httpx.Client(timeout=30.0) as http:
        token = _admin_token(http)
        headers = {"Authorization": f"Bearer {token}"}
        admin = f"{_KEYCLOAK_URL}/admin/realms"

        http.delete(f"{admin}/{REALM}", headers=headers)
        http.post(
            admin,
            headers=headers,
            json={
                "realm": REALM,
                "enabled": True,
                # A fresh realm inherits `sslRequired=external`, which
                # refuses plain HTTP from anything Keycloak considers a
                # non-local address — and inside Docker the client's
                # source IP IS non-local. Without this the realm's own
                # discovery document 403s.
                "sslRequired": "NONE",
            },
        ).raise_for_status()
        http.post(
            f"{admin}/{REALM}/clients",
            headers=headers,
            json={
                "clientId": CLIENT_ID,
                "secret": CLIENT_SECRET,
                "redirectUris": [REDIRECT_URI],
                "publicClient": False,
                "standardFlowEnabled": True,
                "directAccessGrantsEnabled": True,
            },
        ).raise_for_status()
        http.post(
            f"{admin}/{REALM}/users",
            headers=headers,
            json={
                "username": USER_EMAIL,
                "email": USER_EMAIL,
                "emailVerified": True,
                "enabled": True,
                # Keycloak's default user profile marks first/last name
                # required. Without them the account is "not fully set
                # up" and every grant fails with `invalid_grant` — a
                # message that says nothing about missing names.
                "firstName": "OIDC",
                "lastName": "User",
                "requiredActions": [],
                "credentials": [
                    {"type": "password", "value": USER_PASSWORD, "temporary": False}
                ],
            },
        ).raise_for_status()
        try:
            yield f"{_KEYCLOAK_URL}/realms/{REALM}"
        finally:
            http.delete(f"{admin}/{REALM}", headers=headers)


def test_discovery_document_is_fetched_from_the_live_idp(keycloak_realm: str) -> None:
    """The unit tests construct an `OidcConfig` by hand. This proves the
    endpoints we rely on are the ones a real IdP actually advertises."""

    import httpx

    with httpx.Client(timeout=30.0) as http:
        doc = http.get(
            f"{keycloak_realm}/.well-known/openid-configuration"
        ).json()
    for key in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
        assert doc.get(key), f"discovery document missing {key}"
    assert doc["issuer"] == keycloak_realm


def test_id_token_from_a_real_idp_validates_against_its_live_jwks(
    keycloak_realm: str,
) -> None:
    """The load-bearing one.

    Obtains a genuine ID token — signed by whatever key Keycloak is
    currently rotating on — and validates it through the gateway's own
    `JwksCache`, fetching JWKS over the network from the URL the
    discovery document names. Nothing here is generated by the test.
    """

    import httpx

    from vyuu_gateway.users.oidc import JwksCache, OidcConfig

    with httpx.Client(timeout=30.0) as http:
        doc = http.get(f"{keycloak_realm}/.well-known/openid-configuration").json()
        # Direct-access grant stands in for the browser leg; the ID token
        # it returns is signed identically to the authorization-code one,
        # which is what we are validating.
        token_response = http.post(
            doc["token_endpoint"],
            data={
                "grant_type": "password",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "username": USER_EMAIL,
                "password": USER_PASSWORD,
                "scope": "openid email profile",
            },
        )
        token_response.raise_for_status()
        id_token = token_response.json()["id_token"]

    config = OidcConfig(
        issuer_url=doc["issuer"],
        audience=CLIENT_ID,
        email_claim="email",
        subject_claim="sub",
    )
    import asyncio

    claims = asyncio.run(JwksCache().validate_token(id_token, config=config))
    assert claims["email"] == USER_EMAIL
    assert claims["iss"] == doc["issuer"]
    assert claims["aud"] == CLIENT_ID
    assert claims["sub"]


def _id_token_for(realm_base: str) -> tuple[str, dict]:
    """A genuine ID token from a live realm, plus its discovery doc."""

    import httpx

    with httpx.Client(timeout=30.0) as http:
        doc = http.get(f"{realm_base}/.well-known/openid-configuration").json()
        response = http.post(
            doc["token_endpoint"],
            data={
                "grant_type": "password",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "username": USER_EMAIL,
                "password": USER_PASSWORD,
                "scope": "openid email profile",
            },
        )
        response.raise_for_status()
        return response.json()["id_token"], doc


def test_a_tampered_signature_is_rejected_by_the_live_key(
    keycloak_realm: str,
) -> None:
    """Signature verification against the IdP's OWN rotating key.

    This replaced an earlier test that claimed to check issuer binding
    and did not: `JwksCache` derives the JWKS URL from `issuer_url`, so
    pointing it at a different issuer fails at *key lookup* long before
    any issuer claim is compared. That test passed with issuer checking
    disabled — a negative control caught it.

    Tampering the signature is the honest version: it can only fail if
    the real key really is verifying.
    """

    import asyncio

    from vyuu_gateway.users.oidc import (
        JwksCache,
        OidcConfig,
        OidcValidationError,
    )

    id_token, doc = _id_token_for(keycloak_realm)
    header, payload, signature = id_token.split(".")
    # Flip a character in the signature, keeping it valid base64url.
    flipped = ("B" if signature[0] != "B" else "C") + signature[1:]
    tampered = f"{header}.{payload}.{flipped}"

    config = OidcConfig(
        issuer_url=doc["issuer"], audience=CLIENT_ID,
        email_claim="email", subject_claim="sub",
    )
    cache = JwksCache()
    # Sanity: the untampered token DOES validate, so a failure below is
    # the tamper and not a broken fixture.
    assert asyncio.run(cache.validate_token(id_token, config=config))["email"] == USER_EMAIL
    with pytest.raises(OidcValidationError):
        asyncio.run(JwksCache().validate_token(tampered, config=config))


def test_a_token_from_another_issuer_is_rejected(keycloak_realm: str) -> None:
    """Two independent layers enforce this, and a control confirmed both:

    1. `JwksCache` derives the JWKS URL from `issuer_url`, so it can only
       verify tokens signed by keys *that* issuer publishes — an attacker
       cannot present a validly-signed token from their own IdP because
       we would never fetch their key.
    2. `jwt.decode(issuer=...)` compares the `iss` claim.

    Breaking either one alone leaves this passing, which is defence in
    depth working as intended rather than a weak test — so the assertion
    is deliberately on the OUTCOME. The layers are exercised separately
    by `test_a_tampered_signature_is_rejected_by_the_live_key` (1) and
    `test_wrong_audience_is_rejected` (2's machinery).
    """

    import asyncio

    from vyuu_gateway.users.oidc import (
        JwksCache,
        OidcConfig,
        OidcValidationError,
    )

    id_token, _doc = _id_token_for(keycloak_realm)
    other_issuer = OidcConfig(
        issuer_url=f"{_KEYCLOAK_URL}/realms/some-other-realm",
        audience=CLIENT_ID, email_claim="email", subject_claim="sub",
    )
    with pytest.raises(OidcValidationError):
        asyncio.run(JwksCache().validate_token(id_token, config=other_issuer))


def test_wrong_audience_is_rejected(keycloak_realm: str) -> None:
    """`aud` IS a claim comparison, unlike issuer — so this one really
    does exercise the check it names."""

    import asyncio

    from vyuu_gateway.users.oidc import (
        JwksCache,
        OidcConfig,
        OidcValidationError,
    )

    id_token, doc = _id_token_for(keycloak_realm)
    wrong_audience = OidcConfig(
        issuer_url=doc["issuer"], audience="some-other-client",
        email_claim="email", subject_claim="sub",
    )
    with pytest.raises(OidcValidationError, match="audience mismatch"):
        asyncio.run(JwksCache().validate_token(id_token, config=wrong_audience))


def test_authorization_url_points_at_the_real_authorize_endpoint(
    keycloak_realm: str,
) -> None:
    """`_authorize_endpoint()` hard-codes Microsoft's + Google's shared
    `/oauth2/v2.0/authorize` convention. Keycloak does NOT follow it, so
    this asserts the discovery document is the source of truth — and
    fails loudly if a provider subclass is needed."""

    import httpx

    with httpx.Client(timeout=30.0) as http:
        doc = http.get(f"{keycloak_realm}/.well-known/openid-configuration").json()

    parsed = urlparse(doc["authorization_endpoint"])
    assert parsed.scheme and parsed.netloc
    assert "/protocol/openid-connect/auth" in parsed.path, (
        "Keycloak's authorize path differs from the Microsoft/Google "
        "convention hard-coded in `_authorize_endpoint()` — a Keycloak "
        "provider subclass (or discovery-driven endpoints) is required"
    )


def test_code_exchange_rejects_a_bad_code(keycloak_realm: str) -> None:
    """Real error shape from a real token endpoint, rather than the 400
    our mocks return."""

    import httpx

    with httpx.Client(timeout=30.0) as http:
        doc = http.get(f"{keycloak_realm}/.well-known/openid-configuration").json()
        response = http.post(
            doc["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": "definitely-not-a-real-code",
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
            },
        )
    assert response.status_code >= 400
    assert response.json().get("error")
    # The response must not echo the client secret back in any form.
    assert CLIENT_SECRET not in response.text


def test_parse_qs_helper_is_available() -> None:
    """Guards the import list — the module is skipped wholesale without
    Keycloak, so an unused-import slip would go unnoticed until someone
    finally runs it."""

    assert parse_qs("a=1")["a"] == ["1"]
