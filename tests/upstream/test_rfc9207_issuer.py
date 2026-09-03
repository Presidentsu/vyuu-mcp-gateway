"""MCP-2 P3 · RFC 9207 — Authorization Server Issuer Identification.

**The attack this closes.** A client that talks to more than one
authorization server can be induced to send a code it received from a
*malicious* AS to an *honest* AS's token endpoint (or the reverse). Each
individual check still passes: the `state` is ours and validates, PKCE
validates, the code is well-formed. Nothing in a pre-9207 authorization
response says *which* AS produced it.

RFC 9207 closes it by having the AS echo its own `iss`, and the client
compare it against the AS it actually sent the user to. We capture that
expectation into the signed `state` at initiate time — not re-derived at
callback time, because the state is precisely the thing that ties a
response to a request.

The behaviour under absence is a judgement call and is tested explicitly:
a missing `iss` is accepted with a log line, because most static OAuth
providers we front publish no metadata at all, and rejecting would break
every one of them without stopping an attacker — who can simply omit the
parameter too.
"""

from __future__ import annotations

import pytest

from vyuu_gateway.api.oauth_authcode import (
    Rfc9207ViolationError,
    _expected_issuer,
    validate_authorization_response_issuer,
)

# --- Expectation capture ----------------------------------------------------


@pytest.mark.parametrize(
    ("authorize_url", "expected"),
    [
        ("https://github.com/login/oauth/authorize", "https://github.com"),
        ("https://accounts.google.com/o/oauth2/v2/auth", "https://accounts.google.com"),
        # Case and port are normalised so comparison is not accidentally
        # case-sensitive against a provider that varies them.
        ("HTTPS://GitHub.com/login", "https://github.com"),
        ("https://idp.example:8443/authorize", "https://idp.example:8443"),
    ],
)
def test_expected_issuer_is_the_authorization_endpoint_origin(
    authorize_url: str, expected: str
) -> None:
    assert _expected_issuer(authorize_url) == expected


@pytest.mark.parametrize("bad", ["", "not-a-url", "/relative/path", "mailto:x@y.z"])
def test_unparseable_authorize_url_yields_no_expectation(bad: str) -> None:
    """Downgrades to "cannot validate", never to "reject everything" — a
    parse failure on our side must not lock users out of a working
    provider."""

    assert _expected_issuer(bad) is None


# --- The attack -------------------------------------------------------------


def test_mismatched_issuer_is_refused() -> None:
    """The mix-up signature. We sent the user to GitHub; something else
    answered. There is no benign reading of that."""

    with pytest.raises(Rfc9207ViolationError) as exc:
        validate_authorization_response_issuer(
            received_iss="https://evil.example",
            expected_iss="https://github.com",
        )
    # The operator-facing message names the situation without leaking
    # the code or any token material.
    assert "mix-up" in str(exc.value)
    assert "code" not in str(exc.value).lower().split("connection")[0]


@pytest.mark.parametrize(
    "received",
    [
        "https://evil.example",
        # Look-alikes: each of these passes a naive substring or prefix
        # check against "https://github.com".
        "https://github.com.evil.example",
        "https://evil.example/https://github.com",
        "https://github.evil.example",
        "http://github.com",          # scheme downgrade
        "https://github.com:8443",    # different port is a different origin
    ],
)
def test_lookalike_issuers_are_refused(received: str) -> None:
    with pytest.raises(Rfc9207ViolationError):
        validate_authorization_response_issuer(
            received_iss=received, expected_iss="https://github.com"
        )


def test_matching_issuer_passes() -> None:
    validate_authorization_response_issuer(
        received_iss="https://github.com", expected_iss="https://github.com"
    )


def test_issuer_with_a_path_still_matches_on_origin() -> None:
    """An AS's issuer identifier is whatever its metadata says, and some
    publish `https://host/tenant`. We compare origins, because the
    mix-up attack necessarily involves a *different origin* — the attack
    IS that another server answered."""

    validate_authorization_response_issuer(
        received_iss="https://login.microsoftonline.com/contoso/v2.0",
        expected_iss="https://login.microsoftonline.com",
    )


# --- Absence ----------------------------------------------------------------


def test_absent_issuer_is_accepted_deliberately() -> None:
    """Most static OAuth providers we front publish no metadata and never
    send `iss`. Rejecting here would break all of them and stop no
    attacker — who can omit the parameter just as easily."""

    validate_authorization_response_issuer(
        received_iss=None, expected_iss="https://github.com"
    )


def test_no_expectation_means_nothing_to_compare() -> None:
    validate_authorization_response_issuer(
        received_iss="https://anything.example", expected_iss=None
    )
    validate_authorization_response_issuer(received_iss=None, expected_iss=None)


def test_unparseable_received_issuer_is_refused_when_we_expected_one() -> None:
    """Garbage where an issuer should be is not a benign legacy AS — it
    is an AS claiming an identity we cannot verify."""

    with pytest.raises(Rfc9207ViolationError):
        validate_authorization_response_issuer(
            received_iss="not-a-url", expected_iss="https://github.com"
        )
