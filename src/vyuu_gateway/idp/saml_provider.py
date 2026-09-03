"""SAML 2.0 SP wrapper for per-directory sign-in.

Phase 4b of IDP-1. Wraps `pysaml2` so the FastAPI route layer can
build login redirects + parse SAML responses without touching the
XML directly. Signature validation, NameID parsing, and metadata
serialization all delegate to `pysaml2.client.Saml2Client`.

**Deployment note**: pysaml2 shells out to the `xmlsec1` system
binary for signature operations. Production hosts need
`xmlsec1` + `libxml2` installed at the OS layer (
`brew install libxmlsec1` on macOS,
`apt-get install xmlsec1 libxml2-dev` on Debian/Ubuntu,
the `libxmlsec1` package on Alpine via `apk add libxmlsec1`).
The Python wheel doesn't bundle the binary.

The wrapper is intentionally minimal — IDP-1 needs:

1. **`prepare_login(state)`** → returns the IdP redirect URL. The
   `state` string is round-tripped through SAML's `RelayState`
   parameter so we can validate `tenant.directory.<nonce>` on the
   way back, same shape as the OIDC flow.
2. **`parse_response(saml_response_b64)`** → validates the IdP's
   signature against the directory's stored cert + extracts the
   NameID + attributes.
3. **`metadata_xml()`** → SP metadata the admin pastes into Entra /
   Workspace's "SAML application" config so they know our entity
   id, ACS URL, and supported NameID format.

We don't sign the AuthnRequest. Most IdPs don't require it for basic
SP-initiated flows, and the SP signing-key surface area (key
generation, rotation, cert distribution) isn't worth the complexity
when IdP-side metadata + ACS-URL pinning already covers the threat
model. If a future tenant insists on signed requests we add the SP
key as a backlog enhancement.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.metadata import entity_descriptor

if TYPE_CHECKING:
    from saml2.response import AuthnResponse

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SamlLoginResult:
    """Validated SAML response distilled to the bits we persist.

    `name_id` is the IdP's stable subject identifier (Entra
    `objectId`, Workspace `id`) — the same value SCIM puts into
    `users.external_id`, so the post-callback lookup matches.
    """

    name_id: str
    email: str
    display_name: str | None
    raw_attributes: dict[str, Any]


class SamlValidationError(Exception):
    """SAML response failed signature / replay / time-window checks.

    Detail is intentionally generic at the API surface — we don't
    want to leak which sub-check failed to a probing client.
    """


class SamlProvider:
    """Per-directory SAML SP wrapper.

    Construct one of these per HTTP request from the directory's
    stored config. The underlying `Saml2Client` is cheap to build
    (no I/O on init) so we don't bother caching across requests."""

    def __init__(
        self,
        *,
        sp_entity_id: str,
        sp_acs_url: str,
        idp_entity_id: str,
        idp_sso_url: str,
        idp_certificate_pem: str,
    ) -> None:
        self._sp_entity_id = sp_entity_id
        self._sp_acs_url = sp_acs_url
        self._idp_entity_id = idp_entity_id
        self._idp_sso_url = idp_sso_url
        self._idp_certificate_pem = idp_certificate_pem
        self._client = self._build_client()

    def prepare_login(self, *, state: str) -> str:
        """Build the IdP redirect URL for an SP-initiated login.

        Returns the full URL the SP should 302 the browser to.
        `state` is round-tripped via `RelayState` — pysaml2's
        `prepare_for_authenticate` doesn't expose it directly so we
        synthesise it here.
        """

        request_id, info = self._client.prepare_for_authenticate(
            entityid=self._idp_entity_id,
            relay_state=state,
            binding=BINDING_HTTP_REDIRECT,
        )
        del request_id  # we route via RelayState; pysaml2 caches it internally
        for header_name, header_value in info["headers"]:
            if header_name == "Location":
                return header_value
        # Fallback — shouldn't happen for HTTP-Redirect bindings.
        raise SamlValidationError("pysaml2 did not return a Location header")

    def parse_response(self, saml_response_b64: str) -> SamlLoginResult:
        """Validate + extract claims from a base64 SAMLResponse.

        Translates pysaml2's various exception types into
        `SamlValidationError`. The route layer surfaces all of them
        as `401`."""

        try:
            response: AuthnResponse | None = self._client.parse_authn_request_response(
                saml_response_b64,
                BINDING_HTTP_POST,
                outstanding=None,  # we don't dedup requests; RelayState carries state
            )
        except Exception as exc:  # noqa: BLE001 — pysaml2 raises a zoo of types
            raise SamlValidationError(str(exc)) from exc
        if response is None:
            raise SamlValidationError("empty response from IdP")
        return _to_login_result(response)

    def metadata_xml(self) -> str:
        """SP metadata XML — the admin pastes this into Entra /
        Workspace's app-config so the IdP knows our entity id, ACS
        URL, and supported NameID format."""

        return entity_descriptor(self._client.config).to_string().decode("utf-8")

    def _build_client(self) -> Saml2Client:
        # pysaml2's Config can be loaded from a dict in the same shape
        # as its example YAML. We construct it inline rather than
        # writing a temp file because the IdP cert + URLs are per-
        # directory and rotating them shouldn't touch the filesystem.
        sp_config = SPConfig()
        sp_config.load(
            {
                "entityid": self._sp_entity_id,
                "metadata": {
                    "inline": [_inline_idp_metadata(
                        idp_entity_id=self._idp_entity_id,
                        idp_sso_url=self._idp_sso_url,
                        idp_certificate_pem=self._idp_certificate_pem,
                    )],
                },
                "service": {
                    "sp": {
                        "name": "Vyuu MCP Gateway",
                        "endpoints": {
                            "assertion_consumer_service": [
                                (self._sp_acs_url, BINDING_HTTP_POST),
                            ],
                        },
                        # Don't sign requests — most IdPs don't require
                        # it for SP-initiated SSO and the key-management
                        # cost isn't worth it for IDP-1.
                        "authn_requests_signed": False,
                        # IdP-side response signature is REQUIRED.
                        # pysaml2 enforces this when we hand it the
                        # cert via metadata.
                        "want_response_signed": True,
                        # We don't require a signed assertion in
                        # addition to the signed response — Entra
                        # signs the response wrapper, Workspace signs
                        # the assertion. Accepting either is enough
                        # given pysaml2's signature-coverage check.
                        "want_assertions_signed": False,
                        # Accept SAML responses that don't correspond
                        # to a tracked outgoing AuthnRequest. This is
                        # mandatory for IdP-initiated flow (Google's
                        # "Test SAML Login" button, app launcher in
                        # Gmail/Drive, Workspace's daily app-tile
                        # click). Replay protection comes from the
                        # NotOnOrAfter window + signature check, not
                        # from request/response correlation. Cross-
                        # directory defence comes from the signed
                        # Audience element pinned to our per-directory
                        # entity_id.
                        "allow_unsolicited": True,
                        "name_id_format": [
                            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                        ],
                    },
                },
                # We accept clock skew up to 60s in either direction
                # on NotBefore / NotOnOrAfter checks. Larger windows
                # weaken replay defence; smaller ones cause flaky
                # logins on slightly drifted IdP clocks.
                "accepted_time_diff": 60,
            }
        )
        return Saml2Client(sp_config)


def _to_login_result(response: AuthnResponse) -> SamlLoginResult:
    """Distil a validated `AuthnResponse` to the bits we persist.

    We pull the email from common attribute names that Entra and
    Workspace ship by default. Falls back to `name_id.text` if the
    IdP only sent a NameID-as-email."""

    name_id = response.name_id.text if response.name_id else None
    if not name_id:
        raise SamlValidationError("response carries no NameID")

    attrs = response.ava or {}

    email = (
        _first(attrs.get("email"))
        or _first(attrs.get("emailAddress"))
        or _first(
            attrs.get(
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
            )
        )
        or (name_id if "@" in name_id else None)
    )
    if not email:
        raise SamlValidationError("could not extract email from response")

    display_name = (
        _first(attrs.get("displayName"))
        or _first(attrs.get("name"))
        or _first(attrs.get("cn"))
    )

    return SamlLoginResult(
        name_id=name_id,
        email=email,
        display_name=display_name,
        raw_attributes=dict(attrs),
    )


def _first(value: Any) -> str | None:
    """SAML attribute values are lists per the spec; squash to first
    element if it's a list of strings."""

    if value is None:
        return None
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value)


def _inline_idp_metadata(
    *,
    idp_entity_id: str,
    idp_sso_url: str,
    idp_certificate_pem: str,
) -> str:
    """Build a minimal IdP metadata XML so pysaml2 can register the
    IdP without us writing a metadata file to disk.

    The cert is the X.509 PEM body (between `-----BEGIN/END
    CERTIFICATE-----`) — we strip the headers + base64 it as
    `<ds:X509Certificate>` per the SAML metadata spec.
    """

    cert_body = _strip_pem_headers(idp_certificate_pem)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                  entityID="{idp_entity_id}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>{cert_body}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                         Location="{idp_sso_url}"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                         Location="{idp_sso_url}"/>
  </IDPSSODescriptor>
</EntityDescriptor>
"""


def _strip_pem_headers(pem: str) -> str:
    """Extract the base64 body of a PEM cert. Tolerant of CRLF +
    whitespace; rejects anything that doesn't look like valid base64
    after stripping."""

    body_lines: list[str] = []
    in_body = False
    for line in pem.splitlines():
        stripped = line.strip()
        if stripped.startswith("-----BEGIN"):
            in_body = True
            continue
        if stripped.startswith("-----END"):
            in_body = False
            continue
        if in_body and stripped:
            body_lines.append(stripped)
    body = "".join(body_lines)
    if not body:
        raise SamlValidationError("PEM body is empty after header strip")
    # Validate base64 — surface a clean error before pysaml2 chokes.
    try:
        base64.b64decode(body, validate=True)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise SamlValidationError("PEM body is not valid base64") from exc
    return body
