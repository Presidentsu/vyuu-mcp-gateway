import base64
import hashlib
import hmac
import json
from typing import Any
from uuid import UUID

from vyuu_gateway.identity.models import Principal, PrincipalType, principal_from_type
from vyuu_gateway.identity.provider import (
    IdentityCredentials,
    IdentityProvider,
    IdentityValidationError,
)


class FakeIdentityProvider(IdentityProvider):
    """Test identity provider supporting signed test tokens and explicit mock headers."""

    def __init__(
        self,
        *,
        signing_secret: str = "test-secret",
        allow_mock_headers: bool = True,
    ) -> None:
        self._signing_secret = signing_secret.encode("utf-8")
        self._allow_mock_headers = allow_mock_headers

    def validate_principal(
        self,
        *,
        tenant_id: UUID,
        credentials: IdentityCredentials,
    ) -> Principal:
        headers = _normalize_headers(credentials.headers)
        authorization = headers.get("authorization")
        if authorization is not None and authorization.startswith("Bearer "):
            return self._validate_signed_token(tenant_id, authorization.removeprefix("Bearer "))

        if self._allow_mock_headers:
            return _principal_from_mock_headers(tenant_id, headers)

        raise IdentityValidationError("missing supported identity credentials")

    def _validate_signed_token(self, tenant_id: UUID, token: str) -> Principal:
        try:
            encoded_payload, encoded_signature = token.split(".", maxsplit=1)
        except ValueError as exc:
            raise IdentityValidationError("malformed test token") from exc

        expected_signature = _sign(encoded_payload, self._signing_secret)
        if not hmac.compare_digest(encoded_signature, expected_signature):
            raise IdentityValidationError("invalid test token signature")

        try:
            payload = json.loads(_b64decode(encoded_payload).decode("utf-8"))
            token_tenant_id = UUID(payload["tenant_id"])
            principal_type = PrincipalType(payload["type"])
            principal_id = payload["id"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IdentityValidationError("invalid test token payload") from exc

        if token_tenant_id != tenant_id:
            raise IdentityValidationError("principal tenant mismatch")

        return principal_from_type(
            principal_type=principal_type,
            tenant_id=tenant_id,
            principal_id=principal_id,
            display=_string_or_empty(payload.get("display")),
        )

    def sign_test_token(
        self,
        *,
        tenant_id: UUID,
        principal_type: PrincipalType,
        principal_id: str,
        display: str = "",
    ) -> str:
        return sign_test_token(
            tenant_id=tenant_id,
            principal_type=principal_type,
            principal_id=principal_id,
            display=display,
            signing_secret=self._signing_secret.decode("utf-8"),
        )


def sign_test_token(
    *,
    tenant_id: UUID,
    principal_type: PrincipalType,
    principal_id: str,
    display: str = "",
    signing_secret: str = "test-secret",
) -> str:
    payload = {
        "tenant_id": str(tenant_id),
        "type": principal_type.value,
        "id": principal_id,
        "display": display,
    }
    encoded_payload = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    encoded_signature = _sign(encoded_payload, signing_secret.encode("utf-8"))
    return f"{encoded_payload}.{encoded_signature}"


def _principal_from_mock_headers(tenant_id: UUID, headers: dict[str, str]) -> Principal:
    try:
        principal_type = PrincipalType(headers["x-vyuu-principal-type"])
        principal_id = headers["x-vyuu-principal-id"]
    except KeyError as exc:
        raise IdentityValidationError("missing mock identity headers") from exc
    except ValueError as exc:
        raise IdentityValidationError("invalid mock principal type") from exc

    header_tenant_id = headers.get("x-vyuu-tenant-id")
    try:
        if header_tenant_id is not None and UUID(header_tenant_id) != tenant_id:
            raise IdentityValidationError("principal tenant mismatch")
    except ValueError as exc:
        raise IdentityValidationError("invalid mock tenant id") from exc

    return principal_from_type(
        principal_type=principal_type,
        tenant_id=tenant_id,
        principal_id=principal_id,
        display=headers.get("x-vyuu-principal-display", ""),
    )


def _normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


def _sign(encoded_payload: str, secret: bytes) -> str:
    signature = hmac.new(secret, encoded_payload.encode("utf-8"), hashlib.sha256).digest()
    return _b64encode(signature)


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(encoded: str) -> bytes:
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded + padding)


def _string_or_empty(value: Any) -> str:
    return value if isinstance(value, str) else ""
