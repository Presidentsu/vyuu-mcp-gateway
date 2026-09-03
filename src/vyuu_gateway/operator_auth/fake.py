"""Test/dev operator-API auth provider using HMAC-signed bearer tokens.

Token format: `<base64url(json_payload)>.<base64url(hmac_sha256(payload))>`
Payload fields: `tenant_id` (uuid), `operator_id` (uuid), `display` (str).

Constant-time signature comparison is used. This is *not* a production
auth provider — it has no key rotation, no expiry, no audience binding,
and a globally-shared HMAC secret. It exists to let tests and local-dev
exercise the same interface that a real OIDC/API-key provider will satisfy.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any
from uuid import UUID

from vyuu_gateway.operator_auth.models import AuthenticatedOperator
from vyuu_gateway.operator_auth.provider import OperatorAuthError, OperatorAuthProvider


class FakeOperatorAuthProvider(OperatorAuthProvider):
    def __init__(self, *, signing_secret: str) -> None:
        self._signing_secret = signing_secret.encode("utf-8")

    def authenticate(self, token: str) -> AuthenticatedOperator:
        try:
            encoded_payload, encoded_signature = token.split(".", maxsplit=1)
        except ValueError as exc:
            raise OperatorAuthError("malformed bearer token") from exc

        expected_signature = _sign(encoded_payload, self._signing_secret)
        if not hmac.compare_digest(encoded_signature, expected_signature):
            raise OperatorAuthError("invalid bearer token signature")

        try:
            payload = json.loads(_b64decode(encoded_payload).decode("utf-8"))
            tenant_id = UUID(payload["tenant_id"])
            operator_id = UUID(payload["operator_id"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise OperatorAuthError("invalid bearer token payload") from exc

        return AuthenticatedOperator(
            tenant_id=tenant_id,
            operator_id=operator_id,
            display=_string_or_empty(payload.get("display")),
        )


def mint_operator_test_token(
    *,
    tenant_id: UUID,
    operator_id: UUID,
    display: str = "",
    signing_secret: str,
) -> str:
    payload = {
        "tenant_id": str(tenant_id),
        "operator_id": str(operator_id),
        "display": display,
    }
    encoded_payload = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    encoded_signature = _sign(encoded_payload, signing_secret.encode("utf-8"))
    return f"{encoded_payload}.{encoded_signature}"


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
