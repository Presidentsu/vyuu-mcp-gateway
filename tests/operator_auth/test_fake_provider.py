from uuid import uuid4

import pytest

from vyuu_gateway.operator_auth.fake import FakeOperatorAuthProvider, mint_operator_test_token
from vyuu_gateway.operator_auth.provider import OperatorAuthError


def test_round_trip_signed_token() -> None:
    tenant_id = uuid4()
    operator_id = uuid4()
    token = mint_operator_test_token(
        tenant_id=tenant_id,
        operator_id=operator_id,
        display="Acme Admin",
        signing_secret="test-secret",
    )

    operator = FakeOperatorAuthProvider(signing_secret="test-secret").authenticate(token)

    assert operator.tenant_id == tenant_id
    assert operator.operator_id == operator_id
    assert operator.display == "Acme Admin"


def test_token_signed_with_different_secret_is_rejected() -> None:
    token = mint_operator_test_token(
        tenant_id=uuid4(),
        operator_id=uuid4(),
        signing_secret="other-secret",
    )

    with pytest.raises(OperatorAuthError):
        FakeOperatorAuthProvider(signing_secret="test-secret").authenticate(token)


def test_malformed_token_is_rejected() -> None:
    with pytest.raises(OperatorAuthError):
        FakeOperatorAuthProvider(signing_secret="test-secret").authenticate("no-dot-here")


def test_token_with_tampered_payload_is_rejected() -> None:
    token = mint_operator_test_token(
        tenant_id=uuid4(),
        operator_id=uuid4(),
        signing_secret="test-secret",
    )
    tampered = "X" + token[1:]

    with pytest.raises(OperatorAuthError):
        FakeOperatorAuthProvider(signing_secret="test-secret").authenticate(tampered)


def test_token_with_invalid_uuid_payload_is_rejected() -> None:
    # Mint a syntactically-valid token whose payload has bad UUIDs.
    import base64
    import hashlib
    import hmac
    import json

    secret = b"test-secret"
    bad_payload = {
        "tenant_id": "not-a-uuid",
        "operator_id": str(uuid4()),
    }
    encoded_payload = base64.urlsafe_b64encode(
        json.dumps(bad_payload).encode("utf-8")
    ).decode("ascii").rstrip("=")
    signature = hmac.new(secret, encoded_payload.encode("utf-8"), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    token = f"{encoded_payload}.{encoded_signature}"

    with pytest.raises(OperatorAuthError):
        FakeOperatorAuthProvider(signing_secret="test-secret").authenticate(token)


def test_token_missing_required_fields_is_rejected() -> None:
    import base64
    import hashlib
    import hmac
    import json

    secret = b"test-secret"
    incomplete_payload = {"tenant_id": str(uuid4())}  # missing operator_id
    encoded_payload = base64.urlsafe_b64encode(
        json.dumps(incomplete_payload).encode("utf-8")
    ).decode("ascii").rstrip("=")
    signature = hmac.new(secret, encoded_payload.encode("utf-8"), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    token = f"{encoded_payload}.{encoded_signature}"

    with pytest.raises(OperatorAuthError):
        FakeOperatorAuthProvider(signing_secret="test-secret").authenticate(token)


def test_display_defaults_to_empty_when_not_a_string() -> None:
    import base64
    import hashlib
    import hmac
    import json

    secret = b"test-secret"
    payload = {
        "tenant_id": str(uuid4()),
        "operator_id": str(uuid4()),
        "display": 12345,  # non-string falls back to empty
    }
    encoded_payload = base64.urlsafe_b64encode(
        json.dumps(payload).encode("utf-8")
    ).decode("ascii").rstrip("=")
    signature = hmac.new(secret, encoded_payload.encode("utf-8"), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    token = f"{encoded_payload}.{encoded_signature}"

    operator = FakeOperatorAuthProvider(signing_secret="test-secret").authenticate(token)

    assert operator.display == ""
