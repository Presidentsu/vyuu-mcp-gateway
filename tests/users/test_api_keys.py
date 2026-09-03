"""Unit tests for API-key generation, parsing, and verification."""

from __future__ import annotations

from uuid import uuid4

import pytest

from vyuu_gateway.users.api_keys import (
    KEY_PREFIX_PUBLIC_LEN,
    MalformedApiKeyError,
    issue_new_key,
    parse_bearer,
    verify_secret,
)


def test_issue_format() -> None:
    """Plaintext shape: vyuu_user_<26-char-id>_<43+-char-secret>."""
    key_id = uuid4()
    issued = issue_new_key(key_id=key_id)
    assert issued.plaintext.startswith("vyuu_user_")
    parts = issued.plaintext.removeprefix("vyuu_user_").split("_", 1)
    assert len(parts[0]) == 26  # base32-encoded UUID, no padding
    assert len(parts[1]) >= 40  # ~43 chars for 32-byte urlsafe-b64
    assert issued.key_prefix == parts[1][:KEY_PREFIX_PUBLIC_LEN]


def test_parse_round_trip() -> None:
    issued = issue_new_key(key_id=uuid4())
    parsed = parse_bearer(issued.plaintext)
    assert parsed.key_id == issued.key_id
    assert verify_secret(parsed.secret, issued.key_hash)


def test_wrong_secret_does_not_verify() -> None:
    issued = issue_new_key(key_id=uuid4())
    forged = issued.plaintext[:-5] + "AAAAA"
    parsed = parse_bearer(forged)
    assert parsed.key_id == issued.key_id
    assert not verify_secret(parsed.secret, issued.key_hash)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not-a-bearer",
        "vyuu_user_",
        "vyuu_user_abc",
        "vyuu_op_abc_xyz",  # wrong scope
        "vyuu_user_short_xyz",  # id too short
        "vyuu_user_!!!notbase32!!!_xyz",
    ],
)
def test_parse_rejects_malformed(bad: str) -> None:
    with pytest.raises(MalformedApiKeyError):
        parse_bearer(bad)


def test_two_issues_for_same_key_id_have_different_hashes() -> None:
    """Each issuance is a fresh secret + fresh salt, even if the caller
    pre-allocated the same UUID. (Caller normally uses uuid4() per call;
    this just confirms there's no hidden cache.)"""
    key_id = uuid4()
    a = issue_new_key(key_id=key_id)
    b = issue_new_key(key_id=key_id)
    assert a.plaintext != b.plaintext
    assert a.key_hash != b.key_hash
    # Cross-verify rejects.
    parsed_a = parse_bearer(a.plaintext)
    assert not verify_secret(parsed_a.secret, b.key_hash)
