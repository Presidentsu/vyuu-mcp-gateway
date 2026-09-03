"""Unit tests for the password module."""

from __future__ import annotations

import pytest

from vyuu_gateway.users.passwords import (
    MIN_PASSWORD_LENGTH,
    PasswordTooWeakError,
    hash_password,
    validate_password_strength,
    verify_password,
)


def test_hash_and_verify_round_trip() -> None:
    h = hash_password("correct-horse-battery-staple")
    assert verify_password("correct-horse-battery-staple", h)
    assert not verify_password("wrong", h)


def test_hash_is_per_call_unique() -> None:
    """bcrypt salts are random — same password should hash differently."""
    a = hash_password("same-password-12chars")
    b = hash_password("same-password-12chars")
    assert a != b
    # Both still verify against the original.
    assert verify_password("same-password-12chars", a)
    assert verify_password("same-password-12chars", b)


def test_minimum_length_enforced() -> None:
    """Per Q3 — minimum 12 chars."""
    short = "a" * (MIN_PASSWORD_LENGTH - 1)
    with pytest.raises(PasswordTooWeakError):
        validate_password_strength(short)
    # Exactly at the threshold passes.
    validate_password_strength("a" * MIN_PASSWORD_LENGTH)


def test_empty_password_rejected_by_validator() -> None:
    with pytest.raises(PasswordTooWeakError):
        validate_password_strength("")


def test_verify_against_malformed_hash_returns_false() -> None:
    """Defense — never crash a login flow on a corrupt hash row."""
    assert verify_password("password-12chars", "not-a-bcrypt-hash") is False


def test_verify_with_empty_inputs_returns_false() -> None:
    assert verify_password("", "irrelevant") is False
    assert verify_password("password-12chars", "") is False
