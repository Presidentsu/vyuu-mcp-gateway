"""Password hashing + strength rules for `auth_method=local` users.

bcrypt because:
- Industry standard, time-tested, well-audited.
- Built-in salt + adaptive work factor (cost).
- Library is small, no compile-step dep.
- argon2id is technically stronger but adds a heavier dep + the
  user-visible difference is zero on a small deployment. Re-evaluate
  when compliance demands it.

Strength rule: minimum 12 chars (per user direction Q3). No character-
class requirements — those provably reduce real entropy by pushing
users toward predictable substitutions. 12 chars of any printable
ASCII is the floor; longer is encouraged via UI hint.
"""

from __future__ import annotations

import bcrypt

# Bcrypt's `rounds` (work factor). 12 = ~250ms per hash on a 2024-era
# laptop, ~150ms on a server. Doubles every increment. 12 is the modern
# default for auth-app passwords. Tunable per-deployment via Settings.
DEFAULT_BCRYPT_ROUNDS = 12

# Minimum password length per user direction Q3. No max-length cap;
# bcrypt truncates at 72 bytes internally so very long passwords just
# get the first 72 bytes hashed (still safe).
MIN_PASSWORD_LENGTH = 12


class PasswordTooWeakError(ValueError):
    """Raised when a password fails the minimum strength rules.

    Generic message — does NOT echo back which rule was broken in
    detail (so attackers iterating against an admin-set policy can't
    fingerprint the policy). The UI can render the rules separately.
    """

    def __init__(self, message: str = "password does not meet minimum requirements") -> None:
        super().__init__(message)


def validate_password_strength(password: str) -> None:
    """Raise `PasswordTooWeakError` if `password` is below the minimum bar.

    Called at every set-password operation: account creation, admin
    reset, user self-rotate. Same rule everywhere so users can't end
    up with a password that's allowed at creation but rejected on
    rotation (or vice versa)."""

    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordTooWeakError


def hash_password(password: str, *, rounds: int = DEFAULT_BCRYPT_ROUNDS) -> str:
    """Hash `password` with a fresh salt at `rounds` cost.

    Caller MUST have already passed `validate_password_strength` —
    this function does NOT re-check (so admin password-reset flows
    can use the same primitive without double-validating)."""

    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time verify `password` against an existing bcrypt hash.

    Returns False on any malformed-hash or mismatch failure. Never
    raises — the caller decides how to surface the result to keep the
    error message identical regardless of WHICH part of the (email,
    password) tuple was wrong (canonical anti-enumeration practice)."""

    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        # Malformed hash — count as not-matching, never crash a login.
        return False
