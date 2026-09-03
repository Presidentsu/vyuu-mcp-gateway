"""Provision N users with API keys for the multi-user perf sweep.

Snapshots DB size before + after so we can compute per-user storage
cost. Writes a JSON file containing `[(user_id, api_key_plaintext)]`
so the sweep harness can use the keys without re-deriving them.

Usage:
    python tests/perf/provision_users.py --count 500 --label sweep-2026-05-03

Cleanup:
    python tests/perf/provision_users.py --cleanup --label sweep-2026-05-03

The cleanup path identifies users by email prefix
(`perf-{label}-N@vyuulab.io`) and cascade-deletes via the existing
FK ON DELETE rules — `oauth_user_tokens` and `user_api_keys` go
with the user row.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import create_engine, delete, func, select, text
from sqlalchemy.orm import sessionmaker

from vyuu_gateway.db.models import User, UserApiKey, UserAuthMethod
from vyuu_gateway.users.api_keys import issue_new_key
from vyuu_gateway.users.passwords import hash_password

# Lab tenant — same one the seeded servers + operator live under.
TENANT_ID = UUID("11111111-1111-1111-1111-111111111111")
DB_URL = "postgresql+psycopg://vyuu@127.0.0.1:5432/vyuu_gateway"
RESULTS_DIR = Path(__file__).parent / "results"


def _factory():
    return sessionmaker(create_engine(DB_URL, future=True), autoflush=False)()


def _db_size_bytes(session) -> int:
    return int(
        session.execute(text("SELECT pg_database_size('vyuu_gateway')")).scalar() or 0
    )


def _row_counts(session) -> dict[str, int]:
    return {
        "users": session.scalar(select(func.count()).select_from(User)) or 0,
        "user_api_keys": session.scalar(select(func.count()).select_from(UserApiKey)) or 0,
    }


def provision(count: int, label: str) -> None:
    out_path = RESULTS_DIR / f"perf-users-{label}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with _factory() as session:
        before_size = _db_size_bytes(session)
        before_counts = _row_counts(session)

    keys: list[dict[str, str]] = []
    # One bcrypt hash dominates per-user provisioning cost (~150ms).
    # Provisioning 500 users sequentially is ~75s; acceptable for a
    # one-shot setup script.
    t0 = time.perf_counter()
    with _factory() as session:
        for i in range(count):
            user_id = uuid4()
            email = f"perf-{label}-{i:04d}@vyuulab.io"
            session.add(
                User(
                    id=user_id,
                    tenant_id=TENANT_ID,
                    email=email,
                    auth_method=UserAuthMethod.LOCAL,
                    password_hash=hash_password(f"perf-pw-{i}"),
                )
            )
            key_id = uuid4()
            issued = issue_new_key(key_id=key_id)
            session.add(
                UserApiKey(
                    id=key_id,
                    tenant_id=TENANT_ID,
                    user_id=user_id,
                    label=f"perf-key-{i}",
                    key_hash=issued.key_hash,
                    key_prefix=issued.key_prefix,
                )
            )
            keys.append({"user_id": str(user_id), "api_key": issued.plaintext})
            if (i + 1) % 50 == 0:
                session.commit()
                print(f"  provisioned {i + 1}/{count}", flush=True)
        session.commit()
    elapsed = time.perf_counter() - t0

    with _factory() as session:
        after_size = _db_size_bytes(session)
        after_counts = _row_counts(session)

    storage_delta = after_size - before_size
    per_user_bytes = storage_delta // max(1, count)

    summary = {
        "label": label,
        "count": count,
        "elapsed_seconds": round(elapsed, 1),
        "db_size_bytes_before": before_size,
        "db_size_bytes_after": after_size,
        "storage_delta_bytes": storage_delta,
        "per_user_bytes": per_user_bytes,
        "rows_added": {
            k: after_counts[k] - before_counts[k] for k in before_counts
        },
        "projected_storage_at_scale": {
            "100_users_mb": round(per_user_bytes * 100 / (1024 * 1024), 2),
            "1k_users_mb": round(per_user_bytes * 1_000 / (1024 * 1024), 2),
            "10k_users_mb": round(per_user_bytes * 10_000 / (1024 * 1024), 2),
            "100k_users_gb": round(per_user_bytes * 100_000 / (1024 ** 3), 3),
        },
        "keys_file": str(out_path),
    }
    out_path.write_text(json.dumps(keys, indent=2))
    print(json.dumps(summary, indent=2))


def cleanup(label: str) -> None:
    """Cascade-delete every user row with email prefix `perf-{label}-`.
    FK ON DELETE CASCADE on `user_api_keys` + `oauth_user_tokens`
    handles dependents; the rows go with the user."""
    pattern = f"perf-{label}-%@vyuulab.io"
    with _factory() as session:
        n = session.scalar(
            select(func.count()).select_from(User).where(User.email.like(pattern))
        ) or 0
        session.execute(delete(User).where(User.email.like(pattern)))
        session.commit()
    print(f"deleted {n} users matching {pattern}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=500)
    ap.add_argument("--label", default="sweep")
    ap.add_argument("--cleanup", action="store_true")
    args = ap.parse_args()
    if args.cleanup:
        cleanup(args.label)
    else:
        provision(args.count, args.label)


if __name__ == "__main__":
    main()
