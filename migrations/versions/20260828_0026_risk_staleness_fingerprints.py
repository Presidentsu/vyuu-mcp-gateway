"""RISK-2 · make a stale risk assessment detectable

Revision ID: 20260828_0026
Revises: 20260827_0025
Create Date: 2026-08-28

A risk score is a statement about a specific set of tools. Capability
sync changes that set — the whole reason it runs — and nothing recorded
what the score had actually been computed against, so the console kept
rendering an old number as the current posture. A security review found
this: a server could gain a `delete_*` tool and keep a "moderate" badge
earned before that tool existed.

`20260827_0025` already stated the intent — "`source_assessment_ids`
records exactly which assessments it was computed from, so a stale
comparison is detectable rather than merely suspicious" — but only the
vserver half stored its inputs, and nothing on the read side ever
compared them.

## Why a fingerprint and not a timestamp

"Assessment older than the last sync" is the obvious test and it is
wrong in both directions. Sync runs on a cadence and usually changes
nothing, so a timestamp comparison marks every assessment stale after
the next tick — noise that trains operators to ignore the badge. And it
misses the case that matters least visibly: an upstream that edits a
tool's description or input schema in place, which changes what the tool
can be talked into doing without changing any count or adding a row.

Hashing the assessed surface answers the question actually being asked —
"is this score about the tools that are there now?" — and answers it the
same way whether the change was an addition, a removal, or an edit.

## Why nullable

Assessments already stored have no fingerprint and there is no way to
reconstruct one: it would have to hash today's capabilities, which is
precisely the thing being tested against. Backfilling would therefore
manufacture a "fresh" verdict for every existing row — the failure this
migration exists to prevent. NULL means "cannot prove freshness", and
the read path falls back to comparing `capability_count`, which still
catches tools added or removed.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260828_0026"
down_revision = "20260827_0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "mcp_server_risk_assessments",
        sa.Column("capability_fingerprint", sa.Text(), nullable=True),
    )
    op.add_column(
        "virtual_server_risk_assessments",
        sa.Column("inputs_fingerprint", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("virtual_server_risk_assessments", "inputs_fingerprint")
    op.drop_column("mcp_server_risk_assessments", "capability_fingerprint")
