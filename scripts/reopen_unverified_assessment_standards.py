#!/usr/bin/env python3
"""Re-open the Law-folder standards that were promoted without valid provenance.

The promotion script assigned assessment sources to proposed rules by list position,
not by an evidence-backed relationship.  That makes the resulting provenance
misleading even when the generalised wording itself is reasonable.  This repair is
deliberately reversible: it preserves every rule and the earlier review event, marks
the rule staged so runtime cannot use it, and creates a new pending owner review.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import Settings  # noqa: E402
from backend.app.crypto import LocalCipher  # noqa: E402
from backend.app.db import Database, utc_iso  # noqa: E402

PROMOTION_PATH = (
    PROJECT_ROOT / "data" / "review_queue" / "proposed-standards-promotion-2026-08-13.json"
)


def main() -> None:
    payload = json.loads(PROMOTION_PATH.read_text(encoding="utf-8"))
    rule_ids = [str(value) for value in payload.get("canonical_ids", [])]
    if payload.get("schema") != "legalbot.promote-proposed-assessment-standards.v1":
        raise SystemExit("unexpected assessment-promotion schema")
    if len(rule_ids) != 74 or len(set(rule_ids)) != 74:
        raise SystemExit("expected exactly 74 unique promoted standards")

    database = Database(Settings().database_path)
    database.initialize()
    placeholders = ",".join("?" for _ in rule_ids)
    existing = database.fetchall(
        f"SELECT id,review_status FROM rubric_rules WHERE id IN ({placeholders})",
        tuple(rule_ids),
    )
    if {str(row["id"]) for row in existing} != set(rule_ids):
        raise SystemExit("promotion inventory does not match the catalogue")

    cipher = LocalCipher.from_local_key(create=False)
    now = utc_iso()
    note = cipher.encrypt_text(
        "Re-opened during the pre-E2E architecture audit. The prior promotion "
        "assigned source provenance by list position rather than an evidence-backed "
        "mapping. Confirm the wording and bind genuine feedback provenance before "
        "approval. Subject-specific legal propositions also require expert review."
    )
    with database.transaction() as connection:
        connection.execute(
            f"UPDATE rubric_rules SET review_status='staged' WHERE id IN ({placeholders})",
            tuple(rule_ids),
        )
        for rule_id in rule_ids:
            connection.execute(
                """
                INSERT INTO reviews(
                  id,review_type,target_id,status,reason,decision_note,
                  encrypted_decision_note,created_at,decided_at
                ) VALUES (?, 'assessment_rule', ?, 'pending', ?, '[encrypted]', ?, ?, NULL)
                ON CONFLICT(id) DO UPDATE SET
                  status='pending', reason=excluded.reason,
                  decision_note='[encrypted]',
                  encrypted_decision_note=excluded.encrypted_decision_note,
                  decided_at=NULL
                """,
                (
                    f"review-reopen-provenance-{rule_id}",
                    rule_id,
                    "invalid-positional-provenance-requires-owner-and-expert-review",
                    note,
                    now,
                ),
            )

    print(
        json.dumps(
            {
                "reopened": len(rule_ids),
                "runtime_status": "staged",
                "review_status": "pending",
                "rules_deleted": 0,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
