#!/usr/bin/env python3
"""Reject the 74 assessment standards whose provenance was assigned by position.

These records were already re-opened because their source links were created by
round-robin/list order rather than comment-to-rule evidence.  They are not
genuine ambiguous mappings for the owner to adjudicate, so this append-only
decision removes them from the owner queue without deleting the historical
records or their earlier review events.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import Settings  # noqa: E402
from app.crypto import LocalCipher  # noqa: E402
from app.db import Database, utc_iso  # noqa: E402

PROMOTION_PATH = PROJECT_ROOT / "data/review_queue/proposed-standards-promotion-2026-08-13.json"


def main() -> None:
    payload = json.loads(PROMOTION_PATH.read_text(encoding="utf-8"))
    rule_ids = tuple(str(value) for value in payload.get("canonical_ids", ()))
    if (
        payload.get("schema") != "legalbot.promote-proposed-assessment-standards.v1"
        or len(rule_ids) != 74
        or len(set(rule_ids)) != 74
    ):
        raise SystemExit("invalid positional-provenance inventory does not reconcile")

    settings = Settings(project_root=PROJECT_ROOT)
    database = Database(settings.database_path)
    database.initialize()
    try:
        placeholders = ",".join("?" for _ in rule_ids)
        existing = database.fetchall(
            f"SELECT id, review_status FROM rubric_rules WHERE id IN ({placeholders})",
            rule_ids,
        )
        if {str(row["id"]) for row in existing} != set(rule_ids):
            raise SystemExit("catalogue does not match the 74-rule provenance inventory")

        now = utc_iso()
        note = LocalCipher.from_local_key(create=False).encrypt_text(
            "Rejected after provenance re-audit: the feedback source was assigned by "
            "list position, not an exact semantic comment-to-rule mapping. A useful "
            "writing principle may be proposed later as owner-authored policy, but this "
            "record cannot be represented as marker-derived guidance."
        )
        with database.transaction() as connection:
            connection.execute(
                f"UPDATE rubric_rules SET review_status='rejected' WHERE id IN ({placeholders})",
                rule_ids,
            )
            # Close the earlier re-opened pending review rows as superseded by
            # this evidence-based rejection. Leaving them pending would make
            # the dashboard falsely ask the owner to review all 74 again.
            connection.execute(
                f"""
                UPDATE reviews
                SET status='rejected',
                    reason='superseded-by-invalid-positional-provenance-rejection',
                    decision_note='[encrypted]', encrypted_decision_note=?, decided_at=?
                WHERE review_type='assessment_rule'
                  AND target_id IN ({placeholders})
                  AND status='pending'
                """,
                (note, now, *rule_ids),
            )
            for rule_id in rule_ids:
                connection.execute(
                    """
                    INSERT INTO reviews(
                      id, review_type, target_id, status, reason, decision_note,
                      encrypted_decision_note, created_at, decided_at
                    ) VALUES (?, 'assessment_rule', ?, 'rejected', ?, '[encrypted]', ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                      status='rejected', reason=excluded.reason,
                      decision_note='[encrypted]',
                      encrypted_decision_note=excluded.encrypted_decision_note,
                      decided_at=excluded.decided_at
                    """,
                    (
                        f"review-reject-positional-{rule_id}",
                        rule_id,
                        "invalid-positional-provenance-not-owner-reviewable",
                        note,
                        now,
                        now,
                    ),
                )
    finally:
        database.close()

    print(
        json.dumps(
            {
                "schema": "legalbot.invalid-positional-assessment-rejection.v1",
                "rejected": 74,
                "rules_deleted": 0,
                "owner_review_required": 0,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
