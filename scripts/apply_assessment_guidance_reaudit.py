#!/usr/bin/env python3
"""Apply the evidence-based re-audit of the 25 legacy approved feedback rules.

The earlier approval events remain in the append-only review history.  This
repair changes only the current runtime eligibility: only exact mappings return
to staged owner review.  Partial mappings are rejected because narrowing or
expanding a marker comment would create a new owner-authored rule rather than a
faithful feedback-derived rule; the separately SHA-bound owner bundle already
provides that guidance.  Rule prose and source material are never deleted or
rewritten.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import Settings  # noqa: E402
from app.crypto import LocalCipher  # noqa: E402
from app.db import Database, utc_iso  # noqa: E402

REPORT = PROJECT_ROOT / "docs/reports/assessment-guidance-reaudit-2026-08-14.json"
EXPECTED = {
    "exact_support_candidate": 4,
    "partial_support_reword": 10,
    "unsupported_mapping_reopen": 11,
}


def _load_plan(path: Path) -> tuple[dict[str, str], str]:
    raw = path.read_bytes()
    payload = json.loads(raw)
    if (
        payload.get("schema") != "legalbot.assessment-guidance-reaudit.v1"
        or payload.get("database_mutation_performed") is not False
        or payload.get("raw_feedback_included") is not False
    ):
        raise SystemExit("assessment guidance re-audit report contract is invalid")
    records = payload.get("records")
    if not isinstance(records, list):
        raise SystemExit("assessment guidance re-audit records are missing")
    plan: dict[str, str] = {}
    for record in records:
        if not isinstance(record, dict):
            raise SystemExit("assessment guidance re-audit contains a non-object record")
        rule_id = str(record.get("rule_id") or "")
        disposition = str(record.get("disposition") or "")
        if not rule_id.startswith("assessment-canonical-") or disposition not in EXPECTED:
            raise SystemExit("assessment guidance re-audit contains an invalid decision")
        if rule_id in plan:
            raise SystemExit("assessment guidance re-audit contains a duplicate rule")
        plan[rule_id] = disposition
    counts = Counter(plan.values())
    if len(plan) != 25 or dict(counts) != EXPECTED:
        raise SystemExit("assessment guidance re-audit does not reconcile 25 decisions")
    return plan, hashlib.sha256(raw).hexdigest()


def main() -> None:
    plan, report_sha256 = _load_plan(REPORT)
    settings = Settings(project_root=PROJECT_ROOT)
    database = Database(settings.database_path)
    database.initialize()
    try:
        placeholders = ",".join("?" for _ in plan)
        rows = database.fetchall(
            f"SELECT id, review_status FROM rubric_rules WHERE id IN ({placeholders})",
            tuple(sorted(plan)),
        )
        if {str(row["id"]) for row in rows} != set(plan):
            raise SystemExit("catalogue does not contain the exact 25 re-audited rules")

        cipher = LocalCipher.from_local_key(create=False)
        now = utc_iso()
        staged = sorted(
            rule_id
            for rule_id, disposition in plan.items()
            if disposition == "exact_support_candidate"
        )
        rejected = sorted(set(plan) - set(staged))
        staged_note = cipher.encrypt_text(
            "Re-opened by the 2026-08-14 evidence-based feedback provenance re-audit. "
            "Owner review is limited to confirming this direct, polarity-separated "
            "feedback-to-rule mapping."
        )
        rejected_note = cipher.encrypt_text(
            "Rejected by the 2026-08-14 evidence-based feedback provenance re-audit "
            "because the source comment does not exactly support the rule criterion, "
            "scope, polarity or subject. Any useful broader guidance remains separately "
            "owner-authored and SHA-bound."
        )
        with database.transaction() as connection:
            for rule_id in staged:
                connection.execute(
                    "UPDATE rubric_rules SET review_status='staged' WHERE id=?",
                    (rule_id,),
                )
                connection.execute(
                    """
                    INSERT INTO reviews(
                      id, review_type, target_id, status, reason, decision_note,
                      encrypted_decision_note, created_at, decided_at
                    ) VALUES (?, 'assessment_rule', ?, 'pending', ?, '[encrypted]', ?, ?, NULL)
                    ON CONFLICT(id) DO UPDATE SET
                      status='pending', reason=excluded.reason,
                      decision_note='[encrypted]',
                      encrypted_decision_note=excluded.encrypted_decision_note,
                      decided_at=NULL
                    """,
                    (
                        f"review-feedback-reaudit-{rule_id}",
                        rule_id,
                        f"{plan[rule_id]}:owner-review-required",
                        staged_note,
                        now,
                    ),
                )
            for rule_id in rejected:
                connection.execute(
                    "UPDATE rubric_rules SET review_status='rejected' WHERE id=?",
                    (rule_id,),
                )
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
                        f"review-feedback-reaudit-{rule_id}",
                        rule_id,
                        (
                            "partial-feedback-mapping-replaced-by-owner-policy"
                            if plan[rule_id] == "partial_support_reword"
                            else "unsupported-feedback-to-rule-mapping"
                        ),
                        rejected_note,
                        now,
                        now,
                    ),
                )
    finally:
        database.close()

    print(
        json.dumps(
            {
                "schema": "legalbot.assessment-guidance-reaudit-application.v1",
                "report_sha256": report_sha256,
                "legacy_approved_remaining": 0,
                "staged_for_owner_review": len(staged),
                "rejected_non_exact": len(rejected),
                "rules_deleted": 0,
                "runtime_bundle": "owner-authored-and-separately-sha-bound",
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
