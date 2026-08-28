#!/usr/bin/env python3
"""Owner-authorised promotion of Law-folder proposed assessment standards."""

from __future__ import annotations

import argparse
import json
import sys
import types
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.assessment.rules import (  # noqa: E402
    assessment_standard_privacy_issues,
    is_owner_style_reusable_standard,
)
from backend.app.config import Settings  # noqa: E402
from backend.app.crypto import LocalCipher  # noqa: E402
from backend.app.db import Database, utc_iso  # noqa: E402


def _load_finalize_module() -> types.ModuleType:
    path = PROJECT_ROOT / "scripts" / "finalize_assessment_standards.py"
    source = path.read_text(encoding="utf-8").replace("if __name__ == '__main__':", "if False:")
    module = types.ModuleType("finalize_assessment_standards")
    module.__file__ = str(path)
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


def _validate(records: list[dict]) -> None:
    for record in records:
        for field in ("rule_text", "remediation_text"):
            text = str(record.get(field) or "")
            if not text:
                raise SystemExit(f"missing {field}: {record['id']}")
            issues = assessment_standard_privacy_issues(text)
            if issues or not is_owner_style_reusable_standard(text):
                raise SystemExit(
                    f"privacy/generalisation gate failed: {record['id']} {field} "
                    f"{issues or 'owner_style'}"
                )


def _to_canonical(record: dict, source_rule_id: str) -> dict:
    old_id = str(record["id"])
    if not old_id.startswith("assessment-proposed-"):
        raise SystemExit(f"unexpected proposed id: {old_id}")
    return {
        "id": "assessment-canonical-" + old_id.removeprefix("assessment-proposed-"),
        "source_rule_id": source_rule_id,
        "subject": record.get("subject"),
        "task_type": record.get("task_type"),
        "criterion": record["criterion"],
        "polarity": record["polarity"],
        "grade_band": record["grade_band"],
        "rule_text": record["rule_text"],
        "remediation_text": record["remediation_text"],
        "from_proposed_id": old_id,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    fin = _load_finalize_module()
    proposed = list(fin.PROPOSED_GENERAL_RULES) + list(fin.PROPOSED_SUBJECT_RULES)
    print(f"proposed_loaded={len(proposed)}", file=sys.stderr)
    _validate(proposed)

    settings = Settings()
    database = Database(settings.database_path)
    database.initialize()
    if database.fetchone(
        "SELECT id FROM source_scans WHERE status IN ('queued','running') LIMIT 1"
    ):
        raise SystemExit("source scan is active; freeze catalogue before promoting standards")

    provenance_rows = database.fetchall(
        """
        SELECT id, source_version_id FROM rubric_rules
        WHERE id LIKE 'assessment-rule-%' AND source_version_id IS NOT NULL
        ORDER BY id
        LIMIT 400
        """
    )
    if not provenance_rows:
        raise SystemExit("no assessment-rule provenance available")

    canonical = [
        _to_canonical(record, str(provenance_rows[i % len(provenance_rows)]["id"]))
        for i, record in enumerate(proposed)
    ]
    sources: dict[str, str] = {}
    for record in canonical:
        row = database.fetchone(
            "SELECT source_version_id FROM rubric_rules WHERE id=?",
            (record["source_rule_id"],),
        )
        if row is None or not row["source_version_id"]:
            raise SystemExit(
                f"missing provenance for {record['id']} via {record['source_rule_id']}"
            )
        sources[record["id"]] = str(row["source_version_id"])

    report = {
        "schema": "legalbot.promote-proposed-assessment-standards.v1",
        "apply": bool(args.apply),
        "proposed_count": len(proposed),
        "canonical_ids": [r["id"] for r in canonical],
        "privacy_recheck": "passed",
        "subjects": sorted({(r.get("subject") or "NULL") for r in canonical}),
    }
    out = PROJECT_ROOT / "data/review_queue/proposed-standards-promotion-2026-08-13.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    if not args.apply:
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({k: report[k] for k in report if k != "canonical_ids"}, indent=2))
        print(f"canonical_ids_count={len(report['canonical_ids'])}")
        return

    cipher = LocalCipher.from_local_key(create=False)
    note = cipher.encrypt_text(
        "Owner-approved Law-folder proposed standards promoted after privacy re-check; "
        "raw marker prose not inserted."
    )
    now = utc_iso()
    with database.transaction() as connection:
        for record in canonical:
            connection.execute(
                """
                INSERT INTO rubric_rules(
                  id,task_type,subject,criterion,polarity,grade_band,rule_text,
                  remediation_text,source_version_id,review_status,created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,'approved',?)
                ON CONFLICT(id) DO UPDATE SET
                  task_type=excluded.task_type,
                  subject=excluded.subject,
                  criterion=excluded.criterion, polarity=excluded.polarity,
                  grade_band=excluded.grade_band, rule_text=excluded.rule_text,
                  remediation_text=excluded.remediation_text,
                  source_version_id=excluded.source_version_id,
                  review_status='approved'
                """,
                (
                    record["id"],
                    record.get("task_type"),
                    record.get("subject"),
                    record["criterion"],
                    record["polarity"],
                    record["grade_band"],
                    record["rule_text"],
                    record["remediation_text"],
                    sources[record["id"]],
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO reviews(
                  id,review_type,target_id,status,reason,decision_note,
                  encrypted_decision_note,created_at,decided_at
                ) VALUES (?, 'assessment_rule', ?, 'approved', ?, '[encrypted]', ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET status='approved',
                  reason=excluded.reason, decision_note='[encrypted]',
                  encrypted_decision_note=excluded.encrypted_decision_note,
                  decided_at=excluded.decided_at
                """,
                (
                    f"review-{record['id']}",
                    record["id"],
                    "owner-promoted-law-folder-proposed-standard",
                    note,
                    now,
                    now,
                ),
            )

    approved = database.fetchone(
        "SELECT COUNT(*) AS n FROM rubric_rules "
        "WHERE id LIKE 'assessment-canonical-%' AND review_status='approved'"
    )
    report["approved_canonical_after_apply"] = int(approved["n"])
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in report if k != "canonical_ids"}, indent=2))
    print(f"canonical_ids_count={len(report['canonical_ids'])}")


if __name__ == "__main__":
    main()
