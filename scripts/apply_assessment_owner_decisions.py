#!/usr/bin/env python3
"""Apply the sealed M01-M04 assessment decisions without starting later phases.

The manifest contains no source comment, owner identity or filesystem path.  Two
exact marker mappings are approved in place; two amended mappings are rejected
and replaced by source-less owner-authored policy rows.  Re-running a fully
applied decision set is a read-only no-op.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.assessment.guidance_bundle import (  # noqa: E402
    BUNDLE_VERSION,
    OWNER_ASSESSMENT_BUNDLE,
    OWNER_DECISION_MANIFEST_SHA256,
    OWNER_DECISION_RULES,
)
from app.config import Settings  # noqa: E402
from app.crypto import LocalCipher  # noqa: E402
from app.db import Database, utc_iso  # noqa: E402

MANIFEST_PATH = PROJECT_ROOT / "config" / "assessment_owner_decisions_2026-08-14.json"
REAUDIT_PATH = PROJECT_ROOT / "docs" / "reports" / "assessment-guidance-reaudit-2026-08-14.json"
EXPECTED_DOCUMENT_SHA256 = "19984c50774eebf76e4661569684c65c1ea19e446fa6d35886cd850908d7129d"
EXPECTED_DECISIONS = {
    "M01": ("approve_exact_marker_mapping", "assessment-canonical-case-synthesis-v1"),
    "M02": (
        "supersede_with_owner_policy",
        "assessment-canonical-criminal-element-defence-v1",
    ),
    "M03": (
        "supersede_with_owner_policy",
        "assessment-canonical-question-engagement-v1",
    ),
    "M04": (
        "approve_exact_marker_mapping",
        "assessment-canonical-timely-authority-support-v1",
    ),
}
APPROVAL_REASON = "owner-approved-exact-feedback-mapping"
SUPERSESSION_REASON = "superseded-by-owner-authored-replacement"
REPLACEMENT_REASON = "owner-authored-replacement-approved"
MANIFEST_APPLICATION_REASON = "owner-decision-manifest-applied"


class TextCipher(Protocol):
    def encrypt_text(self, value: str) -> bytes: ...


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _object(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return {str(key): item for key, item in value.items()}


def load_and_validate_manifest(project_root: Path = PROJECT_ROOT) -> dict[str, Any]:
    """Load the privacy-safe manifest and verify every immutable binding."""

    path = project_root / "config" / MANIFEST_PATH.name
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != OWNER_DECISION_MANIFEST_SHA256:
        raise ValueError("assessment owner-decision manifest SHA mismatch")
    payload = _object(json.loads(raw), label="owner-decision manifest")
    if payload.get("schema") != "legalbot.assessment-owner-decisions.v1":
        raise ValueError("assessment owner-decision manifest schema mismatch")
    if payload.get("source_document_sha256") != EXPECTED_DOCUMENT_SHA256:
        raise ValueError("assessment owner-decision source document SHA mismatch")
    if payload.get("source_document_content_included") is not False:
        raise ValueError("owner-decision manifest must omit source document content")
    if payload.get("owner_identity_included") is not False:
        raise ValueError("owner-decision manifest must omit owner identity")
    if payload.get("resulting_bundle_version") != BUNDLE_VERSION:
        raise ValueError("owner-decision manifest bundle version mismatch")

    reaudit_path = project_root / "docs" / "reports" / REAUDIT_PATH.name
    if payload.get("reaudit_manifest_sha256") != _sha256(reaudit_path):
        raise ValueError("assessment re-audit manifest SHA mismatch")
    reaudit = _object(json.loads(reaudit_path.read_bytes()), label="assessment re-audit")
    reaudit_records = {
        str(record["rule_id"]): _object(record, label="assessment re-audit record")
        for record in reaudit.get("records", [])
        if isinstance(record, dict) and record.get("rule_id")
    }

    raw_decisions = payload.get("decisions")
    if not isinstance(raw_decisions, list):
        raise ValueError("assessment owner-decision records are missing")
    decisions = {
        str(record.get("decision_id")): _object(record, label="owner decision")
        for record in raw_decisions
        if isinstance(record, dict)
    }
    if set(decisions) != set(EXPECTED_DECISIONS) or len(raw_decisions) != 4:
        raise ValueError("assessment owner-decision inventory mismatch")

    runtime_by_id = {rule.rule_id: rule.canonical_record() for rule in OWNER_DECISION_RULES}
    if len(runtime_by_id) != 4:
        raise ValueError("runtime owner-decision rule inventory mismatch")
    for decision_id, (disposition, original_rule_id) in EXPECTED_DECISIONS.items():
        decision = decisions[decision_id]
        if (
            decision.get("disposition") != disposition
            or decision.get("original_rule_id") != original_rule_id
        ):
            raise ValueError(f"assessment owner decision {decision_id} mismatch")
        reaudit_record = reaudit_records.get(original_rule_id)
        if reaudit_record is None:
            raise ValueError(f"assessment owner decision {decision_id} has no re-audit record")
        if decision.get("source_rule_id") != reaudit_record.get("source_rule_id"):
            raise ValueError(f"assessment owner decision {decision_id} source_rule_id mismatch")
        if decision.get("source_span_sha256") != reaudit_record.get("source_span_hash"):
            raise ValueError(f"assessment owner decision {decision_id} source span mismatch")
        if decision.get("original_rule_text_sha256") != reaudit_record.get("rule_text_hash"):
            raise ValueError(f"assessment owner decision {decision_id} rule hash mismatch")
        runtime = _object(decision.get("runtime_rule"), label="runtime assessment rule")
        runtime_id = str(runtime.get("rule_id") or "")
        if runtime_by_id.get(runtime_id) != runtime:
            raise ValueError(f"assessment owner decision {decision_id} runtime rule mismatch")
        if disposition == "supersede_with_owner_policy":
            if decision.get("replacement_rule_id") != runtime_id:
                raise ValueError(f"assessment owner decision {decision_id} replacement mismatch")
            if runtime.get("verification_signal") != "owner_authored_policy_v1":
                raise ValueError(f"assessment owner decision {decision_id} has false provenance")
        elif runtime_id != original_rule_id:
            raise ValueError(f"assessment owner decision {decision_id} approval target mismatch")
    return payload


def _decision_map(manifest: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(record["decision_id"]): _object(record, label="owner decision")
        for record in manifest["decisions"]
        if isinstance(record, dict)
    }


def _review_state(database: Database, review_id: str) -> tuple[str, str] | None:
    row = database.fetchone("SELECT status, reason FROM reviews WHERE id=?", (review_id,))
    return (str(row["status"]), str(row["reason"])) if row is not None else None


def _fully_applied(database: Database, manifest: Mapping[str, Any]) -> bool:
    manifest_review_id = f"review-assessment-owner-decision-{OWNER_DECISION_MANIFEST_SHA256[:16]}"
    if _review_state(database, manifest_review_id) != (
        "approved",
        MANIFEST_APPLICATION_REASON,
    ):
        return False
    for decision in _decision_map(manifest).values():
        original_id = str(decision["original_rule_id"])
        disposition = str(decision["disposition"])
        expected_status = (
            "approved" if disposition == "approve_exact_marker_mapping" else "rejected"
        )
        row = database.fetchone("SELECT review_status FROM rubric_rules WHERE id=?", (original_id,))
        if row is None or str(row["review_status"]) != expected_status:
            return False
        review_id = f"review-feedback-reaudit-{original_id}"
        expected_review = (
            ("approved", APPROVAL_REASON)
            if disposition == "approve_exact_marker_mapping"
            else ("rejected", SUPERSESSION_REASON)
        )
        if _review_state(database, review_id) != expected_review:
            return False
        if disposition == "supersede_with_owner_policy":
            runtime = _object(decision["runtime_rule"], label="runtime assessment rule")
            replacement_id = str(decision["replacement_rule_id"])
            replacement = database.fetchone(
                """
                SELECT task_type, subject, criterion, polarity, grade_band, rule_text,
                       remediation_text, source_version_id, review_status
                FROM rubric_rules WHERE id=?
                """,
                (replacement_id,),
            )
            if replacement is None:
                return False
            expected_task = None if runtime["task_type"] == "any" else runtime["task_type"]
            expected = (
                expected_task,
                runtime.get("subject"),
                runtime["criterion"],
                "error_to_avoid",
                runtime["grade_band"],
                runtime["anti_pattern"],
                runtime["repair_action"],
                None,
                "approved",
            )
            observed = tuple(replacement)
            if observed != expected:
                return False
            if _review_state(database, f"review-owner-decision-{replacement_id}") != (
                "approved",
                REPLACEMENT_REASON,
            ):
                return False
    return True


def apply_owner_decisions(
    database: Database,
    cipher: TextCipher,
    manifest: Mapping[str, Any],
    *,
    now: str | None = None,
) -> str:
    """Apply the four decisions atomically; return ``applied`` or ``already_applied``."""

    if _fully_applied(database, manifest):
        return "already_applied"
    decisions = _decision_map(manifest)
    for decision_id, decision in decisions.items():
        original_id = str(decision["original_rule_id"])
        original = database.fetchone(
            "SELECT rule_text, review_status FROM rubric_rules WHERE id=?", (original_id,)
        )
        if original is None:
            raise ValueError(f"assessment owner decision {decision_id} target is missing")
        if hashlib.sha256(str(original["rule_text"]).encode("utf-8")).hexdigest() != decision.get(
            "original_rule_text_sha256"
        ):
            raise ValueError(f"assessment owner decision {decision_id} target content changed")
        if str(original["review_status"]) not in {"staged", "approved", "rejected"}:
            raise ValueError(f"assessment owner decision {decision_id} target state is invalid")
        if (
            database.fetchone(
                "SELECT id FROM reviews WHERE id=?",
                (f"review-feedback-reaudit-{original_id}",),
            )
            is None
        ):
            raise ValueError(f"assessment owner decision {decision_id} pending review is missing")

    decided_at = now or utc_iso()
    manifest_sha = OWNER_DECISION_MANIFEST_SHA256
    approval_note = cipher.encrypt_text(
        f"Exact privacy-safe feedback mapping approved by sealed decision manifest {manifest_sha}."
    )
    supersession_note = cipher.encrypt_text(
        f"Staged mapping superseded by separately owner-authored policy in sealed decision manifest {manifest_sha}."
    )
    replacement_note = cipher.encrypt_text(
        f"Owner-authored replacement approved without marker-source attribution in sealed decision manifest {manifest_sha}."
    )
    with database.transaction() as connection:
        for decision in decisions.values():
            original_id = str(decision["original_rule_id"])
            disposition = str(decision["disposition"])
            review_id = f"review-feedback-reaudit-{original_id}"
            if disposition == "approve_exact_marker_mapping":
                connection.execute(
                    "UPDATE rubric_rules SET review_status='approved' WHERE id=?", (original_id,)
                )
                connection.execute(
                    """
                    UPDATE reviews
                    SET status='approved', reason=?, decision_note='[encrypted]',
                        encrypted_decision_note=?, decided_at=?
                    WHERE id=?
                    """,
                    (APPROVAL_REASON, approval_note, decided_at, review_id),
                )
                continue

            connection.execute(
                "UPDATE rubric_rules SET review_status='rejected' WHERE id=?", (original_id,)
            )
            connection.execute(
                """
                UPDATE reviews
                SET status='rejected', reason=?, decision_note='[encrypted]',
                    encrypted_decision_note=?, decided_at=?
                WHERE id=?
                """,
                (SUPERSESSION_REASON, supersession_note, decided_at, review_id),
            )
            runtime = _object(decision["runtime_rule"], label="runtime assessment rule")
            replacement_id = str(decision["replacement_rule_id"])
            task_type = None if runtime["task_type"] == "any" else str(runtime["task_type"])
            connection.execute(
                """
                INSERT INTO rubric_rules(
                  id, task_type, subject, criterion, polarity, grade_band,
                  rule_text, remediation_text, source_version_id, review_status, created_at
                ) VALUES (?, ?, ?, ?, 'error_to_avoid', ?, ?, ?, NULL, 'approved', ?)
                ON CONFLICT(id) DO UPDATE SET
                  task_type=excluded.task_type,
                  subject=excluded.subject,
                  criterion=excluded.criterion,
                  polarity=excluded.polarity,
                  grade_band=excluded.grade_band,
                  rule_text=excluded.rule_text,
                  remediation_text=excluded.remediation_text,
                  source_version_id=NULL,
                  review_status='approved'
                """,
                (
                    replacement_id,
                    task_type,
                    runtime.get("subject"),
                    runtime["criterion"],
                    runtime["grade_band"],
                    runtime["anti_pattern"],
                    runtime["repair_action"],
                    decided_at,
                ),
            )
            connection.execute(
                """
                INSERT INTO reviews(
                  id, review_type, target_id, status, reason, decision_note,
                  encrypted_decision_note, created_at, decided_at
                ) VALUES (?, 'assessment_rule', ?, 'approved', ?, '[encrypted]', ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  status='approved', reason=excluded.reason,
                  decision_note='[encrypted]',
                  encrypted_decision_note=excluded.encrypted_decision_note,
                  decided_at=COALESCE(reviews.decided_at, excluded.decided_at)
                """,
                (
                    f"review-owner-decision-{replacement_id}",
                    replacement_id,
                    REPLACEMENT_REASON,
                    replacement_note,
                    decided_at,
                    decided_at,
                ),
            )
        connection.execute(
            """
            INSERT INTO reviews(
              id, review_type, target_id, status, reason, decision_note,
              encrypted_decision_note, created_at, decided_at
            ) VALUES (?, 'assessment_owner_decision', ?, 'approved', ?,
                      '[encrypted]', ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              status='approved', reason=excluded.reason,
              decision_note='[encrypted]',
              encrypted_decision_note=excluded.encrypted_decision_note,
              decided_at=COALESCE(reviews.decided_at, excluded.decided_at)
            """,
            (
                f"review-assessment-owner-decision-{manifest_sha[:16]}",
                manifest_sha,
                MANIFEST_APPLICATION_REASON,
                replacement_note,
                decided_at,
                decided_at,
            ),
        )
    if not _fully_applied(database, manifest):
        raise RuntimeError("assessment owner decisions did not reach the sealed target state")
    return "applied"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-document",
        type=Path,
        help=(
            "Optional filled owner-decision document for a fresh byte-level check; "
            "only its SHA-256 is used. The committed manifest already records the "
            "previously verified digest."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if (
        args.source_document is not None
        and _sha256(args.source_document) != EXPECTED_DOCUMENT_SHA256
    ):
        raise SystemExit("filled owner-decision document SHA mismatch")
    manifest = load_and_validate_manifest()
    settings = Settings(project_root=PROJECT_ROOT)
    database = Database(settings.database_path)
    database.initialize()
    try:
        result = apply_owner_decisions(
            database,
            LocalCipher.from_local_key(create=False),
            manifest,
        )
    finally:
        database.close()
    print(
        json.dumps(
            {
                "schema": "legalbot.assessment-owner-decision-application.v1",
                "result": result,
                "source_document_sha256": EXPECTED_DOCUMENT_SHA256,
                "decision_manifest_sha256": OWNER_DECISION_MANIFEST_SHA256,
                "assessment_bundle_version": OWNER_ASSESSMENT_BUNDLE.version,
                "assessment_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
                "approved_exact_mappings": 2,
                "approved_owner_replacements": 2,
                "superseded_original_mappings": 2,
                "index_built": False,
                "promotion_performed": False,
                "live_run_started": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
