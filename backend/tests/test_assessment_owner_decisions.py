from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from scripts.apply_assessment_owner_decisions import (
    APPROVAL_REASON,
    REPLACEMENT_REASON,
    SUPERSESSION_REASON,
    apply_owner_decisions,
    load_and_validate_manifest,
)

from app.assessment.guidance_bundle import (
    BUNDLE_VERSION,
    OWNER_ASSESSMENT_BUNDLE,
    OWNER_DECISION_MANIFEST_SHA256,
    OWNER_DECISION_RULES,
    budget_assessment_guidance,
    instruction_for_rule,
    validate_bundle,
)
from app.db import Database

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = PROJECT_ROOT / "config" / "assessment_owner_decisions_2026-08-14.json"


class _Cipher:
    def encrypt_text(self, value: str) -> bytes:
        return b"sealed:" + hashlib.sha256(value.encode("utf-8")).digest()


def _insert_owner_review_fixture(database: Database, manifest: dict[str, object]) -> None:
    decisions = manifest["decisions"]
    assert isinstance(decisions, list)
    now = "2026-08-14T00:00:00+00:00"
    with database.transaction() as connection:
        for decision in decisions:
            assert isinstance(decision, dict)
            runtime = decision["runtime_rule"]
            assert isinstance(runtime, dict)
            original_id = str(decision["original_rule_id"])
            task_type = None if runtime["task_type"] == "any" else str(runtime["task_type"])
            connection.execute(
                """
                INSERT INTO rubric_rules(
                  id, task_type, subject, criterion, polarity, grade_band,
                  rule_text, remediation_text, source_version_id, review_status, created_at
                ) VALUES (?, ?, ?, ?, 'error_to_avoid', ?, ?, ?, NULL, 'staged', ?)
                """,
                (
                    original_id,
                    task_type,
                    runtime.get("subject"),
                    runtime["criterion"],
                    runtime["grade_band"],
                    {
                        "M01": (
                            "Do not discuss key authorities as isolated summaries; explain the "
                            "relationship between the cases and make that synthesis central to the "
                            "essay argument."
                        ),
                        "M02": (
                            "Do not leave an offence element or available defence unaddressed; "
                            "conclude on each element or explain expressly why it is ruled out."
                        ),
                        "M03": (
                            "Do not write a legally relevant but question-neutral discussion; make "
                            "every section advance an answer to the precise problem or proposition set."
                        ),
                        "M04": (
                            "Support each material proposition with appropriate authority at the "
                            "point where it is made; do not postpone essential references until a "
                            "later section."
                        ),
                    }[str(decision["decision_id"])],
                    "historical remediation",
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO reviews(
                  id, review_type, target_id, status, reason, decision_note,
                  encrypted_decision_note, created_at, decided_at
                ) VALUES (?, 'assessment_rule', ?, 'pending',
                          'owner-review-required', '[encrypted]', ?, ?, NULL)
                """,
                (
                    f"review-feedback-reaudit-{original_id}",
                    original_id,
                    b"pending",
                    now,
                ),
            )


def _safe_state(database: Database) -> tuple[tuple[object, ...], ...]:
    rows = database.fetchall(
        """
        SELECT id, task_type, subject, criterion, polarity, grade_band, rule_text,
               remediation_text, source_version_id, review_status, created_at
        FROM rubric_rules ORDER BY id
        """
    )
    reviews = database.fetchall(
        """
        SELECT id, target_id, status, reason, decision_note, created_at, decided_at
        FROM reviews ORDER BY id
        """
    )
    return tuple(tuple(row) for row in (*rows, *reviews))


def test_manifest_is_privacy_safe_and_exactly_binds_runtime_bundle() -> None:
    manifest = load_and_validate_manifest()
    raw = MANIFEST_PATH.read_bytes()

    assert hashlib.sha256(raw).hexdigest() == OWNER_DECISION_MANIFEST_SHA256
    assert manifest["source_document_content_included"] is False
    assert manifest["owner_identity_included"] is False
    assert b"/Users/" not in raw
    assert len(manifest["decisions"]) == 4
    assert OWNER_ASSESSMENT_BUNDLE.version == BUNDLE_VERSION
    assert OWNER_ASSESSMENT_BUNDLE.decision_manifest_sha256 == OWNER_DECISION_MANIFEST_SHA256
    assert validate_bundle(OWNER_ASSESSMENT_BUNDLE) == ()
    assert {rule.rule_id for rule in OWNER_DECISION_RULES} == {
        "assessment-canonical-case-synthesis-v1",
        "assessment-canonical-timely-authority-support-v1",
        "owner-amended-criminal-element-defence-v2",
        "owner-amended-question-engagement-v2",
    }


def test_manifest_tampering_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "docs" / "reports").mkdir(parents=True)
    payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    payload["owner_identity_included"] = True
    (tmp_path / "config" / MANIFEST_PATH.name).write_text(json.dumps(payload), encoding="utf-8")
    shutil.copy2(
        PROJECT_ROOT / "docs" / "reports" / "assessment-guidance-reaudit-2026-08-14.json",
        tmp_path / "docs" / "reports" / "assessment-guidance-reaudit-2026-08-14.json",
    )
    with pytest.raises(ValueError, match="manifest SHA mismatch"):
        load_and_validate_manifest(tmp_path)


def test_all_four_decision_rules_are_eligible_and_budgeted_atomically() -> None:
    essay = budget_assessment_guidance(
        OWNER_ASSESSMENT_BUNDLE,
        task_type="essay",
        subject="public law",
        max_characters=100_000,
    )
    criminal = budget_assessment_guidance(
        OWNER_ASSESSMENT_BUNDLE,
        task_type="problem",
        subject="criminal",
        max_characters=100_000,
    )
    selected = {rule.rule_id for rule in (*essay.selected_rules, *criminal.selected_rules)}
    assert {rule.rule_id for rule in OWNER_DECISION_RULES} <= selected
    assert essay.instructions == tuple(instruction_for_rule(rule) for rule in essay.selected_rules)
    assert criminal.instructions == tuple(
        instruction_for_rule(rule) for rule in criminal.selected_rules
    )
    constrained = budget_assessment_guidance(
        OWNER_ASSESSMENT_BUNDLE,
        task_type="problem",
        subject="criminal",
        max_characters=120,
    )
    assert constrained.instructions == ()
    assert constrained.character_count == 0


def test_application_updates_history_without_false_source_provenance_and_is_idempotent(
    tmp_path: Path,
) -> None:
    manifest = load_and_validate_manifest()
    database = Database(tmp_path / "catalog.sqlite3")
    database.initialize()
    try:
        _insert_owner_review_fixture(database, manifest)
        assert (
            apply_owner_decisions(
                database,
                _Cipher(),
                manifest,
                now="2026-08-14T01:02:03+00:00",
            )
            == "applied"
        )

        expected_originals = {
            "assessment-canonical-case-synthesis-v1": "approved",
            "assessment-canonical-timely-authority-support-v1": "approved",
            "assessment-canonical-criminal-element-defence-v1": "rejected",
            "assessment-canonical-question-engagement-v1": "rejected",
        }
        for rule_id, status in expected_originals.items():
            row = database.fetchone("SELECT review_status FROM rubric_rules WHERE id=?", (rule_id,))
            assert row is not None and row["review_status"] == status

        for replacement_id in (
            "owner-amended-criminal-element-defence-v2",
            "owner-amended-question-engagement-v2",
        ):
            row = database.fetchone(
                """
                SELECT source_version_id, review_status FROM rubric_rules WHERE id=?
                """,
                (replacement_id,),
            )
            assert row is not None
            assert row["source_version_id"] is None
            assert row["review_status"] == "approved"
            review = database.fetchone(
                "SELECT status, reason FROM reviews WHERE id=?",
                (f"review-owner-decision-{replacement_id}",),
            )
            assert review is not None
            assert (review["status"], review["reason"]) == (
                "approved",
                REPLACEMENT_REASON,
            )

        assert (
            database.fetchone(
                "SELECT reason FROM reviews WHERE id=?",
                ("review-feedback-reaudit-assessment-canonical-case-synthesis-v1",),
            )["reason"]
            == APPROVAL_REASON
        )
        assert (
            database.fetchone(
                "SELECT reason FROM reviews WHERE id=?",
                ("review-feedback-reaudit-assessment-canonical-question-engagement-v1",),
            )["reason"]
            == SUPERSESSION_REASON
        )

        first_state = _safe_state(database)
        assert (
            apply_owner_decisions(
                database,
                _Cipher(),
                manifest,
                now="2026-08-15T09:09:09+00:00",
            )
            == "already_applied"
        )
        assert _safe_state(database) == first_state
    finally:
        database.close()


def test_application_fails_if_staged_rule_changed(tmp_path: Path) -> None:
    manifest = load_and_validate_manifest()
    database = Database(tmp_path / "catalog.sqlite3")
    database.initialize()
    try:
        _insert_owner_review_fixture(database, manifest)
        with database.transaction() as connection:
            connection.execute(
                "UPDATE rubric_rules SET rule_text='changed' WHERE id=?",
                ("assessment-canonical-case-synthesis-v1",),
            )
        with pytest.raises(ValueError, match="target content changed"):
            apply_owner_decisions(database, _Cipher(), manifest)
    finally:
        database.close()
