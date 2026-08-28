from __future__ import annotations

import json
from pathlib import Path

from app.db import Database, utc_iso
from app.quality.policy import POLICY_VERSION


def test_raw_repaired_and_released_versions_are_all_preserved(database: Database, cipher) -> None:
    database.create_job(
        job_id="job-1",
        encrypted_question=cipher.encrypt_text("Question"),
        question_summary="Question",
        request={
            "task_type": "essay",
            "jurisdiction": "England and Wales",
            "word_target": 970,
            "online_mode": "local_only",
            "upload_ids": [],
        },
    )
    versions = [
        ("raw", "raw_model", "raw " * 970, None),
        ("checked", "structured", "checked " * 391, None),
        ("released", "targeted_repair", "released " * 780, "verified_full"),
    ]
    for number, (answer_id, kind, content, state) in enumerate(versions, start=1):
        database.store_answer_version(
            answer_id=answer_id,
            job_id="job-1",
            version_number=number,
            version_kind=kind,
            encrypted_content=cipher.encrypt_text(content),
            word_count=len(content.split()),
            release_state=state,
            policy_version=POLICY_VERSION,
            model_version="test-model",
            index_build_id=None,
            parent_version_id=versions[number - 2][0] if number > 1 else None,
            encrypted_diff_from_parent=(
                cipher.encrypt_text("explicit diff") if number > 1 else None
            ),
            purge_after_days=None if state else 30,
        )
    stored = database.answer_versions("job-1")
    assert [row["version_kind"] for row in stored] == ["raw_model", "structured", "targeted_repair"]
    assert cipher.decrypt_text(stored[0]["encrypted_content"]).split().__len__() == 970
    assert cipher.decrypt_text(stored[1]["encrypted_diff_from_parent"]) == "explicit diff"
    assert stored[1]["diff_from_parent"] is None
    assert stored[2]["release_state"] == "verified_full"


def test_quality_report_persists_reviewer_and_standards_identities(
    database: Database, cipher
) -> None:
    database.create_job(
        job_id="job-review-identities",
        encrypted_question=cipher.encrypt_text("Question"),
        question_summary="Question",
        request={"word_target": 100},
    )
    database.store_answer_version(
        answer_id="answer-review-identities",
        job_id="job-review-identities",
        version_number=1,
        version_kind="structured",
        encrypted_content=cipher.encrypt_text("Answer"),
        word_count=1,
        policy_version=POLICY_VERSION,
        model_version="test-model",
        index_build_id=None,
    )
    database.store_quality_report(
        {
            "id": "quality-review-identities",
            "answer_version_id": "answer-review-identities",
            "evidence_passed": True,
            "academic_score": 74.0,
            "rubric_scores": {},
            "findings": [],
            "release_state": "verified_full",
            "ai_evidence_review": {
                "schema": "legalbot.ai-evidence-review.v1",
                "seal_sha256": "a" * 64,
            },
            "ai_evidence_adjudication": {
                "schema": "legalbot.ai-evidence-adjudication.v1",
                "passed": True,
                "seal_sha256": "b" * 64,
            },
            "assessment_standards": {
                "schema": "legalbot.assessment-standards-report.v1",
                "avoidance_passed": True,
                "seal_sha256": "c" * 64,
            },
        },
        POLICY_VERSION,
    )

    row = database.fetchone("SELECT * FROM quality_reports WHERE id='quality-review-identities'")
    assert row is not None
    assert json.loads(row["ai_evidence_review_json"])["seal_sha256"] == "a" * 64
    assert json.loads(row["ai_evidence_adjudication_json"])["passed"] is True
    assert json.loads(row["assessment_standards_json"])["avoidance_passed"] is True


def test_review_decision_atomically_updates_assessment_rule(database: Database) -> None:
    now = utc_iso()
    database.execute(
        """
        INSERT INTO rubric_rules(
          id, task_type, subject, criterion, polarity, grade_band, rule_text,
          review_status, created_at
        ) VALUES ('rule-1', 'essay', 'land', 'analysis', 'positive_pattern',
                  '70+', 'Explain why the authority supports the thesis.', 'staged', ?)
        """,
        (now,),
    )
    database.execute(
        """
        INSERT INTO reviews(id, review_type, target_id, status, reason, created_at)
        VALUES ('review-rule-1', 'assessment_rule', 'rule-1', 'pending', 'check', ?)
        """,
        (now,),
    )
    assert database.decide_review("review-rule-1", "approved", "confirmed")
    rules = database.approved_assessment_rules(task_type="essay", subject="land")
    assert [row["id"] for row in rules] == ["rule-1"]


def test_repair_empty_chunks_backs_up_before_removal(database: Database, tmp_path: Path) -> None:
    now = utc_iso()
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, created_at, updated_at
        ) VALUES ('doc-empty', ?, 'identity-empty', 'Source empty',
                  'text/plain', 'citable', ?, ?)
        """,
        ("a" * 64, now, now),
    )
    database.execute(
        """
        INSERT INTO source_versions(
          id, document_id, version_sha256, canonical_markdown_path, created_at
        ) VALUES ('version-empty', 'doc-empty', ?, 'data/vault/object', ?)
        """,
        ("a" * 64, now),
    )
    database.execute(
        """
        INSERT INTO chunks(
          id, source_version_id, ordinal, locator, text_sha256,
          markdown_text, token_count
        ) VALUES ('chunk-empty', 'version-empty', 0, 'page 1', ?, ' \n\t\r ', 0)
        """,
        ("b" * 64,),
    )

    result = database.repair_empty_chunks(tmp_path / "backups")

    assert result["removed"] == 1
    assert result["backup"]
    assert (tmp_path / "backups" / str(result["backup"])).is_file()
    assert database.fetchone("SELECT id FROM chunks WHERE id='chunk-empty'") is None


def test_initialize_scrubs_legacy_absolute_source_roots(database: Database) -> None:
    now = utc_iso()
    legacy_path = "/Users/owner/Desktop/Private Law Materials"
    database.execute(
        """
        INSERT INTO source_scans(
          id, status, required_roots_json, roots_seen_json, created_at
        ) VALUES ('legacy-roots', 'complete', ?, ?, ?)
        """,
        (
            json.dumps([{"id": "root-old", "path": legacy_path}]),
            json.dumps([legacy_path]),
            now,
        ),
    )

    database.initialize()
    row = database.fetchone(
        "SELECT required_roots_json, roots_seen_json FROM source_scans WHERE id='legacy-roots'"
    )
    assert row is not None
    combined = f"{row['required_roots_json']} {row['roots_seen_json']}"
    assert legacy_path not in combined
    for field in ("required_roots_json", "roots_seen_json"):
        descriptors = json.loads(row[field])
        assert descriptors[0]["id"] == "source-root-1"
        assert len(descriptors[0]["fingerprint"]) == 64

    # Re-running the migration is idempotent rather than repeatedly hashing.
    before = (row["required_roots_json"], row["roots_seen_json"])
    database.initialize()
    after = database.fetchone(
        "SELECT required_roots_json, roots_seen_json FROM source_scans WHERE id='legacy-roots'"
    )
    assert after is not None
    assert (after["required_roots_json"], after["roots_seen_json"]) == before
