from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PARENT = PROJECT_ROOT / "data/evaluations/phase2b-question-drafts"
VISIBLE = PARENT / "LegalBot-Phase2B-2026-08-28-common-public-visible-development-r2"
PRIVATE = PARENT / "LegalBot-Phase2B-2026-08-28-common-public-private-unseen-r2"


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _rows(root: Path) -> list[dict]:
    rows = []
    for path in root.glob("topics/*/*.jsonl"):
        rows.extend(_read_jsonl(path))
    return rows


def _verify_checksums(root: Path) -> None:
    for line in (root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == expected


def test_visible_and_private_packages_are_physically_separate() -> None:
    visible_manifest = json.loads((VISIBLE / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8"))
    private_manifest = json.loads((PRIVATE / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8"))
    assert (
        visible_manifest["status"]
        == "CORRECTED_VISIBLE_COMMON_PUBLIC_R2_READY_FOR_OWNER_REVIEW_NOT_PHASE2B"
    )
    assert visible_manifest["core_question_count"] == 306
    assert visible_manifest["stress_question_count"] == 25
    assert visible_manifest["visible_question_count"] == 331
    assert visible_manifest["unseen_file_count"] == 0
    assert private_manifest["status"] == "PRIVATE_UNSEEN_CUSTODY_R2_READY_NOT_OWNER_FROZEN"
    assert private_manifest["question_count"] == 306
    assert private_manifest["markdown_projection_created"] is False
    assert private_manifest["included_in_visible_zip"] is False
    assert (
        visible_manifest["private_unseen_package_content_sha256"]
        == private_manifest["package_content_sha256"]
    )
    assert not [path for path in VISIBLE.rglob("*") if "unseen" in path.name.casefold()]
    assert not list(PRIVATE.rglob("*.md"))
    for path in PRIVATE.glob("topics/*/*.jsonl"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_all_reconstructed_amendments_and_stress_additions_are_applied() -> None:
    report = json.loads((VISIBLE / "AMENDMENT-APPLICATION-REPORT.json").read_text(encoding="utf-8"))
    assert report["status"] == "PASS_ALL_RECONSTRUCTED_REVIEW_AMENDMENTS_APPLIED"
    assert report["amendment_count"] == 44
    assert report["must_amend_count"] == 34
    assert report["should_amend_count"] == 10
    assert report["contamination_only_rewrite_count"] == 6
    assert report["stress_addition_count"] == 25
    assert report["unmatched_amendment_count"] == 0
    assert report["source_prompt_mismatch_count"] == 0
    assert report["malformed_controlled_vocabulary_count"] == 0
    assert report["universal_clarification_rule_removed"] is True
    rows = _rows(VISIBLE)
    assert len(rows) == 331
    assert Counter(row["lane"] for row in rows) == {
        "COMMON_PUBLIC_VISIBLE_DEVELOPMENT_CORE_R2": 306,
        "COMMON_PUBLIC_VISIBLE_STRESS_TEST_R2": 25,
    }
    priorities = Counter(row["audit_priority"] for row in rows)
    assert priorities["MUST_AMEND"] == 34
    assert priorities["SHOULD_AMEND"] == 10
    assert priorities["CONTAMINATION_REWRITE"] == 6
    assert priorities["STRESS_ADDITION"] == 25


def test_first_class_jurisdiction_time_clarification_and_safety_metadata() -> None:
    rows = _rows(VISIBLE) + _rows(PRIVATE)
    required = {
        "primary_jurisdiction",
        "conditional_jurisdictions",
        "jurisdiction_status",
        "material_date",
        "material_dates",
        "temporal_status",
        "fact_status",
        "limitation_or_deadline_target",
        "blocking_clarification_required",
        "answer_then_clarify_allowed",
        "assumption_disclosure_required",
        "regulated_advice_boundary",
        "safety_refusal_required",
        "immediate_actions",
        "evidence_preservation_required",
        "urgent_handoff_required",
        "prohibited_overstatement",
        "gold_answer_negative_propositions",
    }
    assert len(rows) == 637
    for row in rows:
        assert required.issubset(row)
        assert "must_ask_clarifying_questions" not in row
        assert row["answer_then_clarify_allowed"] is True
        assert row["assumption_disclosure_required"] is True
        assert row["temporal_status"] in {
            "IN_FORCE",
            "TRANSITIONAL",
            "ENACTED_NOT_COMMENCED",
            "PROPOSED",
            "NOT_APPLICABLE",
            "FACT_DEPENDENT",
        }
        assert "SCHEME_RULE_OR BOOKLET" not in row["required_document_categories"]
        assert "DECISION_OR TREATMENT_PLAN" not in row["required_document_categories"]
        assert row["phase2b_authorized"] is False
        assert row["phase2b_run"] is False
    visible_rows = _rows(VISIBLE)
    refusal_rows = [row for row in visible_rows if row["safety_refusal_required"]]
    assert len(refusal_rows) == 4
    assert all("wrongdoing-request" in row["issue_tags"] for row in refusal_rows)
    assert all(row["evidence_preservation_required"] for row in refusal_rows)


def test_administrative_and_wills_are_draft_only_pending_source_admission() -> None:
    for root in (VISIBLE, PRIVATE):
        for topic_id in ("administrative-law", "wills-and-estates"):
            rows = _read_jsonl(next((root / "topics" / topic_id).glob("*.jsonl")))
            assert rows
            assert all(
                row["topic_execution_status"]
                == "DRAFT_ONLY_BLOCKED_PENDING_OFFICIAL_SOURCE_ADMISSION"
                for row in rows
            )
            assert all(row["scored_evaluation_eligible"] is False for row in rows)


def test_cross_bank_contamination_checks_pass() -> None:
    visible_audit = json.loads(
        (VISIBLE / "CROSS-BANK-CONTAMINATION-AUDIT.json").read_text(encoding="utf-8")
    )
    private_audit = json.loads(
        (PRIVATE / "CROSS-BANK-CONTAMINATION-AUDIT.json").read_text(encoding="utf-8")
    )
    assert visible_audit["exact_normalized_prompt_overlap_count"] == 0
    assert (
        visible_audit["maximum_similarity"]
        < visible_audit["near_overlap_threshold_exclusive"]
        == 0.55
    )
    assert private_audit["exact_normalized_prompt_overlap_count"] == 0
    assert (
        private_audit["maximum_similarity"]
        < private_audit["near_overlap_threshold_exclusive"]
        == 0.55
    )
    assert private_audit["reference_question_count"] == 671


def test_three_lane_phase2b_plan_is_general_essay_and_problem_based_only() -> None:
    plan = json.loads((VISIBLE / "PHASE2B-THREE-LANE-TEST-PLAN.json").read_text(encoding="utf-8"))
    assert plan["status"] == "PLANNING_ONLY_NOT_PHASE2B"
    assert plan["question_types"] == ["GENERAL_ENQUIRY", "ESSAY", "PROBLEM_BASED"]
    assert plan["general_enquiry"]["visible_core_count"] == 306
    assert plan["general_enquiry"]["visible_stress_count"] == 25
    assert plan["general_enquiry"]["private_unseen_count"] == 306
    assert plan["essay"]["visible_core_count_after_all_17_topics_admitted"] == 102
    assert plan["problem_based"]["visible_core_count_after_all_17_topics_admitted"] == 102
    assert plan["model_training_export"] is False
    assert plan["phase2b_authorized"] is False
    assert plan["phase2b_run"] is False


def test_currentness_controls_are_checkpoints_not_gold() -> None:
    controls = json.loads((VISIBLE / "CURRENTNESS-CONTROLS.json").read_text(encoding="utf-8"))
    assert controls["status"] == "OFFICIAL_CHECKPOINTS_RECORDED_NOT_GOLD_OR_SOURCE_ADMISSION"
    assert controls["official_checkpoint_count"] == 10
    assert "expected spring 2027" in controls["audit_claim_correction"]
    assert controls["source_bytes_downloaded"] is False
    assert controls["source_admission_authorized"] is False
    assert controls["gold_answer_created"] is False
    assert controls["legal_reviewer_completed"] is False


def test_both_packages_have_valid_checksums() -> None:
    _verify_checksums(VISIBLE)
    _verify_checksums(PRIVATE)


def test_visible_and_private_zip_delivery_boundaries() -> None:
    visible_zip = PARENT / f"{VISIBLE.name}.zip"
    private_zip = PARENT / f"{PRIVATE.name}.zip"
    assert (
        hashlib.sha256(visible_zip.read_bytes()).hexdigest()
        == "e95aa7f6ec544dc6c06446c48c9a87f2ef9042aafebe61f401e4ac3adfb2ae91"
    )
    assert (
        hashlib.sha256(private_zip.read_bytes()).hexdigest()
        == "a5c782b011995932419788b0bcc66ebe10467fabd8d4244a0003a6f4efd6c267"
    )
    assert visible_zip.stat().st_size == 210_008
    assert private_zip.stat().st_size == 99_831
    with zipfile.ZipFile(visible_zip) as archive:
        names = archive.namelist()
        assert names
        assert not any("unseen" in name.casefold() for name in names)
        assert archive.testzip() is None
    with zipfile.ZipFile(private_zip) as archive:
        assert archive.testzip() is None
        assert any("PRIVATE-UNSEEN-QUESTION-SET.jsonl" in name for name in archive.namelist())
    assert stat.S_IMODE(private_zip.stat().st_mode) == 0o600
