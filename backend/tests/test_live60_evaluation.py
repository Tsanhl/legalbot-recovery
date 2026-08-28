from __future__ import annotations

import hashlib
import json
import shutil
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.evaluation.live_suite import (
    LiveGenerationRunPlan,
    admission_as_of_date,
    load_live_evaluation_bundle,
    load_question_registry,
    sealed_sha256,
)
from app.evaluation.live_suite_gold import (
    GOLD_CASE_SCHEMA,
    GOLD_ISSUE_SCHEMA,
    GOLD_SCHEMA,
    LiveSuiteExpertQualification,
    qualification_template_for_suite,
)
from app.orchestration.classifier import classify_subject, classify_subjects
from app.orchestration.routing import decide_route
from app.retrieval.service import _query_subjects
from app.types import TaskType

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
LEGACY_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-30-v1"
SELECTED_IDS = (
    "live30-q02",
    "live30-q03",
    "live30-q06",
    "live30-q07",
    "live30-q13",
    "live30-q15",
    "live30-q16",
    "live30-q17",
    "live30-q20",
    "live30-q21",
    "live30-q23",
    "live30-q24",
    "live30-q26",
    "live30-q27",
    "live30-q29",
    "live60-q31",
    "live60-q32",
    "live60-q35",
    "live60-q38",
    "live60-q40",
    "live60-q42",
    "live60-q43",
    "live60-q46",
    "live60-q48",
    "live60-q49",
    "live60-q51",
    "live60-q53",
    "live60-q56",
    "live60-q59",
    "live60-q60",
)


def test_live60_bundle_is_exact_evaluation_only_contract() -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)

    assert bundle.registry.case_count == 60
    assert bundle.registry.total_word_target == 215_000
    assert Counter(case.task_type for case in bundle.registry.cases) == {
        "problem": 39,
        "essay": 21,
    }
    assert bundle.manifest.accepted_baseline_status == "no_go"
    assert bundle.manifest.expert_reviewers_required == 1
    assert bundle.manifest.eligible_for_training is False
    assert bundle.manifest.training_export_allowed is False
    assert bundle.run_plan.generation_case_count == 30
    assert bundle.run_plan.generation_total_word_target == 114_000
    assert bundle.run_plan.stability_repeats == 0
    assert bundle.run_plan.online_research_allowed is False
    assert (BUNDLE_ROOT / "source-questions-31-60.sha256").read_text().strip() == (
        "b226a8ebf2d5faad8c5dd954ff080a29124fd2305338f3d1d68dbf54b21be06f"
    )
    assert (BUNDLE_ROOT / "accepted-no-go-memo.sha256").read_text().strip() == (
        "07120ee3748221e98583b153efb2ca23fd391433a17fc21a5950a92336421e1f"
    )


def test_live60_preserves_every_sealed_live30_record_and_digest() -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    legacy = load_question_registry(LEGACY_ROOT / "cases.jsonl")

    assert bundle.registry.cases[:30] == legacy.cases
    assert legacy.file_sha256 == (
        "65709b6bda056879c591780e5e8aec5e95e72a26dec7854369e7e4175a64b3c3"
    )
    assert hashlib.sha256((LEGACY_ROOT / "manifest.json").read_bytes()).hexdigest() == (
        "5653c6eec45edba7473aacf810232254f8ccb41a8e875eb08802a794eb52a3e0"
    )
    assert all(case.schema_name.endswith(".v1") for case in bundle.registry.cases[:30])
    assert all(case.schema_name.endswith(".v2") for case in bundle.registry.cases[30:])


def test_run_plan_selects_exact_single_pass_and_marks_every_other_case() -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    selected = tuple(
        item.case_id for item in bundle.run_plan.cases if item.disposition == "generate_once"
    )
    not_selected = tuple(
        item for item in bundle.run_plan.cases if item.disposition == "coverage_only_not_selected"
    )

    assert selected == SELECTED_IDS
    assert len(not_selected) == 30
    assert all(item.pass_count == 0 for item in not_selected)
    assert Counter(
        bundle.registry.case(case_id).expected_research_route for case_id in selected
    ) == {"sectioned": 15, "full_enquiry": 15}
    assert (
        bundle.run_plan.annexes["A"] + bundle.run_plan.annexes["B"] + bundle.run_plan.annexes["C"]
        == selected
    )


def test_london_admission_date_not_utc_controls_current_law() -> None:
    assert admission_as_of_date(datetime(2026, 8, 15, 23, 30, tzinfo=UTC)).isoformat() == (
        "2026-08-16"
    )
    assert admission_as_of_date(datetime(2026, 1, 15, 23, 30, tzinfo=UTC)).isoformat() == (
        "2026-01-15"
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        admission_as_of_date(datetime(2026, 8, 15, 23, 30))


def test_expert_template_is_all_60_and_deliberately_unsealable() -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    template = qualification_template_for_suite(
        bundle,
        index_build_id="candidate-live60-test",
        as_of_date=admission_as_of_date(datetime(2026, 8, 15, 10, 0, tzinfo=UTC)),
    )

    assert template["case_count"] == 60
    assert len(template["cases"]) == 60
    assert template["approval_status"] == "needs_expert_annotation"
    assert template["independent_second_review_status"] == "not_required"
    assert template["owner_is_primary_reviewer"] is True
    assert template["ai_role"] == "mechanical_accuracy_verifier_only"
    assert template["ai_second_reviewer_forbidden"] is True
    assert all(not case["acceptable_source_ids"] for case in template["cases"])
    with pytest.raises(ValidationError):
        LiveSuiteExpertQualification.model_validate(template)


def test_bundle_fails_closed_on_registry_and_lineage_tampering(tmp_path: Path) -> None:
    copied = tmp_path / "live-evaluation-60-v1"
    shutil.copytree(BUNDLE_ROOT, copied)
    rows = (copied / "cases.jsonl").read_text(encoding="utf-8").splitlines()
    first_new = json.loads(rows[30])
    first_new["subject"] = "tampered"
    rows[30] = json.dumps(first_new, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    (copied / "cases.jsonl").write_text("\n".join(rows) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid live question at line 31"):
        load_live_evaluation_bundle(
            copied,
            legacy_live30_registry=LEGACY_ROOT / "cases.jsonl",
            legacy_live30_manifest=LEGACY_ROOT / "manifest.json",
        )


def test_bundle_requires_all_lineage_sidecars(tmp_path: Path) -> None:
    copied = tmp_path / "live-evaluation-60-v1"
    shutil.copytree(BUNDLE_ROOT, copied)
    (copied / "accepted-no-go-memo.sha256").unlink()

    with pytest.raises(ValueError, match="memo digest record"):
        load_live_evaluation_bundle(
            copied,
            legacy_live30_registry=LEGACY_ROOT / "cases.jsonl",
            legacy_live30_manifest=LEGACY_ROOT / "manifest.json",
        )


def test_run_plan_rejects_schema_or_selection_tampering() -> None:
    value = json.loads((BUNDLE_ROOT / "generation-run-plan.json").read_text())
    value["schema"] = "legalbot.wrong.v1"
    with pytest.raises(ValidationError):
        LiveGenerationRunPlan.model_validate(value)


def test_live60_classifier_and_router_match_every_frozen_case() -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    for case in bundle.registry.cases:
        assert (
            decide_route(case.question, case.word_target, TaskType(case.task_type)).route.value
            == case.expected_research_route
        )
    for case in bundle.registry.cases[30:]:
        assert classify_subject(case.question) == case.subject
        assert case.subject in classify_subjects(case.question)
        assert case.subject not in _query_subjects(case.subject)


def test_subject_matching_does_not_use_incidental_substrings() -> None:
    observed = classify_subjects(
        "A practical answer discusses release, remediation and an ordinary consent order."
    )
    assert "financial services" not in observed
    assert "land" not in observed
    assert "mediation and adr" not in observed
    assert "medical law" not in observed


def _test_only_knowledge_gap_overlay(
    *,
    second_status: str = "not_required",
    second_role: str | None = None,
    second_ref: str | None = None,
    approval_ref: str = "1" * 64,
) -> dict[str, object]:
    """Synthetic overlay used only to test reviewer-contract validators.

    Every issue is an explicit knowledge gap. This is not legal gold and must
    never be written into a Live60 run directory or readiness artifact.
    """

    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    value: dict[str, object] = {
        "schema": GOLD_SCHEMA,
        "suite_id": "live-evaluation-60-v1",
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "index_build_id": "candidate-live60-reviewer-contract",
        "as_of_date": "2026-08-16",
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "approval_status": "expert_approved",
        "approval_role": "legal_expert_owner",
        "approval_reviewer_role": "england_wales_qualified_solicitor",
        "approval_reviewer_ref": f"reviewer:{approval_ref}",
        "owner_is_primary_reviewer": True,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "independent_second_review_status": second_status,
        "independent_second_reviewer_role": second_role,
        "independent_second_reviewer_ref": second_ref,
        "material_disagreement_status": "none",
        "adjudication_ref": None,
        "case_count": 60,
        "cases": [
            {
                "schema": GOLD_CASE_SCHEMA,
                "case_id": case.case_id,
                "question_sha256": case.question_sha256,
                "record_sha256": case.record_sha256,
                "status": "knowledge_gap",
                "contrary_authority_status": "reviewed_none",
                "acceptable_source_ids": [],
                "issues": [
                    {
                        "schema": GOLD_ISSUE_SCHEMA,
                        "issue_id": f"issue-{number:02d}",
                        "status": "knowledge_gap",
                        "reason_code": "test-fixture-knowledge-gap",
                        "exact_gold_spans": [],
                    }
                    for number in range(1, len(case.must_cover_issues) + 1)
                ],
            }
            for case in bundle.registry.cases
        ],
    }
    value["seal_sha256"] = sealed_sha256(value)
    return value


def test_live60_one_reviewer_overlay_allows_optional_second_review() -> None:
    overlay = LiveSuiteExpertQualification.model_validate(_test_only_knowledge_gap_overlay())
    assert overlay.independent_second_review_status == "not_required"
    assert overlay.independent_second_reviewer_role is None
    assert overlay.independent_second_reviewer_ref is None
    assert overlay.owner_is_primary_reviewer is True
    assert overlay.ai_role == "mechanical_accuracy_verifier_only"
    assert overlay.ai_second_reviewer_forbidden is True

    pending = LiveSuiteExpertQualification.model_validate(
        _test_only_knowledge_gap_overlay(second_status="needs_independent_review")
    )
    assert pending.independent_second_review_status == "needs_independent_review"

    confirmed = LiveSuiteExpertQualification.model_validate(
        _test_only_knowledge_gap_overlay(
            second_status="confirmed",
            second_role="england_wales_qualified_legal_academic",
            second_ref=f"reviewer:{'2' * 64}",
        )
    )
    assert confirmed.independent_second_reviewer_ref != confirmed.approval_reviewer_ref


def test_live60_second_reviewer_metadata_is_fail_closed() -> None:
    stray_metadata = _test_only_knowledge_gap_overlay(
        second_role="england_wales_qualified_legal_academic"
    )
    with pytest.raises(ValidationError, match="must be empty unless status is confirmed"):
        LiveSuiteExpertQualification.model_validate(stray_metadata)

    missing_confirmed = _test_only_knowledge_gap_overlay(second_status="confirmed")
    with pytest.raises(ValidationError, match="requires independent reviewer details"):
        LiveSuiteExpertQualification.model_validate(missing_confirmed)

    same_reviewer = _test_only_knowledge_gap_overlay(
        second_status="confirmed",
        second_role="england_wales_qualified_legal_academic",
        second_ref=f"reviewer:{'1' * 64}",
    )
    with pytest.raises(ValidationError, match="must be independent"):
        LiveSuiteExpertQualification.model_validate(same_reviewer)
