from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from app.assessment.guidance_bundle import (
    MARKER_POSITIVE_SIGNAL,
    OWNER_ASSESSMENT_BUNDLE,
    AssessmentGuidanceRule,
    budget_assessment_guidance,
    instruction_for_rule,
    source_span_sha256,
    validate_bundle,
    validate_guidance_rule,
    verified_rules_from_reviewed_records,
)


def test_owner_bundle_expresses_70_and_lower_band_repair_semantics() -> None:
    assert validate_bundle(OWNER_ASSESSMENT_BUNDLE) == ()
    positives = [rule for rule in OWNER_ASSESSMENT_BUNDLE.rules if rule.grade_band == "70+"]
    sixty = [rule for rule in OWNER_ASSESSMENT_BUNDLE.rules if rule.grade_band == "60-69"]
    fifty = [rule for rule in OWNER_ASSESSMENT_BUNDLE.rules if rule.grade_band == "50-59"]

    assert positives and sixty and fifty
    assert all(rule.positive_target and rule.anti_pattern is None for rule in positives)
    assert all(rule.anti_pattern and rule.repair_action for rule in [*sixty, *fifty])
    assert all(rule.source_span_hash for rule in OWNER_ASSESSMENT_BUNDLE.rules)
    assert len(OWNER_ASSESSMENT_BUNDLE.rules) == 16
    assert OWNER_ASSESSMENT_BUNDLE.version == "owner-standards-2026-08-14.1"


def test_audit_candidate_assessment_rules_are_not_live() -> None:
    path = (
        Path(__file__).resolve().parents[2]
        / "Live60-2026-08-16"
        / "go-execution"
        / "candidate-assessment-rules-2026-08-16.json"
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    live_ids = {rule.rule_id for rule in OWNER_ASSESSMENT_BUNDLE.rules}
    candidate_ids = {item["Candidate rule ID"] for item in payload["rules"]}
    assert payload["not_live"] is True
    assert payload["do_not_bulk_approve"] is True
    assert payload["oscola_fourth_edition_must_not_overwrite_oscola_5"] is True
    assert live_ids.isdisjoint(candidate_ids)


def test_bundle_sha_is_stable_and_content_sensitive() -> None:
    first = OWNER_ASSESSMENT_BUNDLE.sha256
    assert first == OWNER_ASSESSMENT_BUNDLE.sha256
    changed = replace(
        OWNER_ASSESSMENT_BUNDLE,
        rules=(
            replace(
                OWNER_ASSESSMENT_BUNDLE.rules[0],
                positive_target=OWNER_ASSESSMENT_BUNDLE.rules[0].positive_target + " Extra.",
            ),
            *OWNER_ASSESSMENT_BUNDLE.rules[1:],
        ),
    )
    assert changed.sha256 != first


def test_budgeting_selects_only_whole_rules_and_balances_semantics() -> None:
    full = {
        instruction_for_rule(rule)
        for rule in OWNER_ASSESSMENT_BUNDLE.rules
        if rule.task_type in {"any", "essay"}
    }
    selected = budget_assessment_guidance(
        OWNER_ASSESSMENT_BUNDLE,
        task_type="essay",
        subject="contract",
        max_characters=1_100,
    )

    assert selected.character_count <= 1_100
    assert selected.instructions
    assert set(selected.instructions) <= full
    assert selected.omitted_rule_ids
    assert any(rule.grade_band == "70+" for rule in selected.selected_rules)
    assert any(rule.grade_band in {"60-69", "50-59"} for rule in selected.selected_rules)
    assert all(
        not instruction.endswith((" ant", " or", " and")) for instruction in selected.instructions
    )


@pytest.mark.parametrize(
    ("source_text", "expected"),
    (
        ("Q3: 75 Excellent 3", "source_score_fragment"),
        (
            "Email marker@example.com about /Users/owner/Desktop/file.pdf",
            "source_pii_or_local_path",
        ),
        ("T’s refusal: V good 2.", "source_student_specific_fact"),
        ("Analysis", "source_vague_or_heading"),
        (
            "The Consumer Rights Act 2015 provides the governing answer.",
            "source_substantive_law",
        ),
        (
            "The argument is strong but needs more analysis and clearer authority.",
            "mixed_unsplit_feedback",
        ),
    ),
)
def test_marker_validator_rejects_prohibited_feedback_shapes(
    source_text: str, expected: str
) -> None:
    rule = AssessmentGuidanceRule(
        rule_id="marker-analysis-standard-v1",
        source_span_hash=source_span_sha256(source_text),
        grade_band="70+",
        criterion="analysis",
        task_type="essay",
        subject=None,
        positive_target="Explain the reasoning that connects authority to the qualified conclusion.",
        anti_pattern=None,
        repair_action="Add the missing analytical step.",
        verification_signal=MARKER_POSITIVE_SIGNAL,
    )
    assert expected in validate_guidance_rule(rule, source_span_text=source_text)


def test_marker_validator_detects_subject_and_criterion_provenance_mismatch() -> None:
    source = "Very good knowledge of implied terms and remedies for breach in contract."
    rule = AssessmentGuidanceRule(
        rule_id="marker-trust-classification-v1",
        source_span_hash=source_span_sha256(source),
        grade_band="70+",
        criterion="issue_spotting",
        task_type="problem",
        subject="trusts",
        positive_target="Identify every material issue before beginning the application.",
        anti_pattern=None,
        repair_action="Add the omitted issue to the issue map.",
        verification_signal=MARKER_POSITIVE_SIGNAL,
    )
    issues = validate_guidance_rule(rule, source_span_text=source)
    assert "mismatched_provenance" in issues
    assert "mismatched_subject_provenance" in issues


def test_staged_or_rejected_records_never_enter_verified_bundle() -> None:
    rule = OWNER_ASSESSMENT_BUNDLE.rules[0]
    base = {**rule.canonical_record(), "source_span_text": None}
    loaded = verified_rules_from_reviewed_records(
        (
            {**base, "review_status": "staged"},
            {**base, "review_status": "rejected"},
            {**base, "review_status": "approved"},
        )
    )
    assert loaded == (rule,)


def test_approved_record_with_changed_content_fails_closed() -> None:
    rule = OWNER_ASSESSMENT_BUNDLE.rules[0]
    record = {
        **rule.canonical_record(),
        "review_status": "approved",
        "positive_target": rule.positive_target + " Changed after approval.",
    }
    with pytest.raises(ValueError, match="mismatched_provenance"):
        verified_rules_from_reviewed_records((record,))


def test_reaudit_report_is_machine_readable_and_non_mutating() -> None:
    project_root = Path(__file__).resolve().parents[2]
    payload = json.loads(
        (project_root / "docs/reports/assessment-guidance-reaudit-2026-08-14.json").read_text(
            encoding="utf-8"
        )
    )
    records = payload["records"]
    assert payload["database_mutation_performed"] is False
    assert payload["raw_feedback_included"] is False
    assert len(records) == 25
    assert len({record["rule_id"] for record in records}) == 25
    observed = {
        status: sum(record["disposition"] == status for record in records)
        for status in payload["summary"]
        if status != "automatic_database_decisions"
    }
    assert observed == {
        "exact_support_candidate": 4,
        "partial_support_reword": 10,
        "unsupported_mapping_reopen": 11,
    }
    assert all(len(record["source_span_hash"]) == 64 for record in records)
