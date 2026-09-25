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
from app.runtime_adapters import MAX_ASSESSMENT_RULE_CHARS


def test_owner_bundle_expresses_70_and_lower_band_repair_semantics() -> None:
    assert validate_bundle(OWNER_ASSESSMENT_BUNDLE) == ()
    positives = [rule for rule in OWNER_ASSESSMENT_BUNDLE.rules if rule.grade_band == "70+"]
    sixty = [rule for rule in OWNER_ASSESSMENT_BUNDLE.rules if rule.grade_band == "60-69"]
    fifty = [rule for rule in OWNER_ASSESSMENT_BUNDLE.rules if rule.grade_band == "50-59"]

    assert positives and sixty and fifty
    assert all(rule.positive_target and rule.anti_pattern is None for rule in positives)
    assert all(rule.anti_pattern and rule.repair_action for rule in [*sixty, *fifty])
    assert all(rule.source_span_hash for rule in OWNER_ASSESSMENT_BUNDLE.rules)
    assert len(OWNER_ASSESSMENT_BUNDLE.rules) == 31
    assert {"law-p5-state-assumptions-v1", "law-a-fence-sitting-v1"} <= {
        rule.rule_id for rule in OWNER_ASSESSMENT_BUNDLE.rules
    }
    assert OWNER_ASSESSMENT_BUNDLE.version == "owner-law-folder-2026-09-25.1"
    rules = {rule.rule_id: rule.positive_target for rule in OWNER_ASSESSMENT_BUNDLE.rules}
    assert "exceptions" in rules["law-p3-full-test-applied-v1"]
    assert "obiter" in rules["law-u7-exact-authority-v1"]
    assert "counterargument" in rules["law-u3-counterargument-then-position-v1"]


def test_compact_budget_gives_qwen_every_applicable_rule() -> None:
    for task in ("general", "essay", "problem"):
        guidance = budget_assessment_guidance(
            OWNER_ASSESSMENT_BUNDLE, task_type=task, subject=None,
            max_characters=MAX_ASSESSMENT_RULE_CHARS, compact=True,
        )
        assert guidance.omitted_rule_ids == ()


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
