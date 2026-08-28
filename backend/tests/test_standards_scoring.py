from __future__ import annotations

import json
from datetime import date

import pytest

from app.assessment.guidance_bundle import (
    OWNER_ASSESSMENT_BUNDLE,
    applicable_guidance_rules,
)
from app.assessment.standards_scoring import (
    AssessmentStandardsReport,
    score_applicable_standards,
)
from app.quality.draft_identity import source_draft_sha256
from app.types import StructuredClaimDraft, StructuredDraft, StructuredSectionDraft, TaskType


def _draft(*, task_type: TaskType, text: str) -> StructuredDraft:
    return StructuredDraft(
        title="Analysis",
        task_type=task_type,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 20),
        sections=[
            StructuredSectionDraft(
                id="issues",
                heading="Issues and elements",
                claims=[
                    StructuredClaimDraft(
                        id="claim-1",
                        text=text,
                        evidence_ids=[],
                        material=True,
                    )
                ],
            ),
            StructuredSectionDraft(
                id="conclusion",
                heading="Conclusion",
                claims=[
                    StructuredClaimDraft(
                        id="claim-2",
                        text="Therefore the competing outcome depends on the missing fact.",
                        evidence_ids=[],
                        material=False,
                    )
                ],
            ),
        ],
    )


def test_applicable_rules_are_complete_not_prompt_budgeted() -> None:
    rules = applicable_guidance_rules(
        OWNER_ASSESSMENT_BUNDLE,
        task_type="problem",
        subject="criminal",
    )
    ids = {item.rule_id for item in rules}
    assert "owner-amended-criminal-element-defence-v2" in ids
    assert "owner-problem-issue-application-v1" in ids
    assert "owner-essay-thesis-synthesis-v1" not in ids
    assert len(ids) == len(rules)


def test_standards_report_scores_every_applicable_rule_without_prose() -> None:
    draft = _draft(
        task_type=TaskType.PROBLEM,
        text=(
            "The better view is qualified because each element and defence must be "
            "applied to these facts; however the alternative outcome is weaker."
        ),
    )
    report = score_applicable_standards(
        draft=draft,
        question="Advise the parties on every offence element and defence.",
        subject="criminal",
        evidence_by_id={},
        supported_claim_ids=(),
    )
    applicable = applicable_guidance_rules(
        OWNER_ASSESSMENT_BUNDLE, task_type="problem", subject="criminal"
    )
    assert report.applicable_rule_count == len(applicable)
    assert {item.rule_id for item in report.scores} == {item.rule_id for item in applicable}
    encoded = json.dumps(report.model_dump(mode="json", by_alias=True)).casefold()
    assert "advise the parties" not in encoded
    assert "better view" not in encoded
    assert report.legal_authority is False
    assert report.source_draft_sha256 == source_draft_sha256(draft)


def test_standards_report_is_deterministic_and_tamper_evident() -> None:
    draft = _draft(task_type=TaskType.ESSAY, text="The law applies.")
    kwargs = {
        "draft": draft,
        "question": "Critically evaluate the proposition.",
        "subject": "contract",
        "evidence_by_id": {},
        "supported_claim_ids": (),
    }
    first = score_applicable_standards(**kwargs)
    second = score_applicable_standards(**kwargs)
    assert first == second
    assert not first.avoidance_passed
    changed = first.model_dump(mode="json", by_alias=True)
    changed["quality_target_met"] = not changed["quality_target_met"]
    with pytest.raises(ValueError, match="aggregate|seal"):
        AssessmentStandardsReport.model_validate(changed)
