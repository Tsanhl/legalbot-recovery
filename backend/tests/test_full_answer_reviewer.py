from __future__ import annotations

from datetime import date

import pytest

from app.quality.full_answer_reviewer import (
    FullAnswerReviewerOutput,
    invoke_full_answer_reviewer,
)
from app.types import (
    EvidenceSpan,
    MaterialLane,
    StructuredClaimDraft,
    StructuredDraft,
    StructuredSectionDraft,
    TaskType,
)


def _evidence() -> EvidenceSpan:
    return EvidenceSpan(
        id="evidence-1",
        source_version_id="source-version-1",
        chunk_id="chunk-1",
        text="A tenant must receive the prescribed notice before proceedings.",
        locator="s 1",
        lane=MaterialLane.PRIMARY_AUTHORITY,
        jurisdiction="England and Wales",
        subject="housing",
        currentness_status="current",
        content_sha256="c" * 64,
        index_build_id="candidate-v111",
        identity_verified=True,
        currentness_verified=True,
    )


def _draft() -> StructuredDraft:
    return StructuredDraft(
        title="Notice requirements",
        task_type=TaskType.GENERAL,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 9, 8),
        sections=[
            StructuredSectionDraft(
                id="section-1",
                heading="Rule",
                claims=[
                    StructuredClaimDraft(
                        id="claim-1",
                        text="The prescribed notice must be served before proceedings.",
                        evidence_ids=["evidence-1"],
                    )
                ],
            )
        ],
    )


@pytest.mark.asyncio
async def test_complete_answer_review_is_exact_and_sealed() -> None:
    class Model:
        async def invoke_json(self, **kwargs: object):
            assert kwargs["mode"] == "full_answer_review"
            assert '"writing_checks"' in kwargs["system_prompt"]
            payload = kwargs["user_payload"]
            assert isinstance(payload, dict)
            assert payload["rendered_answer"] == "Rendered answer."
            assert payload["candidate_visible_facts"][0]["text"] == "Can notice be skipped?"
            return (
                "full-review-invocation-1",
                {
                    "reviewed_claim_ids": ["claim-1"],
                    "complete_rendered_answer_reviewed": True,
                    "all_material_omissions_checked": True,
                    "omissions": [
                        {
                            "issue_id": "issue-1",
                            "status": "none",
                            "reason_code": "no_material_omission",
                        }
                    ],
                    "writing_checks": [
                        {"rule_id": row["rule_id"], "verdict": "pass", "section_ids": [],
                         "reason_code": "meaning_meets_target"}
                        for row in payload["writing_rules"]
                    ],
                    "verdict": "pass",
                },
            )

    evidence = _evidence()
    result = await invoke_full_answer_reviewer(
        model=Model(),
        question="Can notice be skipped?",
        draft=_draft(),
        rendered_answer="Rendered answer.",
        evidence_by_id={evidence.id: evidence},
        fact_inputs=[{"fact_id": "fact-1", "text": "Can notice be skipped?"}],
        issue_ids=["issue-1"],
        model_id="local-qwen",
        model_version="pinned-revision",
    )

    assert result.passed is True
    assert result.model_independent is False
    assert result.professional_legal_sign_off is False
    assert result.reviewed_claim_ids == ("claim-1",)
    assert len(result.seal_sha256) == 64
    assert result.writing_checks

    from app.quality.full_answer_reviewer import semantic_writing_findings
    from app.types import QualityFinding, Severity
    rule = result.writing_checks[0].rule_id
    writing = QualityFinding(gate="assessment_standards", code="applicable_avoidance_standard_failed",
                             message=f"Advisory writing check {rule} failed.", severity=Severity.HARD_BLOCKER)
    legal = QualityFinding(gate="claim_evidence", code="unsupported_material_fact",
                           message="Unsupported duration", severity=Severity.HARD_BLOCKER)
    length = QualityFinding(gate="requested_length", code="longer_than_requested",
                            message="Too long", severity=Severity.REPAIRABLE)
    reconciled = semantic_writing_findings([writing, legal, length], result)
    assert reconciled[0].severity == Severity.INFORMATIONAL
    assert reconciled[1:] == [legal, length]


@pytest.mark.asyncio
async def test_incomplete_claim_or_issue_coverage_fails_closed() -> None:
    class Model:
        async def invoke_json(self, **_kwargs: object):
            return (
                "full-review-invocation-2",
                {
                    "reviewed_claim_ids": [],
                    "complete_rendered_answer_reviewed": True,
                    "all_material_omissions_checked": True,
                    "omissions": [],
                    "verdict": "pass",
                },
            )

    evidence = _evidence()
    with pytest.raises(ValueError, match="cover claims"):
        await invoke_full_answer_reviewer(
            model=Model(),
            question="Can notice be skipped?",
            draft=_draft(),
            rendered_answer="Rendered answer.",
            evidence_by_id={evidence.id: evidence},
            fact_inputs=[{"fact_id": "fact-1", "text": "Can notice be skipped?"}],
            issue_ids=["issue-1"],
            model_id="local-qwen",
            model_version="pinned-revision",
        )


def test_semantic_writing_failure_cannot_be_called_a_pass():
    from pydantic import ValidationError
    value = {
        "reviewed_claim_ids": ["claim-1"],
        "complete_rendered_answer_reviewed": True,
        "all_material_omissions_checked": True,
        "omissions": [{"issue_id": "issue-1", "status": "none", "reason_code": "covered"}],
        "writing_checks": [{"rule_id": "rule-1", "verdict": "fail",
                            "section_ids": ["section-1"], "reason_code": "conclusion_not_explained"}],
        "verdict": "pass",
    }
    with pytest.raises(ValidationError, match="verdict differs"):
        FullAnswerReviewerOutput.model_validate(value)
    value["verdict"] = "hold"
    assert FullAnswerReviewerOutput.model_validate(value).verdict == "hold"


def test_length_repair_can_condense_all_sections_without_changing_structure():
    from app.orchestration.targeted_repair import failed_section_scope
    from app.types import QualityFinding, Severity
    draft = _draft()
    findings = [QualityFinding(gate="requested_length", code="longer_than_requested",
                              message="Whole answer exceeds target", severity=Severity.REPAIRABLE)]
    assert failed_section_scope(prior=draft, findings=findings) == ("section-1",)


def test_omission_hold_requires_actionable_reason_and_scope():
    from app.quality.full_answer_reviewer import OmissionReview
    with pytest.raises(ValueError, match='explanation and affected section'):
        OmissionReview(issue_id='issue-1', status='material', reason_code='authority_missing')
    finding = OmissionReview(
        issue_id='issue-1', status='material', reason_code='deadline_trigger_missing',
        explanation='The answer gives a deadline without the triggering event in the supplied rule.',
        section_ids=('section-1',), evidence_ids=('evidence-1',),
    )
    assert finding.section_ids == ('section-1',)


def test_passed_writing_check_may_omit_reason_but_failure_must_explain():
    from app.quality.full_answer_reviewer import WritingCheck
    assert WritingCheck(rule_id='rule-1', verdict='pass', section_ids=(), reason_code='').verdict == 'pass'
    with pytest.raises(ValueError, match='requires a reason'):
        WritingCheck(rule_id='rule-1', verdict='fail', section_ids=('section-1',), reason_code='')
