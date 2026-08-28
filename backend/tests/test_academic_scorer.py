from __future__ import annotations

from datetime import date

from app.quality.evaluator import QualityEvaluator
from app.types import (
    MaterialLane,
    StructuredClaimDraft,
    StructuredDraft,
    StructuredSectionDraft,
    TaskType,
)


def test_keyword_stuffing_and_model_self_scores_cannot_reach_70(evidence) -> None:
    stuffed = " ".join(["thesis scholarship counterargument conclusion analysis"] * 100)
    candidate = StructuredDraft(
        title="Stuffed keywords",
        task_type=TaskType.ESSAY,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 11),
        sections=[
            StructuredSectionDraft(
                id="stuffing",
                heading="Keywords",
                claims=[
                    StructuredClaimDraft(
                        id="stuffed-claim",
                        text=f"The verified statutory proposition {stuffed}.",
                        evidence_ids=[evidence.id],
                    )
                ],
            )
        ],
    )
    report = QualityEvaluator().evaluate(
        answer_version_id="stuffed-answer",
        draft=candidate,
        rendered_text=candidate.sections[0].claims[0].text,
        evidence_by_id={evidence.id: evidence},
        word_count=510,
        word_target=510,
        rubric_scores={
            key: 1
            for key in (
                "authority_accuracy",
                "analysis",
                "organisation",
                "precision",
                "thesis",
                "scholarship",
                "counterargument",
                "synthesis",
            )
        },
    )

    assert report.academic_score < 70
    assert "rubric_cap_missing_thesis" in report.rubric_caps
    assert "rubric_cap_missing_scholarship" in report.rubric_caps
    assert any(finding.code == "model_rubric_ignored" for finding in report.findings)
    assert report.rubric_scores["precision"] < 5


def test_strong_structured_essay_with_verified_scholarship_can_reach_70(evidence) -> None:
    primary = evidence.model_copy(
        update={
            "text": (
                "The verified statutory proposition requires notice and protects reasonable "
                "reliance through a narrow and predictable rule."
            )
        }
    )
    scholarship = evidence.model_copy(
        update={
            "id": "scholarship-1",
            "source_version_id": "source-version-scholarship",
            "chunk_id": "chunk-scholarship",
            "lane": MaterialLane.SCHOLARSHIP,
            "text": (
                "Leading scholarship argues that the verified statutory proposition protects "
                "reliance, although its notice requirement may create uncertainty and unfairness."
            ),
            "canonical_citation": "A Scholar, 'Reliance and Notice' (2026) 1 Journal 1",
            "citation_data": {
                "source_type": "journal",
                "author": "A Scholar",
                "title": "Reliance and Notice",
                "year": 2026,
            },
        }
    )
    candidate = StructuredDraft(
        title="A qualified account of notice and reliance",
        task_type=TaskType.ESSAY,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 11),
        sections=[
            StructuredSectionDraft(
                id="introduction",
                heading="Introduction and thesis",
                claims=[
                    StructuredClaimDraft(
                        id="thesis",
                        text=(
                            "This essay argues that the rule should protect reasonable reliance, "
                            "although a narrow notice requirement is needed to control uncertainty."
                        ),
                        material=False,
                    )
                ],
            ),
            StructuredSectionDraft(
                id="authorities",
                heading="Authority and scholarly analysis",
                claims=[
                    StructuredClaimDraft(
                        id="rule",
                        text=(
                            "Because the verified statutory proposition requires notice, it "
                            "protects reasonable reliance through a narrow and predictable rule."
                        ),
                        evidence_ids=[primary.id],
                    ),
                    StructuredClaimDraft(
                        id="scholarship",
                        text=(
                            "Leading scholarship argues that the verified statutory proposition "
                            "protects reliance because notice promotes predictability."
                        ),
                        evidence_ids=[scholarship.id],
                    ),
                ],
            ),
            StructuredSectionDraft(
                id="counterargument",
                heading="Counterargument and critique",
                claims=[
                    StructuredClaimDraft(
                        id="critique",
                        text=(
                            "However, leading scholarship criticises the verified statutory "
                            "proposition because its notice requirement may create uncertainty "
                            "and unfairness despite protecting reliance."
                        ),
                        evidence_ids=[scholarship.id],
                    )
                ],
            ),
            StructuredSectionDraft(
                id="conclusion",
                heading="Conclusion",
                claims=[
                    StructuredClaimDraft(
                        id="synthesis",
                        text=(
                            "The better view therefore preserves reliance while confining the "
                            "notice rule to cases where predictability outweighs the identified unfairness."
                        ),
                        material=False,
                    )
                ],
            ),
        ],
    )
    report = QualityEvaluator().evaluate(
        answer_version_id="strong-essay",
        draft=candidate,
        rendered_text=" ".join(
            claim.text for section in candidate.sections for claim in section.claims
        ),
        evidence_by_id={primary.id: primary, scholarship.id: scholarship},
        word_count=900,
        word_target=900,
        rubric_scores={key: 0 for key in ("analysis", "thesis", "scholarship")},
    )

    assert report.evidence_passed
    assert report.academic_score >= 70
    assert report.raw_academic_score is not None
    assert report.rubric_caps == []
    assert set(report.rubric_reasons) == set(report.rubric_scores)
    assert report.rubric_scores["authority_accuracy"] >= 20
    assert report.rubric_scores["scholarship"] >= 7


def test_problem_answer_caps_missing_application_and_remedies(evidence) -> None:
    candidate = StructuredDraft(
        title="Rules only",
        task_type=TaskType.PROBLEM,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 11),
        sections=[
            StructuredSectionDraft(
                id="rules",
                heading="Rules",
                claims=[
                    StructuredClaimDraft(
                        id="rule-only",
                        text=(
                            "The verified statutory proposition is the governing authoritative "
                            "rule for the issue."
                        ),
                        evidence_ids=[evidence.id],
                    )
                ],
            )
        ],
    )
    report = QualityEvaluator().evaluate(
        answer_version_id="rules-only",
        draft=candidate,
        rendered_text=candidate.sections[0].claims[0].text,
        evidence_by_id={evidence.id: evidence},
        word_count=400,
        word_target=400,
        rubric_scores={},
    )

    assert report.academic_score <= 59
    assert "rubric_cap_missing_application" in report.rubric_caps
    assert "rubric_cap_missing_remedies" in report.rubric_caps
    assert any(finding.code == "rubric_cap_missing_application" for finding in report.findings)
