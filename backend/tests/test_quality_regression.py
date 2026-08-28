from __future__ import annotations

from datetime import date

from app.quality.evaluator import QualityEvaluator
from app.types import (
    ReleaseState,
    StructuredClaimDraft,
    StructuredDraft,
    StructuredSectionDraft,
    TaskType,
)


def draft(evidence_id: str, words: int = 391) -> StructuredDraft:
    claim_texts = [
        (
            "The better view provides the direct answer because the verified statutory "
            "proposition governs the authoritative contract issue, subject to a qualified "
            "outcome."
        ),
        (
            "Applying the verified statutory proposition therefore supports the stated result, "
            "subject to facts not contained in the approved source."
        ),
        (
            "The present explanation is limited to the approved source and remains uncertain "
            "if the material facts or applicable date change."
        ),
        (
            "The practical next step is to confirm the material facts and obtain the current "
            "official version before relying on the analysis."
        ),
        (
            "The conclusion therefore follows from the verified statutory proposition, but it "
            "should be revisited if better evidence becomes available."
        ),
    ]
    current_words = sum(len(text.split()) for text in claim_texts)
    filler = [
        "context",
        "scope",
        "interpretation",
        "consequence",
        "rationale",
        "distinction",
        "qualification",
        "coherence",
        "relevance",
        "precision",
        "support",
        "authority",
        "application",
        "balance",
        "outcome",
    ]
    if words > current_words:
        extra = [filler[index % len(filler)] for index in range(words - current_words)]
        claim_texts[1] = f"{claim_texts[1]} {' '.join(extra)}"
    return StructuredDraft(
        title="Contract analysis",
        task_type=TaskType.GENERAL,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 11),
        sections=[
            StructuredSectionDraft(
                id="answer",
                heading="Direct answer",
                claims=[
                    StructuredClaimDraft(
                        id="claim-1", text=claim_texts[0], evidence_ids=[evidence_id]
                    )
                ],
            ),
            StructuredSectionDraft(
                id="analysis",
                heading="Legal analysis",
                claims=[
                    StructuredClaimDraft(
                        id="claim-2",
                        text=claim_texts[1],
                        evidence_ids=[evidence_id],
                    )
                ],
            ),
            StructuredSectionDraft(
                id="limitations",
                heading="Limitations and uncertainty",
                claims=[StructuredClaimDraft(id="claim-3", text=claim_texts[2], material=False)],
            ),
            StructuredSectionDraft(
                id="next-steps",
                heading="Practical next steps",
                claims=[StructuredClaimDraft(id="claim-4", text=claim_texts[3], material=False)],
            ),
            StructuredSectionDraft(
                id="conclusion",
                heading="Conclusion",
                claims=[StructuredClaimDraft(id="claim-5", text=claim_texts[4], material=False)],
            ),
        ],
    )


def test_970_to_391_length_case_releases_verified_concise(evidence) -> None:
    candidate = draft(evidence.id)
    report = QualityEvaluator().evaluate(
        answer_version_id="answer-1",
        draft=candidate,
        rendered_text=" ".join(["analysis"] * 391),
        evidence_by_id={evidence.id: evidence},
        word_count=391,
        word_target=970,
        rubric_scores={
            "authority_accuracy": 1,
            "analysis": 1,
            "organisation": 1,
            "precision": 1,
            "thesis": 1,
            "scholarship": 1,
            "counterargument": 1,
            "synthesis": 1,
        },
        question=(
            "What is the better view of the authoritative contract issue and direct outcome?"
        ),
    )
    assert report.evidence_passed
    assert report.academic_score >= 70
    assert report.release_state == ReleaseState.VERIFIED_CONCISE
    assert any(item.code == "shorter_than_requested" for item in report.findings)
    assert all(item.code != "quality_gate_failed" for item in report.findings)


def test_below_70_is_advisory_until_blind_calibration(evidence) -> None:
    candidate = StructuredDraft(
        title="Keyword list",
        task_type=TaskType.ESSAY,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 11),
        sections=[
            StructuredSectionDraft(
                id="keywords",
                heading="Analysis",
                claims=[
                    StructuredClaimDraft(
                        id="claim-keywords",
                        text=(
                            "The better view should answer whether the verified statutory "
                            "proposition meets every requirement, subject to this qualification: "
                            "however "
                            + " ".join(
                                ["thesis scholarship counterargument however conclusion analysis"]
                                * 80
                            )
                        ),
                        evidence_ids=[evidence.id],
                    )
                ],
            )
        ],
    )
    report = QualityEvaluator().evaluate(
        answer_version_id="answer-2",
        draft=candidate,
        rendered_text="supported analysis",
        evidence_by_id={evidence.id: evidence},
        word_count=900,
        word_target=900,
        rubric_scores={
            key: 0.5
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
        question=(
            "Should the better view conclude that the verified statutory proposition "
            "meets every requirement?"
        ),
    )
    assert report.evidence_passed
    assert report.academic_score < 70
    assert report.release_state == ReleaseState.VERIFIED_FULL
    assert any(item.code == "academic_score_below_target" for item in report.findings)


def test_unsupported_material_claim_is_named_and_held(evidence) -> None:
    candidate = draft(evidence.id)
    candidate.sections[0].claims[0].evidence_ids = []
    report = QualityEvaluator().evaluate(
        answer_version_id="answer-3",
        draft=candidate,
        rendered_text="unsupported proposition",
        evidence_by_id={evidence.id: evidence},
        word_count=391,
        word_target=391,
        rubric_scores={},
    )
    assert not report.evidence_passed
    assert report.release_state == ReleaseState.HELD_FOR_REVIEW
    assert any(item.code == "unsupported_material_law" for item in report.findings)
