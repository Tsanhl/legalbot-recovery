from __future__ import annotations

from datetime import date

import pytest

from app.quality.full_answer_reviewer import invoke_full_answer_reviewer
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
