from __future__ import annotations

import json
from datetime import date

import pytest
from pydantic import ValidationError

from app.quality.ai_evidence_reviewer import (
    AIEvidenceAdjudication,
    AIEvidenceReviewResult,
    adjudicate_ai_evidence_review,
    ai_evidence_reviewer_prompt_sha256,
    ai_evidence_reviewer_toolchain_sha256,
    freeze_material_claims,
    frozen_claim_bundle_sha256,
    invoke_ai_evidence_reviewer,
    seal_ai_evidence_review,
)
from app.quality.draft_identity import source_draft_sha256
from app.types import (
    EvidenceSpan,
    MaterialLane,
    StructuredClaimDraft,
    StructuredDraft,
    StructuredSectionDraft,
    TaskType,
)


def _evidence(**changes: object) -> EvidenceSpan:
    values: dict[str, object] = {
        "id": "evidence-1",
        "source_version_id": "source-version-1",
        "chunk_id": "chunk-1",
        "text": "The verified statutory proposition applies.",
        "locator": "s 1",
        "lane": MaterialLane.PRIMARY_AUTHORITY,
        "jurisdiction": "England and Wales",
        "subject": "contract",
        "currentness_status": "current",
        "content_sha256": "c" * 64,
        "index_build_id": "candidate-v111",
        "identity_verified": True,
        "currentness_verified": True,
    }
    values.update(changes)
    return EvidenceSpan.model_validate(values)


def _draft(*, evidence_ids: list[str] | None = None) -> StructuredDraft:
    return StructuredDraft(
        title="Private draft",
        task_type=TaskType.ESSAY,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 20),
        sections=[
            StructuredSectionDraft(
                id="section-1",
                heading="Rule",
                claims=[
                    StructuredClaimDraft(
                        id="claim-1",
                        text="The statutory rule applies.",
                        evidence_ids=evidence_ids or ["evidence-1"],
                    )
                ],
            )
        ],
    )


def _seal(verdict: str, *, cited: tuple[str, ...] = ()) -> AIEvidenceReviewResult:
    draft = _draft()
    frozen = freeze_material_claims(draft=draft, evidence_by_id={"evidence-1": _evidence()})
    return seal_ai_evidence_review(
        model_output={
            "claims": [
                {
                    "claim_id": "claim-1",
                    "verdict": verdict,
                    "reason_codes": ["evidence_checked"],
                    "cited_evidence_ids": list(cited),
                }
            ]
        },
        source_draft=draft,
        frozen_claims=frozen,
        invocation_id="invocation-1",
        model_id="reviewer-model",
        model_version="2026-08-20",
        policy_sha256="a" * 64,
        toolchain_sha256="b" * 64,
    )


def test_review_recomputes_identities_and_persists_no_prose() -> None:
    evidence = _evidence()
    frozen = freeze_material_claims(draft=_draft(), evidence_by_id={evidence.id: evidence})
    review = _seal("supported", cited=(evidence.id,))

    assert review.prompt_sha256 == ai_evidence_reviewer_prompt_sha256()
    assert review.claims[0].claim_sha256 == frozen[0].identity.claim_sha256
    assert review.claims[0].evidence_bundle_sha256 == (frozen[0].identity.evidence_bundle_sha256)
    assert review.source_draft_sha256 == source_draft_sha256(_draft())
    assert review.frozen_claim_bundle_sha256 == frozen_claim_bundle_sha256(frozen)
    encoded = review.model_dump_json(by_alias=True)
    assert "The statutory rule applies" not in encoded
    assert "The verified statutory proposition" not in encoded
    assert "/Users/" not in encoded
    assert review.passed is True
    assert review.reviewer_execution_mode == "separate_verification_pass_same_model_adapter"
    assert review.model_independent is False
    assert review.advisory_recommendations_only is True
    assert review.can_decide_or_adopt is False
    assert review.can_admit_sources is False
    assert review.can_authorize_gates is False
    assert review.may_raise_fail_closed_owner_review_hold is True
    AIEvidenceReviewResult.model_validate_json(encoded)


def test_source_draft_identity_is_distinct_from_frozen_claim_bundle() -> None:
    evidence = _evidence()
    first = _draft()
    second = _draft()
    second.limitations.append("A non-material limitation retained in the source draft.")
    first_frozen = freeze_material_claims(draft=first, evidence_by_id={evidence.id: evidence})
    second_frozen = freeze_material_claims(draft=second, evidence_by_id={evidence.id: evidence})

    assert source_draft_sha256(first) != source_draft_sha256(second)
    assert frozen_claim_bundle_sha256(first_frozen) == frozen_claim_bundle_sha256(second_frozen)


@pytest.mark.parametrize(
    ("verdict", "cited", "blocker", "narrow"),
    [
        ("supported", ("evidence-1",), None, False),
        (
            "partially_supported",
            ("evidence-1",),
            "ai_review_partially_supported",
            True,
        ),
        ("unsupported", (), "ai_review_unsupported", False),
        ("contradicted", (), "ai_review_contradicted", False),
        ("uncertain", (), "ai_review_uncertain", False),
        ("not_reviewable", (), "ai_review_not_reviewable", False),
    ],
)
def test_every_verdict_has_fail_closed_adjudication(
    verdict: str, cited: tuple[str, ...], blocker: str | None, narrow: bool
) -> None:
    review = _seal(verdict, cited=cited)
    adjudication = adjudicate_ai_evidence_review(review)
    claim = adjudication.claims[0]

    assert claim.passed is (blocker is None)
    assert claim.blocking_reason_codes == (() if blocker is None else (blocker,))
    assert claim.requires_targeted_narrowing is narrow
    assert claim.requires_fresh_review is narrow
    assert adjudication.passed is (blocker is None)
    AIEvidenceAdjudication.model_validate_json(adjudication.model_dump_json(by_alias=True))


def test_deterministic_gate_vetoes_supported_ai_review() -> None:
    adjudication = adjudicate_ai_evidence_review(
        _seal("supported", cited=("evidence-1",)),
        deterministic_blocking_reason_codes=("wrong_jurisdiction",),
    )

    assert adjudication.claims[0].passed is True
    assert adjudication.passed is False
    assert adjudication.deterministic_gates_override_ai is True
    assert adjudication.advisory_recommendations_only is True
    assert adjudication.can_authorize_gates is False
    assert adjudication.may_raise_fail_closed_owner_review_hold is True


def test_unknown_verdict_becomes_not_reviewable() -> None:
    review = _seal("invented_verdict")

    assert review.claims[0].verdict == "not_reviewable"
    assert "invalid_model_verdict" in review.claims[0].reason_codes
    assert review.passed is False


def test_model_contract_and_frozen_evidence_fail_closed() -> None:
    evidence = _evidence()
    frozen = freeze_material_claims(draft=_draft(), evidence_by_id={evidence.id: evidence})
    base = {
        "source_draft": _draft(),
        "frozen_claims": frozen,
        "invocation_id": "invocation-1",
        "model_id": "reviewer-model",
        "model_version": "2026-08-20",
        "policy_sha256": "a" * 64,
        "toolchain_sha256": "b" * 64,
    }
    with pytest.raises(ValueError, match="outside its contract"):
        seal_ai_evidence_review(model_output={"claims": [], "chain_of_thought": "secret"}, **base)
    with pytest.raises(ValueError, match="exact contract"):
        seal_ai_evidence_review(
            model_output={
                "claims": [
                    {
                        "claim_id": "claim-1",
                        "verdict": "supported",
                        "reason_codes": [],
                        "cited_evidence_ids": ["evidence-1"],
                        "claim_sha256": "0" * 64,
                    }
                ]
            },
            **base,
        )
    with pytest.raises(ValueError, match="outside its frozen snapshot"):
        freeze_material_claims(draft=_draft(), evidence_by_id={})
    with pytest.raises(ValueError, match="identity/currentness"):
        unverified = _evidence(currentness_verified=False)
        freeze_material_claims(draft=_draft(), evidence_by_id={unverified.id: unverified})
    with pytest.raises(ValueError, match="path metadata"):
        path_evidence = _evidence(text="See /Users/example/private/source.pdf")
        freeze_material_claims(draft=_draft(), evidence_by_id={path_evidence.id: path_evidence})

    changed_draft = _draft()
    changed_draft.sections[0].claims[0].text = "A different source-draft claim."
    with pytest.raises(ValueError, match="differs from the source draft"):
        seal_ai_evidence_review(
            model_output={
                "claims": [
                    {
                        "claim_id": "claim-1",
                        "verdict": "supported",
                        "reason_codes": [],
                        "cited_evidence_ids": ["evidence-1"],
                    }
                ]
            },
            **{**base, "source_draft": changed_draft},
        )


def test_review_seal_detects_tampering() -> None:
    payload = json.loads(_seal("supported", cited=("evidence-1",)).model_dump_json(by_alias=True))
    payload["claims"][0]["verdict"] = "unsupported"

    with pytest.raises(ValidationError, match="pass flag|seal"):
        AIEvidenceReviewResult.model_validate(payload)


@pytest.mark.asyncio
async def test_distinct_reviewer_invocation_is_sealed_from_local_identities() -> None:
    class ReviewerModel:
        async def invoke_json(self, **kwargs: object):
            assert kwargs["mode"] == "semantic_verify"
            assert "separate-pass advisory AI evidence reviewer" in str(kwargs["system_prompt"])
            payload = kwargs["user_payload"]
            assert isinstance(payload, dict)
            assert payload["material_claim_count"] == 1
            assert payload["source_draft_sha256"] == source_draft_sha256(_draft())
            assert payload["frozen_claim_bundle_sha256"]
            return (
                "review-invocation-001",
                {
                    "claims": [
                        {
                            "claim_id": "claim-1",
                            "verdict": "supported",
                            "reason_codes": ["entailed_by_frozen_span"],
                            "cited_evidence_ids": ["evidence-1"],
                        }
                    ]
                },
            )

    evidence = _evidence()
    review = await invoke_ai_evidence_reviewer(
        model=ReviewerModel(),
        draft=_draft(),
        evidence_by_id={evidence.id: evidence},
        model_id="reviewer-model",
        model_version="2026-08-20",
        policy_sha256="a" * 64,
    )

    assert review.passed is True
    assert review.invocation_ids == ("review-invocation-001",)
    assert review.toolchain_sha256 == ai_evidence_reviewer_toolchain_sha256()


@pytest.mark.asyncio
async def test_missing_reviewer_transport_fails_closed() -> None:
    with pytest.raises(RuntimeError, match="transport"):
        await invoke_ai_evidence_reviewer(
            model=object(),
            draft=_draft(),
            evidence_by_id={"evidence-1": _evidence()},
            model_id="reviewer-model",
            model_version="2026-08-20",
            policy_sha256="a" * 64,
        )
