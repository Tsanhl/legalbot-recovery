from __future__ import annotations

from datetime import date
from types import SimpleNamespace

import pytest

import app.quality.evaluator as evaluator_module
from app.orchestration.retry_policy import is_deterministic_safety_failure
from app.quality.evaluator import QualityEvaluator
from app.quality.evidence import (
    currentness_qualifies_for_answer,
    evidence_span_eligible_for_drafting,
    extract_material_facts,
    non_atomic_material_claim_reasons,
)
from app.types import (
    CasePropositionReview,
    ReleaseState,
    Severity,
    StructuredClaimDraft,
    StructuredDraft,
    StructuredSectionDraft,
    TaskType,
    case_proposition_review_sha256,
)


def _draft(text: str, evidence_id: str, *, proposition_hash: str | None = None) -> StructuredDraft:
    return StructuredDraft(
        title="Evidence test",
        task_type=TaskType.GENERAL,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 11),
        sections=[
            StructuredSectionDraft(
                id="law",
                heading="Law",
                claims=[
                    StructuredClaimDraft(
                        id="claim-1",
                        text=text,
                        evidence_ids=[evidence_id],
                        material=True,
                        proposition_hash=proposition_hash,
                    )
                ],
            )
        ],
    )


def _evaluate(text: str, evidence, *, proposition_hash: str | None = None) -> object:
    return QualityEvaluator().evaluate(
        answer_version_id="answer-evidence",
        draft=_draft(text, evidence.id, proposition_hash=proposition_hash),
        rendered_text=text,
        evidence_by_id={evidence.id: evidence},
        word_count=150,
        word_target=150,
        rubric_scores={},
    )


def test_unrelated_span_cannot_verify_a_material_claim(evidence) -> None:
    report = _evaluate(
        "Quantum entanglement permits faster-than-light messages between distant planets.",
        evidence,
    )
    assert not report.evidence_passed
    assert report.release_state == ReleaseState.HELD_FOR_REVIEW
    assert any(finding.code == "unrelated_evidence" for finding in report.findings)


def test_false_quotation_is_a_hard_blocker_even_when_topic_matches(evidence) -> None:
    report = _evaluate(
        'The verified statutory proposition states that "cats may fly on Tuesdays".', evidence
    )
    assert not report.evidence_passed
    assert any(finding.code == "false_quotation" for finding in report.findings)


@pytest.mark.parametrize(
    ("source_text", "claim_text", "expected_kind"),
    [
        (
            "Section 12 provides that the appeal period is 30 days.",
            "Section 12 provides that the appeal period is 90 days.",
            "duration",
        ),
        ("Damages are capped at £5,000.", "Damages are capped at £999,000.", "amount"),
        (
            "The statutory rate is 12.5 per cent.",
            "The statutory rate is 25 per cent.",
            "percentage",
        ),
        (
            "The order took effect on 14 August 2026.",
            "The order took effect on 15 August 2026.",
            "date",
        ),
        (
            "The statutory appeal rule applies.",
            "The statutory appeal rule appears in section 13.",
            "provision",
        ),
    ],
)
def test_altered_typed_fact_is_a_hard_blocker_even_when_topic_matches(
    evidence, source_text: str, claim_text: str, expected_kind: str
) -> None:
    locator = "s 12" if expected_kind == "provision" else evidence.locator
    bound = evidence.model_copy(update={"text": source_text, "locator": locator})

    report = _evaluate(claim_text, bound)

    findings = [item for item in report.findings if item.code == "unsupported_material_fact"]
    assert not report.evidence_passed
    assert report.release_state == ReleaseState.HELD_FOR_REVIEW
    assert len(findings) == 1
    assert expected_kind in findings[0].message
    assert is_deterministic_safety_failure("unsupported_material_fact")


def test_equivalent_date_amount_percentage_duration_and_provision_formats_match(evidence) -> None:
    bound = evidence.model_copy(
        update={
            "text": (
                "On 2026-08-14 section 12 fixed a GBP 5,000 cap, a 12.5 percent rate "
                "and a 30 day period."
            ),
            "locator": "s 12",
        }
    )
    report = _evaluate(
        "On 14 August 2026 s 12 fixed a £5,000 cap, a 12.5 per cent rate and a 30 days period.",
        bound,
    )

    assert all(item.code != "unsupported_material_fact" for item in report.findings)


def test_material_fact_extraction_is_typed_and_normalized() -> None:
    facts = extract_material_facts(
        "On 14 August 2026, s 12 required £5 million within 30 working days at 12.5%."
    )

    assert {(fact.kind, fact.normalized_value) for fact in facts} == {
        ("date", "2026-08-14"),
        ("provision", "section:12"),
        ("amount", "GBP:5000000"),
        ("duration", "30:working:day"),
        ("percentage", "12.5"),
    }


def test_compact_provision_identifier_is_not_missed() -> None:
    facts = extract_material_facts("The time limit in s.12(3)(a) applies.")

    assert {(fact.kind, fact.normalized_value) for fact in facts} == {
        ("provision", "section:12(3)(a)")
    }


def test_every_identifier_in_a_provision_series_is_extracted() -> None:
    facts = extract_material_facts(
        "Sections 15, 16, 20 and 21 apply; subsections (1), (2) and (3) define the test."
    )

    assert {(fact.kind, fact.normalized_value) for fact in facts} == {
        ("provision", "section:15"),
        ("provision", "section:16"),
        ("provision", "section:20"),
        ("provision", "section:21"),
        ("provision", "subsection:1"),
        ("provision", "subsection:2"),
        ("provision", "subsection:3"),
    }


def test_altered_later_provision_in_a_valid_looking_list_is_blocked(evidence) -> None:
    bound = evidence.model_copy(
        update={
            "text": "Sections 15, 16, 20 and 21 exclude or restrict the obligations.",
            "locator": "sections 15, 16, 20 and 21",
        }
    )

    report = _evaluate(
        "Sections 15, 16, 20 and 22 exclude or restrict the obligations.",
        bound,
    )

    assert not report.evidence_passed
    assert any(item.code == "unsupported_material_fact" for item in report.findings)
    assert ("provision", "section:22") in {
        (fact.kind, fact.normalized_value)
        for fact in extract_material_facts(
            "Sections 15, 16, 20 and 22 exclude or restrict the obligations."
        )
    }


def test_hyphenated_duration_is_extracted_and_alteration_is_blocked(evidence) -> None:
    bound = evidence.model_copy(update={"text": "The notice period is 30 days."})

    report = _evaluate("The notice period is a 90-day period.", bound)

    assert not report.evidence_passed
    assert any(item.code == "unsupported_material_fact" for item in report.findings)
    assert ("duration", "90:ordinary:day") in {
        (fact.kind, fact.normalized_value)
        for fact in extract_material_facts("The notice period is a 90-day period.")
    }


def test_multi_proposition_claim_cannot_launder_second_clause_through_one_citation(
    evidence,
) -> None:
    bound = evidence.model_copy(
        update={
            "text": (
                "The claimant must prove breach. The defendant may rely on the limitation clause."
            )
        }
    )
    report = _evaluate(
        "The claimant must prove breach, and the defendant may rely on the limitation clause.",
        bound,
    )

    assert not report.evidence_passed
    assert any(item.code == "non_atomic_material_claim" for item in report.findings)
    assert is_deterministic_safety_failure("non_atomic_material_claim")


def test_elliptical_second_predicate_is_still_a_separate_material_claim(evidence) -> None:
    bound = evidence.model_copy(update={"text": "Section 12 requires notice."})

    report = _evaluate(
        "Section 12 requires notice and permits an immediate damages award.",
        bound,
    )

    assert not report.evidence_passed
    assert any(item.code == "non_atomic_material_claim" for item in report.findings)


def test_single_proposition_may_list_elements_without_atomicity_failure(evidence) -> None:
    text = "The claimant must prove duty, breach, causation and loss."
    bound = evidence.model_copy(update={"text": text})

    report = _evaluate(text, bound)

    assert non_atomic_material_claim_reasons(text) == ()
    assert all(item.code != "non_atomic_material_claim" for item in report.findings)


def test_exact_quotation_and_related_proposition_pass_evidence_gate(evidence) -> None:
    report = _evaluate(
        'The source records "The verified statutory proposition" as the applicable rule.', evidence
    )
    assert report.evidence_passed
    assert all(finding.code != "false_quotation" for finding in report.findings)


def test_release_enforcement_requires_frozen_threshold_proof(evidence) -> None:
    text = "The verified statutory proposition is the applicable rule."
    draft = _draft(text, evidence.id)

    missing = QualityEvaluator(enforce_retrieval_threshold=True).evaluate(
        answer_version_id="answer-threshold-missing",
        draft=draft,
        rendered_text=text,
        evidence_by_id={evidence.id: evidence},
        word_count=150,
        word_target=150,
        rubric_scores={},
    )
    qualified = evidence.model_copy(
        update={
            "retrieval_route": "hybrid_rrf",
            "retrieval_relevance_score": 0.85,
            "retrieval_threshold": 0.8,
            "retrieval_threshold_policy_sha256": "f" * 64,
            "retrieval_threshold_qualified": True,
            "retrieval_qualification_reason": "semantic_threshold_passed",
        }
    )
    passing = QualityEvaluator(enforce_retrieval_threshold=True).evaluate(
        answer_version_id="answer-threshold-passing",
        draft=draft,
        rendered_text=text,
        evidence_by_id={qualified.id: qualified},
        word_count=150,
        word_target=150,
        rubric_scores={},
    )

    assert any(finding.code == "no_threshold_qualified_evidence" for finding in missing.findings)
    assert all(finding.code != "no_threshold_qualified_evidence" for finding in passing.findings)


def test_possessive_apostrophes_are_not_misread_as_quotations(evidence) -> None:
    report = _evaluate(
        "The verified statutory rule governs the claimant's duty and the defendant's response.",
        evidence,
    )
    assert all(finding.code != "false_quotation" for finding in report.findings)


def test_historical_enactment_cannot_support_current_law(evidence) -> None:
    historical = evidence.model_copy(update={"currentness_status": "historical"})
    report = _evaluate(
        "The verified statutory proposition is the applicable current rule.", historical
    )
    assert not report.evidence_passed
    assert any(
        finding.code == "historical_legislation_used_as_current_law" for finding in report.findings
    )


def test_historical_statutory_instrument_cannot_support_current_law(evidence) -> None:
    historical_si = evidence.model_copy(
        update={
            "citation_data": {
                "source_type": "statutory_instrument",
                "title": "Example Regulations 2026",
                "si_number": "2026/1",
                "provision": "reg 1",
            },
            "canonical_citation": "Example Regulations 2026, SI 2026/1, reg 1",
            "currentness_status": "historical_as_enacted",
        }
    )

    assert not currentness_qualifies_for_answer(historical_si)
    assert not evidence_span_eligible_for_drafting(historical_si, as_of_date=date(2026, 8, 11))
    report = _evaluate(
        "The verified statutory proposition is the applicable current rule.",
        historical_si,
    )

    assert not report.evidence_passed
    assert report.release_state == ReleaseState.HELD_FOR_REVIEW
    assert any(
        finding.code == "historical_legislation_used_as_current_law" for finding in report.findings
    )


def test_latest_available_si_with_unresolved_effects_and_extent_is_held(
    evidence,
) -> None:
    limited_si = evidence.model_copy(
        update={
            "citation_data": {
                "source_type": "statutory_instrument",
                "title": "Example Regulations 2026",
                "si_number": "2026/1",
                "provision": "reg 1",
            },
            "canonical_citation": "Example Regulations 2026, SI 2026/1, reg 1",
            "currentness_status": "latest-available-revised-snapshot",
            "unapplied_effect_count": 2,
            "provision_extent_status": "unverified",
        }
    )

    report = _evaluate(
        "The verified statutory proposition is the applicable current rule.",
        limited_si,
    )

    assert not report.evidence_passed
    assert report.release_state == ReleaseState.HELD_FOR_REVIEW
    assert any(
        finding.code == "current_law_verification_limited"
        and finding.severity == Severity.HARD_BLOCKER
        for finding in report.findings
    )
    assert is_deterministic_safety_failure("current_law_verification_limited")


def test_failed_applicable_avoidance_rule_is_an_ordinary_release_blocker(
    evidence,
) -> None:
    report = _evaluate(
        'The source records "The verified statutory proposition" as the applicable rule.',
        evidence,
    )

    assert report.evidence_passed is True
    assert report.assessment_standards is not None
    assert report.assessment_standards["avoidance_passed"] is False
    assert report.release_state == ReleaseState.HELD_FOR_REVIEW
    assert any(
        finding.code == "applicable_avoidance_standard_failed"
        and finding.severity == Severity.HARD_BLOCKER
        for finding in report.findings
    )
    assert is_deterministic_safety_failure("applicable_avoidance_standard_failed")


def test_unmet_70_plus_target_does_not_substitute_for_release_gates(
    evidence, monkeypatch: pytest.MonkeyPatch
) -> None:
    standards = SimpleNamespace(
        avoidance_passed=True,
        quality_target_met=False,
        scores=(),
        model_dump=lambda **_kwargs: {
            "schema": "test-only-standards",
            "avoidance_passed": True,
            "quality_target_met": False,
        },
    )
    monkeypatch.setattr(
        evaluator_module,
        "score_applicable_standards",
        lambda **_kwargs: standards,
    )

    report = _evaluate(
        'The source records "The verified statutory proposition" as the applicable rule.',
        evidence,
    )

    assert all(
        finding.code != "applicable_avoidance_standard_failed" for finding in report.findings
    )
    assert report.release_state != ReleaseState.HELD_FOR_REVIEW


def test_historical_case_needs_issue_specific_later_treatment(evidence) -> None:
    historical_case = evidence.model_copy(
        update={
            "citation_data": {
                "source_type": "case",
                "case_name": "Example v Example",
                "neutral_citation": "[2025] UKSC 99",
            },
            "currentness_status": "historical",
            "legal_role": "holding_ratio",
            "currentness_verified": False,
        }
    )
    report = _evaluate(
        "The verified statutory proposition is the applicable current rule.",
        historical_case,
    )
    assert not report.evidence_passed
    assert any(
        finding.code == "case_subsequent_treatment_unverified" for finding in report.findings
    )


def _case_review(evidence, *, proposition_hash: str = "d" * 64) -> CasePropositionReview:
    value = {
        "schema": "legalbot.case-proposition-currentness-review.v1",
        "source_version_id": evidence.source_version_id,
        "chunk_id": evidence.chunk_id,
        "legal_locator": evidence.locator,
        "exact_span_sha256": evidence.content_sha256,
        "proposition_hash": proposition_hash,
        "legal_role": "holding_ratio",
        "later_treatment_reviewed_as_of_date": "2026-08-11",
        "later_treatment_status": "confirmed_current",
        "contrary_or_limiting_authority_ids": [],
        "reviewer_role": "england_wales_qualified_solicitor",
        "reviewer_ref": f"reviewer:{'e' * 64}",
        "review_scope": "ordinary",
        "second_review_status": "not_required",
        "second_reviewer_ref": None,
    }
    value["seal_sha256"] = case_proposition_review_sha256(value)
    return CasePropositionReview.model_validate(value)


def test_case_currentness_passes_only_matching_reviewed_proposition(evidence) -> None:
    proposition_hash = "d" * 64
    case_evidence = evidence.model_copy(
        update={
            "citation_data": {
                "source_type": "case",
                "case_name": "Example v Example",
                "neutral_citation": "[2025] UKSC 99",
            },
            "currentness_status": "historical",
            "legal_role": "holding_ratio",
            "currentness_verified": False,
            "case_currentness_reviews": (_case_review(evidence),),
        }
    )
    matching = _evaluate(
        "The verified statutory proposition is the applicable current rule.",
        case_evidence,
        proposition_hash=proposition_hash,
    )
    assert all(
        finding.code != "case_subsequent_treatment_unverified" for finding in matching.findings
    )

    missing_hash = _evaluate(
        "The verified statutory proposition is the applicable current rule.",
        case_evidence,
    )
    wrong_hash = _evaluate(
        "The verified statutory proposition is the applicable current rule.",
        case_evidence,
        proposition_hash="f" * 64,
    )
    assert any(
        finding.code == "case_subsequent_treatment_unverified" for finding in missing_hash.findings
    )
    assert any(
        finding.code == "case_subsequent_treatment_unverified" for finding in wrong_hash.findings
    )
