from __future__ import annotations

from app.evaluation.ge_ai_auto_quality_review import (
    AI_ASSESSMENTS,
    FACT_CHECK_COVERAGE_MEANING,
    MIN_FIVE_TOKEN_NGRAM_COVERAGE,
    decision_for,
    five_token_ngram_coverage,
    official_url,
)
from app.evaluation.ge_phase2_progress import (
    AI_AUTO_REVIEW_COMPLETE_TRAINING_AUTHORISATION_PENDING,
    phase2_progress,
)
from app.evaluation.ge_visible_harness import (
    QUALITY_CRITICAL_FLOORS,
    QUALITY_DIMENSION_MAX,
    quality_outcome,
)


def test_ai_assessment_inventory_and_gate_outcomes_are_fail_closed() -> None:
    assert len(AI_ASSESSMENTS) == 20
    accepted = 0
    held = 0
    for profile in AI_ASSESSMENTS.values():
        coverage = profile["material_proposition_coverage"] is True
        scores = profile["quality_scores"]
        decision, score, outcome = decision_for(
            factual_pass=coverage,
            quality_scores=scores,
        )
        if decision == "AI_ACCEPT":
            accepted += 1
            assert score is not None and score >= 70
            assert outcome in {"MEETS_70_STANDARD", "EXCEEDS_70_STANDARD"}
            assert scores is not None
            assert all(scores[name] >= floor for name, floor in QUALITY_CRITICAL_FLOORS.items())
        else:
            held += 1
    assert accepted == 13
    assert held == 7


def test_all_scored_profiles_use_complete_declared_rubric() -> None:
    for profile in AI_ASSESSMENTS.values():
        scores = profile["quality_scores"]
        if scores is None:
            assert profile["material_proposition_coverage"] is False
            continue
        assert set(scores) == set(QUALITY_DIMENSION_MAX)
        score, outcome = quality_outcome(scores)
        assert 0 <= score <= 100
        assert outcome in {
            "EXCEEDS_70_STANDARD",
            "MEETS_70_STANDARD",
            "BELOW_70_STANDARD",
            "MATERIAL_IMPROVEMENT_REQUIRED",
        }


def test_quality_is_prohibited_after_factual_hold() -> None:
    try:
        decision_for(
            factual_pass=False,
            quality_scores={name: maximum for name, maximum in QUALITY_DIMENSION_MAX.items()},
        )
    except RuntimeError as exc:
        assert "prohibited" in str(exc)
    else:
        raise AssertionError("factual hold accepted a quality score")


def test_official_routes_are_exact_and_point_in_time_is_preserved() -> None:
    current, current_mode = official_url("Companies Act 2006", "section 172")
    historic, historic_mode = official_url(
        "Wills Act 1837 (as at 2024-01-15)",
        "section 9",
    )
    assert current == ("https://www.legislation.gov.uk/ukpga/2006/46/section/172/data.xml")
    assert current_mode == "CURRENT_REVISED"
    assert "/section/9/2024-01-15/data.xml" in historic
    assert historic_mode == "POINT_IN_TIME_2024-01-15"


def test_ngram_corroboration_and_coverage_language_do_not_claim_certainty() -> None:
    quote = "the court may grant an interim injunction where it is just and convenient"
    official = f"Section 37 says {quote}. Any order may be subject to conditions."
    assert five_token_ngram_coverage(quote, official) >= MIN_FIVE_TOKEN_NGRAM_COVERAGE
    assert "coverage" in FACT_CHECK_COVERAGE_MEANING.casefold()
    assert "not a professional guarantee" in FACT_CHECK_COVERAGE_MEANING.casefold()


def test_phase_progress_supports_owner_authorized_ai_route() -> None:
    ledger = phase2_progress(
        case_results=[{"case_id": "case-1", "factual_result": {"outcome": "FACTUAL_PASS"}}],
        diagnostic_report="APPROVED",
        routed=True,
        ai_auto_review_complete=True,
    )
    assert ledger["overall_state"] == (AI_AUTO_REVIEW_COMPLETE_TRAINING_AUTHORISATION_PENDING)
