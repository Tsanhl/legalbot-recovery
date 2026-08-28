from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from scripts import review_verified_catalog as review


def test_case_url_is_fail_closed_by_court_division_and_jurisdiction() -> None:
    assert review._canonical_neutral_citation("[2024] EWCA CIV 12") == "[2024] EWCA Civ 12"
    assert review._canonical_neutral_citation("[2024] EWHC 31 (ADMIN)") == "[2024] EWHC 31 (Admin)"
    assert (
        review._case_url("[2024] EWCA Civ 12", "JUDGMENT", "England and Wales")
        == "https://caselaw.nationalarchives.gov.uk/ewca/civ/2024/12"
    )
    assert (
        review._case_url("[2024] EWHC 31 (Admin)", "JUDGMENT", "England and Wales")
        == "https://caselaw.nationalarchives.gov.uk/ewhc/admin/2024/31"
    )
    assert review._case_url("[2024] EWHC 31 (Costs)", "JUDGMENT", "England and Wales") is None
    assert review._case_url("[2024] UKPC 2", "JUDGMENT", "United Kingdom") is None
    assert review._case_url("[2024] EWCA Civ 12", "JUDGMENT", "Canada") is None
    assert review._case_url("[2024] UKSC 1", "JUDGMENT", "England and Wales") is None
    assert review._case_url("[2024] UKSC 1", "JUDGMENT", "United Kingdom") is None
    assert (
        review._case_url(
            "[2024] UKSC 1",
            "JUDGMENT On appeal from [2022] EWCA Civ 12",
            "England and Wales",
        )
        == "https://caselaw.nationalarchives.gov.uk/uksc/2024/1"
    )


def test_title_coverage_and_crossref_year_are_structural() -> None:
    assert (
        review._title_coverage(
            "Paul and another v Royal Wolverhampton NHS Trust",
            "Judgment in Paul and another v Royal Wolverhampton NHS Trust",
        )
        == 1.0
    )
    assert review._title_coverage("Unrelated legal article", "A different source") == 0.0
    assert review._issued_year({"issued": {"date-parts": [[2024, 1, 1]]}}) == "2024"
    assert review._issued_year({"issued": {"date-parts": []}}) is None


def test_official_metadata_fetch_stops_on_second_identical_transient_failure(
    monkeypatch,
) -> None:
    class Client:
        calls = 0

        async def get(self, url: str) -> httpx.Response:
            self.calls += 1
            return httpx.Response(503, request=httpx.Request("GET", url))

    async def no_sleep(_delay: float) -> None:
        return None

    client = Client()
    monkeypatch.setattr(review.asyncio, "sleep", no_sleep)
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(review._verified_get(client, "https://example.invalid/official"))
    assert client.calls == 2


def test_feedback_rule_specificity_is_fail_closed() -> None:
    assert review._rule_specificity_reasons(
        "Excellent analysis.",
        grade_band="70+",
        polarity="positive_pattern",
        subject="general",
    ) == ["positive_pattern_too_generic"]
    assert "positive_pattern_not_actionable" in review._rule_specificity_reasons(
        "Overall this was a very good piece of work.",
        grade_band="70+",
        polarity="positive_pattern",
        subject="general",
    )
    assert "feedback_heading_contamination" in review._rule_specificity_reasons(
        "KNOWLEDGE ANALYSIS COMMUNICATION RESEARCH Very good knowledge displayed.",
        grade_band="70+",
        polarity="positive_pattern",
        subject="mediation and ADR",
    )
    assert (
        review._rule_specificity_reasons(
            "Very good engagement with relevant primary and secondary sources.",
            grade_band="70+",
            polarity="positive_pattern",
            subject="mediation and ADR",
        )
        == []
    )
    assert review._rule_specificity_reasons(
        "The claim that 'incapacity' overrides wishes needs greater analysis.",
        grade_band="60-69",
        polarity="error_to_avoid",
        subject="general",
    ) == ["specific_criticism_has_unresolved_subject"]
    assert review._rule_specificity_reasons(
        "BP: The Briefing Note is very concise and clear.",
        grade_band="70+",
        polarity="positive_pattern",
        subject="biolaw",
    ) == ["feedback_task_type_unresolved"]
    assert review._rule_specificity_reasons(
        "A brieﬁng paper with clear paths to further improvement.",
        grade_band="70+",
        polarity="positive_pattern",
        subject="biolaw",
    ) == ["feedback_task_type_unresolved"]
    assert review._rule_specificity_reasons(
        "If you need clarification on your feedback please email me; [EMAIL].",
        grade_band="50-59",
        polarity="error_to_avoid",
        subject="criminal",
    ) == ["administrative_feedback_not_assessment_rule"]
    assert review._rule_specificity_reasons(
        "See above for where the extra words could have been found.",
        grade_band="50-59",
        polarity="error_to_avoid",
        subject="criminal",
    ) == ["feedback_requires_missing_context"]
    assert review._rule_specificity_reasons(
        "Q6 65 You demonstrate sound knowledge of proprietary estoppel.",
        grade_band="70+",
        polarity="positive_pattern",
        subject="general",
    ) == [
        "source_specific_marker_contamination",
        "specific_legal_feedback_subject_unresolved",
    ]
    assert review._rule_specificity_reasons(
        "You should only include cited cases in your bibliography.",
        grade_band="50-59",
        polarity="error_to_avoid",
        subject="land",
    ) == ["citation_convention_requires_manual_review"]
    assert review._rule_specificity_reasons(
        "Analysis is compressed and references are missing. 2nd marker:",
        grade_band="60-69",
        polarity="error_to_avoid",
        subject="biolaw",
    ) == ["source_specific_marker_contamination"]


def test_public_verifier_holds_legislation_for_official_currentness_review(monkeypatch) -> None:
    legislation_row = {
        "review_id": "review-legislation",
        "safe_display_name": "source-legislation.pdf",
        "target_id": "source-version-legislation",
        "document_status": "citable",
        "retrieval_canonical": 1,
        "chunk_count": 2,
        "metadata_json": (
            '{"classification_confidence":"high",'
            '"material_type_candidate":"legislation",'
            '"public_identifier_candidate":{"scheme":"legislation"}}'
        ),
        "lane": "primary_authority",
    }

    def rows(_database, lane: str):
        return [legislation_row] if lane == "primary_authority" else []

    class FakeDatabase:
        def fetchall(self, _query, _params=()):
            return []

    monkeypatch.setattr(review, "_current_source_rows", rows)
    results = asyncio.run(review.verify_public(FakeDatabase(), apply=False))
    assert results == [
        {
            "review_id": "review-legislation",
            "safe_name": "source-legislation.pdf",
            "lane": "primary_authority",
            "decision": "hold",
            "reasons": ["official_currentness_verification_required"],
        }
    ]


def test_private_teaching_requires_high_confidence_content_classification(monkeypatch) -> None:
    row = {
        "review_id": "review-1",
        "target_id": "source-version-1",
        "safe_display_name": "source-abc.md",
        "document_status": "private_teaching",
        "retrieval_canonical": 1,
        "chunk_count": 2,
        "content_sha256": "a" * 64,
        "metadata_json": json.dumps(
            {
                "selected_chunk_count": 2,
                "classification_confidence": "low",
                "classification_reason": "content_uncertain_private_fallback",
                "material_type_candidate": "course_note",
            }
        ),
    }

    class FakeDatabase:
        def fetchall(self, _query, _params=()):
            return []

        def decide_review(self, *_args, **_kwargs):
            raise AssertionError("a low-confidence teaching source must not be approved")

    monkeypatch.setattr(review, "_current_source_rows", lambda _database, _lane: [row])
    results = review.approve_private_teaching(FakeDatabase(), apply=True)
    assert results[0]["decision"] == "hold"
    assert "teaching_classification_not_high_confidence" in results[0]["reasons"]
