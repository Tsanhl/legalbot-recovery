from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts import build_v111_phase2a_issue_source_rehoming_review as review


def test_review_plan_is_non_admitting_and_corrects_unrelated_mappings() -> None:
    plan = review._load_object(review.DEFAULT_PLAN)
    values = review._validate_plan(plan)

    assert len(values) == 5
    assert sum(len(value["supported_claims"]) for value in values) == 6
    assert sum(len(value["rejected_mappings"]) for value in values) == 13
    assert sum(
        value["source_recommendation"].startswith("PROPOSE_") for value in values
    ) == 4
    lifestyle = next(
        value for value in values if value["proposal_id"] == "issue-source-rehome-004"
    )
    assert lifestyle["source_recommendation"] == (
        "REJECT_SOURCE_FOR_PLANNED_BENCHMARK_ROWS"
    )
    assert lifestyle["supported_claims"] == []
    byers = next(
        value for value in values if value["proposal_id"] == "issue-source-rehome-003"
    )
    assert "live30-q18:issue-05" in {
        row for claim in byers["supported_claims"] for row in claim["row_ids"]
    }
    assert plan["automatic_source_admission"] is False
    assert plan["automatic_indexing"] is False
    assert plan["candidate_mutation_authorized"] is False
    assert plan["phase2b_authorized"] is False


def test_build_verifies_exact_spans_and_preserves_owner_gate(tmp_path: Path) -> None:
    result = review.build(
        plan_path=review.DEFAULT_PLAN,
        quarantine_root=review.DEFAULT_QUARANTINE_ROOT,
        output_root=tmp_path / "review",
    )

    assert result["proposed_source_admission_count"] == 4
    assert result["supported_row_count"] == 6
    assert result["rejected_mapping_count"] == 13
    assert result["source_admission_authorized"] is False
    assert result["phase2b_authorized"] is False
    batch = review._load_object(
        tmp_path / "review/OWNER-ISSUE-SOURCE-ADMISSION-BATCH.json"
    )
    assert review._verify_seal(
        batch,
        "artifact_content_sha256",
        "test_batch_seal_invalid",
    ) == result["owner_batch_content_sha256"]
    assert all(source["source_admitted"] is False for source in batch["source_reviews"])


def test_build_rejects_mutated_exact_span(tmp_path: Path) -> None:
    plan = json.loads(review.DEFAULT_PLAN.read_text(encoding="utf-8"))
    plan["reviews"][0]["supported_claims"][0][
        "exact_normalized_span_text"
    ] = "Generally it is the doctor's consent which makes treatment lawful."
    plan_path = tmp_path / "mutated-plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")

    with pytest.raises(
        ValueError, match="phase2a_rehoming_review_exact_span_not_unique"
    ):
        review.build(
            plan_path=plan_path,
            quarantine_root=review.DEFAULT_QUARANTINE_ROOT,
            output_root=tmp_path / "bad-review",
        )


def test_build_refuses_existing_output() -> None:
    with pytest.raises(ValueError, match="phase2a_rehoming_review_output_exists"):
        review.build(
            plan_path=review.DEFAULT_PLAN,
            quarantine_root=review.DEFAULT_QUARANTINE_ROOT,
            output_root=review.PROJECT_ROOT,
        )
