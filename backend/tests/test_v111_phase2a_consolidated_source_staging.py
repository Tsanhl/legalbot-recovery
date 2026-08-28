from __future__ import annotations

import json

import pytest
from scripts import build_v111_phase2a_consolidated_source_staging as staging


@pytest.fixture(scope="module")
def plan() -> dict[str, object]:
    # The one authorized successor scan has now completed.  Re-running the
    # pre-scan planner would deliberately fail because its sealed predecessor
    # scan is no longer latest; verify the immutable applied staging artifact
    # instead of reconstructing or repeating that earlier step.
    path = staging.OUTPUT_ROOT / "CONSOLIDATED-SOURCE-STAGING.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    staging._sealed(value, "artifact_content_sha256")
    assert (
        value["artifact_content_sha256"]
        == "edd0c6e6a0e26ee776193ceb9256a8a2f5dbc92520dc5ad2346e012e0941e68c"
    )
    return value


def test_consolidated_source_scope_is_exact_and_deduplicated(
    plan: dict[str, object],
) -> None:
    assert plan["seminar_source_count"] == 142
    assert plan["prior_approved_source_count"] == 25
    assert plan["deduplicated_overlap_count"] == 1
    assert plan["consolidated_source_count"] == 166
    assert plan["source_family_counts"] == {
        "official_judgment": 115,
        "legislation": 51,
    }
    records = plan["records"]
    assert isinstance(records, list)
    identities = [record["authority_identity_id"] for record in records]
    assert len(identities) == len(set(identities)) == 166
    assert "neutral-citation:[2024] UKSC 17" not in identities


def test_staging_is_a_changed_scan_plan_not_an_unchanged_retry(
    plan: dict[str, object],
) -> None:
    assert plan["already_scan_covered_count"] == 96
    assert plan["staging_required_count"] == 70
    assert plan["one_final_complete_source_scan_required"] is True
    assert plan["source_scan_started"] is False
    records = plan["records"]
    assert isinstance(records, list)
    staged = [record for record in records if record["requires_final_scan"]]
    assert len(staged) == 70
    assert all(record["staged_relative_path"] for record in staged)


def test_all_later_phase_and_release_gates_remain_closed(
    plan: dict[str, object],
) -> None:
    assert plan["all_packet_exclusions_retained"] is True
    assert plan["all_currentness_and_later_treatment_holds_retained"] is True
    assert plan["catalogue_review_state_mutated"] is False
    assert plan["candidate_mutated"] is False
    assert plan["automatic_indexing"] is False
    assert plan["automatic_embedding"] is False
    assert plan["active_or_previous_write_authorized"] is False
    assert plan["phase2b_authorized"] is False
    assert plan["development30_authorized"] is False
    records = plan["records"]
    assert isinstance(records, list)
    assert all(record["answer_release_eligible"] is False for record in records)
