from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts import build_v111_phase2a_post_r101_research_routing as routing


def test_routing_reconciles_all_364_without_reopening_r94_rejections(
    tmp_path: Path,
) -> None:
    output = tmp_path / "r102"
    artifact = routing.build_routing(output)
    assert artifact["row_count"] == 364
    assert artifact["route_counts"] == routing.EXPECTED_ROUTE_COUNTS
    assert artifact["r94_approved_rejected_mapping_count"] == 13
    assert artifact["outside_source_research_authority_count"] == 16
    assert artifact["outside_source_research_row_link_count"] == 26
    assert len({item["row_id"] for item in artifact["rows"]}) == 364
    assert all(
        artifact[field] is False
        for field in (
            "owner_decisions_applied",
            "new_owner_decisions_created",
            "technical_qualification_assigned",
            "source_admission_authorized",
            "automatic_indexing",
            "automatic_embedding",
            "candidate_mutated",
            "phase2b_authorized",
            "development30_authorized",
        )
    )
    persisted = json.loads(
        (output / "POST-R101-RESEARCH-ROUTING-364.json").read_bytes()
    )
    assert persisted == artifact


def test_r94_rejected_authority_is_removed_from_effective_plan(
    tmp_path: Path,
) -> None:
    artifact = routing.build_routing(tmp_path / "r102")
    by_id = {item["row_id"]: item for item in artifact["rows"]}
    row = by_id["live30-q09:issue-04"]
    rejected = "neutral-citation:[2019] UKSC 22"
    assert rejected in row["r94_rejected_planned_authority_ids"]
    assert rejected not in row["effective_planned_authority_ids"]
    assert row["route"] == "R94_REJECTED_STALE_AUTHORITY_PLAN_RESEARCH_RESET"


def test_routing_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "r102"
    routing.build_routing(output)
    with pytest.raises(ValueError, match="phase2a_r102_output_already_exists"):
        routing.build_routing(output)
