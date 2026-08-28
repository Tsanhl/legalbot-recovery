from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts import collect_v111_phase2a_issue_source_rehoming as collector


def test_plan_is_bounded_non_admitting_and_covers_eighteen_rows() -> None:
    plan = collector._load_plan(collector.DEFAULT_PLAN)
    items = collector._validate_plan(plan)

    assert len(items) == 5
    assert len({row for item in items for row in item["affected_rows"]}) == 18
    assert {item["neutral_citation"] for item in items} == {
        "[2013] UKSC 67",
        "[2019] UKSC 22",
        "[2023] UKSC 51",
        "[2024] UKSC 17",
        "[2024] UKSC 30",
    }
    assert plan["automatic_source_admission"] is False
    assert plan["automatic_indexing"] is False
    assert plan["automatic_embedding"] is False
    assert plan["candidate_mutation_authorized"] is False
    assert plan["phase2b_authorized"] is False
    assert plan["development30_authorized"] is False


def test_plan_rejects_duplicate_affected_row(tmp_path: Path) -> None:
    plan = collector._load_plan(collector.DEFAULT_PLAN)
    duplicate = json.loads(json.dumps(plan))
    duplicate["items"][1]["affected_rows"].append(
        duplicate["items"][0]["affected_rows"][0]
    )
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(duplicate), encoding="utf-8")

    with pytest.raises(
        ValueError, match="phase2a_source_rehoming_plan_item_invalid"
    ):
        collector._validate_plan(collector._load_plan(path))


def test_collector_refuses_existing_output() -> None:
    with pytest.raises(ValueError, match="phase2a_source_rehoming_output_exists"):
        collector._collect(
            plan_path=collector.DEFAULT_PLAN,
            output_root=collector.PROJECT_ROOT,
            retrieved_at=datetime.now(UTC),
        )
