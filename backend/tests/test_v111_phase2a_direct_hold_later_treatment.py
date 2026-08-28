from __future__ import annotations

import copy

import pytest
from scripts import collect_v111_phase2a_direct_hold_later_treatment as collector


def test_direct_hold_plan_is_bounded_and_non_authorizing() -> None:
    plan = collector._load_plan(collector.DEFAULT_PLAN)
    targets = collector._validate_plan(plan)

    assert len(targets) == 4
    assert sum(len(target["candidates"]) for target in targets) == 7
    assert {row for target in targets for row in target["row_ids"]} == {
        "live30-q09:issue-07",
        "live30-q11:issue-02",
        "live60-q38:issue-07",
        "live60-q60:issue-04",
    }
    assert plan["bulk_search"] is False
    assert plan["owner_outcomes_applied"] is False
    assert plan["automatic_source_admission"] is False
    assert plan["automatic_embedding"] is False
    assert plan["phase2b_authorized"] is False


def test_direct_hold_plan_rejects_authorizing_mutation() -> None:
    plan = copy.deepcopy(collector._load_plan(collector.DEFAULT_PLAN))
    plan["automatic_source_admission"] = True

    with pytest.raises(ValueError, match="phase2a_direct_hold_plan_boundary_invalid"):
        collector._validate_plan(plan)


def test_direct_hold_url_allowlist_is_strict() -> None:
    assert collector._safe_url(
        "https://caselaw.nationalarchives.gov.uk/uksc/2025/28/data.xml"
    ).endswith("/data.xml")
    with pytest.raises(ValueError, match="phase2a_direct_hold_url_invalid"):
        collector._safe_url("https://example.com/uksc/2025/28/data.xml")
