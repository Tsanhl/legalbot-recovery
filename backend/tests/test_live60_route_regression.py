from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path

from app.evaluation.live_suite import load_live_evaluation_bundle
from app.evaluation.live_suite_owner_decisions import build_issue_decision_pack

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"


def test_live_pack_matches_registry_research_routes_with_zero_mismatch() -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    pack = build_issue_decision_pack(bundle, as_of_date=date(2026, 8, 16))
    registry_routes = {case.case_id: case.expected_research_route for case in bundle.registry.cases}
    mismatches = [
        {
            "case_id": case["case_id"],
            "pack_route": case["expected_research_route"],
            "registry_route": registry_routes[case["case_id"]],
        }
        for case in pack["cases"]
        if case["expected_research_route"] != registry_routes[case["case_id"]]
    ]
    assert mismatches == []
    assert pack["route_field_used"] == "expected_research_route"



def test_controlling_live60_route_composition() -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    pack = build_issue_decision_pack(bundle, as_of_date=date(2026, 8, 16))
    assert pack["case_count"] == 60
    assert pack["issue_count"] == 585
    selected = [case for case in pack["cases"] if case["generation_disposition"] == "generate_once"]
    coverage = [
        case
        for case in pack["cases"]
        if case["generation_disposition"] == "coverage_only_not_selected"
    ]
    assert len(selected) == 30
    assert len(coverage) == 30
    assert Counter(case["task_type"] for case in selected) == {
        "problem": 19,
        "essay": 11,
    }
    assert Counter(case["expected_research_route"] for case in selected) == {
        "sectioned": 15,
        "full_enquiry": 15,
    }
    assert Counter(case["expected_research_route"] for case in pack["cases"]) == {
        "sectioned": 33,
        "full_enquiry": 27,
    }
    assert all(case["expected_drafting_route"] == "sectioned" for case in pack["cases"])
    full_enquiry_ids = [
        case.case_id
        for case in bundle.registry.cases
        if case.expected_research_route == "full_enquiry"
    ]
    assert len(full_enquiry_ids) == 27
    by_id = {case["case_id"]: case for case in pack["cases"]}
    for case_id in full_enquiry_ids:
        assert by_id[case_id]["expected_research_route"] == "full_enquiry"
