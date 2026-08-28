from pathlib import Path

from scripts import build_v111_phase2a_deterministic_only_work_ledger as ledger
from scripts import plan_v111_phase2a_material_gap_research as planner


def test_deterministic_ledger_excludes_all_planner_output(tmp_path: Path) -> None:
    result = ledger.build_ledger(tmp_path / "ledger")

    planner._verify_seal(
        result,
        "artifact_content_sha256",
        "test_deterministic_ledger_seal_invalid",
    )
    assert result["row_count"] == 364
    assert result["planner_attempt_cap_breached_row_count"] == 38
    assert result["planner_output_consumed_row_count"] == 0
    assert result["deterministic_work_class_counts"] == {
        "CROSSWALK_APPROVED_SOURCE_OR_PREPARE_NEW_ADMISSION": 20,
        "DETERMINISTIC_CANDIDATE_LOCATOR_SEARCH_OR_GOLD_REPAIR": 98,
        "DETERMINISTIC_OFFICIAL_AUTHORITY_SEARCH_OR_GOLD_REPAIR": 189,
        "DETERMINISTIC_OFFICIAL_SOURCE_SEARCH_OR_GOLD_REPAIR": 7,
        "OWNER_GOLD_SCOPE_DECISION_PACKET": 5,
        "VERIFY_EXISTING_EXACT_SPAN_AND_CURRENTNESS": 45,
    }
    assert all(row["planner_output_consumed"] is False for row in result["rows"])
    assert result["source_scan_started"] is False
    assert result["candidate_mutated"] is False
    assert result["phase2b_authorized"] is False


def test_ledger_preserves_deterministic_authority_and_locator_scope(
    tmp_path: Path,
) -> None:
    result = ledger.build_ledger(tmp_path / "ledger")
    row = next(item for item in result["rows"] if item["row_id"] == "live30-q01:issue-01")

    assert row["issue_label"] == "breach"
    assert row["source_route"] == ("SCENARIO_AWARE_IN_CANDIDATE_RECOVERY_OR_GOLD_REPAIR")
    assert row["effective_planned_authority_ids"] == [
        "neutral-citation:[2021] UKSC 29",
        "ukpga:1982:29",
    ]
    assert {item["locator_hint"] for item in row["deterministic_locator_hints"]} == {
        "p 32",
        "section 1",
    }
    assert row["planner_attempt_cap_breached"] is True
    assert row["exact_span_status"] == "PENDING_DETERMINISTIC_VERIFICATION"


def test_work_class_mapping_is_finite_and_explicit() -> None:
    assert ledger._work_class("OWNER_NONMATERIAL_OR_GOLD_SCOPE_REVIEW") == (
        "OWNER_GOLD_SCOPE_DECISION_PACKET"
    )
    assert (
        ledger._work_class("EFFECTIVE_OUTSIDE_SOURCE_QUARANTINE_AND_PROPOSITION_REVIEW")
        == "CROSSWALK_APPROVED_SOURCE_OR_PREPARE_NEW_ADMISSION"
    )
    assert ledger._work_class("R94_OWNER_APPROVED_TARGET_DATE_READY") == (
        "VERIFY_EXISTING_EXACT_SPAN_AND_CURRENTNESS"
    )
