from __future__ import annotations

import json

from scripts import plan_v111_phase2a_material_gap_research as planner
from scripts import repair_v111_phase2a_material_gap_research_post_r118 as r119


def test_r118_failure_is_exact_and_only_68_rows_remain() -> None:
    source = r119._load_post_r118_source()

    assert source.r118_intent["intent_content_sha256"] == (r119.EXPECTED_R118_INTENT_SHA256)
    assert source.r118_failure["failure_content_sha256"] == (
        r119.EXPECTED_R118_FAILURE_CONTENT_SHA256
    )
    assert source.r118_failure["failure_fingerprint"] == (r119.EXPECTED_R118_FAILURE_FINGERPRINT)
    assert len(source.r118_checkpoint_sha256s) == r119.EXPECTED_R118_CHECKPOINT_COUNT
    assert len(source.r118_accepted_plans) == r119.EXPECTED_R118_ACCEPTED_PLAN_COUNT
    assert len(source.remaining_row_ids) == r119.EXPECTED_REPAIR_ROW_COUNT
    assert source.remaining_row_ids[0] == r119.PRIOR_CONTENT_HELD_ROW_ID
    assert r119.TIMEOUT_ROW_ID in source.remaining_row_ids
    assert source.timeout_diagnostic["failure_fingerprint"] == (
        r119.EXPECTED_R118_RUNTIME_FINGERPRINT
    )
    assert source.timeout_diagnostic["response_received"] is False


def test_r119_crosswalk_binds_changed_execution_envelope() -> None:
    source = r119._load_post_r118_source()
    crosswalk = r119._crosswalk(source)

    planner._verify_seal(
        crosswalk,
        "artifact_content_sha256",
        "test_r119_crosswalk_seal_invalid",
    )
    assert crosswalk["row_count"] == r119.EXPECTED_REPAIR_ROW_COUNT
    assert crosswalk["reused_plan_count"] == r119.EXPECTED_REUSED_PLAN_COUNT
    assert crosswalk["reused_rows_will_not_be_reinvoked"] is True
    assert crosswalk["maximum_output_tokens"] == r119.R119_MAX_OUTPUT_TOKENS
    assert [record["row_id"] for record in crosswalk["records"]] == list(source.remaining_row_ids)
    assert crosswalk["phase2b_authorized"] is False


def test_r119_partition_reuses_296_and_repairs_only_68() -> None:
    source = r119._load_post_r118_source()
    repair_ids = set(source.remaining_row_ids)
    reused_ids = {
        str(plan["row_id"]) for plan in (*source.r117.accepted_plans, *source.r118_accepted_plans)
    }

    assert len(repair_ids) == r119.EXPECTED_REPAIR_ROW_COUNT
    assert len(reused_ids) == r119.EXPECTED_REUSED_PLAN_COUNT
    assert repair_ids.isdisjoint(reused_ids)
    assert len(repair_ids | reused_ids) == planner.EXPECTED_GAP_COUNT
    assert repair_ids == set(source.remaining_row_ids)


def test_r118_timeout_debug_report_records_material_plan_change() -> None:
    report = json.loads((r119.DEFAULT_OUTPUT / "DEBUG-REPORT.json").read_bytes())

    planner._verify_seal(
        report,
        "artifact_content_sha256",
        "test_r119_debug_report_seal_invalid",
    )
    assert report["affected_row_id"] == r119.TIMEOUT_ROW_ID
    assert report["error_code"] == "read_timeout"
    assert report["attempt_count"] == 1
    assert report["prior_max_output_tokens"] == planner.MAX_OUTPUT_TOKENS
    assert report["prior_authority_count"] == 24
    assert report["scenario_characters"] == 1080
    assert report["prior_input_json_characters"] == 8582
    assert report["prior_message_characters"] == 10922
    assert (
        "REDUCE_SINGLETON_MAX_OUTPUT_TOKENS_FROM_900_TO_512"
        in report["material_execution_plan_changes"]
    )
    assert report["candidate_mutated"] is False
    assert report["phase2b_authorized"] is False
