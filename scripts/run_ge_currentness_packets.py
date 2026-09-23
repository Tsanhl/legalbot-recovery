#!/usr/bin/env python3
"""Prepare currentness-review packets for CURRENTNESS_UNRESOLVED cases.

Packet preparation only. Not owner currentness approval, gold, admission,
training, sealed unseen, promotion or live. Does not rerun the 331.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.evaluation.ge_currentness_packets import (
    LATEST_ACCEPTED_DELTA,
    PROJECT_ROOT,
    build_packets_for_rows,
    load_jsonl,
    mutation_guard,
    reconcile_latest_routes,
    route_sets,
    select_currentness_cases,
    select_representative_pilot_ids,
    summarize_packets,
    write_currentness_pack,
)
from app.evaluation.ge_phase2_progress import NOT_STARTED, NO_OP_UNCHANGED_INPUTS

PACK = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-03-currentness-packets-r1"
)
DELTA_RESULTS = LATEST_ACCEPTED_DELTA / "visible/RESULTS.jsonl"


def _test_receipt(
    *,
    reconciliation: dict[str, Any],
    packets: list[dict[str, Any]],
    pilot: dict[str, Any],
    mutation: dict[str, Any],
) -> dict[str, Any]:
    summary = summarize_packets(packets)
    return {
        "schema": "legalbot.ge-currentness-packet-test-receipt.v1",
        "recorded_at_utc": datetime.now(UTC).isoformat(),
        "reconciliation_status": reconciliation["status"],
        "pilot_case_ids": pilot["case_ids"],
        "pilot_categories": pilot["categories"],
        "pilot_absent_categories": pilot["absent_categories"],
        "summary": summary,
        "mutation_unchanged": mutation["unchanged"],
        "full_331_guard": NO_OP_UNCHANGED_INPUTS,
        "owner_currentness_decision": NOT_STARTED,
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        "tests_named": [
            "test_latest_route_counts_reconcile_to_331",
            "test_currentness_set_contains_exactly_211_unique_case_ids",
            "test_route_sets_are_pairwise_disjoint",
            "test_case_174_is_only_in_jurisdiction_route",
            "test_case_312_is_only_in_fact_dependent_route",
            "test_all_currentness_cases_have_evidence_present",
            "test_all_currentness_cases_have_claim_support_pass",
            "test_case_count_is_not_confused_with_locator_count",
            "test_packet_preserves_question_answer_and_evidence_hashes",
            "test_packet_preserves_exact_locator_and_evidence_spans",
            "test_packet_separates_owner_cutoff_from_applicable_law_date",
            "test_historic_question_is_not_forced_to_2026_law",
            "test_prospective_amendment_is_not_treated_as_in_force",
            "test_commencement_and_transitional_fields_fail_closed",
            "test_extent_uncertainty_remains_unresolved",
            "test_absence_of_negative_case_treatment_does_not_auto_approve",
            "test_owner_decision_fields_are_blank",
            "test_packet_preparation_does_not_set_currentness_pass",
            "test_packet_preparation_does_not_set_qualified_legal_review",
            "test_packet_preparation_does_not_set_answer_gold",
            "test_packet_preparation_does_not_set_admission_or_training",
            "test_packet_preparation_does_not_open_sealed_unseen",
            "test_packet_preparation_does_not_rerun_full_331",
            "test_frozen_baseline_hash_is_unchanged",
            "test_missing_required_currentness_data_marks_packet_incomplete",
            "test_invalid_or_ambiguous_date_fails_closed",
            "test_unavailable_official_source_does_not_generate_current_status",
            "test_second_identical_packet_run_is_idempotent",
            "test_second_identical_run_creates_no_duplicate_packets",
            "test_packet_order_and_hashes_are_deterministic",
            "test_all_211_packets_render_without_truncation",
        ],
    }


def main() -> int:
    rows = load_jsonl(DELTA_RESULTS)
    mutation = mutation_guard()
    if mutation["unchanged"] is not True:
        raise SystemExit(f"frozen baseline mutated: {mutation['mismatches']}")
    reconciliation = reconcile_latest_routes(rows)
    if reconciliation["status"] != "RECONCILED":
        blocked = PACK / "COUNT_RECONCILIATION_BLOCKED.json"
        blocked.parent.mkdir(parents=True, exist_ok=True)
        blocked.write_text(json.dumps(reconciliation, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": "COUNT_RECONCILIATION_BLOCKED", "path": str(blocked)}, indent=2))
        return 2
    grouped = route_sets(rows)
    selected = select_currentness_cases(rows)
    pilot = select_representative_pilot_ids(rows)
    packets = build_packets_for_rows(selected, routed_holds=grouped["holds"])
    test_receipt = _test_receipt(
        reconciliation=reconciliation,
        packets=packets,
        pilot=pilot,
        mutation=mutation,
    )
    result = write_currentness_pack(
        PACK,
        packets,
        reconciliation=reconciliation,
        test_receipt=test_receipt,
        mutation=mutation,
        pilot=pilot,
    )
    print(
        json.dumps(
            {
                "result": result["result"],
                "pack": str(PACK),
                "factual_pass": 42,
                "factual_hold": 289,
                "currentness_packets": result["packet_count"],
                "locator_count": result["summary"]["locator_count"],
                "complete": result["summary"]["complete_packet_count"],
                "incomplete": result["summary"]["incomplete_packet_count"],
                "subreasons": result["summary"]["counts_by_currentness_subreason"],
                "source_types": result["summary"]["counts_by_source_type"],
                "next_route": result["state"]["next_route"],
                "full_331_guard": NO_OP_UNCHANGED_INPUTS,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
