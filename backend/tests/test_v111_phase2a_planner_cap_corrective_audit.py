from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from scripts import build_v111_phase2a_planner_cap_corrective_audit as audit
from scripts import plan_v111_phase2a_material_gap_research as planner


def test_inventory_finds_every_cumulative_attempt_cap_breach() -> None:
    source_manifest, inventory = audit._inventory()

    planner._verify_seal(
        source_manifest,
        "artifact_content_sha256",
        "test_corrective_source_manifest_seal_invalid",
    )
    planner._verify_seal(
        inventory,
        "artifact_content_sha256",
        "test_corrective_inventory_seal_invalid",
    )
    assert source_manifest["run_count"] == 6
    assert [run["run_id"] for run in source_manifest["runs"]] == [
        "r114",
        "r115",
        "r116",
        "r117",
        "r118",
        "r119",
    ]
    assert inventory["canonical_row_count"] == 364
    assert inventory["over_cap_row_count"] == 38
    assert inventory["over_cap_cumulative_invocation_counts"] == {
        "3": 26,
        "4": 11,
        "5": 1,
    }
    assert inventory["timeout_row_count"] == 10
    assert inventory["over_cap_r118_state_counts"] == {
        "ACCEPTED_ADVISORY_PLAN": 25,
        "HELD_DEBUG_EVIDENCE": 2,
    }
    assert all(
        record["admissibility"]
        == "EXCLUDED_FROM_SUBSTANTIVE_EVIDENCE_DUE_TO_CUMULATIVE_ATTEMPT_CAP_BREACH"
        for record in inventory["records"]
    )


def test_focus_row_records_all_five_invocations_and_fingerprints() -> None:
    _, inventory = audit._inventory()
    focus = next(
        record for record in inventory["records"] if record["row_id"] == audit.FOCUS_ROW_ID
    )

    assert focus["cumulative_invocation_count"] == 5
    assert {run: data["attempt_count"] for run, data in focus["runs"].items()} == {
        "r117": 2,
        "r118": 2,
        "r119": 1,
    }
    assert tuple(focus["failure_fingerprints"]) == audit.EXPECTED_FOCUS_FINGERPRINTS
    assert Counter(
        diagnostic["error_code"]
        for run in focus["runs"].values()
        for diagnostic in run["diagnostics"]
    ) == Counter(
        {
            "structured_output_proposition_too_long": 1,
            "structured_output_proposition_not_linked_to_issue": 2,
            "model_output_truncated": 1,
            "read_timeout": 1,
        }
    )


def test_corrective_audit_is_fail_closed_and_non_authorizing(tmp_path: Path) -> None:
    quiescence_material = {
        "schema": "legalbot.v111.phase2a.planner-quiescence-evidence.v1",
        "observed_at": "2026-08-27T00:00:00+00:00",
        "matching_planner_or_model_process_count": 0,
        "model_runtime_port_8779_listening": False,
        "raw_process_listing_persisted": False,
    }
    quiescence = {
        **quiescence_material,
        "artifact_content_sha256": planner._sealed(quiescence_material),
    }
    output = tmp_path / "corrective-audit"

    result = audit.build_audit(
        output_root=output,
        observed_at=datetime(2026, 8, 27, tzinfo=UTC),
        quiescence=quiescence,
    )

    assert result["status"] == "PHASE_2A_SAFELY_STOPPED_OWNER_INPUT_REQUIRED"
    assert result["over_cap_row_count"] == 38
    assert result["over_cap_results_admissible_as_substantive_evidence"] is False
    assert result["candidate_mutated"] is False
    assert result["source_admission_state_mutated"] is False
    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False
    assert result["validation30_authorized"] is False
    assert result["live_activation_authorized"] is False
    assert "PHASE 2A SAFELY STOPPED" in (output / "OUTCOME.txt").read_text()
    for name, seal_field in (
        ("SOURCE-RUN-FILE-MANIFEST.json", "artifact_content_sha256"),
        ("OVER-CAP-ROW-INVENTORY.json", "artifact_content_sha256"),
        ("PROCESS-QUIESCENCE.json", "artifact_content_sha256"),
        ("PLANNER-CAP-CORRECTIVE-AUDIT.json", "artifact_content_sha256"),
    ):
        payload = json.loads((output / name).read_text())
        planner._verify_seal(payload, seal_field, f"test_{name}_seal_invalid")
