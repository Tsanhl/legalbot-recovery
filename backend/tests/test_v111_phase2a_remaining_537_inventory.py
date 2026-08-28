from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.build_v111_phase2a_remaining_537_inventory import (
    APPROVED_SCHEMA,
    CORRECTION_QUEUE_STATUSES,
    DETERMINISTIC_STATUS,
    HISTORICAL_SCHEMA,
    KEEP_GAP_STATUS,
    MATRIX_SCHEMA,
    OWNER_REVIEWED_SCHEMA,
    RECONCILIATION_SCHEMA,
    _evidence_state,
    _pretty_json,
    _sealed,
    build_inventory,
)


def _write_sealed(path: Path, material: dict[str, object], seal_field: str) -> dict[str, object]:
    value = {**material, seal_field: _sealed(material)}
    path.write_bytes(_pretty_json(value))
    return value


def _synthetic_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    matrix_rows: list[dict[str, object]] = []
    owner_rows: list[dict[str, object]] = []
    historical_records: list[dict[str, object]] = []
    reconciliation_records: list[dict[str, object]] = []
    approved: list[dict[str, object]] = []
    correction_status = next(iter(CORRECTION_QUEUE_STATUSES))

    for ordinal in range(1, 586):
        row_id = f"live30-q{((ordinal - 1) % 30) + 1:02d}:issue-{ordinal:02d}"
        baseline = (
            "GOLD_OR_CASE_DEFECT"
            if ordinal <= 48 or ordinal <= 48 + 467
            else "MATERIAL_CANDIDATE_COVERAGE_GAP"
        )
        matrix_rows.append(
            {
                "ordinal": ordinal,
                "row_id": row_id,
                "case_id": row_id.split(":", 1)[0],
                "issue_id": row_id.split(":", 1)[1],
                "issue_label": f"Issue {ordinal}",
                "issue_label_sha256": "a" * 64,
                "legal_domain": "test",
                "task_type": "problem",
                "baseline_primary_status": baseline,
                "determined_defects": ["MISSING_PROPOSITION_BINDING"],
            }
        )
        owner_rows.append(
            {
                "row_id": row_id,
                "owner_review": {
                    "status": "OWNER_REQUESTED_MORE_EVIDENCE",
                    "owner_decision_sha256": "b" * 64,
                },
            }
        )
        if ordinal <= 293:
            operative_text = "" if ordinal > 137 else f"Proposition {ordinal}"
            historical_record = {
                "issue_key": row_id,
                "question": f"Question {ordinal}",
                "operative_text": operative_text,
                "source_title": "Example Act 2020",
                "source_type": "legislation_or_procedural_instrument",
                "citation": "2020 c 1",
                "legal_locator": "s 1",
                "official_source_url": ("https://www.legislation.gov.uk/ukpga/2020/1/section/1"),
            }
            historical_records.append(historical_record)
            if ordinal <= 48:
                match_status = DETERMINISTIC_STATUS
            elif ordinal <= 137:
                match_status = correction_status
            else:
                match_status = KEEP_GAP_STATUS
            reconciliation_records.append(
                {
                    "row_id": row_id,
                    "match_status": match_status,
                    "historical_staging_record_sha256": _sealed(historical_record),
                    "record_content_sha256": "c" * 64,
                    "candidate_spans": [],
                }
            )
        if ordinal <= 48:
            approved.append(
                {
                    "row_id": row_id,
                    "status": "OWNER_APPROVED_INTERNAL_RESEARCH_TOOL_BINDING",
                    "phase2b_authorized": False,
                    "development30_authorized": False,
                }
            )

    matrix_path = tmp_path / "matrix.json"
    _write_sealed(
        matrix_path,
        {
            "schema": MATRIX_SCHEMA,
            "row_count": 585,
            "rows": matrix_rows,
        },
        "artifact_sha256",
    )
    reconciliation_path = tmp_path / "reconciliation.json"
    _write_sealed(
        reconciliation_path,
        {
            "schema": RECONCILIATION_SCHEMA,
            "record_count": 293,
            "records": reconciliation_records,
        },
        "artifact_content_sha256",
    )
    approved_path = tmp_path / "approved.json"
    _write_sealed(
        approved_path,
        {"schema": APPROVED_SCHEMA, "item_count": 48, "decisions": approved},
        "approved_package_content_sha256",
    )
    owner_path = tmp_path / "owner.json"
    _write_sealed(
        owner_path,
        {
            "schema": OWNER_REVIEWED_SCHEMA,
            "record_count": 585,
            "rows": owner_rows,
        },
        "artifact_content_sha256",
    )
    historical_path = tmp_path / "historical.json"
    historical_path.write_bytes(
        _pretty_json({"schema": HISTORICAL_SCHEMA, "records": historical_records})
    )
    return matrix_path, reconciliation_path, approved_path, owner_path, historical_path


def test_builds_exact_row_level_537_remainder(tmp_path: Path) -> None:
    matrix, reconciliation, approved, owner, historical = _synthetic_inputs(tmp_path)
    output = tmp_path / "output"

    result = build_inventory(
        matrix_path=matrix,
        reconciliation_path=reconciliation,
        approved_path=approved,
        owner_reviewed_path=owner,
        historical_path=historical,
        output_root=output,
    )

    assert result["remaining_issue_count"] == 537
    assert result["official_rebinding_queue_count"] == 89
    assert result["phase2b_authorized"] is False
    inventory = json.loads((output / "REMAINING-537-BLOCKER-INVENTORY.json").read_bytes())
    assert inventory["evidence_state_counts"] == {
        "CONCRETE_STAGING_PROPOSITION_REQUIRES_OFFICIAL_REBINDING": 89,
        "HISTORICAL_REVIEW_KEPT_GAP_NO_SAFE_OPERATIVE_SPAN": 156,
        "NO_HISTORICAL_PROPOSITION_PACKET": 292,
    }
    assert inventory["baseline_status_counts"] == {
        "GOLD_OR_CASE_DEFECT": 467,
        "MATERIAL_CANDIDATE_COVERAGE_GAP": 70,
    }


def test_evidence_states_do_not_turn_search_results_into_qualification() -> None:
    for status in CORRECTION_QUEUE_STATUSES:
        state, correction = _evidence_state(status)
        assert state == "CONCRETE_STAGING_PROPOSITION_REQUIRES_OFFICIAL_REBINDING"
        assert correction.startswith("VERIFY_EXACT_PROPOSITION")
    assert _evidence_state(KEEP_GAP_STATUS)[0].startswith("HISTORICAL_REVIEW_KEPT_GAP")
    assert _evidence_state(None)[0] == "NO_HISTORICAL_PROPOSITION_PACKET"


def test_already_approved_status_cannot_reenter_remainder() -> None:
    with pytest.raises(
        ValueError,
        match="phase2a_remaining_inventory_unexpected_historical_status",
    ):
        _evidence_state(DETERMINISTIC_STATUS)
