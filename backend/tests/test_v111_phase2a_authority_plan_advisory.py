from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from scripts import build_v111_phase2a_authority_plan_advisory as planner


def _response(envelope: dict[str, Any], *, invented: bool = False) -> dict[str, Any]:
    row_input = envelope["payload"]
    authorities = row_input["authorities"]
    authority_id = (
        "invented-authority" if invented else (str(authorities[0]["id"]) if authorities else None)
    )
    rows = []
    for row in row_input["rows"]:
        if authority_id is None:
            rows.append({"row_id": row["row_id"], "assessment": "GAP", "selections": []})
        else:
            rows.append(
                {
                    "row_id": row["row_id"],
                    "assessment": "FOUND",
                    "selections": [{"id": authority_id, "locator": "section 1"}],
                }
            )
    raw = json.dumps(
        {"schema": planner.OUTPUT_SCHEMA, "case_id": row_input["case_id"], "rows": rows}
    )
    return {
        "request_id": envelope["request_id"],
        "model_version": planner.EXPECTED_MODEL_VERSION,
        "backend": planner.MODEL_BACKEND,
        "deterministic": True,
        "warnings": [],
        "finish_reason": "stop",
        "usage": {"input_tokens": 10, "output_tokens": 10, "total_tokens": 20},
        "generation_ms": 1,
        "time_to_first_token_ms": 1,
        "peak_memory_gb": 1.0,
        "raw_text": raw,
        "structured": json.loads(raw),
    }


def test_authority_plan_covers_all_448_without_authorizing_a_gate(tmp_path: Path) -> None:
    result = planner.build_authority_plans(
        remaining_path=planner.DEFAULT_REMAINING,
        original_path=planner.DEFAULT_ORIGINAL,
        deep_path=planner.DEFAULT_DEEP,
        cases_path=planner.DEFAULT_CASES,
        output_root=tmp_path / "plans",
        invoke=_response,
        started_at=datetime(2026, 8, 25, tzinfo=UTC),
    )

    assert result["planned_issue_count"] == 448
    assert result["held_issue_count"] == 0
    assert sum(result["assessment_counts"].values()) == 448
    assert result["owner_decisions_applied"] is False
    assert result["technical_qualification_assigned"] is False
    assert result["source_admission_authorized"] is False
    assert result["candidate_mutated"] is False
    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False
    assert all(row["owner_outcome"] is None for row in result["plans"])


def test_invented_authority_is_rejected_and_batch_is_held_after_two_attempts(
    tmp_path: Path,
) -> None:
    calls = 0

    def invented(envelope: dict[str, Any]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return _response(envelope, invented=True)

    result = planner.build_authority_plans(
        remaining_path=planner.DEFAULT_REMAINING,
        original_path=planner.DEFAULT_ORIGINAL,
        deep_path=planner.DEFAULT_DEEP,
        cases_path=planner.DEFAULT_CASES,
        output_root=tmp_path / "held",
        invoke=invented,
        started_at=datetime(2026, 8, 25, tzinfo=UTC),
    )

    # Every independent batch is attempted twice, but no batch receives a third try.
    checkpoint_count = len(list((tmp_path / "held" / "checkpoints").glob("*.json")))
    assert calls == checkpoint_count * 2
    assert result["planned_issue_count"] == 0
    assert result["held_issue_count"] == 448
    assert len(list((tmp_path / "held" / "diagnostics").glob("*.json"))) == calls
    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False


def test_authority_plan_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    with pytest.raises(ValueError, match="output_already_exists"):
        planner.build_authority_plans(
            remaining_path=planner.DEFAULT_REMAINING,
            original_path=planner.DEFAULT_ORIGINAL,
            deep_path=planner.DEFAULT_DEEP,
            cases_path=planner.DEFAULT_CASES,
            output_root=output,
            invoke=_response,
            started_at=datetime(2026, 8, 25, tzinfo=UTC),
        )
