from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.run_v111_phase2a_owner_advisory_review import (
    MODEL_BACKEND,
    OUTPUT_SCHEMA,
    PINNED_RUNTIME_MODEL_VERSION,
    _load_cases,
    _load_object,
    _review_one,
    _validated_output,
    run_review,
)

ROOT = Path(__file__).resolve().parents[2]
OWNER_REVIEW = ROOT / "data" / "evaluations" / "phase2a-owner-review"
REMAINDER = (
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r29"
    / "REMAINING-448-RESEARCH-PACKETS.json"
)
CASES = ROOT / "benchmarks" / "evaluation" / "live-evaluation-60-v1" / "cases.jsonl"
PROMPT = (
    ROOT
    / "backend"
    / "app"
    / "evaluation"
    / "prompts"
    / "phase2a_owner_advisory_reviewer.v3.txt"
)


def _valid_structured(envelope: dict[str, Any]) -> dict[str, Any]:
    payload = envelope["payload"]
    candidate = payload["candidates_provided"][0]
    rank = candidate["rank"]
    return {
        "schema": OUTPUT_SCHEMA,
        "row_id": payload["row_id"],
        "semantic_assessment": "POTENTIALLY_RELEVANT_EXISTING_SPAN",
        "selected_candidate_ranks": [rank],
        "finding_codes": ["question_context_supported"],
    }


def _body(envelope: dict[str, Any], structured: dict[str, Any]) -> dict[str, Any]:
    raw = json.dumps(structured, ensure_ascii=False, sort_keys=True)
    return {
        "request_id": envelope["request_id"],
        "model_version": PINNED_RUNTIME_MODEL_VERSION,
        "backend": MODEL_BACKEND,
        "structured": structured,
        "raw_text": raw,
        "finish_reason": "stop",
        "usage": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
        "generation_ms": 50,
        "time_to_first_token_ms": 20,
        "peak_memory_gb": 6.0,
        "deterministic": True,
        "warnings": ["rubric_scoring_is_external"],
    }


def test_full_fake_review_keeps_all_448_rows_advisory(tmp_path: Path) -> None:
    def invoke(envelope: dict[str, Any]) -> dict[str, Any]:
        return _body(envelope, _valid_structured(envelope))

    result = run_review(
        remainder_path=REMAINDER,
        cases_path=CASES,
        prompt_path=PROMPT,
        output_root=tmp_path / "output",
        invoke=invoke,
        started_at=datetime(2026, 8, 24, 13, 0, tzinfo=UTC),
    )

    assert result["row_count"] == 448
    assert result["advisory_recommendation_count"] == 448
    assert result["held_for_debug_count"] == 0
    assert result["owner_decisions_applied"] is False
    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False
    artifact = json.loads(
        (tmp_path / "output" / "OWNER-ADVISORY-REVIEW-448.json").read_bytes()
    )
    assert artifact["model_independent_reviewer"] is False
    assert artifact["technical_qualification_assigned"] is False
    assert all(row["owner_decision_required"] is True for row in artifact["rows"])


def test_inconsistent_first_output_gets_only_one_targeted_repair(tmp_path: Path) -> None:
    remainder = _load_object(REMAINDER)
    row = remainder["rows"][0]
    case = _load_cases(CASES)[row["case_id"]]
    calls = 0

    def invoke(envelope: dict[str, Any]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 1:
            invalid = _valid_structured(envelope)
            invalid["selected_candidate_ranks"] = []
            invalid["finding_codes"] = [
                "exact_issue_terms_present",
                "candidates_unrelated",
            ]
            return _body(envelope, invalid)
        assert envelope["payload"]["repair_of_rejected_advisory_output"] is True
        return _body(envelope, _valid_structured(envelope))

    checkpoints = tmp_path / "checkpoints"
    diagnostics = tmp_path / "diagnostics"
    checkpoints.mkdir()
    diagnostics.mkdir()
    checkpoint = _review_one(
        ordinal=1,
        row=row,
        case=case,
        system_prompt=PROMPT.read_text(encoding="utf-8"),
        invoke=invoke,
        checkpoints_root=checkpoints,
        diagnostics_root=diagnostics,
    )

    assert calls == 2
    assert checkpoint["attempt_count"] == 2
    assert checkpoint["repaired_after_rejected_output"] is True
    assert checkpoint["deterministic_finding_codes"] == [
        "case_later_treatment_required",
        "candidate_version_unverified",
    ]
    assert len(list(diagnostics.glob("*-a1.json"))) == 1
    assert not list(diagnostics.glob("*-a2.json"))


def test_same_failure_twice_is_held_before_third_attempt(tmp_path: Path) -> None:
    remainder = _load_object(REMAINDER)
    row = remainder["rows"][0]
    case = _load_cases(CASES)[row["case_id"]]
    calls = 0

    def invoke(envelope: dict[str, Any]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        invalid = _valid_structured(envelope)
        invalid["semantic_assessment"] = "NOT_ALLOWED"
        return _body(envelope, invalid)

    checkpoints = tmp_path / "checkpoints"
    diagnostics = tmp_path / "diagnostics"
    checkpoints.mkdir()
    diagnostics.mkdir()
    held = _review_one(
        ordinal=1,
        row=row,
        case=case,
        system_prompt=PROMPT.read_text(encoding="utf-8"),
        invoke=invoke,
        checkpoints_root=checkpoints,
        diagnostics_root=diagnostics,
    )

    assert calls == 2
    assert held["status"] == "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT"
    assert held["same_failure_fingerprint_twice"] is True
    assert held["debug_required_before_third_attempt"] is True
    assert len(list(diagnostics.glob("*.json"))) == 2


def test_validator_rejects_model_peak_over_owner_ceiling() -> None:
    remainder = _load_object(REMAINDER)
    row = remainder["rows"][0]
    case = _load_cases(CASES)[row["case_id"]]
    from scripts.run_v111_phase2a_owner_advisory_review import _build_row_input

    row_input = _build_row_input(row, case)
    envelope = {
        "request_id": "request-1",
        "payload": row_input,
    }
    body = _body(envelope, _valid_structured(envelope))
    body["peak_memory_gb"] = 12.01

    try:
        _validated_output(body=body, row_input=row_input, request_id="request-1")
    except ValueError as exc:
        assert str(exc) == "model_peak_memory_exceeded"
    else:  # pragma: no cover - safety assertion
        raise AssertionError("peak memory above 12 GiB must fail closed")
