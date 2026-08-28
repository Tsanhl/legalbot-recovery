from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.run_v111_phase2a_independent_reranker_advisory import (
    OUTPUT_NAME,
    PARTIAL_STOP_NAME,
    _load_cases,
    _load_object,
    _pretty_json,
    _review_one,
    _sealed,
    run_review,
    seal_partial_same_adapter_run,
)

ROOT = Path(__file__).resolve().parents[2]
OWNER_REVIEW = ROOT / "data" / "evaluations" / "phase2a-owner-review"
REMAINDER = (
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r29"
    / "REMAINING-448-RESEARCH-PACKETS.json"
)
CASES = ROOT / "benchmarks" / "evaluation" / "live-evaluation-60-v1" / "cases.jsonl"
IDENTITY = {
    "model_repo": "Qwen/Qwen3-Reranker-0.6B",
    "model_revision": "test-pinned-revision",
    "model_file_manifest_sha256": "a" * 64,
    "model_independent_from_drafting_adapter": True,
    "qualification_threshold": None,
}


def _scores(
    _query: str, candidates: list[dict[str, Any]]
) -> tuple[list[float], dict[str, Any]]:
    return [1.0 / (index + 1) for index in range(len(candidates))], {
        "device": "fixture",
        "observed_peak_memory_gb": 0.1,
    }


def test_full_fake_review_keeps_all_448_rows_advisory_and_independent(
    tmp_path: Path,
) -> None:
    result = run_review(
        remainder_path=REMAINDER,
        cases_path=CASES,
        output_root=tmp_path / "output",
        scorer=_scores,
        runtime_identity=IDENTITY,
        started_at=datetime(2026, 8, 24, 14, 0, tzinfo=UTC),
    )

    assert result["row_count"] == 448
    assert result["advisory_ranking_count"] == 448
    assert result["held_for_debug_count"] == 0
    assert result["model_independent_reviewer"] is True
    assert result["owner_decisions_applied"] is False
    assert result["phase2b_authorized"] is False
    artifact = json.loads((tmp_path / "output" / OUTPUT_NAME).read_bytes())
    assert artifact["model_independent_reviewer"] is True
    assert artifact["generative_model_used"] is False
    assert artifact["score_threshold_applied"] is False
    assert artifact["qualification_threshold"] is None
    assert artifact["technical_qualification_assigned"] is False
    assert all(row["owner_decision_required"] is True for row in artifact["rows"])
    assert all(row["candidate_relevance_qualified"] is False for row in artifact["rows"])


def test_same_invalid_score_failure_twice_holds_before_third_attempt(
    tmp_path: Path,
) -> None:
    remainder = _load_object(REMAINDER)
    row = remainder["rows"][0]
    case = _load_cases(CASES)[row["case_id"]]
    calls = 0

    def invalid(
        _query: str, candidates: list[dict[str, Any]]
    ) -> tuple[list[float], dict[str, Any]]:
        nonlocal calls
        calls += 1
        return [float("nan")] * len(candidates), {}

    checkpoints = tmp_path / "checkpoints"
    diagnostics = tmp_path / "diagnostics"
    checkpoints.mkdir()
    diagnostics.mkdir()
    held = _review_one(
        ordinal=1,
        row=row,
        case=case,
        scorer=invalid,
        runtime_identity_sha256="b" * 64,
        checkpoints_root=checkpoints,
        diagnostics_root=diagnostics,
    )

    assert calls == 2
    assert held["status"] == "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT"
    assert held["same_failure_fingerprint_twice"] is True
    assert held["debug_required_before_third_attempt"] is True
    assert len(list(diagnostics.glob("*.json"))) == 2


def test_resume_reuses_bound_checkpoint_without_rescoring(tmp_path: Path) -> None:
    output = tmp_path / "output"
    first = run_review(
        remainder_path=REMAINDER,
        cases_path=CASES,
        output_root=output,
        scorer=_scores,
        runtime_identity=IDENTITY,
        started_at=datetime(2026, 8, 24, 14, 0, tzinfo=UTC),
    )
    assert first["row_count"] == 448
    (output / OUTPUT_NAME).unlink()
    (output / "OUTCOME.txt").unlink()
    (output / "SHA256SUMS.txt").unlink()

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("sealed checkpoints must be reused")

    resumed = run_review(
        remainder_path=REMAINDER,
        cases_path=CASES,
        output_root=output,
        scorer=forbidden,
        runtime_identity=IDENTITY,
        started_at=datetime(2026, 8, 24, 15, 0, tzinfo=UTC),
        resume=True,
    )
    assert resumed["advisory_ranking_count"] == 448


def test_seals_interrupted_same_adapter_run_as_nonfinal_comparison(
    tmp_path: Path,
) -> None:
    root = tmp_path / "partial"
    (root / "checkpoints").mkdir(parents=True)
    (root / "diagnostics").mkdir()
    intent_material = {
        "schema": "legalbot.phase2a.owner-advisory-review-intent.v3",
        "model_independent_reviewer": False,
    }
    intent = {**intent_material, "intent_content_sha256": _sealed(intent_material)}
    (root / "INTENT.json").write_bytes(_pretty_json(intent))
    checkpoint_material = {
        "schema": "legalbot.phase2a.owner-advisory-row-checkpoint.v3",
        "ordinal": 1,
        "row_id": "live30-q01:issue-01",
    }
    checkpoint = {
        **checkpoint_material,
        "checkpoint_content_sha256": _sealed(checkpoint_material),
    }
    (root / "checkpoints" / "0001-test.json").write_bytes(_pretty_json(checkpoint))
    diagnostic_material = {
        "schema": "legalbot.phase2a.owner-advisory-rejected-attempt.v1",
        "ordinal": 1,
    }
    diagnostic = {
        **diagnostic_material,
        "diagnostic_content_sha256": _sealed(diagnostic_material),
    }
    (root / "diagnostics" / "0001-test-a1.json").write_bytes(
        _pretty_json(diagnostic)
    )

    result = seal_partial_same_adapter_run(root, successor_run="r36-independent")

    assert result["completed_checkpoint_count"] == 1
    assert result["diagnostic_count"] == 1
    assert result["technical_qualification_assigned"] is False
    assert result["phase2b_authorized"] is False
    assert (root / PARTIAL_STOP_NAME).is_file()
    assert seal_partial_same_adapter_run(
        root, successor_run="r36-independent"
    ) == result
