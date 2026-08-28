from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.run_v111_phase2a_cross_subject_reranker import (
    OUTPUT_NAME,
    run_cross_subject_review,
)

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (
    ROOT
    / "data"
    / "evaluations"
    / "phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-24-r37-cross-subject"
    / "CROSS-SUBJECT-CURRENT-OFFICIAL-CANDIDATES-37.json"
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


def test_full_37_row_fake_review_stays_advisory(tmp_path: Path) -> None:
    result = run_cross_subject_review(
        source_path=SOURCE,
        cases_path=CASES,
        output_root=tmp_path / "output",
        scorer=_scores,
        runtime_identity=IDENTITY,
        started_at=datetime(2026, 8, 24, 15, 0, tzinfo=UTC),
    )
    assert result["row_count"] == 37
    assert result["advisory_ranking_count"] == 37
    assert result["held_for_debug_count"] == 0
    assert result["phase2b_authorized"] is False
    artifact = json.loads((tmp_path / "output" / OUTPUT_NAME).read_bytes())
    assert artifact["model_independent_reviewer"] is True
    assert artifact["generative_model_used"] is False
    assert artifact["qualification_threshold"] is None
    assert artifact["source_admission_authorized"] is False
    assert artifact["candidate_mutated"] is False
    assert all(row["owner_decision_required"] is True for row in artifact["rows"])
