from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.run_v111_phase2a_cross_subject_reranker import run_cross_subject_review
from scripts.run_v111_phase2a_deep_recovery_reranker import (
    ARTIFACT_SCHEMA,
    EXPECTED_ROW_COUNT,
    EXPECTED_SOURCE_DIGEST,
    EXPECTED_SOURCE_SCHEMA,
    OUTPUT_NAME,
)

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (
    ROOT
    / "data"
    / "evaluations"
    / "phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-24-r40-deep-recovery"
    / "DEEP-CURRENT-OFFICIAL-CANDIDATES-176.json"
)
CASES = ROOT / "benchmarks" / "evaluation" / "live-evaluation-60-v1" / "cases.jsonl"
IDENTITY = {
    "model_repo": "Qwen/Qwen3-Reranker-0.6B",
    "model_revision": "test-pinned-revision",
    "model_file_manifest_sha256": "a" * 64,
    "model_independent_from_drafting_adapter": True,
    "qualification_threshold": None,
}


def _scores(_query: str, candidates: list[dict[str, Any]]) -> tuple[list[float], dict[str, Any]]:
    return [1.0 / (index + 1) for index in range(len(candidates))], {
        "device": "fixture",
        "observed_peak_memory_gb": 0.1,
    }


def test_full_deep_recovery_fake_review_stays_advisory(tmp_path: Path) -> None:
    result = run_cross_subject_review(
        source_path=SOURCE,
        cases_path=CASES,
        output_root=tmp_path / "output",
        scorer=_scores,
        runtime_identity=IDENTITY,
        started_at=datetime(2026, 8, 24, 15, 0, tzinfo=UTC),
        expected_source_digest=EXPECTED_SOURCE_DIGEST,
        expected_source_schema=EXPECTED_SOURCE_SCHEMA,
        expected_row_count=EXPECTED_ROW_COUNT,
        output_name=OUTPUT_NAME,
        artifact_schema=ARTIFACT_SCHEMA,
    )

    assert result["row_count"] == 176
    artifact = json.loads((tmp_path / "output" / OUTPUT_NAME).read_bytes())
    assert artifact["schema"] == ARTIFACT_SCHEMA
    assert artifact["owner_decisions_applied"] is False
    assert artifact["technical_qualification_assigned"] is False
    assert artifact["source_admission_authorized"] is False
    assert artifact["phase2b_authorized"] is False
