from __future__ import annotations

import json
from pathlib import Path

from scripts import build_v111_phase2a_deep_recovery_comparison as comparison

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ORIGINAL = comparison.DEFAULT_ORIGINAL
DEEP_SOURCE = comparison.DEFAULT_DEEP_SOURCE
DEEP_RANKING = comparison.DEFAULT_DEEP_RANKING


def test_deep_recovery_comparison_is_complete_and_non_authorizing(tmp_path: Path) -> None:
    result = comparison.build_comparison(
        original_path=ORIGINAL,
        deep_source_path=DEEP_SOURCE,
        deep_ranking_path=DEEP_RANKING,
        output_root=tmp_path / "comparison",
    )
    artifact = json.loads((tmp_path / "comparison/DEEP-RANKING-COMPARISON-176.json").read_bytes())

    assert result["metrics"]["row_count"] == 176
    assert len(artifact["rows"]) == 176
    assert sum(artifact["metrics"]["score_movement_counts"].values()) == 176
    assert sum(artifact["metrics"]["review_track_counts"].values()) == 176
    assert artifact["diagnostic_triage_floor_is_not_release_threshold"] is True
    assert artifact["score_comparison_is_not_legal_quality_decision"] is True
    assert artifact["owner_decisions_applied"] is False
    assert artifact["technical_qualification_assigned"] is False
    assert artifact["source_admission_authorized"] is False
    assert artifact["candidate_mutated"] is False
    assert artifact["phase2b_authorized"] is False
    assert artifact["development30_authorized"] is False
    assert all(row["owner_decision_required"] is True for row in artifact["rows"])
    assert all(row["technical_qualification_assigned"] is False for row in artifact["rows"])
