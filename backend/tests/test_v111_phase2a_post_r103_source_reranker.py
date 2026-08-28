from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts import run_v111_phase2a_post_r103_source_reranker as reranker

IDENTITY = {
    "model_repo": reranker.PINNED_MODEL_REPO,
    "model_revision": reranker.PINNED_MODEL_REVISION,
    "model_file_manifest_sha256": reranker.PINNED_MODEL_FILE_MANIFEST_SHA256,
    "model_independent_from_drafting_adapter": True,
    "generative_model_used": False,
    "qualification_threshold": None,
    "device": "fixture",
}


def _scores(
    _query: str, candidates: list[dict[str, Any]]
) -> tuple[list[float], dict[str, Any]]:
    return [candidate["rank"] / 100 for candidate in candidates], {
        "device": "fixture",
        "observed_peak_memory_gb": 0.1,
    }


def test_fake_review_reranks_all_26_links_without_gate_change(tmp_path: Path) -> None:
    output = tmp_path / "r105"
    final = reranker.run_review(
        source_path=reranker.SOURCE_PATH,
        output_root=output,
        scorer=_scores,
        runtime_identity=IDENTITY,
        started_at=datetime(2026, 8, 26, 8, 0, tzinfo=UTC),
    )

    assert final["row_source_link_count"] == 26
    assert final["advisory_ranking_count"] == 26
    assert final["held_for_debug_count"] == 0
    assert final["model_independent_from_drafting_adapter"] is True
    assert final["generative_model_used"] is False
    assert final["score_threshold_applied"] is False
    assert final["legal_sufficiency_decided"] is False
    assert final["source_admission_authorized"] is False
    assert final["automatic_indexing"] is False
    assert final["phase2b_authorized"] is False
    assert all(len(row["top_candidates"]) == 8 for row in final["rows"])
    assert all(
        len(row["all_ranked_candidates"]) <= 40 for row in final["rows"]
    )
    assert (output / reranker.OUTPUT_NAME).is_file()
    assert (output / "SHA256SUMS.txt").is_file()


def test_same_failure_twice_holds_before_any_third_attempt(tmp_path: Path) -> None:
    source = reranker._load_source(reranker.SOURCE_PATH)
    checkpoints = tmp_path / "checkpoints"
    diagnostics = tmp_path / "diagnostics"
    checkpoints.mkdir()
    diagnostics.mkdir()
    calls = 0

    def invalid(
        _query: str, candidates: list[dict[str, Any]]
    ) -> tuple[list[float], dict[str, Any]]:
        nonlocal calls
        calls += 1
        return [float("nan")] * len(candidates), {}

    held = reranker._review_one(
        ordinal=1,
        row=source["rows"][0],
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


def test_resume_reuses_bound_checkpoints_without_rescoring(tmp_path: Path) -> None:
    output = tmp_path / "r105"
    reranker.run_review(
        source_path=reranker.SOURCE_PATH,
        output_root=output,
        scorer=_scores,
        runtime_identity=IDENTITY,
        started_at=datetime(2026, 8, 26, 8, 0, tzinfo=UTC),
    )
    (output / reranker.OUTPUT_NAME).unlink()
    (output / "OUTCOME.txt").unlink()
    (output / "SHA256SUMS.txt").unlink()

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("sealed checkpoints must be reused")

    final = reranker.run_review(
        source_path=reranker.SOURCE_PATH,
        output_root=output,
        scorer=forbidden,
        runtime_identity=IDENTITY,
        started_at=datetime(2026, 8, 26, 9, 0, tzinfo=UTC),
        resume=True,
    )
    assert final["advisory_ranking_count"] == 26


def test_source_packet_contains_getty_paragraph_90() -> None:
    source = reranker._load_source(reranker.SOURCE_PATH)
    getty = next(
        row
        for row in source["rows"]
        if row["row_id"] == "live30-q30:issue-16"
        and row["authority_identity_id"] == "neutral-citation:[2025] EWHC 38 (Ch)"
    )
    paragraph = next(
        block for block in getty["candidate_blocks"] if block["locator"] == "paragraph 90"
    )
    assert "QUESTION_SEGMENT_OVERLAP" in paragraph["selection_reasons"]
