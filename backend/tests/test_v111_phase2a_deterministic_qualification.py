from __future__ import annotations

import json
from pathlib import Path

from app.evaluation.live_suite import load_live_evaluation_bundle
from app.evaluation.phase2a_deterministic_qualification import (
    BLOCKED_MATERIAL_GAP,
    OWNER_DECISION_REQUIRED,
    TECHNICALLY_READY,
    build_deterministic_all585_qualification,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OWNER_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"


def _load(relative: str) -> dict[str, object]:
    value = json.loads((OWNER_ROOT / relative).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_real_phase2a_partition_produces_truthful_all585_blocked_result() -> None:
    bundle = load_live_evaluation_bundle(
        PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
    )
    source_manifest = json.loads(
        (
            PROJECT_ROOT / "data/review_queue/approved-source-manifest-current-law-ew-full-"
            "phase2a-held-20260827-v1.json"
        ).read_text(encoding="utf-8")
    )
    result = build_deterministic_all585_qualification(
        bundle=bundle,
        consolidated_matrix=_load(
            "LegalBot-Phase2AB-2026-08-24-r47-consolidated-owner-gate/"
            "COMPLETE-REMEDIATION-MATRIX-585.json"
        ),
        r94_owner_batch=_load(
            "LegalBot-Phase2AB-2026-08-25-r94-consolidated-substantive-owner-batch/"
            "OWNER-SUBSTANTIVE-DECISION-BATCH.json"
        ),
        r113_remaining_gaps=_load(
            "LegalBot-Phase2AB-2026-08-26-r113-post-r110-owner-approved/"
            "REMAINING-MATERIAL-GAPS-364.json"
        ),
        deterministic_crosswalk=_load(
            "LegalBot-Phase2A-2026-08-27-deterministic-exact-span-crosswalk-r2/"
            "DETERMINISTIC-EXACT-SPAN-PACKETS-364.json"
        ),
        source_manifest=source_manifest,
        candidate_identity={
            "build_id": "current-law-ew-full-fp16-v111-20260827-phase2a-a",
            "status": "built_unscored",
            "stage": "built_unscored",
            "document_count": 251,
            "chunk_count": 222_200,
            "vector_count": 222_200,
            "build_seal_sha256": "a" * 64,
        },
        held_retrieval_reattestation={
            "retrieval_quality_passed": True,
            "promotion_eligible": False,
            "answer_release_eligible": False,
            "candidate_status_written": False,
            "active_pointer_written": False,
            "metrics": {
                "query_count": 24,
                "binding_count": 24,
                "positive_recall_at_5": 1.0,
                "positive_recall_at_10": 1.0,
                "mrr": 0.9,
            },
        },
        evidence_file_sha256s={"test": "b" * 64},
    )

    assert len(result["rows"]) == 585
    assert len(result["cases"]) == 60
    assert result["status_counts"] == {
        BLOCKED_MATERIAL_GAP: 98,
        OWNER_DECISION_REQUIRED: 263,
        TECHNICALLY_READY: 224,
    }
    assert result["successor_source_holds"]["currentness_unverified_source_count"] == 186
    assert result["successor_source_holds"]["later_treatment_required_source_count"] == 135
    assert result["phase2a_technical_qualification_passed"] is False
    assert result["phase2b_eligible"] is False
    assert result["common_legal_currentness_cutoff"] is None
