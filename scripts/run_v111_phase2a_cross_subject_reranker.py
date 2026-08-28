#!/usr/bin/env python3
"""Independently rerank the 37 cross-subject current-source recovery rows."""

from __future__ import annotations

import argparse
import json
import stat
import sys
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from scripts.run_v111_phase2a_independent_reranker_advisory import (  # noqa: E402
    REVIEWER_EXECUTION_MODE,
    ScoreRow,
    _checkpoint_name,
    _load_cases,
    _load_checkpoint,
    _load_object,
    _pretty_json,
    _real_scorer,
    _review_one,
    _sealed,
    _sha256_file,
    _validate_row,
    _verify_seal,
    _write_exclusive,
)

EXPECTED_SOURCE_DIGEST = "a79b09a0a19b1f674ec6b600f98cfb9b3decbcc22907ca9356b804c3e47c5559"
EXPECTED_ROW_COUNT = 37
OUTPUT_NAME = "INDEPENDENT-RERANKER-CROSS-SUBJECT-37.json"


def run_cross_subject_review(
    *,
    source_path: Path,
    cases_path: Path,
    output_root: Path,
    scorer: ScoreRow,
    runtime_identity: Mapping[str, Any],
    started_at: datetime,
    resume: bool = False,
    expected_source_digest: str = EXPECTED_SOURCE_DIGEST,
    expected_source_schema: str = "legalbot.v111.phase2a.cross-subject-recovery-37.v1",
    expected_row_count: int = EXPECTED_ROW_COUNT,
    output_name: str = OUTPUT_NAME,
    artifact_schema: str = "legalbot.phase2a.independent-reranker-cross-subject-37.v1",
) -> dict[str, Any]:
    if started_at.tzinfo is None:
        raise ValueError("phase2a_cross_subject_reranker_started_at_naive")
    source = _load_object(source_path)
    source_digest = _verify_seal(
        source,
        "artifact_content_sha256",
        "phase2a_cross_subject_reranker_source_seal_invalid",
    )
    rows = source.get("rows")
    if (
        source_digest != expected_source_digest
        or source.get("schema") != expected_source_schema
        or source.get("row_count") != expected_row_count
        or not isinstance(rows, list)
        or len(rows) != expected_row_count
        or source.get("source_admission_authorized") is not False
        or source.get("candidate_mutated") is not False
        or source.get("phase2b_authorized") is not False
        or source.get("development30_authorized") is not False
        or any(
            not isinstance(row, dict) or row.get("technical_qualification_assigned") is not False
            for row in rows
        )
    ):
        raise ValueError("phase2a_cross_subject_reranker_source_boundary_invalid")
    cases = _load_cases(cases_path)
    runtime_identity_sha256 = _sealed(runtime_identity)
    intent_path = output_root / "INTENT.json"
    if output_root.exists() or output_root.is_symlink():
        if not resume or output_root.is_symlink() or not output_root.is_dir():
            raise ValueError("phase2a_cross_subject_reranker_output_already_exists")
        intent = _load_object(intent_path)
        _verify_seal(
            intent,
            "intent_content_sha256",
            "phase2a_cross_subject_reranker_intent_seal_invalid",
        )
        if (
            intent.get("source_artifact_content_sha256") != source_digest
            or intent.get("runtime_identity_sha256") != runtime_identity_sha256
        ):
            raise ValueError("phase2a_cross_subject_reranker_resume_identity_mismatch")
    else:
        output_root.mkdir(parents=True, mode=0o700)
        if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
            raise ValueError("phase2a_cross_subject_reranker_output_mode_invalid")
        intent_material = {
            "schema": "legalbot.phase2a.cross-subject-reranker-intent.v1",
            "status": "ADVISORY_RELEVANCE_RANKING_ONLY_NO_OWNER_DECISIONS",
            "started_at": started_at.astimezone(UTC).isoformat(timespec="seconds"),
            "source_artifact_content_sha256": source_digest,
            "source_artifact_file_sha256": _sha256_file(source_path),
            "runtime_identity": dict(runtime_identity),
            "runtime_identity_sha256": runtime_identity_sha256,
            "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
            "model_independent_reviewer": True,
            "row_count": expected_row_count,
            "score_threshold_applied": False,
            "qualification_threshold": None,
            "owner_decisions_applied": False,
            "technical_qualification_assigned": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        intent = {**intent_material, "intent_content_sha256": _sealed(intent_material)}
        _write_exclusive(intent_path, _pretty_json(intent))
    checkpoints = output_root / "checkpoints"
    diagnostics = output_root / "diagnostics"
    checkpoints.mkdir(mode=0o700, exist_ok=True)
    diagnostics.mkdir(mode=0o700, exist_ok=True)
    if (output_root / output_name).exists():
        raise ValueError("phase2a_cross_subject_reranker_already_finalized")

    results: list[dict[str, Any]] = []
    for ordinal, raw in enumerate(rows, start=1):
        if not isinstance(raw, dict):
            raise ValueError("phase2a_cross_subject_reranker_row_invalid")
        _validate_row(raw)
        row_id = str(raw["row_id"])
        checkpoint_path = checkpoints / _checkpoint_name(ordinal, row_id)
        if checkpoint_path.exists():
            checkpoint = _load_checkpoint(checkpoint_path)
            if (
                checkpoint.get("ordinal") != ordinal
                or checkpoint.get("row_id") != row_id
                or checkpoint.get("source_row_packet_content_sha256")
                != raw.get("row_packet_content_sha256")
            ):
                raise ValueError("phase2a_cross_subject_reranker_checkpoint_binding_invalid")
            results.append(checkpoint)
            continue
        case = cases.get(str(raw.get("case_id") or ""))
        if case is None:
            raise ValueError("phase2a_cross_subject_reranker_case_missing")
        results.append(
            _review_one(
                ordinal=ordinal,
                row=raw,
                case=case,
                scorer=scorer,
                runtime_identity_sha256=runtime_identity_sha256,
                checkpoints_root=checkpoints,
                diagnostics_root=diagnostics,
            )
        )
    held = [
        result
        for result in results
        if result.get("schema") == "legalbot.phase2a.independent-advisory-held-row.v1"
    ]
    passed = [result for result in results if result not in held]
    counts = Counter(str(result["advisory_recommendation"]) for result in passed)
    final_rows = []
    for result in results:
        if result in held:
            final_rows.append(
                {
                    "ordinal": result["ordinal"],
                    "row_id": result["row_id"],
                    "status": result["status"],
                    "held_content_sha256": result["held_content_sha256"],
                    "owner_decision_required": True,
                }
            )
        else:
            final_rows.append(
                {
                    "ordinal": result["ordinal"],
                    "row_id": result["row_id"],
                    "status": "CROSS_SUBJECT_ADVISORY_RANKING_READY_OWNER_DECISION_REQUIRED",
                    "recommendation": result["advisory_recommendation"],
                    "ranked_candidates": result["ranked_candidates"],
                    "checkpoint_content_sha256": result["checkpoint_content_sha256"],
                    "score_threshold_applied": False,
                    "candidate_relevance_qualified": False,
                    "owner_decision_required": True,
                }
            )
    material = {
        "schema": artifact_schema,
        "status": (
            "INDEPENDENT_CROSS_SUBJECT_ADVISORY_COMPLETE_OWNER_DECISIONS_REQUIRED"
            if not held
            else "INDEPENDENT_CROSS_SUBJECT_ADVISORY_HAS_HELD_ROWS_DEBUG_REQUIRED"
        ),
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_artifact_content_sha256": source_digest,
        "runtime_identity_sha256": runtime_identity_sha256,
        "reviewer_execution_mode": REVIEWER_EXECUTION_MODE,
        "model_independent_reviewer": True,
        "generative_model_used": False,
        "row_count": len(results),
        "advisory_ranking_count": len(passed),
        "held_for_debug_count": len(held),
        "recommendation_counts": dict(sorted(counts.items())),
        "rows": final_rows,
        "score_threshold_applied": False,
        "qualification_threshold": None,
        "scores_are_advisory_not_qualification": True,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    _write_exclusive(output_root / output_name, _pretty_json(artifact))
    _write_exclusive(
        output_root / "OUTCOME.txt",
        b"PHASE 2A CROSS-SUBJECT ADVISORY COMPLETE - OWNER DECISIONS REQUIRED; NO PHASE 2B\n",
    )
    files = sorted(
        path for path in output_root.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in files).encode(),
    )
    return {
        "output_root": str(output_root),
        "artifact_content_sha256": artifact["artifact_content_sha256"],
        "row_count": len(results),
        "advisory_ranking_count": len(passed),
        "held_for_debug_count": len(held),
        "recommendation_counts": artifact["recommendation_counts"],
        "model_independent_reviewer": True,
        "owner_decisions_applied": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--model-path", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    scorer, identity = _real_scorer(args.model_path.resolve(strict=True))
    result = run_cross_subject_review(
        source_path=args.source.resolve(strict=True),
        cases_path=args.cases.resolve(strict=True),
        output_root=args.output_root.resolve(),
        scorer=scorer,
        runtime_identity=identity,
        started_at=datetime.now(UTC),
        resume=bool(args.resume),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
