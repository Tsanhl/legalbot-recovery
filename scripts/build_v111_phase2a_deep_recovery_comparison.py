#!/usr/bin/env python3
"""Compare original and all-subject Phase-2A advisory rankings.

The comparison reports ranking movement only.  Scores are never converted into
qualification, source admission, materiality, or an owner decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ORIGINAL = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r36-independent-advisory/INDEPENDENT-RERANKER-ADVISORY-448.json"
)
DEFAULT_DEEP_SOURCE = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r40-deep-recovery/DEEP-CURRENT-OFFICIAL-CANDIDATES-176.json"
)
DEFAULT_DEEP_RANKING = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r41-deep-recovery-advisory/INDEPENDENT-RERANKER-DEEP-RECOVERY-176.json"
)
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review/LegalBot-Phase2AB-2026-08-24-r43-deep-comparison"
)
EXPECTED_ORIGINAL_DIGEST = (
    "3f7ad672f0e35068919ca1d27483d5aa1e885ba1533800402b718cfafd6d670f"
)
EXPECTED_DEEP_SOURCE_DIGEST = (
    "692cdafd0e10f8b864a96cc35165cb20441dc099b52a2f2cad90b38befcbbbf1"
)
EXPECTED_DEEP_RANKING_DIGEST = (
    "74e4b7c0cdda942d7da20db5360150a5e3b3fbcfa2030ca9930db7199175e680"
)
EXPECTED_ROW_COUNT = 176
DIAGNOSTIC_TRIAGE_FLOOR = 0.5


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_deep_comparison_input_not_object")
    return value


def _verify_seal(
    value: Mapping[str, Any],
    *,
    field: str,
    expected: str,
) -> str:
    claimed = value.get(field)
    if not isinstance(claimed, str) or len(claimed) != 64:
        raise ValueError("phase2a_deep_comparison_source_seal_missing")
    material = dict(value)
    material.pop(field, None)
    actual = _sha256(_canonical_json(material))
    if claimed != actual or claimed != expected:
        raise ValueError("phase2a_deep_comparison_source_seal_invalid")
    return claimed


def _top(row: Mapping[str, Any]) -> Mapping[str, Any]:
    candidates = row.get("ranked_candidates")
    if not isinstance(candidates, list) or not candidates or not isinstance(candidates[0], Mapping):
        raise ValueError("phase2a_deep_comparison_top_candidate_missing")
    return candidates[0]


def _candidate_summary(candidate: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "authority_identity_id": candidate.get("authority_identity_id"),
        "source_version_id": candidate.get("source_version_id"),
        "canonical_citation": candidate.get("canonical_citation"),
        "title": candidate.get("title"),
        "locator": candidate.get("locator"),
        "span_bundle_sha256": candidate.get("span_bundle_sha256"),
        "full_span_text_sha256": candidate.get("full_span_text_sha256"),
        "reranker_score": candidate.get("reranker_score"),
        "identity_verified": candidate.get("identity_verified"),
        "currentness_verified": candidate.get("currentness_verified"),
        "later_treatment_review_required": candidate.get(
            "later_treatment_review_required"
        ),
        "already_in_sealed_candidate": candidate.get("already_in_sealed_candidate"),
    }


def _score(candidate: Mapping[str, Any]) -> float:
    score = candidate.get("reranker_score")
    if not isinstance(score, int | float) or not 0 <= float(score) <= 1:
        raise ValueError("phase2a_deep_comparison_score_invalid")
    return float(score)


def _review_track(original: Mapping[str, Any], deep: Mapping[str, Any]) -> str:
    original_score = _score(original)
    deep_score = _score(deep)
    if original.get("later_treatment_review_required") is True:
        return "INSPECT_CASE_AFTER_LATER_TREATMENT_AND_DEEP_CURRENT_NONCASE"
    if (
        deep.get("authority_identity_id") != original.get("authority_identity_id")
        and deep_score >= original_score + 0.05
    ):
        return "INSPECT_DEEP_CURRENT_NONCASE_FIRST"
    return "INSPECT_ORIGINAL_AND_DEEP_CANDIDATES_TOGETHER"


def build_comparison(
    *,
    original_path: Path,
    deep_source_path: Path,
    deep_ranking_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    original = _load(original_path)
    deep_source = _load(deep_source_path)
    deep_ranking = _load(deep_ranking_path)
    original_digest = _verify_seal(
        original,
        field="artifact_content_sha256",
        expected=EXPECTED_ORIGINAL_DIGEST,
    )
    deep_source_digest = _verify_seal(
        deep_source,
        field="artifact_content_sha256",
        expected=EXPECTED_DEEP_SOURCE_DIGEST,
    )
    deep_ranking_digest = _verify_seal(
        deep_ranking,
        field="artifact_content_sha256",
        expected=EXPECTED_DEEP_RANKING_DIGEST,
    )
    original_rows = original.get("rows")
    deep_source_rows = deep_source.get("rows")
    deep_rows = deep_ranking.get("rows")
    if (
        original.get("schema")
        != "legalbot.phase2a.independent-reranker-advisory-448.v1"
        or original.get("row_count") != 448
        or original.get("held_for_debug_count") != 0
        or deep_source.get("schema")
        != "legalbot.v111.phase2a.deep-current-source-recovery-176.v1"
        or deep_source.get("row_count") != EXPECTED_ROW_COUNT
        or deep_ranking.get("schema")
        != "legalbot.phase2a.independent-reranker-deep-recovery-176.v1"
        or deep_ranking.get("row_count") != EXPECTED_ROW_COUNT
        or deep_ranking.get("held_for_debug_count") != 0
        or not isinstance(original_rows, list)
        or not isinstance(deep_source_rows, list)
        or not isinstance(deep_rows, list)
        or len(deep_source_rows) != EXPECTED_ROW_COUNT
        or len(deep_rows) != EXPECTED_ROW_COUNT
        or original.get("runtime_identity_sha256")
        != deep_ranking.get("runtime_identity_sha256")
    ):
        raise ValueError("phase2a_deep_comparison_source_boundary_invalid")
    original_by_id = {
        str(row["row_id"]): row
        for row in original_rows
        if isinstance(row, Mapping) and row.get("status") != "HELD_FOR_DEBUG"
    }
    source_by_id = {
        str(row["row_id"]): row for row in deep_source_rows if isinstance(row, Mapping)
    }
    deep_by_id = {
        str(row["row_id"]): row for row in deep_rows if isinstance(row, Mapping)
    }
    if set(source_by_id) != set(deep_by_id) or len(deep_by_id) != EXPECTED_ROW_COUNT:
        raise ValueError("phase2a_deep_comparison_row_set_mismatch")

    rows: list[dict[str, Any]] = []
    tracks: Counter[str] = Counter()
    score_movements: Counter[str] = Counter()
    for ordinal, source_row in enumerate(deep_source_rows, start=1):
        row_id = str(source_row["row_id"])
        original_row = original_by_id.get(row_id)
        deep_row = deep_by_id[row_id]
        if original_row is None:
            raise ValueError("phase2a_deep_comparison_original_row_missing")
        original_top = _top(original_row)
        deep_top = _top(deep_row)
        original_score = _score(original_top)
        deep_score = _score(deep_top)
        delta = round(deep_score - original_score, 8)
        movement = "HIGHER" if delta > 0 else "LOWER" if delta < 0 else "UNCHANGED"
        track = _review_track(original_top, deep_top)
        tracks[track] += 1
        score_movements[movement] += 1
        row_material = {
            "schema": "legalbot.v111.phase2a.deep-ranking-comparison-row.v1",
            "ordinal": ordinal,
            "row_id": row_id,
            "case_id": source_row.get("case_id"),
            "issue_id": source_row.get("issue_id"),
            "issue_label": source_row.get("issue_label"),
            "legal_domain": source_row.get("legal_domain"),
            "original_allowed_catalogue_subjects": source_row.get(
                "original_allowed_catalogue_subjects"
            ),
            "original_top": _candidate_summary(original_top),
            "deep_top": _candidate_summary(deep_top),
            "top_score_delta": delta,
            "top_score_movement": movement,
            "authority_identity_changed": original_top.get("authority_identity_id")
            != deep_top.get("authority_identity_id"),
            "source_version_changed": original_top.get("source_version_id")
            != deep_top.get("source_version_id"),
            "span_changed": original_top.get("span_bundle_sha256")
            != deep_top.get("span_bundle_sha256"),
            "original_below_diagnostic_triage_floor": original_score
            < DIAGNOSTIC_TRIAGE_FLOOR,
            "deep_below_diagnostic_triage_floor": deep_score
            < DIAGNOSTIC_TRIAGE_FLOOR,
            "advisory_review_track": track,
            "scores_are_advisory_not_qualification": True,
            "owner_decision_required": True,
            "technical_qualification_assigned": False,
            "source_admitted": False,
            "candidate_mutated": False,
        }
        rows.append(
            {
                **row_material,
                "row_content_sha256": _sha256(_canonical_json(row_material)),
            }
        )

    metrics = {
        "row_count": len(rows),
        "score_movement_counts": dict(sorted(score_movements.items())),
        "authority_identity_changed_count": sum(
            row["authority_identity_changed"] for row in rows
        ),
        "source_version_changed_count": sum(row["source_version_changed"] for row in rows),
        "span_changed_count": sum(row["span_changed"] for row in rows),
        "original_below_diagnostic_triage_floor_count": sum(
            row["original_below_diagnostic_triage_floor"] for row in rows
        ),
        "deep_below_diagnostic_triage_floor_count": sum(
            row["deep_below_diagnostic_triage_floor"] for row in rows
        ),
        "review_track_counts": dict(sorted(tracks.items())),
    }
    material = {
        "schema": "legalbot.v111.phase2a.deep-ranking-comparison-176.v1",
        "status": "ADVISORY_COMPARISON_COMPLETE_OWNER_DECISIONS_REQUIRED",
        "source_original_artifact_content_sha256": original_digest,
        "source_deep_candidate_artifact_content_sha256": deep_source_digest,
        "source_deep_ranking_artifact_content_sha256": deep_ranking_digest,
        "runtime_identity_sha256": original["runtime_identity_sha256"],
        "diagnostic_triage_floor": DIAGNOSTIC_TRIAGE_FLOOR,
        "diagnostic_triage_floor_is_not_release_threshold": True,
        "score_comparison_is_not_legal_quality_decision": True,
        "metrics": metrics,
        "rows": rows,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {
        **material,
        "artifact_content_sha256": _sha256(_canonical_json(material)),
    }
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_deep_comparison_output_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_deep_comparison_output_mode_invalid")
    artifact_path = output_root / "DEEP-RANKING-COMPARISON-176.json"
    artifact_path.write_bytes(_pretty_json(artifact))
    os.chmod(artifact_path, 0o600)
    outcome_path = output_root / "OUTCOME.txt"
    outcome_path.write_text(
        "PHASE 2A DEEP RANKING COMPARISON COMPLETE - OWNER DECISIONS REQUIRED; NO PHASE 2B\n"
    )
    os.chmod(outcome_path, 0o600)
    checksum_path = output_root / "SHA256SUMS.txt"
    checksum_path.write_text(
        "".join(
            f"{_sha256_file(path)}  {path.name}\n"
            for path in sorted((artifact_path, outcome_path))
        )
    )
    os.chmod(checksum_path, 0o600)
    return {
        "output_root": str(output_root),
        "artifact_content_sha256": artifact["artifact_content_sha256"],
        "metrics": metrics,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", type=Path, default=DEFAULT_ORIGINAL)
    parser.add_argument("--deep-source", type=Path, default=DEFAULT_DEEP_SOURCE)
    parser.add_argument("--deep-ranking", type=Path, default=DEFAULT_DEEP_RANKING)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    result = build_comparison(
        original_path=args.original.resolve(strict=True),
        deep_source_path=args.deep_source.resolve(strict=True),
        deep_ranking_path=args.deep_ranking.resolve(strict=True),
        output_root=args.output_root.resolve(),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
