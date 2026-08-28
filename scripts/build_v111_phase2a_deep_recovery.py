#!/usr/bin/env python3
"""Build a deeper current-source retrieval set for 176 Phase-2A rows.

Rows enter this advisory pass when the independent reranker's best original
candidate scored below 0.5, or when the immutable baseline classified the row
as a material candidate-coverage gap.  The 0.5 value is a diagnostic triage
floor only: it is not a release threshold and cannot qualify evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.evaluation.phase2a_research_packets import (  # noqa: E402
    _candidate_manifest_authorities,
    _load_cases,
    _load_spans,
    _open_catalogue,
    _select_sources,
    sealed_sha256,
)
from scripts.build_v111_phase2a_cross_subject_recovery import (  # noqa: E402
    EXPECTED_CANDIDATE_MANIFEST_DIGEST,
    EXPECTED_CASES_FILE_SHA256,
    EXPECTED_CATALOGUE_FILE_SHA256,
    EXPECTED_REMAINDER_DIGEST,
    EXPECTED_REMAINDER_ROWS,
    _load_object,
    _rank_rows,
    _sha256_file,
    _verify_seal,
    _write_exclusive,
)

EXPECTED_ADVISORY_DIGEST = (
    "3f7ad672f0e35068919ca1d27483d5aa1e885ba1533800402b718cfafd6d670f"
)
EXPECTED_BASELINE_DIGEST = (
    "f535fa63a27b86d1c34ef3e3107fc9a0153ddcb1db3a58d51babacbc20704b33"
)
EXPECTED_TARGET_ROWS = 176
DIAGNOSTIC_TRIAGE_FLOOR = 0.5
DEFAULT_LIMIT = 12
OUTPUT_NAME = "DEEP-CURRENT-OFFICIAL-CANDIDATES-176.json"


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def select_deep_recovery_rows(
    *,
    remainder: Mapping[str, Any],
    advisory: Mapping[str, Any],
    baseline: Mapping[str, Any],
) -> list[dict[str, Any]]:
    remainder_rows = remainder.get("rows")
    advisory_rows = advisory.get("rows")
    baseline_rows = baseline.get("rows")
    if (
        not isinstance(remainder_rows, list)
        or len(remainder_rows) != EXPECTED_REMAINDER_ROWS
        or not isinstance(advisory_rows, list)
        or len(advisory_rows) != EXPECTED_REMAINDER_ROWS
        or not isinstance(baseline_rows, list)
        or len(baseline_rows) != 585
    ):
        raise ValueError("phase2a_deep_recovery_row_inventory_invalid")

    advisory_by_id: dict[str, Mapping[str, Any]] = {}
    for row in advisory_rows:
        if not isinstance(row, dict):
            raise ValueError("phase2a_deep_recovery_advisory_row_invalid")
        ranked = row.get("ranked_candidates")
        row_id = str(row.get("row_id") or "")
        if not row_id or row_id in advisory_by_id or not isinstance(ranked, list) or not ranked:
            raise ValueError("phase2a_deep_recovery_advisory_boundary_invalid")
        score = ranked[0].get("reranker_score")
        if isinstance(score, bool) or not isinstance(score, int | float) or not 0 <= score <= 1:
            raise ValueError("phase2a_deep_recovery_advisory_score_invalid")
        advisory_by_id[row_id] = row

    baseline_by_id: dict[str, Mapping[str, Any]] = {}
    for row in baseline_rows:
        if not isinstance(row, dict):
            raise ValueError("phase2a_deep_recovery_baseline_row_invalid")
        row_id = str(row.get("row_id") or "")
        if not row_id or row_id in baseline_by_id:
            raise ValueError("phase2a_deep_recovery_baseline_boundary_invalid")
        baseline_by_id[row_id] = row

    selected: list[dict[str, Any]] = []
    for row in remainder_rows:
        if not isinstance(row, dict):
            raise ValueError("phase2a_deep_recovery_remainder_row_invalid")
        material = dict(row)
        supplied = str(material.pop("row_packet_content_sha256", ""))
        if supplied != sealed_sha256(material):
            raise ValueError("phase2a_deep_recovery_remainder_row_seal_invalid")
        row_id = str(row.get("row_id") or "")
        ranked = advisory_by_id.get(row_id)
        original = baseline_by_id.get(row_id)
        if ranked is None or original is None:
            raise ValueError("phase2a_deep_recovery_row_join_invalid")
        score = float(ranked["ranked_candidates"][0]["reranker_score"])
        baseline_gap = original.get("baseline_primary_status") == (
            "MATERIAL_CANDIDATE_COVERAGE_GAP"
        )
        if score < DIAGNOSTIC_TRIAGE_FLOOR or baseline_gap:
            selected.append(row)
    if len(selected) != EXPECTED_TARGET_ROWS:
        raise ValueError("phase2a_deep_recovery_target_fingerprint_changed")
    return selected


def build_deep_recovery(
    *,
    remainder_path: Path,
    advisory_path: Path,
    baseline_path: Path,
    cases_path: Path,
    candidate_manifest_path: Path,
    catalogue_path: Path,
    target_date: date,
    output_root: Path,
    candidate_limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_deep_recovery_output_already_exists")
    if not 1 <= candidate_limit <= 20:
        raise ValueError("phase2a_deep_recovery_candidate_limit_invalid")

    remainder = _load_object(remainder_path)
    remainder_digest = _verify_seal(
        remainder,
        "artifact_content_sha256",
        "phase2a_deep_recovery_remainder_seal_invalid",
    )
    advisory = _load_object(advisory_path)
    advisory_digest = _verify_seal(
        advisory,
        "artifact_content_sha256",
        "phase2a_deep_recovery_advisory_seal_invalid",
    )
    baseline = _load_object(baseline_path)
    baseline_digest = _verify_seal(
        baseline,
        "artifact_content_sha256",
        "phase2a_deep_recovery_baseline_seal_invalid",
    )
    if (
        remainder_digest != EXPECTED_REMAINDER_DIGEST
        or advisory_digest != EXPECTED_ADVISORY_DIGEST
        or baseline_digest != EXPECTED_BASELINE_DIGEST
        or advisory.get("schema")
        != "legalbot.phase2a.independent-reranker-advisory-448.v1"
        or advisory.get("held_for_debug_count") != 0
        or advisory.get("score_threshold_applied") is not False
        or baseline.get("schema") != "legalbot.v111.phase2a.owner-reviewed-issues.v1"
    ):
        raise ValueError("phase2a_deep_recovery_input_identity_invalid")
    if _sha256_file(cases_path) != EXPECTED_CASES_FILE_SHA256:
        raise ValueError("phase2a_deep_recovery_cases_identity_invalid")
    if _sha256_file(catalogue_path) != EXPECTED_CATALOGUE_FILE_SHA256:
        raise ValueError("phase2a_deep_recovery_catalogue_identity_invalid")
    rows = select_deep_recovery_rows(
        remainder=remainder,
        advisory=advisory,
        baseline=baseline,
    )
    cases = _load_cases(cases_path)
    manifest_digest, candidate_authorities, candidate_versions = (
        _candidate_manifest_authorities(candidate_manifest_path)
    )
    if manifest_digest != EXPECTED_CANDIDATE_MANIFEST_DIGEST:
        raise ValueError("phase2a_deep_recovery_candidate_manifest_identity_invalid")
    with _open_catalogue(catalogue_path) as connection:
        sources = _select_sources(connection, target_date)
        spans = _load_spans(connection, sources)
    packets, metrics = _rank_rows(
        rows=rows,
        cases=cases,
        spans=spans,
        candidate_authorities=candidate_authorities,
        candidate_versions=candidate_versions,
        limit=candidate_limit,
    )
    material = {
        "schema": "legalbot.v111.phase2a.deep-current-source-recovery-176.v1",
        "status": "ADVISORY_DEEP_RECOVERY_COMPLETE_OWNER_REVIEW_REQUIRED",
        "target_date": target_date.isoformat(),
        "row_count": len(packets),
        "candidate_limit_per_row": candidate_limit,
        "diagnostic_triage_floor": DIAGNOSTIC_TRIAGE_FLOOR,
        "diagnostic_triage_floor_is_not_release_threshold": True,
        "selection_rule": (
            "independent_top_score_below_diagnostic_floor_or_baseline_material_gap"
        ),
        "source_remainder_content_sha256": remainder_digest,
        "source_advisory_content_sha256": advisory_digest,
        "source_baseline_content_sha256": baseline_digest,
        "source_cases_file_sha256": EXPECTED_CASES_FILE_SHA256,
        "source_candidate_manifest_sha256": manifest_digest,
        "source_catalogue_file_sha256": EXPECTED_CATALOGUE_FILE_SHA256,
        "source_authority_count": len(sources),
        "source_span_group_count": len(spans),
        "catalogue_opened_immutable_read_only": True,
        "subject_filter_disabled_for_recovery": True,
        "only_identity_and_currentness_verified_noncase_sources_considered": True,
        "rank_metrics": metrics,
        "rows": packets,
        "embedding_model_invoked": False,
        "answer_model_invoked": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": sealed_sha256(material)}
    raw = _pretty_json(artifact)
    progress_material = {
        "schema": "legalbot.v111.phase2a.deep-recovery-progress.v1",
        "status": "PHASE2A_DEEP_RECOVERY_READY_FOR_INDEPENDENT_RERANKING",
        "artifact_content_sha256": artifact["artifact_content_sha256"],
        "artifact_file_sha256": hashlib.sha256(raw).hexdigest(),
        "summary": metrics,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    progress = {
        **progress_material,
        "progress_content_sha256": sealed_sha256(progress_material),
    }
    progress_raw = _pretty_json(progress)
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_deep_recovery_output_mode_invalid")
    _write_exclusive(output_root / OUTPUT_NAME, raw)
    _write_exclusive(output_root / "PHASE2A-DEEP-RECOVERY-PROGRESS.json", progress_raw)
    _write_exclusive(
        output_root / "SHA256SUMS",
        (
            f"{hashlib.sha256(raw).hexdigest()}  {OUTPUT_NAME}\n"
            f"{hashlib.sha256(progress_raw).hexdigest()}  PHASE2A-DEEP-RECOVERY-PROGRESS.json\n"
        ).encode(),
    )
    return progress


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--remainder", type=Path, required=True)
    parser.add_argument("--advisory", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--catalogue", type=Path, required=True)
    parser.add_argument("--target-date", type=date.fromisoformat, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--candidate-limit", type=int, default=DEFAULT_LIMIT)
    args = parser.parse_args()
    result = build_deep_recovery(
        remainder_path=args.remainder.resolve(strict=True),
        advisory_path=args.advisory.resolve(strict=True),
        baseline_path=args.baseline.resolve(strict=True),
        cases_path=args.cases.resolve(strict=True),
        candidate_manifest_path=args.candidate_manifest.resolve(strict=True),
        catalogue_path=args.catalogue.resolve(strict=True),
        target_date=args.target_date,
        output_root=args.output_root.resolve(),
        candidate_limit=args.candidate_limit,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
