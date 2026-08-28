#!/usr/bin/env python3
"""Remap 516 held effects against baseline plus cross-subject evidence rows."""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.build_v111_phase2a_effect_relevance_packets import (  # noqa: E402
    EXPECTED_HELD_EFFECT_COUNT,
    _fact_record,
    _load_object,
    _most_specific_provision_facts,
    _pretty_json,
    _sealed,
    _sha256,
    _validate_effects,
    _validate_research,
    _write_exclusive,
)

EXPECTED_RECOVERY_DIGEST = (
    "a79b09a0a19b1f674ec6b600f98cfb9b3decbcc22907ca9356b804c3e47c5559"
)
EXPECTED_RECOVERY_ROWS = 37
OUTPUT_NAME = "LEGISLATIVE-EFFECT-RELEVANCE-WITH-RECOVERY-516.json"
PROGRESS_NAME = "PHASE2A-EFFECT-RECOVERY-PROGRESS.json"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _validate_recovery(
    value: dict[str, Any],
) -> tuple[str, dict[str, list[dict[str, Any]]]]:
    material = dict(value)
    digest = str(material.pop("artifact_content_sha256", ""))
    rows = value.get("rows")
    if (
        digest != EXPECTED_RECOVERY_DIGEST
        or digest != _sealed(material)
        or value.get("schema") != "legalbot.v111.phase2a.cross-subject-recovery-37.v1"
        or value.get("row_count") != EXPECTED_RECOVERY_ROWS
        or not isinstance(rows, list)
        or len(rows) != EXPECTED_RECOVERY_ROWS
        or value.get("source_admission_authorized") is not False
        or value.get("candidate_mutated") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_effect_recovery_source_boundary_invalid")
    by_authority: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_rows: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("phase2a_effect_recovery_row_invalid")
        row_material = dict(row)
        row_seal = str(row_material.pop("row_packet_content_sha256", ""))
        row_id = str(row.get("row_id") or "")
        candidates = row.get("candidates")
        if (
            not row_id
            or row_id in seen_rows
            or row_seal != _sealed(row_material)
            or row.get("technical_qualification_assigned") is not False
            or not isinstance(candidates, list)
            or len(candidates) != row.get("candidate_count")
        ):
            raise ValueError("phase2a_effect_recovery_row_boundary_invalid")
        seen_rows.add(row_id)
        for candidate in candidates:
            if not isinstance(candidate, dict):
                raise ValueError("phase2a_effect_recovery_candidate_invalid")
            candidate_material = dict(candidate)
            candidate_seal = str(
                candidate_material.pop("candidate_record_content_sha256", "")
            )
            authority = str(candidate.get("authority_identity_id") or "")
            if (
                not authority
                or candidate_seal != _sealed(candidate_material)
                or candidate.get("advisory_only_not_qualified") is not True
                or candidate.get("source_family") == "case"
                or candidate.get("identity_verified") is not True
                or candidate.get("currentness_verified") is not True
                or candidate.get("later_treatment_review_required") is not False
            ):
                raise ValueError("phase2a_effect_recovery_candidate_boundary_invalid")
            by_authority[authority].append(
                {
                    "row_id": row_id,
                    "case_id": row.get("case_id"),
                    "issue_id": row.get("issue_id"),
                    "issue_label": row.get("issue_label"),
                    "rank": candidate.get("rank"),
                    "locator": candidate.get("locator"),
                    "candidate_record_content_sha256": candidate_seal,
                    "mapping_source": "CROSS_SUBJECT_CURRENT_NONCASE_RECOVERY_37",
                }
            )
    return digest, dict(by_authority)


def _packet(
    effect: dict[str, Any], candidates: list[dict[str, Any]]
) -> dict[str, Any]:
    affected = _most_specific_provision_facts(effect.get("affected_provisions"))
    identities = {fact.identity for fact in affected}
    exact = []
    for candidate in candidates:
        locator_facts = _most_specific_provision_facts(candidate.get("locator"))
        intersection = sorted(identities.intersection(fact.identity for fact in locator_facts))
        if intersection:
            exact.append(
                {
                    **candidate,
                    "locator_provision_facts": [
                        _fact_record(fact) for fact in locator_facts
                    ],
                    "exact_intersections": [
                        {"kind": kind, "normalized_value": value}
                        for kind, value in intersection
                    ],
                }
            )
    same_rows = sorted({str(candidate["row_id"]) for candidate in candidates})
    recovered = [
        candidate
        for candidate in candidates
        if candidate.get("mapping_source")
        == "CROSS_SUBJECT_CURRENT_NONCASE_RECOVERY_37"
    ]
    if not candidates:
        status = "NO_SAME_AUTHORITY_CANDIDATE_IN_COMBINED_SCOPE"
        recommendation = "RECOMMEND_NONMATERIAL_TO_COMBINED_EVIDENCE_SCOPE"
    elif exact:
        status = "EXACT_AFFECTED_PROVISION_INTERSECTION_FOUND"
        recommendation = (
            "RECOMMEND_PROPOSITION_LEVEL_OWNER_REVIEW_OF_EXACT_PROVISION_INTERSECTIONS"
        )
    else:
        status = "SAME_AUTHORITY_ONLY_NO_EXACT_AFFECTED_PROVISION_INTERSECTION"
        recommendation = (
            "RECOMMEND_METADATA_ONLY_PENDING_FINAL_PROPOSITION_BINDING_CONFIRMATION"
        )
    material = {
        "schema": "legalbot.v111.phase2a.effect-relevance-with-recovery-row.v1",
        "ordinal": effect.get("ordinal"),
        "effect_id": effect.get("effect_id"),
        "effect_record_key": (
            f"{effect.get('source_version_id')}:{effect.get('source_effect_ordinal')}:"
            f"{effect.get('record_sha256')}"
        ),
        "source_version_id": effect.get("source_version_id"),
        "source_effect_ordinal": effect.get("source_effect_ordinal"),
        "source_record_sha256": effect.get("record_sha256"),
        "source_owner_decision_sha256": effect["owner_review"].get(
            "owner_decision_sha256"
        ),
        "source_title": effect.get("source_title"),
        "authority_identity": effect.get("authority_identity"),
        "official_source_url": effect.get("official_source_url"),
        "official_source_version_sha256": effect.get(
            "official_source_version_sha256"
        ),
        "effect_type": effect.get("type"),
        "affected_provisions": effect.get("affected_provisions"),
        "affecting_provisions": effect.get("affecting_provisions"),
        "affected_provision_facts_used_for_exact_comparison": [
            _fact_record(fact) for fact in affected
        ],
        "same_authority_candidate_row_count": len(same_rows),
        "same_authority_candidate_row_ids": same_rows,
        "cross_subject_recovery_candidate_count": len(recovered),
        "exact_provision_intersection_candidate_count": len(exact),
        "exact_provision_intersection_candidates": exact,
        "mapping_status": status,
        "advisory_recommendation": recommendation,
        "scope_limit": (
            "This mapping covers the immutable unresolved 502 packets plus the "
            "37-row current non-case cross-subject recovery. It is not final until "
            "the owner adopts proposition bindings."
        ),
        "owner_decision_required": True,
        "owner_decision_recorded": False,
        "technical_qualification_assigned": False,
        "source_admitted": False,
        "indexed": False,
        "embedded": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    return {**material, "packet_content_sha256": _sealed(material)}


def build_effect_relevance_with_recovery(
    *,
    effects_path: Path,
    baseline_research_path: Path,
    recovery_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_effect_recovery_output_already_exists")
    effects_digest, effects = _validate_effects(_load_object(effects_path))
    baseline_digest, baseline = _validate_research(_load_object(baseline_research_path))
    recovery_digest, recovery = _validate_recovery(_load_object(recovery_path))
    combined: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for authority, candidates in baseline.items():
        combined[authority].extend(
            {**candidate, "mapping_source": "UNRESOLVED_502_BASELINE"}
            for candidate in candidates
        )
    for authority, candidates in recovery.items():
        combined[authority].extend(candidates)
    packets = [
        _packet(effect, combined.get(str(effect.get("authority_identity") or ""), []))
        for effect in effects
    ]
    if len(packets) != EXPECTED_HELD_EFFECT_COUNT:
        raise ValueError("phase2a_effect_recovery_count_invalid")
    no_authority = sum(
        packet["mapping_status"] == "NO_SAME_AUTHORITY_CANDIDATE_IN_COMBINED_SCOPE"
        for packet in packets
    )
    exact = sum(
        packet["mapping_status"] == "EXACT_AFFECTED_PROVISION_INTERSECTION_FOUND"
        for packet in packets
    )
    authority_only = len(packets) - no_authority - exact
    affected_by_recovery = sum(
        int(packet["cross_subject_recovery_candidate_count"]) > 0 for packet in packets
    )
    summary = {
        "no_same_authority_candidate": no_authority,
        "same_authority_without_exact_provision_intersection": authority_only,
        "exact_provision_intersection": exact,
        "effects_with_cross_subject_recovery_candidates": affected_by_recovery,
        "owner_decision_required": len(packets),
        "owner_decision_recorded": 0,
    }
    material = {
        "schema": "legalbot.v111.phase2a.effect-relevance-with-recovery.v1",
        "status": "OWNER_REVIEW_REQUIRED_EFFECT_DISPOSITIONS_NOT_FINAL",
        "source_effects_artifact_content_sha256": effects_digest,
        "source_baseline_research_content_sha256": baseline_digest,
        "source_cross_subject_recovery_content_sha256": recovery_digest,
        "mapping_scope": "UNRESOLVED_502_PLUS_CURRENT_NONCASE_RECOVERY_37",
        "effect_count": len(packets),
        "summary": summary,
        "effects": packets,
        "automatic_materiality_decision": False,
        "automatic_source_admission": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "common_cutoff_supportable": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    raw = _pretty_json(artifact)
    progress_material = {
        "schema": "legalbot.v111.phase2a.effect-relevance-with-recovery-progress.v1",
        "status": "PHASE2A_REMEDIATION_CONTINUES_OWNER_EFFECT_DECISIONS_REQUIRED",
        "effect_relevance_artifact_content_sha256": artifact[
            "artifact_content_sha256"
        ],
        "effect_relevance_artifact_file_sha256": _sha256(raw),
        "summary": summary,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    progress = {
        **progress_material,
        "progress_content_sha256": _sealed(progress_material),
    }
    progress_raw = _pretty_json(progress)
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_effect_recovery_output_mode_invalid")
    _write_exclusive(output_root / OUTPUT_NAME, raw)
    _write_exclusive(output_root / PROGRESS_NAME, progress_raw)
    _write_exclusive(
        output_root / "SHA256SUMS",
        (
            f"{_sha256(raw)}  {OUTPUT_NAME}\n"
            f"{_sha256(progress_raw)}  {PROGRESS_NAME}\n"
        ).encode(),
    )
    return progress


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--effects", type=Path, required=True)
    parser.add_argument("--baseline-research", type=Path, required=True)
    parser.add_argument("--recovery", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    result = build_effect_relevance_with_recovery(
        effects_path=args.effects.resolve(strict=True),
        baseline_research_path=args.baseline_research.resolve(strict=True),
        recovery_path=args.recovery.resolve(strict=True),
        output_root=args.output_root.resolve(),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
