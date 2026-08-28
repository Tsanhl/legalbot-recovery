#!/usr/bin/env python3
"""Build sealed owner-review packets for the 516 held legislative effects.

This create-only command maps each held effect to the immutable 502-row
lexical research set.  The mapping is advisory evidence for the owner: it does
not decide materiality, qualify an issue, admit a source, index, embed, mutate
a candidate, or authorize Phase 2B or Development 30.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import defaultdict
from pathlib import Path
from typing import Any

from app.quality.evidence import MaterialFact, extract_material_facts

EXPECTED_EFFECTS_DIGEST = "a4e315a333d30c3e02c02c0228696b37b61481c4936ca32cf7d2a205168b34a7"
EXPECTED_RESEARCH_DIGEST = "0718758e3bd9b0f938c4beab09eb3b603ffc5f419d68574399accc47c4a4015c"
EXPECTED_TOTAL_EFFECT_COUNT = 1_896
EXPECTED_HELD_EFFECT_COUNT = 516
EXPECTED_RESEARCH_ROW_COUNT = 502
EXPECTED_NO_AUTHORITY_CANDIDATE_COUNT = 7
EXPECTED_AUTHORITY_ONLY_COUNT = 509
EXPECTED_EXACT_PROVISION_INTERSECTION_COUNT = 0

OUTPUT_NAME = "LEGISLATIVE-EFFECT-RELEVANCE-OWNER-REVIEW-516.json"
PROGRESS_NAME = "PHASE2A-EFFECT-RELEVANCE-PROGRESS.json"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SPECIFIC_PROVISION_PREFIXES = (
    "section:",
    "subsection:",
    "regulation:",
    "article:",
    "paragraph:",
    "rule:",
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_effect_relevance_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_effect_relevance_input_must_be_object")
    return value


def _verify_seal(value: dict[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _fact_record(fact: MaterialFact) -> dict[str, str]:
    return {
        "kind": fact.kind,
        "normalized_value": fact.normalized_value,
        "matched_text": fact.matched_text,
    }


def _most_specific_provision_facts(text: str | None) -> tuple[MaterialFact, ...]:
    """Return exact provision facts without allowing a schedule to launder a section.

    A schedule identifier remains usable when it is the only provision identifier.
    If a section, subsection, regulation, article, paragraph or rule is present,
    broad schedule identifiers are excluded from comparison.
    """

    provisions = tuple(
        fact for fact in extract_material_facts(str(text or "")) if fact.kind == "provision"
    )
    specific = tuple(
        fact
        for fact in provisions
        if fact.normalized_value.startswith(_SPECIFIC_PROVISION_PREFIXES)
    )
    return specific or provisions


def _validate_effects(value: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    digest = _verify_seal(
        value,
        "artifact_content_sha256",
        "phase2a_effect_relevance_effects_seal_invalid",
    )
    effects = value.get("effects")
    summary = value.get("summary")
    if (
        digest != EXPECTED_EFFECTS_DIGEST
        or value.get("schema") != "legalbot.v111.phase2a.owner-reviewed-legislative-effects.v1"
        or value.get("record_count") != EXPECTED_TOTAL_EFFECT_COUNT
        or not isinstance(effects, list)
        or len(effects) != EXPECTED_TOTAL_EFFECT_COUNT
        or not isinstance(summary, dict)
        or summary.get("owner_requested_more_evidence") != EXPECTED_HELD_EFFECT_COUNT
        or value.get("automatic_source_admission") is not False
        or value.get("candidate_mutated") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_effect_relevance_effects_boundary_invalid")

    held: list[dict[str, Any]] = []
    seen_effect_records: set[tuple[str, int, str]] = set()
    for effect in effects:
        if not isinstance(effect, dict):
            raise ValueError("phase2a_effect_relevance_effect_record_invalid")
        effect_id = str(effect.get("effect_id") or "")
        record_sha256 = str(effect.get("record_sha256") or "")
        source_version_id = str(effect.get("source_version_id") or "")
        source_effect_ordinal = int(effect.get("source_effect_ordinal") or 0)
        record_identity = (source_version_id, source_effect_ordinal, record_sha256)
        if (
            not effect_id
            or not source_version_id
            or source_effect_ordinal < 1
            or record_identity in seen_effect_records
            or not _SHA256.fullmatch(record_sha256)
        ):
            raise ValueError("phase2a_effect_relevance_effect_identity_invalid")
        seen_effect_records.add(record_identity)
        if effect.get("owner_decision_required") is not True:
            continue
        owner_review = effect.get("owner_review")
        if (
            effect.get("requires_applied") is not False
            or effect.get("blocks_common_cutoff") is not True
            or effect.get("automatically_ingested") is not False
            or effect.get("disposition") != "APPLICABLE_ONLY_TO_METADATA_OR_CURRENTNESS"
            or not isinstance(owner_review, dict)
            or owner_review.get("status") != "OWNER_REQUESTED_MORE_EVIDENCE"
            or owner_review.get("owner_outcome") != "REQUEST_MORE_EVIDENCE"
            or owner_review.get("does_not_admit_index_or_embed_source") is not True
            or owner_review.get("does_not_authorize_phase2b_or_development30") is not True
        ):
            raise ValueError("phase2a_effect_relevance_held_effect_boundary_invalid")
        held.append(effect)
    if len(held) != EXPECTED_HELD_EFFECT_COUNT:
        raise ValueError("phase2a_effect_relevance_held_effect_count_invalid")
    return digest, held


def _validate_research(
    value: dict[str, Any],
) -> tuple[str, dict[str, list[dict[str, Any]]]]:
    digest = _verify_seal(
        value,
        "artifact_content_sha256",
        "phase2a_effect_relevance_research_seal_invalid",
    )
    rows = value.get("rows")
    if (
        digest != EXPECTED_RESEARCH_DIGEST
        or value.get("schema") != "legalbot.v111.phase2a.unresolved-research-packets.v1"
        or value.get("row_count") != EXPECTED_RESEARCH_ROW_COUNT
        or not isinstance(rows, list)
        or len(rows) != EXPECTED_RESEARCH_ROW_COUNT
        or value.get("source_admission_authorized") is not False
        or value.get("candidate_mutated") is not False
        or value.get("embedding_model_invoked") is not False
        or value.get("answer_model_invoked") is not False
        or value.get("persistent_research_index_created") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_effect_relevance_research_boundary_invalid")

    by_authority: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_rows: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("phase2a_effect_relevance_research_row_invalid")
        row_material = dict(row)
        row_seal = str(row_material.pop("row_packet_content_sha256", ""))
        row_id = str(row.get("row_id") or "")
        if (
            not row_id
            or row_id in seen_rows
            or not _SHA256.fullmatch(row_seal)
            or row_seal != _sealed(row_material)
            or row.get("technical_qualification_assigned") is not False
            or row.get("owner_or_qualified_reviewer_decision_required") is not True
        ):
            raise ValueError("phase2a_effect_relevance_research_row_boundary_invalid")
        seen_rows.add(row_id)
        candidates = row.get("candidates")
        if not isinstance(candidates, list) or len(candidates) != row.get("candidate_count"):
            raise ValueError("phase2a_effect_relevance_candidate_collection_invalid")
        for candidate in candidates:
            if not isinstance(candidate, dict):
                raise ValueError("phase2a_effect_relevance_candidate_invalid")
            candidate_material = dict(candidate)
            candidate_seal = str(candidate_material.pop("candidate_record_content_sha256", ""))
            authority = str(candidate.get("authority_identity_id") or "")
            if (
                not authority
                or not _SHA256.fullmatch(candidate_seal)
                or candidate_seal != _sealed(candidate_material)
                or candidate.get("advisory_only_not_qualified") is not True
            ):
                raise ValueError("phase2a_effect_relevance_candidate_boundary_invalid")
            by_authority[authority].append(
                {
                    "row_id": row_id,
                    "case_id": row.get("case_id"),
                    "issue_id": row.get("issue_id"),
                    "issue_label": row.get("issue_label"),
                    "rank": candidate.get("rank"),
                    "locator": candidate.get("locator"),
                    "candidate_record_content_sha256": candidate_seal,
                }
            )
    return digest, dict(by_authority)


def _effect_packet(
    effect: dict[str, Any],
    authority_candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    affected_facts = _most_specific_provision_facts(effect.get("affected_provisions"))
    affected_identities = {fact.identity for fact in affected_facts}
    exact: list[dict[str, Any]] = []
    for candidate in authority_candidates:
        locator_facts = _most_specific_provision_facts(candidate.get("locator"))
        intersection = sorted(
            affected_identities.intersection(fact.identity for fact in locator_facts)
        )
        if intersection:
            exact.append(
                {
                    **candidate,
                    "locator_provision_facts": [_fact_record(fact) for fact in locator_facts],
                    "exact_intersections": [
                        {"kind": kind, "normalized_value": value} for kind, value in intersection
                    ],
                }
            )

    same_authority_rows = sorted({str(candidate["row_id"]) for candidate in authority_candidates})
    if not authority_candidates:
        mapping_status = "NO_SAME_AUTHORITY_CANDIDATE_IN_UNRESOLVED_502_SET"
        recommendation = "RECOMMEND_NONMATERIAL_TO_CURRENT_UNRESOLVED_502_EVIDENCE_SCOPE"
    elif exact:
        mapping_status = "EXACT_AFFECTED_PROVISION_INTERSECTION_FOUND"
        recommendation = "RECOMMEND_PROPOSITION_LEVEL_OWNER_REVIEW_OF_EXACT_PROVISION_INTERSECTIONS"
    else:
        mapping_status = "SAME_AUTHORITY_ONLY_NO_EXACT_AFFECTED_PROVISION_INTERSECTION"
        recommendation = "RECOMMEND_METADATA_ONLY_PENDING_FINAL_PROPOSITION_BINDING_CONFIRMATION"

    material: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.effect-relevance-owner-review-row.v1",
        "ordinal": effect.get("ordinal"),
        "effect_id": effect.get("effect_id"),
        "effect_record_key": (
            f"{effect.get('source_version_id')}:{effect.get('source_effect_ordinal')}:"
            f"{effect.get('record_sha256')}"
        ),
        "source_version_id": effect.get("source_version_id"),
        "source_effect_ordinal": effect.get("source_effect_ordinal"),
        "source_record_sha256": effect.get("record_sha256"),
        "source_owner_decision_sha256": effect["owner_review"].get("owner_decision_sha256"),
        "source_title": effect.get("source_title"),
        "authority_identity": effect.get("authority_identity"),
        "official_source_url": effect.get("official_source_url"),
        "official_source_version_sha256": effect.get("official_source_version_sha256"),
        "effect_type": effect.get("type"),
        "affected_provisions": effect.get("affected_provisions"),
        "affecting_provisions": effect.get("affecting_provisions"),
        "affected_provision_facts_used_for_exact_comparison": [
            _fact_record(fact) for fact in affected_facts
        ],
        "same_authority_candidate_row_count": len(same_authority_rows),
        "same_authority_candidate_row_ids": same_authority_rows,
        "exact_provision_intersection_candidate_count": len(exact),
        "exact_provision_intersection_candidates": exact,
        "mapping_status": mapping_status,
        "advisory_recommendation": recommendation,
        "scope_limit": (
            "This deterministic mapping covers only the immutable unresolved 502-row "
            "lexical research set. Absence of an exact locator intersection is not "
            "proof of legal nonmateriality while final proposition bindings remain "
            "incomplete."
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


def build_effect_relevance_packets(
    *,
    effects_path: Path,
    research_packets_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Create immutable evidence packets for the 516 unresolved effects."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_effect_relevance_output_already_exists")

    effects_source = _load_object(effects_path)
    research_source = _load_object(research_packets_path)
    effects_digest, held_effects = _validate_effects(effects_source)
    research_digest, candidates_by_authority = _validate_research(research_source)

    packets = [
        _effect_packet(
            effect,
            candidates_by_authority.get(str(effect.get("authority_identity") or ""), []),
        )
        for effect in held_effects
    ]
    no_authority = sum(
        packet["mapping_status"] == "NO_SAME_AUTHORITY_CANDIDATE_IN_UNRESOLVED_502_SET"
        for packet in packets
    )
    exact = sum(
        packet["mapping_status"] == "EXACT_AFFECTED_PROVISION_INTERSECTION_FOUND"
        for packet in packets
    )
    authority_only = len(packets) - no_authority - exact
    if (
        no_authority != EXPECTED_NO_AUTHORITY_CANDIDATE_COUNT
        or authority_only != EXPECTED_AUTHORITY_ONLY_COUNT
        or exact != EXPECTED_EXACT_PROVISION_INTERSECTION_COUNT
    ):
        raise ValueError("phase2a_effect_relevance_mapping_fingerprint_changed")

    material: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.effect-relevance-owner-review.v1",
        "status": "OWNER_REVIEW_REQUIRED_EFFECT_DISPOSITIONS_NOT_FINAL",
        "source_effects_artifact_content_sha256": effects_digest,
        "source_research_packets_content_sha256": research_digest,
        "mapping_scope": "IMMUTABLE_UNRESOLVED_502_LEXICAL_RESEARCH_SET_ONLY",
        "effect_count": len(packets),
        "summary": {
            "no_same_authority_candidate": no_authority,
            "same_authority_without_exact_provision_intersection": authority_only,
            "exact_provision_intersection": exact,
            "owner_decision_required": len(packets),
            "owner_decision_recorded": 0,
        },
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
    artifact_raw = _pretty_json(artifact)

    progress_material: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.effect-relevance-progress.v1",
        "status": "PHASE2A_REMEDIATION_CONTINUES_OWNER_EFFECT_DECISIONS_REQUIRED",
        "effect_relevance_artifact_content_sha256": artifact["artifact_content_sha256"],
        "effect_relevance_artifact_file_sha256": _sha256(artifact_raw),
        "effect_count": len(packets),
        "summary": material["summary"],
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
        raise ValueError("phase2a_effect_relevance_output_mode_invalid")
    _write_exclusive(output_root / OUTPUT_NAME, artifact_raw)
    _write_exclusive(output_root / PROGRESS_NAME, progress_raw)
    sums = (
        f"{_sha256(artifact_raw)}  {OUTPUT_NAME}\n{_sha256(progress_raw)}  {PROGRESS_NAME}\n"
    ).encode()
    _write_exclusive(output_root / "SHA256SUMS", sums)
    return progress


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--effects", type=Path, required=True)
    parser.add_argument("--research-packets", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    result = build_effect_relevance_packets(
        effects_path=args.effects,
        research_packets_path=args.research_packets,
        output_root=args.output_root,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
