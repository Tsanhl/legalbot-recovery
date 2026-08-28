#!/usr/bin/env python3
"""Seal the exact owner decision batch for the r110 source reconciliation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R110_ROOT = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r110-deterministic-source-currentness-reconciliation"
)
R110_PATH = R110_ROOT / "DETERMINISTIC-SOURCE-CURRENTNESS-RECONCILIATION-26.json"
R110_CONTENT_SHA256 = "cffacc05bf449daa5071445531dbb1d8a2e3f98238288b38c6ae8831375299a3"
R110_FILE_SHA256 = "d28ecd4cb9597382a5c82ca54ac7ced8747ff859bd5958c2949795b4bbd4329c"
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r111-source-currentness-owner-batch"
)
BATCH_NAME = "OWNER-SOURCE-CURRENTNESS-DECISION-BATCH.json"
PROMPT_NAME = "OWNER-APPROVAL-PROMPT.txt"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
SOURCE_IDS = (
    "neutral-citation:[2021] UKSC 3",
    "neutral-citation:[2025] UKSC 22",
    "neutral-citation:[2025] EWHC 38 (Ch)",
    "neutral-citation:[2012] EWHC 1257 (Ch)",
    "uksi:2006:246",
)
_BOUNDARY_FIELDS = (
    "owner_decisions_applied",
    "source_admission_authorized",
    "automatic_indexing",
    "automatic_embedding",
    "candidate_mutated",
    "technical_qualification_assigned",
    "phase2b_authorized",
    "development30_authorized",
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


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


def _load_r110() -> dict[str, Any]:
    if R110_PATH.is_symlink() or not R110_PATH.is_file():
        raise ValueError("phase2a_r111_r110_input_not_regular")
    if _sha256_file(R110_PATH) != R110_FILE_SHA256:
        raise ValueError("phase2a_r111_r110_file_digest_invalid")
    value = json.loads(R110_PATH.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r111_r110_input_not_object")
    material = dict(value)
    supplied = str(material.pop("artifact_content_sha256", ""))
    if supplied != R110_CONTENT_SHA256 or supplied != _sealed(material):
        raise ValueError("phase2a_r111_r110_content_seal_invalid")
    if any(value.get(field) is not False for field in _BOUNDARY_FIELDS):
        raise ValueError("phase2a_r111_r110_boundary_invalid")
    return value


def _sealed_binding(binding: Mapping[str, Any]) -> dict[str, Any]:
    material = dict(binding)
    if not material.get("atomic_proposition") or not material.get("quote"):
        raise ValueError("phase2a_r111_binding_incomplete")
    return {**material, "binding_content_sha256": _sealed(material)}


def _mapping_decision(row: Mapping[str, Any]) -> dict[str, Any]:
    material = {
        "ordinal": row["ordinal"],
        "row_source_link_id": row["row_source_link_id"],
        "row_id": row["row_id"],
        "issue_label": row["issue_label"],
        "mapped_authority_identity_id": row["authority_identity_id"],
        "source_title": row["source_title"],
        "recommended_owner_outcome": row["recommended_owner_outcome"],
        "deterministic_reason_code": row["deterministic_reason_code"],
        "deterministic_rationale": row["deterministic_rationale"],
        "replacement_authority_identity_ids": row[
            "replacement_authority_identity_ids"
        ],
        "exact_proposition_bindings": [
            _sealed_binding(binding)
            for binding in row["exact_proposition_bindings"]
        ],
        "same_adapter_advisory_assessment": row[
            "same_adapter_advisory_assessment"
        ],
        "same_adapter_false_negative": row["same_adapter_false_negative"],
        "source_record_content_sha256": row["record_content_sha256"],
        "owner_decision_required": True,
        "owner_outcome": None,
        "technical_qualification_assigned": False,
    }
    return {**material, "decision_content_sha256": _sealed(material)}


def _source_admission_decision(proposal: Mapping[str, Any]) -> dict[str, Any]:
    if (
        proposal.get("owner_source_admission_required") is not True
        or proposal.get("owner_source_admission_decision") is not None
        or proposal.get("source_admission_authorized") is not False
        or proposal.get("automatically_indexed") is not False
        or proposal.get("automatically_embedded") is not False
    ):
        raise ValueError("phase2a_r111_source_proposal_boundary_invalid")
    material = {
        "authority_identity_id": proposal["authority_identity_id"],
        "source_title": proposal["source_title"],
        "source_date": proposal["source_date"],
        "source_representation_sha256": proposal["source_representation_sha256"],
        "source_canonical_xml_sha256": proposal["source_canonical_xml_sha256"],
        "source_class": proposal["source_class"],
        "affected_row_ids": proposal["affected_row_ids"],
        "proposed_candidate_use": proposal["proposed_candidate_use"],
        "currentness_status": proposal["currentness_status"],
        "exact_proposition_bindings": [
            _sealed_binding(binding)
            for binding in proposal["exact_proposition_bindings"]
        ],
        "recommended_owner_outcome": (
            "APPROVE_PROPOSITION_LEVEL_SOURCE_ADMISSION_FOR_CONTINUED_PHASE2A"
        ),
        "owner_source_admission_required": True,
        "owner_outcome": None,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
    }
    return {**material, "decision_content_sha256": _sealed(material)}


def build(output_root: Path = DEFAULT_OUTPUT_ROOT) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_r111_output_already_exists")
    r110 = _load_r110()
    rows = r110.get("reconciled_links")
    proposals = r110.get("source_admission_proposals")
    metadata = r110.get("currentness_metadata_only_sources")
    if (
        not isinstance(rows, list)
        or len(rows) != 26
        or not isinstance(proposals, list)
        or len(proposals) != 5
        or not isinstance(metadata, list)
        or len(metadata) != 1
    ):
        raise ValueError("phase2a_r111_input_inventory_invalid")
    mapping_decisions = [_mapping_decision(row) for row in rows]
    source_decisions = [_source_admission_decision(row) for row in proposals]
    if tuple(row["authority_identity_id"] for row in source_decisions) != SOURCE_IDS:
        raise ValueError("phase2a_r111_source_identity_inventory_invalid")
    outcome_counts = dict(
        sorted(
            Counter(
                row["recommended_owner_outcome"] for row in mapping_decisions
            ).items()
        )
    )
    if outcome_counts != r110["recommendation_counts"]:
        raise ValueError("phase2a_r111_mapping_count_mismatch")

    metadata_source = metadata[0]
    metadata_material = {
        "authority_identity_id": metadata_source["authority_identity_id"],
        "affected_row_ids": metadata_source["affected_row_ids"],
        "treatment_relationship": metadata_source["treatment_relationship"],
        "exact_span": metadata_source["exact_span"],
        "recommended_owner_outcome": (
            "APPROVE_CURRENTNESS_METADATA_ONLY_WITHOUT_CANDIDATE_ADMISSION"
        ),
        "owner_outcome": None,
        "candidate_source_admission_recommended": False,
    }
    metadata_decision = {
        **metadata_material,
        "decision_content_sha256": _sealed(metadata_material),
    }

    batch_material = {
        "schema": "legalbot.v111.phase2a.post-r110-owner-decision-batch.v1",
        "status": "EXACT_OWNER_DECISION_REQUIRED_CONTINUED_PHASE2A_ONLY",
        "owner": "Agnes",
        "decision_date": "2026-08-26",
        "qualification_route": "OWNER_ADOPTED_INTERNAL_RESEARCH_TOOL",
        "not_professional_legal_certification": True,
        "source_r110_artifact_content_sha256": R110_CONTENT_SHA256,
        "source_r110_file_sha256": R110_FILE_SHA256,
        "decision_summary": {
            "row_source_link_decision_count": len(mapping_decisions),
            "affected_unique_row_count": r110["unique_row_count"],
            "mapping_recommendation_counts": outcome_counts,
            "proposition_level_source_admission_count": len(source_decisions),
            "currentness_metadata_only_decision_count": 1,
            "same_adapter_false_negative_count": r110[
                "same_adapter_false_negative_count"
            ],
        },
        "mapping_decisions": mapping_decisions,
        "source_admission_decisions": source_decisions,
        "currentness_metadata_only_decision": metadata_decision,
        "approval_effect": (
            "APPLY_THE_26_LISTED_MAPPING_DISPOSITIONS_AND_ADMIT_EXACTLY_THE_5_"
            "LISTED_OFFICIAL_SOURCES_AT_PROPOSITION_LEVEL_FOR_CONTINUED_PHASE2A"
        ),
        "approval_does_not": [
            "TECHNICALLY_QUALIFY_ANY_AFFECTED_ROW",
            "QUALIFY_THE_REMAINING_PHASE2A_MATERIAL_GAP_INVENTORY",
            "AUTHORIZE_AUTOMATIC_INDEXING_OR_EMBEDDING",
            "AUTHORIZE_AN_IN_PLACE_PREDECESSOR_CANDIDATE_PATCH",
            "AUTHORIZE_A_SUCCESSOR_BUILD_BEFORE_FINAL_SOURCE_SCOPE_IS_PROVEN",
            "AUTHORIZE_PHASE2B",
            "AUTHORIZE_DEVELOPMENT30",
            "AUTHORIZE_VALIDATION_PROMOTION_OR_LIVE_ACTIVATION",
        ],
        "same_adapter_review_used_as_gate": False,
        "owner_decision_required": True,
        "owner_approved": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    if any(batch_material[field] is not False for field in _BOUNDARY_FIELDS):
        raise ValueError("phase2a_r111_batch_boundary_invalid")
    batch = {
        **batch_material,
        "artifact_content_sha256": _sealed(batch_material),
    }

    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_r111_output_mode_invalid")
    batch_path = output_root / BATCH_NAME
    _write_exclusive(batch_path, _pretty_json(batch))
    digest = batch["artifact_content_sha256"]
    source_lines = "\n".join(f"- {source_id}" for source_id in SOURCE_IDS)
    prompt = f"""OWNER DECISION - APPROVE EXACT POST-R110 SOURCE/CURRENTNESS BATCH ONLY

I, Agnes, approve every recommended owner outcome and proposition-level source admission listed in the Phase-2A post-r110 source/currentness owner batch with exact artifact digest:

{digest}

My approval covers exactly:

- 26 source-mapping dispositions affecting 22 Phase-2A rows: 21 unrelated mappings rejected, 2 mappings superseded with current binding authorities, 2 partial proposition bindings with source admission, and 1 partial existing-candidate source binding;
- correction of the 4 recorded same-adapter advisory false negatives through the listed deterministic official-source findings;
- proposition-level admission of exactly these 5 official sources for continued Phase 2A:
{source_lines}
- the listed [2025] EWHC 2863 (Ch) later-same-case disposition as currentness metadata only, without candidate-source admission.

I authorize Codex to apply these exact decisions and record admission of exactly those 5 sources for continued Phase 2A only.

This approval does not technically qualify any affected issue or the remaining Phase-2A material-gap inventory. It does not authorize automatic indexing or embedding, an in-place patch, an immediate successor build, Phase 2B, Development 30, Validation, promotion, ACTIVE/PREVIOUS writes, or live activation.

Any approved source may be indexed only later through one consolidated successor-source manifest and successor candidate after the complete remaining source scope is proven.

I APPROVE THIS EXACT DIGEST-BOUND PHASE-2A BATCH.

Owner typed name: Agnes
Decision date: 2026-08-26
"""
    _write_exclusive(output_root / PROMPT_NAME, prompt.encode("utf-8"))
    _write_exclusive(
        output_root / "OUTCOME.txt",
        b"POST-R110 OWNER DECISION BATCH READY; EXACT DIGEST APPROVAL REQUIRED; "
        b"NO SOURCE ADMITTED, INDEXED, OR EMBEDDED; PHASE 2B CLOSED.\n",
    )
    package_material = {
        "schema": "legalbot.v111.phase2a.post-r110-owner-package.v1",
        "status": batch["status"],
        "owner_batch_content_sha256": digest,
        "owner_batch_file_sha256": _sha256_file(batch_path),
        "owner_approval_prompt_file_sha256": _sha256_file(
            output_root / PROMPT_NAME
        ),
        "outcome_file_sha256": _sha256_file(output_root / "OUTCOME.txt"),
        "owner_approved": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    package = {
        **package_material,
        "package_content_sha256": _sealed(package_material),
    }
    _write_exclusive(output_root / PACKAGE_NAME, _pretty_json(package))
    names = sorted(
        path.name
        for path in output_root.iterdir()
        if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    sums = "".join(
        f"{_sha256_file(output_root / name)}  {name}\n" for name in names
    )
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode("utf-8"))
    return batch


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = output_root / "FAILURE.json"
        if path.exists() or path.is_symlink():
            return
        fingerprint_material = {
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "affected_stage": "PHASE2A_POST_R110_OWNER_DECISION_GATE",
        }
        material = {
            "schema": "legalbot.v111.phase2a.post-r110-owner-batch-failure.v1",
            "failure_fingerprint": _sealed(fingerprint_material),
            **fingerprint_material,
            "affected_rows": "26_SOURCE_LINKS_ACROSS_22_ROWS",
            "completed_work": "PRESERVED_BEFORE_EXCEPTION",
            "root_cause_status": "DEBUG_REQUIRED",
            "required_execution_plan_change": (
                "INSPECT_THE_FAILURE_AND_R110_INPUT_SEALS_BEFORE_RETRY"
            ),
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            _pretty_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except Exception:
        return


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args(argv)
    output_root = args.output_root.resolve()
    try:
        batch = build(output_root)
    except Exception as exc:
        _persist_failure(output_root, exc)
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "artifact_content_sha256": batch["artifact_content_sha256"],
                "decision_summary": batch["decision_summary"],
                "owner_approved": False,
                "source_admission_authorized": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
