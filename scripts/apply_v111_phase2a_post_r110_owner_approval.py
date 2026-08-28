#!/usr/bin/env python3
"""Record Agnes's exact post-r110 Phase-2A owner approval.

This create-only command verifies the sealed r111 owner batch and its reviewed
DOCX package, records all 26 mapping decisions and exactly five proposition-
level source admissions, and carries all 364 unresolved material-gap rows
forward without technical qualification.  It never indexes, embeds, builds or
mutates a candidate, or activates Phase 2B/Development 30.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
DEFAULT_SOURCE_ROOT = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r111-source-currentness-owner-batch"
)
DEFAULT_REVIEW_ROOT = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r112b-post-r110-owner-review-docx"
)
DEFAULT_PREDECESSOR_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r95-substantive-owner-approved"
)
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r113-post-r110-owner-approved"
)

EXPECTED_BATCH_DIGEST = (
    "6c9eda0de5c9c921b99127cac9c6e41bb3ae87151178e250b9f4abcf4a0d7fa1"
)
EXPECTED_R111_PACKAGE_DIGEST = (
    "0027239a81e8823958296bf3e004a7c2dc0d0c8008d0b4afbfd64869f7fb1151"
)
EXPECTED_R111_PACKAGE_FILE_SHA256 = (
    "3b96588ad1ee981f3b816baaedbbd25e81fc82daedda73609452423480fce0ae"
)
EXPECTED_R111_BATCH_FILE_SHA256 = (
    "e657bffbf77e264fd658bb4c61bb3932f8e6e65fa10923b7eebcf20a8739cf20"
)
EXPECTED_R111_PROMPT_FILE_SHA256 = (
    "46013e08350cc3a54d568cf3c7ab86a12ca3cfdde6b39320e48f009d71e21374"
)
EXPECTED_R112B_PACKAGE_DIGEST = (
    "c76b6a72c151989b6948dce91b8e41a4378927242ddd1e7aada2ee0639ebcdc3"
)
EXPECTED_R112B_PACKAGE_FILE_SHA256 = (
    "e4c1bd823236d82a4731d9b0de89e29cd31c427a3ded7722a9985d567d802871"
)
EXPECTED_R95_PACKAGE_DIGEST = (
    "a2df2408785defdefa9622fb7e6df33be3306b2e8d4053b9015ef49a80091f53"
)
EXPECTED_R95_PACKAGE_FILE_SHA256 = (
    "d6dad18bad7d1d4d33e613d38d1e2c10695bb6e02ea45a56618fd439e8734575"
)
EXPECTED_R95_SOURCE_ADMISSIONS_DIGEST = (
    "d744fc4b0a66badd268f1149c290957993e0aedaf4fb066ae4d8648c01814326"
)
EXPECTED_R95_SOURCE_ADMISSIONS_FILE_SHA256 = (
    "f7d53afd7ec32dee9c8298d2ff4250ff16350f12f165ca74ec80fc1bec52a60a"
)
EXPECTED_REMAINING_GAPS_DIGEST = (
    "513c58f6eac13d9c51c99efe657d7809158392687143edd67a6b9832e4ecbb34"
)
EXPECTED_REMAINING_GAPS_FILE_SHA256 = (
    "202e054012f4565de7f648a7219bafa8530778f9f66c166ffc74101b04b2252b"
)
EXPECTED_SOURCE_IDS = (
    "neutral-citation:[2021] UKSC 3",
    "neutral-citation:[2025] UKSC 22",
    "neutral-citation:[2025] EWHC 38 (Ch)",
    "neutral-citation:[2012] EWHC 1257 (Ch)",
    "uksi:2006:246",
)
OWNER_REPLY = """I, Agnes, approve every recommended owner outcome and proposition-level source admission in the Phase-2A post-r110 owner batch with exact artifact digest 6c9eda0de5c9c921b99127cac9c6e41bb3ae87151178e250b9f4abcf4a0d7fa1 for continued Phase 2A only.

I also approve for Phase 2B what need to move on to it.
I APPROVE THIS EXACT DIGEST-BOUND PHASE-2A BATCH."""
OWNER_DECISION_DATE = "2026-08-26"
PHASE2B_ADVANCE_STATEMENT = "I also approve for Phase 2B what need to move on to it."
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


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


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_r113_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r113_input_must_be_object")
    return value


def _verify_seal(
    value: Mapping[str, Any],
    field: str,
    code: str,
    expected: str | None = None,
) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if (
        not _SHA256.fullmatch(supplied)
        or supplied != _sealed(material)
        or (expected is not None and supplied != expected)
    ):
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


def _sealed_artifact(schema: str, material: Mapping[str, Any]) -> dict[str, Any]:
    payload = {"schema": schema, **material}
    return {**payload, "artifact_content_sha256": _sealed(payload)}


def _normalize_owner_reply(value: str) -> str:
    return "\n".join(line.rstrip() for line in value.strip().splitlines())


def _verify_decision(item: Mapping[str, Any], *, source: bool = False) -> None:
    _verify_seal(
        item,
        "decision_content_sha256",
        "phase2a_r113_source_decision_seal_invalid",
    )
    if item.get("owner_outcome") is not None:
        raise ValueError("phase2a_r113_owner_outcome_already_assigned")
    for binding in item.get("exact_proposition_bindings", []):
        if not isinstance(binding, Mapping):
            raise ValueError("phase2a_r113_binding_invalid")
        _verify_seal(
            binding,
            "binding_content_sha256",
            "phase2a_r113_binding_seal_invalid",
        )
    if source and (
        item.get("source_admission_authorized") is not False
        or item.get("automatic_indexing") is not False
        or item.get("automatic_embedding") is not False
    ):
        raise ValueError("phase2a_r113_source_decision_boundary_invalid")


def _verify_source_package(
    source_root: Path,
    review_root: Path,
) -> dict[str, Any]:
    package_path = source_root / "PACKAGE-MANIFEST.json"
    if _sha256_file(package_path) != EXPECTED_R111_PACKAGE_FILE_SHA256:
        raise ValueError("phase2a_r113_r111_package_file_digest_invalid")
    package = _load_object(package_path)
    _verify_seal(
        package,
        "package_content_sha256",
        "phase2a_r113_r111_package_seal_invalid",
        EXPECTED_R111_PACKAGE_DIGEST,
    )
    batch_path = source_root / "OWNER-SOURCE-CURRENTNESS-DECISION-BATCH.json"
    prompt_path = source_root / "OWNER-APPROVAL-PROMPT.txt"
    if (
        package.get("owner_batch_content_sha256") != EXPECTED_BATCH_DIGEST
        or package.get("owner_batch_file_sha256")
        != EXPECTED_R111_BATCH_FILE_SHA256
        or package.get("owner_approval_prompt_file_sha256")
        != EXPECTED_R111_PROMPT_FILE_SHA256
        or _sha256_file(batch_path) != EXPECTED_R111_BATCH_FILE_SHA256
        or _sha256_file(prompt_path) != EXPECTED_R111_PROMPT_FILE_SHA256
        or package.get("owner_approved") is not False
        or package.get("source_admission_authorized") is not False
        or package.get("candidate_mutated") is not False
        or package.get("phase2b_authorized") is not False
        or package.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_r113_r111_package_boundary_invalid")

    batch = _load_object(batch_path)
    _verify_seal(
        batch,
        "artifact_content_sha256",
        "phase2a_r113_r111_batch_seal_invalid",
        EXPECTED_BATCH_DIGEST,
    )
    summary = batch.get("decision_summary")
    mappings = batch.get("mapping_decisions")
    sources = batch.get("source_admission_decisions")
    metadata = batch.get("currentness_metadata_only_decision")
    if (
        batch.get("schema")
        != "legalbot.v111.phase2a.post-r110-owner-decision-batch.v1"
        or not isinstance(summary, Mapping)
        or summary.get("row_source_link_decision_count") != 26
        or summary.get("affected_unique_row_count") != 22
        or summary.get("proposition_level_source_admission_count") != 5
        or summary.get("currentness_metadata_only_decision_count") != 1
        or summary.get("same_adapter_false_negative_count") != 4
        or not isinstance(mappings, list)
        or len(mappings) != 26
        or not isinstance(sources, list)
        or len(sources) != 5
        or not isinstance(metadata, Mapping)
        or batch.get("owner_approved") is not False
        or batch.get("owner_decisions_applied") is not False
        or batch.get("source_admission_authorized") is not False
        or batch.get("automatic_indexing") is not False
        or batch.get("automatic_embedding") is not False
        or batch.get("candidate_mutated") is not False
        or batch.get("technical_qualification_assigned") is not False
        or batch.get("phase2b_authorized") is not False
        or batch.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_r113_r111_batch_boundary_invalid")
    for item in mappings:
        if not isinstance(item, Mapping):
            raise ValueError("phase2a_r113_mapping_inventory_invalid")
        _verify_decision(item)
    for item in sources:
        if not isinstance(item, Mapping):
            raise ValueError("phase2a_r113_source_inventory_invalid")
        _verify_decision(item, source=True)
    if tuple(item["authority_identity_id"] for item in sources) != EXPECTED_SOURCE_IDS:
        raise ValueError("phase2a_r113_source_identity_inventory_invalid")
    _verify_seal(
        metadata,
        "decision_content_sha256",
        "phase2a_r113_currentness_metadata_seal_invalid",
    )
    if (
        metadata.get("owner_outcome") is not None
        or metadata.get("candidate_source_admission_recommended") is not False
    ):
        raise ValueError("phase2a_r113_currentness_metadata_boundary_invalid")

    review_package_path = review_root / "PACKAGE-MANIFEST.json"
    if _sha256_file(review_package_path) != EXPECTED_R112B_PACKAGE_FILE_SHA256:
        raise ValueError("phase2a_r113_review_package_file_digest_invalid")
    review = _load_object(review_package_path)
    _verify_seal(
        review,
        "package_content_sha256",
        "phase2a_r113_review_package_seal_invalid",
        EXPECTED_R112B_PACKAGE_DIGEST,
    )
    if (
        review.get("owner_batch_content_sha256") != EXPECTED_BATCH_DIGEST
        or review.get("status")
        != "VISUAL_AND_STRUCTURAL_QA_PASS_OWNER_DECISION_REQUIRED"
        or review.get("owner_approved") is not False
        or review.get("source_admission_authorized") is not False
        or review.get("candidate_mutated") is not False
        or review.get("phase2b_authorized") is not False
        or review.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_r113_review_package_boundary_invalid")
    return batch


def _verify_predecessor(
    predecessor_root: Path,
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    package_path = predecessor_root / "PACKAGE-INDEX.json"
    if _sha256_file(package_path) != EXPECTED_R95_PACKAGE_FILE_SHA256:
        raise ValueError("phase2a_r113_predecessor_package_file_digest_invalid")
    package = _load_object(package_path)
    _verify_seal(
        package,
        "package_content_sha256",
        "phase2a_r113_predecessor_package_seal_invalid",
        EXPECTED_R95_PACKAGE_DIGEST,
    )
    if (
        package.get("approved_source_admission_count") != 20
        or package.get("remaining_material_gap_count") != 364
        or package.get("automatic_indexing") is not False
        or package.get("automatic_embedding") is not False
        or package.get("candidate_mutated") is not False
        or package.get("phase2b_authorized") is not False
        or package.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_r113_predecessor_boundary_invalid")

    source_path = predecessor_root / "APPROVED-SOURCE-ADMISSIONS-20.json"
    if _sha256_file(source_path) != EXPECTED_R95_SOURCE_ADMISSIONS_FILE_SHA256:
        raise ValueError("phase2a_r113_predecessor_sources_file_digest_invalid")
    old_sources = _load_object(source_path)
    _verify_seal(
        old_sources,
        "artifact_content_sha256",
        "phase2a_r113_predecessor_sources_seal_invalid",
        EXPECTED_R95_SOURCE_ADMISSIONS_DIGEST,
    )
    if old_sources.get("record_count") != 20:
        raise ValueError("phase2a_r113_predecessor_sources_inventory_invalid")
    for record in old_sources.get("records", []):
        if not isinstance(record, Mapping):
            raise ValueError("phase2a_r113_predecessor_source_record_invalid")
        _verify_seal(
            record,
            "source_admission_content_sha256",
            "phase2a_r113_predecessor_source_record_seal_invalid",
        )
        if (
            record.get("source_admission_authorized") is not True
            or record.get("automatic_indexing") is not False
            or record.get("automatic_embedding") is not False
            or record.get("candidate_build_authorized") is not False
            or record.get("phase2b_authorized") is not False
            or record.get("development30_authorized") is not False
        ):
            raise ValueError("phase2a_r113_predecessor_source_record_boundary_invalid")

    remaining_path = predecessor_root / "REMAINING-MATERIAL-GAPS-364.json"
    remaining_raw = remaining_path.read_bytes()
    if _sha256(remaining_raw) != EXPECTED_REMAINING_GAPS_FILE_SHA256:
        raise ValueError("phase2a_r113_remaining_gaps_file_digest_invalid")
    remaining = json.loads(remaining_raw)
    if not isinstance(remaining, dict):
        raise ValueError("phase2a_r113_remaining_gaps_not_object")
    _verify_seal(
        remaining,
        "artifact_content_sha256",
        "phase2a_r113_remaining_gaps_seal_invalid",
        EXPECTED_REMAINING_GAPS_DIGEST,
    )
    if (
        remaining.get("record_count") != 364
        or remaining.get("owner_approved") is not False
        or remaining.get("technical_qualification_assigned") is not False
    ):
        raise ValueError("phase2a_r113_remaining_gaps_boundary_invalid")
    return old_sources, remaining_raw, remaining


def _approved_mapping(item: Mapping[str, Any]) -> dict[str, Any]:
    recommendation = str(item.get("recommended_owner_outcome") or "")
    if not recommendation:
        raise ValueError("phase2a_r113_mapping_recommendation_missing")
    material = {
        "schema": "legalbot.v111.phase2a.r111-owner-approved-mapping.v1",
        "status": "OWNER_DECISION_RECORDED_CONTINUED_PHASE2A_ONLY",
        "source_decision_content_sha256": item["decision_content_sha256"],
        "source_decision": dict(item),
        "owner_typed_name": "Agnes",
        "owner_decision_date": OWNER_DECISION_DATE,
        "owner_outcome": recommendation,
        "technical_qualification_assigned": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_build_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    return {**material, "approved_decision_content_sha256": _sealed(material)}


def _approved_source(item: Mapping[str, Any]) -> dict[str, Any]:
    authority_id = str(item["authority_identity_id"])
    if authority_id.startswith("neutral-citation:"):
        source_identity = authority_id.removeprefix("neutral-citation:")
        source_key = f"judgment:{source_identity}"
        source_group = "OFFICIAL_JUDGMENT"
    elif authority_id.startswith("uksi:"):
        source_identity = authority_id
        source_key = f"official-legislation:{source_identity}"
        source_group = "OFFICIAL_LEGISLATION"
    else:
        raise ValueError("phase2a_r113_source_identity_unsupported")
    material = {
        "source_key": source_key,
        "source_group": source_group,
        "source_identity": source_identity,
        "source_authority_identity_id": authority_id,
        "source_title": item["source_title"],
        "source_date": item["source_date"],
        "source_representation_sha256": item["source_representation_sha256"],
        "source_canonical_xml_sha256": item["source_canonical_xml_sha256"],
        "affected_row_ids": item["affected_row_ids"],
        "proposed_candidate_use": item["proposed_candidate_use"],
        "currentness_status": item["currentness_status"],
        "proposition_level_uses": [
            binding["binding_content_sha256"]
            for binding in item["exact_proposition_bindings"]
        ],
        "source_decision_content_sha256s": [item["decision_content_sha256"]],
        "status": "OWNER_APPROVED_FOR_LATER_CONSOLIDATED_SUCCESSOR_SCOPE",
        "owner_typed_name": "Agnes",
        "owner_decision_date": OWNER_DECISION_DATE,
        "source_admission_authorized": True,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_build_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    return {**material, "source_admission_content_sha256": _sealed(material)}


def _approved_currentness(item: Mapping[str, Any]) -> dict[str, Any]:
    recommendation = str(item.get("recommended_owner_outcome") or "")
    if not recommendation:
        raise ValueError("phase2a_r113_currentness_recommendation_missing")
    material = {
        "schema": "legalbot.v111.phase2a.r111-owner-approved-currentness.v1",
        "status": "OWNER_CURRENTNESS_METADATA_DECISION_RECORDED",
        "source_decision_content_sha256": item["decision_content_sha256"],
        "source_decision": dict(item),
        "owner_typed_name": "Agnes",
        "owner_decision_date": OWNER_DECISION_DATE,
        "owner_outcome": recommendation,
        "candidate_source_admission_authorized": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    return {**material, "approved_decision_content_sha256": _sealed(material)}


def _write_package(output_root: Path, files: Mapping[str, bytes]) -> str:
    for name, raw in files.items():
        _write_exclusive(output_root / name, raw)
    entries = {
        name: {"sha256": _sha256(raw), "bytes": len(raw)}
        for name, raw in sorted(files.items())
    }
    material = {
        "schema": "legalbot.v111.phase2a.r111-owner-approved-package.v1",
        "status": "R111_OWNER_DECISIONS_RECORDED_364_MATERIAL_GAPS_REMAIN",
        "file_count": len(entries),
        "files": entries,
        "source_r111_batch_content_sha256": EXPECTED_BATCH_DIGEST,
        "source_r111_package_content_sha256": EXPECTED_R111_PACKAGE_DIGEST,
        "review_r112b_package_content_sha256": EXPECTED_R112B_PACKAGE_DIGEST,
        "predecessor_r95_package_content_sha256": EXPECTED_R95_PACKAGE_DIGEST,
        "approved_mapping_disposition_count": 26,
        "approved_affected_row_count": 22,
        "approved_new_source_admission_count": 5,
        "cumulative_approved_source_admission_count": 25,
        "remaining_material_gap_count": 364,
        "phase2b_advance_intent_recorded": True,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_build_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    index = {**material, "package_content_sha256": _sealed(material)}
    _write_exclusive(output_root / "PACKAGE-INDEX.json", _pretty_json(index))
    paths = sorted(path for path in output_root.iterdir() if path.is_file())
    sums = "".join(f"{_sha256_file(path)}  {path.name}\n" for path in paths)
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode("utf-8"))
    return str(index["package_content_sha256"])


def apply_approval(
    *,
    source_root: Path,
    review_root: Path,
    predecessor_root: Path,
    output_root: Path,
    owner_reply: str,
    owner_decision_date: str,
    recorded_at: datetime,
) -> dict[str, Any]:
    """Apply the exact r111 approval while keeping all later gates closed."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_r113_output_already_exists")
    if owner_decision_date != OWNER_DECISION_DATE:
        raise ValueError("phase2a_r113_owner_decision_date_invalid")
    if recorded_at.tzinfo is None:
        raise ValueError("phase2a_r113_recorded_at_naive")
    normalized_reply = _normalize_owner_reply(owner_reply)
    if normalized_reply != _normalize_owner_reply(OWNER_REPLY):
        raise ValueError("phase2a_r113_owner_reply_not_exact")
    if normalized_reply.count(EXPECTED_BATCH_DIGEST) != 1:
        raise ValueError("phase2a_r113_owner_reply_digest_invalid")

    batch = _verify_source_package(source_root, review_root)
    old_sources, remaining_raw, remaining = _verify_predecessor(predecessor_root)
    affected_rows = {str(item["row_id"]) for item in batch["mapping_decisions"]}
    pending_rows = {str(item["row_id"]) for item in remaining["records"]}
    if len(affected_rows) != 22 or not affected_rows <= pending_rows:
        raise ValueError("phase2a_r113_affected_row_inventory_invalid")

    approved_mappings = [
        _approved_mapping(item) for item in batch["mapping_decisions"]
    ]
    approved_sources = [
        _approved_source(item) for item in batch["source_admission_decisions"]
    ]
    approved_currentness = _approved_currentness(
        batch["currentness_metadata_only_decision"]
    )
    old_records = old_sources["records"]
    cumulative = [*old_records, *approved_sources]
    source_keys = [str(record["source_key"]) for record in cumulative]
    if len(cumulative) != 25 or len(set(source_keys)) != 25:
        raise ValueError("phase2a_r113_cumulative_source_inventory_invalid")

    recorded = recorded_at.astimezone(UTC).isoformat(timespec="seconds")
    receipt = _sealed_artifact(
        "legalbot.v111.phase2a.r111-owner-approval-receipt.v1",
        {
            "status": "OWNER_APPROVED_EXACT_R111_BATCH_CONTINUED_PHASE2A_ONLY",
            "owner_typed_name": "Agnes",
            "owner_decision_date": owner_decision_date,
            "owner_reply": normalized_reply,
            "owner_reply_sha256": _sha256((normalized_reply + "\n").encode("utf-8")),
            "recorded_at": recorded,
            "source_r111_batch_content_sha256": EXPECTED_BATCH_DIGEST,
            "source_r111_package_content_sha256": EXPECTED_R111_PACKAGE_DIGEST,
            "review_r112b_package_content_sha256": EXPECTED_R112B_PACKAGE_DIGEST,
            "approved_mapping_disposition_count": 26,
            "approved_affected_row_count": 22,
            "approved_new_source_admission_count": 5,
            "remaining_material_gap_count": 364,
            "continued_phase2a_authorized": True,
            "phase2b_advance_intent_recorded": True,
            "phase2b_activation_condition": (
                "SUCCESSFUL_FINAL_PHASE2A_DIGEST_MUST_EXIST_AND_BE_EXPLICITLY_ADOPTED"
            ),
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_build_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )
    mapping_artifact = _sealed_artifact(
        "legalbot.v111.phase2a.owner-approved-r111-mappings-26.v1",
        {
            "record_count": 26,
            "affected_unique_row_count": 22,
            "records": approved_mappings,
            "technical_qualification_assigned": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_build_authorized": False,
        },
    )
    source_artifact = _sealed_artifact(
        "legalbot.v111.phase2a.owner-approved-r111-source-admissions-5.v1",
        {
            "record_count": 5,
            "records": approved_sources,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_build_authorized": False,
        },
    )
    cumulative_artifact = _sealed_artifact(
        "legalbot.v111.phase2a.cumulative-owner-approved-source-admissions-25.v1",
        {
            "record_count": 25,
            "predecessor_record_count": 20,
            "r111_record_count": 5,
            "records": cumulative,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_build_authorized": False,
        },
    )
    currentness_artifact = _sealed_artifact(
        "legalbot.v111.phase2a.owner-approved-r111-currentness-metadata-1.v1",
        {
            "record_count": 1,
            "records": [approved_currentness],
            "candidate_source_admission_authorized": False,
            "technical_qualification_assigned": False,
        },
    )
    phase2b_intent = _sealed_artifact(
        "legalbot.v111.phase2a.conditional-phase2b-advance-intent.v1",
        {
            "status": "ADVANCE_CONDITIONAL_INTENT_RECORDED_NOT_GATE_ACTIVATION",
            "owner_typed_name": "Agnes",
            "owner_decision_date": owner_decision_date,
            "owner_statement": PHASE2B_ADVANCE_STATEMENT,
            "owner_reply_sha256": receipt["owner_reply_sha256"],
            "required_before_activation": [
                "PHASE2A_TECHNICAL_REQUIREMENTS_PASS",
                "EXACT_FINAL_PHASE2A_PACKAGE_DIGEST_EXISTS",
                "OWNER_EXPLICITLY_ADOPTS_THAT_EXACT_DIGEST",
            ],
            "final_phase2a_digest_exists": False,
            "final_phase2a_digest_owner_adopted": False,
            "keys_secrets_roots_or_socket_provisioned": False,
            "split_frozen": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )
    inventory = _sealed_artifact(
        "legalbot.v111.phase2a.post-r111-owner-approval-inventory.v1",
        {
            "status": "R111_RECORDED_364_MATERIAL_GAPS_REMAIN",
            "source_r111_batch_content_sha256": EXPECTED_BATCH_DIGEST,
            "owner_approval_receipt_content_sha256": receipt[
                "artifact_content_sha256"
            ],
            "total_issue_count": 585,
            "recorded_issue_count": 221,
            "pending_issue_count": 364,
            "r111_mapping_disposition_count": 26,
            "r111_affected_row_count": 22,
            "r111_rejected_mapping_count": 21,
            "r111_positive_or_superseding_mapping_count": 5,
            "recorded_legislative_effect_count": 1896,
            "pending_legislative_effect_count": 0,
            "recorded_judgment_disposition_count": 20,
            "pending_judgment_disposition_count": 0,
            "recorded_byte_mismatch_count": 65,
            "pending_byte_mismatch_count": 0,
            "cumulative_approved_source_admission_count": 25,
            "patents_final_decision_pending": True,
            "source_scope_finalized": False,
            "common_cutoff_supportable": False,
            "successor_candidate_built": False,
            "candidate_build_authorized": False,
            "candidate_mutated": False,
            "phase2b_advance_intent_recorded": True,
            "phase2b_authorized": False,
            "development30_authorized": False,
            "terminal_verdict": (
                "PHASE 2A CONTINUES WITH 364 MATERIAL GAPS — PHASE 2B AND "
                "DEVELOPMENT 30 NOT YET AUTHORIZED"
            ),
        },
    )

    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_r113_output_mode_invalid")
    files = {
        "OWNER-APPROVAL-VERBATIM.txt": (normalized_reply + "\n").encode("utf-8"),
        "OWNER-APPROVAL-RECEIPT-R111.json": _pretty_json(receipt),
        "APPROVED-MAPPING-DISPOSITIONS-26.json": _pretty_json(mapping_artifact),
        "APPROVED-SOURCE-ADMISSIONS-5.json": _pretty_json(source_artifact),
        "CUMULATIVE-APPROVED-SOURCE-ADMISSIONS-25.json": _pretty_json(
            cumulative_artifact
        ),
        "APPROVED-CURRENTNESS-METADATA-1.json": _pretty_json(
            currentness_artifact
        ),
        "PHASE2B-ADVANCE-INTENT.json": _pretty_json(phase2b_intent),
        "REMAINING-MATERIAL-GAPS-364.json": remaining_raw,
        "POST-R111-PHASE2A-INVENTORY.json": _pretty_json(inventory),
        "OUTCOME.txt": (str(inventory["terminal_verdict"]) + "\n").encode(
            "utf-8"
        ),
    }
    package_digest = _write_package(output_root, files)
    return {
        "output_root": str(output_root),
        "source_r111_batch_content_sha256": EXPECTED_BATCH_DIGEST,
        "owner_approval_receipt_content_sha256": receipt[
            "artifact_content_sha256"
        ],
        "package_content_sha256": package_digest,
        "approved_mapping_disposition_count": 26,
        "approved_affected_row_count": 22,
        "approved_new_source_admission_count": 5,
        "cumulative_approved_source_admission_count": 25,
        "remaining_material_gap_count": 364,
        "phase2b_advance_intent_recorded": True,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_build_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = output_root / "FAILURE.json"
        if path.exists() or path.is_symlink():
            return
        fingerprint_material = {
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "affected_stage": "PHASE2A_R111_OWNER_APPROVAL_APPLICATION",
        }
        material = {
            "schema": "legalbot.v111.phase2a.r111-owner-approval-failure.v1",
            "failure_fingerprint": _sealed(fingerprint_material),
            **fingerprint_material,
            "affected_rows": "26_SOURCE_LINKS_ACROSS_22_ROWS",
            "completed_work": "PRESERVED_BEFORE_EXCEPTION",
            "root_cause_status": "DEBUG_REQUIRED",
            "required_execution_plan_change": (
                "INSPECT_FAILURE_AND_BOUND_R111_R112B_R95_INPUTS_BEFORE_RETRY"
            ),
            "debug_required_before_any_third_attempt": True,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_build_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            _pretty_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except BaseException:
        return


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--review-root", type=Path, default=DEFAULT_REVIEW_ROOT)
    parser.add_argument(
        "--predecessor-root", type=Path, default=DEFAULT_PREDECESSOR_ROOT
    )
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args(argv)
    output_root = args.output_root.resolve()
    try:
        result = apply_approval(
            source_root=args.source_root.resolve(strict=True),
            review_root=args.review_root.resolve(strict=True),
            predecessor_root=args.predecessor_root.resolve(strict=True),
            output_root=output_root,
            owner_reply=OWNER_REPLY,
            owner_decision_date=OWNER_DECISION_DATE,
            recorded_at=datetime.now(UTC),
        )
    except BaseException as exc:
        _persist_failure(output_root, exc)
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
