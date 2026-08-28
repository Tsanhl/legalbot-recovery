#!/usr/bin/env python3
"""Record the exact 2026-08-28 Phase-2A remediation owner adoption.

This create-only command records the owner's exact digest-bound authorization.
It verifies the immutable owner packet, package and quarantine bindings, but it
does not apply a decision, admit a source, scan, index, embed, build, qualify or
invoke a model.  A post-approval substantive-content audit remains a technical
hold before any of those authorized Phase-2A operations may execute.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
DEFAULT_PACKET_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1"
DEFAULT_QUARANTINE_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-quarantine"
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-approved-r1"
)

PACKET_NAME = "EXACT-REMEDIATION-OWNER-PACKET-361.json"
SOURCE_PACKAGE_NAME = "PACKAGE-MANIFEST.json"
SOURCE_CHECKSUMS_NAME = "SHA256SUMS.txt"
SOURCE_PROMPT_NAME = "OWNER-APPROVAL-PROMPT.txt"
QUARANTINE_MANIFEST_NAME = "QUARANTINE-MANIFEST.json"

RECEIPT_NAME = "OWNER-ADOPTION-RECEIPT.json"
VERBATIM_NAME = "OWNER-APPROVAL-VERBATIM.txt"
OUTCOME_NAME = "OWNER-ADOPTION-OUTCOME.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

EXPECTED_PACKET_CONTENT_SHA256 = "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c"
EXPECTED_PACKET_FILE_SHA256 = "992770c04cb3e08de64bb98e80aa9801171d3e66e4b573b85919091a78b1db3b"
EXPECTED_PACKAGE_CONTENT_SHA256 = "b04327f957d5216ccc96e76c643769d6ac412a6fe551291705efcfa3db6b32e9"
EXPECTED_PACKAGE_FILE_SHA256 = "95670abeeb71af5660d5c2747ad9d0ab8ab31d295965d46c191a33d6ca31ed8d"
EXPECTED_PROMPT_FILE_SHA256 = "f8bdc7c07c3278419e6956052156d0ac5a7b255d6af40b2f497eb87daf12e854"
EXPECTED_CHECKSUMS_FILE_SHA256 = "5eb964dda284c341b92a55a2166152a0ad70b4b78b8bf62b1668ce6d81daf390"
EXPECTED_QUARANTINE_CONTENT_SHA256 = (
    "b6d900b23232379a4d6c19d313f35c47e0758ce5e0bb6eb04008f9eba07a3819"
)
EXPECTED_QUARANTINE_FILE_SHA256 = "f482366a2ba0d9f636c56104d632767a8eadd6e9a9625d50ef5391a5f62995eb"
EXPECTED_FETCH_IDENTITY_SET_SHA256 = (
    "3133440a3cd141110b4217918d48e87f80342d2987702ba7c696212a3a94f368"
)

EXPECTED_OWNER_TYPED_NAME = "Agnes"
EXPECTED_OWNER_DECISION_DATE = "2026-08-28"
EXPECTED_OWNER_REPLY = """I approve exact Phase-2A remediation owner packet content SHA-256
`93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c` and every recommendation and retained hold it contains.

I authorize Codex to apply only those exact 361 owner decisions; admit only the exact source proposals whose listed recommendation is admission and whose raw bytes, content identity and source-version identity are sealed in this packet; retain every listed currentness, later-treatment, jurisdiction, factual, identity and other hold; run one complete source scan; and build/embed one successor candidate that remains non-ACTIVE and answer-ineligible. After that build, I authorize retrieval re-attestation and all-585 technical qualification only.

I do not authorize an answer-model run or answer release, Phase 2B, Development 30, Validation 30, promotion, ACTIVE/PREVIOUS writes, live activation or training export. If qualification still finds a material gap or unresolved owner decision, the workflow must stop and report it without claiming a successful Phase-2A package.
Owner typed name: Agnes Decision date: 2026-08-28"""

STATUS = "OWNER_ADOPTION_RECORDED_TECHNICAL_SOURCE_BINDING_HOLD"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_VERSION_ID = re.compile(r"^proposed-source-version-[0-9a-f]{40}$")

_PACKET_REQUIRED_FALSE_FLAGS = (
    "owner_approved",
    "owner_decisions_applied",
    "owner_outcomes_applied",
    "source_admission_authorized",
    "source_admitted",
    "complete_source_scan_authorized",
    "source_scan_run",
    "successor_build_authorized",
    "successor_build_run",
    "index_build_authorized",
    "index_built",
    "embedding_authorized",
    "embedding_run",
    "automatic_indexing",
    "automatic_embedding",
    "candidate_mutated",
    "qualification_authorized",
    "retrieval_reattestation_run",
    "all585_qualification_run",
    "technical_qualification_assigned",
    "answer_model_authorized",
    "answer_model_run",
    "answer_release_authorized",
    "answer_released",
    "phase2b_authorized",
    "phase2b_run",
    "development30_authorized",
    "development30_run",
    "validation30_authorized",
    "validation30_run",
    "promotion_authorized",
    "promotion_run",
    "active_pointer_write_authorized",
    "active_pointer_written",
    "previous_pointer_write_authorized",
    "previous_pointer_written",
    "live_activation_authorized",
    "live_activation_run",
    "training_export_authorized",
    "training_export_run",
)

_PROHIBITED_FALSE_FLAGS = {
    "answer_model_authorized": False,
    "answer_model_run": False,
    "answer_release_authorized": False,
    "answer_release_run": False,
    "answer_released": False,
    "phase2b_authorized": False,
    "phase2b_run": False,
    "development30_authorized": False,
    "development30_run": False,
    "owner_certification60_authorized": False,
    "owner_certification60_run": False,
    "o04_authorized": False,
    "o04_run": False,
    "validation30_authorized": False,
    "validation30_run": False,
    "validation30_unsealed": False,
    "promotion_authorized": False,
    "promotion_run": False,
    "active_pointer_write_authorized": False,
    "active_pointer_written": False,
    "previous_pointer_write_authorized": False,
    "previous_pointer_written": False,
    "live_activation_authorized": False,
    "live_activation_run": False,
    "training_export_authorized": False,
    "training_export_run": False,
}


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


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


def _normalize_owner_reply(value: str) -> str:
    """Normalize transport wrapping without weakening exact word matching."""

    return re.sub(r"\s+", " ", value.replace("\r\n", "\n")).strip()


EXPECTED_NORMALIZED_OWNER_REPLY_SHA256 = _sha256(
    _normalize_owner_reply(EXPECTED_OWNER_REPLY).encode("utf-8")
)


def _load_object(path: Path, *, code: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(code)
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(code)
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
        _SHA256.fullmatch(supplied) is None
        or supplied != _sealed(material)
        or (expected is not None and supplied != expected)
    ):
        raise ValueError(code)
    return supplied


def _verify_item_seals(
    records: Any,
    *,
    count: int,
    seal_field: str,
    id_field: str,
    code: str,
) -> list[dict[str, Any]]:
    if not isinstance(records, list) or len(records) != count:
        raise ValueError(code)
    checked: list[dict[str, Any]] = []
    identities: list[str] = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError(code)
        _verify_seal(record, seal_field, code)
        identity = str(record.get(id_field) or "")
        if not identity:
            raise ValueError(code)
        identities.append(identity)
        checked.append(record)
    if len(set(identities)) != count:
        raise ValueError(code)
    return checked


def _require_false_flags(value: Mapping[str, Any], fields: Sequence[str], code: str) -> None:
    if any(value.get(field) is not False for field in fields):
        raise ValueError(code)


def _verify_source_package(packet_root: Path) -> dict[str, Any]:
    if packet_root.is_symlink() or not packet_root.is_dir():
        raise ValueError("phase2a_owner_adoption_packet_root_invalid")
    expected_files = {
        PACKET_NAME: EXPECTED_PACKET_FILE_SHA256,
        SOURCE_PACKAGE_NAME: EXPECTED_PACKAGE_FILE_SHA256,
        SOURCE_PROMPT_NAME: EXPECTED_PROMPT_FILE_SHA256,
        SOURCE_CHECKSUMS_NAME: EXPECTED_CHECKSUMS_FILE_SHA256,
    }
    for name, expected in expected_files.items():
        path = packet_root / name
        if path.is_symlink() or not path.is_file() or _sha256_file(path) != expected:
            raise ValueError("phase2a_owner_adoption_source_package_file_digest_invalid")

    checksum_lines = (packet_root / SOURCE_CHECKSUMS_NAME).read_text(encoding="utf-8")
    expected_checksum_lines = "".join(
        f"{digest}  {name}\n"
        for name, digest in sorted(
            {
                PACKET_NAME: EXPECTED_PACKET_FILE_SHA256,
                SOURCE_PACKAGE_NAME: EXPECTED_PACKAGE_FILE_SHA256,
                SOURCE_PROMPT_NAME: EXPECTED_PROMPT_FILE_SHA256,
            }.items()
        )
    )
    if checksum_lines != expected_checksum_lines:
        raise ValueError("phase2a_owner_adoption_source_checksums_invalid")

    package = _load_object(
        packet_root / SOURCE_PACKAGE_NAME,
        code="phase2a_owner_adoption_source_package_invalid",
    )
    _verify_seal(
        package,
        "artifact_content_sha256",
        "phase2a_owner_adoption_source_package_seal_invalid",
        EXPECTED_PACKAGE_CONTENT_SHA256,
    )
    expected_artifacts = [
        {
            "name": PACKET_NAME,
            "file_sha256": EXPECTED_PACKET_FILE_SHA256,
            "content_sha256": EXPECTED_PACKET_CONTENT_SHA256,
        },
        {"name": SOURCE_PROMPT_NAME, "file_sha256": EXPECTED_PROMPT_FILE_SHA256},
    ]
    if (
        package.get("schema") != "legalbot.v111.phase2a.exact-remediation-owner-package.v1"
        or package.get("status") != "EXACT_361_OWNER_DECISIONS_READY_NOT_ADOPTED"
        or package.get("packet_content_sha256") != EXPECTED_PACKET_CONTENT_SHA256
        or package.get("artifacts") != expected_artifacts
    ):
        raise ValueError("phase2a_owner_adoption_source_package_boundary_invalid")
    _require_false_flags(
        package,
        _PACKET_REQUIRED_FALSE_FLAGS,
        "phase2a_owner_adoption_source_package_boundary_invalid",
    )

    packet = _load_object(
        packet_root / PACKET_NAME,
        code="phase2a_owner_adoption_packet_invalid",
    )
    _verify_seal(
        packet,
        "artifact_content_sha256",
        "phase2a_owner_adoption_packet_seal_invalid",
        EXPECTED_PACKET_CONTENT_SHA256,
    )
    summary = packet.get("decision_summary")
    if (
        packet.get("schema") != "legalbot.v111.phase2a.exact-remediation-owner-packet.v1"
        or packet.get("status") != "EXACT_361_OWNER_DECISIONS_READY_NOT_ADOPTED"
        or packet.get("route") != "OWNER_ADOPTED_INTERNAL_PRIVATE_RESEARCH_TOOL"
        or not isinstance(summary, Mapping)
        or summary.get("decision_count") != 361
        or summary.get("unique_row_count") != 361
        or summary.get("research_decision_count") != 316
        or summary.get("direct_exact_span_decision_count") != 45
        or summary.get("proposed_new_source_admission_count") != 247
        or summary.get("representation_bound_source_admission_count") != 247
        or summary.get("quarantine_source_admission_hold_count") != 31
        or summary.get("source_identity_anomaly_hold_count") != 86
        or summary.get("collector_fetch_eligible_identity_count") != 278
        or summary.get("collector_fetch_eligible_identity_set_sha256")
        != EXPECTED_FETCH_IDENTITY_SET_SHA256
        or summary.get("builder_proposal_identity_set_sha256") != EXPECTED_FETCH_IDENTITY_SET_SHA256
        or summary.get("collector_builder_proposal_identity_set_equal") is not True
    ):
        raise ValueError("phase2a_owner_adoption_packet_inventory_invalid")
    _require_false_flags(
        packet,
        _PACKET_REQUIRED_FALSE_FLAGS,
        "phase2a_owner_adoption_packet_boundary_invalid",
    )

    decisions = _verify_item_seals(
        packet.get("decisions"),
        count=361,
        seal_field="decision_content_sha256",
        id_field="row_id",
        code="phase2a_owner_adoption_decision_inventory_invalid",
    )
    proposals = _verify_item_seals(
        packet.get("proposed_new_source_admissions"),
        count=247,
        seal_field="proposal_content_sha256",
        id_field="proposal_id",
        code="phase2a_owner_adoption_source_proposal_inventory_invalid",
    )
    quarantine_holds = _verify_item_seals(
        packet.get("quarantine_source_admission_holds"),
        count=31,
        seal_field="hold_content_sha256",
        id_field="hold_id",
        code="phase2a_owner_adoption_quarantine_hold_inventory_invalid",
    )
    identity_holds = _verify_item_seals(
        packet.get("source_identity_and_admission_holds"),
        count=86,
        seal_field="anomaly_content_sha256",
        id_field="anomaly_id",
        code="phase2a_owner_adoption_identity_hold_inventory_invalid",
    )

    for decision in decisions:
        if (
            decision.get("owner_decision_required") is not True
            or decision.get("owner_outcome") is not None
            or not decision.get("recommended_owner_outcome")
            or decision.get("source_admission_authorized") is not False
            or decision.get("source_admitted") is not False
            or decision.get("candidate_mutated") is not False
            or decision.get("technical_qualification_assigned") is not False
        ):
            raise ValueError("phase2a_owner_adoption_decision_boundary_invalid")
    for proposal in proposals:
        if (
            proposal.get("recommended_owner_outcome")
            != "ADMIT_PROPOSITION_LEVEL_OFFICIAL_SOURCE_WITH_ALL_LISTED_HOLDS_RETAINED"
            or proposal.get("owner_outcome") is not None
            or proposal.get("owner_source_admission_required") is not True
            or proposal.get("representation_binding_complete") is not True
            or proposal.get("source_admission_authorized") is not False
            or proposal.get("source_admitted") is not False
            or proposal.get("automatic_indexing") is not False
            or proposal.get("automatic_embedding") is not False
            or proposal.get("candidate_mutated") is not False
        ):
            raise ValueError("phase2a_owner_adoption_source_proposal_boundary_invalid")
    for hold in quarantine_holds:
        if (
            hold.get("recommended_owner_outcome")
            != "RETAIN_QUARANTINE_REPRESENTATION_SET_HOLD_NO_SOURCE_ADMISSION"
            or hold.get("owner_outcome") is not None
            or hold.get("source_admission_authorized") is not False
            or hold.get("source_admitted") is not False
            or hold.get("automatic_indexing") is not False
            or hold.get("automatic_embedding") is not False
            or hold.get("candidate_mutated") is not False
        ):
            raise ValueError("phase2a_owner_adoption_quarantine_hold_boundary_invalid")
    for hold in identity_holds:
        if (
            hold.get("recommended_owner_outcome")
            != "RETAIN_TECHNICAL_SOURCE_IDENTITY_METADATA_OR_ADMISSION_HOLD"
            or hold.get("owner_outcome") is not None
            or hold.get("source_admission_authorized") is not False
            or hold.get("source_admitted") is not False
            or hold.get("automatic_indexing") is not False
            or hold.get("automatic_embedding") is not False
            or hold.get("candidate_mutated") is not False
        ):
            raise ValueError("phase2a_owner_adoption_identity_hold_boundary_invalid")
    return packet


def _verify_quarantine(
    quarantine_root: Path,
    *,
    packet: Mapping[str, Any],
) -> dict[str, Any]:
    if quarantine_root.is_symlink() or not quarantine_root.is_dir():
        raise ValueError("phase2a_owner_adoption_quarantine_root_invalid")
    manifest_path = quarantine_root / QUARANTINE_MANIFEST_NAME
    if (
        manifest_path.is_symlink()
        or not manifest_path.is_file()
        or _sha256_file(manifest_path) != EXPECTED_QUARANTINE_FILE_SHA256
    ):
        raise ValueError("phase2a_owner_adoption_quarantine_file_digest_invalid")
    manifest = _load_object(
        manifest_path,
        code="phase2a_owner_adoption_quarantine_manifest_invalid",
    )
    _verify_seal(
        manifest,
        "manifest_content_sha256",
        "phase2a_owner_adoption_quarantine_content_digest_invalid",
        EXPECTED_QUARANTINE_CONTENT_SHA256,
    )
    interface = manifest.get("packet_builder_interface")
    if (
        manifest.get("schema") != "legalbot.v111.phase2a.research-wave-quarantine-binding.v2"
        or manifest.get("status") != "QUARANTINE_BINDINGS_CREATED_NOT_ADMITTED"
        or manifest.get("collection_record_count") != 282
        or manifest.get("fetch_eligible_identity_count") != 278
        or manifest.get("fetch_eligible_identity_set_sha256") != EXPECTED_FETCH_IDENTITY_SET_SHA256
        or manifest.get("held_selected_binding_count") != 2
        or not isinstance(interface, Mapping)
        or interface.get("manifest_digest_field") != "manifest_content_sha256"
        or interface.get("record_digest_field") != "record_content_sha256"
    ):
        raise ValueError("phase2a_owner_adoption_quarantine_boundary_invalid")
    _require_false_flags(
        manifest,
        (
            "owner_decisions_applied",
            "source_admission_authorized",
            "source_admitted",
            "catalogue_mutated",
            "source_scan_run",
            "index_built",
            "embedding_run",
            "automatic_indexing",
            "automatic_embedding",
            "candidate_mutated",
            "phase2b_authorized",
            "development30_authorized",
            "validation30_authorized",
            "promotion_authorized",
            "active_pointer_write_authorized",
            "previous_pointer_write_authorized",
            "live_activation_authorized",
            "training_export_authorized",
        ),
        "phase2a_owner_adoption_quarantine_boundary_invalid",
    )

    records = manifest.get("records")
    selected = manifest.get("selected_admission_bindings")
    authority_holds = manifest.get("authority_collection_holds")
    if (
        not isinstance(records, list)
        or len(records) != 282
        or not isinstance(selected, list)
        or len(selected) != 247
        or not isinstance(authority_holds, list)
        or len(authority_holds) != 31
    ):
        raise ValueError("phase2a_owner_adoption_quarantine_inventory_invalid")

    records_by_id: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("phase2a_owner_adoption_quarantine_record_invalid")
        _verify_seal(
            record,
            "record_content_sha256",
            "phase2a_owner_adoption_quarantine_record_seal_invalid",
        )
        record_id = str(record.get("record_id") or "")
        if not record_id or record_id in records_by_id:
            raise ValueError("phase2a_owner_adoption_quarantine_record_invalid")
        records_by_id[record_id] = record

    selected_by_id: dict[str, dict[str, Any]] = {}
    for binding in selected:
        if not isinstance(binding, dict):
            raise ValueError("phase2a_owner_adoption_selected_binding_invalid")
        record_id = str(binding.get("record_id") or "")
        record = records_by_id.get(record_id)
        if not record_id or record_id in selected_by_id or record is None:
            raise ValueError("phase2a_owner_adoption_selected_binding_invalid")
        if (
            binding.get("selected_for_proposed_admission") is not True
            or binding.get("eligible_for_owner_packet") is not True
            or binding.get("authority_representation_set_complete") is not True
            or binding.get("representation_role") != "PROPOSED_ADMISSION_REPRESENTATION"
            or record.get("result") != "DOWNLOADED_QUARANTINED_BOUND"
            or record.get("hold_reason_codes") not in ([], ())
        ):
            raise ValueError("phase2a_owner_adoption_selected_binding_invalid")
        for field in binding:
            if field not in {
                "authority_representation_set_complete",
                "eligible_for_owner_packet",
            } and binding.get(field) != record.get(field):
                raise ValueError("phase2a_owner_adoption_selected_binding_invalid")

        member = str(binding.get("quarantine_member") or "")
        if (
            not member
            or Path(member).name != member
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,200}", member) is None
        ):
            raise ValueError("phase2a_owner_adoption_quarantine_member_invalid")
        member_path = quarantine_root / member
        if member_path.is_symlink() or not member_path.is_file():
            raise ValueError("phase2a_owner_adoption_quarantine_member_invalid")
        raw_sha256 = str(binding.get("raw_sha256") or "")
        if (
            _SHA256.fullmatch(raw_sha256) is None
            or _sha256_file(member_path) != raw_sha256
            or member_path.stat().st_size != binding.get("bytes")
        ):
            raise ValueError("phase2a_owner_adoption_quarantine_member_digest_invalid")
        version_material = {
            "authority_identity_id": binding.get("authority_identity_id"),
            "raw_sha256": raw_sha256,
            "canonical_content_sha256": binding.get("canonical_content_sha256"),
        }
        expected_version_id = "proposed-source-version-" + _sealed(version_material)[:40]
        supplied_version_id = str(binding.get("proposed_source_version_id") or "")
        if (
            _SOURCE_VERSION_ID.fullmatch(supplied_version_id) is None
            or supplied_version_id != expected_version_id
        ):
            raise ValueError("phase2a_owner_adoption_source_version_identity_invalid")
        selected_by_id[record_id] = binding

    packet_proposals = packet.get("proposed_new_source_admissions")
    assert isinstance(packet_proposals, list)
    packet_record_ids: set[str] = set()
    for proposal in packet_proposals:
        representation = proposal.get("quarantine_representation_binding")
        if not isinstance(representation, Mapping):
            raise ValueError("phase2a_owner_adoption_packet_representation_invalid")
        packet_binding = representation.get("selected_admission_binding")
        if not isinstance(packet_binding, Mapping):
            raise ValueError("phase2a_owner_adoption_packet_representation_invalid")
        record_id = str(packet_binding.get("record_id") or "")
        if (
            record_id in packet_record_ids
            or selected_by_id.get(record_id) != packet_binding
            or representation.get("manifest_content_sha256") != EXPECTED_QUARANTINE_CONTENT_SHA256
            or representation.get("manifest_file_sha256") != EXPECTED_QUARANTINE_FILE_SHA256
            or representation.get("manifest_path")
            != (
                "data/evaluations/phase2a-owner-review/"
                "LegalBot-Phase2A-2026-08-28-source-quarantine/"
                "QUARANTINE-MANIFEST.json"
            )
        ):
            raise ValueError("phase2a_owner_adoption_packet_representation_invalid")
        packet_record_ids.add(record_id)
    if packet_record_ids != set(selected_by_id):
        raise ValueError("phase2a_owner_adoption_packet_representation_set_invalid")

    authority_holds_by_key: dict[str, dict[str, Any]] = {}
    for hold in authority_holds:
        if not isinstance(hold, dict):
            raise ValueError("phase2a_owner_adoption_authority_hold_invalid")
        _verify_seal(
            hold,
            "hold_content_sha256",
            "phase2a_owner_adoption_authority_hold_seal_invalid",
        )
        key = str(hold.get("authority_identity_id") or "")
        if not key or key in authority_holds_by_key:
            raise ValueError("phase2a_owner_adoption_authority_hold_invalid")
        authority_holds_by_key[key] = hold
    packet_holds = packet.get("quarantine_source_admission_holds")
    assert isinstance(packet_holds, list)
    packet_hold_keys: set[str] = set()
    for hold in packet_holds:
        authority_hold = hold.get("authority_collection_hold")
        if not isinstance(authority_hold, Mapping):
            raise ValueError("phase2a_owner_adoption_packet_hold_binding_invalid")
        key = str(authority_hold.get("authority_identity_id") or "")
        if key in packet_hold_keys or authority_holds_by_key.get(key) != authority_hold:
            raise ValueError("phase2a_owner_adoption_packet_hold_binding_invalid")
        packet_hold_keys.add(key)
    if packet_hold_keys != set(authority_holds_by_key):
        raise ValueError("phase2a_owner_adoption_packet_hold_set_invalid")
    return manifest


def _sealed_artifact(schema: str, material: Mapping[str, Any]) -> dict[str, Any]:
    payload = {"schema": schema, **material}
    return {**payload, "artifact_content_sha256": _sealed(payload)}


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


def _authorization_and_execution_boundaries() -> dict[str, Any]:
    return {
        "owner_decision_application_authorized": True,
        "source_admission_authorized": True,
        "complete_source_scan_authorized": True,
        "successor_build_authorized": True,
        "index_build_authorized": True,
        "embedding_authorized": True,
        "qualification_authorized": True,
        "retrieval_reattestation_authorized": True,
        "all585_qualification_authorized": True,
        "owner_decisions_applied": False,
        "owner_outcomes_applied": False,
        "source_admitted": False,
        "source_scan_run": False,
        "successor_build_run": False,
        "index_built": False,
        "embedding_run": False,
        "retrieval_reattestation_run": False,
        "all585_qualification_run": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        **_PROHIBITED_FALSE_FLAGS,
    }


def record_owner_adoption(
    *,
    packet_root: Path,
    quarantine_root: Path,
    output_root: Path,
    owner_reply: str,
    owner_typed_name: str,
    owner_decision_date: str,
    recorded_at: datetime | None = None,
) -> dict[str, Any]:
    """Verify and record the exact adoption without applying its scope."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_owner_adoption_output_already_exists")
    if _normalize_owner_reply(owner_reply) != _normalize_owner_reply(EXPECTED_OWNER_REPLY):
        raise ValueError("phase2a_owner_adoption_owner_reply_not_exact")
    if owner_typed_name != EXPECTED_OWNER_TYPED_NAME:
        raise ValueError("phase2a_owner_adoption_owner_name_not_exact")
    try:
        parsed_date = date.fromisoformat(owner_decision_date)
    except ValueError as exc:
        raise ValueError("phase2a_owner_adoption_owner_date_invalid") from exc
    if parsed_date.isoformat() != EXPECTED_OWNER_DECISION_DATE:
        raise ValueError("phase2a_owner_adoption_owner_date_not_exact")
    timestamp = recorded_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("phase2a_owner_adoption_recorded_at_must_be_aware")

    packet = _verify_source_package(packet_root)
    _verify_quarantine(quarantine_root, packet=packet)

    verbatim_raw = owner_reply.encode("utf-8")
    source_bindings = {
        "owner_packet": {
            "file_name": PACKET_NAME,
            "content_sha256": EXPECTED_PACKET_CONTENT_SHA256,
            "file_sha256": EXPECTED_PACKET_FILE_SHA256,
        },
        "owner_packet_package": {
            "file_name": SOURCE_PACKAGE_NAME,
            "content_sha256": EXPECTED_PACKAGE_CONTENT_SHA256,
            "file_sha256": EXPECTED_PACKAGE_FILE_SHA256,
        },
        "owner_approval_prompt": {
            "file_name": SOURCE_PROMPT_NAME,
            "file_sha256": EXPECTED_PROMPT_FILE_SHA256,
        },
        "owner_packet_checksums": {
            "file_name": SOURCE_CHECKSUMS_NAME,
            "file_sha256": EXPECTED_CHECKSUMS_FILE_SHA256,
        },
        "quarantine_manifest": {
            "file_name": QUARANTINE_MANIFEST_NAME,
            "content_sha256": EXPECTED_QUARANTINE_CONTENT_SHA256,
            "file_sha256": EXPECTED_QUARANTINE_FILE_SHA256,
        },
    }
    boundaries = _authorization_and_execution_boundaries()
    audit_hold = {
        "required": True,
        "status": "POST_APPROVAL_SUBSTANTIVE_CONTENT_BINDING_AUDIT_REQUIRED",
        "scope": "ALL_247_SEALED_PROPOSED_SOURCE_REPRESENTATIONS",
        "purpose": (
            "Confirm that each sealed representation contains the intended "
            "substantive official legal content, not merely a loader, shell, "
            "navigation page or other non-substantive response."
        ),
        "owner_packet_or_quarantine_bytes_may_be_silently_replaced": False,
        "changed_raw_bytes_require_new_exact_owner_adoption": True,
        "authorized_phase2a_execution_eligible": False,
        "owner_decisions_may_be_applied_before_audit_pass": False,
        "sources_may_be_admitted_before_audit_pass": False,
        "scan_build_or_embedding_may_run_before_audit_pass": False,
    }
    receipt_material = {
        "status": STATUS,
        "recorded_at": timestamp.astimezone(UTC).isoformat(),
        "owner_typed_name": owner_typed_name,
        "owner_decision_date": owner_decision_date,
        "owner_approved": True,
        "owner_adoption_recorded": True,
        "owner_reply_verbatim_file": VERBATIM_NAME,
        "owner_reply_verbatim_file_sha256": _sha256(verbatim_raw),
        "owner_reply_normalized_sha256": EXPECTED_NORMALIZED_OWNER_REPLY_SHA256,
        "source_bindings": source_bindings,
        "authorized_exact_scope": {
            "owner_decision_count": 361,
            "proposed_source_admission_count": 247,
            "retained_quarantine_source_admission_hold_count": 31,
            "retained_source_identity_and_admission_hold_count": 86,
            "complete_source_scan_maximum_count": 1,
            "successor_candidate_build_with_embedding_maximum_count": 1,
            "successor_must_remain_non_active": True,
            "successor_must_remain_answer_ineligible": True,
            "qualification_stop_on_any_material_gap": True,
            "qualification_stop_on_any_unresolved_owner_decision": True,
        },
        "technical_source_binding_hold": True,
        "post_approval_content_audit": audit_hold,
        **boundaries,
    }
    receipt = _sealed_artifact(
        "legalbot.v111.phase2a.exact-remediation-owner-adoption-receipt.v1",
        receipt_material,
    )
    receipt_raw = _pretty_json(receipt)

    outcome = _sealed_artifact(
        "legalbot.v111.phase2a.exact-remediation-owner-adoption-outcome.v1",
        {
            "status": STATUS,
            "owner_adoption_receipt_content_sha256": receipt["artifact_content_sha256"],
            "owner_adoption_receipt_file_sha256": _sha256(receipt_raw),
            "owner_adoption_recorded": True,
            "technical_source_binding_hold": True,
            "post_approval_content_audit_required": True,
            "next_required_action": (
                "COMPLETE_AND_SEAL_POST_APPROVAL_SUBSTANTIVE_CONTENT_BINDING_AUDIT"
            ),
            "successful_phase2a_package_claimed": False,
            **boundaries,
        },
    )
    outcome_raw = _pretty_json(outcome)

    artifacts = {
        RECEIPT_NAME: receipt_raw,
        VERBATIM_NAME: verbatim_raw,
        OUTCOME_NAME: outcome_raw,
    }
    package = _sealed_artifact(
        "legalbot.v111.phase2a.exact-remediation-owner-adoption-package.v1",
        {
            "status": STATUS,
            "source_owner_packet_content_sha256": EXPECTED_PACKET_CONTENT_SHA256,
            "owner_adoption_receipt_content_sha256": receipt["artifact_content_sha256"],
            "owner_adoption_outcome_content_sha256": outcome["artifact_content_sha256"],
            "artifacts": [
                {"name": name, "file_sha256": _sha256(raw)}
                for name, raw in sorted(artifacts.items())
            ],
            "technical_source_binding_hold": True,
            "post_approval_content_audit_required": True,
            **boundaries,
        },
    )
    package_raw = _pretty_json(package)
    artifacts[PACKAGE_NAME] = package_raw
    checksums_raw = "".join(
        f"{_sha256(raw)}  {name}\n" for name, raw in sorted(artifacts.items())
    ).encode("utf-8")

    output_root.parent.mkdir(parents=True, exist_ok=True)
    output_root.mkdir(mode=0o700)
    try:
        for name, raw in sorted(artifacts.items()):
            _write_exclusive(output_root / name, raw)
        _write_exclusive(output_root / CHECKSUMS_NAME, checksums_raw)
        os.chmod(output_root, 0o700)
        for path in output_root.iterdir():
            os.chmod(path, 0o600)
    except BaseException:
        for path in output_root.iterdir():
            if path.is_file() and not path.is_symlink():
                path.unlink()
        output_root.rmdir()
        raise

    return {
        "status": STATUS,
        "output_root": str(output_root),
        "owner_adoption_receipt_content_sha256": receipt["artifact_content_sha256"],
        "owner_adoption_receipt_file_sha256": _sha256(receipt_raw),
        "package_content_sha256": package["artifact_content_sha256"],
        "package_file_sha256": _sha256(package_raw),
        "owner_decisions_applied": False,
        "source_admitted": False,
        "source_scan_run": False,
        "successor_build_run": False,
        "embedding_run": False,
        "post_approval_content_audit_required": True,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-root", type=Path, default=DEFAULT_PACKET_ROOT)
    parser.add_argument("--quarantine-root", type=Path, default=DEFAULT_QUARANTINE_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--owner-reply-file", type=Path, required=True)
    parser.add_argument("--owner-typed-name", required=True)
    parser.add_argument("--owner-decision-date", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    reply_path = args.owner_reply_file
    if reply_path.is_symlink() or not reply_path.is_file():
        raise ValueError("phase2a_owner_adoption_owner_reply_file_invalid")
    result = record_owner_adoption(
        packet_root=args.packet_root.resolve(strict=True),
        quarantine_root=args.quarantine_root.resolve(strict=True),
        output_root=args.output_root.resolve(strict=False),
        owner_reply=reply_path.read_text(encoding="utf-8"),
        owner_typed_name=args.owner_typed_name,
        owner_decision_date=args.owner_decision_date,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
