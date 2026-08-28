#!/usr/bin/env python3
"""Seal the exact final Phase-2A remediation owner adoption, create-only.

The command verifies the immutable combined owner packet and the original
unspent Phase-2A authority receipt before writing a private adoption receipt.
It does not apply a decision, materialize a source, scan, build, embed,
qualify, invoke a model, or write ACTIVE/PREVIOUS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
PACKET_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-delta-safe-fallback-owner-packet-r1"
ORIGINAL_APPROVAL_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-approved-r1"
)
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-final-remediation-owner-approved-r1"
)

PACKET_NAME = "EXACT-PHASE2A-SOURCE-DELTA-SAFE-FALLBACK-OWNER-PACKET.json"
PACKET_PACKAGE_NAME = "PACKAGE-MANIFEST.json"
PACKET_PROMPT_NAME = "OWNER-APPROVAL-PROMPT.txt"
PACKET_CHECKSUMS_NAME = "SHA256SUMS.txt"
ORIGINAL_RECEIPT_NAME = "OWNER-ADOPTION-RECEIPT.json"
ORIGINAL_OUTCOME_NAME = "OWNER-ADOPTION-OUTCOME.json"
ORIGINAL_PACKAGE_NAME = "PACKAGE-MANIFEST.json"

RECEIPT_NAME = "OWNER-ADOPTION-RECEIPT.json"
OUTCOME_NAME = "OWNER-ADOPTION-OUTCOME.json"
AUTHORITY_STATE_NAME = "PHASE2A-EXECUTION-AUTHORITY.json"
VERBATIM_NAME = "OWNER-APPROVAL-VERBATIM.txt"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

EXPECTED_PACKET_CONTENT_SHA256 = "fd8034b33ebfb0f6fdd6cedd2426b54e368bff9c20b408f3fbd86fb40b9f1b34"
EXPECTED_PACKET_FILE_SHA256 = "8ef85082a8d723ca1396f0c03c244f673a3e775bd0e4b336b443228a3a012341"
EXPECTED_PACKET_PACKAGE_CONTENT_SHA256 = (
    "da5287e93866a547aab1de5bdad121093ff2e7b6ea5f988c4db7a5ac426f4e3f"
)
EXPECTED_PACKET_PACKAGE_FILE_SHA256 = (
    "45e16c47cbd557aed80d77f75ae85372eb7b4e47d58edc7a115a6ba84cebdf9b"
)
EXPECTED_PACKET_PROMPT_FILE_SHA256 = (
    "cc5db746ad161fcd1426108831dedfd3cb5d79841bf99350ed7440d084e91cd4"
)
EXPECTED_PACKET_CHECKSUMS_FILE_SHA256 = (
    "147af38ca7e352c97b63d3904f4f9a506a5d67c3c139a6237b870d639a84bfd2"
)
EXPECTED_ORIGINAL_RECEIPT_CONTENT_SHA256 = (
    "a6ea2794b276946dd24ba3d752203dd81ae14f88aae24224a80b7b62f886d539"
)
EXPECTED_ORIGINAL_RECEIPT_FILE_SHA256 = (
    "ffb2d07c8f6f5d2f44fb78efa01e58a49c7bd79ff1fcb18e74c9ee63bd5f3743"
)
EXPECTED_ORIGINAL_OUTCOME_CONTENT_SHA256 = (
    "fc77c2c63d844c154600810c7014a26bacc12ce41ce705a8946c655cc0f1d978"
)
EXPECTED_ORIGINAL_OUTCOME_FILE_SHA256 = (
    "062acfb08f7af52e2c1c79658205b6a2f46ceb62b4fb2c4228ea208114a4dde2"
)
EXPECTED_ORIGINAL_PACKAGE_CONTENT_SHA256 = (
    "414d848314861662c1b818105a06eef51db6c353b396dbd13001bb514efb8bd5"
)
EXPECTED_ORIGINAL_PACKAGE_FILE_SHA256 = (
    "fab2e99a0b988c1d7f9d62e8a0c8d827bf7c7afdce6405d00f2d22a476f71a29"
)

EXPECTED_OWNER_TYPED_NAME = "Agnes"
EXPECTED_OWNER_DECISION_DATE = "2026-08-28"
EXPECTED_OWNER_REPLY = """I approve exact Phase-2A final remediation owner packet content SHA-256
`fd8034b33ebfb0f6fdd6cedd2426b54e368bff9c20b408f3fbd86fb40b9f1b34` and every recommendation and retained hold it contains.
I adopt every source decision and retained hold bound by source-binding delta packet `01312e142dd084271aa005b3d2a5ba8b93564bf3a841e1f5a4ec68c06a604ac0`, subject only to the explicit supersessions in this combined packet. For the 15 FCA representations, the raw JSON remains immutable provenance but is not the index-admission representation; I admit only the 15 exact parser-compatible canonical-Markdown derivatives bound by manifest `40bf47ebd133b912be63adabe70b1d58c7fc2a31c78ea174ea6823960dd2abf4`.
I adopt fallback coverage advisory `035316cac6f9559744400bc9db7c05bdf74a85c7d120c59eae5cfc41f0462af8` and only its exact two eligible rows. `live60-q58:issue-14` remains in all-585 and may pass only under exact contract `ba6c131f06e05bed9f6b6aa5743dc974f3b13618e3af39ffcaaabaf0f84c72f6`. `live60-q58:issue-09` remains in all-585 and may pass only under exact no-legal-claim contract `91cbb05fad64d2e26d11e75ff8adbe1b1b9d7fc300abea6785630078e5d2036e`. Each must return its exact byte-for-byte insufficiency response, request every listed document or fact, emit `knowledge_gap_event=false` and `matter_information_gap_event=true`, and offer qualified human legal review. Neither may release a legal rule, advice, citation, EvidenceSpan, source binding or answer-model output. No other row is fallback-eligible.
I adopt the held-nine advisory `599d7175005c8978757611be0ce837299845c142147ec02828f53ee7620e75fd` as the fail-closed baseline, then adopt only the exact superseding source sets in ECHR recovery manifest `f5beba682a629d3a6e0e79be374c0d2a3d6690d45abe467fa40f67879dcb0142` and q53 Semenya advisory `fea6a74301ba629c03a1813dbc45d83ee030c25d0c53194c0129fd4515adb814`. I admit the exact KlimaSeniorinnen and Big Brother Watch raw/canonical representations, adopt the exact existing Goodwin quarantine binding, admit the exact Semenya raw/canonical representations, and adopt the exact revised proposition sets and locators listed for the eight affected rows. The unavailable Mutu/Pechstein representation, its historical CAS-independence and Pechstein public-hearing-result claims, and every other excluded component remain excluded. Semenya must not be described as a disciplinary case; R57 alone supplies the listed current disciplinary public-hearing mechanics. All currentness, later-treatment, citation, EvidenceSpan and answer-release holds remain. The Mutu network path remains permanently stopped, and the held Ali Riza source is not required or retried.
I confirm that original owner-adoption receipt `a6ea2794b276946dd24ba3d752203dd81ae14f88aae24224a80b7b62f886d539` has one total unspent Phase-2A execution chain. After this exact combined packet is adopted, Codex may use that one existing chain to apply these exact decisions, materialize only the exact adopted representations, run one complete source scan, build and embed one non-ACTIVE and answer-ineligible successor, run one retrieval re-attestation, and run one all-585 technical qualification. This does not create a second or additional scan, build, embedding, retrieval or qualification authority.
The packet and its builder have not themselves applied a decision, admitted or materialized a source, scanned, indexed, embedded, built or qualified anything. Technical success is not predeclared: if retrieval re-attestation or all-585 finds any material gap, unresolved owner decision or contract violation, the workflow must stop and report it. This approval does not authorize an answer-model run or answer release, Phase 2B, Development 30, Validation 30, Owner Certification 60, promotion, ACTIVE/PREVIOUS writes, live activation or training export.
Owner typed name: Agnes
Decision date: 2026-08-28"""

STATUS = "FINAL_REMEDIATION_OWNER_ADOPTION_RECORDED_EXECUTION_CHAIN_AVAILABLE"
CHAIN_STATUS = "AVAILABLE_UNSPENT"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_PROHIBITED_FALSE_FLAGS = (
    "answer_model_authorized",
    "answer_model_run",
    "answer_release_authorized",
    "answer_release_run",
    "answer_released",
    "phase2b_authorized",
    "phase2b_run",
    "development30_authorized",
    "development30_run",
    "owner_certification60_authorized",
    "owner_certification60_run",
    "o04_authorized",
    "o04_run",
    "validation30_authorized",
    "validation30_run",
    "validation30_unsealed",
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
_UNSPENT_STAGE_FLAGS = (
    "owner_decisions_applied",
    "owner_outcomes_applied",
    "source_admitted",
    "source_scan_run",
    "successor_build_run",
    "index_built",
    "embedding_run",
    "retrieval_reattestation_run",
    "all585_qualification_run",
    "candidate_mutated",
    "technical_qualification_assigned",
)


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


def _sealed(value: Mapping[str, Any]) -> str:
    return _sha256(_canonical_json(value))


def _load_object(path: Path, *, code: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(code)
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(code)
    return value


def _verify_seal(value: Mapping[str, Any], field: str, *, expected: str, code: str) -> None:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if supplied != expected or supplied != _sealed(material):
        raise ValueError(code)


def _require_exact_file(path: Path, expected: str, *, code: str) -> None:
    if path.is_symlink() or not path.is_file() or _sha256_file(path) != expected:
        raise ValueError(code)


def _normalize_owner_reply(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("\r\n", "\n")).strip()


EXPECTED_NORMALIZED_OWNER_REPLY_SHA256 = _sha256(
    _normalize_owner_reply(EXPECTED_OWNER_REPLY).encode("utf-8")
)


def _verify_packet_root(packet_root: Path) -> dict[str, Any]:
    if packet_root.is_symlink() or not packet_root.is_dir():
        raise ValueError("phase2a_final_adoption_packet_root_invalid")
    expected_files = {
        PACKET_NAME: EXPECTED_PACKET_FILE_SHA256,
        PACKET_PACKAGE_NAME: EXPECTED_PACKET_PACKAGE_FILE_SHA256,
        PACKET_PROMPT_NAME: EXPECTED_PACKET_PROMPT_FILE_SHA256,
        PACKET_CHECKSUMS_NAME: EXPECTED_PACKET_CHECKSUMS_FILE_SHA256,
    }
    if {path.name for path in packet_root.iterdir()} != set(expected_files):
        raise ValueError("phase2a_final_adoption_packet_inventory_invalid")
    for name, digest in expected_files.items():
        _require_exact_file(
            packet_root / name,
            digest,
            code="phase2a_final_adoption_packet_file_digest_invalid",
        )
    expected_checksums = "".join(
        f"{digest}  {name}\n"
        for name, digest in sorted(
            {
                PACKET_NAME: EXPECTED_PACKET_FILE_SHA256,
                PACKET_PACKAGE_NAME: EXPECTED_PACKET_PACKAGE_FILE_SHA256,
                PACKET_PROMPT_NAME: EXPECTED_PACKET_PROMPT_FILE_SHA256,
            }.items()
        )
    )
    if (packet_root / PACKET_CHECKSUMS_NAME).read_text() != expected_checksums:
        raise ValueError("phase2a_final_adoption_packet_checksums_invalid")

    packet = _load_object(packet_root / PACKET_NAME, code="phase2a_final_adoption_packet_invalid")
    _verify_seal(
        packet,
        "artifact_content_sha256",
        expected=EXPECTED_PACKET_CONTENT_SHA256,
        code="phase2a_final_adoption_packet_seal_invalid",
    )
    authority = packet.get("single_remaining_phase2a_execution_authority")
    if (
        packet.get("schema") != "legalbot.v111.phase2a.source-delta-safe-fallback-owner-packet.v1"
        or packet.get("status") != "EXACT_PHASE2A_SOURCE_DELTA_SAFE_FALLBACK_READY_NOT_ADOPTED"
        or not isinstance(authority, Mapping)
        or authority.get("authority_origin_owner_receipt_content_sha256")
        != EXPECTED_ORIGINAL_RECEIPT_CONTENT_SHA256
        or authority.get("authority_consumed_before_this_packet") is not False
        or authority.get("total_remaining_execution_chain_count") != 1
        or authority.get("new_or_additional_execution_authority_created_by_this_packet")
        is not False
        or authority.get("second_scan_build_or_embedding_authority_created") is not False
    ):
        raise ValueError("phase2a_final_adoption_packet_authority_boundary_invalid")

    package = _load_object(
        packet_root / PACKET_PACKAGE_NAME,
        code="phase2a_final_adoption_packet_package_invalid",
    )
    _verify_seal(
        package,
        "artifact_content_sha256",
        expected=EXPECTED_PACKET_PACKAGE_CONTENT_SHA256,
        code="phase2a_final_adoption_packet_package_seal_invalid",
    )
    if (
        package.get("packet_content_sha256") != EXPECTED_PACKET_CONTENT_SHA256
        or package.get("new_exact_owner_adoption_required") is not True
        or package.get("packet_builder_effect") != "CREATE_ONLY_NO_EXECUTION"
    ):
        raise ValueError("phase2a_final_adoption_packet_package_boundary_invalid")
    return packet


def _verify_original_chain_unspent(original_root: Path) -> dict[str, Any]:
    if original_root.is_symlink() or not original_root.is_dir():
        raise ValueError("phase2a_final_adoption_original_root_invalid")
    expected = {
        ORIGINAL_RECEIPT_NAME: EXPECTED_ORIGINAL_RECEIPT_FILE_SHA256,
        ORIGINAL_OUTCOME_NAME: EXPECTED_ORIGINAL_OUTCOME_FILE_SHA256,
        ORIGINAL_PACKAGE_NAME: EXPECTED_ORIGINAL_PACKAGE_FILE_SHA256,
    }
    for name, digest in expected.items():
        _require_exact_file(
            original_root / name,
            digest,
            code="phase2a_final_adoption_original_artifact_digest_invalid",
        )
    receipt = _load_object(
        original_root / ORIGINAL_RECEIPT_NAME,
        code="phase2a_final_adoption_original_receipt_invalid",
    )
    outcome = _load_object(
        original_root / ORIGINAL_OUTCOME_NAME,
        code="phase2a_final_adoption_original_outcome_invalid",
    )
    package = _load_object(
        original_root / ORIGINAL_PACKAGE_NAME,
        code="phase2a_final_adoption_original_package_invalid",
    )
    _verify_seal(
        receipt,
        "artifact_content_sha256",
        expected=EXPECTED_ORIGINAL_RECEIPT_CONTENT_SHA256,
        code="phase2a_final_adoption_original_receipt_seal_invalid",
    )
    _verify_seal(
        outcome,
        "artifact_content_sha256",
        expected=EXPECTED_ORIGINAL_OUTCOME_CONTENT_SHA256,
        code="phase2a_final_adoption_original_outcome_seal_invalid",
    )
    _verify_seal(
        package,
        "artifact_content_sha256",
        expected=EXPECTED_ORIGINAL_PACKAGE_CONTENT_SHA256,
        code="phase2a_final_adoption_original_package_seal_invalid",
    )
    values = (receipt, outcome, package)
    if any(
        any(value.get(field) is not False for field in _UNSPENT_STAGE_FLAGS) for value in values
    ):
        raise ValueError("phase2a_final_adoption_execution_chain_already_spent")
    if any(
        any(value.get(field) is not False for field in _PROHIBITED_FALSE_FLAGS) for value in values
    ):
        raise ValueError("phase2a_final_adoption_prohibited_authority_present")
    if (
        receipt.get("owner_decision_application_authorized") is not True
        or receipt.get("complete_source_scan_authorized") is not True
        or receipt.get("successor_build_authorized") is not True
        or receipt.get("embedding_authorized") is not True
        or receipt.get("retrieval_reattestation_authorized") is not True
        or receipt.get("all585_qualification_authorized") is not True
        or receipt.get("authorized_exact_scope", {}).get("complete_source_scan_maximum_count") != 1
        or receipt.get("authorized_exact_scope", {}).get(
            "successor_candidate_build_with_embedding_maximum_count"
        )
        != 1
    ):
        raise ValueError("phase2a_final_adoption_original_authority_invalid")
    return receipt


def _boundaries() -> dict[str, Any]:
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
        **{field: False for field in _PROHIBITED_FALSE_FLAGS},
    }


def _artifact(schema: str, material: Mapping[str, Any]) -> dict[str, Any]:
    value = {"schema": schema, **material}
    return {**value, "artifact_content_sha256": _sealed(value)}


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _publish_noreplace(staging: Path, output: Path) -> None:
    try:
        os.rename(staging, output)
    except FileExistsError as exc:
        raise ValueError("phase2a_final_adoption_output_already_exists") from exc


def record_owner_adoption(
    *,
    packet_root: Path,
    original_approval_root: Path,
    output_root: Path,
    owner_reply: str,
    owner_typed_name: str,
    owner_decision_date: str,
    recorded_at: datetime | None = None,
) -> dict[str, Any]:
    """Record the exact owner adoption without consuming its execution chain."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_final_adoption_output_already_exists")
    if _normalize_owner_reply(owner_reply) != _normalize_owner_reply(EXPECTED_OWNER_REPLY):
        raise ValueError("phase2a_final_adoption_owner_reply_not_exact")
    if owner_typed_name != EXPECTED_OWNER_TYPED_NAME:
        raise ValueError("phase2a_final_adoption_owner_name_not_exact")
    try:
        parsed = date.fromisoformat(owner_decision_date)
    except ValueError as exc:
        raise ValueError("phase2a_final_adoption_owner_date_invalid") from exc
    if parsed.isoformat() != EXPECTED_OWNER_DECISION_DATE:
        raise ValueError("phase2a_final_adoption_owner_date_not_exact")
    timestamp = recorded_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("phase2a_final_adoption_recorded_at_must_be_aware")

    _verify_packet_root(packet_root)
    _verify_original_chain_unspent(original_approval_root)

    chain_id = (
        "phase2a-execution-chain-"
        + _sha256(
            (EXPECTED_ORIGINAL_RECEIPT_CONTENT_SHA256 + EXPECTED_PACKET_CONTENT_SHA256).encode()
        )[:32]
    )
    boundaries = _boundaries()
    authority = _artifact(
        "legalbot.v111.phase2a.final-remediation-execution-authority.v1",
        {
            "status": CHAIN_STATUS,
            "chain_id": chain_id,
            "authority_origin_owner_receipt_content_sha256": (
                EXPECTED_ORIGINAL_RECEIPT_CONTENT_SHA256
            ),
            "final_owner_packet_content_sha256": EXPECTED_PACKET_CONTENT_SHA256,
            "total_execution_chain_count": 1,
            "execution_chain_consumed_count": 0,
            "execution_chain_remaining_count": 1,
            "authority_preexisted_final_packet": True,
            "new_or_additional_authority_created": False,
            "complete_source_scan_maximum_count": 1,
            "successor_build_with_embedding_maximum_count": 1,
            "stages": {
                "owner_decision_application": "NOT_RUN",
                "source_materialization": "NOT_RUN",
                "complete_source_scan": "NOT_RUN",
                "successor_build_embedding": "NOT_RUN",
                "retrieval_reattestation": "NOT_RUN",
                "all585_technical_qualification": "NOT_RUN",
            },
            "successor_must_remain_non_active": True,
            "successor_must_remain_answer_ineligible": True,
            **boundaries,
        },
    )
    authority_raw = _pretty_json(authority)
    verbatim_raw = owner_reply.encode("utf-8")
    receipt = _artifact(
        "legalbot.v111.phase2a.final-remediation-owner-adoption-receipt.v1",
        {
            "status": STATUS,
            "recorded_at": timestamp.astimezone(UTC).isoformat(),
            "owner_typed_name": owner_typed_name,
            "owner_decision_date": owner_decision_date,
            "owner_approved": True,
            "owner_adoption_recorded": True,
            "owner_reply_verbatim_file": VERBATIM_NAME,
            "owner_reply_verbatim_file_sha256": _sha256(verbatim_raw),
            "owner_reply_normalized_sha256": EXPECTED_NORMALIZED_OWNER_REPLY_SHA256,
            "final_owner_packet_content_sha256": EXPECTED_PACKET_CONTENT_SHA256,
            "final_owner_packet_file_sha256": EXPECTED_PACKET_FILE_SHA256,
            "original_owner_receipt_content_sha256": (EXPECTED_ORIGINAL_RECEIPT_CONTENT_SHA256),
            "original_owner_receipt_file_sha256": EXPECTED_ORIGINAL_RECEIPT_FILE_SHA256,
            "execution_authority_content_sha256": authority["artifact_content_sha256"],
            "execution_authority_file_sha256": _sha256(authority_raw),
            "execution_chain_status": CHAIN_STATUS,
            "execution_chain_count": 1,
            "execution_chain_consumed_count": 0,
            "execution_chain_remaining_count": 1,
            "technical_success_predeclared": False,
            **boundaries,
        },
    )
    receipt_raw = _pretty_json(receipt)
    outcome = _artifact(
        "legalbot.v111.phase2a.final-remediation-owner-adoption-outcome.v1",
        {
            "status": STATUS,
            "owner_adoption_receipt_content_sha256": receipt["artifact_content_sha256"],
            "owner_adoption_receipt_file_sha256": _sha256(receipt_raw),
            "execution_authority_content_sha256": authority["artifact_content_sha256"],
            "execution_authority_file_sha256": _sha256(authority_raw),
            "execution_chain_status": CHAIN_STATUS,
            "next_required_action": "APPLY_EXACT_DECISIONS_AND_MATERIALIZE_EXACT_SOURCES",
            "successful_phase2a_package_claimed": False,
            **boundaries,
        },
    )
    outcome_raw = _pretty_json(outcome)
    artifacts = {
        AUTHORITY_STATE_NAME: authority_raw,
        OUTCOME_NAME: outcome_raw,
        RECEIPT_NAME: receipt_raw,
        VERBATIM_NAME: verbatim_raw,
    }
    package = _artifact(
        "legalbot.v111.phase2a.final-remediation-owner-adoption-package.v1",
        {
            "status": STATUS,
            "final_owner_packet_content_sha256": EXPECTED_PACKET_CONTENT_SHA256,
            "original_owner_receipt_content_sha256": (EXPECTED_ORIGINAL_RECEIPT_CONTENT_SHA256),
            "owner_adoption_receipt_content_sha256": receipt["artifact_content_sha256"],
            "execution_authority_content_sha256": authority["artifact_content_sha256"],
            "artifacts": [
                {"name": name, "file_sha256": _sha256(raw)}
                for name, raw in sorted(artifacts.items())
            ],
            "execution_chain_status": CHAIN_STATUS,
            "successful_phase2a_package_claimed": False,
            **boundaries,
        },
    )
    package_raw = _pretty_json(package)
    artifacts[PACKAGE_NAME] = package_raw
    checksums_raw = "".join(
        f"{_sha256(raw)}  {name}\n" for name, raw in sorted(artifacts.items())
    ).encode()

    output_root.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.staging-", dir=output_root.parent))
    os.chmod(staging, 0o700)
    try:
        for name, raw in sorted(artifacts.items()):
            _write_exclusive(staging / name, raw)
        _write_exclusive(staging / CHECKSUMS_NAME, checksums_raw)
        for path in staging.iterdir():
            os.chmod(path, 0o600)
        _publish_noreplace(staging, output_root)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise

    return {
        "status": STATUS,
        "output_name": output_root.name,
        "owner_adoption_receipt_content_sha256": receipt["artifact_content_sha256"],
        "owner_adoption_receipt_file_sha256": _sha256(receipt_raw),
        "execution_authority_content_sha256": authority["artifact_content_sha256"],
        "execution_authority_file_sha256": _sha256(authority_raw),
        "package_content_sha256": package["artifact_content_sha256"],
        "package_file_sha256": _sha256(package_raw),
        "execution_chain_status": CHAIN_STATUS,
        "execution_chain_remaining_count": 1,
        "source_materialized": False,
        "source_scan_run": False,
        "successor_build_run": False,
        "embedding_run": False,
        "retrieval_reattestation_run": False,
        "all585_qualification_run": False,
        "phase2b_run": False,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-root", type=Path, default=PACKET_ROOT)
    parser.add_argument("--original-approval-root", type=Path, default=ORIGINAL_APPROVAL_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--owner-reply-file", type=Path, required=True)
    parser.add_argument("--owner-typed-name", required=True)
    parser.add_argument("--owner-decision-date", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    reply_path = args.owner_reply_file
    if reply_path.is_symlink() or not reply_path.is_file():
        raise ValueError("phase2a_final_adoption_owner_reply_file_invalid")
    result = record_owner_adoption(
        packet_root=args.packet_root.resolve(strict=True),
        original_approval_root=args.original_approval_root.resolve(strict=True),
        output_root=args.output_root.resolve(strict=False),
        owner_reply=reply_path.read_text(encoding="utf-8"),
        owner_typed_name=args.owner_typed_name,
        owner_decision_date=args.owner_decision_date,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
