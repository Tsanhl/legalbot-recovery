#!/usr/bin/env python3
"""Record the exact 142-source seminar-packet owner approval, create-only.

This receipt authorizes admission only at the later consolidated Phase-2A
source-scan/successor-build gate.  It does not execute a scan, index, embedding
or build, and it cannot activate Phase 2B, Development, Validation or live use.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OWNER_REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
DEFAULT_SOURCE_ROOT = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2A-2026-08-27-seminar-source-owner-packet"
)
DEFAULT_OUTPUT_ROOT = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2A-2026-08-27-seminar-source-owner-approved"
)

EXPECTED_APPROVAL_PAYLOAD_SHA256 = (
    "20e21e43aefc6348db5344782ddc3ab9d41a05c2c19aeb24b58a3fcd02371c73"
)
EXPECTED_DECISION_BATCH_SHA256 = (
    "6b2fc70e2c15e706bc26034aed7c6940b28b4220f66a7b0fbd28b97a0f53c8b6"
)
EXPECTED_SOURCE_COUNT = 142
EXPECTED_FAMILY_COUNTS = {"legislation": 43, "official_judgment": 99}
EXPECTED_PACKET_FILES = frozenset(
    {
        "OWNER-AUTHORIZATION-VERBATIM.txt",
        "OWNER-AUTHORIZATION-RECEIPT.json",
        "EXCLUDED-SOURCES.json",
        "SEMINAR-SOURCE-OWNER-DECISION-BATCH.json",
        "OWNER-APPROVAL-PAYLOAD.json",
        "OUTCOME.txt",
        "PACKAGE-INDEX.json",
    }
)
EXPECTED_NOT_AUTHORIZED = frozenset(
    {
        "ACTIVE_OR_PREVIOUS_WRITE",
        "PROMOTION",
        "PHASE_2B",
        "DEVELOPMENT_30",
        "VALIDATION_30",
        "LIVE_ACTIVATION",
        "TRAINING_EXPORT",
    }
)
OWNER_APPROVAL_STATEMENT = """OWNER APPROVAL — EXACT 142-SOURCE SEMINAR PACKET

The owner approves payload SHA-256 20e21e43aefc6348db5344782ddc3ab9d41a05c2c19aeb24b58a3fcd02371c73 and its bound 142-source decision batch SHA-256 6b2fc70e2c15e706bc26034aed7c6940b28b4220f66a7b0fbd28b97a0f53c8b6 under Option B — OWNER_ADOPTED_INTERNAL.

Authorized, narrowly:
- admit exactly the packet's 142 sources (99 official judgments and 43 legislation identities) to the private research index;
- retain every recorded currentness/later-treatment hold and every exclusion;
- perform one complete source scan and one successor candidate build with embedding;
- keep the successor non-ACTIVE and answer-release ineligible.

Not authorized:
- ACTIVE/PREVIOUS writes, promotion, Phase 2B, Development 30, Validation 30, live activation, or training export;
- any held, excluded, unmapped, unconfirmed, or unseen source outside the exact packet.

Execution is deferred to the single consolidated Phase-2A admission manifest and successor build after r117 planning, held-row repair, exact-span work, and crosswalking by canonical authority identity and content SHA. Overlapping staged bytes/chunks must be reused and counted once."""

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
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
        raise ValueError("seminar_owner_approval_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("seminar_owner_approval_input_must_be_object")
    return value


def _verify_seal(
    value: Mapping[str, Any], field: str, code: str, expected: str | None = None
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


def _normalize_statement(value: str) -> str:
    return "\n".join(line.rstrip() for line in value.strip().splitlines())


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


def _sealed_artifact(
    schema: str, material: Mapping[str, Any], digest_field: str
) -> dict[str, Any]:
    payload = {"schema": schema, **material}
    return {**payload, digest_field: _sealed(payload)}


def _verify_packet_checksums(source_root: Path) -> str:
    checksum_path = source_root / "SHA256SUMS.txt"
    if checksum_path.is_symlink() or not checksum_path.is_file():
        raise ValueError("seminar_owner_approval_checksums_missing")
    observed_names: set[str] = set()
    for line in checksum_path.read_text().splitlines():
        parts = line.split("  ", 1)
        if len(parts) != 2:
            raise ValueError("seminar_owner_approval_checksum_line_invalid")
        expected, name = parts
        if (
            not _SHA256.fullmatch(expected)
            or Path(name).name != name
            or name in observed_names
        ):
            raise ValueError("seminar_owner_approval_checksum_entry_invalid")
        path = source_root / name
        if path.is_symlink() or not path.is_file() or _sha256_file(path) != expected:
            raise ValueError("seminar_owner_approval_packet_file_digest_invalid")
        observed_names.add(name)
    if observed_names != EXPECTED_PACKET_FILES:
        raise ValueError("seminar_owner_approval_packet_file_set_invalid")
    return _sha256_file(checksum_path)


def _verify_source_packet(source_root: Path) -> dict[str, Any]:
    checksums_sha256 = _verify_packet_checksums(source_root)
    payload = _load_object(source_root / "OWNER-APPROVAL-PAYLOAD.json")
    _verify_seal(
        payload,
        "owner_approval_payload_content_sha256",
        "seminar_owner_approval_payload_seal_invalid",
        EXPECTED_APPROVAL_PAYLOAD_SHA256,
    )
    batch = _load_object(source_root / "SEMINAR-SOURCE-OWNER-DECISION-BATCH.json")
    _verify_seal(
        batch,
        "owner_decision_batch_content_sha256",
        "seminar_owner_approval_batch_seal_invalid",
        EXPECTED_DECISION_BATCH_SHA256,
    )
    scope = payload.get("approval_scope_if_explicitly_owner_approved")
    records = batch.get("records")
    if (
        payload.get("owner_decision_batch_content_sha256")
        != EXPECTED_DECISION_BATCH_SHA256
        or not isinstance(scope, Mapping)
        or scope.get("source_authority_count") != EXPECTED_SOURCE_COUNT
        or scope.get("source_admission_for_private_research_index") is not True
        or scope.get("retain_currentness_and_later_treatment_holds") is not True
        or scope.get("answer_release_eligible") is not False
        or scope.get("one_full_source_scan_authorized") is not True
        or scope.get("one_successor_candidate_build_and_embedding_authorized")
        is not True
        or scope.get("successor_must_remain_non_active") is not True
        or frozenset(payload.get("expressly_not_authorized", []))
        != EXPECTED_NOT_AUTHORIZED
        or batch.get("source_authority_count") != EXPECTED_SOURCE_COUNT
        or batch.get("source_family_counts") != EXPECTED_FAMILY_COUNTS
        or not isinstance(records, list)
        or len(records) != EXPECTED_SOURCE_COUNT
    ):
        raise ValueError("seminar_owner_approval_scope_invalid")

    registry: list[dict[str, str]] = []
    source_keys: set[str] = set()
    identities: set[str] = set()
    family_counts: Counter[str] = Counter()
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError("seminar_owner_approval_record_invalid")
        _verify_seal(
            record,
            "record_content_sha256",
            "seminar_owner_approval_record_seal_invalid",
        )
        admission = record.get("source_admission")
        selected = record.get("selected_source_version")
        source_key = str(record.get("source_key") or "")
        identity = str(record.get("official_identity") or "")
        family = str(record.get("source_family") or "")
        if (
            not isinstance(admission, Mapping)
            or not isinstance(selected, Mapping)
            or not source_key
            or not identity
            or source_key in source_keys
            or identity in identities
            or admission.get("owner_outcome") is not None
            or admission.get("authorized") is not False
            or admission.get("answer_release_eligible") is not False
            or record.get("indexing_authorized") is not False
            or record.get("embedding_authorized") is not False
            or selected.get("review_status") != "staged"
        ):
            raise ValueError("seminar_owner_approval_record_boundary_invalid")
        content_sha256 = str(selected.get("content_sha256") or "")
        version_sha256 = str(selected.get("version_sha256") or "")
        if not _SHA256.fullmatch(content_sha256) or not _SHA256.fullmatch(
            version_sha256
        ):
            raise ValueError("seminar_owner_approval_source_digest_invalid")
        source_keys.add(source_key)
        identities.add(identity)
        family_counts[family] += 1
        registry.append(
            {
                "source_key": source_key,
                "official_identity": identity,
                "content_sha256": content_sha256,
                "version_sha256": version_sha256,
            }
        )
    if dict(sorted(family_counts.items())) != EXPECTED_FAMILY_COUNTS:
        raise ValueError("seminar_owner_approval_record_family_counts_invalid")
    registry.sort(key=lambda item: item["source_key"])
    return {
        "source_packet_checksums_file_sha256": checksums_sha256,
        "approved_authority_registry_sha256": _sealed(registry),
        "source_authority_count": len(registry),
        "source_family_counts": dict(sorted(family_counts.items())),
    }


def apply_approval(
    *,
    source_root: Path,
    output_root: Path,
    owner_statement: str,
    recorded_at: datetime,
) -> dict[str, Any]:
    if recorded_at.tzinfo is None:
        raise ValueError("seminar_owner_approval_recorded_at_naive")
    if _normalize_statement(owner_statement) != _normalize_statement(
        OWNER_APPROVAL_STATEMENT
    ):
        raise ValueError("seminar_owner_approval_statement_not_exact")
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("seminar_owner_approval_output_already_exists")
    packet = _verify_source_packet(source_root)
    statement = _normalize_statement(owner_statement)
    receipt = _sealed_artifact(
        "legalbot.v111.seminar-source-exact-owner-approval-receipt.v1",
        {
            "status": "EXACT_142_SOURCE_APPROVAL_RECORDED_EXECUTION_DEFERRED_TO_CONSOLIDATED_PHASE2A_BUILD",
            "recorded_at": recorded_at.astimezone(UTC).isoformat(timespec="seconds"),
            "owner_route": "OWNER_ADOPTED_INTERNAL_RESEARCH_TOOL_NOT_PROFESSIONAL_CERTIFICATION",
            "owner_statement_sha256": _sha256((statement + "\n").encode("utf-8")),
            "owner_approval_payload_content_sha256": EXPECTED_APPROVAL_PAYLOAD_SHA256,
            "owner_decision_batch_content_sha256": EXPECTED_DECISION_BATCH_SHA256,
            **packet,
            "source_admission_authorized": True,
            "one_consolidated_full_source_scan_authorized": True,
            "one_consolidated_successor_candidate_build_authorized": True,
            "embedding_in_consolidated_successor_authorized": True,
            "reuse_overlapping_staged_bytes_and_chunks_required": True,
            "canonical_identity_and_content_sha_crosswalk_required": True,
            "currentness_and_later_treatment_holds_retained": True,
            "exclusions_retained": True,
            "answer_release_eligible": False,
            "successor_must_remain_non_active": True,
            "execution_deferred_until_r117_and_exact_span_scope_consolidated": True,
            "source_scan_started": False,
            "candidate_build_started": False,
            "active_or_previous_write_authorized": False,
            "promotion_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
            "validation30_authorized": False,
            "live_activation_authorized": False,
            "training_export_authorized": False,
        },
        "approval_receipt_content_sha256",
    )

    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("seminar_owner_approval_output_mode_invalid")
    statement_name = "OWNER-APPROVAL-VERBATIM.txt"
    receipt_name = "OWNER-APPROVAL-RECEIPT.json"
    outcome_name = "OUTCOME.txt"
    _write_exclusive(output_root / statement_name, (statement + "\n").encode())
    _write_exclusive(output_root / receipt_name, _pretty_json(receipt))
    _write_exclusive(
        output_root / outcome_name,
        (
            "EXACT 142-SOURCE OWNER APPROVAL RECORDED — EXECUTION DEFERRED TO THE "
            "SINGLE CONSOLIDATED PHASE-2A SOURCE SCAN AND SUCCESSOR BUILD\n"
            f"APPROVAL RECEIPT DIGEST: {receipt['approval_receipt_content_sha256']}\n"
            "PHASE 2B, DEVELOPMENT, VALIDATION, PROMOTION AND LIVE REMAIN CLOSED\n"
        ).encode(),
    )
    indexed_names = (statement_name, receipt_name, outcome_name)
    entries = [
        {
            "name": name,
            "byte_count": (output_root / name).stat().st_size,
            "file_sha256": _sha256_file(output_root / name),
        }
        for name in indexed_names
    ]
    package = _sealed_artifact(
        "legalbot.v111.seminar-source-exact-owner-approval-package.v1",
        {
            "status": "IMMUTABLE_EXACT_OWNER_APPROVAL_RECEIPT_NO_EXECUTION",
            "created_at": recorded_at.astimezone(UTC).isoformat(timespec="seconds"),
            "approval_receipt_content_sha256": receipt[
                "approval_receipt_content_sha256"
            ],
            "file_count": len(entries),
            "files": entries,
            "source_scan_started": False,
            "candidate_build_started": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
        "package_index_content_sha256",
    )
    index_name = "PACKAGE-INDEX.json"
    _write_exclusive(output_root / index_name, _pretty_json(package))
    checksum_names = (*indexed_names, index_name)
    checksums = "".join(
        f"{_sha256_file(output_root / name)}  {name}\n" for name in checksum_names
    )
    _write_exclusive(output_root / "SHA256SUMS.txt", checksums.encode())
    return {**receipt, "output_root": output_root}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--recorded-at", required=True)
    args = parser.parse_args()
    result = apply_approval(
        source_root=args.source_root.resolve(strict=True),
        output_root=args.output_root.resolve(strict=False),
        owner_statement=OWNER_APPROVAL_STATEMENT,
        recorded_at=datetime.fromisoformat(args.recorded_at),
    )
    print(
        json.dumps(
            {
                "output_root": str(result["output_root"]),
                "approval_receipt_content_sha256": result[
                    "approval_receipt_content_sha256"
                ],
                "source_authority_count": result["source_authority_count"],
                "source_scan_started": result["source_scan_started"],
                "candidate_build_started": result["candidate_build_started"],
                "phase2b_authorized": result["phase2b_authorized"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
