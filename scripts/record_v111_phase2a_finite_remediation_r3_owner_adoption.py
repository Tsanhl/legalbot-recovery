#!/usr/bin/env python3
"""Record the two-message owner adoption of the finite-remediation R3 packet.

This create-only recorder verifies the immutable R3 packet, its 146-row
contract and the one pre-existing unspent Phase-2A execution authority.  It
records the approval body and the separately supplied signature without
creating, replacing or spending an execution authority.  It performs no
source admission, scan, build, embedding, retrieval or qualification work.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections.abc import Mapping
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
PACKET_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-finite-remediation-owner-packet-r3"
AUTHORITY_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-final-remediation-owner-approved-r1"
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-29-finite-remediation-owner-approved-r1"
)

PACKET_NAME = "EXACT-PHASE2A-FINITE-REMEDIATION-OWNER-PACKET.json"
CONTRACTS_NAME = "EXACT-146-ROW-FINITE-OUTCOME-CONTRACTS.json"
PROMPT_NAME = "OWNER-APPROVAL-PROMPT.txt"
PACKET_PACKAGE_NAME = "PACKAGE-MANIFEST.json"
PACKET_CHECKSUMS_NAME = "SHA256SUMS.txt"
AUTHORITY_NAME = "PHASE2A-EXECUTION-AUTHORITY.json"

APPROVAL_BODY_NAME = "OWNER-APPROVAL-BODY-VERBATIM.txt"
SIGNATURE_NAME = "OWNER-SIGNATURE-FOLLOWUP-VERBATIM.txt"
DECISION_EVIDENCE_NAME = "OWNER-DECISION-EVIDENCE.json"
RECEIPT_NAME = "OWNER-ADOPTION-RECEIPT.json"
OUTCOME_NAME = "OWNER-ADOPTION-OUTCOME.json"
AUTHORITY_LINK_NAME = "EXISTING-EXECUTION-AUTHORITY-LINK.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

EXPECTED_PACKET_CONTENT_SHA256 = "4b90e576afb84e9982c171b02a108b9b7506d48c222e2076810a34f57f43fa91"
EXPECTED_PACKET_FILE_SHA256 = "1775e034b680583df1e4b2e7e907798c2fba45efca00a2f033fdfdc2b46b0f3c"
EXPECTED_CONTRACTS_CONTENT_SHA256 = (
    "6cebd8b70b3044b0b4533c1036c3aaec1b8ac88c4a43873a585616bc7cd573bf"
)
EXPECTED_CONTRACTS_FILE_SHA256 = "0cd3162c482287e443389dd23ffb4ed8c40774b441076b8e62e5f30b9a7ef4a0"
EXPECTED_PACKAGE_CONTENT_SHA256 = "7dc740ebf52f82cfac2da42a975bf36d9b277aa27d4b7e1c4734eacd73a323c8"
EXPECTED_PACKAGE_FILE_SHA256 = "4e12644f3c8c817a3874ed1fa048c09d1d06eb6a070a1ccaef9b85015b3059ae"
EXPECTED_PROMPT_FILE_SHA256 = "b1d7ea6df721f59f301c95d5b63f371c73dc47681c7a062c904523f26d2ea0a9"
EXPECTED_PACKET_CHECKSUMS_FILE_SHA256 = (
    "a58919e89c6fdd71f2aafac0e739752d48e879b3eb26a65ee122055c6ae8b810"
)
EXPECTED_AUTHORITY_CONTENT_SHA256 = (
    "eb0eda2f34c8b261ea38fc9d697257cdd3bd6253c18c2d91355328c8cb78ef7b"
)
EXPECTED_AUTHORITY_FILE_SHA256 = "5171ce79007c68484f9854b5188bf7e7af8f880407b6fbad6e3f808d0c7630ad"
EXPECTED_CHAIN_ID = "phase2a-execution-chain-42fd4adafcde8afeb05825cebdc2865e"
EXPECTED_OWNER_TYPED_NAME = "Agnes"
EXPECTED_OWNER_DECISION_DATE = "2026-08-29"
EXPECTED_SIGNATURE_TEXT = "Owner typed name: Agnes\nDecision date: 2026-08-29\n"
EXPECTED_SIGNATURE_FIELDS_CONTENT_SHA256 = (
    "72270681fd96c78cbdb73554b27f2ce35e0dc559d1ec08ae6f24bcac85624637"
)
EXPECTED_R2_PACKET_CONTENT_SHA256 = (
    "9a84056b160f953f9073809c3519e22317370d04ec30887d0aeb20d2ca24e739"
)
EXPECTED_R2_CONTRACTS_CONTENT_SHA256 = (
    "65c08285f9a35e0274f9ea2e621c8a8c45c02ffd14ad942f392df85f06765f5f"
)
EXPECTED_R1_PACKET_CONTENT_SHA256 = (
    "e8e2cd116510d75c3afa64263f4d032ece563f2cd7aa0fd949cefe6538e59844"
)
EXPECTED_R1_CONTRACTS_CONTENT_SHA256 = (
    "97483887e654a76a2c326bde5c730b0afe9ad9c217965fe34b849ab746e81e40"
)

STATUS = "R3_OWNER_ADOPTION_RECORDED_EXECUTION_CHAIN_AVAILABLE"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

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
_NOT_RUN_FALSE_FLAGS = (
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
    "catalogue_mutated",
    "technical_qualification_assigned",
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


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


def _seal(value: dict[str, Any]) -> dict[str, Any]:
    if "artifact_content_sha256" in value:
        raise ValueError("finite_adoption_duplicate_seal_field")
    result = dict(value)
    result["artifact_content_sha256"] = _sealed(result)
    return result


def _load_exact(path: Path, file_sha256: str, content_sha256: str, *, code: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or _sha256_file(path) != file_sha256:
        raise ValueError(f"{code}_file_invalid")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{code}_object_invalid")
    material = dict(value)
    supplied = material.pop("artifact_content_sha256", "")
    if supplied != content_sha256 or _sealed(material) != content_sha256:
        raise ValueError(f"{code}_content_invalid")
    return value


def _verify_inputs(
    packet_root: Path, authority_root: Path
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    expected_inventory = {
        PACKET_NAME,
        CONTRACTS_NAME,
        PROMPT_NAME,
        PACKET_PACKAGE_NAME,
        PACKET_CHECKSUMS_NAME,
    }
    if (
        packet_root.is_symlink()
        or not packet_root.is_dir()
        or {p.name for p in packet_root.iterdir()} != expected_inventory
    ):
        raise ValueError("finite_adoption_packet_inventory_invalid")
    packet = _load_exact(
        packet_root / PACKET_NAME,
        EXPECTED_PACKET_FILE_SHA256,
        EXPECTED_PACKET_CONTENT_SHA256,
        code="finite_adoption_packet",
    )
    contracts = _load_exact(
        packet_root / CONTRACTS_NAME,
        EXPECTED_CONTRACTS_FILE_SHA256,
        EXPECTED_CONTRACTS_CONTENT_SHA256,
        code="finite_adoption_contracts",
    )
    package = _load_exact(
        packet_root / PACKET_PACKAGE_NAME,
        EXPECTED_PACKAGE_FILE_SHA256,
        EXPECTED_PACKAGE_CONTENT_SHA256,
        code="finite_adoption_package",
    )
    for path, expected, code in (
        (packet_root / PROMPT_NAME, EXPECTED_PROMPT_FILE_SHA256, "finite_adoption_prompt"),
        (
            packet_root / PACKET_CHECKSUMS_NAME,
            EXPECTED_PACKET_CHECKSUMS_FILE_SHA256,
            "finite_adoption_checksums",
        ),
    ):
        if path.is_symlink() or not path.is_file() or _sha256_file(path) != expected:
            raise ValueError(f"{code}_invalid")
    if packet.get("contracts_content_sha256") != EXPECTED_CONTRACTS_CONTENT_SHA256:
        raise ValueError("finite_adoption_packet_contract_binding_invalid")
    if (
        packet.get("supersedes_r2_packet_content_sha256") != EXPECTED_R2_PACKET_CONTENT_SHA256
        or packet.get("also_supersedes_unapproved_r1_packet_content_sha256")
        != EXPECTED_R1_PACKET_CONTENT_SHA256
    ):
        raise ValueError("finite_adoption_packet_supersession_invalid")
    if (
        contracts.get("supersedes_r2_contracts_content_sha256")
        != EXPECTED_R2_CONTRACTS_CONTENT_SHA256
        or contracts.get("also_supersedes_unapproved_r1_contracts_content_sha256")
        != EXPECTED_R1_CONTRACTS_CONTENT_SHA256
    ):
        raise ValueError("finite_adoption_contract_supersession_invalid")
    if (
        packet.get("counts", {}).get("prequalification_blocker_row_count") != 146
        or packet.get("counts", {}).get("exact_cohort_remediation_row_count") != 17
        or packet.get("counts", {}).get("strict_human_review_handoff_row_count") != 129
    ):
        raise ValueError("finite_adoption_counts_invalid")
    if (
        len(contracts.get("source_decisions", [])) != 25
        or len(contracts.get("row_outcomes", [])) != 146
    ):
        raise ValueError("finite_adoption_contract_inventory_invalid")
    if package.get("artifact_content_sha256") != EXPECTED_PACKAGE_CONTENT_SHA256:
        raise ValueError("finite_adoption_package_binding_invalid")
    prompt = (packet_root / PROMPT_NAME).read_bytes()
    if not prompt.endswith(b"Owner typed name:\nDecision date:\n"):
        raise ValueError("finite_adoption_prompt_signature_slots_invalid")

    authority = _load_exact(
        authority_root / AUTHORITY_NAME,
        EXPECTED_AUTHORITY_FILE_SHA256,
        EXPECTED_AUTHORITY_CONTENT_SHA256,
        code="finite_adoption_authority",
    )
    required = {
        "chain_id": EXPECTED_CHAIN_ID,
        "status": "AVAILABLE_UNSPENT",
        "total_execution_chain_count": 1,
        "execution_chain_consumed_count": 0,
        "execution_chain_remaining_count": 1,
        "new_or_additional_authority_created": False,
    }
    if any(authority.get(key) != value for key, value in required.items()):
        raise ValueError("finite_adoption_authority_state_invalid")
    if set(authority.get("stages", {}).values()) != {"NOT_RUN"}:
        raise ValueError("finite_adoption_authority_already_used")
    authority_false_flags = (*_PROHIBITED_FALSE_FLAGS, *_NOT_RUN_FALSE_FLAGS)
    if any(
        authority.get(key) is not False
        for key in authority_false_flags
        if key != "catalogue_mutated"
    ):
        raise ValueError("finite_adoption_authority_boundary_invalid")
    return packet, authority, prompt


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
    libc = ctypes.CDLL(None, use_errno=True)
    source, target = os.fsencode(staging), os.fsencode(output)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        fn = libc.renamex_np
        fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        result = fn(source, target, 0x00000004)
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        fn = libc.renameat2
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        result = fn(-100, source, -100, target, 0x00000001)
    else:
        raise RuntimeError("finite_adoption_atomic_noreplace_unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ValueError("finite_adoption_output_already_exists")
    raise OSError(error_number, "finite_adoption_atomic_publish_failed")


def record_owner_adoption(
    *,
    packet_root: Path = PACKET_ROOT,
    authority_root: Path = AUTHORITY_ROOT,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    approval_body: bytes,
    signature_followup: str,
    owner_typed_name: str,
    owner_decision_date: str,
    recorded_at: datetime | None = None,
) -> dict[str, Any]:
    """Seal an exact two-message adoption receipt; do not execute the chain."""
    timestamp = recorded_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("finite_adoption_recorded_at_timezone_required")
    try:
        if date.fromisoformat(owner_decision_date) > timestamp.date():
            raise ValueError("finite_adoption_owner_date_in_future")
    except ValueError as exc:
        if str(exc) == "finite_adoption_owner_date_in_future":
            raise
        raise ValueError("finite_adoption_owner_date_invalid") from exc
    packet, authority, exact_prompt = _verify_inputs(packet_root, authority_root)
    if approval_body != exact_prompt:
        raise ValueError("finite_adoption_approval_body_not_exact")
    if owner_typed_name != EXPECTED_OWNER_TYPED_NAME:
        raise ValueError("finite_adoption_owner_name_not_exact")
    if owner_decision_date != EXPECTED_OWNER_DECISION_DATE:
        raise ValueError("finite_adoption_owner_date_not_exact")
    if signature_followup != EXPECTED_SIGNATURE_TEXT:
        raise ValueError("finite_adoption_signature_followup_not_exact")

    signature_fields = {
        "schema": "legalbot.v111.phase2a.owner-signature-fields.v1",
        "owner_typed_name": owner_typed_name,
        "owner_decision_date": owner_decision_date,
    }
    signature_fields_sha = _sha256(_canonical_json(signature_fields))
    if signature_fields_sha != EXPECTED_SIGNATURE_FIELDS_CONTENT_SHA256:
        raise ValueError("finite_adoption_signature_fields_invalid")
    evidence = _seal(
        {
            "schema": "legalbot.v111.phase2a.two-message-owner-decision-evidence.v1",
            "approval_body_file": APPROVAL_BODY_NAME,
            "approval_body_file_sha256": _sha256(approval_body),
            "signature_followup_file": SIGNATURE_NAME,
            "signature_followup_file_sha256": _sha256(signature_followup.encode()),
            "signature_fields": signature_fields,
            "signature_fields_content_sha256": signature_fields_sha,
            "ordered_message_count": 2,
            "combined_verbatim_message_claimed": False,
        }
    )

    allowed = {
        "owner_decision_application_authorized": True,
        "source_admission_authorized": True,
        "complete_source_scan_authorized": True,
        "successor_build_authorized": True,
        "index_build_authorized": True,
        "embedding_authorized": True,
        "retrieval_reattestation_authorized": True,
        "all585_qualification_authorized": True,
    }
    base = {
        "status": STATUS,
        "owner_approved": True,
        "owner_adoption_recorded": True,
        "owner_typed_name": owner_typed_name,
        "owner_decision_date": owner_decision_date,
        "recorded_at": timestamp.isoformat(),
        "signature_evidence_mode": "SEPARATE_FOLLOWUP_MESSAGE",
        "decision_evidence_content_sha256": evidence["artifact_content_sha256"],
        "r3_packet_content_sha256": EXPECTED_PACKET_CONTENT_SHA256,
        "r3_packet_file_sha256": EXPECTED_PACKET_FILE_SHA256,
        "r3_contracts_content_sha256": EXPECTED_CONTRACTS_CONTENT_SHA256,
        "r3_contracts_file_sha256": EXPECTED_CONTRACTS_FILE_SHA256,
        "r3_package_content_sha256": EXPECTED_PACKAGE_CONTENT_SHA256,
        "r3_package_file_sha256": EXPECTED_PACKAGE_FILE_SHA256,
        "supersedes_r2_packet_content_sha256": EXPECTED_R2_PACKET_CONTENT_SHA256,
        "supersedes_r2_contracts_content_sha256": EXPECTED_R2_CONTRACTS_CONTENT_SHA256,
        "also_supersedes_unapproved_r1_packet_content_sha256": EXPECTED_R1_PACKET_CONTENT_SHA256,
        "also_supersedes_unapproved_r1_contracts_content_sha256": EXPECTED_R1_CONTRACTS_CONTENT_SHA256,
        "exact_row_contract_count": 146,
        "exact_cohort_remediation_row_count": 17,
        "strict_human_review_handoff_row_count": 129,
        "exact_source_decision_count": 25,
        "existing_execution_authority_content_sha256": EXPECTED_AUTHORITY_CONTENT_SHA256,
        "existing_execution_authority_file_sha256": EXPECTED_AUTHORITY_FILE_SHA256,
        "execution_chain_id": EXPECTED_CHAIN_ID,
        "execution_chain_count": 1,
        "execution_chain_consumed_count": 0,
        "execution_chain_remaining_count": 1,
        "execution_chain_status": "AVAILABLE_UNSPENT",
        "new_or_additional_execution_authority_created": False,
        "technical_success_predeclared": False,
        "successor_must_remain_non_active": True,
        "successor_must_remain_answer_ineligible": True,
        **allowed,
        **{key: False for key in _NOT_RUN_FALSE_FLAGS},
        **{key: False for key in _PROHIBITED_FALSE_FLAGS},
    }
    receipt = _seal(
        {"schema": "legalbot.v111.phase2a.finite-remediation-r3-owner-adoption-receipt.v1", **base}
    )
    outcome = _seal(
        {
            "schema": "legalbot.v111.phase2a.finite-remediation-r3-owner-adoption-outcome.v1",
            **base,
            "receipt_content_sha256": receipt["artifact_content_sha256"],
            "next_step": "APPLY_EXACT_R3_CONTRACTS_USING_EXISTING_SINGLE_CHAIN",
        }
    )
    authority_link = _seal(
        {
            "schema": "legalbot.v111.phase2a.existing-execution-authority-link.v1",
            "status": "EXISTING_AUTHORITY_VERIFIED_UNSPENT_NOT_COPIED_NOT_REPLACED",
            "authority_content_sha256": EXPECTED_AUTHORITY_CONTENT_SHA256,
            "authority_file_sha256": EXPECTED_AUTHORITY_FILE_SHA256,
            "chain_id": EXPECTED_CHAIN_ID,
            "total_count": 1,
            "consumed_count": 0,
            "remaining_count": 1,
            "new_or_additional_execution_authority_created": False,
            "r3_owner_receipt_content_sha256": receipt["artifact_content_sha256"],
        }
    )
    package = _seal(
        {
            "schema": "legalbot.v111.phase2a.finite-remediation-r3-owner-adoption-package.v1",
            "status": STATUS,
            "owner_receipt_content_sha256": receipt["artifact_content_sha256"],
            "owner_outcome_content_sha256": outcome["artifact_content_sha256"],
            "decision_evidence_content_sha256": evidence["artifact_content_sha256"],
            "authority_link_content_sha256": authority_link["artifact_content_sha256"],
            "existing_execution_authority_content_sha256": EXPECTED_AUTHORITY_CONTENT_SHA256,
            "new_or_additional_execution_authority_created": False,
            **{key: False for key in _NOT_RUN_FALSE_FLAGS},
            **{key: False for key in _PROHIBITED_FALSE_FLAGS},
        }
    )

    output = output_root.parent.resolve(strict=True) / output_root.name
    if output.exists() or output.is_symlink():
        raise ValueError("finite_adoption_output_already_exists")
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        os.chmod(staging, 0o700)
        files = {
            APPROVAL_BODY_NAME: approval_body,
            SIGNATURE_NAME: signature_followup.encode(),
            DECISION_EVIDENCE_NAME: _pretty_json(evidence),
            RECEIPT_NAME: _pretty_json(receipt),
            OUTCOME_NAME: _pretty_json(outcome),
            AUTHORITY_LINK_NAME: _pretty_json(authority_link),
            PACKAGE_NAME: _pretty_json(package),
        }
        for name, raw in files.items():
            _write_exclusive(staging / name, raw)
        checksums = "".join(f"{_sha256(raw)}  {name}\n" for name, raw in sorted(files.items()))
        _write_exclusive(staging / CHECKSUMS_NAME, checksums.encode())
        descriptor = os.open(staging, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _publish_noreplace(staging, output)
        staging = Path()
    finally:
        if staging and staging.exists():
            shutil.rmtree(staging)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-root", type=Path, default=PACKET_ROOT)
    parser.add_argument("--authority-root", type=Path, default=AUTHORITY_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--owner-typed-name", default=EXPECTED_OWNER_TYPED_NAME)
    parser.add_argument("--owner-decision-date", default=EXPECTED_OWNER_DECISION_DATE)
    args = parser.parse_args()
    receipt = record_owner_adoption(
        packet_root=args.packet_root,
        authority_root=args.authority_root,
        output_root=args.output_root,
        approval_body=(args.packet_root / PROMPT_NAME).read_bytes(),
        signature_followup=EXPECTED_SIGNATURE_TEXT,
        owner_typed_name=args.owner_typed_name,
        owner_decision_date=args.owner_decision_date,
    )
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "receipt_content_sha256": receipt["artifact_content_sha256"],
                "output_root": args.output_root.name,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
