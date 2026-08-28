#!/usr/bin/env python3
"""Build the exact Phase-2A source-binding delta owner packet.

The create-only builder reconciles the original 247 source proposals with the
sealed substantive-content audit and an exact caller-bound r7 repair
quarantine.  It creates an owner-review packet only.  It never admits a source,
scans, indexes, embeds, builds, qualifies, invokes a model or changes an
ACTIVE/PREVIOUS pointer.
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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
OUTPUT_REVIEW_ROOT = REVIEW_ROOT
REPAIR_INPUT_REVIEW_ROOT = REVIEW_ROOT

ORIGINAL_PACKET_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1"
ORIGINAL_PACKET_NAME = "EXACT-REMEDIATION-OWNER-PACKET-361.json"
ORIGINAL_PACKET_PATH = ORIGINAL_PACKET_ROOT / ORIGINAL_PACKET_NAME
OWNER_ADOPTION_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-approved-r1"
)
OWNER_RECEIPT_PATH = OWNER_ADOPTION_ROOT / "OWNER-ADOPTION-RECEIPT.json"
OWNER_RECEIPT_PACKAGE_PATH = OWNER_ADOPTION_ROOT / "PACKAGE-MANIFEST.json"
AUDIT_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-admission-content-audit-r1"
AUDIT_PATH = AUDIT_ROOT / "ADMISSION-CONTENT-AUDIT-247.json"
AUDIT_OUTCOME_PATH = AUDIT_ROOT / "AUDIT-OUTCOME.json"
AUDIT_PACKAGE_PATH = AUDIT_ROOT / "PACKAGE-MANIFEST.json"
AUDIT_CHECKSUMS_PATH = AUDIT_ROOT / "SHA256SUMS.txt"
EXPECTED_REPAIR_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r7"
DEFAULT_REPAIR_ROOT = REVIEW_ROOT / EXPECTED_REPAIR_ROOT_NAME
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-binding-delta-owner-packet-r1"
)

PACKET_NAME = "EXACT-SOURCE-BINDING-DELTA-OWNER-PACKET.json"
PROMPT_NAME = "OWNER-APPROVAL-PROMPT.txt"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"
REPAIR_MANIFEST_NAME = "REPAIR-QUARANTINE-MANIFEST.json"
REPAIR_PACKAGE_NAME = "PACKAGE-MANIFEST.json"

EXPECTED_ORIGINAL_PACKET_CONTENT_SHA256 = (
    "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c"
)
EXPECTED_ORIGINAL_PACKET_FILE_SHA256 = (
    "992770c04cb3e08de64bb98e80aa9801171d3e66e4b573b85919091a78b1db3b"
)
EXPECTED_ORIGINAL_QUARANTINE_CONTENT_SHA256 = (
    "b6d900b23232379a4d6c19d313f35c47e0758ce5e0bb6eb04008f9eba07a3819"
)
EXPECTED_ORIGINAL_QUARANTINE_FILE_SHA256 = (
    "f482366a2ba0d9f636c56104d632767a8eadd6e9a9625d50ef5391a5f62995eb"
)
EXPECTED_OWNER_RECEIPT_CONTENT_SHA256 = (
    "a6ea2794b276946dd24ba3d752203dd81ae14f88aae24224a80b7b62f886d539"
)
EXPECTED_OWNER_RECEIPT_FILE_SHA256 = (
    "ffb2d07c8f6f5d2f44fb78efa01e58a49c7bd79ff1fcb18e74c9ee63bd5f3743"
)
EXPECTED_OWNER_RECEIPT_PACKAGE_CONTENT_SHA256 = (
    "414d848314861662c1b818105a06eef51db6c353b396dbd13001bb514efb8bd5"
)
EXPECTED_OWNER_RECEIPT_PACKAGE_FILE_SHA256 = (
    "fab2e99a0b988c1d7f9d62e8a0c8d827bf7c7afdce6405d00f2d22a476f71a29"
)
EXPECTED_AUDIT_CONTENT_SHA256 = "fdb0fc0f6233e41da7088304323930cb1edd20ad4a4610774db2d77f056a8e5b"
EXPECTED_AUDIT_FILE_SHA256 = "cdd7e3a8e2dd3bafba07271a74af4a7fa59a9a7a97d2daf957575d12b30225bc"
EXPECTED_AUDIT_OUTCOME_CONTENT_SHA256 = (
    "8971d7d1da61f4558b159092afa6ac78cc78d9585bf380b428eb3779ba2df1d1"
)
EXPECTED_AUDIT_OUTCOME_FILE_SHA256 = (
    "96d3fe2c4ac1e435df83901347045d62004cc68cf5d8e7b5f2253f11e8e1be3b"
)
EXPECTED_AUDIT_PACKAGE_CONTENT_SHA256 = (
    "a59873c691b7b5c398d90e0957135702bee513cbc748b4de729e34944cbdba64"
)
EXPECTED_AUDIT_PACKAGE_FILE_SHA256 = (
    "dc5f2fab0537b2380947b697bf9529944733f2aee2ff6efd0d5140e9d19bb68f"
)
EXPECTED_AUDIT_CHECKSUMS_FILE_SHA256 = (
    "7c0c6a35e9543a134e3ada1605cc2df12c5ed8cab674c8f1dc68fd63c0398343"
)
EXPECTED_MATERIAL_HOLD_ROW_ID = "live60-q58:issue-14"
EXPECTED_MATERIAL_HOLD_DECISION_SHA256 = (
    "f1fb421a849cedf092d5c68a02157d24ede820cce6968b92b79f33c13887fc72"
)

EWCA_HOLD_OLD_RECORD_ID = "quarantine-binding-caeef16146c2eea1e2b03d09"
BIG_BROTHER_WATCH_HOLD_OLD_RECORD_ID = "quarantine-binding-678af407a5abea67aa817bee"
MUTU_PECHSTEIN_HOLD_OLD_RECORD_ID = "quarantine-binding-3688eea8275753b9dcabf559"
KLIMASENIORINNEN_HOLD_OLD_RECORD_ID = "quarantine-binding-0a370f8e41122c812c5f26d2"
GOODWIN_HOLD_OLD_RECORD_ID = "quarantine-binding-d07fad39256d15a7c6a25893"
EXPECTED_UNRESOLVED_REPAIR_IDS = frozenset(
    {
        EWCA_HOLD_OLD_RECORD_ID,
        BIG_BROTHER_WATCH_HOLD_OLD_RECORD_ID,
        MUTU_PECHSTEIN_HOLD_OLD_RECORD_ID,
        KLIMASENIORINNEN_HOLD_OLD_RECORD_ID,
        GOODWIN_HOLD_OLD_RECORD_ID,
    }
)

FAILED_LINEAGE_BINDINGS = (
    {
        "revision": "r1",
        "relative_path": (
            "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r1/FAILURE.json"
        ),
        "file_sha256": ("a5af1153ddbacbd0dd03bd5e4189d9469e68bdffd0ba40afe610878a83f75261"),
        "content_sha256": ("2024c7d6ef0d2af24b982d14298c94d1b4338b36dc162fa8899e11d73a50ee1b"),
        "failure_fingerprint": ("42ee30cfbe8c1d20c611fdbcde002b3103d267740d7083de43c4bc4a14be3df4"),
        "exception_type": "HTTPError",
        "reason": "HTTP Error 404: Not Found",
        "interpretation": "FAILED_COLLECTION_NO_ADMISSIBLE_BYTES",
    },
    {
        "revision": "r2",
        "relative_path": (
            "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r2/FAILURE.json"
        ),
        "file_sha256": ("52253805eeea3efe881809e86d3bac09a153d1548589a390e897cce802d220bf"),
        "content_sha256": ("1b451584a65b32d436415ce321e45fd6705e1430b6b1c136e855c5e72e970aa1"),
        "failure_fingerprint": ("f0f768b3f807de15f99d33fc8c021d181ec6c0f9dd50e6febc6a98e6e54cd362"),
        "exception_type": "RuntimeError",
        "reason": (
            "phase2a_binding_repair_item_failed:"
            "hudoc-001-233206-judgment-pdf:TimeoutError:"
            "The read operation timed out"
        ),
        "interpretation": "FAILED_COLLECTION_NO_ADMISSIBLE_BYTES",
    },
    {
        "revision": "r3",
        "relative_path": (
            "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r3/FAILURE.json"
        ),
        "file_sha256": ("fdd9c9d2ef03cc9bda1743a2cd9c05a96027dd751bc5db1a8b407fe9e8ea25fd"),
        "content_sha256": ("44df6c91c8c24142fccfd405dfca162bd4bff00e8b080e2e40a72d39321a8ab8"),
        "failure_fingerprint": ("fb19824ad9f4094e6abe8a95bd8f15edd38aac11bab8267199753d1197720a97"),
        "exception_type": "RuntimeError",
        "reason": (
            "phase2a_binding_repair_item_failed:hudoc-001-233206-judgment-html:KeyboardInterrupt:"
        ),
        "interpretation": ("INTENTIONAL_INTERRUPTION_AFTER_VALIDATOR_AUDIT_NO_ADMISSIBLE_BYTES"),
    },
    {
        "revision": "r4",
        "relative_path": (
            "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r4/FAILURE.json"
        ),
        "file_sha256": ("67a070cf798e44e2253e14c67644cb51990d2e4e1f3d31eb94c1b1a02eed104e"),
        "content_sha256": ("ec92cadab6112c7c33c29da0fbca73afade9a64a004f8402b8256bd240645808"),
        "failure_fingerprint": ("f65a28f2c53c32a5aec307f84814001e2212dd1857556d6b7a4320437b0238aa"),
        "exception_type": "RuntimeError",
        "reason": (
            "phase2a_binding_repair_item_failed:fca-cobs2-2a-2026-08-14-json:"
            "ValueError:phase2a_binding_repair_title_marker_missing"
        ),
        "interpretation": "VALIDATOR_TITLE_MARKER_FAILURE_NO_ADMISSIBLE_BYTES",
    },
    {
        "revision": "r5",
        "relative_path": (
            "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r5/FAILURE.json"
        ),
        "file_sha256": ("4c155f6eeeab57a9fb6569e144b0e9b409fd2e1601b7eb8c48d7e9575b55ef6b"),
        "content_sha256": ("cfb75bfb5975fa4354c9e7795022435f2d782e3f0de4f59010272d2727e5321d"),
        "failure_fingerprint": ("682392ef9bc42f28072c29368b7a35e2f9e527d4e1699d19597ae9af56734421"),
        "exception_type": "RuntimeError",
        "reason": (
            "phase2a_binding_repair_item_failed:hudoc-001-233206-judgment-html:"
            "ValueError:phase2a_binding_repair_judgment_body_missing"
        ),
        "interpretation": "VALIDATOR_JUDGMENT_BODY_FAILURE_NO_ADMISSIBLE_BYTES",
    },
    {
        "revision": "r6",
        "relative_path": (
            "LegalBot-Phase2A-2026-08-28-source-binding-repair-quarantine-r6/FAILURE.json"
        ),
        "file_sha256": ("4c155f6eeeab57a9fb6569e144b0e9b409fd2e1601b7eb8c48d7e9575b55ef6b"),
        "content_sha256": ("cfb75bfb5975fa4354c9e7795022435f2d782e3f0de4f59010272d2727e5321d"),
        "failure_fingerprint": ("682392ef9bc42f28072c29368b7a35e2f9e527d4e1699d19597ae9af56734421"),
        "exception_type": "RuntimeError",
        "reason": (
            "phase2a_binding_repair_item_failed:hudoc-001-233206-judgment-html:"
            "ValueError:phase2a_binding_repair_judgment_body_missing"
        ),
        "interpretation": ("SECOND_IDENTICAL_VALIDATOR_FINGERPRINT_PATH_STOPPED_BEFORE_THIRD"),
    },
)

EXPECTED_R7_MANIFEST_CONTENT_SHA256 = (
    "8c6c7c926b8612208287ae1c15af4d64b7f47829e9a2ff988fd4a95e9879c817"
)
EXPECTED_R7_MANIFEST_FILE_SHA256 = (
    "955503ce1d3d79602f7fe90f1c6330c63c0aea2dea6588e87f0d821eac129639"
)
EXPECTED_R7_PACKAGE_CONTENT_SHA256 = (
    "6b494e7d933d7f165e603a15934c7a1a0f2eda044897e8186f264eacbf02328c"
)
EXPECTED_R7_PACKAGE_FILE_SHA256 = "38d6b0f6dade2e8f96d0f486250b401e3e46924fdab3666a6a6ef225d74791bf"
EXPECTED_R7_CHECKSUMS_FILE_SHA256 = (
    "290edb9d5a4439ca7fba629de04d555e5c010fadc7faaff9ebfc4901c5c0328b"
)

STATUS = "EXACT_SOURCE_BINDING_DELTA_READY_NOT_ADOPTED"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REPAIR_SOURCE_VERSION = re.compile(r"^proposed-repair-source-version-[0-9a-f]{40}$")
_EMAIL = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
_WINDOWS_DRIVE_PATH = re.compile(r"(?i)(?:^|[^a-z0-9])(?:[a-z]:[\\/])")
_WINDOWS_UNC_PATH = re.compile(r"(?:^|[\s'\"(])(?:\\\\|//)[^\s]+")
_POSIX_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9+.-])/(?!/)[^\s'\"<>]*")
_URL = re.compile(r"(?i)https?://[^\s\]\[<>()'\",]+")
_PLAUSIBLE_PERSONAL_FILENAME = re.compile(
    r"(?i)(?:^|[\s'\"(])[^/\\\n]{1,180}\.(?:docx?|pdf|pptx?|xlsx?|rtf|odt|pages|txt)(?:$|[\s'\"),])"
)
_REPAIR_MEMBER = re.compile(r"^repair-representation-[0-9]{4}-[0-9a-f]{20}\.(?:html|json)$")
_APPROVED_PUBLIC_HTTPS_HOSTS = frozenset(
    {
        "api-handbook.fca.org.uk",
        "caselaw.nationalarchives.gov.uk",
        "eur-lex.europa.eu",
        "gov.uk",
        "handbook.fca.org.uk",
        "hudoc.echr.coe.int",
        "jcpc.uk",
        "justice.gov.uk",
        "publications.parliament.uk",
        "sra.org.uk",
        "supremecourt.uk",
        "tas-cas.org",
        "wada-ama.org",
        "www.echr.coe.int",
        "www.gov.uk",
        "www.jcpc.uk",
        "www.judiciary.uk",
        "www.justice.gov.uk",
        "www.legislation.gov.uk",
        "www.sra.org.uk",
        "www.supremecourt.uk",
        "www.tas-cas.org",
        "www.wada-ama.org",
    }
)
_CONTROLLED_ARTIFACT_NAMES = frozenset(
    {
        ORIGINAL_PACKET_NAME,
        "OWNER-ADOPTION-RECEIPT.json",
        "ADMISSION-CONTENT-AUDIT-247.json",
        REPAIR_MANIFEST_NAME,
        PACKET_NAME,
        PROMPT_NAME,
        PACKAGE_NAME,
        CHECKSUMS_NAME,
        "FAILURE.json",
    }
)

_NO_EXECUTION_FLAGS = {
    "owner_approved": False,
    "owner_adoption_recorded": False,
    "owner_decision_application_authorized": False,
    "owner_decisions_applied": False,
    "owner_outcomes_applied": False,
    "source_admission_authorized": False,
    "source_admitted": False,
    "complete_source_scan_authorized": False,
    "source_scan_run": False,
    "successor_build_authorized": False,
    "successor_build_run": False,
    "index_build_authorized": False,
    "index_built": False,
    "embedding_authorized": False,
    "embedding_run": False,
    "automatic_indexing": False,
    "automatic_embedding": False,
    "candidate_mutated": False,
    "catalogue_mutated": False,
    "qualification_authorized": False,
    "qualification_run": False,
    "retrieval_reattestation_authorized": False,
    "retrieval_reattestation_run": False,
    "all585_qualification_authorized": False,
    "all585_qualification_run": False,
    "technical_qualification_assigned": False,
    "answer_model_authorized": False,
    "answer_model_run": False,
    "answer_eligible": False,
    "answer_release_authorized": False,
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

_REPAIR_SEALED_TOP_LEVEL_FALSE_BOUNDARY_FIELDS = (
    "active_pointer_write_authorized",
    "active_pointer_written",
    "all585_qualification_run",
    "answer_eligible",
    "answer_model_authorized",
    "answer_model_run",
    "answer_release_authorized",
    "answer_released",
    "automatic_embedding",
    "automatic_indexing",
    "candidate_mutated",
    "catalogue_mutated",
    "complete_source_scan_authorized",
    "development30_authorized",
    "development30_run",
    "embedding_authorized",
    "embedding_run",
    "index_build_authorized",
    "index_built",
    "live_activation_authorized",
    "live_activation_run",
    "owner_approved",
    "owner_decisions_applied",
    "owner_outcomes_applied",
    "phase2b_authorized",
    "phase2b_run",
    "previous_pointer_write_authorized",
    "previous_pointer_written",
    "promotion_authorized",
    "promotion_run",
    "qualification_authorized",
    "retrieval_reattestation_run",
    "source_admission_authorized",
    "source_admitted",
    "source_scan_run",
    "successor_build_authorized",
    "successor_build_run",
    "technical_qualification_assigned",
    "training_export_authorized",
    "training_export_run",
    "validation30_authorized",
    "validation30_run",
)
_REPAIR_REQUIRED_FALSE_BOUNDARY_FIELDS = tuple(_NO_EXECUTION_FLAGS)
if len(_REPAIR_REQUIRED_FALSE_BOUNDARY_FIELDS) != 52 or set(
    _REPAIR_REQUIRED_FALSE_BOUNDARY_FIELDS
) != set(_NO_EXECUTION_FLAGS):
    raise RuntimeError("phase2a_delta_repair_boundary_contract_invalid")


@dataclass(frozen=True)
class RepairPackageBinding:
    root: Path
    manifest_content_sha256: str
    manifest_file_sha256: str
    package_content_sha256: str
    package_file_sha256: str


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


def _load_object(path: Path, code: str) -> dict[str, Any]:
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


def _validate_digest(value: str, code: str) -> None:
    if _SHA256.fullmatch(value) is None:
        raise ValueError(code)


def _verify_regular_file(path: Path, expected_sha256: str, code: str) -> None:
    if path.is_symlink() or not path.is_file() or _sha256_file(path) != expected_sha256:
        raise ValueError(code)


def _verify_exact_original_packet() -> dict[str, Any]:
    _verify_regular_file(
        ORIGINAL_PACKET_PATH,
        EXPECTED_ORIGINAL_PACKET_FILE_SHA256,
        "phase2a_delta_original_packet_file_invalid",
    )
    packet = _load_object(ORIGINAL_PACKET_PATH, "phase2a_delta_original_packet_invalid")
    _verify_seal(
        packet,
        "artifact_content_sha256",
        "phase2a_delta_original_packet_seal_invalid",
        EXPECTED_ORIGINAL_PACKET_CONTENT_SHA256,
    )
    proposals = packet.get("proposed_new_source_admissions")
    quarantine_holds = packet.get("quarantine_source_admission_holds")
    identity_holds = packet.get("source_identity_and_admission_holds")
    decisions = packet.get("decisions")
    if (
        packet.get("status") != "EXACT_361_OWNER_DECISIONS_READY_NOT_ADOPTED"
        or not isinstance(proposals, list)
        or len(proposals) != 247
        or not isinstance(quarantine_holds, list)
        or len(quarantine_holds) != 31
        or not isinstance(identity_holds, list)
        or len(identity_holds) != 86
        or not isinstance(decisions, list)
        or len(decisions) != 361
    ):
        raise ValueError("phase2a_delta_original_packet_inventory_invalid")
    for records, seal_field in (
        (proposals, "proposal_content_sha256"),
        (quarantine_holds, "hold_content_sha256"),
        (identity_holds, "anomaly_content_sha256"),
        (decisions, "decision_content_sha256"),
    ):
        for record in records:
            if not isinstance(record, Mapping):
                raise ValueError("phase2a_delta_original_packet_inventory_invalid")
            _verify_seal(
                record,
                seal_field,
                "phase2a_delta_original_packet_item_seal_invalid",
            )
    material_hold = next(
        (item for item in decisions if item.get("row_id") == EXPECTED_MATERIAL_HOLD_ROW_ID),
        None,
    )
    if (
        material_hold is None
        or material_hold.get("decision_content_sha256") != EXPECTED_MATERIAL_HOLD_DECISION_SHA256
        or material_hold.get("recommended_owner_outcome")
        != "RETAIN_MATERIAL_HOLD_NO_SUPPORTED_OFFICIAL_PROPOSITION"
        or material_hold.get("source_queue_record", {}).get("qualification_status")
        != "BLOCKED_MATERIAL_GAP"
    ):
        raise ValueError("phase2a_delta_material_hold_binding_invalid")
    return packet


def _verify_owner_adoption_receipt() -> dict[str, Any]:
    _verify_regular_file(
        OWNER_RECEIPT_PATH,
        EXPECTED_OWNER_RECEIPT_FILE_SHA256,
        "phase2a_delta_owner_receipt_file_invalid",
    )
    _verify_regular_file(
        OWNER_RECEIPT_PACKAGE_PATH,
        EXPECTED_OWNER_RECEIPT_PACKAGE_FILE_SHA256,
        "phase2a_delta_owner_receipt_package_file_invalid",
    )
    receipt = _load_object(OWNER_RECEIPT_PATH, "phase2a_delta_owner_receipt_invalid")
    package = _load_object(
        OWNER_RECEIPT_PACKAGE_PATH,
        "phase2a_delta_owner_receipt_package_invalid",
    )
    _verify_seal(
        receipt,
        "artifact_content_sha256",
        "phase2a_delta_owner_receipt_seal_invalid",
        EXPECTED_OWNER_RECEIPT_CONTENT_SHA256,
    )
    _verify_seal(
        package,
        "artifact_content_sha256",
        "phase2a_delta_owner_receipt_package_seal_invalid",
        EXPECTED_OWNER_RECEIPT_PACKAGE_CONTENT_SHA256,
    )
    if (
        receipt.get("status") != "OWNER_ADOPTION_RECORDED_TECHNICAL_SOURCE_BINDING_HOLD"
        or receipt.get("owner_typed_name") != "Agnes"
        or receipt.get("owner_decision_date") != "2026-08-28"
        or receipt.get("owner_adoption_recorded") is not True
        or receipt.get("technical_source_binding_hold") is not True
        or receipt.get("post_approval_content_audit", {}).get("required") is not True
        or receipt.get("owner_decisions_applied") is not False
        or receipt.get("source_admitted") is not False
        or receipt.get("source_scan_run") is not False
        or receipt.get("successor_build_run") is not False
        or receipt.get("embedding_run") is not False
        or package.get("owner_adoption_receipt_content_sha256")
        != EXPECTED_OWNER_RECEIPT_CONTENT_SHA256
    ):
        raise ValueError("phase2a_delta_owner_receipt_boundary_invalid")
    return receipt


def _verify_content_audit(
    original_proposals_by_record: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    for path, digest in (
        (AUDIT_PATH, EXPECTED_AUDIT_FILE_SHA256),
        (AUDIT_OUTCOME_PATH, EXPECTED_AUDIT_OUTCOME_FILE_SHA256),
        (AUDIT_PACKAGE_PATH, EXPECTED_AUDIT_PACKAGE_FILE_SHA256),
        (AUDIT_CHECKSUMS_PATH, EXPECTED_AUDIT_CHECKSUMS_FILE_SHA256),
    ):
        _verify_regular_file(path, digest, "phase2a_delta_audit_file_invalid")
    audit = _load_object(AUDIT_PATH, "phase2a_delta_audit_invalid")
    outcome = _load_object(AUDIT_OUTCOME_PATH, "phase2a_delta_audit_outcome_invalid")
    package = _load_object(AUDIT_PACKAGE_PATH, "phase2a_delta_audit_package_invalid")
    _verify_seal(
        audit,
        "artifact_content_sha256",
        "phase2a_delta_audit_seal_invalid",
        EXPECTED_AUDIT_CONTENT_SHA256,
    )
    _verify_seal(
        outcome,
        "outcome_content_sha256",
        "phase2a_delta_audit_outcome_seal_invalid",
        EXPECTED_AUDIT_OUTCOME_CONTENT_SHA256,
    )
    _verify_seal(
        package,
        "package_content_sha256",
        "phase2a_delta_audit_package_seal_invalid",
        EXPECTED_AUDIT_PACKAGE_CONTENT_SHA256,
    )
    summary = audit.get("summary")
    records = audit.get("records")
    if (
        audit.get("status") != "BLOCKED_EXACT_SUBSTANTIVE_CONTENT_FAILURE_SET"
        or not isinstance(summary, Mapping)
        or summary.get("audited_representation_count") != 247
        or summary.get("pass_count") != 231
        or summary.get("fail_count") != 16
        or summary.get("pass_with_warning_count") != 1
        or summary.get("warning_reason_counts") != {"TAS_NOISY_SEARCH_OVERLAY_RULE_BODY_PRESENT": 1}
        or summary.get("exact_expected_result") is not True
        or not isinstance(records, list)
        or len(records) != 247
        or package.get("input_content_sha256", {}).get("exact_remediation_owner_packet")
        != EXPECTED_ORIGINAL_PACKET_CONTENT_SHA256
        or package.get("artifacts", [])[0].get("content_sha256") != EXPECTED_AUDIT_CONTENT_SHA256
    ):
        raise ValueError("phase2a_delta_audit_inventory_invalid")
    record_ids: set[str] = set()
    pass_count = 0
    fail_count = 0
    warning_count = 0
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError("phase2a_delta_audit_record_invalid")
        _verify_seal(
            record,
            "record_content_sha256",
            "phase2a_delta_audit_record_seal_invalid",
        )
        record_id = str(record.get("record_id") or "")
        proposal = original_proposals_by_record.get(record_id)
        if not record_id or record_id in record_ids or proposal is None:
            raise ValueError("phase2a_delta_audit_record_invalid")
        binding = proposal["quarantine_representation_binding"]["selected_admission_binding"]
        if any(
            record.get(field) != binding.get(field)
            for field in (
                "record_id",
                "raw_sha256",
                "quarantine_member",
                "proposed_source_version_id",
                "bytes",
                "content_type",
            )
        ) or record.get("proposal_id") != proposal.get("proposal_id"):
            raise ValueError("phase2a_delta_audit_record_binding_invalid")
        verdict = record.get("substantive_content_verdict")
        eligible = record.get("substantive_content_eligible")
        if verdict in {"PASS", "PASS_WITH_WARNING"} and eligible is True:
            pass_count += 1
            if verdict == "PASS_WITH_WARNING":
                warning_count += 1
                if record.get("warning_reason_codes") != [
                    "TAS_NOISY_SEARCH_OVERLAY_RULE_BODY_PRESENT"
                ]:
                    raise ValueError("phase2a_delta_audit_warning_invalid")
        elif verdict == "FAIL" and eligible is False:
            fail_count += 1
            if not record.get("failure_reason_codes"):
                raise ValueError("phase2a_delta_audit_failure_invalid")
        else:
            raise ValueError("phase2a_delta_audit_verdict_invalid")
        record_ids.add(record_id)
    if (pass_count, fail_count, warning_count) != (231, 16, 1):
        raise ValueError("phase2a_delta_audit_partition_invalid")
    return audit


def _verify_failed_lineage() -> list[dict[str, Any]]:
    verified: list[dict[str, Any]] = []
    fingerprints: set[str] = set()
    for binding in FAILED_LINEAGE_BINDINGS:
        path = REVIEW_ROOT / binding["relative_path"]
        _verify_regular_file(
            path,
            str(binding["file_sha256"]),
            "phase2a_delta_failed_lineage_file_invalid",
        )
        value = _load_object(path, "phase2a_delta_failed_lineage_invalid")
        _verify_seal(
            value,
            "failure_content_sha256",
            "phase2a_delta_failed_lineage_seal_invalid",
            str(binding["content_sha256"]),
        )
        if (
            value.get("failure_fingerprint") != binding["failure_fingerprint"]
            or value.get("exception_type") != binding["exception_type"]
            or value.get("error") != binding["reason"]
            or value.get("stage") != "PHASE2A_SOURCE_BINDING_REPAIR_COLLECTION"
            or value.get("source_admission_authorized") is not False
            or value.get("source_admitted") is not False
            or value.get("source_scan_run") is not False
            or value.get("index_built") is not False
            or value.get("embedding_run") is not False
        ):
            raise ValueError("phase2a_delta_failed_lineage_boundary_invalid")
        fingerprints.add(str(binding["failure_fingerprint"]))
        verified.append(
            {
                **binding,
                "supplied_admissible_bytes": False,
                "source_admission_eligible": False,
            }
        )
    revisions = {str(item["revision"]): item for item in verified}
    if (
        len(verified) != 6
        or len(fingerprints) != 5
        or set(revisions) != {"r1", "r2", "r3", "r4", "r5", "r6"}
        or revisions["r5"]["file_sha256"] != revisions["r6"]["file_sha256"]
        or revisions["r5"]["content_sha256"] != revisions["r6"]["content_sha256"]
        or revisions["r5"]["failure_fingerprint"] != revisions["r6"]["failure_fingerprint"]
    ):
        raise ValueError("phase2a_delta_failed_lineage_fingerprints_not_distinct")
    return verified


def _verify_repair_false_boundaries_recursively(value: Any) -> None:
    if isinstance(value, Mapping):
        for field in _REPAIR_REQUIRED_FALSE_BOUNDARY_FIELDS:
            if field in value and value[field] is not False:
                raise ValueError("phase2a_delta_repair_boundary_invalid")
        for nested in value.values():
            _verify_repair_false_boundaries_recursively(nested)
    elif isinstance(value, list | tuple):
        for nested in value:
            _verify_repair_false_boundaries_recursively(nested)


def _verify_repair_package(binding: RepairPackageBinding) -> dict[str, Any]:
    for digest in (
        binding.manifest_content_sha256,
        binding.manifest_file_sha256,
        binding.package_content_sha256,
        binding.package_file_sha256,
    ):
        _validate_digest(digest, "phase2a_delta_repair_digest_invalid")
    root = binding.root
    if root.is_symlink() or not root.is_dir():
        raise ValueError("phase2a_delta_repair_root_absent_or_invalid")
    if root.name != EXPECTED_REPAIR_ROOT_NAME:
        raise ValueError("phase2a_delta_repair_revision_not_r7")
    repair_review_root = REPAIR_INPUT_REVIEW_ROOT.resolve(strict=True)
    expected_repair_root = repair_review_root / EXPECTED_REPAIR_ROOT_NAME
    resolved_repair_root = root.resolve(strict=True)
    if (
        resolved_repair_root != expected_repair_root
        or resolved_repair_root.parent != repair_review_root
        or not resolved_repair_root.is_relative_to(repair_review_root)
    ):
        raise ValueError("phase2a_delta_repair_root_identity_invalid")
    if (
        binding.manifest_content_sha256,
        binding.manifest_file_sha256,
        binding.package_content_sha256,
        binding.package_file_sha256,
    ) != (
        EXPECTED_R7_MANIFEST_CONTENT_SHA256,
        EXPECTED_R7_MANIFEST_FILE_SHA256,
        EXPECTED_R7_PACKAGE_CONTENT_SHA256,
        EXPECTED_R7_PACKAGE_FILE_SHA256,
    ):
        raise ValueError("phase2a_delta_repair_production_r7_digest_invalid")
    manifest_path = root / REPAIR_MANIFEST_NAME
    package_path = root / REPAIR_PACKAGE_NAME
    checksums_path = root / CHECKSUMS_NAME
    _verify_regular_file(
        manifest_path,
        binding.manifest_file_sha256,
        "phase2a_delta_repair_manifest_file_invalid",
    )
    _verify_regular_file(
        package_path,
        binding.package_file_sha256,
        "phase2a_delta_repair_package_file_invalid",
    )
    _verify_regular_file(
        checksums_path,
        EXPECTED_R7_CHECKSUMS_FILE_SHA256,
        "phase2a_delta_repair_checksums_file_invalid",
    )
    manifest = _load_object(manifest_path, "phase2a_delta_repair_manifest_invalid")
    package = _load_object(package_path, "phase2a_delta_repair_package_invalid")
    _verify_seal(
        manifest,
        "manifest_content_sha256",
        "phase2a_delta_repair_manifest_seal_invalid",
        binding.manifest_content_sha256,
    )
    _verify_seal(
        package,
        "package_content_sha256",
        "phase2a_delta_repair_package_seal_invalid",
        binding.package_content_sha256,
    )
    records = manifest.get("records")
    holds = manifest.get("unresolved_repair_holds")
    if (
        manifest.get("schema") != "legalbot.v111.phase2a.source-binding-repair-quarantine.v1"
        or manifest.get("status") != "EXACT_REPLACEMENTS_QUARANTINED_OWNER_DELTA_REQUIRED"
        or manifest.get("source_owner_packet_content_sha256")
        != EXPECTED_ORIGINAL_PACKET_CONTENT_SHA256
        or manifest.get("source_owner_packet_file_sha256") != EXPECTED_ORIGINAL_PACKET_FILE_SHA256
        or manifest.get("source_quarantine_manifest_content_sha256")
        != EXPECTED_ORIGINAL_QUARANTINE_CONTENT_SHA256
        or manifest.get("source_quarantine_manifest_file_sha256")
        != EXPECTED_ORIGINAL_QUARANTINE_FILE_SHA256
        or manifest.get("defective_old_binding_count") != 16
        or manifest.get("repaired_old_binding_count") != 11
        or manifest.get("unresolved_repair_hold_count") != 5
        or manifest.get("replacement_representation_count") != 15
        or manifest.get("all_substantive_body_and_locator_checks_passed") is not True
        or manifest.get("owner_delta_decision_required") is not True
        or not isinstance(records, list)
        or len(records) != 15
        or not isinstance(holds, list)
        or len(holds) != 5
        or package.get("schema") != "legalbot.v111.phase2a.source-binding-repair-package.v1"
        or package.get("status") != "QUARANTINED_NOT_OWNER_ADOPTED"
    ):
        raise ValueError("phase2a_delta_repair_inventory_invalid")
    for field in _REPAIR_SEALED_TOP_LEVEL_FALSE_BOUNDARY_FIELDS:
        if manifest.get(field) is not False or package.get(field) is not False:
            raise ValueError("phase2a_delta_repair_boundary_invalid")
    _verify_repair_false_boundaries_recursively(manifest)
    _verify_repair_false_boundaries_recursively(package)

    package_files = package.get("files")
    if (
        not isinstance(package_files, list)
        or len(package_files) != 17
        or not all(isinstance(item, Mapping) for item in package_files)
        or package.get("file_count") != 17
    ):
        raise ValueError("phase2a_delta_repair_package_inventory_invalid")
    package_files_by_name = {
        str(item.get("path")): item for item in package_files if isinstance(item, Mapping)
    }
    if len(package_files_by_name) != 17:
        raise ValueError("phase2a_delta_repair_package_inventory_invalid")
    if [str(item.get("path")) for item in package_files] != sorted(package_files_by_name):
        raise ValueError("phase2a_delta_repair_package_inventory_invalid")
    for name, item in package_files_by_name.items():
        if Path(name).name != name:
            raise ValueError("phase2a_delta_repair_package_member_invalid")
        path = root / name
        expected = str(item.get("sha256") or "")
        _validate_digest(expected, "phase2a_delta_repair_package_member_invalid")
        _verify_regular_file(path, expected, "phase2a_delta_repair_package_member_invalid")
        if path.stat().st_size != item.get("bytes"):
            raise ValueError("phase2a_delta_repair_package_member_invalid")

    record_ids: set[str] = set()
    version_ids: set[str] = set()
    record_members: set[str] = set()
    repaired_old_ids: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError("phase2a_delta_repair_record_invalid")
        _verify_seal(
            record,
            "record_content_sha256",
            "phase2a_delta_repair_record_seal_invalid",
        )
        record_id = str(record.get("record_id") or "")
        version_id = str(record.get("proposed_source_version_id") or "")
        old_record_id = str(record.get("old_record_id") or "")
        member = str(record.get("quarantine_member") or "")
        raw_sha256 = str(record.get("raw_sha256") or "")
        identity_material = {
            "canonical_url": record.get("canonical_url"),
            "final_url": record.get("final_url"),
            "raw_sha256": raw_sha256,
            "retrieved_at": record.get("retrieved_at"),
        }
        expected_record_id = "binding-repair-" + _sealed(identity_material)[:24]
        expected_version_id = "proposed-repair-source-version-" + _sealed(identity_material)[:40]
        if (
            not record_id
            or record_id != expected_record_id
            or record_id in record_ids
            or _REPAIR_SOURCE_VERSION.fullmatch(version_id) is None
            or version_id != expected_version_id
            or version_id in version_ids
            or not old_record_id
            or Path(member).name != member
            or member in record_members
            or member not in package_files_by_name
            or _SHA256.fullmatch(raw_sha256) is None
            or package_files_by_name[member].get("sha256") != raw_sha256
            or package_files_by_name[member].get("bytes") != record.get("bytes")
            or record.get("content_fitness_status") != "SUBSTANTIVE_BODY_AND_LOCATORS_VERIFIED"
            or not record.get("title_markers_verified")
            or not record.get("locator_markers_verified")
            or record.get("owner_delta_decision_required") is not True
            or record.get("source_admission_authorized") is not False
            or record.get("source_admitted") is not False
            or record.get("automatic_indexing") is not False
            or record.get("automatic_embedding") is not False
            or record.get("candidate_mutated") is not False
        ):
            raise ValueError("phase2a_delta_repair_record_invalid")
        record_ids.add(record_id)
        version_ids.add(version_id)
        record_members.add(member)
        repaired_old_ids.add(old_record_id)
    if len(repaired_old_ids) != 11 or sorted(repaired_old_ids) != manifest.get(
        "repaired_old_record_ids"
    ):
        raise ValueError("phase2a_delta_repair_old_binding_set_invalid")
    expected_package_members = {
        *record_members,
        REPAIR_MANIFEST_NAME,
        "OUTCOME.txt",
    }
    if set(package_files_by_name) != expected_package_members:
        raise ValueError("phase2a_delta_repair_package_member_set_invalid")
    disk_members = {path.name for path in root.iterdir()}
    if disk_members != expected_package_members | {REPAIR_PACKAGE_NAME, CHECKSUMS_NAME}:
        raise ValueError("phase2a_delta_repair_package_member_set_invalid")
    expected_checksums = (
        "".join(
            f"{package_files_by_name[name]['sha256']}  {name}\n"
            for name in sorted(package_files_by_name)
        )
        + f"{binding.package_file_sha256}  {REPAIR_PACKAGE_NAME}\n"
    )
    if checksums_path.read_text(encoding="utf-8") != expected_checksums:
        raise ValueError("phase2a_delta_repair_checksums_content_invalid")

    hold_ids: set[str] = set()
    for hold in holds:
        if not isinstance(hold, Mapping):
            raise ValueError("phase2a_delta_repair_hold_invalid")
        _verify_seal(
            hold,
            "hold_content_sha256",
            "phase2a_delta_repair_hold_seal_invalid",
        )
        old_record_id = str(hold.get("old_record_id") or "")
        if (
            old_record_id in hold_ids
            or old_record_id not in EXPECTED_UNRESOLVED_REPAIR_IDS
            or hold.get("source_admission_authorized") is not False
            or hold.get("source_admitted") is not False
            or hold.get("currentness_hold_retained") is not True
            or hold.get("later_treatment_hold_retained") is not True
        ):
            raise ValueError("phase2a_delta_repair_hold_invalid")
        hold_ids.add(old_record_id)
    if hold_ids != EXPECTED_UNRESOLVED_REPAIR_IDS:
        raise ValueError("phase2a_delta_repair_hold_set_invalid")
    defective_ids = set(str(item) for item in manifest.get("defective_old_record_ids", []))
    if defective_ids != repaired_old_ids | hold_ids or len(defective_ids) != 16:
        raise ValueError("phase2a_delta_repair_defect_partition_invalid")
    return manifest


def _verify_repair_crosslinks(
    repair: Mapping[str, Any],
    original_proposals_by_record: Mapping[str, Mapping[str, Any]],
) -> None:
    for record in repair["records"]:
        old_record_id = str(record.get("old_record_id") or "")
        proposal = original_proposals_by_record.get(old_record_id)
        if proposal is None:
            raise ValueError("phase2a_delta_repair_original_crosslink_invalid")
        old_binding = proposal["quarantine_representation_binding"]["selected_admission_binding"]
        if (
            record.get("old_proposal_id") != proposal.get("proposal_id")
            or record.get("old_proposed_source_version_id")
            != old_binding.get("proposed_source_version_id")
            or record.get("old_raw_sha256") != old_binding.get("raw_sha256")
            or record.get("old_official_urls") != proposal.get("official_urls")
            or record.get("affected_row_ids") != proposal.get("affected_row_ids")
            or record.get("citations") != proposal.get("citations")
            or record.get("titles") != proposal.get("titles")
        ):
            raise ValueError("phase2a_delta_repair_original_crosslink_invalid")
    for hold in repair["unresolved_repair_holds"]:
        if str(hold.get("old_record_id") or "") not in original_proposals_by_record:
            raise ValueError("phase2a_delta_repair_hold_crosslink_invalid")


def _original_proposals_by_record(
    packet: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    proposals = packet["proposed_new_source_admissions"]
    result: dict[str, Mapping[str, Any]] = {}
    for proposal in proposals:
        binding = proposal.get("quarantine_representation_binding", {}).get(
            "selected_admission_binding"
        )
        if not isinstance(binding, Mapping):
            raise ValueError("phase2a_delta_original_proposal_binding_invalid")
        record_id = str(binding.get("record_id") or "")
        if not record_id or record_id in result:
            raise ValueError("phase2a_delta_original_proposal_binding_invalid")
        result[record_id] = proposal
    if len(result) != 247:
        raise ValueError("phase2a_delta_original_proposal_set_invalid")
    return result


def _decision(kind: str, material: Mapping[str, Any]) -> dict[str, Any]:
    base = {
        "decision_kind": kind,
        **material,
        "owner_decision_required": True,
        "owner_outcome": None,
        "owner_decision_applied": False,
        "source_admission_authorized": False,
        "source_admitted": False,
        "source_scan_run": False,
        "index_built": False,
        "embedding_run": False,
        "candidate_mutated": False,
    }
    return {**base, "decision_content_sha256": _sealed(base)}


def _make_delta_decisions(
    *,
    original_proposals_by_record: Mapping[str, Mapping[str, Any]],
    audit: Mapping[str, Any],
    repair: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], ...]:
    audit_by_record = {str(item["record_id"]): item for item in audit["records"]}
    passing: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for record_id, proposal in sorted(original_proposals_by_record.items()):
        audit_record = audit_by_record[record_id]
        binding = proposal["quarantine_representation_binding"]["selected_admission_binding"]
        common = {
            "decision_id": "source-binding-delta-" + _sealed(record_id)[:24],
            "original_proposal_id": proposal["proposal_id"],
            "original_proposal_content_sha256": proposal["proposal_content_sha256"],
            "original_record_id": record_id,
            "original_record_content_sha256": binding["record_content_sha256"],
            "original_proposed_source_version_id": binding["proposed_source_version_id"],
            "original_raw_sha256": binding["raw_sha256"],
            "authority_identity_id": audit_record["authority_identity_id"],
            "audit_record_id": audit_record["audit_record_id"],
            "audit_record_content_sha256": audit_record["record_content_sha256"],
            "audit_verdict": audit_record["substantive_content_verdict"],
            "all_original_packet_holds_retained": True,
        }
        if audit_record["substantive_content_eligible"] is True:
            passing.append(
                _decision(
                    "RETAIN_ORIGINAL_PASSING_REPRESENTATION",
                    {
                        **common,
                        "audit_warning_reason_codes": audit_record["warning_reason_codes"],
                        "recommended_owner_outcome": (
                            "RETAIN_ORIGINAL_SEALED_SOURCE_PROPOSAL_AFTER_"
                            "SUBSTANTIVE_CONTENT_AUDIT_PASS"
                        ),
                    },
                )
            )
        else:
            rejected.append(
                _decision(
                    "REJECT_DEFECTIVE_ORIGINAL_REPRESENTATION",
                    {
                        **common,
                        "audit_failure_reason_codes": audit_record["failure_reason_codes"],
                        "recommended_owner_outcome": (
                            "REJECT_ORIGINAL_NON_SUBSTANTIVE_REPRESENTATION_"
                            "AND_RETAIN_NO_ADMISSION_HOLD"
                        ),
                    },
                )
            )

    corrected: list[dict[str, Any]] = []
    for record in sorted(repair["records"], key=lambda item: item["record_id"]):
        old_id = str(record["old_record_id"])
        original = original_proposals_by_record[old_id]
        corrected.append(
            _decision(
                "PROPOSE_CORRECTED_SUBSTANTIVE_REPRESENTATION_ADMISSION",
                {
                    "decision_id": "source-binding-delta-" + _sealed(record)[:24],
                    "repair_record_id": record["record_id"],
                    "repair_record_content_sha256": record["record_content_sha256"],
                    "replacement_key": record["replacement_key"],
                    "old_record_id": old_id,
                    "old_proposal_id": original["proposal_id"],
                    "old_proposal_content_sha256": original["proposal_content_sha256"],
                    "affected_row_ids": record["affected_row_ids"],
                    "titles": record["titles"],
                    "citations": record["citations"],
                    "canonical_url": record["canonical_url"],
                    "representation_url": record["representation_url"],
                    "final_url": record["final_url"],
                    "content_type": record["content_type"],
                    "bytes": record["bytes"],
                    "raw_sha256": record["raw_sha256"],
                    "quarantine_member": record["quarantine_member"],
                    "proposed_source_version_id": record["proposed_source_version_id"],
                    "source_version_mode": record["source_version_mode"],
                    "content_fitness_status": record["content_fitness_status"],
                    "title_markers_verified": record["title_markers_verified"],
                    "locator_markers_verified": record["locator_markers_verified"],
                    "paragraph_markers_verified": record["paragraph_markers_verified"],
                    "currentness_hold_retained": True,
                    "later_treatment_hold_retained": True,
                    "all_original_packet_holds_retained": True,
                    "changed_bytes_not_covered_by_prior_owner_adoption": True,
                    "recommended_owner_outcome": (
                        "ADMIT_ONLY_THIS_EXACT_CORRECTED_SUBSTANTIVE_"
                        "REPRESENTATION_WITH_ALL_HOLDS_RETAINED"
                    ),
                },
            )
        )

    repair_holds: list[dict[str, Any]] = []
    for hold in sorted(repair["unresolved_repair_holds"], key=lambda item: item["old_record_id"]):
        original = original_proposals_by_record[str(hold["old_record_id"])]
        repair_holds.append(
            _decision(
                "RETAIN_UNRESOLVED_REPAIR_HOLD",
                {
                    "decision_id": "source-binding-delta-" + _sealed(hold)[:24],
                    "old_record_id": hold["old_record_id"],
                    "old_proposal_id": original["proposal_id"],
                    "old_proposal_content_sha256": original["proposal_content_sha256"],
                    "repair_hold_content_sha256": hold["hold_content_sha256"],
                    "category": hold["category"],
                    "reason_code": hold["reason_code"],
                    "checked_official_endpoints": hold["checked_official_endpoints"],
                    "observed_results": hold["observed_results"],
                    "currentness_hold_retained": True,
                    "later_treatment_hold_retained": True,
                    "all_original_packet_holds_retained": True,
                    "recommended_owner_outcome": (
                        "RETAIN_EXPLICIT_REPAIR_HOLD_NO_SOURCE_ADMISSION"
                    ),
                },
            )
        )
    if tuple(map(len, (passing, rejected, corrected, repair_holds))) != (
        231,
        16,
        15,
        5,
    ):
        raise ValueError("phase2a_delta_decision_partition_invalid")
    return passing, rejected, corrected, repair_holds


def _privacy_check_string(value: str, *, field: str) -> None:
    if field in {"file_name", "manifest_file_name", "name"}:
        if value not in _CONTROLLED_ARTIFACT_NAMES:
            raise ValueError("phase2a_delta_privacy_artifact_name_invalid")
        return
    if field == "quarantine_member":
        if _REPAIR_MEMBER.fullmatch(value) is None:
            raise ValueError("phase2a_delta_privacy_artifact_name_invalid")
        return
    if field == "root_name":
        if value != EXPECTED_REPAIR_ROOT_NAME:
            raise ValueError("phase2a_delta_privacy_artifact_name_invalid")
        return
    if field == "relative_path":
        allowed = {str(item["relative_path"]) for item in FAILED_LINEAGE_BINDINGS}
        if value not in allowed:
            raise ValueError("phase2a_delta_privacy_artifact_name_invalid")
        return

    casefolded = value.casefold()
    if (
        "agnes" in casefolded
        or "hltsang" in casefolded
        or "legalbot-new" in casefolded
        or str(PROJECT_ROOT).casefold() in casefolded
        or "file://" in casefolded
        or value.startswith(("~/", "~\\"))
        or _EMAIL.search(value)
        or _WINDOWS_DRIVE_PATH.search(value)
        or _WINDOWS_UNC_PATH.search(value)
    ):
        raise ValueError("phase2a_delta_privacy_violation")

    def _replace_url(match: re.Match[str]) -> str:
        url = match.group(0).rstrip(".;")
        parsed = urlparse(url)
        if (
            parsed.scheme.casefold() != "https"
            or parsed.hostname not in _APPROVED_PUBLIC_HTTPS_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
        ):
            raise ValueError("phase2a_delta_privacy_url_not_approved")
        return "<APPROVED_PUBLIC_HTTPS_URL>" + match.group(0)[len(url) :]

    without_urls = _URL.sub(_replace_url, value)
    without_controlled_names = without_urls
    for name in sorted(_CONTROLLED_ARTIFACT_NAMES, key=len, reverse=True):
        without_controlled_names = without_controlled_names.replace(name, "<ARTIFACT>")
    if _POSIX_ABSOLUTE_PATH.search(without_controlled_names) or _PLAUSIBLE_PERSONAL_FILENAME.search(
        without_controlled_names
    ):
        raise ValueError("phase2a_delta_privacy_violation")


def _privacy_check(values: Sequence[Any]) -> None:
    def walk(value: Any, path: tuple[str, ...]) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                key_text = str(key)
                _privacy_check_string(key_text, field="mapping_key")
                walk(nested, (*path, key_text))
        elif isinstance(value, list | tuple):
            for ordinal, nested in enumerate(value):
                walk(nested, (*path, str(ordinal)))
        elif isinstance(value, str):
            _privacy_check_string(value, field=path[-1] if path else "value")

    walk(list(values), ("root",))


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


def _publish_directory_noreplace(staging: Path, output: Path) -> None:
    """Atomically publish ``staging`` while refusing to replace ``output``."""

    libc = ctypes.CDLL(None, use_errno=True)
    source = os.fsencode(staging)
    target = os.fsencode(output)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        renamex_np = libc.renamex_np
        renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex_np.restype = ctypes.c_int
        result = renamex_np(source, target, 0x00000004)  # RENAME_EXCL
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        renameat2 = libc.renameat2
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(-100, source, -100, target, 0x00000001)  # RENAME_NOREPLACE
    else:
        raise RuntimeError("phase2a_delta_atomic_noreplace_unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ValueError("phase2a_delta_output_already_exists")
    raise OSError(error_number, "phase2a_delta_atomic_publish_failed")


def _ensure_output_path(output_root: Path) -> Path:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_delta_output_already_exists")
    review = OUTPUT_REVIEW_ROOT.resolve(strict=True)
    parent = output_root.parent.resolve(strict=True)
    resolved = parent / output_root.name
    if not output_root.name or not resolved.is_relative_to(review):
        raise ValueError("phase2a_delta_output_outside_review_root")
    return resolved


def build_delta_packet(
    *,
    repair_binding: RepairPackageBinding,
    output_root: Path,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    """Build the exact owner delta packet without applying any decision."""

    output = _ensure_output_path(output_root)
    timestamp = created_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("phase2a_delta_created_at_must_be_aware")
    original_packet = _verify_exact_original_packet()
    _verify_owner_adoption_receipt()
    proposals_by_record = _original_proposals_by_record(original_packet)
    audit = _verify_content_audit(proposals_by_record)
    failed_lineage = _verify_failed_lineage()
    repair = _verify_repair_package(repair_binding)
    _verify_repair_crosslinks(repair, proposals_by_record)

    audit_failure_ids = {
        str(item["record_id"])
        for item in audit["records"]
        if item["substantive_content_verdict"] == "FAIL"
    }
    repair_defect_ids = set(str(item) for item in repair["defective_old_record_ids"])
    if audit_failure_ids != repair_defect_ids:
        raise ValueError("phase2a_delta_repair_audit_failure_set_mismatch")

    passing, rejected, corrected, repair_holds = _make_delta_decisions(
        original_proposals_by_record=proposals_by_record,
        audit=audit,
        repair=repair,
    )
    original_quarantine_holds = [
        {
            "hold_id": item["hold_id"],
            "hold_content_sha256": item["hold_content_sha256"],
            "canonical_authority_identity_key": item["canonical_authority_identity_key"],
        }
        for item in original_packet["quarantine_source_admission_holds"]
    ]
    original_identity_holds = [
        {
            "anomaly_id": item["anomaly_id"],
            "anomaly_content_sha256": item["anomaly_content_sha256"],
            "row_id": item["row_id"],
            "hold_reason_codes": item["hold_reason_codes"],
        }
        for item in original_packet["source_identity_and_admission_holds"]
    ]
    source_bindings = {
        "original_owner_packet": {
            "file_name": ORIGINAL_PACKET_NAME,
            "content_sha256": EXPECTED_ORIGINAL_PACKET_CONTENT_SHA256,
            "file_sha256": EXPECTED_ORIGINAL_PACKET_FILE_SHA256,
        },
        "sealed_owner_adoption_receipt": {
            "file_name": OWNER_RECEIPT_PATH.name,
            "content_sha256": EXPECTED_OWNER_RECEIPT_CONTENT_SHA256,
            "file_sha256": EXPECTED_OWNER_RECEIPT_FILE_SHA256,
            "package_content_sha256": EXPECTED_OWNER_RECEIPT_PACKAGE_CONTENT_SHA256,
            "package_file_sha256": EXPECTED_OWNER_RECEIPT_PACKAGE_FILE_SHA256,
        },
        "production_admission_content_audit": {
            "file_name": AUDIT_PATH.name,
            "content_sha256": EXPECTED_AUDIT_CONTENT_SHA256,
            "file_sha256": EXPECTED_AUDIT_FILE_SHA256,
            "outcome_content_sha256": EXPECTED_AUDIT_OUTCOME_CONTENT_SHA256,
            "outcome_file_sha256": EXPECTED_AUDIT_OUTCOME_FILE_SHA256,
            "package_content_sha256": EXPECTED_AUDIT_PACKAGE_CONTENT_SHA256,
            "package_file_sha256": EXPECTED_AUDIT_PACKAGE_FILE_SHA256,
            "checksums_file_sha256": EXPECTED_AUDIT_CHECKSUMS_FILE_SHA256,
        },
        "corrected_r7_repair_quarantine": {
            "root_name": repair_binding.root.name,
            "manifest_file_name": REPAIR_MANIFEST_NAME,
            "manifest_content_sha256": repair_binding.manifest_content_sha256,
            "manifest_file_sha256": repair_binding.manifest_file_sha256,
            "package_content_sha256": repair_binding.package_content_sha256,
            "package_file_sha256": repair_binding.package_file_sha256,
            "checksums_file_sha256": EXPECTED_R7_CHECKSUMS_FILE_SHA256,
            "source_quarantine_manifest_content_sha256": (
                EXPECTED_ORIGINAL_QUARANTINE_CONTENT_SHA256
            ),
            "source_quarantine_manifest_file_sha256": (EXPECTED_ORIGINAL_QUARANTINE_FILE_SHA256),
        },
    }
    summary = {
        "original_source_proposal_count": 247,
        "retained_original_passing_representation_count": 231,
        "rejected_defective_original_representation_count": 16,
        "tas_pass_with_warning_count": 1,
        "corrected_replacement_representation_count": 15,
        "repaired_old_binding_count": 11,
        "unresolved_repair_hold_count": 5,
        "retained_original_quarantine_hold_count": 31,
        "retained_original_identity_and_admission_hold_count": 86,
        "source_binding_delta_owner_decision_count": 267,
        "known_all585_material_hold_count": 1,
        "failed_collection_lineage_count": 6,
        "identical_r5_r6_fingerprint_path_stopped_before_third": True,
    }
    packet_material = {
        "schema": "legalbot.v111.phase2a.source-binding-delta-owner-packet.v1",
        "status": STATUS,
        "created_at": timestamp.astimezone(UTC).isoformat(),
        "route": "OWNER_ADOPTED_INTERNAL_PRIVATE_RESEARCH_TOOL",
        "source_bindings": source_bindings,
        "failed_collection_lineage": failed_lineage,
        "failed_collection_lineage_supplied_admissible_bytes": False,
        "decision_summary": summary,
        "retained_original_passing_representations": passing,
        "rejected_defective_original_representations": rejected,
        "proposed_corrected_source_admissions": corrected,
        "unresolved_repair_holds": repair_holds,
        "retained_original_packet_holds": {
            "every_original_packet_hold_retained": True,
            "inheritance_bound_to_original_packet_content_sha256": (
                EXPECTED_ORIGINAL_PACKET_CONTENT_SHA256
            ),
            "quarantine_source_admission_holds": original_quarantine_holds,
            "source_identity_and_admission_holds": original_identity_holds,
            "all_currentness_later_treatment_jurisdiction_factual_and_other_"
            "decision_holds_retained": True,
        },
        "known_all585_material_hold": {
            "row_id": EXPECTED_MATERIAL_HOLD_ROW_ID,
            "original_decision_content_sha256": (EXPECTED_MATERIAL_HOLD_DECISION_SHA256),
            "recommended_owner_outcome": ("RETAIN_MATERIAL_HOLD_NO_SUPPORTED_OFFICIAL_PROPOSITION"),
            "qualification_status": "BLOCKED_MATERIAL_GAP",
            "current_all585_can_be_successful": False,
            "successful_phase2a_package_may_be_claimed": False,
        },
        "new_exact_owner_adoption_required": True,
        "prior_owner_adoption_does_not_cover_changed_repair_bytes": True,
        "approval_required_for": [
            "RETAIN_231_EXACT_ORIGINAL_AUDIT_PASSING_REPRESENTATIONS",
            "REJECT_AND_HOLD_16_EXACT_DEFECTIVE_ORIGINAL_REPRESENTATIONS",
            "ADMIT_ONLY_15_EXACT_CORRECTED_REPRESENTATIONS",
            "RETAIN_EXACT_EWCA_AND_ALL_FOUR_HUDOC_REPAIR_HOLDS",
            "RETAIN_EVERY_ORIGINAL_PACKET_HOLD",
        ],
        "approval_does_not_authorize": [
            "ANSWER_MODEL_OR_ANSWER_RELEASE",
            "PHASE2B",
            "DEVELOPMENT30",
            "VALIDATION30",
            "PROMOTION",
            "ACTIVE_OR_PREVIOUS_POINTER_WRITES",
            "LIVE_ACTIVATION",
            "TRAINING_EXPORT",
        ],
        **_NO_EXECUTION_FLAGS,
    }
    packet = {
        **packet_material,
        "artifact_content_sha256": _sealed(packet_material),
    }
    packet_raw = _pretty_json(packet)
    packet_file_sha256 = _sha256(packet_raw)
    prompt = f"""PHASE-2A EXACT SOURCE-BINDING DELTA OWNER APPROVAL

Review the complete machine-readable packet before using this text:

- Packet: {PACKET_NAME}
- Exact delta packet content SHA-256: {packet["artifact_content_sha256"]}
- Exact delta packet file SHA-256: {packet_file_sha256}
- Original audited representations retained: 231 (including one exact TAS warning)
- Defective original representations rejected and held: 16
- Exact corrected replacement representations proposed for admission: 15
- Defective old bindings repaired: 11
- Explicit unresolved repair holds: 5 (EWCA and all four HUDOC bindings)
- Every original packet hold remains retained: 31 quarantine holds and 86 identity/admission holds

APPROVAL TEXT

I approve exact Phase-2A source-binding delta owner packet content SHA-256
`{packet["artifact_content_sha256"]}` and every recommendation and retained hold it contains.

I authorize Codex to retain only the 231 exact original representations that passed the sealed substantive-content audit; reject and hold all 16 exact defective original representations; admit only the 15 exact corrected representations whose raw bytes, content identity, source-version identity and repair-record seal are bound in this delta packet; and retain the exact EWCA and all four HUDOC repair holds plus every hold in original packet `{EXPECTED_ORIGINAL_PACKET_CONTENT_SHA256}`.

This approval is the required new exact owner adoption for changed repair bytes. It does not itself execute source admission, scanning, candidate build, indexing, embedding, retrieval re-attestation or qualification. It does not authorize an answer-model run or answer release, Phase 2B, Development 30, Validation 30, promotion, ACTIVE/PREVIOUS writes, live activation or training export.

I acknowledge that `live60-q58:issue-14` remains a material hold, so the current all-585 set cannot qualify successfully and no successful Phase-2A package may be claimed unless that distinct material hold is later resolved through an exact authorized process.

Owner typed name:
Decision date:
"""
    prompt_raw = prompt.encode("utf-8")
    package_material = {
        "schema": "legalbot.v111.phase2a.source-binding-delta-owner-package.v1",
        "status": STATUS,
        "packet_content_sha256": packet["artifact_content_sha256"],
        "artifacts": [
            {
                "name": PACKET_NAME,
                "content_sha256": packet["artifact_content_sha256"],
                "file_sha256": packet_file_sha256,
            },
            {"name": PROMPT_NAME, "file_sha256": _sha256(prompt_raw)},
        ],
        "new_exact_owner_adoption_required": True,
        "known_all585_material_hold_count": 1,
        **_NO_EXECUTION_FLAGS,
    }
    package = {
        **package_material,
        "artifact_content_sha256": _sealed(package_material),
    }
    package_raw = _pretty_json(package)
    artifacts = {
        PACKET_NAME: packet_raw,
        PROMPT_NAME: prompt_raw,
        PACKAGE_NAME: package_raw,
    }
    checksums_raw = "".join(
        f"{_sha256(raw)}  {name}\n" for name, raw in sorted(artifacts.items())
    ).encode("utf-8")
    _privacy_check([packet, package, prompt])

    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent))
    os.chmod(staging, 0o700)
    try:
        for name, raw in sorted(artifacts.items()):
            _write_exclusive(staging / name, raw)
        _write_exclusive(staging / CHECKSUMS_NAME, checksums_raw)
        for path in staging.iterdir():
            os.chmod(path, 0o600)
        _publish_directory_noreplace(staging, output)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return {
        "status": STATUS,
        "output_name": output.name,
        "packet_content_sha256": packet["artifact_content_sha256"],
        "packet_file_sha256": packet_file_sha256,
        "package_content_sha256": package["artifact_content_sha256"],
        "package_file_sha256": _sha256(package_raw),
        **summary,
        "source_admitted": False,
        "source_scan_run": False,
        "index_built": False,
        "embedding_run": False,
        "retrieval_reattestation_run": False,
        "all585_qualification_run": False,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repair-root", type=Path, default=DEFAULT_REPAIR_ROOT)
    parser.add_argument(
        "--repair-manifest-content-sha256",
        default=EXPECTED_R7_MANIFEST_CONTENT_SHA256,
    )
    parser.add_argument("--repair-manifest-file-sha256", default=EXPECTED_R7_MANIFEST_FILE_SHA256)
    parser.add_argument(
        "--repair-package-content-sha256",
        default=EXPECTED_R7_PACKAGE_CONTENT_SHA256,
    )
    parser.add_argument("--repair-package-file-sha256", default=EXPECTED_R7_PACKAGE_FILE_SHA256)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    result = build_delta_packet(
        repair_binding=RepairPackageBinding(
            root=args.repair_root.resolve(strict=False),
            manifest_content_sha256=args.repair_manifest_content_sha256,
            manifest_file_sha256=args.repair_manifest_file_sha256,
            package_content_sha256=args.repair_package_content_sha256,
            package_file_sha256=args.repair_package_file_sha256,
        ),
        output_root=args.output_root.resolve(strict=False),
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
