#!/usr/bin/env python3
"""Build a create-only owner advisory for the 146 Phase-2A blocker rows.

The default build is deliberately conservative: every row from the sealed r3
prequalification report remains a blocker.  A later revision may consume a
separately sealed, exact 146-row decision input, but only the four row-scoped
outcomes validated here are representable.  The builder does not research,
make a legal judgment, apply a decision, materialize a source, scan, build,
embed, retrieve, qualify, mutate a pointer, or start Phase 2B.
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
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
INPUT_REVIEW_ROOT = REVIEW_ROOT
DECISION_INPUT_REVIEW_ROOT = REVIEW_ROOT
OUTPUT_REVIEW_ROOT = REVIEW_ROOT

R3_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-prequalification-blockers-r3"
R3_REPORT_NAME = "PREQUALIFICATION-BLOCKER-REPORT.json"
R3_PACKAGE_NAME = "PACKAGE-MANIFEST.json"
R3_CHECKSUMS_NAME = "SHA256SUMS.txt"
R3_REPORT_CONTENT_SHA256 = "5efc17b16adcae1ceb2ea1bbd7efcaba469ab0340c24b65c1e994132cb337980"
R3_REPORT_FILE_SHA256 = "7cb044a4c9539162281e10ac41e5e0cb1f0cd846b0eb597a0443b0e67fb48899"
R3_PACKAGE_CONTENT_SHA256 = "f53994654198592d9d8f26698386022a16dec123e035aba2673c8abbf6e7d47e"
R3_PACKAGE_FILE_SHA256 = "ec05e33793e762d7c787a567fb23a85ef7484245e09d3d5807d9bbd59d7ded31"
R3_CHECKSUMS_FILE_SHA256 = "641856f44c0acd31e2f4f9c5ef2c9c697702c7766a158b36d3c2f4e7a7d0b0e6"

ORIGINAL_PACKET_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1"
ORIGINAL_PACKET_NAME = "EXACT-REMEDIATION-OWNER-PACKET-361.json"
ORIGINAL_PACKET_CONTENT_SHA256 = "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c"
ORIGINAL_PACKET_FILE_SHA256 = "992770c04cb3e08de64bb98e80aa9801171d3e66e4b573b85919091a78b1db3b"

ORIGINAL_RECEIPT_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-approved-r1"
ORIGINAL_RECEIPT_NAME = "OWNER-ADOPTION-RECEIPT.json"
ORIGINAL_RECEIPT_CONTENT_SHA256 = "a6ea2794b276946dd24ba3d752203dd81ae14f88aae24224a80b7b62f886d539"
ORIGINAL_RECEIPT_FILE_SHA256 = "ffb2d07c8f6f5d2f44fb78efa01e58a49c7bd79ff1fcb18e74c9ee63bd5f3743"

FINAL_PACKET_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-source-delta-safe-fallback-owner-packet-r1"
FINAL_PACKET_NAME = "EXACT-PHASE2A-SOURCE-DELTA-SAFE-FALLBACK-OWNER-PACKET.json"
FINAL_PACKET_CONTENT_SHA256 = "fd8034b33ebfb0f6fdd6cedd2426b54e368bff9c20b408f3fbd86fb40b9f1b34"
FINAL_PACKET_FILE_SHA256 = "8ef85082a8d723ca1396f0c03c244f673a3e775bd0e4b336b443228a3a012341"

FINAL_RECEIPT_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-final-remediation-owner-approved-r1"
FINAL_RECEIPT_NAME = "OWNER-ADOPTION-RECEIPT.json"
EXECUTION_AUTHORITY_NAME = "PHASE2A-EXECUTION-AUTHORITY.json"
FINAL_RECEIPT_CONTENT_SHA256 = "9b47af237fe4a811b51a4c21f02db1702b71505128576fa54cbd4794e1e739fa"
FINAL_RECEIPT_FILE_SHA256 = "dcf5f5f33debcbecff17552e074a9c12437d7b8cd77d0879c7d19072156c3383"
EXECUTION_AUTHORITY_CONTENT_SHA256 = (
    "eb0eda2f34c8b261ea38fc9d697257cdd3bd6253c18c2d91355328c8cb78ef7b"
)
EXECUTION_AUTHORITY_FILE_SHA256 = "5171ce79007c68484f9854b5188bf7e7af8f880407b6fbad6e3f808d0c7630ad"

R3_ROOT = REVIEW_ROOT / R3_ROOT_NAME
ORIGINAL_PACKET_ROOT = REVIEW_ROOT / ORIGINAL_PACKET_ROOT_NAME
ORIGINAL_RECEIPT_ROOT = REVIEW_ROOT / ORIGINAL_RECEIPT_ROOT_NAME
FINAL_PACKET_ROOT = REVIEW_ROOT / FINAL_PACKET_ROOT_NAME
FINAL_RECEIPT_ROOT = REVIEW_ROOT / FINAL_RECEIPT_ROOT_NAME

PREDECESSOR_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-146-row-superseding-remediation-advisory-r1"
PREDECESSOR_ROOT = REVIEW_ROOT / PREDECESSOR_ROOT_NAME
PREDECESSOR_ADVISORY_CONTENT_SHA256 = (
    "a746df33fe13993ec77d755a2a8901dd6b1ef3761125678bc235ff3de625c56d"
)
PREDECESSOR_ADVISORY_FILE_SHA256 = (
    "dfeb37316f00a76a00f4a9684c0a1ccb721859a594fc3a9e05a759dcdc706063"
)
PREDECESSOR_PACKAGE_CONTENT_SHA256 = (
    "eb430e27e65614839955e8f4cfe63c36fefb01ce2a112bb5ccb0b65f9cd0b66f"
)
PREDECESSOR_PACKAGE_FILE_SHA256 = "f63f9599b141545ff3943b5eede7a59885c1df614fa49bacc4af79a2d5119eba"

AUTHORITATIVE_BASELINE_ROOT_NAME = (
    "LegalBot-Phase2A-2026-08-28-146-row-superseding-remediation-advisory-r2"
)
AUTHORITATIVE_BASELINE_ROOT = REVIEW_ROOT / AUTHORITATIVE_BASELINE_ROOT_NAME
AUTHORITATIVE_BASELINE_ADVISORY_CONTENT_SHA256 = (
    "6078e556e8ee3eb551bd48d310b2a89728e317dc8c240f22030799b54e595e1d"
)
AUTHORITATIVE_BASELINE_ADVISORY_FILE_SHA256 = (
    "81eebbe55d18d5257217d28760d136544523716adfb17746cd6cb34bceb27659"
)
AUTHORITATIVE_BASELINE_PACKAGE_CONTENT_SHA256 = (
    "9137f0538733b1e2abb24889157acaf5afe650a17993b69a8650a314358182c2"
)
AUTHORITATIVE_BASELINE_PACKAGE_FILE_SHA256 = (
    "03b3a94629f0a9140b4fc7da9cffbb0b2c8f7021b06bbce7dc6b201017228050"
)

DEFAULT_OUTPUT_ROOT = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-146-row-superseding-remediation-advisory-r2"
)
ADVISORY_NAME = "EXACT-146-ROW-SUPERSEDING-REMEDIATION-ADVISORY.json"
DECISION_TEMPLATE_NAME = "OWNER-DECISION-INPUT-TEMPLATE.json"
REVIEW_PROMPT_NAME = "OWNER-REVIEW-INSTRUCTIONS.txt"
APPROVAL_PROMPT_NAME = "OWNER-APPROVAL-PROMPT.txt"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

ADVISORY_SCHEMA = "legalbot.v111.phase2a.superseding-remediation-advisory-146.v1"
PACKAGE_SCHEMA = "legalbot.v111.phase2a.superseding-remediation-advisory-package.v1"
DECISION_INPUT_SCHEMA = "legalbot.v111.phase2a.superseding-remediation-owner-input-146.v1"
DECISION_ROW_SCHEMA = "legalbot.v111.phase2a.superseding-remediation-owner-input-row.v1"
FULL_UPGRADE_SCHEMA = "legalbot.v111.phase2a.full-evidence-support-upgrade.v1"
FULL_FINDING_SCHEMA = "legalbot.v111.phase2a.owner-full-support-finding.v1"
EVIDENCE_BINDING_SCHEMA = "legalbot.v111.phase2a.exact-evidence-binding.v1"
EVIDENCE_SPAN_SCHEMA = "legalbot.v111.phase2a.exact-evidence-span-reference.v1"
FALLBACK_CLASSIFICATION_SCHEMA = "legalbot.v111.phase2a.matter-info-only-classification.v1"
SCOPE_CHANGE_SCHEMA = "legalbot.v111.phase2a.owner-rewrite-exclusion.v1"

OUTCOME_FULL = "FULL_EVIDENCE_BINDING"
OUTCOME_FALLBACK = "STRICT_NO_LEGAL_CLAIM_MATTER_INFO_FALLBACK"
OUTCOME_SCOPE_CHANGE = "OWNER_REWRITE_OR_EXCLUSION"
OUTCOME_RETAIN = "RETAIN_BLOCKER"
ALLOWED_OUTCOMES = frozenset({OUTCOME_FULL, OUTCOME_FALLBACK, OUTCOME_SCOPE_CHANGE, OUTCOME_RETAIN})
SCOPE_CHANGE_ACTIONS = frozenset(
    {
        "REWRITE_ROW_QUALIFICATION_CONTRACT",
        "EXCLUDE_EXACT_UNSUPPORTED_COMPONENTS",
        "EXCLUDE_ROW_FROM_PHASE2A_QUALIFICATION_SCOPE",
    }
)

STATUS_BLOCKED = "EXACT_146_ROW_ADVISORY_BASELINE_BLOCKED_NOT_READY_FOR_APPROVAL"
STATUS_REVIEW = "EXACT_146_ROW_SUPERSEDING_ADVISORY_READY_FOR_OWNER_REVIEW_NOT_ADOPTED"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ROW_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}:issue-[0-9]{2}$")
_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9+.-])/(?!/)[^\s'\"<>]*")
_WINDOWS_PATH = re.compile(r"(?i)(?:^|[^a-z0-9])[a-z]:[\\/]")
_EMAIL = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")

# Every field describes state changed by this builder.  All must remain false
# in the advisory and package, including recursively supplied decision input.
_NO_EXECUTION_FLAGS = {
    "owner_approved": False,
    "owner_adoption_recorded": False,
    "owner_decision_application_authorized": False,
    "owner_decisions_applied": False,
    "owner_outcomes_applied": False,
    "source_delta_decisions_applied": False,
    "safe_fallback_decision_applied": False,
    "evaluation_contract_mutated": False,
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


def _content_sha256(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _sealed(value: Mapping[str, Any], *, field: str = "artifact_content_sha256") -> dict[str, Any]:
    material = dict(value)
    material.pop(field, None)
    return {**material, field: _content_sha256(material)}


def _require_seal(
    value: Mapping[str, Any],
    *,
    field: str = "artifact_content_sha256",
    expected: str | None = None,
    code: str,
) -> str:
    observed = str(value.get(field) or "")
    material = dict(value)
    material.pop(field, None)
    if (
        _SHA256.fullmatch(observed) is None
        or observed != _content_sha256(material)
        or (expected is not None and observed != expected)
    ):
        raise ValueError(code)
    return observed


def _load_object(path: Path, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(code) from exc
    if not isinstance(value, dict):
        raise ValueError(code)
    return value


def _require_regular_file(path: Path, expected_sha256: str, code: str) -> None:
    if path.is_symlink() or not path.is_file() or _sha256_file(path) != expected_sha256:
        raise ValueError(code)


def _require_root(root: Path, expected_name: str, expected_members: set[str]) -> Path:
    if root.is_symlink() or not root.is_dir() or root.name != expected_name:
        raise ValueError("phase2a_146_input_root_invalid")
    review = INPUT_REVIEW_ROOT.resolve(strict=True)
    resolved = root.resolve(strict=True)
    if resolved != review / expected_name:
        raise ValueError("phase2a_146_input_root_identity_invalid")
    if {item.name for item in resolved.iterdir()} != expected_members:
        raise ValueError("phase2a_146_input_root_members_invalid")
    return resolved


def _binding(
    *, kind: str, root_name: str, file_name: str, content: str, file: str
) -> dict[str, Any]:
    return {
        "kind": kind,
        "root_name": root_name,
        "file_name": file_name,
        "content_sha256": content,
        "file_sha256": file,
    }


def _predecessor_spec(*, decision_input_present: bool) -> dict[str, str]:
    if decision_input_present:
        return {
            "kind": "authoritative_baseline_146_row_advisory_r2",
            "root_name": AUTHORITATIVE_BASELINE_ROOT_NAME,
            "advisory_content_sha256": AUTHORITATIVE_BASELINE_ADVISORY_CONTENT_SHA256,
            "advisory_file_sha256": AUTHORITATIVE_BASELINE_ADVISORY_FILE_SHA256,
            "package_content_sha256": AUTHORITATIVE_BASELINE_PACKAGE_CONTENT_SHA256,
            "package_file_sha256": AUTHORITATIVE_BASELINE_PACKAGE_FILE_SHA256,
            "revision_reason_code": "EXACT_146_ROW_DECISION_INPUT_SUPERSESSION",
        }
    return {
        "kind": "predecessor_146_row_advisory_r1",
        "root_name": PREDECESSOR_ROOT_NAME,
        "advisory_content_sha256": PREDECESSOR_ADVISORY_CONTENT_SHA256,
        "advisory_file_sha256": PREDECESSOR_ADVISORY_FILE_SHA256,
        "package_content_sha256": PREDECESSOR_PACKAGE_CONTENT_SHA256,
        "package_file_sha256": PREDECESSOR_PACKAGE_FILE_SHA256,
        "revision_reason_code": "EXPAND_EXPLICIT_NO_EXECUTION_FIELD_SET",
    }


def _verify_upstream(
    *,
    r3_root: Path,
    predecessor_root: Path,
    predecessor_spec: Mapping[str, str],
    original_packet_root: Path,
    original_receipt_root: Path,
    final_packet_root: Path,
    final_receipt_root: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    r3 = _require_root(
        r3_root,
        R3_ROOT_NAME,
        {R3_REPORT_NAME, R3_PACKAGE_NAME, R3_CHECKSUMS_NAME},
    )
    _require_regular_file(
        r3 / R3_REPORT_NAME, R3_REPORT_FILE_SHA256, "phase2a_146_r3_report_file_invalid"
    )
    _require_regular_file(
        r3 / R3_PACKAGE_NAME, R3_PACKAGE_FILE_SHA256, "phase2a_146_r3_package_file_invalid"
    )
    _require_regular_file(
        r3 / R3_CHECKSUMS_NAME, R3_CHECKSUMS_FILE_SHA256, "phase2a_146_r3_checksums_file_invalid"
    )
    expected_checksums = (
        f"{R3_REPORT_FILE_SHA256}  {R3_REPORT_NAME}\n{R3_PACKAGE_FILE_SHA256}  {R3_PACKAGE_NAME}\n"
    ).encode()
    if (r3 / R3_CHECKSUMS_NAME).read_bytes() != expected_checksums:
        raise ValueError("phase2a_146_r3_checksums_invalid")
    report = _load_object(r3 / R3_REPORT_NAME, "phase2a_146_r3_report_invalid")
    package = _load_object(r3 / R3_PACKAGE_NAME, "phase2a_146_r3_package_invalid")
    _require_seal(
        report, expected=R3_REPORT_CONTENT_SHA256, code="phase2a_146_r3_report_seal_invalid"
    )
    _require_seal(
        package, expected=R3_PACKAGE_CONTENT_SHA256, code="phase2a_146_r3_package_seal_invalid"
    )
    if (
        report.get("schema") != "legalbot.v111.phase2a.prequalification-blocker-report.v1"
        or report.get("status") != "BLOCKED_BEFORE_SUCCESSOR_QUALIFICATION"
        or report.get("counts", {}).get("blocking_row_count") != 146
        or report.get("execution_chain")
        != {
            "consumed_count": 0,
            "content_sha256": EXECUTION_AUTHORITY_CONTENT_SHA256,
            "remaining_count": 1,
            "status": "AVAILABLE_UNSPENT",
            "this_read_only_report_consumes_chain": False,
            "total_count": 1,
        }
        or package.get("report_content_sha256") != R3_REPORT_CONTENT_SHA256
        or package.get("report_file_sha256") != R3_REPORT_FILE_SHA256
        or package.get("blocking_row_count") != 146
    ):
        raise ValueError("phase2a_146_r3_contract_invalid")

    original_packet = _require_root(
        original_packet_root,
        ORIGINAL_PACKET_ROOT_NAME,
        {
            ORIGINAL_PACKET_NAME,
            "OWNER-APPROVAL-PROMPT.txt",
            "PACKAGE-MANIFEST.json",
            "SHA256SUMS.txt",
            "OWNER-APPROVAL-REPLY-2026-08-28.txt",
        },
    )
    _require_regular_file(
        original_packet / ORIGINAL_PACKET_NAME,
        ORIGINAL_PACKET_FILE_SHA256,
        "phase2a_146_original_packet_file_invalid",
    )
    original_packet_value = _load_object(
        original_packet / ORIGINAL_PACKET_NAME, "phase2a_146_original_packet_invalid"
    )
    _require_seal(
        original_packet_value,
        expected=ORIGINAL_PACKET_CONTENT_SHA256,
        code="phase2a_146_original_packet_seal_invalid",
    )

    original_receipt = _require_root(
        original_receipt_root,
        ORIGINAL_RECEIPT_ROOT_NAME,
        {
            "OWNER-ADOPTION-OUTCOME.json",
            ORIGINAL_RECEIPT_NAME,
            "OWNER-APPROVAL-VERBATIM.txt",
            "PACKAGE-MANIFEST.json",
            "SHA256SUMS.txt",
        },
    )
    _require_regular_file(
        original_receipt / ORIGINAL_RECEIPT_NAME,
        ORIGINAL_RECEIPT_FILE_SHA256,
        "phase2a_146_original_receipt_file_invalid",
    )
    original_receipt_value = _load_object(
        original_receipt / ORIGINAL_RECEIPT_NAME, "phase2a_146_original_receipt_invalid"
    )
    _require_seal(
        original_receipt_value,
        expected=ORIGINAL_RECEIPT_CONTENT_SHA256,
        code="phase2a_146_original_receipt_seal_invalid",
    )
    if (
        original_receipt_value.get("source_bindings", {})
        .get("owner_packet", {})
        .get("content_sha256")
        != ORIGINAL_PACKET_CONTENT_SHA256
    ):
        raise ValueError("phase2a_146_original_receipt_binding_invalid")

    final_packet = _require_root(
        final_packet_root,
        FINAL_PACKET_ROOT_NAME,
        {FINAL_PACKET_NAME, "OWNER-APPROVAL-PROMPT.txt", "PACKAGE-MANIFEST.json", "SHA256SUMS.txt"},
    )
    _require_regular_file(
        final_packet / FINAL_PACKET_NAME,
        FINAL_PACKET_FILE_SHA256,
        "phase2a_146_final_packet_file_invalid",
    )
    final_packet_value = _load_object(
        final_packet / FINAL_PACKET_NAME, "phase2a_146_final_packet_invalid"
    )
    _require_seal(
        final_packet_value,
        expected=FINAL_PACKET_CONTENT_SHA256,
        code="phase2a_146_final_packet_seal_invalid",
    )

    final_receipt = _require_root(
        final_receipt_root,
        FINAL_RECEIPT_ROOT_NAME,
        {
            "OWNER-ADOPTION-OUTCOME.json",
            FINAL_RECEIPT_NAME,
            "OWNER-APPROVAL-VERBATIM.txt",
            EXECUTION_AUTHORITY_NAME,
            "PACKAGE-MANIFEST.json",
            "SHA256SUMS.txt",
        },
    )
    _require_regular_file(
        final_receipt / FINAL_RECEIPT_NAME,
        FINAL_RECEIPT_FILE_SHA256,
        "phase2a_146_final_receipt_file_invalid",
    )
    _require_regular_file(
        final_receipt / EXECUTION_AUTHORITY_NAME,
        EXECUTION_AUTHORITY_FILE_SHA256,
        "phase2a_146_execution_authority_file_invalid",
    )
    final_receipt_value = _load_object(
        final_receipt / FINAL_RECEIPT_NAME, "phase2a_146_final_receipt_invalid"
    )
    authority = _load_object(
        final_receipt / EXECUTION_AUTHORITY_NAME, "phase2a_146_execution_authority_invalid"
    )
    _require_seal(
        final_receipt_value,
        expected=FINAL_RECEIPT_CONTENT_SHA256,
        code="phase2a_146_final_receipt_seal_invalid",
    )
    _require_seal(
        authority,
        expected=EXECUTION_AUTHORITY_CONTENT_SHA256,
        code="phase2a_146_execution_authority_seal_invalid",
    )
    if any(
        (
            final_receipt_value.get("original_owner_receipt_content_sha256")
            != ORIGINAL_RECEIPT_CONTENT_SHA256,
            final_receipt_value.get("final_owner_packet_content_sha256")
            != FINAL_PACKET_CONTENT_SHA256,
            final_receipt_value.get("execution_authority_content_sha256")
            != EXECUTION_AUTHORITY_CONTENT_SHA256,
            final_receipt_value.get("execution_chain_count") != 1,
            final_receipt_value.get("execution_chain_consumed_count") != 0,
            final_receipt_value.get("execution_chain_remaining_count") != 1,
            authority.get("status") != "AVAILABLE_UNSPENT",
            authority.get("total_execution_chain_count") != 1,
            authority.get("execution_chain_consumed_count") != 0,
            authority.get("execution_chain_remaining_count") != 1,
            authority.get("source_scan_run") is not False,
            authority.get("successor_build_run") is not False,
            authority.get("embedding_run") is not False,
            authority.get("retrieval_reattestation_run") is not False,
            authority.get("all585_qualification_run") is not False,
            authority.get("new_or_additional_authority_created") is not False,
        )
    ):
        raise ValueError("phase2a_146_execution_chain_not_exactly_one_unspent")

    expected_r3_bindings = {
        (
            "exact_remediation_owner_packet_361",
            ORIGINAL_PACKET_CONTENT_SHA256,
            ORIGINAL_PACKET_FILE_SHA256,
        ),
        ("final_remediation_owner_packet", FINAL_PACKET_CONTENT_SHA256, FINAL_PACKET_FILE_SHA256),
        ("final_owner_adoption_receipt", FINAL_RECEIPT_CONTENT_SHA256, FINAL_RECEIPT_FILE_SHA256),
        (
            "single_phase2a_execution_authority",
            EXECUTION_AUTHORITY_CONTENT_SHA256,
            EXECUTION_AUTHORITY_FILE_SHA256,
        ),
    }
    observed_r3_bindings = {
        (str(item.get("kind")), str(item.get("content_sha256")), str(item.get("file_sha256")))
        for item in report.get("input_bindings", [])
        if isinstance(item, Mapping)
    }
    if observed_r3_bindings != expected_r3_bindings:
        raise ValueError("phase2a_146_r3_upstream_binding_set_invalid")

    predecessor = _require_root(
        predecessor_root,
        predecessor_spec["root_name"],
        {
            ADVISORY_NAME,
            DECISION_TEMPLATE_NAME,
            REVIEW_PROMPT_NAME,
            PACKAGE_NAME,
            CHECKSUMS_NAME,
        },
    )
    _require_regular_file(
        predecessor / ADVISORY_NAME,
        predecessor_spec["advisory_file_sha256"],
        "phase2a_146_predecessor_advisory_file_invalid",
    )
    _require_regular_file(
        predecessor / PACKAGE_NAME,
        predecessor_spec["package_file_sha256"],
        "phase2a_146_predecessor_package_file_invalid",
    )
    predecessor_advisory = _load_object(
        predecessor / ADVISORY_NAME,
        "phase2a_146_predecessor_advisory_invalid",
    )
    predecessor_package = _load_object(
        predecessor / PACKAGE_NAME,
        "phase2a_146_predecessor_package_invalid",
    )
    _require_seal(
        predecessor_advisory,
        expected=predecessor_spec["advisory_content_sha256"],
        code="phase2a_146_predecessor_advisory_seal_invalid",
    )
    _require_seal(
        predecessor_package,
        expected=predecessor_spec["package_content_sha256"],
        code="phase2a_146_predecessor_package_seal_invalid",
    )
    if (
        predecessor_advisory.get("status") != STATUS_BLOCKED
        or predecessor_advisory.get("row_count") != 146
        or predecessor_advisory.get("fallback_boundary", {}).get("fallback_row_count") != 0
        or predecessor_advisory.get("retained_blocker_boundary", {}).get("retained_row_count")
        != 146
        or predecessor_package.get("advisory_content_sha256")
        != predecessor_spec["advisory_content_sha256"]
    ):
        raise ValueError("phase2a_146_predecessor_contract_invalid")

    bindings = [
        _binding(
            kind="prequalification_blocker_report_r3",
            root_name=R3_ROOT_NAME,
            file_name=R3_REPORT_NAME,
            content=R3_REPORT_CONTENT_SHA256,
            file=R3_REPORT_FILE_SHA256,
        ),
        _binding(
            kind="original_owner_packet_361",
            root_name=ORIGINAL_PACKET_ROOT_NAME,
            file_name=ORIGINAL_PACKET_NAME,
            content=ORIGINAL_PACKET_CONTENT_SHA256,
            file=ORIGINAL_PACKET_FILE_SHA256,
        ),
        _binding(
            kind="original_owner_adoption_receipt",
            root_name=ORIGINAL_RECEIPT_ROOT_NAME,
            file_name=ORIGINAL_RECEIPT_NAME,
            content=ORIGINAL_RECEIPT_CONTENT_SHA256,
            file=ORIGINAL_RECEIPT_FILE_SHA256,
        ),
        _binding(
            kind="final_owner_packet",
            root_name=FINAL_PACKET_ROOT_NAME,
            file_name=FINAL_PACKET_NAME,
            content=FINAL_PACKET_CONTENT_SHA256,
            file=FINAL_PACKET_FILE_SHA256,
        ),
        _binding(
            kind="final_owner_adoption_receipt",
            root_name=FINAL_RECEIPT_ROOT_NAME,
            file_name=FINAL_RECEIPT_NAME,
            content=FINAL_RECEIPT_CONTENT_SHA256,
            file=FINAL_RECEIPT_FILE_SHA256,
        ),
        _binding(
            kind="single_unspent_execution_authority",
            root_name=FINAL_RECEIPT_ROOT_NAME,
            file_name=EXECUTION_AUTHORITY_NAME,
            content=EXECUTION_AUTHORITY_CONTENT_SHA256,
            file=EXECUTION_AUTHORITY_FILE_SHA256,
        ),
        _binding(
            kind=predecessor_spec["kind"],
            root_name=predecessor_spec["root_name"],
            file_name=ADVISORY_NAME,
            content=predecessor_spec["advisory_content_sha256"],
            file=predecessor_spec["advisory_file_sha256"],
        ),
    ]
    return report, bindings


def _component_identity(component: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "component_ordinal": int(component["component_ordinal"]),
        "prior_support_fit": str(component["support_fit"]),
        "proposition_text_sha256": str(component["proposition_text_sha256"]),
        "component_content_sha256": _content_sha256(component),
    }


def _retain_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    material: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.retained-blocker-outcome.v1",
        "row_id": row["row_id"],
        "r3_row_record_content_sha256": row["record_content_sha256"],
        "retained_blocking_components": [
            _component_identity(component) for component in row["blocking_components"]
        ],
        "retained_unclassified_hold_record_content_sha256s": sorted(
            str(item["record_content_sha256"]) for item in row["unclassified_unresolved_holds"]
        ),
        "material_gap_retained": True,
        "technical_pass_eligible": False,
    }
    return _sealed(material, field="outcome_payload_content_sha256")


def _default_decision(row: Mapping[str, Any]) -> dict[str, Any]:
    material: dict[str, Any] = {
        "schema": DECISION_ROW_SCHEMA,
        "row_id": row["row_id"],
        "r3_row_record_content_sha256": row["record_content_sha256"],
        "selected_outcome": OUTCOME_RETAIN,
        "outcome_payload": _retain_payload(row),
    }
    return _sealed(material, field="decision_input_record_content_sha256")


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        raise ValueError(code)


def _validate_span(span: Mapping[str, Any]) -> None:
    _require_exact_keys(
        span,
        {"schema", "exact_locator", "span_text_sha256", "evidence_span_content_sha256"},
        "phase2a_146_evidence_span_shape_invalid",
    )
    if (
        span.get("schema") != EVIDENCE_SPAN_SCHEMA
        or not str(span.get("exact_locator") or "").strip()
        or _SHA256.fullmatch(str(span.get("span_text_sha256") or "")) is None
    ):
        raise ValueError("phase2a_146_evidence_span_invalid")
    _require_seal(
        span, field="evidence_span_content_sha256", code="phase2a_146_evidence_span_seal_invalid"
    )


def _validate_evidence_binding(binding: Mapping[str, Any]) -> None:
    _require_exact_keys(
        binding,
        {
            "schema",
            "canonical_authority_identity_id",
            "source_version_id",
            "raw_sha256",
            "canonical_content_sha256",
            "source_admission_record_content_sha256",
            "jurisdiction_finding_content_sha256",
            "currentness_finding_content_sha256",
            "later_treatment_finding_content_sha256",
            "evidence_spans",
            "record_content_sha256",
        },
        "phase2a_146_evidence_binding_shape_invalid",
    )
    digest_fields = (
        "raw_sha256",
        "canonical_content_sha256",
        "source_admission_record_content_sha256",
        "jurisdiction_finding_content_sha256",
        "currentness_finding_content_sha256",
        "later_treatment_finding_content_sha256",
    )
    spans = binding.get("evidence_spans")
    if (
        binding.get("schema") != EVIDENCE_BINDING_SCHEMA
        or not str(binding.get("canonical_authority_identity_id") or "").strip()
        or not str(binding.get("source_version_id") or "").strip()
        or any(_SHA256.fullmatch(str(binding.get(field) or "")) is None for field in digest_fields)
        or not isinstance(spans, list)
        or not spans
    ):
        raise ValueError("phase2a_146_evidence_binding_invalid")
    for span in spans:
        if not isinstance(span, Mapping):
            raise ValueError("phase2a_146_evidence_span_invalid")
        _validate_span(span)
    _require_seal(
        binding, field="record_content_sha256", code="phase2a_146_evidence_binding_seal_invalid"
    )


def _validate_full_payload(payload: Mapping[str, Any], row: Mapping[str, Any]) -> None:
    _require_exact_keys(
        payload,
        {
            "schema",
            "row_id",
            "r3_row_record_content_sha256",
            "blocking_component_bindings",
            "owner_support_finding",
            "all_prior_blocking_components_now_full",
            "answer_release_eligible",
            "record_content_sha256",
        },
        "phase2a_146_full_payload_shape_invalid",
    )
    bindings = payload.get("blocking_component_bindings")
    prior = {int(item["component_ordinal"]): item for item in row["blocking_components"]}
    if (
        payload.get("schema") != FULL_UPGRADE_SCHEMA
        or payload.get("row_id") != row["row_id"]
        or payload.get("r3_row_record_content_sha256") != row["record_content_sha256"]
        or payload.get("all_prior_blocking_components_now_full") is not True
        or payload.get("answer_release_eligible") is not False
        or not isinstance(bindings, list)
        or len(bindings) != len(prior)
    ):
        raise ValueError("phase2a_146_full_payload_invalid")
    observed: set[int] = set()
    for component in bindings:
        if not isinstance(component, Mapping):
            raise ValueError("phase2a_146_full_component_invalid")
        _require_exact_keys(
            component,
            {
                "component_ordinal",
                "prior_support_fit",
                "proposition_text_sha256",
                "support_fit",
                "evidence_binding_records",
            },
            "phase2a_146_full_component_shape_invalid",
        )
        ordinal = int(component.get("component_ordinal") or 0)
        evidence = component.get("evidence_binding_records")
        expected = prior.get(ordinal)
        if (
            expected is None
            or ordinal in observed
            or component.get("prior_support_fit") != expected["support_fit"]
            or component.get("proposition_text_sha256") != expected["proposition_text_sha256"]
            or component.get("support_fit") != "FULL"
            or not isinstance(evidence, list)
            or not evidence
        ):
            raise ValueError("phase2a_146_full_component_invalid")
        observed.add(ordinal)
        for binding in evidence:
            if not isinstance(binding, Mapping):
                raise ValueError("phase2a_146_evidence_binding_invalid")
            _validate_evidence_binding(binding)
    finding = payload.get("owner_support_finding")
    if not isinstance(finding, Mapping):
        raise ValueError("phase2a_146_full_finding_invalid")
    _require_exact_keys(
        finding,
        {"schema", "row_id", "finding", "component_ordinals", "record_content_sha256"},
        "phase2a_146_full_finding_shape_invalid",
    )
    if (
        finding.get("schema") != FULL_FINDING_SCHEMA
        or finding.get("row_id") != row["row_id"]
        or finding.get("finding") != "ALL_PRIOR_BLOCKING_COMPONENTS_HAVE_EXACT_FULL_SUPPORT"
        or finding.get("component_ordinals") != sorted(prior)
    ):
        raise ValueError("phase2a_146_full_finding_invalid")
    _require_seal(
        finding, field="record_content_sha256", code="phase2a_146_full_finding_seal_invalid"
    )
    _require_seal(
        payload, field="record_content_sha256", code="phase2a_146_full_payload_seal_invalid"
    )


def _fallback_message(row_id: str, requested_information: Sequence[str]) -> str:
    requested = "\n".join(f"- {item}" for item in requested_information)
    return (
        f"I cannot determine issue {row_id} because required matter information is missing. "
        "Please provide all of the following before further review:\n"
        f"{requested}\n"
        "No legal conclusion, rule, advice, citation, EvidenceSpan, source binding, or "
        "answer-model output is provided. You may request review by a qualified human "
        "legal professional."
    )


def _validate_fallback_payload(payload: Mapping[str, Any], row: Mapping[str, Any]) -> None:
    _require_exact_keys(
        payload,
        {
            "schema",
            "row_id",
            "r3_row_record_content_sha256",
            "eligibility_classification_record",
            "fallback_reason_code",
            "ui_cta",
            "knowledge_gap_event",
            "matter_information_gap_event",
            "required_user_message",
            "required_user_message_sha256",
            "reply_match_mode",
            "legal_rule_release_prohibited",
            "legal_advice_release_prohibited",
            "citation_release_prohibited",
            "evidence_span_release_prohibited",
            "source_binding_release_prohibited",
            "answer_model_output_prohibited",
            "answer_release_eligible",
            "record_content_sha256",
        },
        "phase2a_146_fallback_payload_shape_invalid",
    )
    classification = payload.get("eligibility_classification_record")
    if not isinstance(classification, Mapping):
        raise ValueError("phase2a_146_fallback_classification_invalid")
    _require_exact_keys(
        classification,
        {
            "schema",
            "row_id",
            "r3_row_record_content_sha256",
            "classification",
            "classified_component_ordinals",
            "legal_knowledge_gap",
            "official_source_gap",
            "matter_information_gap",
            "requested_information",
            "qualified_human_legal_review_offered",
            "record_content_sha256",
        },
        "phase2a_146_fallback_classification_shape_invalid",
    )
    requested = classification.get("requested_information")
    component_ordinals = sorted(
        int(item["component_ordinal"]) for item in row["blocking_components"]
    )
    if (
        classification.get("schema") != FALLBACK_CLASSIFICATION_SCHEMA
        or classification.get("row_id") != row["row_id"]
        or classification.get("r3_row_record_content_sha256") != row["record_content_sha256"]
        or classification.get("classification")
        != "MATTER_INFORMATION_ONLY_NO_LEGAL_KNOWLEDGE_OR_SOURCE_GAP"
        or classification.get("classified_component_ordinals") != component_ordinals
        or classification.get("legal_knowledge_gap") is not False
        or classification.get("official_source_gap") is not False
        or classification.get("matter_information_gap") is not True
        or classification.get("qualified_human_legal_review_offered") is not True
        or not isinstance(requested, list)
        or not requested
        or len(requested) != len(set(requested))
        or any(
            not isinstance(item, str)
            or not item.strip()
            or item != item.strip()
            or "\n" in item
            or len(item) > 300
            for item in requested
        )
    ):
        raise ValueError("phase2a_146_fallback_classification_invalid")
    _require_seal(
        classification,
        field="record_content_sha256",
        code="phase2a_146_fallback_classification_seal_invalid",
    )
    message = _fallback_message(str(row["row_id"]), requested)
    false_release_fields = (
        "knowledge_gap_event",
        "legal_rule_release_prohibited",
        "legal_advice_release_prohibited",
        "citation_release_prohibited",
        "evidence_span_release_prohibited",
        "source_binding_release_prohibited",
        "answer_model_output_prohibited",
    )
    if (
        payload.get("schema") != "legalbot.v111.phase2a.strict-matter-info-fallback.v1"
        or payload.get("row_id") != row["row_id"]
        or payload.get("r3_row_record_content_sha256") != row["record_content_sha256"]
        or payload.get("fallback_reason_code") != "MATTER_INFORMATION_REQUIRED"
        or payload.get("ui_cta") != "OFFER_QUALIFIED_HUMAN_LEGAL_REVIEW"
        or payload.get("matter_information_gap_event") is not True
        or payload.get("required_user_message") != message
        or payload.get("required_user_message_sha256") != _sha256(message.encode())
        or payload.get("reply_match_mode") != "EXACT_UTF8_STRING"
        or any(
            payload.get(field) is not (field != "knowledge_gap_event")
            for field in false_release_fields
        )
        or payload.get("answer_release_eligible") is not False
    ):
        raise ValueError("phase2a_146_fallback_contract_invalid")
    _require_seal(
        payload, field="record_content_sha256", code="phase2a_146_fallback_payload_seal_invalid"
    )


def _validate_scope_change_payload(payload: Mapping[str, Any], row: Mapping[str, Any]) -> None:
    _require_exact_keys(
        payload,
        {
            "schema",
            "row_id",
            "r3_row_record_content_sha256",
            "action",
            "original_blocking_components",
            "replacement_or_exclusion_contract_content_sha256",
            "owner_scope_change_basis_record_content_sha256",
            "changes_evaluation_contract",
            "requires_exact_owner_adoption_before_application",
            "answer_release_eligible",
            "record_content_sha256",
        },
        "phase2a_146_scope_change_shape_invalid",
    )
    expected_components = [
        _component_identity(component) for component in row["blocking_components"]
    ]
    if (
        payload.get("schema") != SCOPE_CHANGE_SCHEMA
        or payload.get("row_id") != row["row_id"]
        or payload.get("r3_row_record_content_sha256") != row["record_content_sha256"]
        or payload.get("action") not in SCOPE_CHANGE_ACTIONS
        or payload.get("original_blocking_components") != expected_components
        or _SHA256.fullmatch(
            str(payload.get("replacement_or_exclusion_contract_content_sha256") or "")
        )
        is None
        or _SHA256.fullmatch(
            str(payload.get("owner_scope_change_basis_record_content_sha256") or "")
        )
        is None
        or payload.get("changes_evaluation_contract") is not True
        or payload.get("requires_exact_owner_adoption_before_application") is not True
        or payload.get("answer_release_eligible") is not False
    ):
        raise ValueError("phase2a_146_scope_change_invalid")
    _require_seal(
        payload, field="record_content_sha256", code="phase2a_146_scope_change_seal_invalid"
    )


def _validate_retain_payload(payload: Mapping[str, Any], row: Mapping[str, Any]) -> None:
    if dict(payload) != _retain_payload(row):
        raise ValueError("phase2a_146_retain_payload_invalid")


def _validate_no_execution_recursively(value: Any) -> None:
    if isinstance(value, Mapping):
        forbidden_blanket_keys = {
            "fallback_all",
            "fallback_all_rows",
            "automatic_fallback",
            "blanket_fallback",
            "default_fallback",
            "fallback_by_default",
            "fallback_row_range",
            "fallback_wildcard",
        }
        if any(
            key in forbidden_blanket_keys and nested is not False for key, nested in value.items()
        ):
            raise ValueError("phase2a_146_blanket_fallback_field_prohibited")
        for key, nested in value.items():
            if key in _NO_EXECUTION_FLAGS and nested is not False:
                raise ValueError("phase2a_146_execution_boundary_invalid")
            _validate_no_execution_recursively(nested)
    elif isinstance(value, list | tuple):
        for nested in value:
            _validate_no_execution_recursively(nested)


def _validate_decision(decision: Mapping[str, Any], row: Mapping[str, Any]) -> dict[str, Any]:
    _require_exact_keys(
        decision,
        {
            "schema",
            "row_id",
            "r3_row_record_content_sha256",
            "selected_outcome",
            "outcome_payload",
            "decision_input_record_content_sha256",
        },
        "phase2a_146_decision_shape_invalid",
    )
    outcome = str(decision.get("selected_outcome") or "")
    payload = decision.get("outcome_payload")
    if (
        decision.get("schema") != DECISION_ROW_SCHEMA
        or decision.get("row_id") != row["row_id"]
        or decision.get("r3_row_record_content_sha256") != row["record_content_sha256"]
        or outcome not in ALLOWED_OUTCOMES
        or not isinstance(payload, Mapping)
    ):
        raise ValueError("phase2a_146_decision_invalid")
    validators = {
        OUTCOME_FULL: _validate_full_payload,
        OUTCOME_FALLBACK: _validate_fallback_payload,
        OUTCOME_SCOPE_CHANGE: _validate_scope_change_payload,
        OUTCOME_RETAIN: _validate_retain_payload,
    }
    validators[outcome](payload, row)
    _require_seal(
        decision,
        field="decision_input_record_content_sha256",
        code="phase2a_146_decision_seal_invalid",
    )
    _validate_no_execution_recursively(decision)
    return dict(decision)


def _row_map(report: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rows = report.get("rows")
    if not isinstance(rows, list) or len(rows) != 146:
        raise ValueError("phase2a_146_r3_row_set_invalid")
    output: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("phase2a_146_r3_row_invalid")
        row_id = str(row.get("row_id") or "")
        if _ROW_ID.fullmatch(row_id) is None or row_id in output:
            raise ValueError("phase2a_146_r3_row_identity_invalid")
        _require_seal(row, field="record_content_sha256", code="phase2a_146_r3_row_seal_invalid")
        components = row.get("blocking_components")
        if not isinstance(components, list) or not components:
            raise ValueError("phase2a_146_r3_blocking_components_invalid")
        output[row_id] = row
    expected_set_sha = _content_sha256(
        {
            "schema": "legalbot.v111.phase2a.row-id-set.v1",
            "row_ids": sorted(output),
        }
    )
    if report.get("blocker_row_id_set_sha256") != expected_set_sha:
        raise ValueError("phase2a_146_r3_row_set_sha_invalid")
    return output


def _decision_input(
    *,
    report: Mapping[str, Any],
    rows: Mapping[str, Mapping[str, Any]],
    decision_input_path: Path | None,
) -> tuple[dict[str, Any], bool]:
    if decision_input_path is None:
        material: dict[str, Any] = {
            "schema": DECISION_INPUT_SCHEMA,
            "status": "SAFE_BASELINE_ALL_146_BLOCKERS_RETAINED",
            "prequalification_report_content_sha256": R3_REPORT_CONTENT_SHA256,
            "blocker_row_id_set_sha256": report["blocker_row_id_set_sha256"],
            "decision_count": 146,
            "decisions": [_default_decision(rows[row_id]) for row_id in sorted(rows)],
            "not_owner_decision": True,
            "template_requires_new_immutable_revision_for_changes": True,
        }
        return _sealed(material), True

    if decision_input_path.is_symlink() or not decision_input_path.is_file():
        raise ValueError("phase2a_146_decision_input_file_invalid")
    review = DECISION_INPUT_REVIEW_ROOT.resolve(strict=True)
    resolved = decision_input_path.resolve(strict=True)
    if not resolved.is_relative_to(review):
        raise ValueError("phase2a_146_decision_input_outside_review_root")
    value = _load_object(resolved, "phase2a_146_decision_input_invalid")
    _require_exact_keys(
        value,
        {
            "schema",
            "status",
            "prequalification_report_content_sha256",
            "blocker_row_id_set_sha256",
            "decision_count",
            "decisions",
            "not_owner_decision",
            "template_requires_new_immutable_revision_for_changes",
            "artifact_content_sha256",
        },
        "phase2a_146_decision_input_shape_invalid",
    )
    _require_seal(value, code="phase2a_146_decision_input_seal_invalid")
    if (
        value.get("schema") != DECISION_INPUT_SCHEMA
        or value.get("status") != "EXACT_146_ROW_DECISION_INPUT_READY_NOT_ADOPTED"
        or value.get("prequalification_report_content_sha256") != R3_REPORT_CONTENT_SHA256
        or value.get("blocker_row_id_set_sha256") != report["blocker_row_id_set_sha256"]
        or value.get("decision_count") != 146
        or value.get("not_owner_decision") is not True
        or value.get("template_requires_new_immutable_revision_for_changes") is not True
    ):
        raise ValueError("phase2a_146_decision_input_contract_invalid")
    decisions = value.get("decisions")
    if not isinstance(decisions, list) or len(decisions) != 146:
        raise ValueError("phase2a_146_decision_input_count_invalid")
    by_row: dict[str, Mapping[str, Any]] = {}
    supplied_row_order: list[str] = []
    for decision in decisions:
        if not isinstance(decision, Mapping):
            raise ValueError("phase2a_146_decision_input_row_invalid")
        row_id = str(decision.get("row_id") or "")
        if row_id in by_row:
            raise ValueError("phase2a_146_decision_input_row_duplicate")
        by_row[row_id] = decision
        supplied_row_order.append(row_id)
    if set(by_row) != set(rows):
        raise ValueError("phase2a_146_decision_input_row_set_invalid")
    if supplied_row_order != sorted(rows):
        raise ValueError("phase2a_146_decision_input_row_order_invalid")
    validated = [_validate_decision(by_row[row_id], rows[row_id]) for row_id in sorted(rows)]
    material = dict(value)
    material["decisions"] = validated
    _require_seal(material, code="phase2a_146_decision_input_normalization_changed_seal")
    _validate_no_execution_recursively(material)
    return material, False


def _row_advisory(row: Mapping[str, Any], decision: Mapping[str, Any]) -> dict[str, Any]:
    material: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.superseding-remediation-advisory-row.v1",
        "row_id": row["row_id"],
        "r3_row_record_content_sha256": row["record_content_sha256"],
        "original_blocking_support_fits": row["blocking_support_fits"],
        "original_blocking_component_count": row["blocking_component_count"],
        "original_blocking_components": [
            _component_identity(component) for component in row["blocking_components"]
        ],
        "selected_outcome": decision["selected_outcome"],
        "outcome_payload": decision["outcome_payload"],
        "decision_input_record_content_sha256": decision["decision_input_record_content_sha256"],
        "owner_adoption_required_before_application": True,
        "applied": False,
    }
    return _sealed(material, field="record_content_sha256")


def _privacy_check(value: Any) -> None:
    def walk(item: Any, field: str) -> None:
        if isinstance(item, Mapping):
            for key, nested in item.items():
                walk(nested, str(key))
        elif isinstance(item, list | tuple):
            for nested in item:
                walk(nested, field)
        elif isinstance(item, str):
            if _EMAIL.search(item) or _WINDOWS_PATH.search(item):
                raise ValueError("phase2a_146_privacy_violation")
            if _ABSOLUTE_PATH.search(item):
                raise ValueError("phase2a_146_absolute_path_violation")

    walk(value, "value")


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


def _publish_directory_noreplace(staging: Path, output: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    source = os.fsencode(staging)
    target = os.fsencode(output)
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
        raise RuntimeError("phase2a_146_atomic_noreplace_unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ValueError("phase2a_146_output_already_exists")
    raise OSError(error_number, "phase2a_146_atomic_publish_failed")


def _ensure_output(output_root: Path) -> Path:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_146_output_already_exists")
    review = OUTPUT_REVIEW_ROOT.resolve(strict=True)
    output = output_root.parent.resolve(strict=True) / output_root.name
    if not output.name or not output.is_relative_to(review):
        raise ValueError("phase2a_146_output_outside_review_root")
    return output


def build_advisory(
    *,
    r3_root: Path = R3_ROOT,
    predecessor_root: Path | None = None,
    original_packet_root: Path = ORIGINAL_PACKET_ROOT,
    original_receipt_root: Path = ORIGINAL_RECEIPT_ROOT,
    final_packet_root: Path = FINAL_PACKET_ROOT,
    final_receipt_root: Path = FINAL_RECEIPT_ROOT,
    decision_input_path: Path | None = None,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    """Create the advisory package without applying or executing any outcome."""

    output = _ensure_output(output_root)
    timestamp = created_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("phase2a_146_created_at_must_be_timezone_aware")
    predecessor_spec = _predecessor_spec(decision_input_present=decision_input_path is not None)
    selected_predecessor_root = predecessor_root or (
        INPUT_REVIEW_ROOT / predecessor_spec["root_name"]
    )
    report, upstream_bindings = _verify_upstream(
        r3_root=r3_root,
        predecessor_root=selected_predecessor_root,
        predecessor_spec=predecessor_spec,
        original_packet_root=original_packet_root,
        original_receipt_root=original_receipt_root,
        final_packet_root=final_packet_root,
        final_receipt_root=final_receipt_root,
    )
    rows = _row_map(report)
    decision_input, generated_baseline = _decision_input(
        report=report,
        rows=rows,
        decision_input_path=decision_input_path,
    )
    decisions = {item["row_id"]: item for item in decision_input["decisions"]}
    advisories = [_row_advisory(rows[row_id], decisions[row_id]) for row_id in sorted(rows)]
    outcome_counts = Counter(str(item["selected_outcome"]) for item in advisories)
    fallback_row_ids = sorted(
        item["row_id"] for item in advisories if item["selected_outcome"] == OUTCOME_FALLBACK
    )
    retained_row_ids = sorted(
        item["row_id"] for item in advisories if item["selected_outcome"] == OUTCOME_RETAIN
    )
    ready_for_owner_review = not retained_row_ids and not generated_baseline
    status = STATUS_REVIEW if ready_for_owner_review else STATUS_BLOCKED

    advisory_material: dict[str, Any] = {
        "schema": ADVISORY_SCHEMA,
        "status": status,
        "created_at": timestamp.astimezone(UTC).isoformat(),
        "route": "OWNER_ADOPTED_INTERNAL_PRIVATE_RESEARCH_TOOL",
        "phase_scope": "PHASE2A_ONLY",
        "authoritative_input_bindings": upstream_bindings,
        "prequalification_report_content_sha256": R3_REPORT_CONTENT_SHA256,
        "supersedes_advisory_content_sha256": predecessor_spec["advisory_content_sha256"],
        "correction_scope": {
            "reason_code": predecessor_spec["revision_reason_code"],
            "added_false_fields": (
                [
                    "evaluation_contract_mutated",
                    "safe_fallback_decision_applied",
                    "source_delta_decisions_applied",
                ]
                if decision_input_path is None
                else []
            ),
            "predecessor_all_146_rows_retained": True,
            "predecessor_had_zero_fallback_rows": True,
            "no_substantive_row_outcome_changed": len(retained_row_ids) == 146,
        },
        "blocker_row_id_set_sha256": report["blocker_row_id_set_sha256"],
        "decision_input_content_sha256": decision_input["artifact_content_sha256"],
        "decision_input_is_generated_safe_baseline": generated_baseline,
        "row_count": 146,
        "row_advisories": advisories,
        "outcome_counts": {
            outcome: outcome_counts.get(outcome, 0) for outcome in sorted(ALLOWED_OUTCOMES)
        },
        "allowed_exact_row_outcomes": [
            {
                "outcome": OUTCOME_FULL,
                "requires_exact_binding_for_every_original_blocking_component": True,
                "requires_source_admission_jurisdiction_currentness_later_treatment_and_evidence_span_digests": True,
                "builder_does_not_make_legal_support_finding": True,
            },
            {
                "outcome": OUTCOME_FALLBACK,
                "requires_exact_row_specific_matter_info_only_classification": True,
                "legal_or_official_source_gap_makes_outcome_invalid": True,
                "reply_is_exact_and_releases_no_legal_claim": True,
            },
            {
                "outcome": OUTCOME_SCOPE_CHANGE,
                "requires_exact_owner_rewrite_or_exclusion_record": True,
                "changes_evaluation_contract": True,
                "cannot_apply_before_exact_owner_adoption": True,
            },
            {
                "outcome": OUTCOME_RETAIN,
                "retains_every_r3_blocker_for_the_row": True,
                "technical_pass_eligible": False,
            },
        ],
        "fallback_boundary": {
            "automatic_or_blanket_fallback": False,
            "fallback_by_default": False,
            "wildcards_ranges_or_global_switches_permitted": False,
            "fallback_row_ids": fallback_row_ids,
            "fallback_row_count": len(fallback_row_ids),
            "each_fallback_requires_its_own_sealed_row_classification": True,
            "knowledge_or_official_source_gap_may_not_be_hidden_as_matter_information_gap": True,
        },
        "retained_blocker_boundary": {
            "retained_row_ids": retained_row_ids,
            "retained_row_count": len(retained_row_ids),
            "successful_phase2a_package_may_be_claimed": False,
            "all585_may_run_from_this_advisory": False,
        },
        "single_existing_execution_chain": {
            "authority_content_sha256": EXECUTION_AUTHORITY_CONTENT_SHA256,
            "total_count": 1,
            "consumed_count": 0,
            "remaining_count": 1,
            "status": "AVAILABLE_UNSPENT",
            "this_builder_consumes_chain": False,
            "this_advisory_creates_additional_authority": False,
        },
        "advisory_effect": "CREATE_ONLY_NO_EXECUTION_NO_OWNER_DECISION",
        "owner_adoption_required_before_any_application": True,
        "technical_success_not_predeclared": True,
        "answer_release_eligible": False,
        "phase2b_authorized": False,
        **_NO_EXECUTION_FLAGS,
    }
    advisory = _sealed(advisory_material)
    advisory_raw = _pretty_json(advisory)
    advisory_file_sha256 = _sha256(advisory_raw)

    template_raw = _pretty_json(decision_input)
    if ready_for_owner_review:
        prompt_name = APPROVAL_PROMPT_NAME
        prompt = f"""PHASE-2A EXACT 146-ROW SUPERSEDING REMEDIATION OWNER REVIEW

Read {ADVISORY_NAME} in full before deciding. This create-only advisory binds:

- Advisory content SHA-256: {advisory["artifact_content_sha256"]}
- Advisory file SHA-256: {advisory_file_sha256}
- r3 prequalification report content SHA-256: {R3_REPORT_CONTENT_SHA256}
- Exact 146-row decision input content SHA-256: {decision_input["artifact_content_sha256"]}
- Existing execution authority content SHA-256: {EXECUTION_AUTHORITY_CONTENT_SHA256}

This text is not advance approval. If adopted, each outcome applies only to its
exact row and exact sealed payload. No fallback applies by default or by range.
This packet does not itself apply a decision or consume the one existing chain.

Owner typed name:
Decision date:
"""
    else:
        prompt_name = REVIEW_PROMPT_NAME
        prompt = f"""PHASE-2A 146-ROW SUPERSEDING REMEDIATION — REVIEW REQUIRED

This is a safe create-only baseline, not an approval-ready remediation packet.
All {len(retained_row_ids)} unresolved rows remain RETAIN_BLOCKER. Do not use
this packet to claim successful Phase 2A or to run scan/build/embedding,
retrieval re-attestation, all-585, or Phase 2B.

Prepare one new sealed exact 146-row decision input against:

- r3 report content SHA-256: {R3_REPORT_CONTENT_SHA256}
- blocker row-set SHA-256: {report["blocker_row_id_set_sha256"]}
- generated input-template content SHA-256: {decision_input["artifact_content_sha256"]}

For every row choose exactly one validated outcome: FULL_EVIDENCE_BINDING,
STRICT_NO_LEGAL_CLAIM_MATTER_INFO_FALLBACK, OWNER_REWRITE_OR_EXCLUSION, or
RETAIN_BLOCKER. A fallback requires a separate sealed row classification that
states there is no legal-knowledge gap and no official-source gap. Global,
range, wildcard, automatic, and blank fallback are prohibited.
"""
    prompt_raw = prompt.encode()

    package_material: dict[str, Any] = {
        "schema": PACKAGE_SCHEMA,
        "status": status,
        "advisory_content_sha256": advisory["artifact_content_sha256"],
        "prequalification_report_content_sha256": R3_REPORT_CONTENT_SHA256,
        "supersedes_advisory_content_sha256": predecessor_spec["advisory_content_sha256"],
        "decision_input_content_sha256": decision_input["artifact_content_sha256"],
        "blocker_row_id_set_sha256": report["blocker_row_id_set_sha256"],
        "row_count": 146,
        "fallback_row_count": len(fallback_row_ids),
        "retained_blocker_row_count": len(retained_row_ids),
        "ready_for_owner_review": ready_for_owner_review,
        "single_unspent_execution_chain_preserved": True,
        "artifacts": [
            {
                "name": ADVISORY_NAME,
                "content_sha256": advisory["artifact_content_sha256"],
                "file_sha256": advisory_file_sha256,
            },
            {
                "name": DECISION_TEMPLATE_NAME,
                "content_sha256": decision_input["artifact_content_sha256"],
                "file_sha256": _sha256(template_raw),
            },
            {"name": prompt_name, "file_sha256": _sha256(prompt_raw)},
        ],
        "packet_builder_effect": "CREATE_ONLY_NO_EXECUTION",
        **_NO_EXECUTION_FLAGS,
    }
    package = _sealed(package_material)
    package_raw = _pretty_json(package)
    artifacts = {
        ADVISORY_NAME: advisory_raw,
        DECISION_TEMPLATE_NAME: template_raw,
        prompt_name: prompt_raw,
        PACKAGE_NAME: package_raw,
    }
    checksums_raw = "".join(
        f"{_sha256(raw)}  {name}\n" for name, raw in sorted(artifacts.items())
    ).encode()
    _validate_no_execution_recursively([advisory, package, decision_input])
    _privacy_check([advisory, package, prompt])

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
        "status": status,
        "output_name": output.name,
        "advisory_content_sha256": advisory["artifact_content_sha256"],
        "advisory_file_sha256": advisory_file_sha256,
        "package_content_sha256": package["artifact_content_sha256"],
        "package_file_sha256": _sha256(package_raw),
        "decision_input_content_sha256": decision_input["artifact_content_sha256"],
        "row_count": 146,
        "fallback_row_count": len(fallback_row_ids),
        "retained_blocker_row_count": len(retained_row_ids),
        "ready_for_owner_review": ready_for_owner_review,
        "execution_chain_consumed": False,
        "source_scan_run": False,
        "index_built": False,
        "embedding_run": False,
        "retrieval_reattestation_run": False,
        "all585_qualification_run": False,
        "phase2b_run": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r3-root", type=Path, default=R3_ROOT)
    parser.add_argument("--predecessor-root", type=Path)
    parser.add_argument("--original-packet-root", type=Path, default=ORIGINAL_PACKET_ROOT)
    parser.add_argument("--original-receipt-root", type=Path, default=ORIGINAL_RECEIPT_ROOT)
    parser.add_argument("--final-packet-root", type=Path, default=FINAL_PACKET_ROOT)
    parser.add_argument("--final-receipt-root", type=Path, default=FINAL_RECEIPT_ROOT)
    parser.add_argument("--decision-input", type=Path)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = build_advisory(
        r3_root=args.r3_root.resolve(strict=False),
        predecessor_root=(
            args.predecessor_root.resolve(strict=False) if args.predecessor_root else None
        ),
        original_packet_root=args.original_packet_root.resolve(strict=False),
        original_receipt_root=args.original_receipt_root.resolve(strict=False),
        final_packet_root=args.final_packet_root.resolve(strict=False),
        final_receipt_root=args.final_receipt_root.resolve(strict=False),
        decision_input_path=(
            args.decision_input.resolve(strict=False) if args.decision_input else None
        ),
        output_root=args.output_root.resolve(strict=False),
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
