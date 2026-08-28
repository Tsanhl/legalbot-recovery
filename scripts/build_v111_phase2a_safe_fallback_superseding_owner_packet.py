#!/usr/bin/env python3
"""Build the exact Phase-2A source-delta and safe-fallback owner packet.

This create-only builder binds the sealed source-binding delta packet and
supersedes only its disposition for ``live60-q58:issue-14``.  The row remains
in the 585-row qualification set, but it is evaluated as a deterministic,
fact-dependent human-escalation fallback instead of an unsupported substantive
answer.  The builder never applies a decision, admits a source, scans, indexes,
embeds, builds, qualifies, invokes a model, changes a pointer or starts Phase
2B.
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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.evaluation.phase2a_safe_fallback_qualification import (  # noqa: E402
    FAILURE_STATUS,
    HUMAN_ESCALATION_CTA,
    MISSING_INFORMATION_CATEGORIES,
    OUTCOME_CLASS,
    PERFORMANCE_BOND_ACTION,
    PERFORMANCE_BOND_HELD9_ADVISORY_CONTENT_SHA256,
    PERFORMANCE_BOND_MISSING_INFORMATION_CATEGORIES,
    PERFORMANCE_BOND_OUTCOME_CLASS,
    PERFORMANCE_BOND_REASON_CODE,
    PERFORMANCE_BOND_ROW_ID,
    PERFORMANCE_BOND_SAFE_FALLBACK_MESSAGE,
    PERFORMANCE_BOND_UI_CTA,
    QUALIFICATION_STATUS,
    REASON_CODE,
    ROW_ID,
    SAFE_FALLBACK_MESSAGE,
    UI_CTA,
    performance_bond_safe_fallback_contract,
    safe_fallback_contract,
)

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
INPUT_REVIEW_ROOT = REVIEW_ROOT
OUTPUT_REVIEW_ROOT = REVIEW_ROOT

SOURCE_DELTA_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-source-binding-delta-owner-packet-r1"
SOURCE_DELTA_ROOT = REVIEW_ROOT / SOURCE_DELTA_ROOT_NAME
SOURCE_DELTA_PACKET_NAME = "EXACT-SOURCE-BINDING-DELTA-OWNER-PACKET.json"
SOURCE_DELTA_PACKAGE_NAME = "PACKAGE-MANIFEST.json"
SOURCE_DELTA_PROMPT_NAME = "OWNER-APPROVAL-PROMPT.txt"
SOURCE_DELTA_CHECKSUMS_NAME = "SHA256SUMS.txt"

EXPECTED_SOURCE_DELTA_CONTENT_SHA256 = (
    "01312e142dd084271aa005b3d2a5ba8b93564bf3a841e1f5a4ec68c06a604ac0"
)
EXPECTED_SOURCE_DELTA_FILE_SHA256 = (
    "a3498ce36e0782d941b9c167dd9ab3e78da1a7df2537e590946b1ccea666ca3a"
)
EXPECTED_SOURCE_DELTA_PACKAGE_CONTENT_SHA256 = (
    "ae614759964e5b0f7cf3e3a86d968342cb68d016fcc0bc62b3267e76400be517"
)
EXPECTED_SOURCE_DELTA_PACKAGE_FILE_SHA256 = (
    "b65036bc46fc88128c52779e9f0751f21a2869d7cff878477ee9af0362bda9db"
)
EXPECTED_SOURCE_DELTA_PROMPT_FILE_SHA256 = (
    "9b72c5f9b7c41b7aa10806be4f813cc228a61f446ab711f2876d08f2e6ca00bd"
)
EXPECTED_SOURCE_DELTA_CHECKSUMS_FILE_SHA256 = (
    "e2636b9dcaa0303203fb18b60a11ffeb2c8cbc234771d60e6ad09a04192ab066"
)
EXPECTED_PRIOR_HOLD_DECISION_SHA256 = (
    "f1fb421a849cedf092d5c68a02157d24ede820cce6968b92b79f33c13887fc72"
)
EXPECTED_ORIGINAL_OWNER_PACKET_CONTENT_SHA256 = (
    "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c"
)
EXPECTED_ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256 = (
    "a6ea2794b276946dd24ba3d752203dd81ae14f88aae24224a80b7b62f886d539"
)

FCA_DERIVATION_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-fca-canonical-markdown-quarantine-r1"
FCA_DERIVATION_ROOT = REVIEW_ROOT / FCA_DERIVATION_ROOT_NAME
FCA_DERIVATION_MANIFEST_NAME = "FCA-CANONICAL-MARKDOWN-QUARANTINE-MANIFEST.json"
FCA_DERIVATION_PACKAGE_NAME = "PACKAGE-MANIFEST.json"
FCA_DERIVATION_CHECKSUMS_NAME = "SHA256SUMS.txt"
EXPECTED_FCA_DERIVATION_MANIFEST_CONTENT_SHA256 = (
    "40bf47ebd133b912be63adabe70b1d58c7fc2a31c78ea174ea6823960dd2abf4"
)
EXPECTED_FCA_DERIVATION_MANIFEST_FILE_SHA256 = (
    "5bb190e914c168ab48a5fb1827707fbbc321f2910ed92c6fbf2fe740ad2806c5"
)
EXPECTED_FCA_DERIVATION_PACKAGE_CONTENT_SHA256 = (
    "8c76ee274654beecaef858764ecf67b4769750acc2d537f47f0ecbb96de5c764"
)
EXPECTED_FCA_DERIVATION_PACKAGE_FILE_SHA256 = (
    "26c78ac32f54372f6fd80fbba0fd9bc16d960861717e741d78cda05f94a29636"
)
EXPECTED_FCA_DERIVATION_CHECKSUMS_FILE_SHA256 = (
    "98ec86f53b53525d81ca2c45ac02cd1c12940c69743b0a9323be1b7da73ea378"
)

EXPECTED_SAFE_FALLBACK_CONTRACT_CONTENT_SHA256 = (
    "ba6c131f06e05bed9f6b6aa5743dc974f3b13618e3af39ffcaaabaf0f84c72f6"
)
EXPECTED_SAFE_FALLBACK_REPLY_SHA256 = (
    "93209b264f9b5285b9af12e0200b251ef19b9cb4274f486999bf7a6053ff38e9"
)
EXPECTED_SAFE_FALLBACK_CATEGORIES_SHA256 = (
    "d09f850fabf778ebf0ec764999b213bdf53e531254e4b5de23e9c3437597d24a"
)

HELD9_ADVISORY_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-held9-surviving-support-advisory-r1"
HELD9_ADVISORY_ROOT = REVIEW_ROOT / HELD9_ADVISORY_ROOT_NAME
HELD9_ADVISORY_NAME = "HELD9-SURVIVING-SUPPORT-ADVISORY.json"
HELD9_PACKAGE_NAME = "PACKAGE-MANIFEST.json"
HELD9_CHECKSUMS_NAME = "SHA256SUMS.txt"
EXPECTED_HELD9_ADVISORY_CONTENT_SHA256 = (
    "599d7175005c8978757611be0ce837299845c142147ec02828f53ee7620e75fd"
)
EXPECTED_HELD9_ADVISORY_FILE_SHA256 = (
    "2fe8eb506bce8ba455b7dea69d21927bba8fb54e242dba81c4287096a6535ef1"
)
EXPECTED_HELD9_PACKAGE_CONTENT_SHA256 = (
    "8441d58a633e3787b8280b536f77ba9bdae525e4472d4572232a85c165f4e632"
)
EXPECTED_HELD9_PACKAGE_FILE_SHA256 = (
    "2f6abdd57a75d0834e0ffa9cdf339e6fda9759fee7d2d6cb1e2158fc794f6247"
)
EXPECTED_HELD9_CHECKSUMS_FILE_SHA256 = (
    "8058cb61aea37a5324414a63d331dcf6e5c8262d6a7ec0f69baa8d4f21315837"
)
EXPECTED_WUHAN_PROPOSAL_CONTENT_SHA256 = (
    "0e0b4015fe6e2fecd4e9fadf43370dad28d9313e64fda6c7ed5f09bfa61a98b4"
)
EXPECTED_WUHAN_BINDING_RECORD_CONTENT_SHA256 = (
    "7f089f7b05a87a72129ac5bf936d8976bd33cec3ccb478f497f927aa2a5b29fc"
)

FACT_FALLBACK_ADVISORY_ROOT_NAME = (
    "LegalBot-Phase2A-2026-08-28-fact-only-fallback-coverage-advisory-r1"
)
FACT_FALLBACK_ADVISORY_ROOT = REVIEW_ROOT / FACT_FALLBACK_ADVISORY_ROOT_NAME
FACT_FALLBACK_ADVISORY_NAME = "FACT-ONLY-FALLBACK-COVERAGE-ADVISORY-585.json"
FACT_FALLBACK_PACKAGE_NAME = "PACKAGE-MANIFEST.json"
FACT_FALLBACK_CHECKSUMS_NAME = "SHA256SUMS.txt"
EXPECTED_FACT_FALLBACK_ADVISORY_CONTENT_SHA256 = (
    "035316cac6f9559744400bc9db7c05bdf74a85c7d120c59eae5cfc41f0462af8"
)
EXPECTED_FACT_FALLBACK_ADVISORY_FILE_SHA256 = (
    "caa33a34cf3164a9691f854425cb452a0780590066493a79cd9e6e5f5aeef889"
)
EXPECTED_FACT_FALLBACK_PACKAGE_CONTENT_SHA256 = (
    "a7dc24c582bfc05736b01e3e317b9888c770dcefc05bf5c5f54bd8ce2bcfd1f6"
)
EXPECTED_FACT_FALLBACK_PACKAGE_FILE_SHA256 = (
    "a6a9ef47061d06df8281c03ea6b1370a75cb77e81b39365d6dc180b70cc08c23"
)
EXPECTED_FACT_FALLBACK_CHECKSUMS_FILE_SHA256 = (
    "fa2b0aa027016ec20d5208011fec15e959eaf7a9f7f9e0ae7c14be6c95a90731"
)
EXPECTED_PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256 = (
    "91cbb05fad64d2e26d11e75ff8adbe1b1b9d7fc300abea6785630078e5d2036e"
)

ECHR_RECOVERY_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-echr-held-source-recovery-quarantine-r3"
ECHR_RECOVERY_ROOT = REVIEW_ROOT / ECHR_RECOVERY_ROOT_NAME
ECHR_RECOVERY_MANIFEST_NAME = "ECHR-RECOVERY-QUARANTINE-MANIFEST.json"
ECHR_RECOVERY_PACKAGE_NAME = "PACKAGE-MANIFEST.json"
ECHR_RECOVERY_CHECKSUMS_NAME = "SHA256SUMS.txt"
EXPECTED_ECHR_RECOVERY_MANIFEST_CONTENT_SHA256 = (
    "f5beba682a629d3a6e0e79be374c0d2a3d6690d45abe467fa40f67879dcb0142"
)
EXPECTED_ECHR_RECOVERY_MANIFEST_FILE_SHA256 = (
    "c2682917d3f2dbc7cc701ad63ff98552eeb0e0398a85503b4b55a12c72b78471"
)
EXPECTED_ECHR_RECOVERY_PACKAGE_CONTENT_SHA256 = (
    "41d724f7a590cd59ec768d635f977461ad28e22895e69f1acd74e23bbbda27e4"
)
EXPECTED_ECHR_RECOVERY_PACKAGE_FILE_SHA256 = (
    "dae5fb683e292709902ead5052a8d431efecc9be8038ca74e52107cb62905bd9"
)
EXPECTED_ECHR_RECOVERY_CHECKSUMS_FILE_SHA256 = (
    "1b5327aefca101429fe6d07f94610a7ee7d1fb8855298365d28c2d5930073d3e"
)
EXPECTED_ECHR_KLIMA_RAW_SHA256 = "798f181056e6c12d77063559c9a9bf0fe919c1d263b6502454ea13eabfa662c6"
EXPECTED_ECHR_KLIMA_CANONICAL_SHA256 = (
    "b2625664eacfe6a81b1d311f956d8c03159db49a9460b4640934cecfaec9e8db"
)
EXPECTED_ECHR_KLIMA_RECORD_CONTENT_SHA256 = (
    "b9cc4b3c3d5566bec4f62c374d257d6d286fcd5681bc67d6ec0d810c3903871f"
)
EXPECTED_ECHR_BIG_BROTHER_RAW_SHA256 = (
    "2bab2b5596ca559242c98c1a723586c004b8df94a22fac019a03686bc3ef67df"
)
EXPECTED_ECHR_BIG_BROTHER_CANONICAL_SHA256 = (
    "4ac630159b18e49893bd1db87ed4e24145ff7e1903fc8ed91e2314c90c3e352f"
)
EXPECTED_ECHR_BIG_BROTHER_RECORD_CONTENT_SHA256 = (
    "201c6c8a088b48eccbe08d527bec182350ca24695496c97170349ca1039cc20d"
)
EXPECTED_ECHR_GOODWIN_RAW_SHA256 = (
    "49074fe49a3280239806d86233f2a4be081777859467fa7df723adc1590d4441"
)
EXPECTED_ECHR_GOODWIN_RECORD_CONTENT_SHA256 = (
    "be390e6a0f1def7c073f0fae329b56d3e7c4e6acf7610ce6fffef8d15b7da145"
)
EXPECTED_ECHR_MUTU_FAILURE_FINGERPRINT_SHA256 = (
    "cd73206a613336d1790a6b8c2db5aab2e621dda9206ed3decf20f22a9034924c"
)
EXPECTED_ECHR_MUTU_ATTEMPT_IDENTITY_SHA256 = (
    "86517dd2d35137e5dfd3ed7918161efaa26174e9231806b2cf14df3452443c61"
)
EXPECTED_ECHR_MUTU_HOLD_CONTENT_SHA256 = (
    "9bce887cef120efcc310aafe157261d1c7f62b6ca52d2d6d77cb5dc4b62f13f6"
)

Q53_SUBSTITUTE_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-q53-semenya-substitute-quarantine-r1"
Q53_SUBSTITUTE_ROOT = REVIEW_ROOT / Q53_SUBSTITUTE_ROOT_NAME
Q53_SUBSTITUTE_ADVISORY_NAME = "Q53-SEMENYA-SUBSTITUTE-SOURCE-ADVISORY.json"
Q53_SUBSTITUTE_PACKAGE_NAME = "PACKAGE-MANIFEST.json"
Q53_SUBSTITUTE_CHECKSUMS_NAME = "SHA256SUMS.txt"
EXPECTED_Q53_SUBSTITUTE_ADVISORY_CONTENT_SHA256 = (
    "fea6a74301ba629c03a1813dbc45d83ee030c25d0c53194c0129fd4515adb814"
)
EXPECTED_Q53_SUBSTITUTE_ADVISORY_FILE_SHA256 = (
    "8096be02c196d1bc6d2bee31c9d5ce665229d91865bc61de40f03483b656b0df"
)
EXPECTED_Q53_SUBSTITUTE_PACKAGE_CONTENT_SHA256 = (
    "e81f8869cae30b0e3eed49d8310cf7ab4f825ddfc0ae979cc092d8228e679704"
)
EXPECTED_Q53_SUBSTITUTE_PACKAGE_FILE_SHA256 = (
    "8d792997a19a8892ef039405b7adaddeb91281747bc60dd187ac36726ca6f829"
)
EXPECTED_Q53_SUBSTITUTE_CHECKSUMS_FILE_SHA256 = (
    "9b7498b084dee41b44a4c27539aec3b8be1555e41321a45617d4b416d2f2b508"
)
EXPECTED_Q53_SEMENYA_RAW_SHA256 = "52f5485626ffd7235993db907a3051010af8f8104804db551e11d58648455d62"
EXPECTED_Q53_SEMENYA_CANONICAL_SHA256 = (
    "b9394f938b01840e14c21b8676b536ae4fd247920e2b9eb75d536a1e3d02440e"
)
EXPECTED_Q53_SEMENYA_RECORD_CONTENT_SHA256 = (
    "3ff2126597a311845a212fcb1966cf4b1d5947c46880b2955bf64c9fb51b2160"
)
EXPECTED_Q53_ALI_RIZA_FAILURE_FINGERPRINT_SHA256 = (
    "47fa26238510e94eafc33c24a55efe6c3656ea891b97d362feddb6df9e6b77b6"
)

_HELD9_ROW_IDS = frozenset(
    {
        "live30-q22:issue-02",
        "live30-q22:issue-04",
        "live30-q22:issue-06",
        "live60-q51:issue-05",
        "live60-q53:issue-04",
        "live60-q53:issue-11",
        "live60-q56:issue-01",
        "live60-q56:issue-05",
        "live60-q58:issue-09",
    }
)
_HELD9_GAP_ROW_IDS = _HELD9_ROW_IDS - {"live60-q58:issue-09"}

DEFAULT_OUTPUT_ROOT = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-source-delta-safe-fallback-owner-packet-r1"
)
PACKET_NAME = "EXACT-PHASE2A-SOURCE-DELTA-SAFE-FALLBACK-OWNER-PACKET.json"
PROMPT_NAME = "OWNER-APPROVAL-PROMPT.txt"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

STATUS = "EXACT_PHASE2A_SOURCE_DELTA_SAFE_FALLBACK_READY_NOT_ADOPTED"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EMAIL = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
_WINDOWS_DRIVE_PATH = re.compile(r"(?i)(?:^|[^a-z0-9])(?:[a-z]:[\\/])")
_WINDOWS_UNC_PATH = re.compile(r"(?:^|[\s'\"(])(?:\\\\|//)[^\s]+")
_POSIX_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9+.-])/(?!/)[^\s'\"<>]*")
_PLAUSIBLE_PERSONAL_FILENAME = re.compile(
    r"(?i)(?:^|[\s'\"(])[^/\\\n]{1,180}\."
    r"(?:docx?|pdf|pptx?|xlsx?|rtf|odt|pages)(?:$|[\s'\"),])"
)
_CONTROLLED_ARTIFACT_NAMES = frozenset(
    {
        PACKET_NAME,
        PROMPT_NAME,
        PACKAGE_NAME,
        CHECKSUMS_NAME,
        SOURCE_DELTA_PACKET_NAME,
        SOURCE_DELTA_PROMPT_NAME,
        SOURCE_DELTA_PACKAGE_NAME,
        SOURCE_DELTA_CHECKSUMS_NAME,
        FCA_DERIVATION_MANIFEST_NAME,
        HELD9_ADVISORY_NAME,
        FACT_FALLBACK_ADVISORY_NAME,
        ECHR_RECOVERY_MANIFEST_NAME,
        Q53_SUBSTITUTE_ADVISORY_NAME,
        "EXACT-REMEDIATION-OWNER-PACKET-361.json",
        "ADMISSION-CONTENT-AUDIT-247.json",
        "approved-source-manifest.json",
    }
)

_ALLOWED_ROOT_NAMES = frozenset(
    {
        SOURCE_DELTA_ROOT_NAME,
        FCA_DERIVATION_ROOT_NAME,
        HELD9_ADVISORY_ROOT_NAME,
        FACT_FALLBACK_ADVISORY_ROOT_NAME,
        ECHR_RECOVERY_ROOT_NAME,
        Q53_SUBSTITUTE_ROOT_NAME,
        "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1",
        "LegalBot-Phase2A-2026-08-28-admission-content-audit-r1",
        "current-law-ew-full-fp16-v111-20260827-phase2a-a",
    }
)

# These fields describe what this create-only packet builder has done.  Every
# field must remain false in both the packet and its package manifest.
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


def _load_object(path: Path, code: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(code)
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(code)
    return value


def _verify_regular_file(path: Path, expected_sha256: str, code: str) -> None:
    if path.is_symlink() or not path.is_file() or _sha256_file(path) != expected_sha256:
        raise ValueError(code)


def _source_root_identity(source_root: Path) -> Path:
    if source_root.is_symlink() or not source_root.is_dir():
        raise ValueError("phase2a_safe_fallback_source_delta_root_invalid")
    review = INPUT_REVIEW_ROOT.resolve(strict=True)
    resolved = source_root.resolve(strict=True)
    expected = review / SOURCE_DELTA_ROOT_NAME
    if resolved != expected or source_root.name != SOURCE_DELTA_ROOT_NAME:
        raise ValueError("phase2a_safe_fallback_source_delta_root_identity_invalid")
    return resolved


def _verify_source_delta(source_root: Path) -> dict[str, Any]:
    root = _source_root_identity(source_root)
    packet_path = root / SOURCE_DELTA_PACKET_NAME
    package_path = root / SOURCE_DELTA_PACKAGE_NAME
    prompt_path = root / SOURCE_DELTA_PROMPT_NAME
    checksums_path = root / SOURCE_DELTA_CHECKSUMS_NAME

    _verify_regular_file(
        packet_path,
        EXPECTED_SOURCE_DELTA_FILE_SHA256,
        "phase2a_safe_fallback_source_delta_packet_file_invalid",
    )
    _verify_regular_file(
        package_path,
        EXPECTED_SOURCE_DELTA_PACKAGE_FILE_SHA256,
        "phase2a_safe_fallback_source_delta_package_file_invalid",
    )
    _verify_regular_file(
        prompt_path,
        EXPECTED_SOURCE_DELTA_PROMPT_FILE_SHA256,
        "phase2a_safe_fallback_source_delta_prompt_file_invalid",
    )
    _verify_regular_file(
        checksums_path,
        EXPECTED_SOURCE_DELTA_CHECKSUMS_FILE_SHA256,
        "phase2a_safe_fallback_source_delta_checksums_file_invalid",
    )

    packet = _load_object(packet_path, "phase2a_safe_fallback_source_delta_packet_invalid")
    _verify_seal(
        packet,
        "artifact_content_sha256",
        "phase2a_safe_fallback_source_delta_packet_seal_invalid",
        EXPECTED_SOURCE_DELTA_CONTENT_SHA256,
    )
    if packet.get("schema") != "legalbot.v111.phase2a.source-binding-delta-owner-packet.v1":
        raise ValueError("phase2a_safe_fallback_source_delta_schema_invalid")
    if packet.get("status") != "EXACT_SOURCE_BINDING_DELTA_READY_NOT_ADOPTED":
        raise ValueError("phase2a_safe_fallback_source_delta_status_invalid")

    prior_hold = packet.get("known_all585_material_hold")
    if not isinstance(prior_hold, dict) or prior_hold != {
        "current_all585_can_be_successful": False,
        "original_decision_content_sha256": EXPECTED_PRIOR_HOLD_DECISION_SHA256,
        "qualification_status": "BLOCKED_MATERIAL_GAP",
        "recommended_owner_outcome": ("RETAIN_MATERIAL_HOLD_NO_SUPPORTED_OFFICIAL_PROPOSITION"),
        "row_id": ROW_ID,
        "successful_phase2a_package_may_be_claimed": False,
    }:
        raise ValueError("phase2a_safe_fallback_prior_hold_contract_invalid")

    package = _load_object(package_path, "phase2a_safe_fallback_source_delta_package_invalid")
    _verify_seal(
        package,
        "artifact_content_sha256",
        "phase2a_safe_fallback_source_delta_package_seal_invalid",
        EXPECTED_SOURCE_DELTA_PACKAGE_CONTENT_SHA256,
    )
    if (
        package.get("packet_content_sha256") != EXPECTED_SOURCE_DELTA_CONTENT_SHA256
        or package.get("status") != "EXACT_SOURCE_BINDING_DELTA_READY_NOT_ADOPTED"
    ):
        raise ValueError("phase2a_safe_fallback_source_delta_package_binding_invalid")
    artifacts = package.get("artifacts")
    if not isinstance(artifacts, list) or artifacts != [
        {
            "content_sha256": EXPECTED_SOURCE_DELTA_CONTENT_SHA256,
            "file_sha256": EXPECTED_SOURCE_DELTA_FILE_SHA256,
            "name": SOURCE_DELTA_PACKET_NAME,
        },
        {
            "file_sha256": EXPECTED_SOURCE_DELTA_PROMPT_FILE_SHA256,
            "name": SOURCE_DELTA_PROMPT_NAME,
        },
    ]:
        raise ValueError("phase2a_safe_fallback_source_delta_artifact_binding_invalid")

    expected_checksums = (
        f"{EXPECTED_SOURCE_DELTA_FILE_SHA256}  {SOURCE_DELTA_PACKET_NAME}\n"
        f"{EXPECTED_SOURCE_DELTA_PROMPT_FILE_SHA256}  {SOURCE_DELTA_PROMPT_NAME}\n"
        f"{EXPECTED_SOURCE_DELTA_PACKAGE_FILE_SHA256}  {SOURCE_DELTA_PACKAGE_NAME}\n"
    ).encode()
    if checksums_path.read_bytes() != expected_checksums:
        raise ValueError("phase2a_safe_fallback_source_delta_checksums_invalid")

    for field in _NO_EXECUTION_FLAGS:
        # The three packet-only supersession fields do not exist upstream.
        if field in {
            "source_delta_decisions_applied",
            "safe_fallback_decision_applied",
            "evaluation_contract_mutated",
        }:
            continue
        if packet.get(field) is not False or package.get(field) is not False:
            raise ValueError("phase2a_safe_fallback_source_delta_execution_boundary_invalid")
    bindings = packet.get("source_bindings")
    if not isinstance(bindings, dict):
        raise ValueError("phase2a_safe_fallback_source_delta_authority_binding_invalid")
    original_packet = bindings.get("original_owner_packet")
    owner_receipt = bindings.get("sealed_owner_adoption_receipt")
    if (
        not isinstance(original_packet, dict)
        or original_packet.get("content_sha256") != EXPECTED_ORIGINAL_OWNER_PACKET_CONTENT_SHA256
        or not isinstance(owner_receipt, dict)
        or owner_receipt.get("content_sha256") != EXPECTED_ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256
    ):
        raise ValueError("phase2a_safe_fallback_source_delta_authority_binding_invalid")
    corrected = packet.get("proposed_corrected_source_admissions")
    if not isinstance(corrected, list) or len(corrected) != 15:
        raise ValueError("phase2a_safe_fallback_source_delta_corrected_set_invalid")
    return packet


def _fca_root_identity(root: Path) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("phase2a_safe_fallback_fca_derivation_root_invalid")
    review = INPUT_REVIEW_ROOT.resolve(strict=True)
    resolved = root.resolve(strict=True)
    expected = review / FCA_DERIVATION_ROOT_NAME
    if resolved != expected or root.name != FCA_DERIVATION_ROOT_NAME:
        raise ValueError("phase2a_safe_fallback_fca_derivation_root_identity_invalid")
    return resolved


def _verify_no_execution_true_recursively(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if key in _NO_EXECUTION_FLAGS and nested is not False:
                raise ValueError("phase2a_safe_fallback_fca_execution_boundary_invalid")
            _verify_no_execution_true_recursively(nested)
    elif isinstance(value, list | tuple):
        for nested in value:
            _verify_no_execution_true_recursively(nested)


def _verify_fca_derivation(
    *, root: Path, source_delta: Mapping[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    resolved = _fca_root_identity(root)
    manifest_path = resolved / FCA_DERIVATION_MANIFEST_NAME
    package_path = resolved / FCA_DERIVATION_PACKAGE_NAME
    checksums_path = resolved / FCA_DERIVATION_CHECKSUMS_NAME
    _verify_regular_file(
        manifest_path,
        EXPECTED_FCA_DERIVATION_MANIFEST_FILE_SHA256,
        "phase2a_safe_fallback_fca_manifest_file_invalid",
    )
    _verify_regular_file(
        package_path,
        EXPECTED_FCA_DERIVATION_PACKAGE_FILE_SHA256,
        "phase2a_safe_fallback_fca_package_file_invalid",
    )
    _verify_regular_file(
        checksums_path,
        EXPECTED_FCA_DERIVATION_CHECKSUMS_FILE_SHA256,
        "phase2a_safe_fallback_fca_checksums_file_invalid",
    )
    manifest = _load_object(manifest_path, "phase2a_safe_fallback_fca_manifest_invalid")
    package = _load_object(package_path, "phase2a_safe_fallback_fca_package_invalid")
    _verify_seal(
        manifest,
        "manifest_content_sha256",
        "phase2a_safe_fallback_fca_manifest_seal_invalid",
        EXPECTED_FCA_DERIVATION_MANIFEST_CONTENT_SHA256,
    )
    _verify_seal(
        package,
        "package_content_sha256",
        "phase2a_safe_fallback_fca_package_seal_invalid",
        EXPECTED_FCA_DERIVATION_PACKAGE_CONTENT_SHA256,
    )
    if (
        manifest.get("schema") != "legalbot.v111.phase2a.fca-canonical-markdown-quarantine.v1"
        or manifest.get("canonical_markdown_schema") != "legalbot.canonical-markdown.v3"
        or manifest.get("no_raw_source_bytes_copied") is not True
        or manifest.get("no_source_root_materialization") is not True
        or manifest.get("owner_adoption_required") is not True
    ):
        raise ValueError("phase2a_safe_fallback_fca_manifest_contract_invalid")
    if (
        package.get("schema") != "legalbot.v111.phase2a.fca-canonical-markdown-package.v1"
        or package.get("status") != "QUARANTINED_PRE_OWNER_NOT_ADMITTED"
        or package.get("source_binding_delta_content_sha256")
        != EXPECTED_SOURCE_DELTA_CONTENT_SHA256
        or package.get("source_admission_required_for_derived_representations") is not True
    ):
        raise ValueError("phase2a_safe_fallback_fca_package_contract_invalid")
    _verify_no_execution_true_recursively([manifest, package])

    records = manifest.get("records")
    corrected = source_delta.get("proposed_corrected_source_admissions")
    if not isinstance(records, list) or len(records) != 15 or not isinstance(corrected, list):
        raise ValueError("phase2a_safe_fallback_fca_record_set_invalid")
    source_decisions = {
        str(item.get("decision_content_sha256")): item
        for item in corrected
        if isinstance(item, dict)
    }
    if len(source_decisions) != 15:
        raise ValueError("phase2a_safe_fallback_fca_source_decision_set_invalid")

    slim: list[dict[str, Any]] = []
    provision_count = 0
    derived_members: set[str] = set()
    for ordinal, item in enumerate(records, start=1):
        if not isinstance(item, dict):
            raise ValueError("phase2a_safe_fallback_fca_record_invalid")
        _verify_seal(
            item,
            "record_content_sha256",
            "phase2a_safe_fallback_fca_record_seal_invalid",
        )
        decision_sha = str(item.get("source_delta_decision_content_sha256", ""))
        source_decision = source_decisions.get(decision_sha)
        if source_decision is None or any(
            (
                item.get("source_delta_decision_id") != source_decision.get("decision_id"),
                item.get("proposed_source_version_id")
                != source_decision.get("proposed_source_version_id"),
                item.get("repair_record_id") != source_decision.get("repair_record_id"),
                item.get("repair_record_content_sha256")
                != source_decision.get("repair_record_content_sha256"),
                item.get("raw_sha256") != source_decision.get("raw_sha256"),
            )
        ):
            raise ValueError("phase2a_safe_fallback_fca_source_crosslink_invalid")
        structural = item.get("structural_verification")
        equivalence = item.get("equivalence")
        parser = item.get("parser_compatibility")
        member = str(item.get("derived_member", ""))
        derived_sha256 = str(item.get("derived_sha256", ""))
        if (
            item.get("ordinal") != ordinal
            or not member.endswith(".md")
            or Path(member).name != member
            or member in derived_members
            or _SHA256.fullmatch(derived_sha256) is None
            or not isinstance(structural, dict)
            or structural.get("all_provision_fields_preserved") is not True
            or structural.get("all_response_metadata_fields_preserved") is not True
            or not isinstance(equivalence, dict)
            or equivalence.get("full_json_object_semantic_equality") is not True
            or equivalence.get("raw_byte_sha256_bound") is not True
            or not isinstance(parser, dict)
            or parser.get("passed") is not True
            or parser.get("parse_status") != "ready"
            or item.get("privacy_check_passed") is not True
            or item.get("source_admission_required") is not True
            or item.get("source_binding_delta_content_sha256")
            != EXPECTED_SOURCE_DELTA_CONTENT_SHA256
            or item.get("currentness_hold_retained") is not True
            or item.get("later_treatment_hold_retained") is not True
        ):
            raise ValueError("phase2a_safe_fallback_fca_record_contract_invalid")
        _verify_regular_file(
            resolved / member,
            derived_sha256,
            "phase2a_safe_fallback_fca_derived_member_invalid",
        )
        provision_count += int(structural.get("source_provision_count", -1))
        derived_members.add(member)
        slim.append(
            {
                "ordinal": ordinal,
                "source_delta_decision_id": item["source_delta_decision_id"],
                "source_delta_decision_content_sha256": decision_sha,
                "repair_record_id": item["repair_record_id"],
                "repair_record_content_sha256": item["repair_record_content_sha256"],
                "proposed_source_version_id": item["proposed_source_version_id"],
                "raw_sha256": item["raw_sha256"],
                "derived_member": member,
                "derived_sha256": derived_sha256,
                "derivation_record_content_sha256": item["record_content_sha256"],
                "canonical_markdown_schema": item["canonical_markdown_schema"],
                "transform_identity": item["transform_identity"],
                "transform_schema": item["transform_schema"],
                "transform_version": item["transform_version"],
                "full_json_object_semantic_equality": True,
                "parser_compatibility_passed": True,
                "privacy_check_passed": True,
                "currentness_hold_retained": True,
                "later_treatment_hold_retained": True,
                "recommended_owner_outcome": (
                    "ADMIT_EXACT_CANONICAL_MARKDOWN_DERIVATIVE_INSTEAD_OF_RAW_JSON"
                ),
            }
        )
    if provision_count != 312 or len(derived_members) != 15:
        raise ValueError("phase2a_safe_fallback_fca_provision_contract_invalid")
    if set(source_decisions) != {item["source_delta_decision_content_sha256"] for item in slim}:
        raise ValueError("phase2a_safe_fallback_fca_source_decision_set_invalid")

    package_entries = package.get("files")
    if not isinstance(package_entries, list) or package.get("file_count") != 17:
        raise ValueError("phase2a_safe_fallback_fca_package_members_invalid")
    entries: dict[str, str] = {}
    checksum_lines: list[str] = []
    for entry in package_entries:
        if not isinstance(entry, dict):
            raise ValueError("phase2a_safe_fallback_fca_package_members_invalid")
        path = str(entry.get("path", ""))
        sha256 = str(entry.get("sha256", ""))
        if Path(path).name != path or path in entries or _SHA256.fullmatch(sha256) is None:
            raise ValueError("phase2a_safe_fallback_fca_package_members_invalid")
        _verify_regular_file(
            resolved / path,
            sha256,
            "phase2a_safe_fallback_fca_package_member_invalid",
        )
        if (resolved / path).stat().st_size != entry.get("bytes"):
            raise ValueError("phase2a_safe_fallback_fca_package_member_invalid")
        entries[path] = sha256
        checksum_lines.append(f"{sha256}  {path}\n")
    if set(entries) != {
        FCA_DERIVATION_MANIFEST_NAME,
        "OUTCOME.txt",
        *derived_members,
    }:
        raise ValueError("phase2a_safe_fallback_fca_package_members_invalid")
    checksum_lines.append(
        f"{EXPECTED_FCA_DERIVATION_PACKAGE_FILE_SHA256}  {FCA_DERIVATION_PACKAGE_NAME}\n"
    )
    if checksums_path.read_text(encoding="utf-8") != "".join(checksum_lines):
        raise ValueError("phase2a_safe_fallback_fca_checksums_invalid")
    exact_members = set(entries) | {
        FCA_DERIVATION_PACKAGE_NAME,
        FCA_DERIVATION_CHECKSUMS_NAME,
    }
    if {path.name for path in resolved.iterdir()} != exact_members:
        raise ValueError("phase2a_safe_fallback_fca_package_members_invalid")
    holds = manifest.get("holds")
    if (
        not isinstance(holds, dict)
        or holds.get("r7_unresolved_repair_hold_count") != 5
        or holds.get("r7_unresolved_repair_holds_retained_unchanged") is not True
        or holds.get("all_currentness_holds_retained") is not True
        or holds.get("all_later_treatment_holds_retained") is not True
    ):
        raise ValueError("phase2a_safe_fallback_fca_holds_invalid")
    return manifest, slim


def _held9_root_identity(root: Path) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("phase2a_safe_fallback_held9_root_invalid")
    review = INPUT_REVIEW_ROOT.resolve(strict=True)
    resolved = root.resolve(strict=True)
    expected = review / HELD9_ADVISORY_ROOT_NAME
    if resolved != expected or root.name != HELD9_ADVISORY_ROOT_NAME:
        raise ValueError("phase2a_safe_fallback_held9_root_identity_invalid")
    return resolved


def _verify_held9_advisory(root: Path) -> dict[str, Any]:
    resolved = _held9_root_identity(root)
    advisory_path = resolved / HELD9_ADVISORY_NAME
    package_path = resolved / HELD9_PACKAGE_NAME
    checksums_path = resolved / HELD9_CHECKSUMS_NAME
    _verify_regular_file(
        advisory_path,
        EXPECTED_HELD9_ADVISORY_FILE_SHA256,
        "phase2a_safe_fallback_held9_advisory_file_invalid",
    )
    _verify_regular_file(
        package_path,
        EXPECTED_HELD9_PACKAGE_FILE_SHA256,
        "phase2a_safe_fallback_held9_package_file_invalid",
    )
    _verify_regular_file(
        checksums_path,
        EXPECTED_HELD9_CHECKSUMS_FILE_SHA256,
        "phase2a_safe_fallback_held9_checksums_file_invalid",
    )
    if {path.name for path in resolved.iterdir()} != {
        HELD9_ADVISORY_NAME,
        HELD9_PACKAGE_NAME,
        HELD9_CHECKSUMS_NAME,
    }:
        raise ValueError("phase2a_safe_fallback_held9_member_set_invalid")
    advisory = _load_object(advisory_path, "phase2a_safe_fallback_held9_advisory_invalid")
    package = _load_object(package_path, "phase2a_safe_fallback_held9_package_invalid")
    _verify_seal(
        advisory,
        "artifact_content_sha256",
        "phase2a_safe_fallback_held9_advisory_seal_invalid",
        EXPECTED_HELD9_ADVISORY_CONTENT_SHA256,
    )
    _verify_seal(
        package,
        "package_content_sha256",
        "phase2a_safe_fallback_held9_package_seal_invalid",
        EXPECTED_HELD9_PACKAGE_CONTENT_SHA256,
    )
    if (
        advisory.get("schema") != "legalbot.v111.phase2a.held9-surviving-support-advisory.v1"
        or advisory.get("status") != "SEALED_ADVISORY_ONLY_NO_PRODUCTION_STATE"
        or advisory.get("not_owner_decision") is not True
        or advisory.get("not_source_admission") is not True
        or advisory.get("not_qualification_result") is not True
        or advisory.get("not_legal_currentness_certification") is not True
        or advisory.get("not_later_treatment_certification") is not True
        or package.get("schema") != "legalbot.v111.phase2a.held9-surviving-support-package.v1"
        or package.get("status") != "SEALED_ADVISORY_ONLY_NO_PRODUCTION_STATE"
        or package.get("advisory")
        != {
            "artifact_content_sha256": EXPECTED_HELD9_ADVISORY_CONTENT_SHA256,
            "file_name": HELD9_ADVISORY_NAME,
            "file_sha256": EXPECTED_HELD9_ADVISORY_FILE_SHA256,
        }
    ):
        raise ValueError("phase2a_safe_fallback_held9_contract_invalid")
    no_execution = advisory.get("no_execution_flags")
    package_no_execution = package.get("no_execution_flags")
    if (
        not isinstance(no_execution, dict)
        or not no_execution
        or any(value is not False for value in no_execution.values())
        or package_no_execution != no_execution
    ):
        raise ValueError("phase2a_safe_fallback_held9_execution_boundary_invalid")
    _verify_no_execution_true_recursively([advisory, package])
    expected_checksums = (
        f"{EXPECTED_HELD9_ADVISORY_FILE_SHA256}  {HELD9_ADVISORY_NAME}\n"
        f"{EXPECTED_HELD9_PACKAGE_FILE_SHA256}  {HELD9_PACKAGE_NAME}\n"
    ).encode()
    if checksums_path.read_bytes() != expected_checksums:
        raise ValueError("phase2a_safe_fallback_held9_checksums_invalid")

    scope = advisory.get("scope")
    if not isinstance(scope, dict) or any(
        (
            scope.get("held_proposal_count") != 5,
            scope.get("exact_row_count") != 9,
            set(scope.get("exact_row_ids", [])) != _HELD9_ROW_IDS,
            scope.get("surviving_audit_pass_or_warning_proposal_count") != 9,
            scope.get("existing_candidate_source_count") != 3,
            scope.get("defective_representation_count") != 16,
        )
    ):
        raise ValueError("phase2a_safe_fallback_held9_scope_invalid")
    inputs = advisory.get("input_bindings")
    if not isinstance(inputs, list) or not any(
        isinstance(item, dict)
        and item.get("kind") == "delta"
        and item.get("content_sha256") == EXPECTED_SOURCE_DELTA_CONTENT_SHA256
        and item.get("file_sha256") == EXPECTED_SOURCE_DELTA_FILE_SHA256
        for item in inputs
    ):
        raise ValueError("phase2a_safe_fallback_held9_input_binding_invalid")
    held = advisory.get("five_unresolved_held_proposals")
    if (
        not isinstance(held, list)
        or len(held) != 5
        or any(
            not isinstance(item, dict)
            or item.get("representation_excluded") is not True
            or item.get("legal_rule_release_prohibited") is not True
            or item.get("source_admission_authorized") is not False
            or item.get("source_admitted") is not False
            or item.get("currentness_hold_retained") is not True
            or item.get("later_treatment_hold_retained") is not True
            for item in held
        )
    ):
        raise ValueError("phase2a_safe_fallback_held9_hold_set_invalid")
    row_outcomes = advisory.get("row_outcomes")
    if not isinstance(row_outcomes, list) or len(row_outcomes) != 9:
        raise ValueError("phase2a_safe_fallback_held9_row_set_invalid")
    by_row = {str(item.get("row_id")): item for item in row_outcomes if isinstance(item, dict)}
    if set(by_row) != _HELD9_ROW_IDS:
        raise ValueError("phase2a_safe_fallback_held9_row_set_invalid")
    for row_id in _HELD9_GAP_ROW_IDS:
        row = by_row[row_id]
        if (
            row.get("safe_fallback_eligible") is not False
            or row.get("safe_fallback_prohibited") is not True
            or row.get("blocker_class")
            not in {"LEGAL_AUTHORITY_GAP", "DUAL_LEGAL_SOURCE_AND_MATTER_FACT_HOLD"}
        ):
            raise ValueError("phase2a_safe_fallback_held9_gap_route_invalid")
    q58 = by_row["live60-q58:issue-09"]
    if any(
        (
            q58.get("outcome") != "NO_LEGAL_CLAIM_MATTER_FACT_SUPPLEMENTATION_FALLBACK_ADVISORY",
            q58.get("safe_fallback_eligible") is not True,
            q58.get("safe_fallback_prohibited") is not False,
            q58.get("knowledge_gap_event") is not False,
            q58.get("matter_information_gap_event") is not True,
            q58.get("fallback_releases_material_legal_claim") is not False,
            q58.get("legal_rule_release_prohibited") is not True,
            q58.get("citation_release_prohibited") is not True,
            q58.get("evidence_span_release_prohibited") is not True,
            q58.get("wuhan_source_admission_authorized") is not False,
        )
    ):
        raise ValueError("phase2a_safe_fallback_held9_q58_route_invalid")
    survivors = advisory.get("surviving_pass_or_pass_with_warning_representations")
    existing = advisory.get("surviving_existing_candidate_sources")
    defects = advisory.get("sixteen_defective_original_representations_excluded")
    if (
        not isinstance(survivors, list)
        or len(survivors) != 9
        or not isinstance(existing, list)
        or len(existing) != 3
        or not isinstance(defects, list)
        or len(defects) != 16
        or any(item.get("excluded") is not True for item in defects)
    ):
        raise ValueError("phase2a_safe_fallback_held9_support_set_invalid")
    wuhan = next(
        (
            item
            for item in survivors
            if item.get("proposal_content_sha256") == EXPECTED_WUHAN_PROPOSAL_CONTENT_SHA256
        ),
        None,
    )
    if (
        not isinstance(wuhan, dict)
        or wuhan.get("binding_record_content_sha256")
        != EXPECTED_WUHAN_BINDING_RECORD_CONTENT_SHA256
        or wuhan.get("cross_row_candidate_only") is not True
        or wuhan.get("cross_row_owner_decision_required") is not True
        or wuhan.get("legal_rule_release_prohibited") is not True
        or wuhan.get("currentness_hold_retained") is not True
        or wuhan.get("later_treatment_hold_retained") is not True
        or wuhan.get("row_locator_bindings") != {"live60-q58:issue-09": ["paragraphs 25-33"]}
    ):
        raise ValueError("phase2a_safe_fallback_held9_wuhan_invalid")
    interpretation = advisory.get("interpretation_contract")
    if not isinstance(interpretation, dict) or any(
        interpretation.get(field) is not True
        for field in (
            "essay_safe_fallback_prohibited",
            "fact_fallback_must_release_no_material_legal_claim",
            "fallback_must_not_hide_legal_knowledge_or_source_gap",
            "no_source_or_span_becomes_releasable_by_this_advisory",
            "supported_subset_is_not_a_pass",
            "wuhan_cross_row_candidate_is_not_an_owner_decision",
            "wuhan_currentness_and_later_treatment_holds_retained",
        )
    ):
        raise ValueError("phase2a_safe_fallback_held9_interpretation_invalid")
    return advisory


def _held9_owner_decisions(advisory: Mapping[str, Any]) -> dict[str, Any]:
    by_row = {item["row_id"]: item for item in advisory["row_outcomes"]}
    gap_decisions = [
        {
            "row_id": row_id,
            "blocker_class": by_row[row_id]["blocker_class"],
            "adopted_supported_subset": by_row[row_id]["supported_subset"],
            "retained_excluded_unsupported_components": by_row[row_id][
                "excluded_unsupported_components"
            ],
            "owner_outcome": ("ADOPT_LIMITED_SUPPORTED_SUBSET_RETAIN_AUTHORITY_GAP_NO_PASS"),
            "safe_fallback_prohibited": True,
            "technical_pass_eligible": False,
            "current_law_certified": False,
            "legal_rule_release_from_held_source_authorized": False,
        }
        for row_id in sorted(_HELD9_GAP_ROW_IDS)
    ]
    q58 = by_row["live60-q58:issue-09"]
    wuhan = next(
        item
        for item in advisory["surviving_pass_or_pass_with_warning_representations"]
        if item.get("proposal_content_sha256") == EXPECTED_WUHAN_PROPOSAL_CONTENT_SHA256
    )
    return {
        "sealed_advisory_content_sha256": EXPECTED_HELD9_ADVISORY_CONTENT_SHA256,
        "eight_fail_closed_legal_authority_gap_decisions": gap_decisions,
        "limited_supported_subsets_are_not_qualification_passes": True,
        "q58_issue09_no_legal_claim_fallback_decision": {
            "row_id": "live60-q58:issue-09",
            "owner_outcome": ("ADOPT_NO_LEGAL_CLAIM_MATTER_FACT_SUPPLEMENTATION_FALLBACK"),
            "reason_code": q58["reason_code"],
            "ui_cta": q58["ui_cta"],
            "knowledge_gap_event": False,
            "matter_information_gap_event": True,
            "requested_material": q58["requested_material"],
            "exact_safe_fallback_text": q58["safe_fallback_text"],
            "exact_safe_fallback_text_sha256": _sha256(q58["safe_fallback_text"].encode()),
            "fallback_releases_material_legal_claim": False,
            "legal_rule_release_prohibited": True,
            "citation_release_prohibited": True,
            "evidence_span_release_prohibited": True,
            "technical_pass_eligible_only_if_exact_fallback_contract_satisfied": True,
        },
        "wuhan_cross_row_candidate_decision": {
            "proposal_id": wuhan["proposal_id"],
            "proposal_content_sha256": wuhan["proposal_content_sha256"],
            "binding_record_content_sha256": wuhan["binding_record_content_sha256"],
            "proposed_source_version_id": wuhan["proposed_source_version_id"],
            "raw_sha256": wuhan["raw_sha256"],
            "row_locator_bindings": wuhan["row_locator_bindings"],
            "owner_outcome": ("ADOPT_CROSS_ROW_CANDIDATE_IDENTITY_ONLY_RETAIN_ALL_RELEASE_HOLDS"),
            "new_source_admission_required": False,
            "currentness_hold_retained": True,
            "later_treatment_hold_retained": True,
            "legal_rule_release_prohibited": True,
            "citation_release_prohibited": True,
            "evidence_span_release_prohibited": True,
        },
        "five_unresolved_source_holds_retained_exactly": advisory["five_unresolved_held_proposals"],
    }


def _fact_fallback_root_identity(root: Path) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("phase2a_safe_fallback_coverage_root_invalid")
    review = INPUT_REVIEW_ROOT.resolve(strict=True)
    resolved = root.resolve(strict=True)
    expected = review / FACT_FALLBACK_ADVISORY_ROOT_NAME
    if resolved != expected or root.name != FACT_FALLBACK_ADVISORY_ROOT_NAME:
        raise ValueError("phase2a_safe_fallback_coverage_root_identity_invalid")
    return resolved


def _verify_fact_fallback_advisory(root: Path) -> dict[str, Any]:
    resolved = _fact_fallback_root_identity(root)
    advisory_path = resolved / FACT_FALLBACK_ADVISORY_NAME
    package_path = resolved / FACT_FALLBACK_PACKAGE_NAME
    checksums_path = resolved / FACT_FALLBACK_CHECKSUMS_NAME
    _verify_regular_file(
        advisory_path,
        EXPECTED_FACT_FALLBACK_ADVISORY_FILE_SHA256,
        "phase2a_safe_fallback_coverage_advisory_file_invalid",
    )
    _verify_regular_file(
        package_path,
        EXPECTED_FACT_FALLBACK_PACKAGE_FILE_SHA256,
        "phase2a_safe_fallback_coverage_package_file_invalid",
    )
    _verify_regular_file(
        checksums_path,
        EXPECTED_FACT_FALLBACK_CHECKSUMS_FILE_SHA256,
        "phase2a_safe_fallback_coverage_checksums_file_invalid",
    )
    if {path.name for path in resolved.iterdir()} != {
        FACT_FALLBACK_ADVISORY_NAME,
        FACT_FALLBACK_PACKAGE_NAME,
        FACT_FALLBACK_CHECKSUMS_NAME,
    }:
        raise ValueError("phase2a_safe_fallback_coverage_member_set_invalid")

    advisory = _load_object(advisory_path, "phase2a_safe_fallback_coverage_advisory_invalid")
    package = _load_object(package_path, "phase2a_safe_fallback_coverage_package_invalid")
    _verify_seal(
        advisory,
        "artifact_content_sha256",
        "phase2a_safe_fallback_coverage_advisory_seal_invalid",
        EXPECTED_FACT_FALLBACK_ADVISORY_CONTENT_SHA256,
    )
    _verify_seal(
        package,
        "artifact_content_sha256",
        "phase2a_safe_fallback_coverage_package_seal_invalid",
        EXPECTED_FACT_FALLBACK_PACKAGE_CONTENT_SHA256,
    )
    if (
        advisory.get("schema") != "legalbot.v111.phase2a.fact-only-fallback-coverage-advisory.v1"
        or advisory.get("status") != "EXACT_585_ROW_FALLBACK_COVERAGE_ADVISORY_READY_NOT_APPLIED"
        or advisory.get("advisory_effect")
        != "NO_EXECUTION_NO_OWNER_DECISION_NO_PRODUCTION_QUALIFICATION"
        or advisory.get("phase_scope") != "PHASE2A_ONLY"
        or package.get("schema") != "legalbot.v111.phase2a.fact-only-fallback-coverage-package.v1"
        or package.get("status") != "EXACT_585_ROW_FALLBACK_COVERAGE_ADVISORY_READY_NOT_APPLIED"
        or package.get("advisory_content_sha256") != EXPECTED_FACT_FALLBACK_ADVISORY_CONTENT_SHA256
        or package.get("eligible_row_ids") != [PERFORMANCE_BOND_ROW_ID, ROW_ID]
        or package.get("eligible_row_count") != 2
    ):
        raise ValueError("phase2a_safe_fallback_coverage_contract_invalid")
    _verify_no_execution_true_recursively([advisory, package])
    expected_checksums = (
        f"{EXPECTED_FACT_FALLBACK_ADVISORY_FILE_SHA256}  {FACT_FALLBACK_ADVISORY_NAME}\n"
        f"{EXPECTED_FACT_FALLBACK_PACKAGE_FILE_SHA256}  {FACT_FALLBACK_PACKAGE_NAME}\n"
    ).encode()
    if checksums_path.read_bytes() != expected_checksums:
        raise ValueError("phase2a_safe_fallback_coverage_checksums_invalid")
    if package.get("artifacts") != [
        {
            "content_sha256": EXPECTED_FACT_FALLBACK_ADVISORY_CONTENT_SHA256,
            "file_sha256": EXPECTED_FACT_FALLBACK_ADVISORY_FILE_SHA256,
            "name": FACT_FALLBACK_ADVISORY_NAME,
        }
    ]:
        raise ValueError("phase2a_safe_fallback_coverage_package_binding_invalid")

    coverage = advisory.get("coverage_verdict")
    classification = advisory.get("classification_contract")
    remaining = advisory.get("remaining_583_row_policy")
    rows = advisory.get("eligible_rows")
    if (
        not isinstance(coverage, dict)
        or coverage.get("coverage_complete_for_exact_585_row_audit") is not True
        or coverage.get("eligible_row_ids") != [PERFORMANCE_BOND_ROW_ID, ROW_ID]
        or coverage.get("project_rescue_contract_content_sha256")
        != EXPECTED_SAFE_FALLBACK_CONTRACT_CONTENT_SHA256
        or coverage.get("performance_bond_contract_content_sha256")
        != EXPECTED_PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256
        or not isinstance(classification, dict)
        or classification.get("strict_fact_only_row_ids") != [ROW_ID]
        or classification.get("no_legal_claim_exception_row_ids") != [PERFORMANCE_BOND_ROW_ID]
        or classification.get("fallback_must_not_hide_a_legal_knowledge_or_source_gap") is not True
        or classification.get("row_removal_or_cancellation_prohibited") is not True
        or not isinstance(remaining, dict)
        or remaining.get("row_count") != 583
        or remaining.get("automatic_safe_fallback_eligibility") is not False
        or not isinstance(rows, list)
        or len(rows) != 2
    ):
        raise ValueError("phase2a_safe_fallback_coverage_scope_invalid")
    by_row = {str(row.get("row_id")): row for row in rows if isinstance(row, dict)}
    if set(by_row) != {PERFORMANCE_BOND_ROW_ID, ROW_ID}:
        raise ValueError("phase2a_safe_fallback_coverage_row_set_invalid")
    q14 = by_row[ROW_ID]
    q09 = by_row[PERFORMANCE_BOND_ROW_ID]
    if (
        q14.get("eligibility_class") != "STRICT_FACT_ONLY_REMAINING_BLOCKER"
        or q14.get("contract_content_sha256") != EXPECTED_SAFE_FALLBACK_CONTRACT_CONTENT_SHA256
        or q14.get("required_user_message") != SAFE_FALLBACK_MESSAGE
        or q14.get("required_missing_information_categories")
        != list(MISSING_INFORMATION_CATEGORIES)
        or q14.get("knowledge_gap_event") is not False
        or q14.get("matter_information_gap_event") is not True
        or q14.get("material_legal_claim_released") is not False
    ):
        raise ValueError("phase2a_safe_fallback_coverage_q14_invalid")
    if (
        q09.get("eligibility_class") != "NO_LEGAL_CLAIM_MATTER_FACT_FALLBACK_EXCEPTION"
        or q09.get("contract_content_sha256") != EXPECTED_PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256
        or q09.get("bound_held9_advisory_content_sha256") != EXPECTED_HELD9_ADVISORY_CONTENT_SHA256
        or q09.get("required_user_message") != PERFORMANCE_BOND_SAFE_FALLBACK_MESSAGE
        or q09.get("required_missing_information_categories")
        != list(PERFORMANCE_BOND_MISSING_INFORMATION_CATEGORIES)
        or q09.get("knowledge_gap_event") is not False
        or q09.get("matter_information_gap_event") is not True
        or q09.get("material_legal_claim_released") is not False
        or q09.get("retained_underlying_holds")
        != {
            "currentness_hold_retained": True,
            "later_treatment_hold_retained": True,
            "underlying_substantive_answer_not_qualified": True,
        }
    ):
        raise ValueError("phase2a_safe_fallback_coverage_q09_invalid")
    return advisory


def _canonical_performance_bond_contract() -> dict[str, Any]:
    contract = performance_bond_safe_fallback_contract()
    _verify_seal(
        contract,
        "contract_content_sha256",
        "phase2a_safe_fallback_performance_bond_contract_invalid",
        EXPECTED_PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256,
    )
    if (
        contract.get("row_id") != PERFORMANCE_BOND_ROW_ID
        or contract.get("held9_advisory_content_sha256")
        != PERFORMANCE_BOND_HELD9_ADVISORY_CONTENT_SHA256
        or contract.get("outcome_class") != PERFORMANCE_BOND_OUTCOME_CLASS
        or contract.get("reason_code") != PERFORMANCE_BOND_REASON_CODE
        or contract.get("required_action") != PERFORMANCE_BOND_ACTION
        or contract.get("ui_cta") != PERFORMANCE_BOND_UI_CTA
        or contract.get("required_missing_information_categories")
        != list(PERFORMANCE_BOND_MISSING_INFORMATION_CATEGORIES)
        or contract.get("required_user_message") != PERFORMANCE_BOND_SAFE_FALLBACK_MESSAGE
        or contract.get("event_policy", {}).get("knowledge_gap_event") is not False
        or contract.get("event_policy", {}).get("matter_information_gap_event") is not True
        or contract.get("evidence_policy", {}).get("evidence_spans_permitted") is not False
        or contract.get("evidence_policy", {}).get("citations_permitted") is not False
    ):
        raise ValueError("phase2a_safe_fallback_performance_bond_contract_mismatch")
    return contract


def _performance_bond_safe_fallback_decision() -> dict[str, Any]:
    contract = _canonical_performance_bond_contract()
    material: dict[str, Any] = {
        "row_id": PERFORMANCE_BOND_ROW_ID,
        "row_retained_in_all585": True,
        "evaluation_row_removed": False,
        "classification": PERFORMANCE_BOND_OUTCOME_CLASS,
        "fallback_reason_code": PERFORMANCE_BOND_REASON_CODE,
        "human_escalation_cta": HUMAN_ESCALATION_CTA,
        "ui_cta": PERFORMANCE_BOND_UI_CTA,
        "knowledge_gap_event": False,
        "matter_information_gap_event": True,
        "substantive_legal_answer_required": False,
        "evidence_span_required": False,
        "legal_rule_release_prohibited": True,
        "citation_release_prohibited": True,
        "evidence_span_release_prohibited": True,
        "answer_model_output_for_this_issue_prohibited": True,
        "underlying_legal_source_holds_resolved": False,
        "currentness_hold_retained": True,
        "later_treatment_hold_retained": True,
        "missing_information_categories": list(PERFORMANCE_BOND_MISSING_INFORMATION_CATEGORIES),
        "missing_information_categories_sha256": _sha256(
            _canonical_json(list(PERFORMANCE_BOND_MISSING_INFORMATION_CATEGORIES))
        ),
        "deterministic_reply": PERFORMANCE_BOND_SAFE_FALLBACK_MESSAGE,
        "deterministic_reply_sha256": _sha256(PERFORMANCE_BOND_SAFE_FALLBACK_MESSAGE.encode()),
        "reply_match_mode": "EXACT_UTF8_STRING",
        "qualification_result_when_contract_satisfied": QUALIFICATION_STATUS,
        "qualification_result_when_contract_violated": FAILURE_STATUS,
        "canonical_contract": contract,
        "canonical_contract_content_sha256": contract["contract_content_sha256"],
        "material_legal_proposition_claimed_resolved": False,
        "answer_release_eligible": False,
        "phase2a_technical_qualification_only": True,
        "phase2b_authorized": False,
    }
    return {**material, "decision_content_sha256": _sealed(material)}


def _echr_recovery_root_identity(root: Path) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("phase2a_safe_fallback_echr_recovery_root_invalid")
    review = INPUT_REVIEW_ROOT.resolve(strict=True)
    resolved = root.resolve(strict=True)
    expected = review / ECHR_RECOVERY_ROOT_NAME
    if resolved != expected or root.name != ECHR_RECOVERY_ROOT_NAME:
        raise ValueError("phase2a_safe_fallback_echr_recovery_root_identity_invalid")
    return resolved


def _verify_echr_recovery(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    resolved = _echr_recovery_root_identity(root)
    manifest_path = resolved / ECHR_RECOVERY_MANIFEST_NAME
    package_path = resolved / ECHR_RECOVERY_PACKAGE_NAME
    checksums_path = resolved / ECHR_RECOVERY_CHECKSUMS_NAME
    _verify_regular_file(
        manifest_path,
        EXPECTED_ECHR_RECOVERY_MANIFEST_FILE_SHA256,
        "phase2a_safe_fallback_echr_recovery_manifest_file_invalid",
    )
    _verify_regular_file(
        package_path,
        EXPECTED_ECHR_RECOVERY_PACKAGE_FILE_SHA256,
        "phase2a_safe_fallback_echr_recovery_package_file_invalid",
    )
    _verify_regular_file(
        checksums_path,
        EXPECTED_ECHR_RECOVERY_CHECKSUMS_FILE_SHA256,
        "phase2a_safe_fallback_echr_recovery_checksums_file_invalid",
    )
    manifest = _load_object(manifest_path, "phase2a_safe_fallback_echr_recovery_manifest_invalid")
    package = _load_object(package_path, "phase2a_safe_fallback_echr_recovery_package_invalid")
    _verify_seal(
        manifest,
        "manifest_content_sha256",
        "phase2a_safe_fallback_echr_recovery_manifest_seal_invalid",
        EXPECTED_ECHR_RECOVERY_MANIFEST_CONTENT_SHA256,
    )
    _verify_seal(
        package,
        "package_content_sha256",
        "phase2a_safe_fallback_echr_recovery_package_seal_invalid",
        EXPECTED_ECHR_RECOVERY_PACKAGE_CONTENT_SHA256,
    )
    if (
        manifest.get("schema") != "legalbot.v111.phase2a.echr-held-source-recovery-quarantine.v1"
        or manifest.get("status") != "EXACT_ECHR_REPRESENTATIONS_QUARANTINED_OWNER_DELTA_REQUIRED"
        or manifest.get("planned_document_count") != 4
        or manifest.get("successful_document_count") != 3
        or manifest.get("new_successful_document_count") != 2
        or manifest.get("carried_forward_document_count") != 1
        or manifest.get("held_document_count") != 1
        or manifest.get("single_attempt_per_document_enforced") is not True
        or package.get("schema") != "legalbot.v111.phase2a.echr-held-source-recovery-package.v1"
        or package.get("status") != "QUARANTINED_NOT_OWNER_ADOPTED"
        or package.get("file_count") != 6
    ):
        raise ValueError("phase2a_safe_fallback_echr_recovery_contract_invalid")
    _verify_no_execution_true_recursively([manifest, package])

    entries = package.get("files")
    if not isinstance(entries, list) or len(entries) != 6:
        raise ValueError("phase2a_safe_fallback_echr_recovery_member_set_invalid")
    package_members: dict[str, str] = {}
    checksum_lines: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("phase2a_safe_fallback_echr_recovery_member_set_invalid")
        member = str(entry.get("path", ""))
        member_sha256 = str(entry.get("sha256", ""))
        if (
            not member
            or Path(member).name != member
            or member in package_members
            or _SHA256.fullmatch(member_sha256) is None
        ):
            raise ValueError("phase2a_safe_fallback_echr_recovery_member_set_invalid")
        member_path = resolved / member
        _verify_regular_file(
            member_path,
            member_sha256,
            "phase2a_safe_fallback_echr_recovery_member_invalid",
        )
        if member_path.stat().st_size != entry.get("bytes"):
            raise ValueError("phase2a_safe_fallback_echr_recovery_member_invalid")
        package_members[member] = member_sha256
        checksum_lines.append(f"{member_sha256}  {member}\n")
    expected_members = {
        ECHR_RECOVERY_MANIFEST_NAME,
        "OUTCOME.txt",
        "echr-representation-0001-798f181056e6c12d7706.html",
        "echr-canonical-0001-b2625664eacfe6a81b1d.md",
        "echr-representation-0003-2bab2b5596ca559242c9.html",
        "echr-canonical-0003-4ac630159b18e49893bd.md",
    }
    if set(package_members) != expected_members:
        raise ValueError("phase2a_safe_fallback_echr_recovery_member_set_invalid")
    checksum_lines.append(
        f"{EXPECTED_ECHR_RECOVERY_PACKAGE_FILE_SHA256}  {ECHR_RECOVERY_PACKAGE_NAME}\n"
    )
    if checksums_path.read_text(encoding="utf-8") != "".join(checksum_lines):
        raise ValueError("phase2a_safe_fallback_echr_recovery_checksums_invalid")
    if {path.name for path in resolved.iterdir()} != {
        *expected_members,
        ECHR_RECOVERY_PACKAGE_NAME,
        ECHR_RECOVERY_CHECKSUMS_NAME,
    }:
        raise ValueError("phase2a_safe_fallback_echr_recovery_member_set_invalid")

    records = manifest.get("records")
    if not isinstance(records, list) or len(records) != 2:
        raise ValueError("phase2a_safe_fallback_echr_recovery_record_set_invalid")
    expected_records = {
        EXPECTED_ECHR_KLIMA_RECORD_CONTENT_SHA256: {
            "raw_sha256": EXPECTED_ECHR_KLIMA_RAW_SHA256,
            "canonical_markdown_sha256": EXPECTED_ECHR_KLIMA_CANONICAL_SHA256,
            "affected_row_ids": {
                "live30-q22:issue-02",
                "live30-q22:issue-04",
                "live30-q22:issue-06",
            },
            "required_paragraph_count": 27,
        },
        EXPECTED_ECHR_BIG_BROTHER_RECORD_CONTENT_SHA256: {
            "raw_sha256": EXPECTED_ECHR_BIG_BROTHER_RAW_SHA256,
            "canonical_markdown_sha256": EXPECTED_ECHR_BIG_BROTHER_CANONICAL_SHA256,
            "affected_row_ids": {"live60-q56:issue-01", "live60-q56:issue-05"},
            "required_paragraph_count": 36,
        },
    }
    recovered_bindings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("phase2a_safe_fallback_echr_recovery_record_invalid")
        record_sha256 = _verify_seal(
            record,
            "record_content_sha256",
            "phase2a_safe_fallback_echr_recovery_record_seal_invalid",
        )
        expected = expected_records.get(record_sha256)
        if expected is None or record_sha256 in seen:
            raise ValueError("phase2a_safe_fallback_echr_recovery_record_set_invalid")
        seen.add(record_sha256)
        raw_member = str(record.get("quarantine_member", ""))
        canonical_member = str(record.get("canonical_markdown_member", ""))
        if (
            record.get("raw_sha256") != expected["raw_sha256"]
            or record.get("canonical_markdown_sha256") != expected["canonical_markdown_sha256"]
            or set(record.get("affected_row_ids", [])) != expected["affected_row_ids"]
            or record.get("required_paragraph_count") != expected["required_paragraph_count"]
            or len(record.get("required_paragraphs_verified", []))
            != expected["required_paragraph_count"]
            or record.get("content_fitness_status")
            != "OFFICIAL_FULL_JUDGMENT_BODY_AND_REQUIRED_SPANS_VERIFIED"
            or record.get("currentness_hold_retained") is not True
            or record.get("later_treatment_hold_retained") is not True
            or record.get("owner_delta_decision_required") is not True
            or package_members.get(raw_member) != expected["raw_sha256"]
            or package_members.get(canonical_member) != expected["canonical_markdown_sha256"]
        ):
            raise ValueError("phase2a_safe_fallback_echr_recovery_record_invalid")
        recovered_bindings.append(
            {
                "record_id": record["record_id"],
                "record_content_sha256": record_sha256,
                "proposed_source_version_id": record["proposed_source_version_id"],
                "raw_sha256": record["raw_sha256"],
                "canonical_markdown_sha256": record["canonical_markdown_sha256"],
                "quarantine_member": raw_member,
                "canonical_markdown_member": canonical_member,
                "affected_row_ids": record["affected_row_ids"],
                "exact_locators": record["exact_locators"],
                "required_paragraphs_verified": record["required_paragraphs_verified"],
                "recommended_owner_outcome": (
                    "ADMIT_EXACT_OFFICIAL_RAW_AND_CANONICAL_MARKDOWN_REPRESENTATIONS"
                ),
                "currentness_hold_retained": True,
                "later_treatment_hold_retained": True,
                "answer_release_authorized": False,
            }
        )
    if seen != set(expected_records):
        raise ValueError("phase2a_safe_fallback_echr_recovery_record_set_invalid")

    carried = manifest.get("carried_forward_records")
    if not isinstance(carried, list) or len(carried) != 1:
        raise ValueError("phase2a_safe_fallback_echr_recovery_goodwin_invalid")
    goodwin = carried[0]
    if (
        goodwin.get("document_id") != "001-57974"
        or goodwin.get("carry_mode") != "SEALED_REFERENCE_NO_NETWORK_NO_BYTE_COPY"
        or goodwin.get("raw_sha256") != EXPECTED_ECHR_GOODWIN_RAW_SHA256
        or goodwin.get("record_content_sha256") != EXPECTED_ECHR_GOODWIN_RECORD_CONTENT_SHA256
        or goodwin.get("owner_delta_decision_required") is not True
        or goodwin.get("source_manifest_content_sha256")
        != "c6672a3f227b9a518ac628861bc1bcaf361d9c29968f20c490f27d3f34592145"
        or goodwin.get("source_manifest_file_sha256")
        != "e7f23bbe8219370f24ae86e3dab7356bab6ad90fc8a405c92ee1b06f8bd74879"
    ):
        raise ValueError("phase2a_safe_fallback_echr_recovery_goodwin_invalid")

    holds = manifest.get("holds")
    if not isinstance(holds, list) or len(holds) != 1:
        raise ValueError("phase2a_safe_fallback_echr_recovery_mutu_hold_invalid")
    mutu = holds[0]
    if (
        set(mutu.get("affected_row_ids", [])) != {"live60-q53:issue-04", "live60-q53:issue-11"}
        or mutu.get("failure_fingerprint") != EXPECTED_ECHR_MUTU_FAILURE_FINGERPRINT_SHA256
        or mutu.get("attempt_identity_sha256") != EXPECTED_ECHR_MUTU_ATTEMPT_IDENTITY_SHA256
        or mutu.get("hold_content_sha256") != EXPECTED_ECHR_MUTU_HOLD_CONTENT_SHA256
        or mutu.get("reason_code") != "OFFICIAL_HUDOC_RECOVERY_SINGLE_CHANGED_PATH_ATTEMPT_FAILED"
        or mutu.get("hold_retained") is not True
        or mutu.get("retry_run") is not False
    ):
        raise ValueError("phase2a_safe_fallback_echr_recovery_mutu_hold_invalid")
    return manifest, recovered_bindings


def _q53_substitute_root_identity(root: Path) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("phase2a_safe_fallback_q53_substitute_root_invalid")
    review = INPUT_REVIEW_ROOT.resolve(strict=True)
    resolved = root.resolve(strict=True)
    expected = review / Q53_SUBSTITUTE_ROOT_NAME
    if resolved != expected or root.name != Q53_SUBSTITUTE_ROOT_NAME:
        raise ValueError("phase2a_safe_fallback_q53_substitute_root_identity_invalid")
    return resolved


def _verify_q53_substitute(
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    resolved = _q53_substitute_root_identity(root)
    advisory_path = resolved / Q53_SUBSTITUTE_ADVISORY_NAME
    package_path = resolved / Q53_SUBSTITUTE_PACKAGE_NAME
    checksums_path = resolved / Q53_SUBSTITUTE_CHECKSUMS_NAME
    _verify_regular_file(
        advisory_path,
        EXPECTED_Q53_SUBSTITUTE_ADVISORY_FILE_SHA256,
        "phase2a_safe_fallback_q53_substitute_advisory_file_invalid",
    )
    _verify_regular_file(
        package_path,
        EXPECTED_Q53_SUBSTITUTE_PACKAGE_FILE_SHA256,
        "phase2a_safe_fallback_q53_substitute_package_file_invalid",
    )
    _verify_regular_file(
        checksums_path,
        EXPECTED_Q53_SUBSTITUTE_CHECKSUMS_FILE_SHA256,
        "phase2a_safe_fallback_q53_substitute_checksums_file_invalid",
    )
    raw_member = "echr-001-244348-52f5485626ffd7235993.html"
    canonical_member = "echr-001-244348-b9394f938b01840e14c2.md"
    _verify_regular_file(
        resolved / raw_member,
        EXPECTED_Q53_SEMENYA_RAW_SHA256,
        "phase2a_safe_fallback_q53_substitute_raw_invalid",
    )
    _verify_regular_file(
        resolved / canonical_member,
        EXPECTED_Q53_SEMENYA_CANONICAL_SHA256,
        "phase2a_safe_fallback_q53_substitute_canonical_invalid",
    )
    if {path.name for path in resolved.iterdir()} != {
        Q53_SUBSTITUTE_ADVISORY_NAME,
        Q53_SUBSTITUTE_PACKAGE_NAME,
        Q53_SUBSTITUTE_CHECKSUMS_NAME,
        raw_member,
        canonical_member,
    }:
        raise ValueError("phase2a_safe_fallback_q53_substitute_member_set_invalid")
    advisory = _load_object(advisory_path, "phase2a_safe_fallback_q53_substitute_advisory_invalid")
    package = _load_object(package_path, "phase2a_safe_fallback_q53_substitute_package_invalid")
    _verify_seal(
        advisory,
        "artifact_content_sha256",
        "phase2a_safe_fallback_q53_substitute_advisory_seal_invalid",
        EXPECTED_Q53_SUBSTITUTE_ADVISORY_CONTENT_SHA256,
    )
    _verify_seal(
        package,
        "package_content_sha256",
        "phase2a_safe_fallback_q53_substitute_package_seal_invalid",
        EXPECTED_Q53_SUBSTITUTE_PACKAGE_CONTENT_SHA256,
    )
    if (
        advisory.get("schema") != "legalbot.v111.phase2a.q53-semenya-substitute-source-advisory.v1"
        or advisory.get("status")
        != "PROPOSITION_COMPLETE_SUBSTITUTE_QUARANTINED_OWNER_DELTA_REQUIRED"
        or advisory.get("not_owner_decision") is not True
        or advisory.get("not_source_admission") is not True
        or advisory.get("not_qualification_result") is not True
        or advisory.get("not_legal_currentness_certification") is not True
        or advisory.get("not_later_treatment_certification") is not True
        or package.get("schema")
        != "legalbot.v111.phase2a.q53-semenya-substitute-package-manifest.v1"
        or package.get("advisory_content_sha256") != EXPECTED_Q53_SUBSTITUTE_ADVISORY_CONTENT_SHA256
        or package.get("advisory_file_sha256") != EXPECTED_Q53_SUBSTITUTE_ADVISORY_FILE_SHA256
        or package.get("raw_member") != raw_member
        or package.get("raw_sha256") != EXPECTED_Q53_SEMENYA_RAW_SHA256
        or package.get("canonical_markdown_member") != canonical_member
        or package.get("canonical_markdown_sha256") != EXPECTED_Q53_SEMENYA_CANONICAL_SHA256
    ):
        raise ValueError("phase2a_safe_fallback_q53_substitute_contract_invalid")
    _verify_no_execution_true_recursively([advisory, package])
    expected_checksums = (
        f"{EXPECTED_Q53_SEMENYA_RAW_SHA256}  {raw_member}\n"
        f"{EXPECTED_Q53_SEMENYA_CANONICAL_SHA256}  {canonical_member}\n"
        f"{EXPECTED_Q53_SUBSTITUTE_ADVISORY_FILE_SHA256}  {Q53_SUBSTITUTE_ADVISORY_NAME}\n"
        f"{EXPECTED_Q53_SUBSTITUTE_PACKAGE_FILE_SHA256}  {Q53_SUBSTITUTE_PACKAGE_NAME}\n"
    ).encode()
    if checksums_path.read_bytes() != expected_checksums:
        raise ValueError("phase2a_safe_fallback_q53_substitute_checksums_invalid")

    inputs = advisory.get("input_bindings")
    scope = advisory.get("scope")
    interpretation = advisory.get("interpretation_contract")
    if (
        not isinstance(inputs, dict)
        or inputs.get("echr_recovery_r3", {}).get("content_sha256")
        != EXPECTED_ECHR_RECOVERY_MANIFEST_CONTENT_SHA256
        or inputs.get("echr_recovery_r3", {}).get("mutu_failure_fingerprint")
        != EXPECTED_ECHR_MUTU_FAILURE_FINGERPRINT_SHA256
        or inputs.get("held9_advisory", {}).get("content_sha256")
        != EXPECTED_HELD9_ADVISORY_CONTENT_SHA256
        or not isinstance(scope, dict)
        or scope.get("row_ids") != ["live60-q53:issue-04", "live60-q53:issue-11"]
        or scope.get("mutu_pechstein_fetched_or_retried_here") is not False
        or scope.get("mutu_pechstein_path_permanently_stopped") is not True
        or not isinstance(interpretation, dict)
        or interpretation.get("no_claim_from_party_submission") is not True
        or interpretation.get("no_claim_from_press_release_or_case_law_note") is not True
        or "R57" not in str(interpretation.get("public_hearing_boundary", ""))
        or "not a disciplinary-sanctions case"
        not in str(interpretation.get("semenya_case_boundary", ""))
    ):
        raise ValueError("phase2a_safe_fallback_q53_substitute_scope_invalid")

    source = advisory.get("semenya_source_record")
    if not isinstance(source, dict):
        raise ValueError("phase2a_safe_fallback_q53_substitute_source_invalid")
    _verify_seal(
        source,
        "record_content_sha256",
        "phase2a_safe_fallback_q53_substitute_source_seal_invalid",
        EXPECTED_Q53_SEMENYA_RECORD_CONTENT_SHA256,
    )
    if (
        source.get("raw_member") != raw_member
        or source.get("raw_sha256") != EXPECTED_Q53_SEMENYA_RAW_SHA256
        or source.get("canonical_markdown_member") != canonical_member
        or source.get("canonical_markdown_sha256") != EXPECTED_Q53_SEMENYA_CANONICAL_SHA256
        or source.get("required_paragraph_count") != 40
        or source.get("required_paragraphs_verified") != [*range(193, 219), *range(226, 240)]
        or source.get("content_fitness_status")
        != "OFFICIAL_FULL_JUDGMENT_BODY_AND_EXACT_SUBSTITUTE_SPANS_VERIFIED"
        or source.get("official_front_matter_finality_statement_verified") is not True
        or source.get("currentness_hold_retained") is not True
        or source.get("later_treatment_hold_retained") is not True
        or source.get("answer_eligible") is not False
        or source.get("source_admission_recommendation")
        != "ADMIT_ONLY_THIS_EXACT_SEALED_REPRESENTATION_IF_OWNER_ADOPTS_THE_FINAL_EXACT_PACKET"
    ):
        raise ValueError("phase2a_safe_fallback_q53_substitute_source_invalid")

    rows = advisory.get("row_outcomes")
    if not isinstance(rows, list) or len(rows) != 2:
        raise ValueError("phase2a_safe_fallback_q53_substitute_row_set_invalid")
    by_row = {str(row.get("row_id")): row for row in rows if isinstance(row, dict)}
    if set(by_row) != {"live60-q53:issue-04", "live60-q53:issue-11"}:
        raise ValueError("phase2a_safe_fallback_q53_substitute_row_set_invalid")
    expected_locators = {
        "live60-q53:issue-04": {
            "Code of Sports-related Arbitration 2025": ["R47", "R57"],
            "Semenya v Switzerland [GC]": ["paras 195-218", "paras 226-239"],
            "Arbitration Act 1996": ["sections 33 and 68"],
        },
        "live60-q53:issue-11": {
            "Code of Sports-related Arbitration 2025": ["R27", "R47", "R57", "R59"],
            "Semenya v Switzerland [GC]": ["paras 195-218", "paras 226-239"],
            "Arbitration Act 1996": ["sections 1, 33, 67-70, 81(1)(a) and 103(3)"],
        },
    }
    row_decisions: list[dict[str, Any]] = []
    for row_id in sorted(by_row):
        row = by_row[row_id]
        support_set = row.get("support_set")
        if (
            row.get("outcome")
            != "PROPOSITION_COMPLETE_SUBSTITUTE_SET_ADVISORY_OWNER_DELTA_REQUIRED"
            or row.get("safe_fallback_eligible") is not False
            or row.get("safe_fallback_prohibited") is not True
            or row.get("answer_eligible") is not False
            or row.get("currentness_hold_retained") is not True
            or row.get("later_treatment_hold_retained") is not True
            or not isinstance(row.get("superseded_old_mutu_specific_wording"), list)
            or len(row["superseded_old_mutu_specific_wording"]) != 2
            or not isinstance(support_set, list)
            or len(support_set) != 3
        ):
            raise ValueError("phase2a_safe_fallback_q53_substitute_row_invalid")
        actual_locators = {
            str(item.get("source")): item.get("locators")
            for item in support_set
            if isinstance(item, dict)
        }
        if actual_locators != expected_locators[row_id] or not any(
            item.get("record_content_sha256") == EXPECTED_Q53_SEMENYA_RECORD_CONTENT_SHA256
            for item in support_set
            if isinstance(item, dict)
        ):
            raise ValueError("phase2a_safe_fallback_q53_substitute_support_invalid")
        row_decisions.append(
            {
                "row_id": row_id,
                "owner_outcome": "ADOPT_REVISED_PROPOSITION_COMPLETE_SUBSTITUTE_SET",
                "support_set": support_set,
                "replacement_boundary": row["replacement_boundary"],
                "superseded_old_mutu_specific_wording": row["superseded_old_mutu_specific_wording"],
                "safe_fallback_prohibited": True,
                "currentness_hold_retained": True,
                "later_treatment_hold_retained": True,
                "answer_eligible": False,
            }
        )
    ali_riza = advisory.get("ali_riza_single_attempt_hold")
    if (
        not isinstance(ali_riza, dict)
        or ali_riza.get("failure_fingerprint") != EXPECTED_Q53_ALI_RIZA_FAILURE_FINGERPRINT_SHA256
        or ali_riza.get("attempt_count") != 1
        or ali_riza.get("retry_run") is not False
        or ali_riza.get("path_stopped") is not True
        or ali_riza.get("required_for_revised_substitute_set") is not False
        or ali_riza.get("hold_retained") is not True
    ):
        raise ValueError("phase2a_safe_fallback_q53_substitute_ali_riza_hold_invalid")
    source_binding = {
        "record_id": source["record_id"],
        "record_content_sha256": source["record_content_sha256"],
        "proposed_source_version_id": source["proposed_source_version_id"],
        "raw_member": raw_member,
        "raw_sha256": EXPECTED_Q53_SEMENYA_RAW_SHA256,
        "canonical_markdown_member": canonical_member,
        "canonical_markdown_sha256": EXPECTED_Q53_SEMENYA_CANONICAL_SHA256,
        "required_paragraphs_verified": source["required_paragraphs_verified"],
        "recommended_owner_outcome": (
            "ADMIT_EXACT_OFFICIAL_RAW_AND_CANONICAL_MARKDOWN_REPRESENTATIONS"
        ),
        "currentness_hold_retained": True,
        "later_treatment_hold_retained": True,
        "answer_release_authorized": False,
    }
    return advisory, source_binding, row_decisions


def _canonical_safe_fallback_contract() -> dict[str, Any]:
    contract = safe_fallback_contract()
    _verify_seal(
        contract,
        "contract_content_sha256",
        "phase2a_safe_fallback_canonical_contract_invalid",
        EXPECTED_SAFE_FALLBACK_CONTRACT_CONTENT_SHA256,
    )
    categories_sha256 = _sha256(_canonical_json(list(MISSING_INFORMATION_CATEGORIES)))
    reply_sha256 = _sha256(SAFE_FALLBACK_MESSAGE.encode())
    if (
        categories_sha256 != EXPECTED_SAFE_FALLBACK_CATEGORIES_SHA256
        or reply_sha256 != EXPECTED_SAFE_FALLBACK_REPLY_SHA256
        or contract.get("row_id") != ROW_ID
        or contract.get("outcome_class") != OUTCOME_CLASS
        or contract.get("reason_code") != REASON_CODE
        or contract.get("human_escalation_cta") != HUMAN_ESCALATION_CTA
        or contract.get("ui_cta") != UI_CTA
        or contract.get("required_missing_information_categories")
        != list(MISSING_INFORMATION_CATEGORIES)
        or contract.get("required_user_message") != SAFE_FALLBACK_MESSAGE
        or contract.get("qualification_status") != QUALIFICATION_STATUS
        or contract.get("qualification_result_when_contract_satisfied") != QUALIFICATION_STATUS
        or contract.get("qualification_result_when_contract_violated") != FAILURE_STATUS
        or contract.get("event_policy")
        != {
            "knowledge_gap_event": False,
            "matter_information_gap_event": True,
            "event_reason_code": REASON_CODE,
            "ui_cta": UI_CTA,
        }
    ):
        raise ValueError("phase2a_safe_fallback_canonical_contract_mismatch")
    return contract


def _safe_fallback_decision() -> dict[str, Any]:
    contract = _canonical_safe_fallback_contract()
    material: dict[str, Any] = {
        "row_id": ROW_ID,
        "row_retained_in_all585": True,
        "evaluation_row_removed": False,
        "prior_disposition_superseded": "BLOCKED_MATERIAL_GAP",
        "classification": OUTCOME_CLASS,
        "fallback_reason_code": REASON_CODE,
        "human_escalation_cta": HUMAN_ESCALATION_CTA,
        "ui_cta": UI_CTA,
        "knowledge_gap_event": False,
        "matter_information_gap_event": True,
        "fact_dependency": "PROJECT_SPECIFIC_INFORMATION_REQUIRED",
        "substantive_answer_requirement": "CANCELLED_FOR_THIS_ROW",
        "evidence_span_requirement": "CANCELLED_FOR_THIS_ROW",
        "substantive_legal_answer_required": False,
        "evidence_span_required": False,
        "retrieval_evidence_span_required": False,
        "additional_official_source_search_required": False,
        "additional_source_admission_required_for_this_row": False,
        "no_further_source_search_loop_for_this_row": True,
        "missing_information_categories": list(MISSING_INFORMATION_CATEGORIES),
        "missing_information_categories_sha256": (EXPECTED_SAFE_FALLBACK_CATEGORIES_SHA256),
        "deterministic_reply": SAFE_FALLBACK_MESSAGE,
        "deterministic_reply_sha256": EXPECTED_SAFE_FALLBACK_REPLY_SHA256,
        "reply_match_mode": "EXACT_UTF8_STRING",
        "qualification_result_when_contract_satisfied": QUALIFICATION_STATUS,
        "qualification_result_when_contract_violated": FAILURE_STATUS,
        "canonical_contract": contract,
        "canonical_contract_content_sha256": contract["contract_content_sha256"],
        "material_gap_resolved_only_as_safe_fallback_contract": True,
        "material_legal_proposition_claimed_resolved": False,
        "answer_release_eligible": False,
        "phase2a_technical_qualification_only": True,
        "phase2b_authorized": False,
    }
    return {**material, "decision_content_sha256": _sealed(material)}


def _privacy_check_string(value: str, *, field: str) -> None:
    if field in {"file_name", "name"}:
        if value not in _CONTROLLED_ARTIFACT_NAMES:
            raise ValueError("phase2a_safe_fallback_privacy_artifact_name_invalid")
        return
    if field == "root_name":
        if value not in _ALLOWED_ROOT_NAMES:
            raise ValueError("phase2a_safe_fallback_privacy_artifact_name_invalid")
        return

    folded = value.casefold()
    if (
        "agnes" in folded
        or "hltsang" in folded
        or "legalbot-new" in folded
        or str(PROJECT_ROOT).casefold() in folded
        or "file://" in folded
        or value.startswith(("~/", "~\\"))
        or _EMAIL.search(value)
        or _WINDOWS_DRIVE_PATH.search(value)
        or _WINDOWS_UNC_PATH.search(value)
    ):
        raise ValueError("phase2a_safe_fallback_privacy_violation")
    replaced = value
    for name in sorted(_CONTROLLED_ARTIFACT_NAMES, key=len, reverse=True):
        replaced = replaced.replace(name, "<ARTIFACT>")
    if _POSIX_ABSOLUTE_PATH.search(replaced) or _PLAUSIBLE_PERSONAL_FILENAME.search(replaced):
        raise ValueError("phase2a_safe_fallback_privacy_violation")


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
        raise RuntimeError("phase2a_safe_fallback_atomic_noreplace_unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ValueError("phase2a_safe_fallback_output_already_exists")
    raise OSError(error_number, "phase2a_safe_fallback_atomic_publish_failed")


def _ensure_output_path(output_root: Path) -> Path:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_safe_fallback_output_already_exists")
    review = OUTPUT_REVIEW_ROOT.resolve(strict=True)
    parent = output_root.parent.resolve(strict=True)
    resolved = parent / output_root.name
    if not output_root.name or not resolved.is_relative_to(review):
        raise ValueError("phase2a_safe_fallback_output_outside_review_root")
    return resolved


def build_superseding_packet(
    *,
    source_delta_root: Path,
    fca_derivation_root: Path,
    held9_advisory_root: Path,
    fact_fallback_advisory_root: Path,
    echr_recovery_root: Path,
    q53_substitute_root: Path,
    output_root: Path,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    """Create the exact owner packet without applying or executing anything."""

    output = _ensure_output_path(output_root)
    timestamp = created_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("phase2a_safe_fallback_created_at_must_be_aware")
    source_delta = _verify_source_delta(source_delta_root)
    _fca_manifest, fca_derived_bindings = _verify_fca_derivation(
        root=fca_derivation_root,
        source_delta=source_delta,
    )
    held9_advisory = _verify_held9_advisory(held9_advisory_root)
    held9_decisions = _held9_owner_decisions(held9_advisory)
    fact_fallback_advisory = _verify_fact_fallback_advisory(fact_fallback_advisory_root)
    echr_recovery, echr_recovered_bindings = _verify_echr_recovery(echr_recovery_root)
    _q53_substitute, q53_source_binding, q53_row_decisions = _verify_q53_substitute(
        q53_substitute_root
    )
    safe_fallback = _safe_fallback_decision()
    performance_bond_fallback = _performance_bond_safe_fallback_decision()

    packet_material: dict[str, Any] = {
        "schema": ("legalbot.v111.phase2a.source-delta-safe-fallback-owner-packet.v1"),
        "status": STATUS,
        "created_at": timestamp.astimezone(UTC).isoformat(),
        "route": "OWNER_ADOPTED_INTERNAL_PRIVATE_RESEARCH_TOOL",
        "phase_scope": "PHASE2A_ONLY",
        "source_binding_delta": {
            "root_name": SOURCE_DELTA_ROOT_NAME,
            "file_name": SOURCE_DELTA_PACKET_NAME,
            "content_sha256": EXPECTED_SOURCE_DELTA_CONTENT_SHA256,
            "file_sha256": EXPECTED_SOURCE_DELTA_FILE_SHA256,
            "package_content_sha256": EXPECTED_SOURCE_DELTA_PACKAGE_CONTENT_SHA256,
            "package_file_sha256": EXPECTED_SOURCE_DELTA_PACKAGE_FILE_SHA256,
            "prompt_file_sha256": EXPECTED_SOURCE_DELTA_PROMPT_FILE_SHA256,
            "checksums_file_sha256": EXPECTED_SOURCE_DELTA_CHECKSUMS_FILE_SHA256,
            "source_decisions_incorporated_except_explicit_supersessions": True,
            "source_holds_incorporated_without_change": True,
            "raw_json_source_identity_and_provenance_incorporated_without_change": True,
            "raw_json_index_admission_recommendations_superseded": True,
            "raw_json_index_admission_replacement": (
                "ADMIT_ONLY_15_EXACT_CANONICAL_MARKDOWN_DERIVATIVES"
            ),
            "prior_material_hold_disposition_superseded_only_for_row_id": ROW_ID,
        },
        "source_delta_decision_summary_bound": source_delta["decision_summary"],
        "fca_canonical_markdown_derivation": {
            "root_name": FCA_DERIVATION_ROOT_NAME,
            "manifest_file_name": FCA_DERIVATION_MANIFEST_NAME,
            "manifest_content_sha256": (EXPECTED_FCA_DERIVATION_MANIFEST_CONTENT_SHA256),
            "manifest_file_sha256": EXPECTED_FCA_DERIVATION_MANIFEST_FILE_SHA256,
            "package_content_sha256": EXPECTED_FCA_DERIVATION_PACKAGE_CONTENT_SHA256,
            "package_file_sha256": EXPECTED_FCA_DERIVATION_PACKAGE_FILE_SHA256,
            "checksums_file_sha256": EXPECTED_FCA_DERIVATION_CHECKSUMS_FILE_SHA256,
            "derived_representation_count": 15,
            "preserved_provision_count": 312,
            "full_json_object_semantic_equivalence_count": 15,
            "parser_compatibility_pass_count": 15,
            "privacy_pass_count": 15,
            "raw_json_bytes_retained_as_immutable_provenance": True,
            "raw_json_bytes_not_index_admission_representations": True,
            "derived_canonical_markdown_bindings": fca_derived_bindings,
            "all_currentness_and_later_treatment_holds_retained": True,
            "all_five_r7_unresolved_official_holds_retained": True,
            "new_exact_owner_adoption_required": True,
        },
        "held9_surviving_support_advisory": {
            "root_name": HELD9_ADVISORY_ROOT_NAME,
            "file_name": HELD9_ADVISORY_NAME,
            "content_sha256": EXPECTED_HELD9_ADVISORY_CONTENT_SHA256,
            "file_sha256": EXPECTED_HELD9_ADVISORY_FILE_SHA256,
            "package_content_sha256": EXPECTED_HELD9_PACKAGE_CONTENT_SHA256,
            "package_file_sha256": EXPECTED_HELD9_PACKAGE_FILE_SHA256,
            "checksums_file_sha256": EXPECTED_HELD9_CHECKSUMS_FILE_SHA256,
            "full_sealed_advisory": held9_advisory,
            "exact_owner_decisions_requested": held9_decisions,
            "advisory_itself_was_not_an_owner_decision": True,
            "all_row_outcomes_fail_closed": True,
        },
        "fact_only_fallback_coverage_advisory": {
            "root_name": FACT_FALLBACK_ADVISORY_ROOT_NAME,
            "file_name": FACT_FALLBACK_ADVISORY_NAME,
            "content_sha256": EXPECTED_FACT_FALLBACK_ADVISORY_CONTENT_SHA256,
            "file_sha256": EXPECTED_FACT_FALLBACK_ADVISORY_FILE_SHA256,
            "package_content_sha256": EXPECTED_FACT_FALLBACK_PACKAGE_CONTENT_SHA256,
            "package_file_sha256": EXPECTED_FACT_FALLBACK_PACKAGE_FILE_SHA256,
            "checksums_file_sha256": EXPECTED_FACT_FALLBACK_CHECKSUMS_FILE_SHA256,
            "full_sealed_advisory": fact_fallback_advisory,
            "exact_eligible_row_ids": [PERFORMANCE_BOND_ROW_ID, ROW_ID],
            "remaining_583_rows_not_safe_fallback_eligible": True,
            "advisory_itself_was_not_an_owner_decision": True,
        },
        "echr_held_source_recovery": {
            "root_name": ECHR_RECOVERY_ROOT_NAME,
            "manifest_file_name": ECHR_RECOVERY_MANIFEST_NAME,
            "manifest_content_sha256": EXPECTED_ECHR_RECOVERY_MANIFEST_CONTENT_SHA256,
            "manifest_file_sha256": EXPECTED_ECHR_RECOVERY_MANIFEST_FILE_SHA256,
            "package_content_sha256": EXPECTED_ECHR_RECOVERY_PACKAGE_CONTENT_SHA256,
            "package_file_sha256": EXPECTED_ECHR_RECOVERY_PACKAGE_FILE_SHA256,
            "checksums_file_sha256": EXPECTED_ECHR_RECOVERY_CHECKSUMS_FILE_SHA256,
            "exact_new_source_admission_bindings": echr_recovered_bindings,
            "goodwin_existing_quarantine_binding": {
                "carry_mode": "SEALED_REFERENCE_NO_NETWORK_NO_BYTE_COPY",
                "raw_sha256": EXPECTED_ECHR_GOODWIN_RAW_SHA256,
                "record_content_sha256": EXPECTED_ECHR_GOODWIN_RECORD_CONTENT_SHA256,
                "source_manifest_content_sha256": (
                    "c6672a3f227b9a518ac628861bc1bcaf361d9c29968f20c490f27d3f34592145"
                ),
                "source_manifest_file_sha256": (
                    "e7f23bbe8219370f24ae86e3dab7356bab6ad90fc8a405c92ee1b06f8bd74879"
                ),
                "affected_row_ids": ["live60-q51:issue-05"],
                "required_paragraph_count": 11,
                "recommended_owner_outcome": ("ADOPT_EXISTING_EXACT_GOODWIN_QUARANTINE_BINDING"),
                "new_source_admission_required": False,
                "currentness_hold_retained": True,
                "later_treatment_hold_retained": True,
                "answer_release_authorized": False,
            },
            "mutu_pechstein_transport_hold": echr_recovery["holds"][0],
            "no_more_mutu_network_attempts": True,
            "advisory_itself_was_not_an_owner_decision": True,
        },
        "q53_semenya_substitute_advisory": {
            "root_name": Q53_SUBSTITUTE_ROOT_NAME,
            "file_name": Q53_SUBSTITUTE_ADVISORY_NAME,
            "content_sha256": EXPECTED_Q53_SUBSTITUTE_ADVISORY_CONTENT_SHA256,
            "file_sha256": EXPECTED_Q53_SUBSTITUTE_ADVISORY_FILE_SHA256,
            "package_content_sha256": EXPECTED_Q53_SUBSTITUTE_PACKAGE_CONTENT_SHA256,
            "package_file_sha256": EXPECTED_Q53_SUBSTITUTE_PACKAGE_FILE_SHA256,
            "checksums_file_sha256": EXPECTED_Q53_SUBSTITUTE_CHECKSUMS_FILE_SHA256,
            "semenya_source_admission_binding": q53_source_binding,
            "exact_revised_proposition_set_owner_decisions": q53_row_decisions,
            "mutu_historical_claims_explicitly_excluded": True,
            "mutu_network_path_permanently_stopped": True,
            "semenya_not_described_as_disciplinary": True,
            "r57_only_for_current_disciplinary_public_hearing_mechanics": True,
            "currentness_and_later_treatment_holds_retained": True,
            "answer_eligible": False,
            "advisory_itself_was_not_an_owner_decision": True,
        },
        "safe_fallback_decision": safe_fallback,
        "performance_bond_safe_fallback_decision": performance_bond_fallback,
        "decision_precedence": {
            "explicit_supersessions": [
                {
                    "superseded_source_delta_field": "known_all585_material_hold",
                    "superseded_row_id": ROW_ID,
                    "superseded_original_decision_content_sha256": (
                        EXPECTED_PRIOR_HOLD_DECISION_SHA256
                    ),
                    "superseding_decision_content_sha256": safe_fallback["decision_content_sha256"],
                },
                {
                    "superseded_source_delta_field": (
                        "proposed_corrected_source_admissions[*].raw_json_"
                        "representation_for_index_admission"
                    ),
                    "superseded_representation_count": 15,
                    "superseding_fca_derivation_manifest_content_sha256": (
                        EXPECTED_FCA_DERIVATION_MANIFEST_CONTENT_SHA256
                    ),
                    "superseding_representation_count": 15,
                    "raw_json_retained_as_immutable_provenance": True,
                },
                {
                    "superseded_held9_field": (
                        "row_outcomes[live60-q58:issue-09].informal_fallback_contract"
                    ),
                    "superseding_contract_content_sha256": (
                        EXPECTED_PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256
                    ),
                    "all_underlying_legal_release_holds_retained": True,
                },
                {
                    "superseded_held9_gap_row_ids": [
                        "live30-q22:issue-02",
                        "live30-q22:issue-04",
                        "live30-q22:issue-06",
                        "live60-q51:issue-05",
                        "live60-q53:issue-04",
                        "live60-q53:issue-11",
                        "live60-q56:issue-01",
                        "live60-q56:issue-05",
                    ],
                    "superseding_echr_recovery_manifest_content_sha256": (
                        EXPECTED_ECHR_RECOVERY_MANIFEST_CONTENT_SHA256
                    ),
                    "superseding_q53_substitute_advisory_content_sha256": (
                        EXPECTED_Q53_SUBSTITUTE_ADVISORY_CONTENT_SHA256
                    ),
                    "supersession_scope": (
                        "LEGAL_AUTHORITY_REPRESENTATION_GAP_ONLY_EXACT_REVISED_PROPOSITIONS"
                    ),
                    "all_currentness_later_treatment_and_answer_release_holds_retained": True,
                },
            ],
            "all_other_source_delta_decisions_and_holds_unchanged": True,
        },
        "owner_decision_requested": {
            "adopt_exact_source_binding_delta_decisions_and_holds": True,
            "adopt_15_exact_fca_canonical_markdown_derivatives": True,
            "supersede_raw_json_as_index_admission_representation": True,
            "adopt_held9_limited_supported_subsets_as_baseline": True,
            "retain_all_five_held9_legal_rule_release_holds": True,
            "adopt_exact_fact_only_fallback_coverage_advisory": True,
            "adopt_q58_issue09_exact_no_legal_claim_matter_fact_fallback": True,
            "adopt_q58_issue14_exact_strict_fact_only_fallback": True,
            "keep_both_fallback_rows_in_all585": True,
            "admit_exact_klima_and_big_brother_recovered_representations": True,
            "adopt_existing_exact_goodwin_quarantine_binding": True,
            "admit_exact_semenya_representations": True,
            "adopt_q53_exact_revised_proposition_sets": True,
            "exclude_all_superseded_mutu_historical_claims": True,
            "retain_all_currentness_later_treatment_and_answer_release_holds": True,
        },
        "single_remaining_phase2a_execution_authority": {
            "authority_origin_owner_packet_content_sha256": (
                EXPECTED_ORIGINAL_OWNER_PACKET_CONTENT_SHA256
            ),
            "authority_origin_owner_receipt_content_sha256": (
                EXPECTED_ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256
            ),
            "authority_preexisted_this_packet": True,
            "authority_consumed_before_this_packet": False,
            "new_or_additional_execution_authority_created_by_this_packet": False,
            "total_remaining_execution_chain_count": 1,
            "execution_chain_after_exact_owner_adoption": [
                "APPLY_EXACT_OWNER_DECISIONS",
                "MATERIALIZE_ONLY_EXACT_ADOPTED_SOURCE_REPRESENTATIONS",
                "RUN_ONE_COMPLETE_SOURCE_SCAN",
                "BUILD_AND_EMBED_ONE_NON_ACTIVE_ANSWER_INELIGIBLE_SUCCESSOR",
                "RUN_ONE_RETRIEVAL_REATTESTATION",
                "RUN_ONE_ALL585_TECHNICAL_QUALIFICATION",
            ],
            "second_scan_build_or_embedding_authority_created": False,
            "successor_must_remain_non_active": True,
            "successor_must_remain_answer_ineligible": True,
        },
        "qualification_effect_after_owner_adoption_and_technical_application": {
            "row_can_pass_only_as_safe_fallback": True,
            "row_pass_does_not_claim_substantive_legal_answer": True,
            "row_pass_does_not_claim_material_legal_proposition_resolved": True,
            "all585_success_requires_every_other_row_to_pass": True,
            "successful_phase2a_package_not_created_by_this_packet": True,
            "eight_held9_legal_authority_representation_gaps_have_exact_superseding_support_sets": True,
            "q58_issue09_can_pass_only_as_no_legal_claim_fallback": True,
            "q58_issue14_can_pass_only_as_strict_fact_only_fallback": True,
            "technical_success_not_predeclared": True,
            "all585_must_stop_if_any_retained_gap_remains": True,
        },
        "approval_does_not_authorize": [
            "ANSWER_MODEL_OR_ANSWER_RELEASE",
            "PHASE2B",
            "DEVELOPMENT30",
            "VALIDATION30",
            "OWNER_CERTIFICATION60",
            "PROMOTION",
            "ACTIVE_OR_PREVIOUS_POINTER_WRITES",
            "LIVE_ACTIVATION",
            "TRAINING_EXPORT",
        ],
        "packet_builder_effect": "CREATE_ONLY_NO_EXECUTION",
        **_NO_EXECUTION_FLAGS,
    }
    packet = {
        **packet_material,
        "artifact_content_sha256": _sealed(packet_material),
    }
    packet_raw = _pretty_json(packet)
    packet_file_sha256 = _sha256(packet_raw)

    prompt = f"""PHASE-2A EXACT FINAL REMEDIATION OWNER APPROVAL

Review the complete machine-readable packet before using this text:

- Packet: {PACKET_NAME}
- Exact combined packet content SHA-256: {packet["artifact_content_sha256"]}
- Exact combined packet file SHA-256: {packet_file_sha256}
- Bound source-binding delta content SHA-256: {EXPECTED_SOURCE_DELTA_CONTENT_SHA256}
- Bound FCA canonical-Markdown manifest content SHA-256: {EXPECTED_FCA_DERIVATION_MANIFEST_CONTENT_SHA256}
- Bound held-nine advisory content SHA-256: {EXPECTED_HELD9_ADVISORY_CONTENT_SHA256}
- Bound exact 585-row fallback coverage advisory content SHA-256: {EXPECTED_FACT_FALLBACK_ADVISORY_CONTENT_SHA256}
- Bound ECHR recovery manifest content SHA-256: {EXPECTED_ECHR_RECOVERY_MANIFEST_CONTENT_SHA256}
- Bound q53 Semenya substitute advisory content SHA-256: {EXPECTED_Q53_SUBSTITUTE_ADVISORY_CONTENT_SHA256}
- Project-rescue fallback contract content SHA-256: {EXPECTED_SAFE_FALLBACK_CONTRACT_CONTENT_SHA256}
- Performance-bond no-legal-claim fallback contract content SHA-256: {EXPECTED_PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256}

APPROVAL TEXT

I approve exact Phase-2A final remediation owner packet content SHA-256
`{packet["artifact_content_sha256"]}` and every recommendation and retained hold it contains.

I adopt every source decision and retained hold bound by source-binding delta packet `{EXPECTED_SOURCE_DELTA_CONTENT_SHA256}`, subject only to the explicit supersessions in this combined packet. For the 15 FCA representations, the raw JSON remains immutable provenance but is not the index-admission representation; I admit only the 15 exact parser-compatible canonical-Markdown derivatives bound by manifest `{EXPECTED_FCA_DERIVATION_MANIFEST_CONTENT_SHA256}`.

I adopt fallback coverage advisory `{EXPECTED_FACT_FALLBACK_ADVISORY_CONTENT_SHA256}` and only its exact two eligible rows. `{ROW_ID}` remains in all-585 and may pass only under exact contract `{EXPECTED_SAFE_FALLBACK_CONTRACT_CONTENT_SHA256}`. `{PERFORMANCE_BOND_ROW_ID}` remains in all-585 and may pass only under exact no-legal-claim contract `{EXPECTED_PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256}`. Each must return its exact byte-for-byte insufficiency response, request every listed document or fact, emit `knowledge_gap_event=false` and `matter_information_gap_event=true`, and offer qualified human legal review. Neither may release a legal rule, advice, citation, EvidenceSpan, source binding or answer-model output. No other row is fallback-eligible.

I adopt the held-nine advisory `{EXPECTED_HELD9_ADVISORY_CONTENT_SHA256}` as the fail-closed baseline, then adopt only the exact superseding source sets in ECHR recovery manifest `{EXPECTED_ECHR_RECOVERY_MANIFEST_CONTENT_SHA256}` and q53 Semenya advisory `{EXPECTED_Q53_SUBSTITUTE_ADVISORY_CONTENT_SHA256}`. I admit the exact KlimaSeniorinnen and Big Brother Watch raw/canonical representations, adopt the exact existing Goodwin quarantine binding, admit the exact Semenya raw/canonical representations, and adopt the exact revised proposition sets and locators listed for the eight affected rows. The unavailable Mutu/Pechstein representation, its historical CAS-independence and Pechstein public-hearing-result claims, and every other excluded component remain excluded. Semenya must not be described as a disciplinary case; R57 alone supplies the listed current disciplinary public-hearing mechanics. All currentness, later-treatment, citation, EvidenceSpan and answer-release holds remain. The Mutu network path remains permanently stopped, and the held Ali Riza source is not required or retried.

I confirm that original owner-adoption receipt `{EXPECTED_ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256}` has one total unspent Phase-2A execution chain. After this exact combined packet is adopted, Codex may use that one existing chain to apply these exact decisions, materialize only the exact adopted representations, run one complete source scan, build and embed one non-ACTIVE and answer-ineligible successor, run one retrieval re-attestation, and run one all-585 technical qualification. This does not create a second or additional scan, build, embedding, retrieval or qualification authority.

The packet and its builder have not themselves applied a decision, admitted or materialized a source, scanned, indexed, embedded, built or qualified anything. Technical success is not predeclared: if retrieval re-attestation or all-585 finds any material gap, unresolved owner decision or contract violation, the workflow must stop and report it. This approval does not authorize an answer-model run or answer release, Phase 2B, Development 30, Validation 30, Owner Certification 60, promotion, ACTIVE/PREVIOUS writes, live activation or training export.

Owner typed name:
Decision date:
"""
    prompt_raw = prompt.encode("utf-8")

    package_material: dict[str, Any] = {
        "schema": ("legalbot.v111.phase2a.source-delta-safe-fallback-owner-package.v1"),
        "status": STATUS,
        "packet_content_sha256": packet["artifact_content_sha256"],
        "source_binding_delta_content_sha256": EXPECTED_SOURCE_DELTA_CONTENT_SHA256,
        "fca_derivation_manifest_content_sha256": (EXPECTED_FCA_DERIVATION_MANIFEST_CONTENT_SHA256),
        "held9_advisory_content_sha256": EXPECTED_HELD9_ADVISORY_CONTENT_SHA256,
        "fact_fallback_advisory_content_sha256": (EXPECTED_FACT_FALLBACK_ADVISORY_CONTENT_SHA256),
        "echr_recovery_manifest_content_sha256": (EXPECTED_ECHR_RECOVERY_MANIFEST_CONTENT_SHA256),
        "q53_substitute_advisory_content_sha256": (EXPECTED_Q53_SUBSTITUTE_ADVISORY_CONTENT_SHA256),
        "canonical_safe_fallback_contract_content_sha256": (
            EXPECTED_SAFE_FALLBACK_CONTRACT_CONTENT_SHA256
        ),
        "safe_fallback_decision_content_sha256": safe_fallback["decision_content_sha256"],
        "performance_bond_contract_content_sha256": (
            EXPECTED_PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256
        ),
        "performance_bond_decision_content_sha256": performance_bond_fallback[
            "decision_content_sha256"
        ],
        "artifacts": [
            {
                "name": PACKET_NAME,
                "content_sha256": packet["artifact_content_sha256"],
                "file_sha256": packet_file_sha256,
            },
            {"name": PROMPT_NAME, "file_sha256": _sha256(prompt_raw)},
        ],
        "new_exact_owner_adoption_required": True,
        "packet_builder_effect": "CREATE_ONLY_NO_EXECUTION",
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
        "source_binding_delta_content_sha256": EXPECTED_SOURCE_DELTA_CONTENT_SHA256,
        "fca_derivation_manifest_content_sha256": (EXPECTED_FCA_DERIVATION_MANIFEST_CONTENT_SHA256),
        "held9_advisory_content_sha256": EXPECTED_HELD9_ADVISORY_CONTENT_SHA256,
        "fact_fallback_advisory_content_sha256": (EXPECTED_FACT_FALLBACK_ADVISORY_CONTENT_SHA256),
        "echr_recovery_manifest_content_sha256": (EXPECTED_ECHR_RECOVERY_MANIFEST_CONTENT_SHA256),
        "q53_substitute_advisory_content_sha256": (EXPECTED_Q53_SUBSTITUTE_ADVISORY_CONTENT_SHA256),
        "safe_fallback_decision_content_sha256": safe_fallback["decision_content_sha256"],
        "performance_bond_decision_content_sha256": performance_bond_fallback[
            "decision_content_sha256"
        ],
        "fallback_row_ids": [PERFORMANCE_BOND_ROW_ID, ROW_ID],
        "fallback_rows_retained_in_all585": True,
        "row_id": ROW_ID,
        "row_retained_in_all585": True,
        "source_admitted": False,
        "source_scan_run": False,
        "index_built": False,
        "embedding_run": False,
        "retrieval_reattestation_run": False,
        "all585_qualification_run": False,
        "phase2b_run": False,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-delta-root", type=Path, default=SOURCE_DELTA_ROOT)
    parser.add_argument("--fca-derivation-root", type=Path, default=FCA_DERIVATION_ROOT)
    parser.add_argument("--held9-advisory-root", type=Path, default=HELD9_ADVISORY_ROOT)
    parser.add_argument(
        "--fact-fallback-advisory-root",
        type=Path,
        default=FACT_FALLBACK_ADVISORY_ROOT,
    )
    parser.add_argument("--echr-recovery-root", type=Path, default=ECHR_RECOVERY_ROOT)
    parser.add_argument("--q53-substitute-root", type=Path, default=Q53_SUBSTITUTE_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    result = build_superseding_packet(
        source_delta_root=args.source_delta_root.resolve(strict=False),
        fca_derivation_root=args.fca_derivation_root.resolve(strict=False),
        held9_advisory_root=args.held9_advisory_root.resolve(strict=False),
        fact_fallback_advisory_root=args.fact_fallback_advisory_root.resolve(strict=False),
        echr_recovery_root=args.echr_recovery_root.resolve(strict=False),
        q53_substitute_root=args.q53_substitute_root.resolve(strict=False),
        output_root=args.output_root.resolve(strict=False),
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
