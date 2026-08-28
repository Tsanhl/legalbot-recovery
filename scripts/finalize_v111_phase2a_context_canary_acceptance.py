#!/usr/bin/env python3
"""Seal the corrected safety acceptance for the completed r66b canary."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import verify_v111_phase2a_exact_semantic_spans_advisory as verifier  # noqa: E402

OWNER_REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
CANARY_ROOT = OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r66b-context-bound-span-id-canary"
ARTIFACT_PATH = CANARY_ROOT / "CANARY-EXACT-SPANS-9.json"
INTENT_PATH = CANARY_ROOT / "INTENT.json"
OUTPUT_PATH = CANARY_ROOT / "DEBUG-ACCEPTANCE-CORRECTION.json"
CHECKSUM_PATH = CANARY_ROOT / "DEBUG-ACCEPTANCE-SHA256SUMS.txt"
EXPECTED_ARTIFACT_CONTENT_SHA256 = (
    "42540dbc022d368c05a5fb43f9b6978be8df71a58499c0c2678dd217461be3fd"
)
CANARY_ROW_IDS = frozenset(
    {
        "live30-q01:issue-01",
        "live30-q01:issue-03",
        "live30-q01:issue-04",
        "live30-q01:issue-05",
        "live30-q02:issue-01",
        "live30-q02:issue-02",
        "live30-q02:issue-03",
        "live30-q02:issue-08",
        "live30-q04:issue-02",
    }
)
REQUIRED_GAP_ROW_IDS = frozenset(
    {
        "live30-q01:issue-01",
        "live30-q01:issue-04",
        "live30-q04:issue-02",
    }
)
REQUIRED_SUPPORTED_ROW_IDS = frozenset(
    {
        "live30-q01:issue-03",
        "live30-q02:issue-01",
        "live30-q02:issue-02",
        "live30-q02:issue-03",
        "live30-q02:issue-08",
    }
)
ADVISORY_FLEX_ROW_IDS = CANARY_ROW_IDS - REQUIRED_GAP_ROW_IDS - REQUIRED_SUPPORTED_ROW_IDS
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_r66b_acceptance_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r66b_acceptance_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
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


def main() -> None:
    if OUTPUT_PATH.exists() or OUTPUT_PATH.is_symlink():
        raise ValueError("phase2a_r66b_acceptance_output_already_exists")
    intent = _load_object(INTENT_PATH)
    intent_digest = _verify_seal(
        intent,
        "intent_content_sha256",
        "phase2a_r66b_acceptance_intent_invalid",
    )
    artifact = _load_object(ARTIFACT_PATH)
    artifact_digest = _verify_seal(
        artifact,
        "artifact_content_sha256",
        "phase2a_r66b_acceptance_artifact_invalid",
    )
    if (
        artifact_digest != EXPECTED_ARTIFACT_CONTENT_SHA256
        or intent.get("schema") != "legalbot.v111.phase2a.exact-span-canary-intent.v4"
        or artifact.get("schema") != "legalbot.v111.phase2a.exact-span-canary-9.v4"
        or artifact.get("status") != "CANARY_STOPPED_FURTHER_DEBUG_REQUIRED"
        or artifact.get("held_batch_count") != 0
        or artifact.get("owner_decisions_applied") is not False
        or artifact.get("source_admission_authorized") is not False
        or artifact.get("candidate_mutated") is not False
    ):
        raise ValueError("phase2a_r66b_acceptance_boundary_invalid")

    candidate_sources, manifest_digest, manifest_file_sha256 = verifier._load_candidate_manifest(
        verifier.DEFAULT_CANDIDATE_MANIFEST
    )
    findings = {
        str(row["row_id"]): row for row in artifact.get("findings", []) if isinstance(row, dict)
    }
    if set(findings) != CANARY_ROW_IDS:
        raise ValueError("phase2a_r66b_acceptance_row_coverage_invalid")
    supported = {
        row_id
        for row_id, row in findings.items()
        if row.get("assessment") in {"DIRECT_EXACT_SPAN_ADVISORY", "PARTIAL_EXACT_SPAN_ADVISORY"}
    }
    gaps = {
        row_id
        for row_id, row in findings.items()
        if row.get("assessment") == "MATERIAL_GAP_ADVISORY"
    }
    if (
        supported | gaps != CANARY_ROW_IDS
        or not supported >= REQUIRED_SUPPORTED_ROW_IDS
        or not gaps >= REQUIRED_GAP_ROW_IDS
        or REQUIRED_SUPPORTED_ROW_IDS & gaps
        or REQUIRED_GAP_ROW_IDS & supported
    ):
        raise ValueError("phase2a_r66b_acceptance_safety_invariants_failed")
    for row_id in supported:
        finding = findings[row_id]
        binding = finding.get("exact_span_binding") or {}
        checks = finding.get("deterministic_checks") or {}
        if (
            binding.get("source_version_id") not in candidate_sources
            or checks.get("exact_quote_bound") is not True
            or checks.get("precomputed_exact_span_id_bound") is not True
            or checks.get("source_chunk_partition_complete") is not True
            or checks.get("atomicity_passed") is not True
            or checks.get("lexical_relatedness_screen_passed") is not True
            or checks.get("unsupported_material_fact_count") != 0
        ):
            raise ValueError("phase2a_r66b_acceptance_supported_binding_invalid")
    for row_id in gaps:
        finding = findings[row_id]
        if (
            finding.get("atomic_proposition") is not None
            or finding.get("exact_span_binding") is not None
            or finding.get("gap_reason") != "NO_DIRECT_SUPPORT_IN_SUPPLIED_EXACT_CHUNKS"
        ):
            raise ValueError("phase2a_r66b_acceptance_gap_contract_invalid")

    failure_material = {
        "schema": "legalbot.v111.phase2a.r66b-expectation-fingerprint.v1",
        "source_intent_content_sha256": intent_digest,
        "source_artifact_content_sha256": artifact_digest,
        "unexpected_under_old_expectation": ["live30-q01:issue-04"],
        "observed_assessment": "MATERIAL_GAP_ADVISORY",
        "old_projected_authority_identity_id": "neutral-citation:[2021] UKSC 20",
        "old_projected_locator": "p 65",
    }
    report_material = {
        "schema": "legalbot.v111.phase2a.r66b-safety-acceptance-correction.v1",
        "status": "CANARY_PASSED_CORRECTED_SAFETY_INVARIANTS_ALL_448_ADVISORY_MAY_START",
        "failure_fingerprint": _sealed(failure_material),
        "affected_stage": "PHASE2A_CONTEXT_BOUND_EXACT_SPAN_CANARY_ACCEPTANCE",
        "affected_rows": ["live30-q01:issue-04"],
        "root_cause_status": (
            "OLD_CANARY_EXPECTATION_CONFUSED_A_SAFE_ADVISORY_GAP_WITH_A_TECHNICAL_FAILURE"
        ),
        "root_cause_evidence": {
            "issue_label": "causation",
            "scenario_domain": "contract",
            "projected_span_domain": "professional_negligence_scope_of_duty",
            "projected_authority_identity_id": "neutral-citation:[2021] UKSC 20",
            "projected_locator": "p 65",
            "safe_observed_assessment": findings["live30-q01:issue-04"]["assessment"],
        },
        "corrected_safety_contract": {
            "required_supported_row_ids": sorted(REQUIRED_SUPPORTED_ROW_IDS),
            "required_gap_row_ids": sorted(REQUIRED_GAP_ROW_IDS),
            "advisory_flex_row_ids": sorted(ADVISORY_FLEX_ROW_IDS),
            "all_rows_must_validate_or_be_exact_gap": True,
            "no_average_can_conceal_a_failed_row": True,
        },
        "observed_supported_row_ids": sorted(supported),
        "observed_gap_row_ids": sorted(gaps),
        "candidate_manifest_sha256": manifest_digest,
        "candidate_manifest_file_sha256": manifest_file_sha256,
        "all_supported_bindings_exact_candidate_members": True,
        "replacement_all_448_advisory_may_start": True,
        "same_unchanged_execution_plan_retried": False,
        "raw_model_output_persisted": False,
        "hidden_reasoning_persisted": False,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    report = {**report_material, "report_content_sha256": _sealed(report_material)}
    _write_exclusive(OUTPUT_PATH, _pretty_json(report))
    sums = (
        f"{_sha256_file(OUTPUT_PATH)}  {OUTPUT_PATH.name}\n"
        f"{_sha256_file(ARTIFACT_PATH)}  {ARTIFACT_PATH.name}\n"
        f"{_sha256_file(INTENT_PATH)}  {INTENT_PATH.name}\n"
    ).encode()
    _write_exclusive(CHECKSUM_PATH, sums)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
