#!/usr/bin/env python3
"""Seal the r66 canary expectation and omitted-context root-cause analysis."""

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

OWNER_REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
CANARY_ROOT = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r66-candidate-bound-span-id-canary"
)
CASES_PATH = (
    PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1/cases.jsonl"
)
ARTIFACT_PATH = CANARY_ROOT / "CANARY-EXACT-SPANS-9.json"
INTENT_PATH = CANARY_ROOT / "INTENT.json"
OUTPUT_PATH = CANARY_ROOT / "DEBUG-CORRECTION.json"
CHECKSUM_PATH = CANARY_ROOT / "DEBUG-SHA256SUMS.txt"
AFFECTED_ROW_ID = "live30-q01:issue-01"
EXPECTED_CONTAMINATION_GAP_ROW_ID = "live30-q04:issue-02"
EXPECTED_OLD_SOURCE_VERSION_ID = (
    "source-version-0aedf4e4df18f61476e593b497c940151fc56324"
)
EXPECTED_OLD_AUTHORITY_ID = "ukpga:1977:50"
EXPECTED_CASES_FILE_SHA256 = (
    "78a738afd920ff840dcedeb0fd3fd5ca81035f499a0630d351d49e7c6cd3777a"
)
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
        raise ValueError("phase2a_r66_debug_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r66_debug_input_must_be_object")
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


def _case() -> dict[str, Any]:
    if _sha256_file(CASES_PATH) != EXPECTED_CASES_FILE_SHA256:
        raise ValueError("phase2a_r66_debug_cases_identity_invalid")
    for line in CASES_PATH.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if isinstance(value, dict) and value.get("case_id") == "live30-q01":
            return value
    raise ValueError("phase2a_r66_debug_case_missing")


def main() -> None:
    if OUTPUT_PATH.exists() or OUTPUT_PATH.is_symlink():
        raise ValueError("phase2a_r66_debug_output_already_exists")
    intent = _load_object(INTENT_PATH)
    intent_digest = _verify_seal(
        intent,
        "intent_content_sha256",
        "phase2a_r66_debug_intent_invalid",
    )
    artifact = _load_object(ARTIFACT_PATH)
    artifact_digest = _verify_seal(
        artifact,
        "artifact_content_sha256",
        "phase2a_r66_debug_artifact_invalid",
    )
    findings = {
        str(row["row_id"]): row
        for row in artifact.get("findings", [])
        if isinstance(row, dict)
    }
    affected = findings.get(AFFECTED_ROW_ID) or {}
    contamination = findings.get(EXPECTED_CONTAMINATION_GAP_ROW_ID) or {}
    if (
        intent.get("schema")
        != "legalbot.v111.phase2a.exact-span-canary-intent.v3"
        or artifact.get("status") != "CANARY_STOPPED_FURTHER_DEBUG_REQUIRED"
        or artifact.get("replacement_all_448_advisory_may_start") is not False
        or affected.get("assessment") != "MATERIAL_GAP_ADVISORY"
        or contamination.get("assessment") != "MATERIAL_GAP_ADVISORY"
        or artifact.get("held_batch_count") != 0
    ):
        raise ValueError("phase2a_r66_debug_failure_state_changed")
    case = _case()
    scenario = str(case.get("question") or "")
    if (
        case.get("question_sha256") != _sha256(scenario.encode("utf-8"))
        or "bespoke AI recruitment platform" not in scenario
        or "time is of the essence" not in scenario
    ):
        raise ValueError("phase2a_r66_debug_scenario_identity_invalid")

    checkpoint = _load_object(next((CANARY_ROOT / "checkpoints").glob("001-*.json")))
    _verify_seal(
        checkpoint,
        "checkpoint_content_sha256",
        "phase2a_r66_debug_checkpoint_invalid",
    )
    if checkpoint.get("input_content_sha256") is None:
        raise ValueError("phase2a_r66_debug_input_identity_missing")

    failure_material = {
        "schema": "legalbot.v111.phase2a.r66-canary-expectation-fingerprint.v1",
        "source_intent_content_sha256": intent_digest,
        "source_artifact_content_sha256": artifact_digest,
        "affected_row_id": AFFECTED_ROW_ID,
        "unsafe_expected_assessment": "DIRECT_OR_PARTIAL_EXACT_SPAN_ADVISORY",
        "observed_fail_closed_assessment": "MATERIAL_GAP_ADVISORY",
        "scenario_text_was_supplied": False,
        "old_projected_source_version_id": EXPECTED_OLD_SOURCE_VERSION_ID,
        "old_projected_authority_identity_id": EXPECTED_OLD_AUTHORITY_ID,
    }
    report_material = {
        "schema": "legalbot.v111.phase2a.r66-canary-debug-correction.v1",
        "status": "ROOT_CAUSE_CONFIRMED_REVISED_CONTEXT_BOUND_CANARY_REQUIRED",
        "failure_fingerprint": _sealed(failure_material),
        "affected_stage": "PHASE2A_CANDIDATE_BOUND_EXACT_SPAN_CANARY",
        "affected_rows": [AFFECTED_ROW_ID],
        "completed_work": {
            "source_identity_contamination_gap_passed": True,
            "valid_supported_findings": artifact.get("supported_row_count"),
            "held_batch_count": artifact.get("held_batch_count"),
            "malformed_output_diagnostics_persisted": 1,
            "single_targeted_repair_succeeded": True,
        },
        "root_cause_status": (
            "CANARY_EXPECTATION_WAS_TOO_PERMISSIVE_AND_THE_EXACT_SPAN_"
            "REVIEW_INPUT_OMITTED_SCENARIO_CONTEXT_NEEDED_TO_DISAMBIGUATE_"
            "THE_TERSE_BREACH_LABEL"
        ),
        "root_cause_evidence": {
            "issue_label": "breach",
            "scenario_content_sha256": case["question_sha256"],
            "old_projected_authority_identity_id": EXPECTED_OLD_AUTHORITY_ID,
            "old_projected_source_version_id": EXPECTED_OLD_SOURCE_VERSION_ID,
            "old_projected_locator": "section 25",
            "old_span_scope": (
                "SCOTLAND_PART_II_EXCLUSION_OR_RESTRICTION_OF_LIABILITY_"
                "DEFINITION_NOT_THE_GENERAL_BREACH_RULE_REQUIRED_BY_THE_SCENARIO"
            ),
            "observed_fail_closed_assessment": affected["assessment"],
        },
        "required_change_in_execution_plan": [
            "Supply the immutable case scenario to the advisory verifier solely to disambiguate issue scope; continue prohibiting answers and application.",
            "Prefer the scenario-aware upstream authority-plan selection over issue-label-only global recovery when both exact candidate members exist.",
            "Treat this row as an expected safe GAP in the revised canary unless directly applicable candidate evidence is supplied.",
            "Run a new append-only canary revision before the replacement all-448 pass.",
        ],
        "same_unchanged_execution_plan_retried": False,
        "new_revision_required": True,
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
