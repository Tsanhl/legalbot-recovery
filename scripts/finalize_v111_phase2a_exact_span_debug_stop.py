#!/usr/bin/env python3
"""Seal the intentionally stopped r52 exact-span advisory run.

The r52 process is append-only and was stopped after its completed checkpoints
showed a systemic evidence-planning/prompt problem.  This command preserves
that partial work and records the root-cause change required before a new
revision.  It never converts advisory findings into owner decisions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OWNER_REVIEW_ROOT = PROJECT_ROOT / "data" / "evaluations" / "phase2a-owner-review"
DEFAULT_PARTIAL_ROOT = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r52-exact-semantic-span-advisory"
)
DEFAULT_LOCATORS = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r51c-context-safe-locator-resolution"
    / "DETERMINISTIC-LOCATOR-RESOLUTION-448.json"
)

EXPECTED_COMPLETED_BATCHES = 6
EXPECTED_COMPLETED_ROWS = 12
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
        raise ValueError("phase2a_debug_stop_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_debug_stop_input_must_be_object")
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


def finalize_debug_stop(*, partial_root: Path, locators_path: Path) -> dict[str, Any]:
    """Record the exact stopped state and root-cause evidence create-only."""

    final_path = partial_root / "ADVISORY-EXACT-SEMANTIC-SPANS-448.json"
    if final_path.exists() or final_path.is_symlink():
        raise ValueError("phase2a_debug_stop_run_already_finalized")
    report_path = partial_root / "DEBUG-STOP-REPORT.json"
    if report_path.exists() or report_path.is_symlink():
        raise ValueError("phase2a_debug_stop_report_already_exists")

    intent = _load_object(partial_root / "INTENT.json")
    intent_sha256 = _verify_seal(
        intent, "intent_content_sha256", "phase2a_debug_stop_intent_seal_invalid"
    )
    if (
        intent.get("schema") != "legalbot.v111.phase2a.exact-span-intent.v1"
        or intent.get("issue_count") != 448
        or intent.get("owner_decisions_applied") is not False
        or intent.get("source_admission_authorized") is not False
        or intent.get("candidate_mutated") is not False
        or intent.get("phase2b_authorized") is not False
        or intent.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_debug_stop_intent_boundary_invalid")

    checkpoints: list[dict[str, Any]] = []
    checkpoint_files = sorted((partial_root / "checkpoints").glob("*.json"))
    for path in checkpoint_files:
        value = _load_object(path)
        if value.get("schema") != "legalbot.v111.phase2a.exact-span-checkpoint.v1":
            raise ValueError("phase2a_debug_stop_checkpoint_schema_invalid")
        _verify_seal(
            value,
            "checkpoint_content_sha256",
            "phase2a_debug_stop_checkpoint_seal_invalid",
        )
        checkpoints.append(value)
    ordinals = [int(item.get("batch_ordinal") or 0) for item in checkpoints]
    findings = [
        finding
        for checkpoint in checkpoints
        for finding in checkpoint.get("findings", [])
        if isinstance(finding, dict)
    ]
    if (
        len(checkpoints) != EXPECTED_COMPLETED_BATCHES
        or ordinals != list(range(1, EXPECTED_COMPLETED_BATCHES + 1))
        or len(findings) != EXPECTED_COMPLETED_ROWS
    ):
        raise ValueError("phase2a_debug_stop_checkpoint_fingerprint_changed")

    diagnostics = sorted((partial_root / "diagnostics").glob("*.json"))
    if diagnostics:
        raise ValueError("phase2a_debug_stop_unexpected_rejected_attempts")
    findings_by_row = {str(item.get("row_id") or ""): item for item in findings}
    if len(findings_by_row) != EXPECTED_COMPLETED_ROWS:
        raise ValueError("phase2a_debug_stop_duplicate_finding")

    locators = _load_object(locators_path)
    locator_sha256 = _verify_seal(
        locators,
        "artifact_content_sha256",
        "phase2a_debug_stop_locator_seal_invalid",
    )
    if locator_sha256 != intent.get("source_locator_content_sha256"):
        raise ValueError("phase2a_debug_stop_locator_identity_mismatch")
    locator_by_row = {
        str(item.get("row_id") or ""): item
        for item in locators.get("records", [])
        if isinstance(item, dict)
    }

    quality_row = locator_by_row.get("live30-q02:issue-01")
    misrep_row = locator_by_row.get("live30-q02:issue-08")
    if quality_row is None or misrep_row is None:
        raise ValueError("phase2a_debug_stop_root_cause_rows_missing")
    quality_selections = quality_row.get("resolved_selections")
    misrep_selections = misrep_row.get("resolved_selections")
    if not isinstance(quality_selections, list) or not isinstance(misrep_selections, list):
        raise ValueError("phase2a_debug_stop_root_cause_selections_invalid")
    wrong_quality_locator = any(
        item.get("authority_identity_id") == "ukpga:2015:15"
        and item.get("canonical_locator") == "section 29"
        for item in quality_selections
        if isinstance(item, dict)
    )
    over_bound_quality_locator = any(
        item.get("authority_identity_id") == "ukpga:1979:54"
        and item.get("canonical_locator") == "section 14"
        and item.get("resolution_status")
        == "LOCATOR_AMBIGUOUS_EXCEEDS_DETERMINISTIC_BOUND"
        for item in quality_selections
        if isinstance(item, dict)
    )
    direct_misrep_text_supplied = any(
        item.get("authority_identity_id") == "ukpga:1967:7"
        and item.get("canonical_locator") == "section 2"
        and bool(item.get("exact_chunks"))
        for item in misrep_selections
        if isinstance(item, dict)
    )
    if not (wrong_quality_locator and over_bound_quality_locator and direct_misrep_text_supplied):
        raise ValueError("phase2a_debug_stop_root_cause_fingerprint_changed")
    if any(
        findings_by_row[row_id].get("assessment") != "MATERIAL_GAP_ADVISORY"
        for row_id in ("live30-q02:issue-01", "live30-q02:issue-08")
    ):
        raise ValueError("phase2a_debug_stop_advisory_pattern_changed")

    counts = Counter(str(item.get("assessment") or "") for item in findings)
    fingerprint_material = {
        "schema": "legalbot.v111.phase2a.exact-span-systemic-failure-fingerprint.v1",
        "source_intent_content_sha256": intent_sha256,
        "source_locator_content_sha256": locator_sha256,
        "completed_batch_ordinals": ordinals,
        "assessment_counts": dict(sorted(counts.items())),
        "root_cause_codes": [
            "UPSTREAM_WRONG_LOCATOR_FOR_NAMED_ISSUE",
            "OVER_BOUND_LOCATOR_REJECTED_WITHOUT_RANKED_EXACT_CHUNK_PROJECTION",
            "ADVISORY_PROMPT_REJECTED_DIRECT_GENERAL_RULE_AS_NOT_COMPLETE_CONTROLLING_SUPPORT",
        ],
    }
    failure_fingerprint = _sealed(fingerprint_material)
    report_material = {
        "schema": "legalbot.v111.phase2a.exact-span-debug-stop-report.v1",
        "status": "STOPPED_FOR_ROOT_CAUSE_DEBUG_BEFORE_NEW_REVISION",
        "failure_fingerprint": failure_fingerprint,
        "affected_stage": "PHASE2A_EXACT_SEMANTIC_SPAN_ADVISORY",
        "affected_rows": "ALL_448_REQUIRE_REGENERATED_TARGETED_EVIDENCE_INPUTS",
        "completed_work": {
            "completed_batch_count": len(checkpoints),
            "completed_row_count": len(findings),
            "completed_row_ids": sorted(findings_by_row),
            "assessment_counts": dict(sorted(counts.items())),
            "checkpoint_content_sha256s": [
                str(item["checkpoint_content_sha256"]) for item in checkpoints
            ],
            "rejected_attempt_diagnostic_count": 0,
        },
        "root_cause_status": "CONFIRMED_SYSTEMIC_UPSTREAM_AND_PROMPT_DEFECT",
        "root_cause_evidence": [
            {
                "row_id": "live30-q02:issue-01",
                "issue": "satisfactory quality",
                "observation": (
                    "The packet supplied Consumer Rights Act 2015 section 29 "
                    "(risk) and rejected Sale of Goods Act 1979 section 14 as over-bound."
                ),
            },
            {
                "row_id": "live30-q02:issue-08",
                "issue": "misrepresentation",
                "observation": (
                    "An exact Misrepresentation Act 1967 section 2 span was supplied, "
                    "but the advisory prompt still returned a material gap."
                ),
            },
        ],
        "required_change_in_execution_plan": [
            "Build a read-only global issue-label-first authority recovery over target-date sources.",
            "Project whole exact chunks with explicit omitted-set digests when a locator exceeds the context bound.",
            "Clarify that a source-stated general governing rule may be direct support without completing scenario application.",
            "Run a bounded canary on the confirmed defect rows before starting the replacement all-448 pass.",
        ],
        "old_revision_resume_forbidden": True,
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
    report_raw = _pretty_json(report)
    outcome_raw = (
        "PHASE 2A r52 ADVISORY PASS SAFELY STOPPED FOR ROOT-CAUSE DEBUG. "
        "NO OWNER DECISION, SOURCE ADMISSION, CANDIDATE CHANGE, PHASE 2B, OR "
        "DEVELOPMENT 30 AUTHORIZATION OCCURRED.\n"
    ).encode()
    _write_exclusive(report_path, report_raw)
    _write_exclusive(partial_root / "DEBUG-STOP-OUTCOME.txt", outcome_raw)
    sums = (
        f"{_sha256(report_raw)}  DEBUG-STOP-REPORT.json\n"
        f"{_sha256(outcome_raw)}  DEBUG-STOP-OUTCOME.txt\n"
    ).encode()
    _write_exclusive(partial_root / "DEBUG-STOP-SHA256SUMS.txt", sums)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--partial-root", type=Path, default=DEFAULT_PARTIAL_ROOT)
    parser.add_argument("--locators", type=Path, default=DEFAULT_LOCATORS)
    args = parser.parse_args()
    report = finalize_debug_stop(
        partial_root=args.partial_root.resolve(strict=True),
        locators_path=args.locators.resolve(strict=True),
    )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
