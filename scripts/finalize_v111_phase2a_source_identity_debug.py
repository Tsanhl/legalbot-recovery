#!/usr/bin/env python3
"""Seal the stopped r65 source-identity and material-fact debug evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.quality.evidence import extract_material_facts  # noqa: E402
from app.retrieval.source_manifest import (  # noqa: E402
    approved_source_manifest_sha256,
)
from scripts import build_v111_phase2a_authority_plan_advisory as planner  # noqa: E402
from scripts import verify_v111_phase2a_exact_semantic_spans_advisory as verifier  # noqa: E402

OWNER_REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
PARTIAL_ROOT = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r65-span-id-exact-semantic-span-advisory"
)
CANDIDATE_MANIFEST_PATH = (
    PROJECT_ROOT
    / "data/indexes/builds/current-law-ew-full-fp16-v111-20260818-a"
    / "approved-source-manifest.json"
)
MISCLASSIFIED_SOURCE_VERSION_ID = (
    "source-version-5e1963ec7ed2cb7e17094f9c447deaf9a3a21c5a"
)
MISCLASSIFIED_AUTHORITY_ID = "neutral-citation:[2007] EWCA Crim 125"
MISCLASSIFIED_CHUNK_SHA256 = (
    "02b7a776dffe260f51c4c68a0cee55918c3586ddf48248e4e381ea22d3d85a0c"
)
CONFIRMED_MISMATCH_ROWS = ("live30-q04:issue-02", "live60-q34:issue-04")
EXPECTED_NONCANDIDATE_TOP_ROWS = (
    "live30-q04:issue-02",
    "live30-q08:issue-02",
    "live30-q10:issue-03",
    "live30-q23:issue-03",
    "live30-q27:issue-01",
    "live30-q27:issue-03",
    "live30-q28:issue-02",
    "live60-q34:issue-04",
    "live60-q39:issue-11",
    "live60-q48:issue-10",
    "live60-q51:issue-02",
    "live60-q54:issue-07",
    "live60-q55:issue-04",
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
        raise ValueError("phase2a_source_identity_debug_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_source_identity_debug_input_must_be_object")
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


def _projected_noncandidate_rows() -> tuple[list[str], Counter[str]]:
    locators = _load_object(verifier.DEFAULT_LOCATORS)
    _verify_seal(
        locators,
        "artifact_content_sha256",
        "phase2a_source_identity_debug_locator_seal_invalid",
    )
    records = {
        str(record["row_id"]): record for record in locators.get("records", [])
    }
    issues, _digest = planner._load_issue_rows(verifier.DEFAULT_REMAINING)
    noncandidate: list[str] = []
    source_counts: Counter[str] = Counter()
    for issue in issues:
        row_id = str(issue["item_id"])
        projected = verifier._review_row(issue, records[row_id])
        if projected is None:
            continue
        source = projected["evidence_candidates"][0]
        metadata = source.get("candidate_source_metadata") or {}
        if metadata.get("already_in_sealed_candidate") is not True:
            noncandidate.append(row_id)
            source_counts[str(source["source_version_id"])] += 1
    if tuple(noncandidate) != EXPECTED_NONCANDIDATE_TOP_ROWS:
        raise ValueError("phase2a_source_identity_debug_noncandidate_scope_changed")
    return noncandidate, source_counts


def main() -> None:
    report_path = PARTIAL_ROOT / "DEBUG-STOP-REPORT.json"
    if report_path.exists() or report_path.is_symlink():
        raise ValueError("phase2a_source_identity_debug_report_already_exists")
    if (PARTIAL_ROOT / "ADVISORY-EXACT-SEMANTIC-SPANS-448.json").exists():
        raise ValueError("phase2a_source_identity_debug_revision_already_finalized")

    intent = _load_object(PARTIAL_ROOT / "INTENT.json")
    intent_digest = _verify_seal(
        intent,
        "intent_content_sha256",
        "phase2a_source_identity_debug_intent_invalid",
    )
    checkpoint_paths = sorted((PARTIAL_ROOT / "checkpoints").glob("*.json"))
    diagnostic_paths = sorted((PARTIAL_ROOT / "diagnostics").glob("*.json"))
    if len(checkpoint_paths) != 23 or len(diagnostic_paths) != 1:
        raise ValueError("phase2a_source_identity_debug_partial_counts_changed")

    mismatch_finding: dict[str, Any] | None = None
    for path in checkpoint_paths:
        checkpoint = _load_object(path)
        _verify_seal(
            checkpoint,
            "checkpoint_content_sha256",
            "phase2a_source_identity_debug_checkpoint_invalid",
        )
        for finding in checkpoint.get("findings", []):
            if finding.get("row_id") == CONFIRMED_MISMATCH_ROWS[0]:
                mismatch_finding = finding
    if mismatch_finding is None:
        raise ValueError("phase2a_source_identity_debug_mismatch_checkpoint_missing")
    binding = mismatch_finding.get("exact_span_binding") or {}
    currentness = mismatch_finding.get("source_currentness") or {}
    exact_text = str(binding.get("exact_text") or "")
    if (
        binding.get("source_version_id") != MISCLASSIFIED_SOURCE_VERSION_ID
        or binding.get("authority_identity_id") != MISCLASSIFIED_AUTHORITY_ID
        or binding.get("chunk_text_sha256") != MISCLASSIFIED_CHUNK_SHA256
        or currentness.get("already_in_sealed_candidate") is not False
        or "Thomson Reuters" not in exact_text
        or "L.Q.R." not in exact_text
    ):
        raise ValueError("phase2a_source_identity_debug_mismatch_evidence_changed")

    for path in diagnostic_paths:
        diagnostic = _load_object(path)
        _verify_seal(
            diagnostic,
            "diagnostic_content_sha256",
            "phase2a_source_identity_debug_diagnostic_invalid",
        )

    manifest = _load_object(CANDIDATE_MANIFEST_PATH)
    manifest_digest = str(manifest.get("manifest_sha256") or "")
    if (
        manifest_digest != approved_source_manifest_sha256(manifest)
        or manifest.get("source_count") != 85
        or MISCLASSIFIED_SOURCE_VERSION_ID
        in {str(source["source_version_id"]) for source in manifest.get("sources", [])}
    ):
        raise ValueError("phase2a_source_identity_debug_candidate_manifest_invalid")

    noncandidate_rows, source_counts = _projected_noncandidate_rows()
    extracted = extract_material_facts("sections 15, 16, 20 and 21")
    extracted_ids = [fact.normalized_value for fact in extracted]
    if extracted_ids != ["section:15"]:
        raise ValueError("phase2a_source_identity_debug_fact_parser_state_changed")

    source_fingerprint_material = {
        "schema": "legalbot.v111.phase2a.source-identity-failure-fingerprint.v1",
        "source_version_id": MISCLASSIFIED_SOURCE_VERSION_ID,
        "claimed_authority_identity_id": MISCLASSIFIED_AUTHORITY_ID,
        "chunk_text_sha256": MISCLASSIFIED_CHUNK_SHA256,
        "publisher_markers": ["L.Q.R.", "Thomson Reuters"],
        "already_in_sealed_candidate": False,
        "selected_by_old_revision": True,
    }
    fact_fingerprint_material = {
        "schema": "legalbot.v111.phase2a.provision-series-parser-failure-fingerprint.v1",
        "input": "sections 15, 16, 20 and 21",
        "extracted_provision_ids": extracted_ids,
        "required_provision_ids": [
            "section:15",
            "section:16",
            "section:20",
            "section:21",
        ],
    }
    report_material = {
        "schema": "legalbot.v111.phase2a.source-identity-and-fact-debug-stop.v1",
        "status": "STOPPED_BEFORE_UNVERIFIED_SOURCE_OR_INCOMPLETE_FACT_CHECK_REACHED_OWNER_GATE",
        "failure_fingerprints": {
            "source_identity": _sealed(source_fingerprint_material),
            "provision_series_extraction": _sealed(fact_fingerprint_material),
        },
        "affected_stage": "PHASE2A_EXACT_SPAN_ADVISORY_INPUT_AND_VALIDATION",
        "affected_rows": {
            "confirmed_misclassified_source_rows": list(CONFIRMED_MISMATCH_ROWS),
            "noncandidate_top_projection_rows": noncandidate_rows,
            "provision_series_demonstration_row": "live30-q01:issue-01",
        },
        "completed_work": {
            "completed_checkpoint_count": len(checkpoint_paths),
            "rejected_attempt_diagnostic_count": len(diagnostic_paths),
            "checkpoints_eligible_for_owner_package_before_revalidation": 0,
            "remaining_rows_not_run": 448 - len(checkpoint_paths),
        },
        "root_cause_status": "CONFIRMED_TWO_INDEPENDENT_FAIL_CLOSED_GAPS",
        "root_cause_evidence": {
            "source_intent_content_sha256": intent_digest,
            "candidate_manifest_sha256": manifest_digest,
            "candidate_source_count": manifest["source_count"],
            "misclassified_source_absent_from_candidate_manifest": True,
            "misclassified_source_version_id": MISCLASSIFIED_SOURCE_VERSION_ID,
            "misclassified_source_claimed_authority_identity_id": (
                MISCLASSIFIED_AUTHORITY_ID
            ),
            "misclassified_source_exact_chunk_sha256": MISCLASSIFIED_CHUNK_SHA256,
            "noncandidate_top_projection_count": len(noncandidate_rows),
            "noncandidate_top_projection_source_counts": dict(
                sorted(source_counts.items())
            ),
            "provision_series_input": "sections 15, 16, 20 and 21",
            "old_extracted_provision_ids": extracted_ids,
        },
        "required_change_in_execution_plan": [
            "Bind advisory inputs to the exact sealed candidate manifest and reject any source version outside that manifest.",
            "Route missing candidate coverage to a separate allowlisted official-source quarantine and owner-admission batch.",
            "Reject private publisher and secondary-material content that is mislabelled as primary authority, regardless of catalogue metadata.",
            "Extract every identifier in provision lists and ranges, then add altered-list adversarial tests.",
            "Run a new candidate-membership and material-fact canary before starting a create-only replacement all-448 revision.",
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
    _write_exclusive(report_path, _pretty_json(report))
    _write_exclusive(
        PARTIAL_ROOT / "DEBUG-STOP-OUTCOME.txt",
        b"r65 STOPPED: SOURCE-MANIFEST MEMBERSHIP AND COMPLETE MATERIAL-FACT EXTRACTION REQUIRED IN A NEW REVISION.\n",
    )
    names = [
        "INTENT.json",
        *[str(path.relative_to(PARTIAL_ROOT)) for path in checkpoint_paths],
        *[str(path.relative_to(PARTIAL_ROOT)) for path in diagnostic_paths],
        "DEBUG-STOP-REPORT.json",
        "DEBUG-STOP-OUTCOME.txt",
    ]
    sums = "".join(
        f"{_sha256_file(PARTIAL_ROOT / name)}  {name}\n" for name in names
    ).encode("utf-8")
    _write_exclusive(PARTIAL_ROOT / "DEBUG-STOP-SHA256SUMS.txt", sums)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
