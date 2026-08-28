#!/usr/bin/env python3
"""Seal the stopped multi-row r62 exact-span advisory revision."""

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

OWNER_REVIEW_ROOT = PROJECT_ROOT / "data" / "evaluations" / "phase2a-owner-review"
PARTIAL_ROOT = OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r62-exact-semantic-span-advisory"
CANARY_ROOT = OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r61f-exact-span-canary"
CONTRADICTION_ROW_ID = "live30-q01:issue-03"
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
        raise ValueError("phase2a_multirow_debug_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_multirow_debug_input_must_be_object")
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
    report_path = PARTIAL_ROOT / "DEBUG-STOP-REPORT.json"
    if report_path.exists() or report_path.is_symlink():
        raise ValueError("phase2a_multirow_debug_report_already_exists")
    if (PARTIAL_ROOT / "ADVISORY-EXACT-SEMANTIC-SPANS-448.json").exists():
        raise ValueError("phase2a_multirow_debug_revision_already_finalized")

    intent = _load_object(PARTIAL_ROOT / "INTENT.json")
    intent_digest = _verify_seal(
        intent, "intent_content_sha256", "phase2a_multirow_debug_intent_invalid"
    )
    checkpoint_paths = sorted((PARTIAL_ROOT / "checkpoints").glob("*.json"))
    if len(checkpoint_paths) != 1:
        raise ValueError("phase2a_multirow_debug_checkpoint_count_changed")
    checkpoint = _load_object(checkpoint_paths[0])
    checkpoint_digest = _verify_seal(
        checkpoint,
        "checkpoint_content_sha256",
        "phase2a_multirow_debug_checkpoint_invalid",
    )
    findings = checkpoint.get("findings")
    if (
        checkpoint.get("batch_ordinal") != 1
        or checkpoint.get("attempt_count") != 1
        or not isinstance(findings, list)
        or len(findings) != 6
        or any(row.get("assessment") != "MATERIAL_GAP_ADVISORY" for row in findings)
        or CONTRADICTION_ROW_ID not in checkpoint.get("row_ids", [])
    ):
        raise ValueError("phase2a_multirow_debug_checkpoint_fingerprint_changed")

    canary_intent = _load_object(CANARY_ROOT / "INTENT.json")
    _verify_seal(
        canary_intent,
        "intent_content_sha256",
        "phase2a_multirow_debug_canary_intent_invalid",
    )
    canary = _load_object(CANARY_ROOT / "CANARY-EXACT-SPANS-5.json")
    canary_digest = _verify_seal(
        canary,
        "artifact_content_sha256",
        "phase2a_multirow_debug_canary_invalid",
    )
    canary_row = next(
        row for row in canary["findings"] if row.get("row_id") == CONTRADICTION_ROW_ID
    )
    if (
        canary.get("replacement_all_448_advisory_may_start") is not True
        or canary_row.get("assessment")
        not in {"DIRECT_EXACT_SPAN_ADVISORY", "PARTIAL_EXACT_SPAN_ADVISORY"}
        or canary_intent.get("prompt_sha256") != intent.get("prompt_sha256")
        or canary_intent.get("runtime_identity_sha256") != intent.get("runtime_identity_sha256")
    ):
        raise ValueError("phase2a_multirow_debug_canary_contradiction_changed")

    fingerprint_material = {
        "schema": "legalbot.v111.phase2a.multirow-false-gap-fingerprint.v1",
        "source_intent_content_sha256": intent_digest,
        "source_checkpoint_content_sha256": checkpoint_digest,
        "singleton_canary_artifact_content_sha256": canary_digest,
        "contradiction_row_id": CONTRADICTION_ROW_ID,
        "multirow_assessment": "MATERIAL_GAP_ADVISORY",
        "singleton_assessment": canary_row["assessment"],
        "multirow_input_tokens": checkpoint["model_metrics"]["input_tokens"],
        "multirow_row_count": len(findings),
    }
    failure_fingerprint = _sealed(fingerprint_material)
    report_material = {
        "schema": "legalbot.v111.phase2a.multirow-false-gap-debug-stop.v1",
        "status": "STOPPED_BEFORE_SECOND_BATCH_COMPLETED_NEW_REVISION_REQUIRED",
        "failure_fingerprint": failure_fingerprint,
        "affected_stage": "PHASE2A_ALL_448_EXACT_SPAN_ADVISORY",
        "affected_rows": checkpoint["row_ids"],
        "completed_work": {
            "completed_batch_count": 1,
            "completed_row_count": 6,
            "checkpoint_content_sha256": checkpoint_digest,
            "rejected_attempt_diagnostic_count": len(
                list((PARTIAL_ROOT / "diagnostics").glob("*.json"))
            ),
            "second_batch_interrupted_before_checkpoint": True,
        },
        "root_cause_status": ("CONFIRMED_MULTIROW_LONG_CONTEXT_ADVISORY_FALSE_NEGATIVE"),
        "root_cause_evidence": {
            "contradiction_row_id": CONTRADICTION_ROW_ID,
            "singleton_canary_assessment": canary_row["assessment"],
            "multirow_assessment": "MATERIAL_GAP_ADVISORY",
            "same_prompt_sha256": intent["prompt_sha256"],
            "same_runtime_identity_sha256": intent["runtime_identity_sha256"],
            "multirow_input_tokens": checkpoint["model_metrics"]["input_tokens"],
            "multirow_time_to_first_token_ms": checkpoint["model_metrics"][
                "time_to_first_token_ms"
            ],
        },
        "required_change_in_execution_plan": [
            "Set the all-448 advisory batch size to one row, matching the passed singleton canary.",
            "Start a create-only successor revision; do not resume r62 or reuse its false-GAP checkpoint.",
            "Keep one permitted targeted repair and the two-identical-fingerprint anti-loop stop for each singleton row.",
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
        (b"r62 STOPPED: MULTIROW FALSE GAP CONFIRMED; SINGLETON SUCCESSOR REVISION REQUIRED.\n"),
    )
    names = (
        "INTENT.json",
        str(checkpoint_paths[0].relative_to(PARTIAL_ROOT)),
        "DEBUG-STOP-REPORT.json",
        "DEBUG-STOP-OUTCOME.txt",
    )
    sums = "".join(f"{_sha256_file(PARTIAL_ROOT / name)}  {name}\n" for name in names).encode()
    _write_exclusive(PARTIAL_ROOT / "DEBUG-STOP-SHA256SUMS.txt", sums)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
