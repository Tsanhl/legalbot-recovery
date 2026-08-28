#!/usr/bin/env python3
"""Seal the stopped r63 free-form exact-quote copy failure."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OWNER_REVIEW_ROOT = PROJECT_ROOT / "data" / "evaluations" / "phase2a-owner-review"
PARTIAL_ROOT = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r63-singleton-exact-semantic-span-advisory"
)
HELD_ROWS = ("live30-q01:issue-04", "live30-q01:issue-05")
EXPECTED_CHUNK_SHA256 = "fb6230dd1f7d08667b6ee4248e5c3724d2616258dfe1ae50892ba44e500998f9"
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
        raise ValueError("phase2a_quote_debug_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_quote_debug_input_must_be_object")
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
        raise ValueError("phase2a_quote_debug_report_already_exists")
    if (PARTIAL_ROOT / "ADVISORY-EXACT-SEMANTIC-SPANS-448.json").exists():
        raise ValueError("phase2a_quote_debug_revision_already_finalized")

    intent = _load_object(PARTIAL_ROOT / "INTENT.json")
    intent_digest = _verify_seal(
        intent, "intent_content_sha256", "phase2a_quote_debug_intent_invalid"
    )
    checkpoint_paths = sorted((PARTIAL_ROOT / "checkpoints").glob("*.json"))
    diagnostic_paths = sorted((PARTIAL_ROOT / "diagnostics").glob("*.json"))
    if len(checkpoint_paths) != 5 or len(diagnostic_paths) != 4:
        raise ValueError("phase2a_quote_debug_file_count_changed")

    checkpoints: list[dict[str, Any]] = []
    for path in checkpoint_paths:
        value = _load_object(path)
        field = (
            "checkpoint_content_sha256"
            if value.get("schema") == "legalbot.v111.phase2a.exact-span-checkpoint.v1"
            else "held_content_sha256"
        )
        _verify_seal(value, field, "phase2a_quote_debug_checkpoint_invalid")
        checkpoints.append(value)
    if [row["row_ids"][0] for row in checkpoints[-2:]] != list(HELD_ROWS):
        raise ValueError("phase2a_quote_debug_held_rows_changed")
    if any(
        row.get("schema") != "legalbot.v111.phase2a.exact-span-held-batch.v1"
        or row.get("attempt_count") != 2
        or row.get("same_failure_fingerprint_twice") is not True
        for row in checkpoints[-2:]
    ):
        raise ValueError("phase2a_quote_debug_hold_contract_changed")

    diagnostics: list[dict[str, Any]] = []
    for path in diagnostic_paths:
        value = _load_object(path)
        _verify_seal(
            value,
            "diagnostic_content_sha256",
            "phase2a_quote_debug_diagnostic_invalid",
        )
        diagnostics.append(value)
    by_row = {
        row_id: [row for row in diagnostics if row.get("row_ids") == [row_id]]
        for row_id in HELD_ROWS
    }
    for row_id, rows in by_row.items():
        if (
            len(rows) != 2
            or [row.get("attempt") for row in rows] != [1, 2]
            or any(
                row.get("error_code") != "structured_output_quote_not_exact_substring"
                for row in rows
            )
            or rows[0].get("failure_fingerprint") != rows[1].get("failure_fingerprint")
            or rows[1].get("same_failure_fingerprint_as_prior_attempt") is not True
        ):
            raise ValueError(f"phase2a_quote_debug_fingerprint_changed_{row_id}")

    fingerprint_material = {
        "schema": "legalbot.v111.phase2a.freeform-quote-copy-fingerprint.v1",
        "source_intent_content_sha256": intent_digest,
        "affected_row_ids": list(HELD_ROWS),
        "failure_fingerprints": [by_row[row_id][0]["failure_fingerprint"] for row_id in HELD_ROWS],
        "shared_source_chunk_text_sha256": EXPECTED_CHUNK_SHA256,
        "error_code": "structured_output_quote_not_exact_substring",
    }
    failure_fingerprint = _sealed(fingerprint_material)
    report_material = {
        "schema": "legalbot.v111.phase2a.freeform-quote-copy-debug-stop.v1",
        "status": "STOPPED_AFTER_TWO_CONSECUTIVE_ROWS_EXPOSED_SYSTEMIC_QUOTE_COPY_FAILURE",
        "failure_fingerprint": failure_fingerprint,
        "affected_stage": "PHASE2A_SINGLETON_EXACT_SPAN_ADVISORY",
        "affected_rows": list(HELD_ROWS),
        "completed_work": {
            "completed_checkpoint_count": 5,
            "accepted_checkpoint_count": 3,
            "held_checkpoint_count": 2,
            "rejected_attempt_diagnostic_count": 4,
            "next_row_interrupted_before_checkpoint": True,
        },
        "root_cause_status": "CONFIRMED_FREE_FORM_QUOTE_COPY_IS_NOT_RELIABLE_FOR_OCR_SOURCE_TEXT",
        "root_cause_evidence": {
            "shared_source_chunk_text_sha256": EXPECTED_CHUNK_SHA256,
            "shared_source_chunk_character_count": 1720,
            "source_contains_ocr_spacing_artifacts": True,
            "both_attempts_rejected_before_any_evidence_binding": True,
        },
        "required_change_in_execution_plan": [
            "Deterministically partition every supplied whole chunk into exhaustive exact source-byte span options with stable IDs and offsets.",
            "Require the advisory model to select a supplied span ID instead of reproducing quotation text.",
            "Resolve the selected ID back to the original exact source bytes and validate all proposition facts against that bound span.",
            "Run a new canary before starting a create-only all-448 successor revision.",
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
        (
            b"r63 STOPPED: FREE-FORM QUOTE COPYING REPLACED BY DETERMINISTIC "
            b"EXACT-SPAN ID SELECTION IN A NEW REVISION.\n"
        ),
    )
    names = [
        "INTENT.json",
        *[str(path.relative_to(PARTIAL_ROOT)) for path in checkpoint_paths],
        *[str(path.relative_to(PARTIAL_ROOT)) for path in diagnostic_paths],
        "DEBUG-STOP-REPORT.json",
        "DEBUG-STOP-OUTCOME.txt",
    ]
    sums = "".join(f"{_sha256_file(PARTIAL_ROOT / name)}  {name}\n" for name in names).encode()
    _write_exclusive(PARTIAL_ROOT / "DEBUG-STOP-SHA256SUMS.txt", sums)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
