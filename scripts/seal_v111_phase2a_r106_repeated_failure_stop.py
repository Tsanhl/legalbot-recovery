#!/usr/bin/env python3
"""Seal the r106 repeated-contract-failure stop before a changed plan."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-26-r106-source-link-exact-span-advisory"
)
TARGET = ROOT / "DEBUG-STOP.json"
EXPECTED_FINGERPRINT = (
    "e846bdf51b25a9948494b8e2e0f9884e384d018f6a5a4c9999292fdc2902c283"
)
EXPECTED_ERROR = "structured_output_contract_invalid"


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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_r106_stop_input_invalid")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r106_stop_input_not_object")
    return value


def _verify(value: Mapping[str, Any], field: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if supplied != _sealed(material):
        raise ValueError("phase2a_r106_stop_input_seal_invalid")
    return supplied


def _write(path: Path, raw: bytes) -> None:
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


def seal_stop(root: Path = ROOT) -> dict[str, Any]:
    target = root / TARGET.name
    if target.exists():
        value = _load(target)
        _verify(value, "debug_stop_content_sha256")
        return value
    intent = _load(root / "INTENT.json")
    intent_digest = _verify(intent, "intent_content_sha256")
    checkpoints = sorted((root / "checkpoints").glob("*.json"))
    diagnostics = sorted((root / "diagnostics").glob("*.json"))
    epochs = sorted((root / "runtime-epochs").glob("*.json"))
    if len(checkpoints) != 1 or len(diagnostics) != 2 or len(epochs) != 1:
        raise ValueError("phase2a_r106_stop_inventory_invalid")
    checkpoint = _load(checkpoints[0])
    checkpoint_digest = _verify(checkpoint, "checkpoint_content_sha256")
    diagnostic_rows = []
    for path in diagnostics:
        value = _load(path)
        digest = _verify(value, "diagnostic_content_sha256")
        diagnostic_rows.append(
            {
                "relative_path": f"diagnostics/{path.name}",
                "file_sha256": _sha256_file(path),
                "content_sha256": digest,
                "attempt": value.get("attempt"),
                "error_code": value.get("error_code"),
                "failure_fingerprint": value.get("failure_fingerprint"),
            }
        )
    epoch = _load(epochs[0])
    epoch_digest = _verify(epoch, "epoch_content_sha256")
    if (
        checkpoint.get("finding", {}).get("assessment")
        != "HELD_FOR_DEBUG_BEFORE_ANY_THIRD_ATTEMPT"
        or checkpoint.get("same_failure_fingerprint_twice") is not True
        or [row["attempt"] for row in diagnostic_rows] != [1, 2]
        or {row["error_code"] for row in diagnostic_rows} != {EXPECTED_ERROR}
        or {row["failure_fingerprint"] for row in diagnostic_rows}
        != {EXPECTED_FINGERPRINT}
        or epoch.get("epoch_error_code") != "keyboard_interrupt"
        or epoch.get("processed_count") != 1
    ):
        raise ValueError("phase2a_r106_stop_failure_binding_invalid")
    material = {
        "schema": "legalbot.v111.phase2a.r106-repeated-failure-debug-stop.v1",
        "status": "STOPPED_AFTER_TWO_IDENTICAL_FAILURES_BEFORE_ANY_THIRD_ATTEMPT",
        "source_intent_content_sha256": intent_digest,
        "affected_stage": "same_adapter_source_link_exact_span_advisory",
        "affected_row_id": checkpoint["row_id"],
        "affected_row_source_link_id": checkpoint["row_source_link_id"],
        "failure_fingerprint": EXPECTED_FINGERPRINT,
        "error_code": EXPECTED_ERROR,
        "attempt_count": 2,
        "checkpoint_content_sha256": checkpoint_digest,
        "diagnostic_custody": diagnostic_rows,
        "diagnostic_custody_sha256": _sealed(diagnostic_rows),
        "runtime_epoch_content_sha256": epoch_digest,
        "completed_work": {
            "deterministic_source_packets_sealed": True,
            "independent_reranking_26_of_26_complete": True,
            "same_adapter_review_links_completed": 1,
            "same_adapter_review_links_remaining": 25,
        },
        "root_cause_status": (
            "The model returned the exact required top-level key set, but one "
            "free-form contract subfield failed validation twice. The exact subfield "
            "is not reconstructable because raw output and structural values were "
            "correctly not persisted; this exposed a diagnostic-observability gap."
        ),
        "required_execution_plan_change": {
            "historical_r106_preserved": True,
            "fresh_append_only_successor_run_required": True,
            "remove_model_authored_reason_codes": True,
            "derive_reason_codes_deterministically": True,
            "persist_safe_structural_validation_diagnostics": True,
            "new_prompt_and_schema_digest_required": True,
            "no_identical_third_attempt": True,
        },
        "owner_decision_assigned": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "debug_stop_content_sha256": _sealed(material)}
    _write(target, _pretty_json(artifact))
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    sums = "".join(
        f"{_sha256_file(path)}  {path.relative_to(root)}\n" for path in files
    )
    _write(root / "SHA256SUMS.txt", sums.encode("utf-8"))
    return artifact


def main() -> None:
    result = seal_stop()
    print(
        json.dumps(
            {
                "debug_stop_content_sha256": result[
                    "debug_stop_content_sha256"
                ],
                "failure_fingerprint": result["failure_fingerprint"],
                "status": result["status"],
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
