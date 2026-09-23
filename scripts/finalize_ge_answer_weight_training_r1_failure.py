#!/usr/bin/env python3
"""Finalize the preserved r1 answer-weight training OOM as immutable evidence."""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN_ID = "LegalBot-GE-2026-09-04-answer-weight-training-r1"
OUTPUT = ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
ZIP = ROOT.parent / f"{CAMPAIGN_ID}.zip"
EXPECTED_FAILURE_SHA256 = "8cfbf43b67e7cbfc0b2c1bbb9032d59bddd81b8597af3fe20d9892df8a77bda8"
EXPECTED_TRAINING_LOG_SHA256 = "5d0fe88dc180fb9e826c9af13e9592798464519aa69d2475d6bc9efff7bb0215"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sealed(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["content_sha256"] = hashlib.sha256(canonical(result)).hexdigest()
    return result


def write_json(path: Path, value: Any) -> None:
    if path.exists():
        raise RuntimeError(f"refusing to replace {path}")
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def write_text(path: Path, value: str) -> None:
    if path.exists():
        raise RuntimeError(f"refusing to replace {path}")
    path.write_text(value)


def main() -> int:
    failure = OUTPUT / "FAILURE-RECEIPT.json"
    training_log = OUTPUT / "TRAINING-LOG.txt"
    if sha256_file(failure) != EXPECTED_FAILURE_SHA256:
        raise RuntimeError("r1 failure receipt changed")
    if sha256_file(training_log) != EXPECTED_TRAINING_LOG_SHA256:
        raise RuntimeError("r1 training log changed")
    log = training_log.read_text()
    if "Insufficient Memory" not in log or "Command buffer execution failed" not in log:
        raise RuntimeError("r1 failure fingerprint is not the expected Metal OOM")
    if (OUTPUT / "adapter/adapters.safetensors").exists():
        raise RuntimeError("unexpected r1 adapter weights exist")
    baseline = (OUTPUT / "BASELINE-LOG.txt").read_text()
    match = re.search(
        r"Test loss ([0-9]+(?:\.[0-9]+)?), Test ppl ([0-9]+(?:\.[0-9]+)?)\.", baseline
    )
    if match is None:
        raise RuntimeError("baseline metric missing")

    manifest = sealed(
        {
            "schema": "legalbot.ge-answer-weight-training-failed-run.v1",
            "campaign_id": CAMPAIGN_ID,
            "status": "FAILED_PRESERVED",
            "failure_stage": "LORA_TRAINING",
            "failure_fingerprint": "METAL_COMMAND_BUFFER_OUT_OF_MEMORY_AFTER_INITIAL_VALIDATION",
            "process_exit_code": -6,
            "baseline_test_loss": float(match.group(1)),
            "baseline_test_perplexity": float(match.group(2)),
            "adapter_weights_created": False,
            "base_model_mutated": False,
            "private_unseen_opened": False,
            "held_rows_included": False,
            "failure_receipt_sha256": sha256_file(failure),
            "training_log_sha256": sha256_file(training_log),
            "implementation_sha256": sha256_file(
                ROOT / "backend/app/evaluation/ge_answer_weight_training.py"
            ),
            "targeted_repair": {
                "successor_campaign_id": "LegalBot-GE-2026-09-04-answer-weight-training-r2",
                "num_layers": {"from": 4, "to": 1},
                "lora_rank": {"from": 4, "to": 2},
                "training_max_sequence_length": {"from": 1536, "to": 768},
                "separate_no_gradient_test_evaluation": True,
            },
            "finalized_at": datetime.now(UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        }
    )
    write_json(OUTPUT / "FAILED-RUN-MANIFEST.json", manifest)
    write_json(
        OUTPUT / "STATE-TRANSITION-RECEIPT.json",
        sealed(
            {
                "schema": "legalbot.ge-answer-weight-training-state.v1",
                "campaign_id": CAMPAIGN_ID,
                "overall_state": "ANSWER_WEIGHT_TRAINING_FAILED_TARGETED_REPAIR_REQUIRED",
                "answer_weight_training": "FAILED_NO_WEIGHTS_CREATED",
                "failure_fingerprint": manifest["failure_fingerprint"],
                "authorized_exact_hash_count": 13,
                "held_case_count_excluded": 7,
                "private_306_bank": "SEALED_NOT_OPENED",
                "sealed_unseen_execution": "NOT_STARTED",
                "promotion": "NOT_STARTED",
                "live": "NOT_STARTED",
                "retry_without_targeted_repair": False,
                "targeted_successor": "LegalBot-GE-2026-09-04-answer-weight-training-r2",
            }
        ),
    )
    write_text(
        OUTPUT / "README.md",
        "\n".join(
            [
                "# GE answer-weight training r1 — preserved failed execution",
                "",
                "The pinned local model and baseline internal test loaded successfully.",
                "The first gradient step then stopped with a Metal command-buffer out-of-memory",
                "error after the initial validation pass. No adapter weights were created and",
                "the immutable base model was not modified.",
                "",
                "The 13 authorized hashes were the only corpus records. The seven holds were",
                "excluded and the private 306-case unseen bank remained sealed.",
                "",
                "A retry is permitted only as a new r2 artifact after the recorded memory",
                "repair: one trainable layer, rank two, 768 training tokens and separate",
                "no-gradient test evaluation.",
                "",
            ]
        ),
    )
    artifacts = {
        path.relative_to(OUTPUT).as_posix(): sha256_file(path)
        for path in sorted(OUTPUT.rglob("*"))
        if path.is_file() and path.name != "ARTIFACT-SHA256-REGISTER.json"
    }
    write_json(
        OUTPUT / "ARTIFACT-SHA256-REGISTER.json",
        {
            "schema": "legalbot.ge-answer-weight-training-hashes.v1",
            "campaign_id": CAMPAIGN_ID,
            "artifacts": artifacts,
        },
    )
    if ZIP.exists():
        raise RuntimeError("r1 failure zip already exists")
    with zipfile.ZipFile(ZIP, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(OUTPUT.rglob("*")):
            if path.is_file():
                archive.write(path, arcname=str(Path(OUTPUT.name) / path.relative_to(OUTPUT)))
    print(
        json.dumps(
            {
                "campaign_id": CAMPAIGN_ID,
                "status": "FAILED_PRESERVED",
                "zip": str(ZIP),
                "zip_sha256": sha256_file(ZIP),
                "manifest_sha256": sha256_file(OUTPUT / "FAILED-RUN-MANIFEST.json"),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
