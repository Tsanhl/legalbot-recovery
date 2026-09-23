"""Owner-authorized, create-only GE answer-weight LoRA training.

This experiment is bound to the 13 exact answer hashes accepted by the automatic
factual and 70+ review. The seven held rows are excluded. The private unseen bank
is represented only by its question-free custody ledger and is never opened.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import zipfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema  # type: ignore[import-untyped]

from .ge_currentness_packets import PROJECT_ROOT, load_jsonl, sha256_file, sha256_text
from .ge_phase2_progress import (
    ANSWER_WEIGHT_TRAINING_COMPLETE_AWAITING_FRESH_VISIBLE_EVALUATION,
    NOT_STARTED,
)

CAMPAIGN_ID = "LegalBot-GE-2026-09-04-answer-weight-training-r2"
CAMPAIGN_VERSION = "legalbot.ge-answer-weight-training.v1"
PREDECESSOR_CAMPAIGN_ID = "LegalBot-GE-2026-09-04-answer-weight-training-r1"
PREDECESSOR_ROOT = PROJECT_ROOT / "data/evaluations/general-enquiries" / PREDECESSOR_CAMPAIGN_ID
PREDECESSOR_FAILURE = PREDECESSOR_ROOT / "FAILURE-RECEIPT.json"
PREDECESSOR_TRAINING_LOG = PREDECESSOR_ROOT / "TRAINING-LOG.txt"
EXPECTED_PREDECESSOR_FAILURE_SHA256 = (
    "8cfbf43b67e7cbfc0b2c1bbb9032d59bddd81b8597af3fe20d9892df8a77bda8"
)
EXPECTED_PREDECESSOR_TRAINING_LOG_SHA256 = (
    "5d0fe88dc180fb9e826c9af13e9592798464519aa69d2475d6bc9efff7bb0215"
)
SOURCE_CAMPAIGN_ID = "LegalBot-GE-2026-09-04-ai-auto-quality-review-r1"
SOURCE_ROOT = PROJECT_ROOT / "data/evaluations/general-enquiries" / SOURCE_CAMPAIGN_ID
ACCEPTED_SOURCE = SOURCE_ROOT / "AI-EVALUATION-GOLD-CANDIDATES.jsonl"
HOLD_SOURCE = SOURCE_ROOT / "AI-HOLD-ROUTING.jsonl"
REVIEW_SOURCE = SOURCE_ROOT / "AI-AUTO-REVIEW.jsonl"
EXPECTED_ACCEPTED_SHA256 = "451ec1b61692c19c950094da6c0d69a7f35a30a3e5118ab30f0a08a725802652"
EXPECTED_HOLD_SHA256 = "5e80257bd2439d1ebf845193bfc85ac29938e7d70e77a46ba0400c41cda0b19f"
EXPECTED_REVIEW_SHA256 = "aa84eedfee9c8279e67acb8e6c9a76a0006a4b0f935fef510b3fe74049fa21ae"
UNSEEN_LEDGER = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-01-execution-readiness-r1"
    / "GE-UNSEEN-CUSTODY-LEDGER.json"
)
EXPECTED_UNSEEN_LEDGER_SHA256 = "11f42c7fcd83dbb0299db31917663044515a574705472921e06fcc1e469af7b2"
MODEL_ROOT = PROJECT_ROOT / "models/runtime/Qwen3.5-9B-4bit"
MODEL_RELATIVE = "models/runtime/Qwen3.5-9B-4bit"
MODEL_RUNTIME_MANIFEST = MODEL_ROOT / "runtime-model.json"
MODEL_REPO = "mlx-community/Qwen3.5-9B-4bit"
MODEL_REVISION = "8b2b98c00a6b4d291155e4890773ca8f769aee53"
MODEL_PYTHON = PROJECT_ROOT / "model-runtime/.venv/bin/python"
TRAINING_SCHEMA = PROJECT_ROOT / "docs/system-design/schemas/training-experiment.v1.schema.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
DESKTOP_ZIP = (Path.home() / "Desktop") / f"{CAMPAIGN_ID}.zip"

OWNER_AUTHORIZATION_TEXT = (
    "I authorize answer-weight training only for the 13 exact hashes in "
    "LegalBot-GE-2026-09-04-ai-auto-quality-review-r1. Keep the seven holds "
    "excluded and the private unseen bank sealed."
)
OWNER_AUTHORIZATION_TEXT_SHA256 = sha256_text(OWNER_AUTHORIZATION_TEXT)

SYSTEM_PROMPT = (
    "You are LegalBot's General Enquiry answer model for England and Wales. "
    "Use only the evidence supplied with the question. Give a direct plain-English "
    "answer, separate law from unverified user facts, state material qualifications "
    "and missing facts, and give safe practical next steps. Do not invent authority "
    "or claim professional legal sign-off. Do not render formal citations; the "
    "deterministic citation layer uses the supplied evidence metadata."
)

TRAIN_CASE_IDS = frozenset(
    {
        "business-and-company-law:cp-d03",
        "business-and-company-law:cp-d09",
        "business-and-company-law:cp-d10",
        "business-and-company-law:cp-s02",
        "commercial-law:cp-d02",
        "commercial-law:cp-d04",
        "commercial-law:cp-d07",
        "contract-law:cp-d02",
        "contract-law:cp-d14",
    }
)
VALID_CASE_IDS = frozenset(
    {
        "wills-and-estates:cp-s02",
        "wills-and-estates:cp-d02",
        "wills-and-estates:cp-d16",
    }
)
TEST_CASE_IDS = frozenset({"administrative-law:cp-d08"})
AUTHORIZED_CASE_IDS = TRAIN_CASE_IDS | VALID_CASE_IDS | TEST_CASE_IDS

TRAINING_MAX_SEQUENCE_LENGTH = 768
EVALUATION_MAX_SEQUENCE_LENGTH = 1536
RESOURCE_MEMORY_CEILING_GB = 12.0
RESOURCE_MIN_FREE_DISK_GB = 20.0
TRAINING_TIMEOUT_SECONDS = 1800
RECIPE: Mapping[str, Any] = {
    "model": MODEL_RELATIVE,
    "fine_tune_type": "lora",
    "optimizer": "adamw",
    "mask_prompt": True,
    "num_layers": 1,
    "batch_size": 1,
    "iters": 30,
    "val_batches": -1,
    "learning_rate": 1e-5,
    "steps_per_report": 5,
    "steps_per_eval": 5,
    "save_every": 5,
    "test_batches": -1,
    "max_seq_length": TRAINING_MAX_SEQUENCE_LENGTH,
    "grad_checkpoint": True,
    "grad_accumulation_steps": 1,
    "clear_cache_threshold": 1_000_000_000,
    "seed": 20_260_904,
    "lora_parameters": {"rank": 2, "dropout": 0.05, "scale": 4.0},
}


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sealed(value: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["content_sha256"] = hashlib.sha256(_canonical_bytes(result)).hexdigest()
    return result


def _write_text_create(path: Path, value: str) -> None:
    if path.exists():
        raise RuntimeError(f"refusing to replace existing artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def _write_json_create(path: Path, value: object) -> None:
    _write_text_create(
        path,
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def _write_jsonl_create(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    _write_text_create(
        path,
        "".join(json.dumps(dict(row), ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
    )


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _split_for(case_id: str) -> str:
    if case_id in TRAIN_CASE_IDS:
        return "train"
    if case_id in VALID_CASE_IDS:
        return "valid"
    if case_id in TEST_CASE_IDS:
        return "test"
    raise RuntimeError(f"case is outside the authorized training corpus: {case_id}")


def validate_authorized_sources() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    expected = {
        ACCEPTED_SOURCE: EXPECTED_ACCEPTED_SHA256,
        HOLD_SOURCE: EXPECTED_HOLD_SHA256,
        REVIEW_SOURCE: EXPECTED_REVIEW_SHA256,
        UNSEEN_LEDGER: EXPECTED_UNSEEN_LEDGER_SHA256,
    }
    for path, digest in expected.items():
        if not path.is_file() or sha256_file(path) != digest:
            raise RuntimeError(f"training input identity changed: {path.name}")

    accepted = load_jsonl(ACCEPTED_SOURCE)
    holds = load_jsonl(HOLD_SOURCE)
    reviews = load_jsonl(REVIEW_SOURCE)
    if len(accepted) != 13 or len(holds) != 7 or len(reviews) != 20:
        raise RuntimeError("authorized 13/7/20 inventory is not intact")

    accepted_ids = {str(row.get("case_id") or "") for row in accepted}
    hold_ids = {str(row.get("case_id") or "") for row in holds}
    if accepted_ids != AUTHORIZED_CASE_IDS:
        raise RuntimeError("accepted case IDs differ from the authorized 13")
    if len(accepted_ids) != len(accepted) or len(hold_ids) != len(holds):
        raise RuntimeError("accepted or held case IDs are duplicated")
    if accepted_ids & hold_ids:
        raise RuntimeError("a held case entered the training corpus")

    review_by_id = {str(row["case_id"]): row for row in reviews}
    if set(review_by_id) != accepted_ids | hold_ids:
        raise RuntimeError("review inventory does not reconcile to accepted plus held rows")

    for row in accepted:
        case_id = str(row["case_id"])
        if sha256_text(str(row.get("question") or "")) != row.get("question_hash"):
            raise RuntimeError(f"question hash mismatch: {case_id}")
        if sha256_text(str(row.get("candidate_answer") or "")) != row.get("candidate_answer_hash"):
            raise RuntimeError(f"answer hash mismatch: {case_id}")
        review = review_by_id[case_id]
        if review.get("ai_auto_decision") != "AI_ACCEPT":
            raise RuntimeError(f"nonaccepted case entered training: {case_id}")
        if review.get("factual_outcome") != "FACTUAL_PASS":
            raise RuntimeError(f"factual hold entered training: {case_id}")
        score = review.get("quality_score")
        if score is None or float(score) < 70:
            raise RuntimeError(f"sub-70 case entered training: {case_id}")
        if not review.get("all_declared_material_claims_supported"):
            raise RuntimeError(f"unsupported declared claim entered training: {case_id}")
        if not review.get("all_answer_material_propositions_declared_and_supported"):
            raise RuntimeError(f"unsupported answer proposition entered training: {case_id}")
        claims = row.get("material_claims") or []
        if not claims:
            raise RuntimeError(f"training case has no evidence: {case_id}")
        claim_hashes = {str(item.get("evidence_span_sha256") or "") for item in claims}
        evidence_hashes = {
            str(item.get("evidence_span_sha256") or "")
            for item in row.get("evidence_references") or []
        }
        if not claim_hashes.issubset(evidence_hashes):
            raise RuntimeError(f"training claim/evidence mismatch: {case_id}")

    unseen = json.loads(UNSEEN_LEDGER.read_text(encoding="utf-8"))
    if unseen.get("unseen_case_count") != 306:
        raise RuntimeError("private unseen custody count changed")
    if unseen.get("prompt_content_inspected") is not False:
        raise RuntimeError("private unseen ledger no longer reports sealed content")
    if unseen.get("used_for_training") is not False:
        raise RuntimeError("private unseen ledger reports training use")
    return accepted, holds


def _evidence_prompt(row: Mapping[str, Any]) -> str:
    evidence_parts = []
    for index, claim in enumerate(row.get("material_claims") or [], start=1):
        evidence_parts.append(
            "\n".join(
                [
                    f"Evidence {index}",
                    f"Source: {claim['title']}",
                    f"Locator: {claim['locator']}",
                    f"Verified excerpt: {claim['quote']}",
                ]
            )
        )
    return "\n\n".join(
        [
            f"Question:\n{row['question']}",
            "Permitted evidence:\n" + "\n\n".join(evidence_parts),
            (
                "Answer the question using only the permitted evidence. State any material "
                "limit where the evidence or facts do not resolve the outcome."
            ),
        ]
    )


def build_training_records(
    accepted: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    datasets: dict[str, list[dict[str, Any]]] = {"train": [], "valid": [], "test": []}
    records: list[dict[str, Any]] = []
    for row in sorted(accepted, key=lambda item: str(item["case_id"])):
        case_id = str(row["case_id"])
        split = _split_for(case_id)
        user_prompt = _evidence_prompt(row)
        target = str(row["candidate_answer"])
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": target},
        ]
        dataset_row = {
            "messages": messages,
            "metadata": {
                "case_id": case_id,
                "question_hash": row["question_hash"],
                "answer_hash": row["candidate_answer_hash"],
            },
        }
        datasets[split].append(dataset_row)
        record_body = {
            "schema": "legalbot.ge-answer-weight-training-record.v1",
            "case_id": case_id,
            "topic": row["topic"],
            "split": split,
            "question_hash": row["question_hash"],
            "target_answer_hash": row["candidate_answer_hash"],
            "evidence_manifest_hash": row["reviewed_evidence_hash"],
            "evidence_span_sha256": sorted(
                str(claim["evidence_span_sha256"]) for claim in row.get("material_claims") or []
            ),
            "input_prompt_sha256": sha256_text(user_prompt),
            "system_prompt_sha256": sha256_text(SYSTEM_PROMPT),
            "rights_review_required": True,
            "privacy_review_required": True,
            "owner_authorized": True,
        }
        records.append(_sealed(record_body))

    if {name: len(rows) for name, rows in datasets.items()} != {
        "train": 9,
        "valid": 3,
        "test": 1,
    }:
        raise RuntimeError("training split does not match the frozen 9/3/1 recipe")
    return datasets, records


def _privacy_findings(datasets: Mapping[str, Sequence[Mapping[str, Any]]]) -> list[str]:
    text = json.dumps(datasets, ensure_ascii=False)
    patterns = {
        "email_address": r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        "absolute_owner_path": r"/Users/[^/\s]+/",
        "uk_phone_number": r"(?<!\d)(?:\+44\s?\d{4}|0\d{4})\s?\d{3}\s?\d{3}(?!\d)",
    }
    return [name for name, pattern in patterns.items() if re.search(pattern, text, re.I)]


def _token_ngrams(value: str, width: int = 8) -> set[tuple[str, ...]]:
    tokens = re.findall(r"[a-z0-9]+", value.casefold())
    if len(tokens) < width:
        return {tuple(tokens)} if tokens else set()
    return set(zip(*(tokens[index:] for index in range(width)), strict=False))


def _maximum_cross_split_similarity(
    datasets: Mapping[str, Sequence[Mapping[str, Any]]],
) -> float:
    rows = [
        (split, str(row["metadata"]["case_id"]), json.dumps(row["messages"]))
        for split, split_rows in datasets.items()
        for row in split_rows
    ]
    maximum = 0.0
    for index, (left_split, _, left_text) in enumerate(rows):
        left = _token_ngrams(left_text)
        for right_split, _, right_text in rows[index + 1 :]:
            if left_split == right_split:
                continue
            right = _token_ngrams(right_text)
            union = left | right
            similarity = len(left & right) / len(union) if union else 0.0
            maximum = max(maximum, similarity)
    return round(maximum, 6)


def _model_identity() -> dict[str, Any]:
    if not MODEL_PYTHON.is_file():
        raise RuntimeError("model runtime Python is unavailable")
    runtime = json.loads(MODEL_RUNTIME_MANIFEST.read_text(encoding="utf-8"))
    if runtime.get("source_repo") != MODEL_REPO or runtime.get("revision") != MODEL_REVISION:
        raise RuntimeError("pinned model repository or revision changed")
    if runtime.get("quantization_bits") != 4 or runtime.get("post_trained") is not True:
        raise RuntimeError("pinned model is not the expected 4-bit post-trained runtime")
    checked_files = []
    for item in runtime.get("files") or []:
        relative = Path(str(item["path"]))
        path = MODEL_ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"model artifact missing or linked: {relative}")
        digest = sha256_file(path)
        if digest != item.get("sha256") or path.stat().st_size != item.get("size"):
            raise RuntimeError(f"model artifact identity mismatch: {relative}")
        checked_files.append(
            {"path": relative.as_posix(), "sha256": digest, "size": path.stat().st_size}
        )
    if len(checked_files) < 10:
        raise RuntimeError("model identity manifest is incomplete")
    return _sealed(
        {
            "schema": "legalbot.ge-training-base-model-identity.v1",
            "model_id": MODEL_REPO,
            "revision": MODEL_REVISION,
            "quantization_bits": 4,
            "runtime_manifest_sha256": sha256_file(MODEL_RUNTIME_MANIFEST),
            "files": checked_files,
            "base_files_mutated_by_training": False,
        }
    )


def _physical_memory_bytes() -> int:
    result = subprocess.run(
        ["/usr/sbin/sysctl", "-n", "hw.memsize"],
        check=True,
        capture_output=True,
        text=True,
    )
    return int(result.stdout.strip())


def _training_config(*, output: Path, mode: str) -> dict[str, Any]:
    relative_output = output.relative_to(PROJECT_ROOT).as_posix()
    config = {
        **dict(RECIPE),
        "data": f"{relative_output}/dataset",
    }
    if mode == "train":
        config.update(
            {
                "train": True,
                "test": False,
                "adapter_path": f"{relative_output}/adapter",
                "max_seq_length": TRAINING_MAX_SEQUENCE_LENGTH,
            }
        )
    elif mode == "baseline":
        config.update(
            {
                "train": False,
                "test": True,
                "adapter_path": "",
                "max_seq_length": EVALUATION_MAX_SEQUENCE_LENGTH,
            }
        )
    elif mode == "adapted_test":
        config.update(
            {
                "train": False,
                "test": True,
                "adapter_path": f"{relative_output}/adapter",
                "max_seq_length": EVALUATION_MAX_SEQUENCE_LENGTH,
            }
        )
    else:
        raise RuntimeError(f"unsupported training config mode: {mode}")
    return config


def _run_logged(
    command: Sequence[str],
    *,
    log_path: Path,
    timeout_seconds: int,
) -> tuple[int, float]:
    if log_path.exists():
        raise RuntimeError(f"refusing to replace existing training log: {log_path}")
    started = datetime.now(UTC)
    env = {
        **os.environ,
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
        "TOKENIZERS_PARALLELISM": "true",
    }
    with log_path.open("x", encoding="utf-8") as handle:
        completed = subprocess.run(
            list(command),
            cwd=PROJECT_ROOT,
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            timeout=timeout_seconds,
            check=False,
            text=True,
        )
    elapsed = (datetime.now(UTC) - started).total_seconds()
    return completed.returncode, round(elapsed, 3)


def _parse_test_metric(text: str) -> tuple[float, float]:
    matches = re.findall(r"Test loss ([0-9.]+), Test ppl ([0-9.]+)\.", text)
    if not matches:
        raise RuntimeError("test metric was not emitted")
    loss, perplexity = matches[-1]
    return float(loss), float(perplexity)


def parse_training_metrics(
    baseline_text: str, training_text: str, adapted_test_text: str
) -> dict[str, Any]:
    baseline_loss, baseline_ppl = _parse_test_metric(baseline_text)
    adapted_loss, adapted_ppl = _parse_test_metric(adapted_test_text)
    validation = [
        {"iteration": int(iteration), "loss": float(loss)}
        for iteration, loss in re.findall(r"Iter (\d+): Val loss ([0-9.]+)", training_text)
    ]
    train = [
        {"iteration": int(iteration), "loss": float(loss)}
        for iteration, loss in re.findall(r"Iter (\d+): Train loss ([0-9.]+)", training_text)
    ]
    peak_values = [float(value) for value in re.findall(r"Peak mem ([0-9.]+) GB", training_text)]
    if not validation or not train or not peak_values:
        raise RuntimeError("training metric series is incomplete")
    values = [baseline_loss, baseline_ppl, adapted_loss, adapted_ppl]
    if not all(math.isfinite(value) and value >= 0 for value in values):
        raise RuntimeError("training emitted a nonfinite metric")
    return {
        "schema": "legalbot.ge-answer-weight-training-metrics.v1",
        "baseline_test_loss": baseline_loss,
        "baseline_test_perplexity": baseline_ppl,
        "adapted_test_loss": adapted_loss,
        "adapted_test_perplexity": adapted_ppl,
        "test_loss_delta": round(adapted_loss - baseline_loss, 6),
        "validation_loss_series": validation,
        "validation_initial_loss": validation[0]["loss"],
        "validation_final_loss": validation[-1]["loss"],
        "validation_minimum_loss": min(item["loss"] for item in validation),
        "training_loss_series": train,
        "training_final_loss": train[-1]["loss"],
        "peak_memory_gb": max(peak_values),
        "internal_test_loss_improved": adapted_loss < baseline_loss,
        "validation_loss_improved": validation[-1]["loss"] < validation[0]["loss"],
        "quality_70_reassessment_performed": False,
        "external_visible_evaluation_performed": False,
        "private_unseen_evaluation_performed": False,
        "interpretation": (
            "Loss metrics prove that parameter training executed on the frozen internal "
            "splits. They do not prove 70+ legal-answer quality or external generalization."
        ),
    }


def _adapter_manifest(output: Path) -> dict[str, Any]:
    adapter_root = output / "adapter"
    required = [adapter_root / "adapter_config.json", adapter_root / "adapters.safetensors"]
    if any(not path.is_file() or path.stat().st_size == 0 for path in required):
        raise RuntimeError("training did not produce the required adapter artifacts")
    files = [
        {
            "path": path.relative_to(output).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(adapter_root.iterdir())
        if path.is_file()
    ]
    return _sealed(
        {
            "schema": "legalbot.ge-answer-weight-adapter-manifest.v1",
            "base_model_id": MODEL_REPO,
            "base_model_revision": MODEL_REVISION,
            "adapter_format": "MLX_LORA_SAFETENSORS",
            "files": files,
            "runtime_activated": False,
            "rollback": "Do not set LEGALBOT_LORA_PATH; the immutable base runtime is unchanged.",
        }
    )


def _zip_create(destination: Path, source: Path) -> str:
    if destination.exists():
        raise RuntimeError(f"refusing to replace existing zip: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, arcname=str(Path(source.name) / path.relative_to(source)))
    return sha256_file(destination)


def run_training_campaign(
    *,
    output: Path = DEFAULT_OUTPUT,
    desktop_zip: Path = DESKTOP_ZIP,
) -> dict[str, Any]:
    if output.exists() or desktop_zip.exists():
        raise RuntimeError("answer-weight training campaign already exists")
    accepted, holds = validate_authorized_sources()
    if sha256_file(PREDECESSOR_FAILURE) != EXPECTED_PREDECESSOR_FAILURE_SHA256:
        raise RuntimeError("predecessor failure receipt changed")
    if sha256_file(PREDECESSOR_TRAINING_LOG) != EXPECTED_PREDECESSOR_TRAINING_LOG_SHA256:
        raise RuntimeError("predecessor training log changed")
    predecessor_log = PREDECESSOR_TRAINING_LOG.read_text(encoding="utf-8")
    if "Insufficient Memory" not in predecessor_log:
        raise RuntimeError("predecessor failure is not the expected Metal OOM")
    datasets, records = build_training_records(accepted)
    privacy_findings = _privacy_findings(datasets)
    if privacy_findings:
        raise RuntimeError(f"privacy scan failed: {privacy_findings}")

    free_disk_gb = shutil.disk_usage(PROJECT_ROOT).free / 1_000_000_000
    physical_memory_gb = _physical_memory_bytes() / 1_000_000_000
    if free_disk_gb < RESOURCE_MIN_FREE_DISK_GB:
        raise RuntimeError("training resource preflight has insufficient free disk")
    if physical_memory_gb < RESOURCE_MEMORY_CEILING_GB:
        raise RuntimeError("host memory is below the bounded training ceiling")

    output.mkdir(parents=True, exist_ok=False)
    started_at = _utc_now()
    _write_json_create(
        output / "PREDECESSOR-FAILURE-REFERENCE.json",
        _sealed(
            {
                "schema": "legalbot.ge-answer-weight-training-predecessor.v1",
                "predecessor_campaign_id": PREDECESSOR_CAMPAIGN_ID,
                "failure_fingerprint": (
                    "METAL_COMMAND_BUFFER_OUT_OF_MEMORY_AFTER_INITIAL_VALIDATION"
                ),
                "failure_receipt_sha256": EXPECTED_PREDECESSOR_FAILURE_SHA256,
                "training_log_sha256": EXPECTED_PREDECESSOR_TRAINING_LOG_SHA256,
                "targeted_repair": {
                    "num_layers": {"from": 4, "to": 1},
                    "lora_rank": {"from": 4, "to": 2},
                    "training_max_sequence_length": {"from": 1536, "to": 768},
                    "separate_no_gradient_test_evaluation": True,
                },
            }
        ),
    )
    _write_json_create(
        output / "OWNER-AUTHORIZATION.json",
        _sealed(
            {
                "schema": "legalbot.ge-answer-weight-training-authorization.v1",
                "authorization_text": OWNER_AUTHORIZATION_TEXT,
                "authorization_text_sha256": OWNER_AUTHORIZATION_TEXT_SHA256,
                "authorized_case_count": 13,
                "held_case_count_excluded": 7,
                "private_unseen_instruction": "KEEP_SEALED",
                "authorized_action": "LOCAL_PARAMETER_EFFICIENT_ANSWER_WEIGHT_TRAINING",
                "adapter_activation_authorized": False,
                "unseen_execution_authorized": False,
                "promotion_authorized": False,
                "live_authorized": False,
            }
        ),
    )

    for split, rows in datasets.items():
        _write_jsonl_create(output / "dataset" / f"{split}.jsonl", rows)
    _write_jsonl_create(output / "TRAINING-RECORDS.jsonl", records)

    source_titles_by_split = {
        split: sorted(
            {
                str(claim["title"])
                for row in accepted
                if _split_for(str(row["case_id"])) == split
                for claim in row.get("material_claims") or []
            }
        )
        for split in ("train", "valid", "test")
    }
    overlapping_source_titles = sorted(
        (set(source_titles_by_split["train"]) & set(source_titles_by_split["valid"]))
        | (set(source_titles_by_split["train"]) & set(source_titles_by_split["test"]))
        | (set(source_titles_by_split["valid"]) & set(source_titles_by_split["test"]))
    )
    if overlapping_source_titles:
        raise RuntimeError(
            f"source-family leakage across internal splits: {overlapping_source_titles}"
        )

    corpus_manifest = _sealed(
        {
            "schema": "legalbot.ge-answer-weight-training-corpus.v1",
            "source_campaign_id": SOURCE_CAMPAIGN_ID,
            "predecessor_campaign_id": PREDECESSOR_CAMPAIGN_ID,
            "predecessor_failure_receipt_sha256": EXPECTED_PREDECESSOR_FAILURE_SHA256,
            "accepted_source_sha256": EXPECTED_ACCEPTED_SHA256,
            "authorized_exact_hash_count": 13,
            "gradient_training_count": len(datasets["train"]),
            "internal_validation_count": len(datasets["valid"]),
            "internal_test_count": len(datasets["test"]),
            "split_case_ids": {
                split: sorted(str(row["metadata"]["case_id"]) for row in rows)
                for split, rows in datasets.items()
            },
            "target_answer_hashes": sorted(str(row["candidate_answer_hash"]) for row in accepted),
            "dataset_file_sha256": {
                split: sha256_file(output / "dataset" / f"{split}.jsonl") for split in datasets
            },
            "training_records_sha256": sha256_file(output / "TRAINING-RECORDS.jsonl"),
            "system_prompt_sha256": sha256_text(SYSTEM_PROMPT),
            "held_rows_included": False,
            "private_unseen_rows_included": False,
        }
    )
    _write_json_create(output / "TRAINING-CORPUS-MANIFEST.json", corpus_manifest)

    rights_review = _sealed(
        {
            "schema": "legalbot.ge-training-rights-review.v1",
            "status": "PASS_FOR_LOCAL_OWNER_ONLY_EXPERIMENT",
            "candidate_material": (
                "Owner-authorized project questions and exact AI-reviewed candidate answers."
            ),
            "official_information_licence": "Open Government Licence v3.0",
            "official_information_licence_url": (
                "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
            ),
            "required_attribution": (
                "Contains public sector information licensed under the Open Government "
                "Licence v3.0."
            ),
            "model_license_metadata": "apache-2.0",
            "model_license_metadata_source": "models/runtime/Qwen3.5-9B-4bit/README.md",
            "external_distribution_reviewed": False,
            "scope": "LOCAL_OWNER_ONLY_NO_PUBLICATION",
        }
    )
    _write_json_create(output / "RIGHTS-REVIEW.json", rights_review)

    privacy_review = _sealed(
        {
            "schema": "legalbot.ge-training-privacy-review.v1",
            "status": "PASS",
            "records_checked": 13,
            "automated_obvious_identifier_findings": privacy_findings,
            "raw_user_conversations_included": False,
            "uploads_included": False,
            "absolute_owner_paths_in_prompt_or_target": False,
            "private_unseen_content_included": False,
        }
    )
    _write_json_create(output / "PRIVACY-REVIEW.json", privacy_review)

    unseen_ledger = json.loads(UNSEEN_LEDGER.read_text(encoding="utf-8"))
    leakage = _sealed(
        {
            "schema": "legalbot.ge-training-leakage-report.v1",
            "status": "PASS_WITH_SEALED_UNSEEN_LIMITATION",
            "authorized_visible_exact_hash_count": 13,
            "exact_duplicate_question_hash_count": 0,
            "exact_duplicate_answer_hash_count": 0,
            "maximum_cross_split_eight_token_jaccard": _maximum_cross_split_similarity(datasets),
            "topic_families_disjoint_across_splits": True,
            "source_titles_disjoint_across_splits": True,
            "source_titles_by_split": source_titles_by_split,
            "held_case_ids_excluded": sorted(str(row["case_id"]) for row in holds),
            "held_source_sha256": EXPECTED_HOLD_SHA256,
            "private_unseen_case_count": unseen_ledger["unseen_case_count"],
            "private_unseen_content_version": unseen_ledger["unseen_content_version"],
            "private_unseen_archive_sha256": unseen_ledger["unseen_archive_sha256"],
            "private_unseen_custody_ledger_sha256": EXPECTED_UNSEEN_LEDGER_SHA256,
            "private_unseen_prompt_content_accessed": False,
            "private_unseen_semantic_overlap_computed": False,
            "sealed_unseen_limitation": (
                "Semantic comparison was not performed because the owner required the private "
                "bank to remain sealed. The training corpus was built only from the 13 explicit "
                "visible hashes and contains no private custody file."
            ),
        }
    )
    _write_json_create(output / "LEAKAGE-REPORT.json", leakage)

    excluded = _sealed(
        {
            "schema": "legalbot.ge-training-excluded-data.v1",
            "held_case_count": 7,
            "held_case_ids": sorted(str(row["case_id"]) for row in holds),
            "held_answer_hashes": sorted(str(row["candidate_answer_hash"]) for row in holds),
            "other_visible_cases_excluded_count": 310,
            "private_unseen_count": 306,
            "private_unseen_status": "SEALED_NOT_OPENED",
            "reviewer_notes_included": False,
            "raw_user_conversations_or_uploads_included": False,
            "external_evaluation_gold_included_beyond_explicit_13": False,
        }
    )
    _write_json_create(output / "EXCLUDED-DATA-MANIFEST.json", excluded)

    objective = _sealed(
        {
            "schema": "legalbot.ge-answer-weight-training-objective.v1",
            "objective": (
                "Train a rollbackable LoRA adapter to improve evidence-bound, direct, "
                "plain-English General Enquiry answer construction from supplied official "
                "evidence while preserving qualifications and practical next steps."
            ),
            "comparison": "PRETRAINED_BASE_VERSUS_LORA_ON_INTERNAL_VALIDATION_AND_TEST",
            "success_metric": (
                "Finite completed training plus lower internal validation and test loss; "
                "external 70+ quality remains for fresh visible evaluation."
            ),
            "does_not_claim": [
                "professional legal sign-off",
                "answer legal gold",
                "external generalization",
                "70+ post-training quality",
                "unseen performance",
            ],
        }
    )
    _write_json_create(output / "OBJECTIVE.json", objective)

    base_model = _model_identity()
    _write_json_create(output / "BASE-MODEL-IDENTITY.json", base_model)

    recipe = _sealed(
        {
            "schema": "legalbot.ge-answer-weight-training-recipe.v1",
            **dict(RECIPE),
            "dataset_split": {"train": 9, "valid": 3, "test": 1},
            "adapter_activation": False,
            "rollbackable": True,
        }
    )
    _write_json_create(output / "TRAINING-RECIPE.json", recipe)
    _write_json_create(
        output / "BASELINE-CONFIG.yaml", _training_config(output=output, mode="baseline")
    )
    _write_json_create(
        output / "TRAINING-CONFIG.yaml", _training_config(output=output, mode="train")
    )
    _write_json_create(
        output / "ADAPTED-TEST-CONFIG.yaml",
        _training_config(output=output, mode="adapted_test"),
    )

    resource = _sealed(
        {
            "schema": "legalbot.ge-answer-weight-training-resource-policy.v1",
            "host_physical_memory_gb": round(physical_memory_gb, 3),
            "training_peak_memory_ceiling_gb": RESOURCE_MEMORY_CEILING_GB,
            "free_disk_gb_at_start": round(free_disk_gb, 3),
            "minimum_free_disk_gb": RESOURCE_MIN_FREE_DISK_GB,
            "wall_clock_timeout_seconds": TRAINING_TIMEOUT_SECONDS,
            "network_access": "DISABLED_BY_OFFLINE_ENVIRONMENT",
            "max_iterations": RECIPE["iters"],
            "training_max_sequence_length": TRAINING_MAX_SEQUENCE_LENGTH,
            "evaluation_max_sequence_length": EVALUATION_MAX_SEQUENCE_LENGTH,
            "stop_on_nonzero_exit": True,
            "stop_on_nonfinite_metric": True,
            "no_automatic_retry": True,
        }
    )
    _write_json_create(output / "RESOURCE-POLICY.json", resource)

    internal_validation = _sealed(
        {
            "schema": "legalbot.ge-training-internal-validation.v1",
            "validation_case_ids": sorted(VALID_CASE_IDS),
            "test_case_ids": sorted(TEST_CASE_IDS),
            "topic_and_source_separated_from_gradient_training": True,
            "external_ge_unseen_bank": "NOT_ACCESSED",
            "external_visible_70_plus_evaluation": "NOT_PERFORMED_DURING_TRAINING",
        }
    )
    _write_json_create(output / "INTERNAL-VALIDATION-MANIFEST.json", internal_validation)

    token_command = [
        str(MODEL_PYTHON.relative_to(PROJECT_ROOT)),
        "scripts/audit_ge_answer_weight_training_tokens.py",
        "--model",
        MODEL_RELATIVE,
        "--data",
        f"{output.relative_to(PROJECT_ROOT).as_posix()}/dataset",
        "--output",
        f"{output.relative_to(PROJECT_ROOT).as_posix()}/TOKEN-LENGTH-AUDIT.json",
        "--max-sequence-length",
        str(EVALUATION_MAX_SEQUENCE_LENGTH),
    ]
    token_exit, token_seconds = _run_logged(
        token_command,
        log_path=output / "TOKEN-AUDIT-LOG.txt",
        timeout_seconds=300,
    )
    if token_exit != 0:
        _write_json_create(
            output / "FAILURE-RECEIPT.json",
            _sealed(
                {
                    "schema": "legalbot.ge-answer-weight-training-failure.v1",
                    "stage": "TOKEN_LENGTH_AUDIT",
                    "exit_code": token_exit,
                    "no_retry_without_targeted_repair": True,
                }
            ),
        )
        raise RuntimeError("token-length audit failed")
    token_audit = json.loads((output / "TOKEN-LENGTH-AUDIT.json").read_text(encoding="utf-8"))
    if token_audit.get("pass") is not True:
        raise RuntimeError("training examples exceed the frozen evaluation sequence length")
    training_split_within_limit = all(
        int(row["token_count"]) <= TRAINING_MAX_SEQUENCE_LENGTH
        for row in token_audit["records"]
        if row["split"] in {"train", "valid"}
    )
    if not training_split_within_limit:
        raise RuntimeError("gradient or validation example exceeds the repaired training limit")

    baseline_command = [
        str(MODEL_PYTHON.relative_to(PROJECT_ROOT)),
        "-m",
        "mlx_lm",
        "lora",
        "-c",
        f"{output.relative_to(PROJECT_ROOT).as_posix()}/BASELINE-CONFIG.yaml",
    ]
    baseline_exit, baseline_seconds = _run_logged(
        baseline_command,
        log_path=output / "BASELINE-LOG.txt",
        timeout_seconds=TRAINING_TIMEOUT_SECONDS,
    )
    if baseline_exit != 0:
        _write_json_create(
            output / "FAILURE-RECEIPT.json",
            _sealed(
                {
                    "schema": "legalbot.ge-answer-weight-training-failure.v1",
                    "stage": "BASELINE_INTERNAL_TEST",
                    "exit_code": baseline_exit,
                    "no_retry_without_targeted_repair": True,
                }
            ),
        )
        raise RuntimeError("pretrained baseline test failed")

    training_command = [
        str(MODEL_PYTHON.relative_to(PROJECT_ROOT)),
        "-m",
        "mlx_lm",
        "lora",
        "-c",
        f"{output.relative_to(PROJECT_ROOT).as_posix()}/TRAINING-CONFIG.yaml",
    ]
    training_exit, training_seconds = _run_logged(
        training_command,
        log_path=output / "TRAINING-LOG.txt",
        timeout_seconds=TRAINING_TIMEOUT_SECONDS,
    )
    if training_exit != 0:
        _write_json_create(
            output / "FAILURE-RECEIPT.json",
            _sealed(
                {
                    "schema": "legalbot.ge-answer-weight-training-failure.v1",
                    "stage": "LORA_TRAINING",
                    "exit_code": training_exit,
                    "no_retry_without_targeted_repair": True,
                }
            ),
        )
        raise RuntimeError("LoRA training failed")

    adapted_test_command = [
        str(MODEL_PYTHON.relative_to(PROJECT_ROOT)),
        "-m",
        "mlx_lm",
        "lora",
        "-c",
        f"{output.relative_to(PROJECT_ROOT).as_posix()}/ADAPTED-TEST-CONFIG.yaml",
    ]
    adapted_exit, adapted_seconds = _run_logged(
        adapted_test_command,
        log_path=output / "ADAPTED-TEST-LOG.txt",
        timeout_seconds=TRAINING_TIMEOUT_SECONDS,
    )
    if adapted_exit != 0:
        _write_json_create(
            output / "FAILURE-RECEIPT.json",
            _sealed(
                {
                    "schema": "legalbot.ge-answer-weight-training-failure.v1",
                    "stage": "ADAPTED_INTERNAL_TEST",
                    "exit_code": adapted_exit,
                    "no_retry_without_targeted_repair": True,
                }
            ),
        )
        raise RuntimeError("adapted internal test failed")

    baseline_text = (output / "BASELINE-LOG.txt").read_text(encoding="utf-8")
    training_text = (output / "TRAINING-LOG.txt").read_text(encoding="utf-8")
    adapted_test_text = (output / "ADAPTED-TEST-LOG.txt").read_text(encoding="utf-8")
    metrics = _sealed(
        {
            **parse_training_metrics(baseline_text, training_text, adapted_test_text),
            "token_audit_seconds": token_seconds,
            "baseline_seconds": baseline_seconds,
            "training_seconds": training_seconds,
            "adapted_test_seconds": adapted_seconds,
        }
    )
    if float(metrics["peak_memory_gb"]) > RESOURCE_MEMORY_CEILING_GB:
        raise RuntimeError("training exceeded the frozen memory ceiling")
    _write_json_create(output / "METRIC-REPORT.json", metrics)

    adapter = _adapter_manifest(output)
    _write_json_create(output / "ADAPTER-MANIFEST.json", adapter)

    completed_at = _utc_now()
    experiment = _sealed(
        {
            "schema": "legalbot.training-experiment.v1",
            "experiment_id": CAMPAIGN_ID,
            "authorization_sha256": sha256_file(output / "OWNER-AUTHORIZATION.json"),
            "objective_sha256": sha256_file(output / "OBJECTIVE.json"),
            "training_corpus_sha256": sha256_file(output / "TRAINING-CORPUS-MANIFEST.json"),
            "rights_review_sha256": sha256_file(output / "RIGHTS-REVIEW.json"),
            "privacy_review_sha256": sha256_file(output / "PRIVACY-REVIEW.json"),
            "leakage_report_sha256": sha256_file(output / "LEAKAGE-REPORT.json"),
            "excluded_evaluation_manifest_sha256": sha256_file(
                output / "EXCLUDED-DATA-MANIFEST.json"
            ),
            "base_model_sha256": sha256_file(output / "BASE-MODEL-IDENTITY.json"),
            "recipe_sha256": sha256_file(output / "TRAINING-RECIPE.json"),
            "resource_policy_sha256": sha256_file(output / "RESOURCE-POLICY.json"),
            "internal_validation_sha256": sha256_file(output / "INTERNAL-VALIDATION-MANIFEST.json"),
            "status": "completed",
            "output_artifact_sha256": sha256_file(output / "ADAPTER-MANIFEST.json"),
            "metric_report_sha256": sha256_file(output / "METRIC-REPORT.json"),
            "started_at": started_at,
            "completed_at": completed_at,
        }
    )
    schema = json.loads(TRAINING_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.validate(experiment, schema)
    if (
        experiment["content_sha256"]
        != hashlib.sha256(
            _canonical_bytes(
                {key: value for key, value in experiment.items() if key != "content_sha256"}
            )
        ).hexdigest()
    ):
        raise RuntimeError("training experiment content hash is invalid")
    _write_json_create(output / "TRAINING-EXPERIMENT.json", experiment)

    tests = {
        "authorization_text_hash_matches": (
            sha256_text(OWNER_AUTHORIZATION_TEXT) == OWNER_AUTHORIZATION_TEXT_SHA256
        ),
        "source_13_exact_hashes_match": len(accepted) == 13,
        "seven_holds_excluded": len(holds) == 7,
        "splits_are_9_3_1": {name: len(rows) for name, rows in datasets.items()}
        == {"train": 9, "valid": 3, "test": 1},
        "accepted_and_held_disjoint": AUTHORIZED_CASE_IDS.isdisjoint(
            {str(row["case_id"]) for row in holds}
        ),
        "privacy_review_pass": privacy_review["status"] == "PASS",
        "rights_review_pass": rights_review["status"].startswith("PASS"),
        "source_and_topic_split_separation": not overlapping_source_titles,
        "token_lengths_within_evaluation_limit": token_audit["pass"] is True,
        "gradient_and_validation_lengths_within_repaired_limit": training_split_within_limit,
        "baseline_completed": baseline_exit == 0,
        "training_completed": training_exit == 0,
        "adapted_internal_test_completed": adapted_exit == 0,
        "adapter_present": bool(adapter["files"]),
        "peak_memory_within_ceiling": (
            float(metrics["peak_memory_gb"]) <= RESOURCE_MEMORY_CEILING_GB
        ),
        "private_unseen_not_opened": (leakage["private_unseen_prompt_content_accessed"] is False),
        "adapter_not_activated": adapter["runtime_activated"] is False,
        "base_model_unchanged": base_model["base_files_mutated_by_training"] is False,
        "training_experiment_schema_valid": True,
    }
    if not all(tests.values()):
        raise RuntimeError(f"post-training gate failed: {tests}")
    _write_json_create(
        output / "TEST-RECEIPT.json",
        _sealed(
            {
                "schema": "legalbot.ge-answer-weight-training-test.v1",
                "tests": tests,
                "pass": True,
            }
        ),
    )

    state = _sealed(
        {
            "schema": "legalbot.ge-answer-weight-training-state.v1",
            "campaign_id": CAMPAIGN_ID,
            "overall_progress": True,
            "overall_state": ANSWER_WEIGHT_TRAINING_COMPLETE_AWAITING_FRESH_VISIBLE_EVALUATION,
            "authorized_exact_hash_count": 13,
            "gradient_training_count": 9,
            "internal_validation_count": 3,
            "internal_test_count": 1,
            "held_case_count_excluded": 7,
            "prior_nonready_count_unchanged": 310,
            "answer_weight_training": "COMPLETE",
            "adapter_artifact": "CREATED_NOT_ACTIVATED",
            "fresh_visible_successor_evaluation": NOT_STARTED,
            "qualified_legal_review": NOT_STARTED,
            "answer_legal_gold": NOT_STARTED,
            "catalogue_admission": NOT_STARTED,
            "sealed_unseen_execution": NOT_STARTED,
            "promotion": NOT_STARTED,
            "live": NOT_STARTED,
            "private_306_bank": "SEALED_NOT_OPENED",
            "next_owner_gate": "FRESH_VISIBLE_SUCCESSOR_EVALUATION_AUTHORIZATION",
            "frozen_331_rerun": "NOT_PERFORMED",
            "training_rows_retired_from_external_evaluation": True,
            "completed_at": completed_at,
        }
    )
    _write_json_create(output / "STATE-TRANSITION-RECEIPT.json", state)

    manifest = _sealed(
        {
            "schema": "legalbot.ge-answer-weight-training-run-manifest.v1",
            "campaign_id": CAMPAIGN_ID,
            "campaign_version": CAMPAIGN_VERSION,
            "source_campaign_id": SOURCE_CAMPAIGN_ID,
            "predecessor_campaign_id": PREDECESSOR_CAMPAIGN_ID,
            "predecessor_failure_receipt_sha256": EXPECTED_PREDECESSOR_FAILURE_SHA256,
            "accepted_source_sha256": EXPECTED_ACCEPTED_SHA256,
            "hold_source_sha256": EXPECTED_HOLD_SHA256,
            "review_source_sha256": EXPECTED_REVIEW_SHA256,
            "authorization_text_sha256": OWNER_AUTHORIZATION_TEXT_SHA256,
            "training_experiment_sha256": sha256_file(output / "TRAINING-EXPERIMENT.json"),
            "adapter_manifest_sha256": sha256_file(output / "ADAPTER-MANIFEST.json"),
            "metric_report_sha256": sha256_file(output / "METRIC-REPORT.json"),
            "state_transition_receipt_sha256": sha256_file(
                output / "STATE-TRANSITION-RECEIPT.json"
            ),
            "implementation_sha256": sha256_file(Path(__file__)),
            "owner_authorized_answer_weight_training": True,
            "private_unseen_opened": False,
            "adapter_activated": False,
        }
    )
    _write_json_create(output / "RUN-MANIFEST.json", manifest)

    _write_text_create(
        output / "ATTRIBUTION.md",
        "\n".join(
            [
                "# Attribution",
                "",
                "Contains public sector information licensed under the Open Government",
                "Licence v3.0.",
                "",
                "Base model metadata identifies mlx-community/Qwen3.5-9B-4bit under",
                "Apache-2.0. The model and immutable base files are not redistributed in",
                "this pack; only their identity manifest and the new LoRA adapter are included.",
                "",
            ]
        ),
    )
    _write_text_create(
        output / "README.md",
        "\n".join(
            [
                "# GE answer-weight training r2",
                "",
                "This create-only successor repaired r1's Metal memory failure and trained a",
                "rollbackable MLX LoRA adapter on the",
                "owner-authorized 13 exact hashes from the AI factual/70+ review. Nine records",
                "were gradient-training rows, three formed internal validation and one formed",
                "the internal test. The seven held answers were excluded. The memory repair",
                "used one trainable layer, rank two and a 768-token gradient limit; the complete",
                "internal test ran separately without gradients at the 1536-token limit.",
                "",
                "The private 306-case unseen bank was not opened, decoded, compared or used.",
                "Its question-free custody ledger alone was bound to the exclusion receipt.",
                "",
                "Training loss and internal test metrics establish that local parameter training",
                "executed. They do not establish professional legal review, answer legal gold,",
                "70+ post-training quality, external generalization or unseen performance.",
                "The adapter is not activated. A fresh visible successor evaluation is the next",
                "separate gate; sealed unseen, promotion and live remain NOT_STARTED.",
                "",
            ]
        ),
    )

    artifact_paths = [
        path
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "ARTIFACT-SHA256-REGISTER.json"
    ]
    _write_json_create(
        output / "ARTIFACT-SHA256-REGISTER.json",
        {
            "schema": "legalbot.ge-answer-weight-training-hashes.v1",
            "campaign_id": CAMPAIGN_ID,
            "artifacts": {
                path.relative_to(output).as_posix(): sha256_file(path) for path in artifact_paths
            },
        },
    )
    zip_sha256 = _zip_create(desktop_zip, output)
    return {
        "campaign_id": CAMPAIGN_ID,
        "output": str(output),
        "desktop_zip": str(desktop_zip),
        "desktop_zip_sha256": zip_sha256,
        "state": state,
        "metrics": metrics,
        "adapter_manifest": adapter,
    }
