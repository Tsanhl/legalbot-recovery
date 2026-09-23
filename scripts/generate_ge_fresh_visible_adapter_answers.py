#!/usr/bin/env python3
"""Generate one exact base or r2-adapter answer set for fresh visible review."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GE_ROOT = PROJECT_ROOT / "data/evaluations/general-enquiries"
DEFAULT_OUTPUT = GE_ROOT / "LegalBot-GE-2026-09-04-fresh-visible-adapter-evaluation-r2"
MODEL_PATH = PROJECT_ROOT / "models/runtime/Qwen3.5-9B-4bit"
TRAINING_ROOT = GE_ROOT / "LegalBot-GE-2026-09-04-answer-weight-training-r2"
TRAINING_RECORDS = TRAINING_ROOT / "TRAINING-RECORDS.jsonl"
ADAPTER_PATH = TRAINING_ROOT / "adapter"
EXPECTED_ADAPTER_SHA256 = "228a79524282bcbf708e43a8324da0295c9717c8aa8eefdd328b4b0f8262c298"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _sealed(payload: dict[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result["content_sha256"] = hashlib.sha256(_canonical_json(result)).hexdigest()
    return result


def _clean_generation(text: str) -> tuple[str, bool]:
    original = text
    text = re.sub(r"^\s*<think>.*?</think>\s*", "", text, flags=re.DOTALL)
    text = text.split("<|im_end|>", 1)[0].strip()
    return text, text != original.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=("base", "adapter"), required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--max-tokens", type=int, default=320)
    args = parser.parse_args()

    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    from mlx import core as mx  # type: ignore[import-not-found]
    from mlx_lm import generate, load  # type: ignore[import-not-found]
    from mlx_lm.sample_utils import make_sampler  # type: ignore[import-not-found]

    variant = "BASE" if args.variant == "base" else "R2_ADAPTER"
    filename = "BASE-OUTPUTS.jsonl" if variant == "BASE" else "R2-ADAPTER-OUTPUTS.jsonl"
    receipt_name = (
        "BASE-GENERATION-RECEIPT.json"
        if variant == "BASE"
        else "R2-ADAPTER-GENERATION-RECEIPT.json"
    )
    output_path = args.output / filename
    receipt_path = args.output / receipt_name
    if output_path.exists() or receipt_path.exists():
        raise RuntimeError(f"refusing to replace {variant} generation")
    if not MODEL_PATH.is_dir():
        raise RuntimeError("pinned local model is absent")
    adapter_path: str | None = None
    if variant == "R2_ADAPTER":
        adapter_file = ADAPTER_PATH / "adapters.safetensors"
        if sha256_file(adapter_file) != EXPECTED_ADAPTER_SHA256:
            raise RuntimeError("r2 adapter hash changed")
        adapter_path = str(ADAPTER_PATH)

    inputs = load_jsonl(args.output / "MODEL-INPUTS.jsonl")
    if len(inputs) != 23:
        raise RuntimeError("fresh visible input count is not 23")
    started = time.monotonic()
    model, tokenizer = load(
        str(MODEL_PATH),
        adapter_path=adapter_path,
        lazy=False,
    )
    mx.eval(model.parameters())
    mx.reset_peak_memory()
    sampler = make_sampler(temp=0.0)
    rows: list[dict[str, Any]] = []
    with output_path.open("x", encoding="utf-8") as handle:
        for record in inputs:
            prompt = tokenizer.apply_chat_template(
                record["messages"],
                tokenize=False,
                add_generation_prompt=True,
                enable_thinking=False,
            )
            prompt_tokens = len(tokenizer.encode(prompt))
            case_started = time.monotonic()
            raw = generate(
                model,
                tokenizer,
                prompt=prompt,
                max_tokens=args.max_tokens,
                sampler=sampler,
                verbose=False,
            )
            candidate, reasoning_markup_removed = _clean_generation(raw)
            if not candidate:
                raise RuntimeError(f"empty generation: {record['case_id']}")
            output_tokens = len(tokenizer.encode(candidate))
            row = _sealed(
                {
                    "schema": "legalbot.ge-fresh-visible-candidate-output.v1",
                    "ordinal": record["ordinal"],
                    "case_id": record["case_id"],
                    "question_hash": record["question_hash"],
                    "input_hash": record["input_hash"],
                    "candidate_variant": variant,
                    "candidate_answer": candidate,
                    "candidate_answer_hash": sha256_text(candidate),
                    "raw_generation_sha256": sha256_text(raw),
                    "reasoning_markup_removed": reasoning_markup_removed,
                    "prompt_token_count": prompt_tokens,
                    "output_token_count": output_tokens,
                    "generation_seconds": round(time.monotonic() - case_started, 3),
                    "max_tokens": args.max_tokens,
                    "greedy_temperature": 0.0,
                }
            )
            rows.append(row)
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            print(
                f"{variant} {record['ordinal']:02d}/23 {record['case_id']} "
                f"tokens={output_tokens} seconds={row['generation_seconds']}",
                flush=True,
            )
    if len({row["candidate_answer_hash"] for row in rows}) != 23:
        raise RuntimeError(f"{variant} produced duplicate exact answers")
    trained_hashes = {row["target_answer_hash"] for row in load_jsonl(TRAINING_RECORDS)}
    if trained_hashes & {row["candidate_answer_hash"] for row in rows}:
        raise RuntimeError(f"{variant} output exactly duplicates a training target")
    receipt = _sealed(
        {
            "schema": "legalbot.ge-fresh-visible-generation-receipt.v1",
            "candidate_variant": variant,
            "case_count": len(rows),
            "model_id": "mlx-community/Qwen3.5-9B-4bit",
            "model_revision": "8b2b98c00a6b4d291155e4890773ca8f769aee53",
            "adapter_sha256": EXPECTED_ADAPTER_SHA256 if adapter_path else "",
            "adapter_loaded_for_isolated_evaluation": adapter_path is not None,
            "adapter_runtime_activated": False,
            "private_unseen_prompt_content_accessed": False,
            "generation_seconds": round(time.monotonic() - started, 3),
            "peak_memory_gb": round(mx.get_peak_memory() / 1_000_000_000, 3),
            "output_sha256": sha256_file(output_path),
            "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
    )
    with receipt_path.open("x", encoding="utf-8") as handle:
        json.dump(receipt, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
