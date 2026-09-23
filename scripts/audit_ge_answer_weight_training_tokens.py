#!/usr/bin/env python3
"""Audit MLX chat-template token lengths without emitting prompt content."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--data", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-sequence-length", required=True, type=int)
    args = parser.parse_args()

    from transformers import AutoTokenizer

    model = Path(args.model)
    data = Path(args.data)
    output = Path(args.output)
    if output.exists():
        raise RuntimeError(f"refusing to replace token audit: {output}")
    tokenizer = AutoTokenizer.from_pretrained(  # type: ignore[no-untyped-call]
        model,
        local_files_only=True,
        trust_remote_code=True,
    )
    rows: list[dict[str, Any]] = []
    dataset_hashes: dict[str, str] = {}
    for split in ("train", "valid", "test"):
        path = data / f"{split}.jsonl"
        dataset_hashes[split] = sha256_file(path)
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            case_id = str(record["metadata"]["case_id"])
            tokens = tokenizer.apply_chat_template(record["messages"], return_dict=False)
            rows.append({"case_id": case_id, "split": split, "token_count": len(tokens)})
    maximum = max(row["token_count"] for row in rows)
    result = {
        "schema": "legalbot.ge-answer-weight-training-token-audit.v1",
        "record_count": len(rows),
        "maximum_token_count": maximum,
        "max_sequence_length": args.max_sequence_length,
        "truncated_record_count": sum(
            row["token_count"] > args.max_sequence_length for row in rows
        ),
        "records": rows,
        "dataset_file_sha256": dataset_hashes,
        "prompt_content_emitted": False,
        "pass": maximum <= args.max_sequence_length and len(rows) == 13,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
