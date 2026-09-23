#!/usr/bin/env python3
"""Run the owner-authorized 13-hash GE LoRA training experiment."""

from __future__ import annotations

import json

from app.evaluation.ge_answer_weight_training import run_training_campaign


def main() -> int:
    result = run_training_campaign()
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
