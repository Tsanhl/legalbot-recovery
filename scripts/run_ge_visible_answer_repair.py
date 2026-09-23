#!/usr/bin/env python3
"""Prepare or finalize the bounded GE visible answer repair."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.evaluation.ge_currentness_packets import load_jsonl
from app.evaluation.ge_visible_answer_repair import finalize_campaign, prepare_campaign


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("prepare", "finalize"))
    parser.add_argument("--answers", type=Path)
    args = parser.parse_args()
    if args.stage == "prepare":
        if args.answers is None:
            parser.error("prepare requires --answers")
        answer_rows = load_jsonl(args.answers)
        answers = {row["case_id"]: row["repaired_answer"] for row in answer_rows}
        result = prepare_campaign(answers)
    else:
        result = finalize_campaign()
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
