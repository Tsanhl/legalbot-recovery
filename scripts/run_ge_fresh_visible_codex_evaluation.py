#!/usr/bin/env python3
"""Prepare, record, blind, or finalize the fresh visible Codex evaluation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.evaluation.ge_currentness_packets import load_jsonl
from app.evaluation.ge_fresh_visible_codex_evaluation import (
    build_blind_workbook,
    finalize_campaign,
    prepare_campaign,
    record_codex_answers,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("prepare", "record-codex", "blind", "finalize"))
    parser.add_argument("--answers", type=Path)
    args = parser.parse_args()
    if args.stage == "prepare":
        result = prepare_campaign()
    elif args.stage == "record-codex":
        if args.answers is None:
            parser.error("record-codex requires --answers")
        rows = load_jsonl(args.answers)
        result = record_codex_answers(
            {str(row["case_id"]): str(row["candidate_answer"]) for row in rows}
        )
    elif args.stage == "blind":
        result = build_blind_workbook()
    else:
        result = finalize_campaign()
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
