#!/usr/bin/env python3
"""Prepare, blind, or finalize the fresh visible r2-adapter evaluation."""

from __future__ import annotations

import argparse
import json

from app.evaluation.ge_fresh_visible_adapter_evaluation import (
    build_blind_workbook,
    finalize_campaign,
    prepare_campaign,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("prepare", "blind", "finalize"))
    args = parser.parse_args()
    if args.stage == "prepare":
        result = prepare_campaign()
    elif args.stage == "blind":
        result = build_blind_workbook()
    else:
        result = finalize_campaign()
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
