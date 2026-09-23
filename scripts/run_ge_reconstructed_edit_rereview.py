#!/usr/bin/env python3
"""Prepare or finalize changed-answer blind re-review and final QLR routing."""

from __future__ import annotations

import argparse
import json

from app.evaluation.ge_reconstructed_edit_rereview import finalize_campaign, prepare_campaign


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("prepare", "finalize"))
    args = parser.parse_args()
    result = prepare_campaign() if args.mode == "prepare" else finalize_campaign()
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
