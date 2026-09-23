#!/usr/bin/env python3
"""Read-only verification for the completed one-pass sealed-unseen run."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from app.evaluation.ge_sealed_unseen_codex_evaluation import verify_completed_campaign


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-root", type=Path)
    args = parser.parse_args()
    print(
        json.dumps(
            asdict(verify_completed_campaign(private_root=args.private_root)),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
