#!/usr/bin/env python3
"""Wrapper: export sealed Live60 candidate review rows."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.crypto import LocalCipher  # noqa: E402
from app.evaluation.live_suite_path_b import export_review_candidates  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--as-of-date", type=date.fromisoformat, default=date(2026, 8, 16))
    parser.add_argument("--ticks", type=Path)
    args = parser.parse_args()
    ticks = json.loads(args.ticks.read_text(encoding="utf-8")) if args.ticks else None
    result = export_review_candidates(
        project_root=PROJECT_ROOT,
        destination=args.out,
        cipher=LocalCipher.from_local_key(create=True),
        as_of_date=args.as_of_date,
        ticks=ticks,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
