#!/usr/bin/env python3
"""Apply a filled Live60 owner RETURN/HOLD pack. Does not seal gold or authorise generation."""

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

from app.evaluation.live_suite_owner_review import apply_owner_return_hold  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--filled-workbook", type=Path, required=True)
    parser.add_argument("--filled-checklist", type=Path, required=True)
    parser.add_argument("--as-of-date", type=date.fromisoformat)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    result = apply_owner_return_hold(
        project_root=args.project_root.resolve(),
        filled_workbook=args.filled_workbook.resolve(),
        filled_checklist=args.filled_checklist.resolve(),
        as_of_date=args.as_of_date,
        overwrite=args.overwrite,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
