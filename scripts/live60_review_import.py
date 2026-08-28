#!/usr/bin/env python3
"""Wrapper: import owner-reviewed Live60 rows from a sealed export."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.evaluation.live_suite_path_b import import_reviewed_rows  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", required=True, type=Path)
    parser.add_argument("--reviewed", required=True, type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--repair", type=Path)
    parser.add_argument("--catalog", type=Path)
    args = parser.parse_args()
    repair = json.loads(args.repair.read_text(encoding="utf-8")) if args.repair else None
    result = import_reviewed_rows(
        project_root=PROJECT_ROOT,
        export_path=args.export,
        reviewed_path=args.reviewed,
        catalog_path=args.catalog,
        repair=repair,
    )
    if args.out:
        args.out.write_text(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps({key: value for key, value in result.items() if key != "rows"}, indent=2))


if __name__ == "__main__":
    main()
