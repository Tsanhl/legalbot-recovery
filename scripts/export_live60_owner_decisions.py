#!/usr/bin/env python3
"""Export Live60 owner-decision packs. Does not seal gold or promote ACTIVE."""

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

from app.evaluation.live_suite_owner_decisions import (  # noqa: E402
    default_official_fetcher,
    export_owner_decision_artifacts,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--as-of-date", type=date.fromisoformat, default=date(2026, 8, 16))
    parser.add_argument("--catalog", type=Path)
    parser.add_argument("--skip-official-fetch", action="store_true")
    parser.add_argument("--no-desktop-copy", action="store_true")
    args = parser.parse_args()
    result = export_owner_decision_artifacts(
        project_root=args.project_root.resolve(),
        as_of_date=args.as_of_date,
        catalog_path=args.catalog,
        fetch_official=None if args.skip_official_fetch else default_official_fetcher,
        copy_desktop=not args.no_desktop_copy,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
