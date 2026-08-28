#!/usr/bin/env python3
"""Create the dated Live60 owner expert-review pack. Does not seal legal gold."""

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

from app.evaluation.live_suite_owner_review import (  # noqa: E402
    prepare_live60_owner_review_pack,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--as-of-date", type=date.fromisoformat)
    parser.add_argument(
        "--index-build-id",
        default="candidate-pending-owner-review",
    )
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    result = prepare_live60_owner_review_pack(
        project_root=args.project_root.resolve(),
        as_of_date=args.as_of_date,
        index_build_id=args.index_build_id,
        overwrite=args.overwrite,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
