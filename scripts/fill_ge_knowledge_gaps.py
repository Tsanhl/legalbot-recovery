#!/usr/bin/env python3
"""Create-only official-source fill for GE knowledge gaps.

Fetches only allowlisted legislation.gov.uk / Find Case Law bytes, keeps
locator-bound factual chunks, and writes an evaluation sidecar. Does not
mutate catalog.sqlite3, ACTIVE indexes, gold, or admission flags.
Wrong-route quotations are recorded, not indexed as authority.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.evaluation.ge_factual_gap_fill import (  # noqa: E402
    existing_titles,
    fill_gaps,
    latest_visible_results,
    next_output_pack,
    remaining_fetchable_titles,
    scan_results,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results",
        type=Path,
        default=None,
        help="Path to visible RESULTS.jsonl. Defaults to the latest diagnostic pack.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Create-only output pack. Defaults to the next factual-gap-fill rN.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and report remaining official titles without fetching.",
    )
    args = parser.parse_args()
    results = args.results or latest_visible_results(ROOT)
    if results is None or not results.is_file():
        print("No GE visible RESULTS.jsonl found.", file=sys.stderr)
        return 2
    already = existing_titles(project_root=ROOT)
    remaining = remaining_fetchable_titles(results_path=results, already=already)
    scanned = scan_results(results)
    if args.dry_run or not remaining:
        print(
            json.dumps(
                {
                    "results": str(results),
                    "missing_declared": len(scanned.get("missing") or []),
                    "wrong_routes": len(scanned.get("wrong_routes") or []),
                    "already_titled": len(already),
                    "remaining_fetchable": remaining,
                    "fetched": False if not remaining and not args.dry_run else None,
                    "live_catalogue_insert": False,
                    "legal_gold": False,
                    "admitted": False,
                },
                indent=2,
            )
        )
        return 0
    output = args.output or next_output_pack(ROOT)
    manifest = fill_gaps(
        results_path=results,
        output=output,
        already_titled=already,
        project_root=ROOT,
    )
    print(
        json.dumps(
            {
                "output": str(output),
                "ingested_count": manifest.get("ingested_count"),
                "failed_count": manifest.get("failed_count"),
                "skipped_count": manifest.get("skipped_count"),
                "wrong_route_count": manifest.get("wrong_route_count"),
                "admitted": False,
                "legal_gold": False,
                "live_catalogue_insert": False,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
