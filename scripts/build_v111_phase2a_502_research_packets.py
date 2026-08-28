#!/usr/bin/env python3
"""Build create-only lexical research packets for the unresolved 502 rows."""

from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path

from app.evaluation.phase2a_research_packets import build_research_packets


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--remaining-inventory", type=Path, required=True)
    parser.add_argument("--approved-35", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--catalogue", type=Path, required=True)
    parser.add_argument("--target-date", type=date.fromisoformat, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--candidate-limit", type=int, default=8)
    args = parser.parse_args()
    result = build_research_packets(
        remaining_inventory_path=args.remaining_inventory,
        approved_35_path=args.approved_35,
        cases_path=args.cases,
        candidate_manifest_path=args.candidate_manifest,
        catalogue_path=args.catalogue,
        target_date=args.target_date,
        output_root=args.output_root,
        candidate_limit=args.candidate_limit,
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "row_count": result["row_count"],
                "source_authority_count": result["source_authority_count"],
                "source_span_group_count": result["source_span_group_count"],
                "artifact_content_sha256": result["artifact_content_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
