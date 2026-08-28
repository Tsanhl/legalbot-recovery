#!/usr/bin/env python3
"""Validate an owner-bound Live60 issue tick. Mechanical exact-match only."""

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

from app.evaluation.live_suite_tick_draft import (  # noqa: E402
    apply_contrary_authority_status,
    bind_issue_tick,
    load_live60_bundle,
    load_repair_payload,
    load_tick_draft,
    summarize_tick_draft,
    write_json,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--catalog", type=Path)
    parser.add_argument("--repair", type=Path)
    parser.add_argument(
        "--draft",
        type=Path,
        default=PROJECT_ROOT / "Live60-2026-08-16" / "artifacts" / "issue-ticks-draft.json",
    )
    parser.add_argument("--progress", type=Path)
    parser.add_argument("--as-of-date", type=date.fromisoformat, default=date(2026, 8, 16))
    parser.add_argument("--case")
    parser.add_argument("--issue")
    parser.add_argument(
        "--status",
        choices=("knowledge_gap", "qualified", "limited"),
    )
    parser.add_argument("--chunk-id")
    parser.add_argument("--content-sha256")
    parser.add_argument("--locator")
    parser.add_argument("--source-version-id")
    parser.add_argument("--later-treatment")
    parser.add_argument("--gap-reason")
    parser.add_argument(
        "--contrary-authority",
        choices=("reviewed_none", "reviewed_and_bound", "blank"),
        help="Owner-flagged bulk contrary-authority tick for the draft only",
    )
    args = parser.parse_args()
    root = args.project_root.resolve()
    catalog = args.catalog or (root / "data" / "catalog.sqlite3")
    repair = load_repair_payload(
        args.repair
        or (root / "Live60-2026-08-16" / "artifacts" / "held-span-contiguous-repair-v2.json")
    )
    draft = load_tick_draft(args.draft, as_of_date=args.as_of_date.isoformat())
    bound = None
    if args.case or args.issue or args.status:
        if not (args.case and args.issue and args.status):
            raise SystemExit("--case, --issue and --status must be supplied together")
        span = None
        if args.chunk_id or args.content_sha256 or args.locator:
            if not (args.chunk_id and args.content_sha256 and args.locator):
                raise SystemExit(
                    "--chunk-id, --content-sha256 and --locator must be supplied together"
                )
            span = {
                "chunk_id": args.chunk_id,
                "content_sha256": args.content_sha256,
                "legal_locator": args.locator,
            }
            if args.source_version_id:
                span["source_version_id"] = args.source_version_id
        bound = bind_issue_tick(
            draft,
            bundle=load_live60_bundle(root),
            case_id=args.case,
            issue_id=args.issue,
            status=args.status,
            span=span,
            catalog_path=catalog if catalog.is_file() else None,
            repair=repair,
            later_treatment=args.later_treatment,
            gap_reason=args.gap_reason,
        )
    if args.contrary_authority:
        apply_contrary_authority_status(draft, status=args.contrary_authority)
    write_json(args.draft, draft)
    progress = summarize_tick_draft(draft)
    progress_path = args.progress or args.draft.with_name("owner-tick-progress.json")
    write_json(progress_path, progress)
    print(
        json.dumps(
            {
                "draft": str(args.draft.relative_to(root))
                if args.draft.is_relative_to(root)
                else args.draft.name,
                "progress": str(progress_path.relative_to(root))
                if progress_path.is_relative_to(root)
                else progress_path.name,
                "bound": bound,
                "progress_counts": progress,
            },
            indent=2,
            sort_keys=True,
            default=str,
        )
    )


if __name__ == "__main__":
    main()
