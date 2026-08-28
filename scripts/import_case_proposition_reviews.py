#!/usr/bin/env python3
"""Validate and materialise a sealed case-proposition review manifest.

Dry-run is the default.  ``--apply`` updates only derived chunk metadata and
records an immutable, privacy-safe audit artifact.  It does not alter raw
sources, canonical Markdown, source approval, indexes or ACTIVE/PREVIOUS.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.case_proposition_reviews import (  # noqa: E402
    immutable_import_report,
    load_case_review_manifest,
    materialise_case_proposition_reviews,
    write_immutable_import_report,
)
from backend.app.config import Settings  # noqa: E402
from backend.app.db import Database  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--report-dir",
        type=Path,
        help="Override the default local review-queue audit directory",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    project_root = args.project_root.resolve()
    settings = Settings(project_root=project_root)
    manifest = load_case_review_manifest(args.manifest.resolve())
    database = Database(settings.database_path)
    database.initialize()
    try:
        report = materialise_case_proposition_reviews(database, manifest, apply=args.apply)
    finally:
        database.close()

    if args.apply:
        report_dir = (
            args.report_dir.resolve()
            if args.report_dir is not None
            else settings.data_dir / "review_queue" / "case-proposition-review-imports"
        )
        report_path = report_dir / f"{manifest.seal_sha256}.json"
        write_immutable_import_report(report_path, immutable_import_report(report))
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
