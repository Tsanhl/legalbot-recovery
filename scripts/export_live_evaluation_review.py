#!/usr/bin/env python3
"""Export strict Word review artifacts for a completed local live run."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.crypto import LocalCipher  # noqa: E402
from backend.app.evaluation.review_docx import (  # noqa: E402
    ReviewExportError,
    export_live60_review_bundle,
    export_live_review_docx,
    verify_live60_render_gate,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True, help="Safe live-evaluation run ID")
    parser.add_argument(
        "--project-root",
        type=Path,
        default=PROJECT_ROOT,
        help="LegalBot-New project root (defaults to this checkout)",
    )
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument(
        "--output",
        type=Path,
        help="Legacy Live30 destination .docx path",
    )
    output.add_argument(
        "--output-dir",
        type=Path,
        help="Live60 bundle directory for one control, three annexes and manifest",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing destination only after all input gates pass",
    )
    args = parser.parse_args()

    project_root = args.project_root.resolve()
    run_dir = project_root / "data" / "evaluations" / "e2e" / "runs" / args.run_id
    cipher = LocalCipher.from_local_key(create=False)
    if args.output_dir is not None:
        manifest = export_live60_review_bundle(
            run_dir=run_dir,
            output_dir=args.output_dir,
            cipher=cipher,
            overwrite=args.overwrite,
        )
        # This deliberately fails until the four DOCX files have been rendered
        # and a human-inspected render-gate artifact has been recorded.
        try:
            verify_live60_render_gate(args.output_dir)
        except ReviewExportError:
            print(f"{manifest} (render gate pending)")
        else:
            print(f"{manifest} (render gate verified)")
    else:
        exported = export_live_review_docx(
            run_dir=run_dir,
            output_path=args.output,
            cipher=cipher,
            require_complete=True,
            overwrite=args.overwrite,
        )
        print(exported)


if __name__ == "__main__":
    main()
