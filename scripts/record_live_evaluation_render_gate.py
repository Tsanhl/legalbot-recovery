#!/usr/bin/env python3
"""Record or verify the human-inspected Live60 DOCX render gate."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.evaluation.review_docx import (  # noqa: E402
    record_live60_render_gate,
    verify_live60_render_gate,
)

DOCUMENT_IDS = ("control", "annex-a", "annex-b", "annex-c")


def _page_number(path: Path) -> int:
    try:
        return int(path.stem.removeprefix("page-"))
    except ValueError as exc:
        raise SystemExit(f"invalid rendered page filename: {path.name}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify the existing immutable gate and all document/page digests",
    )
    parser.add_argument(
        "--inspector-ref",
        help="Opaque reviewer:<sha256> reference; names do not enter the artifact",
    )
    parser.add_argument(
        "--confirm-visually-inspected-all-pages",
        action="store_true",
        help="Required acknowledgement after opening every rendered PNG at 100% zoom",
    )
    args = parser.parse_args()

    if args.verify_only:
        gate = verify_live60_render_gate(args.output_dir)
        print(gate.seal_sha256)
        return
    if not args.confirm_visually_inspected_all_pages:
        raise SystemExit(
            "Refusing to record a pass: visually inspect every page and provide the "
            "explicit confirmation flag."
        )
    if not args.inspector_ref:
        raise SystemExit("--inspector-ref is required when recording the render gate")
    rendered_root = args.output_dir.resolve() / "rendered"
    page_sets = {
        document_id: tuple(
            sorted(
                (rendered_root / document_id).glob("page-*.png"),
                key=_page_number,
            )
        )
        for document_id in DOCUMENT_IDS
    }
    gate_path = record_live60_render_gate(
        output_dir=args.output_dir,
        rendered_pages=page_sets,
        inspector_ref=args.inspector_ref,
    )
    print(gate_path)


if __name__ == "__main__":
    main()
