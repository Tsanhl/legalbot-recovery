#!/usr/bin/env python3
"""Run the production, zero-query Frozen Retrieval v1.1 binding preflight."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.config import Settings  # noqa: E402
from app.retrieval.binding_preflight import run_binding_preflight, write_new_report  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    settings = Settings()
    output = args.output if args.output.is_absolute() else PROJECT_ROOT / args.output
    report = run_binding_preflight(settings, build_id=args.build_id)
    write_new_report(output, report)
    print(f"passed: {report['suite']['bound_row_count']}/24 bound; 0 retrieval queries")


if __name__ == "__main__":
    main()
