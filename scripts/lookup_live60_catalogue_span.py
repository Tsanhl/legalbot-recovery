#!/usr/bin/env python3
"""Print copy-paste catalogue or repair-span identities. Does not seal gold."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.evaluation.live_suite_tick_draft import (  # noqa: E402
    load_repair_payload,
    lookup_catalogue_spans,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--catalog", type=Path)
    parser.add_argument("--repair", type=Path)
    parser.add_argument("--authority", required=True, help="Stable identity, e.g. ukpga:1980:58")
    parser.add_argument("--locator", required=True, help="Locator or substring, e.g. s 14A")
    args = parser.parse_args()
    root = args.project_root.resolve()
    catalog = args.catalog or (root / "data" / "catalog.sqlite3")
    repair = load_repair_payload(
        args.repair
        or (root / "Live60-2026-08-16" / "artifacts" / "held-span-contiguous-repair-v2.json")
    )
    result = lookup_catalogue_spans(
        catalog_path=catalog,
        authority_identity_id=args.authority,
        locator=args.locator,
        repair=repair,
    )
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main()
