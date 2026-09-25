#!/usr/bin/env python3
"""Build search indexes on the finished unified local index.

Run once after ``build_unified_local_index.py`` completes (and again after any
later incremental embedding). Adds, per lane table:

* a BM25 full-text index on ``text`` for exact names and section numbers
  (the retriever fuses it with vector search), and
* an IVF-PQ vector index so vector search does not scan every row.

Refuses to run until the builder has written ``MANIFEST.json``.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from datetime import UTC, datetime
from pathlib import Path

import lancedb

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "data/indexes/unified-local-v1"
# IVF-PQ needs enough rows per partition to train; smaller tables stay flat.
MIN_ROWS_FOR_ANN = 20_000


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", type=Path, default=INDEX)
    parser.add_argument(
        "--apply-exclusions", action="store_true",
        help="Physically remove excluded rows and re-lane misfiled articles first",
    )
    args = parser.parse_args()
    manifest_path = args.index / "MANIFEST.json"
    if not manifest_path.is_file():
        print("Embedding has not finished (no MANIFEST.json); not indexing.", file=sys.stderr)
        return 2
    db = lancedb.connect(str(args.index / "lance"))
    report: dict[str, dict[str, object]] = {}
    if args.apply_exclusions:
        decisions = json.loads((args.index / "EXCLUSIONS.json").read_text())["decisions"]
        removed = [key for key, item in decisions.items() if item["action"].startswith("exclude")]
        relaned = [key for key, item in decisions.items() if item["action"] == "relane_scholarship"]
        for name in db.table_names():
            table = db.open_table(name)
            for batch in range(0, len(removed), 200):
                ids = ", ".join(f"'{key}'" for key in removed[batch:batch + 200])
                table.delete(f"source_version_id IN ({ids})")
            for batch in range(0, len(relaned), 200):
                ids = ", ".join(f"'{key}'" for key in relaned[batch:batch + 200])
                table.update(where=f"source_version_id IN ({ids})", values={"lane": "scholarship"})
        print(f"removed {len(removed)} sources, re-laned {len(relaned)}", flush=True)
    for name in db.table_names():
        table = db.open_table(name)
        rows = table.count_rows()
        table.create_fts_index("text", use_tantivy=False, replace=True)
        entry: dict[str, object] = {"rows": rows, "fts": True, "ann": False}
        if rows >= MIN_ROWS_FOR_ANN:
            partitions = max(16, int(math.sqrt(rows)))
            table.create_index(
                vector_column_name="vector",
                num_partitions=partitions,
                num_sub_vectors=64,
                replace=True,
            )
            entry.update({"ann": True, "num_partitions": partitions})
        report[name] = entry
        print(name, entry, flush=True)
    manifest = json.loads(manifest_path.read_text())
    manifest["search_indexes"] = {"built_at": datetime.now(UTC).isoformat(), "tables": report}
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
