#!/usr/bin/env python3
"""Decide which unified-index sources must not be cited (owner decision 2026-09-25).

* The owner's own work (notes, drafts, formatives, exams, feedback) is never an
  authority: every Word/OpenDocument file in a citable lane, plus anything the
  title scan classed as ``student_work``, is excluded.
* Textbook chapters, lecture handouts and slide decks are not citable either;
  their knowledge is rephrased into the non-citable knowledge lane instead.
* Journal articles misfiled as primary authority are re-laned to scholarship.

Writes data/indexes/unified-local-v1/EXCLUSIONS.json; the catalogue is unchanged.
The retriever applies it at query time; ``index_unified_local.py
--apply-exclusions`` later removes excluded rows physically.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "data/indexes/unified-local-v1"
OWN_WORK_TYPES = ("wordprocessing", "opendocument")
SLIDE_TYPES = ("presentation",)

SQL = """
SELECT sv.id, d.lane, d.media_type FROM documents d
JOIN source_versions sv ON sv.document_id = d.id
WHERE d.duplicate_of IS NULL AND d.status = 'citable' AND sv.superseded_by IS NULL
  AND d.lane IN ('primary_authority', 'scholarship', 'official_secondary')
"""


def main() -> int:
    titles = json.loads((INDEX / "TITLES.json").read_text())["entries"]
    catalogue = sqlite3.connect(f"file:{ROOT / 'data/catalog.sqlite3'}?mode=ro", uri=True)
    decisions: dict[str, dict[str, str]] = {}
    for source_version_id, lane, media_type in catalogue.execute(SQL):
        kind = str((titles.get(source_version_id) or {}).get("kind") or "")
        action = None
        if any(part in media_type for part in OWN_WORK_TYPES) or kind == "student_work":
            action = "exclude_own_work"
        elif any(part in media_type for part in SLIDE_TYPES) or kind in {
            "lecture_material", "textbook_chapter",
        }:
            action = "exclude_to_knowledge_lane"
        elif lane == "primary_authority" and kind in {"article", "article_westlaw"}:
            action = "relane_scholarship"
        if action:
            decisions[source_version_id] = {"action": action, "lane": lane, "kind": kind or "untyped"}
    (INDEX / "EXCLUSIONS.json").write_text(json.dumps({
        "schema": "legalbot.unified-exclusions.v1",
        "created_at": datetime.now(UTC).isoformat(),
        "owner_decision": "2026-09-25: own work is never authority; textbooks and lectures "
                          "only as rephrased knowledge; articles cite as scholarship",
        "decisions": decisions,
    }, indent=1) + "\n")
    print(Counter(item["action"] for item in decisions.values()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
