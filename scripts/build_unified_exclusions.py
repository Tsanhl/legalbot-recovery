#!/usr/bin/env python3
"""Decide which unified-index sources may be cited (owner decisions 2026-09-25).

Only four source types may ever be cited: legislation, case law, journal
articles and books. Everything else is excluded from answers:

* the owner's own work (Word/OpenDocument files in citable lanes, and anything
  the title scan classed as ``student_work``);
* teaching material of any kind (seminars, lectures, tutorials, handouts,
  slides, module guides, exams and revision material), whose knowledge enters
  only through the law-only knowledge lane;
* other types (official guidance, reports, web pages and similar);
* unidentified sources, which are held until they are titled and classified.

Journal articles misfiled as primary authority are re-laned to scholarship.

Writes data/indexes/unified-local-v1/EXCLUSIONS.json; the catalogue is unchanged.
The retriever applies it at query time. Re-run it after titling or verification
to release newly identified sources.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "data/indexes/unified-local-v1"
OWN_WORK_TYPES = ("wordprocessing", "opendocument")
SLIDE_TYPES = ("presentation",)
CITABLE_TYPES = frozenset({"legislation", "case", "journal", "book"})
TEACHING = re.compile(
    r"\b(seminar|lecture|tutorial|handout|workshop|slides?|module (guide|handbook)|handbook|"
    r"reading list|formative|summative|exam (paper|question)s?|examination paper|past paper|revision|week \d+|coursework|"
    r"marking scheme|assessment criteria|problem question|essay question|study guide)\b",
    re.IGNORECASE,
)
LEGISLATION = re.compile(
    r"\b(Act|Regulations?|Order|Rules|Directive|Regulation \((EU|EC)\)|Treaty|Convention|"
    r"Statutory Instrument)\b( \d{4})?", re.IGNORECASE,
)
CASE = re.compile(r"\s v\.? |\[\d{4}\] [A-Z]|\bRe [A-Z]|\bCase C[-‑]\d+/\d+|\bEx p(arte)?\b")

SQL = """
SELECT sv.id, d.lane, d.media_type, coalesce(sv.title, '') FROM documents d
JOIN source_versions sv ON sv.document_id = d.id
WHERE d.duplicate_of IS NULL AND d.status = 'citable' AND sv.superseded_by IS NULL
  AND d.lane IN ('primary_authority', 'scholarship', 'official_secondary')
"""


def source_type(title: str, lane: str, kind: str, verified_kind: str) -> str:
    """legislation | case | journal | book | teaching | own_work | other | unknown."""

    if kind == "student_work":
        return "own_work"
    if kind == "lecture_material" or TEACHING.search(title):
        return "teaching"
    if verified_kind in {"legislation", "legislation_title_match"}:
        return "legislation"
    if verified_kind in {"judgment", "judgment_title_match"}:
        return "case"
    if kind == "legislation":
        return "legislation"
    if kind == "case":
        return "case"
    if kind in {"article", "article_westlaw"}:
        return "journal"
    if kind == "textbook_chapter":
        return "book"
    untitled = not title or re.match(r"source-[0-9a-f]+\.", title)
    if untitled or kind == "unknown":
        return "unknown"
    if lane == "primary_authority":
        if CASE.search(title):
            return "case"
        if LEGISLATION.search(title):
            return "legislation"
        return "unknown"
    if lane == "scholarship":
        return "journal"
    return "other"  # official guidance, reports, web pages: not on the owner's list


def main() -> int:
    titles = json.loads((INDEX / "TITLES.json").read_text())["entries"]
    ledger_path = INDEX / "VERIFICATION.json"
    verified = json.loads(ledger_path.read_text())["entries"] if ledger_path.is_file() else {}
    catalogue = sqlite3.connect(f"file:{ROOT / 'data/catalog.sqlite3'}?mode=ro", uri=True)
    decisions: dict[str, dict[str, str]] = {}
    types: Counter[str] = Counter()
    for source_version_id, lane, media_type, catalogue_title in catalogue.execute(SQL):
        entry = titles.get(source_version_id) or {}
        kind = str(entry.get("kind") or "")
        title = str(entry.get("title") or catalogue_title or "")
        verified_kind = str((verified.get(source_version_id) or {}).get("kind") or "")
        if any(part in media_type for part in OWN_WORK_TYPES):
            kind = "student_work"
        if any(part in media_type for part in SLIDE_TYPES):
            kind = "lecture_material"
        stype = source_type(title, lane, kind, verified_kind)
        types[stype] += 1
        action = {
            "own_work": "exclude_own_work",
            "teaching": "exclude_teaching_material",
            "other": "exclude_not_citable_type",
            "unknown": "hold_unidentified",
        }.get(stype)
        if action is None and lane == "primary_authority" and stype in {"journal", "book"}:
            action = "relane_scholarship"
        if action:
            decisions[source_version_id] = {
                "action": action, "lane": lane, "kind": kind or "untyped", "source_type": stype,
            }
    (INDEX / "EXCLUSIONS.json").write_text(json.dumps({
        "schema": "legalbot.unified-exclusions.v2",
        "created_at": datetime.now(UTC).isoformat(),
        "owner_decision": "2026-09-25: only legislation, case law, journal articles and books "
                          "may be cited; teaching material and the owner's own work never",
        "citable_types": sorted(CITABLE_TYPES),
        "source_types": dict(types),
        "decisions": decisions,
    }, indent=1) + "\n")
    print("source types:", dict(types))
    print("actions:", Counter(item["action"] for item in decisions.values()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
