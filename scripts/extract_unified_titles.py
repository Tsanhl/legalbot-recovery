#!/usr/bin/env python3
"""Recover display titles for untitled catalogue sources (filenames were stripped).

Reads the first body chunks of every citable source whose catalogue title is a
``source-<hash>.<ext>`` placeholder and writes a sidecar map; the catalogue is
not modified. Each entry also records the document kind the text looks like,
so authority-lane files that are really lecture handouts, textbook chapters or
articles can be flagged for re-classification.

Output: data/indexes/unified-local-v1/TITLES.json
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data/indexes/unified-local-v1/TITLES.json"

SQL = """
SELECT sv.id, d.lane,
  (SELECT group_concat(t, ' ') FROM (
     SELECT markdown_text AS t FROM chunks c
     WHERE c.source_version_id = sv.id AND c.stream = 'body' ORDER BY c.ordinal LIMIT 3)) AS head
FROM documents d JOIN source_versions sv ON sv.document_id = d.id
WHERE d.duplicate_of IS NULL AND d.status = 'citable' AND sv.superseded_by IS NULL
  AND sv.title LIKE 'source-%'
"""

WESTLAW = re.compile(r"^(?P<title>.{8,220}?),\s+(?P<cite>[A-Z][A-Za-z.& ]{1,40}\.?\s+(?:\d{4}|\(\d{4}\)),?\s+\d+.*?)©")
LAW_TROVE = re.compile(r"^(?P<title>.{3,160}?)\s+Page 1 of \d+\s+Printed from Oxford Law Trove")
LECTURE = re.compile(r"(?i)\blecture\s+\d+\b")
ARTICLE_HINTS = re.compile(
    r"(?i)\b(abstract|journal|review article|published in|law review|l\.?\s?rev|lecturer in law|"
    r"university|doi\b|conv(?:eyancer)?\b)"
)
LEGISLATION = re.compile(
    r"\b([A-Z][A-Za-z,()'&\- ]{3,120}?\b(?:Act|Regulations|Order|Rules)\s+(?:18|19|20)\d{2})\b"
)
CASE = re.compile(r"\b([A-Z][\w.'&\- ]{1,80}\s+v\.?\s+[A-Z][\w.'&\- ]{1,80}?)\s*[\[(](?:18|19|20)\d{2}[\])]")


STUDENT_WORK = re.compile(
    r"(?i)([A-Za-z]\d{7}\b|anonymous code|word count:\s*\d|completed date|digital receipt|"
    r"submission id|change summary \(before|formative (?:essay|assessment)|"
    r"great scrape and the great scan)"
)
TITLE_FIELD = re.compile(
    r"^Title:\s*(?P<title>.{5,200}?)\s+(?:Abstract|Anonymous code|Word Count|Table of Contents|Chapter 1)"
)
JSTOR_CHAPTER = re.compile(
    r"Chapter Title:\s*(?P<chapter>.+?)\s+Book Title:\s*(?P<book>.+?)\s+(?:Book Subtitle|Book Author)"
)
NEUTRAL = re.compile(r"Neutral Citation(?: Number)?:?\s*(?P<nc>\[\d{4}\]\s+[A-Z]+(?:\s+[A-Za-z]+)?\s+\d+(?:\s*\([A-Za-z ]+\))?)")
EU_CASE = re.compile(r"(?P<kind>JUDGMENT OF THE COURT|OPINION OF ADVOCATE GENERAL)[^C]{0,200}?(?P<case>Case C[‑-]\d+/\d+)(?P<parties>[^()]{0,120})")
EU_ACT = re.compile(r"(?P<type>REGULATION|DIRECTIVE|DECISION)\s*\((?:EU|EC|EEC)\)\s*(?:No\s*)?(?P<num>\d+/\d+)")


def _despace(text: str) -> str:
    """Rejoin PDF-split capitals such as 'REGUL A TION'."""
    return re.sub(r"\b([A-Z]{2,})\s(?=[A-Z]{1,3}\b)", r"\1", text)


def _clean(text: str) -> str:
    text = re.sub(r"\s+", " ", text).strip(" .:-|")
    return text[:180]


def extract(head: str) -> tuple[str | None, str]:
    """Return (title, kind); kind is a best-effort document type."""
    flat = re.sub(r"\s+", " ", head or "").strip()
    if not flat:
        return None, "empty"
    if STUDENT_WORK.search(flat[:600]):
        m = TITLE_FIELD.match(flat)
        return _clean(m.group("title") if m else flat[:120]), "student_work"
    if m := TITLE_FIELD.match(flat):
        return _clean(m.group("title")), "article"
    if m := JSTOR_CHAPTER.search(flat[:600]):
        return _clean(f"{m.group('book').title()}: {m.group('chapter').title()}"), "textbook_chapter"
    if m := NEUTRAL.search(flat[:400]):
        return _clean(m.group("nc")), "case"
    if m := EU_CASE.search(flat[:700]):
        label = "AG Opinion in " if m.group("kind").startswith("OPINION") else ""
        parties = re.split(r"\s{2,}|\(|—|ECLI", m.group("parties"))[0]
        return _clean(f"{label}{m.group('case')} {parties}"), "case"
    if m := EU_ACT.search(_despace(flat[:400])):
        return _clean(f"{m.group('type').title()} (EU) {m.group('num')}"), "legislation"
    if m := WESTLAW.match(flat):
        return _clean(m.group("title").rstrip(".")), "article_westlaw"
    if m := LAW_TROVE.match(flat):
        return _clean(re.sub(r"^\d+\.\s*", "", m.group("title"))), "textbook_chapter"
    if LECTURE.search(flat[:200]):
        words = re.sub(r"^\d+", "", flat[:200])
        # Stop at the lecturer's name or the learning objectives.
        words = re.split(r"\s(?:Dr\.?|Professor|Prof\.?|Learning Objectives)\s", words)[0]
        words = re.split(r"\s[A-Z][a-z]+ [A-Z][a-z]+ (?:Commercial|Criminal|Land|Trusts)? ?Law Lecture", words)[0]
        return _clean(words[:120]), "lecture_material"
    if m := CASE.search(flat[:400]):
        return _clean(m.group(1)), "case"
    if m := LEGISLATION.search(flat[:300]):
        return _clean(m.group(1)), "legislation"
    first = re.split(r"(?<=[a-z.?!])\s+(?=[A-Z])|\s{2,}", flat[:240])[0]
    kind = "article" if ARTICLE_HINTS.search(flat[:1500]) else "unknown"
    return (_clean(first) if len(first) >= 8 else None), kind


def main() -> int:
    catalogue = sqlite3.connect(f"file:{ROOT / 'data/catalog.sqlite3'}?mode=ro", uri=True)
    entries: dict[str, dict[str, str | None]] = {}
    kinds: Counter[str] = Counter()
    for source_version_id, lane, head in catalogue.execute(SQL):
        title, kind = extract(head or "")
        kinds[kind] += 1
        entries[source_version_id] = {
            "title": title,
            "kind": kind,
            "lane": lane,
            # Authority-lane files that read as teaching or commentary need re-filing.
            "lane_suspect": (
                lane == "primary_authority"
                and kind in {"lecture_material", "textbook_chapter", "article", "article_westlaw"}
            ) or kind == "student_work",
        }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "schema": "legalbot.unified-titles.v1",
        "created_at": datetime.now(UTC).isoformat(),
        "method": "deterministic first-chunk patterns; catalogue unchanged",
        "entries": entries,
    }, indent=1) + "\n")
    missing = sum(entry["title"] is None for entry in entries.values())
    suspects = sum(bool(entry["lane_suspect"]) for entry in entries.values())
    print(f"{len(entries)} untitled sources | no title: {missing} | lane suspects: {suspects}")
    print(dict(kinds.most_common()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
