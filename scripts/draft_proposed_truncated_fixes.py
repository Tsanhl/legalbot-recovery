#!/usr/bin/env python3
"""Draft proposed fuller gold-span replacements for truncated review-queue cases.

READ-ONLY w.r.t. benchmarks/evaluation/v1/draft-suite.jsonl.
Writes proposals under data/review_queue/expert-review/proposed-fixes-truncated/.
Does NOT apply changes. Does NOT set expert_annotated. Does NOT invent seals.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SUITE_PATH = ROOT / "benchmarks/evaluation/v1/draft-suite.jsonl"
QUEUE_PATH = ROOT / "data/review_queue/expert-review/first-pass/by-action/replace_truncated.jsonl"
CATALOG_PATH = ROOT / "data/catalog.sqlite3"
OUT_DIR = ROOT / "data/review_queue/expert-review/proposed-fixes-truncated"

MAX_EXTRA_SIBLINGS = 8

TRUNC_PATTERNS = [
    re.compile(r"[—–]\s*$"),
    re.compile(r"\bif-\s*$", re.I),
    re.compile(r";\s*$"),
    re.compile(r"(?<![A-Za-z])(?:or|and)\s*$", re.I),
    re.compile(r"[A-Za-z]-$"),
]


def is_truncated(text: str) -> bool:
    t = (text or "").rstrip()
    if not t:
        return False
    return any(p.search(t) for p in TRUNC_PATTERNS)


_COMPLETE_END = re.compile(r"[.!?…][\"'”’)\]]*$")


def looks_complete_unit(text: str) -> bool:
    """True when text no longer matches truncation cues and ends a sentence/unit."""
    t = (text or "").rstrip()
    if not t or is_truncated(t):
        return False
    return _COMPLETE_END.search(t) is not None


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def span_key(s: dict[str, Any]) -> tuple:
    return (
        s.get("chunk_id"),
        s.get("character_start"),
        s.get("character_end"),
        s.get("source_version_id"),
    )


def full_chunk_span(
    chunk: sqlite3.Row,
    template: dict[str, Any] | None,
    *,
    relevance_grade: int | None = None,
    supported_issue_ids: list[str] | None = None,
) -> dict[str, Any]:
    text = chunk["markdown_text"]
    grade = relevance_grade
    issues = supported_issue_ids
    if template is not None:
        if grade is None:
            grade = template.get("relevance_grade", 3)
        if issues is None:
            issues = list(template.get("supported_issue_ids") or [])
    if grade is None:
        grade = 3
    if issues is None:
        issues = []
    return {
        "chunk_id": chunk["id"],
        "source_version_id": chunk["source_version_id"],
        "exact_locator": chunk["locator"],
        "character_start": 0,
        "character_end": len(text),
        "content_hash": chunk["text_sha256"],
        "relevance_grade": grade,
        "supported_issue_ids": issues,
    }


def fetch_chunk(conn: sqlite3.Connection, chunk_id: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM chunks WHERE id = ?", (chunk_id,)).fetchone()


def fetch_siblings(
    conn: sqlite3.Connection,
    source_version_id: str,
    locator: str,
    ordinal: int,
    limit: int,
) -> list[sqlite3.Row]:
    return list(
        conn.execute(
            """
            SELECT *
            FROM chunks
            WHERE source_version_id = ?
              AND locator = ?
              AND ordinal >= ?
            ORDER BY ordinal ASC
            LIMIT ?
            """,
            (source_version_id, locator, ordinal, limit),
        )
    )


def count_forward_siblings(
    conn: sqlite3.Connection,
    source_version_id: str,
    locator: str,
    ordinal: int,
) -> int:
    row = conn.execute(
        """
        SELECT COUNT(*) AS n
        FROM chunks
        WHERE source_version_id = ?
          AND locator = ?
          AND ordinal > ?
        """,
        (source_version_id, locator, ordinal),
    ).fetchone()
    return int(row["n"])


def expand_one_span(
    conn: sqlite3.Connection,
    span: dict[str, Any],
    acceptable: set[str],
) -> tuple[str, list[dict[str, Any]] | None, str]:
    """Return (status, new_spans_or_none, note).

    status: keep | drafted | needs_manual
    """
    chunk = fetch_chunk(conn, span["chunk_id"])
    if chunk is None:
        return "needs_manual", None, f"chunk missing from catalog: {span['chunk_id']}"

    sv = span.get("source_version_id") or chunk["source_version_id"]
    if sv not in acceptable:
        return (
            "needs_manual",
            None,
            f"span source_version_id {sv} not in case acceptable_source_ids",
        )
    if chunk["source_version_id"] not in acceptable:
        return (
            "needs_manual",
            None,
            "chunk source_version_id not in case acceptable_source_ids",
        )

    text = chunk["markdown_text"]
    start = int(span.get("character_start") or 0)
    end = int(span.get("character_end") if span.get("character_end") is not None else len(text))
    # Clamp
    start = max(0, min(start, len(text)))
    end = max(start, min(end, len(text)))
    slice_text = text[start:end]

    # In-chunk expansion opportunity
    if (start != 0 or end != len(text)) and len(text) > end - start:
        full_span = full_chunk_span(chunk, span)
        if not is_truncated(text):
            return "drafted", [full_span], "expanded character offsets to full in-chunk text"
        # fuller in-chunk still truncated → continue with siblings using full chunk as base
        slice_text = text
        start, end = 0, len(text)
    elif not is_truncated(slice_text):
        return "keep", None, "span not truncated; keep as-is"

    # Sibling expansion under same locator / source_version_id
    forward_available = count_forward_siblings(
        conn, chunk["source_version_id"], chunk["locator"], chunk["ordinal"]
    )
    # Fetch enough to see whether the whole remaining locator group fits in cap
    siblings = fetch_siblings(
        conn,
        chunk["source_version_id"],
        chunk["locator"],
        chunk["ordinal"],
        MAX_EXTRA_SIBLINGS + 1,
    )
    if len(siblings) <= 1:
        return (
            "needs_manual",
            None,
            "no same-locator sibling chunks under acceptable source_version_id to complete truncated provision",
        )

    capped = siblings[: MAX_EXTRA_SIBLINGS + 1]
    selected = None
    strategy = None

    # CRTPA-style: if the entire remaining same-locator group fits in the cap
    # and ends as a complete unit, take the whole group.
    whole_group_fits = forward_available <= MAX_EXTRA_SIBLINGS
    if whole_group_fits and looks_complete_unit(capped[-1]["markdown_text"]):
        selected = capped
        strategy = "whole_locator_group"
    else:
        # Otherwise complete only the immediately truncated provision:
        # shortest prefix whose last chunk is a complete unit.
        for i in range(1, len(capped) + 1):
            if looks_complete_unit(capped[i - 1]["markdown_text"]):
                selected = capped[:i]
                strategy = "first_complete_unit"
                break

    if not selected:
        if forward_available > MAX_EXTRA_SIBLINGS:
            return (
                "needs_manual",
                None,
                f"still incomplete after +{MAX_EXTRA_SIBLINGS} sibling cap under locator {chunk['locator']!r}",
            )
        return (
            "needs_manual",
            None,
            "no further same-locator chunks; provision still appears incomplete after available siblings",
        )

    new_spans = [full_chunk_span(sib, span) for sib in selected]
    n_extra = len(selected) - 1
    note = (
        f"expanded truncated span at locator {chunk['locator']!r} ord={chunk['ordinal']} "
        f"with +{n_extra} same-locator sibling chunk(s) via {strategy} "
        f"(cap={MAX_EXTRA_SIBLINGS})"
    )
    return "drafted", new_spans, note


def process_case(conn: sqlite3.Connection, case: dict[str, Any]) -> dict[str, Any]:
    case_id = case["case_id"]
    old_spans = list(case.get("exact_gold_spans") or [])
    acceptable = set(case.get("acceptable_source_ids") or [])
    if not acceptable:
        return {
            "case_id": case_id,
            "old_spans": old_spans,
            "new_spans": None,
            "action": "needs_manual",
            "notes": "case has empty acceptable_source_ids; refusing to invent sources",
            "confidence": 0.0,
            "status": "needs_manual",
        }

    kept: list[dict[str, Any]] = []
    drafted_groups: list[list[dict[str, Any]]] = []
    notes: list[str] = []
    any_drafted = False
    any_manual = False
    truncated_seen = False

    for span in old_spans:
        status, new_spans, note = expand_one_span(conn, span, acceptable)
        notes.append(note)
        if status == "keep":
            kept.append(span)
        elif status == "drafted":
            any_drafted = True
            truncated_seen = True
            drafted_groups.append(new_spans or [])
        else:
            any_manual = True
            truncated_seen = True
            # Do not invent a partial replacement for this span
            kept.append(span)

    if any_manual and not any_drafted:
        return {
            "case_id": case_id,
            "old_spans": old_spans,
            "new_spans": None,
            "action": "needs_manual",
            "notes": " | ".join(notes),
            "confidence": 0.2,
            "status": "needs_manual",
        }

    if not truncated_seen and not any_drafted:
        # Shouldn't happen for this queue, but be safe
        return {
            "case_id": case_id,
            "old_spans": old_spans,
            "new_spans": None,
            "action": "needs_manual",
            "notes": "no truncated spans detected against catalog text; needs human check",
            "confidence": 0.3,
            "status": "needs_manual",
        }

    if any_manual and any_drafted:
        # Mixed: some spans expandable, some not — mark needs_manual overall
        return {
            "case_id": case_id,
            "old_spans": old_spans,
            "new_spans": None,
            "action": "needs_manual",
            "notes": "mixed: some truncated spans expandable but others need_manual — "
            + " | ".join(notes),
            "confidence": 0.35,
            "status": "needs_manual",
        }

    # Merge drafted replacements + kept non-truncated, dedupe by chunk_id (prefer drafted full)
    replacement_chunk_ids = {s["chunk_id"] for group in drafted_groups for s in group}
    new_spans: list[dict[str, Any]] = []
    seen_chunks: set[str] = set()
    for group in drafted_groups:
        for s in group:
            if s["chunk_id"] in seen_chunks:
                continue
            seen_chunks.add(s["chunk_id"])
            new_spans.append(s)
    for s in kept:
        # Drop if orphaned / superseded by replacement set covering same chunk
        if s.get("chunk_id") in replacement_chunk_ids:
            continue
        if s.get("chunk_id") in seen_chunks:
            continue
        seen_chunks.add(s.get("chunk_id"))
        new_spans.append(s)

    # Confidence: higher when expansions modest and hashes present
    n_old = len(old_spans)
    n_new = len(new_spans)
    growth = n_new - n_old
    conf = 0.85
    if growth > 6:
        conf = 0.7
    if growth <= 0 and n_new == n_old:
        conf = 0.75
    conf = round(conf, 2)

    return {
        "case_id": case_id,
        "old_spans": old_spans,
        "new_spans": new_spans,
        "action": "replace_proposed",
        "notes": " | ".join(notes),
        "confidence": conf,
        "status": "drafted",
    }


def preview_text(conn: sqlite3.Connection, span: dict[str, Any], limit: int = 180) -> str:
    chunk = fetch_chunk(conn, span["chunk_id"])
    if chunk is None:
        return "<missing chunk>"
    text = chunk["markdown_text"]
    start = int(span.get("character_start") or 0)
    end = int(span.get("character_end") if span.get("character_end") is not None else len(text))
    sl = text[start:end]
    if len(sl) <= limit:
        return sl
    return sl[: limit - 1] + "…"


def choose_samples(results: list[dict[str, Any]]) -> list[str]:
    """Pick 5 diverse case_ids for owner spot-check."""
    drafted = [r for r in results if r["status"] == "drafted"]
    manual = [r for r in results if r["status"] == "needs_manual"]
    picks: list[str] = []

    def add(cid: str) -> None:
        if cid and cid not in picks:
            picks.append(cid)

    # Prefer a simple core Act section expansion
    for r in drafted:
        if r["case_id"].startswith("core-") and r.get("new_spans") and len(r["new_spans"]) >= 3:
            add(r["case_id"])
            break
    # A larger expansion
    big = sorted(
        [r for r in drafted if r.get("new_spans")],
        key=lambda r: len(r["new_spans"]),
        reverse=True,
    )
    if big:
        add(big[0]["case_id"])
    # A para-* case if present
    for r in drafted:
        if r["case_id"].startswith("para-"):
            add(r["case_id"])
            break
    # A multi-* case
    for r in drafted:
        if r["case_id"].startswith("multi-"):
            add(r["case_id"])
            break
    # A needs_manual example
    for r in manual:
        add(r["case_id"])
        break
    # Fill from drafted
    for r in drafted:
        add(r["case_id"])
        if len(picks) >= 5:
            break
    for r in results:
        add(r["case_id"])
        if len(picks) >= 5:
            break
    return picks[:5]


def write_samples_md(
    conn: sqlite3.Connection, results: list[dict[str, Any]], sample_ids: list[str]
) -> str:
    by_id = {r["case_id"]: r for r in results}
    lines = [
        "# Proposed truncated-span fixes — sample previews",
        "",
        "**NOT APPLIED.** Owner must approve before any suite mutation.",
        "",
    ]
    for cid in sample_ids:
        r = by_id[cid]
        lines.append(f"## {cid}")
        lines.append("")
        lines.append(f"- status: `{r['status']}`")
        lines.append(f"- action: `{r['action']}`")
        lines.append(f"- confidence: {r['confidence']}")
        lines.append(f"- notes: {r['notes']}")
        lines.append("")
        lines.append("### Before (old_spans)")
        lines.append("")
        for i, s in enumerate(r["old_spans"] or []):
            lines.append(
                f"{i + 1}. `{s.get('exact_locator')}` chunk `{s.get('chunk_id')}` "
                f"[{s.get('character_start')}:{s.get('character_end')}]"
            )
            lines.append("")
            lines.append("```")
            lines.append(preview_text(conn, s))
            lines.append("```")
            lines.append("")
        lines.append("### After (new_spans)")
        lines.append("")
        if not r.get("new_spans"):
            lines.append("_No replacement proposed (needs_manual)._")
            lines.append("")
        else:
            for i, s in enumerate(r["new_spans"]):
                lines.append(
                    f"{i + 1}. `{s.get('exact_locator')}` chunk `{s.get('chunk_id')}` "
                    f"[{s.get('character_start')}:{s.get('character_end')}] "
                    f"hash=`{(s.get('content_hash') or '')[:12]}…`"
                )
                lines.append("")
                lines.append("```")
                lines.append(preview_text(conn, s))
                lines.append("```")
                lines.append("")
    return "\n".join(lines)


def write_readme() -> str:
    return """# Proposed fixes for truncated gold spans

**NOT APPLIED.** These files are draft proposals only.

## Hard rules / owner gate

- `benchmarks/evaluation/v1/draft-suite.jsonl` was **not** modified by this pass.
- **No** case status was changed to `expert_annotated` (or sealed).
- **No** expert seals / approvals were invented.
- **No** `acceptable_source_ids` were changed.
- **No** span text was invented; every proposed span is a full catalog chunk
  (`character_start=0`, `character_end=len(markdown_text)`,
  `content_hash=text_sha256`) under a `source_version_id` already accepted on the case.
- Owner must review and explicitly approve before any apply step.

## Contents

| File | Purpose |
|---|---|
| `summary.json` | Counts: `drafted`, `needs_manual`, `total` |
| `proposed-fixes.jsonl` | One row per truncated-queue case |
| `samples.md` | Five diverse before/after previews for owner spot-check |
| `README.md` | This file |

## Row schema (`proposed-fixes.jsonl`)

- `case_id`
- `old_spans` — current `exact_gold_spans` copied from the suite (read-only snapshot)
- `new_spans` — proposed replacement list, or `null` when `needs_manual`
- `action` — `replace_proposed` or `needs_manual`
- `notes` — expansion / blocker rationale
- `confidence` — heuristic confidence in `[0,1]`
- `status` — `drafted` or `needs_manual`

## Expansion heuristic

Same pattern as owner-replaced `core-001` CRTPA 1999 s.1:

1. Detect mid-sentence / mid-provision truncation (`if—`, em/en dash, trailing `or`/`and`, `;`, hyphenated mid-word).
2. Prefer full-chunk spans (`character_start=0`, `character_end=len`, `content_hash=text_sha256`).
3. If still truncated, load following sibling chunks with the **same**
   `source_version_id` and **same** `locator`, ordered by `ordinal`, cap **+8**:
   - If the entire remaining same-locator group fits in the cap and ends as a
     complete unit → take the whole group (CRTPA-style).
   - Else take the shortest prefix ending at the first complete provision unit.
4. If expansion cannot safely complete the provision, mark `needs_manual`.

## Apply

See `scripts/apply_proposed_truncated_fixes.py`. It applies **only** when invoked
with `--apply` **and** an allowlist file. Do not run with `--apply` unless the
owner has approved specific case ids.
"""


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    queue = load_jsonl(QUEUE_PATH)
    wanted = {r["case_id"] for r in queue}
    suite_by_id: dict[str, dict[str, Any]] = {}
    with SUITE_PATH.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            case = json.loads(line)
            if case.get("case_id") in wanted:
                suite_by_id[case["case_id"]] = case

    conn = sqlite3.connect(f"file:{CATALOG_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    results: list[dict[str, Any]] = []
    for q in queue:
        cid = q["case_id"]
        case = suite_by_id.get(cid)
        if case is None:
            results.append(
                {
                    "case_id": cid,
                    "old_spans": [],
                    "new_spans": None,
                    "action": "needs_manual",
                    "notes": "case_id not found in draft-suite.jsonl",
                    "confidence": 0.0,
                    "status": "needs_manual",
                }
            )
            continue
        results.append(process_case(conn, case))

    drafted = sum(1 for r in results if r["status"] == "drafted")
    needs_manual = sum(1 for r in results if r["status"] == "needs_manual")
    summary = {
        "total": len(results),
        "drafted": drafted,
        "needs_manual": needs_manual,
        "source_queue": str(QUEUE_PATH.relative_to(ROOT)),
        "suite_path": str(SUITE_PATH.relative_to(ROOT)),
        "suite_mutated": False,
        "expert_annotated_set": False,
        "max_extra_siblings": MAX_EXTRA_SIBLINGS,
    }

    fixes_path = OUT_DIR / "proposed-fixes.jsonl"
    with fixes_path.open("w", encoding="utf-8") as f:
        for r in results:
            out = {
                "case_id": r["case_id"],
                "old_spans": r["old_spans"],
                "new_spans": r["new_spans"],
                "action": r["action"],
                "notes": r["notes"],
                "confidence": r["confidence"],
            }
            f.write(json.dumps(out, ensure_ascii=False) + "\n")

    sample_ids = choose_samples(results)
    (OUT_DIR / "samples.md").write_text(
        write_samples_md(conn, results, sample_ids), encoding="utf-8"
    )
    (OUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (OUT_DIR / "README.md").write_text(write_readme(), encoding="utf-8")
    # Record sample ids in summary for the agent report
    summary["sample_case_ids"] = sample_ids
    (OUT_DIR / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    conn.close()
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
