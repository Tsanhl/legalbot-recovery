#!/usr/bin/env python3
"""Embed the rephrased lecture notes as a non-citable "law and rules" knowledge lane.

Owner decision 2026-09-25: teaching material enters only as extracted law and
rules. Technique, exercises, reflection questions, essay angles, debates and
statistics are dropped here, deterministically, before anything is embedded.
The knowledge lane is used only to spot issues and to name authorities for
extra retrieval queries; its text is never evidence and is never cited.

Writes data/indexes/unified-local-v1/knowledge-lance (table "knowledge") and
KNOWLEDGE-MANIFEST.json. Run after the main embedding has finished (it loads
the embedding model and would otherwise compete for memory).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

NOTES = ROOT / "data/knowledge/lecture-notes"
INDEX = ROOT / "data/indexes/unified-local-v1"
KNOWLEDGE_DIR = INDEX / "knowledge-lance"
MAX_CHUNK_CHARS = 1_600

# Whole notes about writing technique rather than law.
EXCLUDED_FILES = frozenset({"general-essay-writing-tips.md", "pil-12-review-essay-technique-comity.md"})
# Sections that are not law or rules (checklists of legal elements are kept).
DROP_HEADING = re.compile(
    r"reflection|worked|exercise|technique|essay|formative|seminar problem|writing|"
    r"answering questions|debate|criticism|critical themes|caution about hype|"
    r"^context|statistic|brexit prompt|problem-based|problem types|^problem questions$",
    re.IGNORECASE,
)
SUBJECT_JURISDICTION = {
    "eu internal market": "European Union",
    "international commercial mediation": "Comparative",
}
_HEADING = re.compile(r"^(#{1,4})\s+(.*\S)\s*$")


def parse_note(text: str) -> tuple[dict[str, str], str]:
    meta: dict[str, str] = {}
    if text.startswith("---\n"):
        head, _, body = text[4:].partition("\n---\n")
        for line in head.splitlines():
            key, sep, value = line.partition(":")
            if sep:
                meta[key.strip()] = value.strip()
        return meta, body
    return meta, text


def law_sections(body: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Return kept (heading, text) sections and the headings that were dropped."""

    kept: list[tuple[str, str]] = []
    dropped: list[str] = []
    heading, level, lines = "", 0, []
    skip_below: int | None = None

    def flush() -> None:
        content = "\n".join(lines).strip()
        if content and heading:
            kept.append((heading, content))

    for line in body.splitlines():
        match = _HEADING.match(line)
        if not match:
            if skip_below is None:
                lines.append(line)
            continue
        new_level, title = len(match.group(1)), match.group(2)
        if skip_below is not None and new_level > skip_below:
            continue  # nested under a dropped section
        flush()
        lines, skip_below = [], None
        if new_level == 1:
            heading, level = "", 1
            continue
        if DROP_HEADING.search(title):
            dropped.append(title)
            skip_below = new_level
            heading = ""
            continue
        heading, level = title, new_level
    flush()
    del level
    return kept, dropped


def split_chunks(prefix: str, text: str) -> list[str]:
    """Keep chunks under the size cap, splitting on top-level bullets."""

    if len(prefix) + len(text) <= MAX_CHUNK_CHARS:
        return [f"{prefix}\n{text}"]
    blocks: list[str] = []
    for block in re.split(r"\n(?=- |\d+\. )", text):
        # A single oversized bullet group is split again on its sub-bullets.
        if len(prefix) + len(block) > MAX_CHUNK_CHARS:
            blocks.extend(re.split(r"\n(?=\s+- )", block))
        else:
            blocks.append(block)
    chunks, current = [], ""
    for block in blocks:
        if current and len(prefix) + len(current) + len(block) > MAX_CHUNK_CHARS:
            chunks.append(f"{prefix}\n{current.strip()}")
            current = ""
        current += "\n" + block
    if current.strip():
        chunks.append(f"{prefix}\n{current.strip()}")
    return chunks


def build_rows() -> tuple[list[dict[str, str]], dict[str, object]]:
    rows: list[dict[str, str]] = []
    report: dict[str, object] = {"files": {}, "excluded_files": sorted(EXCLUDED_FILES)}
    for path in sorted(NOTES.glob("*.md")):
        if path.name.startswith("_") or path.name in EXCLUDED_FILES:
            continue
        raw = path.read_text(encoding="utf-8")
        meta, body = parse_note(raw)
        subject = meta.get("subject", "general")
        topic = meta.get("topic", path.stem)
        sections, dropped = law_sections(body)
        count = 0
        for heading, text in sections:
            prefix = f"{subject.title()} — {topic} — {heading}"
            for chunk in split_chunks(prefix, text):
                digest = hashlib.sha256(chunk.encode("utf-8")).hexdigest()
                rows.append({
                    "chunk_id": f"K{digest[:16]}",
                    "content_sha256": digest,
                    "source_version_id": f"knowledge-{path.stem}",
                    "subject": subject,
                    "jurisdiction": SUBJECT_JURISDICTION.get(subject, "England and Wales"),
                    "heading": heading,
                    "text": chunk,
                })
                count += 1
        report["files"][path.name] = {  # type: ignore[index]
            "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            "chunks": count,
            "dropped_sections": dropped,
        }
    return rows, report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Report sections without embedding")
    args = parser.parse_args()
    rows, report = build_rows()
    dropped = sum(len(v["dropped_sections"]) for v in report["files"].values())  # type: ignore[union-attr]
    print(f"{len(report['files'])} notes, {len(rows)} law-and-rules chunks, {dropped} sections dropped")
    if args.dry_run:
        return 0

    import lancedb

    from app.config import Settings
    from app.retrieval.service import (
        PINNED_EMBEDDING_REPO,
        PINNED_EMBEDDING_REVISION,
        QwenEmbeddingProvider,
    )

    settings = Settings()
    embedder = QwenEmbeddingProvider(
        PINNED_EMBEDDING_REPO, PINNED_EMBEDDING_REVISION, settings.embedding_model_path
    )
    for start in range(0, len(rows), 8):
        batch = rows[start:start + 8]
        for row, vector in zip(batch, embedder.embed_documents([r["text"] for r in batch]), strict=True):
            row["vector"] = list(vector)  # type: ignore[assignment]
        print(f"embedded {min(start + 8, len(rows))}/{len(rows)}", flush=True)
    db = lancedb.connect(str(KNOWLEDGE_DIR))
    table = db.create_table("knowledge", data=rows, mode="overwrite")
    table.create_fts_index("text", use_tantivy=False, replace=True)
    report.update({
        "schema": "legalbot.knowledge-lane.v1",
        "created_at": datetime.now(UTC).isoformat(),
        "rows": len(rows),
        "owner_decision": "2026-09-25: teaching material enters only as extracted law and rules; "
                          "used for issue spotting and authority queries, never cited",
    })
    (INDEX / "KNOWLEDGE-MANIFEST.json").write_text(json.dumps(report, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
