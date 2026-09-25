#!/usr/bin/env python3
"""Build the single unified local retrieval index (owner direction, 25 Sept 2026).

One LanceDB folder, one table per lane, one row per unique chunk text:
  data/indexes/unified-local-v1/lance/{authority,scholarship,official_secondary}

Includes every non-duplicate citable document's latest non-rejected version,
reviewed or staged. ``review_status`` and ``currentness_status`` are carried
on each row so answers can label unreviewed material. Vectors from the sealed
recovery-b build are reused by exact prompt-text SHA-256; everything else is
embedded with the same pinned Qwen3-Embedding model and text view
(``_prompt_safe_index_text``), so query/document embeddings stay compatible.

Resumable: completed source versions are recorded in PROGRESS.json and skipped.
Never writes ACTIVE, the catalogue, or any existing build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

import lancedb  # noqa: E402
import numpy as np  # noqa: E402
import pyarrow as pa  # noqa: E402

from app.config import Settings  # noqa: E402
from app.retrieval.service import (  # noqa: E402
    PINNED_EMBEDDING_REPO,
    PINNED_EMBEDDING_REVISION,
    QwenEmbeddingProvider,
    _prompt_safe_index_text,
)

OUT = ROOT / "data/indexes/unified-local-v1"
PARENT = ROOT / "data/indexes/builds/current-law-ew-full-fp16-v111-20260829-recovery-b/lance"
TABLES = {
    "primary_authority": "authority",
    "scholarship": "scholarship",
    "official_secondary": "official_secondary",
}
DIM = 1024
PATH_LEAK = re.compile(r"/(Users|home|private|var/folders)/[^\s]+")

SCHEMA = pa.schema([
    ("chunk_id", pa.string()),
    ("content_sha256", pa.string()),
    ("source_version_id", pa.string()),
    ("document_id", pa.string()),
    ("lane", pa.string()),
    ("subject", pa.string()),
    ("jurisdiction", pa.string()),
    ("title", pa.string()),
    ("stable_identifier", pa.string()),
    ("canonical_url", pa.string()),
    ("locator", pa.string()),
    ("heading_path", pa.string()),
    ("review_status", pa.string()),
    ("currentness_status", pa.string()),
    ("as_of_date", pa.string()),
    ("text", pa.string()),
    ("vector", pa.list_(pa.float32(), DIM)),
])

VERSIONS_SQL = """
WITH v AS (
  SELECT sv.id AS source_version_id, d.id AS document_id, d.lane, d.subject_primary,
         d.jurisdiction, sv.title, sv.stable_identifier, sv.canonical_url,
         sv.review_status, sv.currentness_status,
         COALESCE(sv.as_of_date, sv.source_date, '') AS as_of_date,
         ROW_NUMBER() OVER (
           PARTITION BY d.id
           ORDER BY COALESCE(sv.as_of_date, sv.source_date, '') DESC, sv.created_at DESC
         ) AS rn
  FROM documents d JOIN source_versions sv ON sv.document_id = d.id
  WHERE d.duplicate_of IS NULL AND d.status = 'citable'
    AND d.lane IN ('primary_authority', 'scholarship', 'official_secondary')
    AND sv.superseded_by IS NULL AND COALESCE(sv.review_status, '') <> 'rejected'
    AND COALESCE(json_extract(sv.metadata_json, '$.ai_use_policy'), '') <> 'prohibited'
)
SELECT * FROM v WHERE rn = 1 ORDER BY lane, source_version_id
"""
CHUNKS_SQL = """
SELECT id, locator, heading_path, markdown_text FROM chunks
WHERE source_version_id = ? AND stream = 'body' ORDER BY ordinal
"""


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).strftime('%H:%M:%S')}] {msg}", flush=True)


def load_parent_vectors() -> dict[str, np.ndarray]:
    table = lancedb.connect(str(PARENT / "authority")).open_table("chunks")
    data = table.to_arrow().select(["content_sha256", "vector"])
    hashes = data.column("content_sha256").to_pylist()
    vectors = np.asarray(data.column("vector").combine_chunks().values, dtype=np.float32)
    vectors = vectors.reshape(len(hashes), DIM)
    return {h: vectors[i] for i, h in enumerate(hashes)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--limit-sources", type=int, help="Smoke-test on N source versions")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()
    out = args.out

    settings = Settings(project_root=ROOT)
    out.mkdir(parents=True, exist_ok=True)
    progress_path = out / "PROGRESS.json"
    progress = json.loads(progress_path.read_text()) if progress_path.exists() else {
        "done_source_versions": [], "rows": 0, "reused": 0, "embedded": 0,
        "duplicates_skipped": 0, "path_leaks_scrubbed": 0,
    }
    done = set(progress["done_source_versions"])

    catalogue = sqlite3.connect(f"file:{settings.database_path}?mode=ro", uri=True)
    catalogue.row_factory = sqlite3.Row
    versions = [dict(r) for r in catalogue.execute(VERSIONS_SQL)]
    if args.limit_sources:
        versions = versions[: args.limit_sources]
    log(f"{len(versions)} source versions; {len(done)} already done")

    db = lancedb.connect(str(out / "lance"))
    tables = {}
    seen: set[str] = set()
    for name in TABLES.values():
        if name in db.table_names():
            tables[name] = db.open_table(name)
            seen.update(tables[name].to_arrow().column("content_sha256").to_pylist())
    log(f"{len(seen)} existing unique chunks; loading parent vectors")
    parent = load_parent_vectors()
    log(f"{len(parent)} reusable parent vectors")
    embedder = QwenEmbeddingProvider(
        PINNED_EMBEDDING_REPO, PINNED_EMBEDDING_REVISION, settings.embedding_model_path
    )
    model = embedder._load()

    started = time.time()
    for n, ver in enumerate(versions, 1):
        svid = ver["source_version_id"]
        if svid in done:
            continue
        rows, to_embed = [], []
        for c in catalogue.execute(CHUNKS_SQL, (svid,)):
            text = _prompt_safe_index_text(c)
            if PATH_LEAK.search(text):
                text = PATH_LEAK.sub("[path removed]", text)
                progress["path_leaks_scrubbed"] += 1
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if not text.strip() or digest in seen:
                progress["duplicates_skipped"] += 1
                continue
            seen.add(digest)
            row = {
                "chunk_id": c["id"], "content_sha256": digest, "source_version_id": svid,
                "document_id": ver["document_id"], "lane": ver["lane"],
                "subject": ver["subject_primary"] or "", "jurisdiction": ver["jurisdiction"] or "",
                "title": ver["title"] or "", "stable_identifier": ver["stable_identifier"] or "",
                "canonical_url": ver["canonical_url"] or "", "locator": c["locator"] or "",
                "heading_path": c["heading_path"] or "", "review_status": ver["review_status"] or "",
                "currentness_status": ver["currentness_status"] or "",
                "as_of_date": ver["as_of_date"] or "", "text": text, "vector": parent.get(digest),
            }
            if row["vector"] is None:
                to_embed.append(row)
            else:
                progress["reused"] += 1
            rows.append(row)
        if to_embed:
            order = sorted(range(len(to_embed)), key=lambda i: len(to_embed[i]["text"]))
            vectors = model.encode(
                [to_embed[i]["text"] for i in order], batch_size=args.batch_size,
                normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False,
            )
            for j, i in enumerate(order):
                to_embed[i]["vector"] = vectors[j].astype(np.float32)
            progress["embedded"] += len(to_embed)
        if rows:
            for r in rows:
                r["vector"] = np.asarray(r["vector"], dtype=np.float32).tolist()
            batch = pa.Table.from_pylist(rows, schema=SCHEMA)
            name = TABLES[ver["lane"]]
            if name in tables:
                tables[name].add(batch)
            else:
                tables[name] = db.create_table(name, batch)
            progress["rows"] += len(rows)
        done.add(svid)
        progress["done_source_versions"] = sorted(done)
        progress["updated_at"] = datetime.now(UTC).isoformat()
        progress_path.write_text(json.dumps(progress) + "\n")
        if n % 10 == 0 or to_embed:
            rate = progress["embedded"] / max(1.0, time.time() - started)
            log(f"{n}/{len(versions)} sources | rows {progress['rows']} | "
                f"reused {progress['reused']} | embedded {progress['embedded']} ({rate:.1f}/s)")

    (out / "MANIFEST.json").write_text(json.dumps({
        "schema": "legalbot.unified-local-index.v1",
        "embedding_model": f"{PINNED_EMBEDDING_REPO}@{PINNED_EMBEDDING_REVISION}",
        "document_text_view": "_prompt_safe_index_text (scrub_pii markdown_text)",
        "tables": {k: tables[k].count_rows() for k in tables},
        "source_versions": len(done),
        "includes_unreviewed_staged_sources": True,
        "writes_active": False,
        "completed_at": datetime.now(UTC).isoformat(),
        **{k: progress[k] for k in ("rows", "reused", "embedded", "duplicates_skipped", "path_leaks_scrubbed")},
    }, indent=2) + "\n")
    log("complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
