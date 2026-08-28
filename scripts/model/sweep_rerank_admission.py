#!/usr/bin/env python3
"""Sweep pre-rerank admission caps against fused-size fixtures.

Does not rewrite frozen gold. Prints privacy-safe counts only.
"""

from __future__ import annotations

import json

from app.ingestion.models import Jurisdiction, MaterialLane
from app.retrieval.admission import admit_for_rerank
from app.retrieval.hybrid import DeterministicHashEmbedding
from app.retrieval.models import IndexedChunk, SearchHit

EMBEDDER = DeterministicHashEmbedding()
CAPS = (20, 30, 40, 50, 60, 80, 120)


def _chunk(chunk_id: str, source: str) -> IndexedChunk:
    return IndexedChunk(
        chunk_id=chunk_id,
        text=f"Authority passage {chunk_id} consideration promisee unpaid seller.",
        vector=EMBEDDER.embed_query(chunk_id),
        jurisdiction=Jurisdiction.ENGLAND_WALES,
        material_lane=MaterialLane.PRIMARY_AUTHORITY,
        subject="contract",
        review_state="approved",
        source_identity=source,
        content_sha256=(chunk_id.encode("utf-8").hex() + "0" * 64)[:64],
        metadata={"locator": chunk_id},
    )


def main() -> int:
    gold_ids = {f"gold-{index}" for index in range(3)}
    fused = [
        SearchHit(_chunk(f"gold-{index}", f"gold-source-{index}"), 1.0 - (index * 0.01))
        for index in range(3)
    ]
    fused.extend(
        SearchHit(_chunk(f"other-{index}", f"other-{index // 9}"), 0.4 - (index * 0.001))
        for index in range(221)
    )
    rows = []
    for cap in CAPS:
        admitted = admit_for_rerank(fused, rerank_candidate_limit=cap)
        survived = gold_ids.intersection(hit.chunk.chunk_id for hit in admitted)
        rows.append(
            {
                "rerank_candidate_limit": cap,
                "fused": len(fused),
                "admitted": len(admitted),
                "gold_survived": len(survived),
                "gold_required": len(gold_ids),
                "pre_rerank_gold_recall": round(len(survived) / len(gold_ids), 4),
            }
        )
    print(json.dumps({"schema": "legalbot.admission-cap-sweep.v1", "rows": rows}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
