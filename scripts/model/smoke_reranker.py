#!/usr/bin/env python3
"""Run a real pinned Qwen3 causal-LM reranker relevance smoke test."""

from __future__ import annotations

import argparse
import json
import math
import warnings
from pathlib import Path

from app.ingestion.models import Jurisdiction, MaterialLane
from app.retrieval.models import IndexedChunk, SearchHit
from app.retrieval.service import (
    PINNED_RERANKER_REPO,
    PINNED_RERANKER_REVISION,
    RERANK_BATCH_SIZE,
    QwenRerankerProvider,
)


def _hit(chunk_id: str, text: str) -> SearchHit:
    return SearchHit(
        chunk=IndexedChunk(
            chunk_id=chunk_id,
            text=text,
            vector=(0.0,) * 1024,
            jurisdiction=Jurisdiction.ENGLAND_WALES,
            material_lane=MaterialLane.PRIMARY_AUTHORITY,
            subject="contract",
            review_state="approved",
            source_identity=f"smoke:{chunk_id}",
            content_sha256=(chunk_id.encode().hex() + "0" * 64)[:64],
        ),
        score=0.1,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model-path",
        type=Path,
        required=True,
        help="Verified local Qwen3-Reranker-0.6B directory",
    )
    args = parser.parse_args()
    provider = QwenRerankerProvider(
        PINNED_RERANKER_REPO,
        PINNED_RERANKER_REVISION,
        args.model_path.resolve(),
    )
    query = "What is required for valid consideration in English contract law?"
    related = _hit(
        "related",
        "In English contract law, consideration requires a bargained-for exchange of value and "
        "must move from the promisee.",
    )
    unrelated = _hit(
        "unrelated",
        "Saturn is a gas giant with a prominent system of icy rings orbiting the planet.",
    )
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        ranked = provider.rerank(query, (unrelated, related), limit=2)
    warning_text = "\n".join(str(item.message) for item in captured)
    unsafe_warning = any(
        marker in warning_text.casefold()
        for marker in ("newly initialized", "score.weight", "sequenceclassification")
    )
    scores = {hit.chunk.chunk_id: float(hit.rerank_score or 0.0) for hit in ranked}
    runtime = provider._load()
    classifier_head_present = getattr(runtime.model, "score", None) is not None
    passed = (
        [hit.chunk.chunk_id for hit in ranked] == ["related", "unrelated"]
        and all(math.isfinite(score) for score in scores.values())
        and scores["related"] > scores["unrelated"]
        and not unsafe_warning
        and not classifier_head_present
    )
    result = {
        "schema": "legalbot.reranker-smoke.v1",
        "passed": passed,
        "model": f"{PINNED_RERANKER_REPO}@{PINNED_RERANKER_REVISION}",
        "model_class": type(runtime.model).__name__,
        "classifier_head_present": classifier_head_present,
        "padding_side": runtime.tokenizer.padding_side,
        "pad_token_id": runtime.tokenizer.pad_token_id,
        "false_token_id": runtime.false_token_id,
        "true_token_id": runtime.true_token_id,
        "batch_limit": RERANK_BATCH_SIZE,
        "ranking": [hit.chunk.chunk_id for hit in ranked],
        "scores": scores,
        "unsafe_head_warning": unsafe_warning,
        "warnings": warning_text,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
