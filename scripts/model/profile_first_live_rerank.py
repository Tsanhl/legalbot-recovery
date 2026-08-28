#!/usr/bin/env python3
"""Profile first-live rerank workload without printing questions.

Records fused vs admitted counts, ranking token bounds, and device. Does not
submit an answer job. Writes JSON under data/retrieval_telemetry/.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from app.config import Settings
from app.retrieval.budget import (
    BASELINE_SECONDS_PER_HIT_AT_1024,
    RERANK_WORK_SAFETY_MARGIN,
    estimate_rerank_seconds,
)
from app.retrieval.ranking_text import RANKING_PAYLOAD_MAX_TOKENS, RANKING_REPRESENTATION_VERSION
from app.retrieval.service import (
    LIVE_RERANK_CANDIDATE_LIMIT,
    LIVE_SEARCH_DEPTH_FLOOR,
    RERANK_BATCH_SIZE,
    RERANK_HARD_MAX_HITS,
    RERANK_INFERENCE_SLOTS,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hit-count", type=int, default=224)
    parser.add_argument("--sections", type=int, default=2)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    settings = Settings()
    admitted = min(args.hit_count, LIVE_RERANK_CANDIDATE_LIMIT)
    estimated_one = estimate_rerank_seconds(
        hit_count=admitted, ranking_payload_tokens=RANKING_PAYLOAD_MAX_TOKENS
    )
    serialized = estimated_one * max(1, args.sections)
    report = {
        "schema": "legalbot.first-live-rerank-profile.v1",
        "created_at": datetime.now(UTC).isoformat(),
        "device_policy": "cpu_unless_LEGALBOT_TORCH_DEVICE",
        "live_search_depth_floor": LIVE_SEARCH_DEPTH_FLOOR,
        "rerank_candidate_limit": LIVE_RERANK_CANDIDATE_LIMIT,
        "rerank_hard_max_hits": RERANK_HARD_MAX_HITS,
        "rerank_batch_size": RERANK_BATCH_SIZE,
        "rerank_inference_slots": RERANK_INFERENCE_SLOTS,
        "ranking_representation_version": RANKING_REPRESENTATION_VERSION,
        "ranking_payload_max_tokens": RANKING_PAYLOAD_MAX_TOKENS,
        "observed_fused_hits_example": args.hit_count,
        "admitted_hits": admitted,
        "sections": args.sections,
        "estimated_seconds_one_section": round(estimated_one, 3),
        "estimated_seconds_serialized_sections": round(serialized, 3),
        "baseline_seconds_per_hit_at_1024": BASELINE_SECONDS_PER_HIT_AT_1024,
        "safety_margin": RERANK_WORK_SAFETY_MARGIN,
        "research_budget_seconds": 300,
        "acceptance_seconds": 210,
        "fits_acceptance": serialized <= 210,
        "fits_research_budget": serialized <= 300,
        "measured_q31_r6": {
            "job_id": "1a5f95f4-bd1c-4fc3-b406-3fe3e317fde2",
            "terminal": "stage_timeout",
            "research_seconds": 300,
            "notes": "32-hit CPU rerank at 1024 ranking tokens did not finish inside 300s",
        },
        "data_dir": str(settings.data_dir.name),
    }
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    destination = args.out or (
        settings.project_root / "data" / "retrieval_telemetry" / "first-live-profile.json"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")
    print(
        json.dumps(
            {
                "wrote": str(destination.relative_to(settings.project_root)),
                **{
                    key: report[key]
                    for key in (
                        "admitted_hits",
                        "estimated_seconds_serialized_sections",
                        "fits_acceptance",
                    )
                },
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
