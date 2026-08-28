#!/usr/bin/env python3
"""Independently rerank the 176-row Phase-2A deep recovery set."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from scripts.run_v111_phase2a_cross_subject_reranker import (  # noqa: E402
    run_cross_subject_review,
)
from scripts.run_v111_phase2a_independent_reranker_advisory import (  # noqa: E402
    _real_scorer,
)

EXPECTED_SOURCE_DIGEST = "692cdafd0e10f8b864a96cc35165cb20441dc099b52a2f2cad90b38befcbbbf1"
EXPECTED_SOURCE_SCHEMA = "legalbot.v111.phase2a.deep-current-source-recovery-176.v1"
EXPECTED_ROW_COUNT = 176
OUTPUT_NAME = "INDEPENDENT-RERANKER-DEEP-RECOVERY-176.json"
ARTIFACT_SCHEMA = "legalbot.phase2a.independent-reranker-deep-recovery-176.v1"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--model-path", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    scorer, identity = _real_scorer(args.model_path.resolve(strict=True))
    result = run_cross_subject_review(
        source_path=args.source.resolve(strict=True),
        cases_path=args.cases.resolve(strict=True),
        output_root=args.output_root.resolve(),
        scorer=scorer,
        runtime_identity=identity,
        started_at=datetime.now(UTC),
        resume=bool(args.resume),
        expected_source_digest=EXPECTED_SOURCE_DIGEST,
        expected_source_schema=EXPECTED_SOURCE_SCHEMA,
        expected_row_count=EXPECTED_ROW_COUNT,
        output_name=OUTPUT_NAME,
        artifact_schema=ARTIFACT_SCHEMA,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
