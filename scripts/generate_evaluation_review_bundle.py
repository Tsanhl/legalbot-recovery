#!/usr/bin/env python3
"""Validate the 240-case draft and emit review and development benchmark artefacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.evaluation.suite import load_evaluation_suite  # noqa: E402
from backend.app.retrieval.benchmark import load_retrieval_benchmark  # noqa: E402

DEFAULT_SUITE = PROJECT_ROOT / "benchmarks" / "evaluation" / "v1" / "draft-suite.jsonl"
DEFAULT_MANIFEST = PROJECT_ROOT / "benchmarks" / "evaluation" / "v1" / "manifest.json"
DEFAULT_CHECKLIST = PROJECT_ROOT / "benchmarks" / "evaluation" / "v1" / "expert-review-checklist.md"
DEFAULT_BENCHMARK = PROJECT_ROOT / "benchmarks" / "retrieval" / "draft-v1.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_spans(database: sqlite3.Connection, suite: Any) -> dict[str, Any]:
    checked = 0
    failures: list[dict[str, str]] = []
    for case in suite.cases:
        for span in case.exact_gold_spans:
            checked += 1
            row = database.execute(
                """
                SELECT c.text_sha256,c.markdown_text,c.locator,c.source_version_id,
                       sv.review_status,sv.superseded_by,sv.metadata_json,d.lane
                FROM chunks c
                JOIN source_versions sv ON sv.id=c.source_version_id
                JOIN documents d ON d.id=sv.document_id
                WHERE c.id=?
                """,
                (span.chunk_id,),
            ).fetchone()
            reasons: list[str] = []
            if row is None:
                reasons.append("missing_chunk")
            else:
                metadata = json.loads(row["metadata_json"] or "{}")
                if str(row["source_version_id"]) != span.source_version_id:
                    reasons.append("source_version_mismatch")
                if str(row["text_sha256"]) != span.content_hash:
                    reasons.append("content_hash_mismatch")
                if str(row["locator"]) != span.exact_locator:
                    reasons.append("locator_mismatch")
                if span.character_end > len(str(row["markdown_text"])):
                    reasons.append("offset_out_of_bounds")
                if row["review_status"] != "approved" or row["superseded_by"] is not None:
                    reasons.append("source_not_current_approved_version")
                if row["lane"] != "primary_authority":
                    reasons.append("proposed_gold_is_not_primary_authority")
                if not metadata.get("identity_verified") or not metadata.get(
                    "currentness_verified"
                ):
                    reasons.append("source_identity_or_currentness_unverified")
            if reasons:
                failures.append(
                    {
                        "case_id": case.case_id,
                        "chunk_id": span.chunk_id,
                        "reason": ",".join(reasons),
                    }
                )
    return {"checked": checked, "failures": failures, "passed": not failures}


def _benchmark_payload(suite: Any) -> dict[str, Any]:
    queries: list[dict[str, Any]] = []
    for case in suite.cases:
        if case.expected_behaviour != "answer" or not case.exact_gold_spans:
            continue
        chunk_ids = list(dict.fromkeys(span.chunk_id for span in case.exact_gold_spans))[:10]
        primary = chunk_ids[:5]
        grades: dict[str, int] = {}
        for span in case.exact_gold_spans:
            if span.chunk_id in chunk_ids:
                grades[span.chunk_id] = max(grades.get(span.chunk_id, 1), span.relevance_grade)
        queries.append(
            {
                "id": case.case_id,
                "query": case.query,
                "jurisdiction": case.jurisdiction,
                "subject": case.subject,
                "as_of_date": case.as_of_date.isoformat(),
                "primary_must_hit_chunk_ids": primary,
                "relevant_chunk_ids": chunk_ids,
                "relevance_grades": grades,
                "paraphrase_group": case.paraphrase_group,
            }
        )
    return {
        "schema": "legalbot.retrieval-benchmark.v1",
        "benchmark_id": "legalbot-evaluation-v1-development-draft",
        "version": "1.0.0",
        "status": "draft",
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "approval_required": "independent_expert_and_owner",
        "queries": queries,
    }


def _checklist() -> str:
    return """# LegalBot evaluation v1 — independent expert review checklist

This bundle is evaluation-only. The system proposals are not gold until a legally
qualified reviewer checks them against the frozen corpus.

For every case:

- verify task, subject, jurisdiction, as-of date, route and expected behaviour;
- accept, replace or remove every proposed source;
- inspect the exact chunk, locator, hash and character offsets;
- bind each accepted span only to the issue(s) it actually supports;
- add leading and limiting/contrary authority where required;
- confirm prohibited lanes and sources;
- confirm the rubric and answer/refusal/clarification expectation;
- record reviewer identity privately and sign the case decision.

Sealing rules:

- development cases become `expert_annotated` after review;
- promotion and adversarial cases become `sealed` and must not be previewed during tuning;
- paraphrase families must remain wholly within one split;
- any change creates suite version 1.0.1 or later with an explicit diff;
- the benchmark changes from `draft` to `approved` only after every included query is checked;
- blind 70+ calibration must be performed by a person who did not create or tune the answer.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=PROJECT_ROOT / "data" / "catalog.sqlite3")
    parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--checklist", type=Path, default=DEFAULT_CHECKLIST)
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    parser.add_argument(
        "--write-checklist",
        action="store_true",
        help="Overwrite expert-review-checklist.md with the embedded stub (default: leave the hand-maintained checklist untouched)",
    )
    args = parser.parse_args()

    suite = load_evaluation_suite(args.suite, require_complete=False)
    database = sqlite3.connect(args.database)
    database.row_factory = sqlite3.Row
    try:
        span_integrity = _validate_spans(database, suite)
    finally:
        database.close()
    if not span_integrity["passed"]:
        raise SystemExit(json.dumps(span_integrity, indent=2, sort_keys=True))

    benchmark = _benchmark_payload(suite)
    args.benchmark.parent.mkdir(parents=True, exist_ok=True)
    args.benchmark.write_text(
        json.dumps(benchmark, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    executable = load_retrieval_benchmark(args.benchmark, require_approved=False)

    if args.write_checklist or not args.checklist.is_file():
        args.checklist.parent.mkdir(parents=True, exist_ok=True)
        args.checklist.write_text(_checklist(), encoding="utf-8")
    manifest = {
        "schema": "legalbot.evaluation-suite-manifest.v1",
        "suite_version": suite.version,
        "status": "needs_independent_expert_annotation",
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "suite_path": str(args.suite.relative_to(PROJECT_ROOT)),
        "suite_file_sha256": _sha256(args.suite),
        "canonical_suite_sha256": suite.sha256,
        "case_count": len(suite.cases),
        "split_counts": dict(sorted(Counter(case.split for case in suite.cases).items())),
        "category_counts": dict(sorted(Counter(case.category for case in suite.cases).items())),
        "status_counts": dict(sorted(Counter(case.status for case in suite.cases).items())),
        "proposed_span_integrity": span_integrity,
        "development_benchmark_path": str(args.benchmark.relative_to(PROJECT_ROOT)),
        "development_benchmark_sha256": executable.sha256,
        "promotion_eligible": False,
        "blocking_gate": "independent_expert_annotation_and_owner_approval",
    }
    args.manifest.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
