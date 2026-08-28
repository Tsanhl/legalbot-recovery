#!/usr/bin/env python3
"""Generate strict unannotated development records for the 16 supplied questions."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.evaluation.suite import EvaluationCase, load_evaluation_suite  # noqa: E402


def main() -> None:
    root = PROJECT_ROOT / "benchmarks" / "evaluation" / "v1"
    source = json.loads((root / "phase8-development-source.json").read_text(encoding="utf-8"))
    records: list[EvaluationCase] = []
    for raw in source["cases"]:
        query = str(raw["query"])
        target = int(raw["word_target"])
        research_route = "full_enquiry" if target > 3000 else "sectioned"
        record = EvaluationCase.model_validate(
            {
                "case_id": raw["case_id"],
                "suite_version": source["suite_version"],
                "split": "development",
                "category": "long_form",
                "status": "needs_expert_annotation",
                "synthetic": True,
                "query": query,
                "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
                "paraphrase_group": None,
                "task_type": raw["task_type"],
                "subject": raw["subject"],
                "jurisdiction": "England and Wales",
                "as_of_date": "2026-08-12",
                "word_target": target,
                "expected_research_route": research_route,
                "expected_drafting_route": "sectioned",
                "expected_behaviour": "answer",
                "acceptable_source_ids": [],
                "exact_gold_spans": [],
                "forbidden_lanes": ["private_teaching", "assessment_guidance"],
                "forbidden_source_ids": [],
                "must_cover_issues": raw["must_cover_issues"],
                "known_contrary_authority_ids": [],
                "rubric": {
                    "target": "blind_human_70_plus",
                    "automated_score_is_lint_only": True,
                },
                "privacy_flags": [],
                "failure_mode_labels": ["FM3", "FM4", "FM7", "FM8", "FM10"],
                "corpus_manifest_sha256": None,
                "index_build_id": None,
            }
        )
        records.append(record)
    destination = root / "development-drafts.jsonl"
    destination.write_text(
        "".join(
            json.dumps(record.model_dump(mode="json"), ensure_ascii=False, sort_keys=True) + "\n"
            for record in records
        ),
        encoding="utf-8",
    )
    suite = load_evaluation_suite(destination, require_complete=False)
    print(
        json.dumps(
            {
                "path": str(destination.relative_to(PROJECT_ROOT)),
                "case_count": len(suite.cases),
                "suite_sha256": suite.sha256,
                "status": "needs_expert_annotation",
                "eligible_for_training": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
