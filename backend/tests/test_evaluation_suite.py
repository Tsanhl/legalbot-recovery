from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from app.evaluation.suite import EvaluationCase, load_evaluation_suite


def _case(**updates):
    query = updates.pop("query", "Explain the governing rule")
    value = {
        "case_id": "development-contract-001",
        "suite_version": "1.0.0",
        "split": "development",
        "category": "core_single_authority",
        "status": "needs_expert_annotation",
        "synthetic": True,
        "query": query,
        "query_sha256": hashlib.sha256(query.encode()).hexdigest(),
        "paraphrase_group": None,
        "task_type": "general",
        "subject": "contract",
        "jurisdiction": "England and Wales",
        "as_of_date": "2026-08-12",
        "word_target": 1000,
        "expected_research_route": "sectioned",
        "expected_drafting_route": "sectioned",
        "expected_behaviour": "answer",
        "acceptable_source_ids": [],
        "exact_gold_spans": [],
        "forbidden_lanes": ["private_teaching", "assessment_guidance"],
        "forbidden_source_ids": [],
        "must_cover_issues": ["rule"],
        "known_contrary_authority_ids": [],
        "rubric": {},
        "privacy_flags": [],
        "failure_mode_labels": [],
        "corpus_manifest_sha256": None,
        "index_build_id": None,
    }
    value.update(updates)
    return value


def test_unannotated_case_is_honestly_valid_but_not_promotion_ready(tmp_path) -> None:
    case = EvaluationCase.model_validate(_case())
    path = tmp_path / "development.jsonl"
    path.write_text(json.dumps(case.model_dump(mode="json")) + "\n", encoding="utf-8")
    suite = load_evaluation_suite(path, require_complete=False)
    assert suite.cases[0].status == "needs_expert_annotation"
    with pytest.raises(ValueError, match="split counts"):
        load_evaluation_suite(path, require_complete=True)


def test_annotated_answer_cannot_claim_expertise_without_exact_spans() -> None:
    with pytest.raises(ValueError, match="sources and exact gold spans"):
        EvaluationCase.model_validate(
            _case(
                status="expert_annotated",
                corpus_manifest_sha256="a" * 64,
            )
        )


def test_supplied_long_form_questions_are_frozen_as_unannotated_development() -> None:
    project_root = Path(__file__).resolve().parents[2]
    suite = load_evaluation_suite(
        project_root / "benchmarks" / "evaluation" / "v1" / "development-drafts.jsonl",
        require_complete=False,
    )
    assert len(suite.cases) == 16
    assert {case.split for case in suite.cases} == {"development"}
    assert {case.status for case in suite.cases} == {"needs_expert_annotation"}
