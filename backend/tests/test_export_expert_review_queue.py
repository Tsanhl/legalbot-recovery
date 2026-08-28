from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.export_expert_review_queue import (
    assert_export_text_safe,
    build_expert_review_queue,
    case_queue_row,
    write_expert_review_queue,
)


def _case(**updates: object) -> dict:
    value = {
        "case_id": "core-001",
        "suite_version": "1.0.0",
        "split": "development",
        "category": "core_single_authority",
        "status": "needs_expert_annotation",
        "synthetic": True,
        "query": "PRIVATE TEACHING PROSE MUST NOT BE EXPORTED",
        "query_sha256": "a" * 64,
        "paraphrase_group": None,
        "task_type": "research",
        "subject": "contract",
        "jurisdiction": "England and Wales",
        "as_of_date": "2026-08-12",
        "expected_behaviour": "answer",
        "acceptable_source_ids": ["source-version-1"],
        "exact_gold_spans": [{"chunk_id": "chunk-1"}],
        "forbidden_lanes": ["private_teaching"],
        "must_cover_issues": ["issue"],
        "known_contrary_authority_ids": [],
        "privacy_flags": [],
    }
    value.update(updates)
    return value


def test_case_queue_row_omits_query_prose() -> None:
    row = case_queue_row(_case())
    assert "query" not in row
    assert row["case_id"] == "core-001"
    assert row["query_sha256"] == "a" * 64
    assert row["proposed_span_count"] == 1
    assert row["status"] == "needs_expert_annotation"


def test_build_queue_never_approves_and_counts_splits() -> None:
    cases = [
        _case(case_id="core-001", split="development"),
        _case(case_id="core-002", split="promotion", category="long_form"),
        _case(
            case_id="core-003",
            split="adversarial_holdout",
            status="needs_expert_annotation",
        ),
    ]
    manifest = {
        "status": "needs_independent_expert_annotation",
        "case_count": 3,
        "status_counts": {"needs_expert_annotation": 3},
        "split_counts": {
            "development": 1,
            "promotion": 1,
            "adversarial_holdout": 1,
        },
        "category_counts": {"core_single_authority": 2, "long_form": 1},
        "suite_version": "1.0.0",
        "suite_file_sha256": "b" * 64,
        "canonical_suite_sha256": "c" * 64,
        "blocking_gate": "independent_expert_annotation_and_owner_approval",
        "training_export_allowed": False,
        "promotion_eligible": False,
    }
    payload = build_expert_review_queue(cases, manifest, generated_at="2026-08-13T00:00:00+00:00")
    assert payload["marks_cases_approved"] is False
    assert payload["training_export_allowed"] is False
    assert payload["promotion_eligible"] is False
    assert payload["needs_expert_annotation_count"] == 3
    assert payload["split_counts_needing_review"] == {
        "adversarial_holdout": 1,
        "development": 1,
        "promotion": 1,
    }
    serialised = json.dumps(payload)
    assert "PRIVATE TEACHING PROSE" not in serialised
    assert "/Users/" not in serialised
    assert payload["gates"]["promotion_blocked_until_expert_seal"] is True


def test_assert_export_text_safe_fail_closed() -> None:
    with pytest.raises(ValueError, match="absolute host path"):
        assert_export_text_safe("see /Users/example/Desktop/secret.pdf", context="unit")
    with pytest.raises(ValueError, match="email"):
        assert_export_text_safe("contact student@example.com", context="unit")


def test_write_queue_artefacts(tmp_path: Path) -> None:
    cases = [_case(), _case(case_id="core-002", split="promotion")]
    manifest = {
        "status": "needs_independent_expert_annotation",
        "case_count": 2,
        "status_counts": {"needs_expert_annotation": 2},
        "split_counts": {"development": 1, "promotion": 1},
        "category_counts": {"core_single_authority": 2},
        "suite_version": "1.0.0",
        "training_export_allowed": False,
        "promotion_eligible": False,
    }
    payload = build_expert_review_queue(cases, manifest, generated_at="2026-08-13T00:00:00+00:00")
    written = write_expert_review_queue(tmp_path, payload)
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert "cases_needing_review" not in summary
    assert summary["needs_expert_annotation_count"] == 2
    assert summary["marks_cases_approved"] is False
    lines = (tmp_path / "cases-needing-review.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for line in lines:
        row = json.loads(line)
        assert "query" not in row
        assert row["status"] == "needs_expert_annotation"
    assert (tmp_path / "by-split" / "development.json").is_file()
    assert (tmp_path / "by-split" / "promotion.json").is_file()
    assert "summary" in written
