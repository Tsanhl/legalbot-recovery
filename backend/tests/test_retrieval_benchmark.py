from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.retrieval.benchmark import (
    REPORT_SCHEMA,
    assert_passing_benchmark_report,
    load_retrieval_benchmark,
    score_retrieval_benchmark,
)


def _benchmark_file(path: Path, *, status: str = "approved") -> Path:
    path.write_text(
        json.dumps(
            {
                "schema": "legalbot.retrieval-benchmark.v1",
                "benchmark_id": "promotion-suite",
                "version": "1.2.0",
                "status": status,
                "queries": [
                    {
                        "id": "must-hit",
                        "query": "judicial review procedural fairness",
                        "jurisdiction": "England and Wales",
                        "subject": "public law",
                        "as_of_date": "2026-08-11",
                        "primary_must_hit_chunk_ids": ["primary-1"],
                        "relevant_chunk_ids": [
                            "secondary-1",
                            *[f"broader-{number}" for number in range(1, 9)],
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_versioned_benchmark_is_owner_approved_and_hashes_canonical_json(tmp_path: Path) -> None:
    approved = load_retrieval_benchmark(_benchmark_file(tmp_path / "benchmark.json"))
    assert approved.version == "1.2.0"
    assert len(approved.sha256) == 64
    assert approved.queries[0].relevant_chunk_ids[0] == "primary-1"

    with pytest.raises(ValueError, match="owner-approved"):
        load_retrieval_benchmark(_benchmark_file(tmp_path / "draft.json", status="draft"))
    with pytest.raises(ValueError, match="missing"):
        load_retrieval_benchmark(tmp_path / "does-not-exist.json")


def test_scoring_enforces_primary_broader_and_mrr_thresholds(tmp_path: Path) -> None:
    benchmark = load_retrieval_benchmark(_benchmark_file(tmp_path / "benchmark.json"))
    expected = benchmark.queries[0].relevant_chunk_ids
    lanes = {chunk_id: "official_secondary" for chunk_id in expected}
    lanes["primary-1"] = "primary_authority"

    passing = score_retrieval_benchmark(
        benchmark,
        {"must-hit": expected[:9]},
        lanes,
    )
    assert passing["metrics"]["primary_recall_at_5"] == 1.0
    assert passing["metrics"]["broader_recall_at_10"] == 0.9
    assert passing["passed"] is False

    # The persisted report validator independently checks exact boundary values.
    boundary_report = {
        "schema": REPORT_SCHEMA,
        "passed": True,
        "integrity_failures": [],
        "metrics": {
            "primary_recall_at_5": 1.0,
            "broader_recall_at_10": 0.95,
            "mrr": 0.8,
        },
    }
    assert_passing_benchmark_report(boundary_report)
    for metric, value in (
        ("primary_recall_at_5", 0.999),
        ("broader_recall_at_10", 0.949),
        ("mrr", 0.799),
    ):
        failing = {**boundary_report, "metrics": {**boundary_report["metrics"], metric: value}}
        with pytest.raises(RuntimeError, match="promotion gates did not pass"):
            assert_passing_benchmark_report(failing)
