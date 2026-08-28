from __future__ import annotations

from backend.tests.test_evaluation_suite import _case

from app.evaluation.metrics import RetrievalObservation, score_evaluation_retrieval
from app.evaluation.suite import EvaluationCase


def test_layered_metrics_score_retrieval_filters_spans_and_fallback() -> None:
    value = _case(
        status="sealed",
        corpus_manifest_sha256="a" * 64,
        acceptable_source_ids=["source-one"],
        exact_gold_spans=[
            {
                "source_version_id": "source-one",
                "chunk_id": "chunk-one",
                "content_hash": "b" * 64,
                "exact_locator": "[1]",
                "character_start": 0,
                "character_end": 10,
                "relevance_grade": 3,
                "supported_issue_ids": ["rule"],
            }
        ],
    )
    case = EvaluationCase.model_validate(value)
    report = score_evaluation_retrieval(
        [case],
        {
            case.case_id: RetrievalObservation(
                ranked_chunk_ids=("chunk-one", "noise"),
                ranked_source_ids=("source-one", "source-noise"),
                matched_gold_span_keys=frozenset({"chunk-one:0:10"}),
                context_tokens=100,
                relevant_context_tokens=70,
            )
        },
    )
    assert report["aggregate"]["recall_at_5"] == 1
    assert report["aggregate"]["mrr"] == 1
    assert report["aggregate"]["exact_span_recall"] == 1
    assert report["aggregate"]["context_noise_fraction"] == 0.3
    assert report["aggregate"]["filter_violations"] == {
        "prohibited_lane": 0,
        "wrong_jurisdiction": 0,
        "wrong_date": 0,
    }
