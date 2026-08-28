"""Layer-separated retrieval, filtering and abstention metrics."""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .suite import EvaluationCase


@dataclass(frozen=True, slots=True)
class RetrievalObservation:
    ranked_chunk_ids: tuple[str, ...]
    ranked_source_ids: tuple[str, ...]
    matched_gold_span_keys: frozenset[str] = frozenset()
    returned_contrary_source_ids: frozenset[str] = frozenset()
    prohibited_lane_hits: int = 0
    wrong_jurisdiction_hits: int = 0
    wrong_date_hits: int = 0
    context_tokens: int = 0
    relevant_context_tokens: int = 0
    parent_expansion_expected: bool = False
    parent_recovered: bool = False
    observed_behaviour: str = "answer"


def score_evaluation_retrieval(
    cases: Sequence[EvaluationCase],
    observations: Mapping[str, RetrievalObservation],
) -> dict[str, Any]:
    if not cases:
        raise ValueError("retrieval evaluation has no cases")
    if any(case.status == "needs_expert_annotation" for case in cases):
        raise ValueError("retrieval metrics require expert-annotated gold records")
    reports: list[dict[str, Any]] = []
    paraphrase_recall: dict[str, list[float]] = defaultdict(list)
    paraphrase_ranks: dict[str, list[int]] = defaultdict(list)
    fallback_tp = fallback_fp = fallback_fn = 0
    totals = {
        "recall_at_5": 0.0,
        "recall_at_10": 0.0,
        "precision_at_5": 0.0,
        "precision_at_10": 0.0,
        "mrr": 0.0,
        "ndcg_at_10": 0.0,
        "exact_source_hit": 0.0,
        "exact_span_recall": 0.0,
        "contrary_authority_recall": 0.0,
        "context_noise_fraction": 0.0,
    }
    contrary_cases = span_cases = noise_cases = 0
    parent_expected = parent_recovered = 0
    filter_violations = {"prohibited_lane": 0, "wrong_jurisdiction": 0, "wrong_date": 0}

    for case in cases:
        observed = observations.get(case.case_id)
        if observed is None:
            raise ValueError(f"missing retrieval observation for {case.case_id}")
        relevant_chunks = {span.chunk_id for span in case.exact_gold_spans}
        relevant_sources = set(case.acceptable_source_ids)
        top5 = set(observed.ranked_chunk_ids[:5])
        top10 = set(observed.ranked_chunk_ids[:10])
        recall5 = len(top5 & relevant_chunks) / len(relevant_chunks) if relevant_chunks else 1.0
        recall10 = len(top10 & relevant_chunks) / len(relevant_chunks) if relevant_chunks else 1.0
        precision5 = len(top5 & relevant_chunks) / 5
        precision10 = len(top10 & relevant_chunks) / 10
        first_rank = next(
            (
                index
                for index, chunk_id in enumerate(observed.ranked_chunk_ids, start=1)
                if chunk_id in relevant_chunks
            ),
            None,
        )
        mrr = 1 / first_rank if first_rank is not None else 0.0
        grades = {span.chunk_id: span.relevance_grade for span in case.exact_gold_spans}
        gains = [grades.get(chunk_id, 0) for chunk_id in observed.ranked_chunk_ids[:10]]
        ideal = sorted(grades.values(), reverse=True)[:10]
        dcg = sum((2**gain - 1) / math.log2(index + 1) for index, gain in enumerate(gains, 1))
        idcg = sum((2**gain - 1) / math.log2(index + 1) for index, gain in enumerate(ideal, 1))
        ndcg = dcg / idcg if idcg else 1.0
        source_hit = float(bool(relevant_sources & set(observed.ranked_source_ids)))
        expected_span_keys = {
            f"{span.chunk_id}:{span.character_start}:{span.character_end}"
            for span in case.exact_gold_spans
        }
        span_recall = (
            len(expected_span_keys & observed.matched_gold_span_keys) / len(expected_span_keys)
            if expected_span_keys
            else 1.0
        )
        if expected_span_keys:
            span_cases += 1
            totals["exact_span_recall"] += span_recall
        contrary_expected = set(case.known_contrary_authority_ids)
        contrary_recall = (
            len(contrary_expected & observed.returned_contrary_source_ids) / len(contrary_expected)
            if contrary_expected
            else 1.0
        )
        if contrary_expected:
            contrary_cases += 1
            totals["contrary_authority_recall"] += contrary_recall
        noise = 0.0
        if observed.context_tokens:
            noise = max(
                0.0,
                min(
                    1.0,
                    (observed.context_tokens - observed.relevant_context_tokens)
                    / observed.context_tokens,
                ),
            )
            noise_cases += 1
            totals["context_noise_fraction"] += noise
        if observed.parent_expansion_expected:
            parent_expected += 1
            parent_recovered += int(observed.parent_recovered)
        filter_violations["prohibited_lane"] += observed.prohibited_lane_hits
        filter_violations["wrong_jurisdiction"] += observed.wrong_jurisdiction_hits
        filter_violations["wrong_date"] += observed.wrong_date_hits
        expects_fallback = case.expected_behaviour in {"refuse", "clarify", "fallback"}
        observed_fallback = observed.observed_behaviour in {"refuse", "clarify", "fallback"}
        fallback_tp += int(expects_fallback and observed_fallback)
        fallback_fp += int(not expects_fallback and observed_fallback)
        fallback_fn += int(expects_fallback and not observed_fallback)
        if case.paraphrase_group:
            paraphrase_recall[case.paraphrase_group].append(recall10)
            paraphrase_ranks[case.paraphrase_group].append(first_rank or 11)
        for key, value in (
            ("recall_at_5", recall5),
            ("recall_at_10", recall10),
            ("precision_at_5", precision5),
            ("precision_at_10", precision10),
            ("mrr", mrr),
            ("ndcg_at_10", ndcg),
            ("exact_source_hit", source_hit),
        ):
            totals[key] += value
        reports.append(
            {
                "case_id": case.case_id,
                "recall_at_5": recall5,
                "recall_at_10": recall10,
                "precision_at_5": precision5,
                "precision_at_10": precision10,
                "mrr": mrr,
                "ndcg_at_10": ndcg,
                "exact_source_hit": source_hit,
                "exact_span_recall": span_recall,
                "contrary_authority_recall": contrary_recall,
                "context_noise_fraction": noise,
            }
        )
    count = len(cases)
    aggregate: dict[str, Any] = {
        key: value / count
        for key, value in totals.items()
        if key not in {"exact_span_recall", "contrary_authority_recall", "context_noise_fraction"}
    }
    aggregate.update(
        {
            "exact_span_recall": totals["exact_span_recall"] / span_cases if span_cases else None,
            "contrary_authority_recall": (
                totals["contrary_authority_recall"] / contrary_cases if contrary_cases else None
            ),
            "context_noise_fraction": (
                totals["context_noise_fraction"] / noise_cases if noise_cases else None
            ),
            "parent_section_recovery_rate": (
                parent_recovered / parent_expected if parent_expected else None
            ),
            "paraphrase_worst_case_recall_at_10": (
                min(min(values) for values in paraphrase_recall.values())
                if paraphrase_recall
                else None
            ),
            "paraphrase_max_rank_spread": (
                max(max(values) - min(values) for values in paraphrase_ranks.values())
                if paraphrase_ranks
                else None
            ),
            "fallback_precision": (
                fallback_tp / (fallback_tp + fallback_fp) if fallback_tp + fallback_fp else None
            ),
            "fallback_recall": (
                fallback_tp / (fallback_tp + fallback_fn) if fallback_tp + fallback_fn else None
            ),
            "filter_violations": filter_violations,
        }
    )
    return {
        "schema": "legalbot.layered-retrieval-metrics.v1",
        "case_count": count,
        "aggregate": aggregate,
        "cases": reports,
    }
