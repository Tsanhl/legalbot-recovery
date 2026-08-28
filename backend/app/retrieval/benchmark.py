"""Legacy chunk-ID benchmark support for isolated unit fixtures only.

This is not the LegalBot promotion scorer. Chunk IDs are implementation
artefacts. The sole promotion specification is v1.1 and is scored by
``retrieval_v1.py`` against stable authority + locator/span gold.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

BENCHMARK_SCHEMA = "legalbot.retrieval-benchmark.v1"
REPORT_SCHEMA = "legalbot.retrieval-benchmark-report.v1"
PRIMARY_RECALL_AT_5_MINIMUM = 1.0
BROADER_RECALL_AT_10_MINIMUM = 0.95
MRR_MINIMUM = 0.8


@dataclass(frozen=True, slots=True)
class BenchmarkQuery:
    id: str
    query: str
    jurisdiction: str
    subject: str | None
    as_of_date: date
    primary_must_hit_chunk_ids: tuple[str, ...]
    relevant_chunk_ids: tuple[str, ...]
    relevance_grades: Mapping[str, int]
    paraphrase_group: str | None


@dataclass(frozen=True, slots=True)
class RetrievalBenchmark:
    benchmark_id: str
    version: str
    queries: tuple[BenchmarkQuery, ...]
    canonical_bytes: bytes
    sha256: str


def load_retrieval_benchmark(path: Path, *, require_approved: bool = True) -> RetrievalBenchmark:
    """Load a versioned benchmark; promotion requires owner-approved status."""

    if not path.is_file():
        raise ValueError(f"versioned retrieval benchmark is missing: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("retrieval benchmark must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("retrieval benchmark root must be an object")
    if payload.get("schema") != BENCHMARK_SCHEMA:
        raise ValueError(f"retrieval benchmark schema must be {BENCHMARK_SCHEMA}")
    benchmark_id = _required_safe_text(payload, "benchmark_id")
    version = _required_safe_text(payload, "version")
    if not re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", version):
        raise ValueError("retrieval benchmark version must be semantic (for example 1.0.0)")
    status = payload.get("status")
    if require_approved and status != "approved":
        raise ValueError("retrieval benchmark must have owner-approved status")
    if not require_approved and status not in {"draft", "approved"}:
        raise ValueError("development benchmark status must be draft or approved")
    raw_queries = payload.get("queries")
    if not isinstance(raw_queries, list) or not raw_queries:
        raise ValueError("retrieval benchmark must contain at least one query")

    queries: list[BenchmarkQuery] = []
    query_ids: set[str] = set()
    primary_count = 0
    for position, value in enumerate(raw_queries):
        if not isinstance(value, dict):
            raise ValueError(f"retrieval benchmark query {position + 1} must be an object")
        query_id = _required_safe_text(value, "id")
        if query_id in query_ids:
            raise ValueError(f"retrieval benchmark query id is duplicated: {query_id}")
        query_ids.add(query_id)
        query_text = _required_text(value, "query")
        jurisdiction = _required_text(value, "jurisdiction")
        subject_value = value.get("subject")
        if subject_value is not None and (
            not isinstance(subject_value, str) or not subject_value.strip()
        ):
            raise ValueError(f"benchmark query {query_id} has an invalid subject")
        try:
            as_of = date.fromisoformat(_required_text(value, "as_of_date"))
        except ValueError as exc:
            raise ValueError(f"benchmark query {query_id} has an invalid as_of_date") from exc
        primary = _unique_id_list(value, "primary_must_hit_chunk_ids", query_id)
        relevant = _unique_id_list(value, "relevant_chunk_ids", query_id)
        if not primary and not relevant:
            raise ValueError(f"benchmark query {query_id} has no expected chunks")
        if len(primary) > 5:
            raise ValueError(f"benchmark query {query_id} has more than five primary must-hits")
        primary_count += len(primary)
        # Primary must-hits are always relevant for the broader and MRR gates.
        combined_relevant = tuple(dict.fromkeys((*primary, *relevant)))
        if len(combined_relevant) > 10:
            raise ValueError(f"benchmark query {query_id} has more than ten relevant chunks")
        raw_grades = value.get("relevance_grades", {})
        if not isinstance(raw_grades, dict) or any(
            chunk_id not in combined_relevant
            or isinstance(grade, bool)
            or not isinstance(grade, int)
            or grade < 1
            or grade > 3
            for chunk_id, grade in raw_grades.items()
        ):
            raise ValueError(f"benchmark query {query_id} has invalid relevance grades")
        grades = {
            chunk_id: int(raw_grades.get(chunk_id, 3 if chunk_id in primary else 1))
            for chunk_id in combined_relevant
        }
        paraphrase_group = value.get("paraphrase_group")
        if paraphrase_group is not None and (
            not isinstance(paraphrase_group, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", paraphrase_group)
        ):
            raise ValueError(f"benchmark query {query_id} has invalid paraphrase group")
        queries.append(
            BenchmarkQuery(
                id=query_id,
                query=query_text,
                jurisdiction=jurisdiction,
                subject=subject_value.strip() if isinstance(subject_value, str) else None,
                as_of_date=as_of,
                primary_must_hit_chunk_ids=primary,
                relevant_chunk_ids=combined_relevant,
                relevance_grades=grades,
                paraphrase_group=paraphrase_group,
            )
        )
    if primary_count == 0:
        raise ValueError("retrieval benchmark must contain primary-authority must-hit chunks")

    canonical = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    return RetrievalBenchmark(
        benchmark_id=benchmark_id,
        version=version,
        queries=tuple(queries),
        canonical_bytes=canonical,
        sha256=hashlib.sha256(canonical).hexdigest(),
    )


def score_retrieval_benchmark(
    benchmark: RetrievalBenchmark,
    rankings: Mapping[str, Sequence[str]],
    indexed_chunk_lanes: Mapping[str, str],
) -> dict[str, Any]:
    """Score deterministic rankings and return a sealable gate report."""

    integrity_failures: list[str] = []
    expected = {chunk_id for query in benchmark.queries for chunk_id in query.relevant_chunk_ids}
    missing = sorted(expected - indexed_chunk_lanes.keys())
    if missing:
        integrity_failures.append(
            "benchmark expected chunks missing from candidate: " + ", ".join(missing)
        )
    wrong_primary_lane = sorted(
        {
            chunk_id
            for query in benchmark.queries
            for chunk_id in query.primary_must_hit_chunk_ids
            if indexed_chunk_lanes.get(chunk_id) not in {None, "primary_authority"}
        }
    )
    if wrong_primary_lane:
        integrity_failures.append(
            "primary must-hit chunks are not primary authority: " + ", ".join(wrong_primary_lane)
        )

    primary_total = 0
    primary_hits = 0
    broader_total = 0
    broader_hits = 0
    reciprocal_ranks: list[float] = []
    precision_at_5_values: list[float] = []
    precision_at_10_values: list[float] = []
    ndcg_at_10_values: list[float] = []
    group_recalls: dict[str, list[float]] = {}
    group_ranks: dict[str, list[int]] = {}
    query_reports: list[dict[str, Any]] = []
    for query in benchmark.queries:
        ranking = tuple(dict.fromkeys(str(item) for item in rankings.get(query.id, ())))
        top_five = set(ranking[:5])
        top_ten = set(ranking[:10])
        primary_expected = set(query.primary_must_hit_chunk_ids)
        relevant_expected = set(query.relevant_chunk_ids)
        primary_found = primary_expected & top_five
        relevant_found = relevant_expected & top_ten
        primary_total += len(primary_expected)
        primary_hits += len(primary_found)
        broader_total += len(relevant_expected)
        broader_hits += len(relevant_found)
        first_rank = next(
            (rank for rank, chunk_id in enumerate(ranking, 1) if chunk_id in relevant_expected),
            None,
        )
        reciprocal_rank = 1.0 / first_rank if first_rank is not None else 0.0
        reciprocal_ranks.append(reciprocal_rank)
        precision_at_5 = len(relevant_expected & top_five) / 5
        precision_at_10 = len(relevant_found) / 10
        precision_at_5_values.append(precision_at_5)
        precision_at_10_values.append(precision_at_10)
        gains = [int(query.relevance_grades.get(chunk_id, 0)) for chunk_id in ranking[:10]]
        ideal = sorted(query.relevance_grades.values(), reverse=True)[:10]
        dcg = sum((2**gain - 1) / math.log2(rank + 1) for rank, gain in enumerate(gains, 1))
        idcg = sum((2**gain - 1) / math.log2(rank + 1) for rank, gain in enumerate(ideal, 1))
        ndcg_at_10 = dcg / idcg if idcg else 0.0
        ndcg_at_10_values.append(ndcg_at_10)
        if query.paraphrase_group:
            recall = len(relevant_found) / len(relevant_expected)
            group_recalls.setdefault(query.paraphrase_group, []).append(recall)
            group_ranks.setdefault(query.paraphrase_group, []).append(first_rank or 11)
        query_reports.append(
            {
                "id": query.id,
                "primary_expected": sorted(primary_expected),
                "primary_found_at_5": sorted(primary_found),
                "relevant_expected": sorted(relevant_expected),
                "relevant_found_at_10": sorted(relevant_found),
                "first_relevant_rank": first_rank,
                "returned_chunk_ids": list(ranking),
                "precision_at_5": precision_at_5,
                "precision_at_10": precision_at_10,
                "ndcg_at_10": ndcg_at_10,
            }
        )

    primary_recall = primary_hits / primary_total
    broader_recall = broader_hits / broader_total
    mrr = sum(reciprocal_ranks) / len(reciprocal_ranks)
    thresholds = {
        "primary_recall_at_5": PRIMARY_RECALL_AT_5_MINIMUM,
        "broader_recall_at_10": BROADER_RECALL_AT_10_MINIMUM,
        "mrr": MRR_MINIMUM,
    }
    metrics = {
        "primary_recall_at_5": primary_recall,
        "broader_recall_at_10": broader_recall,
        "mrr": mrr,
        "primary_hits": primary_hits,
        "primary_expected": primary_total,
        "broader_hits": broader_hits,
        "broader_expected": broader_total,
        "query_count": len(benchmark.queries),
        "precision_at_5": sum(precision_at_5_values) / len(precision_at_5_values),
        "precision_at_10": sum(precision_at_10_values) / len(precision_at_10_values),
        "ndcg_at_10": sum(ndcg_at_10_values) / len(ndcg_at_10_values),
        "paraphrase_worst_case_recall_at_10": (
            min(min(values) for values in group_recalls.values()) if group_recalls else None
        ),
        "paraphrase_max_rank_spread": (
            max(max(values) - min(values) for values in group_ranks.values())
            if group_ranks
            else None
        ),
    }
    passed = (
        not integrity_failures
        and primary_recall >= PRIMARY_RECALL_AT_5_MINIMUM
        and broader_recall >= BROADER_RECALL_AT_10_MINIMUM
        and mrr >= MRR_MINIMUM
    )
    return {
        "schema": REPORT_SCHEMA,
        "benchmark_id": benchmark.benchmark_id,
        "benchmark_version": benchmark.version,
        "benchmark_sha256": benchmark.sha256,
        "passed": passed,
        "thresholds": thresholds,
        "metrics": metrics,
        "integrity_failures": integrity_failures,
        "queries": query_reports,
    }


def assert_passing_benchmark_report(report: Mapping[str, Any]) -> None:
    """Re-evaluate persisted metrics instead of trusting a single passed flag."""

    if report.get("schema") != REPORT_SCHEMA:
        raise RuntimeError("candidate retrieval benchmark report schema is invalid")
    metrics = report.get("metrics")
    failures = report.get("integrity_failures")
    if not isinstance(metrics, dict) or not isinstance(failures, list):
        raise RuntimeError("candidate retrieval benchmark report is incomplete")
    try:
        primary_recall = float(metrics["primary_recall_at_5"])
        broader_recall = float(metrics["broader_recall_at_10"])
        mrr = float(metrics["mrr"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("candidate retrieval benchmark metrics are invalid") from exc
    if (
        report.get("passed") is not True
        or failures
        or primary_recall < PRIMARY_RECALL_AT_5_MINIMUM
        or broader_recall < BROADER_RECALL_AT_10_MINIMUM
        or mrr < MRR_MINIMUM
    ):
        raise RuntimeError("candidate retrieval benchmark promotion gates did not pass")


def _required_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"retrieval benchmark field {key} is required")
    return value.strip()


def _required_safe_text(payload: Mapping[str, Any], key: str) -> str:
    value = _required_text(payload, key)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
        raise ValueError(f"retrieval benchmark field {key} contains unsafe characters")
    return value


def _unique_id_list(payload: Mapping[str, Any], key: str, query_id: str) -> tuple[str, ...]:
    value = payload.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"benchmark query {query_id} field {key} must be a list of ids")
    if len(value) != len(set(value)):
        raise ValueError(f"benchmark query {query_id} field {key} contains duplicate ids")
    return tuple(value)
