"""Coverage-first Stage A evaluation for a manifest-driven Live60 run."""

from __future__ import annotations

import asyncio
import hashlib
import math
import time
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Protocol, cast

from ..orchestration.classifier import classify_subject, classify_subjects
from ..orchestration.routing import decide_route
from ..retrieval.service import _query_subjects
from ..types import EvidenceSpan, TaskType
from .live30 import RunEventType, RunStage, RunStatus
from .live30_coverage import _candidate_matches_gold, _safe_candidate
from .live_suite import LiveEvaluationBundle, LiveQuestionCase
from .live_suite_gold import (
    LiveCaseQualification,
    LiveGoldSpan,
    LiveSuiteExpertQualification,
)
from .live_suite_store import LiveSuiteRunEvent, LiveSuiteRunStore

COVERAGE_SCHEMA = "legalbot.live-coverage.v3"
RETRIEVAL_SCHEMA = "legalbot.live-retrieval.v3"
EVIDENCE_MAP_SCHEMA = "legalbot.live-evidence-map.v3"
METRICS_SCHEMA = "legalbot.live-readiness-metrics.v3"
SUMMARY_SCHEMA = "legalbot.live-coverage-summary.v3"


class CoverageRetriever(Protocol):
    async def retrieve(
        self,
        *,
        query: str,
        jurisdiction: str,
        subject: str | None,
        as_of_date: date,
        limit: int = 30,
    ) -> Sequence[EvidenceSpan]: ...


@dataclass(frozen=True, slots=True)
class CoverageCaseResult:
    case_id: str
    disposition: str
    qualification_status: str | None
    deterministic_outcome: str
    coverage_status: str
    evidence_generation_eligible: bool
    selected_generation_eligible: bool
    route_passed: bool
    subject_routing_passed: bool
    subject_routing_state: str
    issue_count: int
    scored_issue_count: int
    issues_with_candidates: int
    issues_with_no_candidates: int
    retrieval_duration_ms: int
    index_build_id: str | None
    filter_violation_count: int
    context_token_count: int
    context_noise_token_count: int
    issue_hits_at_5: int
    issue_hits_at_10: int
    reciprocal_rank_sum: float
    ndcg_sum: float
    gold_span_count: int
    retrieved_gold_span_count: int
    contrary_gold_span_count: int
    retrieved_contrary_gold_span_count: int


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _subject_routing_readiness(
    case: LiveQuestionCase,
) -> tuple[str, bool, tuple[str, ...]]:
    observed = classify_subjects(case.question)
    expected_catalogue = _query_subjects(case.subject)
    observed_catalogue = frozenset(
        subject for item in observed for subject in _query_subjects(item)
    )
    if expected_catalogue.intersection(observed_catalogue):
        return "compatible", True, observed
    if not observed or case.expected_research_route == "full_enquiry":
        return "explicit_broad_fallback", True, observed
    return "incompatible_narrow_filter", False, observed


async def _retrieve_issue(
    *,
    retriever: CoverageRetriever,
    case: LiveQuestionCase,
    issue_number: int,
    issue: str,
    as_of_date: date,
    semaphore: asyncio.Semaphore,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    issue_id = f"issue-{issue_number:02d}"
    started = time.perf_counter()
    error_code: str | None = None
    retrieval_subject = classify_subject(issue)
    evidence: list[EvidenceSpan]
    try:
        async with semaphore:
            evidence = list(
                await retriever.retrieve(
                    query=issue,
                    jurisdiction=case.jurisdiction,
                    subject=retrieval_subject,
                    as_of_date=as_of_date,
                    limit=10,
                )
            )
    except Exception as exc:
        evidence = []
        error_code = type(exc).__name__
    duration_ms = round((time.perf_counter() - started) * 1_000)
    candidates: list[dict[str, object]] = []
    for rank, span in enumerate(evidence, 1):
        candidate = _safe_candidate(
            span,
            rank,
            requested_jurisdiction=case.jurisdiction,
            as_of_date=as_of_date,
        )
        candidate["context_token_count"] = len(span.text.split())
        candidates.append(candidate)
    qualified_count = sum(bool(item["runtime_qualification_passed"]) for item in candidates)
    status = (
        "retrieval_error"
        if error_code
        else "candidate_evidence_needs_expert_span_review"
        if qualified_count
        else "knowledge_gap"
    )
    return (
        {
            "issue_id": issue_id,
            "issue_sha256": _sha256(issue),
            "status": status,
            "duration_ms": duration_ms,
            "result_count": len(candidates),
            "runtime_qualified_candidate_count": qualified_count,
            "expert_support_verified": False,
            "retrieval_subject": retrieval_subject,
            "error_code": error_code,
        },
        candidates,
    )


def _matches(candidate: Mapping[str, object], gold: LiveGoldSpan) -> bool:
    return _candidate_matches_gold(candidate, gold)


async def run_case_coverage(
    *,
    store: LiveSuiteRunStore,
    retriever: CoverageRetriever,
    run_id: str,
    case: LiveQuestionCase,
    disposition: str,
    qualification: LiveCaseQualification | None = None,
) -> CoverageCaseResult:
    as_of_date, encrypted_case = store.load_encrypted_question(run_id=run_id, case_id=case.case_id)
    if encrypted_case.record_sha256 != case.record_sha256:
        raise RuntimeError("run question differs from the immutable registry")
    started = time.perf_counter()
    observed_route = decide_route(case.question, case.word_target, TaskType(case.task_type))
    route_passed = str(observed_route.route) == case.expected_research_route
    subject_state, subject_passed, recognised_subjects = _subject_routing_readiness(case)
    store.record_event(
        LiveSuiteRunEvent(
            event_id=uuid.uuid4().hex,
            timestamp=datetime.now(UTC),
            run_id=run_id,
            case_id=case.case_id,
            event_type=RunEventType.CASE_STARTED,
            stage=RunStage.ROUTING,
            status=RunStatus.RUNNING,
        )
    )
    semaphore = asyncio.Semaphore(4)
    issue_results = await asyncio.gather(
        *(
            _retrieve_issue(
                retriever=retriever,
                case=case,
                issue_number=index,
                issue=issue,
                as_of_date=as_of_date,
                semaphore=semaphore,
            )
            for index, issue in enumerate(case.must_cover_issues, 1)
        )
    )

    issues = [item[0] for item in issue_results]
    evidence_map: list[dict[str, Any]] = []
    reciprocal_ranks: list[float] = []
    issue_ndcg: list[float] = []
    issue_hits_at_5 = 0
    issue_hits_at_10 = 0
    scored_issue_count = 0
    retrieved_gold_ids: set[str] = set()
    all_gold_ids: set[str] = set()
    retrieved_contrary_ids: set[str] = set()
    contrary_gold_ids: set[str] = set()
    filter_violations = 0
    context_tokens = 0
    noise_tokens = 0

    for issue, candidates in issue_results:
        issue_qualification = (
            qualification.issue(cast(str, issue["issue_id"])) if qualification is not None else None
        )
        qualification_status = (
            issue_qualification.status if issue_qualification is not None else None
        )
        ranking_evaluable = qualification_status in {"qualified", "limited"}
        issue_gold = (
            issue_qualification.exact_gold_spans
            if issue_qualification is not None and ranking_evaluable
            else ()
        )
        if ranking_evaluable:
            scored_issue_count += 1
        contrary_issue_gold = tuple(span for span in issue_gold if span.contrary_or_limiting)
        all_gold_ids.update(span.gold_span_id for span in issue_gold)
        contrary_gold_ids.update(span.gold_span_id for span in contrary_issue_gold)
        matched_positive_ranks: list[int] = []
        matched_gold: list[str] = []
        credited_for_dcg: set[str] = set()
        dcg = 0.0
        for rank, candidate in enumerate(candidates, 1):
            token_count = cast(int, candidate.get("context_token_count") or 0)
            context_tokens += token_count
            filter_violations += int(candidate.get("runtime_qualification_passed") is not True)
            candidate_matched = False
            for gold in issue_gold:
                if not _matches(candidate, gold):
                    continue
                candidate_matched = True
                matched_gold.append(gold.gold_span_id)
                retrieved_gold_ids.add(gold.gold_span_id)
                if gold.contrary_or_limiting:
                    retrieved_contrary_ids.add(gold.gold_span_id)
                else:
                    matched_positive_ranks.append(rank)
                if rank <= 10 and gold.gold_span_id not in credited_for_dcg:
                    dcg += (2**gold.relevance_grade - 1) / math.log2(rank + 1)
                    credited_for_dcg.add(gold.gold_span_id)
            if ranking_evaluable and not candidate_matched:
                noise_tokens += token_count
        ideal_grades = sorted((span.relevance_grade for span in issue_gold), reverse=True)[:10]
        idcg = sum(
            (2**grade - 1) / math.log2(rank + 1) for rank, grade in enumerate(ideal_grades, 1)
        )
        if ranking_evaluable:
            issue_ndcg.append(dcg / idcg if idcg else 1.0)
        if matched_positive_ranks:
            best_rank = min(matched_positive_ranks)
            reciprocal_ranks.append(1 / best_rank)
            issue_hits_at_5 += int(best_rank <= 5)
            issue_hits_at_10 += int(best_rank <= 10)
        elif ranking_evaluable:
            reciprocal_ranks.append(0.0)
        issue["expert_qualification_status"] = qualification_status
        issue["expert_reason_code"] = (
            issue_qualification.reason_code if issue_qualification is not None else None
        )
        issue["ranking_evaluated"] = ranking_evaluable
        issue["expert_support_verified"] = bool(ranking_evaluable and matched_positive_ranks)
        issue["contrary_support_verified"] = bool(
            ranking_evaluable
            and (
                not contrary_issue_gold
                or all(span.gold_span_id in retrieved_contrary_ids for span in contrary_issue_gold)
            )
        )
        evidence_map.append(
            {
                "issue_id": issue["issue_id"],
                "issue_sha256": issue["issue_sha256"],
                "expert_qualification_status": qualification_status,
                "ranking_evaluated": ranking_evaluable,
                "matched_gold_span_ids": sorted(set(matched_gold)),
                "ndcg_at_10": (round(issue_ndcg[-1], 8) if ranking_evaluable else None),
                "candidates": candidates,
            }
        )

    issues_with_candidates = sum(
        int(cast(int, item["runtime_qualified_candidate_count"]) > 0) for item in issues
    )
    errors = sum(int(item["status"] == "retrieval_error") for item in issues)
    missing = len(issues) - issues_with_candidates
    qualification_status = qualification.status if qualification is not None else None
    if qualification_status == "knowledge_gap":
        coverage_status = "knowledge_gap"
    elif qualification_status == "limited":
        coverage_status = "evidence_limited"
    elif qualification_status == "qualified":
        if errors:
            coverage_status = "retrieval_error"
        elif any(not bool(item["expert_support_verified"]) for item in issues):
            coverage_status = "qualified_gold_not_retrieved"
        elif not route_passed or not subject_passed:
            coverage_status = "routing_failure"
        elif filter_violations:
            coverage_status = "filtering_failure"
        else:
            coverage_status = "qualified"
    elif errors:
        coverage_status = "retrieval_error"
    elif missing:
        coverage_status = "knowledge_gap"
    else:
        coverage_status = "provisional_needs_expert_span_review"

    evidence_eligible = bool(
        qualification is not None
        and qualification.status == "qualified"
        and not errors
        and not filter_violations
        and route_passed
        and subject_passed
        and all(bool(item["expert_support_verified"]) for item in issues)
        and all(bool(item["contrary_support_verified"]) for item in issues)
    )
    selected_eligible = evidence_eligible and disposition == "generate_once"
    deterministic_outcome = (
        "coverage_only_not_selected"
        if disposition == "coverage_only_not_selected"
        else "generate"
        if selected_eligible
        else "limited"
        if qualification_status == "limited"
        else "held"
    )
    duration_ms = round((time.perf_counter() - started) * 1_000)
    build_ids = {
        str(candidate["index_build_id"])
        for item in evidence_map
        for candidate in cast(list[dict[str, object]], item["candidates"])
    }
    if len(build_ids) > 1:
        raise RuntimeError("coverage retrieval mixed immutable index builds")

    store.store_safe_case_json(
        run_id=run_id,
        case_id=case.case_id,
        filename="retrieval.json",
        value={
            "schema": RETRIEVAL_SCHEMA,
            "run_id": run_id,
            "case_id": case.case_id,
            "as_of_date": as_of_date.isoformat(),
            "index_build_id": next(iter(build_ids), None),
            "issue_results": issues,
        },
    )
    store.store_safe_case_json(
        run_id=run_id,
        case_id=case.case_id,
        filename="evidence-map.json",
        value={
            "schema": EVIDENCE_MAP_SCHEMA,
            "run_id": run_id,
            "case_id": case.case_id,
            "expert_qualification_present": qualification is not None,
            "issues": evidence_map,
        },
    )
    store.store_safe_case_json(
        run_id=run_id,
        case_id=case.case_id,
        filename="coverage.json",
        value={
            "schema": COVERAGE_SCHEMA,
            "run_id": run_id,
            "case_id": case.case_id,
            "run_plan_disposition": disposition,
            "coverage_status": coverage_status,
            "expert_qualification_status": qualification_status,
            "deterministic_outcome": deterministic_outcome,
            "evidence_generation_eligible": evidence_eligible,
            "selected_generation_eligible": selected_eligible,
            "expected_route": case.expected_research_route,
            "observed_route": str(observed_route.route),
            "route_passed": route_passed,
            "subject_routing_passed": subject_passed,
            "subject_routing_state": subject_state,
            "recognised_subjects": list(recognised_subjects),
            "route_reason_codes": list(observed_route.reasons),
            "issue_count": len(issues),
            "scored_issue_count": scored_issue_count,
            "issues_with_candidates": issues_with_candidates,
            "issues_with_no_candidates": missing,
            "retrieval_errors": errors,
            "filter_violation_count": filter_violations,
        },
    )
    store.store_safe_case_json(
        run_id=run_id,
        case_id=case.case_id,
        filename="metrics.json",
        value={
            "schema": METRICS_SCHEMA,
            "run_id": run_id,
            "case_id": case.case_id,
            "retrieval_duration_ms": duration_ms,
            "expert_qualification_status": qualification_status,
            "scored_issue_count": scored_issue_count,
            "recall_at_5": (
                round(issue_hits_at_5 / scored_issue_count, 8) if scored_issue_count else None
            ),
            "recall_at_10": (
                round(issue_hits_at_10 / scored_issue_count, 8) if scored_issue_count else None
            ),
            "mrr": (
                round(sum(reciprocal_ranks) / len(reciprocal_ranks), 8)
                if reciprocal_ranks
                else None
            ),
            "ndcg_at_10": (round(sum(issue_ndcg) / len(issue_ndcg), 8) if issue_ndcg else None),
            "exact_span_recall": (
                round(len(retrieved_gold_ids) / len(all_gold_ids), 8) if all_gold_ids else None
            ),
            "contrary_authority_recall": (
                round(len(retrieved_contrary_ids) / len(contrary_gold_ids), 8)
                if contrary_gold_ids
                else 1.0
                if scored_issue_count
                else None
            ),
            "filter_violation_count": filter_violations,
            "context_token_count": context_tokens,
            "context_noise_token_fraction": (
                round(noise_tokens / context_tokens, 8)
                if context_tokens and scored_issue_count
                else None
            ),
            "ranking_metric_state": (
                "evaluated_against_sealed_qualifying_issue_gold"
                if scored_issue_count
                else "not_evaluated_without_qualifying_issue_gold"
            ),
        },
    )
    for issue in issues:
        expert_status = issue.get("expert_qualification_status")
        reason_code = (
            "expert_knowledge_gap"
            if expert_status == "knowledge_gap"
            else "expert_evidence_limited"
            if expert_status == "limited"
            else cast(str, issue["status"])
            if issue["status"] in {"knowledge_gap", "retrieval_error"}
            else None
        )
        if reason_code is not None:
            store.append_safe_run_index(
                run_id=run_id,
                index_name="knowledge-gaps",
                value={
                    "schema": "legalbot.live-safe-gap.v2",
                    "gap_id": f"gap-{uuid.uuid4().hex[:20]}",
                    "run_id": run_id,
                    "case_id": case.case_id,
                    "issue_id": issue["issue_id"],
                    "issue_sha256": issue["issue_sha256"],
                    "status": "open",
                    "reason_code": reason_code,
                    "expert_reason_code": issue.get("expert_reason_code"),
                },
            )
    store.record_event(
        LiveSuiteRunEvent(
            event_id=uuid.uuid4().hex,
            timestamp=datetime.now(UTC),
            run_id=run_id,
            case_id=case.case_id,
            event_type=RunEventType.STAGE_COMPLETED,
            stage=RunStage.RETRIEVAL,
            status=RunStatus.COMPLETE,
            duration_ms=duration_ms,
        )
    )
    return CoverageCaseResult(
        case_id=case.case_id,
        disposition=disposition,
        qualification_status=qualification_status,
        deterministic_outcome=deterministic_outcome,
        coverage_status=coverage_status,
        evidence_generation_eligible=evidence_eligible,
        selected_generation_eligible=selected_eligible,
        route_passed=route_passed,
        subject_routing_passed=subject_passed,
        subject_routing_state=subject_state,
        issue_count=len(issues),
        scored_issue_count=scored_issue_count,
        issues_with_candidates=issues_with_candidates,
        issues_with_no_candidates=missing,
        retrieval_duration_ms=duration_ms,
        index_build_id=next(iter(build_ids), None),
        filter_violation_count=filter_violations,
        context_token_count=context_tokens,
        context_noise_token_count=noise_tokens,
        issue_hits_at_5=issue_hits_at_5,
        issue_hits_at_10=issue_hits_at_10,
        reciprocal_rank_sum=sum(reciprocal_ranks),
        ndcg_sum=sum(issue_ndcg),
        gold_span_count=len(all_gold_ids),
        retrieved_gold_span_count=len(retrieved_gold_ids),
        contrary_gold_span_count=len(contrary_gold_ids),
        retrieved_contrary_gold_span_count=len(retrieved_contrary_ids),
    )


async def run_suite_coverage(
    *,
    store: LiveSuiteRunStore,
    retriever: CoverageRetriever,
    run_id: str,
    bundle: LiveEvaluationBundle,
    qualification: LiveSuiteExpertQualification | None = None,
) -> Mapping[str, object]:
    manifest = store.load_run_manifest(run_id)
    if manifest.suite_manifest_seal_sha256 != bundle.manifest.seal_sha256:
        raise ValueError("run is bound to a different suite manifest")
    if manifest.run_plan_seal_sha256 != bundle.run_plan.seal_sha256:
        raise ValueError("run is bound to a different generation plan")
    if qualification is not None:
        if qualification.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256:
            raise ValueError("expert qualification is bound to a different registry")
        if qualification.run_plan_sha256 != bundle.manifest.run_plan_sha256:
            raise ValueError("expert qualification is bound to a different run plan")
        if qualification.index_build_id != manifest.provenance.index_build_id:
            raise ValueError("expert qualification is bound to a different index build")
        if qualification.as_of_date.isoformat() != manifest.as_of_date:
            raise ValueError("expert qualification is bound to a different legal date")
        store.store_safe_run_json(
            run_id=run_id,
            filename="expert-qualification.json",
            value=qualification.model_dump(mode="json", by_alias=True),
        )
    dispositions = {item.case_id: item.disposition for item in bundle.run_plan.cases}
    results = [
        await run_case_coverage(
            store=store,
            retriever=retriever,
            run_id=run_id,
            case=case,
            disposition=dispositions[case.case_id],
            qualification=(qualification.case(case.case_id) if qualification else None),
        )
        for case in bundle.registry.cases
    ]
    statuses = Counter(item.coverage_status for item in results)
    qualification_statuses = Counter(
        item.qualification_status for item in results if item.qualification_status is not None
    )
    total_issues = sum(item.issue_count for item in results)
    scored_issues = sum(item.scored_issue_count for item in results)
    total_gold = sum(item.gold_span_count for item in results)
    retrieved_gold = sum(item.retrieved_gold_span_count for item in results)
    total_contrary = sum(item.contrary_gold_span_count for item in results)
    retrieved_contrary = sum(item.retrieved_contrary_gold_span_count for item in results)
    total_context_tokens = sum(item.context_token_count for item in results)
    total_noise_tokens = sum(item.context_noise_token_count for item in results)
    filter_violations = sum(item.filter_violation_count for item in results)
    index_build_ids = {item.index_build_id for item in results if item.index_build_id is not None}
    if len(index_build_ids) > 1:
        raise RuntimeError("suite coverage mixed immutable index builds")
    coverage_build_id = next(iter(index_build_ids), None)
    if coverage_build_id is not None and coverage_build_id != manifest.provenance.index_build_id:
        raise RuntimeError("coverage index differs from the run candidate")
    recall_5 = (
        sum(item.issue_hits_at_5 for item in results) / scored_issues if scored_issues else None
    )
    recall_10 = (
        sum(item.issue_hits_at_10 for item in results) / scored_issues if scored_issues else None
    )
    mrr = (
        sum(item.reciprocal_rank_sum for item in results) / scored_issues if scored_issues else None
    )
    stage_a_passed = bool(
        qualification is not None
        and len(results) == bundle.registry.case_count
        and scored_issues
        and recall_5 == 1.0
        and recall_10 is not None
        and recall_10 >= 0.95
        and mrr is not None
        and mrr >= 0.8
        and filter_violations == 0
        and all(item.route_passed and item.subject_routing_passed for item in results)
    )
    summary: dict[str, object] = {
        "schema": SUMMARY_SCHEMA,
        "run_id": run_id,
        "suite_id": bundle.manifest.suite_id,
        "index_build_id": coverage_build_id,
        "case_count": len(results),
        "case_ids": [item.case_id for item in results],
        "coverage_only_not_selected_case_ids": [
            item.case_id for item in results if item.disposition == "coverage_only_not_selected"
        ],
        "selected_generation_case_count": bundle.run_plan.generation_case_count,
        "selected_generation_eligible_case_ids": [
            item.case_id for item in results if item.selected_generation_eligible
        ],
        "deterministic_limited_case_ids": [
            item.case_id for item in results if item.deterministic_outcome == "limited"
        ],
        "deterministic_held_case_ids": [
            item.case_id for item in results if item.deterministic_outcome == "held"
        ],
        "route_pass_count": sum(item.route_passed for item in results),
        "subject_routing_pass_count": sum(item.subject_routing_passed for item in results),
        "issue_count": total_issues,
        "scored_issue_count": scored_issues,
        "coverage_status_counts": dict(sorted(statuses.items())),
        "qualification_status_counts": dict(sorted(qualification_statuses.items())),
        "ranking_metric_state": (
            "evaluated_against_sealed_qualifying_issue_gold"
            if scored_issues
            else "not_evaluated_without_expert_qualification"
        ),
        "expert_qualification_sha256": (
            qualification.seal_sha256 if qualification is not None else None
        ),
        "recall_at_5": round(recall_5, 8) if recall_5 is not None else None,
        "recall_at_10": round(recall_10, 8) if recall_10 is not None else None,
        "mrr": round(mrr, 8) if mrr is not None else None,
        "ndcg_at_10": (
            round(sum(item.ndcg_sum for item in results) / scored_issues, 8)
            if scored_issues
            else None
        ),
        "exact_span_recall": (round(retrieved_gold / total_gold, 8) if total_gold else None),
        "contrary_authority_recall": (
            round(retrieved_contrary / total_contrary, 8)
            if total_contrary
            else 1.0
            if scored_issues
            else None
        ),
        "filter_violation_count": filter_violations,
        "filter_correctness": 1.0 if filter_violations == 0 else 0.0,
        "context_noise_token_fraction": (
            round(total_noise_tokens / total_context_tokens, 8)
            if total_context_tokens and scored_issues
            else None
        ),
        "stage_a_policy": {
            "recall_at_5": 1.0,
            "recall_at_10_minimum": 0.95,
            "mrr_minimum": 0.8,
            "filter_violation_maximum": 0,
            "all_routes_required": True,
        },
        "stage_a_evaluated": qualification is not None,
        "stage_a_passed": stage_a_passed,
        "generation_started": False,
    }
    store.store_safe_run_json(run_id=run_id, filename="coverage-summary.json", value=summary)
    return summary
