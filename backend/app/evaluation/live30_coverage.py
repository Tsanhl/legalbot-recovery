"""Coverage-first execution for the immutable live-30 development suite.

This stage deliberately does not draft answers.  It runs the real sealed
retriever against every owner-supplied issue, records only IDs/locators and
timings, and distinguishes candidate evidence from expert-qualified legal
support.  Empty gold fields therefore produce ``not_evaluated`` ranking
metrics rather than invented Recall/MRR values.
"""

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

from ..jurisdictions import compatible
from ..orchestration.classifier import classify_subject, classify_subjects
from ..orchestration.routing import decide_route
from ..quality.evidence import (
    evidence_span_eligible_for_drafting,
    is_citable_authority_lane,
)
from ..types import EvidenceSpan, TaskType
from .live30 import (
    EXPECTED_CASE_IDS,
    E2ERunEvent,
    Live30RunStore,
    LiveEvaluationCase,
    LiveEvaluationSuite,
    RunEventType,
    RunStage,
    RunStatus,
)
from .live30_gold import (
    Live30CaseQualification,
    Live30ExpertQualification,
    Live30GoldSpan,
)

COVERAGE_SCHEMA = "legalbot.live30-coverage.v2"
RETRIEVAL_SCHEMA = "legalbot.live30-retrieval.v2"
EVIDENCE_MAP_SCHEMA = "legalbot.live30-evidence-map.v2"
METRICS_SCHEMA = "legalbot.live30-readiness-metrics.v2"
SUMMARY_SCHEMA = "legalbot.live30-coverage-summary.v2"


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
    qualification_status: str | None
    deterministic_outcome: str
    coverage_status: str
    generation_eligible: bool
    route_passed: bool
    subject_routing_passed: bool
    subject_routing_state: str
    issue_count: int
    scored_issue_count: int
    issues_with_candidates: int
    issues_with_no_candidates: int
    retrieval_duration_ms: int
    recall_at_5: float | None
    recall_at_10: float | None
    mrr: float | None
    ndcg_at_10: float | None
    exact_span_recall: float | None
    contrary_authority_recall: float | None
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


_SUBJECT_ALIASES: dict[str, frozenset[str]] = {
    "contract": frozenset({"contract"}),
    "consumer": frozenset({"consumer"}),
    "tort": frozenset({"tort"}),
    "criminal": frozenset({"criminal"}),
    "professional negligence": frozenset({"professional negligence"}),
    "criminal evidence": frozenset({"criminal evidence"}),
    "employment and equality": frozenset({"employment"}),
    "land": frozenset({"land"}),
    "public law": frozenset({"public and constitutional"}),
    "company": frozenset({"company"}),
    "family": frozenset({"family"}),
    "human rights and constitutional": frozenset({"human rights", "public and constitutional"}),
    "equity and trusts": frozenset({"trusts"}),
    "civil litigation": frozenset({"civil litigation"}),
    "intellectual property": frozenset({"intellectual property"}),
    "wills and succession": frozenset({"wills and succession"}),
    "corporate governance": frozenset({"company"}),
    "banking fraud and restitution": frozenset({"banking fraud and restitution"}),
    "competition and digital markets": frozenset({"competition"}),
    "medical": frozenset({"medical law"}),
    "public procurement and administrative": frozenset({"public procurement and administrative"}),
    "environmental and climate": frozenset({"environmental and climate"}),
    "data protection and privacy": frozenset({"data protection and privacy", "data protection"}),
    "legal ethics and artificial intelligence": frozenset(
        {"legal ethics and artificial intelligence"}
    ),
    "insolvency and corporate transactions": frozenset({"insolvency and corporate transactions"}),
    "construction and commercial": frozenset({"construction and commercial"}),
    "constitutional and administrative": frozenset({"public and constitutional"}),
    "land trusts family property and insolvency": frozenset(
        {"land trusts family property and insolvency"}
    ),
    "corporate fraud regulation and litigation": frozenset(
        {"corporate fraud regulation and litigation"}
    ),
    "multi-area artificial intelligence litigation": frozenset(
        {"multi-area artificial intelligence litigation"}
    ),
}


def _subject_routing_readiness(case: LiveEvaluationCase) -> tuple[str, bool, tuple[str, ...]]:
    observed = classify_subjects(case.question)
    accepted = _SUBJECT_ALIASES.get(case.subject, frozenset({case.subject}))
    if accepted.intersection(observed):
        return "compatible", True, observed
    # ``None`` is an actual broad retrieval in the runtime and is safe (though
    # less selective). Composite full-enquiry work also has an explicit broad
    # section fallback. A wrong narrow filter on a sectioned case is not safe.
    if not observed or case.expected_research_route == "full_enquiry":
        return "explicit_broad_fallback", True, observed
    return "incompatible_narrow_filter", False, observed


def _qualified(span: EvidenceSpan, jurisdiction: str, *, as_of_date: date) -> bool:
    return bool(
        evidence_span_eligible_for_drafting(span, as_of_date=as_of_date)
        and is_citable_authority_lane(span)
        and compatible(jurisdiction, span.jurisdiction, span.citation_data)
        and span.locator.strip()
        and span.text.strip()
    )


def _safe_candidate(
    span: EvidenceSpan,
    rank: int,
    *,
    requested_jurisdiction: str,
    as_of_date: date,
) -> dict[str, object]:
    return {
        "rank": rank,
        "evidence_id": span.id,
        "index_build_id": span.index_build_id,
        "source_version_id": span.source_version_id,
        "chunk_id": span.chunk_id,
        "content_sha256": span.content_sha256,
        "locator": span.locator,
        "lane": str(span.lane),
        "jurisdiction": span.jurisdiction,
        "currentness_status": span.currentness_status,
        "legal_role": span.legal_role,
        "provision_extent_status": span.provision_extent_status,
        "unapplied_effect_count": span.unapplied_effect_count,
        "identity_verified": span.identity_verified,
        "currentness_verified": span.currentness_verified,
        "case_proposition_hashes": sorted(
            review.proposition_hash for review in span.case_currentness_reviews
        ),
        "case_currentness_review_seals": sorted(
            review.seal_sha256 for review in span.case_currentness_reviews
        ),
        "case_currentness_manifest_seals": sorted(span.case_currentness_manifest_seals),
        "runtime_qualification_passed": _qualified(
            span, requested_jurisdiction, as_of_date=as_of_date
        ),
        "retrieval_relevance_score": (
            round(float(span.retrieval_relevance_score), 8)
            if span.retrieval_relevance_score is not None
            else None
        ),
    }


def _normal_locator(value: object) -> str:
    return " ".join(str(value or "").split()).casefold()


def _candidate_matches_gold(candidate: Mapping[str, object], gold: Live30GoldSpan) -> bool:
    return bool(
        candidate.get("source_version_id") == gold.source_version_id
        and candidate.get("chunk_id") == gold.chunk_id
        and candidate.get("content_sha256") == gold.content_sha256
        and _normal_locator(candidate.get("locator")) == _normal_locator(gold.legal_locator)
        and candidate.get("legal_role") == gold.legal_role
        and (
            gold.case_currentness_review is None
            or (
                gold.proposition_hash
                in cast(Sequence[object], candidate.get("case_proposition_hashes") or ())
                and gold.case_currentness_review.seal_sha256
                in cast(
                    Sequence[object],
                    candidate.get("case_currentness_review_seals") or (),
                )
            )
        )
        and candidate.get("runtime_qualification_passed") is True
    )


async def _retrieve_issue(
    *,
    retriever: CoverageRetriever,
    case: LiveEvaluationCase,
    issue_number: int,
    issue: str,
    as_of_date: date,
    semaphore: asyncio.Semaphore,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    issue_id = f"issue-{issue_number:02d}"
    started = time.perf_counter()
    error_code: str | None = None
    retrieval_subject = classify_subject(issue)
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
    except Exception as exc:  # reported as a code; prose never enters telemetry
        evidence = []
        error_code = type(exc).__name__
    duration_ms = round((time.perf_counter() - started) * 1_000)
    candidates = [
        _safe_candidate(
            span,
            rank,
            requested_jurisdiction=case.jurisdiction,
            as_of_date=as_of_date,
        )
        for rank, span in enumerate(evidence, 1)
    ]
    qualified_count = sum(bool(item["runtime_qualification_passed"]) for item in candidates)
    status = (
        "retrieval_error"
        if error_code
        else "candidate_evidence_needs_expert_span_review"
        if qualified_count
        else "knowledge_gap"
    )
    record: dict[str, object] = {
        "issue_id": issue_id,
        "issue_sha256": _sha256(issue),
        "status": status,
        "duration_ms": duration_ms,
        "result_count": len(candidates),
        "runtime_qualified_candidate_count": qualified_count,
        "expert_support_verified": False,
        "retrieval_subject": retrieval_subject,
        "error_code": error_code,
    }
    return record, candidates


async def run_case_coverage(
    *,
    store: Live30RunStore,
    retriever: CoverageRetriever,
    run_id: str,
    case: LiveEvaluationCase,
    qualification: Live30CaseQualification | None = None,
) -> CoverageCaseResult:
    as_of_date, encrypted_case = store.load_encrypted_question(run_id=run_id, case_id=case.case_id)
    if encrypted_case.record_sha256 != case.record_sha256:
        raise RuntimeError("run question differs from the immutable suite record")
    started = time.perf_counter()
    task_type = TaskType(case.task_type)
    observed_route = decide_route(case.question, case.word_target, task_type)
    route_passed = str(observed_route.route) == case.expected_research_route
    subject_routing_state, subject_routing_passed, recognised_subjects = _subject_routing_readiness(
        case
    )

    store.record_event(
        E2ERunEvent(
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
    issue_ndcg_at_10: list[float] = []
    issue_hits_at_5 = 0
    issue_hits_at_10 = 0
    scored_issue_count = 0
    retrieved_gold_ids: set[str] = set()
    all_gold_ids: set[str] = set()
    retrieved_contrary_ids: set[str] = set()
    contrary_gold_ids: set[str] = set()
    for issue, candidates in issue_results:
        issue_qualification = (
            qualification.issue(cast(str, issue["issue_id"])) if qualification is not None else None
        )
        qualification_status = (
            issue_qualification.status if issue_qualification is not None else None
        )
        # A limited issue has reviewed evidence, but its gold is explicitly
        # incomplete.  Counting it in Recall/MRR would let a knowingly partial
        # annotation inflate the Stage A gate.  Only complete, expert-qualified
        # issue gold enters ranking denominators; limited and knowledge-gap
        # issues remain visible as deterministic non-release outcomes.
        ranking_evaluable = qualification_status == "qualified"
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
        matched_ranks: list[int] = []
        matched_gold: list[str] = []
        matched_positive_ranks: list[int] = []
        credited_for_dcg: set[str] = set()
        dcg = 0.0
        for rank, candidate in enumerate(candidates, 1):
            for gold in issue_gold:
                if _candidate_matches_gold(candidate, gold):
                    matched_ranks.append(rank)
                    matched_gold.append(gold.gold_span_id)
                    retrieved_gold_ids.add(gold.gold_span_id)
                    if gold.contrary_or_limiting:
                        retrieved_contrary_ids.add(gold.gold_span_id)
                    else:
                        matched_positive_ranks.append(rank)
                    if rank <= 10 and gold.gold_span_id not in credited_for_dcg:
                        dcg += (2**gold.relevance_grade - 1) / math.log2(rank + 1)
                        credited_for_dcg.add(gold.gold_span_id)
        ideal_grades = sorted((span.relevance_grade for span in issue_gold), reverse=True)[:10]
        idcg = sum(
            (2**grade - 1) / math.log2(rank + 1) for rank, grade in enumerate(ideal_grades, 1)
        )
        if ranking_evaluable:
            issue_ndcg_at_10.append(dcg / idcg if idcg else 1.0)
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
                "ndcg_at_10": (round(issue_ndcg_at_10[-1], 8) if ranking_evaluable else None),
                "candidates": candidates,
            }
        )
    with_candidates = sum(
        int(cast(int, item["runtime_qualified_candidate_count"]) > 0) for item in issues
    )
    errors = sum(int(item["status"] == "retrieval_error") for item in issues)
    missing = len(issues) - with_candidates
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
        elif not route_passed or not subject_routing_passed:
            coverage_status = "routing_failure"
        else:
            coverage_status = "qualified"
    elif errors:
        coverage_status = "retrieval_error"
    elif missing:
        coverage_status = "knowledge_gap"
    else:
        coverage_status = "provisional_needs_expert_span_review"

    # Candidate retrieval is never enough on its own.  Drafting is enabled
    # only when a separately sealed expert overlay matches a runtime-qualified
    # source/version/locator/content identity for every issue.
    generation_eligible = bool(
        qualification is not None
        and qualification.status == "qualified"
        and not errors
        and route_passed
        and subject_routing_passed
        and all(bool(item["expert_support_verified"]) for item in issues)
        and all(bool(item["contrary_support_verified"]) for item in issues)
    )
    deterministic_outcome = (
        "generate"
        if generation_eligible
        else "limited"
        if qualification_status == "limited"
        else "held"
    )
    total_ms = round((time.perf_counter() - started) * 1_000)
    build_ids = {
        str(candidate["index_build_id"])
        for item in evidence_map
        for candidate in cast(list[dict[str, object]], item["candidates"])
    }
    if len(build_ids) > 1:
        raise RuntimeError("coverage retrieval mixed immutable index builds")
    retrieval_payload: dict[str, object] = {
        "schema": RETRIEVAL_SCHEMA,
        "run_id": run_id,
        "case_id": case.case_id,
        "as_of_date": as_of_date.isoformat(),
        "index_build_id": next(iter(build_ids), None),
        "issue_results": issues,
    }
    store.store_safe_case_json(
        run_id=run_id,
        case_id=case.case_id,
        filename="retrieval.json",
        value=retrieval_payload,
    )
    store.store_safe_case_json(
        run_id=run_id,
        case_id=case.case_id,
        filename="evidence-map.json",
        value={
            "schema": EVIDENCE_MAP_SCHEMA,
            "run_id": run_id,
            "case_id": case.case_id,
            "expert_qualified": qualification is not None,
            "expert_qualification_status": qualification_status,
            "expert_qualification_passed": generation_eligible,
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
            "coverage_status": coverage_status,
            "expert_qualification_status": qualification_status,
            "deterministic_outcome": deterministic_outcome,
            "generation_eligible": generation_eligible,
            "expert_qualification_present": qualification is not None,
            "expected_route": case.expected_research_route,
            "observed_route": str(observed_route.route),
            "route_passed": route_passed,
            "subject_routing_passed": subject_routing_passed,
            "subject_routing_state": subject_routing_state,
            "recognised_subjects": list(recognised_subjects),
            "route_reason_codes": list(observed_route.reasons),
            "issue_count": len(issues),
            "scored_issue_count": scored_issue_count,
            "issues_with_candidates": with_candidates,
            "issues_with_no_candidates": missing,
            "retrieval_errors": errors,
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
            "retrieval_duration_ms": total_ms,
            "candidate_issue_coverage": round(with_candidates / len(issues), 8),
            "expert_qualification_status": qualification_status,
            "scored_issue_count": scored_issue_count,
            "route_passed": route_passed,
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
            "ndcg_at_10": (
                round(sum(issue_ndcg_at_10) / len(issue_ndcg_at_10), 8)
                if issue_ndcg_at_10
                else None
            ),
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
            "contrary_authority_metric_state": (
                "evaluated_against_bound_contrary_gold"
                if contrary_gold_ids
                else "explicitly_reviewed_not_applicable"
                if scored_issue_count
                else "not_evaluated_explicit_knowledge_gap"
                if qualification is not None
                else "not_evaluated_without_expert_qualification"
            ),
            "ranking_metric_state": (
                "evaluated_against_sealed_qualifying_issue_gold"
                if scored_issue_count
                else "not_evaluated_explicit_knowledge_gap"
                if qualification is not None
                else "not_evaluated_without_expert_qualification"
            ),
        },
    )
    for issue in issues:
        expert_issue_status = issue.get("expert_qualification_status")
        reason_code = (
            "expert_knowledge_gap"
            if expert_issue_status == "knowledge_gap"
            else "expert_evidence_limited"
            if expert_issue_status == "limited"
            else cast(str, issue["status"])
            if issue["status"] in {"knowledge_gap", "retrieval_error"}
            else None
        )
        if reason_code is not None:
            store.append_safe_run_index(
                run_id=run_id,
                index_name="knowledge-gaps",
                value={
                    "schema": "legalbot.live30-safe-gap.v1",
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
        E2ERunEvent(
            event_id=uuid.uuid4().hex,
            timestamp=datetime.now(UTC),
            run_id=run_id,
            case_id=case.case_id,
            event_type=RunEventType.STAGE_COMPLETED,
            stage=RunStage.RETRIEVAL,
            status=RunStatus.COMPLETE,
            duration_ms=total_ms,
        )
    )
    return CoverageCaseResult(
        case_id=case.case_id,
        qualification_status=qualification_status,
        deterministic_outcome=deterministic_outcome,
        coverage_status=coverage_status,
        generation_eligible=generation_eligible,
        route_passed=route_passed,
        subject_routing_passed=subject_routing_passed,
        subject_routing_state=subject_routing_state,
        issue_count=len(issues),
        scored_issue_count=scored_issue_count,
        issues_with_candidates=with_candidates,
        issues_with_no_candidates=missing,
        retrieval_duration_ms=total_ms,
        recall_at_5=(issue_hits_at_5 / scored_issue_count if scored_issue_count else None),
        recall_at_10=(issue_hits_at_10 / scored_issue_count if scored_issue_count else None),
        mrr=(sum(reciprocal_ranks) / len(reciprocal_ranks) if reciprocal_ranks else None),
        ndcg_at_10=(sum(issue_ndcg_at_10) / len(issue_ndcg_at_10) if issue_ndcg_at_10 else None),
        exact_span_recall=(len(retrieved_gold_ids) / len(all_gold_ids) if all_gold_ids else None),
        contrary_authority_recall=(
            len(retrieved_contrary_ids) / len(contrary_gold_ids)
            if contrary_gold_ids
            else 1.0
            if scored_issue_count
            else None
        ),
        issue_hits_at_5=issue_hits_at_5,
        issue_hits_at_10=issue_hits_at_10,
        reciprocal_rank_sum=sum(reciprocal_ranks),
        ndcg_sum=sum(issue_ndcg_at_10),
        gold_span_count=len(all_gold_ids),
        retrieved_gold_span_count=len(retrieved_gold_ids),
        contrary_gold_span_count=len(contrary_gold_ids),
        retrieved_contrary_gold_span_count=len(retrieved_contrary_ids),
    )


async def run_suite_coverage(
    *,
    store: Live30RunStore,
    retriever: CoverageRetriever,
    run_id: str,
    suite: LiveEvaluationSuite,
    case_ids: Sequence[str] = EXPECTED_CASE_IDS,
    qualification: Live30ExpertQualification | None = None,
) -> Mapping[str, object]:
    selected = tuple(case_ids)
    if (
        not selected
        or len(selected) != len(set(selected))
        or any(item not in EXPECTED_CASE_IDS for item in selected)
    ):
        raise ValueError("coverage case IDs must be unique live-30 IDs")
    by_id = {case.case_id: case for case in suite.cases}
    if qualification is not None:
        manifest = store.load_run_manifest(run_id)
        if qualification.suite_canonical_sha256 != suite.canonical_sha256:
            raise ValueError("expert qualification is bound to a different suite")
        if qualification.index_build_id != manifest.provenance.index_build_id:
            raise ValueError("expert qualification is bound to a different index build")
        if qualification.as_of_date != manifest.as_of_date:
            raise ValueError("expert qualification is bound to a different as-of date")
        store.store_safe_run_json(
            run_id=run_id,
            filename="expert-qualification.json",
            value=qualification.model_dump(mode="json", by_alias=True),
        )
    # Execute serially: the real embedding/reranker stack is memory-bound and
    # model concurrency for release one remains one.
    results = [
        await run_case_coverage(
            store=store,
            retriever=retriever,
            run_id=run_id,
            case=by_id[case_id],
            qualification=(qualification.case(case_id) if qualification is not None else None),
        )
        for case_id in selected
    ]
    statuses = Counter(item.coverage_status for item in results)
    qualification_statuses = Counter(
        item.qualification_status for item in results if item.qualification_status is not None
    )
    total_issues = sum(item.issue_count for item in results)
    scored_issues = sum(item.scored_issue_count for item in results)
    candidate_issues = sum(item.issues_with_candidates for item in results)
    total_gold_spans = sum(item.gold_span_count for item in results)
    retrieved_gold_spans = sum(item.retrieved_gold_span_count for item in results)
    total_contrary_gold = sum(item.contrary_gold_span_count for item in results)
    retrieved_contrary_gold = sum(item.retrieved_contrary_gold_span_count for item in results)
    summary: dict[str, object] = {
        "schema": SUMMARY_SCHEMA,
        "run_id": run_id,
        "case_count": len(results),
        "case_ids": list(selected),
        "generation_eligible_case_count": sum(item.generation_eligible for item in results),
        "generation_eligible_case_ids": [
            item.case_id for item in results if item.generation_eligible
        ],
        "deterministic_limited_case_ids": [
            item.case_id for item in results if item.deterministic_outcome == "limited"
        ],
        "deterministic_held_case_ids": [
            item.case_id for item in results if item.deterministic_outcome == "held"
        ],
        "route_pass_count": sum(item.route_passed for item in results),
        "subject_routing_pass_count": sum(item.subject_routing_passed for item in results),
        "subject_broad_fallback_count": sum(
            item.subject_routing_state == "explicit_broad_fallback" for item in results
        ),
        "subject_incompatible_case_ids": [
            item.case_id for item in results if not item.subject_routing_passed
        ],
        "route_recall": round(sum(item.route_passed for item in results) / len(results), 8),
        "issue_count": total_issues,
        "scored_issue_count": scored_issues,
        "issues_with_runtime_candidates": candidate_issues,
        "candidate_issue_coverage": round(candidate_issues / total_issues, 8),
        "coverage_status_counts": dict(sorted(statuses.items())),
        "qualification_status_counts": dict(sorted(qualification_statuses.items())),
        "ranking_metric_state": (
            "evaluated_against_sealed_qualifying_issue_gold"
            if scored_issues
            else "not_evaluated_no_qualifying_issue_gold"
            if qualification is not None
            else "not_evaluated_without_expert_qualification"
        ),
        "expert_qualification_sha256": (
            qualification.seal_sha256 if qualification is not None else None
        ),
        "recall_at_5": (
            round(sum(item.issue_hits_at_5 for item in results) / scored_issues, 8)
            if scored_issues
            else None
        ),
        "recall_at_10": (
            round(sum(item.issue_hits_at_10 for item in results) / scored_issues, 8)
            if scored_issues
            else None
        ),
        "mrr": (
            round(sum(item.reciprocal_rank_sum for item in results) / scored_issues, 8)
            if scored_issues
            else None
        ),
        "ndcg_at_10": (
            round(sum(item.ndcg_sum for item in results) / scored_issues, 8)
            if scored_issues
            else None
        ),
        "exact_span_recall": (
            round(retrieved_gold_spans / total_gold_spans, 8) if total_gold_spans else None
        ),
        "contrary_authority_recall": (
            round(retrieved_contrary_gold / total_contrary_gold, 8)
            if total_contrary_gold
            else 1.0
            if scored_issues
            else None
        ),
        "generation_started": False,
    }
    store.store_safe_run_json(
        run_id=run_id,
        filename="coverage-summary.json",
        value=summary,
    )
    return summary
