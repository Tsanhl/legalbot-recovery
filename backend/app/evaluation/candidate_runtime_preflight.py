"""Candidate-pinned retrieval-only cold/warm runtime preflight.

The harness reproduces deterministic section-query planning in memory, but it
never constructs an answer runner, calls an answer model, or persists question,
query, source, or answer prose.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from ..jurisdictions import compatible
from ..observability.live_metrics import SLOBand, SLOPolicy
from ..orchestration.classifier import classify_subject, classify_subjects
from ..orchestration.issues import build_issue_plan
from ..orchestration.retry_policy import MAX_ATTEMPTS, decide_retry, failure_fingerprint
from ..orchestration.routing import build_section_tasks
from ..quality.evidence import evidence_span_eligible_for_drafting
from ..retrieval.budget import (
    RetrievalBudgetExhausted,
    bind_retrieval_budget,
)
from ..retrieval.models import RetrievalPlanItem
from ..types import EvidenceSpan
from .live_suite import LiveEvaluationBundle, LiveQuestionCase, sealed_sha256
from .nonrelease_artifacts import CreateOnlyRunDirectory, sealed_safe_payload
from .sealed_candidate import SealedCandidateIdentity

RUNTIME_PREFLIGHT_SCHEMA = "legalbot.candidate-retrieval-runtime-preflight.v2"
RUNTIME_PREFLIGHT_RESULT_SCHEMA = "legalbot.candidate-retrieval-runtime-result.v2"
RUNTIME_PREFLIGHT_STOP_SCHEMA = "legalbot.candidate-retrieval-runtime-stop.v1"
PREFLIGHT_SELECTION_SCHEMA = "legalbot.generic-preflight-case-selection.v1"
PREFLIGHT_SELECTION_ALGORITHM_VERSION = "legalbot.sealed-hash-slo-band-selection.v2"
PREFLIGHT_SELECTION_ORDER_RULE = (
    "ascending-slo-band-id; minimum-sha256(algorithm-version,selection-seed,"
    "slo-band-id,question-sha256); explicit-additions-in-caller-order"
)
RUNTIME_PREFLIGHT_POLICY = {
    "schema": "legalbot.candidate-retrieval-runtime-policy.v2",
    "case_specific_authority": False,
    "selection_algorithm_version": PREFLIGHT_SELECTION_ALGORITHM_VERSION,
    "coverage_constraint": "at-least-one-case-per-eligible-slo-band",
    "sample_labels": ["cold", "warm"],
    "cold_definition": "first_same_process_model_runtime_pass",
    "warm_definition": "second_same_process_model_runtime_pass",
    "retrieval_cache_mode": "bypass",
    "query_plan": "deterministic-runtime-section-plan-without-teaching-notes-v1",
    "attempts": MAX_ATTEMPTS,
    "failure_policy": "deterministic-or-repeat-stop",
    "provisional_ceiling_metric": "retrieval_seconds",
    "answer_generation": False,
    "release_prose": False,
}
RUNTIME_PREFLIGHT_POLICY_SHA256 = sealed_sha256(RUNTIME_PREFLIGHT_POLICY)

_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_DETERMINISTIC_FAILURES = frozenset(
    {
        "candidate_identity_mismatch",
        "evidence_filter_violation",
        "retrieval_batch_count_mismatch",
        "retrieval_empty_batch",
        "retrieval_budget_exceeded",
        "retrieval_deadline_exceeded",
        "retrieval_result_invalid",
    }
)


@dataclass(frozen=True, slots=True)
class PreflightCase:
    case: LiveQuestionCase
    band: SLOBand
    requests: tuple[RetrievalPlanItem, ...]
    query_plan_sha256: str


@dataclass(frozen=True, slots=True)
class PreflightCaseSelection:
    algorithm_version: str
    eligible_case_set_sha256: str
    selection_seed_sha256: str
    selection_order_rule: str
    coverage_constraints: tuple[dict[str, Any], ...]
    explicit_additional_case_ids: tuple[str, ...]
    selected_case_ids: tuple[str, ...]
    selected_set_sha256: str

    def safe_dict(self) -> dict[str, Any]:
        return {
            "schema": PREFLIGHT_SELECTION_SCHEMA,
            "algorithm_version": self.algorithm_version,
            "eligible_case_set_sha256": self.eligible_case_set_sha256,
            "selection_seed_sha256": self.selection_seed_sha256,
            "selection_order_rule": self.selection_order_rule,
            "coverage_constraints": [dict(item) for item in self.coverage_constraints],
            "explicit_additional_case_ids": list(self.explicit_additional_case_ids),
            "selected_case_ids": list(self.selected_case_ids),
            "selected_set_sha256": self.selected_set_sha256,
        }


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_reason_code(exc: BaseException) -> str:
    if isinstance(exc, RetrievalBudgetExhausted):
        candidate = exc.reason_code
    elif isinstance(exc, TimeoutError):
        candidate = "timeout_error"
    else:
        raw = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
        candidate = raw.removesuffix("_exception") or "runtime_error"
    candidate = candidate.strip().casefold().replace("-", "_")
    return candidate if _SAFE_CODE.fullmatch(candidate) else "runtime_error"


def _runtime_subjects(case: LiveQuestionCase) -> tuple[str | None, tuple[str, ...]]:
    whole = classify_subject(case.question)
    recognised = classify_subjects(case.question)
    return whole, tuple(recognised)


def _prepare_case(case: LiveQuestionCase, band: SLOBand, *, as_of_date: date) -> PreflightCase:
    whole_subject, recognised = _runtime_subjects(case)
    issue_plan = build_issue_plan(
        question=case.question,
        jurisdiction=case.jurisdiction,
        subject=whole_subject,
        notes=(),
    )
    tasks = build_section_tasks(
        question=case.question,
        word_target=case.word_target,
        issue_plan=issue_plan,
    )
    requests: list[RetrievalPlanItem] = []
    safe_identities: list[dict[str, Any]] = []
    for task in tasks:
        heading_subject = classify_subject(task.heading)
        subject = heading_subject
        if subject is None and len(recognised) <= 1:
            subject = whole_subject
        requests.append(
            RetrievalPlanItem(
                query=task.query,
                jurisdiction=case.jurisdiction,
                subject=subject,
                as_of_date=as_of_date,
                limit=30,
                cacheable=False,
            )
        )
        safe_identities.append(
            {
                "query_sha256": _sha256_text(task.query),
                "subject_sha256": _sha256_text(subject or "broad_all_approved"),
                "limit": 30,
            }
        )
    return PreflightCase(
        case=case,
        band=band,
        requests=tuple(requests),
        query_plan_sha256=sealed_sha256(
            {
                "schema": "legalbot.candidate-retrieval-query-plan-identity.v1",
                "case_id": case.case_id,
                "question_sha256": case.question_sha256,
                "queries": safe_identities,
            }
        ),
    )


def build_preflight_case_selection(
    *,
    bundle: LiveEvaluationBundle,
    slo_policy: SLOPolicy,
    additional_case_ids: Sequence[str] | None,
) -> PreflightCaseSelection:
    """Choose a reproducible, case-agnostic set covering every eligible SLO band."""

    registry_ids = {case.case_id for case in bundle.registry.cases}
    explicit_additions = tuple(additional_case_ids or ())
    if len(set(explicit_additions)) != len(explicit_additions):
        raise ValueError("runtime-preflight case IDs must be unique")
    if any(case_id not in registry_ids for case_id in explicit_additions):
        raise ValueError("runtime-preflight case ID is outside the sealed suite")

    eligible_cases: list[dict[str, Any]] = []
    by_band: dict[str, list[LiveQuestionCase]] = {}
    for case in bundle.registry.cases:
        band = slo_policy.band_for(route=case.expected_research_route, word_target=case.word_target)
        by_band.setdefault(band.id, []).append(case)
        eligible_cases.append(
            {
                "case_id": case.case_id,
                "question_sha256": case.question_sha256,
                "record_sha256": case.record_sha256,
                "route": case.expected_research_route,
                "word_target": case.word_target,
                "slo_band_id": band.id,
            }
        )
    eligible_cases.sort(key=lambda item: (str(item["slo_band_id"]), str(item["case_id"])))
    eligible_case_set_sha256 = sealed_sha256(
        {
            "schema": "legalbot.generic-preflight-eligible-case-set.v1",
            "cases": eligible_cases,
        }
    )
    selection_seed_sha256 = sealed_sha256(
        {
            "schema": "legalbot.generic-preflight-selection-seed.v1",
            "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
            "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
            "slo_policy_id": slo_policy.policy_id,
            "eligible_case_set_sha256": eligible_case_set_sha256,
        }
    )
    selected: list[str] = []
    for band_id, cases in sorted(by_band.items()):
        representative = min(
            cases,
            key=lambda case: (
                hashlib.sha256(
                    "\0".join(
                        (
                            PREFLIGHT_SELECTION_ALGORITHM_VERSION,
                            selection_seed_sha256,
                            band_id,
                            case.question_sha256,
                        )
                    ).encode("utf-8")
                ).hexdigest(),
                case.case_id,
            ),
        )
        selected.append(representative.case_id)
    for case_id in explicit_additions:
        if case_id not in selected:
            selected.append(case_id)
    selected_case_ids = tuple(selected)
    coverage_constraints = (
        {
            "kind": "at-least-one-case-per-eligible-slo-band",
            "eligible_slo_band_ids": sorted(by_band),
        },
        {
            "kind": "case-specific-preference-forbidden",
            "case_specific_authority": False,
        },
    )
    selected_set_sha256 = sealed_sha256(
        {
            "schema": "legalbot.generic-preflight-selected-case-set.v1",
            "algorithm_version": PREFLIGHT_SELECTION_ALGORITHM_VERSION,
            "eligible_case_set_sha256": eligible_case_set_sha256,
            "selection_seed_sha256": selection_seed_sha256,
            "coverage_constraints": list(coverage_constraints),
            "explicit_additional_case_ids": list(explicit_additions),
            "selected_case_ids": list(selected_case_ids),
        }
    )
    return PreflightCaseSelection(
        algorithm_version=PREFLIGHT_SELECTION_ALGORITHM_VERSION,
        eligible_case_set_sha256=eligible_case_set_sha256,
        selection_seed_sha256=selection_seed_sha256,
        selection_order_rule=PREFLIGHT_SELECTION_ORDER_RULE,
        coverage_constraints=coverage_constraints,
        explicit_additional_case_ids=explicit_additions,
        selected_case_ids=selected_case_ids,
        selected_set_sha256=selected_set_sha256,
    )


def select_preflight_case_ids(
    *,
    bundle: LiveEvaluationBundle,
    slo_policy: SLOPolicy,
    additional_case_ids: Sequence[str] | None,
) -> tuple[str, ...]:
    """Compatibility projection of the complete generic selection record."""

    return build_preflight_case_selection(
        bundle=bundle,
        slo_policy=slo_policy,
        additional_case_ids=additional_case_ids,
    ).selected_case_ids


def prepare_preflight_cases(
    *,
    bundle: LiveEvaluationBundle,
    slo_policy: SLOPolicy,
    as_of_date: date,
    additional_case_ids: Sequence[str] | None = None,
) -> tuple[PreflightCase, ...]:
    if bundle.registry.case_count != 60:
        raise ValueError("runtime preflight requires the sealed Live60 registry")
    selection = build_preflight_case_selection(
        bundle=bundle,
        slo_policy=slo_policy,
        additional_case_ids=additional_case_ids,
    )
    return tuple(
        _prepare_case(
            bundle.registry.case(case_id),
            slo_policy.band_for(
                route=bundle.registry.case(case_id).expected_research_route,
                word_target=bundle.registry.case(case_id).word_target,
            ),
            as_of_date=as_of_date,
        )
        for case_id in selection.selected_case_ids
    )


def _span_field(span: Any, name: str) -> Any:
    if isinstance(span, Mapping):
        return span.get(name)
    return getattr(span, name, None)


def _span_is_qualified(
    span: Any,
    *,
    candidate_build_id: str,
    jurisdiction: str,
    as_of_date: date,
) -> bool:
    if str(_span_field(span, "index_build_id") or "") != candidate_build_id:
        return False
    lane = str(_span_field(span, "lane") or "")
    if lane not in {"primary_authority", "official_secondary", "scholarship"}:
        return False
    citation_data = _span_field(span, "citation_data")
    if not compatible(
        jurisdiction,
        str(_span_field(span, "jurisdiction") or ""),
        citation_data if isinstance(citation_data, Mapping) else None,
    ):
        return False
    if isinstance(span, EvidenceSpan):
        return bool(
            span.locator.strip()
            and span.text.strip()
            and evidence_span_eligible_for_drafting(span, as_of_date=as_of_date)
        )
    return bool(
        str(_span_field(span, "locator") or "").strip()
        and str(_span_field(span, "text") or "").strip()
        and _span_field(span, "identity_verified")
        and _span_field(span, "currentness_verified")
    )


def _success_payload(
    *,
    prepared: PreflightCase,
    sample_label: str,
    attempt_number: int,
    duration_seconds: float,
    batches: Sequence[Sequence[Any]],
    candidate: SealedCandidateIdentity,
) -> dict[str, Any]:
    if len(batches) != len(prepared.requests):
        raise RuntimeError("retrieval_batch_count_mismatch")
    if not prepared.requests or any(len(batch) < 1 for batch in batches):
        raise RuntimeError("retrieval_empty_batch")
    filter_violations = sum(
        not _span_is_qualified(
            span,
            candidate_build_id=candidate.build_id,
            jurisdiction=prepared.case.jurisdiction,
            as_of_date=prepared.requests[0].as_of_date,
        )
        for batch in batches
        for span in batch
    )
    if filter_violations:
        raise RuntimeError("evidence_filter_violation")
    counts = [len(batch) for batch in batches]
    retrieval_ceiling = float(prepared.band.targets_p95_seconds["retrieval_seconds"])
    return {
        "schema": "legalbot.candidate-retrieval-runtime-sample.v1",
        "case_id": prepared.case.case_id,
        "question_sha256": prepared.case.question_sha256,
        "query_plan_sha256": prepared.query_plan_sha256,
        "sample_label": sample_label,
        "attempt_number": attempt_number,
        "route": prepared.case.expected_research_route,
        "word_target": prepared.case.word_target,
        "slo_band_id": prepared.band.id,
        "provisional_retrieval_p95_seconds": retrieval_ceiling,
        "provisional_completion_p95_seconds": float(
            prepared.band.targets_p95_seconds["completion_seconds"]
        ),
        "slo_enforcement": "observe_only",
        "query_count": len(prepared.requests),
        "batch_count": len(batches),
        "evidence_count": sum(counts),
        "minimum_batch_evidence_count": min(counts, default=0),
        "maximum_batch_evidence_count": max(counts, default=0),
        "filter_violation_count": 0,
        "duration_seconds": round(duration_seconds, 6),
        "within_provisional_retrieval_ceiling": duration_seconds <= retrieval_ceiling,
        "candidate_build_id": candidate.build_id,
        "retrieval_cache_mode": "bypass",
        "answer_generation_invoked": False,
        "released_prose_written": False,
        "status": "succeeded",
    }


def _failure_payload(
    *,
    prepared: PreflightCase,
    sample_label: str,
    attempt_number: int,
    duration_seconds: float,
    reason_code: str,
    candidate: SealedCandidateIdentity,
    prior_fingerprints: Sequence[str],
) -> dict[str, Any]:
    fingerprint = failure_fingerprint(
        stage="runtime_preflight",
        reason_code=reason_code,
        scope_id=prepared.case.case_id,
        identity_digests=tuple(
            dict.fromkeys((candidate.candidate_manifest_sha256, prepared.query_plan_sha256))
        ),
        safe_context={"sample_label": sample_label},
    )
    decision = decide_retry(
        attempt_number=attempt_number,
        failure_reason_code=reason_code,
        failure_fingerprint_sha256=fingerprint,
        prior_failure_fingerprints=prior_fingerprints,
        deterministic_safety=reason_code in _DETERMINISTIC_FAILURES,
        retryable=reason_code not in _DETERMINISTIC_FAILURES,
        # A retry is a fresh cache-bypassed retrieval invocation.  Repeating
        # its semantic failure still stops on occurrence two.
        input_or_condition_changed=reason_code not in _DETERMINISTIC_FAILURES,
    )
    return {
        "schema": "legalbot.candidate-retrieval-runtime-attempt-failure.v1",
        "case_id": prepared.case.case_id,
        "question_sha256": prepared.case.question_sha256,
        "query_plan_sha256": prepared.query_plan_sha256,
        "sample_label": sample_label,
        "attempt_number": attempt_number,
        "duration_seconds": round(duration_seconds, 6),
        "failure_reason_code": reason_code,
        "failure_fingerprint_sha256": fingerprint,
        "decision_action": decision.action,
        "decision_reason": decision.reason,
        "retries_remaining": decision.retries_remaining,
        "candidate_build_id": candidate.build_id,
        "answer_generation_invoked": False,
        "released_prose_written": False,
        "status": "failed",
    }


async def run_candidate_runtime_preflight(
    *,
    run_id: str,
    output_root: Path,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    retriever: Any,
    slo_policy: SLOPolicy,
    slo_policy_sha256: str,
    as_of_date: date,
    code_revision: str,
    code_dirty: bool,
    additional_case_ids: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Run serial cold/warm retrieval samples and stop fail-closed."""

    if candidate.build_id != str(retriever.active_build_id() or ""):
        raise RuntimeError("candidate_identity_mismatch")
    selection = build_preflight_case_selection(
        bundle=bundle,
        slo_policy=slo_policy,
        additional_case_ids=additional_case_ids,
    )
    prepared_cases = prepare_preflight_cases(
        bundle=bundle,
        slo_policy=slo_policy,
        as_of_date=as_of_date,
        additional_case_ids=additional_case_ids,
    )
    store = CreateOnlyRunDirectory(root=output_root, run_id=run_id, resume=False)
    manifest = sealed_safe_payload(
        {
            "schema": RUNTIME_PREFLIGHT_SCHEMA,
            "run_id": run_id,
            "suite_id": bundle.manifest.suite_id,
            "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
            "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
            **candidate.safe_dict(),
            "as_of_date": as_of_date.isoformat(),
            "case_ids": [item.case.case_id for item in prepared_cases],
            "case_count": len(prepared_cases),
            "case_selection": selection.safe_dict(),
            "sample_labels": ["cold", "warm"],
            "policy_sha256": RUNTIME_PREFLIGHT_POLICY_SHA256,
            "slo_policy_id": slo_policy.policy_id,
            "slo_policy_sha256": slo_policy_sha256,
            "slo_enforcement": slo_policy.enforcement,
            "code_revision": code_revision,
            "code_dirty": code_dirty,
            "purpose": "retrieval_runtime_preflight_only",
            "local_only": True,
            "online_research_allowed": False,
            "eligible_for_training": False,
            "training_export_allowed": False,
            "requires_active": False,
            "requires_stage_a": False,
            "writes_active": False,
            "writes_o04": False,
            "answer_generation_allowed": False,
            "released_prose_allowed": False,
        }
    )
    store.write_json("run-manifest.json", manifest)
    samples: list[dict[str, Any]] = []
    try:
        for prepared in prepared_cases:
            for sample_label in ("cold", "warm"):
                prior_fingerprints: list[str] = []
                for attempt_number in range(1, MAX_ATTEMPTS + 1):
                    retrieval_ceiling = float(
                        prepared.band.targets_p95_seconds["retrieval_seconds"]
                    )
                    bind_retrieval_budget(
                        deadline_at=datetime.now(UTC) + timedelta(seconds=retrieval_ceiling)
                    )
                    started = time.perf_counter()
                    try:
                        batches = tuple(await retriever.retrieve_certified_plan(prepared.requests))
                        sample = _success_payload(
                            prepared=prepared,
                            sample_label=sample_label,
                            attempt_number=attempt_number,
                            duration_seconds=time.perf_counter() - started,
                            batches=batches,
                            candidate=candidate,
                        )
                    except Exception as exc:
                        reason_code = _safe_reason_code(exc)
                        if isinstance(exc, RuntimeError) and exc.args:
                            explicit = str(exc.args[0]).strip().casefold().replace("-", "_")
                            if _SAFE_CODE.fullmatch(explicit):
                                reason_code = explicit
                        failure = _failure_payload(
                            prepared=prepared,
                            sample_label=sample_label,
                            attempt_number=attempt_number,
                            duration_seconds=time.perf_counter() - started,
                            reason_code=reason_code,
                            candidate=candidate,
                            prior_fingerprints=prior_fingerprints,
                        )
                        store.write_json(
                            f"attempts/{prepared.case.case_id}/{sample_label}-attempt-"
                            f"{attempt_number:02d}.json",
                            sealed_safe_payload(failure),
                        )
                        prior_fingerprints.append(str(failure["failure_fingerprint_sha256"]))
                        if failure["decision_action"] == "retry":
                            continue
                        stopped = sealed_safe_payload(
                            {
                                "schema": RUNTIME_PREFLIGHT_STOP_SCHEMA,
                                "run_id": run_id,
                                "candidate_build_id": candidate.build_id,
                                "case_id": prepared.case.case_id,
                                "sample_label": sample_label,
                                "attempt_number": attempt_number,
                                "failure_reason_code": reason_code,
                                "failure_fingerprint_sha256": failure["failure_fingerprint_sha256"],
                                "stop_reason": failure["decision_reason"],
                                "completed_sample_count": len(samples),
                                "writes_active": False,
                                "writes_o04": False,
                                "answer_generation_invoked": False,
                                "released_prose_written": False,
                                "status": "stopped",
                            }
                        )
                        store.write_json("STOPPED.json", stopped)
                        return stopped
                    else:
                        bind_retrieval_budget(deadline_at=None)
                        sealed_sample = sealed_safe_payload(sample)
                        store.write_json(
                            f"samples/{prepared.case.case_id}/{sample_label}.json",
                            sealed_sample,
                        )
                        samples.append(sealed_sample)
                        break
        passed = bool(samples) and all(
            item["within_provisional_retrieval_ceiling"] is True for item in samples
        )
        result = sealed_safe_payload(
            {
                "schema": RUNTIME_PREFLIGHT_RESULT_SCHEMA,
                "run_id": run_id,
                "candidate_build_id": candidate.build_id,
                "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
                "policy_sha256": RUNTIME_PREFLIGHT_POLICY_SHA256,
                "slo_policy_sha256": slo_policy_sha256,
                "case_count": len(prepared_cases),
                "case_selection": selection.safe_dict(),
                "sample_count": len(samples),
                "sample_set_sha256": sealed_sha256(
                    {
                        "schema": "legalbot.candidate-retrieval-sample-set.v1",
                        "sample_seal_sha256s": [item["seal_sha256"] for item in samples],
                    }
                ),
                "cold_sample_count": sum(item["sample_label"] == "cold" for item in samples),
                "warm_sample_count": sum(item["sample_label"] == "warm" for item in samples),
                "provisional_ceiling_miss_count": sum(
                    item["within_provisional_retrieval_ceiling"] is not True for item in samples
                ),
                "filter_violation_count": 0,
                "preflight_passed": passed,
                "writes_active": False,
                "writes_o04": False,
                "answer_generation_invoked": False,
                "released_prose_written": False,
                "status": "passed" if passed else "provisional_ceiling_failed",
            }
        )
        store.write_json("result.json", result)
        return result
    finally:
        bind_retrieval_budget(deadline_at=None)
