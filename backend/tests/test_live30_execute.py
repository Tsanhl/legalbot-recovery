from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
from app.crypto import LocalCipher
from app.evaluation.live30 import (
    Live30RunStore,
    LiveEvaluationSuite,
    RunProvenance,
    load_live30_suite,
)
from app.evaluation.live30_execute import (
    ExecutionPreflight,
    Live30Executor,
    _enforce_stage_a_thresholds,
    _gold_source_is_current_for_run,
    _safe_evidence_records,
    _validate_current_law_manifest,
    finalize_review_export,
    verify_execution_prerequisites,
)
from app.evaluation.live30_gold import (
    Live30ExpertQualification,
    qualification_sha256,
)
from app.retrieval.source_manifest import approved_source_manifest_sha256


def _suite() -> LiveEvaluationSuite:
    root = Path(__file__).resolve().parents[2]
    return load_live30_suite(root / "benchmarks/evaluation/live-evaluation-30-v1/cases.jsonl")


def _store(tmp_path: Path) -> tuple[Live30RunStore, str]:
    store = Live30RunStore(
        tmp_path,
        LocalCipher(Fernet(Fernet.generate_key())),
    )
    run_id = "live30-execute-test"
    store.create_run(
        run_id=run_id,
        suite=_suite(),
        provenance=RunProvenance(
            git_sha="a" * 40,
            git_dirty=False,
            model_version="test-model",
            index_build_id="active-test-build",
            prompt_version="prompt-v1",
            router_version="router-v1",
            classifier_version="classifier-v1",
            policy_sha256="b" * 64,
            assessment_rules_sha256=OWNER_ASSESSMENT_BUNDLE.sha256,
        ),
        as_of_date=date(2026, 8, 14),
    )
    return store, run_id


def _qualification_value() -> dict[str, Any]:
    suite = _suite()
    value: dict[str, Any] = {
        "schema": "legalbot.live30-expert-qualification.v2",
        "suite_id": "live-evaluation-30-v1",
        "suite_canonical_sha256": suite.canonical_sha256,
        "index_build_id": "active-test-build",
        "as_of_date": "2026-08-14",
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "approval_status": "expert_approved",
        "approval_role": "legal_expert_owner",
        "approval_reviewer_role": "england_wales_qualified_solicitor",
        "approval_reviewer_ref": f"reviewer:{'1' * 64}",
        "independent_second_review_status": "confirmed",
        "independent_second_reviewer_role": ("england_wales_qualified_legal_academic"),
        "independent_second_reviewer_ref": f"reviewer:{'2' * 64}",
        "material_disagreement_status": "none",
        "adjudication_ref": None,
        "case_count": 30,
        "cases": [],
    }
    cases: list[dict[str, Any]] = []
    for case in suite.cases:
        identity = f"authority-{case.case_id}"
        spans = [
            {
                "schema": "legalbot.live30-gold-span.v2",
                "gold_span_id": f"gold-{case.case_id}-{number:02d}",
                "issue_id": f"issue-{number:02d}",
                "stable_source_id": identity,
                "legal_authority_id": None,
                "source_version_id": f"source-version-{case.case_id}",
                "chunk_id": f"chunk-{case.case_id}-{number:02d}",
                "legal_locator": f"paragraph {number}",
                "content_sha256": hashlib.sha256(
                    f"synthetic-{case.case_id}-{number}".encode()
                ).hexdigest(),
                "source_type": "legislation",
                "legal_role": "statutory_text",
                "proposition_hash": None,
                "case_currentness_review": None,
                "relevance_grade": 3,
                "contrary_or_limiting": False,
            }
            for number in range(1, len(case.must_cover_issues) + 1)
        ]
        cases.append(
            {
                "schema": "legalbot.live30-case-qualification.v2",
                "case_id": case.case_id,
                "question_sha256": case.question_sha256,
                "record_sha256": case.record_sha256,
                "status": "qualified",
                "contrary_authority_status": "reviewed_none",
                "acceptable_source_ids": [identity],
                "issues": [
                    {
                        "schema": "legalbot.live30-issue-qualification.v1",
                        "issue_id": f"issue-{number:02d}",
                        "status": "qualified",
                        "reason_code": None,
                        "exact_gold_spans": [span],
                    }
                    for number, span in enumerate(spans, 1)
                ],
            }
        )
    value["cases"] = cases
    value["seal_sha256"] = qualification_sha256(value)
    return value


def test_expert_qualification_is_complete_sealed_and_tamper_evident() -> None:
    value = _qualification_value()
    qualified = Live30ExpertQualification.model_validate(value)
    assert len(qualified.cases) == 30
    assert qualified.eligible_for_training is False

    value["cases"][0]["issues"][0]["exact_gold_spans"][0]["legal_locator"] = "paragraph 999"
    with pytest.raises(ValidationError, match="seal does not match"):
        Live30ExpertQualification.model_validate(value)


def test_complete_live30_gold_requires_independent_second_review_and_adjudication_ref() -> None:
    same_reviewer = _qualification_value()
    same_reviewer["independent_second_reviewer_ref"] = same_reviewer["approval_reviewer_ref"]
    same_reviewer["seal_sha256"] = qualification_sha256(same_reviewer)
    with pytest.raises(ValidationError, match="must be independent"):
        Live30ExpertQualification.model_validate(same_reviewer)

    missing_adjudication = _qualification_value()
    missing_adjudication["material_disagreement_status"] = "adjudicated"
    missing_adjudication["seal_sha256"] = qualification_sha256(missing_adjudication)
    with pytest.raises(ValidationError, match="requires a safe reference"):
        Live30ExpertQualification.model_validate(missing_adjudication)


def test_gold_keeps_internal_source_id_separate_from_real_ukhl_identity() -> None:
    value = _qualification_value()
    first = value["cases"][0]["issues"][0]["exact_gold_spans"][0]
    first["stable_source_id"] = value["cases"][0]["acceptable_source_ids"][0]
    first["legal_authority_id"] = "neutral-citation:[2002] UKHL 12"
    value["seal_sha256"] = qualification_sha256(value)

    qualified = Live30ExpertQualification.model_validate(value)

    assert (
        qualified.cases[0].exact_gold_spans[0].stable_source_id.startswith("authority-live30-q01")
    )
    assert (
        qualified.cases[0].exact_gold_spans[0].legal_authority_id
        == "neutral-citation:[2002] UKHL 12"
    )


def test_execution_fails_closed_before_api_when_expert_gold_is_missing(
    tmp_path: Path,
) -> None:
    store, run_id = _store(tmp_path)
    with pytest.raises(ValueError, match="expert qualification manifest is missing"):
        verify_execution_prerequisites(
            project_root=tmp_path,
            store=store,
            suite=_suite(),
            run_id=run_id,
            base_url="http://127.0.0.1:8777",
        )


def _passing_stage_a_metrics() -> dict[str, Any]:
    return {
        "scored_issue_count": 20,
        "recall_at_5": 1.0,
        "recall_at_10": 0.95,
        "mrr": 0.8,
        "ndcg_at_10": 0.9,
        "exact_span_recall": 0.85,
        "contrary_authority_recall": 1.0,
    }


def test_stage_a_thresholds_accept_exact_owner_boundaries() -> None:
    _enforce_stage_a_thresholds(_passing_stage_a_metrics())


@pytest.mark.parametrize(
    ("metric", "value", "message"),
    (
        ("recall_at_5", 0.999, "Recall@5"),
        ("recall_at_10", 0.949, "Recall@10"),
        ("mrr", 0.799, "MRR"),
    ),
)
def test_stage_a_thresholds_fail_closed_below_each_owner_gate(
    metric: str, value: float, message: str
) -> None:
    metrics = _passing_stage_a_metrics()
    metrics[metric] = value

    with pytest.raises(RuntimeError, match=message):
        _enforce_stage_a_thresholds(metrics)


def test_stage_a_thresholds_reject_no_qualifying_issue_gold() -> None:
    metrics = _passing_stage_a_metrics()
    metrics["scored_issue_count"] = 0

    with pytest.raises(RuntimeError, match="no annotated qualifying issues"):
        _enforce_stage_a_thresholds(metrics)


def test_current_law_manifest_rejects_stale_run_date_without_rewriting_judgment_date() -> None:
    payload: dict[str, Any] = {
        "schema": "legalbot.approved-source-manifest.v1",
        "current_law_as_of_date": "2026-08-12",
        "sources": [
            {
                "source_version_id": "source-version-ukhl-001",
                "as_of_date": "2002-03-21",
                "currentness_reviewed_as_of_date": "2026-08-14",
                "full_current_law_verification_eligible": True,
            }
        ],
    }
    payload["manifest_sha256"] = approved_source_manifest_sha256(payload)
    with pytest.raises(RuntimeError, match="snapshot date"):
        _validate_current_law_manifest(
            payload,
            expected_sha256=str(payload["manifest_sha256"]),
            run_as_of_date="2026-08-14",
        )

    payload["current_law_as_of_date"] = "2026-08-14"
    payload["manifest_sha256"] = approved_source_manifest_sha256(payload)
    sources = _validate_current_law_manifest(
        payload,
        expected_sha256=str(payload["manifest_sha256"]),
        run_as_of_date="2026-08-14",
    )
    judgment = sources["source-version-ukhl-001"]
    assert judgment["as_of_date"] == "2002-03-21"
    assert _gold_source_is_current_for_run(judgment, run_as_of_date="2026-08-14")


class _Response:
    def __init__(self, status_code: int, value: dict[str, Any]) -> None:
        self.status_code = status_code
        self._value = value

    def json(self) -> dict[str, Any]:
        return self._value


class _FakeLocalClient:
    def __init__(self) -> None:
        self.jobs: dict[str, str] = {}
        self.submissions: list[str] = []
        self.cancelled: list[str] = []

    async def post(self, url: str, **kwargs: Any) -> _Response:
        if url.endswith("/api/v1/questions"):
            headers = kwargs["headers"]
            case_id = str(headers["X-Evaluation-Case-ID"])
            assert kwargs["json"]["online_mode"] == "local_only"
            assert headers["X-Evaluation-Run-ID"] == "live30-execute-test"
            job_id = f"job-{case_id}"
            self.jobs[job_id] = case_id
            self.submissions.append(case_id)
            return _Response(
                202,
                {
                    "job_id": job_id,
                    "status": "queued",
                    "stage": "queued",
                    "events_url": f"/api/v1/jobs/{job_id}/events",
                },
            )
        if url.endswith("/cancel"):
            self.cancelled.append(url)
            return _Response(200, {"cancel_requested": True})
        raise AssertionError(url)

    async def get(self, url: str, **_kwargs: Any) -> _Response:
        if url.endswith("/api/v1/health"):
            return _Response(
                200,
                {
                    "status": "ready",
                    "worker_ready": True,
                    "model_ready": True,
                    "active_index": "active-test-build",
                    "model_id": "test-model",
                },
            )
        if "/api/v1/jobs/" in url:
            job_id = url.rsplit("/", 1)[-1]
            case_id = self.jobs[job_id]
            return _Response(
                200,
                {
                    "id": job_id,
                    "status": "complete",
                    "stage": "complete",
                    "progress": 1,
                    "answer_id": f"answer-{case_id}",
                    "release_state": "verified_full",
                    "trace_id": f"trace-{case_id}",
                },
            )
        if url.endswith("/evidence"):
            case_id = url.split("/answers/", 1)[1].split("/", 1)[0].removeprefix("answer-")
            evidence_id = f"evidence-{case_id}"
            return _Response(
                200,
                {
                    "answer_id": f"answer-{case_id}",
                    "claims": [
                        {
                            "id": f"claim-{case_id}",
                            "material": True,
                            "verification_status": "verified",
                            "evidence_ids": [evidence_id],
                        }
                    ],
                    "evidence": [
                        {
                            "id": evidence_id,
                            "source_version_id": f"source-version-{case_id}",
                            "locator": "paragraph 1",
                            "legal_role": "holding_ratio",
                            "identity_verified": True,
                            "currentness_verified": True,
                            "jurisdiction": "England and Wales",
                            "citation_data": {"source_type": "case"},
                            "currentness_status": "later_treatment_checked",
                        }
                    ],
                },
            )
        if "/api/v1/answers/" in url:
            case_id = url.rsplit("/", 1)[-1].removeprefix("answer-")
            content = f"Verified answer for {case_id} with authority."
            return _Response(
                200,
                {
                    "id": f"answer-{case_id}",
                    "job_id": f"job-{case_id}",
                    "content": content,
                    "word_count": len(content.split()),
                    "release_state": "verified_full",
                    "policy_version": "policy-v1",
                    "model_version": "test-model",
                    "index_build_id": "active-test-build",
                    "quality": {
                        "evidence_passed": 1,
                        "academic_score": 72.0,
                        "findings_json": json.dumps([{"code": "rubric_cap_missing_application"}]),
                    },
                },
            )
        raise AssertionError(url)


@pytest.mark.asyncio
async def test_executor_serially_captures_only_encrypted_answers_and_finalizes_review(
    tmp_path: Path,
) -> None:
    store, run_id = _store(tmp_path)
    client = _FakeLocalClient()
    preflight = ExecutionPreflight(
        run_id=run_id,
        base_url="http://127.0.0.1:8777",
        index_build_id="active-test-build",
        model_version="test-model",
        policy_sha256="b" * 64,
        assessment_bundle_sha256=OWNER_ASSESSMENT_BUNDLE.sha256,
        qualification_sha256="c" * 64,
        owner_identifiers=(),
        generation_eligible_case_ids=tuple(f"live30-q{number:02d}" for number in range(1, 31)),
    )
    executor = Live30Executor(
        store=store,
        suite=_suite(),
        preflight=preflight,
        client=client,
        poll_interval_seconds=0,
        case_timeout_seconds=2,
    )
    outcomes = await executor.execute(pass_number=1, stability_sample=False)

    assert len(outcomes) == 30
    assert client.submissions == [f"live30-q{number:02d}" for number in range(1, 31)]
    assert all(outcome.released for outcome in outcomes)
    assert "owner-problem-conclusory-application-v1" in (outcomes[0].triggered_assessment_rule_ids)
    repeated = await executor.execute(pass_number=1, stability_sample=False)
    assert tuple(item.answer_sha256 for item in repeated) == tuple(
        item.answer_sha256 for item in outcomes
    )
    assert len(client.submissions) == 30
    first_artifact = (
        store.runs_root
        / run_id
        / "cases/live30-q01/artifacts/answer"
        / f"{outcomes[0].answer_artifact_id}.enc"
    )
    assert b"Verified answer" not in first_artifact.read_bytes()
    assert "Verified answer" not in store.events_log.read_text()
    assert "Verified answer" not in store.case_index_log.read_text()
    released_path = store.runs_root / run_id / "cases/live30-q01/released-answer.md"
    assert released_path.read_text().startswith("Verified answer")
    assert released_path.stat().st_mode & 0o777 == 0o600

    with pytest.raises(RuntimeError, match="48 planned"):
        finalize_review_export(store=store, suite=_suite(), run_id=run_id)
    await executor.execute(pass_number=2, stability_sample=True)
    await executor.execute(pass_number=3, stability_sample=True)
    review = finalize_review_export(store=store, suite=_suite(), run_id=run_id)
    assert len(review.cases) == 30
    assert review.privacy_report_passed is True
    assert review.eligible_for_training is False
    assert (store.runs_root / run_id / "review-export.json").is_file()
    assert (store.runs_root / run_id / "cases/live30-q01/outcomes/pass-3.json").is_file()


@pytest.mark.asyncio
async def test_partial_qualification_has_deterministic_terminal_nonrelease_outcomes(
    tmp_path: Path,
) -> None:
    store, run_id = _store(tmp_path)
    client = _FakeLocalClient()
    executor = Live30Executor(
        store=store,
        suite=_suite(),
        preflight=ExecutionPreflight(
            run_id=run_id,
            base_url="http://127.0.0.1:8777",
            index_build_id="active-test-build",
            model_version="test-model",
            policy_sha256="b" * 64,
            assessment_bundle_sha256=OWNER_ASSESSMENT_BUNDLE.sha256,
            qualification_sha256="c" * 64,
            owner_identifiers=(),
            generation_eligible_case_ids=(),
            limited_case_ids=("live30-q01",),
            knowledge_gap_case_ids=("live30-q02",),
            held_case_ids=tuple(f"live30-q{number:02d}" for number in range(3, 31)),
        ),
        client=client,
        poll_interval_seconds=0,
        case_timeout_seconds=2,
    )

    outcomes = await executor.execute(pass_number=1, stability_sample=False)

    assert len(outcomes) == 30
    assert client.submissions == []
    assert all(item.status == "held" for item in outcomes)
    assert outcomes[0].failure_codes == ("expert_qualification_limited",)
    assert outcomes[1].failure_codes == ("expert_qualification_knowledge_gap",)
    assert all(item.failure_codes == ("coverage_not_generation_eligible",) for item in outcomes[2:])
    assert not list((store.runs_root / run_id).rglob("released-answer.md"))
    issue_rows = (
        (store.runs_root / run_id / "issues/index.jsonl").read_text(encoding="utf-8").splitlines()
    )
    assert len(issue_rows) == 30


def test_safe_evidence_report_fails_closed_and_preserves_runtime_legal_roles() -> None:
    payload = {
        "claims": [
            {
                "material": True,
                "verification_status": "verified",
                "evidence_ids": ["evidence-safe-001", "evidence-safe-002"],
            }
        ],
        "evidence": [
            {
                "id": "evidence-safe-001",
                "source_version_id": "source-version-safe-001",
                "locator": "paragraph 12",
                "legal_role": "holding_ratio",
                "currentness_status": "later_treatment_checked",
                "identity_verified": True,
                "currentness_verified": True,
                "jurisdiction": "England and Wales",
                "citation_data": {"source_type": "case"},
            },
            {
                "id": "evidence-safe-002",
                "source_version_id": "source-version-safe-002",
                "locator": "section 1",
                "legal_role": "binding_legal_rule",
                "currentness_status": "unknown",
                "identity_verified": False,
                "currentness_verified": False,
                "jurisdiction": "Scotland",
                "citation_data": {"source_type": "legislation"},
            },
        ],
    }

    records = _safe_evidence_records(payload, requested_jurisdiction="England and Wales")

    assert records[0].legal_role == "holding_ratio"
    assert records[0].identity_state == "verified"
    assert records[0].currentness_state == "verified_current"
    assert records[0].jurisdiction_state == "verified"
    assert records[1].legal_role == "binding_legal_rule"
    assert records[1].identity_state == "unverified"
    assert records[1].currentness_state == "unverified"
    assert records[1].jurisdiction_state == "unverified"


@pytest.mark.asyncio
async def test_pass_two_requires_and_uses_only_the_frozen_stability_sample(
    tmp_path: Path,
) -> None:
    store, run_id = _store(tmp_path)
    executor = Live30Executor(
        store=store,
        suite=_suite(),
        preflight=ExecutionPreflight(
            run_id=run_id,
            base_url="http://127.0.0.1:8777",
            index_build_id="active-test-build",
            model_version="test-model",
            policy_sha256="b" * 64,
            assessment_bundle_sha256=OWNER_ASSESSMENT_BUNDLE.sha256,
            qualification_sha256="c" * 64,
            owner_identifiers=(),
            generation_eligible_case_ids=tuple(f"live30-q{number:02d}" for number in range(1, 31)),
        ),
        client=(client := _FakeLocalClient()),
        poll_interval_seconds=0,
        case_timeout_seconds=2,
    )
    with pytest.raises(ValueError, match="passes 2 and 3"):
        await executor.execute(pass_number=2, stability_sample=False)

    outcomes = await executor.execute(pass_number=2, stability_sample=True)
    assert len(outcomes) == 9
    assert tuple(client.submissions) == (
        "live30-q01",
        "live30-q03",
        "live30-q07",
        "live30-q09",
        "live30-q13",
        "live30-q17",
        "live30-q25",
        "live30-q27",
        "live30-q30",
    )
