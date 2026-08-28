from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet

from app.crypto import LocalCipher
from app.evaluation.live30 import RunProvenance, SensitiveArtifactKind
from app.evaluation.live_suite import (
    LiveEvaluationBundle,
    load_live_evaluation_bundle,
    sealed_sha256,
)
from app.evaluation.live_suite_admin import LiveSuiteAdminReader
from app.evaluation.live_suite_execute import (
    Live60ExecutionAuthorization,
    Live60ExecutionPreflight,
)
from app.evaluation.live_suite_http_execute import (
    Live60Executor,
    Live60RuntimeBinding,
    finalize_live60_review_export,
    live60_evaluation_request_sha256,
)
from app.evaluation.live_suite_store import LiveSuiteRunStore

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"


class _Response:
    def __init__(self, status_code: int, value: dict[str, Any]) -> None:
        self.status_code = status_code
        self._value = value

    def json(self) -> dict[str, Any]:
        return self._value


class _FakeClient:
    def __init__(
        self,
        bundle: LiveEvaluationBundle,
        preflight: Live60ExecutionPreflight,
        runtime: Live60RuntimeBinding,
        *,
        valid_citation: bool = True,
        resume_once: bool = False,
    ) -> None:
        self.bundle = bundle
        self.preflight = preflight
        self.runtime = runtime
        self.valid_citation = valid_citation
        self.resume_once = resume_once
        self.resumed = False
        self.submissions: list[str] = []
        self.cancelled: list[str] = []
        self.jobs: dict[str, str] = {}

    def _case(self, case_id: str) -> Any:
        return next(item for item in self.bundle.registry.cases if item.case_id == case_id)

    def _request_sha(self, case_id: str) -> str:
        case = self._case(case_id)
        return live60_evaluation_request_sha256(
            bundle=self.bundle,
            preflight=self.preflight,
            case_id=case_id,
            route=case.expected_research_route,
        )

    async def post(self, url: str, **kwargs: Any) -> _Response:
        if url.endswith("/api/v1/questions"):
            headers = kwargs["headers"]
            case_id = str(headers["X-Evaluation-Case-ID"])
            assert headers["X-Evaluation-Run-ID"] == "live60-http-test"
            assert headers["X-Idempotency-Key"].startswith("live60-")
            assert kwargs["json"]["online_mode"] == "local_only"
            assert kwargs["json"]["as_of_date"] == "2026-08-15"
            job_id = f"job-{case_id}"
            self.jobs[job_id] = case_id
            self.submissions.append(case_id)
            return _Response(202, {"job_id": job_id, "status": "queued"})
        if url.endswith("/resume"):
            self.resumed = True
            return _Response(200, {"status": "queued", "resume_mode": "digest_checked"})
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
                    "active_index": "candidate-live60-http",
                    "model_id": "test-model",
                    "prompt_version": "prompt-v1",
                    "router_version": "router-v1",
                    "classifier_version": "classifier-v1",
                    "policy_sha256": "1" * 64,
                    "assessment_bundle_sha256": "2" * 64,
                },
            )
        if "/api/v1/jobs/" in url:
            job_id = url.rsplit("/", 1)[-1]
            case_id = self.jobs[job_id]
            case = self._case(case_id)
            binding = {
                "route": case.expected_research_route,
                "word_target": case.word_target,
                "as_of_date": "2026-08-15",
                "pinned_index_build_id": "candidate-live60-http",
                "evaluation_request_sha256": self._request_sha(case_id),
                "worker_prompt_version": "prompt-v1",
                "worker_router_version": "router-v1",
                "worker_classifier_version": "classifier-v1",
                "worker_policy_sha256": "1" * 64,
                "assessment_bundle_sha256": "2" * 64,
            }
            if self.resume_once and not self.resumed:
                return _Response(
                    200,
                    {
                        "id": job_id,
                        "status": "system_error",
                        "trace_id": f"trace-{case_id}",
                        **binding,
                    },
                )
            return _Response(
                200,
                {
                    "id": job_id,
                    "status": "complete",
                    "answer_id": f"answer-{case_id}",
                    "release_state": "verified_full",
                    "trace_id": f"trace-{case_id}",
                    **binding,
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
                            "locator": "para 1",
                            "legal_role": "holding_ratio",
                            "identity_verified": True,
                            "currentness_verified": True,
                            "currentness_status": "later_treatment_checked",
                            "jurisdiction": "England and Wales",
                            "canonical_citation": (
                                "Test Case [2026] UKSC 1" if self.valid_citation else ""
                            ),
                            "citation_data": (
                                {
                                    "source_type": "case",
                                    "case_name": "Test Case",
                                    "neutral_citation": "[2026] UKSC 1",
                                }
                                if self.valid_citation
                                else {}
                            ),
                        }
                    ],
                },
            )
        if "/api/v1/answers/" in url:
            case_id = url.rsplit("/", 1)[-1].removeprefix("answer-")
            case = self._case(case_id)
            content = f"Verified answer for {case_id} supported by authority."
            return _Response(
                200,
                {
                    "id": f"answer-{case_id}",
                    "job_id": f"job-{case_id}",
                    "content": content,
                    "word_count": len(content.split()),
                    "release_state": "verified_full",
                    "policy_version": "test-policy",
                    "model_version": "test-model",
                    "index_build_id": "candidate-live60-http",
                    "route": case.expected_research_route,
                    "as_of_date": "2026-08-15",
                    "word_target": case.word_target,
                    "evaluation_request_sha256": self._request_sha(case_id),
                    "prompt_version": "prompt-v1",
                    "router_version": "router-v1",
                    "classifier_version": "classifier-v1",
                    "runtime_policy_sha256": "1" * 64,
                    "assessment_bundle_sha256": "2" * 64,
                    "quality": {
                        "evidence_passed": 1,
                        "academic_score": 72.0,
                        "findings_json": "[]",
                        "release_state": "verified_full",
                        "policy_sha256": "1" * 64,
                    },
                },
            )
        raise AssertionError(url)


def _fixture(
    tmp_path: Path, *, eligible_count: int = 1
) -> tuple[
    LiveSuiteRunStore,
    LiveEvaluationBundle,
    Live60ExecutionPreflight,
    Live60RuntimeBinding,
]:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    store = LiveSuiteRunStore(tmp_path / "project", LocalCipher(Fernet(Fernet.generate_key())))
    manifest = store.create_run(
        run_id="live60-http-test",
        bundle=bundle,
        provenance=RunProvenance(
            git_sha="a" * 40,
            git_dirty=False,
            model_version="test-model",
            index_build_id="candidate-live60-http",
            prompt_version="prompt-v1",
            router_version="router-v1",
            classifier_version="classifier-v1",
            policy_sha256="1" * 64,
            assessment_rules_sha256="2" * 64,
        ),
        admitted_at=datetime(2026, 8, 15, 8, 0, tzinfo=UTC),
    )
    selected = tuple(
        item.case_id for item in bundle.run_plan.cases if item.disposition == "generate_once"
    )
    authorization_value: dict[str, Any] = {
        "schema": "legalbot.live60-execution-authorization.v1",
        "authorization_id": "authorization-live60-http-test",
        "run_id": manifest.run_id,
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "run_plan_seal_sha256": bundle.run_plan.seal_sha256,
        "active_build_id": "candidate-live60-http",
        "owner_promotion_ref": "promotion:" + "3" * 64,
        "rollback_repromotion_report_sha256": "4" * 64,
        "browser_recovery_report_sha256": "5" * 64,
        "readiness_report_sha256": "6" * 64,
        "readiness_ready": True,
        "readiness_blocker_count": 0,
        "o04_authorization_ref": "o04:" + "7" * 64,
        "local_only": True,
        "online_research_allowed": False,
        "authorized_pass_count": 1,
        "authorized_case_ids": selected,
        "issued_at": "2026-08-15T08:30:00Z",
        "owner_ref": "owner:" + "8" * 64,
    }
    authorization_value["seal_sha256"] = sealed_sha256(authorization_value)
    authorization = Live60ExecutionAuthorization.model_validate(authorization_value)
    eligible = selected[:eligible_count]
    held = selected[eligible_count:]
    preflight = Live60ExecutionPreflight(
        run_manifest=manifest,
        authorization=authorization,
        generated_case_ids=selected,
        evidence_ready_case_ids=eligible,
        limited_or_held_case_ids=held,
        held_case_ids=held,
    )
    runtime = Live60RuntimeBinding(
        run_id=manifest.run_id,
        base_url="http://127.0.0.1:8777",
        index_build_id="candidate-live60-http",
        model_version="test-model",
        prompt_version="prompt-v1",
        router_version="router-v1",
        classifier_version="classifier-v1",
        policy_sha256="1" * 64,
        assessment_bundle_sha256="2" * 64,
        as_of_date=date(2026, 8, 15),
        owner_identifiers=(),
        readiness_report_sha256="6" * 64,
        rollback_report_sha256="4" * 64,
        browser_recovery_report_sha256="5" * 64,
    )
    return store, bundle, preflight, runtime


@pytest.mark.asyncio
async def test_live60_executor_submits_only_eligible_selected_once_and_resumes(
    tmp_path: Path,
) -> None:
    store, bundle, preflight, runtime = _fixture(tmp_path)
    client = _FakeClient(bundle, preflight, runtime, resume_once=True)
    executor = Live60Executor(
        store=store,
        bundle=bundle,
        preflight=preflight,
        runtime=runtime,
        client=client,
        poll_interval_seconds=0,
        case_timeout_seconds=2,
        legal_date_provider=lambda: date(2026, 8, 15),
    )

    outcomes = await executor.execute()

    assert len(outcomes) == 30
    assert client.submissions == [preflight.evidence_ready_case_ids[0]]
    assert client.resumed is True
    assert outcomes[0].released is True
    assert all(not item.released for item in outcomes[1:])
    assert not any(
        (store._case_path(runtime.run_id, item.case_id) / "outcome.json").exists()
        for item in bundle.run_plan.cases
        if item.disposition == "coverage_only_not_selected"
    )

    repeated = await executor.execute()
    assert tuple(item.outcome_id for item in repeated) == tuple(
        item.outcome_id for item in outcomes
    )
    assert client.submissions == [preflight.evidence_ready_case_ids[0]]
    detail = LiveSuiteAdminReader(store).run_detail(runtime.run_id)
    first_pass = next(item for item in detail["cases"] if item["case_id"] == outcomes[0].case_id)[
        "passes"
    ][0]
    assert first_pass["job_id"] == outcomes[0].job_id
    assert first_pass["rule_evaluation_state"] == "recorded"
    assert first_pass["assessment_rule_ids"]
    assert first_pass["evidence"][0]["support_state"] == "supported"
    quality = store.load_safe_case_json(
        run_id=runtime.run_id,
        case_id=outcomes[0].case_id,
        filename="quality.json",
    )
    assert quality["advisory_ai_review"]["status"] == "not_run"
    assert quality["advisory_ai_review"]["can_authorize_gates"] is False


@pytest.mark.asyncio
async def test_failed_citation_gate_keeps_prose_encrypted_and_outcome_unreleased(
    tmp_path: Path,
) -> None:
    store, bundle, preflight, runtime = _fixture(tmp_path)
    client = _FakeClient(bundle, preflight, runtime, valid_citation=False)
    executor = Live60Executor(
        store=store,
        bundle=bundle,
        preflight=preflight,
        runtime=runtime,
        client=client,
        poll_interval_seconds=0,
        case_timeout_seconds=2,
        legal_date_provider=lambda: date(2026, 8, 15),
    )

    outcomes = await executor.execute()

    first = outcomes[0]
    assert first.terminal_state == "held"
    assert first.answer_artifact_id is None
    assert "released_answer_citation_failure" in first.failure_codes
    artifact_id = (
        "answer-"
        + hashlib.sha256(
            (f"{runtime.run_id}\0{first.case_id}\0answer-{first.case_id}\0pass-1").encode()
        ).hexdigest()[:24]
    )
    encrypted = store._case_path(runtime.run_id, first.case_id) / (
        f"artifacts/{SensitiveArtifactKind.ANSWER.value}-{artifact_id}.enc"
    )
    assert encrypted.is_file()
    assert b"Verified answer" not in encrypted.read_bytes()


@pytest.mark.asyncio
async def test_live60_finalizer_is_idempotent_and_covers_all_sixty(
    tmp_path: Path,
) -> None:
    store, bundle, preflight, runtime = _fixture(tmp_path, eligible_count=0)
    executor = Live60Executor(
        store=store,
        bundle=bundle,
        preflight=preflight,
        runtime=runtime,
        client=_FakeClient(bundle, preflight, runtime),
        poll_interval_seconds=0,
        case_timeout_seconds=2,
        legal_date_provider=lambda: date(2026, 8, 15),
    )
    await executor.execute()
    for case in bundle.registry.cases:
        store.store_safe_case_json(
            run_id=runtime.run_id,
            case_id=case.case_id,
            filename="coverage.json",
            value={
                "schema": "legalbot.live-coverage.v3",
                "run_id": runtime.run_id,
                "case_id": case.case_id,
                "coverage_status": "knowledge_gap",
            },
        )

    review = finalize_live60_review_export(store=store, bundle=bundle, run_id=runtime.run_id)
    repeated = finalize_live60_review_export(store=store, bundle=bundle, run_id=runtime.run_id)

    assert len(review.cases) == 60
    assert sum(item.run_plan_outcome_count or 0 for item in review.cases) == 30
    assert review.model_dump(mode="json", by_alias=True) == repeated.model_dump(
        mode="json", by_alias=True
    )
    assert (store._run_path(runtime.run_id) / "review-export.json").is_file()
    slo = store.load_safe_run_json(run_id=runtime.run_id, filename="slo-evaluation.json")
    assert slo["schema"] == "legalbot.observability-slo-evaluation.v1"
    assert slo["observe_only"] is True
    assert slo["eligible_for_training"] is False
    coverage_only = [
        item for item in review.cases if item.run_plan_disposition == "coverage_only_not_selected"
    ]
    assert coverage_only
    assert all(item.privacy_passed is False for item in coverage_only)
    assert all(item.evidence_passed is False for item in coverage_only)
    assert review.privacy_report_passed is True


@pytest.mark.asyncio
async def test_live60_executor_stops_if_london_date_changes(tmp_path: Path) -> None:
    store, bundle, preflight, runtime = _fixture(tmp_path)
    executor = Live60Executor(
        store=store,
        bundle=bundle,
        preflight=preflight,
        runtime=runtime,
        client=_FakeClient(bundle, preflight, runtime),
        legal_date_provider=lambda: date(2026, 8, 16),
    )

    with pytest.raises(RuntimeError, match="date changed"):
        await executor.execute()
