from __future__ import annotations

import hashlib
import json
import stat
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from pydantic import ValidationError
from test_owner_quality_canary_projection import _contracts, _positive_result

from app.api.main import app
from app.assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
from app.config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from app.db import Database, utc_iso
from app.evaluation.all60_qualification import ExactAll60Qualification
from app.evaluation.canary_review_workspace import (
    CanaryReviewWorkspace,
    CanaryReviewWorkspaceManifest,
)
from app.evaluation.live_suite import sealed_sha256
from app.evaluation.live_suite_stage_a_v2_runner import STAGE_A_SCORER_IDENTITY_SHA256
from app.evaluation.owner_quality_canary import (
    ALL60_QUALIFICATION_SCHEMA,
    All60CaseQualification,
    OwnerQualityCanaryManifest,
    owner_quality_manifest_bytes,
)
from app.evaluation.owner_quality_canary_acceptance import (
    create_owner_canary_acceptance_summary,
)
from app.evaluation.owner_quality_canary_artifacts import (
    DETERMINISTIC_RELEASE_GATES,
    seal_owner_canary_deterministic_gate_report,
    seal_owner_canary_release_attestation,
)
from app.evaluation.owner_quality_canary_authorization import (
    OwnerDecisionRequired,
    OwnerQualityHoldoutAuthorization,
)
from app.evaluation.owner_quality_canary_circuit import (
    OwnerCanaryAttemptRequest,
    OwnerCanaryCaseAttemptResult,
    _request,
    seal_owner_canary_case_result,
)
from app.evaluation.owner_quality_canary_feedback import append_owner_canary_feedback
from app.evaluation.owner_quality_canary_runtime import (
    OWNER_CANARY_RUNTIME_ENVELOPE_SCHEMA,
    OWNER_CANARY_RUNTIME_REPORT_SCHEMA,
    OwnerCanaryRuntimeAttemptEnvelope,
    OwnerCanaryRuntimeReleaseReport,
    _execute_owner_quality_canary_with_client,
    _verify_lane_runtime_prerequisites,
)
from app.evaluation.owner_quality_v111_promotion import (
    V111_PROMOTION_PRESENTATION_SCHEMA,
    OwnerQualityV111PromotionPresentation,
    V111PromotionArtifactRef,
    expected_owner_promotion_confirmation,
    write_owner_quality_v111_promotion_authorization,
)
from app.evaluation.sealed_candidate import SealedCandidateIdentity
from app.evaluation.v111_technical_attestation import FIXED_CHECK_MATRIX_SHA256
from app.orchestration.classifier import CLASSIFIER_VERSION
from app.orchestration.routing import ROUTER_VERSION
from app.quality.policy import POLICY_SHA256
from app.retrieval.service import promote_candidate_index
from app.runtime_adapters import PROMPT_VERSION

NOW = datetime(2026, 8, 20, 6, 0, tzinfo=UTC)
REPO_ROOT = Path(__file__).resolve().parents[2]


class _Response:
    def __init__(self, status_code: int, value: dict[str, Any]) -> None:
        self.status_code = status_code
        self._value = value

    def json(self) -> dict[str, Any]:
        return self._value


def _runtime_envelope(
    *,
    request: OwnerCanaryAttemptRequest,
    result: OwnerCanaryCaseAttemptResult,
    settings: Settings,
    runtime_release_state: str = "verified_full",
) -> OwnerCanaryRuntimeAttemptEnvelope:
    assert result.released
    assert result.job_id is not None
    assert result.answer_version_id is not None
    assert result.answer_artifact_id is not None
    assert result.answer_sha256 is not None
    assert result.word_count is not None
    assert result.ai_review is not None
    assert result.ai_adjudication is not None
    assert result.standards_report is not None
    assert result.evidence_bundle is not None
    gates = {gate: True for gate in DETERMINISTIC_RELEASE_GATES}
    report_value: dict[str, Any] = {
        "schema": OWNER_CANARY_RUNTIME_REPORT_SCHEMA,
        "run_id": result.run_id,
        "authorization_seal_sha256": result.authorization_seal_sha256,
        "canary_manifest_seal_sha256": result.canary_manifest_seal_sha256,
        "case_id": result.case_id,
        "attempt_number": result.attempt_number,
        "input_revision_sha256": result.input_revision_sha256,
        "candidate_build_id": result.candidate_build_id,
        "candidate_manifest_sha256": result.candidate_manifest_sha256,
        "integration_sha": request.authorization_seal_sha256[:40],
        "job_id": result.job_id,
        "answer_version_id": result.answer_version_id,
        "quality_report_id": f"quality-{result.case_id}",
        "runtime_release_state": runtime_release_state,
        "answer_sha256": result.answer_sha256,
        "word_count": result.word_count,
        "answer_workflow_attempt_count": 1,
        "targeted_repair_version_count": 0,
        "versioned_repair_chain_verified": True,
        "configured_model_id": settings.model_id,
        "answer_model_version": "fake-service-answer-model-v1",
        "prompt_version": PROMPT_VERSION,
        "router_version": ROUTER_VERSION,
        "classifier_version": CLASSIFIER_VERSION,
        "policy_sha256": POLICY_SHA256,
        "assessment_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
        "ai_review_seal_sha256": result.ai_review.seal_sha256,
        "ai_adjudication_seal_sha256": result.ai_adjudication.seal_sha256,
        "standards_report_seal_sha256": result.standards_report.seal_sha256,
        "evidence_identity_set_sha256": sealed_sha256(
            {"evidence_span_ids": list(result.evidence_bundle.evidence_span_ids)}
        ),
        "deterministic_gate_inputs": gates,
        "gate_implementation_sha256": "6" * 64,
        "persisted_quality_report": True,
        "candidate_pin_reconciled": True,
        "authoritative_db_projection": False,
        "synthetic_non_authoritative": True,
        "plaintext_question_included": False,
        "plaintext_answer_included": False,
    }
    report_value["seal_sha256"] = sealed_sha256(report_value)
    report = OwnerCanaryRuntimeReleaseReport.model_validate(report_value)
    gate_report = seal_owner_canary_deterministic_gate_report(
        run_id=result.run_id,
        authorization_seal_sha256=result.authorization_seal_sha256,
        canary_manifest_seal_sha256=result.canary_manifest_seal_sha256,
        case_id=result.case_id,
        candidate_build_id=result.candidate_build_id,
        candidate_manifest_sha256=result.candidate_manifest_sha256,
        job_id=result.job_id,
        answer_version_id=result.answer_version_id,
        answer_sha256=result.answer_sha256,
        requested_word_target=request.requested_word_target,
        word_count=result.word_count,
        evidence_bundle=result.evidence_bundle,
        source_release_report_sha256=report.seal_sha256,
        gate_implementation_sha256=report.gate_implementation_sha256,
        passed_gates=gates,
    )
    release = seal_owner_canary_release_attestation(
        answer_artifact_id=result.answer_artifact_id,
        runtime_release_state="verified_full",
        evidence_bundle=result.evidence_bundle,
        deterministic_gate_report=gate_report,
    )
    rebound = seal_owner_canary_case_result(
        result_id=result.result_id,
        run_id=result.run_id,
        authorization_seal_sha256=result.authorization_seal_sha256,
        canary_manifest_seal_sha256=result.canary_manifest_seal_sha256,
        case_id=result.case_id,
        attempt_number=result.attempt_number,
        input_revision_sha256=result.input_revision_sha256,
        candidate_build_id=result.candidate_build_id,
        candidate_manifest_sha256=result.candidate_manifest_sha256,
        job_id=result.job_id,
        answer_version_id=result.answer_version_id,
        answer_artifact_id=result.answer_artifact_id,
        released=True,
        answer_sha256=result.answer_sha256,
        word_count=result.word_count,
        ai_review=result.ai_review,
        ai_adjudication=result.ai_adjudication,
        standards_report=result.standards_report,
        evidence_bundle=result.evidence_bundle,
        deterministic_gate_report=gate_report,
        release_attestation=release,
    )
    value: dict[str, Any] = {
        "schema": OWNER_CANARY_RUNTIME_ENVELOPE_SCHEMA,
        "runtime_report": report.model_dump(mode="json", by_alias=True),
        "attempt_result": rebound.model_dump(mode="json", by_alias=True),
    }
    value["seal_sha256"] = sealed_sha256(value)
    return OwnerCanaryRuntimeAttemptEnvelope.model_validate(value)


class _FakeOwnerQualityService:
    """HTTP-shaped service double; it cannot inject the production callback."""

    def __init__(
        self, *, settings: Settings, bundle: Any, manifest: Any, authorization: Any
    ) -> None:
        self.settings = settings
        self.bundle = bundle
        self.manifest = manifest
        self.authorization = authorization
        self.answers: dict[str, bytes] = {}
        self.envelopes: dict[str, OwnerCanaryRuntimeAttemptEnvelope] = {}
        self.jobs: dict[str, dict[str, Any]] = {}
        self.case_ids: list[str] = []

    def post(self, url: str, **kwargs: Any) -> _Response:
        if url.endswith("/api/v1/questions"):
            headers = kwargs["headers"]
            case_id = str(headers["X-Owner-Canary-Case-ID"])
            attempt_number = int(headers["X-Owner-Canary-Attempt"])
            sequence = self.authorization.authorized_case_ids.index(case_id) + 1
            case = self.bundle.registry.case(case_id)
            request = _request(
                authorization=self.authorization,
                manifest=self.manifest,
                case_id=case_id,
                sequence_number=sequence,
                attempt_number=attempt_number,
                word_target=case.word_target,
                input_revision_sha256=str(headers["X-Owner-Canary-Input-Revision"]),
            )
            assert headers["X-Owner-Canary-Request-Seal"] == request.seal_sha256
            result = _positive_result(
                request=request,
                case=case,
                authorization=self.authorization,
                manifest=self.manifest,
                answers=self.answers,
            )
            envelope = _runtime_envelope(request=request, result=result, settings=self.settings)
            answer_id = str(envelope.attempt_result.answer_version_id)
            job_id = str(envelope.attempt_result.job_id)
            self.envelopes[answer_id] = envelope
            self.jobs[job_id] = {
                "status": "complete",
                "pinned_index_build_id": self.authorization.candidate_build_id,
                "evaluation_request_sha256": "present",
                "answer_id": answer_id,
            }
            self.case_ids.append(case_id)
            return _Response(202, {"job_id": job_id})
        if url.endswith("/cancel"):
            return _Response(202, {"status": "cancelled"})
        raise AssertionError(f"unexpected POST {url}")

    def get(self, url: str, **_kwargs: Any) -> _Response:
        if url.endswith("/api/v1/health"):
            return _Response(
                200,
                {
                    "worker_ready": True,
                    "model_ready": True,
                    "model_id": self.settings.model_id,
                    "prompt_version": PROMPT_VERSION,
                    "router_version": ROUTER_VERSION,
                    "classifier_version": CLASSIFIER_VERSION,
                    "policy_sha256": POLICY_SHA256,
                    "assessment_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
                },
            )
        if "/api/v1/jobs/" in url:
            return _Response(200, self.jobs[url.rsplit("/", 1)[-1]])
        if "/api/v1/owner-canary/answers/" in url:
            answer_id = url.split("/answers/", 1)[1].split("/", 1)[0]
            return _Response(
                200,
                self.envelopes[answer_id].model_dump(mode="json", by_alias=True),
            )
        if "/api/v1/answers/" in url:
            answer_id = url.rsplit("/", 1)[-1]
            result = self.envelopes[answer_id].attempt_result
            return _Response(
                200,
                {"content": self.answers[str(result.answer_artifact_id)].decode("utf-8")},
            )
        raise AssertionError(f"unexpected GET {url}")


def _write_model(path: Path, model: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(model.model_dump(mode="json", by_alias=True), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def test_owner_canary_runtime_rejects_limited_release_before_review(tmp_path: Path) -> None:
    bundle, manifest, authorization, _workspace, initial, _cipher = _contracts(tmp_path)
    case_id = authorization.authorized_case_ids[0]
    case = bundle.registry.case(case_id)
    request = _request(
        authorization=authorization,
        manifest=manifest,
        case_id=case_id,
        sequence_number=1,
        attempt_number=1,
        word_target=case.word_target,
        input_revision_sha256=initial[case_id],
    )
    result = _positive_result(
        request=request,
        case=case,
        authorization=authorization,
        manifest=manifest,
        answers={},
    )
    with pytest.raises(ValueError, match="verified_full"):
        _runtime_envelope(
            request=request,
            result=result,
            settings=Settings(project_root=tmp_path, test_mode=True),
            runtime_release_state="verified_limited",
        )


def _authoritative_candidate_and_qualification(
    *, bundle: Any, manifest: Any
) -> tuple[SealedCandidateIdentity, ExactAll60Qualification]:
    candidate = SealedCandidateIdentity(
        build_id=manifest.candidate_build_id,
        status="candidate",
        candidate_manifest_sha256=manifest.candidate_manifest_sha256,
        candidate_seal_sha256="b" * 64,
        source_manifest_sha256="c" * 64,
        embedding_model="embedding-model-v1",
        reranker_model="reranker-model-v1",
        document_count=85,
        chunk_count=149_855,
        vector_count=149_855,
    )
    case_ids = [case.case_id for case in bundle.registry.cases]
    shallow_value: dict[str, Any] = {
        "schema": ALL60_QUALIFICATION_SCHEMA,
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "candidate_build_id": candidate.build_id,
        "case_count": 60,
        "case_ids": case_ids,
        "qualified_case_ids": case_ids,
        "limited_case_ids": [],
        "review_complete": True,
        "unreviewed_issue_count": 0,
    }
    shallow_value["seal_sha256"] = sealed_sha256(shallow_value)
    shallow = All60CaseQualification.model_validate(shallow_value)
    exact = ExactAll60Qualification.model_construct(
        **shallow.model_dump(mode="python", by_alias=False),
        candidate_manifest_sha256=candidate.candidate_manifest_sha256,
        candidate_seal_sha256=candidate.candidate_seal_sha256,
        candidate_source_manifest_sha256=candidate.source_manifest_sha256,
    )
    assert exact.seal_sha256 == manifest.qualification_seal_sha256
    return candidate, exact


def test_fake_http_service_drives_exact_development_30_to_final_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "contract-fixture").mkdir()
    bundle, manifest, authorization, _unused, _initial, cipher = _contracts(
        tmp_path / "contract-fixture"
    )
    settings = Settings(project_root=tmp_path, test_mode=True)
    manifest_path = tmp_path / "inputs" / "owner-quality-manifest.json"
    qualification_path = tmp_path / "inputs" / "all60-qualification.json"
    authorization_path = tmp_path / "inputs" / "development-authorization.json"
    _write_model(manifest_path, manifest)
    _write_model(authorization_path, authorization)
    candidate, exact_qualification = _authoritative_candidate_and_qualification(
        bundle=bundle, manifest=manifest
    )
    qualification_path.write_text(
        json.dumps({"seal_sha256": exact_qualification.seal_sha256}) + "\n",
        encoding="utf-8",
    )
    qualification_path.chmod(0o600)
    settings.observability_slo_path.parent.mkdir(parents=True, exist_ok=True)
    settings.observability_slo_path.write_bytes(
        (REPO_ROOT / "config/observability_slo.yaml").read_bytes()
    )
    monkeypatch.setattr(
        "app.evaluation.owner_quality_canary_runtime.load_live_evaluation_bundle",
        lambda _path: bundle,
    )
    monkeypatch.setattr(
        "app.evaluation.owner_quality_canary_runtime.load_sealed_candidate_identity",
        lambda **_kwargs: candidate,
    )
    monkeypatch.setattr(
        "app.evaluation.owner_quality_canary.load_all60_qualification",
        lambda _path: exact_qualification,
    )
    service = _FakeOwnerQualityService(
        settings=settings,
        bundle=bundle,
        manifest=manifest,
        authorization=authorization,
    )

    redrawn_value = manifest.model_dump(mode="json", by_alias=True)
    redrawn_value["cases"][0]["selection_rank_sha256"] = "f" * 64
    redrawn_value["seal_sha256"] = sealed_sha256(redrawn_value)
    redrawn = OwnerQualityCanaryManifest.model_validate(redrawn_value)
    redrawn_path = tmp_path / "inputs" / "favorably-redrawn-manifest.json"
    redrawn_path.write_bytes(owner_quality_manifest_bytes(redrawn))
    redrawn_path.chmod(0o600)
    with pytest.raises(ValueError, match="redraw or derivation mismatch"):
        _execute_owner_quality_canary_with_client(
            settings=settings,
            cipher=cipher,
            manifest_path=redrawn_path,
            qualification_path=qualification_path,
            authorization_path=authorization_path,
            review_date=date(2026, 8, 20),
            legal_date=date(2026, 8, 20),
            base_url="http://127.0.0.1:8777",
            client=service,
            poll_interval_seconds=0.01,
            case_timeout_seconds=5,
            synthetic_non_authoritative=True,
        )
    assert service.case_ids == []

    execution = _execute_owner_quality_canary_with_client(
        settings=settings,
        cipher=cipher,
        manifest_path=manifest_path,
        qualification_path=qualification_path,
        authorization_path=authorization_path,
        review_date=date(2026, 8, 20),
        legal_date=date(2026, 8, 20),
        base_url="http://127.0.0.1:8777",
        client=service,
        poll_interval_seconds=0.01,
        case_timeout_seconds=5,
        synthetic_non_authoritative=True,
    )

    assert execution.circuit_result.status == "passed"
    assert execution.final_package is not None
    assert execution.final_package.case_ids == authorization.authorized_case_ids
    assert service.case_ids == list(authorization.authorized_case_ids)
    root = settings.evaluation_dir / "canary-output-review" / "2026-08-20" / authorization.run_id
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE((root / "execution-authorization.json").stat().st_mode) == 0o600
    assert all(
        (root / "cases" / case_id / "released-answer.md").is_file() for case_id in service.case_ids
    )
    assert not (settings.index_dir / "ACTIVE.json").exists()
    assert not tuple(root.rglob("*o04*"))
    assert (root / "all60-qualification.json").read_bytes() == qualification_path.read_bytes()

    package = execution.final_package
    workspace = CanaryReviewWorkspace(
        root=root,
        manifest=CanaryReviewWorkspaceManifest.model_validate_json(
            (root / "workspace-manifest.json").read_bytes()
        ),
    )
    previous = None
    for ordinal, case_id in enumerate(package.case_ids, start=1):
        previous, _index = append_owner_canary_feedback(
            workspace=workspace,
            package=package,
            cipher=cipher,
            case_id=case_id,
            decision="pass",
            feedback_text=f"Explicit fake-service owner test pass {ordinal}.",
            owner_ref="owner:" + "7" * 64,
            submitted_at=NOW + timedelta(minutes=ordinal),
            previous=previous,
        )
    acceptance = create_owner_canary_acceptance_summary(
        workspace=workspace,
        package=package,
        created_at=NOW + timedelta(hours=1),
    )
    assert acceptance.case_count == 30
    from app.evaluation.owner_quality_v111_promotion import _verify_final_package_files

    with pytest.raises(ValueError, match="synthetic or unbound runtime evidence"):
        _verify_final_package_files(workspace=workspace, package=package)


def _holdout_from_development(manifest: Any, development: Any) -> OwnerQualityHoldoutAuthorization:
    value = development.model_dump(mode="json", by_alias=True)
    value.update(
        {
            "schema": "legalbot.owner-quality-canary-holdout-authorization.v1",
            "authorization_id": "owner-canary-holdout-" + "7" * 20,
            "run_id": "owner-holdout-runtime-001",
            "lane": "blind_holdout",
            "authorized_case_ids": list(manifest.blind_holdout_case_ids),
            "requires_active": True,
            "requires_owner_promotion": True,
            "requires_operational_proof": True,
            "requires_o04": True,
            "active_build_id": development.candidate_build_id,
            "promoted_active_proof_seal_sha256": "8" * 64,
            "operational_proof_seal_sha256": "9" * 64,
            "o04_approval_seal_sha256": "a" * 64,
            "o04_approval_ref": "o04:" + "b" * 64,
            "owner_ref": "owner:" + "c" * 64,
        }
    )
    value.pop("seal_sha256")
    value["seal_sha256"] = sealed_sha256(value)
    return OwnerQualityHoldoutAuthorization.model_validate(value)


def test_holdout_runtime_stays_closed_without_authoritative_completion_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "contract-fixture").mkdir()
    _bundle, manifest, development, _workspace, _initial, _cipher = _contracts(
        tmp_path / "contract-fixture"
    )
    authorization = _holdout_from_development(manifest, development)
    settings = Settings(project_root=tmp_path)
    database = Database(settings.database_path)
    database.initialize()
    now = utc_iso()
    database.execute(
        """
        INSERT INTO index_builds(
          id, status, path, document_count, chunk_count, vector_count,
          embedding_model, reranker_model, created_at, promoted_at
        ) VALUES (?, 'active', ?, 1, 1, 1, 'embed', 'rerank', ?, ?)
        """,
        (authorization.candidate_build_id, "data/indexes/candidate-v111", now, now),
    )
    active = settings.index_dir / "ACTIVE.json"
    active.parent.mkdir(parents=True, exist_ok=True)
    active.write_text(
        json.dumps({"build_id": authorization.candidate_build_id}) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "app.evaluation.owner_quality_canary_runtime.load_sealed_candidate_identity",
        lambda **_kwargs: SimpleNamespace(
            candidate_manifest_sha256=authorization.candidate_manifest_sha256
        ),
    )
    try:
        with pytest.raises(OwnerDecisionRequired) as stopped:
            _verify_lane_runtime_prerequisites(
                settings=settings,
                database=database,
                manifest=manifest,
                authorization=authorization,
            )
        assert stopped.value.reason_code == "authoritative_completion_preflight_required"
    finally:
        database.close()


def _promotion_presentation() -> OwnerQualityV111PromotionPresentation:
    references = {
        name: V111PromotionArtifactRef(
            relative_path=f"data/evaluations/v111-promotion/{name}.json",
            file_sha256=hashlib.sha256(f"file-{name}".encode()).hexdigest(),
            artifact_seal_sha256=hashlib.sha256(f"seal-{name}".encode()).hexdigest(),
        )
        for name in (
            "canary_manifest",
            "all60_qualification",
            "development_authorization",
            "development_final_package",
            "development_owner_acceptance",
            "technical_attestation_admission",
        )
    }
    candidate = "candidate-v111"
    candidate_manifest = "d" * 64
    integration = "e" * 40
    manifest_seal = "f" * 64
    package_seal = "1" * 64
    acceptance_seal = "2" * 64
    admission_id = "v111-technical-admission:" + "6" * 64
    admission_seal = references["technical_attestation_admission"].artifact_seal_sha256
    artifact_set = "7" * 64
    identity = sealed_sha256(
        {
            "candidate_build_id": candidate,
            "candidate_manifest_sha256": candidate_manifest,
            "integration_sha": integration,
            "canary_manifest_seal_sha256": manifest_seal,
            "all60_qualification_file_sha256": references["all60_qualification"].file_sha256,
            "development_final_package_seal_sha256": package_seal,
            "development_owner_acceptance_seal_sha256": acceptance_seal,
            "technical_admission_id": admission_id,
            "technical_admission_seal_sha256": admission_seal,
            "technical_attestation_admission_file_sha256": references[
                "technical_attestation_admission"
            ].file_sha256,
            "technical_artifact_set_sha256": artifact_set,
        }
    )
    value: dict[str, Any] = {
        "schema": V111_PROMOTION_PRESENTATION_SCHEMA,
        "presentation_id": f"promotion:{identity}",
        "candidate_build_id": candidate,
        "candidate_manifest_sha256": candidate_manifest,
        "integration_sha": integration,
        "canary_manifest_id": "owner-quality-canary-" + "3" * 20,
        "canary_manifest_seal_sha256": manifest_seal,
        "development_run_id": "owner-development-v111-001",
        "development_authorization_seal_sha256": "4" * 64,
        "development_final_package_seal_sha256": package_seal,
        "development_owner_acceptance_seal_sha256": acceptance_seal,
        "exact_development_case_count": 30,
        "exact_development_case_ids": [f"live60-q{number:02d}" for number in range(1, 31)],
        "exact_development_answer_sha256s": [
            hashlib.sha256(f"answer-{number}".encode()).hexdigest() for number in range(1, 31)
        ],
        **{key: item.model_dump(mode="json") for key, item in references.items()},
        "technical_run_id": "technical-run-001",
        "technical_admission_id": admission_id,
        "technical_admission_seal_sha256": admission_seal,
        "technical_final_attestation_seal_sha256": "8" * 64,
        "technical_matrix_sha256": FIXED_CHECK_MATRIX_SHA256,
        "technical_artifact_set_sha256": artifact_set,
        "technical_artifact_member_count": 32,
        "technical_stage_a_result_seal_sha256": "9" * 64,
        "technical_stage_a_attestation_seal_sha256": "a" * 64,
        "technical_rollback_plan_seal_sha256": "b" * 64,
        "technical_rollback_policy_binding_seal_sha256": "c" * 64,
        "scorer_identity_sha256": STAGE_A_SCORER_IDENTITY_SHA256,
        "legacy_technical_summaries_accepted": False,
        "test_results_passed": True,
        "rollback_plan_ready": True,
        "exact_artifacts_verified": True,
        "owner_decision_required": True,
        "owner_authorization_present": False,
        "authorizes_active": False,
        "writes_active": False,
        "writes_previous": False,
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
    }
    value["seal_sha256"] = sealed_sha256(value)
    return OwnerQualityV111PromotionPresentation.model_validate(value)


def test_owner_active_authorization_stops_for_trusted_signature_policy(
    tmp_path: Path,
) -> None:
    presentation = _promotion_presentation()
    presentation_path = tmp_path / "presentation.json"
    _write_model(presentation_path, presentation)
    destination = tmp_path / "owner-authorization.json"
    with pytest.raises(OwnerDecisionRequired) as stopped:
        write_owner_quality_v111_promotion_authorization(
            presentation_path=presentation_path,
            destination=destination,
            owner_ref="owner:" + "6" * 64,
            exact_confirmation="AUTHORIZE-ACTIVE candidate-v111",
            authorized_at=NOW,
        )
    assert stopped.value.reason_code == "trusted_owner_promotion_signature_policy_missing"
    assert not destination.exists()
    with pytest.raises(OwnerDecisionRequired):
        write_owner_quality_v111_promotion_authorization(
            presentation_path=presentation_path,
            destination=destination,
            owner_ref="owner:" + "6" * 64,
            exact_confirmation=expected_owner_promotion_confirmation(presentation),
            authorized_at=NOW,
        )


def test_promotion_presentation_rejects_legacy_or_mutated_technical_summaries() -> None:
    presentation = _promotion_presentation()
    legacy = presentation.model_dump(mode="json", by_alias=True)
    for key in tuple(legacy):
        if key.startswith("technical_") or key == "legacy_technical_summaries_accepted":
            legacy.pop(key)
    legacy.update(
        {
            "complete_test_results": presentation.technical_attestation_admission.model_dump(
                mode="json"
            ),
            "scorer_identity": presentation.technical_attestation_admission.model_dump(mode="json"),
            "rollback_plan": presentation.technical_attestation_admission.model_dump(mode="json"),
            "test_results_passed": True,
            "rollback_plan_ready": True,
        }
    )
    legacy["seal_sha256"] = sealed_sha256(legacy)
    with pytest.raises(ValidationError):
        OwnerQualityV111PromotionPresentation.model_validate(legacy)

    mutated = presentation.model_dump(mode="json", by_alias=True)
    mutated["technical_matrix_sha256"] = "0" * 64
    mutated["seal_sha256"] = sealed_sha256(mutated)
    with pytest.raises(ValidationError, match="technically bound"):
        OwnerQualityV111PromotionPresentation.model_validate(mutated)


def test_first_live_promotion_rejects_legacy_and_missing_v111_owner_evidence(
    tmp_path: Path,
) -> None:
    settings = Settings(
        project_root=tmp_path,
        live_profile=FIRST_LIVE_LOCAL_ONLY_PROFILE,
        test_mode=True,
    )
    database = Database(settings.database_path)
    database.initialize()
    presentation = _promotion_presentation()
    presentation_path = tmp_path / "presentation.json"
    _write_model(presentation_path, presentation)
    try:
        with pytest.raises(ValueError, match="cannot use the legacy"):
            promote_candidate_index(
                settings,
                database,
                "candidate-v111",
                live60_attestation=object(),
            )
        with pytest.raises(ValueError, match="exact dev30 presentation"):
            promote_candidate_index(settings, database, "candidate-v111")
        with pytest.raises((FileNotFoundError, ValueError)):
            promote_candidate_index(
                settings,
                database,
                "candidate-v111",
                v111_promotion_presentation=presentation,
                v111_owner_authorization={},
            )
    finally:
        database.close()
    assert not (settings.index_dir / "ACTIVE.json").exists()


@pytest.mark.asyncio
async def test_first_live_active_alone_cannot_admit_ordinary_question_or_report_ready(
    tmp_path: Path,
) -> None:
    settings = Settings(
        project_root=tmp_path,
        live_profile=FIRST_LIVE_LOCAL_ONLY_PROFILE,
    )
    database = Database(settings.database_path)
    database.initialize()
    now = utc_iso()
    database.execute(
        """
        INSERT INTO index_builds(
          id, status, path, document_count, chunk_count, vector_count,
          embedding_model, reranker_model, created_at, promoted_at
        ) VALUES ('active-v111', 'active', 'data/indexes/active-v111',
                  1, 1, 1, 'embed', 'rerank', ?, ?)
        """,
        (now, now),
    )

    class HealthyModel:
        async def health(self) -> bool:
            return True

    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        settings=settings,
        database=database,
        model=HealthyModel(),
    )
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4321))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            response = await client.post(
                "/api/v1/questions",
                json={
                    "question": "Was a contract formed?",
                    "task_type": "problem",
                    "jurisdiction": "England and Wales",
                    "as_of_date": "2026-08-20",
                    "word_target": 500,
                    "online_mode": "local_only",
                    "upload_ids": [],
                },
            )
            health = await client.get("/api/v1/health")
        assert response.status_code == 503
        assert response.json()["detail"] == (
            "TECHNICAL_IMPLEMENTATION_REQUIRED:normal_live_release_content_certification_missing"
        )
        assert health.status_code == 200
        health_value = health.json()
        assert health_value["status"] == "not_ready"
        assert "normal_live_release_content_certification_missing" in health_value["reasons"]
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous
        database.close()
