from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from cryptography.fernet import Fernet
from scripts import create_v111_all60_currentness_decision as currentness_cli
from scripts import run_live60_all_ai_evidence_review as all60_batch_cli
from scripts.create_v111_all60_currentness_decision import main as create_currentness_stop
from scripts.owner_quality_v111 import _owner_stop_envelope

from app.api.main import app
from app.config import Settings
from app.crypto import LocalCipher
from app.db import Database
from app.evaluation.all60_evidence_review import (
    All60OwnerDecisionRequired,
    _CandidateContext,
    verify_runtime_candidate_evidence_spans,
)
from app.evaluation.evaluation_job_authority import (
    build_completion_nonrelease_job_authority,
)
from app.evaluation.live_suite import sealed_sha256
from app.evaluation.owner_quality_canary_authorization import (
    OwnerDecisionRequired,
    replay_authorization_stage_a,
)
from app.evaluation.owner_quality_canary_runtime import (
    _canonical_persisted_release_findings,
    _deterministic_citations,
    configured_authoritative_canary_output_root,
    derive_owner_canary_gap_inventory,
    load_verified_all60_batch_for_owner_runtime,
    require_authoritative_canary_output_root,
)
from app.evaluation.owner_quality_normal_live_readiness import (
    _verified_release_authority_from_artifacts,
    owner_quality_normal_live_readiness_status,
    owner_quality_normal_live_release_authority,
)
from app.evaluation.sealed_candidate import SealedCandidateIdentity
from app.model_runtime.config import PINNED_RUNTIME_MODEL_VERSION, PINNED_RUNTIME_REPO
from app.orchestration.contracts import ModelDraft
from app.orchestration.runner import (
    AnswerRunner,
    _bind_model_draft_context,
    _quality_failure_identity_sha256,
)
from app.orchestration.targeted_repair import verify_targeted_structured_repair
from app.privacy import PRIVATE_QUESTION_SUMMARY
from app.quality.evaluator import QualityEvaluator
from app.quality.policy import POLICY_VERSION
from app.retrieval.retrieval_reattest import _clean_integration_sha
from app.runtime_adapters import LoopbackModelGateway
from app.types import (
    EvidenceSpan,
    MaterialLane,
    QualityFinding,
    QualityReport,
    QuestionRequest,
    ReleaseState,
    Severity,
    StructuredClaimDraft,
    StructuredDraft,
    StructuredSectionDraft,
    TaskType,
)


def _cipher() -> LocalCipher:
    return LocalCipher(Fernet(Fernet.generate_key()))


@pytest.mark.asyncio
async def test_all60_reviewer_batch_stops_on_currentness_before_model_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalogue = tmp_path / "catalogue.db"
    catalogue.touch()
    settings = SimpleNamespace(
        online_default="local_only",
        official_research_enabled=False,
        database_path=catalogue,
        index_dir=tmp_path / "indexes",
    )
    candidate = SimpleNamespace(
        build_id="candidate-v111",
        candidate_manifest_sha256="1" * 64,
        source_manifest_sha256="2" * 64,
    )
    launch_attempted = False

    def launcher(**_kwargs: Any) -> object:
        nonlocal launch_attempted
        launch_attempted = True
        raise AssertionError("model launcher must not be constructed before currentness approval")

    monkeypatch.setattr(all60_batch_cli, "Settings", lambda **_kwargs: settings)
    monkeypatch.setattr(all60_batch_cli, "load_live_evaluation_bundle", lambda _path: object())
    monkeypatch.setattr(
        all60_batch_cli, "load_readonly_sealed_candidate", lambda **_kwargs: candidate
    )
    monkeypatch.setattr(
        all60_batch_cli, "load_suite_expert_qualification", lambda *_args, **_kwargs: object()
    )
    monkeypatch.setattr(all60_batch_cli, "_clean_integration_sha", lambda _root: "3" * 40)
    monkeypatch.setattr(
        all60_batch_cli,
        "load_all60_reviewer_batch_inputs",
        lambda **_kwargs: (SimpleNamespace(issue_identity_sha256="4" * 64),),
    )

    def currentness_stop(**_kwargs: Any) -> None:
        raise All60OwnerDecisionRequired(
            "LEGAL_CURRENTNESS_OWNER_DECISION_UNRESOLVED",
            row_id="candidate:candidate-v111",
            decision_id="v111-all60-currentness-test",
        )

    monkeypatch.setattr(
        all60_batch_cli, "require_trusted_all60_currentness_resolution", currentness_stop
    )
    monkeypatch.setattr(all60_batch_cli, "LoopbackCandidateCompletionLauncher", launcher)
    args = SimpleNamespace(
        run_id="all60-review-v111",
        candidate_build_id="candidate-v111",
        as_of_date=date(2026, 8, 20),
        expert_qualification=tmp_path / "expert.json",
        bundle=tmp_path / "bundle",
        model_start_timeout_seconds=900.0,
    )
    with pytest.raises(
        All60OwnerDecisionRequired,
        match="LEGAL_CURRENTNESS_OWNER_DECISION_UNRESOLVED",
    ):
        await all60_batch_cli._run(args)
    assert launch_attempted is False


def test_all60_batch_replay_projects_active_build_to_frozen_candidate_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.evaluation.candidate_completion_authority as completion_authority
    import app.evaluation.candidate_completion_runtime as completion_runtime
    import app.evaluation.owner_quality_canary_runtime as owner_runtime

    candidate = SealedCandidateIdentity(
        build_id="candidate-v111",
        status="active",
        candidate_manifest_sha256="1" * 64,
        candidate_seal_sha256="2" * 64,
        source_manifest_sha256="3" * 64,
        embedding_model="embed",
        reranker_model="rerank",
        document_count=85,
        chunk_count=149_855,
        vector_count=149_855,
    )
    observed: list[tuple[str, str]] = []

    def runtime_binding(**kwargs: Any) -> dict[str, Any]:
        projected = kwargs["candidate"]
        observed.append((projected.build_id, projected.status))
        return {"seal_sha256": "4" * 64}

    def memory_policy(*args: Any, **kwargs: Any) -> object:
        del args
        projected = kwargs["candidate"]
        observed.append((projected.build_id, projected.status))
        return object()

    qualification = SimpleNamespace(
        ai_review_batch_run_date=date(2026, 8, 20),
        ai_review_batch_run_id="all60-review-v111",
        as_of_date=date(2026, 8, 20),
        ai_review_batch_attestation_seal_sha256="5" * 64,
        ai_review_batch_manifest_seal_sha256="6" * 64,
        ai_review_batch_checkpoint_set_sha256="7" * 64,
        ai_review_batch_intent_ledger_sha256="8" * 64,
        ai_review_batch_outcome_ledger_sha256="9" * 64,
        ai_review_batch_launcher_start_sha256="a" * 64,
        ai_review_batch_launcher_end_sha256="b" * 64,
    )
    verified = SimpleNamespace(
        attestation=SimpleNamespace(seal_sha256="5" * 64),
        manifest_seal_sha256="6" * 64,
        checkpoint_set_sha256="7" * 64,
        invocation_intent_ledger_sha256="8" * 64,
        invocation_outcome_ledger_sha256="9" * 64,
        launcher_start_attestation_sha256="a" * 64,
        launcher_end_attestation_sha256="b" * 64,
    )

    def batch_loader(**kwargs: Any) -> object:
        projected = kwargs["candidate"]
        observed.append((projected.build_id, projected.status))
        return verified

    slo_path = tmp_path / "slo.json"
    slo_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        owner_runtime,
        "load_slo_policy",
        lambda _path: SimpleNamespace(policy_id="slo-v1"),
    )
    monkeypatch.setattr(
        completion_runtime, "build_local_completion_runtime_binding", runtime_binding
    )
    monkeypatch.setattr(completion_authority, "load_completion_memory_policy", memory_policy)
    monkeypatch.setattr(owner_runtime, "load_verified_all60_ai_review_batch", batch_loader)
    settings = SimpleNamespace(
        observability_slo_path=slo_path,
        completion_memory_policy_path=tmp_path / "memory.json",
        owner_decision_root=tmp_path / "owner-decisions",
        index_dir=tmp_path / "indexes",
    )
    result = load_verified_all60_batch_for_owner_runtime(
        settings=settings,  # type: ignore[arg-type]
        bundle=SimpleNamespace(),  # type: ignore[arg-type]
        candidate=candidate,
        expert=SimpleNamespace(),  # type: ignore[arg-type]
        qualification=qualification,  # type: ignore[arg-type]
        integration_sha="c" * 40,
        evaluation_root=tmp_path / "evaluations",
    )
    assert result is verified
    assert observed == [(candidate.build_id, "candidate")] * 3


def test_owner_stop_routes_technical_and_currentness_boundaries_exactly(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    technical = _owner_stop_envelope(
        boundary="run",
        reason_code="authoritative_owner_canary_owned_model_runtime_required",
        row_id=None,
    )
    assert technical["state"] == "TECHNICAL_IMPLEMENTATION_REQUIRED"
    assert technical["decision_id"] is None
    assert technical["recommended_option_id"] == "implement-and-reverify"
    assert "local-ed25519-pinned-key" not in technical["bounded_option_ids"]
    operations = _owner_stop_envelope(
        boundary="activate-normal-live",
        reason_code="typed_operational_evidence_replay_contract_missing",
        row_id=None,
    )
    assert operations["state"] == "TECHNICAL_IMPLEMENTATION_REQUIRED"
    privacy = _owner_stop_envelope(
        boundary="run",
        reason_code="canary_output_privacy_owner_decision_unresolved",
        row_id=None,
    )
    assert privacy["decision_id"] is None
    assert privacy["recommended_option_id"] == "approve-owner-private-nonsynced-root"
    o04_signature = _owner_stop_envelope(
        boundary="activate-normal-live",
        reason_code="trusted_owner_o04_signature_verifier_missing",
        row_id=None,
    )
    assert str(o04_signature["decision_id"]).startswith("v111-trusted-owner-signature-")
    assert "o04-signature-boundary" not in str(o04_signature["decision_id"])
    transport = _owner_stop_envelope(
        boundary="run",
        reason_code="owner_canary_exclusive_model_transport_unresolved",
        row_id=None,
    )
    assert transport["state"] == "OWNER_DECISION_REQUIRED"
    assert str(transport["decision_id"]).startswith("v111-owner-canary-transport-")
    assert transport["recommended_option_id"] == "private-unix-domain-socket"
    assert transport["bounded_option_ids"] == [
        "private-unix-domain-socket",
        "approve-loopback-session-capability",
        "verified-in-process-mlx",
    ]

    build_id = "candidate-v111"
    candidate_root = tmp_path / "data/indexes/builds" / build_id
    candidate_root.mkdir(parents=True)
    candidate_manifest_bytes = b'{"candidate":"v111"}\n'
    source_manifest_bytes = b'{"approved_sources":[]}\n'
    (candidate_root / "manifest.json").write_bytes(candidate_manifest_bytes)
    (candidate_root / "approved-source-manifest.json").write_bytes(source_manifest_bytes)
    candidate_manifest = hashlib.sha256(candidate_manifest_bytes).hexdigest()
    source_manifest = hashlib.sha256(source_manifest_bytes).hexdigest()
    inventory = "3" * 64
    integration = "4" * 40
    monkeypatch.setattr(currentness_cli, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(
        currentness_cli,
        "require_exact_clean_head",
        lambda _root, expected: expected,
    )
    create_currentness_stop(
        [
            "--candidate-build-id",
            build_id,
            "--candidate-manifest-sha256",
            candidate_manifest,
            "--source-manifest-sha256",
            source_manifest,
            "--all60-inventory-sha256",
            inventory,
            "--as-of-date",
            "2026-08-20",
            "--integration-sha",
            integration,
            "--store-root",
            str(tmp_path / "owner-decisions"),
        ]
    )
    created = json.loads(capsys.readouterr().out)
    expected_identity = sealed_sha256(
        {
            "schema": "legalbot.all60-currentness-owner-decision-identity.v1",
            "candidate_build_id": build_id,
            "candidate_manifest_sha256": candidate_manifest,
            "candidate_source_manifest_sha256": source_manifest,
            "all60_inventory_sha256": inventory,
            "as_of_date": "2026-08-20",
            "integration_sha": integration,
        }
    )
    decision_id = f"v111-all60-currentness-{expected_identity[:20]}"
    assert created["decision_id"] == decision_id
    currentness = _owner_stop_envelope(
        boundary="run",
        reason_code="LEGAL_CURRENTNESS_OWNER_DECISION_UNRESOLVED",
        row_id=f"candidate:{build_id}",
        decision_id_hint=decision_id,
    )
    assert currentness["state"] == "OWNER_DECISION_REQUIRED"
    assert currentness["decision_id"] == decision_id
    assert currentness["decision_request_relative_path"].endswith(f"/{decision_id}/request.json")
    post_resolution = _owner_stop_envelope(
        boundary="run",
        reason_code="TRUSTED_OWNER_DECISION_SIGNATURE_VERIFIER_MISSING",
        row_id=f"candidate:{build_id}",
        decision_id_hint=decision_id,
    )
    assert post_resolution["decision_id"] != decision_id
    assert post_resolution["recommended_option_id"] == "local-ed25519-pinned-key"
    assert "owner-accepts-bound-as-of-date" not in post_resolution["bounded_option_ids"]
    assert currentness["recommended_option_id"] == "stage-official-currentness-review"


def _job(
    database: Database,
    cipher: LocalCipher,
    *,
    job_id: str,
    evaluation: bool = False,
) -> None:
    database.execute(
        """
        INSERT OR IGNORE INTO index_builds(
          id, status, path, document_count, chunk_count, vector_count,
          embedding_model, reranker_model, created_at
        ) VALUES ('candidate-v111', 'candidate', 'data/indexes/candidate-v111',
                  1, 1, 1, 'embed', 'rerank', '2026-08-20T00:00:00+00:00')
        """
    )
    database.create_job(
        job_id=job_id,
        encrypted_question=cipher.encrypt_text("Was a contract formed?"),
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={
            "task_type": "problem",
            "jurisdiction": "England and Wales",
            "as_of_date": "2026-08-20",
            "word_target": 500,
            "online_mode": "local_only",
            "upload_ids": [],
        },
        pinned_index_build_id="candidate-v111",
        evaluation_run_id="owner-development-v111-001" if evaluation else None,
        evaluation_case_id="live60-q01" if evaluation else None,
        evaluation_request_sha256="a" * 64 if evaluation else None,
        evaluation_authority=(_test_release_authority() if evaluation else None),
        trace_full_retention=evaluation,
        word_target=500,
    )


def _test_release_authority() -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": "legalbot.persisted-evaluation-job-authority.v1",
        "lane": "owner_quality_canary",
        "mode": "candidate_pinned_evaluation_release",
        "run_id": "owner-development-v111-001",
        "case_id": "live60-q01",
        "request_sha256": "a" * 64,
        "candidate_build_id": "candidate-v111",
        "authorization_seal_sha256": "c" * 64,
        "canary_manifest_seal_sha256": "d" * 64,
        "review_date": "2026-08-20",
        "attempt_number": 1,
        "input_revision_sha256": "e" * 64,
        "attempt_request_seal_sha256": "f" * 64,
        "writes_active": False,
        "release_allowed": True,
    }
    value["seal_sha256"] = sealed_sha256(value)
    return value


def _test_normal_live_authority() -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": "legalbot.owner-quality-normal-live-release-authority.v1",
        "normal_live_ready": True,
        "release_audience": "normal_live",
        "candidate_build_id": "candidate-v111",
        "readiness_generation_sha256": "3" * 64,
        "trusted_owner_o04_signature_verified": True,
        "trusted_post_run_owner_acceptance_signature_verified": True,
    }
    value["seal_sha256"] = sealed_sha256(value)
    return value


def _release_ordinary_for_test(
    database: Database, answer_id: str, release_state: str = "verified_full"
) -> None:
    """Materialise a historical pre-content-contract ordinary outbox fixture."""

    authority = _test_normal_live_authority()
    answer = database.answer(answer_id)
    assert answer is not None
    job_id = str(answer["job_id"])
    now = "2026-08-20T00:00:00+00:00"
    with database.transaction() as connection:
        connection.execute(
            "UPDATE answer_versions SET release_state=? WHERE id=?",
            (release_state, answer_id),
        )
        connection.execute(
            "UPDATE jobs SET status='complete',stage='complete',progress=1,answer_id=?,"
            "release_state=?,normal_live_authority_sha256=?,updated_at=?,last_progress_at=? "
            "WHERE id=?",
            (
                answer_id,
                release_state,
                authority["seal_sha256"],
                now,
                now,
                job_id,
            ),
        )
        connection.execute(
            "INSERT INTO release_outbox("
            "id,job_id,answer_id,release_state,release_audience,"
            "normal_live_authority_sha256,idempotency_key,status,created_at,published_at"
            ") VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                f"historical-{job_id}",
                job_id,
                answer_id,
                release_state,
                "normal_live",
                authority["seal_sha256"],
                hashlib.sha256(f"release-v1\0{job_id}".encode()).hexdigest(),
                "published",
                now,
                now,
            ),
        )


def _answer(database: Database, cipher: LocalCipher, *, job_id: str, answer_id: str) -> None:
    database.store_answer_version(
        answer_id=answer_id,
        job_id=job_id,
        version_number=1,
        version_kind="structured",
        encrypted_content=cipher.encrypt_text("Evidence-bound answer."),
        word_count=2,
        policy_version=POLICY_VERSION,
        model_version=PINNED_RUNTIME_MODEL_VERSION,
        index_build_id="candidate-v111",
    )


def test_partial_evaluation_markers_cannot_create_an_authorised_job(tmp_path: Path) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    try:
        with pytest.raises(ValueError, match="request and authority"):
            database.create_job(
                job_id="partial-evaluation",
                encrypted_question=cipher.encrypt_text("Was a contract formed?"),
                question_summary=PRIVATE_QUESTION_SUMMARY,
                request={
                    "task_type": "problem",
                    "jurisdiction": "England and Wales",
                    "as_of_date": "2026-08-20",
                    "word_target": 500,
                    "online_mode": "local_only",
                    "upload_ids": [],
                },
                pinned_index_build_id="candidate-v111",
                evaluation_run_id="owner-development-v111-001",
                evaluation_case_id="live60-q01",
                word_target=500,
            )
        assert database.job("partial-evaluation") is None
    finally:
        database.close()


def test_nonrelease_completion_authority_cannot_publish(tmp_path: Path) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    try:
        database.execute(
            """
            INSERT INTO index_builds(
              id,status,path,document_count,chunk_count,vector_count,
              embedding_model,reranker_model,created_at
            ) VALUES ('candidate-v111','candidate','data/indexes/candidate-v111',
                      1,1,1,'embed','rerank','2026-08-20T00:00:00+00:00')
            """
        )
        authority = build_completion_nonrelease_job_authority(
            run_id="completion-preflight-123456789012345678901234",
            case_id="live60-q31",
            request_sha256="1" * 64,
            candidate_build_id="candidate-v111",
            runtime_binding_sha256="2" * 64,
        )
        database.create_job(
            job_id="completion-nonrelease",
            encrypted_question=cipher.encrypt_text("Private q31 preflight"),
            question_summary=PRIVATE_QUESTION_SUMMARY,
            request={
                "task_type": "problem",
                "jurisdiction": "England and Wales",
                "as_of_date": "2026-08-20",
                "word_target": 500,
                "online_mode": "local_only",
                "upload_ids": [],
            },
            pinned_index_build_id="candidate-v111",
            evaluation_run_id="completion-preflight-123456789012345678901234",
            evaluation_case_id="live60-q31",
            evaluation_request_sha256="1" * 64,
            evaluation_authority=authority,
            word_target=500,
        )
        _answer(
            database,
            cipher,
            job_id="completion-nonrelease",
            answer_id="completion-nonrelease-answer",
        )
        # A matching self-seal is not authority: only a capability returned by
        # the current lane replay may cross the atomic release boundary.
        with pytest.raises(RuntimeError, match="was not replayed"):
            database.release_answer_once(
                "completion-nonrelease-answer",
                "verified_full",
                expected_evaluation_authority_sha256=str(authority["seal_sha256"]),
                evaluation_authority_verifier=lambda: str(authority["seal_sha256"]),
            )
        assert database.released_outbox_for_job("completion-nonrelease") is None
        assert database.answer("completion-nonrelease-answer")["release_state"] is None
    finally:
        database.close()


def test_authoritative_output_is_closed_without_trusted_privacy_resolution(
    tmp_path: Path,
) -> None:
    with pytest.raises(OwnerDecisionRequired) as lane_missing:
        require_authoritative_canary_output_root(Settings(project_root=tmp_path))
    assert lane_missing.value.reason_code == "owner_canary_review_root_lane_required"

    with pytest.raises(OwnerDecisionRequired) as unresolved:
        require_authoritative_canary_output_root(Settings(project_root=tmp_path), "development")
    assert unresolved.value.reason_code == "canary_output_privacy_owner_decision_unresolved"

    development = tmp_path.parent / f"{tmp_path.name}-development-review"
    sealed_validation = tmp_path.parent / f"{tmp_path.name}-sealed-validation-review"
    settings = Settings(
        project_root=tmp_path,
        development_review_root=development,
        sealed_validation_review_root=sealed_validation,
    )
    assert configured_authoritative_canary_output_root(
        settings, "development"
    ) == development.resolve(strict=False)
    assert configured_authoritative_canary_output_root(
        settings, "blind_holdout"
    ) == sealed_validation.resolve(strict=False)
    with pytest.raises(OwnerDecisionRequired) as untrusted:
        require_authoritative_canary_output_root(settings, "development")
    assert untrusted.value.reason_code == "trusted_canary_output_privacy_verifier_missing"
    assert not development.exists()
    assert not sealed_validation.exists()

    legacy_only = Settings(
        project_root=tmp_path,
        canary_review_root=tmp_path.parent / f"{tmp_path.name}-legacy-review",
    )
    with pytest.raises(OwnerDecisionRequired) as legacy_rejected:
        require_authoritative_canary_output_root(legacy_only, "blind_holdout")
    assert legacy_rejected.value.reason_code == "canary_output_privacy_owner_decision_unresolved"

    shared = tmp_path.parent / f"{tmp_path.name}-shared-review"
    equal_roots = Settings(
        project_root=tmp_path,
        development_review_root=shared,
        sealed_validation_review_root=shared,
    )
    with pytest.raises(OwnerDecisionRequired) as not_isolated:
        configured_authoritative_canary_output_root(equal_roots, "development")
    assert not_isolated.value.reason_code == "canary_output_lane_roots_not_isolated"

    nested_roots = Settings(
        project_root=tmp_path,
        development_review_root=shared,
        sealed_validation_review_root=shared / "sealed-validation",
    )
    with pytest.raises(OwnerDecisionRequired) as nested_not_isolated:
        configured_authoritative_canary_output_root(nested_roots, "blind_holdout")
    assert nested_not_isolated.value.reason_code == "canary_output_lane_roots_not_isolated"


def test_favorable_legacy_authorization_without_stage_a_artifacts_stops(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="no replayable Stage A run"):
        replay_authorization_stage_a(
            settings=Settings(project_root=tmp_path),
            authorization=SimpleNamespace(stage_a_run_id="legacy-stage-a-unbound"),  # type: ignore[arg-type]
            bundle=SimpleNamespace(),  # type: ignore[arg-type]
            candidate=SimpleNamespace(),  # type: ignore[arg-type]
            qualification=SimpleNamespace(),  # type: ignore[arg-type]
            expert_qualification=SimpleNamespace(),  # type: ignore[arg-type]
        )


def test_evaluation_bound_manual_resume_is_rejected_without_state_change(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    try:
        _job(database, cipher, job_id="evaluation-resume", evaluation=True)
        database.execute(
            "UPDATE jobs SET status='system_error', attempt_count=1 WHERE id=?",
            ("evaluation-resume",),
        )
        before = dict(database.job("evaluation-resume"))
        with pytest.raises(ValueError, match="sealed run controller"):
            database.resume_answer_job("evaluation-resume")
        after = dict(database.job("evaluation-resume"))
        assert after == before
        assert database.retry_decisions("job", "evaluation-resume") == []
    finally:
        database.close()


def test_atomic_release_rejects_cancelled_job_and_leaves_no_outbox(tmp_path: Path) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    try:
        _job(database, cipher, job_id="cancel-race", evaluation=True)
        _answer(database, cipher, job_id="cancel-race", answer_id="cancel-race-answer")
        database.execute(
            "UPDATE jobs SET status='running', cancel_requested=1 WHERE id='cancel-race'"
        )
        with pytest.raises(RuntimeError, match="cancelled or terminal"):
            database.release_answer_once("cancel-race-answer", "verified_full")
        assert database.released_outbox_for_job("cancel-race") is None
        assert database.answer("cancel-race-answer")["release_state"] is None
    finally:
        database.close()


def test_ordinary_release_stops_until_content_certification_exists(tmp_path: Path) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    try:
        _job(database, cipher, job_id="ordinary-direct-release")
        _answer(
            database,
            cipher,
            job_id="ordinary-direct-release",
            answer_id="ordinary-direct-answer",
        )
        with pytest.raises(RuntimeError, match="normal_live_release_content_certification_missing"):
            database.release_answer_once("ordinary-direct-answer", "verified_full")
        assert database.released_outbox_for_job("ordinary-direct-release") is None
        assert database.answer("ordinary-direct-answer")["release_state"] is None

        database.execute("UPDATE index_builds SET status='active' WHERE id='candidate-v111'")
        authority = _test_normal_live_authority()
        database.activate_normal_live_readiness_state(
            authority,
            verifier=lambda: authority,
        )

        def revoked_during_atomic_replay() -> dict[str, Any]:
            revoked = {**authority, "normal_live_ready": False}
            revoked["seal_sha256"] = sealed_sha256(revoked)
            return revoked

        with pytest.raises(RuntimeError, match="normal_live_release_content_certification_missing"):
            database.release_answer_once(
                "ordinary-direct-answer",
                "verified_full",
                normal_live_authority=authority,
                normal_live_authority_verifier=revoked_during_atomic_replay,
            )
        assert database.released_outbox_for_job("ordinary-direct-release") is None
        assert database.answer("ordinary-direct-answer")["release_state"] is None
    finally:
        database.close()


@pytest.mark.parametrize("release_state", ["verified_limited", "verified_concise"])
def test_first_live_atomic_boundary_publishes_only_verified_full(
    tmp_path: Path, release_state: str
) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    try:
        job_id = f"ordinary-{release_state}"
        answer_id = f"answer-{release_state}"
        _job(database, cipher, job_id=job_id)
        _answer(database, cipher, job_id=job_id, answer_id=answer_id)
        database.execute("UPDATE index_builds SET status='active' WHERE id='candidate-v111'")
        authority = _test_normal_live_authority()
        database.activate_normal_live_readiness_state(authority, verifier=lambda: authority)
        with pytest.raises(RuntimeError, match="exact verified_full"):
            database.release_answer_once(
                answer_id,
                release_state,
                normal_live_authority=authority,
                normal_live_authority_verifier=lambda: authority,
            )
        assert database.released_outbox_for_job(job_id) is None
        assert database.answer(answer_id)["release_state"] is None
    finally:
        database.close()


def test_terminal_quality_status_is_held_without_release_outbox(tmp_path: Path) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    try:
        _job(database, cipher, job_id="quality-held")
        _answer(database, cipher, job_id="quality-held", answer_id="quality-parent")
        runner = object.__new__(AnswerRunner)
        runner.database = database
        runner.cipher = cipher
        runner.evaluator = QualityEvaluator(database)
        runner.retriever = SimpleNamespace(active_build_id=lambda: "candidate-v111")
        answer_id, release_state = runner._release_gate_status(
            job_id="quality-held",
            request=QuestionRequest(
                question="Was a contract formed?",
                task_type=TaskType.PROBLEM,
                jurisdiction="England and Wales",
                as_of_date=date(2026, 8, 20),
                word_target=500,
            ),
            task_type=TaskType.PROBLEM,
            as_of=date(2026, 8, 20),
            parent_id="quality-parent",
        )
        assert release_state == ReleaseState.HELD_FOR_REVIEW
        assert database.answer(answer_id)["release_state"] == "held_for_review"
        assert database.released_outbox_for_job("quality-held") is None
    finally:
        database.close()


@pytest.mark.asyncio
async def test_failed_targeted_repair_never_falls_back_to_whole_draft_subset(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    settings = Settings(project_root=tmp_path, test_mode=True)
    settings.ensure_runtime_dirs()
    try:
        _job(database, cipher, job_id="repair-failure-held")
        _answer(
            database,
            cipher,
            job_id="repair-failure-held",
            answer_id="repair-failure-parent",
        )

        class Retriever:
            @staticmethod
            def active_build_id() -> str:
                return "candidate-v111"

        class RepairableEvaluator:
            @staticmethod
            def evaluate(**kwargs: Any) -> QualityReport:
                return QualityReport(
                    id=f"report-{kwargs['answer_version_id']}",
                    answer_version_id=str(kwargs["answer_version_id"]),
                    evidence_passed=True,
                    academic_score=75,
                    findings=[
                        QualityFinding(
                            gate="claim_evidence",
                            code="targeted_narrowing_required",
                            message="Only the named claim may change.",
                            severity=Severity.REPAIRABLE,
                            section_id="failed-section",
                            claim_id="failed-claim",
                        )
                    ],
                    release_state=ReleaseState.VERIFIED_LIMITED,
                )

        runner = AnswerRunner(
            settings=settings,
            database=database,
            cipher=cipher,
            retriever=Retriever(),  # type: ignore[arg-type]
            model=SimpleNamespace(),  # type: ignore[arg-type]
        )
        runner.evaluator = RepairableEvaluator()  # type: ignore[assignment]
        repair_calls = 0

        async def failed_repair(**_kwargs: Any) -> tuple[ModelDraft, bool]:
            nonlocal repair_calls
            repair_calls += 1
            raise RuntimeError("targeted repair failed")

        runner._repair_with_checkpoint = failed_repair  # type: ignore[method-assign]
        draft = StructuredDraft(
            title="Evidence-first legal analysis",
            task_type=TaskType.PROBLEM,
            jurisdiction="England and Wales",
            as_of_date=date(2026, 8, 20),
            sections=[
                StructuredSectionDraft(
                    id="failed-section",
                    heading="Analysis 1",
                    claims=[
                        StructuredClaimDraft(
                            id="failed-claim",
                            text="A proposition requiring targeted repair.",
                        )
                    ],
                ),
                StructuredSectionDraft(
                    id="unaffected-section",
                    heading="Analysis 2",
                    claims=[
                        StructuredClaimDraft(
                            id="unaffected-claim",
                            text="This section must never be filtered by fallback.",
                        )
                    ],
                ),
            ],
        )
        result = await runner._verify_and_repair(
            job_id="repair-failure-held",
            question="Was a contract formed?",
            request=QuestionRequest(
                question="Was a contract formed?",
                task_type=TaskType.PROBLEM,
                jurisdiction="England and Wales",
                as_of_date=date(2026, 8, 20),
                word_target=500,
            ),
            candidate=ModelDraft(
                raw_text="Encrypted prior draft",
                structured=draft,
                rubric_scores={},
                model_version="test-model",
                metrics={},
            ),
            evidence_by_id={},
            version_number=2,
            parent_id="repair-failure-parent",
            parent_text="Evidence-bound answer.",
        )
        assert repair_calls == 1
        assert result[1] == ReleaseState.HELD_FOR_REVIEW
        assert database.released_outbox_for_job("repair-failure-held") is None
        assert database.answer(result[0])["release_state"] == "held_for_review"
        assert (
            database.fetchone(
                "SELECT COUNT(*) AS n FROM answer_versions "
                "WHERE job_id='repair-failure-held' AND version_kind='targeted_repair'"
            )["n"]
            == 0
        )
    finally:
        database.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_code",
    [
        "current_law_verification_limited",
        "applicable_avoidance_standard_failed",
    ],
)
async def test_deterministic_currentness_and_avoidance_failures_never_call_repair_or_publish(
    tmp_path: Path,
    failure_code: str,
) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    settings = Settings(project_root=tmp_path, test_mode=True)
    settings.ensure_runtime_dirs()
    try:
        job_id = f"deterministic-{failure_code}"
        _job(database, cipher, job_id=job_id)
        _answer(database, cipher, job_id=job_id, answer_id=f"{job_id}-parent")

        class Retriever:
            @staticmethod
            def active_build_id() -> str:
                return "candidate-v111"

        class DeterministicFailureEvaluator:
            @staticmethod
            def evaluate(**kwargs: Any) -> QualityReport:
                return QualityReport(
                    id=f"report-{kwargs['answer_version_id']}",
                    answer_version_id=str(kwargs["answer_version_id"]),
                    evidence_passed=(failure_code == "applicable_avoidance_standard_failed"),
                    academic_score=89.5,
                    assessment_standards={
                        "avoidance_passed": False,
                        "quality_target_met": True,
                    },
                    findings=[
                        QualityFinding(
                            gate=(
                                "currentness"
                                if failure_code == "current_law_verification_limited"
                                else "assessment_standards"
                            ),
                            code=failure_code,
                            message="A deterministic release gate failed.",
                            severity=Severity.HARD_BLOCKER,
                            section_id="failed-section",
                            claim_id="failed-claim",
                        )
                    ],
                    release_state=ReleaseState.HELD_FOR_REVIEW,
                )

        runner = AnswerRunner(
            settings=settings,
            database=database,
            cipher=cipher,
            retriever=Retriever(),  # type: ignore[arg-type]
            model=SimpleNamespace(),  # type: ignore[arg-type]
        )
        runner.evaluator = DeterministicFailureEvaluator()  # type: ignore[assignment]
        repair_calls = 0

        async def forbidden_repair(**_kwargs: Any) -> tuple[ModelDraft, bool]:
            nonlocal repair_calls
            repair_calls += 1
            raise AssertionError("a deterministic failure cannot invoke repair")

        runner._repair_with_checkpoint = forbidden_repair  # type: ignore[method-assign]
        draft = StructuredDraft(
            title="Evidence-first legal analysis",
            task_type=TaskType.PROBLEM,
            jurisdiction="England and Wales",
            as_of_date=date(2026, 8, 20),
            sections=[
                StructuredSectionDraft(
                    id="failed-section",
                    heading="Analysis 1",
                    claims=[
                        StructuredClaimDraft(
                            id="failed-claim",
                            text="A proposition stopped by a deterministic release gate.",
                        )
                    ],
                )
            ],
        )

        answer_id, release_state = await runner._verify_and_repair(
            job_id=job_id,
            question="Was a contract formed?",
            request=QuestionRequest(
                question="Was a contract formed?",
                task_type=TaskType.PROBLEM,
                jurisdiction="England and Wales",
                as_of_date=date(2026, 8, 20),
                word_target=500,
            ),
            candidate=ModelDraft(
                raw_text="Encrypted prior draft",
                structured=draft,
                rubric_scores={},
                model_version="test-model",
                metrics={},
            ),
            evidence_by_id={},
            version_number=2,
            parent_id=f"{job_id}-parent",
            parent_text="Evidence-bound answer.",
        )

        assert repair_calls == 0
        assert release_state == ReleaseState.HELD_FOR_REVIEW
        assert database.answer(answer_id)["release_state"] == "held_for_review"
        assert database.released_outbox_for_job(job_id) is None
    finally:
        database.close()


def test_database_readiness_revocation_blocks_status_and_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    try:
        database.execute(
            """
            INSERT INTO index_builds(
              id,status,path,document_count,chunk_count,vector_count,
              embedding_model,reranker_model,created_at
            ) VALUES ('candidate-v111','active','data/indexes/candidate-v111',
                      1,1,1,'embed','rerank','2026-08-20T00:00:00+00:00')
            """
        )
        authority = _test_normal_live_authority()
        database.activate_normal_live_readiness_state(
            authority,
            verifier=lambda: authority,
        )
        pointer = SimpleNamespace(current_contract=SimpleNamespace(), seal_sha256="1" * 64)
        contract = SimpleNamespace()
        monkeypatch.setattr(
            "app.evaluation.owner_quality_normal_live_readiness._load_pointer",
            lambda _root: pointer,
        )
        monkeypatch.setattr(
            "app.evaluation.owner_quality_normal_live_readiness._load_referenced_model",
            lambda *_args, **_kwargs: (tmp_path / "contract.json", contract),
        )
        monkeypatch.setattr(
            "app.evaluation.owner_quality_normal_live_readiness._verify_exact_artifacts",
            lambda **_kwargs: SimpleNamespace(),
        )
        monkeypatch.setattr(
            "app.evaluation.owner_quality_normal_live_readiness._verify_trusted_owner_o04_signature",
            lambda _approval: None,
        )
        monkeypatch.setattr(
            "app.evaluation.owner_quality_normal_live_readiness._verify_trusted_post_run_owner_acceptance_signature",
            lambda: None,
        )
        monkeypatch.setattr(
            "app.evaluation.owner_quality_normal_live_readiness._verified_release_authority_from_artifacts",
            lambda **_kwargs: authority,
        )
        settings = Settings(
            project_root=tmp_path,
            live_profile="first_live_local_only",
            online_default="local_only",
        )
        before = owner_quality_normal_live_readiness_status(
            tmp_path,
            database=database,
            settings=settings,
        )
        assert before["normal_live_ready"] is False
        assert before["db_readiness_generation_verified"] is True
        assert before["blocking_reason_codes"] == [
            "normal_live_release_content_certification_missing"
        ]

        database.revoke_normal_live_readiness_state()

        after = owner_quality_normal_live_readiness_status(
            tmp_path,
            database=database,
            settings=settings,
        )
        assert after["normal_live_ready"] is False
        assert after["db_readiness_generation_verified"] is False
        assert after["blocking_reason_codes"] == [
            "owner_quality_normal_live_artifact_verification_failed"
        ]
        with pytest.raises(RuntimeError, match="normal_live_release_content_certification_missing"):
            owner_quality_normal_live_release_authority(
                tmp_path,
                database=database,
                settings=settings,
            )
    finally:
        database.close()


@pytest.mark.parametrize(
    ("host", "model_url"),
    (
        ("127.0.0.2", "http://127.0.0.1:8778"),
        ("127.0.0.1", "http://127.0.0.2:8778"),
        ("::1", "http://[::1]:8778"),
    ),
)
def test_first_live_authority_requires_literal_loopback_contract(
    tmp_path: Path, host: str, model_url: str
) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    try:
        settings = Settings(
            project_root=tmp_path,
            live_profile="first_live_local_only",
            online_default="local_only",
            host=host,
            model_url=model_url,
        )
        with pytest.raises(RuntimeError, match="first_live_settings_invalid"):
            _verified_release_authority_from_artifacts(
                project_root=tmp_path,
                database=database,
                settings=settings,
            )
    finally:
        database.close()


@pytest.mark.asyncio
async def test_blocked_ordinary_runner_never_calls_model_or_publishes(tmp_path: Path) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    _job(database, cipher, job_id="ordinary-queued")

    class Retriever:
        def active_build_id(self) -> str:
            return "candidate-v111"

    class Model:
        calls = 0

        async def draft(self, **_kwargs: Any) -> Any:
            self.calls += 1
            raise AssertionError("blocked ordinary job reached inference")

    model = Model()
    runner = AnswerRunner(
        settings=Settings(project_root=tmp_path),
        database=database,
        cipher=cipher,
        retriever=Retriever(),  # type: ignore[arg-type]
        model=model,  # type: ignore[arg-type]
    )
    try:
        with pytest.raises(RuntimeError, match="normal_live_release_content_certification_missing"):
            await runner._run_bound("ordinary-queued", raise_on_error=True)
        assert model.calls == 0
        assert database.answer_versions("ordinary-queued") == []
        assert database.released_outbox_for_job("ordinary-queued") is None
    finally:
        database.close()


@pytest.mark.asyncio
async def test_blocked_ordinary_runner_does_not_recover_old_outbox(tmp_path: Path) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    _job(database, cipher, job_id="ordinary-old-outbox")
    _answer(database, cipher, job_id="ordinary-old-outbox", answer_id="old-answer")
    _release_ordinary_for_test(database, "old-answer")
    database.execute(
        """
        UPDATE jobs SET status='running', stage='queued', progress=0,
          answer_id=NULL, release_state=NULL
        WHERE id='ordinary-old-outbox'
        """
    )

    class Retriever:
        def active_build_id(self) -> str:
            return "candidate-v111"

    class Model:
        calls = 0

        async def draft(self, **_kwargs: Any) -> Any:
            self.calls += 1
            raise AssertionError("blocked outbox recovery reached inference")

    model = Model()
    runner = AnswerRunner(
        settings=Settings(project_root=tmp_path),
        database=database,
        cipher=cipher,
        retriever=Retriever(),  # type: ignore[arg-type]
        model=model,  # type: ignore[arg-type]
    )
    try:
        with pytest.raises(RuntimeError, match="normal_live_release_content_certification_missing"):
            await runner._run_bound("ordinary-old-outbox", raise_on_error=True)
        row = database.job("ordinary-old-outbox")
        assert row["status"] == "running"
        assert row["answer_id"] is None
        assert model.calls == 0
    finally:
        database.close()


@pytest.mark.asyncio
async def test_diagnostic_pin_has_no_public_release_bypass(tmp_path: Path) -> None:
    from app.retrieval.diagnostic_slice import DIAGNOSTIC_SLICE_BUILD_ID

    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    _job(database, cipher, job_id="diagnostic-nonrelease")
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,document_count,chunk_count,vector_count,
          embedding_model,reranker_model,created_at
        ) VALUES (?, 'built_unscored', ?, 1, 1, 1, 'embed', 'rerank', ?)
        """,
        (
            DIAGNOSTIC_SLICE_BUILD_ID,
            f"data/indexes/{DIAGNOSTIC_SLICE_BUILD_ID}",
            "2026-08-20T00:00:00+00:00",
        ),
    )
    database.execute(
        "UPDATE jobs SET pinned_index_build_id=? WHERE id='diagnostic-nonrelease'",
        (DIAGNOSTIC_SLICE_BUILD_ID,),
    )

    class Retriever:
        def active_build_id(self) -> str:
            return DIAGNOSTIC_SLICE_BUILD_ID

    class Model:
        calls = 0

        async def draft(self, **_kwargs: Any) -> Any:
            self.calls += 1
            raise AssertionError("diagnostic bypass reached inference")

    model = Model()
    runner = AnswerRunner(
        settings=Settings(project_root=tmp_path),
        database=database,
        cipher=cipher,
        retriever=Retriever(),  # type: ignore[arg-type]
        model=model,  # type: ignore[arg-type]
    )
    try:
        with pytest.raises(RuntimeError, match="normal_live_release_content_certification_missing"):
            await runner._run_bound("diagnostic-nonrelease", raise_on_error=True)
        assert model.calls == 0
        assert database.answer_versions("diagnostic-nonrelease") == []
        assert database.released_outbox_for_job("diagnostic-nonrelease") is None
    finally:
        database.close()


@pytest.mark.asyncio
async def test_blocked_ordinary_plaintext_and_evidence_are_not_served(tmp_path: Path) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    _job(database, cipher, job_id="ordinary-released")
    _answer(database, cipher, job_id="ordinary-released", answer_id="ordinary-answer")
    _release_ordinary_for_test(database, "ordinary-answer")
    services = SimpleNamespace(
        settings=Settings(project_root=tmp_path),
        database=database,
        cipher=cipher,
    )
    previous = getattr(app.state, "services", None)
    app.state.services = services
    try:
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4311))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            answer = await client.get("/api/v1/answers/ordinary-answer")
            evidence = await client.get("/api/v1/answers/ordinary-answer/evidence")
            assert answer.status_code == 503
            assert "Evidence-bound answer" not in answer.text
            assert evidence.status_code == 503

            database.execute("UPDATE jobs SET release_state=NULL WHERE id='ordinary-released'")
            inconsistent = await client.get("/api/v1/answers/ordinary-answer")
            assert inconsistent.status_code == 409
            assert "Evidence-bound answer" not in inconsistent.text

            database.execute(
                "UPDATE jobs SET release_state='verified_full' WHERE id='ordinary-released'"
            )
            database.execute(
                """
                UPDATE jobs SET evaluation_run_id='forged-evaluation',
                  evaluation_case_id='live60-q01'
                WHERE id='ordinary-released'
                """
            )
            relabelled = await client.get(
                "/api/v1/answers/ordinary-answer",
                headers={
                    "x-owner-canary-run-id": "forged-evaluation",
                    "x-owner-canary-case-id": "live60-q01",
                },
            )
            assert relabelled.status_code == 409
            assert "Evidence-bound answer" not in relabelled.text
            database.execute(
                """
                UPDATE jobs SET evaluation_run_id=NULL, evaluation_case_id=NULL
                WHERE id='ordinary-released'
                """
            )
            database.execute("DELETE FROM release_outbox WHERE job_id='ordinary-released'")
            no_outbox = await client.get("/api/v1/answers/ordinary-answer")
            assert no_outbox.status_code == 409
            assert "Evidence-bound answer" not in no_outbox.text
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous
        database.close()


@pytest.mark.asyncio
async def test_forged_evaluation_release_self_seal_cannot_create_readable_output(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    _job(database, cipher, job_id="evaluation-read", evaluation=True)
    _answer(database, cipher, job_id="evaluation-read", answer_id="evaluation-answer")
    job = database.job("evaluation-read")
    assert job is not None
    with pytest.raises(RuntimeError, match="was not replayed"):
        database.release_answer_once(
            "evaluation-answer",
            "verified_full",
            expected_evaluation_authority_sha256=str(job["evaluation_authority_sha256"]),
            evaluation_authority_verifier=lambda: str(job["evaluation_authority_sha256"]),
        )
    assert database.released_outbox_for_job("evaluation-read") is None
    assert database.answer("evaluation-answer")["release_state"] is None
    services = SimpleNamespace(
        settings=Settings(project_root=tmp_path),
        database=database,
        cipher=cipher,
    )
    previous = getattr(app.state, "services", None)
    app.state.services = services
    try:
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4311))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            denied = await client.get("/api/v1/answers/evaluation-answer")
            still_denied = await client.get(
                "/api/v1/answers/evaluation-answer",
                headers={
                    "x-owner-canary-run-id": "owner-development-v111-001",
                    "x-owner-canary-case-id": "live60-q01",
                },
            )
        assert denied.status_code == 409
        assert still_denied.status_code == 409
        assert "Evidence-bound answer" not in denied.text
        assert "Evidence-bound answer" not in still_denied.text
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous
        database.close()


@pytest.mark.asyncio
async def test_public_resume_endpoint_cannot_bypass_evaluation_circuit(tmp_path: Path) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    _job(database, cipher, job_id="evaluation-api-resume", evaluation=True)
    database.execute(
        "UPDATE jobs SET status='system_error', attempt_count=1 WHERE id=?",
        ("evaluation-api-resume",),
    )
    before = dict(database.job("evaluation-api-resume"))
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(database=database)
    try:
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4311))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            response = await client.post("/api/v1/jobs/evaluation-api-resume/resume")
        assert response.status_code == 409
        assert dict(database.job("evaluation-api-resume")) == before
        assert database.retry_decisions("job", "evaluation-api-resume") == []
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous
        database.close()


def test_model_material_and_structural_prose_cannot_bypass_claim_gates() -> None:
    unsafe = StructuredDraft(
        title="The claimant necessarily wins",
        task_type=TaskType.PROBLEM,
        jurisdiction="Wrong jurisdiction",
        as_of_date=date(2020, 1, 1),
        sections=[
            StructuredSectionDraft(
                id="issue",
                heading="The contract is enforceable",
                claims=[
                    StructuredClaimDraft(
                        id="claim",
                        text="The contract is enforceable as a matter of law",
                        material=False,
                        evidence_ids=[],
                    )
                ],
            )
        ],
        limitations=["The limitation period definitely expired"],
    )
    bound = _bind_model_draft_context(
        ModelDraft(
            raw_text="private raw output",
            structured=unsafe,
            rubric_scores={},
            model_version=PINNED_RUNTIME_MODEL_VERSION,
        ),
        task_type=TaskType.PROBLEM,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 20),
    )
    assert bound.structured.title == "Evidence-first legal analysis"
    assert bound.structured.sections[0].heading == "Analysis 1"
    assert bound.structured.limitations == []
    assert bound.structured.sections[0].claims[0].material is True
    report = QualityEvaluator().evaluate(
        answer_version_id="answer",
        draft=bound.structured,
        rendered_text="",
        evidence_by_id={},
        word_count=8,
        word_target=500,
        rubric_scores={},
    )
    assert any(item.code == "unsupported_material_law" for item in report.findings)


def test_rubric_marker_cannot_hide_a_hard_blocker_or_duplicate() -> None:
    marker = QualityFinding(
        gate="academic_rubric",
        code="model_rubric_ignored",
        message=(
            "Model-supplied rubric values were ignored; the academic score was "
            "computed independently from observable structure and verified evidence."
        ),
        severity=Severity.INFORMATIONAL,
    )
    assert _canonical_persisted_release_findings((marker,)) == []
    with pytest.raises(ValueError, match="not canonical"):
        _canonical_persisted_release_findings((marker, marker))
    with pytest.raises(ValueError, match="not canonical"):
        _canonical_persisted_release_findings(
            (marker.model_copy(update={"severity": Severity.HARD_BLOCKER}),)
        )


def test_authoritative_gap_inventory_is_derived_and_material_open_gap_blocks(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "legalbot.sqlite3")
    database.initialize()
    cipher = _cipher()
    try:
        _job(database, cipher, job_id="gap-catalogue-anchor")
        database.store_research_gap_binding(
            gap_id="research-gap-open-001",
            fingerprint_sha256="1" * 64,
            candidate_build_id="candidate-v111",
            source_manifest_sha256="2" * 64,
            case_id="live60-q01",
            issue_id="issue-01",
            subject="contract",
            jurisdiction="England and Wales",
            as_of_date="2026-08-20",
            attempted_retrieval_sha256="3" * 64,
            materiality="material",
            detail_sha256="4" * 64,
            encrypted_detail=cipher.encrypt_text("private gap detail"),
        )
        authorization = SimpleNamespace(
            authorized_case_ids=("live60-q01",),
            candidate_build_id="candidate-v111",
        )
        qualification = SimpleNamespace(
            issue_bindings=(SimpleNamespace(case_id="live60-q01", issue_id="issue-01"),),
            candidate_source_manifest_sha256="2" * 64,
            as_of_date=date(2026, 8, 20),
        )
        case = SimpleNamespace(
            jurisdiction="England and Wales",
            subject="contract",
        )
        bundle = SimpleNamespace(
            registry=SimpleNamespace(case=lambda _case_id: case),
        )
        gaps = derive_owner_canary_gap_inventory(
            database=database,
            authorization=authorization,  # type: ignore[arg-type]
            bundle=bundle,  # type: ignore[arg-type]
            qualification=qualification,  # type: ignore[arg-type]
        )
        assert gaps["live60-q01"][0].status == "owner_decision_required"
        assert gaps["live60-q01"][0].material is True
    finally:
        database.close()


def _draft(section_two_text: str = "Unaffected proposition") -> StructuredDraft:
    return StructuredDraft(
        title="Analysis",
        task_type=TaskType.PROBLEM,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 20),
        sections=[
            StructuredSectionDraft(
                id="failed-section",
                heading="Failed issue",
                claims=[StructuredClaimDraft(id="failed-claim", text="Initial proposition")],
            ),
            StructuredSectionDraft(
                id="safe-section",
                heading="Safe issue",
                claims=[StructuredClaimDraft(id="safe-claim", text=section_two_text)],
            ),
        ],
    )


def test_targeted_repair_rejects_whole_answer_rewrite() -> None:
    prior = _draft()
    finding = QualityFinding(
        gate="claim_evidence",
        code="unsupported_material_law",
        message="Failed claim requires narrowing.",
        severity=Severity.REPAIRABLE,
        section_id="failed-section",
        claim_id="failed-claim",
    )
    legitimate = prior.model_copy(
        update={
            "sections": [
                prior.sections[0].model_copy(
                    update={
                        "claims": [
                            prior.sections[0]
                            .claims[0]
                            .model_copy(update={"text": "Narrowed proposition"})
                        ]
                    }
                ),
                prior.sections[1],
            ]
        }
    )
    verify_targeted_structured_repair(
        prior=prior,
        repaired=legitimate,
        failed_sections=("failed-section",),
        findings=(finding,),
    )
    malicious = legitimate.model_copy(
        update={"sections": [legitimate.sections[0], _draft("Rewritten safe prose").sections[1]]}
    )
    with pytest.raises(ValueError, match="unaffected section"):
        verify_targeted_structured_repair(
            prior=prior,
            repaired=malicious,
            failed_sections=("failed-section",),
            findings=(finding,),
        )


def test_same_quality_failure_with_new_claim_id_has_same_retry_fingerprint() -> None:
    first = QualityFinding(
        gate="claim_evidence",
        code="unsupported_material_law",
        message="First failed version.",
        severity=Severity.REPAIRABLE,
        section_id="failed-section",
        claim_id="model-claim-v1",
    )
    repaired = first.model_copy(
        update={"message": "Second failed version.", "claim_id": "model-claim-v2"}
    )
    assert _quality_failure_identity_sha256((first,)) == _quality_failure_identity_sha256(
        (repaired,)
    )


def _candidate_evidence() -> tuple[EvidenceSpan, _CandidateContext]:
    citation = {
        "source_type": "legislation",
        "title": "Public Act 2026",
    }
    span = EvidenceSpan(
        id="evidence-1",
        source_version_id="source-version-1",
        chunk_id="chunk-1",
        text="The verified statutory requirement applies.",
        locator="s 1",
        lane=MaterialLane.PRIMARY_AUTHORITY,
        jurisdiction="England and Wales",
        subject="contract",
        citation_data=citation,
        canonical_citation="Public Act 2026, s 1",
        currentness_status="latest_available_revised_snapshot",
        content_sha256=hashlib.sha256(b"The verified statutory requirement applies.").hexdigest(),
        index_build_id="candidate-v111",
        canonical_url="https://www.legislation.gov.uk/ukpga/2026/1/section/1",
        legal_role="statutory_text",
        unapplied_effect_count=0,
        provision_extent_status="england_and_wales_verified",
        identity_verified=True,
        currentness_verified=True,
    )
    row = {
        "source_version_id": span.source_version_id,
        "chunk_id": span.chunk_id,
        "text": span.text,
        "content_sha256": span.content_sha256,
        "locator": span.locator,
        "catalog_lane": str(span.lane),
        "catalog_jurisdiction": span.jurisdiction,
        "subject": span.subject,
        "citation_json": json.dumps(citation, sort_keys=True),
        "canonical_citation": span.canonical_citation,
        "canonical_url": span.canonical_url,
        "legal_role": span.legal_role,
        "currentness_status": span.currentness_status,
        "identity_verified": True,
        "currentness_verified": True,
        "case_currentness_reviews_json": "[]",
        "case_currentness_manifest_seals_json": "[]",
    }
    source = {
        "stable_identifier": "ukpga:2026:1",
        "jurisdiction": span.jurisdiction,
        "licence_name": "Open Government Licence v3.0",
        "identity_verified": True,
        "currentness_verified": True,
        "currentness_reviewed_as_of_date": "2026-08-20",
        "document_status": "citable",
        "lane": str(span.lane),
        "unapplied_effect_count": 0,
        "provision_extent_status": "england_and_wales_verified",
    }
    provision = {
        "section_unapplied_effect_count": 0,
        "verified_extent": "E+W",
    }
    context = _CandidateContext(
        candidate_build_id="candidate-v111",
        rows={span.chunk_id: row},
        sources={span.source_version_id: source},
        provisions={("ukpga:2026:1", "s 1"): provision},
        source_manifest_file_sha256="1" * 64,
        lance_tree_sha256="2" * 64,
        provision_sha256="3" * 64,
        current_law_as_of_date="2026-08-20",
    )
    return span, context


def test_runtime_candidate_evidence_rejects_mutable_citation_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    span, context = _candidate_evidence()
    monkeypatch.setattr(
        "app.evaluation.all60_evidence_review._candidate_context",
        lambda **_kwargs: context,
    )
    candidate = SimpleNamespace(build_id="candidate-v111")
    verify_runtime_candidate_evidence_spans(
        candidate=candidate,
        candidate_build_root=tmp_path,
        evidence=(span,),
        required_as_of_date=date(2026, 8, 20),
    )
    for changed in (
        span.model_copy(update={"citation_data": {"source_type": "case", "title": "Fake"}}),
        span.model_copy(update={"canonical_url": "https://example.invalid/fake"}),
        span.model_copy(update={"legal_role": "holding_ratio"}),
        span.model_copy(update={"subject": "criminal"}),
    ):
        with pytest.raises(ValueError, match="exact Lance/source identity"):
            verify_runtime_candidate_evidence_spans(
                candidate=candidate,
                candidate_build_root=tmp_path,
                evidence=(changed,),
                required_as_of_date=date(2026, 8, 20),
            )


def test_authoritative_citation_render_never_falls_back_to_canonical_text() -> None:
    span, _context = _candidate_evidence()
    malformed = span.model_copy(update={"citation_data": {"source_type": "legislation"}})
    with pytest.raises(ValueError):
        _deterministic_citations({malformed.id: malformed})


def test_pinned_runtime_model_version_accepts_production_shape_and_rejects_fake(
    tmp_path: Path,
) -> None:
    gateway = LoopbackModelGateway(Settings(project_root=tmp_path))
    assert (
        gateway._validated_model_version(
            {"model_version": PINNED_RUNTIME_MODEL_VERSION, "warnings": []}
        )
        == PINNED_RUNTIME_MODEL_VERSION
    )
    with pytest.raises(RuntimeError, match="pinned local identity"):
        gateway._validated_model_version({"model_version": PINNED_RUNTIME_REPO, "warnings": []})


@pytest.mark.asyncio
async def test_loopback_model_health_disables_environment_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: list[dict[str, Any]] = []

    class Response:
        status_code = 200

        @staticmethod
        def json() -> dict[str, Any]:
            return {
                "model_loaded": True,
                "model_id": PINNED_RUNTIME_REPO,
                "stub_mode": False,
            }

    class Client:
        def __init__(self, **kwargs: Any) -> None:
            observed.append(kwargs)

        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        async def get(self, _url: str) -> Response:
            return Response()

    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    monkeypatch.setattr("app.runtime_adapters.httpx.AsyncClient", Client)
    assert await LoopbackModelGateway(Settings(project_root=tmp_path)).health()
    assert observed == [{"timeout": 5, "trust_env": False, "follow_redirects": False}]


def test_clean_integration_uses_trusted_git_and_sanitized_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[list[str], dict[str, str]]] = []
    exact_calls: list[tuple[Path, str]] = []

    def run(command: list[str], **kwargs: Any) -> SimpleNamespace:
        calls.append((command, kwargs["env"]))
        return SimpleNamespace(stdout="a" * 40)

    def exact(root: Path, revision: str) -> str:
        exact_calls.append((root, revision))
        return revision

    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr("app.retrieval.retrieval_reattest.subprocess.run", run)
    monkeypatch.setattr(
        "app.governance.v111_decision_generation.require_exact_clean_head",
        exact,
    )
    assert _clean_integration_sha(tmp_path) == "a" * 40
    assert all(command[0] == "/usr/bin/git" for command, _env in calls)
    assert len(calls) == 1
    assert calls[0][1] == {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    assert exact_calls == [(tmp_path, "a" * 40)]
