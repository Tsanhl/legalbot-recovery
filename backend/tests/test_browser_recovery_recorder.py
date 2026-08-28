from __future__ import annotations

import hashlib
import json
import shutil
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from app.assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
from app.config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from app.crypto import LocalCipher
from app.db import Database, utc_iso
from app.evaluation.browser_recovery import (
    BROWSER_RECOVERY_RELATIVE_PATH,
    BrowserRecoveryConfirmations,
    first_live_recorder_settings,
    record_browser_recovery_drill,
    verify_browser_recovery_drill,
)
from app.evaluation.live30 import RunProvenance
from app.evaluation.live_suite import (
    admission_as_of_date,
    load_live_evaluation_bundle,
    sealed_sha256,
)
from app.evaluation.live_suite_execute import _reject_browser_drill_as_selected_outcome
from app.evaluation.live_suite_store import LiveSuiteRunStore
from app.orchestration.classifier import CLASSIFIER_VERSION
from app.orchestration.routing import ROUTER_VERSION
from app.quality.policy import POLICY_SHA256
from app.readiness import _browser_recovery_status
from app.retrieval.lancedb import ImmutableLanceRepository
from app.runtime_adapters import PROMPT_VERSION

ROOT = Path(__file__).resolve().parents[2]
BUILD_ID = "browser-drill-build"
RUN_ID = "live60-browser-drill"
JOB_ID = "job-browser-recovery"
ANSWER_ID = "answer-browser-recovery"


def _all_confirmed(**changes: bool) -> BrowserRecoveryConfirmations:
    values = {
        "real_browser": True,
        "page_reloaded_while_running": True,
        "same_job_recovered_after_reload": True,
        "progress_resumed": True,
        "terminal_state_visible": True,
        "no_indefinite_spinner": True,
        "exactly_one_release": True,
        "privacy_passed": True,
        "loopback_only": True,
        "zero_online_calls": True,
    }
    values.update(changes)
    return BrowserRecoveryConfirmations(**values)


def _prepared_runtime(
    tmp_path: Path,
) -> tuple[Settings, Database, str, str]:
    evaluation = tmp_path / "benchmarks" / "evaluation"
    evaluation.mkdir(parents=True)
    shutil.copytree(
        ROOT / "benchmarks/evaluation/live-evaluation-30-v1",
        evaluation / "live-evaluation-30-v1",
    )
    shutil.copytree(
        ROOT / "benchmarks/evaluation/live-evaluation-60-v1",
        evaluation / "live-evaluation-60-v1",
    )
    settings = Settings(
        project_root=tmp_path,
        host="127.0.0.1",
        model_url="http://127.0.0.1:8778",
        live_profile=FIRST_LIVE_LOCAL_ONLY_PROFILE,
        online_default="local_only",
        official_research_enabled=False,
    )
    bundle = load_live_evaluation_bundle(evaluation / "live-evaluation-60-v1")
    repository = ImmutableLanceRepository(settings.index_dir)
    repository.prepare_staging(BUILD_ID)
    repository.seal_staging(
        BUILD_ID,
        chunk_count=1,
        embedding_model="embedding-test",
        reranker_model="reranker-test",
        source_manifest_sha256="a" * 64,
    )
    repository.promote(BUILD_ID)

    database = Database(settings.database_path)
    database.initialize()
    now = utc_iso()
    database.execute(
        """
        INSERT INTO index_builds(
          id, status, path, document_count, chunk_count, vector_count,
          embedding_model, reranker_model, created_at, promoted_at
        ) VALUES (?, 'active', ?, 1, 1, 1, ?, ?, ?, ?)
        """,
        (
            BUILD_ID,
            "data/indexes/builds/browser-drill-build",
            "embedding-test",
            "reranker-test",
            now,
            now,
        ),
    )
    cipher = LocalCipher(Fernet(Fernet.generate_key()))
    store = LiveSuiteRunStore(tmp_path, cipher)
    legal_date = admission_as_of_date(datetime.now(UTC))
    store.create_run(
        run_id=RUN_ID,
        bundle=bundle,
        provenance=RunProvenance(
            git_sha="a" * 40,
            git_dirty=False,
            model_version=settings.model_id,
            index_build_id=BUILD_ID,
            prompt_version=PROMPT_VERSION,
            router_version=ROUTER_VERSION,
            classifier_version=CLASSIFIER_VERSION,
            policy_sha256=POLICY_SHA256,
            assessment_rules_sha256=OWNER_ASSESSMENT_BUNDLE.sha256,
        ),
        admitted_at=datetime.now(UTC),
    )
    database.create_job(
        job_id=JOB_ID,
        encrypted_question=cipher.encrypt_text("private drill question"),
        question_summary="private",
        request={
            "task_type": "problem",
            "jurisdiction": "England and Wales",
            "as_of_date": legal_date.isoformat(),
            "word_target": 1_000,
            "online_mode": "local_only",
            "upload_ids": [],
        },
        pinned_index_build_id=BUILD_ID,
        word_target=1_000,
    )
    database.bind_job_runtime_identity(
        JOB_ID,
        prompt_version=PROMPT_VERSION,
        router_version=ROUTER_VERSION,
        classifier_version=CLASSIFIER_VERSION,
        policy_sha256=POLICY_SHA256,
    )
    database.bind_job_assessment_bundle(JOB_ID, OWNER_ASSESSMENT_BUNDLE.sha256)
    database.store_answer_version(
        answer_id=ANSWER_ID,
        job_id=JOB_ID,
        version_number=1,
        version_kind="initial",
        encrypted_content=cipher.encrypt_text("private released answer"),
        word_count=1_000,
        policy_version="policy-v1",
        model_version=settings.model_id,
        index_build_id=BUILD_ID,
        release_state="verified_full",
        purge_after_days=None,
    )
    database.update_job(
        JOB_ID,
        status="complete",
        stage="complete",
        progress=1,
        message="Released",
        answer_id=ANSWER_ID,
        release_state="verified_full",
    )
    normal_live_authority = {
        "schema": "legalbot.owner-quality-normal-live-release-authority.v1",
        "normal_live_ready": True,
        "release_audience": "normal_live",
        "candidate_build_id": BUILD_ID,
        "readiness_generation_sha256": "3" * 64,
        "trusted_owner_o04_signature_verified": True,
        "trusted_post_run_owner_acceptance_signature_verified": True,
    }
    normal_live_authority["seal_sha256"] = sealed_sha256(normal_live_authority)
    database.activate_normal_live_readiness_state(
        normal_live_authority,
        verifier=lambda: normal_live_authority,
    )
    # Historical browser-recovery fixtures predate the now-required generic
    # ordinary content capability.  Materialise that legacy row directly so
    # recorder validation remains testable without reopening publication.
    database.execute(
        "UPDATE jobs SET normal_live_authority_sha256=? WHERE id=?",
        (normal_live_authority["seal_sha256"], JOB_ID),
    )
    now = utc_iso()
    database.execute(
        "INSERT INTO release_outbox("
        "id,job_id,answer_id,release_state,release_audience,"
        "normal_live_authority_sha256,idempotency_key,status,created_at,published_at"
        ") VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            "historical-browser-recovery-outbox",
            JOB_ID,
            ANSWER_ID,
            "verified_full",
            "normal_live",
            normal_live_authority["seal_sha256"],
            hashlib.sha256(f"release-v1\0{JOB_ID}".encode()).hexdigest(),
            "published",
            now,
            now,
        ),
    )
    job = database.fetchone("SELECT trace_id FROM jobs WHERE id=?", (JOB_ID,))
    assert job is not None
    return settings, database, str(job["trace_id"]), bundle.registry.canonical_sha256


def test_recorder_requires_every_explicit_owner_confirmation(tmp_path: Path) -> None:
    settings, database, trace_id, suite_sha = _prepared_runtime(tmp_path)
    try:
        with pytest.raises(ValueError, match="every browser-recovery"):
            record_browser_recovery_drill(
                settings,
                job_id=JOB_ID,
                trace_id=trace_id,
                run_id=RUN_ID,
                suite_canonical_sha256=suite_sha,
                as_of_date=admission_as_of_date(),
                active_build_id=BUILD_ID,
                confirmations=_all_confirmed(progress_resumed=False),
            )
        assert not (tmp_path / BROWSER_RECOVERY_RELATIVE_PATH).exists()
    finally:
        database.close()


def test_recorder_cross_checks_and_writes_readiness_compatible_gate(
    tmp_path: Path,
) -> None:
    settings, database, trace_id, suite_sha = _prepared_runtime(tmp_path)
    try:
        path = record_browser_recovery_drill(
            settings,
            job_id=JOB_ID,
            trace_id=trace_id,
            run_id=RUN_ID,
            suite_canonical_sha256=suite_sha,
            as_of_date=admission_as_of_date(),
            active_build_id=BUILD_ID,
            confirmations=_all_confirmed(),
        )
        gate = verify_browser_recovery_drill(path)
        assert gate.job_id == JOB_ID
        assert gate.trace_id == trace_id
        assert gate.online_adapter_call_count == 0
        assert gate.exactly_one_release is True
        assert gate.counts_as_live60_selected_outcome is False
        assert gate.live60_evaluation_binding_absent is True
        assert gate.live60_case_run_link_count == 0
        assert gate.route == "direct"
        assert gate.word_target == 1_000
        assert gate.model_version == settings.model_id
        assert gate.source_manifest_sha256 == "a" * 64
        assert gate.prompt_version == PROMPT_VERSION
        assert gate.router_version == ROUTER_VERSION
        assert gate.classifier_version == CLASSIFIER_VERSION
        assert gate.policy_sha256 == POLICY_SHA256
        assert gate.assessment_bundle_sha256 == OWNER_ASSESSMENT_BUNDLE.sha256
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        raw = json.loads(path.read_text(encoding="utf-8"))
        assert not ({"question", "answer", "path", "filename"} & set(raw))

        readiness = _browser_recovery_status(
            settings,
            database,
            active_build_id=BUILD_ID,
            suite_canonical_sha256=suite_sha,
            as_of_date=admission_as_of_date(),
        )
        assert readiness["passed"] is True

        with pytest.raises(ValueError, match="cannot count as a Live60 outcome"):
            _reject_browser_drill_as_selected_outcome(
                project_root=tmp_path,
                job_id=JOB_ID,
            )

        with pytest.raises(FileExistsError, match="immutable"):
            record_browser_recovery_drill(
                settings,
                job_id=JOB_ID,
                trace_id=trace_id,
                run_id=RUN_ID,
                suite_canonical_sha256=suite_sha,
                as_of_date=admission_as_of_date(),
                active_build_id=BUILD_ID,
                confirmations=_all_confirmed(),
            )

        database.execute(
            """
            UPDATE jobs SET evaluation_run_id='later-run',
              evaluation_case_id='live60-q02'
            WHERE id=?
            """,
            (JOB_ID,),
        )
        no_longer_eligible = _browser_recovery_status(
            settings,
            database,
            active_build_id=BUILD_ID,
            suite_canonical_sha256=suite_sha,
            as_of_date=admission_as_of_date(),
        )
        assert no_longer_eligible["passed"] is False
    finally:
        database.close()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("trace_id", "trace-" + "f" * 40),
        ("active_build_id", "different-build"),
        ("suite_canonical_sha256", "f" * 64),
    ),
)
def test_recorder_fails_closed_on_runtime_identity_mismatch(
    tmp_path: Path, field: str, value: str
) -> None:
    settings, database, trace_id, suite_sha = _prepared_runtime(tmp_path)
    arguments = {
        "job_id": JOB_ID,
        "trace_id": trace_id,
        "run_id": RUN_ID,
        "suite_canonical_sha256": suite_sha,
        "as_of_date": admission_as_of_date(),
        "active_build_id": BUILD_ID,
        "confirmations": _all_confirmed(),
    }
    arguments[field] = value
    try:
        with pytest.raises(RuntimeError):
            record_browser_recovery_drill(settings, **arguments)  # type: ignore[arg-type]
        assert not (tmp_path / BROWSER_RECOVERY_RELATIVE_PATH).exists()
    finally:
        database.close()


def test_recorder_rejects_non_local_runtime_profile(tmp_path: Path) -> None:
    settings, database, trace_id, suite_sha = _prepared_runtime(tmp_path)
    unsafe = Settings(
        project_root=tmp_path,
        host="127.0.0.1",
        model_url="http://127.0.0.1:8778",
        live_profile="standard",
        online_default="local_only",
        official_research_enabled=False,
    )
    try:
        with pytest.raises(RuntimeError, match="loopback-only runtime profile"):
            record_browser_recovery_drill(
                unsafe,
                job_id=JOB_ID,
                trace_id=trace_id,
                run_id=RUN_ID,
                suite_canonical_sha256=suite_sha,
                as_of_date=admission_as_of_date(),
                active_build_id=BUILD_ID,
                confirmations=_all_confirmed(),
            )
        assert not (tmp_path / BROWSER_RECOVERY_RELATIVE_PATH).exists()
    finally:
        database.close()


@pytest.mark.parametrize(
    "mutation",
    (
        "UPDATE jobs SET worker_prompt_version='stale-prompt' WHERE id=?",
        """
        UPDATE jobs SET evaluation_run_id='live60-browser-drill',
          evaluation_case_id='live60-q02', evaluation_request_sha256=?
        WHERE id=?
        """,
    ),
)
def test_recorder_rejects_stale_runtime_or_evaluation_bound_job(
    tmp_path: Path, mutation: str
) -> None:
    settings, database, trace_id, suite_sha = _prepared_runtime(tmp_path)
    if "evaluation_request_sha256" in mutation:
        database.execute(mutation, ("f" * 64, JOB_ID))
    else:
        database.execute(mutation, (JOB_ID,))
    try:
        with pytest.raises(RuntimeError, match="bindings disagree"):
            record_browser_recovery_drill(
                settings,
                job_id=JOB_ID,
                trace_id=trace_id,
                run_id=RUN_ID,
                suite_canonical_sha256=suite_sha,
                as_of_date=admission_as_of_date(),
                active_build_id=BUILD_ID,
                confirmations=_all_confirmed(),
            )
        assert not (tmp_path / BROWSER_RECOVERY_RELATIVE_PATH).exists()
    finally:
        database.close()


def test_recorder_settings_require_first_live_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LEGALBOT_LIVE_PROFILE", raising=False)
    with pytest.raises(RuntimeError, match="first_live_local_only"):
        first_live_recorder_settings(tmp_path)
    monkeypatch.setenv("LEGALBOT_LIVE_PROFILE", FIRST_LIVE_LOCAL_ONLY_PROFILE)
    settings = first_live_recorder_settings(tmp_path)
    assert settings.live_profile == FIRST_LIVE_LOCAL_ONLY_PROFILE
    assert settings.official_research_enabled is False
    assert settings.online_default == "local_only"
