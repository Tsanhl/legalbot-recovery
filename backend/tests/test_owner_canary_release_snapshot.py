from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from cryptography.fernet import Fernet

from app import db as db_module
from app.api.main import app
from app.config import Settings
from app.crypto import LocalCipher
from app.db import Database
from app.evaluation import evaluation_job_authority as job_authority_module
from app.evaluation import owner_quality_canary_runtime as canary_runtime_module
from app.evaluation import owner_quality_owned_model_runtime as owned_runtime_module
from app.evaluation.evaluation_job_authority import (
    VerifiedEvaluationReleaseAuthority,
    replay_evaluation_job_authority,
    verified_owner_canary_content_graph,
)
from app.evaluation.live_suite import sealed_sha256
from app.evaluation.owner_canary_release_snapshot import (
    OWNER_CANARY_RELEASE_SNAPSHOT_RECHECK_BUDGET_SECONDS,
    OwnerCanaryReleaseSnapshotPlan,
    build_owner_canary_release_snapshot_plan,
    capture_owner_canary_release_filesystem_snapshot,
    require_owner_canary_release_snapshot_current,
)
from app.jobs import deadline_after
from app.orchestration.object_store import EncryptedObjectStore
from app.orchestration.runner import AnswerRunner
from app.privacy import PRIVATE_QUESTION_SUMMARY
from app.types import QuestionRequest, TaskType

_RUN_ID = "owner-canary-snapshot-test"
_CASE_ID = "live60-q01"
_CANDIDATE_ID = "candidate-v111"
_REVIEW_DATE = date(2026, 8, 20)
_GIT_ENV = {
    "GIT_AUTHOR_DATE": "2026-08-20T00:00:00+00:00",
    "GIT_AUTHOR_EMAIL": "snapshot-test@example.invalid",
    "GIT_AUTHOR_NAME": "Snapshot Test",
    "GIT_COMMITTER_DATE": "2026-08-20T00:00:00+00:00",
    "GIT_COMMITTER_EMAIL": "snapshot-test@example.invalid",
    "GIT_COMMITTER_NAME": "Snapshot Test",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}


@dataclass(slots=True)
class ReleaseScenario:
    settings: Settings
    database: Database
    cipher: LocalCipher
    authority: dict[str, Any]
    capability: VerifiedEvaluationReleaseAuthority
    plan: OwnerCanaryReleaseSnapshotPlan
    project_root: Path
    review_root: Path
    tracked_file: Path
    candidate_file: Path
    model_file: Path
    workspace_file: Path
    answer_id: str
    job_id: str


def _git(project_root: Path, *arguments: str) -> None:
    subprocess.run(
        ["/usr/bin/git", "-C", str(project_root), *arguments],
        check=True,
        capture_output=True,
        env=_GIT_ENV,
        timeout=5,
    )


def _prepare_scenario(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> ReleaseScenario:
    project_root = tmp_path / "integration"
    tracked_file = project_root / "backend" / "app" / "release_input.py"
    tracked_file.parent.mkdir(parents=True)
    tracked_file.write_text("RELEASE_POLICY = 'v1.11'\n", encoding="utf-8")
    _git(project_root, "init", "--quiet")
    _git(project_root, "add", "--", "backend/app/release_input.py")
    _git(project_root, "commit", "--quiet", "-m", "snapshot fixture")

    candidate_file = project_root / "data" / "indexes" / "builds" / _CANDIDATE_ID / "index.bin"
    candidate_file.parent.mkdir(parents=True)
    candidate_file.write_bytes(b"sealed-candidate")
    model_file = project_root / "models" / "runtime" / "Qwen3.5-9B-4bit" / "weights.safetensors"
    model_file.parent.mkdir(parents=True)
    model_file.write_bytes(b"fixed-model")
    review_root = tmp_path / "owner-private-review"
    workspace_file = review_root / _REVIEW_DATE.isoformat() / _RUN_ID / "workspace.json"
    workspace_file.parent.mkdir(parents=True)
    workspace_file.write_text('{"safe":true}\n', encoding="utf-8")

    database_path = tmp_path / "database" / "legalbot.sqlite3"
    database_path.parent.mkdir()
    database = Database(database_path)
    database.initialize()
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,document_count,chunk_count,vector_count,
          embedding_model,reranker_model,created_at
        ) VALUES (?,?,?,?,?,?,?,?,?)
        """,
        (
            _CANDIDATE_ID,
            "candidate",
            "data/indexes/builds/candidate-v111",
            1,
            1,
            1,
            "embed",
            "rerank",
            "2026-08-20T00:00:00+00:00",
        ),
    )
    cipher = LocalCipher(Fernet(Fernet.generate_key()))
    payload = QuestionRequest(
        question="Was a contract formed?",
        task_type=TaskType.PROBLEM,
        jurisdiction="England and Wales",
        as_of_date=_REVIEW_DATE,
        word_target=500,
    )
    authority: dict[str, Any] = {
        "schema": "legalbot.persisted-evaluation-job-authority.v1",
        "lane": "owner_quality_canary",
        "mode": "candidate_pinned_evaluation_release",
        "run_id": _RUN_ID,
        "case_id": _CASE_ID,
        "request_sha256": "a" * 64,
        "candidate_build_id": _CANDIDATE_ID,
        "authorization_seal_sha256": "b" * 64,
        "canary_manifest_seal_sha256": "c" * 64,
        "review_date": _REVIEW_DATE.isoformat(),
        "review_lane": "development",
        "attempt_number": 1,
        "input_revision_sha256": "d" * 64,
        "attempt_request_seal_sha256": "e" * 64,
        "owned_runtime_start_attestation_sha256": "f" * 64,
        "owned_runtime_instance_sha256": "1" * 64,
        "owned_runtime_memory_policy_sha256": "2" * 64,
        "owned_runtime_before_checkpoint_sha256": "3" * 64,
        "owned_runtime_frontier_generation": 1,
        "owned_runtime_state": "active",
        "writes_active": False,
        "release_allowed": True,
    }
    authority["seal_sha256"] = sealed_sha256(authority)
    request_json = payload.model_dump(mode="json")
    request_json.pop("question")
    job_id = "snapshot-job"
    answer_id = "snapshot-answer"
    database.create_job(
        job_id=job_id,
        encrypted_question=cipher.encrypt_text(payload.question),
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request=request_json,
        pinned_index_build_id=_CANDIDATE_ID,
        evaluation_run_id=_RUN_ID,
        evaluation_case_id=_CASE_ID,
        evaluation_request_sha256="a" * 64,
        evaluation_authority=authority,
        word_target=500,
    )
    database.store_answer_version(
        answer_id=answer_id,
        job_id=job_id,
        version_number=1,
        version_kind="structured",
        encrypted_content=cipher.encrypt_text("Evidence-bound answer."),
        word_count=2,
        policy_version="v1.11-test",
        model_version="fixed-model-test",
        index_build_id=_CANDIDATE_ID,
    )
    objects = EncryptedObjectStore(project_root / "data" / "runtime_objects", database, cipher)
    evidence_object_key = objects.put_json(
        namespace="evidence_packs",
        value={"private": "frozen evidence"},
        metadata={"purpose": "snapshot fixture"},
        ttl_days=None,
    )
    database.freeze_evidence_pack(
        pack_id="snapshot-pack",
        job_id=job_id,
        section_key="whole-answer",
        digest="4" * 64,
        index_build_id=_CANDIDATE_ID,
        source_ids=[],
        encrypted_payload=b"",
        object_key=evidence_object_key,
    )
    draft_object_key = objects.put_json(
        namespace="draft_checkpoints",
        value={"private": "model checkpoint"},
        metadata={"purpose": "snapshot fixture"},
        ttl_days=None,
    )
    database.store_stage_attempt(
        attempt_id="snapshot-draft-attempt",
        job_id=job_id,
        stage_key="draft",
        section_key="whole-answer",
        attempt_number=1,
        status="complete",
        encrypted_output=None,
        output_object_key=draft_object_key,
        input_digest="5" * 64,
        evidence_pack_digest="4" * 64,
    )
    database.execute(
        """
        UPDATE jobs SET status='running',stage='verifying',attempt_count=1,
          lease_owner='owner-release-snapshot-test',lease_expires_at=?,heartbeat_at=?,
          workflow_deadline_at=?,stage_deadline_at=? WHERE id=?
        """,
        (
            deadline_after(3_600),
            datetime.now().astimezone().isoformat(),
            deadline_after(3_600),
            deadline_after(300),
            job_id,
        ),
    )

    settings = Settings(
        project_root=project_root,
        development_review_root=review_root,
        sealed_validation_review_root=tmp_path / "sealed-validation-review",
        test_mode=True,
    )
    fake_binding = SimpleNamespace(
        lane="development",
        run_id=_RUN_ID,
        case_id=_CASE_ID,
        as_of_date=_REVIEW_DATE,
        request_sha256="a" * 64,
        candidate_build_id=_CANDIDATE_ID,
        authorization_seal_sha256="b" * 64,
        context=SimpleNamespace(manifest=SimpleNamespace(seal_sha256="c" * 64)),
        owned_runtime_start_attestation_sha256="f" * 64,
        owned_runtime_instance_sha256="1" * 64,
        owned_runtime_memory_policy_sha256="2" * 64,
        owned_runtime_before_checkpoint_sha256="3" * 64,
        owned_runtime_frontier_generation=1,
        owned_runtime_state="active",
    )
    monkeypatch.setattr(
        job_authority_module,
        "require_authoritative_canary_output_root",
        lambda _settings, _lane: review_root,
    )
    monkeypatch.setattr(
        job_authority_module,
        "validate_owner_canary_api_admission",
        lambda **_kwargs: fake_binding,
    )
    answer_sha256 = hashlib.sha256(b"Evidence-bound answer.").hexdigest()
    monkeypatch.setattr(
        canary_runtime_module,
        "_verify_owner_canary_runtime_semantic_core",
        lambda **_kwargs: SimpleNamespace(
            runtime_report=SimpleNamespace(
                answer_sha256=answer_sha256,
                runtime_release_state="verified_full",
                word_count=2,
            ),
            attempt_result=SimpleNamespace(
                ai_review=SimpleNamespace(
                    material_claim_count=1,
                    invocation_ids=("ai-review-invocation-1",),
                    claims=(SimpleNamespace(evidence_span_ids=("evidence-1",)),),
                ),
                standards_report=SimpleNamespace(avoidance_passed=True),
                evidence_bundle=SimpleNamespace(evidence_span_ids=("evidence-1",)),
            ),
        ),
    )
    row = database.job(job_id)
    assert row is not None
    capability = replay_evaluation_job_authority(
        settings=settings,
        database=database,
        cipher=cipher,
        row=row,
        payload=payload,
        answer_id=answer_id,
        owner_canary_publication_phase="pre_release",
    )
    plan = build_owner_canary_release_snapshot_plan(
        settings=settings,
        private_review_root=review_root,
        review_date=_REVIEW_DATE,
        run_id=_RUN_ID,
        candidate_build_id=_CANDIDATE_ID,
    )
    return ReleaseScenario(
        settings=settings,
        database=database,
        cipher=cipher,
        authority=authority,
        capability=capability,
        plan=plan,
        project_root=project_root,
        review_root=review_root,
        tracked_file=tracked_file,
        candidate_file=candidate_file,
        model_file=model_file,
        workspace_file=workspace_file,
        answer_id=answer_id,
        job_id=job_id,
    )


def _disable_unrelated_owned_runtime_guards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        Database,
        "_verify_owner_canary_runtime_release_frontier",
        staticmethod(lambda _connection, _authority: None),
    )
    monkeypatch.setattr(
        owned_runtime_module,
        "verify_owner_canary_runtime_atomic_release",
        lambda _authority: None,
    )


def _assert_no_public_state(scenario: ReleaseScenario) -> None:
    assert scenario.database.released_outbox_for_job(scenario.job_id) is None
    answer = scenario.database.answer(scenario.answer_id)
    job = scenario.database.job(scenario.job_id)
    assert answer is not None and answer["release_state"] is None
    assert job is not None
    assert job["answer_id"] is None
    assert job["release_state"] is None
    assert job["status"] == "running"
    assert job["stage"] == "verifying"


def test_current_snapshot_allows_private_release_and_never_enters_caller_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _prepare_scenario(tmp_path, monkeypatch)
    try:
        _disable_unrelated_owned_runtime_guards(monkeypatch)
        persisted = str(scenario.database.job(scenario.job_id)["evaluation_authority_json"])
        persisted_value = json.loads(persisted)
        assert not any("filesystem" in key or "raw_path" in key for key in persisted_value)
        assert str(scenario.project_root) not in persisted
        assert str(scenario.review_root) not in persisted

        scenario.database.release_answer_once(
            scenario.answer_id,
            "verified_full",
            expected_evaluation_authority_sha256=str(scenario.authority["seal_sha256"]),
            evaluation_authority_verifier=lambda: scenario.capability,
        )
        outbox = scenario.database.released_outbox_for_job(scenario.job_id)
        assert outbox is not None
        assert outbox["release_audience"] == "owner_evaluation"
        assert scenario.database.answer(scenario.answer_id)["release_state"] == "verified_full"
    finally:
        scenario.database.close()


def test_expired_direct_execution_fence_rejects_before_owner_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _prepare_scenario(tmp_path, monkeypatch)
    try:
        _disable_unrelated_owned_runtime_guards(monkeypatch)
        scenario.database.execute(
            "UPDATE jobs SET workflow_deadline_at=? WHERE id=?",
            (deadline_after(-1), scenario.job_id),
        )

        with pytest.raises(RuntimeError, match="owner_canary_job_execution_fence_expired"):
            scenario.database.release_answer_once(
                scenario.answer_id,
                "verified_full",
                expected_evaluation_authority_sha256=str(scenario.authority["seal_sha256"]),
                evaluation_authority_verifier=lambda: scenario.capability,
            )

        _assert_no_public_state(scenario)
    finally:
        scenario.database.close()


def test_stale_content_graph_rejects_db_mutation_before_any_public_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _prepare_scenario(tmp_path, monkeypatch)
    try:
        _disable_unrelated_owned_runtime_guards(monkeypatch)
        scenario.database.execute(
            "UPDATE answer_versions SET encrypted_content=? WHERE id=?",
            (scenario.cipher.encrypt_text("Mutated private answer."), scenario.answer_id),
        )
        with pytest.raises(RuntimeError, match="owner_canary_content_graph_changed_before_release"):
            scenario.database.release_answer_once(
                scenario.answer_id,
                "verified_full",
                expected_evaluation_authority_sha256=str(scenario.authority["seal_sha256"]),
                evaluation_authority_verifier=lambda: scenario.capability,
            )
        _assert_no_public_state(scenario)
    finally:
        scenario.database.close()


def test_content_capability_and_outbox_never_contain_plaintext_and_binding_is_immutable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _prepare_scenario(tmp_path, monkeypatch)
    try:
        _disable_unrelated_owned_runtime_guards(monkeypatch)
        graph = verified_owner_canary_content_graph(scenario.capability)
        assert repr(graph) == "<VerifiedOwnerCanaryContentGraph>"
        assert "Was a contract formed?" not in repr(graph)
        assert "Evidence-bound answer." not in repr(graph)

        scenario.database.release_answer_once(
            scenario.answer_id,
            "verified_full",
            expected_evaluation_authority_sha256=str(scenario.authority["seal_sha256"]),
            evaluation_authority_verifier=lambda: scenario.capability,
        )
        outbox = scenario.database.released_outbox_for_job(scenario.job_id)
        assert outbox is not None
        serialized = json.dumps(dict(outbox), sort_keys=True)
        assert "Was a contract formed?" not in serialized
        assert "Evidence-bound answer." not in serialized
        assert outbox["owner_canary_content_graph_sha256"] == graph.graph_sha256
        assert outbox["answer_sha256"] == graph.answer_sha256
        with pytest.raises(sqlite3.IntegrityError, match="release outbox is immutable"):
            scenario.database.execute(
                "UPDATE release_outbox SET answer_sha256=? WHERE job_id=?",
                ("0" * 64, scenario.job_id),
            )
        with pytest.raises(sqlite3.IntegrityError, match="release outbox is immutable"):
            scenario.database.execute(
                "DELETE FROM release_outbox WHERE job_id=?", (scenario.job_id,)
            )
        scenario.database.execute("PRAGMA recursive_triggers=OFF")
        conflict_values = {
            "id": str(outbox["id"]),
            "job_id": str(outbox["job_id"]),
            "answer_id": str(outbox["answer_id"]),
            "idempotency_key": str(outbox["idempotency_key"]),
        }
        for conflict_column in conflict_values:
            values = {
                "id": "alternate-release-id",
                "job_id": "alternate-job-id",
                "answer_id": "alternate-answer-id",
                "idempotency_key": "alternate-idempotency-key",
            }
            values[conflict_column] = conflict_values[conflict_column]
            with (
                pytest.raises(
                    sqlite3.IntegrityError,
                    match="bound release outbox identity cannot be replaced",
                ),
                scenario.database.transaction() as connection,
            ):
                connection.execute(
                    """
                    INSERT OR REPLACE INTO release_outbox(
                      id,job_id,answer_id,release_state,release_audience,
                      evaluation_authority_sha256,normal_live_authority_sha256,
                      owner_canary_content_graph_sha256,answer_sha256,
                      idempotency_key,status,created_at,published_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?, 'published',?,?)
                    """,
                    (
                        values["id"],
                        values["job_id"],
                        values["answer_id"],
                        "verified_full",
                        "owner_evaluation",
                        scenario.authority["seal_sha256"],
                        None,
                        graph.graph_sha256,
                        graph.answer_sha256,
                        values["idempotency_key"],
                        "2026-08-20T00:00:00+00:00",
                        "2026-08-20T00:00:00+00:00",
                    ),
                )
    finally:
        scenario.database.close()


@pytest.mark.parametrize(
    "mutation_kind",
    [
        "candidate_content",
        "tracked_input",
        "workspace_addition",
        "untracked_import_shadow",
        "active_pointer",
        "runtime_object",
        "symlink",
    ],
)
def test_release_snapshot_mutation_rejects_before_any_public_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation_kind: str,
) -> None:
    scenario = _prepare_scenario(tmp_path, monkeypatch)
    try:
        _disable_unrelated_owned_runtime_guards(monkeypatch)

        def stale_capability_after_mutation() -> VerifiedEvaluationReleaseAuthority:
            if mutation_kind == "candidate_content":
                scenario.candidate_file.write_bytes(b"changed-candidate")
            elif mutation_kind == "tracked_input":
                scenario.tracked_file.write_text("RELEASE_POLICY = 'changed'\n", encoding="utf-8")
            elif mutation_kind == "workspace_addition":
                (scenario.workspace_file.parent / "late-addition.json").write_text(
                    "{}\n", encoding="utf-8"
                )
            elif mutation_kind == "untracked_import_shadow":
                (scenario.tracked_file.parent / "release_shadow.py").write_text(
                    "RELEASE_POLICY = 'shadow'\n", encoding="utf-8"
                )
            elif mutation_kind == "active_pointer":
                (scenario.project_root / "data" / "indexes" / "ACTIVE.json").write_text(
                    json.dumps({"build_id": _CANDIDATE_ID}),
                    encoding="utf-8",
                )
            elif mutation_kind == "runtime_object":
                object_row = scenario.database.fetchone(
                    "SELECT relative_path FROM runtime_objects ORDER BY object_key LIMIT 1"
                )
                assert object_row is not None
                object_path = (
                    scenario.project_root
                    / "data"
                    / "runtime_objects"
                    / str(object_row["relative_path"])
                )
                object_path.write_bytes(b"replaced encrypted checkpoint bytes")
            else:
                target = tmp_path / "outside-regular-file"
                target.write_bytes(b"not-the-candidate")
                scenario.candidate_file.unlink()
                scenario.candidate_file.symlink_to(target)
            return scenario.capability

        with pytest.raises(
            RuntimeError,
            match=r"owner_canary_release_snapshot_(?:not_current|path_type_invalid)",
        ):
            scenario.database.release_answer_once(
                scenario.answer_id,
                "verified_full",
                expected_evaluation_authority_sha256=str(scenario.authority["seal_sha256"]),
                evaluation_authority_verifier=stale_capability_after_mutation,
            )
        _assert_no_public_state(scenario)
    finally:
        scenario.database.close()


def test_caller_forged_snapshot_capability_cannot_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _prepare_scenario(tmp_path, monkeypatch)
    try:
        _disable_unrelated_owned_runtime_guards(monkeypatch)

        class CallerForgedCapability:
            seal_sha256 = scenario.authority["seal_sha256"]
            snapshot_current = True

        with pytest.raises(RuntimeError, match="evaluation release authority was not replayed"):
            scenario.database.release_answer_once(
                scenario.answer_id,
                "verified_full",
                expected_evaluation_authority_sha256=str(scenario.authority["seal_sha256"]),
                evaluation_authority_verifier=CallerForgedCapability,
            )
        _assert_no_public_state(scenario)
    finally:
        scenario.database.close()


def test_metadata_recheck_reports_bounded_latency_and_exact_file_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _prepare_scenario(tmp_path, monkeypatch)
    try:
        snapshot = capture_owner_canary_release_filesystem_snapshot(scenario.plan)
        result = require_owner_canary_release_snapshot_current(snapshot)
        assert snapshot.regular_file_count == 4
        assert result.regular_file_count == snapshot.regular_file_count
        assert result.directory_count == snapshot.directory_count == 6
        assert result.elapsed_seconds >= 0
        assert result.elapsed_seconds < OWNER_CANARY_RELEASE_SNAPSHOT_RECHECK_BUDGET_SECONDS
    finally:
        scenario.database.close()


def test_pre_and_post_replay_snapshots_must_be_identical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _prepare_scenario(tmp_path, monkeypatch)
    try:
        row = scenario.database.job(scenario.job_id)
        assert row is not None
        payload_dict = json.loads(str(row["request_json"]))
        payload_dict["question"] = scenario.cipher.decrypt_text(bytes(row["encrypted_question"]))
        payload = QuestionRequest.model_validate(payload_dict)
        original_validate = job_authority_module.validate_owner_canary_api_admission

        def mutate_during_replay(**kwargs: Any) -> object:
            scenario.model_file.write_bytes(b"model-mutated-during-replay")
            return original_validate(**kwargs)

        monkeypatch.setattr(
            job_authority_module,
            "validate_owner_canary_api_admission",
            mutate_during_replay,
        )
        with pytest.raises(
            RuntimeError, match="owner_canary_release_snapshot_changed_during_replay"
        ):
            replay_evaluation_job_authority(
                settings=scenario.settings,
                database=scenario.database,
                cipher=scenario.cipher,
                row=row,
                payload=payload,
            )
        _assert_no_public_state(scenario)
    finally:
        scenario.database.close()


def test_primary_sqlite_connection_rejects_swap_during_connect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "database" / "catalog.sqlite3"
    replacement_path = tmp_path / "replacement.sqlite3"
    database_path.parent.mkdir()
    real_connect = sqlite3.connect
    for path, marker in ((database_path, "configured"), (replacement_path, "replacement")):
        connection = real_connect(path)
        connection.execute("CREATE TABLE marker(value TEXT NOT NULL)")
        connection.execute("INSERT INTO marker(value) VALUES (?)", (marker,))
        connection.commit()
        connection.close()
        path.chmod(0o600)
    configured_saved = tmp_path / "configured-saved.sqlite3"
    attacked = False

    def swap_only_while_connecting(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        nonlocal attacked
        target = Path(args[0]) if args else Path(str(kwargs.get("database")))
        if not attacked and target == database_path:
            attacked = True
            database_path.rename(configured_saved)
            replacement_path.rename(database_path)
            try:
                opened = real_connect(*args, **kwargs)
            finally:
                database_path.rename(replacement_path)
                configured_saved.rename(database_path)
            return opened
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(db_module.sqlite3, "connect", swap_only_while_connecting)
    with pytest.raises(RuntimeError, match="sqlite_primary_connection_identity_invalid"):
        Database(database_path)
    assert attacked
    connection = real_connect(database_path)
    try:
        assert connection.execute("SELECT value FROM marker").fetchone()[0] == "configured"
    finally:
        connection.close()


def test_primary_path_swap_blocks_direct_access_and_close_cleans_descriptors(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "database" / "catalog.sqlite3"
    baseline_descriptors = set(db_module._process_file_descriptors())
    database = Database(database_path)
    database.initialize()
    database.execute("CREATE TABLE path_swap_probe(value TEXT NOT NULL)")
    database.execute("INSERT INTO path_swap_probe(value) VALUES ('before')")
    held_path = database_path.with_name("catalog-held.sqlite3")
    database_path.rename(held_path)
    replacement_descriptor = os.open(
        database_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    os.close(replacement_descriptor)
    try:
        with pytest.raises(RuntimeError, match="identity_changed"):
            database.fetchone("SELECT value FROM path_swap_probe")
        with pytest.raises(RuntimeError, match="identity_changed"):
            database.execute("INSERT INTO path_swap_probe(value) VALUES ('after')")
        with pytest.raises(RuntimeError, match="identity_changed"):
            database.close()
        # Cleanup after an integrity failure is complete and idempotent.
        database.close()
    finally:
        if database_path.exists():
            database_path.unlink()
        held_path.rename(database_path)
        database.close()
    assert set(db_module._process_file_descriptors()) == baseline_descriptors
    connection = sqlite3.connect(database_path)
    try:
        values = connection.execute("SELECT value FROM path_swap_probe").fetchall()
        assert values == [("before",)]
    finally:
        connection.close()


def test_primary_and_detached_snapshot_views_keep_exact_identity_guards(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "database" / "catalog.sqlite3")
    try:
        database.initialize()
        database.execute("CREATE TABLE snapshot_view_probe(value TEXT NOT NULL)")
        database.execute("INSERT INTO snapshot_view_probe(value) VALUES ('bound')")
        with database.read_snapshot() as connection:
            view = database.snapshot_view(connection)
            assert view.fetchone("SELECT value FROM snapshot_view_probe")["value"] == "bound"
            assert len(view.fetchall("SELECT value FROM snapshot_view_probe")) == 1
        with database.detached_read_snapshot() as (view, _connection):
            assert view.fetchone("SELECT value FROM snapshot_view_probe")["value"] == "bound"
            assert len(view.fetchall("SELECT value FROM snapshot_view_probe")) == 1
    finally:
        database.close()


def test_two_database_instances_share_wal_without_sharing_identity_ownership(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "database" / "catalog.sqlite3"
    baseline_descriptors = set(db_module._process_file_descriptors())
    first = Database(database_path)
    first.initialize()
    first.execute("CREATE TABLE two_connection_probe(value INTEGER NOT NULL)")
    first.execute("INSERT INTO two_connection_probe(value) VALUES (1)")
    second = Database(database_path)
    try:
        second.initialize()
        with first.detached_read_snapshot() as (frozen, _connection):
            assert frozen.fetchone("SELECT value FROM two_connection_probe")["value"] == 1
            second.execute("UPDATE two_connection_probe SET value=2")
            assert frozen.fetchone("SELECT value FROM two_connection_probe")["value"] == 1
        second.close()
        second.close()
        assert first.fetchone("SELECT value FROM two_connection_probe")["value"] == 2
        assert Path(f"{database_path}-wal").exists()
        assert Path(f"{database_path}-shm").exists()
    finally:
        second.close()
        first.close()
    assert set(db_module._process_file_descriptors()) == baseline_descriptors
    assert not Path(f"{database_path}-wal").exists()
    assert not Path(f"{database_path}-shm").exists()


def test_database_parent_accepts_only_safe_mode_tightening_and_nlink_changes(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "data"
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)
    database = Database(parent / "catalog.sqlite3")
    try:
        database.initialize()
        parent.chmod(0o700)
        database.fetchone("SELECT COUNT(*) AS count FROM sqlite_schema")
        child = parent / "legitimate-runtime-directory"
        child.mkdir(mode=0o700)
        database.fetchone("SELECT COUNT(*) AS count FROM sqlite_schema")
        child.rmdir()
        database.fetchone("SELECT COUNT(*) AS count FROM sqlite_schema")
        parent.chmod(0o770)
        with pytest.raises(RuntimeError, match="database_snapshot_parent_identity_changed"):
            database.fetchone("SELECT COUNT(*) AS count FROM sqlite_schema")
        parent.chmod(0o700)
        database.fetchone("SELECT COUNT(*) AS count FROM sqlite_schema")
    finally:
        parent.chmod(0o700)
        database.close()

    unsafe_parent = tmp_path / "unsafe-data"
    unsafe_parent.mkdir(mode=0o770)
    unsafe_parent.chmod(0o770)
    with pytest.raises(RuntimeError, match="database_snapshot_parent_permissions_invalid"):
        Database(unsafe_parent / "catalog.sqlite3")


def test_detached_snapshot_binds_shared_shm_and_failed_close_is_idempotent(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "database" / "catalog.sqlite3"
    baseline_descriptors = set(db_module._process_file_descriptors())
    database = Database(database_path)
    database.initialize()
    database.execute("CREATE TABLE shm_swap_probe(value TEXT NOT NULL)")
    shm_path = Path(f"{database_path}-shm")
    held_shm_path = Path(f"{database_path}-shm-held")
    shm_path.rename(held_shm_path)
    replacement_descriptor = os.open(
        shm_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    os.close(replacement_descriptor)
    try:
        with (
            pytest.raises(RuntimeError, match="sqlite_detached_connection_identity_changed"),
            database.detached_read_snapshot(),
        ):
            raise AssertionError("replaced shared-memory path entered a read snapshot")
        with pytest.raises(RuntimeError, match="identity_changed"):
            database.close()
        database.close()
    finally:
        if shm_path.exists():
            shm_path.unlink()
        if held_shm_path.exists():
            held_shm_path.rename(shm_path)
        database.close()
    assert set(db_module._process_file_descriptors()) == baseline_descriptors


def test_assume_unchanged_cannot_hide_modified_release_verifier(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "exact-clean"
    verifier = project_root / "backend" / "app" / "release_verifier.py"
    verifier.parent.mkdir(parents=True)
    verifier.write_text("RELEASE_CHECK = 'trusted'\n", encoding="utf-8")
    _git(project_root, "init", "--quiet")
    _git(project_root, "add", "--", "backend/app/release_verifier.py")
    _git(project_root, "commit", "--quiet", "-m", "exact clean fixture")
    integration_sha = subprocess.run(
        ["/usr/bin/git", "-C", str(project_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        env=_GIT_ENV,
        timeout=5,
    ).stdout.strip()
    _git(
        project_root,
        "update-index",
        "--assume-unchanged",
        "backend/app/release_verifier.py",
    )
    verifier.write_text("RELEASE_CHECK = 'forged!'\n", encoding="utf-8")
    with pytest.raises(ValueError, match="integration differs from authorization"):
        canary_runtime_module._require_clean_authorized_integration(
            settings=Settings(project_root=project_root),
            authorization=SimpleNamespace(integration_sha=integration_sha),
        )


def test_inert_same_name_outbox_trigger_is_rejected_by_schema_contract(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "catalog.sqlite3")
    try:
        database.initialize()
        database.execute("DROP TRIGGER trg_release_outbox_owner_binding_no_update")
        database.execute(
            """
            CREATE TRIGGER trg_release_outbox_owner_binding_no_update
            BEFORE UPDATE ON release_outbox
            BEGIN SELECT 1; END
            """
        )
        with pytest.raises(RuntimeError, match="release_outbox_schema_contract_invalid"):
            database.initialize()
    finally:
        database.close()


def test_pre_release_phase_mutation_and_uncertified_lanes_never_write_public_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _prepare_scenario(tmp_path / "owner", monkeypatch)
    try:
        _disable_unrelated_owned_runtime_guards(monkeypatch)
        scenario.database.execute(
            "UPDATE jobs SET status='queued',stage='queued' WHERE id=?",
            (scenario.job_id,),
        )
        with pytest.raises(RuntimeError, match="atomic release pre-release phase changed"):
            scenario.database.release_answer_once(
                scenario.answer_id,
                "verified_full",
                expected_evaluation_authority_sha256=str(scenario.authority["seal_sha256"]),
                evaluation_authority_verifier=lambda: scenario.capability,
            )
        assert scenario.database.released_outbox_for_job(scenario.job_id) is None
        assert scenario.database.answer(scenario.answer_id)["release_state"] is None
    finally:
        scenario.database.close()

    ordinary = Database(tmp_path / "ordinary" / "catalog.sqlite3")
    ordinary_cipher = LocalCipher(Fernet(Fernet.generate_key()))
    try:
        ordinary.initialize()
        ordinary.execute(
            """
            INSERT INTO index_builds(
              id,status,path,document_count,chunk_count,vector_count,
              embedding_model,reranker_model,created_at
            ) VALUES ('missing-certification','active','indexes/missing',0,0,0,
                      'embed','rerank','2026-08-20T00:00:00+00:00')
            """
        )
        ordinary.create_job(
            job_id="ordinary-job",
            encrypted_question=ordinary_cipher.encrypt_text("Private ordinary question"),
            question_summary=PRIVATE_QUESTION_SUMMARY,
            request={"word_target": 500},
            pinned_index_build_id="missing-certification",
        )
        ordinary.execute(
            "UPDATE jobs SET status='running',stage='verifying' WHERE id='ordinary-job'"
        )
        ordinary.store_answer_version(
            answer_id="ordinary-answer",
            job_id="ordinary-job",
            version_number=1,
            version_kind="structured",
            encrypted_content=ordinary_cipher.encrypt_text("Uncertified ordinary answer"),
            word_count=3,
            policy_version="test",
            model_version="test",
            index_build_id="missing-certification",
        )
        with pytest.raises(
            RuntimeError,
            match="normal_live_release_content_certification_missing",
        ):
            ordinary.release_answer_once("ordinary-answer", "verified_full")
        assert ordinary.released_outbox_for_job("ordinary-job") is None
        assert ordinary.answer("ordinary-answer")["release_state"] is None
    finally:
        ordinary.close()


def test_superseded_evaluation_lane_release_is_an_explicit_no_write_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _prepare_scenario(tmp_path, monkeypatch)
    try:
        _disable_unrelated_owned_runtime_guards(monkeypatch)
        legacy_authority = dict(scenario.authority)
        legacy_authority["lane"] = "live60_evaluation_v2"
        scenario.database.execute(
            "UPDATE jobs SET evaluation_authority_json=? WHERE id=?",
            (json.dumps(legacy_authority, sort_keys=True), scenario.job_id),
        )
        with pytest.raises(
            RuntimeError,
            match="superseded_evaluation_release_content_certification_missing",
        ):
            scenario.database.release_answer_once(
                scenario.answer_id,
                "verified_full",
                expected_evaluation_authority_sha256=str(scenario.authority["seal_sha256"]),
                evaluation_authority_verifier=lambda: scenario.capability,
            )
        _assert_no_public_state(scenario)
    finally:
        scenario.database.close()


@pytest.mark.asyncio
async def test_recovered_superseded_evaluation_job_stops_before_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _prepare_scenario(tmp_path, monkeypatch)

    class ModelSentinel:
        calls = 0

        async def draft(self, **_kwargs: Any) -> None:
            self.calls += 1
            raise AssertionError("superseded recovered job reached the model")

    model = ModelSentinel()
    try:
        legacy_authority = dict(scenario.authority)
        legacy_authority["lane"] = "live60_evaluation_v2"
        scenario.database.execute(
            "UPDATE jobs SET evaluation_authority_json=? WHERE id=?",
            (json.dumps(legacy_authority, sort_keys=True), scenario.job_id),
        )
        runner = AnswerRunner(
            settings=scenario.settings,
            database=scenario.database,
            cipher=scenario.cipher,
            retriever=SimpleNamespace(active_build_id=lambda: _CANDIDATE_ID),  # type: ignore[arg-type]
            model=model,  # type: ignore[arg-type]
        )
        with pytest.raises(
            RuntimeError,
            match="superseded_evaluation_release_content_certification_missing",
        ):
            await runner._run_bound(scenario.job_id, raise_on_error=True)
        assert model.calls == 0
        assert scenario.database.released_outbox_for_job(scenario.job_id) is None
    finally:
        scenario.database.close()


def test_supplied_snapshot_connection_controls_all_admission_database_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _prepare_scenario(tmp_path, monkeypatch)
    try:
        row = scenario.database.job(scenario.job_id)
        assert row is not None
        payload_value = json.loads(str(row["request_json"]))
        payload_value["question"] = scenario.cipher.decrypt_text(bytes(row["encrypted_question"]))
        payload = QuestionRequest.model_validate(payload_value)
        frozen_validate = job_authority_module.validate_owner_canary_api_admission

        def mutate_primary_during_admission(**kwargs: Any) -> object:
            replay_database = kwargs["database"]
            scenario.database.execute(
                "UPDATE jobs SET route='sectioned' WHERE id=?",
                (scenario.job_id,),
            )
            frozen = replay_database.job(scenario.job_id)
            assert frozen is not None and frozen["route"] == "direct"
            return frozen_validate(**kwargs)

        monkeypatch.setattr(
            job_authority_module,
            "validate_owner_canary_api_admission",
            mutate_primary_during_admission,
        )
        with scenario.database.detached_read_snapshot() as (_view, connection):
            frozen_row = connection.execute(
                "SELECT * FROM jobs WHERE id=?", (scenario.job_id,)
            ).fetchone()
            assert frozen_row is not None
            replayed = replay_evaluation_job_authority(
                settings=scenario.settings,
                database=scenario.database,
                cipher=scenario.cipher,
                row=frozen_row,
                payload=payload,
                answer_id=scenario.answer_id,
                owner_canary_publication_phase="pre_release",
                connection=connection,
            )
        assert verified_owner_canary_content_graph(replayed).job_id == scenario.job_id
        assert scenario.database.job(scenario.job_id)["route"] == "sectioned"
    finally:
        scenario.database.close()


@pytest.mark.asyncio
async def test_dropped_outbox_trigger_and_legacy_read_never_serve_plaintext(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _prepare_scenario(tmp_path, monkeypatch)
    previous_services = getattr(app.state, "services", None)
    try:
        _disable_unrelated_owned_runtime_guards(monkeypatch)
        scenario.database.release_answer_once(
            scenario.answer_id,
            "verified_full",
            expected_evaluation_authority_sha256=str(scenario.authority["seal_sha256"]),
            evaluation_authority_verifier=lambda: scenario.capability,
        )
        app.state.services = SimpleNamespace(
            database=scenario.database,
            cipher=scenario.cipher,
            settings=scenario.settings,
        )
        headers = {
            "x-owner-canary-run-id": _RUN_ID,
            "x-owner-canary-case-id": _CASE_ID,
        }
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4311))
        original_job = scenario.database.job(scenario.job_id)
        assert original_job is not None
        scenario.database.execute(
            "UPDATE jobs SET trace_id='UNBOUND-TRACE-TEXT' WHERE id=?",
            (scenario.job_id,),
        )
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8777",
        ) as client:
            trace_response = await client.get(f"/api/v1/jobs/{scenario.job_id}", headers=headers)
        assert trace_response.status_code == 409
        assert "UNBOUND-TRACE-TEXT" not in trace_response.text
        scenario.database.execute(
            "UPDATE jobs SET trace_id=? WHERE id=?",
            (original_job["trace_id"], scenario.job_id),
        )

        scenario.database.execute("DROP TRIGGER trg_release_outbox_owner_binding_no_update")
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8777",
        ) as client:
            response = await client.get(f"/api/v1/answers/{scenario.answer_id}", headers=headers)
        assert response.status_code == 409
        assert "Evidence-bound answer." not in response.text

        # Reinstalling the exact trigger is an explicit test-fixture action;
        # the second read verifies the superseded-lane technical stop itself.
        scenario.database.initialize()
        legacy = dict(scenario.authority)
        legacy["lane"] = "live60_o04_v1"
        scenario.database.execute(
            "UPDATE jobs SET evaluation_authority_json=? WHERE id=?",
            (json.dumps(legacy, sort_keys=True), scenario.job_id),
        )
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8777",
        ) as client:
            legacy_response = await client.get(
                f"/api/v1/answers/{scenario.answer_id}", headers=headers
            )
        assert legacy_response.status_code == 409
        assert "superseded_evaluation_release_content_certification_missing" in (
            legacy_response.text
        )
        assert "Evidence-bound answer." not in legacy_response.text
    finally:
        if previous_services is None:
            if hasattr(app.state, "services"):
                del app.state.services
        else:
            app.state.services = previous_services
        scenario.database.close()


@pytest.mark.asyncio
async def test_slow_publish_and_released_read_keep_runtime_heartbeat_live_and_serve_bound_dtos(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _prepare_scenario(tmp_path, monkeypatch)
    previous_services = getattr(app.state, "services", None)
    try:
        _disable_unrelated_owned_runtime_guards(monkeypatch)
        scenario.database.activate_owner_canary_runtime_session(
            run_id=_RUN_ID,
            authorization_sha256="b" * 64,
            start_attestation_sha256="f" * 64,
            runtime_instance_sha256="1" * 64,
            candidate_build_id=_CANDIDATE_ID,
            memory_policy_sha256="2" * 64,
            controller_pid=os.getpid(),
        )

        def heartbeat_after_four_seconds(
            entered: threading.Event,
            result: dict[str, float],
        ) -> None:
            assert entered.wait(timeout=2)
            time.sleep(4.0)
            started = time.perf_counter()
            scenario.database.heartbeat_owner_canary_runtime_session(
                run_id=_RUN_ID,
                start_attestation_sha256="f" * 64,
                runtime_instance_sha256="1" * 64,
                controller_pid=os.getpid(),
            )
            result["latency"] = time.perf_counter() - started

        publish_entered = threading.Event()
        publish_heartbeat: dict[str, float] = {}
        publish_thread = threading.Thread(
            target=heartbeat_after_four_seconds,
            args=(publish_entered, publish_heartbeat),
            daemon=True,
        )
        publish_thread.start()

        def slow_release_replay() -> VerifiedEvaluationReleaseAuthority:
            with scenario.database.detached_read_snapshot():
                publish_entered.set()
                time.sleep(5.25)
            return scenario.capability

        scenario.database.release_answer_once(
            scenario.answer_id,
            "verified_full",
            expected_evaluation_authority_sha256=str(scenario.authority["seal_sha256"]),
            evaluation_authority_verifier=slow_release_replay,
        )
        publish_thread.join(timeout=1)
        assert not publish_thread.is_alive()
        assert publish_heartbeat["latency"] < 1.0
        scenario.database.heartbeat_owner_canary_runtime_session(
            run_id=_RUN_ID,
            start_attestation_sha256="f" * 64,
            runtime_instance_sha256="1" * 64,
            controller_pid=os.getpid(),
        )

        # Runner finalization and exact-outbox recovery may update these
        # operational fields after publication.  Neither field is answer
        # content, and neither may invalidate or leak through the bound DTO.
        scenario.database.execute(
            "UPDATE jobs SET user_message=?,checkpoint_json=?,updated_at=?,last_progress_at=? "
            "WHERE id=?",
            (
                "UNBOUND MUTABLE MESSAGE MUST NOT BE SERVED",
                json.dumps(
                    {
                        "answer_id": scenario.answer_id,
                        "release_state": "verified_full",
                        "issue_plan": [],
                    },
                    sort_keys=True,
                ),
                "1999-01-01T00:00:00+00:00",
                "1999-01-01T00:00:00+00:00",
                scenario.job_id,
            ),
        )

        fast_semantic_core = canary_runtime_module._verify_owner_canary_runtime_semantic_core
        read_entered = threading.Event()

        def slow_semantic_core(**kwargs: Any) -> object:
            read_entered.set()
            time.sleep(5.25)
            return fast_semantic_core(**kwargs)

        monkeypatch.setattr(
            canary_runtime_module,
            "_verify_owner_canary_runtime_semantic_core",
            slow_semantic_core,
        )
        read_heartbeat: dict[str, float] = {}
        read_thread = threading.Thread(
            target=heartbeat_after_four_seconds,
            args=(read_entered, read_heartbeat),
            daemon=True,
        )
        read_thread.start()
        app.state.services = SimpleNamespace(
            database=scenario.database,
            cipher=scenario.cipher,
            settings=scenario.settings,
        )
        headers = {
            "x-owner-canary-run-id": _RUN_ID,
            "x-owner-canary-case-id": _CASE_ID,
        }
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4311))
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8777",
            timeout=20,
        ) as client:
            job_response = await client.get(f"/api/v1/jobs/{scenario.job_id}", headers=headers)
            read_thread.join(timeout=1)
            assert not read_thread.is_alive()
            assert read_heartbeat["latency"] < 1.0
            assert job_response.status_code == 200
            assert job_response.json()["message"] == (
                "Verified owner-evaluation answer is ready for private review."
            )
            outbox = scenario.database.released_outbox_for_job(scenario.job_id)
            assert outbox is not None
            published_at = datetime.fromisoformat(str(outbox["published_at"]))
            assert (
                datetime.fromisoformat(job_response.json()["updated_at"].replace("Z", "+00:00"))
                == published_at
            )
            assert (
                datetime.fromisoformat(
                    job_response.json()["last_progress_at"].replace("Z", "+00:00")
                )
                == published_at
            )
            assert "1999-01-01" not in job_response.text

            monkeypatch.setattr(
                canary_runtime_module,
                "_verify_owner_canary_runtime_semantic_core",
                fast_semantic_core,
            )
            answer_response = await client.get(
                f"/api/v1/answers/{scenario.answer_id}", headers=headers
            )
            evidence_response = await client.get(
                f"/api/v1/answers/{scenario.answer_id}/evidence", headers=headers
            )
            events_response = await client.get(
                f"/api/v1/jobs/{scenario.job_id}/events", headers=headers
            )
        assert answer_response.status_code == 200
        assert answer_response.json()["content"] == "Evidence-bound answer."
        assert evidence_response.status_code == 200
        assert evidence_response.json()["claims"] == []
        assert events_response.status_code == 200
        assert "UNBOUND MUTABLE MESSAGE" not in events_response.text
        assert "Verified owner-evaluation answer is ready for private review." in (
            events_response.text
        )
        immutable_outbox = dict(scenario.database.released_outbox_for_job(scenario.job_id))
        scenario.database.revoke_owner_canary_runtime_session(
            _RUN_ID,
            start_attestation_sha256="f" * 64,
            runtime_instance_sha256="1" * 64,
        )
        assert dict(scenario.database.released_outbox_for_job(scenario.job_id)) == (
            immutable_outbox
        )
        session = scenario.database.owner_canary_runtime_session(_RUN_ID)
        assert session is not None and session["status"] == "revoked"
        assert scenario.database.answer(scenario.answer_id)["release_state"] == "verified_full"
        assert scenario.database.job(scenario.job_id)["release_state"] == "verified_full"
    finally:
        if previous_services is None:
            if hasattr(app.state, "services"):
                del app.state.services
        else:
            app.state.services = previous_services
        scenario.database.close()
