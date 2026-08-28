from __future__ import annotations

import os
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from app.db import Database
from app.evaluation.candidate_completion_authority import (
    MEMORY_MAX_SAMPLE_INTERVAL_SECONDS,
    MEMORY_MEASUREMENT_METHOD,
    MEMORY_SAMPLE_INTERVAL_SECONDS,
    write_create_only_private_safe_json,
)
from app.evaluation.live_suite import sealed_sha256
from app.evaluation.owner_quality_canary_authorization import OwnerDecisionRequired
from app.evaluation.owner_quality_canary_projection import OwnerCanaryFinalReviewPackage
from app.evaluation.owner_quality_canary_runtime import (
    execute_owner_quality_canary_with_owned_runtime,
)
from app.evaluation.owner_quality_owned_model_runtime import (
    OWNED_RUNTIME_CHECKPOINT_DIRNAME,
    OWNED_RUNTIME_CHECKPOINT_SCHEMA,
    OWNED_RUNTIME_END_FILENAME,
    OWNED_RUNTIME_END_SCHEMA,
    OWNED_RUNTIME_START_FILENAME,
    OWNED_RUNTIME_START_SCHEMA,
    OwnerCanaryOwnedModelRuntime,
    _MemoryMonitor,
    load_active_owner_canary_runtime,
    load_ended_owner_canary_runtime,
    verify_owner_canary_runtime_atomic_release,
)
from app.evaluation.owner_quality_v111_promotion import _verify_final_package_files

SHA = "a" * 64
LISTENER_SHA = "b" * 64
CASES = tuple(f"live60-q{number:02d}" for number in range(1, 31))


def _sealed(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["seal_sha256"] = sealed_sha256(result)
    return result


def _memory(ordinal: int) -> dict[str, Any]:
    return {
        "measurement_method": MEMORY_MEASUREMENT_METHOD,
        "sampling_interval_seconds": MEMORY_SAMPLE_INTERVAL_SECONDS,
        "maximum_allowed_sample_interval_seconds": (MEMORY_MAX_SAMPLE_INTERVAL_SECONDS),
        "sample_count": ordinal + 1,
        "maximum_observed_sample_interval_seconds": min(0.2, 0.1 + ordinal / 10_000),
        "maximum_sampling_jitter_seconds": ordinal / 20_000,
        "controller_sampled_peak_rss_bytes": 1_000 + ordinal,
        "owned_sidecar_tree_sampled_peak_rss_bytes": 2_000 + ordinal,
        "sampled_peak_combined_working_set_bytes": 3_000 + ordinal,
        "minimum_sampled_host_available_memory_bytes": 1_000_000 - ordinal,
    }


def _start() -> dict[str, Any]:
    return _sealed(
        {
            "schema": OWNED_RUNTIME_START_SCHEMA,
            "run_id": "owned-runtime-test",
            "lane": "development",
            "authorization_seal_sha256": "1" * 64,
            "canary_manifest_seal_sha256": "2" * 64,
            "workspace_seal_sha256": "3" * 64,
            "privacy_root_sha256": "4" * 64,
            "candidate_build_id": "candidate-v111",
            "candidate_manifest_sha256": "5" * 64,
            "integration_sha": "6" * 40,
            "completion_preflight_result_sha256": "7" * 64,
            "runtime_binding_sha256": "8" * 64,
            "memory_policy_sha256": "9" * 64,
            "memory_policy_source_file_sha256": "a" * 64,
            "trusted_model_identity_sha256": "b" * 64,
            "trusted_model_file_manifest_sha256": "c" * 64,
            "trusted_toolchain_identity_sha256": SHA,
            "installed_environment_manifest_sha256": "d" * 64,
            "base_python_runtime_manifest_sha256": "e" * 64,
            "venv_control_manifest_sha256": "f" * 64,
            "launcher_implementation_sha256": "0" * 64,
            "model_runtime_implementation_sha256": "1" * 64,
            "launch_argv_sha256": "2" * 64,
            "model_id": "mlx-community/Qwen3.5-9B-4bit",
            "model_revision": "8b2b98c00a6b4d291155e4890773ca8f769aee53",
            "model_host": "127.0.0.1",
            "model_port": 8778,
            "launched_pid": os.getpid(),
            "owned_process_group_id": os.getpid(),
            "launch_nonce": "3" * 64,
            "owned_listener_proof_sha256": LISTENER_SHA,
            "runtime_instance_sha256": "4" * 64,
            "authorized_case_ids": list(CASES),
            "startup_memory": _memory(0),
            "adapter_present": False,
            "proxy_environment_inherited": False,
            "local_only": True,
            "public_traffic_allowed": False,
            "writes_active": False,
            "writes_o04": False,
            "synthetic_non_authoritative": False,
        }
    )


def _checkpoint(
    start: dict[str, Any], sequence: int, phase: str, *, generation: int | None = None
) -> dict[str, Any]:
    case_id = CASES[sequence - 1]
    ordinal = sequence * 2 - (1 if phase == "before_case" else 0)
    return _sealed(
        {
            "schema": OWNED_RUNTIME_CHECKPOINT_SCHEMA,
            "run_id": start["run_id"],
            "case_id": case_id,
            "sequence_number": sequence,
            "phase": phase,
            "start_attestation_sha256": start["seal_sha256"],
            "runtime_instance_sha256": start["runtime_instance_sha256"],
            "owned_listener_proof_sha256": LISTENER_SHA,
            "memory_policy_sha256": start["memory_policy_sha256"],
            "memory": _memory(ordinal),
            "model_artifact_rehashed": True,
            "toolchain_rehashed": True,
            "integration_reverified": True,
            "release_authority_active": True,
            "frontier_generation": ordinal if generation is None else generation,
        }
    )


def _artifact_graph(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    start = _start()
    write_create_only_private_safe_json(root / "safe-metrics" / OWNED_RUNTIME_START_FILENAME, start)
    before: list[str] = []
    after: list[str] = []
    for sequence, case_id in enumerate(CASES, start=1):
        for phase, suffix, target in (
            ("before_case", "before", before),
            ("after_case", "after", after),
        ):
            checkpoint = _checkpoint(start, sequence, phase)
            target.append(str(checkpoint["seal_sha256"]))
            write_create_only_private_safe_json(
                root
                / "safe-metrics"
                / OWNED_RUNTIME_CHECKPOINT_DIRNAME
                / f"{sequence:02d}-{case_id}-{suffix}.json",
                checkpoint,
            )
    checkpoint_set = sealed_sha256(
        {
            "schema": "legalbot.owner-canary-owned-runtime-checkpoint-set.v1",
            "case_ids": list(CASES),
            "before": before,
            "after": after,
        }
    )
    end = _sealed(
        {
            "schema": OWNED_RUNTIME_END_SCHEMA,
            "run_id": start["run_id"],
            "authorization_seal_sha256": start["authorization_seal_sha256"],
            "canary_manifest_seal_sha256": start["canary_manifest_seal_sha256"],
            "workspace_seal_sha256": start["workspace_seal_sha256"],
            "candidate_build_id": start["candidate_build_id"],
            "candidate_manifest_sha256": start["candidate_manifest_sha256"],
            "integration_sha": start["integration_sha"],
            "start_attestation_sha256": start["seal_sha256"],
            "runtime_instance_sha256": start["runtime_instance_sha256"],
            "memory_policy_sha256": start["memory_policy_sha256"],
            "case_ids": list(CASES),
            "before_checkpoint_seal_sha256s": before,
            "after_checkpoint_seal_sha256s": after,
            "checkpoint_set_sha256": checkpoint_set,
            "full_run_memory": _memory(61),
            "final_owned_listener_proof_sha256": LISTENER_SHA,
            "model_artifact_rehashed_after_run": True,
            "toolchain_rehashed_after_run": True,
            "integration_reverified_after_run": True,
            "owned_process_stopped": True,
            "memory_monitor_active_through_process_exit": True,
            "owned_process_group_and_nonce_lineage_absent_after_stop": True,
            "shutdown_controller_and_host_sampled": True,
            "successful_end": True,
            "synthetic_non_authoritative": False,
        }
    )
    write_create_only_private_safe_json(root / "safe-metrics" / OWNED_RUNTIME_END_FILENAME, end)
    return start, end


def _active_artifact_graph(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    start = _start()
    before = _checkpoint(start, 1, "before_case")
    write_create_only_private_safe_json(root / "safe-metrics" / OWNED_RUNTIME_START_FILENAME, start)
    write_create_only_private_safe_json(
        root / "safe-metrics" / OWNED_RUNTIME_CHECKPOINT_DIRNAME / f"01-{CASES[0]}-before.json",
        before,
    )
    return start, before


def _insert_session(
    database: Database, start: dict[str, Any], *, status: str, end_sha: str | None
) -> None:
    now = datetime.now(UTC)
    database.execute(
        """
        INSERT INTO owner_canary_runtime_sessions(
          run_id,authorization_sha256,start_attestation_sha256,
          runtime_instance_sha256,candidate_build_id,memory_policy_sha256,
          expected_case_count,next_sequence,active_case_id,
          active_before_checkpoint_sha256,frontier_generation,controller_pid,
          heartbeat_at,lease_expires_at,status,end_attestation_sha256,updated_at
        ) VALUES (?,?,?,?,?,?,30,31,NULL,NULL,61,?,?,?,?,?,?)
        """,
        (
            start["run_id"],
            start["authorization_seal_sha256"],
            start["seal_sha256"],
            start["runtime_instance_sha256"],
            start["candidate_build_id"],
            start["memory_policy_sha256"],
            os.getpid(),
            now.isoformat(),
            (now + timedelta(minutes=1)).isoformat(),
            status,
            end_sha,
            now.isoformat(),
        ),
    )


def _insert_active_session(
    database: Database, start: dict[str, Any], before: dict[str, Any]
) -> None:
    now = datetime.now(UTC)
    database.execute(
        """
        INSERT INTO owner_canary_runtime_sessions(
          run_id,authorization_sha256,start_attestation_sha256,
          runtime_instance_sha256,candidate_build_id,memory_policy_sha256,
          expected_case_count,next_sequence,active_case_id,
          active_before_checkpoint_sha256,frontier_generation,controller_pid,
          heartbeat_at,lease_expires_at,status,end_attestation_sha256,updated_at
        ) VALUES (?,?,?,?,?,?,30,1,?,?,1,?,?,?,'active',NULL,?)
        """,
        (
            start["run_id"],
            start["authorization_seal_sha256"],
            start["seal_sha256"],
            start["runtime_instance_sha256"],
            start["candidate_build_id"],
            start["memory_policy_sha256"],
            CASES[0],
            before["seal_sha256"],
            os.getpid(),
            now.isoformat(),
            (now + timedelta(minutes=1)).isoformat(),
            now.isoformat(),
        ),
    )


def _patch_historical_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.evaluation import owner_quality_owned_model_runtime as runtime

    monkeypatch.setattr(runtime, "_verify_static_bindings", lambda **_kwargs: object())
    monkeypatch.setattr(runtime, "_assert_memory_payload", lambda *_args: None)


def _load_end(root: Path, database: Database, start: dict[str, Any]) -> Any:
    return load_ended_owner_canary_runtime(
        settings=cast(Any, SimpleNamespace()),
        workspace_root=root,
        candidate=cast(
            Any,
            SimpleNamespace(
                build_id=start["candidate_build_id"],
                candidate_manifest_sha256=start["candidate_manifest_sha256"],
            ),
        ),
        authorization_seal_sha256=start["authorization_seal_sha256"],
        canary_manifest_seal_sha256=start["canary_manifest_seal_sha256"],
        workspace_seal_sha256=start["workspace_seal_sha256"],
        runtime_binding={"seal_sha256": start["runtime_binding_sha256"]},
        memory_policy=cast(Any, object()),
        completion_preflight_result_sha256=start["completion_preflight_result_sha256"],
        expected_case_ids=CASES,
        database=database,
    )


def _load_active(root: Path, database: Database, start: dict[str, Any]) -> Any:
    return load_active_owner_canary_runtime(
        settings=cast(Any, SimpleNamespace()),
        workspace_root=root,
        case_id=CASES[0],
        candidate=cast(
            Any,
            SimpleNamespace(
                build_id=start["candidate_build_id"],
                candidate_manifest_sha256=start["candidate_manifest_sha256"],
            ),
        ),
        authorization_seal_sha256=start["authorization_seal_sha256"],
        canary_manifest_seal_sha256=start["canary_manifest_seal_sha256"],
        workspace_seal_sha256=start["workspace_seal_sha256"],
        runtime_binding={"seal_sha256": start["runtime_binding_sha256"]},
        memory_policy=cast(Any, object()),
        completion_preflight_result_sha256=start["completion_preflight_result_sha256"],
        database=database,
    )


def test_atomic_controller_job_is_never_visible_as_queued(database: Database) -> None:
    start = _start()
    database.activate_owner_canary_runtime_session(
        run_id=str(start["run_id"]),
        authorization_sha256=str(start["authorization_seal_sha256"]),
        start_attestation_sha256=str(start["seal_sha256"]),
        runtime_instance_sha256=str(start["runtime_instance_sha256"]),
        candidate_build_id=str(start["candidate_build_id"]),
        memory_policy_sha256=str(start["memory_policy_sha256"]),
        controller_pid=os.getpid(),
    )
    before = _checkpoint(start, 1, "before_case")
    generation = database.advance_owner_canary_runtime_before_case(
        run_id=str(start["run_id"]),
        sequence_number=1,
        case_id=CASES[0],
        checkpoint_sha256=str(before["seal_sha256"]),
        start_attestation_sha256=str(start["seal_sha256"]),
        runtime_instance_sha256=str(start["runtime_instance_sha256"]),
    )
    authority = _sealed(
        {
            "schema": "legalbot.persisted-evaluation-job-authority.v1",
            "lane": "owner_quality_canary",
            "mode": "candidate_pinned_evaluation_release",
            "run_id": start["run_id"],
            "case_id": CASES[0],
            "request_sha256": "c" * 64,
            "candidate_build_id": start["candidate_build_id"],
            "authorization_seal_sha256": start["authorization_seal_sha256"],
            "owned_runtime_before_checkpoint_sha256": before["seal_sha256"],
            "owned_runtime_frontier_generation": generation,
            "writes_active": False,
            "release_allowed": True,
        }
    )
    worker = database.create_job(
        job_id="owner-runtime-job-1",
        encrypted_question=b"ciphertext",
        question_summary="Private encrypted question",
        request={"word_target": 100},
        pinned_index_build_id=str(start["candidate_build_id"]),
        evaluation_run_id=str(start["run_id"]),
        evaluation_case_id=CASES[0],
        evaluation_request_sha256="c" * 64,
        evaluation_authority=authority,
        word_target=100,
        owner_canary_controller_claim={
            "controller_pid": os.getpid(),
            "before_checkpoint_sha256": before["seal_sha256"],
            "frontier_generation": generation,
            "lease_seconds": 60,
        },
    )
    row = database.job("owner-runtime-job-1")
    assert worker is not None
    assert row is not None and row["status"] == "running"
    assert row["lease_owner"] == worker and row["attempt_count"] == 1
    assert database.claim_next_job("ambient-worker", job_types=("answer",)) is None


def test_expired_runtime_lease_cannot_be_resurrected(database: Database) -> None:
    start = _start()
    database.activate_owner_canary_runtime_session(
        run_id=str(start["run_id"]),
        authorization_sha256=str(start["authorization_seal_sha256"]),
        start_attestation_sha256=str(start["seal_sha256"]),
        runtime_instance_sha256=str(start["runtime_instance_sha256"]),
        candidate_build_id=str(start["candidate_build_id"]),
        memory_policy_sha256=str(start["memory_policy_sha256"]),
        controller_pid=os.getpid(),
    )
    database.execute(
        "UPDATE owner_canary_runtime_sessions SET lease_expires_at=? WHERE run_id=?",
        ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), start["run_id"]),
    )
    with pytest.raises(RuntimeError, match="heartbeat_rejected"):
        database.heartbeat_owner_canary_runtime_session(
            run_id=str(start["run_id"]),
            start_attestation_sha256=str(start["seal_sha256"]),
            runtime_instance_sha256=str(start["runtime_instance_sha256"]),
            controller_pid=os.getpid(),
        )


def test_failed_duplicate_generation_cannot_revoke_current_session(
    database: Database,
) -> None:
    start = _start()
    database.activate_owner_canary_runtime_session(
        run_id=str(start["run_id"]),
        authorization_sha256=str(start["authorization_seal_sha256"]),
        start_attestation_sha256=str(start["seal_sha256"]),
        runtime_instance_sha256=str(start["runtime_instance_sha256"]),
        candidate_build_id=str(start["candidate_build_id"]),
        memory_policy_sha256=str(start["memory_policy_sha256"]),
        controller_pid=os.getpid(),
    )
    database.revoke_owner_canary_runtime_session(
        str(start["run_id"]),
        start_attestation_sha256="e" * 64,
        runtime_instance_sha256="f" * 64,
    )
    row = database.owner_canary_runtime_session(str(start["run_id"]))
    assert row is not None and row["status"] == "active"


def test_strict_end_rejects_resealed_nonmonotonic_frontier(
    tmp_path: Path, database: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "review"
    start, end = _artifact_graph(root)
    _insert_session(database, start, status="ended", end_sha=str(end["seal_sha256"]))
    _patch_historical_replay(monkeypatch)
    path = root / "safe-metrics" / OWNED_RUNTIME_CHECKPOINT_DIRNAME / f"01-{CASES[0]}-before.json"
    path.chmod(0o600)
    value = _checkpoint(start, 1, "before_case", generation=17)
    path.unlink()
    write_create_only_private_safe_json(path, value)
    with pytest.raises(RuntimeError, match="checkpoint_mismatch"):
        _load_end(root, database, start)


def test_strict_end_rejects_non_cumulative_memory(
    tmp_path: Path, database: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "review"
    start, end = _artifact_graph(root)
    _insert_session(database, start, status="ended", end_sha=str(end["seal_sha256"]))
    _patch_historical_replay(monkeypatch)
    path = root / "safe-metrics" / OWNED_RUNTIME_CHECKPOINT_DIRNAME / f"01-{CASES[0]}-after.json"
    value = _checkpoint(start, 1, "after_case")
    value["memory"]["sample_count"] = 1
    value["seal_sha256"] = sealed_sha256(value)
    path.unlink()
    write_create_only_private_safe_json(path, value)
    with pytest.raises(RuntimeError, match="memory_not_cumulative"):
        _load_end(root, database, start)


def test_strict_end_rejects_changed_end_listener(
    tmp_path: Path, database: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "review"
    start, end = _artifact_graph(root)
    end_path = root / "safe-metrics" / OWNED_RUNTIME_END_FILENAME
    end["final_owned_listener_proof_sha256"] = "e" * 64
    end["seal_sha256"] = sealed_sha256(end)
    end_path.unlink()
    write_create_only_private_safe_json(end_path, end)
    _insert_session(database, start, status="ended", end_sha=str(end["seal_sha256"]))
    _patch_historical_replay(monkeypatch)
    with pytest.raises(RuntimeError, match="end_mismatch"):
        _load_end(root, database, start)


def test_strict_end_rejects_missing_end_attestation(
    tmp_path: Path, database: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "review"
    start, end = _artifact_graph(root)
    (root / "safe-metrics" / OWNED_RUNTIME_END_FILENAME).unlink()
    _insert_session(database, start, status="ended", end_sha=str(end["seal_sha256"]))
    _patch_historical_replay(monkeypatch)
    with pytest.raises(RuntimeError, match="artifact_missing"):
        _load_end(root, database, start)


def test_preclaimed_model_port_stops_before_process_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.evaluation import owner_quality_owned_model_runtime as runtime_module

    runtime = object.__new__(OwnerCanaryOwnedModelRuntime)
    cast(Any, runtime).settings = SimpleNamespace()
    runtime.process = None
    runtime._ended = False
    monkeypatch.setattr(
        runtime_module,
        "require_owner_canary_exclusive_model_transport_resolution",
        lambda: None,
    )
    monkeypatch.setattr(runtime_module, "_validate_fixed_settings", lambda _settings: None)
    monkeypatch.setattr(OwnerCanaryOwnedModelRuntime, "_port_open", staticmethod(lambda: True))
    with pytest.raises(RuntimeError, match="port_preclaimed"):
        runtime.start()


def test_swapped_model_weights_stop_before_process_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.evaluation import owner_quality_owned_model_runtime as runtime_module

    runtime = object.__new__(OwnerCanaryOwnedModelRuntime)
    cast(Any, runtime).settings = SimpleNamespace(project_root=tmp_path)
    runtime.process = None
    runtime._ended = False
    runtime.integration_sha = "6" * 40
    runtime.memory_policy = cast(Any, object())
    monkeypatch.setattr(
        runtime_module,
        "require_owner_canary_exclusive_model_transport_resolution",
        lambda: None,
    )
    monkeypatch.setattr(runtime_module, "_validate_fixed_settings", lambda _settings: None)
    monkeypatch.setattr(OwnerCanaryOwnedModelRuntime, "_port_open", staticmethod(lambda: False))
    monkeypatch.setattr(runtime_module, "_clean_integration_sha", lambda _project_root: "6" * 40)
    monkeypatch.setattr(runtime_module, "_policy_identity", lambda _policy: (object(), "a" * 64))
    monkeypatch.setattr(
        runtime_module,
        "load_trusted_model_identity",
        lambda _project_root: {"seal_sha256": "b" * 64},
    )
    monkeypatch.setattr(
        runtime_module,
        "_model_root",
        lambda _settings: tmp_path / "swapped-model",
    )
    monkeypatch.setattr(
        runtime_module,
        "_verify_model_artifact_manifest",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("model_artifact_identity_mismatch")),
    )
    with pytest.raises(RuntimeError, match="model_artifact_identity_mismatch"):
        runtime.start()


def test_unresolved_exclusive_transport_stops_before_any_launch_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.evaluation import owner_quality_owned_model_runtime as runtime_module

    runtime = object.__new__(OwnerCanaryOwnedModelRuntime)
    monkeypatch.setattr(
        runtime_module,
        "_validate_fixed_settings",
        lambda _settings: (_ for _ in ()).throw(AssertionError("launch checks reached")),
    )
    with pytest.raises(OwnerDecisionRequired) as exc_info:
        runtime.start()
    assert exc_info.value.reason_code == "owner_canary_exclusive_model_transport_unresolved"


def test_production_entry_stops_transport_before_workspace_or_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.evaluation import owner_quality_canary_runtime as canary_runtime

    monkeypatch.setattr(
        canary_runtime,
        "_execute_owner_quality_canary_with_client",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("execution reached")),
    )
    with pytest.raises(OwnerDecisionRequired) as exc_info:
        execute_owner_quality_canary_with_owned_runtime(
            settings=cast(Any, object()),
            cipher=cast(Any, object()),
            manifest_path=Path("unused-manifest"),
            qualification_path=Path("unused-qualification"),
            expert_qualification_path=Path("unused-expert"),
            authorization_path=Path("unused-authorization"),
            review_date=datetime.now(UTC).date(),
            legal_date=datetime.now(UTC).date(),
            case_timeout_seconds=1,
        )
    assert exc_info.value.reason_code == "owner_canary_exclusive_model_transport_unresolved"


def test_fake_localhost_listener_cannot_mint_active_authority(
    tmp_path: Path, database: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.evaluation import owner_quality_owned_model_runtime as runtime_module

    root = tmp_path / "review"
    start, before = _active_artifact_graph(root)
    _insert_active_session(database, start, before)
    toolchain = SimpleNamespace(
        system_tools={},
        safe_binding=lambda: {"trusted_toolchain_identity_sha256": SHA},
    )
    monkeypatch.setattr(runtime_module, "_verify_static_bindings", lambda **_kwargs: toolchain)
    monkeypatch.setattr(runtime_module, "_assert_memory_payload", lambda *_args: None)
    monkeypatch.setattr(runtime_module, "attest_owned_listener", lambda **_kwargs: "f" * 64)
    with pytest.raises(RuntimeError, match="listener_changed"):
        _load_active(root, database, start)


def test_active_memory_breach_is_a_hard_stop(
    tmp_path: Path, database: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.evaluation import owner_quality_owned_model_runtime as runtime_module

    root = tmp_path / "review"
    start, before = _active_artifact_graph(root)
    _insert_active_session(database, start, before)
    toolchain = SimpleNamespace(
        system_tools={},
        safe_binding=lambda: {"trusted_toolchain_identity_sha256": SHA},
    )

    class FakeSampler:
        def __init__(self, **_kwargs: Any) -> None:
            self.peak_combined_working_set_bytes = 99_000
            self.minimum_host_available_memory_bytes = 1
            self.maximum_observed_sample_interval_seconds = 0.1

        def sample(self) -> None:
            return None

    monkeypatch.setattr(runtime_module, "_verify_static_bindings", lambda **_kwargs: toolchain)
    monkeypatch.setattr(runtime_module, "_assert_memory_payload", lambda *_args: None)
    monkeypatch.setattr(runtime_module, "attest_owned_listener", lambda **_kwargs: LISTENER_SHA)
    monkeypatch.setattr(runtime_module, "_verify_health", lambda *_args: None)
    monkeypatch.setattr(runtime_module, "WorkflowMemorySampler", FakeSampler)
    monkeypatch.setattr(
        runtime_module,
        "_enforce_memory",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("memory_working_set_exceeds_owner_ceiling")
        ),
    )
    with pytest.raises(RuntimeError, match="memory_working_set"):
        _load_active(root, database, start)


def test_atomic_release_requires_current_registered_controller() -> None:
    with pytest.raises(RuntimeError, match="controller_not_active"):
        verify_owner_canary_runtime_atomic_release({"run_id": "unregistered-run"})


def test_shutdown_monitor_tolerates_only_expected_owned_parent_exit() -> None:
    monitor = object.__new__(_MemoryMonitor)
    monitor.process = cast(Any, SimpleNamespace(poll=lambda: 0))
    monitor._sample_lock = threading.Lock()
    monitor._expected_process_exit = threading.Event()
    monitor._expected_process_exit.set()
    cast(Any, monitor)._shutdown_snapshot = lambda: ((), frozenset())

    class MissingOwnedParent:
        @staticmethod
        def sample() -> None:
            raise RuntimeError("owned_sidecar_process_missing")

    monitor.sampler = cast(Any, MissingOwnedParent())
    assert monitor.sample_now() is False

    class BrokenHostMeasurement:
        @staticmethod
        def sample() -> None:
            raise RuntimeError("memory_measurement_unavailable")

    monitor.sampler = cast(Any, BrokenHostMeasurement())
    with pytest.raises(RuntimeError, match="memory_measurement_unavailable"):
        monitor.sample_now()


def test_shutdown_confirmation_rejects_surviving_owned_lineage() -> None:
    monitor = object.__new__(_MemoryMonitor)
    monitor.process = cast(Any, SimpleNamespace(poll=lambda: 0))
    monitor._sample_lock = threading.Lock()
    cast(Any, monitor)._shutdown_snapshot = lambda: (
        ((os.getpid(), 1, 1024),),
        frozenset({77}),
    )
    with pytest.raises(RuntimeError, match="process_tree_not_stopped"):
        monitor.confirm_owned_process_stopped()


def test_failure_cleanup_kills_surviving_group_and_nonce_lineage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.evaluation import owner_quality_owned_model_runtime as runtime_module

    class FakeProcess:
        pid = 41
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, *, timeout: float) -> int:
            del timeout
            self.returncode = 0
            return 0

    monitor = object.__new__(_MemoryMonitor)
    monitor.process = cast(Any, FakeProcess())
    monitor.owned_process_group_id = 41
    monitor._shutdown_group_owned = False
    monitor._expected_process_exit = threading.Event()
    monitor._stop = threading.Event()
    monitor._sample_lock = threading.Lock()
    monitor._thread = threading.Thread(target=lambda: None)
    snapshots = iter(
        (
            (((41, 1, 1024), (42, 41, 2048)), frozenset({42}), frozenset({42})),
            (((os.getpid(), 1, 1024),), frozenset(), frozenset()),
            (((os.getpid(), 1, 1024),), frozenset(), frozenset()),
        )
    )
    cast(Any, monitor)._raw_shutdown_snapshot = lambda: next(snapshots)
    killed_groups: list[tuple[int, int]] = []
    killed_pids: list[tuple[int, int]] = []
    monkeypatch.setattr(
        runtime_module.os,
        "killpg",
        lambda group_id, signal_number: killed_groups.append((group_id, signal_number)),
    )
    monkeypatch.setattr(
        runtime_module.os,
        "kill",
        lambda pid, signal_number: killed_pids.append((pid, signal_number)),
    )
    monkeypatch.setattr(runtime_module.os, "getpgid", lambda _pid: 41)
    assert monitor.force_stop_owned_lineage() is True
    assert (41, runtime_module.signal.SIGTERM) in killed_groups
    assert (41, runtime_module.signal.SIGKILL) in killed_groups
    assert (42, runtime_module.signal.SIGKILL) in killed_pids


def test_failure_cleanup_continues_nonce_cleanup_after_process_group_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.evaluation import owner_quality_owned_model_runtime as runtime_module

    class FakeProcess:
        pid = 41
        returncode: int | None = None
        terminated = False
        killed = False
        wait_calls = 0

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, *, timeout: float) -> int:
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise runtime_module.subprocess.TimeoutExpired("model", timeout)
            self.returncode = 0
            return 0

        def kill(self) -> None:
            self.killed = True
            self.returncode = 0

    process = FakeProcess()
    monitor = object.__new__(_MemoryMonitor)
    monitor.process = cast(Any, process)
    monitor.owned_process_group_id = 41
    monitor._shutdown_group_owned = False
    monitor._expected_process_exit = threading.Event()
    monitor._stop = threading.Event()
    monitor._sample_lock = threading.Lock()
    monitor._thread = threading.Thread(target=lambda: None)
    snapshots = iter(
        (
            (
                ((42, 1, 2048), (77, 1, 1024)),
                frozenset({77}),
                frozenset({42}),
            ),
            (
                ((os.getpid(), 1, 1024), (77, 1, 1024)),
                frozenset({77}),
                frozenset(),
            ),
            (
                ((os.getpid(), 1, 1024), (77, 1, 1024)),
                frozenset({77}),
                frozenset(),
            ),
        )
    )
    cast(Any, monitor)._raw_shutdown_snapshot = lambda: next(snapshots)
    killed_pids: list[int] = []
    killed_groups: list[int] = []
    monkeypatch.setattr(runtime_module.os, "getpgid", lambda _pid: 99)
    monkeypatch.setattr(
        runtime_module.os,
        "killpg",
        lambda group_id, _signal_number: killed_groups.append(group_id),
    )
    monkeypatch.setattr(
        runtime_module.os,
        "kill",
        lambda pid, _signal_number: killed_pids.append(pid),
    )
    assert monitor.force_stop_owned_lineage() is True
    assert process.terminated is True
    assert process.killed is True
    assert killed_groups == []
    assert killed_pids == [42]


def test_pre_monitor_cleanup_does_not_signal_an_unverified_reused_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.evaluation import owner_quality_owned_model_runtime as runtime_module

    runtime = object.__new__(OwnerCanaryOwnedModelRuntime)
    runtime.monitor = None
    runtime.process = cast(Any, SimpleNamespace(pid=41, poll=lambda: 0))
    runtime.process_group_id = 41
    runtime.toolchain = cast(
        Any,
        SimpleNamespace(system_tools={"ps": Path("/bin/ps")}),
    )
    runtime.nonce = "3" * 64
    snapshots = iter(
        (
            (((42, 1, 2048),), frozenset({42})),
            (((os.getpid(), 1, 1024),), frozenset()),
        )
    )
    monkeypatch.setattr(
        runtime_module,
        "_process_memory_snapshot",
        lambda **_kwargs: next(snapshots),
    )
    monkeypatch.setattr(
        runtime_module,
        "_process_group_members",
        lambda **_kwargs: (77,),
    )
    killed_groups: list[int] = []
    killed_pids: list[int] = []
    monkeypatch.setattr(
        runtime_module.os,
        "killpg",
        lambda group_id, _signal_number: killed_groups.append(group_id),
    )
    monkeypatch.setattr(
        runtime_module.os,
        "kill",
        lambda pid, _signal_number: killed_pids.append(pid),
    )
    assert runtime._stop_owned_process_lineage() is True
    assert killed_groups == []
    assert killed_pids == [42]


def test_legacy_package_cannot_enter_v111_promotion() -> None:
    package = OwnerCanaryFinalReviewPackage.model_construct(
        lane="development",
        case_ids=CASES,
        candidate_build_id="candidate-v111",
        candidate_manifest_sha256="5" * 64,
        authoritative_owned_runtime=False,
        synthetic_non_authoritative=False,
    )
    workspace = SimpleNamespace(
        manifest=SimpleNamespace(
            expected_case_ids=CASES,
            candidate_build_id="candidate-v111",
            candidate_manifest_sha256="5" * 64,
        )
    )
    with pytest.raises(ValueError, match="synthetic or unbound runtime evidence"):
        _verify_final_package_files(workspace=cast(Any, workspace), package=package)
