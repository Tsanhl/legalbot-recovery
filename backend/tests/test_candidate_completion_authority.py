from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.config import Settings
from app.evaluation import candidate_completion_authority as completion_authority
from app.evaluation.candidate_completion_authority import (
    LAUNCHER_START_SCHEMA,
    WorkflowMemorySampler,
    _base_python_runtime_manifest,
    _installed_package_inventory,
    _sqlite_backup_create_only,
    _venv_control_manifest,
    candidate_tree_sha256,
    isolated_model_python_arguments,
    listener_belongs_to_launch,
    listener_endpoints_are_loopback,
    load_completion_memory_policy,
    load_trusted_model_identity,
    load_trusted_toolchain_identity,
    materialize_completion_memory_policy,
    owned_process_tree_rss_bytes,
    sanitized_model_launch_environment,
    trusted_model_toolchain_binding,
    trusted_system_tool,
    verify_launcher_attestation,
)
from app.evaluation.candidate_completion_preflight import completion_runtime_binding
from app.evaluation.live_suite import sealed_sha256
from app.evaluation.nonrelease_artifacts import sealed_safe_payload
from app.evaluation.owner_quality_canary_authorization import OwnerDecisionRequired
from app.evaluation.sealed_candidate import SealedCandidateIdentity
from app.governance.existing_catalogue_read import open_existing_catalogue_read_database
from app.governance.owner_stop import (
    OwnerDecisionStore,
    seal_owner_decision_resolution,
)
from app.governance.v111_decision_generation import (
    build_completion_memory_decision_request,
)
from app.model_runtime.config import PINNED_RUNTIME_REPO, PINNED_RUNTIME_REVISION

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _candidate() -> SealedCandidateIdentity:
    return SealedCandidateIdentity(
        build_id="candidate-v111",
        status="candidate",
        candidate_manifest_sha256="a" * 64,
        candidate_seal_sha256="b" * 64,
        source_manifest_sha256="c" * 64,
        embedding_model="Qwen/Qwen3-Embedding-0.6B",
        reranker_model="Qwen/Qwen3-Reranker-0.6B",
        document_count=85,
        chunk_count=149_855,
        vector_count=149_855,
    )


def _binding() -> dict[str, object]:
    return completion_runtime_binding(
        candidate=_candidate(),
        model_id=PINNED_RUNTIME_REPO,
        model_revision=PINNED_RUNTIME_REVISION,
        model_version=f"{PINNED_RUNTIME_REPO}@{PINNED_RUNTIME_REVISION[:12]}",
        model_runtime_implementation_sha256="1" * 64,
        launcher_implementation_sha256="d" * 64,
        authority_implementation_sha256="e" * 64,
        model_artifact_metadata_sha256="2" * 64,
        trusted_model_identity_sha256="3" * 64,
        model_toolchain={
            "trusted_toolchain_identity_sha256": "0" * 64,
            "uv_executable_sha256": "1" * 64,
            "python_executable_sha256": "2" * 64,
            "model_runtime_lock_sha256": "3" * 64,
            "model_runtime_pyproject_sha256": "4" * 64,
            "locked_package_set_sha256": "5" * 64,
            "launch_environment_policy_sha256": "6" * 64,
            "installed_environment_manifest_sha256": "7" * 64,
            "base_python_runtime_manifest_sha256": "8" * 64,
            "venv_control_manifest_sha256": "9" * 64,
            "system_tool_set_sha256": "0" * 64,
        },
        model_runtime_profile={
            "context_window_tokens": 8192,
            "max_output_tokens": 2048,
            "prefill_step_size": 512,
            "kv_cache_bits": 8,
            "kv_group_size": 64,
            "clear_cache_after_request": True,
            "single_flight_generation": True,
        },
        draft_prompt_version="prompt-v1",
        draft_prompt_implementation_sha256="4" * 64,
        quality_policy_version="quality-v1",
        quality_policy_sha256="5" * 64,
        standards_bundle_version="standards-v1",
        standards_bundle_sha256="6" * 64,
        reviewer_role="ai_evidence_reviewer",
        reviewer_prompt_sha256="7" * 64,
        reviewer_policy_sha256="8" * 64,
        reviewer_toolchain_sha256="9" * 64,
        reviewer_implementation_sha256="a" * 64,
        retry_implementation_sha256="b" * 64,
        slo_policy_id="slo-v1",
        slo_policy_sha256="c" * 64,
        integration_sha="d" * 40,
    )


def _owner_decision(root: Path, *, resolved: bool) -> tuple[str, str | None]:
    request = build_completion_memory_decision_request(
        candidate_build_id=_candidate().build_id,
        candidate_manifest_sha256=_candidate().candidate_manifest_sha256,
        runtime_binding_sha256=str(_binding()["seal_sha256"]),
        integration_sha="d" * 40,
        host_physical_memory_bytes=16 * 1024**3,
        trusted_model_identity_file_sha256=hashlib.sha256(
            (PROJECT_ROOT / "config/completion_preflight_model_identity.json").read_bytes()
        ).hexdigest(),
        trusted_toolchain_identity_file_sha256=hashlib.sha256(
            (PROJECT_ROOT / "config/completion_preflight_toolchain_identity.json").read_bytes()
        ).hexdigest(),
        created_at=datetime(2026, 8, 20, 8, 0, tzinfo=UTC),
    )
    store = OwnerDecisionStore(root)
    store.write_request(request)
    if not resolved:
        return request.seal_sha256, None
    resolution = seal_owner_decision_resolution(
        request=request,
        selected_option_id="max-12884901888-min-3221225472",
        owner_ref=f"owner:{'e' * 64}",
        decided_at=datetime(2026, 8, 20, 8, 5, tzinfo=UTC),
    )
    store.write_resolution(resolution)
    return request.seal_sha256, resolution.seal_sha256


def _policy_payload(
    binding: dict[str, object],
    *,
    decision_id: str,
    request_seal: str,
    resolution_seal: str,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": "legalbot.completion-memory-policy.v2",
        "policy_id": "owner-memory-envelope-test",
        "candidate_build_id": "candidate-v111",
        "candidate_manifest_sha256": "a" * 64,
        "runtime_binding_sha256": binding["seal_sha256"],
        "integration_sha": "d" * 40,
        "measurement_schema": "legalbot.completion-memory-measurement.v2",
        "host_physical_memory_bytes": 16 * 1024**3,
        "max_peak_combined_working_set_bytes": 12 * 1024**3,
        "minimum_host_available_memory_bytes": 3 * 1024**3,
        "owner_decision_id": decision_id,
        "owner_decision_request_seal_sha256": request_seal,
        "owner_decision_resolution_seal_sha256": resolution_seal,
        "owner_selected_option_id": "max-12884901888-min-3221225472",
        "created_at": "2026-08-20T08:00:00+00:00",
    }
    payload["seal_sha256"] = sealed_sha256(payload)
    return payload


def test_missing_memory_policy_is_owner_decision_required(tmp_path: Path) -> None:
    binding = _binding()
    with pytest.raises(OwnerDecisionRequired) as caught:
        load_completion_memory_policy(
            tmp_path / "missing.json",
            owner_decision_root=tmp_path / "owner-decisions",
            candidate=_candidate(),
            runtime_binding=binding,
            integration_sha="d" * 40,
        )
    assert caught.value.reason_code == "completion_memory_policy_missing"
    assert str(caught.value) == "OWNER_DECISION_REQUIRED"


def test_memory_policy_requires_private_storage_and_exact_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "app.evaluation.candidate_completion_authority.host_physical_memory_bytes",
        lambda: 16 * 1024**3,
    )
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir(mode=0o700)
    decision_root = tmp_path / "owner-decisions"
    request_seal, resolution_seal = _owner_decision(decision_root, resolved=True)
    assert resolution_seal is not None
    decision_id = next(decision_root.iterdir()).name
    path = policy_dir / "memory.json"
    path.write_text(
        json.dumps(
            _policy_payload(
                _binding(),
                decision_id=decision_id,
                request_seal=request_seal,
                resolution_seal=resolution_seal,
            )
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    with pytest.raises(OwnerDecisionRequired) as caught:
        load_completion_memory_policy(
            path,
            owner_decision_root=decision_root,
            candidate=_candidate(),
            runtime_binding=_binding(),
            integration_sha="d" * 40,
        )
    assert caught.value.reason_code == "trusted_owner_memory_signature_verifier_missing"

    path.chmod(0o644)
    with pytest.raises(RuntimeError, match="storage_invalid"):
        load_completion_memory_policy(
            path,
            owner_decision_root=decision_root,
            candidate=_candidate(),
            runtime_binding=_binding(),
            integration_sha="d" * 40,
        )


def test_unresolved_memory_owner_decision_stops_before_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "app.evaluation.candidate_completion_authority.host_physical_memory_bytes",
        lambda: 16 * 1024**3,
    )
    decision_root = tmp_path / "owner-decisions"
    request_seal, _ = _owner_decision(decision_root, resolved=False)
    decision_id = next(decision_root.iterdir()).name
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir(mode=0o700)
    path = policy_dir / "memory.json"
    path.write_text(
        json.dumps(
            _policy_payload(
                _binding(),
                decision_id=decision_id,
                request_seal=request_seal,
                resolution_seal="f" * 64,
            )
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    with pytest.raises(OwnerDecisionRequired) as caught:
        load_completion_memory_policy(
            path,
            owner_decision_root=decision_root,
            candidate=_candidate(),
            runtime_binding=_binding(),
            integration_sha="d" * 40,
        )
    assert caught.value.reason_code == "completion_memory_owner_resolution_missing"


def test_memory_policy_materializer_requires_trusted_signature_then_binds_exact_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        completion_authority,
        "host_physical_memory_bytes",
        lambda: 16 * 1024**3,
    )
    decision_root = tmp_path / "owner-decisions"
    request_seal, resolution_seal = _owner_decision(decision_root, resolved=True)
    assert resolution_seal is not None
    destination = tmp_path / "policies" / "completion-memory-policy.json"
    settings = Settings(project_root=PROJECT_ROOT)
    with pytest.raises(OwnerDecisionRequired) as stopped:
        materialize_completion_memory_policy(
            settings=settings,
            destination=destination,
            owner_decision_root=decision_root,
            candidate=_candidate(),
            runtime_binding=_binding(),
            integration_sha="d" * 40,
            created_at=datetime(2026, 8, 20, 8, 10, tzinfo=UTC),
        )
    assert stopped.value.reason_code == "trusted_owner_memory_signature_verifier_missing"
    assert not destination.exists()

    monkeypatch.setattr(
        completion_authority,
        "_verify_trusted_owner_memory_signature",
        lambda _request, _resolution: None,
    )
    revalidated = False

    def revalidate(**_kwargs: object) -> None:
        nonlocal revalidated
        revalidated = True

    monkeypatch.setattr(
        completion_authority,
        "_require_current_completion_memory_materialization",
        revalidate,
    )
    monkeypatch.setattr(
        completion_authority,
        "require_exact_clean_head",
        lambda _root, expected: expected,
    )
    policy = materialize_completion_memory_policy(
        settings=settings,
        destination=destination,
        owner_decision_root=decision_root,
        candidate=_candidate(),
        runtime_binding=_binding(),
        integration_sha="d" * 40,
        created_at=datetime(2026, 8, 20, 8, 10, tzinfo=UTC),
    )
    assert destination.is_file()
    assert revalidated is True
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert policy.owner_decision_id.startswith("v111-completion-memory-")
    assert policy.owner_decision_request_seal_sha256 == request_seal
    assert policy.owner_decision_resolution_seal_sha256 == resolution_seal


def test_same_uid_external_loopback_listener_cannot_claim_launch() -> None:
    assert listener_belongs_to_launch(
        launched_pid=100,
        listener_pids=(102,),
        parent_by_pid={102: 101, 101: 100, 100: 1},
        nonce_matching_pids=frozenset({102}),
    )

    assert listener_endpoints_are_loopback(("127.0.0.1:8778", "[::1]:8778"), port=8778)
    assert not listener_endpoints_are_loopback(("*:8778",), port=8778)


def test_owned_sidecar_rss_sums_root_and_descendants_in_normalized_bytes() -> None:
    rows = (
        (100, 1, 10 * 1024),
        (101, 100, 20 * 1024),
        (102, 101, 30 * 1024),
        (200, 1, 999 * 1024),
    )
    assert (
        owned_process_tree_rss_bytes(
            launched_pid=100,
            rows=rows,
            nonce_matching_pids=frozenset({100, 101, 102}),
        )
        == 60 * 1024
    )
    with pytest.raises(RuntimeError, match="nonce_mismatch"):
        owned_process_tree_rss_bytes(
            launched_pid=100,
            rows=rows,
            nonce_matching_pids=frozenset({100, 101}),
        )
    assert not listener_belongs_to_launch(
        launched_pid=100,
        listener_pids=(202,),
        parent_by_pid={202: 1, 100: 1},
        nonce_matching_pids=frozenset({202}),
    )
    assert not listener_belongs_to_launch(
        launched_pid=100,
        listener_pids=(102,),
        parent_by_pid={102: 100, 100: 1},
        nonce_matching_pids=frozenset(),
    )


def test_self_sealed_launcher_claim_without_owned_proofs_is_refused() -> None:
    candidate = _candidate()
    payload = sealed_safe_payload(
        {
            "schema": LAUNCHER_START_SCHEMA,
            "run_id": "completion-fake-launcher",
            "candidate_build_id": candidate.build_id,
            "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
            "runtime_binding_sha256": "1" * 64,
            "integration_sha_start": "2" * 40,
            "trusted_model_identity_sha256": "3" * 64,
            "local_only": True,
            "public_traffic_allowed": False,
            "writes_active": False,
            "writes_o04": False,
            "real_catalogue_write_count": 0,
        }
    )
    with pytest.raises(RuntimeError, match="production_launcher_attestation_invalid"):
        verify_launcher_attestation(
            payload,
            schema=LAUNCHER_START_SCHEMA,
            run_id="completion-fake-launcher",
            candidate=candidate,
            runtime_binding_sha256="1" * 64,
            integration_sha="2" * 40,
            trusted_model_identity_sha256="3" * 64,
            installed_environment_manifest_sha256="4" * 64,
        )


def test_launcher_attestations_bind_installed_environment_and_candidate_tree() -> None:
    candidate = _candidate()
    runtime_binding_sha256 = "1" * 64
    integration_sha = "2" * 40
    model_sha256 = "3" * 64
    toolchain_sha256 = "4" * 64
    environment_sha256 = "5" * 64
    base_runtime_sha256 = "6" * 64
    venv_sha256 = "7" * 64
    tree_sha256 = "8" * 64
    outbox_sha256 = "9" * 64
    launcher_sha256 = "a" * 64
    common = {
        "run_id": "completion-attestation-bindings",
        "candidate_build_id": candidate.build_id,
        "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
        "runtime_binding_sha256": runtime_binding_sha256,
        "local_only": True,
        "public_traffic_allowed": False,
        "writes_active": False,
        "writes_o04": False,
        "real_catalogue_write_count": 0,
    }
    start = sealed_safe_payload(
        {
            **common,
            "schema": LAUNCHER_START_SCHEMA,
            "integration_sha_start": integration_sha,
            "launcher_implementation_sha256": launcher_sha256,
            "trusted_model_identity_sha256": model_sha256,
            "trusted_toolchain_identity_sha256": toolchain_sha256,
            "installed_environment_manifest_sha256": environment_sha256,
            "base_python_runtime_manifest_sha256": base_runtime_sha256,
            "venv_control_manifest_sha256": venv_sha256,
            "real_catalogue_data_version_start": 7,
            "real_catalogue_outbox_sha256_start": outbox_sha256,
            "active_pointer_present_start": False,
            "active_pointer_sha256_start": None,
            "candidate_copy_on_write": True,
            "candidate_copy_read_only": True,
            "isolated_candidate_tree_sha256": tree_sha256,
            "isolated_candidate_reverified_before_launch": True,
            "evaluation_database_isolated": True,
            "runtime_objects_isolated": True,
            "retrieval_candidate_pinned": True,
            "model_artifact_rehashed_before_launch": True,
            "model_toolchain_rehashed_before_launch": True,
            "base_python_runtime_rehashed_before_launch": True,
            "venv_control_rehashed_before_launch": True,
            "offline_locked_no_sync_launch": True,
            "child_environment_sanitized": True,
            "direct_verified_venv_python_launch": True,
        }
    )
    verified_start = verify_launcher_attestation(
        start,
        schema=LAUNCHER_START_SCHEMA,
        run_id="completion-attestation-bindings",
        candidate=candidate,
        runtime_binding_sha256=runtime_binding_sha256,
        integration_sha=integration_sha,
        trusted_model_identity_sha256=model_sha256,
        trusted_toolchain_identity_sha256=toolchain_sha256,
        installed_environment_manifest_sha256=environment_sha256,
        base_python_runtime_manifest_sha256=base_runtime_sha256,
        venv_control_manifest_sha256=venv_sha256,
        launcher_implementation_sha256=launcher_sha256,
    )
    end = sealed_safe_payload(
        {
            **common,
            "schema": completion_authority.LAUNCHER_END_SCHEMA,
            "integration_sha_start": integration_sha,
            "integration_sha_end": integration_sha,
            "git_sha_unchanged": True,
            "git_worktree_clean_start_end": True,
            "real_catalogue_data_version_start": 7,
            "real_catalogue_data_version_end": 7,
            "real_catalogue_outbox_sha256_start": outbox_sha256,
            "real_catalogue_outbox_sha256_end": outbox_sha256,
            "real_catalogue_unchanged": True,
            "candidate_unchanged": True,
            "isolated_candidate_tree_sha256_start": tree_sha256,
            "isolated_candidate_tree_sha256_end": tree_sha256,
            "isolated_candidate_tree_unchanged": True,
            "isolated_candidate_reverified_after_run": True,
            "active_pointer_present_start": False,
            "active_pointer_present_end": False,
            "active_pointer_sha256_start": None,
            "active_pointer_sha256_end": None,
            "active_pointer_unchanged": True,
            "evaluation_database_isolated": True,
            "runtime_objects_isolated": True,
            "model_artifact_rehashed_after_run": True,
            "trusted_model_identity_sha256": model_sha256,
            "trusted_toolchain_identity_sha256": toolchain_sha256,
            "installed_environment_manifest_sha256": environment_sha256,
            "base_python_runtime_manifest_sha256": base_runtime_sha256,
            "base_python_runtime_rehashed_after_run": True,
            "venv_control_manifest_sha256": venv_sha256,
            "venv_control_rehashed_after_run": True,
            "model_toolchain_rehashed_after_run": True,
        }
    )
    verify_launcher_attestation(
        end,
        schema=completion_authority.LAUNCHER_END_SCHEMA,
        run_id="completion-attestation-bindings",
        candidate=candidate,
        runtime_binding_sha256=runtime_binding_sha256,
        integration_sha=integration_sha,
        trusted_model_identity_sha256=model_sha256,
        trusted_toolchain_identity_sha256=toolchain_sha256,
        installed_environment_manifest_sha256=environment_sha256,
        base_python_runtime_manifest_sha256=base_runtime_sha256,
        venv_control_manifest_sha256=venv_sha256,
        verified_start_attestation=verified_start,
    )

    bad_start = sealed_safe_payload(
        {
            **{key: value for key, value in start.items() if key != "seal_sha256"},
            "installed_environment_manifest_sha256": "f" * 64,
        }
    )
    with pytest.raises(RuntimeError, match="production_launcher_attestation_invalid"):
        verify_launcher_attestation(
            bad_start,
            schema=LAUNCHER_START_SCHEMA,
            run_id="completion-attestation-bindings",
            candidate=candidate,
            runtime_binding_sha256=runtime_binding_sha256,
            integration_sha=integration_sha,
            trusted_model_identity_sha256=model_sha256,
            trusted_toolchain_identity_sha256=toolchain_sha256,
            installed_environment_manifest_sha256=environment_sha256,
            base_python_runtime_manifest_sha256=base_runtime_sha256,
            venv_control_manifest_sha256=venv_sha256,
            launcher_implementation_sha256=launcher_sha256,
        )

    bad_end = sealed_safe_payload(
        {
            **{key: value for key, value in end.items() if key != "seal_sha256"},
            "isolated_candidate_tree_sha256_start": "f" * 64,
            "isolated_candidate_tree_sha256_end": "f" * 64,
        }
    )
    with pytest.raises(RuntimeError, match="production_launcher_attestation_invalid"):
        verify_launcher_attestation(
            bad_end,
            schema=completion_authority.LAUNCHER_END_SCHEMA,
            run_id="completion-attestation-bindings",
            candidate=candidate,
            runtime_binding_sha256=runtime_binding_sha256,
            integration_sha=integration_sha,
            trusted_model_identity_sha256=model_sha256,
            trusted_toolchain_identity_sha256=toolchain_sha256,
            installed_environment_manifest_sha256=environment_sha256,
            base_python_runtime_manifest_sha256=base_runtime_sha256,
            venv_control_manifest_sha256=venv_sha256,
            verified_start_attestation=verified_start,
        )


def test_evaluation_database_backup_cannot_mutate_real_catalogue(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    (data / ".catalog-initialize.lock").touch(mode=0o600)
    real_path = data / "catalog.sqlite3"
    connection = sqlite3.connect(real_path)
    connection.executescript(
        """
        CREATE TABLE marker(id INTEGER PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO marker(value) VALUES ('original');
        CREATE TABLE release_outbox(
          id TEXT, job_id TEXT, answer_id TEXT, release_state TEXT,
          idempotency_key TEXT, status TEXT, created_at TEXT, published_at TEXT
        );
        """
    )
    connection.commit()
    connection.close()
    real_path.chmod(0o600)

    real = open_existing_catalogue_read_database(real_path)
    try:
        start_version = int(real.fetchone("PRAGMA data_version")[0])  # type: ignore[index]
        evaluation_path = tmp_path / "private/evaluation.sqlite3"
        _sqlite_backup_create_only(real, evaluation_path)
        evaluation = sqlite3.connect(evaluation_path)
        evaluation.execute("INSERT INTO marker(value) VALUES ('evaluation-only')")
        evaluation.commit()
        evaluation.close()

        assert real.fetchone("SELECT COUNT(*) FROM marker")[0] == 1  # type: ignore[index]
        assert real.fetchone("SELECT value FROM marker")[0] == "original"  # type: ignore[index]
        assert int(real.fetchone("PRAGMA data_version")[0]) == start_version  # type: ignore[index]
        assert real.total_changes() == 0
        assert oct(os.stat(evaluation_path).st_mode & 0o777) == "0o600"
    finally:
        real.close()


def test_trusted_model_identity_is_tracked_and_self_sealed() -> None:
    identity = load_trusted_model_identity(PROJECT_ROOT)
    assert identity["model_id"] == PINNED_RUNTIME_REPO
    assert identity["model_revision"] == PINNED_RUNTIME_REVISION
    assert (
        identity["seal_sha256"]
        == "4bb625aeb1ad76cf1a15508c339a421402b0f6fbf5363b8593668fa38a71bf05"
    )
    assert len(str(identity["tracked_identity_file_sha256"])) == 64


def test_trusted_toolchain_refuses_path_shadow_and_environment_poisoning(
    tmp_path: Path,
) -> None:
    shadow = tmp_path / "uv"
    shadow.write_bytes(b"not-the-tracked-uv")
    shadow.chmod(0o700)
    with pytest.raises(RuntimeError, match="trusted_uv_executable_mismatch"):
        trusted_model_toolchain_binding(
            PROJECT_ROOT,
            ambient_environment={"PATH": str(tmp_path)},
        )

    real_uv = shutil.which("uv")
    assert real_uv is not None
    with pytest.raises(RuntimeError, match="model_launch_environment_poisoned"):
        trusted_model_toolchain_binding(
            PROJECT_ROOT,
            ambient_environment={
                "PATH": str(Path(real_uv).parent),
                "UV_PROJECT": str(tmp_path / "attacker-project"),
            },
        )
    with pytest.raises(RuntimeError, match="model_launch_environment_poisoned"):
        trusted_model_toolchain_binding(
            PROJECT_ROOT,
            ambient_environment={
                "PATH": str(Path(real_uv).parent),
                "PYTHONHOME": str(tmp_path / "attacker-python"),
            },
        )


def test_authority_helpers_ignore_path_shadow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("git", "ps", "vm_stat", "sysctl", "lsof", "cp"):
        fake = tmp_path / name
        fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert trusted_system_tool("git", project_root=PROJECT_ROOT) == Path("/usr/bin/git")
    assert trusted_system_tool("ps", project_root=PROJECT_ROOT) == Path("/bin/ps")
    assert trusted_system_tool("vm_stat", project_root=PROJECT_ROOT) == Path("/usr/bin/vm_stat")


def test_sanitized_launch_environment_inherits_no_path_or_proxy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert completion_authority._LAUNCH_ENVIRONMENT_POLICY["execution_mediator"] == (
        "none_direct_verified_venv_python"
    )
    assert completion_authority._LAUNCH_ENVIRONMENT_POLICY["uv_used_for_launch"] is False
    assert completion_authority._LAUNCH_ENVIRONMENT_POLICY["uv_flags"] == []
    entrypoint = tmp_path / "backend/app/model_runtime/__main__.py"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.write_text("raise SystemExit(0)\n", encoding="utf-8")
    values = {
        "LEGALBOT_MODEL_MODE": "mlx",
        "LEGALBOT_MODEL_HOST": "127.0.0.1",
        "LEGALBOT_MODEL_PORT": "8778",
        "LEGALBOT_MODEL_ID": PINNED_RUNTIME_REPO,
        "LEGALBOT_MODEL_REVISION": PINNED_RUNTIME_REVISION,
        "LEGALBOT_MODEL_PATH": str(tmp_path / "model"),
        "LEGALBOT_MODEL_CONTEXT_TOKENS": "8192",
        "LEGALBOT_MODEL_MAX_OUTPUT_TOKENS": "2048",
        "LEGALBOT_MODEL_PREFILL_STEP_SIZE": "512",
        "LEGALBOT_MODEL_KV_BITS": "8",
        "LEGALBOT_MODEL_KV_GROUP_SIZE": "64",
        "LEGALBOT_MODEL_CLEAR_CACHE": "true",
    }
    environment = sanitized_model_launch_environment(
        project_root=tmp_path,
        private_pycache_root=tmp_path / "private-pycache",
        launch_nonce="a" * 64,
        values=values,
    )
    assert environment["UV_OFFLINE"] == "1"
    assert environment["UV_LOCKED"] == "1"
    assert environment["UV_NO_SYNC"] == "1"
    assert (
        not {
            "PATH",
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONUSERBASE",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
        }
        & environment.keys()
    )

    attacker_cwd = tmp_path / "attacker-cwd"
    attacker_cwd.mkdir()
    marker = tmp_path / "sitecustomize-executed"
    (attacker_cwd / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
        encoding="utf-8",
    )
    user_site = tmp_path / "attacker-userbase/lib/python3.13/site-packages"
    user_site.mkdir(parents=True)
    (user_site / "usercustomize.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONUSERBASE", str(tmp_path / "attacker-userbase"))
    private_pycache_root = tmp_path / "private-pycache"
    arguments = isolated_model_python_arguments(
        tmp_path,
        private_pycache_root=private_pycache_root,
    )
    assert arguments[3:5] == (
        "-X",
        f"pycache_prefix={private_pycache_root}",
    )
    completed = subprocess.run(
        [
            str(Path(PROJECT_ROOT / "model-runtime/.venv/bin/python").resolve()),
            *arguments[:5],
            "-v",
            "-c",
            (
                "import encodings.cp500,site,sys;"
                "assert not site.ENABLE_USER_SITE;"
                "assert '' not in sys.path"
            ),
        ],
        cwd=attacker_cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert not marker.exists()
    assert "__pycache__/cp500.cpython-313.pyc" not in completed.stderr
    assert "encodings/cp500.py" in completed.stderr


def test_installed_dependency_bytes_must_match_wheel_record(tmp_path: Path) -> None:
    environment = tmp_path / ".venv"
    site = environment / "lib/python3.13/site-packages"
    package = site / "example_runtime"
    dist_info = site / "example_runtime-1.2.3.dist-info"
    package.mkdir(parents=True)
    dist_info.mkdir()
    source = package / "__init__.py"
    source.write_bytes(b"VALUE = 1\n")
    metadata = dist_info / "METADATA"
    metadata.write_text("Name: example-runtime\nVersion: 1.2.3\n", encoding="utf-8")

    def record_value(path: Path) -> str:
        raw = hashlib.sha256(path.read_bytes()).digest()
        encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        return f"sha256={encoded},{path.stat().st_size}"

    record = dist_info / "RECORD"
    record.write_text(
        "\n".join(
            (
                f"example_runtime/__init__.py,{record_value(source)}",
                f"example_runtime-1.2.3.dist-info/METADATA,{record_value(metadata)}",
                "example_runtime-1.2.3.dist-info/RECORD,,",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    packages, manifest = _installed_package_inventory(environment)
    assert packages == [{"name": "example-runtime", "version": "1.2.3"}]
    assert len(manifest) == 64

    source.write_bytes(b"VALUE = 'poisoned'\n")
    with pytest.raises(RuntimeError, match="model_runtime_installed_file_mismatch"):
        _installed_package_inventory(environment)
    source.write_bytes(b"VALUE = 1\n")
    pycache = package / "__pycache__"
    pycache.mkdir()
    (pycache / "__init__.cpython-313.pyc").write_bytes(b"attacker-bytecode")
    with pytest.raises(RuntimeError, match="model_runtime_executable_bytecode_refused"):
        _installed_package_inventory(environment)


def test_trusted_toolchain_identity_pins_installed_bytes() -> None:
    identity = load_trusted_toolchain_identity(PROJECT_ROOT)
    assert identity["seal_sha256"] == (
        "31c0b7c74f33c547197856a8bc13fd771a4263210b3be6ce7496f5a4b4105106"
    )
    assert identity["installed_environment_manifest_sha256"] == (
        "a765cd262190804a7292d9ef1f8b8837d4b60fc3e05990baef1ea4efd65714c2"
    )
    assert identity["base_python_runtime_manifest_sha256"] == (
        "943303f0a13f4ea02df3d99040e7b839bfbb0b68ab77aa335062dec8b606b272"
    )
    assert identity["venv_control_manifest_sha256"] == (
        "ab51e64e135db0f71c7602bcf6255bf2022a64fd370d199c89e902a5001f9739"
    )


def test_venv_control_refuses_system_site_flip_and_launcher_relink(tmp_path: Path) -> None:
    base_python = tmp_path / "base/bin/python3.13"
    base_python.parent.mkdir(parents=True)
    base_python.write_bytes(b"trusted-python")
    environment = tmp_path / ".venv"
    (environment / "bin").mkdir(parents=True)
    config = environment / "pyvenv.cfg"

    def write_config(*, include_system: str) -> None:
        config.write_text(
            "\n".join(
                (
                    f"home = {base_python.parent}",
                    "implementation = CPython",
                    "uv = 0.9.7",
                    "version_info = 3.13.7",
                    f"include-system-site-packages = {include_system}",
                    "prompt = legalbot-model-runtime",
                )
            )
            + "\n",
            encoding="utf-8",
        )

    write_config(include_system="false")
    (environment / "bin/python").symlink_to(base_python)
    (environment / "bin/python3").symlink_to("python")
    (environment / "bin/python3.13").symlink_to("python")
    launcher, initial = _venv_control_manifest(
        environment,
        expected_base_python=base_python,
        expected_python_version="3.13.7",
        expected_uv_version="uv 0.9.7 (test)",
    )
    assert launcher == environment / "bin/python"
    assert len(initial) == 64

    write_config(include_system="true")
    with pytest.raises(RuntimeError, match="model_runtime_venv_control_invalid"):
        _venv_control_manifest(
            environment,
            expected_base_python=base_python,
            expected_python_version="3.13.7",
            expected_uv_version="uv 0.9.7 (test)",
        )
    write_config(include_system="false")
    (environment / "bin/python3").unlink()
    (environment / "bin/python3").symlink_to(base_python.parent / "other-python")
    with pytest.raises(RuntimeError, match="model_runtime_venv_launcher_invalid"):
        _venv_control_manifest(
            environment,
            expected_base_python=base_python,
            expected_python_version="3.13.7",
            expected_uv_version="uv 0.9.7 (test)",
        )


def test_base_python_runtime_manifest_detects_stdlib_mutation(tmp_path: Path) -> None:
    runtime = tmp_path / "Python.framework/Versions/3.13"
    (runtime / "bin").mkdir(parents=True)
    (runtime / "_CodeSignature").mkdir()
    (runtime / "lib/python3.13").mkdir(parents=True)
    (runtime / "Frameworks/Tcl.framework").mkdir(parents=True)
    (runtime / "Python").write_bytes(b"framework-runtime")
    (runtime / "bin/python3.13").write_bytes(b"launcher")
    (runtime / "_CodeSignature/CodeResources").write_bytes(b"signature")
    site = runtime / "lib/python3.13/site.py"
    site.write_bytes(b"ENABLE_USER_SITE = False\n")
    (runtime / "lib/libssl.3.dylib").write_bytes(b"ssl-runtime")
    (runtime / "Frameworks/Tcl.framework/Tcl").write_bytes(b"tcl-runtime")

    initial = _base_python_runtime_manifest(runtime)
    import_zip = runtime / "lib/python313.zip"
    import_zip.write_bytes(b"malicious import shadow")
    assert _base_python_runtime_manifest(runtime) != initial
    import_zip.unlink()
    site.write_bytes(b"ENABLE_USER_SITE = True\n")
    assert _base_python_runtime_manifest(runtime) != initial
    (runtime / "lib/python3.13/shadow.pyc").write_bytes(b"sourceless attacker bytecode")
    with pytest.raises(RuntimeError, match="base_python_runtime_executable_bytecode_refused"):
        _base_python_runtime_manifest(runtime)


def test_isolated_candidate_tree_mutation_is_detected(tmp_path: Path) -> None:
    tree = tmp_path / "builds"
    candidate = tree / "candidate-v111"
    candidate.mkdir(parents=True)
    vector = candidate / "vectors.bin"
    vector.write_bytes(b"sealed-vector-bytes")
    vector.chmod(0o400)
    candidate.chmod(0o500)
    tree.chmod(0o500)
    initial = candidate_tree_sha256(tree)
    assert len(initial) == 64

    tree.chmod(0o700)
    candidate.chmod(0o700)
    vector.chmod(0o600)
    vector.write_bytes(b"mutated-vector-bytes")
    vector.chmod(0o400)
    candidate.chmod(0o500)
    tree.chmod(0o500)
    assert candidate_tree_sha256(tree) != initial


def test_memory_sampler_uses_one_snapshot_and_one_headroom_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"snapshot": 0, "headroom": 0}

    def snapshot(
        *, nonce: str, ps_path: Path
    ) -> tuple[tuple[tuple[int, int, int], ...], frozenset[int]]:
        del nonce, ps_path
        calls["snapshot"] += 1
        return (((os.getpid(), 1, 100), (999, os.getpid(), 200)), frozenset({999}))

    def headroom(*, vm_stat_path: Path | None = None) -> int:
        del vm_stat_path
        calls["headroom"] += 1
        return 1_000

    monkeypatch.setattr(completion_authority, "_process_memory_snapshot", snapshot)
    monkeypatch.setattr(completion_authority, "host_available_memory_bytes", headroom)
    sampler = WorkflowMemorySampler(
        owned_sidecar_pid=999,
        launch_nonce="a" * 64,
        system_tools={"ps": Path("/bin/ps"), "vm_stat": Path("/usr/bin/vm_stat")},
    )
    sampler.sample()
    assert calls == {"snapshot": 1, "headroom": 1}
    assert sampler.peak_combined_working_set_bytes == 300


@pytest.mark.asyncio
async def test_memory_sampling_work_does_not_block_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sampler = WorkflowMemorySampler(
        owned_sidecar_pid=999,
        launch_nonce="a" * 64,
        system_tools={"ps": Path("/bin/ps"), "vm_stat": Path("/usr/bin/vm_stat")},
    )

    def slow_sample() -> None:
        import time

        time.sleep(0.05)

    monkeypatch.setattr(sampler, "sample", slow_sample)
    task = asyncio.create_task(sampler.run())
    heartbeat = 0
    for _ in range(5):
        await asyncio.sleep(0.005)
        heartbeat += 1
    sampler.stop()
    await task
    assert heartbeat == 5
