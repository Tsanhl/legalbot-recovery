from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from app.config import Settings
from app.db import Database
from app.evaluation import v111_technical_attestation as technical
from app.evaluation import v111_technical_attestation_admission as admission
from app.evaluation.live_suite import sealed_sha256
from app.evaluation.live_suite_stage_a_v2_runner import (
    STAGE_A_RUNNER_POLICY_SHA256,
    STAGE_A_SCORER_IDENTITY_SHA256,
)
from app.evaluation.nonrelease_artifacts import sealed_safe_payload
from app.evaluation.sealed_candidate import SealedCandidateIdentity

_SHA = "a" * 64
_INTEGRATION = "b" * 40
_BUNDLE_SEAL = "7" * 64


def _candidate() -> SealedCandidateIdentity:
    return SealedCandidateIdentity(
        build_id="candidate-v111",
        status="candidate",
        candidate_manifest_sha256="1" * 64,
        candidate_seal_sha256="2" * 64,
        source_manifest_sha256="3" * 64,
        embedding_model="embedding-model-v1",
        reranker_model="reranker-model-v1",
        document_count=85,
        chunk_count=149_855,
        vector_count=149_855,
    )


def _sealed(schema: str, **values: Any) -> dict[str, Any]:
    return sealed_safe_payload({"schema": schema, **values})


def _context(
    candidate: SealedCandidateIdentity,
    *,
    integration_sha: str = _INTEGRATION,
    scorer_marker: str = "stage-a-current",
    pointer_marker: str = "pointer-current",
) -> technical._Context:
    stage_a = _sealed(
        technical.TECHNICAL_STAGE_A_SCHEMA,
        marker=scorer_marker,
        scorer_identity_sha256=STAGE_A_SCORER_IDENTITY_SHA256,
        suite_manifest_seal_sha256=_BUNDLE_SEAL,
        result_seal_sha256="d" * 64,
        completion_preflight_verified_result_sha256=_SHA,
    )
    toolchain_binding = _sealed(
        "legalbot.v111-technical-toolchain.v1",
        marker="toolchain-current",
    )
    lock_binding = _sealed(
        "legalbot.v111-technical-lock-set.v1",
        marker="locks-current",
    )
    state_binding = _sealed(
        "legalbot.v111-candidate-active-catalogue-state.v1",
        marker=pointer_marker,
        active_pointer={
            "pointer_id": "active",
            "state": "present",
            "build_id": "prior-active-v111",
            "manifest_sha256": "8" * 64,
            "pointer_sha256": "9" * 64,
        },
        previous_pointer={"pointer_id": "previous", "state": "missing"},
        catalogue_active_build_id="prior-active-v111",
    )
    rollback_binding = _sealed(
        technical.TECHNICAL_ROLLBACK_SCHEMA,
        marker=f"rollback-{pointer_marker}",
    )
    return technical._Context(
        integration_sha=integration_sha,
        candidate_binding=candidate.safe_dict(),
        stage_a_binding=stage_a,
        toolchain=technical._Toolchain(
            uv=Path("/fixed/uv"),
            node=Path("/fixed/node"),
            npm_cli=Path("/fixed/npm-cli.js"),
            sandbox_exec=Path("/fixed/sandbox-exec"),
            git=Path("/fixed/git"),
            binding=toolchain_binding,
        ),
        lock_binding=lock_binding,
        state_binding=state_binding,
        rollback_binding=rollback_binding,
    )


def _stage_a() -> technical.StageAReplayInputs:
    return technical.StageAReplayInputs(
        output_root=Path("stage-a-v2"),
        run_id="stage-a-test",
        bundle=cast(Any, object()),
        all60_qualification=cast(Any, object()),
        expert_qualification=cast(Any, object()),
        as_of_date=cast(Any, object()),
        completion_preflight_verified_result_sha256=_SHA,
    )


def _passing_semantics(check_id: str) -> dict[str, int]:
    outputs: dict[str, bytes] = {
        "python_full_suite": b"================ 2 passed, 1 skipped in 1.00s ================\n",
        "python_ruff": b"All checks passed!\n",
        "python_ruff_format": b"321 files already formatted\n",
        "python_static_baseline": json.dumps(
            {
                "ruff_error_count": 1,
                "mypy_error_count": 2,
                "mypy_file_count": 1,
                "baseline": {
                    "ruff": {"max_error_count": 14},
                    "mypy": {"max_error_count": 14, "max_file_count": 6},
                },
            }
        ).encode(),
        "workflow_security": b"workflow security scan passed\n",
        "clean_room": b"Clean-room check passed: exact policy\n",
        "live60_verify": ("7" * 64 + "\n").encode(),
        "web_clean_install": b"added 245 packages in 2s\n",
        "web_lint": b"> legalbot-new-web@0.1.0 lint\n> eslint .\n",
        "web_test": b"> legalbot-new-web@0.1.0 test\n# tests 2\n# pass 2\n# fail 0\n",
        "web_build": "> legalbot-new-web@0.1.0 build\n✓ built in 1s\n".encode(),
        "web_audit": json.dumps(
            {
                "metadata": {
                    "vulnerabilities": {
                        "critical": 0,
                        "high": 0,
                        "moderate": 0,
                        "low": 0,
                        "info": 0,
                        "total": 0,
                    }
                }
            }
        ).encode(),
        "repository_secret_scan": json.dumps(
            {
                "finding_count": 0,
                "scanned_byte_count": 100,
                "scanned_member_count": 5,
            }
        ).encode(),
        "repository_diff_check": b"",
    }
    return technical._semantic_counts(check_id, outputs[check_id], b"")


def _observation(
    check_id: str,
    exit_code: int = 0,
    *,
    semantic_counts: dict[str, int] | None = None,
) -> technical._ExecutionObservation:
    stdout_sha256 = "5" * 64
    if check_id == "live60_verify":
        stdout_sha256 = hashlib.sha256(f"{_BUNDLE_SEAL}\n".encode()).hexdigest()
    return technical._ExecutionObservation(
        exit_code=exit_code,
        stdout_sha256=stdout_sha256,
        stderr_sha256="6" * 64,
        stdout_byte_count=0 if check_id == "repository_diff_check" else 13,
        stderr_byte_count=0,
        stdout_line_count=0 if check_id == "repository_diff_check" else 1,
        stderr_line_count=0,
        semantic_counts=semantic_counts or _passing_semantics(check_id),
    )


def _settings(tmp_path: Path) -> Settings:
    return Settings(project_root=tmp_path)


def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    exit_codes: dict[str, int] | None = None,
    semantic_overrides: dict[str, dict[str, int]] | None = None,
    replay_context: technical._Context | None = None,
    database_override: object | None = None,
) -> tuple[
    technical.CompletedV111TechnicalRun,
    Settings,
    SealedCandidateIdentity,
    technical.StageAReplayInputs,
    object,
]:
    candidate = _candidate()
    stage_a = _stage_a()
    settings = _settings(tmp_path)
    database = database_override or object()
    initial = _context(candidate)
    contexts = [initial, initial, replay_context or initial, initial, initial]

    def capture(**_: object) -> technical._Context:
        return contexts.pop(0) if contexts else initial

    failures = exit_codes or {}
    overridden_semantics = semantic_overrides or {}

    def execute(**kwargs: object) -> technical._ExecutionObservation:
        spec = cast(technical._CheckSpec, kwargs["spec"])
        return _observation(
            spec.check_id,
            failures.get(spec.check_id, 0),
            semantic_counts=overridden_semantics.get(spec.check_id),
        )

    monkeypatch.setattr(technical, "_capture_context", capture)
    monkeypatch.setattr(technical, "_execute_check", execute)
    completed = technical.run_v111_technical_attestation_create_only(
        run_id="technical-run-001",
        settings=settings,
        database=cast(Any, database),
        candidate=candidate,
        stage_a=stage_a,
        expected_integration_sha=_INTEGRATION,
    )
    return completed, settings, candidate, stage_a, database


def _load(
    completed: object,
    *,
    settings: Settings,
    candidate: SealedCandidateIdentity,
    stage_a: technical.StageAReplayInputs,
    database: object,
) -> technical.VerifiedV111TechnicalAttestation:
    return technical.load_verified_v111_technical_attestation(
        completed,
        settings=settings,
        database=cast(Any, database),
        candidate=candidate,
        stage_a=stage_a,
        expected_integration_sha=_INTEGRATION,
    )


def _rewrite_sealed(member: Path, mutate: Any) -> None:
    payload = json.loads(member.read_text(encoding="utf-8"))
    payload.pop("seal_sha256")
    mutate(payload)
    member.write_text(
        json.dumps(sealed_safe_payload(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    member.chmod(0o600)


def test_strict_loader_issues_opaque_capability_for_exact_live_matrix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    completed, settings, candidate, stage_a, database = _run(monkeypatch, tmp_path)

    verified = _load(
        completed,
        settings=settings,
        candidate=candidate,
        stage_a=stage_a,
        database=database,
    )

    assert technical.require_verified_v111_technical_attestation(verified) is verified
    assert verified.integration_sha == _INTEGRATION
    assert verified.candidate_build_id == candidate.build_id
    assert verified.attestation["outcome_count"] == 14
    assert set(verified.run_directory.iterdir()) == {
        verified.run_directory / "run-manifest.json",
        verified.run_directory / "stage-a-scorer-reattestation.json",
        verified.run_directory / "rollback-plan-readiness.json",
        verified.run_directory / "final-attestation.json",
        verified.run_directory / "intents",
        verified.run_directory / "outcomes",
    }
    assert not any("stdout" in member.name for member in verified.run_directory.rglob("*"))
    assert os.stat(verified.run_directory).st_mode & 0o077 == 0


def test_forged_exit_zero_cannot_replace_live_nonzero_outcome(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    completed, settings, candidate, stage_a, database = _run(
        monkeypatch,
        tmp_path,
        exit_codes={"python_full_suite": 1},
    )
    outcome = completed._run_root / "outcomes/01-python_full_suite.json"
    _rewrite_sealed(outcome, lambda payload: payload.__setitem__("exit_code", 0))

    with pytest.raises(ValueError, match="differs from live execution"):
        _load(
            completed,
            settings=settings,
            candidate=candidate,
            stage_a=stage_a,
            database=database,
        )


def test_omitted_check_is_not_a_complete_matrix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    completed, settings, candidate, stage_a, database = _run(monkeypatch, tmp_path)
    (completed._run_root / "outcomes/12-web_audit.json").unlink()

    with pytest.raises(ValueError, match="inventory is not exact"):
        _load(
            completed,
            settings=settings,
            candidate=candidate,
            stage_a=stage_a,
            database=database,
        )


@pytest.mark.parametrize(
    ("check_id", "semantic_counts"),
    [
        (
            "python_full_suite",
            {
                "passed": 30,
                "failed": 0,
                "skipped": 0,
                "xfailed": 0,
                "xpassed": 0,
                "errors": 0,
                "summary_match_count": 0,
            },
        ),
        ("web_audit", {"audit_json_invalid": 1}),
    ],
)
def test_exit_zero_with_malformed_semantic_result_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    check_id: str,
    semantic_counts: dict[str, int],
) -> None:
    completed, settings, candidate, stage_a, database = _run(
        monkeypatch,
        tmp_path,
        semantic_overrides={check_id: semantic_counts},
    )
    with pytest.raises(ValueError, match="semantic result"):
        _load(
            completed,
            settings=settings,
            candidate=candidate,
            stage_a=stage_a,
            database=database,
        )


@pytest.mark.parametrize(
    "stdout",
    [
        b"================ 2 passed, 1 error in 1.00s ================\n",
        b"================ 2 passed, 1 errors in 1.00s ================\n",
        b"================ 2 passed, 3 passed in 1.00s ================\n",
    ],
)
def test_pytest_summary_rejects_errors_and_duplicate_result_tokens(stdout: bytes) -> None:
    counts = technical._semantic_counts("python_full_suite", stdout, b"")
    with pytest.raises(ValueError, match="semantic result"):
        technical._require_semantic_pass(
            check_id="python_full_suite",
            counts=counts,
            outcome={},
        )


@pytest.mark.parametrize(
    "vulnerabilities",
    [
        {},
        {"critical": 0, "high": 0, "moderate": 0, "low": 0, "info": 0},
        {"critical": 0, "high": 0, "moderate": 1, "low": 0, "info": 0, "total": 0},
    ],
)
def test_npm_audit_requires_complete_consistent_canonical_counts(
    vulnerabilities: dict[str, int],
) -> None:
    stdout = json.dumps({"metadata": {"vulnerabilities": vulnerabilities}}).encode()
    counts = technical._semantic_counts("web_audit", stdout, b"")
    with pytest.raises(ValueError, match="semantic result"):
        technical._require_semantic_pass(check_id="web_audit", counts=counts, outcome={})


def test_resealed_command_substitution_is_not_a_fixed_intent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    completed, settings, candidate, stage_a, database = _run(monkeypatch, tmp_path)
    intent = completed._run_root / "intents/02-python_ruff.json"

    def inject(payload: dict[str, Any]) -> None:
        payload["check_contract"]["arguments"] = ["$(touch technical-bypass)"]

    _rewrite_sealed(intent, inject)
    with pytest.raises(ValueError, match="fixed command"):
        _load(
            completed,
            settings=settings,
            candidate=candidate,
            stage_a=stage_a,
            database=database,
        )


@pytest.mark.parametrize(
    ("changed", "message"),
    [
        (_context(_candidate(), integration_sha="c" * 40), "integration context changed"),
        (_context(_candidate(), scorer_marker="forged-scorer"), "integration context changed"),
        (_context(_candidate(), pointer_marker="mutated-pointer"), "integration context changed"),
    ],
)
def test_changed_integration_scorer_or_pointer_fails_current_replay(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    changed: technical._Context,
    message: str,
) -> None:
    completed, settings, candidate, stage_a, database = _run(
        monkeypatch, tmp_path, replay_context=changed
    )
    with pytest.raises(ValueError, match=message):
        _load(
            completed,
            settings=settings,
            candidate=candidate,
            stage_a=stage_a,
            database=database,
        )


def test_favorable_self_seal_or_direct_constructor_is_not_authority(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    favorable = sealed_safe_payload(
        {
            "schema": technical.TECHNICAL_FINAL_SCHEMA,
            "terminal_state": "matrix_completed",
            "outcome_count": 14,
        }
    )
    with pytest.raises(TypeError, match="live_runner_capability"):
        technical.load_verified_v111_technical_attestation(
            favorable,
            settings=_settings(tmp_path),
            database=cast(Any, object()),
            candidate=_candidate(),
            stage_a=_stage_a(),
            expected_integration_sha=_INTEGRATION,
        )
    with pytest.raises(TypeError, match="strict_loader"):
        technical.VerifiedV111TechnicalAttestation(
            run_root=tmp_path,
            attestation=favorable,
            _token=object(),
        )
    with pytest.raises(TypeError, match="capability_not_loader_verified"):
        technical.require_verified_v111_technical_attestation(favorable)


def test_technical_run_id_cannot_create_an_unreferenceable_colon_path(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="run ID is invalid"):
        technical._expected_run_root(_settings(tmp_path), "technical:run:001")


def test_external_command_uses_fixed_sandbox_no_shell_or_ambient_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    candidate = _candidate()
    context = _context(candidate)
    observed: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> Any:
        observed["argv"] = argv
        observed.update(kwargs)
        return type(
            "Completed",
            (),
            {"returncode": 0, "stdout": b"1 passed\n", "stderr": b""},
        )()

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setenv("HTTP_PROXY", "http://attacker.invalid")
    monkeypatch.setenv("PATH", "/attacker/bin")
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)

    result = technical._execute_check(
        spec=technical.FIXED_CHECK_MATRIX[0],
        settings=_settings(tmp_path),
        toolchain=context.toolchain,
        scratch_root=scratch,
    )

    assert result.exit_code == 0
    assert observed["argv"][:3] == [
        "/fixed/sandbox-exec",
        "-p",
        technical._NETWORK_DENY_PROFILE,
    ]
    assert observed["argv"][3:] == [
        "/fixed/uv",
        "run",
        "--isolated",
        "--offline",
        "--frozen",
        "pytest",
    ]
    assert observed["shell"] is False
    assert observed["env"]["PATH"] == (
        "/Library/Frameworks/Python.framework/Versions/3.13/bin:/usr/bin:/bin"
    )
    assert "HTTP_PROXY" not in observed["env"]
    assert "ALL_PROXY" not in observed["env"]
    assert "LEGALBOT_MODEL_ADAPTER_PATH" not in observed["env"]
    assert observed["env"]["UV_ISOLATED"] == "1"


def test_mutable_project_virtualenv_is_never_accepted_as_matrix_authority(
    tmp_path: Path,
) -> None:
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    pytest_entry = tmp_path / ".venv/bin/pytest"
    pytest_entry.parent.mkdir(parents=True)
    pytest_entry.write_text("forged exit-zero tool", encoding="utf-8")

    with pytest.raises(
        RuntimeError,
        match="trusted_offline_python_matrix_environment_missing",
    ):
        technical._require_trusted_python_matrix_environment(tmp_path)


def test_secret_scan_covers_all_tracked_repository_members(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    backend_member = tmp_path / "backend/config.py"
    web_member = tmp_path / "web/app.js"
    backend_member.parent.mkdir(parents=True)
    web_member.parent.mkdir(parents=True)
    backend_member.write_text(
        "client_" + 'secret = "abcdefghijklmnop"\n',
        encoding="utf-8",
    )
    web_member.write_text("export const ok = true;\n", encoding="utf-8")

    def fake_run(*_: object, **__: object) -> Any:
        return SimpleNamespace(
            returncode=0,
            stdout=b"backend/config.py\0web/app.js\0",
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    exit_code, stdout, stderr = technical._execute_repository_secret_scan(
        project_root=tmp_path,
        toolchain=_context(_candidate()).toolchain,
        environment={"PATH": "/usr/bin:/bin"},
    )
    payload = json.loads(stdout)
    assert exit_code == 1
    assert stderr == b""
    assert payload == {
        "finding_count": 1,
        "scanned_byte_count": backend_member.stat().st_size + web_member.stat().st_size,
        "scanned_member_count": 2,
    }


def test_secret_scan_rejects_tracked_symlink_before_resolution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "target.py"
    target.write_text("safe = True\n", encoding="utf-8")
    (tmp_path / "tracked-link.py").symlink_to(target)

    def fake_run(*_: object, **__: object) -> Any:
        return SimpleNamespace(returncode=0, stdout=b"tracked-link.py\0", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="repository_inventory_invalid"):
        technical._execute_repository_secret_scan(
            project_root=tmp_path,
            toolchain=_context(_candidate()).toolchain,
            environment={"PATH": "/usr/bin:/bin"},
        )


def test_live60_verifier_output_must_equal_bound_suite_seal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    wrong_output_sha256 = hashlib.sha256(("8" * 64 + "\n").encode()).hexdigest()
    completed, settings, candidate, stage_a, database = _run(monkeypatch, tmp_path)
    live_outcome = completed._run_root / "outcomes/07-live60_verify.json"
    _rewrite_sealed(
        live_outcome,
        lambda value: value.__setitem__("stdout_sha256", wrong_output_sha256),
    )
    live_index = next(
        index
        for index, value in enumerate(completed._outcomes)
        if value["check_id"] == "live60_verify"
    )
    replacement = json.loads(live_outcome.read_text(encoding="utf-8"))
    completed._outcomes = tuple(
        replacement if index == live_index else value
        for index, value in enumerate(completed._outcomes)
    )

    with pytest.raises(ValueError, match="bound suite seal"):
        _load(
            completed,
            settings=settings,
            candidate=candidate,
            stage_a=stage_a,
            database=database,
        )


def test_matrix_contract_is_complete_fixed_and_nonretrying() -> None:
    assert tuple(item.ordinal for item in technical.FIXED_CHECK_MATRIX) == tuple(range(1, 15))
    assert tuple(item.check_id for item in technical.FIXED_CHECK_MATRIX) == (
        "python_full_suite",
        "python_ruff",
        "python_ruff_format",
        "python_static_baseline",
        "workflow_security",
        "clean_room",
        "live60_verify",
        "web_clean_install",
        "web_lint",
        "web_test",
        "web_build",
        "web_audit",
        "repository_secret_scan",
        "repository_diff_check",
    )
    assert all(
        ";" not in token and "$" not in token
        for item in technical.FIXED_CHECK_MATRIX
        for token in item.arguments
    )
    assert (
        sealed_sha256(
            {
                "schema": "legalbot.v111-fixed-technical-check-matrix.v1",
                "checks": [item.safe_dict() for item in technical.FIXED_CHECK_MATRIX],
                "shell": "never",
                "network": "sandbox_denied_and_offline_flags",
                "retry_count": 0,
            }
        )
        == technical.FIXED_CHECK_MATRIX_SHA256
    )


def test_stage_a_scorer_binding_is_derived_from_strict_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate()
    bundle = SimpleNamespace(
        root=Path("bundle"),
        manifest=SimpleNamespace(
            seal_sha256="7" * 64,
            run_plan_sha256="8" * 64,
        ),
        registry=SimpleNamespace(canonical_sha256="9" * 64),
    )
    all60 = SimpleNamespace(seal_sha256="a" * 64)
    expert = SimpleNamespace(seal_sha256="b" * 64)
    stage_a = technical.StageAReplayInputs(
        output_root=Path("stage-a"),
        run_id="stage-a-test",
        bundle=cast(Any, bundle),
        all60_qualification=cast(Any, all60),
        expert_qualification=cast(Any, expert),
        as_of_date=cast(Any, object()),
        completion_preflight_verified_result_sha256="c" * 64,
    )
    replayed: dict[str, Any] = {
        "run_id": stage_a.run_id,
        "candidate_build_id": candidate.build_id,
        "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "all60_qualification_seal_sha256": all60.seal_sha256,
        "expert_qualification_seal_sha256": expert.seal_sha256,
        "completion_preflight_verified_result_sha256": "c" * 64,
        "completion_preflight_authoritative": True,
        "scorer_identity_sha256": STAGE_A_SCORER_IDENTITY_SHA256,
        "runner_policy_sha256": STAGE_A_RUNNER_POLICY_SHA256,
        "code_revision": _INTEGRATION,
        "completed_checkpoint_count": 585,
        "issue_count": 585,
        "timeout_count": 0,
        "worker_failure_count": 0,
        "hard_failure_count": 0,
        "run_status": "passed",
        "stage_a_passed": True,
        "authorization_eligible": True,
        "seal_sha256": "d" * 64,
        "checkpoint_set_sha256": "e" * 64,
        "issue_identity_set_sha256": "f" * 64,
    }
    monkeypatch.setattr(
        technical,
        "load_verified_stage_a_v2_artifact_set",
        lambda **_: dict(replayed),
    )

    binding = technical._stage_a_binding(
        candidate=candidate,
        stage_a=stage_a,
        integration_sha=_INTEGRATION,
    )
    assert binding["result_seal_sha256"] == "d" * 64
    assert binding["scorer_identity_sha256"] == STAGE_A_SCORER_IDENTITY_SHA256

    replayed["scorer_identity_sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="stage_a_replay_mismatch"):
        technical._stage_a_binding(
            candidate=candidate,
            stage_a=stage_a,
            integration_sha=_INTEGRATION,
        )


def test_rollback_plan_requires_owner_strategy_when_no_active_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate()
    state = _sealed(
        "legalbot.v111-candidate-active-catalogue-state.v1",
        active_pointer={"pointer_id": "active", "state": "missing"},
        previous_pointer={"pointer_id": "previous", "state": "missing"},
        catalogue_active_build_id="none",
    )

    def owner_stop(**_: object) -> None:
        raise RuntimeError("OWNER_DECISION_REQUIRED:first_live_rollback_target_policy_unresolved")

    monkeypatch.setattr(technical, "_require_trusted_first_live_rollback_strategy", owner_stop)
    with pytest.raises(RuntimeError, match="first_live_rollback_target_policy_unresolved"):
        technical._rollback_binding(
            settings=cast(Any, object()),
            database=cast(Any, object()),
            candidate=candidate,
            state_binding=state,
            integration_sha=_INTEGRATION,
        )


def test_first_live_rollback_request_is_bounded_and_recommends_no_active_recovery() -> None:
    candidate = _candidate()
    state = _sealed(
        "legalbot.v111-first-live-rollback-decision-state.v1",
        candidate_build_id=candidate.build_id,
        candidate_manifest_sha256=candidate.candidate_manifest_sha256,
        active_pointer={"pointer_id": "active", "state": "missing"},
        previous_pointer={"pointer_id": "previous", "state": "missing"},
        catalogue_active_build_id="none",
        prior_catalogue_build_count=0,
        prior_catalogue_build_set_sha256="0" * 64,
    )
    request = technical.build_first_live_rollback_decision_request(
        candidate=candidate,
        integration_sha=_INTEGRATION,
        state_binding=state,
        created_at=datetime(2026, 8, 20, tzinfo=UTC),
    )

    assert request.state == "OWNER_DECISION_REQUIRED"
    assert request.recommended_option_id == "restore-verified-no-active-state"
    assert {item.option_id for item in request.options} == {
        "restore-verified-no-active-state",
        "select-explicit-prior-rollback-candidate",
        "defer-and-keep-closed",
    }
    assert "active_promotion" in request.blocked_actions
    assert request.seal_sha256 == sealed_sha256(request.model_dump(mode="json", by_alias=True))


def _admitted_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[
    admission.AdmittedV111TechnicalAttestation,
    technical.VerifiedV111TechnicalAttestation,
    Settings,
    SealedCandidateIdentity,
    technical.StageAReplayInputs,
    Database,
]:
    settings = _settings(tmp_path)
    database = Database(settings.database_path)
    database.initialize()
    completed, settings, candidate, stage_a, _ = _run(
        monkeypatch,
        tmp_path,
        database_override=database,
    )
    verified = _load(
        completed,
        settings=settings,
        candidate=candidate,
        stage_a=stage_a,
        database=database,
    )
    monkeypatch.setattr(admission, "_clean_integration_sha", lambda _root: _INTEGRATION)
    monkeypatch.setattr(
        admission,
        "load_sealed_candidate_identity",
        lambda **_kwargs: candidate,
    )
    admitted = admission.admit_verified_v111_technical_attestation(
        verified,
        settings=settings,
        database=database,
        candidate=candidate,
        stage_a=stage_a,
        expected_integration_sha=_INTEGRATION,
    )
    return admitted, verified, settings, candidate, stage_a, database


def test_strict_capability_mints_one_create_only_ledger_backed_admission(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    admitted, verified, settings, candidate, stage_a, database = _admitted_run(
        monkeypatch, tmp_path
    )
    replayed = admission.load_admitted_v111_technical_attestation(
        admitted.receipt_path,
        settings=settings,
        database=database,
        candidate=candidate,
        stage_a=stage_a,
        expected_integration_sha=_INTEGRATION,
        phase="prepromotion",
    )
    assert admission.require_admitted_v111_technical_attestation(replayed) is replayed
    assert replayed.admission_id == admitted.admission_id
    assert replayed.receipt["artifact_member_count"] == 32
    assert replayed.receipt["legacy_favorable_summaries_accepted"] is False
    row = database.fetchone(
        "SELECT * FROM runtime_objects WHERE object_key=?",
        (admitted.receipt["runtime_object_key"],),
    )
    assert row is not None
    assert json.loads(str(row["metadata_json"]))["admission_state"] == "active"

    with pytest.raises(FileExistsError, match="create-only"):
        admission.admit_verified_v111_technical_attestation(
            verified,
            settings=settings,
            database=database,
            candidate=candidate,
            stage_a=stage_a,
            expected_integration_sha=_INTEGRATION,
        )
    database.close()


def test_admission_replay_rejects_receipt_ledger_and_source_mutations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    admitted, _verified, settings, candidate, stage_a, database = _admitted_run(
        monkeypatch, tmp_path
    )
    with pytest.raises(TypeError, match="strictly replayed"):
        admission.require_admitted_v111_technical_attestation(dict(admitted.receipt))

    outcome = admitted.receipt_path.parent / "outcomes/01-python_full_suite.json"
    original = outcome.read_bytes()
    _rewrite_sealed(outcome, lambda value: value.__setitem__("stdout_sha256", "9" * 64))
    with pytest.raises(ValueError, match="source artifact bytes changed"):
        admission.load_admitted_v111_technical_attestation(
            admitted.receipt_path,
            settings=settings,
            database=database,
            candidate=candidate,
            stage_a=stage_a,
            expected_integration_sha=_INTEGRATION,
            phase="prepromotion",
        )
    outcome.write_bytes(original)
    outcome.chmod(0o600)

    database.execute(
        "UPDATE runtime_objects SET metadata_json=? WHERE object_key=?",
        (
            json.dumps({"schema": admission.V111_TECHNICAL_ADMISSION_LEDGER_SCHEMA}),
            admitted.receipt["runtime_object_key"],
        ),
    )
    with pytest.raises(ValueError, match="ledger binding differs or is revoked"):
        admission.load_admitted_v111_technical_attestation(
            admitted.receipt_path,
            settings=settings,
            database=database,
            candidate=candidate,
            stage_a=stage_a,
            expected_integration_sha=_INTEGRATION,
            phase="prepromotion",
        )
    database.close()


def test_admission_mint_rejects_favorable_legacy_mapping(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    database = Database(settings.database_path)
    database.initialize()
    with pytest.raises(TypeError, match="capability_not_loader_verified"):
        admission.admit_verified_v111_technical_attestation(
            {
                "schema": technical.TECHNICAL_FINAL_SCHEMA,
                "terminal_state": "matrix_completed",
                "seal_sha256": _SHA,
            },
            settings=settings,
            database=database,
            candidate=_candidate(),
            stage_a=_stage_a(),
            expected_integration_sha=_INTEGRATION,
        )
    database.close()


def test_postpromotion_transition_reconciles_active_previous_and_catalogue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_candidate = replace(_candidate(), status="active")
    prior_candidate = replace(
        _candidate(),
        build_id="prior-active-v111",
        status="superseded",
        candidate_manifest_sha256="8" * 64,
    )
    implementation = {"implementation_sha256": "e" * 64}
    context_details = {
        "prepromotion_state": _sealed(
            "legalbot.v111-candidate-active-catalogue-state.v1",
            active_pointer={
                "state": "present",
                "build_id": prior_candidate.build_id,
                "manifest_sha256": prior_candidate.candidate_manifest_sha256,
                "pointer_sha256": "9" * 64,
            },
        ),
        "rollback": _sealed(
            technical.TECHNICAL_ROLLBACK_SCHEMA,
            expected_previous_after_promotion_build_id=prior_candidate.build_id,
            expected_previous_after_promotion_manifest_sha256=(
                prior_candidate.candidate_manifest_sha256
            ),
            implementation=implementation,
        ),
    }
    pointers = {
        "active": {
            "state": "present",
            "build_id": active_candidate.build_id,
            "manifest_sha256": active_candidate.candidate_manifest_sha256,
            "pointer_sha256": "a" * 64,
        },
        "previous": {
            "state": "present",
            "build_id": prior_candidate.build_id,
            "manifest_sha256": prior_candidate.candidate_manifest_sha256,
            "pointer_sha256": "b" * 64,
        },
    }
    fake_database = SimpleNamespace(
        fetchall=lambda *_args, **_kwargs: [{"id": active_candidate.build_id}],
        fetchone=lambda *_args, **_kwargs: {"status": "superseded"},
    )
    monkeypatch.setattr(
        technical,
        "_pointer_binding",
        lambda _settings, pointer_id: pointers[pointer_id],
    )
    monkeypatch.setattr(
        technical,
        "_rollback_implementation_binding",
        lambda: implementation,
    )
    monkeypatch.setattr(
        admission,
        "load_sealed_candidate_identity",
        lambda **_kwargs: prior_candidate,
    )

    transition = admission._postpromotion_transition(
        settings=cast(Any, object()),
        database=cast(Any, fake_database),
        candidate=active_candidate,
        context_details=context_details,
    )

    assert transition["active_build_id"] == active_candidate.build_id
    assert transition["previous_build_id"] == prior_candidate.build_id
    assert transition["rollback_plan_seal_sha256"] == context_details["rollback"]["seal_sha256"]

    pointers["previous"] = {**pointers["previous"], "manifest_sha256": "f" * 64}
    with pytest.raises(ValueError, match="rollback transition differs"):
        admission._postpromotion_transition(
            settings=cast(Any, object()),
            database=cast(Any, fake_database),
            candidate=active_candidate,
            context_details=context_details,
        )
