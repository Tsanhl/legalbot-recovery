from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sqlite3
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings


def _readiness_module():
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts" / "runtime_readiness.py"
    spec = importlib.util.spec_from_file_location("legalbot_runtime_readiness", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _first_live_settings(root: Path) -> Settings:
    return Settings(
        project_root=root,
        host="127.0.0.1",
        port=8777,
        live_profile=FIRST_LIVE_LOCAL_ONLY_PROFILE,
        model_url="http://127.0.0.1:8778",
        model_id="mlx-community/Qwen3.5-9B-4bit",
        online_default="local_only",
        official_research_enabled=False,
        xerj_enabled=False,
        phoenix_enabled=False,
        test_mode=True,
    )


class _FakeReadinessDatabase:
    def __init__(self, state: dict[str, Any], *, revoke_on_transaction: bool = False) -> None:
        self.state = state
        self.revoke_on_transaction = revoke_on_transaction
        self.closed = False

    def close(self) -> None:
        self.closed = True

    @contextmanager
    def transaction(self) -> Iterator[None]:
        if self.revoke_on_transaction:
            self.state["active"] = 0
        yield

    def normal_live_readiness_state(self) -> dict[str, Any]:
        return self.state


def _normal_live_authority() -> dict[str, Any]:
    return {
        "candidate_build_id": "build-1",
        "seal_sha256": "a" * 64,
        "readiness_generation_sha256": "b" * 64,
    }


def _active_readiness_state() -> dict[str, Any]:
    authority = _normal_live_authority()
    return {
        "active": 1,
        "candidate_build_id": authority["candidate_build_id"],
        "authority_sha256": authority["seal_sha256"],
        "generation_sha256": authority["readiness_generation_sha256"],
    }


def _admit_normal_live(
    readiness: Any, monkeypatch: pytest.MonkeyPatch, database: _FakeReadinessDatabase
) -> None:
    monkeypatch.setattr(
        readiness,
        "owner_quality_normal_live_readiness_status",
        lambda *_args, **_kwargs: {"normal_live_ready": True},
    )
    monkeypatch.setattr(
        readiness,
        "owner_quality_normal_live_release_authority",
        lambda *_args, **_kwargs: _normal_live_authority(),
    )
    assert database.normal_live_readiness_state() is database.state


def _clear_first_live_forbidden_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    readiness = _readiness_module()
    for name in readiness._FORBIDDEN_FIRST_LIVE_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)
    for name in tuple(os.environ):
        if name.startswith("LEGALBOT_") and ("ADAPTER" in name.upper() or "LORA" in name.upper()):
            monkeypatch.delenv(name, raising=False)


def test_first_live_profile_is_fail_closed_for_online_research(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_first_live_forbidden_environment(monkeypatch)
    assert Settings(project_root=tmp_path).official_research_enabled is False
    settings = _first_live_settings(tmp_path)

    assert settings.evaluation_forbids_online_research is True
    with pytest.raises(RuntimeError, match="attempted"):
        settings.assert_online_research_adapter_allowed()
    with pytest.raises(RuntimeError, match="explicit operator enablement"):
        Settings(project_root=tmp_path).assert_online_research_adapter_allowed()
    Settings(
        project_root=tmp_path,
        official_research_enabled=True,
    ).assert_online_research_adapter_allowed()
    with pytest.raises(ValueError, match="OFFICIAL_RESEARCH_ENABLED=false"):
        Settings(
            project_root=tmp_path,
            live_profile=FIRST_LIVE_LOCAL_ONLY_PROFILE,
            online_default="local_only",
            official_research_enabled=True,
        )
    with pytest.raises(ValueError, match="ONLINE_MODE=local_only"):
        Settings(
            project_root=tmp_path,
            live_profile=FIRST_LIVE_LOCAL_ONLY_PROFILE,
            online_default="always",
            official_research_enabled=False,
        )


def test_first_live_profile_requires_exact_literal_ports_and_no_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    readiness = _readiness_module()
    _clear_first_live_forbidden_environment(monkeypatch)
    readiness.validate_first_live_profile(_first_live_settings(tmp_path))

    with pytest.raises(readiness.ReadinessError, match="exact local contract"):
        readiness.validate_first_live_profile(
            replace(_first_live_settings(tmp_path), host="127.0.0.2")
        )
    monkeypatch.setenv("LEGALBOT_MODEL_ADAPTER_PATH", "")
    with pytest.raises(readiness.ReadinessError, match="exact local contract"):
        readiness.validate_first_live_profile(_first_live_settings(tmp_path))


def test_first_live_profile_rejects_standard_profile_and_model_path_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    readiness = _readiness_module()
    _clear_first_live_forbidden_environment(monkeypatch)
    with pytest.raises(readiness.ReadinessError, match="first-live local-only"):
        readiness.validate_first_live_profile(Settings(project_root=tmp_path))
    monkeypatch.setenv("LEGALBOT_MODEL_PATH", str(tmp_path / "other-model"))
    with pytest.raises(readiness.ReadinessError, match="exact local contract"):
        readiness.validate_first_live_profile(_first_live_settings(tmp_path))


def test_readiness_requires_pointer_catalogue_and_physical_lane_agreement(
    tmp_path: Path,
) -> None:
    readiness = _readiness_module()
    settings = _first_live_settings(tmp_path)
    settings.index_dir.mkdir(parents=True)
    build_id = "active-test-build"
    build_path = settings.index_dir / "builds" / build_id
    (build_path / "lance" / "authority").mkdir(parents=True)
    manifest = b'{"build_id":"active-test-build"}\n'
    (build_path / "manifest.json").write_bytes(manifest)
    lane_manifest = {
        "schema": "legalbot.physical-lanes.v1",
        "separated": True,
        "tables": {
            "authority": {"row_count": 3},
            "teaching": {"row_count": 0},
            "assessment": {"row_count": 0},
        },
    }
    (build_path / "lance" / "physical-lanes.json").write_text(
        json.dumps(lane_manifest), encoding="utf-8"
    )
    (settings.index_dir / "ACTIVE.json").write_text(
        json.dumps(
            {
                "build_id": build_id,
                "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                "promoted_at": "2026-08-14T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    settings.data_dir.mkdir(exist_ok=True)
    connection = sqlite3.connect(settings.database_path)
    connection.execute(
        "CREATE TABLE index_builds ("
        "id TEXT, status TEXT, path TEXT, promoted_at TEXT, created_at TEXT)"
    )
    connection.execute(
        "INSERT INTO index_builds VALUES (?, 'active', ?, ?, ?)",
        (
            build_id,
            f"data/indexes/builds/{build_id}",
            "2026-08-14T00:00:00+00:00",
            "2026-08-14T00:00:00+00:00",
        ),
    )
    connection.commit()
    connection.close()

    result = readiness.validate_active_build(settings, verify_seal=False)

    assert result == {
        "build_id": build_id,
        "lane_counts": {"authority": 3, "teaching": 0, "assessment": 0},
    }


def test_preflight_fails_when_active_pointer_is_missing(tmp_path: Path) -> None:
    readiness = _readiness_module()
    settings = _first_live_settings(tmp_path)
    settings.data_dir.mkdir(parents=True)
    settings.index_dir.mkdir(parents=True)
    settings.database_path.write_bytes(b"")
    with pytest.raises(readiness.ReadinessError, match="ACTIVE index pointer is missing"):
        readiness.validate_active_build(settings, verify_seal=False)

    readiness = _readiness_module()
    healthy = {
        "status": "ready",
        "database_ready": True,
        "worker_ready": True,
        "model_ready": True,
        "active_index": "build-1",
    }

    readiness.validate_health_payload(healthy, "build-1")
    with pytest.raises(readiness.ReadinessError, match="model_ready"):
        readiness.validate_health_payload({**healthy, "model_ready": False}, "build-1")
    with pytest.raises(readiness.ReadinessError, match="ACTIVE build"):
        readiness.validate_health_payload(healthy, "different-build")


@pytest.mark.parametrize(
    ("state_update", "message"),
    [
        ({"active": 0}, "absent, stale, or revoked"),
        ({"generation_sha256": "c" * 64}, "absent, stale, or revoked"),
        ({"candidate_build_id": "other-build"}, "absent, stale, or revoked"),
    ],
)
def test_normal_live_authority_rejects_revoked_or_stale_db_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state_update: dict[str, Any],
    message: str,
) -> None:
    readiness = _readiness_module()
    _clear_first_live_forbidden_environment(monkeypatch)
    state = {**_active_readiness_state(), **state_update}
    database = _FakeReadinessDatabase(state)
    _admit_normal_live(readiness, monkeypatch, database)

    with pytest.raises(readiness.ReadinessError, match=message):
        readiness.validate_normal_live_authority(_first_live_settings(tmp_path), database=database)


def test_exact_first_live_preflight_reconciles_active_authority_and_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    readiness = _readiness_module()
    _clear_first_live_forbidden_environment(monkeypatch)
    database = _FakeReadinessDatabase(_active_readiness_state())
    _admit_normal_live(readiness, monkeypatch, database)
    monkeypatch.setattr(
        readiness,
        "validate_active_build",
        lambda *_args, **_kwargs: {
            "build_id": "build-1",
            "lane_counts": {"authority": 1, "teaching": 0, "assessment": 0},
        },
    )
    monkeypatch.setattr(
        readiness,
        "validate_pinned_model_artifacts",
        lambda _settings: {"seal_sha256": "d" * 64},
    )

    result = readiness.validate_first_live_startup_authority(
        _first_live_settings(tmp_path), database=database
    )

    assert result["build_id"] == "build-1"
    assert result["authority_seal_sha256"] == "a" * 64
    assert result["readiness_generation_sha256"] == "b" * 64
    assert result["trusted_model_identity_sha256"] == "d" * 64


def test_model_artifact_verifier_refuses_symlink_and_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    readiness = _readiness_module()
    _clear_first_live_forbidden_environment(monkeypatch)
    real_model = tmp_path / "real-model"
    real_model.mkdir()
    fixed_parent = tmp_path / "models" / "runtime"
    fixed_parent.mkdir(parents=True)
    (fixed_parent / "Qwen3.5-9B-4bit").symlink_to(real_model, target_is_directory=True)
    with pytest.raises(readiness.ReadinessError, match="cannot be a symlink"):
        readiness.validate_pinned_model_artifacts(_first_live_settings(tmp_path))

    (fixed_parent / "Qwen3.5-9B-4bit").unlink()
    (fixed_parent / "Qwen3.5-9B-4bit").mkdir()
    monkeypatch.setattr(
        readiness,
        "load_trusted_model_identity",
        lambda _root: {"seal_sha256": "d" * 64},
    )

    def mutation_rejected(_root: Path, _identity: dict[str, Any]) -> None:
        raise RuntimeError("model_artifact_identity_mismatch")

    monkeypatch.setattr(readiness, "_verify_model_artifact_manifest", mutation_rejected)
    with pytest.raises(readiness.ReadinessError, match="identity failed verification"):
        readiness.validate_pinned_model_artifacts(_first_live_settings(tmp_path))


def test_launch_model_stops_before_spawn_on_revoke_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    readiness = _readiness_module()
    _clear_first_live_forbidden_environment(monkeypatch)
    database = _FakeReadinessDatabase(_active_readiness_state(), revoke_on_transaction=True)
    _admit_normal_live(readiness, monkeypatch, database)
    monkeypatch.setattr(
        readiness,
        "validate_active_build",
        lambda *_args, **_kwargs: {
            "build_id": "build-1",
            "lane_counts": {"authority": 1, "teaching": 0, "assessment": 0},
        },
    )
    monkeypatch.setattr(
        readiness,
        "validate_pinned_model_artifacts",
        lambda _settings: {"seal_sha256": "d" * 64},
    )
    monkeypatch.setattr(readiness, "_require_model_port_available", lambda: None)
    monkeypatch.setattr(
        readiness,
        "resolve_verified_model_toolchain",
        lambda *_args, **_kwargs: SimpleNamespace(python_executable=Path("/trusted/python")),
    )
    monkeypatch.setattr(
        readiness,
        "isolated_model_python_arguments",
        lambda *_args, **_kwargs: ("-I", "-B", "-c", "trusted-entrypoint"),
    )
    monkeypatch.setattr(
        readiness,
        "sanitized_model_launch_environment",
        lambda **_kwargs: {"LEGALBOT_MODEL_MODE": "mlx"},
    )
    spawned = False

    def forbidden_exec(*_args: Any, **_kwargs: Any) -> None:
        nonlocal spawned
        spawned = True

    monkeypatch.setattr(readiness.os, "execvpe", forbidden_exec)
    with pytest.raises(readiness.ReadinessError, match="stale, or revoked"):
        readiness.guarded_first_live_model_exec(_first_live_settings(tmp_path), database=database)
    assert spawned is False


def test_exact_launch_preflight_stays_closed_until_owned_runtime_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    readiness = _readiness_module()
    _clear_first_live_forbidden_environment(monkeypatch)
    database = _FakeReadinessDatabase(_active_readiness_state())
    _admit_normal_live(readiness, monkeypatch, database)
    monkeypatch.setattr(
        readiness,
        "validate_active_build",
        lambda *_args, **_kwargs: {
            "build_id": "build-1",
            "lane_counts": {"authority": 1, "teaching": 0, "assessment": 0},
        },
    )
    monkeypatch.setattr(
        readiness,
        "validate_pinned_model_artifacts",
        lambda _settings: {"seal_sha256": "d" * 64},
    )
    monkeypatch.setattr(readiness, "_require_model_port_available", lambda: None)
    monkeypatch.setattr(
        readiness,
        "resolve_verified_model_toolchain",
        lambda *_args, **_kwargs: SimpleNamespace(python_executable=Path("/trusted/python")),
    )
    monkeypatch.setattr(
        readiness,
        "isolated_model_python_arguments",
        lambda *_args, **_kwargs: ("-I", "-B", "-c", "trusted-entrypoint"),
    )
    captured_environment: dict[str, str] = {}

    def sanitized(**kwargs: Any) -> dict[str, str]:
        captured_environment.update(kwargs["values"])
        return dict(kwargs["values"])

    monkeypatch.setattr(readiness, "sanitized_model_launch_environment", sanitized)
    with pytest.raises(
        readiness.ReadinessError,
        match="TECHNICAL_IMPLEMENTATION_REQUIRED:first_live_owned_model_runtime_authority_missing",
    ):
        readiness.guarded_first_live_model_exec(_first_live_settings(tmp_path), database=database)
    assert captured_environment == {
        "LEGALBOT_MODEL_MODE": "mlx",
        "LEGALBOT_MODEL_HOST": "127.0.0.1",
        "LEGALBOT_MODEL_PORT": "8778",
        "LEGALBOT_MODEL_ID": "mlx-community/Qwen3.5-9B-4bit",
        "LEGALBOT_MODEL_REVISION": "8b2b98c00a6b4d291155e4890773ca8f769aee53",
        "LEGALBOT_MODEL_PATH": str(tmp_path / "models/runtime/Qwen3.5-9B-4bit"),
        "LEGALBOT_MODEL_CONTEXT_TOKENS": "8192",
        "LEGALBOT_MODEL_MAX_OUTPUT_TOKENS": "2048",
        "LEGALBOT_MODEL_PREFILL_STEP_SIZE": "512",
        "LEGALBOT_MODEL_KV_BITS": "8",
        "LEGALBOT_MODEL_KV_GROUP_SIZE": "64",
        "LEGALBOT_MODEL_CLEAR_CACHE": "true",
    }


def test_runtime_cli_subcommands_reject_swallowed_or_extra_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    readiness = _readiness_module()
    monkeypatch.setattr(
        sys,
        "argv",
        ["runtime_readiness.py", "launch-model", "--", "/tmp/python", "-m", "fake"],
    )
    with pytest.raises(SystemExit) as exc_info:
        readiness.main()
    assert exc_info.value.code == 2


def test_check_never_reports_passed_when_generation_is_revoked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    readiness = _readiness_module()
    database = _FakeReadinessDatabase({**_active_readiness_state(), "active": 0})
    monkeypatch.setattr(readiness, "_settings", lambda _root: _first_live_settings(tmp_path))
    monkeypatch.setattr(readiness, "validate_first_live_profile", lambda _settings: None)
    monkeypatch.setattr(
        readiness,
        "validate_active_build",
        lambda *_args, **_kwargs: {
            "build_id": "build-1",
            "lane_counts": {"authority": 1, "teaching": 0, "assessment": 0},
        },
    )
    monkeypatch.setattr(readiness, "Database", lambda _path: database)
    monkeypatch.setattr(
        readiness,
        "validate_first_live_startup_authority",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            readiness.ReadinessError("v1.11 normal-live DB generation is revoked")
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["runtime_readiness.py", "preflight", "--project-root", str(tmp_path)],
    )

    assert readiness.main() == 2
    captured = capsys.readouterr()
    assert '"status": "ready"' not in captured.out
    assert "revoked" in captured.err
    assert database.closed is True


def test_preexisting_model_port_is_a_hard_no_spawn_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    readiness = _readiness_module()

    class OccupiedSocket:
        def bind(self, _address: tuple[str, int]) -> None:
            raise OSError("occupied")

        def close(self) -> None:
            pass

    monkeypatch.setattr(readiness.socket, "socket", lambda *_args: OccupiedSocket())
    with pytest.raises(readiness.ReadinessError, match="already occupied"):
        readiness._require_model_port_available()

    monkeypatch.setattr(
        sys,
        "argv",
        ["runtime_readiness.py", "preflight", "--unknown-option", "value"],
    )
    with pytest.raises(SystemExit) as exc_info:
        readiness.main()
    assert exc_info.value.code == 2


def test_start_launcher_pins_first_live_profile_and_runs_dependency_checks() -> None:
    root = Path(__file__).resolve().parents[2]
    launcher = (root / "scripts" / "start.sh").read_text(encoding="utf-8")

    assert 'live_profile="${LEGALBOT_LIVE_PROFILE:-first_live_local_only}"' in launcher
    assert 'official_research_enabled="${LEGALBOT_OFFICIAL_RESEARCH_ENABLED:-false}"' in launcher
    assert 'export LEGALBOT_ONLINE_MODE="$online_mode"' in launcher
    assert 'preflight --project-root "$project_dir"' in launcher
    assert 'wait-health --project-root "$project_dir"' in launcher
    assert '[[ "$app_port" == "8777" ]]' in launcher
    assert '[[ "$model_port" == "8778" ]]' in launcher
    assert 'model_path="$project_dir/models/runtime/Qwen3.5-9B-4bit"' in launcher
    assert "LEGALBOT_MODEL_PATH overrides are forbidden" in launcher
    assert "launch-model" in launcher
    assert '|| fail "owned model-runtime authority is not admitted"' in launcher
    assert '"$model_python" -m app.model_runtime' not in launcher
    assert launcher.index("launch-model") < launcher.index("Starting LegalBot-New")
