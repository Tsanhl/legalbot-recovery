from pathlib import Path

import pytest

from app.config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings


def test_development_state_separates_writable_data_but_keeps_model_identity(tmp_path):
    ordinary = Settings(project_root=tmp_path, development_state_id=None)
    scoped = Settings(project_root=tmp_path, development_state_id="ge-qwen-20260908")
    assert scoped.database_path != ordinary.database_path
    assert scoped.index_dir != ordinary.index_dir
    assert scoped.logs_dir != ordinary.logs_dir
    assert scoped.owner_decision_root != ordinary.owner_decision_root
    assert scoped.embedding_model_path == ordinary.embedding_model_path
    assert scoped.model_id == ordinary.model_id
    scoped.ensure_runtime_dirs()
    assert scoped.data_dir.is_dir()
    assert not ordinary.database_path.exists()
    assert not ordinary.index_dir.exists()


@pytest.mark.parametrize("overrides", [
    {"environment": "production"},
    {"live_profile": FIRST_LIVE_LOCAL_ONLY_PROFILE},
    {"host": "0.0.0.0"},
    {"development_state_id": "../catalogue"},
    {"development_state_id": "/tmp/escape"},
])
def test_isolation_cannot_be_used_as_live_or_path_override(tmp_path, overrides):
    values = {"project_root": tmp_path, "development_state_id": "ge-qwen"}
    values.update(overrides)
    with pytest.raises(ValueError):
        Settings(**values)


def test_isolation_rejects_symlink_to_shared_state(tmp_path):
    (tmp_path / "data" / "development-runtime").mkdir(parents=True)
    (tmp_path / "data" / "development-runtime" / "ge-qwen").symlink_to(tmp_path)
    with pytest.raises(ValueError, match="symlinks"):
        Settings(project_root=tmp_path, development_state_id="ge-qwen")


def test_development_state_environment_is_read_for_each_settings_instance(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGALBOT_DEVELOPMENT_STATE_ID", "ge-qwen")
    settings = Settings(project_root=tmp_path)
    assert settings.data_dir == Path(tmp_path) / "data/development-runtime/ge-qwen/data"


def test_startup_rechecks_nested_symlink_added_after_configuration(tmp_path):
    settings = Settings(project_root=tmp_path, development_state_id="ge-qwen")
    settings.data_dir.parent.mkdir(parents=True)
    settings.data_dir.symlink_to(tmp_path)
    with pytest.raises(ValueError, match="symlinks"):
        settings.ensure_runtime_dirs()
