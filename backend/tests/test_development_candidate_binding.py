from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.config import Settings
from app.services import _select_retriever, build_services


def test_pin_requires_isolated_state():
    with pytest.raises(ValueError, match="isolated state"):
        Settings(development_state_id=None, development_candidate_build_id="candidate-one")


def test_conflicting_pin_fails_before_storage_creation(tmp_path):
    settings = Settings(project_root=tmp_path, development_state_id="ge-qwen",
                        development_candidate_build_id="candidate-one")
    with pytest.raises(ValueError, match="differs"):
        build_services(settings, candidate_build_id="candidate-two")
    assert not settings.data_dir.exists()


def test_pinned_service_does_not_construct_active_retriever(tmp_path, monkeypatch):
    settings = Settings(project_root=tmp_path, development_state_id="ge-qwen",
                        development_candidate_build_id="candidate-one")
    active = Mock(side_effect=AssertionError("ACTIVE-following route constructed"))
    monkeypatch.setattr("app.retrieval.service.HybridRetrievalService", active)
    candidate = object()
    factory = SimpleNamespace(for_build=Mock(return_value=candidate))
    database = SimpleNamespace(fetchone=Mock(return_value={"status": "candidate"}))
    assert _select_retriever(settings, database, None, factory, "candidate-one") is candidate
    factory.for_build.assert_called_once_with("candidate-one")
    active.assert_not_called()


@pytest.mark.parametrize("row", [None, {"status": "active"}, {"status": "built_unscored"}])
def test_development_pin_cannot_select_unqualified_or_active_build(tmp_path, row):
    settings = Settings(project_root=tmp_path, development_state_id="ge-qwen",
                        development_candidate_build_id="candidate-one")
    factory = SimpleNamespace(for_build=Mock())
    database = SimpleNamespace(fetchone=Mock(return_value=row))
    with pytest.raises(RuntimeError, match="non-ACTIVE"):
        _select_retriever(settings, database, None, factory, "candidate-one")
    factory.for_build.assert_not_called()


def test_pin_failure_does_not_fall_back(tmp_path):
    settings = Settings(project_root=tmp_path, development_state_id=None,
                        development_candidate_build_id=None)
    factory = SimpleNamespace(for_build=Mock(side_effect=RuntimeError("seal invalid")))
    with pytest.raises(RuntimeError, match="seal invalid"):
        _select_retriever(settings, None, None, factory, "candidate-one")
