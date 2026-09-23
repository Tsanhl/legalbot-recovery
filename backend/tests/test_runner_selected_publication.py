"""Synthetic wiring checks; no evaluation/live capability is created."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.config import Settings
from app.orchestration.runner import AnswerRunner
from app.types import ReleaseState


@pytest.mark.parametrize("outcome", ["exact", "wrong-answer", "wrong-state", "missing-chain"])
def test_runner_replays_selected_content_before_publication(monkeypatch, outcome):
    runner = object.__new__(AnswerRunner)
    runner.settings = Settings(project_root=Path.cwd(), development_state_id="synthetic",
                               development_candidate_build_id="candidate-one")
    runner.objects = object()
    runner.conversations = None
    runner.observability = None
    job = {name: None for name in ["evaluation_run_id", "evaluation_case_id",
                                  "evaluation_request_sha256", "evaluation_authority_json",
                                  "evaluation_authority_sha256"]}
    job["id"] = "job-one"
    published = []

    def synthetic_atomic_boundary(answer_id, release, **kwargs):
        # Exercise the callback that the real database replays before its
        # independent authority and transactional publication checks.
        proof = kwargs["selected_publication_verifier"]()
        published.append(proof)

    runner.database = SimpleNamespace(
        answer=Mock(return_value={"job_id": "job-one"}), job=Mock(return_value=job),
        fetchone=Mock(return_value=None), release_answer_once=synthetic_atomic_boundary,
    )
    runner._raise_if_cancelled = Mock()
    runner._require_normal_live_for_ordinary_job = Mock(return_value={})
    proof = {"answer_id": "answer-one", "release_state": "verified_full"}
    if outcome == "wrong-answer":
        proof["answer_id"] = "other-answer"
    if outcome == "wrong-state":
        proof["release_state"] = "verified_limited"
    loader = Mock(return_value=proof)
    if outcome == "missing-chain":
        loader.side_effect = RuntimeError("persisted selected answer chain is incomplete")
    monkeypatch.setattr("app.contracts.SelectedAnswerContractStore",
                        Mock(return_value=SimpleNamespace(load_publication_proof=loader)))
    if outcome == "exact":
        runner._mark_released("answer-one", ReleaseState.VERIFIED_FULL)
        assert published == [proof]
    else:
        with pytest.raises(RuntimeError):
            runner._mark_released("answer-one", ReleaseState.VERIFIED_FULL)
        assert published == []
    loader.assert_called_once_with("job-one")


async def test_worker_runner_refuses_different_candidate_before_model_or_retrieval():
    runner = object.__new__(AnswerRunner)
    runner.settings = Settings(development_state_id="synthetic",
                               development_candidate_build_id="candidate-one")
    runner.database = SimpleNamespace(job=Mock(return_value={"pinned_index_build_id": "other"}))
    runner.retriever_factory = SimpleNamespace(for_build=Mock())
    runner.model = Mock()
    with pytest.raises(RuntimeError, match="job pin differs"):
        await runner.run("job-one")
    runner.retriever_factory.for_build.assert_not_called()
    assert runner.model.mock_calls == []
