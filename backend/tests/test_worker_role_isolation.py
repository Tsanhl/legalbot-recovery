from __future__ import annotations

from app.privacy import PRIVATE_QUESTION_SUMMARY
from app.types import JobType


def _create(database, *, job_id: str, job_type: str) -> None:
    database.create_job(
        job_id=job_id,
        encrypted_question=b"" if job_type == JobType.INDEX_BUILD else b"encrypted",
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={"job_type": job_type, "build_id": "build-one"}
        if job_type == JobType.INDEX_BUILD
        else {"task_type": "general", "word_target": 500},
        job_type=job_type,
    )


def test_answer_worker_cannot_claim_index_job(database) -> None:
    _create(database, job_id="index-one", job_type=JobType.INDEX_BUILD)
    assert database.claim_next_job("answer-worker-one", job_types=(JobType.ANSWER,)) is None
    claimed = database.claim_next_job("index-worker-one", job_types=(JobType.INDEX_BUILD,))
    assert claimed is not None
    assert claimed["id"] == "index-one"


def test_index_worker_cannot_claim_answer_job(database) -> None:
    _create(database, job_id="answer-one", job_type=JobType.ANSWER)
    assert database.claim_next_job("index-worker-one", job_types=(JobType.INDEX_BUILD,)) is None
    claimed = database.claim_next_job("answer-worker-one", job_types=(JobType.ANSWER,))
    assert claimed is not None
    assert claimed["id"] == "answer-one"


def test_default_claim_remains_backward_compatible(database) -> None:
    _create(database, job_id="answer-one", job_type=JobType.ANSWER)
    claimed = database.claim_next_job("legacy-worker")
    assert claimed is not None
    assert claimed["id"] == "answer-one"


def test_unknown_job_type_filter_is_rejected(database) -> None:
    try:
        database.claim_next_job("worker-one", job_types=("unknown",))
    except ValueError as exc:
        assert "unsupported job type" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("unknown job type was accepted")


def test_empty_job_type_filter_is_rejected(database) -> None:
    try:
        database.claim_next_job("worker-one", job_types=())
    except ValueError as exc:
        assert "unsupported job type" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("empty job type filter was accepted")
