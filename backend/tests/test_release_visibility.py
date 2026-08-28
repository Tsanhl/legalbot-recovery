from __future__ import annotations

from app.api.main import _is_public_release
from app.quality.policy import POLICY_VERSION
from app.types import ReleaseState


def test_held_draft_is_not_public_or_listed(database) -> None:
    database.create_job(
        job_id="job-held",
        encrypted_question=b"encrypted",
        question_summary="held question",
        request={"task_type": "general"},
    )
    database.store_answer_version(
        answer_id="held-answer",
        job_id="job-held",
        version_number=1,
        version_kind="structured",
        encrypted_content=b"encrypted-held-draft",
        word_count=100,
        release_state=ReleaseState.HELD_FOR_REVIEW,
        policy_version=POLICY_VERSION,
        model_version="test",
        index_build_id=None,
    )

    assert not _is_public_release(ReleaseState.HELD_FOR_REVIEW.value)
    assert database.released_answers() == []


def test_legacy_verified_limited_answer_is_not_first_live_public(database) -> None:
    database.create_job(
        job_id="job-limited",
        encrypted_question=b"encrypted",
        question_summary="limited question",
        request={"task_type": "general"},
    )
    database.store_answer_version(
        answer_id="limited-answer",
        job_id="job-limited",
        version_number=1,
        version_kind="verified_supported_portion",
        encrypted_content=b"encrypted-limited-answer",
        word_count=100,
        release_state=ReleaseState.VERIFIED_LIMITED,
        policy_version=POLICY_VERSION,
        model_version="test",
        index_build_id=None,
        purge_after_days=None,
    )

    assert not _is_public_release(ReleaseState.VERIFIED_LIMITED.value)
    assert database.released_answers() == []
