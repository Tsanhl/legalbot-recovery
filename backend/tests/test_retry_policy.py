from __future__ import annotations

import pytest

from app.orchestration.retry_policy import (
    MAX_ATTEMPTS,
    MAX_RETRIES,
    decide_retry,
    failure_fingerprint,
    is_deterministic_safety_failure,
)


def _fingerprint(reason: str, *, scope: str = "live60-q31") -> str:
    return failure_fingerprint(
        stage="verifying",
        reason_code=reason,
        scope_id=scope,
        identity_digests=("a" * 64,),
        safe_context={"attempt_band": 1, "cold_start": False},
    )


def test_initial_attempt_plus_at_most_two_retries() -> None:
    one = _fingerprint("transient_worker_failure", scope="case-1")
    two = _fingerprint("transient_worker_failure", scope="case-2")
    three = _fingerprint("transient_worker_failure", scope="case-3")

    first = decide_retry(
        attempt_number=1,
        failure_reason_code="transient_worker_failure",
        failure_fingerprint_sha256=one,
    )
    second = decide_retry(
        attempt_number=2,
        failure_reason_code="transient_worker_failure",
        failure_fingerprint_sha256=two,
        prior_failure_fingerprints=(one,),
    )
    third = decide_retry(
        attempt_number=3,
        failure_reason_code="transient_worker_failure",
        failure_fingerprint_sha256=three,
        prior_failure_fingerprints=(one, two),
    )

    assert (MAX_RETRIES, MAX_ATTEMPTS) == (2, 3)
    assert (first.should_retry, first.retries_remaining) == (True, 2)
    assert (second.should_retry, second.retries_remaining) == (True, 1)
    assert (third.should_retry, third.reason) == (False, "retry_cap_exhausted")


def test_deterministic_safety_and_repeat_stop_early() -> None:
    safety = _fingerprint("wrong_jurisdiction")
    repeated = _fingerprint("transient_worker_failure")

    assert is_deterministic_safety_failure("wrong-jurisdiction") is True
    assert is_deterministic_safety_failure("unsupported_material_law") is True
    assert is_deterministic_safety_failure("unrelated_evidence") is True
    assert (
        decide_retry(
            attempt_number=1,
            failure_reason_code="wrong_jurisdiction",
            failure_fingerprint_sha256=safety,
        ).reason
        == "deterministic_safety_failure"
    )
    assert (
        decide_retry(
            attempt_number=2,
            failure_reason_code="transient_worker_failure",
            failure_fingerprint_sha256=repeated,
            prior_failure_fingerprints=(repeated,),
        ).reason
        == "repeated_failure_fingerprint"
    )


def test_retry_requires_changed_condition_and_supports_stricter_lane_cap() -> None:
    fingerprint = _fingerprint("transient_worker_failure")
    assert (
        decide_retry(
            attempt_number=1,
            failure_reason_code="transient_worker_failure",
            failure_fingerprint_sha256=fingerprint,
            input_or_condition_changed=False,
        ).reason
        == "retry_condition_unchanged"
    )
    assert (
        decide_retry(
            attempt_number=1,
            failure_reason_code="transient_worker_failure",
            failure_fingerprint_sha256=fingerprint,
            retryable=False,
        ).reason
        == "non_retryable_failure"
    )
    assert (
        decide_retry(
            attempt_number=1,
            failure_reason_code="transient_worker_failure",
            failure_fingerprint_sha256=fingerprint,
            max_attempts=1,
        ).reason
        == "retry_cap_exhausted"
    )


def test_failure_fingerprint_is_stable_and_prose_free() -> None:
    assert _fingerprint("transient_worker_failure") == _fingerprint("transient-worker-failure")
    with pytest.raises(ValueError, match="safe opaque"):
        failure_fingerprint(
            stage="drafting",
            reason_code="failure",
            safe_context={"message": "The whole answer failed again"},
        )
    with pytest.raises(ValueError, match="identity digest"):
        failure_fingerprint(stage="drafting", reason_code="failure", identity_digests=("bad",))
