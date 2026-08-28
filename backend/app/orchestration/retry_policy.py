"""One fail-closed retry policy for answer work and serial canary control.

Attempt 1 is the initial attempt. Attempts 2 and 3 are the only permitted
retries. Deterministic safety failures never retry, and the second occurrence
of the same safe failure fingerprint stops before the retry cap is consumed.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

MAX_RETRIES = 2
MAX_ATTEMPTS = 1 + MAX_RETRIES

RetryAction = Literal["retry", "stop"]
RetryReason = Literal[
    "retry_allowed",
    "deterministic_safety_failure",
    "non_retryable_failure",
    "repeated_failure_fingerprint",
    "retry_condition_unchanged",
    "retry_cap_exhausted",
]

_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_SAFE_SCOPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

DETERMINISTIC_SAFETY_FAILURE_CODES = frozenset(
    {
        "applicable_avoidance_standard_failed",
        "authority_identity_failed",
        "case_subsequent_treatment_unverified",
        "chunk_embedding_count_mismatch",
        "current_law_verification_limited",
        "currentness_metadata_missing",
        "document_safety_failed",
        "false_quotation",
        "historical_legislation_used_as_current_law",
        "materially_outdated_law",
        "non_authority_lane",
        "non_atomic_material_claim",
        "no_threshold_qualified_evidence",
        "personal_data_leakage",
        "private_path_leakage",
        "prompt_injection",
        "required_source_family_truncated",
        "released_answer_citation_failure",
        "released_answer_evidence_failure",
        "released_answer_injection_failure",
        "released_answer_privacy_failure",
        "reviewed_material_update_unresolved",
        "unrelated_evidence",
        "unsupported_material_fact",
        "unsupported_material_law",
        "unverified_case_legal_role",
        "wrong_authority_identity",
        "wrong_jurisdiction",
    }
)


def _safe_code(value: str, *, label: str) -> str:
    cleaned = value.strip().casefold().replace("-", "_")
    if not _SAFE_CODE.fullmatch(cleaned):
        raise ValueError(f"{label} must be a safe machine code")
    return cleaned


def failure_fingerprint(
    *,
    stage: str,
    reason_code: str,
    scope_id: str | None = None,
    identity_digests: Sequence[str] = (),
    safe_context: Mapping[str, str | int | bool | None] | None = None,
) -> str:
    """Hash a prose-free failure identity suitable for repeat detection.

    ``safe_context`` accepts only safe keys and scalar machine values. It must
    never contain an exception message, question, answer, source text or path.
    """

    stage_code = _safe_code(stage, label="failure stage")
    failure_code = _safe_code(reason_code, label="failure reason")
    if scope_id is not None and not _SAFE_SCOPE.fullmatch(scope_id):
        raise ValueError("failure scope must be a safe opaque identifier")
    digests = tuple(identity_digests)
    if any(not _SHA256.fullmatch(value) for value in digests):
        raise ValueError("failure identity digest is invalid")
    if len(digests) != len(set(digests)):
        raise ValueError("failure identity digests are duplicated")

    context: dict[str, str | int | bool | None] = {}
    for key, value in (safe_context or {}).items():
        safe_key = _safe_code(key, label="failure context key")
        if isinstance(value, str):
            if not _SAFE_SCOPE.fullmatch(value):
                raise ValueError("failure context string must be a safe opaque value")
        elif value is not None and not isinstance(value, int | bool):
            raise ValueError("failure context values must be safe scalars")
        context[safe_key] = value

    material: dict[str, Any] = {
        "schema": "legalbot.failure-fingerprint.v1",
        "stage": stage_code,
        "reason_code": failure_code,
        "scope_id": scope_id,
        "identity_digests": list(digests),
        "safe_context": dict(sorted(context.items())),
    }
    encoded = (
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def is_deterministic_safety_failure(reason_code: str) -> bool:
    return _safe_code(reason_code, label="failure reason") in (DETERMINISTIC_SAFETY_FAILURE_CODES)


def normalise_failure_reason_code(reason_code: str) -> str:
    """Return a prose-free code, hashing unsafe exception strings.

    Durable workers can receive third-party exception class names or legacy
    rows whose reason was not constrained at admission.  Those values must not
    make a retry trace invalid or leak prose into a safe debug record.
    """

    cleaned = reason_code.strip().casefold().replace("-", "_")
    if _SAFE_CODE.fullmatch(cleaned):
        return cleaned
    digest = hashlib.sha256(reason_code.encode("utf-8", errors="replace")).hexdigest()
    return f"unsafe_reason_{digest[:24]}"


@dataclass(frozen=True, slots=True)
class RetryDecision:
    action: RetryAction
    reason: RetryReason
    attempt_number: int
    retries_used: int
    retries_remaining: int
    failure_fingerprint: str

    @property
    def should_retry(self) -> bool:
        return self.action == "retry"


def decide_retry(
    *,
    attempt_number: int,
    failure_reason_code: str,
    failure_fingerprint_sha256: str,
    prior_failure_fingerprints: Sequence[str] = (),
    deterministic_safety: bool = False,
    retryable: bool = True,
    input_or_condition_changed: bool = True,
    max_attempts: int = MAX_ATTEMPTS,
) -> RetryDecision:
    """Decide the next action without consuming prose or mutating state."""

    if attempt_number < 1:
        raise ValueError("attempt numbers start at one")
    if not 1 <= max_attempts <= MAX_ATTEMPTS:
        raise ValueError("retry max attempts must be between one and three")
    if not _SHA256.fullmatch(failure_fingerprint_sha256):
        raise ValueError("failure fingerprint is invalid")
    reason_code = _safe_code(failure_reason_code, label="failure reason")
    prior = tuple(prior_failure_fingerprints)
    if any(not _SHA256.fullmatch(value) for value in prior):
        raise ValueError("prior failure fingerprint is invalid")

    retries_used = max(0, attempt_number - 1)
    retries_remaining = max(0, max_attempts - attempt_number)
    if deterministic_safety or reason_code in DETERMINISTIC_SAFETY_FAILURE_CODES:
        action: RetryAction = "stop"
        reason: RetryReason = "deterministic_safety_failure"
    elif not retryable:
        action = "stop"
        reason = "non_retryable_failure"
    elif failure_fingerprint_sha256 in prior:
        action = "stop"
        reason = "repeated_failure_fingerprint"
    elif not input_or_condition_changed:
        action = "stop"
        reason = "retry_condition_unchanged"
    elif attempt_number >= max_attempts:
        action = "stop"
        reason = "retry_cap_exhausted"
    else:
        action = "retry"
        reason = "retry_allowed"

    return RetryDecision(
        action=action,
        reason=reason,
        attempt_number=attempt_number,
        retries_used=retries_used,
        retries_remaining=retries_remaining if action == "retry" else 0,
        failure_fingerprint=failure_fingerprint_sha256,
    )
