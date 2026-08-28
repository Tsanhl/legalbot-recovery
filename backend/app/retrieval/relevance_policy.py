"""Route-specific relevance qualification and deterministic threshold calibration."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

POLICY_SCHEMA = "legalbot.retrieval-relevance-policy.v1"
PENDING_STATUS: Literal["PENDING_PHASE2B_CALIBRATION"] = "PENDING_PHASE2B_CALIBRATION"
FROZEN_STATUS: Literal["FROZEN_CALIBRATED"] = "FROZEN_CALIBRATED"
SEMANTIC_ROUTE = "hybrid_rrf"
EXACT_ROUTES = frozenset({"exact_authority_identity", "exact_legislation_reference"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def canonical_policy_bytes(value: dict[str, Any]) -> bytes:
    material = dict(value)
    material.pop("policy_sha256", None)
    return (
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def relevance_policy_sha256(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_policy_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class RelevanceThresholdPolicy:
    version: str
    status: Literal["PENDING_PHASE2B_CALIBRATION", "FROZEN_CALIBRATED"]
    semantic_threshold: float | None
    policy_sha256: str
    source_path: Path | None = None
    test_only: bool = False

    @property
    def frozen(self) -> bool:
        return self.status == FROZEN_STATUS and self.semantic_threshold is not None


@dataclass(frozen=True, slots=True)
class RelevanceQualification:
    route: str
    score: float | None
    threshold: float | None
    policy_sha256: str
    qualified: bool
    reason: str


def _validate_payload(value: Any, *, path: Path | None = None) -> RelevanceThresholdPolicy:
    if not isinstance(value, dict):
        raise ValueError("relevance threshold policy must be an object")
    supplied = str(value.get("policy_sha256") or "")
    if not _SHA256.fullmatch(supplied) or supplied != relevance_policy_sha256(value):
        raise ValueError("relevance threshold policy seal is invalid")
    if (
        value.get("schema") != POLICY_SCHEMA
        or value.get("status") not in {PENDING_STATUS, FROZEN_STATUS}
        or value.get("score_scale") != "qwen_yes_probability_0_1"
        or value.get("semantic_routes") != [SEMANTIC_ROUTE]
        or set(value.get("exact_routes") or ()) != EXACT_ROUTES
    ):
        raise ValueError("relevance threshold policy contract is invalid")
    threshold = value.get("semantic_threshold")
    if value["status"] == PENDING_STATUS:
        if threshold is not None:
            raise ValueError("pending relevance policy cannot contain a threshold")
    elif isinstance(threshold, bool) or not isinstance(threshold, int | float):
        raise ValueError("frozen relevance policy requires a numeric threshold")
    elif not math.isfinite(float(threshold)) or not 0.0 <= float(threshold) <= 1.0:
        raise ValueError("semantic relevance threshold must be within 0..1")
    status: Literal["PENDING_PHASE2B_CALIBRATION", "FROZEN_CALIBRATED"] = (
        PENDING_STATUS if value["status"] == PENDING_STATUS else FROZEN_STATUS
    )
    calibration = value.get("calibration")
    if (
        not isinstance(calibration, dict)
        or calibration.get("training_query_count") != 20
        or calibration.get("holdout_query_count") != 10
    ):
        raise ValueError("relevance threshold policy calibration split is invalid")
    return RelevanceThresholdPolicy(
        version=str(value.get("version") or ""),
        status=status,
        semantic_threshold=float(threshold) if threshold is not None else None,
        policy_sha256=supplied,
        source_path=path,
    )


def load_relevance_threshold_policy(
    path: Path, *, test_mode: bool = False
) -> RelevanceThresholdPolicy:
    """Load the sealed production policy or a clearly marked test-only policy."""

    if test_mode:
        material = {
            "schema": POLICY_SCHEMA,
            "version": "test-only-zero-threshold",
            "status": FROZEN_STATUS,
            "score_scale": "qwen_yes_probability_0_1",
            "semantic_routes": [SEMANTIC_ROUTE],
            "exact_routes": sorted(EXACT_ROUTES),
            "semantic_threshold": 0.0,
            "calibration": {
                "training_query_count": 20,
                "holdout_query_count": 10,
                "test_only": True,
            },
        }
        digest = relevance_policy_sha256(material)
        return RelevanceThresholdPolicy(
            version="test-only-zero-threshold",
            status=FROZEN_STATUS,
            semantic_threshold=0.0,
            policy_sha256=digest,
            source_path=None,
            test_only=True,
        )
    value = json.loads(path.read_text(encoding="utf-8"))
    return _validate_payload(value, path=path)


def qualify_retrieval_score(
    *,
    route: str,
    score: float | None,
    policy: RelevanceThresholdPolicy,
    exact_identity_and_locator_verified: bool = False,
) -> RelevanceQualification:
    """Apply binary exact-route checks or the frozen semantic threshold."""

    if route in EXACT_ROUTES:
        return RelevanceQualification(
            route=route,
            score=1.0 if exact_identity_and_locator_verified else 0.0,
            threshold=1.0,
            policy_sha256=policy.policy_sha256,
            qualified=exact_identity_and_locator_verified,
            reason=(
                "exact_identity_locator_verified"
                if exact_identity_and_locator_verified
                else "exact_identity_locator_failed"
            ),
        )
    if route != SEMANTIC_ROUTE:
        return RelevanceQualification(
            route=route,
            score=None,
            threshold=policy.semantic_threshold,
            policy_sha256=policy.policy_sha256,
            qualified=False,
            reason="unknown_retrieval_route",
        )
    threshold = policy.semantic_threshold
    if not policy.frozen or threshold is None:
        return RelevanceQualification(
            route=route,
            score=score,
            threshold=None,
            policy_sha256=policy.policy_sha256,
            qualified=False,
            reason="relevance_threshold_policy_not_frozen",
        )
    if score is None or not math.isfinite(float(score)):
        return RelevanceQualification(
            route=route,
            score=None,
            threshold=policy.semantic_threshold,
            policy_sha256=policy.policy_sha256,
            qualified=False,
            reason="rerank_score_missing_or_invalid",
        )
    normalized = min(1.0, max(0.0, float(score))) if policy.test_only else float(score)
    if not policy.test_only and not 0.0 <= normalized <= 1.0:
        return RelevanceQualification(
            route=route,
            score=normalized,
            threshold=policy.semantic_threshold,
            policy_sha256=policy.policy_sha256,
            qualified=False,
            reason="rerank_score_outside_probability_scale",
        )
    qualified = normalized >= threshold
    return RelevanceQualification(
        route=route,
        score=normalized,
        threshold=policy.semantic_threshold,
        policy_sha256=policy.policy_sha256,
        qualified=qualified,
        reason="semantic_threshold_passed" if qualified else "below_relevance_threshold",
    )


def select_zero_danger_threshold(
    labelled_scores: list[tuple[float, bool]],
) -> float | None:
    """Return the lowest threshold admitting no dangerous negative example."""

    if not labelled_scores or any(
        not math.isfinite(score) or not 0.0 <= score <= 1.0
        for score, _is_relevant in labelled_scores
    ):
        raise ValueError("calibration scores must be finite probabilities")
    positives = [score for score, relevant in labelled_scores if relevant]
    negatives = [score for score, relevant in labelled_scores if not relevant]
    if not positives:
        return None
    candidates = sorted(set(positives))
    for candidate in candidates:
        if all(score < candidate for score in negatives):
            return candidate
    return None
