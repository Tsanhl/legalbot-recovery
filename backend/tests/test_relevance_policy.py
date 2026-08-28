from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.config import Settings
from app.evaluation.owner_quality_canary_authorization import (
    OwnerDecisionRequired,
    owner_canary_policy_bindings,
)
from app.retrieval.relevance_policy import (
    EXACT_ROUTES,
    FROZEN_STATUS,
    PENDING_STATUS,
    POLICY_SCHEMA,
    SEMANTIC_ROUTE,
    RelevanceThresholdPolicy,
    load_relevance_threshold_policy,
    qualify_retrieval_score,
    relevance_policy_sha256,
    select_zero_danger_threshold,
)


def _policy(*, threshold: float | None, pending: bool = False) -> RelevanceThresholdPolicy:
    return RelevanceThresholdPolicy(
        version="test-policy",
        status=PENDING_STATUS if pending else FROZEN_STATUS,
        semantic_threshold=threshold,
        policy_sha256="a" * 64,
    )


def _sealed_payload(*, threshold: float | None, pending: bool = False) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": POLICY_SCHEMA,
        "version": "test-policy",
        "status": PENDING_STATUS if pending else FROZEN_STATUS,
        "score_scale": "qwen_yes_probability_0_1",
        "semantic_routes": [SEMANTIC_ROUTE],
        "exact_routes": sorted(EXACT_ROUTES),
        "semantic_threshold": threshold,
        "calibration": {
            "training_query_count": 20,
            "holdout_query_count": 10,
        },
    }
    payload["policy_sha256"] = relevance_policy_sha256(payload)
    return payload


def test_semantic_retrieval_requires_a_frozen_threshold() -> None:
    decision = qualify_retrieval_score(
        route=SEMANTIC_ROUTE,
        score=0.99,
        policy=_policy(threshold=None, pending=True),
    )

    assert decision.qualified is False
    assert decision.reason == "relevance_threshold_policy_not_frozen"
    assert decision.threshold is None


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0.79, False), (0.8, True), (0.95, True)],
)
def test_semantic_threshold_is_inclusive_and_fail_closed(
    score: float, expected: bool
) -> None:
    decision = qualify_retrieval_score(
        route=SEMANTIC_ROUTE,
        score=score,
        policy=_policy(threshold=0.8),
    )

    assert decision.qualified is expected
    assert decision.threshold == 0.8


@pytest.mark.parametrize("route", sorted(EXACT_ROUTES))
def test_exact_routes_require_binary_identity_and_locator_proof(route: str) -> None:
    rejected = qualify_retrieval_score(
        route=route,
        score=1.0,
        policy=_policy(threshold=0.8),
        exact_identity_and_locator_verified=False,
    )
    accepted = qualify_retrieval_score(
        route=route,
        score=0.0,
        policy=_policy(threshold=0.8),
        exact_identity_and_locator_verified=True,
    )

    assert rejected.qualified is False
    assert rejected.reason == "exact_identity_locator_failed"
    assert accepted.qualified is True
    assert accepted.score == 1.0
    assert accepted.threshold == 1.0


def test_calibration_selects_lowest_zero_danger_threshold() -> None:
    threshold = select_zero_danger_threshold(
        [(0.40, False), (0.65, False), (0.70, True), (0.80, True), (0.95, True)]
    )

    assert threshold == 0.70
    assert select_zero_danger_threshold([(0.90, False), (0.80, True)]) is None


def test_production_policy_seal_is_verified_and_test_mode_needs_no_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "policy.json"
    payload = _sealed_payload(threshold=0.8)
    path.write_text(json.dumps(payload), encoding="utf-8")

    loaded = load_relevance_threshold_policy(path)
    assert loaded.semantic_threshold == 0.8
    assert loaded.policy_sha256 == payload["policy_sha256"]

    payload["semantic_threshold"] = 0.1
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="seal"):
        load_relevance_threshold_policy(path)

    test_only = load_relevance_threshold_policy(tmp_path / "missing.json", test_mode=True)
    assert test_only.test_only is True
    assert test_only.semantic_threshold == 0.0


def test_development_authorization_cannot_bind_a_pending_threshold(
    tmp_path: Path,
) -> None:
    settings = Settings(project_root=tmp_path, test_mode=False)
    settings.relevance_threshold_policy_path.parent.mkdir(parents=True)
    pending = _sealed_payload(threshold=None, pending=True)
    settings.relevance_threshold_policy_path.write_text(
        json.dumps(pending), encoding="utf-8"
    )

    with pytest.raises(OwnerDecisionRequired) as caught:
        owner_canary_policy_bindings(settings=settings)
    assert caught.value.reason_code == "relevance_threshold_policy_not_frozen"

    frozen = _sealed_payload(threshold=0.8)
    settings.relevance_threshold_policy_path.write_text(
        json.dumps(frozen), encoding="utf-8"
    )
    bindings = owner_canary_policy_bindings(settings=settings)

    assert bindings.relevance_threshold_policy_sha256 == frozen["policy_sha256"]
    assert bindings.semantic_relevance_threshold == 0.8
    assert bindings.ai_reviewer_model_independent is False
