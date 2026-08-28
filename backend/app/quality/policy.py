from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]  # PyYAML does not ship inline typing.

from ..config import PROJECT_ROOT
from ..types import ReleaseState, Severity, TaskType

POLICY_PATH = PROJECT_ROOT / "config" / "policy.yaml"


def _load_policy(path: Path = POLICY_PATH) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    payload = yaml.safe_load(raw)
    if not isinstance(payload, dict):
        raise RuntimeError("config/policy.yaml must contain an object")
    required = {"schema", "version", "hard_blockers", "academic_quality", "product_scope"}
    if not required <= payload.keys():
        raise RuntimeError("config/policy.yaml is missing required policy fields")
    blockers = payload.get("hard_blockers")
    if not isinstance(blockers, list) or not blockers or len(blockers) != len(set(blockers)):
        raise RuntimeError("config/policy.yaml hard_blockers must be a unique non-empty list")
    return payload, hashlib.sha256(raw).hexdigest()


POLICY, POLICY_SHA256 = _load_policy()
POLICY_VERSION = str(POLICY["version"])
HARD_BLOCKER_CODES = frozenset(str(item) for item in POLICY["hard_blockers"])
ACADEMIC_SCORE_RELEASE_GATE = bool(POLICY["academic_quality"]["release_gate"])
ACADEMIC_TARGET_SCORE = float(POLICY["academic_quality"]["target_score"])
PRODUCT_JURISDICTION = str(POLICY["product_scope"]["jurisdiction"])


@dataclass(frozen=True, slots=True)
class RubricCriterion:
    key: str
    label: str
    weight: float


COMMON = (
    RubricCriterion("authority_accuracy", "Accurate, current, authoritative law", 25),
    RubricCriterion("analysis", "Reasoned legal analysis", 20),
    RubricCriterion("organisation", "Coherent structure and signposting", 10),
    RubricCriterion("precision", "Precision, relevance and disciplined expression", 10),
)

OVERLAYS: dict[TaskType, tuple[RubricCriterion, ...]] = {
    TaskType.ESSAY: (
        RubricCriterion("thesis", "Qualified thesis", 10),
        RubricCriterion("scholarship", "Critical engagement with scholarship", 10),
        RubricCriterion("counterargument", "Counterargument and policy evaluation", 10),
        RubricCriterion("synthesis", "Synthesis and reasoned conclusion", 5),
    ),
    TaskType.PROBLEM: (
        RubricCriterion("issue_map", "Party and issue map", 8),
        RubricCriterion("application", "Fact-specific application", 12),
        RubricCriterion("counterargument", "Counterarguments and uncertainty", 6),
        RubricCriterion("remedies", "Remedies, procedure and ranked outcomes", 9),
    ),
    TaskType.GENERAL: (
        RubricCriterion("direct_answer", "Direct answer and assumptions", 12),
        RubricCriterion("limitations", "Limitations and uncertainty", 8),
        RubricCriterion("next_steps", "Practical next steps", 8),
        RubricCriterion("synthesis", "Clear synthesis", 7),
    ),
    TaskType.AUTO: (),
}


def severity_for(code: str) -> Severity:
    return Severity.HARD_BLOCKER if code in HARD_BLOCKER_CODES else Severity.REPAIRABLE


def decide_release(
    *,
    hard_blocker: bool,
    evidence_passed: bool,
    academic_score: float,
    word_count: int,
    word_target: int,
    has_gaps: bool,
) -> ReleaseState:
    if hard_blocker or not evidence_passed:
        return ReleaseState.HELD_FOR_REVIEW
    if has_gaps:
        return ReleaseState.VERIFIED_LIMITED
    if ACADEMIC_SCORE_RELEASE_GATE and academic_score < ACADEMIC_TARGET_SCORE:
        return ReleaseState.VERIFIED_LIMITED
    if word_count < max(100, int(word_target * 0.8)):
        return ReleaseState.VERIFIED_CONCISE
    return ReleaseState.VERIFIED_FULL
