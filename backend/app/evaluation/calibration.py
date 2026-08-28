"""Blind human 70+ calibration contracts and privacy-safe aggregate scoring."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

CRITERION_MAXIMA = {
    "issue_spotting": 15,
    "rule_accuracy": 20,
    "application_or_critical_analysis": 20,
    "authority_and_counterargument": 15,
    "completeness_and_uncertainty": 15,
    "structure_and_conclusion": 10,
    "citation_accuracy": 5,
}


class BlindHumanReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1.0.0"
    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    subject: str = Field(min_length=2, max_length=100)
    reviewer_id_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    independent: bool
    blinded_to_automated_score: bool
    blinded_to_model_identity: bool
    criteria: dict[str, int]
    total_score: int = Field(ge=0, le=100)
    fatal_legal_error: bool = False
    fatal_citation_error: bool = False
    recommendation: str

    @model_validator(mode="after")
    def validate_review(self) -> BlindHumanReview:
        if set(self.criteria) != set(CRITERION_MAXIMA):
            raise ValueError("human review criteria do not match the frozen rubric")
        if any(
            isinstance(score, bool) or score < 0 or score > CRITERION_MAXIMA[key]
            for key, score in self.criteria.items()
        ):
            raise ValueError("human review criterion score is out of range")
        if sum(self.criteria.values()) != self.total_score:
            raise ValueError("human review total does not equal criterion scores")
        if self.recommendation not in {"70_plus", "below_70"}:
            raise ValueError("human review recommendation is invalid")
        expected = (
            "70_plus"
            if self.total_score >= 70
            and not self.fatal_legal_error
            and not self.fatal_citation_error
            else "below_70"
        )
        if self.recommendation != expected:
            raise ValueError("human recommendation conflicts with the frozen 70+ rule")
        if not (
            self.independent and self.blinded_to_automated_score and self.blinded_to_model_identity
        ):
            raise ValueError("human calibration review was not independent and blind")
        return self


class AutomatedScore(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    score: float = Field(ge=0, le=100)


def _load_jsonl(path: Path, model: type[BaseModel]) -> list[BaseModel]:
    records: list[BaseModel] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(model.model_validate(json.loads(line)))
        except Exception as exc:
            raise ValueError(f"invalid calibration record at line {line_number}") from exc
    if not records:
        raise ValueError("calibration input is empty")
    return records


def score_blind_calibration(human_path: Path, automated_path: Path) -> dict[str, Any]:
    humans = [
        item
        for item in _load_jsonl(human_path, BlindHumanReview)
        if isinstance(item, BlindHumanReview)
    ]
    automated = [
        item
        for item in _load_jsonl(automated_path, AutomatedScore)
        if isinstance(item, AutomatedScore)
    ]
    auto_by_key = {(item.case_id, item.run_id): item for item in automated}
    if len(auto_by_key) != len(automated):
        raise ValueError("automated calibration keys are duplicated")
    by_key: dict[tuple[str, str], list[BlindHumanReview]] = defaultdict(list)
    for review in humans:
        by_key[(review.case_id, review.run_id)].append(review)
    missing = sorted(set(by_key) - set(auto_by_key))
    if missing:
        raise ValueError("human calibration rows lack matching automated scores")

    comparison: list[dict[str, Any]] = []
    for key, reviews in sorted(by_key.items()):
        average = sum(review.total_score for review in reviews) / len(reviews)
        fatal = any(review.fatal_legal_error or review.fatal_citation_error for review in reviews)
        human_pass = average >= 70 and not fatal
        automated_score = auto_by_key[key].score
        automated_pass = automated_score >= 70
        comparison.append(
            {
                "case_id": key[0],
                "run_id": key[1],
                "subject": reviews[0].subject,
                "reviewer_count": len({review.reviewer_id_hash for review in reviews}),
                "human_score": round(average, 3),
                "automated_score": automated_score,
                "human_pass": human_pass,
                "automated_pass": automated_pass,
                "fatal_error": fatal,
            }
        )
    unique_cases = len({item["case_id"] for item in comparison})
    subjects = len({item["subject"] for item in comparison})
    reviewers = len({review.reviewer_id_hash for review in humans})
    double_reviewed = sum(item["reviewer_count"] >= 2 for item in comparison)
    agreements = sum(item["human_pass"] == item["automated_pass"] for item in comparison)
    false_passes = sum(item["automated_pass"] and not item["human_pass"] for item in comparison)
    dangerous_false_passes = sum(
        item["automated_pass"] and item["fatal_error"] for item in comparison
    )
    absolute_errors = [
        abs(float(item["human_score"]) - float(item["automated_score"])) for item in comparison
    ]
    human_outcomes = Counter(item["human_pass"] for item in comparison)
    metrics = {
        "unique_cases": unique_cases,
        "subjects": subjects,
        "independent_reviewers": reviewers,
        "double_reviewed_cases": double_reviewed,
        "double_review_fraction": double_reviewed / len(comparison),
        "human_70_plus": human_outcomes[True],
        "human_below_70": human_outcomes[False],
        "pass_fail_agreement": agreements / len(comparison),
        "mean_absolute_score_error": sum(absolute_errors) / len(absolute_errors),
        "automated_false_passes": false_passes,
        "dangerous_false_passes": dangerous_false_passes,
    }
    thresholds = {
        "unique_cases_minimum": 20,
        "subjects_minimum": 5,
        "independent_reviewers_minimum": 2,
        "double_review_fraction_minimum": 0.20,
        "human_70_plus_minimum": 5,
        "human_below_70_minimum": 5,
        "pass_fail_agreement_minimum": 0.85,
        "mean_absolute_score_error_maximum": 10.0,
        "dangerous_false_passes_maximum": 0,
    }
    passed = (
        unique_cases >= 20
        and subjects >= 5
        and reviewers >= 2
        and metrics["double_review_fraction"] >= 0.20
        and human_outcomes[True] >= 5
        and human_outcomes[False] >= 5
        and metrics["pass_fail_agreement"] >= 0.85
        and metrics["mean_absolute_score_error"] <= 10
        and dangerous_false_passes == 0
    )
    return {
        "schema": "legalbot.blind-human-calibration-report.v1",
        "passed": passed,
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "human_input_sha256": hashlib.sha256(human_path.read_bytes()).hexdigest(),
        "automated_input_sha256": hashlib.sha256(automated_path.read_bytes()).hexdigest(),
        "thresholds": thresholds,
        "metrics": metrics,
        "cases": comparison,
    }
