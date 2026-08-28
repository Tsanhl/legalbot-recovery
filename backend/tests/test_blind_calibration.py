from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.evaluation.calibration import CRITERION_MAXIMA, score_blind_calibration


def test_blind_calibration_requires_balanced_independent_reviews(tmp_path: Path) -> None:
    human = tmp_path / "human.jsonl"
    automated = tmp_path / "auto.jsonl"
    human_rows = []
    auto_rows = []
    for index in range(20):
        score = 80 if index < 10 else 60
        criteria = dict(CRITERION_MAXIMA)
        if score == 80:
            criteria["rule_accuracy"] = 10
            criteria["application_or_critical_analysis"] = 10
        else:
            criteria["rule_accuracy"] = 0
            criteria["application_or_critical_analysis"] = 0
        reviewers = ("reviewer-a", "reviewer-b") if index < 4 else ("reviewer-a",)
        for reviewer in reviewers:
            human_rows.append(
                {
                    "schema_version": "1.0.0",
                    "case_id": f"case-{index:03d}",
                    "run_id": f"run-{index:03d}",
                    "subject": f"subject-{index % 5}",
                    "reviewer_id_hash": hashlib.sha256(reviewer.encode()).hexdigest(),
                    "independent": True,
                    "blinded_to_automated_score": True,
                    "blinded_to_model_identity": True,
                    "criteria": criteria,
                    "total_score": score,
                    "fatal_legal_error": False,
                    "fatal_citation_error": False,
                    "recommendation": "70_plus" if score >= 70 else "below_70",
                }
            )
        auto_rows.append(
            {"case_id": f"case-{index:03d}", "run_id": f"run-{index:03d}", "score": score}
        )
    human.write_text("".join(json.dumps(row) + "\n" for row in human_rows))
    automated.write_text("".join(json.dumps(row) + "\n" for row in auto_rows))
    report = score_blind_calibration(human, automated)
    assert report["passed"] is True
    assert report["metrics"]["double_review_fraction"] == 0.2
    assert report["metrics"]["dangerous_false_passes"] == 0
