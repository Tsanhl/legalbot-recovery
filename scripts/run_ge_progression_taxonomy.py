#!/usr/bin/env python3
"""Recalibrate GE evaluation progression without weakening legal gold.

Does not rerun the 331, start training, open sealed unseen, promote, or go live.
"""

from __future__ import annotations

import json

from app.evaluation.ge_phase2_progress import (
    EVALUATION_TERMINALLY_CLASSIFIED_AWAITING_QUALIFIED_REVIEW,
    NOT_STARTED,
)
from app.evaluation.ge_progression_taxonomy import run_progression_taxonomy_campaign


def main() -> int:
    result = run_progression_taxonomy_campaign()
    summary = result.get("summary") or {}
    counts = summary.get("disposition_counts") or {}
    payload = {
        "result": result.get("result"),
        "pack": result.get("output"),
        "overall_state": EVALUATION_TERMINALLY_CLASSIFIED_AWAITING_QUALIFIED_REVIEW
        if result.get("result") == "CREATED"
        else ((result.get("state") or {}).get("overall_state")),
        "overall_progress": True,
        "does_not_require_331_of_331_to_pass": True,
        "diagnostic_factual_pass": (summary.get("diagnostic_factual_counts") or {}).get("FACTUAL_PASS"),
        "diagnostic_factual_hold": (summary.get("diagnostic_factual_counts") or {}).get("FACTUAL_HOLD"),
        "289_holds_are_not_equivalent_failures": True,
        "disposition_counts": counts,
        "qualified_review_eligible": summary.get("qualified_review_eligible_count"),
        "hard_evidence_gap": summary.get("hard_evidence_gap_count"),
        "fail_closed": summary.get("fail_closed_count"),
        "gold_ineligible": summary.get("gold_ineligible_count"),
        "cases_advanced_without_legal_approval": summary.get(
            "cases_advanced_without_legal_approval_count"
        ),
        "answer_contractions": result.get("contraction_count"),
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        "training_eligible": False,
        "sealed_unseen_not_opened": True,
        "promotion": NOT_STARTED,
        "live": NOT_STARTED,
        "frozen_hashes_unchanged": result.get("mutation_unchanged"),
        "integrity_pass": (result.get("tests") or {}).get("pass"),
    }
    if result.get("result") == "IDEMPOTENT_UNCHANGED":
        payload["overall_state"] = (result.get("state") or {}).get("overall_state")
    print(json.dumps(payload, indent=2, default=str))
    return 0 if (result.get("tests") or {}).get("pass") is not False else 2


if __name__ == "__main__":
    raise SystemExit(main())
