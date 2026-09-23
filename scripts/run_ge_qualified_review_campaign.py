#!/usr/bin/env python3
"""Prepare the 330-case qualified-review workbook and stop for a reviewer.

Does not complete qualified legal review, start training, or open sealed unseen.
"""

from __future__ import annotations

import json

from app.evaluation.ge_phase2_progress import AWAITING_QUALIFIED_REVIEWER, NOT_STARTED
from app.evaluation.ge_qualified_review_campaign import run_qualified_review_campaign


def main() -> int:
    result = run_qualified_review_campaign()
    state = result.get("state") or {}
    payload = {
        "result": result.get("result"),
        "pack": result.get("output"),
        "overall_state": state.get("overall_state") or AWAITING_QUALIFIED_REVIEWER,
        "overall_progress": state.get("overall_progress", True),
        "qualified_legal_review": state.get("qualified_legal_review") or NOT_STARTED,
        "answer_legal_gold": state.get("answer_legal_gold") or NOT_STARTED,
        "answer_weight_training": state.get("answer_weight_training") or NOT_STARTED,
        "sealed_unseen_execution": state.get("sealed_unseen_execution") or NOT_STARTED,
        "working_disposition_counts": state.get("working_disposition_counts"),
        "direct_review_ready_count": state.get("direct_review_ready_count"),
        "qualified_review_queue": state.get("qualified_review_queue"),
        "contractions_retained_limited": state.get("contractions_retained_limited"),
        "contractions_reclassified_hold_material": state.get("contractions_reclassified_hold_material"),
        "reviewer_identity_supplied": state.get("human_qualified_reviewer_identity_supplied"),
        "ai_did_not_complete_qualified_review": state.get("ai_did_not_complete_qualified_review"),
        "full_331_not_rerun": True,
        "integrity_pass": (result.get("tests") or {}).get("pass", True),
    }
    print(json.dumps(payload, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
