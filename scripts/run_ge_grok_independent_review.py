#!/usr/bin/env python3
"""Run the Grok independent blind review. Does not complete qualified legal review."""

from __future__ import annotations

import json

from app.evaluation.ge_grok_independent_review import run_grok_independent_review
from app.evaluation.ge_phase2_progress import AWAITING_QUALIFIED_REVIEWER, NOT_STARTED


def main() -> int:
    result = run_grok_independent_review()
    state = result.get("state") or {}
    summary = result.get("summary") or {}
    payload = {
        "result": result.get("result"),
        "pack": result.get("output"),
        "qlr_zip": result.get("qlr_zip"),
        "blind_zip": result.get("blind_zip"),
        "overall_state": state.get("overall_state") or AWAITING_QUALIFIED_REVIEWER,
        "qualified_legal_review": state.get("qualified_legal_review") or NOT_STARTED,
        "professional_legal_sign_off": state.get("professional_legal_sign_off"),
        "reviewer_kind": state.get("reviewer_kind"),
        "reviewer_model": state.get("reviewer_model"),
        "recommendation_counts": state.get("recommendation_counts") or summary.get("recommendation_counts"),
        "grok_independent_blind_review": state.get("grok_independent_blind_review"),
        "dual_ai_review": state.get("dual_ai_review"),
        "legal_gold": state.get("legal_gold") or NOT_STARTED,
        "answer_weight_training": state.get("answer_weight_training") or NOT_STARTED,
    }
    print(json.dumps(payload, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
