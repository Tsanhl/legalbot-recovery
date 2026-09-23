#!/usr/bin/env python3
"""Run the Grok exact-hash readiness audit. Does not complete qualified legal review."""

from __future__ import annotations

import json

from app.evaluation.ge_grok_readiness_audit import run_grok_readiness_audit
from app.evaluation.ge_phase2_progress import (
    ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW,
    NOT_STARTED,
)


def main() -> int:
    result = run_grok_readiness_audit()
    state = result.get("state") or {}
    audit = result.get("audit") or {}
    payload = {
        "result": result.get("result"),
        "pack": result.get("output"),
        "overall_state": state.get("overall_state")
        or ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW,
        "qualified_legal_review": state.get("qualified_legal_review") or NOT_STARTED,
        "professional_legal_sign_off": state.get("professional_legal_sign_off"),
        "reviewer_kind": state.get("reviewer_kind"),
        "recommendation_counts": state.get("recommendation_counts"),
        "dual_ai_current_hash_consensus": state.get("dual_ai_current_hash_consensus"),
        "fallback_template_answers": audit.get("fallback_template_answers"),
        "hold_330": audit.get("exact_answer_hashes_recommended_hold"),
    }
    print(json.dumps(payload, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
