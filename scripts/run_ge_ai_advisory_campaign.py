#!/usr/bin/env python3
"""Run the continuous AI-assisted owner-advisory GE campaign.

Does not train, open sealed unseen, promote, activate live, or ask the owner
to continue between cases.
"""

from __future__ import annotations

import json
from collections import Counter

from app.evaluation.ge_ai_advisory_campaign import (
    DEFAULT_OUTPUT,
    SIX_NO_EVIDENCE,
    run_ai_advisory_campaign,
)
from app.evaluation.ge_currentness_packets import EXPECTED_R2_RESULTS
from app.evaluation.ge_evaluation_completion_campaign import GlobalIntegrityError
from app.evaluation.ge_phase2_progress import (
    AI_ADVISORY_COMPLETE_AWAITING_QUALIFIED_LEGAL_REVIEW,
    NOT_STARTED,
)


def _summary(result: dict) -> dict:
    dispositions = result.get("dispositions") or []
    classes = Counter(str(item.get("terminal_advisory_class") or "") for item in dispositions)
    state = result.get("state") or {}
    six = result.get("six_research") or []
    return {
        "result": result.get("result"),
        "pack": result.get("output") or str(DEFAULT_OUTPUT),
        "overall_state": state.get("overall_state") or AI_ADVISORY_COMPLETE_AWAITING_QUALIFIED_LEGAL_REVIEW,
        "overall_progress": state.get("overall_progress"),
        "owner_standing_policy_authorisation": state.get("owner_standing_policy_authorisation"),
        "ai_assisted_owner_advisory_research": state.get("ai_assisted_owner_advisory_research"),
        "ai_assisted_case_dispositions": state.get("ai_assisted_case_dispositions"),
        "human_case_by_case_owner_review": state.get("human_case_by_case_owner_review") or "NOT_PERFORMED",
        "qualified_legal_review": state.get("qualified_legal_review") or NOT_STARTED,
        "answer_legal_gold": state.get("answer_legal_gold") or NOT_STARTED,
        "legal_gold": state.get("legal_gold"),
        "catalogue_admission": state.get("catalogue_admission") or NOT_STARTED,
        "full_current_law_eligible": state.get("full_current_law_eligible") or NOT_STARTED,
        "answer_weight_training": state.get("answer_weight_training") or NOT_STARTED,
        "sealed_unseen_execution": state.get("sealed_unseen_execution") or NOT_STARTED,
        "promotion": state.get("promotion") or NOT_STARTED,
        "live": state.get("live") or NOT_STARTED,
        "terminal_advisory_classes": dict(classes),
        "qualified_review_queue_size": state.get("qualified_review_queue_size"),
        "excluded_from_gold_count": state.get("excluded_from_gold_count"),
        "post_delta_factual_pass": state.get("post_delta_factual_pass"),
        "post_delta_factual_hold": state.get("post_delta_factual_hold"),
        "changed_case_ids": result.get("changed_case_ids"),
        "six_no_evidence": {
            item.get("case_id"): {
                "research_status": item.get("research_status"),
                "attached": item.get("attached"),
                "advisory_disposition": item.get("advisory_disposition"),
            }
            for item in six
            if item.get("case_id") in SIX_NO_EVIDENCE
        },
        "frozen_r2_results": EXPECTED_R2_RESULTS,
        "frozen_r2_unchanged": (result.get("mutation") or {}).get("unchanged"),
        "integrity_tests_failed": [
            name
            for name, row in (result.get("tests") or {}).items()
            if isinstance(row, dict) and row.get("pass") is False
        ],
        "master_hashes": result.get("master_hashes"),
        "intake": result.get("intake"),
        "next_gate": "QUALIFIED_LEGAL_REVIEW",
    }


def main() -> int:
    try:
        first = run_ai_advisory_campaign(allow_network=True)
        second = run_ai_advisory_campaign(allow_network=True)
    except GlobalIntegrityError as exc:
        print(json.dumps({"status": "GLOBAL_INTEGRITY_BLOCKED", "error": str(exc)}, indent=2))
        return 2
    payload = _summary(first)
    payload["second_run"] = second.get("result")
    payload["second_run_idempotent"] = second.get("result") == "IDEMPOTENT_UNCHANGED"
    print(json.dumps(payload, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
