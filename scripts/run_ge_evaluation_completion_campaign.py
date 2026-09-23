#!/usr/bin/env python3
"""Run the continuous pre-training evaluation-packet completion campaign.

Stops at AWAITING_OWNER_EVALUATION_REVIEW. Does not train, open sealed unseen,
promote, or activate live. Does not ask the owner to continue between packet families.
"""

from __future__ import annotations

import json
from collections import Counter

from app.evaluation.ge_currentness_packets import EXPECTED_R2_RESULTS
from app.evaluation.ge_evaluation_completion_campaign import (
    DEFAULT_MASTER_PACK,
    GlobalIntegrityError,
    run_evaluation_completion_campaign,
)
from app.evaluation.ge_phase2_progress import AWAITING_OWNER_EVALUATION_REVIEW, NOT_STARTED


def _summary(result: dict) -> dict:
    currentness = result.get("currentness_packets") or []
    residual = result.get("residual_packets") or []
    tests = result.get("tests") or {}
    six = result.get("six_no_evidence") or []
    status_counts = Counter(str(item.get("packet_status") or "") for item in currentness)
    return {
        "result": result.get("result"),
        "pack": result.get("output") or str(DEFAULT_MASTER_PACK),
        "overall_state": (result.get("state") or {}).get("overall_state"),
        "evaluation_packet_preparation": (result.get("state") or {}).get("evaluation_packet_preparation"),
        "owner_evaluation_review": (result.get("state") or {}).get("owner_evaluation_review"),
        "qualified_legal_review": (result.get("state") or {}).get("qualified_legal_review") or NOT_STARTED,
        "answer_legal_gold": (result.get("state") or {}).get("answer_legal_gold") or NOT_STARTED,
        "answer_weight_training": (result.get("state") or {}).get("answer_weight_training") or NOT_STARTED,
        "sealed_unseen_execution": (result.get("state") or {}).get("sealed_unseen_execution") or NOT_STARTED,
        "promotion": (result.get("state") or {}).get("promotion") or NOT_STARTED,
        "live": (result.get("state") or {}).get("live") or NOT_STARTED,
        "legal_gold": (result.get("state") or {}).get("legal_gold"),
        "factual_pass": 42,
        "factual_hold": 289,
        "currentness_packets": len(currentness),
        "currentness_ready": status_counts.get("READY_FOR_OWNER_CURRENTNESS_REVIEW", 0),
        "currentness_incomplete_final": status_counts.get("INCOMPLETE_FINAL", 0),
        "jurisdiction_packets": len(result.get("jurisdiction_packets") or []),
        "residual_packets": len(residual),
        "factual_pass_packets": len(result.get("pass_packets") or []),
        "case_312_packet_status": (result.get("fact_packet") or {}).get("packet_status"),
        "six_no_evidence": six,
        "frozen_r2_results": EXPECTED_R2_RESULTS,
        "frozen_r2_unchanged": (result.get("mutation") or {}).get("unchanged"),
        "integrity_tests_failed": [
            name for name, row in tests.items() if isinstance(row, dict) and row.get("pass") is False
        ],
        "artifacts": result.get("artifacts") or (result.get("state") or {}).get("artifacts"),
        "next_gate": "OWNER_EVALUATION_REVIEW",
    }


def main() -> int:
    try:
        result = run_evaluation_completion_campaign(allow_network=True)
    except GlobalIntegrityError as exc:
        print(json.dumps({"status": "GLOBAL_INTEGRITY_BLOCKED", "error": str(exc)}, indent=2))
        return 2
    payload = _summary(result)
    if result.get("result") == "IDEMPOTENT_UNCHANGED":
        payload["overall_state"] = payload["overall_state"] or AWAITING_OWNER_EVALUATION_REVIEW
    print(json.dumps(payload, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
