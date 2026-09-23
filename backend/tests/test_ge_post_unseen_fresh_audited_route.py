from __future__ import annotations

import hashlib
import json

from scripts.run_ge_post_unseen_fresh_audited_route import PUBLIC_ROOT, verify


def _jsonl(name: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in (PUBLIC_ROOT / name).read_text().splitlines()]


def test_completed_post_unseen_audited_route_reconciles() -> None:
    result = verify()
    assert result == {
        "verified": True,
        "overall_state": (
            "POST_UNSEEN_FRESH_AUDITED_ROUTE_PASS_AWAITING_NEW_UNSEEN_BANK_DESIGN"
        ),
        "factual_pass": 23,
        "full_pass": 23,
    }

    outputs = _jsonl("AUDITED-CODEX-OUTPUTS.jsonl")
    reviews = _jsonl("CODEX-BLIND-REVIEW.jsonl")
    assert len(outputs) == len(reviews) == 23
    assert {row["case_id"] for row in outputs} == {row["case_id"] for row in reviews}
    assert all(
        row["candidate_answer_hash"]
        == hashlib.sha256(str(row["candidate_answer"]).encode()).hexdigest()
        for row in outputs
    )
    assert all(row["factual_outcome"] == "FACTUAL_PASS" for row in reviews)
    assert all(row["quality_outcome"] == "MEETS_70_STANDARD" for row in reviews)
    assert all(float(row["quality_score"]) >= 70 for row in reviews)
    assert all(row["critical_floor_pass"] is True for row in reviews)

    state = json.loads((PUBLIC_ROOT / "STATE-TRANSITION-RECEIPT.json").read_text())
    assert state["consumed_unseen_prompt_or_findings_used"] is False
    assert state["new_unseen_bank"] == "NOT_CREATED"
    assert state["new_unseen_execution"] == "NOT_AUTHORIZED_NOT_STARTED"
    assert state["answer_weight_training"] == "NOT_AUTHORIZED_NOT_PERFORMED"
    assert state["r2_adapter"] == "INACTIVE_NOT_USED"
