from __future__ import annotations

from app.evaluation.ge_visible_answer_repair import REPAIR_CASE_IDS, surface_guard


def test_repair_queue_is_exactly_fifteen_disjoint_cases() -> None:
    assert len(REPAIR_CASE_IDS) == 15
    assert len(set(REPAIR_CASE_IDS)) == 15


def test_surface_guard_accepts_complete_concise_answer() -> None:
    answer = " ".join(["This supported sentence explains the material rule clearly."] * 12)
    assert surface_guard(answer) == []


def test_surface_guard_rejects_truncation_length_and_planner_language() -> None:
    assert "INCOMPLETE_FINAL_SENTENCE" in surface_guard("word " * 80)
    assert "EXCEEDS_260_WORD_REPAIR_LIMIT" in surface_guard("word " * 261 + ".")
    planner = " ".join(["This is only a candidate answer for owner review."] * 10)
    assert "PLANNER_OR_NONFINAL_LANGUAGE" in surface_guard(planner)
