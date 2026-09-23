"""Offline triage and terminal reporting; no model, browser or source IO."""
import copy

from scripts import ge_auto_case_protocol as p
from scripts.ge_auto_visible_case_execution import completion_summary
from scripts.ge_auto_visible_diagnostics import assess_mapper


def test_final_hold_does_not_mask_callback_failure_or_become_supported_answer():
    held = {"answer": {"status": "HOLD"}, "holds": ["CURRENTNESS_UNRESOLVED"]}
    assert completion_summary([held], None)["status"] == "HELD_OR_LIMITED_PENDING_BLIND_REVIEW"
    broken = copy.deepcopy(held)
    broken["holds"].append("CALLBACK_RUNTIMEERROR")
    summary = completion_summary([broken], None)
    assert summary["status"] == "EXECUTION_HOLD"
    assert summary["runtime_hold_codes"] == ["CALLBACK_RUNTIMEERROR"]
    assert not summary["supported_answer_proven"]
    assert completion_summary([], None)["status"] == "EXECUTION_HOLD"
    answer = {"answer": {"status": "ANSWER"}, "holds": []}
    assert completion_summary([answer], None)["status"] == "EXECUTED_PENDING_BLIND_REVIEW"
    assert not completion_summary([answer], None)["supported_answer_proven"]
    assert completion_summary([answer], None, unresolved_operations=[{"code": "FAILED"}])["status"] == "EXECUTION_HOLD"


def test_valid_reference_replay_preserves_substantive_currentness_hold():
    sha = "a" * 64
    text = "Synthetic rule\u00a0with a condition."
    span = {"source_sha256": sha, "part_id": "p1", "start": 0, "end": len(text)}
    output = {"propositions": [{"proposition_id": "p1", "jurisdiction": "Wales",
        "as_of_date": "2026-09-05", "point": span, "conditions": [], "context": [span],
        "currentness": {"status": "UNRESOLVED", "valid_from": None, "valid_to": None, "checks": []}}],
        "holds": ["CURRENTNESS_UNRESOLVED"]}
    payload = {"sources": [{"source_sha256": sha, "parts": [{"part_id": "p1", "text": text}]}],
               "queries": [{"jurisdiction": "Wales", "as_of_date": "2026-09-05"}]}
    before = p.digest(output)
    result = assess_mapper(output, payload, references=True)
    assert result["mechanical_mapping"] == "PASS"
    assert result["all_propositions_currentness_unresolved"]
    assert result["next_action"] == "RESOLVE_SOURCE_CURRENTNESS_BEFORE_ANOTHER_FULL_RUN"
    assert result["mapper_holds"] == output["holds"]
    assert p.digest(output) == before
