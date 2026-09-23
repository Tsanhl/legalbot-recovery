from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.evaluation.ge_diagnostic_evaluator import locator_hints_for_case
from app.evaluation.ge_hold_reason_router import CASE_174
from app.evaluation.ge_kajima_mediation_family import (
    ATTACHABLE_PENDING_TARGETED_FAMILY,
    KAJIMA_TITLE,
    OUTSIDE_TARGETED_MEDIATION_FAMILY,
    PARAGRAPH_29,
    PARAGRAPH_30,
    TARGETED_MEDIATION_FAMILY,
    decide_kajima_attachment,
    derive_kajima_29_30_affected_case_ids,
    execute_kajima_attachments,
    filter_attached_evidence_rows,
    kajima_29_30_hint_dependency_changed,
    kajima_29_in_scope,
    mediation_family_locator_allowed,
)
from scripts.run_ge_retrieval_training_cycle import ISSUE_LOCATOR_HINTS

DELTA = Path(
    "data/evaluations/general-enquiries/"
    "LegalBot-GE-2026-09-02-mechanical-repair-delta-r1/visible/RESULTS.jsonl"
)
PARA_29 = (
    "paragraph 29 As to issue (a), the judge found that the DRP gave rise to a "
    "condition precedent: see [55]-[58]. There is no cross appeal by CAP in respect "
    "of that finding. It may be important to note, however, that the judge said that "
    "this conclusion was based on paragraph 2, paragraph 3.1, paragraph 3.2 and "
    "paragraph 7.1 of schedule 26, the last of which permitted recourse to the court "
    "“to the extent not finally resolved pursuant to the DRP”."
)
PARA_30 = (
    "paragraph 30 As to issue (b), the judge found that the DRP was not enforceable: "
    "see [59]-[66]. The challenge to that conclusion comprises Ground 1 of the appeal."
)


def _load_delta() -> list[dict[str, object]]:
    return [json.loads(line) for line in DELTA.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_kajima_29_30_hint_delta_is_three_mediation_cases() -> None:
    if not DELTA.is_file():
        return
    rows = _load_delta()
    affected = derive_kajima_29_30_affected_case_ids(rows, ISSUE_LOCATOR_HINTS)
    assert affected == (
        "international-commercial-mediation:cp-d01",
        "international-commercial-mediation:cp-d05",
        "international-commercial-mediation:cp-d09",
    )
    mediation = [row for row in rows if row.get("topic_id") == "international-commercial-mediation"]
    unchanged = [
        str(row["case_id"])
        for row in mediation
        if not kajima_29_30_hint_dependency_changed(row, ISSUE_LOCATOR_HINTS)
    ]
    assert "international-commercial-mediation:cp-d17" in unchanged
    assert "international-commercial-mediation:cp-d09" not in unchanged


def test_kajima_29_supports_multi_tier_and_not_interim_relief() -> None:
    d09 = {
        "case_id": "international-commercial-mediation:cp-d09",
        "topic_id": "international-commercial-mediation",
        "issue_tags": ["multi-tier-clause", "refusal"],
        "question": (
            "Our dispute clause says negotiation first, then mediation, then court. "
            "The other side will not cooperate. What can we do without getting the next step wrong?"
        ),
    }
    d05 = {
        "case_id": "international-commercial-mediation:cp-d05",
        "topic_id": "international-commercial-mediation",
        "issue_tags": ["mediation", "interim-relief", "cross-border"],
        "question": "The other company is overseas. Can we mediate while also asking a court to protect assets?",
    }
    accept_29 = decide_kajima_attachment(
        d09, title=KAJIMA_TITLE, locator=PARAGRAPH_29, stored_text=PARA_29
    )
    refuse_30 = decide_kajima_attachment(
        d09, title=KAJIMA_TITLE, locator=PARAGRAPH_30, stored_text=PARA_30
    )
    refuse_d05 = decide_kajima_attachment(
        d05, title=KAJIMA_TITLE, locator=PARAGRAPH_29, stored_text=PARA_29
    )
    assert accept_29["decision"] == "ATTACH"
    assert accept_29["paragraph_role"] == "OPERATIVE"
    assert refuse_30["decision"] == "REFUSE"
    assert refuse_30["paragraph_role"] == "PROCEDURAL"
    assert refuse_d05["decision"] == "REFUSE"
    assert refuse_d05["refuse_reason"] == "beyond_kajima_dispute_resolution_scope_interim_relief"
    in_scope, _reason = kajima_29_in_scope(str(d09["question"]), d09["issue_tags"])
    assert in_scope is True


def test_discovery_of_attachable_kajima_locator_does_not_execute_attach() -> None:
    blocked = execute_kajima_attachments(
        route="GENERIC_RETRIEVAL",
        decisions=[{"case_id": "international-commercial-mediation:cp-d09", "decision": "ATTACH"}],
    )
    assert blocked["attach_executed"] is False
    assert blocked["refused_reason"] == OUTSIDE_TARGETED_MEDIATION_FAMILY
    allowed = execute_kajima_attachments(
        route=TARGETED_MEDIATION_FAMILY,
        decisions=[{"case_id": "international-commercial-mediation:cp-d09", "decision": "ATTACH"}],
    )
    assert allowed["attach_executed"] is True
    assert allowed["accepted_case_ids"] == ["international-commercial-mediation:cp-d09"]
    assert ATTACHABLE_PENDING_TARGETED_FAMILY != "attached"


def test_case_174_hints_include_kajima_29_and_not_cable() -> None:
    hints = locator_hints_for_case(
        ["cross-border", "multi-tier-clause", "icc-mediation", "certainty", "stay"],
        ISSUE_LOCATOR_HINTS,
    )
    assert (KAJIMA_TITLE, PARAGRAPH_29) in hints
    assert (KAJIMA_TITLE, PARAGRAPH_30) in hints
    assert all("cable" not in title.casefold() for title, _locator in hints)
    assert all("arbitration act 1996" not in title.casefold() for title, _locator in hints)
    assert CASE_174 == "international-commercial-mediation:cp-d01"


def test_mediation_family_kajima_delta_pack_records_test_history_and_closes_queue() -> None:
    pack = Path(
        "data/evaluations/general-enquiries/"
        "LegalBot-GE-2026-09-02-mediation-family-kajima-delta-r1"
    )
    if not pack.is_dir():
        return
    receipt = json.loads((pack / "STATE-TRANSITION-RECEIPT.json").read_text(encoding="utf-8"))
    history = json.loads((pack / "TEST-HISTORY-RECEIPT.json").read_text(encoding="utf-8"))
    assert history["initial_unit_test_result"] == "FAIL"
    assert history["actual_remaining_runnable_count"] == 1
    assert history["later_test_result"] == "PASS"
    assert history["do_not_describe_first_run_as_passing"] is True
    assert receipt["content_sha256"] == (
        "ab9cf937ba2ea862dc1eaa4599bd5fb948b1188e8a82bea160c4c2b0b024e9ea"
    )
    assert receipt["frozen_r2_results_sha256"] == (
        "a3142fce995b7ae575864ae8411e9346d084306bf1197a4153326a8506a0908c"
    )
    assert receipt["full_331_r3_executed"] is False
    assert receipt["qualified_legal_review"] == "NOT_STARTED"
    assert receipt["answer_gold"] == "NOT_STARTED"
    assert receipt["dependency_affected_mediation_family_case_ids"] == [
        "international-commercial-mediation:cp-d01",
        "international-commercial-mediation:cp-d05",
        "international-commercial-mediation:cp-d09",
    ]
    assert receipt["cp_d09_is_only_affected_case"] is False
    assert receipt["remaining_mediation_family_runnable_count"] == 0
    assert receipt["mediation_mechanical_queue_closed"] is True
    assert receipt["named_case_174"]["kajima_locators"] == ["paragraph 29"]
    assert receipt["named_case_174"]["no_cable_and_wireless"] is True
    r2 = Path(
        "data/evaluations/general-enquiries/"
        "LegalBot-GE-2026-09-02-visible-331-diagnostic-r2/visible/RESULTS.jsonl"
    )
    digest = hashlib.sha256(r2.read_bytes()).hexdigest()
    assert digest == receipt["frozen_r2_results_sha256"]


def test_interim_relief_refuses_icc_and_keeps_cpr_25() -> None:
    question = (
        "The other company is overseas. Can we mediate while also asking a court "
        "to protect assets?"
    )
    tags = ["mediation", "interim-relief", "cross-border"]
    allowed, reason = mediation_family_locator_allowed(
        "ICC Mediation Rules (contractually incorporated edition)",
        "article 5",
        question,
        tags,
    )
    assert allowed is False
    assert "interim_relief" in reason
    allowed, _reason = mediation_family_locator_allowed(
        "The Civil Procedure Rules 1998",
        "rule 25.1",
        question,
        tags,
    )
    assert allowed is True
    allowed, _reason = mediation_family_locator_allowed(
        "The Civil Procedure Rules 1998",
        "rule 1.1",
        question,
        tags,
    )
    assert allowed is False


def test_filter_drops_off_issue_icc_article_5_on_multi_tier() -> None:
    question = (
        "Our dispute clause says negotiation first, then mediation, then court. "
        "The other side will not cooperate. What can we do without getting the "
        "next step wrong?"
    )
    tags = ["multi-tier-clause", "refusal"]
    icc_quote = (
        "Selection of the Mediator 1 – The parties may jointly nominate a Mediator "
        "for confirmation by the Centre."
    )
    kept, dropped = filter_attached_evidence_rows(
        [
            {
                "title": "ICC Mediation Rules (contractually incorporated edition)",
                "locator": "article 5",
                "quote": icc_quote,
                "stored_text": icc_quote,
            },
            {
                "title": KAJIMA_TITLE,
                "locator": "paragraph 29",
                "quote": PARA_29,
                "stored_text": PARA_29,
            },
        ],
        question=question,
        issue_tags=tags,
    )
    assert [item["locator"] for item in kept] == ["paragraph 29"]
    assert any(item["locator"] == "article 5" for item in dropped)
