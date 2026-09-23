from __future__ import annotations

from pathlib import Path

import pytest

from app.evaluation.ge_currentness_packets import (
    CASE_174,
    CASE_312,
    EXPECTED_R2_RESULTS,
    load_jsonl,
    load_latest_delta_rows,
    mutation_guard,
    reconcile_latest_routes,
    repair_currentness_packet,
    route_sets,
)
from app.evaluation.ge_evaluation_completion_campaign import (
    DEFAULT_MASTER_PACK,
    classify_six_no_evidence,
    load_currentness_r1_packets,
)
from app.evaluation.ge_fact_dependent_packets import build_fact_dependent_packet
from app.evaluation.ge_jurisdiction_packets import CASE_174_REVIEWER_QUESTION, build_jurisdiction_packet
from app.evaluation.ge_phase2_progress import AWAITING_OWNER_EVALUATION_REVIEW, NOT_STARTED
from app.evaluation.ge_qualified_review_packets import build_factual_pass_packet
from app.evaluation.ge_residual_support_packets import build_residual_packet
from scripts.run_ge_retrieval_training_cycle import ISSUE_LOCATOR_HINTS, TOPIC_SOURCES

MASTER = DEFAULT_MASTER_PACK
CURRENTNESS_R1 = Path(
    "data/evaluations/general-enquiries/LegalBot-GE-2026-09-03-currentness-packets-r1"
)


class _FakeIndex:
    def __init__(self, recovered: dict[str, str] | None = None, *, empty: bool = False) -> None:
        if empty:
            self.recovered = {}
        else:
            self.recovered = recovered or {
                "source_version_date": "2026-08-14",
                "source_version_date_origin": "test",
            }

    def lookup_locator(self, record: dict[str, object]) -> dict[str, str]:
        if str(record.get("source_version_date") or "") in {"", "not_recorded"}:
            return dict(self.recovered)
        return {}


@pytest.fixture(scope="module")
def latest_rows() -> list[dict[str, object]]:
    rows = load_latest_delta_rows()
    assert len(rows) == 331
    return rows


@pytest.fixture(scope="module")
def grouped(latest_rows: list[dict[str, object]]) -> dict[str, object]:
    return route_sets(latest_rows)


def test_frozen_r2_hash_is_unchanged() -> None:
    mutation = mutation_guard()
    assert mutation["unchanged"] is True
    assert mutation["frozen_hashes"]["r2_results"] == EXPECTED_R2_RESULTS


def test_latest_routes_still_reconcile(latest_rows: list[dict[str, object]]) -> None:
    receipt = reconcile_latest_routes(latest_rows)
    assert receipt["status"] == "RECONCILED"


def test_repair_recovers_missing_source_version_date() -> None:
    packets = load_currentness_r1_packets(CURRENTNESS_R1)
    incomplete = next(item for item in packets if item["packet_status"] == "INCOMPLETE" and item["case_id"] != "land-law:cp-d05")
    repaired = repair_currentness_packet(incomplete, _FakeIndex())
    assert repaired["question"] == incomplete["question"]
    assert repaired["candidate_answer"] == incomplete["candidate_answer"]
    assert repaired["answer_hash"] == incomplete["answer_hash"]
    assert repaired["evidence_manifest_hash"] == incomplete["evidence_manifest_hash"]
    assert repaired["currentness_status"] == "UNRESOLVED"
    assert repaired["owner_decision"] == ""
    assert repaired["packet_status"] == "READY_FOR_OWNER_CURRENTNESS_REVIEW"
    assert repaired["missing_fields"] == []


def test_repair_without_metadata_is_incomplete_final() -> None:
    packets = load_currentness_r1_packets(CURRENTNESS_R1)
    incomplete = next(item for item in packets if item["packet_status"] == "INCOMPLETE" and item["case_id"] != "land-law:cp-d05")
    repaired = repair_currentness_packet(incomplete, _FakeIndex(empty=True))
    assert repaired["packet_status"] == "INCOMPLETE_FINAL"
    assert repaired["currentness_status"] == "UNRESOLVED"
    assert repaired["owner_decision"] == ""
    assert repaired["next_route"] == "CURRENTNESS_METADATA_REPAIR_EXHAUSTED"
    assert repaired["missing_fields"]


def test_land_law_cp_d05_stays_fail_closed_on_ambiguous_dates() -> None:
    packets = load_currentness_r1_packets(CURRENTNESS_R1)
    packet = next(item for item in packets if item["case_id"] == "land-law:cp-d05")
    repaired = repair_currentness_packet(packet, _FakeIndex())
    assert repaired["applicable_law_date_status"] == "INVALID_OR_AMBIGUOUS"
    assert repaired["applicable_law_date"] in {"", "not_recorded"}
    assert repaired["packet_status"] == "INCOMPLETE_FINAL"
    assert "applicable_law_date" in repaired["missing_fields"]
    assert repaired["currentness_status"] == "UNRESOLVED"


def test_case_174_jurisdiction_packet_preserves_accepted_and_excludes_forbidden(
    latest_rows: list[dict[str, object]], grouped: dict[str, object]
) -> None:
    row = next(item for item in latest_rows if item["case_id"] == CASE_174)
    packet = build_jurisdiction_packet(row, routed=grouped["holds"][CASE_174])
    assert packet["exact_question_for_reviewer"] == CASE_174_REVIEWER_QUESTION
    titles = " ".join(str(item.get("title") or "") for item in packet["accepted_authorities"]).casefold()
    assert "icc" in titles
    assert "ohpen" in titles
    assert "kajima" in titles
    assert "churchill" in titles
    excluded = " ".join(str(item.get("title") or "") for item in packet["excluded_authorities"]).casefold()
    assert "cable & wireless" in excluded
    assert "arbitration act 1996" in excluded
    attached = " ".join(str(item.get("title") or "") for item in packet["attached_authorities"]).casefold()
    assert "cable & wireless" not in attached
    assert "arbitration act 1996" not in attached
    assert packet["owner_jurisdiction_decision"] == ""
    assert packet["qualified_legal_review"] == NOT_STARTED
    assert packet["factual_status"] == "FACTUAL_HOLD"


def test_six_no_evidence_cases_are_genuinely_empty(
    latest_rows: list[dict[str, object]], grouped: dict[str, object]
) -> None:
    leftover = [item for item in latest_rows if item["case_id"] in grouped["leftover"]]
    classified = classify_six_no_evidence(leftover, grouped["holds"])
    assert len(classified) == 6
    expected = {
        "ai-and-data-protection:cp-d03",
        "ai-and-data-protection:cp-d07",
        "ai-and-data-protection:cp-d09",
        "competition-law:cp-d02",
        "land-law:cp-d17",
        "tort-law:cp-d13",
    }
    assert {item["case_id"] for item in classified} == expected
    for item in classified:
        assert item["no_evidence_class"] == "GENUINELY_EVIDENCE_PRESENT_FALSE"
        assert item["evidence_present_on_latest_record"] is False
        assert item["evidence_row_count"] == 0


def test_residual_packet_exhausts_mechanical_route(
    latest_rows: list[dict[str, object]], grouped: dict[str, object]
) -> None:
    leftover = [item for item in latest_rows if item["case_id"] in grouped["leftover"]]
    row = leftover[0]
    packet = build_residual_packet(
        row,
        routed=grouped["holds"][str(row["case_id"])],
        locator_hints=ISSUE_LOCATOR_HINTS,
        topic_sources=TOPIC_SOURCES,
    )
    assert packet["mechanical_status"] == "EXHAUSTED"
    assert packet["terminal_for_mechanical_route"] is True
    assert packet["terminal_for_entire_pipeline"] is False
    assert packet["do_not_generic_retrieve"] is True
    assert packet["owner_residual_decision"] == ""
    assert packet["qualified_legal_review"] == NOT_STARTED


def test_case_312_fact_dependent_packet_is_conditional_not_definitive(
    latest_rows: list[dict[str, object]], grouped: dict[str, object]
) -> None:
    row = next(item for item in latest_rows if item["case_id"] == CASE_312)
    packet = build_fact_dependent_packet(row, routed=grouped["holds"][CASE_312])
    assert packet["factual_status"] == "FACTUAL_HOLD"
    assert packet["factual_outcome"] == "HOLD"
    assert packet["packet_status"] == "READY_FOR_FACT_DEPENDENT_REVIEW"
    assert packet["answer_may_be_conditionally_approvable"] is True
    assert packet["applicable_law_date"] == "2024-01-15"
    titles = " ".join(item["title"] for item in packet["formality_authorities"]).casefold()
    assert "wills act 1837" in titles
    assert "2020" in titles
    assert "2022" in titles
    assert "the will is valid" not in packet["proposed_conditional_answer"].casefold()
    assert packet["owner_fact_dependent_decision"] == ""
    assert packet["qualified_legal_review"] == NOT_STARTED


def test_factual_pass_packet_is_not_gold(latest_rows: list[dict[str, object]], grouped: dict[str, object]) -> None:
    case_id = sorted(grouped["factual_pass"])[0]
    row = next(item for item in latest_rows if item["case_id"] == case_id)
    packet = build_factual_pass_packet(row)
    assert packet["factual_status"] == "FACTUAL_PASS"
    assert packet["qualified_legal_review"] == NOT_STARTED
    assert packet["answer_legal_gold"] == NOT_STARTED
    assert packet["legal_gold"] is False
    assert packet["owner_decision"] == ""


def test_master_pack_if_present_is_awaiting_owner_review() -> None:
    manifest = MASTER / "MASTER-331-EVALUATION-MANIFEST.jsonl"
    if not manifest.is_file():
        pytest.skip("master pack not generated yet")
    records = load_jsonl(manifest)
    assert len(records) == 331
    assert len({item["case_id"] for item in records}) == 331
    assert all(item["owner_decision"] == "" for item in records)
    assert all(item["qualified_legal_review"] == NOT_STARTED for item in records)
    assert all(item["answer_legal_gold"] == NOT_STARTED for item in records)
    state = (MASTER / "receipts/STATE-TRANSITION-RECEIPT.json").read_text(encoding="utf-8")
    assert AWAITING_OWNER_EVALUATION_REVIEW in state
    assert '"evaluation_packet_preparation": "COMPLETE"' in state
    assert '"answer_weight_training": "NOT_STARTED"' in state
    assert '"sealed_unseen_execution": "NOT_STARTED"' in state
    assert CASE_174 in {item["case_id"] for item in records if item["route"] == "JURISDICTION_SCOPE_REVIEW"}
    assert CASE_312 in {item["case_id"] for item in records if item["route"] == "FACT_DEPENDENT_OUTCOME"}
