from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.contracts.schema_registry import ContractSchemaRegistry
from app.evaluation.ge_currentness_packets import (
    CASE_174,
    CASE_312,
    EXPECTED_CURRENTNESS,
    EXPECTED_FACTUAL_HOLD,
    EXPECTED_FACTUAL_PASS,
    EXPECTED_TOTAL,
    OWNER_CURRENTNESS_CUTOFF,
    applicable_law_date_fields,
    build_currentness_packet,
    build_locator_record,
    build_packets_for_rows,
    classify_source_type,
    evidence_manifest_hash,
    full_331_guard_result,
    load_latest_delta_rows,
    mutation_guard,
    reconcile_latest_routes,
    render_topic_batch,
    route_sets,
    select_currentness_cases,
    select_representative_pilot_ids,
    sha256_text,
    summarize_packets,
    validate_packet,
    write_currentness_pack,
)
from app.evaluation.ge_currentness_subrouter import CURRENTNESS_SUBREASONS
from app.evaluation.ge_hold_reason_router import route_hold
from app.evaluation.ge_phase2_progress import NOT_STARTED, NO_OP_UNCHANGED_INPUTS

DELTA_RESULTS = Path(
    "data/evaluations/general-enquiries/"
    "LegalBot-GE-2026-09-03-mechanical-repair-delta-r1/visible/RESULTS.jsonl"
)


def _currentness_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "case_id": "contract-law:cp-d99",
        "topic_id": "contract-law",
        "scenario_family_id": "cp-d99",
        "question": "Does this statutory duty apply in England?",
        "user_facing_answer": "The selected provision is quoted below.",
        "answer": "The selected provision is quoted below.",
        "issue_tags": ["currentness"],
        "planner_output": "Identify the applicable provision and date.",
        "factual_result": {
            "outcome": "FACTUAL_HOLD",
            "checks": {
                "claim_evidence_support": "PASS",
                "requested_date_and_currentness": "FAIL",
                "jurisdiction_scope": "PASS",
            },
            "reasons": {"requested_date_and_currentness": "currentness unverified"},
            "diagnostic_checks": {},
        },
        "evidence": [
            {
                "title": "Limitation Act 1980",
                "locator": "section 2",
                "quote": "An action founded on tort shall not be brought after the expiration of six years.",
                "stored_text": "An action founded on tort shall not be brought after the expiration of six years.",
                "evidence_span_sha256": "a" * 64,
                "source_version_id": "src-limitation-1980",
                "chunk_id": "chunk-1",
                "stable_identifier": "ukpga-1980-58",
                "canonical_url": "https://www.legislation.gov.uk/ukpga/1980/58",
                "currentness_verified": False,
                "currentness_reviewed_as_of_date": "2026-08-14",
                "provision_extent_status": "unverified",
                "unapplied_effect_count": 3,
                "jurisdiction": "England and Wales",
            }
        ],
    }
    row.update(overrides)
    return row


@pytest.fixture(scope="module")
def latest_rows() -> list[dict[str, object]]:
    rows = load_latest_delta_rows()
    assert len(rows) == EXPECTED_TOTAL
    return rows


@pytest.fixture(scope="module")
def latest_reconciliation(latest_rows: list[dict[str, object]]) -> dict[str, object]:
    return reconcile_latest_routes(latest_rows)


@pytest.fixture(scope="module")
def currentness_rows(latest_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    return select_currentness_cases(latest_rows)


def test_latest_route_counts_reconcile_to_331(latest_reconciliation: dict[str, object]) -> None:
    assert latest_reconciliation["status"] == "RECONCILED"
    stored = latest_reconciliation["stored_counts"]
    assert stored["FACTUAL_PASS"] == EXPECTED_FACTUAL_PASS
    assert stored["FACTUAL_HOLD"] == EXPECTED_FACTUAL_HOLD
    assert stored["total"] == EXPECTED_TOTAL
    recomputed = latest_reconciliation["recomputed_counts"]
    assert recomputed["sum_routes_and_pass"] == EXPECTED_TOTAL
    assert (
        recomputed["CURRENTNESS_UNRESOLVED"]
        + recomputed["JURISDICTION_SCOPE_REVIEW"]
        + recomputed["LEFTOVER_CLAIM_OR_NO_EVIDENCE"]
        + recomputed["FACT_DEPENDENT_OUTCOME"]
        + recomputed["FACTUAL_PASS"]
        == EXPECTED_TOTAL
    )


def test_currentness_set_contains_exactly_211_unique_case_ids(
    latest_reconciliation: dict[str, object],
) -> None:
    ids = latest_reconciliation["selected_currentness_case_ids"]
    assert len(ids) == EXPECTED_CURRENTNESS
    assert len(set(ids)) == EXPECTED_CURRENTNESS


def test_route_sets_are_pairwise_disjoint(latest_rows: list[dict[str, object]]) -> None:
    grouped = route_sets(latest_rows)
    sets = {
        "currentness": grouped["currentness"],
        "jurisdiction": grouped["jurisdiction"],
        "leftover": grouped["leftover"],
        "case_312": grouped["fact_dependent"],
    }
    names = list(sets)
    for index, left in enumerate(names):
        for right in names[index + 1 :]:
            assert sets[left] & sets[right] == set(), f"{left} ∩ {right}"


def test_case_174_is_only_in_jurisdiction_route(latest_rows: list[dict[str, object]]) -> None:
    grouped = route_sets(latest_rows)
    assert CASE_174 in grouped["jurisdiction"]
    assert CASE_174 not in grouped["currentness"]
    assert CASE_174 not in grouped["leftover"]
    assert CASE_174 not in grouped["fact_dependent"]
    assert CASE_174 not in grouped["factual_pass"]


def test_case_312_is_only_in_fact_dependent_route(latest_rows: list[dict[str, object]]) -> None:
    grouped = route_sets(latest_rows)
    assert CASE_312 in grouped["fact_dependent"]
    assert CASE_312 not in grouped["currentness"]
    assert CASE_312 not in grouped["jurisdiction"]
    assert CASE_312 not in grouped["leftover"]
    assert CASE_312 not in grouped["factual_pass"]


def test_all_currentness_cases_have_evidence_present(
    latest_rows: list[dict[str, object]],
    currentness_rows: list[dict[str, object]],
) -> None:
    grouped = route_sets(latest_rows)
    for row in currentness_rows:
        hold = grouped["holds"][row["case_id"]]
        assert hold["evidence_present"] is True
        assert row.get("evidence")


def test_all_currentness_cases_have_claim_support_pass(
    latest_rows: list[dict[str, object]],
    currentness_rows: list[dict[str, object]],
) -> None:
    grouped = route_sets(latest_rows)
    for row in currentness_rows:
        hold = grouped["holds"][row["case_id"]]
        assert hold["claim_support_status"] == "PASS"


def test_case_count_is_not_confused_with_locator_count(
    latest_reconciliation: dict[str, object],
    currentness_rows: list[dict[str, object]],
) -> None:
    locator_count = latest_reconciliation["locator_count_across_selected"]
    assert len(currentness_rows) == EXPECTED_CURRENTNESS
    assert locator_count == 593
    assert locator_count != EXPECTED_CURRENTNESS
    assert locator_count > EXPECTED_CURRENTNESS


def test_packet_preserves_question_answer_and_evidence_hashes() -> None:
    row = _currentness_row()
    packet = build_currentness_packet(row)
    assert packet["question"] == row["question"]
    assert packet["candidate_answer"] == row["user_facing_answer"]
    assert packet["question_hash"] == sha256_text(str(row["question"]))
    assert packet["answer_hash"] == sha256_text(str(row["user_facing_answer"]))
    assert packet["evidence_manifest_hash"] == evidence_manifest_hash(row)


def test_packet_preserves_exact_locator_and_evidence_spans() -> None:
    row = _currentness_row()
    packet = build_currentness_packet(row)
    evidence = row["evidence"][0]
    locator = packet["locators"][0]
    assert locator["exact_locator"] == evidence["locator"]
    assert locator["exact_supporting_passage"] == evidence["quote"]
    assert locator["evidence_span_sha256"] == evidence["evidence_span_sha256"]


def test_packet_separates_owner_cutoff_from_applicable_law_date() -> None:
    packet = build_currentness_packet(
        _currentness_row(question="As at 15 January 2024, did section 9 apply?")
    )
    assert packet["owner_currentness_cutoff"] == OWNER_CURRENTNESS_CUTOFF
    assert packet["applicable_law_date"] == "2024-01-15"
    assert packet["owner_currentness_cutoff"] != packet["applicable_law_date"]


def test_historic_question_is_not_forced_to_2026_law() -> None:
    fields = applicable_law_date_fields("On 15 January 2024 a video-witnessed will was signed.")
    assert fields["applicable_law_date"] == "2024-01-15"
    assert fields["applicable_law_date_basis"] == "QUESTION_AS_OF_DATE"
    packet = build_currentness_packet(
        _currentness_row(question="On 15 January 2024 a video-witnessed will was signed.")
    )
    assert packet["applicable_law_date"] != OWNER_CURRENTNESS_CUTOFF
    assert packet["locators"][0]["relevant_legal_date"] == "2024-01-15"


def test_prospective_amendment_is_not_treated_as_in_force() -> None:
    row = _currentness_row(
        question="The new statutory subscription-contract regime was not yet in force on 28 August 2026.",
        evidence=[
            {
                "title": "Consumer Rights Act 2015",
                "locator": "section 2",
                "quote": "The new regime is not yet in force for these contracts.",
                "stored_text": "The new regime is not yet in force for these contracts.",
                "evidence_span_sha256": "b" * 64,
                "source_version_id": "src-cra",
                "chunk_id": "chunk-2",
                "stable_identifier": "ukpga-2015-15",
                "currentness_verified": False,
                "currentness_reviewed_as_of_date": "2026-08-14",
                "provision_extent_status": "unverified",
                "unapplied_effect_count": 12,
            }
        ],
    )
    packet = build_currentness_packet(row)
    record = packet["locators"][0]
    assert record["prospective_amendment_treated_as_in_force"] is False
    assert "not treated as in force" in record["prospective_amendments"]
    assert record["authority_status"] != "CURRENT"


def test_commencement_and_transitional_fields_fail_closed() -> None:
    packet = build_currentness_packet(_currentness_row())
    record = packet["locators"][0]
    assert record["commencement_information"] in {
        "not_recorded",
        "mentioned_in_selected_text_not_verified",
    }
    assert record["transitional_or_savings_provisions"] in {
        "not_recorded",
        "mentioned_in_selected_text_not_verified",
    }
    assert "commenced" not in record["commencement_information"].casefold() or record[
        "commencement_information"
    ].startswith("mentioned")
    assert packet["currentness_status"] == "UNRESOLVED"


def test_extent_uncertainty_remains_unresolved() -> None:
    packet = build_currentness_packet(_currentness_row())
    assert packet["locators"][0]["territorial_extent"] == "unverified"
    assert packet["currentness_status"] == "UNRESOLVED"
    assert packet["owner_currentness_decision"] == NOT_STARTED


def test_absence_of_negative_case_treatment_does_not_auto_approve() -> None:
    record = build_locator_record(
        {
            "title": "Osborn v The Parole Board",
            "locator": "paragraph 2",
            "quote": "Fairness requires disclosure.",
            "stored_text": "Fairness requires disclosure.",
            "evidence_span_sha256": "c" * 64,
            "source_version_id": "src-osborn",
            "chunk_id": "chunk-3",
            "stable_identifier": "uksc-2013-61",
        },
        applicable_law_date="2026-08-28",
        question="What does fairness require?",
    )
    assert record["negative_treatment_found"] is False
    assert record["owner_status_decision"] == NOT_STARTED
    assert record["authority_status"] == "UNRESOLVED"
    assert record["authority_status"] != "CURRENT"


def test_owner_decision_fields_are_blank() -> None:
    packet = build_currentness_packet(_currentness_row())
    assert packet["owner_decision"] == ""
    assert packet["owner_currentness_decision"] == NOT_STARTED
    assert packet["locators"][0]["owner_decision"] == ""
    assert packet["review_status"] == NOT_STARTED


def test_packet_preparation_does_not_set_currentness_pass() -> None:
    packet = build_currentness_packet(_currentness_row())
    assert packet["currentness_status"] == "UNRESOLVED"
    assert packet["factual_status"] == "FACTUAL_HOLD"
    assert packet["currentness_status"] != "PASS"


def test_packet_preparation_does_not_set_qualified_legal_review() -> None:
    packet = build_currentness_packet(_currentness_row())
    assert packet["qualified_legal_review"] == NOT_STARTED


def test_packet_preparation_does_not_set_answer_gold() -> None:
    packet = build_currentness_packet(_currentness_row())
    assert packet["answer_legal_gold"] == NOT_STARTED
    assert packet["legal_gold"] is False


def test_packet_preparation_does_not_set_admission_or_training() -> None:
    packet = build_currentness_packet(_currentness_row())
    assert packet["admitted"] is False
    assert packet["full_current_law_eligible"] is False
    assert packet["answer_weight_training"] == NOT_STARTED


def test_packet_preparation_does_not_open_sealed_unseen() -> None:
    packet = build_currentness_packet(_currentness_row())
    assert packet["sealed_unseen_execution"] == NOT_STARTED
    guard = mutation_guard()
    assert guard["sealed_unseen_not_opened"] is True


def test_packet_preparation_does_not_rerun_full_331() -> None:
    from scripts.run_ge_retrieval_training_cycle import run

    try:
        result = run(Path("/tmp/legalbot-currentness-packets-full-331-guard"))
    except RuntimeError as exc:
        assert "repair-queue" in str(exc) or "Full 331" in str(exc)
        return
    assert result.get("result") == NO_OP_UNCHANGED_INPUTS
    assert full_331_guard_result() == NO_OP_UNCHANGED_INPUTS


def test_frozen_baseline_hash_is_unchanged() -> None:
    guard = mutation_guard()
    assert guard["unchanged"] is True
    assert guard["mismatches"] == []
    assert guard["frozen_hashes"]["r2_results"] == (
        "a3142fce995b7ae575864ae8411e9346d084306bf1197a4153326a8506a0908c"
    )


def test_missing_required_currentness_data_marks_packet_incomplete() -> None:
    row = _currentness_row(
        evidence=[
            {
                "title": "Mystery Instrument",
                "locator": "",
                "quote": "",
                "stored_text": "",
                "evidence_span_sha256": "",
                "source_version_id": "",
                "chunk_id": "",
                "stable_identifier": "",
                "currentness_verified": False,
                "provision_extent_status": "unverified",
            }
        ]
    )
    packet = build_currentness_packet(row)
    assert packet["packet_status"] == "INCOMPLETE"
    assert packet["currentness_status"] == "UNRESOLVED"
    assert packet["next_route"] == "CURRENTNESS_PACKET_REPAIR"
    assert packet["missing_fields"]


def test_invalid_or_ambiguous_date_fails_closed() -> None:
    invalid = applicable_law_date_fields("On 32 January 2026 the duty applied.")
    assert invalid["applicable_law_date_status"] == "INVALID_OR_AMBIGUOUS"
    assert invalid["applicable_law_date"] == ""
    ambiguous = applicable_law_date_fields(
        "Compare the law as at 15 January 2024 with 1 May 2026."
    )
    assert ambiguous["applicable_law_date_status"] == "INVALID_OR_AMBIGUOUS"
    packet = build_currentness_packet(
        _currentness_row(question="On 32 January 2026 the duty applied.")
    )
    assert packet["packet_status"] == "INCOMPLETE"
    assert "applicable_law_date" in packet["missing_fields"]
    assert packet["currentness_status"] == "UNRESOLVED"


def test_unavailable_official_source_does_not_generate_current_status() -> None:
    record = build_locator_record(
        {
            "title": "Cable & Wireless plc v IBM United Kingdom Ltd",
            "locator": "paragraph 1",
            "quote": "Official source unavailable.",
            "evidence_span_sha256": "d" * 64,
            "source_version_id": "fail-closed",
            "stable_identifier": "cable-and-wireless-unavailable",
        },
        applicable_law_date="2026-08-28",
        question="Is Cable & Wireless available?",
    )
    assert record["authority_status"] == "UNRESOLVED"
    assert record["authority_status"] != "CURRENT"
    assert record["in_force_or_status_information"] != "CURRENT"


def test_second_identical_packet_run_is_idempotent() -> None:
    row = _currentness_row()
    first = build_currentness_packet(row)
    second = build_currentness_packet(row)
    assert first == second
    assert first["packet_hash"] == second["packet_hash"]


def test_second_identical_run_creates_no_duplicate_packets(tmp_path: Path) -> None:
    packets = [build_currentness_packet(_currentness_row())]
    reconciliation = {"status": "RECONCILED"}
    test_receipt = {"status": "PASS"}
    mutation = mutation_guard()
    first = write_currentness_pack(
        tmp_path / "pack",
        packets,
        reconciliation=reconciliation,
        test_receipt=test_receipt,
        mutation=mutation,
    )
    second = write_currentness_pack(
        tmp_path / "pack",
        packets,
        reconciliation=reconciliation,
        test_receipt=test_receipt,
        mutation=mutation,
    )
    assert first["result"] == "CREATED"
    assert second["result"] == "IDEMPOTENT_UNCHANGED"
    assert second["duplicate_packets_created"] is False
    lines = (tmp_path / "pack/currentness-packet-manifest.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1


def test_packet_order_and_hashes_are_deterministic(currentness_rows: list[dict[str, object]]) -> None:
    sample = currentness_rows[:8] + currentness_rows[-4:]
    first = build_packets_for_rows(list(reversed(sample)))
    second = build_packets_for_rows(sample)
    assert [item["case_id"] for item in first] == sorted(row["case_id"] for row in sample)
    assert [item["packet_hash"] for item in first] == [item["packet_hash"] for item in second]


def test_all_211_packets_render_without_truncation(currentness_rows: list[dict[str, object]]) -> None:
    packets = build_packets_for_rows(currentness_rows)
    assert len(packets) == EXPECTED_CURRENTNESS
    registry = ContractSchemaRegistry.from_project_root(Path.cwd())
    rendered_by_topic: dict[str, str] = {}
    for packet in packets:
        validate_packet(packet)
        registry.validate_new(packet, verify_digest=False)
        assert packet["currentness_subreason"] in CURRENTNESS_SUBREASONS
        assert packet["currentness_status"] == "UNRESOLVED"
        assert packet["owner_decision"] == ""
        assert packet["locator_count"] == len(packet["locators"])
        topic = str(packet["topic"])
        rendered_by_topic.setdefault(topic, "")
    grouped: dict[str, list[dict[str, object]]] = {}
    for packet in packets:
        grouped.setdefault(str(packet["topic"]), []).append(packet)
    for topic, group in grouped.items():
        rendered = render_topic_batch(topic, group)
        for packet in group:
            assert packet["question"] in rendered
            assert packet["candidate_answer"] in rendered
            for record in packet["locators"]:
                assert record["exact_locator"] in rendered
                assert record["exact_supporting_passage"] in rendered
    summary = summarize_packets(packets)
    assert summary["packet_count"] == EXPECTED_CURRENTNESS
    assert summary["locator_count"] == 593
    assert summary["owner_decision_blank"] is True


def test_contractual_and_procedural_source_types() -> None:
    assert classify_source_type("ICC Mediation Rules (contractually incorporated edition)") == (
        "CONTRACTUAL_RULE"
    )
    assert classify_source_type("The Civil Procedure Rules 1998") == "PROCEDURAL_RULE"
    packet = build_currentness_packet(
        _currentness_row(
            evidence=[
                {
                    "title": "ICC Mediation Rules (contractually incorporated edition)",
                    "locator": "article 5",
                    "quote": "The Centre may appoint a Mediator.",
                    "stored_text": "The Centre may appoint a Mediator.",
                    "evidence_span_sha256": "e" * 64,
                    "source_version_id": "src-icc",
                    "chunk_id": "chunk-icc",
                    "stable_identifier": "icc-mediation-rules-2014",
                    "currentness_verified": False,
                    "currentness_reviewed_as_of_date": "2014-01-01",
                    "provision_extent_status": "unverified",
                }
            ]
        )
    )
    assert packet["locators"][0]["source_type"] == "CONTRACTUAL_RULE"
    assert "CONTRACTUALLY_INCORPORATED_EDITION" in packet["currentness_subreasons"] or packet[
        "currentness_subreason"
    ] == "CONTRACTUALLY_INCORPORATED_EDITION"


def test_pilot_covers_representative_categories(latest_rows: list[dict[str, object]]) -> None:
    pilot = select_representative_pilot_ids(latest_rows)
    assert 8 <= len(pilot["case_ids"]) <= 16
    present = {name for name, value in pilot["categories"].items() if value}
    assert "historic_as_of" in present
    assert "case_law_treatment" in present
    assert "procedural_rule_version" in present
    assert "multiple_locators" in present
    assert "incomplete_currentness_metadata" in present
    grouped = route_sets(latest_rows)
    for case_id in pilot["case_ids"]:
        assert case_id in grouped["currentness"]
        assert case_id != CASE_174
        assert case_id != CASE_312


def test_currentness_hold_reason_is_not_generic_only(currentness_rows: list[dict[str, object]]) -> None:
    packet = build_currentness_packet(currentness_rows[0])
    assert packet["hold_reason"] == "CURRENTNESS_UNRESOLVED"
    assert packet["currentness_subreason"] != "CURRENTNESS_UNRESOLVED"
    assert packet["currentness_subreason"] in CURRENTNESS_SUBREASONS


def test_routed_synthetic_row_is_currentness() -> None:
    routed = route_hold(_currentness_row())
    assert routed["hold_reason_code"] == "CURRENTNESS_UNRESOLVED"
    assert routed["claim_support_status"] == "PASS"
    assert routed["evidence_present"] is True
