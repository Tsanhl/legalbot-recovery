from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from scripts import build_v111_phase2a_finite_remediation_owner_packet as builder

OUTPUT_ROOT = builder.REVIEW_ROOT / builder.OUTPUT_ROOT_NAME
EXPECTED = {
    "contracts_content_sha256": "6cebd8b70b3044b0b4533c1036c3aaec1b8ac88c4a43873a585616bc7cd573bf",
    "contracts_file_sha256": "0cd3162c482287e443389dd23ffb4ed8c40774b441076b8e62e5f30b9a7ef4a0",
    "packet_content_sha256": "4b90e576afb84e9982c171b02a108b9b7506d48c222e2076810a34f57f43fa91",
    "packet_file_sha256": "1775e034b680583df1e4b2e7e907798c2fba45efca00a2f033fdfdc2b46b0f3c",
    "package_content_sha256": "7dc740ebf52f82cfac2da42a975bf36d9b277aa27d4b7e1c4734eacd73a323c8",
    "package_file_sha256": "4e12644f3c8c817a3874ed1fa048c09d1d06eb6a070a1ccaef9b85015b3059ae",
    "prompt_file_sha256": "b1d7ea6df721f59f301c95d5b63f371c73dc47681c7a062c904523f26d2ea0a9",
}


def _load(name: str) -> dict[str, Any]:
    value = json.loads((OUTPUT_ROOT / name).read_bytes())
    assert isinstance(value, dict)
    return value


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_sealed(value: dict[str, Any], field: str = "artifact_content_sha256") -> None:
    material = dict(value)
    observed = material.pop(field)
    assert observed == builder._content_sha256(material)


def _walk_no_execution(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in builder.NO_EXECUTION_FLAGS:
                assert nested is False, key
            _walk_no_execution(nested)
    elif isinstance(value, list):
        for nested in value:
            _walk_no_execution(nested)


def test_published_r2_exact_identities_and_checksums() -> None:
    contracts = _load(builder.CONTRACTS_NAME)
    packet = _load(builder.PACKET_NAME)
    package = _load(builder.PACKAGE_NAME)
    _assert_sealed(contracts)
    _assert_sealed(packet)
    _assert_sealed(package)
    assert contracts["artifact_content_sha256"] == EXPECTED["contracts_content_sha256"]
    assert packet["artifact_content_sha256"] == EXPECTED["packet_content_sha256"]
    assert package["artifact_content_sha256"] == EXPECTED["package_content_sha256"]
    assert _file_sha256(OUTPUT_ROOT / builder.CONTRACTS_NAME) == EXPECTED["contracts_file_sha256"]
    assert _file_sha256(OUTPUT_ROOT / builder.PACKET_NAME) == EXPECTED["packet_file_sha256"]
    assert _file_sha256(OUTPUT_ROOT / builder.PACKAGE_NAME) == EXPECTED["package_file_sha256"]
    assert _file_sha256(OUTPUT_ROOT / builder.PROMPT_NAME) == EXPECTED["prompt_file_sha256"]
    expected_lines = {
        f"{_file_sha256(OUTPUT_ROOT / name)}  {name}"
        for name in (
            builder.CONTRACTS_NAME,
            builder.PACKET_NAME,
            builder.PROMPT_NAME,
            builder.PACKAGE_NAME,
        )
    }
    assert set((OUTPUT_ROOT / builder.CHECKSUMS_NAME).read_text().splitlines()) == expected_lines


def test_exact_17_129_partition_covers_all_146_rows_once() -> None:
    contracts = _load(builder.CONTRACTS_NAME)
    rows = contracts["row_outcomes"]
    assert len(rows) == 146
    assert len({row["row_id"] for row in rows}) == 146
    counts = Counter(row["selected_outcome"] for row in rows)
    assert counts == {
        "ADOPT_EXACT_COHORT_REMEDIATION": 17,
        "STRICT_NO_LEGAL_CLAIM_HUMAN_REVIEW_HANDOFF": 129,
    }
    observed_ready = {
        row["row_id"] for row in rows if row["selected_outcome"] == "ADOPT_EXACT_COHORT_REMEDIATION"
    }
    assert observed_ready == set().union(*builder.READY_ROW_IDS_BY_COHORT.values())
    for row in rows:
        _assert_sealed(row, "row_outcome_content_sha256")


def test_all_129_handoffs_are_exact_fail_closed_and_keep_gap_identity() -> None:
    contracts = _load(builder.CONTRACTS_NAME)
    handoffs = [
        row
        for row in contracts["row_outcomes"]
        if row["selected_outcome"] == "STRICT_NO_LEGAL_CLAIM_HUMAN_REVIEW_HANDOFF"
    ]
    assert len(handoffs) == 129
    for row in handoffs:
        contract = row["handoff_contract"]
        _assert_sealed(contract, "handoff_contract_content_sha256")
        assert contract["reason_code"] == "LEGAL_EVIDENCE_OR_REVIEW_GAP"
        assert contract["ui_cta_code"] == "REQUEST_QUALIFIED_HUMAN_LEGAL_REVIEW"
        assert contract["knowledge_gap_event"] is True
        assert contract["matter_information_gap_event"] is False
        assert contract["matter_information_classification"] == (
            "NOT_DETERMINED_FROM_UNCLASSIFIED_HOLD_TEXT"
        )
        assert contract["reply_match_mode"] == "EXACT_UTF8_STRING"
        assert (
            hashlib.sha256(contract["required_user_message"].encode()).hexdigest()
            == contract["required_user_message_sha256"]
        )
        assert row["row_id"] in contract["required_user_message"]
        assert contract["material_gap_erased_or_relabelled"] is False
        assert row["residual_material_gap_retained"] is True
        assert row["new_source_admission_for_this_row"] is False
        for field in (
            "legal_claim_released",
            "legal_rule_released",
            "legal_advice_released",
            "citation_released",
            "evidence_span_released",
            "source_binding_released",
            "answer_model_output_allowed",
            "answer_release_eligible",
            "applied",
        ):
            assert contract[field] is False
        assert contract["requested_review_items"]
        assert contract["residual_blocking_components"]


def test_17_ready_rows_keep_exact_cohort_boundaries() -> None:
    contracts = _load(builder.CONTRACTS_NAME)
    ready = {
        row["row_id"]: row
        for row in contracts["row_outcomes"]
        if row["selected_outcome"] == "ADOPT_EXACT_COHORT_REMEDIATION"
    }
    kinds = Counter(row["cohort_remediation_kind"] for row in ready.values())
    assert kinds == {
        "EXACT_MATTER_INFORMATION_NON_ANSWER": 4,
        "EXACT_REWRITE_EXCLUSION_OR_MATTER_INTAKE_SPLIT": 7,
        "EXACT_SOURCE_BOUND_REMEDIATION_OR_EXCLUSION": 6,
    }
    for row in ready.values():
        assert row["cohort_recommendation_content_sha256s"]
        assert row["answer_release_eligible"] is False
        assert row["technical_success_predeclared"] is False
        if row["cohort"] == "SOURCE_READY_R5":
            assert len(row["exact_non_answer_contract_bindings"]) == 1
            binding = row["exact_non_answer_contract_bindings"][0]
            assert binding["reason_code"] == "MATTER_INFORMATION_INSUFFICIENT"
            assert binding["ui_cta_code"] == ("PROVIDE_MISSING_INFORMATION_OR_REQUEST_HUMAN_REVIEW")


def test_source_decisions_are_exact_ready_row_only_and_admission_complete() -> None:
    contracts = _load(builder.CONTRACTS_NAME)
    decisions = contracts["source_decisions"]
    assert len(decisions) == 25
    assert Counter(item["proposed_action"] for item in decisions) == {
        "RETAIN_EXISTING_EXACT_SOURCE_VERSION": 14,
        "MATERIALIZE_AND_ADMIT_EXACT_BOUND_REPRESENTATION": 5,
        "ADMIT_EXACT_BOUND_REPRESENTATION": 3,
        "RETAIN_EXACT_BOUND_SOURCE_RECORD_NO_NEW_ADMISSION": 3,
    }
    ready_ids = set().union(*builder.READY_ROW_IDS_BY_COHORT.values())
    identities: set[tuple[str | None, str | None]] = set()
    for decision in decisions:
        _assert_sealed(decision, "source_decision_content_sha256")
        assert set(decision["referenced_by_ready_row_ids"]) <= ready_ids
        assert decision["applied"] is False
        identity = (decision["source_version_id"], decision["representation_file_sha256"])
        assert identity not in identities
        identities.add(identity)
        assert len(decision["source_binding_record_content_sha256s"]) == len(
            decision["binding_record_references"]
        )
        for reference in decision["binding_record_references"]:
            _assert_sealed(reference, "binding_reference_content_sha256")
        if decision["proposed_action"] in {
            "ADMIT_EXACT_BOUND_REPRESENTATION",
            "MATERIALIZE_AND_ADMIT_EXACT_BOUND_REPRESENTATION",
        }:
            assert len(decision["representation_file_sha256"]) == 64
            assert decision["source_version_id"]
            assert any(
                decision[field]
                for field in (
                    "canonical_content_sha256s",
                    "normalized_representation_text_sha256s",
                )
            )
    shared = [item for item in decisions if len(item["binding_record_references"]) > 1]
    assert len(shared) == 1
    assert shared[0]["authority_identity_ids"] == ["neutral-citation:[2013] UKSC 61"]
    assert shared[0]["cohorts"] == ["AUTHORITYLESS_R4", "HELD_MISSING_R3"]
    assert set(shared[0]["referenced_by_ready_row_ids"]) == {
        "live30-q30:issue-02",
        "live60-q46:issue-05",
    }


def test_r3_explicitly_supersedes_non_authorizing_r1_and_r2() -> None:
    contracts = _load(builder.CONTRACTS_NAME)
    packet = _load(builder.PACKET_NAME)
    package = _load(builder.PACKAGE_NAME)
    assert (
        contracts["supersedes_r2_contracts_content_sha256"]
        == builder.INPUTS["predecessor_r2_contracts"]["content_sha256"]
    )
    assert (
        packet["supersedes_r2_packet_content_sha256"]
        == builder.INPUTS["predecessor_r2_packet"]["content_sha256"]
    )
    assert (
        package["supersedes_r2_packet_content_sha256"]
        == builder.INPUTS["predecessor_r2_packet"]["content_sha256"]
    )
    assert packet["correction_scope"]["r1_must_not_be_approved_or_executed"] is True
    assert packet["correction_scope"]["r2_must_not_be_approved_or_executed"] is True
    assert (
        packet["correction_scope"][
            "r3_deduplicates_source_actions_by_source_version_and_raw_byte_identity"
        ]
        is True
    )
    prompt = (OUTPUT_ROOT / builder.PROMPT_NAME).read_text()
    assert "neither R1 nor R2 is approved" in prompt


def test_no_execution_flags_are_false_recursively_and_prompt_stays_phase2a_only() -> None:
    contracts = _load(builder.CONTRACTS_NAME)
    packet = _load(builder.PACKET_NAME)
    package = _load(builder.PACKAGE_NAME)
    _walk_no_execution([contracts, packet, package])
    assert packet["single_existing_execution_chain"] == {
        "execution_authority_content_sha256": builder.INPUTS["execution_authority"][
            "content_sha256"
        ],
        "total_count": 1,
        "consumed_count": 0,
        "remaining_count": 1,
        "status": "AVAILABLE_UNSPENT",
        "this_packet_consumes_chain": False,
        "this_packet_creates_second_chain": False,
    }
    prompt = (OUTPUT_ROOT / builder.PROMPT_NAME).read_text()
    for phrase in (
        "one complete source scan",
        "one non-ACTIVE and answer-ineligible successor",
        "does not authorize an answer-model run or answer release",
        "Phase 2B",
        "ACTIVE/PREVIOUS writes",
    ):
        assert phrase in prompt


def test_output_is_private_regular_files_without_symlinks() -> None:
    assert OUTPUT_ROOT.stat().st_mode & 0o777 == 0o700
    expected = {
        builder.CONTRACTS_NAME,
        builder.PACKET_NAME,
        builder.PROMPT_NAME,
        builder.PACKAGE_NAME,
        builder.CHECKSUMS_NAME,
    }
    assert {item.name for item in OUTPUT_ROOT.iterdir()} == expected
    for path in OUTPUT_ROOT.iterdir():
        assert path.is_file()
        assert not path.is_symlink()
        assert path.stat().st_mode & 0o777 == 0o600


def test_builder_is_deterministic_for_fixed_timestamp(tmp_path: Path) -> None:
    created_at = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    first = tmp_path / "first"
    second = tmp_path / "second"
    result1 = builder.build_packet(
        output_root=first,
        output_review_root=tmp_path,
        created_at=created_at,
    )
    result2 = builder.build_packet(
        output_root=second,
        output_review_root=tmp_path,
        created_at=created_at,
    )
    for key in (
        "packet_content_sha256",
        "contracts_content_sha256",
        "package_content_sha256",
        "owner_approval_prompt_file_sha256",
    ):
        assert result1[key] == result2[key]
    assert {path.name: path.read_bytes() for path in first.iterdir()} == {
        path.name: path.read_bytes() for path in second.iterdir()
    }


def test_builder_refuses_overwrite_and_naive_timestamp(tmp_path: Path) -> None:
    output = tmp_path / "packet"
    builder.build_packet(
        output_root=output,
        output_review_root=tmp_path,
        created_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
    )
    with pytest.raises(ValueError, match="finite_packet_output_already_exists"):
        builder.build_packet(
            output_root=output,
            output_review_root=tmp_path,
            created_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
        )
    with pytest.raises(ValueError, match="finite_packet_created_at_must_be_timezone_aware"):
        builder.build_packet(
            output_root=tmp_path / "naive",
            output_review_root=tmp_path,
            created_at=datetime(2026, 8, 28, 12, 0),
        )


def test_input_identity_and_privacy_guards(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(builder.INPUTS["prequalification"], "file_sha256", "0" * 64)
    with pytest.raises(ValueError, match="finite_packet_input_file_invalid:prequalification"):
        builder._load_inputs(builder.REVIEW_ROOT)
    builder._privacy_check("official-url:https://www.legislation.gov.uk/ukpga/1998/41")
    with pytest.raises(ValueError, match="finite_packet_privacy_absolute_path_invalid"):
        builder._privacy_check({"leak": "/Users/example/private.txt"})
    with pytest.raises(ValueError, match="finite_packet_privacy_email_invalid"):
        builder._privacy_check({"leak": "owner@example.com"})


def test_active_and_previous_pointers_remain_absent() -> None:
    assert not (builder.PROJECT_ROOT / "data/indexes/ACTIVE.json").exists()
    assert not (builder.PROJECT_ROOT / "data/indexes/PREVIOUS.json").exists()
    assert os.access(OUTPUT_ROOT, os.R_OK)
