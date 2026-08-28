from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from scripts import build_v111_phase2a_146_superseding_remediation_advisory as builder


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _report_and_rows() -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    report = _load(builder.R3_ROOT / builder.R3_REPORT_NAME)
    rows = {str(row["row_id"]): row for row in report["rows"]}
    return report, rows


@pytest.fixture(scope="module")
def built_baseline(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("phase2a-146-advisory")
    output = root / "advisory-r1"
    patcher = pytest.MonkeyPatch()
    patcher.setattr(builder, "OUTPUT_REVIEW_ROOT", root)
    try:
        result = builder.build_advisory(
            output_root=output,
            created_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
        )
    finally:
        patcher.undo()
    assert result["status"] == builder.STATUS_BLOCKED
    assert result["row_count"] == 146
    assert result["fallback_row_count"] == 0
    assert result["retained_blocker_row_count"] == 146
    assert result["execution_chain_consumed"] is False
    return output


def test_baseline_binds_authoritative_r3_packets_receipts_and_authority(
    built_baseline: Path,
) -> None:
    advisory = _load(built_baseline / builder.ADVISORY_NAME)
    bindings = {item["kind"]: item for item in advisory["authoritative_input_bindings"]}
    assert bindings["prequalification_blocker_report_r3"]["content_sha256"] == (
        builder.R3_REPORT_CONTENT_SHA256
    )
    assert bindings["original_owner_packet_361"]["content_sha256"] == (
        builder.ORIGINAL_PACKET_CONTENT_SHA256
    )
    assert bindings["original_owner_adoption_receipt"]["content_sha256"] == (
        builder.ORIGINAL_RECEIPT_CONTENT_SHA256
    )
    assert bindings["final_owner_packet"]["content_sha256"] == (builder.FINAL_PACKET_CONTENT_SHA256)
    assert bindings["final_owner_adoption_receipt"]["content_sha256"] == (
        builder.FINAL_RECEIPT_CONTENT_SHA256
    )
    assert bindings["single_unspent_execution_authority"]["content_sha256"] == (
        builder.EXECUTION_AUTHORITY_CONTENT_SHA256
    )
    assert bindings["predecessor_146_row_advisory_r1"]["content_sha256"] == (
        builder.PREDECESSOR_ADVISORY_CONTENT_SHA256
    )
    assert advisory["supersedes_advisory_content_sha256"] == (
        builder.PREDECESSOR_ADVISORY_CONTENT_SHA256
    )
    assert advisory["correction_scope"]["no_substantive_row_outcome_changed"] is True
    assert builder._require_seal(advisory, code="invalid") == advisory["artifact_content_sha256"]


def test_baseline_has_exact_146_rows_and_retains_every_blocker(
    built_baseline: Path,
) -> None:
    advisory = _load(built_baseline / builder.ADVISORY_NAME)
    report, rows = _report_and_rows()
    row_advisories = advisory["row_advisories"]
    assert len(row_advisories) == 146
    assert {item["row_id"] for item in row_advisories} == set(rows)
    assert advisory["blocker_row_id_set_sha256"] == report["blocker_row_id_set_sha256"]
    assert all(item["selected_outcome"] == builder.OUTCOME_RETAIN for item in row_advisories)
    assert advisory["outcome_counts"] == {
        builder.OUTCOME_FULL: 0,
        builder.OUTCOME_SCOPE_CHANGE: 0,
        builder.OUTCOME_RETAIN: 146,
        builder.OUTCOME_FALLBACK: 0,
    }
    assert (
        advisory["retained_blocker_boundary"]["successful_phase2a_package_may_be_claimed"] is False
    )
    assert advisory["retained_blocker_boundary"]["all585_may_run_from_this_advisory"] is False


def test_baseline_has_no_blanket_or_automatic_fallback(built_baseline: Path) -> None:
    advisory = _load(built_baseline / builder.ADVISORY_NAME)
    boundary = advisory["fallback_boundary"]
    assert boundary == {
        "automatic_or_blanket_fallback": False,
        "each_fallback_requires_its_own_sealed_row_classification": True,
        "fallback_by_default": False,
        "fallback_row_count": 0,
        "fallback_row_ids": [],
        "knowledge_or_official_source_gap_may_not_be_hidden_as_matter_information_gap": True,
        "wildcards_ranges_or_global_switches_permitted": False,
    }
    with pytest.raises(ValueError, match="blanket_fallback"):
        builder._validate_no_execution_recursively({"fallback_all_rows": True})


def test_single_execution_chain_is_preserved_and_no_execution_is_claimed(
    built_baseline: Path,
) -> None:
    advisory = _load(built_baseline / builder.ADVISORY_NAME)
    package = _load(built_baseline / builder.PACKAGE_NAME)
    assert advisory["single_existing_execution_chain"] == {
        "authority_content_sha256": builder.EXECUTION_AUTHORITY_CONTENT_SHA256,
        "consumed_count": 0,
        "remaining_count": 1,
        "status": "AVAILABLE_UNSPENT",
        "this_advisory_creates_additional_authority": False,
        "this_builder_consumes_chain": False,
        "total_count": 1,
    }
    for name in builder._NO_EXECUTION_FLAGS:
        assert advisory[name] is False
        assert package[name] is False
    builder._validate_no_execution_recursively([advisory, package])


def test_no_execution_field_set_is_at_least_as_strict_as_final_packet_builder() -> None:
    from scripts import build_v111_phase2a_safe_fallback_superseding_owner_packet as prior

    assert set(builder._NO_EXECUTION_FLAGS) == set(prior._NO_EXECUTION_FLAGS) | {
        "answer_release_run"
    }
    assert set(builder._NO_EXECUTION_FLAGS) >= {
        "evaluation_contract_mutated",
        "safe_fallback_decision_applied",
        "source_delta_decisions_applied",
    }


def _span(locator: str = "paragraph 1") -> dict[str, Any]:
    return builder._sealed(
        {
            "schema": builder.EVIDENCE_SPAN_SCHEMA,
            "exact_locator": locator,
            "span_text_sha256": "1" * 64,
        },
        field="evidence_span_content_sha256",
    )


def _evidence_binding() -> dict[str, Any]:
    return builder._sealed(
        {
            "schema": builder.EVIDENCE_BINDING_SCHEMA,
            "canonical_authority_identity_id": "neutral-citation:[2026] UKSC 1",
            "source_version_id": "source-version-test-001",
            "raw_sha256": "2" * 64,
            "canonical_content_sha256": "3" * 64,
            "source_admission_record_content_sha256": "4" * 64,
            "jurisdiction_finding_content_sha256": "5" * 64,
            "currentness_finding_content_sha256": "6" * 64,
            "later_treatment_finding_content_sha256": "7" * 64,
            "evidence_spans": [_span()],
        },
        field="record_content_sha256",
    )


def _full_decision(row: dict[str, Any]) -> dict[str, Any]:
    ordinals = sorted(int(item["component_ordinal"]) for item in row["blocking_components"])
    finding = builder._sealed(
        {
            "schema": builder.FULL_FINDING_SCHEMA,
            "row_id": row["row_id"],
            "finding": "ALL_PRIOR_BLOCKING_COMPONENTS_HAVE_EXACT_FULL_SUPPORT",
            "component_ordinals": ordinals,
        },
        field="record_content_sha256",
    )
    payload = builder._sealed(
        {
            "schema": builder.FULL_UPGRADE_SCHEMA,
            "row_id": row["row_id"],
            "r3_row_record_content_sha256": row["record_content_sha256"],
            "blocking_component_bindings": [
                {
                    "component_ordinal": component["component_ordinal"],
                    "prior_support_fit": component["support_fit"],
                    "proposition_text_sha256": component["proposition_text_sha256"],
                    "support_fit": "FULL",
                    "evidence_binding_records": [_evidence_binding()],
                }
                for component in row["blocking_components"]
            ],
            "owner_support_finding": finding,
            "all_prior_blocking_components_now_full": True,
            "answer_release_eligible": False,
        },
        field="record_content_sha256",
    )
    return builder._sealed(
        {
            "schema": builder.DECISION_ROW_SCHEMA,
            "row_id": row["row_id"],
            "r3_row_record_content_sha256": row["record_content_sha256"],
            "selected_outcome": builder.OUTCOME_FULL,
            "outcome_payload": payload,
        },
        field="decision_input_record_content_sha256",
    )


def _fallback_decision(row: dict[str, Any]) -> dict[str, Any]:
    requested = ["the executed agreement", "the relevant dated communications"]
    classification = builder._sealed(
        {
            "schema": builder.FALLBACK_CLASSIFICATION_SCHEMA,
            "row_id": row["row_id"],
            "r3_row_record_content_sha256": row["record_content_sha256"],
            "classification": "MATTER_INFORMATION_ONLY_NO_LEGAL_KNOWLEDGE_OR_SOURCE_GAP",
            "classified_component_ordinals": sorted(
                int(item["component_ordinal"]) for item in row["blocking_components"]
            ),
            "legal_knowledge_gap": False,
            "official_source_gap": False,
            "matter_information_gap": True,
            "requested_information": requested,
            "qualified_human_legal_review_offered": True,
        },
        field="record_content_sha256",
    )
    message = builder._fallback_message(str(row["row_id"]), requested)
    payload = builder._sealed(
        {
            "schema": "legalbot.v111.phase2a.strict-matter-info-fallback.v1",
            "row_id": row["row_id"],
            "r3_row_record_content_sha256": row["record_content_sha256"],
            "eligibility_classification_record": classification,
            "fallback_reason_code": "MATTER_INFORMATION_REQUIRED",
            "ui_cta": "OFFER_QUALIFIED_HUMAN_LEGAL_REVIEW",
            "knowledge_gap_event": False,
            "matter_information_gap_event": True,
            "required_user_message": message,
            "required_user_message_sha256": builder._sha256(message.encode()),
            "reply_match_mode": "EXACT_UTF8_STRING",
            "legal_rule_release_prohibited": True,
            "legal_advice_release_prohibited": True,
            "citation_release_prohibited": True,
            "evidence_span_release_prohibited": True,
            "source_binding_release_prohibited": True,
            "answer_model_output_prohibited": True,
            "answer_release_eligible": False,
        },
        field="record_content_sha256",
    )
    return builder._sealed(
        {
            "schema": builder.DECISION_ROW_SCHEMA,
            "row_id": row["row_id"],
            "r3_row_record_content_sha256": row["record_content_sha256"],
            "selected_outcome": builder.OUTCOME_FALLBACK,
            "outcome_payload": payload,
        },
        field="decision_input_record_content_sha256",
    )


def _scope_change_decision(row: dict[str, Any]) -> dict[str, Any]:
    payload = builder._sealed(
        {
            "schema": builder.SCOPE_CHANGE_SCHEMA,
            "row_id": row["row_id"],
            "r3_row_record_content_sha256": row["record_content_sha256"],
            "action": "EXCLUDE_EXACT_UNSUPPORTED_COMPONENTS",
            "original_blocking_components": [
                builder._component_identity(component) for component in row["blocking_components"]
            ],
            "replacement_or_exclusion_contract_content_sha256": "8" * 64,
            "owner_scope_change_basis_record_content_sha256": "9" * 64,
            "changes_evaluation_contract": True,
            "requires_exact_owner_adoption_before_application": True,
            "answer_release_eligible": False,
        },
        field="record_content_sha256",
    )
    return builder._sealed(
        {
            "schema": builder.DECISION_ROW_SCHEMA,
            "row_id": row["row_id"],
            "r3_row_record_content_sha256": row["record_content_sha256"],
            "selected_outcome": builder.OUTCOME_SCOPE_CHANGE,
            "outcome_payload": payload,
        },
        field="decision_input_record_content_sha256",
    )


def test_full_outcome_requires_exact_full_binding_for_every_blocking_component() -> None:
    _, rows = _report_and_rows()
    row = rows[sorted(rows)[0]]
    decision = _full_decision(row)
    assert builder._validate_decision(decision, row)["selected_outcome"] == builder.OUTCOME_FULL

    broken = json.loads(json.dumps(decision))
    broken["outcome_payload"]["blocking_component_bindings"].pop()
    broken["outcome_payload"] = builder._sealed(
        broken["outcome_payload"], field="record_content_sha256"
    )
    broken = builder._sealed(broken, field="decision_input_record_content_sha256")
    with pytest.raises(ValueError, match="full_payload_invalid"):
        builder._validate_decision(broken, row)


def test_fallback_requires_row_specific_no_knowledge_no_source_gap_record() -> None:
    _, rows = _report_and_rows()
    row = rows[sorted(rows)[0]]
    decision = _fallback_decision(row)
    validated = builder._validate_decision(decision, row)
    payload = validated["outcome_payload"]
    assert payload["knowledge_gap_event"] is False
    assert payload["matter_information_gap_event"] is True
    assert payload["required_user_message_sha256"] == builder._sha256(
        payload["required_user_message"].encode()
    )
    assert "qualified human legal professional" in payload["required_user_message"]

    broken = json.loads(json.dumps(decision))
    classification = broken["outcome_payload"]["eligibility_classification_record"]
    classification["official_source_gap"] = True
    broken["outcome_payload"]["eligibility_classification_record"] = builder._sealed(
        classification, field="record_content_sha256"
    )
    broken["outcome_payload"] = builder._sealed(
        broken["outcome_payload"], field="record_content_sha256"
    )
    broken = builder._sealed(broken, field="decision_input_record_content_sha256")
    with pytest.raises(ValueError, match="fallback_classification_invalid"):
        builder._validate_decision(broken, row)


def test_owner_rewrite_or_exclusion_is_exact_and_non_applying() -> None:
    _, rows = _report_and_rows()
    row = rows[sorted(rows)[0]]
    decision = _scope_change_decision(row)
    validated = builder._validate_decision(decision, row)
    payload = validated["outcome_payload"]
    assert payload["changes_evaluation_contract"] is True
    assert payload["requires_exact_owner_adoption_before_application"] is True
    assert payload["answer_release_eligible"] is False


def test_external_decision_input_must_be_exact_146_rows_and_row_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report, rows = _report_and_rows()
    decisions = [builder._default_decision(rows[row_id]) for row_id in sorted(rows)]
    decisions[0] = _fallback_decision(rows[sorted(rows)[0]])
    material: dict[str, Any] = {
        "schema": builder.DECISION_INPUT_SCHEMA,
        "status": "EXACT_146_ROW_DECISION_INPUT_READY_NOT_ADOPTED",
        "prequalification_report_content_sha256": builder.R3_REPORT_CONTENT_SHA256,
        "blocker_row_id_set_sha256": report["blocker_row_id_set_sha256"],
        "decision_count": 146,
        "decisions": decisions,
        "not_owner_decision": True,
        "template_requires_new_immutable_revision_for_changes": True,
    }
    decision_input = builder._sealed(material)
    input_path = tmp_path / "decision-input.json"
    input_path.write_bytes(builder._pretty_json(decision_input))
    monkeypatch.setattr(builder, "DECISION_INPUT_REVIEW_ROOT", tmp_path)
    value, generated = builder._decision_input(
        report=report,
        rows=rows,
        decision_input_path=input_path,
    )
    assert generated is False
    assert (
        sum(item["selected_outcome"] == builder.OUTCOME_FALLBACK for item in value["decisions"])
        == 1
    )

    monkeypatch.setattr(builder, "OUTPUT_REVIEW_ROOT", tmp_path)
    output = tmp_path / "decision-bearing-r3"
    result = builder.build_advisory(
        decision_input_path=input_path,
        output_root=output,
        created_at=datetime(2026, 8, 28, 13, 0, tzinfo=UTC),
    )
    assert result["fallback_row_count"] == 1
    advisory = _load(output / builder.ADVISORY_NAME)
    assert advisory["supersedes_advisory_content_sha256"] == (
        builder.AUTHORITATIVE_BASELINE_ADVISORY_CONTENT_SHA256
    )
    assert advisory["correction_scope"]["no_substantive_row_outcome_changed"] is False
    bindings = {item["kind"]: item for item in advisory["authoritative_input_bindings"]}
    assert bindings["authoritative_baseline_146_row_advisory_r2"]["content_sha256"] == (
        builder.AUTHORITATIVE_BASELINE_ADVISORY_CONTENT_SHA256
    )

    reversed_input = json.loads(json.dumps(decision_input))
    reversed_input["decisions"] = list(reversed(reversed_input["decisions"]))
    reversed_input = builder._sealed(reversed_input)
    input_path.unlink()
    input_path.write_bytes(builder._pretty_json(reversed_input))
    with pytest.raises(ValueError, match="row_order_invalid"):
        builder._decision_input(report=report, rows=rows, decision_input_path=input_path)

    duplicate = json.loads(json.dumps(decision_input))
    duplicate["decisions"][-1] = duplicate["decisions"][0]
    duplicate = builder._sealed(duplicate)
    input_path.unlink()
    input_path.write_bytes(builder._pretty_json(duplicate))
    with pytest.raises(ValueError, match="row_duplicate"):
        builder._decision_input(report=report, rows=rows, decision_input_path=input_path)


def test_external_input_rejects_hidden_blanket_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report, rows = _report_and_rows()
    material: dict[str, Any] = {
        "schema": builder.DECISION_INPUT_SCHEMA,
        "status": "EXACT_146_ROW_DECISION_INPUT_READY_NOT_ADOPTED",
        "prequalification_report_content_sha256": builder.R3_REPORT_CONTENT_SHA256,
        "blocker_row_id_set_sha256": report["blocker_row_id_set_sha256"],
        "decision_count": 146,
        "decisions": [builder._default_decision(rows[row_id]) for row_id in sorted(rows)],
        "not_owner_decision": True,
        "template_requires_new_immutable_revision_for_changes": True,
        "fallback_all_rows": True,
    }
    input_path = tmp_path / "decision-input.json"
    input_path.write_bytes(builder._pretty_json(builder._sealed(material)))
    monkeypatch.setattr(builder, "DECISION_INPUT_REVIEW_ROOT", tmp_path)
    with pytest.raises(ValueError, match="decision_input_shape_invalid"):
        builder._decision_input(report=report, rows=rows, decision_input_path=input_path)


def test_package_is_create_only_private_and_create_new(built_baseline: Path) -> None:
    assert stat.S_IMODE(built_baseline.stat().st_mode) == 0o700
    members = {path.name for path in built_baseline.iterdir()}
    assert members == {
        builder.ADVISORY_NAME,
        builder.DECISION_TEMPLATE_NAME,
        builder.REVIEW_PROMPT_NAME,
        builder.PACKAGE_NAME,
        builder.CHECKSUMS_NAME,
    }
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in built_baseline.iterdir())
    checksum_lines = (built_baseline / builder.CHECKSUMS_NAME).read_text().splitlines()
    assert len(checksum_lines) == 4
    with pytest.raises(ValueError, match="output_already_exists"):
        builder._ensure_output(built_baseline)


def test_output_contains_no_absolute_source_path_or_owner_identity(built_baseline: Path) -> None:
    combined = b"\n".join(path.read_bytes() for path in sorted(built_baseline.iterdir()))
    assert b"/Users/" not in combined
    assert b"hltsang" not in combined.lower()
    assert b"Agnes" not in combined


def test_future_evidence_locator_cannot_smuggle_an_absolute_local_path() -> None:
    with pytest.raises(ValueError, match="absolute_path_violation"):
        builder._privacy_check({"exact_locator": "/Users/example/private.pdf"})
