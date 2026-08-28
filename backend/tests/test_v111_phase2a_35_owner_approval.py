from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts.apply_v111_phase2a_35_owner_approval import (
    APPROVAL_SCHEMA,
    DECISION_SCHEMA,
    PROPOSAL_SCHEMA,
    _pretty_json,
    _sealed,
    _sha256_file,
    _validate_decision,
    apply_approval,
)


def _decision(row_number: int) -> dict[str, object]:
    source_admission = row_number <= 23
    locator_confirmation = row_number > 32
    action = (
        "OWNER_SOURCE_ADMISSION_DECISION_REQUIRED"
        if source_admission
        else "CANDIDATE_REBIND_OR_SUCCESSOR_DECISION_REQUIRED"
    )
    status = (
        "EXACT_OFFICIAL_TEXT_DIFFERENT_OR_UNCONFIRMED_LOCATOR"
        if locator_confirmation
        else "EXACT_OFFICIAL_TEXT_AND_STATED_LOCATOR_MATCH"
    )
    material: dict[str, object] = {
        "schema": DECISION_SCHEMA,
        "status": "PROPOSED_NOT_OWNER_APPROVED",
        "row_id": f"row-{row_number:02d}",
        "owner_typed_name": "Agnes",
        "owner_decision_date": "2026-08-24",
        "proposed_owner_outcome": (
            "APPROVE_INTERNAL_PROPOSITION_MATERIALITY_AND_REBINDING_SCOPE"
        ),
        "internal_research_tool_only": True,
        "professional_legal_certification": False,
        "legal_advice": False,
        "exact_proposition_text": f"Proposition {row_number}",
        "official_source_title": "Example Act 2020",
        "official_source_type": "legislation_or_procedural_instrument",
        "official_citation": "2020 c 1",
        "official_legal_locator": "s 1",
        "official_source_url": "https://www.legislation.gov.uk/ukpga/2020/1/section/1",
        "fresh_official_verification_status": status,
        "owner_locator_confirmation_required": locator_confirmation,
        "source_verification_record_content_sha256": "a" * 64,
        "required_candidate_action": action,
        "source_admission_if_approved": source_admission,
        "candidate_rebind_or_successor_scope_if_approved": True,
        "defer_candidate_build_until_one_consolidated_phase2a_scope": True,
        "expressly_not_authorized": {
            "automatic_indexing_or_embedding": True,
            "candidate_build_before_full_consolidated_scope": True,
            "common_currentness_cutoff": True,
            "development30": True,
            "phase2b": True,
            "validation_promotion_or_live": True,
        },
    }
    return {**material, "decision_content_sha256": _sealed(material)}


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    proposal_material: dict[str, object] = {
        "schema": PROPOSAL_SCHEMA,
        "status": "PROPOSED_NOT_OWNER_APPROVED",
        "authoritative": False,
        "owner_typed_name": "Agnes",
        "owner_decision_date": "2026-08-24",
        "source_verification_content_sha256": "b" * 64,
        "source_verification_file_sha256": "c" * 64,
        "source_queue_content_sha256": "d" * 64,
        "item_count": 35,
        "confirmed_locator_count": 32,
        "owner_locator_confirmation_count": 3,
        "source_admission_row_count": 23,
        "candidate_rebind_row_count": 12,
        "proposed_decisions": [_decision(index) for index in range(1, 36)],
        "authority_if_explicitly_approved": {
            "approve_internal_proposition_materiality_for_35_rows": True,
            "confirm_three_stated_locators_as_owner_decisions": True,
            "authorize_source_admission_scope_for_23_rows": True,
            "authorize_candidate_rebind_or_successor_scope_for_35_rows": True,
            "defer_build_until_one_consolidated_phase2a_scope": True,
            "continue_phase2a_remediation": True,
            "automatic_indexing_or_embedding": False,
            "candidate_build_now": False,
            "common_currentness_cutoff": False,
            "development30": False,
            "phase2b": False,
            "validation_promotion_or_live": False,
        },
    }
    proposal = {
        **proposal_material,
        "proposal_content_sha256": _sealed(proposal_material),
    }
    proposal_path = tmp_path / "proposal.json"
    proposal_path.write_bytes(_pretty_json(proposal))

    approval_material: dict[str, object] = {
        "schema": APPROVAL_SCHEMA,
        "status": "AWAITING_EXPLICIT_OWNER_REPLY",
        "owner_typed_name": "Agnes",
        "owner_decision_date": "2026-08-24",
        "proposal_content_sha256": proposal["proposal_content_sha256"],
        "proposal_file_sha256": _sha256_file(proposal_path),
        "item_count": 35,
        "requested_reply": "OK",
    }
    approval = {
        **approval_material,
        "approval_payload_content_sha256": _sealed(approval_material),
    }
    approval_path = tmp_path / "approval.json"
    approval_path.write_bytes(_pretty_json(approval))
    return proposal_path, approval_path


def test_exact_ok_records_35_scopes_without_advancing_gates(tmp_path: Path) -> None:
    proposal_path, approval_path = _inputs(tmp_path)
    output = tmp_path / "output"

    result = apply_approval(
        proposal_path=proposal_path,
        approval_path=approval_path,
        output_root=output,
        owner_reply="OK",
        recorded_at=datetime(2026, 8, 24, tzinfo=UTC),
    )

    assert result["approved_item_count"] == 35
    assert result["recorded_owner_decision_count"] == 83
    assert result["remaining_owner_decision_issue_count"] == 502
    assert result["candidate_build_authorized"] is False
    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False
    assert (output / "OWNER-APPROVAL-RECEIPT-35.json").is_file()
    assert (output / "SOURCE-ADMISSION-SCOPE-23.json").is_file()
    assert (output / "CANDIDATE-REBINDING-SCOPE-35.json").is_file()


def test_reply_must_be_exact_ok(tmp_path: Path) -> None:
    proposal_path, approval_path = _inputs(tmp_path)

    with pytest.raises(
        ValueError,
        match="phase2a_35_owner_approval_authority_boundary_invalid",
    ):
        apply_approval(
            proposal_path=proposal_path,
            approval_path=approval_path,
            output_root=tmp_path / "output",
            owner_reply="ok",
            recorded_at=datetime(2026, 8, 24, tzinfo=UTC),
        )


def test_resealed_decision_cannot_expand_phase2b_authority() -> None:
    decision = _decision(1)
    decision.pop("decision_content_sha256")
    decision["expressly_not_authorized"]["phase2b"] = False  # type: ignore[index]
    decision["decision_content_sha256"] = _sealed(decision)

    with pytest.raises(
        ValueError,
        match="phase2a_35_owner_approval_decision_boundary_invalid",
    ):
        _validate_decision(decision)


def test_resealed_decision_cannot_claim_immediate_candidate_build() -> None:
    decision = _decision(1)
    decision.pop("decision_content_sha256")
    decision["defer_candidate_build_until_one_consolidated_phase2a_scope"] = False
    decision["decision_content_sha256"] = _sealed(decision)

    with pytest.raises(
        ValueError,
        match="phase2a_35_owner_approval_decision_boundary_invalid",
    ):
        _validate_decision(decision)
