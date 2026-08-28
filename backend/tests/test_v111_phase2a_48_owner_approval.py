from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts.apply_v111_phase2a_48_owner_approval import (
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
    material: dict[str, object] = {
        "schema": DECISION_SCHEMA,
        "status": "PROPOSED_NOT_OWNER_APPROVED",
        "row_id": f"row-{row_number:02d}",
        "canonical_issue_id": f"issue-{row_number:02d}",
        "canonical_issue_label_sha256": "a" * 64,
        "proposed_owner_outcome": ("APPROVE_INTERNAL_PROPOSITION_AND_EXACT_SPAN_BINDING"),
        "internal_research_tool_only": True,
        "professional_legal_certification": False,
        "legal_advice": False,
        "proposed_exact_proposition_text": f"Proposition {row_number}",
        "official_source_title": "Example Act 2020",
        "official_source_type": "legislation_or_procedural_instrument",
        "official_citation": "2020 c 1",
        "official_legal_locator": "s 1",
        "official_source_url": ("https://www.legislation.gov.uk/ukpga/2020/1/section/1"),
        "exact_candidate_span_bindings": [
            {
                "chunk_id": f"chunk-{row_number:02d}",
                "content_sha256": "b" * 64,
                "locator": "section 1",
                "text": f"Proposition {row_number}",
            }
        ],
        "fresh_official_span_verification_record_content_sha256": "c" * 64,
        "all_candidate_components_match_fresh_2026_08_14_official_anchors": True,
        "proposed_determinations_if_approved": {
            "exact_candidate_spans_bind_the_proposition": True,
        },
        "expressly_not_decided_or_authorized": {
            "automatic_source_admission_indexing_or_embedding": True,
            "candidate_mutation_or_successor_build": True,
            "common_currentness_cutoff": True,
            "development30": True,
            "other_issues_or_propositions": True,
            "phase2b": True,
            "validation_promotion_or_live": True,
            "whole_document_byte_mismatch_materiality_outside_exact_spans": True,
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
        "item_count": 48,
        "authority_if_explicitly_approved": {
            "approve_exact_internal_proposition_and_span_bindings_for_48_rows": True,
            "candidate_mutation_or_successor_build": False,
            "common_currentness_cutoff": False,
            "continue_phase2a_remediation": True,
            "development30": False,
            "phase2b": False,
            "prepare_versioned_gold_successor_bindings_for_48_rows": True,
            "source_admission_indexing_or_embedding": False,
            "validation_promotion_or_live": False,
        },
        "proposed_decisions": [_decision(index) for index in range(1, 49)],
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
        "proposal_content_sha256": proposal["proposal_content_sha256"],
        "proposal_file_sha256": _sha256_file(proposal_path),
        "item_count": 48,
        "owner_typed_name": "Agnes",
        "owner_decision_date": "2026-08-24",
        "requested_reply": "OK",
    }
    approval = {
        **approval_material,
        "approval_payload_content_sha256": _sealed(approval_material),
    }
    approval_path = tmp_path / "approval.json"
    approval_path.write_bytes(_pretty_json(approval))
    return proposal_path, approval_path


def test_exact_ok_records_48_bindings_without_advancing_gates(tmp_path: Path) -> None:
    proposal_path, approval_path = _inputs(tmp_path)
    output = tmp_path / "output"

    result = apply_approval(
        proposal_path=proposal_path,
        approval_path=approval_path,
        output_root=output,
        owner_reply="OK",
        recorded_at=datetime(2026, 8, 24, tzinfo=UTC),
    )

    assert result["approved_binding_count"] == 48
    assert result["remaining_blocked_material_issue_count"] == 537
    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False
    assert (output / "OWNER-APPROVAL-RECEIPT-48.json").is_file()
    assert (output / "GOLD-SUCCESSOR-BINDINGS-48.json").is_file()


def test_reply_must_be_exact_ok(tmp_path: Path) -> None:
    proposal_path, approval_path = _inputs(tmp_path)

    with pytest.raises(
        ValueError,
        match="phase2a_48_owner_approval_authority_boundary_invalid",
    ):
        apply_approval(
            proposal_path=proposal_path,
            approval_path=approval_path,
            output_root=tmp_path / "output",
            owner_reply="YES",
            recorded_at=datetime(2026, 8, 24, tzinfo=UTC),
        )


def test_resealed_decision_cannot_expand_phase2b_authority() -> None:
    decision = _decision(1)
    decision.pop("decision_content_sha256")
    decision["expressly_not_decided_or_authorized"]["phase2b"] = False  # type: ignore[index]
    decision["decision_content_sha256"] = _sealed(decision)

    with pytest.raises(
        ValueError,
        match="phase2a_48_owner_approval_decision_boundary_invalid",
    ):
        _validate_decision(decision)
