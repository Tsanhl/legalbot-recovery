from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.evaluation import phase2a_prequalification_blockers as blockers
from app.evaluation.phase2a_successor_qualification import require_seal

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OWNER_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
ORIGINAL = OWNER_ROOT / (
    "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1/"
    "EXACT-REMEDIATION-OWNER-PACKET-361.json"
)
FINAL = OWNER_ROOT / (
    "LegalBot-Phase2A-2026-08-28-source-delta-safe-fallback-owner-packet-r1/"
    "EXACT-PHASE2A-SOURCE-DELTA-SAFE-FALLBACK-OWNER-PACKET.json"
)
RECEIPT = OWNER_ROOT / (
    "LegalBot-Phase2A-2026-08-28-final-remediation-owner-approved-r1/OWNER-ADOPTION-RECEIPT.json"
)
AUTHORITY = OWNER_ROOT / (
    "LegalBot-Phase2A-2026-08-28-final-remediation-owner-approved-r1/"
    "PHASE2A-EXECUTION-AUTHORITY.json"
)
CLI = PROJECT_ROOT / "scripts/build_v111_phase2a_prequalification_blocker_report.py"


def _load(path: Path) -> dict:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _build() -> dict:
    return blockers.build_report_from_paths(
        original_packet_path=ORIGINAL,
        final_packet_path=FINAL,
        owner_receipt_path=RECEIPT,
        execution_authority_path=AUTHORITY,
        project_root=PROJECT_ROOT,
    )


def test_exact_prequalification_report_is_deterministic_and_fail_closed() -> None:
    first = _build()
    second = _build()
    assert first == second
    assert require_seal(first, label="prequalification report") == first["artifact_content_sha256"]
    assert first["status"] == "BLOCKED_BEFORE_SUCCESSOR_QUALIFICATION"
    assert first["counts"] == {
        "adopt_supported_components_retain_holds_recommendation_count": 315,
        "blocking_component_count": 193,
        "blocking_row_count": 146,
        "raw_unresolved_hold_count": 461,
        "none_component_count": 77,
        "none_row_count": 72,
        "official_research_recommendation_count": 316,
        "original_decision_count": 361,
        "partial_and_none_overlap_row_count": 26,
        "partial_component_count": 116,
        "partial_row_count": 100,
        "decisions_after_exact_precedence_exclusions": 351,
        "retain_material_hold_no_supported_proposition_recommendation_count": 1,
        "safe_fallback_row_count": 2,
        "special_substantive_supersession_row_count": 8,
    }
    assert "hold_classification_counts" not in first["counts"]
    assert "classified_hold_count" not in first["counts"]
    assert first["classification_policy_revision"] == (
        "v3-no-automated-semantic-hold-classification"
    )
    assert first["supersedes_prequalification_report_content_sha256"] == (
        blockers.PREDECESSOR_R2_REPORT_CONTENT_SHA256
    )
    assert first["predecessor_set_identity_comparison"] == {
        "blocker_row_id_set_sha256": blockers.PREDECESSOR_R1_BLOCKER_ROW_ID_SET_SHA256,
        "partial_row_id_set_sha256": blockers.PREDECESSOR_R1_PARTIAL_ROW_ID_SET_SHA256,
        "none_row_id_set_sha256": blockers.PREDECESSOR_R1_NONE_ROW_ID_SET_SHA256,
        "all_three_sets_unchanged": True,
    }
    assert first["recommendation_semantics_proof"] == {
        "builder_rule": (
            "support_fits_minus_FULL_or_unresolved_holds_or_component_holds_or_"
            "ineligible_authority_implies_retain_holds_recommendation"
        ),
        "official_research_recommendation_count": 316,
        "retain_holds_recommendation_count": 315,
        "retain_material_hold_no_supported_proposition_count": 1,
        "partial_or_none_components_are_not_upgraded_by_owner_adoption": True,
    }


def test_report_applies_exact_eight_plus_two_precedence_before_blocker_predicate() -> None:
    report = _build()
    precedence = report["packet_precedence"]
    assert set(precedence["special_substantive_supersession_row_ids"]) == (
        blockers.EXPECTED_SPECIAL_SUPERSESSION_ROW_IDS
    )
    assert set(precedence["safe_fallback_row_ids"]) == blockers.EXPECTED_FALLBACK_ROW_IDS
    blocker_ids = {row["row_id"] for row in report["rows"]}
    assert not blocker_ids & blockers.EXPECTED_SPECIAL_SUPERSESSION_ROW_IDS
    assert not blocker_ids & blockers.EXPECTED_FALLBACK_ROW_IDS
    assert precedence["excluded_precedence_row_ids_disjoint"] is True
    assert precedence["excluded_precedence_rows_removed_before_blocker_predicate"] is True


def test_every_reported_blocker_has_exact_component_proposition_source_and_locator_data() -> None:
    report = _build()
    for row in report["rows"]:
        assert require_seal(
            row,
            field="record_content_sha256",
            label=f"blocker {row['row_id']}",
        )
        assert row["material_gap"] is True
        assert row["successor_crosswalk_eligible"] is False
        assert row["blocking_components"]
        for component in row["blocking_components"]:
            assert component["support_fit"] in {"PARTIAL", "NONE"}
            assert len(component["proposition_text_sha256"]) == 64
            if component["support_fit"] == "PARTIAL":
                assert component["authorities"]
            for authority in component["authorities"]:
                assert len(authority["authority_content_sha256"]) == 64
                assert authority["canonical_authority_identity_id"]
                assert authority["exact_locators"]
        assert "classified_unresolved_holds" not in row
        for hold in row["unclassified_unresolved_holds"]:
            assert require_seal(
                hold,
                field="record_content_sha256",
                label="unclassified hold",
            )
            assert hold["classification"] == "UNCLASSIFIED_NON_OPERATIVE"
            assert hold["requires_human_semantic_classification"] is True
            assert hold["automated_semantic_classification_performed"] is False
            assert "classification_reason_codes" not in hold
            assert hold["classification_did_not_create_or_clear_row_blocker"] is True


def test_read_only_report_binds_unspent_execution_chain_and_no_run() -> None:
    report = _build()
    assert report["execution_chain"] == {
        "content_sha256": blockers.EXECUTION_AUTHORITY_CONTENT_SHA256,
        "status": "AVAILABLE_UNSPENT",
        "total_count": 1,
        "remaining_count": 1,
        "consumed_count": 0,
        "this_read_only_report_consumes_chain": False,
    }
    for field in (
        "source_scan_run",
        "index_build_run",
        "embedding_run",
        "retrieval_reattestation_run",
        "all585_qualification_run",
        "answer_model_run",
        "candidate_mutated",
        "active_pointer_written",
        "previous_pointer_written",
        "phase2b_authorized",
    ):
        assert report[field] is False


def test_no_automated_semantic_hold_category_claims_remain() -> None:
    report = _build()
    holds = {
        (row["row_id"], hold["hold_text"]): hold
        for row in report["rows"]
        for hold in row["unclassified_unresolved_holds"]
    }
    auditor_examples = {
        (
            "live30-q04:issue-01",
            "The officer's time of death remains a factual and expert-evidence question.",
        ),
        (
            "live30-q13:issue-02",
            "The facts do not state possession, delivery, symbolic delivery, deed or "
            "declaration-of-trust facts for the painting.",
        ),
        (
            "live30-q16:issue-02",
            "The drafting solicitor's attendance notes and any contemporaneous capacity "
            "assessment are absent.",
        ),
        (
            "live60-q57:issue-01",
            "Relevant tax years and their historical statutory versions are not fixed.",
        ),
    }
    for identity in auditor_examples:
        hold = holds[identity]
        assert hold["classification"] == "UNCLASSIFIED_NON_OPERATIVE"
        assert hold["requires_human_semantic_classification"] is True
    assert report["automated_semantic_hold_classification_performed"] is False
    assert report["all_raw_holds_require_human_semantic_classification"] is True
    encoded = json.dumps(report, sort_keys=True)
    assert '"classification": "MATERIAL"' not in encoded
    assert '"classification": "MATTER_FACT"' not in encoded
    assert '"classification": "RELEASE_ONLY"' not in encoded


def test_tampered_owner_packet_or_precedence_fails_closed() -> None:
    original = _load(ORIGINAL)
    final = _load(FINAL)
    receipt = _load(RECEIPT)
    authority = _load(AUTHORITY)
    changed = copy.deepcopy(original)
    changed["decisions"][0]["source_research_record"]["atomic_components"][0]["support_fit"] = (
        "FULL"
    )
    with pytest.raises(ValueError, match="content seal"):
        blockers.build_prequalification_blocker_report(
            original_packet=changed,
            final_packet=final,
            owner_receipt=receipt,
            execution_authority=authority,
            original_packet_path="original.json",
            original_packet_file_sha256="a" * 64,
            final_packet_path="final.json",
            final_packet_file_sha256="b" * 64,
            owner_receipt_path="receipt.json",
            owner_receipt_file_sha256="c" * 64,
            execution_authority_path="authority.json",
            execution_authority_file_sha256="d" * 64,
        )


def test_cli_requires_all_immutable_inputs() -> None:
    completed = subprocess.run(
        [sys.executable, str(CLI), "--help"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    for option in (
        "--project-root",
        "--original-packet",
        "--final-packet",
        "--owner-receipt",
        "--execution-authority",
        "--output-root",
    ):
        assert option in completed.stdout
