from __future__ import annotations

import json
from pathlib import Path

from app.evaluation.ge_diagnostic_evaluator import evaluate_factual_checks
from app.evaluation.ge_locator_gold_overlay import (
    load_locator_gold_overlay,
    overlay_from_mapping,
)
from tests.test_ge_retrieval_training_cycle import _row

def test_unsigned_on_disk_gold_draft_is_a_noop() -> None:
    path = Path(
        "data/evaluations/general-enquiries/"
        "LegalBot-GE-2026-09-02-per-locator-gold-draft-r1/LOCATOR-GOLD-DRAFT.json"
    )
    overlay = load_locator_gold_overlay(path)
    assert overlay is not None
    assert overlay.owner_pack_signed is False
    assert overlay.effective_approve(
        {
            "source_version_id": overlay.receipts[0].source_version_id,
            "title": overlay.receipts[0].title,
            "locator": overlay.receipts[0].locator,
        }
    ) is None


def _signed_approve(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "legalbot.ge-per-locator-gold-receipt.v1",
        "evaluation_as_of_date": "2026-08-28",
        "owner_pack_signed": True,
        "locators": [
            {
                "source_version_id": "sv-1",
                "title": "Example Act",
                "locator": "section 1",
                "owner_signed": True,
                "owner_decision": "APPROVE",
                "effects_reviewed": True,
                "provision_extent_status": "verified",
                "currentness_reviewed_as_of_date": "2026-09-02",
                "evaluation_as_of_date": "2026-08-28",
                "legal_gold": False,
                "admitted": False,
                "full_current_law_eligible": True,
                "qualified_legal_review": False,
            }
        ],
    }
    locators = list(value["locators"])  # type: ignore[arg-type]
    locators[0] = {**locators[0], **overrides}
    value["locators"] = locators
    if "owner_pack_signed" in overrides:
        value["owner_pack_signed"] = overrides["owner_pack_signed"]
    return value


def test_unsigned_overlay_is_a_noop_even_with_approve_rows() -> None:
    overlay = overlay_from_mapping(
        {
            "evaluation_as_of_date": "2026-08-28",
            "owner_pack_signed": False,
            "locators": [
                {
                    "source_version_id": "sv-1",
                    "title": "Example Act",
                    "locator": "section 1",
                    "owner_signed": False,
                    "owner_decision": "PENDING",
                    "effects_reviewed": True,
                    "provision_extent_status": "verified",
                    "currentness_reviewed_as_of_date": "2026-09-02",
                    "legal_gold": False,
                }
            ],
        }
    )
    result = evaluate_factual_checks(
        case={
            "prompt": "What is the rule?",
            "issue_tags": ["example"],
            "primary_jurisdiction": "ENGLAND_AND_WALES",
            "legal_currentness_cutoff": "2026-09-01",
        },
        evidence_rows=[_row(unapplied_effect_count=24, currentness_verified=True)],
        source_manifest_sha256="b" * 64,
        user_facing_answer_text="Your question is repeated.",
        overlay=overlay,
    )
    assert result.diagnostic_checks["currentness"]["outcome"] == "FAIL"
    assert result.diagnostic_checks["jurisdiction_applicability"]["outcome"] == "FAIL"


def test_signed_locator_can_pass_currentness_with_nonzero_effects() -> None:
    overlay = overlay_from_mapping(_signed_approve())
    result = evaluate_factual_checks(
        case={
            "prompt": "What is the rule?",
            "issue_tags": ["example"],
            "primary_jurisdiction": "ENGLAND_AND_WALES",
            "legal_currentness_cutoff": "2026-09-01",
        },
        evidence_rows=[
            _row(
                unapplied_effect_count=24,
                currentness_verified=True,
                full_current_law_verification_eligible=False,
                provision_extent_status="unverified",
                currentness_reviewed_as_of_date="2026-08-14",
            )
        ],
        source_manifest_sha256="b" * 64,
        user_facing_answer_text="Your question is repeated.",
        overlay=overlay,
    )
    assert result.diagnostic_checks["currentness"]["outcome"] == "PASS"
    assert result.diagnostic_checks["jurisdiction_applicability"]["outcome"] == "PASS"
    assert result.checks["requested_date_and_currentness"] == "PASS"
    assert result.checks["jurisdiction_scope"] == "PASS"


def test_tulrca_unsigned_locator_stays_hold() -> None:
    overlay = overlay_from_mapping(
        {
            "evaluation_as_of_date": "2026-08-28",
            "owner_pack_signed": True,
            "locators": [
                {
                    "source_version_id": "sv-tulrca",
                    "title": "Trade Union and Labour Relations (Consolidation) Act 1992",
                    "locator": "section 1",
                    "owner_signed": True,
                    "owner_decision": "HOLD",
                    "effects_reviewed": True,
                    "provision_extent_status": "unverified",
                    "currentness_reviewed_as_of_date": "2026-09-02",
                    "legal_gold": False,
                }
            ],
        }
    )
    result = evaluate_factual_checks(
        case={
            "prompt": "Trade union question",
            "issue_tags": ["example"],
            "primary_jurisdiction": "ENGLAND_AND_WALES",
            "legal_currentness_cutoff": "2026-08-28",
        },
        evidence_rows=[
            _row(
                source_version_id="sv-tulrca",
                title="Trade Union and Labour Relations (Consolidation) Act 1992",
                unapplied_effect_count=297,
            )
        ],
        source_manifest_sha256="b" * 64,
        user_facing_answer_text="Your question is repeated.",
        overlay=overlay,
    )
    assert result.diagnostic_checks["currentness"]["outcome"] == "FAIL"


def test_historical_date_passes_when_point_in_time_matches() -> None:
    overlay = overlay_from_mapping(
        _signed_approve(
            title="Wills Act 1837 (as at 2024-01-15)",
            locator="section 9",
            point_in_time_as_at="2024-01-15",
        )
    )
    result = evaluate_factual_checks(
        case={
            "prompt": (
                "In England on 15 January 2024, a will-maker and two witnesses used a "
                "live video link. Could that will be valid?"
            ),
            "issue_tags": ["video-will"],
            "primary_jurisdiction": "ENGLAND_AND_WALES",
            "legal_currentness_cutoff": "2026-08-28",
        },
        evidence_rows=[
            _row(
                source_version_id="sv-1",
                title="Wills Act 1837 (as at 2024-01-15)",
                locator="section 9",
                quote="No will shall be valid unless it is in writing and signed by the testator.",
                stored_text="No will shall be valid unless it is in writing and signed by the testator.",
                point_in_time_as_at="2024-01-15",
            )
        ],
        source_manifest_sha256="b" * 64,
        user_facing_answer_text="Your question is repeated.",
        overlay=overlay,
    )
    assert result.diagnostic_checks["historical_date_applicability"]["outcome"] == "PASS"
    assert result.checks["requested_date_and_currentness"] == "PASS"


def test_resolved_r2_rows_are_locator_evaluation_gold_not_answer_gold() -> None:
    path = Path(
        "data/evaluations/general-enquiries/"
        "LegalBot-GE-2026-09-02-per-locator-evaluation-gold-resolved-r2/"
        "LegalBot-GE-2026-09-02-Per-Locator-Evaluation-Gold-Resolved-r2.json"
    )
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["owner_adopted"] = True
    overlay = overlay_from_mapping(raw)
    assert overlay.owner_pack_signed is True
    assert overlay.evaluation_as_of_date == "2026-08-28"
    decisions = {item.owner_decision for item in overlay.receipts}
    assert decisions == {"APPROVE", "REJECT"}
    assert sum(item.owner_decision == "APPROVE" for item in overlay.receipts) == 66
    assert sum(item.owner_decision == "REJECT" for item in overlay.receipts) == 1
    assert all(item.legal_gold is False for item in overlay.receipts)
    assert all(item.admitted is False for item in overlay.receipts)
    assert overlay.is_rejected_mandatory(
        "Cable & Wireless plc v IBM United Kingdom Ltd [2002] EWHC 2059 (Comm)"
    )
    approved = overlay.effective_approve(
        {"title": "Equality Act 2010", "locator": "section 20"}
    )
    assert approved is not None
    assert approved.locator_evaluation_gold is True
    icc = overlay.effective_approve(
        {
            "title": "ICC Mediation Rules (contractually incorporated edition)",
            "locator": "article 5",
        }
    )
    assert icc is not None
    wills = overlay.effective_approve(
        {
            "title": "Wills Act 1837 (as at 2024-01-15)",
            "locator": "section 9",
        }
    )
    assert wills is not None
    assert wills.point_in_time_as_at == "2024-01-15"


def test_phase2_progress_stays_true_when_cases_are_held() -> None:
    from app.evaluation.ge_phase2_progress import phase2_progress

    ledger = phase2_progress(
        case_results=[
            {"case_id": "a", "factual_result": {"outcome": "FACTUAL_PASS"}},
            {"case_id": "b", "factual_result": {"outcome": "FACTUAL_HOLD"}},
        ]
    )
    assert ledger["overall_progress"] is True
    assert ledger["overall_state"] == "RUNNING_WITH_CASE_BLOCKERS"
    assert ledger["held_or_fail_closed_cases"] == 1
    stopped = phase2_progress(case_results=[], hard_stop_reasons=["explicit_owner_stop"])
    assert stopped["overall_progress"] is False
    assert stopped["overall_state"] == "HARD_STOP"
