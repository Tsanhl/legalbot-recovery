from __future__ import annotations

import json
from typing import Any

import pytest

from app.config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from app.db import utc_iso
from app.evaluation.live_runtime_separation import (
    early_canary_may_run_before_all_305,
    full_selected_run_requires_305_verified,
    ordinary_live_smoke_uses_active,
)
from app.evaluation.live_suite import sealed_sha256
from app.evaluation.live_suite_overlay_complete import overlay_complete_v2
from app.evaluation.live_suite_production_promotion import require_live60_production_attestation
from app.evaluation.live_suite_semantic_disposition import (
    contradiction_cannot_be_unrestricted_qualified,
    dispose_semantic_hold,
)
from app.evaluation.live_suite_semantic_resume import resume_semantic_hold
from app.evaluation.live_suite_source_admission import (
    SOURCE_ADMISSION_PACK_SCHEMA,
    apply_auto_source_admission_pack,
    apply_source_admission_decision,
    evaluate_source_admission,
    mechanical_legislation_source_approval,
    one_source_may_affect_many_rows,
    seal_source_admission_decision,
)
from app.evaluation.live_suite_source_hold_review import (
    assert_old_pack_immutable,
    build_v2_source_decision_pack,
    reconstruct_held_source_pack,
    review_one_held_source,
    xml_admission_flags,
)
from app.evaluation.live_suite_source_version_pack import (
    apply_source_version_decision_pack,
    build_source_version_decision_pack,
    confirmation_token,
    pack_sha256,
)
from app.evaluation.live_suite_stage_a_v2 import score_stage_a_v2
from app.retrieval.diagnostic_slice import (
    DIAGNOSTIC_SLICE_BUILD_ID,
    refuse_diagnostic_slice_for_production,
)


def _checks(**overrides: bool) -> dict[str, bool]:
    payload = {
        "source_identity_verified": True,
        "official_origin_verified": True,
        "source_bytes_sha256_verified": True,
        "source_version_sha256_verified": True,
        "stable_source_id_verified": True,
        "jurisdiction_verified": True,
        "england_and_wales_extent_verified": True,
        "licence_or_model_use_verified": True,
        "ai_use_not_prohibited": True,
        "parser_success": True,
        "document_not_quarantined": True,
        "document_not_duplicate_or_superseded": True,
        "currentness_status_acceptable": True,
        "unapplied_effects_reviewed_or_nonmaterial": True,
        "content_nonempty": True,
        "legal_locator_structure_valid": True,
        "source_scan_id_acceptable": True,
    }
    payload.update(overrides)
    return payload


def _evidence(**kwargs: Any) -> dict[str, Any]:
    payload = {
        "official_primary": True,
        "official_source_url": "https://www.legislation.gov.uk/ukpga/2015/15/section/47",
        "source_version_id": "sv-official-1",
        "stable_source_id": "ukpga:2015:15:section:47:latest-available@2026-08-17",
        "checks": _checks(),
    }
    payload.update(kwargs)
    return payload


def _semantic(*, result: str, contradiction: int = 0, spans: int = 1) -> dict[str, Any]:
    nested = {
        "schema": "legalbot.semantic-verification-result.v2",
        "result": result,
        "claims_supported": result in {"supported", "limited"},
        "unsupported_claim_count": 0 if result in {"supported", "limited"} else 1,
        "contradiction_count": contradiction,
        "seal_sha256": "d" * 64,
    }
    return {
        "row_id": "live30-q06:issue-07",
        "issue_id": "issue-07",
        "case_id": "live30-q06",
        "exact_gold_spans": (
            [
                {"chunk_id": f"chunk-{index}", "content_sha256": f"{index:064x}"}
                for index in range(spans)
            ]
            if spans
            else []
        ),
        "semantic_result": nested,
        "semantic_result_seal_sha256": "d" * 64,
    }


def _seed_source(database: Any, *, source_id: str = "sv-official-1") -> None:
    now = utc_iso()
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, lane, subject_primary, jurisdiction, retrieval_canonical,
          created_at, updated_at
        ) VALUES ('doc-official', ?, 'ukpga:2015:15', 'ok.xml', 'application/xml',
                  'citable', 'primary_authority', 'contract', 'England and Wales', 1, ?, ?)
        """,
        ("a" * 64, now, now),
    )
    database.execute(
        """
        INSERT INTO source_versions(
          id, document_id, version_sha256, canonical_markdown_path, title,
          stable_identifier, currentness_status, licence_name, review_status,
          metadata_json, created_at
        ) VALUES (?, 'doc-official', ?, 'data/vault/source.md', 'Consumer Rights Act 2015',
                  'local-path-sha256:abc', 'unknown', NULL, 'staged', ?, ?)
        """,
        (
            source_id,
            "a" * 64,
            json.dumps({"eligible_for_model_use": True, "ai_use_policy": "unreviewed"}),
            now,
        ),
    )
    database.execute(
        """
        INSERT INTO reviews(id, review_type, target_id, status, reason, created_at)
        VALUES ('review-official', 'source_version', ?, 'pending', 'source-admission', ?)
        """,
        (source_id, now),
    )


def test_official_source_auto_approves_without_human_identity() -> None:
    decision = evaluate_source_admission(evidence=_evidence(), actor_type="deterministic")
    assert decision["decision"] == "APPROVE"
    assert decision["auto_admission_eligible"] is True
    assert decision["operator_decision_required"] is False
    assert decision["actor_type"] != "human"
    assert evaluate_source_admission(evidence=_evidence(), actor_type="ai")["decision"] == "APPROVE"


def test_ai_confidence_alone_cannot_approve_a_source() -> None:
    decision = evaluate_source_admission(
        evidence=_evidence(checks=_checks(source_identity_verified=False)),
        actor_type="ai",
        ai_confidence=0.99,
    )
    assert decision["decision"] != "APPROVE"
    assert "ai_confidence_is_not_approval" in decision["reason_codes"]


def test_missing_source_version_id_blocks_approve() -> None:
    decision = evaluate_source_admission(evidence=_evidence(source_version_id=None))
    assert decision["decision"] == "HOLD"
    assert "missing_source_version_id" in decision["reason_codes"]
    with pytest.raises(ValueError, match="source_version_id"):
        apply_source_admission_decision(
            None,
            seal_source_admission_decision(
                {
                    "decision": "APPROVE",
                    "auto_admission_eligible": True,
                    "source_version_id": None,
                    "actor_type": "deterministic",
                }
            ),
        )


def test_one_source_decision_may_affect_multiple_issue_rows() -> None:
    mapping = one_source_may_affect_many_rows(
        [
            {
                "source_version_id": "sv-1",
                "affected_row_ids": [
                    "live30-q24:issue-02",
                    "live30-q24:issue-03",
                    "live30-q24:issue-09",
                ],
            }
        ]
    )
    assert len(mapping["sv-1"]) == 3


def test_old_56_hold_pack_remains_immutable_after_new_review() -> None:
    old = build_source_version_decision_pack(
        code_sha="e" * 64,
        scan_id="a6200da832c587e7",
        catalogue_state_sha256="f" * 64,
        as_of_date="2026-08-17",
        decisions=[
            {
                "decision_id": "svd-001",
                "source_version_id": None,
                "official_source_url": "https://www.legislation.gov.uk/ukpga/2015/15/section/47",
                "recommended_decision": "HOLD",
                "affected_row_ids": ["live30-q02:issue-09"],
            }
        ],
    )
    digest = old["pack_sha256"]
    review_one_held_source(
        old["decisions"][0],
        catalogue={
            "source_version_id": "sv-1",
            "version_sha256": "a" * 64,
            "document_status": "citable",
            "jurisdiction": "England and Wales",
            "chunk_count": 2,
            "scan_ids": ("a6200da832c587e7",),
            "ai_use_policy": "unreviewed",
            "title": "Consumer Rights Act 2015",
        },
        official_bytes=(
            b"<Legislation RestrictExtent='E+W'><Title>Consumer Rights Act 2015</Title></Legislation>"
        ),
        scan_id="a6200da832c587e7",
        as_of_date="2026-08-17",
    )
    assert_old_pack_immutable(old, digest)
    assert pack_sha256(old) == digest


def test_new_source_pack_cannot_reuse_old_confirmation_token() -> None:
    old = build_source_version_decision_pack(
        code_sha="e" * 64,
        scan_id="a6200da832c587e7",
        catalogue_state_sha256="f" * 64,
        as_of_date="2026-08-17",
        decisions=[
            {
                "decision_id": "svd-001",
                "recommended_decision": "HOLD",
                "affected_row_ids": ["live30-q02:issue-09"],
            }
        ],
    )
    new = build_v2_source_decision_pack(
        reviews=[
            {
                "decision_id": "svd-001",
                "actual_current_source_version_id": "sv-1",
                "stable_source_id": "ukpga:2015:15",
                "official_source_url": "https://www.legislation.gov.uk/ukpga/2015/15",
                "new_recommendation": "APPROVE",
                "v2_auto_admission_eligible": True,
                "reason_codes": ["v2_objective_checks_verified"],
                "affected_row_ids": ["live30-q02:issue-09"],
                "admission_decision": {"seal_sha256": "a" * 64},
            }
        ],
        code_sha="e" * 64,
        scan_id="a6200da832c587e7",
        as_of_date="2026-08-17",
        old_pack_sha256=old["pack_sha256"],
        include="auto",
    )
    assert new["pack_sha256"] != old["pack_sha256"]
    assert new["schema"] == SOURCE_ADMISSION_PACK_SCHEMA
    with pytest.raises(ValueError, match="cannot apply a new pack"):
        apply_source_version_decision_pack(new, confirmation_token_value=old["confirmation_token"])


def test_rights_ambiguity_remains_hold() -> None:
    decision = evaluate_source_admission(
        evidence=_evidence(
            checks=_checks(licence_or_model_use_verified=False),
            rights_ambiguous=True,
        )
    )
    assert decision["decision"] == "HOLD"
    assert "rights_ambiguity" in decision["reason_codes"]


def test_quarantined_source_can_never_be_approve() -> None:
    decision = evaluate_source_admission(
        evidence=_evidence(quarantined=True, checks=_checks(document_not_quarantined=False))
    )
    assert decision["decision"] == "REJECT"
    assert "quarantined_source" in decision["reason_codes"]


def test_parser_failure_can_never_be_approve() -> None:
    decision = evaluate_source_admission(
        evidence=_evidence(parser_success=False, checks=_checks(parser_success=False))
    )
    assert decision["decision"] == "REJECT"
    assert "parser_failure" in decision["reason_codes"]


def _clml(*, extent: str = "E+W", effects: str = "") -> bytes:
    return (
        "<Legislation>"
        f"<P1 RestrictExtent='{extent}'><Title>Official primary</Title>"
        "<Text>Operative words.</Text></P1>"
        f"{effects}"
        "</Legislation>"
    ).encode()


def _unapplied(*, requires: str, affected: str, ref: str, uri: str) -> str:
    return (
        f"<UnappliedEffect RequiresApplied='{requires}' AffectedProvisions='{affected}'>"
        "<AffectedProvisions>"
        f"<Section Ref='{ref}' URI='{uri}'>{affected}</Section>"
        "</AffectedProvisions>"
        "</UnappliedEffect>"
    )


def _catalogue() -> dict[str, Any]:
    return {
        "source_version_id": "sv-1",
        "version_sha256": "a" * 64,
        "document_status": "citable",
        "jurisdiction": "England and Wales",
        "chunk_count": 2,
        "scan_ids": ("a6200da832c587e7",),
        "ai_use_policy": "unreviewed",
        "title": "Official primary",
    }


def test_unapplied_effect_on_other_provision_is_nonmaterial() -> None:
    xml = _clml(
        effects=_unapplied(
            requires="true",
            affected="Art. 4(A2A)",
            ref="article-4-A2A",
            uri="http://www.legislation.gov.uk/id/eur/2016/679/article/4/A2A",
        )
    )
    flags = xml_admission_flags(
        xml,
        official_source_url="https://www.legislation.gov.uk/eur/2016/679/article/32/data.xml",
    )
    assert flags["unapplied_effect_requires_applied_count"] == 0
    assert flags["unapplied_effect_other_provision_count"] == 1
    assert flags["unapplied_effects_reviewed_or_nonmaterial"] is True
    reviewed = review_one_held_source(
        {
            "decision_id": "svd-other",
            "official_source_url": (
                "https://www.legislation.gov.uk/eur/2016/679/article/32/data.xml"
            ),
            "bind_reason_code": "unapplied_effects_unresolved",
            "affected_row_ids": ["live30-q23:issue-04"],
        },
        catalogue=_catalogue(),
        official_bytes=xml,
        scan_id="a6200da832c587e7",
        as_of_date="2026-08-17",
    )
    assert reviewed["new_recommendation"] == "APPROVE"
    assert reviewed["v2_auto_admission_eligible"] is True


def test_unapplied_effect_on_this_provision_remains_hold() -> None:
    xml = _clml(
        effects=_unapplied(
            requires="true",
            affected="Art. 15(1)(f)",
            ref="article-15-1-f",
            uri="http://www.legislation.gov.uk/id/eur/2016/679/article/15/1/f",
        )
    )
    flags = xml_admission_flags(
        xml,
        official_source_url="https://www.legislation.gov.uk/eur/2016/679/article/15/data.xml",
    )
    assert flags["unapplied_effect_requires_applied_count"] == 1
    assert flags["unapplied_effects_reviewed_or_nonmaterial"] is False
    reviewed = review_one_held_source(
        {
            "decision_id": "svd-self",
            "official_source_url": (
                "https://www.legislation.gov.uk/eur/2016/679/article/15/data.xml"
            ),
            "bind_reason_code": "unapplied_effects_unresolved",
            "affected_row_ids": ["live30-q23:issue-06"],
        },
        catalogue=_catalogue(),
        official_bytes=xml,
        scan_id="a6200da832c587e7",
        as_of_date="2026-08-17",
    )
    assert reviewed["new_recommendation"] == "HOLD"
    assert "unapplied_effects_unresolved" in reviewed["reason_codes"]


def test_whole_instrument_unapplied_effect_remains_hold() -> None:
    xml = _clml(
        effects=(
            "<UnappliedEffect RequiresApplied='true' AffectedProvisions='Act'></UnappliedEffect>"
        )
    )
    reviewed = review_one_held_source(
        {
            "decision_id": "svd-act",
            "official_source_url": (
                "https://www.legislation.gov.uk/ukpga/1980/58/section/4A/data.xml"
            ),
            "bind_reason_code": "unapplied_effects_unresolved",
            "affected_row_ids": ["live60-q32:issue-08"],
        },
        catalogue=_catalogue(),
        official_bytes=xml,
        scan_id="a6200da832c587e7",
        as_of_date="2026-08-17",
    )
    assert reviewed["new_recommendation"] == "HOLD"
    assert "unapplied_effects_unresolved" in reviewed["reason_codes"]


def test_section_range_on_other_provision_is_nonmaterial() -> None:
    xml = _clml(
        effects=(
            "<UnappliedEffect RequiresApplied='true' AffectedProvisions='s. 20B(3)-(10)'>"
            "<AffectedProvisions>"
            "<SectionRange Start='section-20B-3' End='section-20B-10' "
            "URI='http://www.legislation.gov.uk/id/ukpga/1985/70/section/20B/3' "
            "UpTo='http://www.legislation.gov.uk/id/ukpga/1985/70/section/20B/10' "
            "FoundStart='section-20B' FoundEnd='section-20B'/>"
            "</AffectedProvisions>"
            "</UnappliedEffect>"
        )
    )
    flags = xml_admission_flags(
        xml,
        official_source_url="https://www.legislation.gov.uk/ukpga/1985/70/section/11/data.xml",
    )
    assert flags["unapplied_effects_reviewed_or_nonmaterial"] is True
    assert flags["unapplied_effect_other_provision_count"] == 1
    reviewed = review_one_held_source(
        {
            "decision_id": "svd-range",
            "official_source_url": (
                "https://www.legislation.gov.uk/ukpga/1985/70/section/11/data.xml"
            ),
            "bind_reason_code": "unapplied_effects_unresolved",
            "affected_row_ids": ["live30-q20:issue-03"],
        },
        catalogue=_catalogue(),
        official_bytes=xml,
        scan_id="a6200da832c587e7",
        as_of_date="2026-08-17",
    )
    assert reviewed["new_recommendation"] == "APPROVE"


def test_section_2_does_not_match_section_21za() -> None:
    xml = _clml(
        effects=_unapplied(
            requires="true",
            affected="s. 21ZA",
            ref="section-21ZA",
            uri="http://www.legislation.gov.uk/id/ukpga/2005/9/section/21ZA",
        )
    )
    flags = xml_admission_flags(
        xml,
        official_source_url="https://www.legislation.gov.uk/ukpga/2005/9/section/2/data.xml",
    )
    assert flags["unapplied_effects_reviewed_or_nonmaterial"] is True
    assert flags["unapplied_effect_other_provision_count"] == 1


def test_currentness_ambiguity_cannot_auto_approve() -> None:
    decision = evaluate_source_admission(
        evidence=_evidence(
            currentness_ambiguous=True,
            checks=_checks(currentness_status_acceptable=False),
        )
    )
    assert decision["decision"] != "APPROVE"
    assert "currentness_ambiguity" in decision["reason_codes"]


def test_supported_semantic_result_becomes_verified_qualified() -> None:
    disposed = dispose_semantic_hold(_semantic(result="supported", spans=2))
    assert disposed["recommendation"] == "QUALIFIED"
    assert disposed["unrestricted_qualified"] is True
    assert disposed["issue_update"]["final_verification_status"] == "VERIFIED"
    assert disposed["issue_update"]["disposition"] == "qualified"
    assert disposed["issue_update"]["exact_gold_spans"]


def test_excluded_source_does_not_keep_issue_on_hold() -> None:
    from app.evaluation.live_suite_excluded_source_issue import (
        resolve_issue_after_excluded_source,
    )

    gap = resolve_issue_after_excluded_source(
        {"row_id": "live60-q35:issue-08", "issue_id": "issue-08"},
        exclusion_kind="hold",
    )
    assert gap["resolution"] == "verified_knowledge_gap"
    assert gap["issue_update"]["final_verification_status"] == "VERIFIED"
    assert gap["issue_update"]["disposition"] == "knowledge_gap"
    assert gap["issue_update"]["exact_gold_spans"] == []
    rebound = resolve_issue_after_excluded_source(
        {"row_id": "live30-q24:issue-02", "issue_id": "issue-02"},
        exclusion_kind="reject",
        alternative_approved_source_version_id="sv-alt",
        alternative_exact_spans=[{"chunk_id": "chunk-alt", "content_sha256": "a" * 64}],
    )
    assert rebound["resolution"] == "alternative_source_bound"
    assert rebound["issue_update"]["gap_reason"] == "source_admitted_semantic_pending"


def test_provision_effect_other_provision_is_not_material() -> None:
    from app.evaluation.live_suite_provision_effects import classify_source_effects

    xml = _clml(
        effects=_unapplied(
            requires="true",
            affected="s. 21ZA",
            ref="section-21ZA",
            uri="http://www.legislation.gov.uk/id/ukpga/2005/9/section/21ZA",
        )
    )
    classified = classify_source_effects(
        xml,
        official_source_url="https://www.legislation.gov.uk/ukpga/2005/9/section/2/data.xml",
        as_of_date="2026-08-17",
    )
    assert classified["may_clear_source_admission"] is True
    assert classified["classification"] == "EFFECT_NOT_MATERIAL_TO_CURRENT_PROPOSITION"


def test_early_canary_allowed_before_all_305() -> None:
    from app.evaluation.live_suite_early_canary import plan_early_canary

    issues = [
        {
            "row_id": "live30-q03:issue-01",
            "case_id": "live30-q03",
            "issue_id": "issue-01",
            "disposition": "knowledge_gap",
            "status": "knowledge_gap",
            "final_verification_status": "VERIFIED",
            "exact_gold_spans": [],
            "gap_reason": "defined_source_set_exhausted",
            "gap_verification_seal_sha256": "e" * 64,
            "invented_span": False,
        }
    ]
    planned = plan_early_canary(
        issues=issues,
        v2_verified_selected=1,
        diagnostic_slice_contains_required_chunks=True,
    )
    assert planned["allowed"] is True
    assert planned["promotable"] is False
    assert planned["canary_case_id"] == "live30-q03"
    assert planned["non_promotable_diagnostic_canary"] is True
    assert planned["writes_active"] is False
    uncovered = plan_early_canary(
        issues=issues,
        v2_verified_selected=1,
        diagnostic_slice_contains_required_chunks=False,
    )
    assert uncovered["allowed"] is False
    assert uncovered["canary_build_id"] is None
    assert "diagnostic_slice_missing_required_evidence_chunks" in uncovered["blocking_reason_codes"]


def test_unsupported_with_gap_proof_becomes_verified_knowledge_gap() -> None:
    disposed = dispose_semantic_hold(_semantic(result="unsupported", spans=2))
    assert disposed["recommendation"] == "KNOWLEDGE_GAP"
    assert disposed["issue_update"]["final_verification_status"] == "VERIFIED"
    assert disposed["issue_update"]["exact_gold_spans"] == []
    assert disposed["issue_update"]["gap_verification"]["seal_sha256"]


def test_partial_support_with_limitation_becomes_verified_limited() -> None:
    disposed = dispose_semantic_hold(_semantic(result="knowledge_gap", spans=1))
    assert disposed["cause"] == "PARTIAL_SUPPORT"
    assert disposed["recommendation"] == "LIMITED"
    assert disposed["issue_update"]["limitation_reason"]
    assert disposed["issue_update"]["exact_gold_spans"]


def test_unbound_contradiction_becomes_verified_knowledge_gap() -> None:
    from app.evaluation.live_suite_semantic_disposition import (
        finalize_unbound_contradiction_as_gap,
    )

    gap = finalize_unbound_contradiction_as_gap(
        {"row_id": "live30-q15:issue-04", "issue_id": "issue-04"}
    )
    assert gap["recommendation"] == "KNOWLEDGE_GAP"
    assert gap["unrestricted_qualified"] is False
    assert gap["issue_update"]["final_verification_status"] == "VERIFIED"
    assert gap["issue_update"]["exact_gold_spans"] == []
    contradiction_cannot_be_unrestricted_qualified(gap)


def test_contradiction_cannot_become_unrestricted_qualified() -> None:
    disposed = dispose_semantic_hold(_semantic(result="unsupported", contradiction=1, spans=3))
    assert disposed["recommendation"] != "QUALIFIED"
    contradiction_cannot_be_unrestricted_qualified(disposed)
    with pytest.raises(ValueError, match="unrestricted qualified"):
        contradiction_cannot_be_unrestricted_qualified(
            {"cause": "CONTRADICTION", "recommendation": "QUALIFIED"}
        )


def test_substantive_semantic_hold_cannot_be_retried_until_yes() -> None:
    record = _semantic(result="unsupported")
    with pytest.raises(ValueError, match="cannot be retried until it says yes"):
        dispose_semantic_hold(record, retry_until_supported=True)
    resumed = resume_semantic_hold(record)
    assert resumed["final_verification_status"] == "HOLD"


def test_v2_verified_count_increases_only_after_valid_seal() -> None:
    gap = dispose_semantic_hold(_semantic(result="unsupported"))["issue_update"]
    overlay = overlay_complete_v2(
        selected_issues=[
            {
                "row_id": "live30-q02:issue-01",
                "case_id": "live30-q02",
                "issue_id": "issue-01",
                **gap,
            }
        ],
        selected_issue_count=1,
        selected_case_count=1,
        enforce_frozen_identities=False,
    )
    assert overlay["selected_knowledge_gap_count"] == 1
    incomplete = overlay_complete_v2(
        selected_issues=[
            {
                "row_id": "live30-q02:issue-01",
                "case_id": "live30-q02",
                "issue_id": "issue-01",
                "disposition": "knowledge_gap",
                "status": "knowledge_gap",
                "final_verification_status": "VERIFIED",
                "exact_gold_spans": [],
                "gap_reason": "missing-seal",
            }
        ],
        selected_issue_count=1,
        selected_case_count=1,
        enforce_frozen_identities=False,
    )
    assert incomplete["unreviewed_issue_count"] == 1


def test_canary_may_run_before_all_305_but_remains_non_promotable() -> None:
    state = early_canary_may_run_before_all_305(
        any_selected_case_fully_verified=True,
        v2_verified_selected=212,
    )
    assert state["allowed"] is True
    assert state["promotable"] is False
    assert full_selected_run_requires_305_verified(v2_verified_selected=212, total_hold=93) is False


def test_full_run_still_requires_305_verified_dispositions() -> None:
    assert full_selected_run_requires_305_verified(v2_verified_selected=305, total_hold=0) is True
    assert full_selected_run_requires_305_verified(v2_verified_selected=304, total_hold=1) is False


def test_diagnostic_slice_cannot_become_production_active() -> None:
    with pytest.raises(ValueError, match="diagnostic slice"):
        refuse_diagnostic_slice_for_production(
            DIAGNOSTIC_SLICE_BUILD_ID, purpose="production ACTIVE"
        )
    with pytest.raises(ValueError, match="production Stage A"):
        score_stage_a_v2(
            issues=[],
            unreviewed_issue_count=0,
            candidate_build_id=DIAGNOSTIC_SLICE_BUILD_ID,
            rankings=[],
        )


def test_production_attestation_cannot_refer_to_diagnostic_slice(tmp_path: Any) -> None:
    settings = Settings(
        project_root=tmp_path,
        live_profile=FIRST_LIVE_LOCAL_ONLY_PROFILE,
        test_mode=True,
    )
    payload = {
        "schema": "legalbot.production-promotion-attestation.v2",
        "candidate_build_id": DIAGNOSTIC_SLICE_BUILD_ID,
        "candidate_seal_sha256": "1" * 64,
        "evaluation_run_id": "eval-run-01",
        "evaluation_aggregate_sha256": "2" * 64,
        "answer_quality_passed": True,
        "privacy_security_passed": True,
        "required_readiness_passed": True,
        "rollback_canary_required": False,
        "operator_deployment_authorization": "operator:" + ("3" * 64),
        "policy_version": "v1",
        "writes_active": True,
        "legal_evidence_review_is_not_deployment": True,
    }
    payload["seal_sha256"] = sealed_sha256(payload)
    with pytest.raises(ValueError, match="diagnostic slice"):
        require_live60_production_attestation(
            settings=settings,
            build_id=DIAGNOSTIC_SLICE_BUILD_ID,
            attestation=payload,
        )


def test_ordinary_live_uses_only_final_active_candidate() -> None:
    ordinary_live_smoke_uses_active(active_build_id="active-1", job_pinned_build_id="active-1")
    with pytest.raises(ValueError, match="must pin ACTIVE"):
        ordinary_live_smoke_uses_active(
            active_build_id="active-1",
            job_pinned_build_id=DIAGNOSTIC_SLICE_BUILD_ID,
        )


def test_auto_admission_writes_catalogue_without_owner_token(database: Any) -> None:
    _seed_source(database)
    decision = evaluate_source_admission(evidence=_evidence(), actor_type="hybrid")
    approval = mechanical_legislation_source_approval(
        official_source_url="https://www.legislation.gov.uk/ukpga/2015/15/section/47",
        title="Consumer Rights Act 2015",
        as_of_date="2026-08-17",
        stable_identifier="ukpga:2015:15:section:47:latest-available@2026-08-17",
    )
    applied = apply_source_admission_decision(database, decision, source_approval=approval)
    assert applied["applied"] is True
    assert applied["issue_gold_minted"] is False
    row = database.fetchone("SELECT review_status FROM source_versions WHERE id='sv-official-1'")
    assert row["review_status"] == "approved"
    pack = {
        "schema": SOURCE_ADMISSION_PACK_SCHEMA,
        "operator_decision_required": False,
        "decisions": [decision],
        "applied": False,
    }
    auto = apply_auto_source_admission_pack(pack)
    assert auto["operator_confirmed"] is False


def test_admitted_source_exact_span_does_not_qualify_issue() -> None:
    from app.evaluation.live_suite_admitted_span import exact_spans_for_admitted_source

    xml = (
        b"<Legislation><P1 id='section-47' RestrictExtent='E+W'>"
        b"<Pnumber>47</Pnumber><Text>A term of a contract is not binding.</Text>"
        b"</P1></Legislation>"
    )
    row = {
        "chunk_id": "chunk-1",
        "text_sha256": "a" * 64,
        "jurisdiction": "England and Wales",
        "authority_identity_id": "ukpga:2015:15",
        "locator": "section 47",
        "source_version_id": "sv-1",
        "stable_source_id": "ukpga:2015:15:section:47",
        "markdown_text": "section 47 A term of a contract is not binding.",
        "ordinal": 1,
    }
    bound = exact_spans_for_admitted_source(
        official_xml=xml,
        chunk_rows=[row],
        as_of_date=__import__("datetime").date(2026, 8, 17),
    )
    assert bound["exact_match"] is True
    assert bound["issue_qualified"] is False
    assert bound["final_verification_status"] == "HOLD"
    assert bound["exact_gold_spans"][0]["chunk_id"] == "chunk-1"
    assert "markdown_text" not in bound["exact_gold_spans"][0]


def test_reconstruct_batch_does_not_mutate_old_pack() -> None:
    old = build_source_version_decision_pack(
        code_sha="e" * 64,
        scan_id="a6200da832c587e7",
        catalogue_state_sha256="f" * 64,
        as_of_date="2026-08-17",
        decisions=[
            {
                "decision_id": "svd-001",
                "official_source_url": (
                    "https://www.legislation.gov.uk/ukpga/2015/15/section/47/data.xml"
                ),
                "recommended_decision": "HOLD",
                "affected_row_ids": ["live30-q02:issue-09", "live30-q02:issue-10"],
                "bind_reason_code": "operator_source_approval_required",
            }
        ],
    )
    xml = (
        b"<Legislation><P1 RestrictExtent='E+W'><Title>Consumer Rights Act 2015</Title>"
        b"<Text>A term is not binding.</Text></P1></Legislation>"
    )
    url = old["decisions"][0]["official_source_url"]
    batch = reconstruct_held_source_pack(
        old_pack=old,
        official_bytes_by_url={url: xml},
        catalogue_by_url={
            url: {
                "source_version_id": "sv-1",
                "version_sha256": "a" * 64,
                "document_status": "citable",
                "jurisdiction": "England and Wales",
                "chunk_count": 3,
                "scan_ids": ("a6200da832c587e7",),
                "ai_use_policy": "unreviewed",
                "title": "Consumer Rights Act 2015",
            }
        },
        code_sha="e" * 64,
        scan_id="a6200da832c587e7",
        as_of_date="2026-08-17",
        expected_old_sha256=old["pack_sha256"],
    )
    assert batch["old_pack_hold_count"] == 1
    assert old["pack_sha256"] == pack_sha256(old)
    assert confirmation_token(old["pack_sha256"]) == old["confirmation_token"]
    assert any(len(rows) == 2 for rows in batch["source_to_rows"].values())
