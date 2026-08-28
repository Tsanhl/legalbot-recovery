from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts import build_v111_phase2a_safe_fallback_superseding_owner_packet as builder


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _write_source_delta(root: Path) -> dict[str, str]:
    root.mkdir(mode=0o700)
    packet_material: dict[str, object] = {
        "schema": "legalbot.v111.phase2a.source-binding-delta-owner-packet.v1",
        "status": "EXACT_SOURCE_BINDING_DELTA_READY_NOT_ADOPTED",
        "decision_summary": {
            "retained_original_passing_representation_count": 231,
            "rejected_defective_original_representation_count": 16,
            "corrected_replacement_representation_count": 15,
            "unresolved_repair_hold_count": 5,
            "source_binding_delta_owner_decision_count": 267,
        },
        "known_all585_material_hold": {
            "current_all585_can_be_successful": False,
            "original_decision_content_sha256": (builder.EXPECTED_PRIOR_HOLD_DECISION_SHA256),
            "qualification_status": "BLOCKED_MATERIAL_GAP",
            "recommended_owner_outcome": ("RETAIN_MATERIAL_HOLD_NO_SUPPORTED_OFFICIAL_PROPOSITION"),
            "row_id": builder.ROW_ID,
            "successful_phase2a_package_may_be_claimed": False,
        },
        **{
            field: False
            for field in builder._NO_EXECUTION_FLAGS
            if field
            not in {
                "source_delta_decisions_applied",
                "safe_fallback_decision_applied",
                "evaluation_contract_mutated",
            }
        },
    }
    packet = {
        **packet_material,
        "artifact_content_sha256": builder._sealed(packet_material),
    }
    packet_raw = builder._pretty_json(packet)
    prompt_raw = b"Synthetic source-delta prompt for tests only.\n"
    packet_sha256 = builder._sha256(packet_raw)
    prompt_sha256 = builder._sha256(prompt_raw)
    package_material: dict[str, object] = {
        "schema": "legalbot.v111.phase2a.source-binding-delta-owner-package.v1",
        "status": "EXACT_SOURCE_BINDING_DELTA_READY_NOT_ADOPTED",
        "packet_content_sha256": packet["artifact_content_sha256"],
        "artifacts": [
            {
                "content_sha256": packet["artifact_content_sha256"],
                "file_sha256": packet_sha256,
                "name": builder.SOURCE_DELTA_PACKET_NAME,
            },
            {
                "file_sha256": prompt_sha256,
                "name": builder.SOURCE_DELTA_PROMPT_NAME,
            },
        ],
        **{
            field: False
            for field in builder._NO_EXECUTION_FLAGS
            if field
            not in {
                "source_delta_decisions_applied",
                "safe_fallback_decision_applied",
                "evaluation_contract_mutated",
            }
        },
    }
    package = {
        **package_material,
        "artifact_content_sha256": builder._sealed(package_material),
    }
    package_raw = builder._pretty_json(package)
    package_sha256 = builder._sha256(package_raw)
    checksums_raw = (
        f"{packet_sha256}  {builder.SOURCE_DELTA_PACKET_NAME}\n"
        f"{prompt_sha256}  {builder.SOURCE_DELTA_PROMPT_NAME}\n"
        f"{package_sha256}  {builder.SOURCE_DELTA_PACKAGE_NAME}\n"
    ).encode()
    files = {
        builder.SOURCE_DELTA_PACKET_NAME: packet_raw,
        builder.SOURCE_DELTA_PROMPT_NAME: prompt_raw,
        builder.SOURCE_DELTA_PACKAGE_NAME: package_raw,
        builder.SOURCE_DELTA_CHECKSUMS_NAME: checksums_raw,
    }
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    return {
        "packet_content": str(packet["artifact_content_sha256"]),
        "packet_file": packet_sha256,
        "package_content": str(package["artifact_content_sha256"]),
        "package_file": package_sha256,
        "prompt_file": prompt_sha256,
        "checksums_file": builder._sha256(checksums_raw),
    }


def _install_source_contract(
    monkeypatch: pytest.MonkeyPatch,
    review: Path,
    hashes: dict[str, str],
) -> None:
    monkeypatch.setattr(builder, "INPUT_REVIEW_ROOT", review)
    monkeypatch.setattr(builder, "OUTPUT_REVIEW_ROOT", review)
    monkeypatch.setattr(builder, "EXPECTED_SOURCE_DELTA_CONTENT_SHA256", hashes["packet_content"])
    monkeypatch.setattr(builder, "EXPECTED_SOURCE_DELTA_FILE_SHA256", hashes["packet_file"])
    monkeypatch.setattr(
        builder,
        "EXPECTED_SOURCE_DELTA_PACKAGE_CONTENT_SHA256",
        hashes["package_content"],
    )
    monkeypatch.setattr(
        builder, "EXPECTED_SOURCE_DELTA_PACKAGE_FILE_SHA256", hashes["package_file"]
    )
    monkeypatch.setattr(builder, "EXPECTED_SOURCE_DELTA_PROMPT_FILE_SHA256", hashes["prompt_file"])
    monkeypatch.setattr(
        builder,
        "EXPECTED_SOURCE_DELTA_CHECKSUMS_FILE_SHA256",
        hashes["checksums_file"],
    )


@pytest.fixture(scope="module")
def built_packet(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("safe-fallback-owner-packet")
    review = root / "review"
    review.mkdir()
    output = review / "safe-fallback-owner-packet-r1"
    patcher = pytest.MonkeyPatch()
    patcher.setattr(builder, "OUTPUT_REVIEW_ROOT", review)
    try:
        result = builder.build_superseding_packet(
            source_delta_root=builder.SOURCE_DELTA_ROOT,
            fca_derivation_root=builder.FCA_DERIVATION_ROOT,
            held9_advisory_root=builder.HELD9_ADVISORY_ROOT,
            fact_fallback_advisory_root=builder.FACT_FALLBACK_ADVISORY_ROOT,
            echr_recovery_root=builder.ECHR_RECOVERY_ROOT,
            q53_substitute_root=builder.Q53_SUBSTITUTE_ROOT,
            output_root=output,
            created_at=datetime(2026, 8, 28, 9, 0, tzinfo=UTC),
        )
    finally:
        patcher.undo()
    assert result["status"] == builder.STATUS
    assert result["output_name"] == output.name
    assert "output_root" not in result
    assert result["row_retained_in_all585"] is True
    assert result["source_scan_run"] is False
    assert result["phase2b_run"] is False
    return output


def test_packet_binds_source_delta_and_exact_superseding_decisions(
    built_packet: Path,
) -> None:
    packet = _load(built_packet / builder.PACKET_NAME)
    source = packet["source_binding_delta"]
    assert isinstance(source, dict)
    assert source["content_sha256"] == builder.EXPECTED_SOURCE_DELTA_CONTENT_SHA256
    assert source["source_decisions_incorporated_except_explicit_supersessions"] is True
    assert source["source_holds_incorporated_without_change"] is True
    assert source["raw_json_index_admission_recommendations_superseded"] is True
    assert source["raw_json_index_admission_replacement"] == (
        "ADMIT_ONLY_15_EXACT_CANONICAL_MARKDOWN_DERIVATIVES"
    )
    assert source["prior_material_hold_disposition_superseded_only_for_row_id"] == (builder.ROW_ID)
    precedence = packet["decision_precedence"]
    assert len(precedence["explicit_supersessions"]) == 4
    assert precedence["explicit_supersessions"][0]["superseded_row_id"] == builder.ROW_ID
    assert precedence["explicit_supersessions"][1]["superseded_representation_count"] == 15
    assert (
        precedence["explicit_supersessions"][2]["superseding_contract_content_sha256"]
        == builder.EXPECTED_PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256
    )
    assert precedence["explicit_supersessions"][3]["superseded_held9_gap_row_ids"] == [
        "live30-q22:issue-02",
        "live30-q22:issue-04",
        "live30-q22:issue-06",
        "live60-q51:issue-05",
        "live60-q53:issue-04",
        "live60-q53:issue-11",
        "live60-q56:issue-01",
        "live60-q56:issue-05",
    ]
    assert precedence["all_other_source_delta_decisions_and_holds_unchanged"] is True
    assert builder._verify_seal(packet, "artifact_content_sha256", "invalid")


def test_packet_binds_all_fca_markdown_derivatives_and_supersedes_raw_json_only(
    built_packet: Path,
) -> None:
    packet = _load(built_packet / builder.PACKET_NAME)
    fca = packet["fca_canonical_markdown_derivation"]
    assert fca["manifest_content_sha256"] == (
        builder.EXPECTED_FCA_DERIVATION_MANIFEST_CONTENT_SHA256
    )
    assert fca["derived_representation_count"] == 15
    assert fca["preserved_provision_count"] == 312
    assert fca["full_json_object_semantic_equivalence_count"] == 15
    assert fca["parser_compatibility_pass_count"] == 15
    assert fca["privacy_pass_count"] == 15
    assert fca["raw_json_bytes_retained_as_immutable_provenance"] is True
    assert fca["raw_json_bytes_not_index_admission_representations"] is True
    assert len(fca["derived_canonical_markdown_bindings"]) == 15
    assert all(
        item["recommended_owner_outcome"]
        == "ADMIT_EXACT_CANONICAL_MARKDOWN_DERIVATIVE_INSTEAD_OF_RAW_JSON"
        for item in fca["derived_canonical_markdown_bindings"]
    )


def test_packet_binds_held9_rows_fail_closed_and_never_releases_held_law(
    built_packet: Path,
) -> None:
    packet = _load(built_packet / builder.PACKET_NAME)
    held9 = packet["held9_surviving_support_advisory"]
    assert held9["content_sha256"] == builder.EXPECTED_HELD9_ADVISORY_CONTENT_SHA256
    decisions = held9["exact_owner_decisions_requested"]
    gaps = decisions["eight_fail_closed_legal_authority_gap_decisions"]
    assert len(gaps) == 8
    assert all(item["technical_pass_eligible"] is False for item in gaps)
    assert all(item["safe_fallback_prohibited"] is True for item in gaps)
    assert decisions["limited_supported_subsets_are_not_qualification_passes"] is True
    q58 = decisions["q58_issue09_no_legal_claim_fallback_decision"]
    assert q58["knowledge_gap_event"] is False
    assert q58["matter_information_gap_event"] is True
    assert q58["fallback_releases_material_legal_claim"] is False
    assert q58["legal_rule_release_prohibited"] is True
    assert q58["citation_release_prohibited"] is True
    assert q58["evidence_span_release_prohibited"] is True
    wuhan = decisions["wuhan_cross_row_candidate_decision"]
    assert wuhan["proposal_content_sha256"] == (builder.EXPECTED_WUHAN_PROPOSAL_CONTENT_SHA256)
    assert wuhan["legal_rule_release_prohibited"] is True
    assert wuhan["currentness_hold_retained"] is True
    assert wuhan["later_treatment_hold_retained"] is True


def test_packet_binds_exact_585_fallback_coverage_and_both_contracts(
    built_packet: Path,
) -> None:
    packet = _load(built_packet / builder.PACKET_NAME)
    coverage = packet["fact_only_fallback_coverage_advisory"]
    assert coverage["content_sha256"] == (builder.EXPECTED_FACT_FALLBACK_ADVISORY_CONTENT_SHA256)
    assert coverage["exact_eligible_row_ids"] == [
        builder.PERFORMANCE_BOND_ROW_ID,
        builder.ROW_ID,
    ]
    assert coverage["remaining_583_rows_not_safe_fallback_eligible"] is True
    decision = packet["performance_bond_safe_fallback_decision"]
    assert decision["row_id"] == builder.PERFORMANCE_BOND_ROW_ID
    assert decision["row_retained_in_all585"] is True
    assert decision["legal_rule_release_prohibited"] is True
    assert decision["citation_release_prohibited"] is True
    assert decision["evidence_span_release_prohibited"] is True
    assert decision["knowledge_gap_event"] is False
    assert decision["matter_information_gap_event"] is True
    assert decision["canonical_contract"] == (builder.performance_bond_safe_fallback_contract())
    assert decision["canonical_contract_content_sha256"] == (
        builder.EXPECTED_PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256
    )
    assert builder._verify_seal(decision, "decision_content_sha256", "invalid")


def test_packet_binds_echr_recoveries_goodwin_and_stopped_mutu_path(
    built_packet: Path,
) -> None:
    packet = _load(built_packet / builder.PACKET_NAME)
    recovery = packet["echr_held_source_recovery"]
    assert recovery["manifest_content_sha256"] == (
        builder.EXPECTED_ECHR_RECOVERY_MANIFEST_CONTENT_SHA256
    )
    records = recovery["exact_new_source_admission_bindings"]
    assert {record["record_content_sha256"] for record in records} == {
        builder.EXPECTED_ECHR_KLIMA_RECORD_CONTENT_SHA256,
        builder.EXPECTED_ECHR_BIG_BROTHER_RECORD_CONTENT_SHA256,
    }
    assert all(record["currentness_hold_retained"] is True for record in records)
    assert all(record["later_treatment_hold_retained"] is True for record in records)
    goodwin = recovery["goodwin_existing_quarantine_binding"]
    assert goodwin["record_content_sha256"] == (builder.EXPECTED_ECHR_GOODWIN_RECORD_CONTENT_SHA256)
    assert goodwin["new_source_admission_required"] is False
    mutu = recovery["mutu_pechstein_transport_hold"]
    assert mutu["failure_fingerprint"] == (builder.EXPECTED_ECHR_MUTU_FAILURE_FINGERPRINT_SHA256)
    assert mutu["retry_run"] is False
    assert recovery["no_more_mutu_network_attempts"] is True


def test_packet_binds_q53_semenya_exact_revised_propositions_only(
    built_packet: Path,
) -> None:
    packet = _load(built_packet / builder.PACKET_NAME)
    q53 = packet["q53_semenya_substitute_advisory"]
    assert q53["content_sha256"] == (builder.EXPECTED_Q53_SUBSTITUTE_ADVISORY_CONTENT_SHA256)
    source = q53["semenya_source_admission_binding"]
    assert source["record_content_sha256"] == (builder.EXPECTED_Q53_SEMENYA_RECORD_CONTENT_SHA256)
    assert source["raw_sha256"] == builder.EXPECTED_Q53_SEMENYA_RAW_SHA256
    assert source["canonical_markdown_sha256"] == (builder.EXPECTED_Q53_SEMENYA_CANONICAL_SHA256)
    assert len(source["required_paragraphs_verified"]) == 40
    rows = q53["exact_revised_proposition_set_owner_decisions"]
    assert {row["row_id"] for row in rows} == {
        "live60-q53:issue-04",
        "live60-q53:issue-11",
    }
    assert all(row["safe_fallback_prohibited"] is True for row in rows)
    assert all(row["currentness_hold_retained"] is True for row in rows)
    assert q53["mutu_historical_claims_explicitly_excluded"] is True
    assert q53["mutu_network_path_permanently_stopped"] is True
    assert q53["semenya_not_described_as_disciplinary"] is True
    assert q53["answer_eligible"] is False


def test_safe_fallback_keeps_row_and_cancels_only_unsupported_answer_contract(
    built_packet: Path,
) -> None:
    packet = _load(built_packet / builder.PACKET_NAME)
    decision = packet["safe_fallback_decision"]
    assert isinstance(decision, dict)
    assert decision["row_id"] == builder.ROW_ID
    assert decision["row_retained_in_all585"] is True
    assert decision["evaluation_row_removed"] is False
    assert decision["classification"] == builder.OUTCOME_CLASS
    assert decision["fallback_reason_code"] == builder.REASON_CODE
    assert decision["ui_cta"] == builder.UI_CTA
    assert decision["knowledge_gap_event"] is False
    assert decision["matter_information_gap_event"] is True
    assert decision["substantive_answer_requirement"] == "CANCELLED_FOR_THIS_ROW"
    assert decision["evidence_span_requirement"] == "CANCELLED_FOR_THIS_ROW"
    assert decision["substantive_legal_answer_required"] is False
    assert decision["evidence_span_required"] is False
    assert decision["additional_official_source_search_required"] is False
    assert decision["no_further_source_search_loop_for_this_row"] is True
    assert decision["qualification_result_when_contract_satisfied"] == (
        builder.QUALIFICATION_STATUS
    )
    assert decision["qualification_result_when_contract_violated"] == builder.FAILURE_STATUS
    assert decision["material_legal_proposition_claimed_resolved"] is False
    assert decision["canonical_contract_content_sha256"] == (
        builder.EXPECTED_SAFE_FALLBACK_CONTRACT_CONTENT_SHA256
    )
    assert decision["canonical_contract"] == builder.safe_fallback_contract()
    assert builder._verify_seal(decision, "decision_content_sha256", "invalid")


def test_deterministic_reply_has_every_required_information_category_and_escalation(
    built_packet: Path,
) -> None:
    packet = _load(built_packet / builder.PACKET_NAME)
    decision = packet["safe_fallback_decision"]
    reply = decision["deterministic_reply"].casefold()
    assert decision["reply_match_mode"] == "EXACT_UTF8_STRING"
    assert decision["missing_information_categories"] == list(
        builder.MISSING_INFORMATION_CATEGORIES
    )
    for marker in (
        "insufficient",
        "contracts",
        "notices",
        "deadlines",
        "financing",
        "security",
        "insurance",
        "safety",
        "consents",
        "provide",
        "qualified human lawyer",
    ):
        assert marker in reply
    assert decision["human_escalation_cta"] == builder.HUMAN_ESCALATION_CTA
    assert decision["deterministic_reply"] == builder.SAFE_FALLBACK_MESSAGE
    assert decision["deterministic_reply_sha256"] == (builder.EXPECTED_SAFE_FALLBACK_REPLY_SHA256)
    assert decision["missing_information_categories_sha256"] == (
        builder.EXPECTED_SAFE_FALLBACK_CATEGORIES_SHA256
    )
    assert decision["canonical_contract"]["pass_requirements"] == {
        "substantive_project_rescue_advice_refused": True,
        "all_missing_information_categories_identified": True,
        "supplementation_requested": True,
        "qualified_human_legal_review_required": True,
        "knowledge_gap_event": False,
        "matter_information_gap_event": True,
        "material_legal_claim_released": False,
        "answer_model_invoked_for_this_issue": False,
    }


def test_every_execution_and_phase2b_boundary_remains_closed(built_packet: Path) -> None:
    packet = _load(built_packet / builder.PACKET_NAME)
    package = _load(built_packet / builder.PACKAGE_NAME)
    assert len(builder._NO_EXECUTION_FLAGS) == 55
    for field, value in builder._NO_EXECUTION_FLAGS.items():
        assert value is False
        assert packet[field] is False
        assert package[field] is False
    assert packet["phase_scope"] == "PHASE2A_ONLY"
    assert "PHASE2B" in packet["approval_does_not_authorize"]
    assert packet["packet_builder_effect"] == "CREATE_ONLY_NO_EXECUTION"
    assert package["packet_builder_effect"] == "CREATE_ONLY_NO_EXECUTION"
    assert builder._verify_seal(package, "artifact_content_sha256", "invalid")


def test_packet_preserves_one_total_unspent_phase2a_execution_chain(
    built_packet: Path,
) -> None:
    packet = _load(built_packet / builder.PACKET_NAME)
    authority = packet["single_remaining_phase2a_execution_authority"]
    assert authority["authority_origin_owner_packet_content_sha256"] == (
        builder.EXPECTED_ORIGINAL_OWNER_PACKET_CONTENT_SHA256
    )
    assert authority["authority_origin_owner_receipt_content_sha256"] == (
        builder.EXPECTED_ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256
    )
    assert authority["authority_preexisted_this_packet"] is True
    assert authority["authority_consumed_before_this_packet"] is False
    assert authority["new_or_additional_execution_authority_created_by_this_packet"] is False
    assert authority["total_remaining_execution_chain_count"] == 1
    assert authority["second_scan_build_or_embedding_authority_created"] is False
    assert authority["execution_chain_after_exact_owner_adoption"] == [
        "APPLY_EXACT_OWNER_DECISIONS",
        "MATERIALIZE_ONLY_EXACT_ADOPTED_SOURCE_REPRESENTATIONS",
        "RUN_ONE_COMPLETE_SOURCE_SCAN",
        "BUILD_AND_EMBED_ONE_NON_ACTIVE_ANSWER_INELIGIBLE_SUCCESSOR",
        "RUN_ONE_RETRIEVAL_REATTESTATION",
        "RUN_ONE_ALL585_TECHNICAL_QUALIFICATION",
    ]


def test_prompt_is_exact_and_does_not_claim_execution_or_phase2b_authority(
    built_packet: Path,
) -> None:
    packet = _load(built_packet / builder.PACKET_NAME)
    prompt = (built_packet / builder.PROMPT_NAME).read_text(encoding="utf-8")
    assert packet["artifact_content_sha256"] in prompt
    assert builder.ROW_ID in prompt
    assert "remains in all-585" in prompt
    assert builder.PERFORMANCE_BOND_ROW_ID in prompt
    assert "exact byte-for-byte insufficiency response" in prompt
    assert "offer qualified human legal review" in prompt
    assert "Neither may release a legal rule, advice, citation, EvidenceSpan" in prompt
    assert "raw JSON remains immutable provenance" in prompt
    assert builder.EXPECTED_ECHR_RECOVERY_MANIFEST_CONTENT_SHA256 in prompt
    assert builder.EXPECTED_Q53_SUBSTITUTE_ADVISORY_CONTENT_SHA256 in prompt
    assert "Mutu network path remains permanently stopped" in prompt
    assert "one total unspent Phase-2A execution chain" in prompt
    assert "does not create a second or additional scan" in prompt
    assert "have not themselves applied a decision" in prompt
    assert "does not authorize an answer-model run or answer release, Phase 2B" in prompt
    assert prompt.endswith("Owner typed name:\nDecision date:\n")


def test_output_is_private_atomic_create_only_and_checksum_exact(
    built_packet: Path,
) -> None:
    assert stat.S_IMODE(built_packet.stat().st_mode) == 0o700
    assert not list(built_packet.parent.glob(f".{built_packet.name}.staging-*"))
    for path in built_packet.iterdir():
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    checksums = (built_packet / builder.CHECKSUMS_NAME).read_text(encoding="utf-8")
    expected = "".join(
        f"{builder._sha256_file(path)}  {path.name}\n"
        for path in sorted(built_packet.iterdir())
        if path.name != builder.CHECKSUMS_NAME
    )
    assert checksums == expected


def test_source_delta_tampering_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    review = tmp_path / "review"
    review.mkdir()
    source = review / builder.SOURCE_DELTA_ROOT_NAME
    hashes = _write_source_delta(source)
    _install_source_contract(monkeypatch, review, hashes)
    with (source / builder.SOURCE_DELTA_PACKET_NAME).open("ab") as handle:
        handle.write(b"tamper")
    with pytest.raises(ValueError, match="source_delta_packet_file_invalid"):
        builder._verify_source_delta(source)


def test_external_same_basename_source_root_is_rejected(tmp_path: Path) -> None:
    external = tmp_path / builder.SOURCE_DELTA_ROOT_NAME
    _write_source_delta(external)
    with pytest.raises(ValueError, match="source_delta_root_identity_invalid"):
        builder._verify_source_delta(external)


def test_output_path_is_scoped_and_create_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    review = tmp_path / "review"
    review.mkdir()
    monkeypatch.setattr(builder, "OUTPUT_REVIEW_ROOT", review)
    existing = review / "existing"
    existing.mkdir()
    with pytest.raises(ValueError, match="output_already_exists"):
        builder._ensure_output_path(existing)
    with pytest.raises(ValueError, match="output_outside_review_root"):
        builder._ensure_output_path(tmp_path / "outside")


def test_naive_timestamp_is_rejected_before_any_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    review = tmp_path / "review"
    review.mkdir()
    source = review / builder.SOURCE_DELTA_ROOT_NAME
    hashes = _write_source_delta(source)
    _install_source_contract(monkeypatch, review, hashes)
    output = review / "output"
    with pytest.raises(ValueError, match="created_at_must_be_aware"):
        builder.build_superseding_packet(
            source_delta_root=source,
            fca_derivation_root=builder.FCA_DERIVATION_ROOT,
            held9_advisory_root=builder.HELD9_ADVISORY_ROOT,
            fact_fallback_advisory_root=builder.FACT_FALLBACK_ADVISORY_ROOT,
            echr_recovery_root=builder.ECHR_RECOVERY_ROOT,
            q53_substitute_root=builder.Q53_SUBSTITUTE_ROOT,
            output_root=output,
            created_at=datetime(2026, 8, 28, 9, 0),
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "leak",
    [
        "/Users/reviewer/Desktop/private-notes.docx",
        "/home/reviewer/source.pdf",
        r"C:\Users\reviewer\Documents\source.docx",
        r"\\server\private-share\source.pdf",
        "reviewer@example.com",
        "Agnes",
        "LegalBot-New/private-source.pdf",
    ],
)
def test_privacy_check_rejects_paths_identity_email_and_personal_files(
    leak: str,
) -> None:
    with pytest.raises(ValueError, match="phase2a_safe_fallback_privacy"):
        builder._privacy_check([{"nested": [{"value": leak}]}])


def test_real_exact_source_delta_artifacts_verify() -> None:
    packet = builder._verify_source_delta(builder.SOURCE_DELTA_ROOT)
    assert packet["artifact_content_sha256"] == (
        "01312e142dd084271aa005b3d2a5ba8b93564bf3a841e1f5a4ec68c06a604ac0"
    )
    assert packet["known_all585_material_hold"]["row_id"] == builder.ROW_ID


def test_real_exact_fca_derivation_and_canonical_fallback_contract_verify() -> None:
    source_delta = builder._verify_source_delta(builder.SOURCE_DELTA_ROOT)
    manifest, bindings = builder._verify_fca_derivation(
        root=builder.FCA_DERIVATION_ROOT,
        source_delta=source_delta,
    )
    assert manifest["manifest_content_sha256"] == (
        builder.EXPECTED_FCA_DERIVATION_MANIFEST_CONTENT_SHA256
    )
    assert len(bindings) == 15
    assert builder._canonical_safe_fallback_contract()["contract_content_sha256"] == (
        builder.EXPECTED_SAFE_FALLBACK_CONTRACT_CONTENT_SHA256
    )
    held9 = builder._verify_held9_advisory(builder.HELD9_ADVISORY_ROOT)
    assert held9["artifact_content_sha256"] == (builder.EXPECTED_HELD9_ADVISORY_CONTENT_SHA256)
