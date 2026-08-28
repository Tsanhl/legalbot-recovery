from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.build_v111_phase2a_judgment_readiness import (
    EXPECTED_FRESH_MANIFEST_DIGEST,
    OUTPUT_NAME,
    _pretty_json,
    _sealed,
    build_judgment_readiness,
)

ROOT = Path(__file__).resolve().parents[2]
OWNER_REVIEW = ROOT / "data" / "evaluations" / "phase2a-owner-review"
JUDGMENTS = (
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r4"
    / "owner-reviewed-judgments-20.json"
)
CANDIDATE_MANIFEST = (
    ROOT
    / "data"
    / "indexes"
    / "builds"
    / "current-law-ew-full-fp16-v111-20260818-a"
    / "approved-source-manifest.json"
)
RESEARCH = (
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r17"
    / "UNRESOLVED-502-LEXICAL-RESEARCH-PACKETS.json"
)
FRESH = OWNER_REVIEW / "LegalBot-Phase2AB-2026-08-24-r34-quarantine"
QUISTCLOSE_DOWNLOAD = ROOT / "data" / "review_queue" / "quistclose-authority-download.json"
QUISTCLOSE_APPROVAL = ROOT / "data" / "review_queue" / "quistclose-authority-approval.json"
PRIOR = [
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r9"
    / "GOLD-SUCCESSOR-BINDINGS-48.json",
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r16"
    / "CANDIDATE-REBINDING-SCOPE-35.json",
    OWNER_REVIEW
    / "LegalBot-Phase2AB-2026-08-24-r28"
    / "OWNER-APPROVED-CANDIDATE-REBINDING-SCOPE-54.json",
]


def _build(tmp_path: Path, *, fresh_root: Path = FRESH) -> dict[str, object]:
    return build_judgment_readiness(
        judgments_path=JUDGMENTS,
        candidate_manifest_path=CANDIDATE_MANIFEST,
        research_packets_path=RESEARCH,
        fresh_quarantine_root=fresh_root,
        vault_root=ROOT / "data" / "vault" / "objects" / "sha256",
        quistclose_download_path=QUISTCLOSE_DOWNLOAD,
        quistclose_approval_path=QUISTCLOSE_APPROVAL,
        prior_approval_paths=PRIOR,
        output_root=tmp_path / "output",
    )


def test_verifies_source_custody_but_keeps_all_later_treatment_held(
    tmp_path: Path,
) -> None:
    progress = _build(tmp_path)
    artifact = json.loads((tmp_path / "output" / OUTPUT_NAME).read_bytes())

    assert progress["summary"] == {
        "fresh_official_access_blocked_with_sealed_local_provenance": 3,
        "fresh_official_identity_downloaded": 17,
        "judgment_record_count": 20,
        "later_treatment_owner_decisions_required": 20,
        "later_treatment_resolved": 0,
        "sealed_historical_snapshot_integrity_verified": 20,
        "source_versions_not_referenced_in_approved_137_or_unresolved_502": 6,
        "source_versions_referenced_in_unresolved_502": 14,
        "unique_neutral_citation_count": 18,
        "unresolved_502_judgment_candidate_references": 690,
        "unresolved_502_rows_with_judgment_candidates": 306,
    }
    assert artifact["all_historical_snapshot_bytes_verified"] is True
    assert artifact["all_later_treatment_resolved"] is False
    assert artifact["legacy_bulk_search_findings_consumed"] is False
    assert artifact["find_case_law_computational_analysis_licence_evidence_sha256"] is None
    assert artifact["automatic_source_admission"] is False
    assert artifact["candidate_mutated"] is False
    assert artifact["phase2b_authorized"] is False
    assert artifact["development30_authorized"] is False
    assert all(
        record["sealed_historical_snapshot"]["identity_binding_verified"] is True
        for record in artifact["records"]
    )
    twinsectra = [
        record
        for record in artifact["records"]
        if record["neutral_citation"] == "[2002] UKHL 12"
    ]
    assert len(twinsectra) == 3
    assert all(record["historical_local_recovery_provenance"] for record in twinsectra)
    assert all(record["fresh_official_retrieval"]["http_status"] == 403 for record in twinsectra)
    assert all(record["owner_decision_required"] is True for record in artifact["records"])


def test_rejects_resealed_fresh_manifest_that_claims_unlicensed_bulk_authority(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "fresh"
    copied.mkdir()
    manifest = json.loads((FRESH / "QUARANTINE-MANIFEST.json").read_bytes())
    assert manifest.pop("manifest_sha256") == EXPECTED_FRESH_MANIFEST_DIGEST
    manifest["find_case_law_computational_analysis"][
        "bulk_later_treatment_search_authorized"
    ] = True
    manifest["manifest_sha256"] = _sealed(manifest)
    (copied / "QUARANTINE-MANIFEST.json").write_bytes(_pretty_json(manifest))

    with pytest.raises(
        ValueError,
        match="phase2a_judgment_readiness_fresh_manifest_boundary_invalid",
    ):
        _build(tmp_path, fresh_root=copied)


def test_create_only_output_refuses_existing_directory(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    with pytest.raises(ValueError, match="phase2a_judgment_readiness_output_already_exists"):
        build_judgment_readiness(
            judgments_path=JUDGMENTS,
            candidate_manifest_path=CANDIDATE_MANIFEST,
            research_packets_path=RESEARCH,
            fresh_quarantine_root=FRESH,
            vault_root=ROOT / "data" / "vault" / "objects" / "sha256",
            quistclose_download_path=QUISTCLOSE_DOWNLOAD,
            quistclose_approval_path=QUISTCLOSE_APPROVAL,
            prior_approval_paths=PRIOR,
            output_root=output,
        )
