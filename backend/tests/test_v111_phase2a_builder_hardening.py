from __future__ import annotations

import hashlib
import json
from contextlib import nullcontext
from copy import deepcopy
from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from scripts import build_v111_phase2a_review_package as builder

from app.evaluation.live_suite import load_live_evaluation_bundle, sealed_sha256

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
BUILD_ROOT = PROJECT_ROOT / "data/indexes/builds" / "current-law-ew-full-fp16-v111-20260818-a"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inputs() -> tuple[object, dict[str, object]]:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    manifest = json.loads((BUILD_ROOT / "approved-source-manifest.json").read_text())
    return bundle, manifest


def test_findings_bind_stable_content_temporal_state_and_exact_issue_rows() -> None:
    bundle, manifest = _inputs()
    records = builder._finding_review_records(
        bundle=bundle,
        candidate_source_manifest=manifest,
    )

    assert len(records) == len(builder.OFFICIAL_FINDINGS) == 11
    assert {record["finding_id"] for record in records} == set(builder.FINDING_AFFECTED_ISSUE_ROWS)
    for record in records:
        material = dict(record)
        digest = material.pop("record_sha256")
        assert digest == sealed_sha256(material)
        assert record["affected_issue_row_ids"]
        assert record["document_content_identity"]["media_type"] == "application/pdf"
        assert record["document_content_identity"]["content_bytes_retrieved_by_builder"] is False
        assert record["temporal_status"]["single_effective_date_claimed"] is False
        assert record["candidate_absence_observation"]["scope"] == (
            "SEALED_APPROVED_SOURCE_MANIFEST_ONLY"
        )
        if record["finding_id"].endswith(("uksc-28", "uksc-6", "uksc-14", "uksc-24", "uksc-30")):
            assert record["core_canonical_url_role"] == (
                "MUTABLE_OFFICIAL_LOCATOR_ONLY_NOT_CONTENT_PROOF"
            )
            assert record["document_content_identity"]["content_url"].startswith(
                "https://caselaw.nationalarchives.gov.uk/"
            )
            assert record["temporal_status"]["authority_date_kind"] == ("JUDGMENT_DELIVERY_DATE")
        else:
            assert record["temporal_status"]["authority_date_kind"] == "ROYAL_ASSENT_DATE"
            assert (
                record["temporal_status"]["per_provision_commencement_effective_transition_state"]
                == "REVIEW_REQUIRED_NOT_COMPLETED"
            )


def test_candidate_absence_is_scoped_and_rejects_an_authority_match() -> None:
    bundle, manifest = _inputs()
    injected = deepcopy(manifest)
    injected["sources"][0]["authority_identity_id"] = builder.FINDING_AUTHORITY_IDENTITIES[
        "gap-augustine-2026-uksc-30"
    ]

    with pytest.raises(RuntimeError, match="phase2a_external_finding_present_in_candidate"):
        builder._finding_review_records(
            bundle=bundle,
            candidate_source_manifest=injected,
        )


@pytest.mark.parametrize(
    "url_alias",
    (
        "https://legislation.gov.uk/ukpga/2025/26/pdfs/ukpga_20250026_en.pdf/",
        "https://legislation.gov.uk/ukpga/2025/26/pdfs/%75kpga_20250026_en.pdf",
        "https://www.legislation.gov.uk/ukpga/2025/26/pdfs/unused/../ukpga_20250026_en.pdf",
    ),
)
def test_candidate_absence_rejects_equivalent_official_url_alias(url_alias: str) -> None:
    bundle, manifest = _inputs()
    injected = deepcopy(manifest)
    injected["sources"][0]["canonical_url"] = url_alias

    with pytest.raises(RuntimeError, match="phase2a_external_finding_present_in_candidate"):
        builder._finding_review_records(
            bundle=bundle,
            candidate_source_manifest=injected,
        )


def test_mapped_finding_rows_require_successor_candidate_bytes() -> None:
    bundle, manifest = _inputs()
    records = builder._finding_review_records(
        bundle=bundle,
        candidate_source_manifest=manifest,
    )
    dispositions = builder._blocked_dispositions(
        bundle=bundle,
        review=SimpleNamespace(official_source_review_method_sha256="a" * 64),
        finding_review_records=records,
    )
    mapped_rows = {row_id for record in records for row_id in record["affected_issue_row_ids"]}

    assert len(dispositions) == 585
    assert mapped_rows
    assert {
        row_id
        for row_id, disposition in dispositions.items()
        if disposition.candidate_bytes_change_required is True
    } == mapped_rows
    for row_id in mapped_rows:
        disposition = dispositions[row_id]
        assert disposition.primary_status == "MATERIAL_CANDIDATE_COVERAGE_GAP"
        assert disposition.external_official_finding_ids
        assert disposition.affected_proposition_state == "MAPPED_MATERIAL_GAP"
    for row_id in set(dispositions).difference(mapped_rows):
        disposition = dispositions[row_id]
        assert disposition.primary_status == "GOLD_OR_CASE_DEFECT"
        assert disposition.candidate_bytes_change_required is None
        assert disposition.external_official_finding_ids == ()


def test_candidate_binding_calls_sealed_tree_and_both_store_verifiers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = json.loads((BUILD_ROOT / "manifest.json").read_text())
    source_manifest = json.loads((BUILD_ROOT / "approved-source-manifest.json").read_text())
    sealed = SimpleNamespace(
        build_id=builder.CANDIDATE_ID,
        status="candidate",
        candidate_manifest_sha256=_sha256(BUILD_ROOT / "manifest.json"),
        candidate_seal_sha256=_sha256(BUILD_ROOT / "seal.json"),
        source_manifest_sha256=source_manifest["manifest_sha256"],
        embedding_model=manifest["embedding_model"],
        reranker_model=manifest["reranker_model"],
        document_count=source_manifest["source_count"],
        chunk_count=manifest["chunk_count"],
        vector_count=manifest["chunk_count"],
    )
    embedding_path = PROJECT_ROOT / "models/retrieval/Qwen3-Embedding-0.6B"
    reranker_path = PROJECT_ROOT / "models/retrieval/Qwen3-Reranker-0.6B"
    settings = SimpleNamespace(
        database_path=PROJECT_ROOT / "data/catalog.sqlite3",
        embedding_model_path=embedding_path,
        reranker_model_path=reranker_path,
    )
    calls: list[tuple[Path, str, str, str]] = []

    monkeypatch.setattr(
        builder,
        "open_immutable_phase2_catalogue",
        lambda _path: nullcontext(object()),
    )
    monkeypatch.setattr(
        builder,
        "load_phase2_candidate_and_retrieval_evidence",
        lambda **_kwargs: (sealed, object()),
    )

    def verify_store(
        path: Path, repo: str, revision: str, *, expected_file_manifest_sha256: str
    ) -> Path:
        calls.append((path, repo, revision, expected_file_manifest_sha256))
        return path

    monkeypatch.setattr(builder, "_verified_local_model", verify_store)
    monkeypatch.setattr(
        builder,
        "_local_model_file_manifest_sha256",
        lambda path: (
            builder.PINNED_EMBEDDING_FILE_MANIFEST_SHA256
            if path == embedding_path
            else builder.PINNED_RERANKER_FILE_MANIFEST_SHA256
        ),
    )
    monkeypatch.setattr(
        builder, "_production_embedding_identity", lambda _settings: sealed.embedding_model
    )
    monkeypatch.setattr(
        builder, "_production_reranker_identity", lambda _settings: sealed.reranker_model
    )

    binding = builder._candidate_binding(settings=settings, code=object())

    assert binding.candidate_manifest_sha256 == sealed.candidate_manifest_sha256
    assert binding.candidate_seal_file_sha256 == sealed.candidate_seal_sha256
    assert {call[0] for call in calls} == {embedding_path, reranker_path}
    assert {call[3] for call in calls} == {
        builder.PINNED_EMBEDDING_FILE_MANIFEST_SHA256,
        builder.PINNED_RERANKER_FILE_MANIFEST_SHA256,
    }


def test_hardened_extensions_build_a_strict_blocked_package() -> None:
    bundle, source_manifest = _inputs()
    candidate_manifest = json.loads((BUILD_ROOT / "manifest.json").read_text())
    records = builder._finding_review_records(
        bundle=bundle,
        candidate_source_manifest=source_manifest,
    )
    synthetic = {
        "schema": "legalbot.v111-phase2a-synthetic-split-test-result.v1",
        "record_sha256": "c" * 64,
    }
    extensions = builder._details(
        code_commit="a" * 40,
        code_tree="b" * 40,
        action_audit={"schema": "phase2a-scoped-absence", "audit_sha256": "d" * 64},
        synthetic=synthetic,
        finding_review_records=records,
    )
    candidate = builder.Phase2ACandidateBinding.model_validate(
        {
            "build_id": builder.CANDIDATE_ID,
            "candidate_manifest_sha256": _sha256(BUILD_ROOT / "manifest.json"),
            "candidate_seal_file_sha256": _sha256(BUILD_ROOT / "seal.json"),
            "approved_source_manifest_sha256": source_manifest["manifest_sha256"],
            "approved_source_manifest_file_sha256": _sha256(
                BUILD_ROOT / "approved-source-manifest.json"
            ),
            "embedding_store_sha256": builder.PINNED_EMBEDDING_FILE_MANIFEST_SHA256,
            "reranker_store_sha256": builder.PINNED_RERANKER_FILE_MANIFEST_SHA256,
            "document_count": source_manifest["source_count"],
            "chunk_count": candidate_manifest["chunk_count"],
            "vector_count": candidate_manifest["chunk_count"],
            "dimensions": candidate_manifest["vector_dimensions"],
        }
    )
    action_audit = builder.Phase2AActionAbsenceAudit(
        audit_sha256="d" * 64,
        active_pointer_absent=True,
        previous_pointer_absent=True,
        real_split_absent=True,
        real_split_secret_absent=True,
        signing_key_absent=True,
        session_secret_absent=True,
        real_review_roots_absent=True,
        stage_a_results_absent=True,
        answer_model_results_absent=True,
        development_projection_absent=True,
    )
    official_method = extensions["official-source-provenance-register"]["review_method"]
    cutoff = extensions["cutoff-recommendation"]
    freshness = extensions["freshness-material-change-policy"]
    security = extensions["security-owner-controls-proposal"]
    contract = extensions["certification-contract-proposal"]
    review = builder.Phase2AReviewInputs(
        generated_at=datetime(2026, 8, 22, 16, 0, tzinfo=UTC),
        code=builder.Phase2ACodeBinding(
            commit_sha="a" * 40,
            tree_sha="b" * 40,
            worktree_clean=True,
        ),
        candidate=candidate,
        action_absence_audit=action_audit,
        entry_state_sha256="e" * 64,
        official_source_review_method_sha256=sealed_sha256(official_method),
        recommended_cutoff_date=None,
        review_target_cutoff_date=date(2026, 8, 14),
        cutoff_support_status="UNSUPPORTABLE_ON_CURRENT_CANDIDATE",
        cutoff_basis_sha256=sealed_sha256(cutoff),
        freshness_policy_sha256=sealed_sha256(freshness),
        security_controls_proposal_sha256=sealed_sha256(security),
        certification_contract_proposal_sha256=sealed_sha256(contract),
        synthetic_split_verification_sha256="c" * 64,
        synthetic_split_verification_passed=True,
        terminal_verdict="BLOCKED_MATERIAL_GAPS",
        candidate_rebuild_required=True,
        confirmed_material_candidate_finding_count=11,
    )
    dispositions = builder._blocked_dispositions(
        bundle=bundle,
        review=review,
        finding_review_records=records,
    )

    package = builder.build_phase2a_package(
        bundle=bundle,
        candidate_source_manifest=source_manifest,
        review=review,
        dispositions=dispositions,
        external_official_findings=builder.OFFICIAL_FINDINGS,
        artifact_payload_extensions=extensions,
    )

    impact = package.artifact("candidate-impact-report").payload
    assert impact["candidate_rebuild_required"] is True
    assert impact["candidate_change_required_issue_count"] == len(
        {row_id for record in records for row_id in record["affected_issue_row_ids"]}
    )
    assert package.artifact("final-invariants").payload["phase2b_allowed"] is False

    renters = builder.OFFICIAL_FINDINGS[0]
    data_act = builder.OFFICIAL_FINDINGS[1]
    forged_renters = renters.model_copy(
        update={
            "official_title": data_act.official_title,
            "official_identifier": data_act.official_identifier,
            "canonical_url": data_act.canonical_url,
            "retrieved_content_sha256": data_act.retrieved_content_sha256,
            "legal_effect_date": data_act.legal_effect_date,
        }
    )
    with pytest.raises(ValueError, match="finding content/absence binding"):
        builder.build_phase2a_package(
            bundle=bundle,
            candidate_source_manifest=source_manifest,
            review=review,
            dispositions=dispositions,
            external_official_findings=(
                forged_renters,
                *builder.OFFICIAL_FINDINGS[1:],
            ),
            artifact_payload_extensions=extensions,
        )
