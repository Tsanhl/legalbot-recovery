from __future__ import annotations

import hashlib
import json

import pytest
from scripts import verify_v111_phase2a_post_r94_exact_spans as verifier


def _candidate(rank: int, chunk_id: str) -> dict[str, object]:
    text = f"Section {rank} provides an exact rule. A second sentence remains available."
    material: dict[str, object] = {
        "rank": rank,
        "chunk_id": chunk_id,
        "source_version_id": f"source-version-{rank}",
        "source_identity": f"ukpga:2000:{rank}:latest-available@2026-08-14",
        "authority_identity_id": f"ukpga:2000:{rank}",
        "title": f"Example Act {rank}",
        "canonical_url": f"https://www.legislation.gov.uk/ukpga/2000/{rank}",
        "citation": f"Example Act {rank}",
        "canonical_citation": f"Example Act {rank}",
        "locator": f"section {rank}",
        "text": text,
        "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "source_version_sha256": str(rank) * 64,
        "source_date": "2000-01-01",
        "as_of_date": "2026-08-14",
        "currentness_status": "latest_available_revised_snapshot",
        "currentness_verified": True,
        "legal_role": "primary_legislation",
        "case_currentness_reviews_json": "[]",
        "case_currentness_manifest_seals_json": "[]",
        "rrf_score": 0.01,
        "reranker_score": 0.9,
        "selection_basis": "GLOBAL_RERANK_FILL",
        "route_evidence": [{"route": "VECTOR_GLOBAL", "rank": rank}],
        "already_in_exact_sealed_candidate": True,
        "candidate_manifest_source_bound": True,
    }
    return {**material, "candidate_content_sha256": verifier._sealed(material)}


def _checkpoint_row(
    *, status: str, candidates: object
) -> dict[str, object]:
    material: dict[str, object] = {
        "schema": "legalbot.v111.phase2a.post-r94-candidate-recovery-row.v2",
        "ordinal": 1,
        "row_id": "live30-q01:issue-01",
        "case_id": "live30-q01",
        "issue_label": "example issue",
        "status": status,
        "classification": "DETERMINISTIC_ISSUE_QUERY",
        "advisory_atomic_proposition": None,
        "planned_authority_ids": [],
        "planned_source_identities_in_candidate": [],
        "planned_authority_ids_outside_candidate": [],
        "source_issue_registry_content_sha256": (
            verifier.EXPECTED_ISSUE_REGISTRY_DIGEST
        ),
        "source_issue_registry_row_content_sha256": "1" * 64,
        "query": "example issue exact rule",
        "candidates": candidates,
        "source_plans_content_sha256": "a" * 64,
        "threshold_applied": False,
        "technical_qualification_assigned": False,
        "owner_decision_required": True,
    }
    return {**material, "checkpoint_content_sha256": verifier._sealed(material)}


def _recovery(row: dict[str, object]) -> dict[str, object]:
    material: dict[str, object] = {
        "schema": "legalbot.v111.phase2a.post-r94-candidate-recovery-361.v2",
        "status": "ADVISORY_EXACT_CANDIDATE_RECOVERY_COMPLETE_OWNER_REVIEW_REQUIRED",
        "candidate_manifest_sha256": verifier.EXPECTED_CANDIDATE_MANIFEST_DIGEST,
        "source_issue_registry_content_sha256": (
            verifier.EXPECTED_ISSUE_REGISTRY_DIGEST
        ),
        "row_count": 1,
        "rows": [row],
        "deterministic_query_strategy": {
            "sealed_registry_planned_authority_routes_used": True,
            "route_diverse_candidate_selection": True,
        },
        "deterministic_retrieval_precedes_advisory_ai": True,
        "advisory_planner_required": False,
        "issue_labels_and_legal_domains_registry_bound": True,
        "threshold_applied": False,
        "old_candidate_fallback": False,
        "network_answering": False,
        "answer_model_invoked": False,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    return {**material, "artifact_content_sha256": verifier._sealed(material)}


def test_static_findings_are_explicit_and_unknown_status_fails_closed() -> None:
    no_hit = verifier._static_finding(
        {
            "row_id": "live30-q01:issue-01",
            "status": "NO_EXACT_CANDIDATE_HIT_OFFICIAL_SOURCE_RESEARCH_REQUIRED",
        }
    )
    assert no_hit is not None
    assert no_hit["assessment"] == "MATERIAL_GAP_ADVISORY"
    assert no_hit["owner_decision_required"] is True

    assert (
        verifier._static_finding(
            {
                "row_id": "live30-q01:issue-01",
                "status": "EXACT_CANDIDATE_CHUNKS_READY_FOR_SPAN_VERIFICATION",
            }
        )
        is None
    )
    with pytest.raises(
        ValueError, match="phase2a_post_r94_span_recovery_status_invalid"
    ):
        verifier._static_finding(
            {"row_id": "live30-q01:issue-01", "status": "UNSEEN_STATUS"}
        )


def test_review_projection_preserves_full_text_and_records_omissions() -> None:
    projected = verifier._project_review_row(
        {
            "row_id": "live30-q01:issue-01",
            "issue_label": "example issue",
            "advisory_atomic_proposition": "An exact rule applies.",
            "candidates": [
                _candidate(1, "chunk-1"),
                _candidate(2, "chunk-2"),
                _candidate(3, "chunk-3"),
                _candidate(4, "chunk-4"),
            ],
        }
    )

    assert len(projected["evidence_candidates"]) == 3
    first = projected["evidence_candidates"][0]
    chunk = first["chunks"][0]
    assert chunk["silent_text_truncation"] is False
    assert chunk["source_text_reproduced_by_partition_sha256"] == chunk["text_sha256"]
    assert first["projection_integrity"]["omitted_candidate_count"] == 1


def test_recovery_loader_rejects_non_list_candidates_and_unknown_status(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(verifier, "EXPECTED_ROW_COUNT", 1)

    malformed = _recovery(
        _checkpoint_row(
            status="NO_EXACT_CANDIDATE_HIT_OFFICIAL_SOURCE_RESEARCH_REQUIRED",
            candidates={},
        )
    )
    malformed_path = tmp_path / "malformed.json"
    malformed_path.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(
        ValueError, match="phase2a_post_r94_span_recovery_row_boundary_invalid"
    ):
        verifier._load_recovery(malformed_path)

    unknown = _recovery(_checkpoint_row(status="UNKNOWN", candidates=[]))
    unknown_path = tmp_path / "unknown.json"
    unknown_path.write_text(json.dumps(unknown), encoding="utf-8")
    with pytest.raises(
        ValueError, match="phase2a_post_r94_span_recovery_status_invalid"
    ):
        verifier._load_recovery(unknown_path)


def test_recovery_loader_requires_each_planned_identity_candidate(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(verifier, "EXPECTED_ROW_COUNT", 1)
    row = _checkpoint_row(
        status="EXACT_CANDIDATE_CHUNKS_READY_FOR_SPAN_VERIFICATION",
        candidates=[_candidate(1, "chunk-1")],
    )
    material = dict(row)
    material.pop("checkpoint_content_sha256")
    material["planned_authority_ids"] = ["ukpga:2000:2"]
    material["planned_source_identities_in_candidate"] = [
        "ukpga:2000:2:latest-available@2026-08-14"
    ]
    row = {
        **material,
        "checkpoint_content_sha256": verifier._sealed(material),
    }
    artifact = _recovery(row)
    path = tmp_path / "missing-planned-candidate.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")

    with pytest.raises(
        ValueError, match="phase2a_post_r94_span_planned_candidate_coverage_invalid"
    ):
        verifier._load_recovery(path)


def test_post_r94_wrapper_preserves_singleton_runtime_budget_contract() -> None:
    assert verifier.MAX_BATCH_SIZE == 1
    assert verifier.base.BATCH_SIZE == 1
