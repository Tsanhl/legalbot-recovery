from __future__ import annotations

import hashlib

import pytest
from scripts import build_v111_phase2a_post_r94_candidate_recovery as recovery


def _route(chunk_id: str, route: str, rank: int, score: float) -> dict[str, object]:
    return {
        "chunk_id": chunk_id,
        "source_version_id": "source-version-1",
        "source_identity": "ukpga:2000:1:latest-available@2026-08-14",
        "text": "The court may make an order.",
        "content_sha256": hashlib.sha256(b"The court may make an order.").hexdigest(),
        "title": "Example Act",
        "canonical_url": "https://www.legislation.gov.uk/ukpga/2000/1",
        "citation": "Example Act 2000",
        "canonical_citation": "Example Act 2000",
        "locator": "section 1",
        "currentness_status": "latest_available_revised_snapshot",
        "identity_verified": True,
        "currentness_verified": True,
        "legal_role": "unclassified",
        "case_currentness_reviews_json": "[]",
        "case_currentness_manifest_seals_json": "[]",
        "retrieval_eligible": True,
        "source_date": "2000-01-01",
        "as_of_date": "2026-08-14",
        "retrieval_route": route,
        "route_rank": rank,
        "route_score": score,
    }


def test_fusion_rewards_independent_routes_and_preserves_route_evidence() -> None:
    fused = recovery._fuse_candidates(
        [
            [
                _route("chunk-a", "VECTOR_GLOBAL", 1, 0.1),
                _route("chunk-b", "VECTOR_GLOBAL", 2, 0.2),
            ],
            [_route("chunk-b", "FTS_GLOBAL", 1, 9.0)],
        ]
    )

    assert [row["chunk_id"] for row in fused] == ["chunk-b", "chunk-a"]
    assert [item["route"] for item in fused[0]["route_evidence"]] == [
        "VECTOR_GLOBAL",
        "FTS_GLOBAL",
    ]


def test_fusion_rejects_conflicting_chunk_identity() -> None:
    first = _route("chunk-a", "VECTOR_GLOBAL", 1, 0.1)
    second = _route("chunk-a", "FTS_GLOBAL", 1, 9.0)
    second["text"] = "Different bytes"

    with pytest.raises(ValueError, match="phase2a_candidate_recovery_chunk_identity_conflict"):
        recovery._fuse_candidates([[first], [second]])


def test_query_is_deterministic_and_does_not_depend_on_ai_proposition() -> None:
    value = recovery._build_query(
        issue_label="access to courts",
        legal_domain="constitutional and administrative",
        subject="constitutional law",
    )

    assert "access to courts" in value
    assert "constitutional and administrative" in value
    assert "official primary authority" in value
    assert len(value) <= recovery.MAX_QUERY_CHARACTERS

    with pytest.raises(ValueError, match="phase2a_candidate_recovery_query_fields_missing"):
        recovery._build_query(
            issue_label="",
            legal_domain="contract",
            subject="contract",
        )


def test_remaining_rows_are_bound_to_registry_labels_and_domains(monkeypatch) -> None:
    monkeypatch.setattr(recovery, "EXPECTED_ROW_COUNT", 1)
    enriched = recovery._enrich_remaining_rows(
        [{"row_id": "live30-q01:issue-01"}],
        {
            "live30-q01:issue-01": {
                "row_id": "live30-q01:issue-01",
                "case_id": "live30-q01",
                "issue_label": "breach",
                "legal_domain": "contract",
                "triage_class": "CANDIDATE_LOCATOR_OR_GOLD_DEFINITION_REPAIR",
                "planned_authorities": [{"authority_identity_id": "ukpga:2000:1"}],
                "r70_assessment": "MATERIAL_GAP_ADVISORY",
                "technical_qualification_assigned": False,
                "record_content_sha256": "1" * 64,
            }
        },
    )

    assert enriched[0]["issue_label"] == "breach"
    assert enriched[0]["legal_domain"] == "contract"
    assert enriched[0]["registry_planned_authority_ids"] == ["ukpga:2000:1"]
    assert enriched[0]["source_issue_registry_row_content_sha256"] == "1" * 64


def test_candidate_projection_requires_exact_text_hash_and_manifest_binding() -> None:
    text = "The court may make an order."
    raw = {
        **_route("chunk-a", "VECTOR_GLOBAL", 1, 0.1),
        "rrf_score": 0.02,
        "route_evidence": [{"route": "VECTOR_GLOBAL", "rank": 1, "score": 0.1}],
    }
    raw.pop("retrieval_route")
    raw.pop("route_rank")
    raw.pop("route_score")
    manifest = {
        "source-version-1": {
            "authority_identity_id": "ukpga:2000:1",
            "stable_identifier": "ukpga:2000:1:latest-available@2026-08-14",
            "canonical_url": "https://www.legislation.gov.uk/ukpga/2000/1",
            "version_sha256": "1" * 64,
        }
    }

    projected = recovery._candidate_projection(
        raw=raw,
        rank=1,
        score=0.95,
        selection_basis="GLOBAL_RERANK_FILL",
        manifest_sources=manifest,
    )
    assert projected["text"] == text
    assert projected["authority_identity_id"] == "ukpga:2000:1"
    assert projected["source_identity"] == ("ukpga:2000:1:latest-available@2026-08-14")
    assert projected["candidate_manifest_source_bound"] is True
    assert projected["reranker_score"] == 0.95

    raw["content_sha256"] = "0" * 64
    with pytest.raises(
        recovery.CandidateBindingError,
        match="phase2a_candidate_recovery_candidate_binding_invalid",
    ) as caught:
        recovery._candidate_projection(
            raw=raw,
            rank=1,
            score=0.95,
            selection_basis="GLOBAL_RERANK_FILL",
            manifest_sources=manifest,
        )
    assert "CHUNK_TEXT_SHA256_MISMATCH" in caught.value.reasons


def test_candidate_projection_binds_stable_and_authority_identities_separately() -> None:
    raw = _route("chunk-a", "VECTOR_GLOBAL", 1, 0.1)
    raw.update(
        {
            "rrf_score": 0.02,
            "route_evidence": [{"route": "VECTOR_GLOBAL", "rank": 1, "score": 0.1}],
            "source_identity": "ukpga:2000:1:wrong-version",
        }
    )
    for key in ("retrieval_route", "route_rank", "route_score"):
        raw.pop(key)
    manifest = {
        "source-version-1": {
            "authority_identity_id": "ukpga:2000:1",
            "stable_identifier": "ukpga:2000:1:latest-available@2026-08-14",
            "canonical_url": "https://www.legislation.gov.uk/ukpga/2000/1",
            "version_sha256": "1" * 64,
        }
    }

    with pytest.raises(recovery.CandidateBindingError) as caught:
        recovery._candidate_projection(
            raw=raw,
            rank=1,
            score=0.95,
            selection_basis="GLOBAL_RERANK_FILL",
            manifest_sources=manifest,
        )
    assert caught.value.reasons == ("STABLE_IDENTIFIER_MISMATCH",)


def test_route_diverse_selection_keeps_registry_identity_before_global_fill() -> None:
    planned_identity = "ukpga:2000:1:latest-available@2026-08-14"
    global_hit = {
        **_route("global", "VECTOR_GLOBAL", 1, 0.1),
        "rrf_score": 0.03,
        "route_evidence": [{"route": "VECTOR_GLOBAL", "rank": 1, "score": 0.1}],
    }
    planned_hit = {
        **_route("planned", f"VECTOR_REGISTRY_IDENTITY:{planned_identity}", 1, 0.2),
        "rrf_score": 0.02,
        "route_evidence": [
            {
                "route": f"VECTOR_REGISTRY_IDENTITY:{planned_identity}",
                "rank": 1,
                "score": 0.2,
            }
        ],
    }
    for row in (global_hit, planned_hit):
        row.pop("retrieval_route")
        row.pop("route_rank")
        row.pop("route_score")

    selected = recovery._select_route_diverse_candidates(
        [global_hit, planned_hit],
        [0.99, 0.10],
        [planned_identity],
    )

    assert selected[0][0]["chunk_id"] == "planned"
    assert selected[0][2] == "REGISTRY_PLANNED_IDENTITY_DIVERSITY"
    assert selected[1][0]["chunk_id"] == "global"
    assert selected[1][2] == "GLOBAL_RERANK_FILL"


def test_pre_rerank_selection_reserves_registry_identity_candidates() -> None:
    planned_identity = "ukpga:2000:1:latest-available@2026-08-14"
    global_rows = [
        {
            **_route(f"global-{index}", "VECTOR_GLOBAL", index, 0.1),
            "rrf_score": 1.0 / (60 + index),
            "route_evidence": [{"route": "VECTOR_GLOBAL", "rank": index, "score": 0.1}],
        }
        for index in range(1, 14)
    ]
    planned = {
        **_route(
            "planned",
            f"VECTOR_REGISTRY_IDENTITY:{planned_identity}",
            1,
            0.2,
        ),
        "rrf_score": 0.001,
        "route_evidence": [
            {
                "route": f"VECTOR_REGISTRY_IDENTITY:{planned_identity}",
                "rank": 1,
                "score": 0.2,
            }
        ],
    }
    for row in [*global_rows, planned]:
        row.pop("retrieval_route")
        row.pop("route_rank")
        row.pop("route_score")

    selected = recovery._preselect_route_diverse_fused([*global_rows, planned], [planned_identity])

    assert len(selected) == recovery.PRE_RERANK_LIMIT
    assert selected[0]["chunk_id"] == "planned"
