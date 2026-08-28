from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path

import pytest

from app.config import PROJECT_ROOT, Settings
from app.ingestion.models import Jurisdiction, MaterialLane
from app.retrieval.models import IndexedChunk, QueryFilters, SearchHit
from app.retrieval.provision_verification import load_provision_verifications
from app.retrieval.retrieval_v1 import (
    CandidateGoldBindingError,
    FrozenBenchmarkMismatchError,
    _candidate_bound_retrieval_date,
    aggregate_split,
    bind_frozen_rows_to_candidate,
    bind_retrieval_rows_to_candidate,
    load_retrieval_v1_jsonl,
    parse_locators,
    score_query_hits,
    verify_jsonl_sha256,
    verify_owner_freeze,
)
from app.retrieval.service import (
    PHYSICAL_AUTHORITY_LANE,
    _catalogue_row_to_indexed,
    _import_lancedb,
    _LanceLexicalBackend,
    _query_exact_jurisdictions,
    _query_jurisdictions,
)
from app.retrieval.source_manifest import (
    CURRENT_LAW_SLICE_CORPUS_ID,
    HOLDOUT_ONLY_IDENTIFIERS,
    SLICE_CURRENT_IDENTIFIERS,
    SLICE_UKSC_IDENTIFIERS,
    authority_identity_id,
    build_approved_source_manifest,
    chunk_locator_allowed,
    load_pack_identities,
)


def _hit(
    *,
    chunk_id: str,
    source_identity: str,
    locator: str,
    text: str = "passage",
    lane: str = "primary_authority",
    currentness: str = "point_in_time",
    content_sha256: str = "a" * 64,
) -> SearchHit:
    chunk = IndexedChunk(
        chunk_id=chunk_id,
        text=text,
        vector=(0.0,) * 1024,
        jurisdiction=Jurisdiction.ENGLAND_WALES,
        material_lane=MaterialLane.PRIMARY_AUTHORITY,
        subject="contract",
        review_state="approved",
        source_identity=source_identity,
        content_sha256=content_sha256,
        metadata={
            "locator": locator,
            "catalog_lane": lane,
            "currentness_status": currentness,
            "canonical_chunk_sha256": content_sha256,
        },
    )
    return SearchHit(chunk, 1.0, lexical_rank=1, vector_rank=1)


def test_repository_retrieval_v1_has_a_valid_owner_freeze() -> None:
    freeze = verify_owner_freeze(
        PROJECT_ROOT, PROJECT_ROOT / "benchmarks" / "retrieval" / "v1.1.jsonl"
    )
    assert freeze["status"] == "owner_frozen"
    assert freeze["row_count"] == 24


def test_readme_describes_frozen_v1_1_and_separate_live30_suite() -> None:
    text = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    assert "24-row development-and-promotion pack is\nowner-frozen" in text
    assert "24-row pack is intentionally an owner-review draft" not in text
    assert "legacy 240-case draft suite" in text
    assert "`live-evaluation-30-v1` package remains immutable historical audit material" in text
    assert "current controlled contract is the separate `live-evaluation-60-v1`" in text


def test_repository_provision_registry_is_exact_and_ew_qualified() -> None:
    records, digest = load_provision_verifications(PROJECT_ROOT)
    assert len(records) == 14
    assert len(digest) == 64
    assert (
        records[("ukpga:1977:50:latest-available@2026-08-14", "section 2")][
            "section_unapplied_effect_count"
        ]
        == 0
    )
    assert not any("ukpga:1980:58:" in source_id for source_id, _ in records)
    assert not any("ukpga:2000:29:" in source_id for source_id, _ in records)
    assert not any("ukpga:1975:63:" in source_id for source_id, _ in records)
    assert all("E+W" in record["verified_extent"] for record in records.values())


def test_only_exact_verified_provision_receives_extent_qualification() -> None:
    source = "ukpga:1977:50:latest-available@2026-08-14"
    records, _ = load_provision_verifications(PROJECT_ROOT)
    source_digest = str(records[(source, "section 2")]["source_content_sha256"])

    def row(locator: str) -> dict[str, object]:
        text = "A prompt-safe statutory provision."
        return {
            "source_metadata_json": json.dumps(
                {
                    "identity_verified": True,
                    "currentness_verified": True,
                    "official_snapshot": {"unapplied_effect_count": 99},
                    "citation_data": {"source_type": "legislation"},
                }
            ),
            "chunk_metadata_json": "{}",
            "lane": "primary_authority",
            "jurisdiction": "United Kingdom",
            "markdown_text": text,
            "currentness_status": "latest_available_revised_snapshot",
            "stable_identifier": source,
            "source_identity_id": "ukpga:1977:50",
            "chunk_id": f"chunk-{locator}",
            "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "document_sha256": source_digest,
            "source_version_id": "source-version",
            "version_sha256": source_digest,
            "representation_group_id": "representation",
            "retrieval_canonical": 1,
            "locator": locator,
            "stream": "body",
            "subject_primary": "professional negligence",
            "title": "Unfair Contract Terms Act 1977",
            "canonical_url": "https://www.legislation.gov.uk/ukpga/1977/50",
            "source_date": "1977-10-26",
            "as_of_date": "2026-08-14",
            "heading_path": "[]",
        }

    verified = _catalogue_row_to_indexed(
        row("section 2"), (0.0,) * 1024, provision_verifications=records
    )
    unverified = _catalogue_row_to_indexed(
        row("section 4"), (0.0,) * 1024, provision_verifications=records
    )
    wrong_bytes = row("section 2")
    wrong_bytes["document_sha256"] = "f" * 64
    wrong_bytes["version_sha256"] = "f" * 64
    mismatched = _catalogue_row_to_indexed(
        wrong_bytes, (0.0,) * 1024, provision_verifications=records
    )
    assert verified.metadata["provision_extent_status"] == "england_and_wales_verified"
    assert verified.metadata["unapplied_effect_count"] == 0
    assert unverified.metadata["provision_extent_status"] == "unverified"
    assert unverified.metadata["unapplied_effect_count"] == 99
    assert mismatched.metadata["provision_extent_status"] == "unverified"
    assert mismatched.metadata["unapplied_effect_count"] == 99


def test_frozen_jsonl_mismatch_stops(tmp_path: Path) -> None:
    path = tmp_path / "v1.jsonl"
    path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(FrozenBenchmarkMismatchError):
        verify_jsonl_sha256(path, "0" * 64)


def _binding_fixture() -> tuple[
    dict[str, object], dict[str, object], list[dict[str, str]], dict[str, object]
]:
    frozen = {
        "id": "dev-ucta-s2",
        "source_type": "legislation",
        "expected_authority_id": "ukpga:1977:50",
        "expected_source_id": "ukpga:1977:50:latest-available@2026-08-12",
        "expected_source_version_id": "source-version-old",
        "legal_locator": "section 2",
        "proposition_span_sha256": "a" * 64,
        "gold_spans": [
            {
                "span_sha256": "a" * 64,
                "legal_locator": "section 2",
                "proposition": "section 2(1)",
            }
        ],
        "match_mode": "source_and_span",
    }
    manifest = {
        "schema": "legalbot.approved-source-manifest.v1",
        "authority_lane_only": True,
        "benchmark_answers_used_for_selection": False,
        "current_law_as_of_date": "2026-08-14",
        "sources": [
            {
                "authority_identity_id": "ukpga:1977:50",
                "stable_identifier": "ukpga:1977:50:latest-available@2026-08-14",
                "source_version_id": "source-version-new",
                "content_sha256": "b" * 64,
                "version_sha256": "b" * 64,
            }
        ],
    }
    chunks = [
        {
            "source_identity": "ukpga:1977:50:latest-available@2026-08-14",
            "source_version_id": "source-version-new",
            "locator": "section 2",
            "content_sha256": "a" * 64,
        }
    ]
    provisions = {
        "schema": "legalbot.provision-verification.v1",
        "records": [
            {
                "stable_source_id": "ukpga:1977:50:latest-available@2026-08-14",
                "legal_locator": "section 2",
                "source_content_sha256": "b" * 64,
                "source_version_sha256": "b" * 64,
                "verified_extent": "E+W+S+N.I.",
            }
        ],
    }
    return frozen, manifest, chunks, provisions


def _bind_fixture(
    frozen: dict[str, object],
    manifest: dict[str, object],
    chunks: list[dict[str, str]],
    provisions: dict[str, object],
) -> tuple[list[dict[str, object]], dict[str, object]]:
    return bind_frozen_rows_to_candidate(
        [frozen],
        build_id="candidate-20260814",
        benchmark_sha256="c" * 64,
        candidate_manifest=manifest,
        candidate_manifest_sha256="d" * 64,
        candidate_chunks=chunks,
        provision_registry=provisions,
        provision_registry_sha256="e" * 64,
    )


def test_candidate_binding_rolls_version_without_mutating_frozen_gold() -> None:
    frozen, manifest, chunks, provisions = _binding_fixture()
    original = json.loads(json.dumps(frozen))

    bound, report = _bind_fixture(frozen, manifest, chunks, provisions)

    assert frozen == original
    assert bound[0]["expected_source_id"] == ("ukpga:1977:50:latest-available@2026-08-14")
    assert bound[0]["expected_source_version_id"] == "source-version-new"
    assert bound[0]["frozen_expected_source_id"] == ("ukpga:1977:50:latest-available@2026-08-12")
    assert report["status"] == "bound"
    assert report["frozen_benchmark_mutated"] is False


def test_candidate_binding_fails_closed_when_exact_gold_span_changed() -> None:
    frozen, manifest, chunks, provisions = _binding_fixture()
    chunks[0]["content_sha256"] = "f" * 64

    with pytest.raises(CandidateGoldBindingError) as caught:
        _bind_fixture(frozen, manifest, chunks, provisions)

    assert caught.value.report["status"] == "blocked"
    assert {issue["code"] for issue in caught.value.report["issues"]} == {
        "frozen_gold_span_missing_in_candidate"
    }


def test_candidate_binding_fails_closed_without_exact_provision_review() -> None:
    frozen, manifest, chunks, provisions = _binding_fixture()
    provisions["records"] = []

    with pytest.raises(CandidateGoldBindingError) as caught:
        _bind_fixture(frozen, manifest, chunks, provisions)

    assert {issue["code"] for issue in caught.value.report["issues"]} == {
        "candidate_provision_not_qualified"
    }


def test_candidate_binding_accepts_exact_span_at_deterministic_subsection_locator() -> None:
    frozen, manifest, chunks, provisions = _binding_fixture()
    chunks[0]["locator"] = "s 2(1) chapeau"

    bound, report = _bind_fixture(frozen, manifest, chunks, provisions)

    assert len(bound) == 1
    assert report["status"] == "bound"


@pytest.mark.parametrize("wrong_locator", ["section 20", "s 2A(1)", "paragraph 2"])
def test_candidate_binding_rejects_same_span_at_wrong_provision_alias(
    wrong_locator: str,
) -> None:
    frozen, manifest, chunks, provisions = _binding_fixture()
    chunks[0]["locator"] = wrong_locator

    with pytest.raises(CandidateGoldBindingError) as caught:
        _bind_fixture(frozen, manifest, chunks, provisions)

    assert "frozen_gold_span_missing_in_candidate" in {
        issue["code"] for issue in caught.value.report["issues"]
    }


def test_candidate_binding_rejects_same_span_from_wrong_source_version() -> None:
    frozen, manifest, chunks, provisions = _binding_fixture()
    chunks[0]["source_version_id"] = "source-version-wrong"
    chunks.append(
        {
            "source_identity": chunks[0]["source_identity"],
            "source_version_id": "source-version-new",
            "locator": "s 2(1)",
            "content_sha256": "f" * 64,
        }
    )

    with pytest.raises(CandidateGoldBindingError) as caught:
        _bind_fixture(frozen, manifest, chunks, provisions)

    assert "frozen_gold_span_missing_in_candidate" in {
        issue["code"] for issue in caught.value.report["issues"]
    }


def test_repository_candidate_successor_binds_all_frozen_cases_without_search() -> None:
    benchmark = PROJECT_ROOT / "benchmarks" / "retrieval" / "v1.1.jsonl"
    freeze = verify_owner_freeze(PROJECT_ROOT, benchmark)
    rows = load_retrieval_v1_jsonl(benchmark, str(freeze["jsonl_sha256"]))
    build_id = "current-law-ew-full-fp16-v111-20260818-a"
    build_path = PROJECT_ROOT / "data" / "indexes" / "builds" / build_id
    qualification_path = (
        PROJECT_ROOT
        / "config/archive/provision-verification/"
        "candidate-provision-qualification-current-law-ew-full-fp16-v111-20260818-a.v1.json"
    )

    bound, report = bind_retrieval_rows_to_candidate(
        build_path,
        rows,
        build_id=build_id,
        benchmark_sha256=str(freeze["jsonl_sha256"]),
        project_root=PROJECT_ROOT,
        qualification_path=qualification_path,
    )

    assert len(bound) == 24
    assert report["row_count"] == 24
    assert report["status"] == "bound"
    assert report["issues"] == []
    assert len(str(report["candidate_qualification_successor_sha256"])) == 64
    assert _candidate_bound_retrieval_date(report, bound).isoformat() == "2026-08-14"


def test_candidate_bound_date_keeps_rebound_legislation_in_candidate_pool() -> None:
    benchmark = PROJECT_ROOT / "benchmarks" / "retrieval" / "v1.1.jsonl"
    freeze = verify_owner_freeze(PROJECT_ROOT, benchmark)
    rows = load_retrieval_v1_jsonl(benchmark, str(freeze["jsonl_sha256"]))
    build_id = "current-law-ew-full-fp16-v111-20260818-a"
    build_path = PROJECT_ROOT / "data" / "indexes" / "builds" / build_id
    qualification_path = (
        PROJECT_ROOT
        / "config/archive/provision-verification/"
        "candidate-provision-qualification-current-law-ew-full-fp16-v111-20260818-a.v1.json"
    )
    bound, report = bind_retrieval_rows_to_candidate(
        build_path,
        rows,
        build_id=build_id,
        benchmark_sha256=str(freeze["jsonl_sha256"]),
        project_root=PROJECT_ROOT,
        qualification_path=qualification_path,
    )
    row = next(value for value in bound if value["id"] == "dev-ucta-s2")
    filters = QueryFilters(
        jurisdictions=frozenset(_query_jurisdictions(str(row["jurisdiction"]))),
        material_lanes=frozenset({MaterialLane.PRIMARY_AUTHORITY}),
        exact_jurisdictions=frozenset(_query_exact_jurisdictions(str(row["jurisdiction"]))),
        subjects=frozenset(),
        review_states=frozenset({"approved"}),
    )
    table = (
        _import_lancedb()
        .connect(str(build_path / "lance" / PHYSICAL_AUTHORITY_LANE))
        .open_table("chunks")
    )
    frozen_date = date.fromisoformat(str(row["as_of_date"]))
    candidate_date = _candidate_bound_retrieval_date(report, bound)

    excluded = _LanceLexicalBackend(table, frozen_date).search(
        str(row["query"]), filters=filters, limit=20
    )
    admitted = _LanceLexicalBackend(table, candidate_date).search(
        str(row["query"]), filters=filters, limit=20
    )

    assert candidate_date > frozen_date
    assert all(hit.chunk.source_identity != row["expected_source_id"] for hit in excluded)
    assert any(hit.chunk.source_identity == row["expected_source_id"] for hit in admitted)


def test_candidate_retrieval_date_rejects_unbound_legislation_snapshot() -> None:
    rows = [
        {
            "id": "synthetic-statute",
            "source_type": "legislation",
            "expected_source_id": "ukpga:2031:1:latest-available@2031-02-03",
            "expected_source_version_id": "source-version-current",
        }
    ]
    report = {
        "candidate_current_law_as_of_date": "2031-02-03",
        "bindings": [
            {
                "case_id": "synthetic-statute",
                "status": "bound",
                "candidate_as_of_date": "2031-02-02",
                "candidate_source_id": "ukpga:2031:1:latest-available@2031-02-03",
                "candidate_selected_source_version_id": "source-version-current",
            }
        ],
    }

    with pytest.raises(RuntimeError, match="not bound to one candidate snapshot"):
        _candidate_bound_retrieval_date(report, rows)


def test_candidate_retrieval_date_does_not_depend_on_case_gold() -> None:
    rows = [
        {
            "id": "arbitrary-future-statute",
            "source_type": "legislation",
            "expected_source_id": "uksi:2032:44:latest-available@2032-06-01",
            "expected_source_version_id": "source-version-arbitrary",
        },
        {
            "id": "arbitrary-case",
            "source_type": "case",
            "expected_source_id": "neutral-citation:[2032] UKSC 4",
            "expected_source_version_id": "source-version-case",
        },
    ]
    report = {
        "candidate_current_law_as_of_date": "2032-06-01",
        "bindings": [
            {
                "case_id": "arbitrary-future-statute",
                "status": "bound",
                "candidate_as_of_date": "2032-06-01",
                "candidate_source_id": "uksi:2032:44:latest-available@2032-06-01",
                "candidate_selected_source_version_id": "source-version-arbitrary",
            }
        ],
    }

    assert _candidate_bound_retrieval_date(report, rows).isoformat() == "2032-06-01"


def test_identity_only_case_requires_the_frozen_immutable_source_version() -> None:
    frozen = {
        "id": "dev-triple-point-identity",
        "source_type": "case",
        "expected_authority_id": "neutral-citation:[2021] UKSC 29",
        "expected_source_id": "neutral-citation:[2021] UKSC 29",
        "expected_source_version_id": "source-version-case",
        "legal_locator": None,
        "gold_spans": [],
        "match_mode": "source_identity_only",
    }
    manifest = {
        "schema": "legalbot.approved-source-manifest.v1",
        "authority_lane_only": True,
        "benchmark_answers_used_for_selection": False,
        "current_law_as_of_date": "2026-08-14",
        "sources": [
            {
                "authority_identity_id": "neutral-citation:[2021] UKSC 29",
                "stable_identifier": "neutral-citation:[2021] UKSC 29",
                "source_version_id": "source-version-different",
                "content_sha256": "b" * 64,
                "version_sha256": "b" * 64,
            }
        ],
    }
    chunks = [
        {
            "source_identity": "neutral-citation:[2021] UKSC 29",
            "source_version_id": "source-version-different",
            "locator": "p 1",
            "content_sha256": "a" * 64,
        }
    ]

    with pytest.raises(CandidateGoldBindingError) as caught:
        _bind_fixture(frozen, manifest, chunks, {"records": []})

    assert {issue["code"] for issue in caught.value.report["issues"]} == {
        "immutable_case_source_version_missing"
    }


def test_identity_only_match_does_not_count() -> None:
    row = {
        "id": "dev-case-name-triple-point",
        "family": "case_name",
        "polarity": "positive",
        "source_type": "case",
        "expected_source_id": "neutral-citation:[2021] UKSC 29",
        "legal_locator": "p 17; p 18",
        "match_mode": "source_and_locator",
        "forbidden_lanes": ["private_teaching", "assessment_guidance"],
    }
    identity_only = [
        _hit(
            chunk_id="wrong-page",
            source_identity="neutral-citation:[2021] UKSC 29",
            locator="p 4",
            currentness="historical",
        )
    ]
    scored = score_query_hits(row, identity_only)
    assert scored["hit@3"] is False
    assert scored["hit@10"] is False
    assert scored["identity_only_ranks"] == [1]
    gold = [
        _hit(
            chunk_id="p17",
            source_identity="neutral-citation:[2021] UKSC 29",
            locator="p 17",
            currentness="historical",
        )
    ]
    scored_gold = score_query_hits(row, gold)
    assert scored_gold["hit@3"] is True
    assert scored_gold["gold_rank"] == 1
    assert scored_gold["top_hit_diagnostics"] == [
        {
            "chunk_id": "p17",
            "fused_score": 1.0,
            "lexical_rank": 1,
            "vector_rank": 1,
            "reranker_score": None,
        }
    ]


def test_source_and_span_requires_exact_hash() -> None:
    row = {
        "id": "dev-multi-ca2006-directors",
        "source_type": "legislation",
        "expected_source_id": "ukpga:2006:46:latest-available@2026-08-12",
        "legal_locator": "section 172",
        "proposition_span_sha256": "a" * 64,
        "match_mode": "source_and_span",
        "forbidden_lanes": [],
    }
    only_172 = [
        _hit(
            chunk_id="s172",
            source_identity="ukpga:2006:46:latest-available@2026-08-12",
            locator="section 172",
        )
    ]
    scored = score_query_hits(row, only_172)
    assert scored["hit@3"] is True
    wrong_hash = [
        _hit(
            chunk_id="s172-wrong",
            source_identity="ukpga:2006:46:latest-available@2026-08-12",
            locator="section 172",
            text="different",
            content_sha256="b" * 64,
        ),
    ]
    scored_wrong = score_query_hits(row, wrong_hash)
    assert scored_wrong["hit@3"] is False


def test_legislation_scoring_uses_strict_provision_family_not_text_aliases() -> None:
    source = "ukpga:1980:58:latest-available@2026-08-14"
    row = {
        "id": "synthetic-section-family",
        "source_type": "legislation",
        "expected_source_id": source,
        "legal_locator": "section 14A",
        "proposition_span_sha256": "a" * 64,
        "gold_spans": [
            {
                "span_sha256": "a" * 64,
                "legal_locator": "section 14A",
                "proposition": "subsection proposition",
            }
        ],
        "match_mode": "source_and_span",
        "forbidden_lanes": [],
    }
    correct = _hit(
        chunk_id="correct-subsection",
        source_identity=source,
        locator="s 14A(4)(a) chapeau",
    )
    wrong = _hit(
        chunk_id="wrong-section",
        source_identity=source,
        locator="section 14",
    )

    assert score_query_hits(row, [correct])["hit@3"] is True
    assert score_query_hits(row, [wrong])["hit@3"] is False


def test_source_and_locator_reports_exact_gold_bundle_recall() -> None:
    source = "ukpga:1977:50:latest-available@2026-08-12"
    row = {
        "id": "dev-ucta-s3",
        "source_type": "legislation",
        "expected_source_id": source,
        "legal_locator": "section 3",
        "proposition_span_sha256": None,
        "gold_spans": [
            {
                "span_sha256": "a" * 64,
                "legal_locator": "section 3",
                "proposition": "trigger",
            },
            {
                "span_sha256": "b" * 64,
                "legal_locator": "section 3",
                "proposition": "control",
            },
        ],
        "match_mode": "source_and_locator",
        "forbidden_lanes": [],
    }
    hits = [
        _hit(
            chunk_id="trigger",
            source_identity=source,
            locator="section 3",
            content_sha256="a" * 64,
        ),
        _hit(
            chunk_id="noise",
            source_identity=source,
            locator="section 3",
            content_sha256="c" * 64,
        ),
    ]
    scored = score_query_hits(row, hits)
    assert scored["hit@3"] is True
    assert scored["gold_span_count"] == 2
    assert scored["exact_span_recall_at_10"] == 0.5


def test_as_enacted_is_wrong_version_against_current_gold() -> None:
    row = {
        "id": "dev-exact-statute-ucta-s2",
        "family": "exact_statute",
        "polarity": "positive",
        "source_type": "legislation",
        "expected_source_id": "ukpga:1977:50:latest-available@2026-08-12",
        "corpus_locator": "section 2",
        "legal_locator": "section 2",
        "forbidden_lanes": [],
    }
    hits = [
        _hit(
            chunk_id="enacted",
            source_identity="ukpga:1977:50:enacted",
            locator="section 2",
            currentness="historical",
        ),
        _hit(
            chunk_id="current",
            source_identity="ukpga:1977:50:latest-available@2026-08-12",
            locator="section 2",
            currentness="point_in_time",
        ),
    ]
    scored = score_query_hits(row, hits)
    assert scored["wrong_version"] is True
    assert scored["current_outranks_as_enacted"] is False
    assert scored["hit@3"] is True


def test_teaching_lane_is_forbidden() -> None:
    row = {
        "id": "dev-teaching-not-authority",
        "family": "teaching_not_authority",
        "polarity": "negative",
        "source_type": None,
        "expected_source_id": None,
        "corpus_locator": None,
        "forbidden_lanes": ["private_teaching", "assessment_guidance"],
    }
    hits = [
        _hit(
            chunk_id="handout",
            source_identity="private-handout",
            locator="p 1",
            lane="private_teaching",
        )
    ]
    scored = score_query_hits(row, hits)
    assert scored["forbidden_lane"] is True
    assert scored["teaching_assessment_hits"] == 1


def test_aggregate_gates_require_primary_recall_at_5_and_mrr() -> None:
    positives = []
    for ident, family, hit in (
        ("a", "exact_statute", True),
        ("b", "case_name", False),
        ("c", "faithful_paraphrase", True),
    ):
        positives.append(
            {
                "id": ident,
                "family": family,
                "polarity": "positive",
                "hit@3": hit,
                "hit@5": hit,
                "hit@10": hit,
                "reciprocal_rank": 1.0 if hit else 0.0,
                "primary_must_hit": family in {"exact_statute", "case_name"},
                "wrong_version": False,
                "forbidden_lane": False,
                "teaching_assessment_hits": 0,
                "private_path_hits": 0,
                "current_outranks_as_enacted": True,
            }
        )
    summary = aggregate_split(positives)
    assert summary["primary_must_hit_recall_at_5"] == 0.5
    assert summary["go"] is False


def test_split_gate_cannot_be_hidden_by_combined_average() -> None:
    def result(split: str, ident: str, hit: bool) -> dict[str, object]:
        return {
            "id": ident,
            "split": split,
            "hit@3": hit,
            "hit@5": hit,
            "hit@10": hit,
            "reciprocal_rank": 1.0 if hit else 0.0,
            "primary_must_hit": True,
            "wrong_version": False,
            "forbidden_lane": False,
            "teaching_assessment_hits": 0,
            "private_path_hits": 0,
        }

    development = [result("development", f"dev-{index}", True) for index in range(16)]
    promotion = [result("promotion", "prom-miss", False)] + [
        result("promotion", f"prom-{index}", True) for index in range(7)
    ]
    assert aggregate_split(development)["go"] is True
    assert aggregate_split(promotion)["go"] is False
    # The aggregate is reported for diagnostics, but the runtime report now
    # requires both per-split summaries to pass independently.
    assert aggregate_split(development + promotion)["positive_recall_at_10"] > 0.95


def test_parse_locators() -> None:
    assert parse_locators("p 17; p 18") == ("p 17", "p 18")
    assert parse_locators(None) == ()


def test_slice_has_no_benchmark_shaped_locator_allowlist() -> None:
    ident = "ukpga:2006:46:latest-available@2026-08-12"
    assert chunk_locator_allowed(ident, "section 172") is True
    assert chunk_locator_allowed(ident, "section 172(1)") is True
    assert chunk_locator_allowed(ident, "section 1") is True
    assert chunk_locator_allowed("ukpga:1977:50:latest-available@2026-08-12", "section 2") is True
    assert chunk_locator_allowed("ukpga:1977:50:latest-available@2026-08-12", "section 99") is True
    assert chunk_locator_allowed("ukpga:2015:15:latest-available@2026-08-12", "section 9") is True
    assert chunk_locator_allowed("ukpga:2015:15:latest-available@2026-08-12", "section 62") is True


def _write_packs(project: Path, *, as_of_date: str = "2026-08-12") -> None:
    (project / "config").mkdir(parents=True)
    (project / "config" / "official_legislation_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.official-legislation-pack.v1",
                "version": "test",
                "licence": {"name": "Open Government Licence", "version": "3.0", "url": "x"},
                "items": [{"identity": "ukpga/1977/50", "title": "UCTA"}],
            }
        ),
        encoding="utf-8",
    )
    (project / "config" / "current_legislation_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.current-legislation-pack.v1",
                "version": "test-current",
                "as_of_date": as_of_date,
                "items": [
                    {"identity": "ukpga/1977/50", "title": "UCTA"},
                    {"identity": "ukpga/2010/15", "title": "EQA"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (project / "config" / "uksc_authority_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.uksc-authority-pack.v1",
                "version": "test",
                "licence": {"name": "Open Government Licence", "version": "3.0"},
                "items": [
                    {"neutral_citation": "[2021] UKSC 29", "case_name": "Triple Point"},
                    {"neutral_citation": "[2015] UKSC 67", "case_name": "Cavendish"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (project / "config" / "current_law_slice_policy.yaml").write_text(
        """schema: legalbot.current-law-slice-policy.v1
version: test
corpus_id: current-law-ew-core-slice-v1
jurisdiction: England and Wales
subjects: [contract]
source_families: [legislation, uksc]
approved_only: true
authority_lane_only: true
latest_available_legislation_only: true
include_historical_as_enacted: false
exclude_find_case_law_full_text: true
max_source_body_chunks: 1000
locator_allowlists: false
benchmark_case_ids_used_for_selection: false
""",
        encoding="utf-8",
    )


def test_pack_identities_use_the_configured_current_snapshot_date(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_packs(project, as_of_date="2027-02-03")

    packs = load_pack_identities(Settings(project_root=project, test_mode=True))

    assert packs["current_law_as_of_date"] == "2027-02-03"
    assert packs["legislation_stable_ids"] == [
        "ukpga:1977:50:latest-available@2027-02-03",
        "ukpga:2010:15:latest-available@2027-02-03",
    ]
    assert packs["test_fixture_pack_fallback"] is False


def test_pack_identities_reject_an_invalid_current_snapshot_date(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_packs(project, as_of_date="2027-02-30")

    with pytest.raises(ValueError, match="not a valid date"):
        load_pack_identities(Settings(project_root=project, test_mode=True))


def test_authority_identity_strips_any_valid_snapshot_date_and_enacted() -> None:
    assert authority_identity_id("ukpga:1977:50:latest-available@2027-02-03") == "ukpga:1977:50"
    assert authority_identity_id("ukpga:1977:50:enacted") == "ukpga:1977:50"
    assert (
        authority_identity_id("ukpga:1977:50:latest-available@2027-02-30")
        == "ukpga:1977:50:latest-available@2027-02-30"
    )


def test_missing_current_pack_uses_enacted_only_in_test_mode(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _write_packs(project)
    (project / "config" / "current_legislation_pack.json").unlink()

    packs = load_pack_identities(Settings(project_root=project, test_mode=True))
    assert packs["legislation_stable_ids"] == ["ukpga:1977:50:enacted"]
    assert packs["test_fixture_pack_fallback"] is True

    with pytest.raises(ValueError, match="required for serving builds"):
        load_pack_identities(Settings(project_root=project, test_mode=False))


def _seed_source(
    database,
    *,
    doc_id: str,
    sv_id: str,
    ident: str,
    title: str,
    currentness: str,
    locators: tuple[str, ...],
    markdown: Path,
    eligible_for_model_use: bool = True,
) -> None:
    now = "2026-08-12T00:00:00+00:00"
    markdown.parent.mkdir(parents=True, exist_ok=True)
    markdown.write_text(f"# {title}\n", encoding="utf-8")
    digest = hashlib.sha256(doc_id.encode()).hexdigest()
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, lane, subject_primary, jurisdiction, retrieval_canonical,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'application/xml',
                  'citable', 'primary_authority', 'contract', 'England and Wales', 1, ?, ?)
        """,
        (doc_id, digest, ident.split(":")[0], f"source-{doc_id}.xml", now, now),
    )
    database.execute(
        """
        INSERT INTO source_versions(
          id, document_id, version_sha256, canonical_markdown_path, title,
          stable_identifier, currentness_status, licence_name, review_status,
          metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'Open Government Licence v3.0',
                  'approved', ?, ?)
        """,
        (
            sv_id,
            doc_id,
            digest,
            str(markdown),
            title,
            ident,
            currentness,
            json.dumps(
                {
                    "identity_verified": True,
                    "currentness_verified": not ident.startswith("neutral-citation:"),
                    "citation_data": {
                        "source_type": (
                            "case" if ident.startswith("neutral-citation:") else "legislation"
                        )
                    },
                    "eligible_for_model_use": eligible_for_model_use,
                    "ai_use_policy": (
                        "unreviewed"
                        if eligible_for_model_use
                        else "metadata_only_pending_rights_review"
                    ),
                }
            ),
            now,
        ),
    )
    for index, locator in enumerate(locators):
        database.execute(
            """
            INSERT INTO chunks(
              id, source_version_id, ordinal, locator, text_sha256, markdown_text, token_count, stream
            ) VALUES (?, ?, ?, ?, ?, ?, 8, 'body')
            """,
            (
                f"{sv_id}-chunk-{index}",
                sv_id,
                index,
                locator,
                "c" * 64,
                f"{title} {locator}",
            ),
        )


def test_current_law_slice_is_source_policy_selected_not_benchmark_selected(
    database, tmp_path: Path
) -> None:
    project = tmp_path / "project"
    _write_packs(project)
    vault = project / "data" / "vault"
    _seed_source(
        database,
        doc_id="doc-ucta",
        sv_id="sv-ucta",
        ident="ukpga:1977:50:latest-available@2026-08-12",
        title="UCTA 1977",
        currentness="point_in_time",
        locators=("section 2",),
        markdown=vault / "ucta.md",
    )
    _seed_source(
        database,
        doc_id="doc-eqa",
        sv_id="sv-eqa",
        ident="ukpga:2010:15:latest-available@2026-08-12",
        title="EQA 2010",
        currentness="point_in_time",
        locators=("section 13",),
        markdown=vault / "eqa.md",
    )
    _seed_source(
        database,
        doc_id="doc-tp",
        sv_id="sv-tp",
        ident="neutral-citation:[2021] UKSC 29",
        title="Triple Point",
        currentness="historical",
        locators=("p 17", "p 18"),
        markdown=vault / "tp.md",
    )
    _seed_source(
        database,
        doc_id="doc-cav",
        sv_id="sv-cav",
        ident="neutral-citation:[2015] UKSC 67",
        title="Cavendish",
        currentness="historical",
        locators=("p 18",),
        markdown=vault / "cav.md",
    )
    settings = Settings(project_root=project, test_mode=True)
    manifest = build_approved_source_manifest(
        database, settings, corpus_id=CURRENT_LAW_SLICE_CORPUS_ID
    )
    idents = {item["stable_identifier"] for item in manifest["sources"]}
    assert "ukpga:1977:50:latest-available@2026-08-12" in idents
    assert "neutral-citation:[2021] UKSC 29" in idents
    assert "ukpga:2010:15:latest-available@2026-08-12" in idents
    assert "neutral-citation:[2015] UKSC 67" in idents
    assert frozenset() == HOLDOUT_ONLY_IDENTIFIERS
    assert SLICE_CURRENT_IDENTIFIERS == ()
    assert SLICE_UKSC_IDENTIFIERS == ()
    assert manifest["exclude_find_case_law_full_text"] is True
    assert manifest["historical_default_excluded"] is True
    assert manifest["selection_policy"] == "subject-policy-current-law-slice"
    assert manifest["benchmark_answers_used_for_selection"] is False
    assert manifest["locator_allowlists"] == {}


def test_source_manifest_excludes_identity_approved_rights_pending_full_text(
    database, tmp_path: Path
) -> None:
    project = tmp_path / "project"
    _write_packs(project)
    _seed_source(
        database,
        doc_id="doc-rights-held-tp",
        sv_id="sv-rights-held-tp",
        ident="neutral-citation:[2021] UKSC 29",
        title="Triple Point",
        currentness="historical",
        locators=("p 17",),
        markdown=project / "data/vault/held.md",
        eligible_for_model_use=False,
    )

    manifest = build_approved_source_manifest(
        database,
        Settings(project_root=project, test_mode=True),
        corpus_id=CURRENT_LAW_SLICE_CORPUS_ID,
    )

    assert manifest["sources"] == []
    assert manifest["source_count"] == 0
