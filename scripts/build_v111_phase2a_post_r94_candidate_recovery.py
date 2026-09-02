#!/usr/bin/env python3
"""Search the exact sealed predecessor for the post-r94 Phase-2A rows.

This create-only advisory pass combines the pinned Qwen embedding model, the
sealed Lance FTS/vector indexes and the independently pinned Qwen reranker.  It
does not apply a relevance threshold or treat a score as qualification.  Every
selected chunk is re-bound to the exact 85-source candidate manifest and its
authoritative bytes are preserved for a later exact-span verifier.

No source is admitted, no candidate is mutated, and no gate is authorized.
Rows with no candidate hit remain explicit research gaps; there is no fallback
to another index, an unreranked result, network answering or model knowledge.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
for root in (PROJECT_ROOT, BACKEND_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from app.retrieval.ge_generic_read_guard import (  # noqa: E402
    require_generic_index_read_allowed,
)
from app.retrieval.source_manifest import approved_source_manifest_sha256  # noqa: E402
from scripts import run_v111_phase2a_independent_reranker_advisory as reranker  # noqa: E402

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
DEFAULT_REMAINING = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r96-approved-binding-reconciliation"
    / "REMAINING-PHASE2A-RESEARCH-ROWS-361.json"
)
DEFAULT_CASES = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1/cases.jsonl"
DEFAULT_ISSUE_REGISTRY = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r71-gap-triage" / "ISSUE-GAP-TRIAGE-448.json"
)
DEFAULT_BUILD_ROOT = PROJECT_ROOT / "data/indexes/builds/current-law-ew-full-fp16-v111-20260818-a"
DEFAULT_CANDIDATE_MANIFEST = DEFAULT_BUILD_ROOT / "approved-source-manifest.json"
DEFAULT_OUTPUT_ROOT = REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r98d-candidate-recovery"
DEFAULT_EMBEDDING_MODEL = PROJECT_ROOT / "models/retrieval/Qwen3-Embedding-0.6B"
DEFAULT_RERANKER_MODEL = PROJECT_ROOT / "models/retrieval/Qwen3-Reranker-0.6B"

EXPECTED_REMAINING_DIGEST = "213d809d3dd9ee26b2a7e516a856d86efbd28bd2b607ad1cee03046b6dfac63e"
EXPECTED_ISSUE_REGISTRY_DIGEST = "d813a1fdc1b9b6f2d6c67b0ac2c113af696343cc8c619355c74ee8654beca475"
EXPECTED_R96_PACKAGE_DIGEST = "967f8993e4f06f98f5099c8b0f360eeeef839716d7d7838d84348b472f84978b"
EXPECTED_CASES_FILE_SHA256 = "78a738afd920ff840dcedeb0fd3fd5ca81035f499a0630d351d49e7c6cd3777a"
EXPECTED_CANDIDATE_MANIFEST_DIGEST = (
    "d2c1434fd5fc44d4f2f7e4f7629293f646bb28ed9b8466687feb6c470ea53ac0"
)
EXPECTED_BUILD_MANIFEST_FILE_SHA256 = (
    "e28a4138e87cfeb2502e746073208ab25a647de8082a3c7fe96a44ed7d5cc74a"
)
EXPECTED_LANCE_TREE_SHA256 = "992f7c11184afc7667abedc6dca07a0b690bbcb34b0c9071cb7f5faa4d12e705"
EXPECTED_ROW_COUNT = 361
EXPECTED_ISSUE_REGISTRY_ROW_COUNT = 448
EXPECTED_SOURCE_COUNT = 85
EXPECTED_CHUNK_COUNT = 149_855
PRE_RERANK_LIMIT = 12
PRE_RERANK_IDENTITY_LIMIT = 2
FINAL_CANDIDATE_LIMIT = 6
VECTOR_LIMIT = 24
FTS_LIMIT = 24
IDENTITY_LIMIT = 6
RRF_K = 60
MAX_QUERY_CHARACTERS = 1_200
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"[a-z0-9]+(?:['’-][a-z0-9]+)?", re.IGNORECASE)
_ROW_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}:issue-[0-9]{2}$")
_SAFE_FILENAME = re.compile(r"[^a-zA-Z0-9_.-]+")

EmbedQueries = Callable[[Sequence[str]], tuple[Sequence[Sequence[float]], Mapping[str, Any]]]
ScoreRow = Callable[
    [str, Sequence[Mapping[str, Any]]],
    tuple[Sequence[float], Mapping[str, Any]],
]
SearchRows = Callable[
    [str, Sequence[float], Sequence[str]],
    tuple[Sequence[Mapping[str, Any]], Mapping[str, Any]],
]


class CandidateBindingError(ValueError):
    """A stable, diagnostic-rich candidate-to-manifest binding failure."""

    def __init__(self, reasons: Sequence[str], context: Mapping[str, Any]) -> None:
        super().__init__("phase2a_candidate_recovery_candidate_binding_invalid")
        self.code = "phase2a_candidate_recovery_candidate_binding_invalid"
        self.reasons = tuple(sorted(set(reasons)))
        self.context = dict(context)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_candidate_recovery_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_candidate_recovery_input_must_be_object")
    return value


def _verify_seal(
    value: Mapping[str, Any], field: str, code: str, expected: str | None = None
) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if (
        not _SHA256.fullmatch(supplied)
        or supplied != _sealed(material)
        or (expected is not None and supplied != expected)
    ):
        raise ValueError(code)
    return supplied


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _load_remaining(path: Path) -> tuple[list[dict[str, Any]], str]:
    artifact = _load_object(path)
    digest = _verify_seal(
        artifact,
        "artifact_content_sha256",
        "phase2a_candidate_recovery_remaining_seal_invalid",
        EXPECTED_REMAINING_DIGEST,
    )
    rows = artifact.get("records")
    if (
        artifact.get("record_count") != EXPECTED_ROW_COUNT
        or artifact.get("technical_qualification_assigned") is not False
        or artifact.get("source_admission_authorized") is not False
        or artifact.get("automatic_indexing") is not False
        or artifact.get("automatic_embedding") is not False
        or artifact.get("candidate_mutated") is not False
        or artifact.get("phase2b_authorized") is not False
        or artifact.get("development30_authorized") is not False
        or not isinstance(rows, list)
        or len(rows) != EXPECTED_ROW_COUNT
        or any(not isinstance(row, dict) for row in rows)
    ):
        raise ValueError("phase2a_candidate_recovery_remaining_boundary_invalid")
    row_ids = [str(row.get("row_id") or "") for row in rows]
    if len(set(row_ids)) != EXPECTED_ROW_COUNT or any(
        not _ROW_ID.fullmatch(row_id) for row_id in row_ids
    ):
        raise ValueError("phase2a_candidate_recovery_remaining_rows_invalid")
    package = _load_object(path.parent / "PACKAGE-INDEX.json")
    _verify_seal(
        package,
        "package_content_sha256",
        "phase2a_candidate_recovery_r96_package_invalid",
        EXPECTED_R96_PACKAGE_DIGEST,
    )
    return [dict(row) for row in rows], digest


def _load_issue_registry(path: Path) -> tuple[dict[str, dict[str, Any]], str]:
    artifact = _load_object(path)
    digest = _verify_seal(
        artifact,
        "artifact_content_sha256",
        "phase2a_candidate_recovery_issue_registry_seal_invalid",
        EXPECTED_ISSUE_REGISTRY_DIGEST,
    )
    rows = artifact.get("rows")
    if (
        artifact.get("schema") != "legalbot.v111.phase2a.issue-gap-triage-448.v1"
        or artifact.get("row_count") != EXPECTED_ISSUE_REGISTRY_ROW_COUNT
        or artifact.get("owner_decisions_applied") is not False
        or artifact.get("source_admission_authorized") is not False
        or artifact.get("candidate_mutated") is not False
        or artifact.get("phase2b_authorized") is not False
        or artifact.get("development30_authorized") is not False
        or not isinstance(rows, list)
        or len(rows) != EXPECTED_ISSUE_REGISTRY_ROW_COUNT
        or any(not isinstance(row, dict) for row in rows)
    ):
        raise ValueError("phase2a_candidate_recovery_issue_registry_boundary_invalid")
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        _verify_seal(
            row,
            "record_content_sha256",
            "phase2a_candidate_recovery_issue_registry_row_seal_invalid",
        )
        row_id = str(row.get("row_id") or "")
        case_id = str(row.get("case_id") or "")
        issue_label = str(row.get("issue_label") or "").strip()
        legal_domain = str(row.get("legal_domain") or "").strip()
        if (
            not _ROW_ID.fullmatch(row_id)
            or row_id in by_id
            or case_id != row_id.split(":", 1)[0]
            or not issue_label
            or not legal_domain
        ):
            raise ValueError("phase2a_candidate_recovery_issue_registry_row_invalid")
        by_id[row_id] = dict(row)
    return by_id, digest


def _enrich_remaining_rows(
    remaining: Sequence[Mapping[str, Any]],
    issue_registry: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for row in remaining:
        row_id = str(row.get("row_id") or "")
        issue = issue_registry.get(row_id)
        if (
            issue is None
            or issue.get("r70_assessment") != "MATERIAL_GAP_ADVISORY"
            or issue.get("technical_qualification_assigned") is not False
        ):
            raise ValueError("phase2a_candidate_recovery_issue_registry_mapping_invalid")
        planned = issue.get("planned_authorities")
        if not isinstance(planned, list) or any(not isinstance(item, dict) for item in planned):
            raise ValueError("phase2a_candidate_recovery_registry_plan_invalid")
        planned_authority_ids: list[str] = []
        for item in planned:
            authority_id = str(item.get("authority_identity_id") or "")
            if not authority_id:
                raise ValueError("phase2a_candidate_recovery_registry_plan_invalid")
            if authority_id not in planned_authority_ids:
                planned_authority_ids.append(authority_id)
        enriched.append(
            {
                **dict(row),
                "case_id": issue["case_id"],
                "issue_label": issue["issue_label"],
                "legal_domain": issue["legal_domain"],
                "triage_class": issue["triage_class"],
                "registry_planned_authority_ids": planned_authority_ids,
                "source_issue_registry_row_content_sha256": issue["record_content_sha256"],
            }
        )
    if len(enriched) != EXPECTED_ROW_COUNT:
        raise ValueError("phase2a_candidate_recovery_enriched_row_count_invalid")
    return enriched


def _load_cases(path: Path) -> dict[str, dict[str, Any]]:
    if _sha256_file(path) != EXPECTED_CASES_FILE_SHA256:
        raise ValueError("phase2a_candidate_recovery_cases_identity_invalid")
    cases: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict):
            raise ValueError("phase2a_candidate_recovery_case_invalid")
        case_id = str(item.get("case_id") or "")
        if not case_id or case_id in cases:
            raise ValueError("phase2a_candidate_recovery_case_registry_invalid")
        cases[case_id] = item
    if len(cases) != 60:
        raise ValueError("phase2a_candidate_recovery_case_count_invalid")
    return cases


def _load_candidate_manifest(path: Path) -> tuple[dict[str, dict[str, Any]], str]:
    manifest = _load_object(path)
    digest = approved_source_manifest_sha256(manifest)
    sources = manifest.get("sources")
    if (
        digest != EXPECTED_CANDIDATE_MANIFEST_DIGEST
        or manifest.get("manifest_sha256") != digest
        or manifest.get("source_count") != EXPECTED_SOURCE_COUNT
        or manifest.get("chunk_count") != EXPECTED_CHUNK_COUNT
        or manifest.get("authority_lane_only") is not True
        or manifest.get("exclude_find_case_law_full_text") is not True
        or manifest.get("exclude_teaching_as_authority") is not True
        or manifest.get("exclude_assessment_as_authority") is not True
        or not isinstance(sources, list)
        or len(sources) != EXPECTED_SOURCE_COUNT
    ):
        raise ValueError("phase2a_candidate_recovery_manifest_invalid")
    by_version: dict[str, dict[str, Any]] = {}
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("phase2a_candidate_recovery_manifest_source_invalid")
        source_id = str(source.get("source_version_id") or "")
        authority_identity_id = str(source.get("authority_identity_id") or "")
        stable_identifier = str(source.get("stable_identifier") or "")
        if (
            not source_id
            or source_id in by_version
            or not authority_identity_id
            or not stable_identifier
            or source.get("document_status") != "citable"
            or source.get("lane") != "primary_authority"
            or source.get("identity_verified") is not True
            or not _SHA256.fullmatch(str(source.get("version_sha256") or ""))
        ):
            raise ValueError("phase2a_candidate_recovery_manifest_source_invalid")
        by_version[source_id] = dict(source)
    return by_version, digest


def _verify_build(build_root: Path, manifest_digest: str) -> dict[str, Any]:
    build = _load_object(build_root / "manifest.json")
    seal = _load_object(build_root / "seal.json")
    if (
        _sha256_file(build_root / "manifest.json") != EXPECTED_BUILD_MANIFEST_FILE_SHA256
        or build.get("sealed") is not True
        or build.get("chunk_count") != EXPECTED_CHUNK_COUNT
        or build.get("vector_dimensions") != 1024
        or build.get("source_manifest_sha256") != manifest_digest
        or seal.get("manifest_sha256") != EXPECTED_BUILD_MANIFEST_FILE_SHA256
        or seal.get("lance_tree_sha256") != EXPECTED_LANCE_TREE_SHA256
        or seal.get("promotion") != "not_requested"
    ):
        raise ValueError("phase2a_candidate_recovery_build_identity_invalid")
    return {
        "build_id": build["build_id"],
        "build_manifest_file_sha256": EXPECTED_BUILD_MANIFEST_FILE_SHA256,
        "lance_tree_sha256": EXPECTED_LANCE_TREE_SHA256,
        "embedding_model": build["embedding_model"],
        "reranker_model": build["reranker_model"],
    }


def _build_query(*, issue_label: str, legal_domain: str, subject: str) -> str:
    if not issue_label.strip() or not legal_domain.strip() or not subject.strip():
        raise ValueError("phase2a_candidate_recovery_query_fields_missing")
    query = " ".join(
        (
            f"Issue: {issue_label}. Legal domain: {legal_domain}. "
            f"Subject: {subject}. England and Wales governing legal rule "
            "official primary authority."
        ).split()
    )
    if not query or len(query) > MAX_QUERY_CHARACTERS:
        raise ValueError("phase2a_candidate_recovery_query_invalid")
    return query


def _fts_query(query: str) -> str:
    tokens = [token.casefold().replace("’", "'") for token in _TOKEN.findall(query)]
    return " ".join(tokens[:80])


def _sql_literal(value: str) -> str:
    return value.replace("'", "''")


def _route_ranked(
    rows: Sequence[Mapping[str, Any]], *, route: str, score_field: str
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for rank, raw in enumerate(rows, start=1):
        item = dict(raw)
        score = item.pop(score_field, None)
        if isinstance(score, bool) or not isinstance(score, int | float):
            raise ValueError("phase2a_candidate_recovery_search_score_invalid")
        output.append(
            {
                **item,
                "retrieval_route": route,
                "route_rank": rank,
                "route_score": float(score),
            }
        )
    return output


def _fuse_candidates(
    route_rows: Sequence[Sequence[Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    fused: dict[str, dict[str, Any]] = {}
    for rows in route_rows:
        for raw in rows:
            chunk_id = str(raw.get("chunk_id") or "")
            if not chunk_id:
                raise ValueError("phase2a_candidate_recovery_chunk_id_invalid")
            route = str(raw.get("retrieval_route") or "")
            rank = int(raw.get("route_rank") or 0)
            if not route or rank < 1:
                raise ValueError("phase2a_candidate_recovery_route_invalid")
            record = fused.setdefault(
                chunk_id,
                {
                    key: value
                    for key, value in raw.items()
                    if key not in {"retrieval_route", "route_rank", "route_score"}
                }
                | {"route_evidence": [], "rrf_score": 0.0},
            )
            identity = {
                key: value
                for key, value in raw.items()
                if key not in {"retrieval_route", "route_rank", "route_score"}
            }
            if any(record.get(key) != value for key, value in identity.items()):
                raise ValueError("phase2a_candidate_recovery_chunk_identity_conflict")
            record["route_evidence"].append(
                {
                    "route": route,
                    "rank": rank,
                    "score": float(raw["route_score"]),
                }
            )
            record["rrf_score"] += 1.0 / (RRF_K + rank)
    output = list(fused.values())
    output.sort(key=lambda row: (-float(row["rrf_score"]), str(row["chunk_id"])))
    return output


def _select_route_diverse_candidates(
    fused: Sequence[Mapping[str, Any]],
    scores: Sequence[float],
    planned_source_identities: Sequence[str],
) -> list[tuple[dict[str, Any], float, str]]:
    if len(fused) != len(scores):
        raise ValueError("phase2a_candidate_recovery_reranker_result_invalid")
    ranked = sorted(
        ((dict(candidate), float(score)) for candidate, score in zip(fused, scores, strict=True)),
        key=lambda item: (
            -item[1],
            -float(item[0]["rrf_score"]),
            str(item[0]["chunk_id"]),
        ),
    )
    selected: list[tuple[dict[str, Any], float, str]] = []
    selected_ids: set[str] = set()
    for source_identity in planned_source_identities:
        route = f"VECTOR_REGISTRY_IDENTITY:{source_identity}"
        for candidate, score in ranked:
            routes = candidate.get("route_evidence")
            if not isinstance(routes, list):
                raise ValueError("phase2a_candidate_recovery_route_evidence_invalid")
            if str(candidate["chunk_id"]) in selected_ids or not any(
                isinstance(item, dict) and item.get("route") == route for item in routes
            ):
                continue
            selected.append((candidate, score, "REGISTRY_PLANNED_IDENTITY_DIVERSITY"))
            selected_ids.add(str(candidate["chunk_id"]))
            break
    for candidate, score in ranked:
        chunk_id = str(candidate["chunk_id"])
        if chunk_id in selected_ids:
            continue
        selected.append((candidate, score, "GLOBAL_RERANK_FILL"))
        selected_ids.add(chunk_id)
        if len(selected) >= FINAL_CANDIDATE_LIMIT:
            break
    return selected[:FINAL_CANDIDATE_LIMIT]


def _preselect_route_diverse_fused(
    fused: Sequence[Mapping[str, Any]], source_identities: Sequence[str]
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    for source_identity in source_identities:
        route = f"VECTOR_REGISTRY_IDENTITY:{source_identity}"
        routed: list[tuple[int, dict[str, Any]]] = []
        for candidate in fused:
            evidence = candidate.get("route_evidence")
            if not isinstance(evidence, list):
                raise ValueError("phase2a_candidate_recovery_route_evidence_invalid")
            ranks = [
                int(item["rank"])
                for item in evidence
                if isinstance(item, dict) and item.get("route") == route
            ]
            if ranks:
                routed.append((min(ranks), dict(candidate)))
        routed.sort(key=lambda item: (item[0], str(item[1]["chunk_id"])))
        for _, candidate in routed[:PRE_RERANK_IDENTITY_LIMIT]:
            chunk_id = str(candidate["chunk_id"])
            if chunk_id in selected_ids:
                continue
            selected.append(candidate)
            selected_ids.add(chunk_id)
    for candidate in fused:
        chunk_id = str(candidate["chunk_id"])
        if chunk_id in selected_ids:
            continue
        selected.append(dict(candidate))
        selected_ids.add(chunk_id)
        if len(selected) >= PRE_RERANK_LIMIT:
            break
    return selected[:PRE_RERANK_LIMIT]


def _real_embedder(model_path: Path) -> tuple[EmbedQueries, dict[str, Any]]:
    import app.retrieval.service as retrieval_service

    provider = retrieval_service.QwenEmbeddingProvider(
        retrieval_service.PINNED_EMBEDDING_REPO,
        retrieval_service.PINNED_EMBEDDING_REVISION,
        model_path,
    )
    runtime = provider._load()

    def embed(queries: Sequence[str]) -> tuple[Sequence[Sequence[float]], Mapping[str, Any]]:
        instructed = [
            "Instruct: Retrieve authoritative legal passages that answer the research query.\n"
            f"Query: {query}"
            for query in queries
        ]
        vectors = provider._encode(instructed)
        if len(vectors) != len(queries):
            raise RuntimeError("phase2a_candidate_recovery_embedding_count_invalid")
        return vectors, {
            "query_count": len(queries),
            "dimensions": provider.dimensions,
            "normalized": True,
        }

    identity = {
        "model_repo": retrieval_service.PINNED_EMBEDDING_REPO,
        "model_revision": retrieval_service.PINNED_EMBEDDING_REVISION,
        "model_file_manifest_sha256": (retrieval_service.PINNED_EMBEDDING_FILE_MANIFEST_SHA256),
        "adapter": "QwenEmbeddingProvider",
        "runtime_class": type(runtime).__name__,
        "dimensions": provider.dimensions,
        "generative_model_used": False,
    }
    return embed, identity


def _real_searcher(build_root: Path) -> tuple[SearchRows, dict[str, Any]]:
    import lancedb

    require_generic_index_read_allowed(build_root, expected_build_id=build_root.name)
    database = lancedb.connect(str(build_root / "lance/authority"))
    if database.table_names() != ["chunks"]:
        raise ValueError("phase2a_candidate_recovery_lance_table_invalid")
    table = database.open_table("chunks")
    if table.count_rows() != EXPECTED_CHUNK_COUNT:
        raise ValueError("phase2a_candidate_recovery_lance_row_count_invalid")
    columns = [
        "chunk_id",
        "source_version_id",
        "source_identity",
        "text",
        "content_sha256",
        "title",
        "canonical_url",
        "citation",
        "canonical_citation",
        "locator",
        "currentness_status",
        "identity_verified",
        "currentness_verified",
        "legal_role",
        "case_currentness_reviews_json",
        "case_currentness_manifest_seals_json",
        "retrieval_eligible",
        "source_date",
        "as_of_date",
    ]
    where = "retrieval_eligible = true AND identity_verified = true"

    def search(
        query: str, vector: Sequence[float], source_identities: Sequence[str]
    ) -> tuple[Sequence[Mapping[str, Any]], Mapping[str, Any]]:
        if len(vector) != 1024 or any(not math.isfinite(float(item)) for item in vector):
            raise ValueError("phase2a_candidate_recovery_vector_invalid")
        vector_rows = (
            table.search(list(vector))
            .where(where)
            .select([*columns, "_distance"])
            .limit(VECTOR_LIMIT)
            .to_list()
        )
        routes: list[list[dict[str, Any]]] = [
            _route_ranked(vector_rows, route="VECTOR_GLOBAL", score_field="_distance")
        ]
        fts = _fts_query(query)
        fts_failed = False
        if fts:
            try:
                fts_rows = (
                    table.search(fts, query_type="fts", fts_columns="text")
                    .where(where)
                    .select([*columns, "_score"])
                    .limit(FTS_LIMIT)
                    .to_list()
                )
                routes.append(_route_ranked(fts_rows, route="FTS_GLOBAL", score_field="_score"))
            except Exception:
                fts_failed = True
        candidate_source_identities = []
        for source_identity in source_identities:
            if not source_identity or source_identity in candidate_source_identities:
                continue
            candidate_source_identities.append(source_identity)
            identity_where = f"{where} AND source_identity = '{_sql_literal(source_identity)}'"
            identity_rows = (
                table.search(list(vector))
                .where(identity_where)
                .select([*columns, "_distance"])
                .limit(IDENTITY_LIMIT)
                .to_list()
            )
            routes.append(
                _route_ranked(
                    identity_rows,
                    route=f"VECTOR_REGISTRY_IDENTITY:{source_identity}",
                    score_field="_distance",
                )
            )
        fused = _fuse_candidates(routes)
        preselected = _preselect_route_diverse_fused(fused, candidate_source_identities)
        return preselected, {
            "vector_global_hit_count": len(vector_rows),
            "fts_query": fts,
            "fts_failed": fts_failed,
            "route_count": len(routes),
            "registry_identity_count": len(candidate_source_identities),
            "fused_hit_count": len(fused),
            "pre_rerank_hit_count": len(preselected),
            "pre_rerank_identity_limit_per_source": PRE_RERANK_IDENTITY_LIMIT,
        }

    return search, {
        "adapter": "LanceDB sealed vector+FTS reciprocal-rank fusion",
        "table": "authority/chunks",
        "row_count": table.count_rows(),
        "vector_limit": VECTOR_LIMIT,
        "fts_limit": FTS_LIMIT,
        "identity_limit": IDENTITY_LIMIT,
        "rrf_k": RRF_K,
        "old_candidate_fallback": False,
        "network_search": False,
    }


def _candidate_projection(
    *,
    raw: Mapping[str, Any],
    rank: int,
    score: float,
    selection_basis: str,
    manifest_sources: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    source_version_id = str(raw.get("source_version_id") or "")
    source = manifest_sources.get(source_version_id)
    text = str(raw.get("text") or "")
    content_sha256 = str(raw.get("content_sha256") or "")
    source_identity = str(raw.get("source_identity") or "")
    authority_identity_id = str((source or {}).get("authority_identity_id") or "")
    stable_identifier = str((source or {}).get("stable_identifier") or "")
    reasons: list[str] = []
    if source is None:
        reasons.append("SOURCE_VERSION_NOT_IN_MANIFEST")
    if not text:
        reasons.append("CHUNK_TEXT_EMPTY")
    if content_sha256 != _sha256(text.encode()):
        reasons.append("CHUNK_TEXT_SHA256_MISMATCH")
    if raw.get("retrieval_eligible") is not True:
        reasons.append("CHUNK_NOT_RETRIEVAL_ELIGIBLE")
    if raw.get("identity_verified") is not True:
        reasons.append("CHUNK_IDENTITY_NOT_VERIFIED")
    if source is not None and source_identity != stable_identifier:
        reasons.append("STABLE_IDENTIFIER_MISMATCH")
    if source is not None and str(raw.get("canonical_url") or "") != str(
        source.get("canonical_url") or ""
    ):
        reasons.append("CANONICAL_URL_MISMATCH")
    if source is not None and not authority_identity_id:
        reasons.append("AUTHORITY_IDENTITY_MISSING")
    if reasons:
        raise CandidateBindingError(
            reasons,
            {
                "chunk_id": str(raw.get("chunk_id") or ""),
                "source_version_id": source_version_id,
                "observed_source_identity": source_identity,
                "expected_stable_identifier": stable_identifier,
                "authority_identity_id": authority_identity_id,
                "observed_canonical_url": str(raw.get("canonical_url") or ""),
                "expected_canonical_url": str((source or {}).get("canonical_url") or ""),
                "observed_content_sha256": content_sha256,
                "computed_content_sha256": _sha256(text.encode()),
            },
        )
    material = {
        "rank": rank,
        "chunk_id": str(raw["chunk_id"]),
        "source_version_id": source_version_id,
        "source_identity": source_identity,
        "authority_identity_id": authority_identity_id,
        "title": str(raw.get("title") or ""),
        "canonical_url": str(raw.get("canonical_url") or ""),
        "citation": str(raw.get("citation") or ""),
        "canonical_citation": str(raw.get("canonical_citation") or ""),
        "locator": str(raw.get("locator") or ""),
        "text": text,
        "content_sha256": content_sha256,
        "source_version_sha256": str(source["version_sha256"]),
        "source_date": raw.get("source_date"),
        "as_of_date": raw.get("as_of_date"),
        "currentness_status": raw.get("currentness_status"),
        "currentness_verified": raw.get("currentness_verified"),
        "legal_role": raw.get("legal_role"),
        "case_currentness_reviews_json": raw.get("case_currentness_reviews_json"),
        "case_currentness_manifest_seals_json": raw.get("case_currentness_manifest_seals_json"),
        "rrf_score": round(float(raw["rrf_score"]), 12),
        "reranker_score": round(float(score), 12),
        "selection_basis": selection_basis,
        "route_evidence": raw["route_evidence"],
        "already_in_exact_sealed_candidate": True,
        "candidate_manifest_source_bound": True,
    }
    return {**material, "candidate_content_sha256": _sealed(material)}


def _checkpoint_name(ordinal: int, row_id: str) -> str:
    safe = _SAFE_FILENAME.sub("-", row_id)
    return f"{ordinal:03d}-{safe}.json"


def _validate_checkpoint(
    path: Path,
    row_id: str,
    query_strategy_digest: str,
    issue_registry_digest: str,
) -> dict[str, Any]:
    value = _load_object(path)
    _verify_seal(
        value,
        "checkpoint_content_sha256",
        "phase2a_candidate_recovery_checkpoint_invalid",
    )
    if (
        value.get("row_id") != row_id
        or value.get("deterministic_query_strategy_sha256") != query_strategy_digest
        or value.get("source_issue_registry_content_sha256") != issue_registry_digest
    ):
        raise ValueError("phase2a_candidate_recovery_checkpoint_identity_invalid")
    return value


def build_recovery(
    *,
    remaining_path: Path,
    issue_registry_path: Path,
    cases_path: Path,
    candidate_manifest_path: Path,
    build_root: Path,
    output_root: Path,
    embed_queries: EmbedQueries,
    embedding_identity: Mapping[str, Any],
    score_row: ScoreRow,
    reranker_identity: Mapping[str, Any],
    search_rows: SearchRows,
    search_identity: Mapping[str, Any],
    started_at: datetime,
    resume: bool = False,
) -> dict[str, Any]:
    if started_at.tzinfo is None:
        raise ValueError("phase2a_candidate_recovery_started_at_naive")
    remaining, remaining_digest = _load_remaining(remaining_path)
    issue_registry, issue_registry_digest = _load_issue_registry(issue_registry_path)
    remaining = _enrich_remaining_rows(remaining, issue_registry)
    cases = _load_cases(cases_path)
    manifest_sources, manifest_digest = _load_candidate_manifest(candidate_manifest_path)
    stable_identities_by_authority: dict[str, list[str]] = {}
    for source in manifest_sources.values():
        authority_id = str(source["authority_identity_id"])
        stable_identifier = str(source["stable_identifier"])
        stable_identities_by_authority.setdefault(authority_id, []).append(stable_identifier)
    for identities in stable_identities_by_authority.values():
        identities.sort()
    build_identity = _verify_build(build_root, manifest_digest)
    query_strategy = {
        "schema": "legalbot.v111.phase2a.deterministic-candidate-query-strategy.v1",
        "fields": ["issue_label", "legal_domain", "case_subject"],
        "scenario_text_used": False,
        "advisory_ai_proposition_used": False,
        "advisory_ai_authority_selection_used": False,
        "sealed_registry_planned_authority_routes_used": True,
        "route_diverse_candidate_selection": True,
        "one_priority_candidate_per_registry_identity_before_global_fill": True,
        "official_primary_authority_suffix": True,
        "maximum_query_characters": MAX_QUERY_CHARACTERS,
        "all_remaining_rows_searched": True,
    }
    query_strategy_digest = _sealed(query_strategy)
    input_identity = {
        "remaining_content_sha256": remaining_digest,
        "issue_registry_content_sha256": issue_registry_digest,
        "issue_registry_file_sha256": _sha256_file(issue_registry_path),
        "deterministic_query_strategy": query_strategy,
        "deterministic_query_strategy_sha256": query_strategy_digest,
        "cases_file_sha256": EXPECTED_CASES_FILE_SHA256,
        "candidate_manifest_sha256": manifest_digest,
        "build_identity": build_identity,
        "embedding_identity": dict(embedding_identity),
        "reranker_identity": dict(reranker_identity),
        "search_identity": dict(search_identity),
        "builder_code_file_sha256": _sha256_file(Path(__file__).resolve()),
    }
    input_identity_sha256 = _sealed(input_identity)
    intent_path = output_root / "INTENT.json"
    if output_root.exists() or output_root.is_symlink():
        if not resume or output_root.is_symlink() or not output_root.is_dir():
            raise ValueError("phase2a_candidate_recovery_output_already_exists")
        intent = _load_object(intent_path)
        _verify_seal(
            intent,
            "intent_content_sha256",
            "phase2a_candidate_recovery_intent_invalid",
        )
        if intent.get("input_identity_sha256") != input_identity_sha256:
            raise ValueError("phase2a_candidate_recovery_resume_identity_mismatch")
    else:
        output_root.mkdir(parents=True, mode=0o700)
        if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
            raise ValueError("phase2a_candidate_recovery_output_mode_invalid")
        intent_material = {
            "schema": "legalbot.v111.phase2a.post-r94-candidate-recovery-intent.v1",
            "status": "ADVISORY_EXACT_CANDIDATE_SEARCH_ONLY",
            "started_at": started_at.astimezone(UTC).isoformat(timespec="seconds"),
            "input_identity": input_identity,
            "input_identity_sha256": input_identity_sha256,
            "row_count": EXPECTED_ROW_COUNT,
            "deterministic_retrieval_precedes_advisory_ai": True,
            "advisory_planner_required": False,
            "issue_labels_and_legal_domains_registry_bound": True,
            "threshold_applied": False,
            "owner_decisions_applied": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        intent = {**intent_material, "intent_content_sha256": _sealed(intent_material)}
        _write_exclusive(intent_path, _pretty_json(intent))
    checkpoints = output_root / "checkpoints"
    diagnostics = output_root / "diagnostics"
    checkpoints.mkdir(mode=0o700, exist_ok=True)
    diagnostics.mkdir(mode=0o700, exist_ok=True)
    final_path = output_root / "CANDIDATE-RECOVERY-361.json"
    if final_path.exists() or final_path.is_symlink():
        raise ValueError("phase2a_candidate_recovery_already_finalized")

    queries: list[str] = []
    searchable_ids: list[str] = []
    planned_source_identities_by_id: dict[str, list[str]] = {}
    planned_outside_candidate_authorities_by_id: dict[str, list[str]] = {}
    for row in remaining:
        row_id = str(row["row_id"])
        case_id = row_id.split(":", 1)[0]
        case = cases.get(case_id)
        if case is None:
            raise ValueError("phase2a_candidate_recovery_case_missing")
        query = _build_query(
            issue_label=str(row.get("issue_label") or ""),
            legal_domain=str(row.get("legal_domain") or ""),
            subject=str(case.get("subject") or ""),
        )
        planned_authorities = row.get("registry_planned_authority_ids")
        if not isinstance(planned_authorities, list):
            raise ValueError("phase2a_candidate_recovery_registry_plan_invalid")
        planned_source_identities: list[str] = []
        outside_candidate: list[str] = []
        for authority_id in planned_authorities:
            identities = stable_identities_by_authority.get(str(authority_id), [])
            if not identities:
                outside_candidate.append(str(authority_id))
                continue
            for identity in identities:
                if identity not in planned_source_identities:
                    planned_source_identities.append(identity)
        queries.append(query)
        searchable_ids.append(row_id)
        planned_source_identities_by_id[row_id] = planned_source_identities
        planned_outside_candidate_authorities_by_id[row_id] = outside_candidate
    vectors, embedding_metrics = embed_queries(queries)
    if len(vectors) != len(searchable_ids):
        raise ValueError("phase2a_candidate_recovery_embedding_result_invalid")
    vector_by_id = dict(zip(searchable_ids, vectors, strict=True))
    query_by_id = dict(zip(searchable_ids, queries, strict=True))

    results: list[dict[str, Any]] = []
    for ordinal, row in enumerate(remaining, start=1):
        row_id = str(row["row_id"])
        checkpoint_path = checkpoints / _checkpoint_name(ordinal, row_id)
        if checkpoint_path.exists():
            results.append(
                _validate_checkpoint(
                    checkpoint_path,
                    row_id,
                    query_strategy_digest,
                    issue_registry_digest,
                )
            )
            continue
        case_id = row_id.split(":", 1)[0]
        query = query_by_id[row_id]
        planned_source_identities = planned_source_identities_by_id[row_id]
        try:
            fused, search_metrics = search_rows(
                query, vector_by_id[row_id], planned_source_identities
            )
            scorer_candidates: list[dict[str, Any]] = []
            for rank, candidate in enumerate(fused, start=1):
                text = str(candidate.get("text") or "")
                excerpt, truncated = reranker._salient_excerpt(
                    text,
                    issue_label=str(row.get("issue_label") or ""),
                    question=query,
                )
                scorer_candidates.append(
                    {
                        "rank": rank,
                        "excerpt": excerpt,
                        "excerpt_sha256": _sha256((excerpt + "\n").encode()),
                        "excerpt_truncated": truncated,
                        "title": candidate.get("title"),
                        "canonical_citation": candidate.get("canonical_citation"),
                        "locator": candidate.get("locator"),
                        "source_version_id": candidate.get("source_version_id"),
                        "lexical_tfidf_score": candidate.get("rrf_score"),
                    }
                )
            if scorer_candidates:
                scores, rerank_metrics = score_row(query, scorer_candidates)
                if len(scores) != len(fused) or any(
                    not math.isfinite(float(score)) for score in scores
                ):
                    raise ValueError("phase2a_candidate_recovery_reranker_result_invalid")
                ordered = _select_route_diverse_candidates(
                    fused,
                    scores,
                    planned_source_identities,
                )
                projected = [
                    _candidate_projection(
                        raw=candidate,
                        rank=rank,
                        score=float(score),
                        selection_basis=selection_basis,
                        manifest_sources=manifest_sources,
                    )
                    for rank, (candidate, score, selection_basis) in enumerate(ordered, start=1)
                ]
            else:
                rerank_metrics = {"not_invoked_reason": "NO_EXACT_CANDIDATE_HITS"}
                projected = []
        except Exception as exc:
            error_code = (
                exc.code
                if isinstance(exc, CandidateBindingError)
                else str(exc) or type(exc).__name__
            )
            error_context = exc.context if isinstance(exc, CandidateBindingError) else {}
            failure_identity = {
                "stage": "PHASE2A_POST_R94_EXACT_CANDIDATE_RECOVERY",
                "row_id": row_id,
                "error_code": error_code,
                "error_context": error_context,
                "deterministic_query_strategy_sha256": query_strategy_digest,
            }
            diagnostic_material = {
                "schema": "legalbot.v111.phase2a.candidate-recovery-failure.v1",
                "ordinal": ordinal,
                "row_id": row_id,
                "error_type": type(exc).__name__,
                "error_code": error_code,
                "error_context": error_context,
                "failure_fingerprint": _sealed(failure_identity),
                "query_sha256": _sha256(query.encode()),
                "diagnostic_persisted_before_exception": True,
                "debug_required_before_unchanged_retry": True,
                "technical_qualification_assigned": False,
                "source_admission_authorized": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            diagnostic = {
                **diagnostic_material,
                "diagnostic_content_sha256": _sealed(diagnostic_material),
            }
            _write_exclusive(
                diagnostics / f"{_checkpoint_name(ordinal, row_id)[:-5]}-a1.json",
                _pretty_json(diagnostic),
            )
            raise
        material = {
            "schema": "legalbot.v111.phase2a.post-r94-candidate-recovery-row.v2",
            "ordinal": ordinal,
            "row_id": row_id,
            "case_id": case_id,
            "issue_label": row.get("issue_label"),
            "status": (
                "EXACT_CANDIDATE_CHUNKS_READY_FOR_SPAN_VERIFICATION"
                if projected
                else "NO_EXACT_CANDIDATE_HIT_OFFICIAL_SOURCE_RESEARCH_REQUIRED"
            ),
            "classification": "DETERMINISTIC_ISSUE_QUERY",
            "advisory_atomic_proposition": None,
            "official_source_search_query": query,
            "planned_authority_ids": row["registry_planned_authority_ids"],
            "planned_source_identities_in_candidate": planned_source_identities,
            "planned_authority_ids_outside_candidate": (
                planned_outside_candidate_authorities_by_id[row_id]
            ),
            "query": query,
            "search_metrics": dict(search_metrics),
            "reranker_metrics": dict(rerank_metrics),
            "candidates": projected,
            "deterministic_query_strategy_sha256": query_strategy_digest,
            "source_issue_registry_content_sha256": issue_registry_digest,
            "source_issue_registry_row_content_sha256": row[
                "source_issue_registry_row_content_sha256"
            ],
            "threshold_applied": False,
            "technical_qualification_assigned": False,
            "owner_decision_required": True,
        }
        checkpoint = {
            **material,
            "checkpoint_content_sha256": _sealed(material),
        }
        _write_exclusive(checkpoint_path, _pretty_json(checkpoint))
        results.append(checkpoint)

    status_counts: dict[str, int] = {}
    for result in results:
        status = str(result["status"])
        status_counts[status] = status_counts.get(status, 0) + 1
    final_material = {
        "schema": "legalbot.v111.phase2a.post-r94-candidate-recovery-361.v2",
        "status": "ADVISORY_EXACT_CANDIDATE_RECOVERY_COMPLETE_OWNER_REVIEW_REQUIRED",
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_remaining_content_sha256": remaining_digest,
        "source_issue_registry_content_sha256": issue_registry_digest,
        "source_issue_registry_file_sha256": _sha256_file(issue_registry_path),
        "deterministic_query_strategy": query_strategy,
        "deterministic_query_strategy_sha256": query_strategy_digest,
        "candidate_manifest_sha256": manifest_digest,
        "build_identity": build_identity,
        "embedding_identity": dict(embedding_identity),
        "embedding_metrics": dict(embedding_metrics),
        "reranker_identity": dict(reranker_identity),
        "search_identity": dict(search_identity),
        "row_count": len(results),
        "status_counts": dict(sorted(status_counts.items())),
        "rows": results,
        "threshold_applied": False,
        "scores_are_advisory_not_qualification": True,
        "deterministic_retrieval_precedes_advisory_ai": True,
        "advisory_planner_required": False,
        "issue_labels_and_legal_domains_registry_bound": True,
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
    final = {**final_material, "artifact_content_sha256": _sealed(final_material)}
    _write_exclusive(final_path, _pretty_json(final))
    _write_exclusive(
        output_root / "OUTCOME.txt",
        b"PHASE 2A EXACT CANDIDATE RECOVERY COMPLETE - OWNER REVIEW REQUIRED; NO PHASE 2B\n",
    )
    files = sorted(
        path for path in output_root.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in files).encode(),
    )
    return final


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--remaining", type=Path, default=DEFAULT_REMAINING)
    parser.add_argument("--issue-registry", type=Path, default=DEFAULT_ISSUE_REGISTRY)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--candidate-manifest", type=Path, default=DEFAULT_CANDIDATE_MANIFEST)
    parser.add_argument("--build-root", type=Path, default=DEFAULT_BUILD_ROOT)
    parser.add_argument("--embedding-model", type=Path, default=DEFAULT_EMBEDDING_MODEL)
    parser.add_argument("--reranker-model", type=Path, default=DEFAULT_RERANKER_MODEL)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    embed, embedding_identity = _real_embedder(args.embedding_model.resolve(strict=True))
    score, reranker_identity = reranker._real_scorer(args.reranker_model.resolve(strict=True))
    search, search_identity = _real_searcher(args.build_root.resolve(strict=True))
    result = build_recovery(
        remaining_path=args.remaining.resolve(strict=True),
        issue_registry_path=args.issue_registry.resolve(strict=True),
        cases_path=args.cases.resolve(strict=True),
        candidate_manifest_path=args.candidate_manifest.resolve(strict=True),
        build_root=args.build_root.resolve(strict=True),
        output_root=args.output_root.resolve(),
        embed_queries=embed,
        embedding_identity=embedding_identity,
        score_row=score,
        reranker_identity=reranker_identity,
        search_rows=search,
        search_identity=search_identity,
        started_at=datetime.now(UTC),
        resume=bool(args.resume),
    )
    print(
        json.dumps(
            {
                "output_root": str(args.output_root),
                "artifact_content_sha256": result["artifact_content_sha256"],
                "row_count": result["row_count"],
                "status_counts": result["status_counts"],
                "phase2b_authorized": result["phase2b_authorized"],
                "development30_authorized": result["development30_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
