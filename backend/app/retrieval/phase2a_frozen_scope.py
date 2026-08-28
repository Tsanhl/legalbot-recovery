"""Exact Phase-2A held-source scope for the one authorized successor build."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..config import Settings
from ..db import Database

CORPUS_ID = "current-law-ew-full-phase2a-held-20260827-v1"
SCOPE_RELATIVE_PATH = Path(
    "data/evaluations/phase2a-owner-review/"
    "LegalBot-Phase2A-2026-08-27-consolidated-source-admission/"
    "FROZEN-SUCCESSOR-SOURCE-SCOPE.json"
)
PACKAGE_RELATIVE_PATH = SCOPE_RELATIVE_PATH.with_name("PACKAGE-INDEX.json")
EXPECTED_SCOPE_CONTENT_SHA256 = "9c7ee397441eccd00a3b909dc2bdeb6d01d7baf9710bddb966f9d4a04882d84d"
EXPECTED_PACKAGE_CONTENT_SHA256 = "923270611744c0da1927c639b64b042612fb34628e8b115f65c9562cc91f86bf"
EXPECTED_SCAN_ID = "18dded91dadf9fa0"
EXPECTED_SCAN_MANIFEST_SHA256 = "fb6e0d82ff205e74052aa0f536049702e84c8af86624305f5fa03e19eb6e820d"
EXPECTED_STAGING_ARTIFACT_SHA256 = (
    "edd0c6e6a0e26ee776193ceb9256a8a2f5dbc92520dc5ad2346e012e0941e68c"
)
EXPECTED_PREDECESSOR_MANIFEST_SHA256 = (
    "d2c1434fd5fc44d4f2f7e4f7629293f646bb28ed9b8466687feb6c470ea53ac0"
)
EXPECTED_SOURCE_COUNT = 251
EXPECTED_CHUNK_COUNT = 222_200
EXPECTED_OWNER_ADMITTED_SOURCE_COUNT = 166
EXPECTED_FAMILY_COUNTS = {"legislation": 116, "official_judgment": 135}


def is_phase2a_frozen_scope_corpus(corpus_id: str | None) -> bool:
    return str(corpus_id or "") == CORPUS_ID


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Phase-2A frozen-scope input unavailable: {path.name}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"Phase-2A frozen-scope input is not an object: {path.name}")
    return value


def _verify_content_digest(value: Mapping[str, Any], *, field: str, expected: str) -> None:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if supplied != expected or _sha256_bytes(_canonical_json(material)) != supplied:
        raise ValueError(f"Phase-2A frozen-scope seal changed: {field}")


def load_phase2a_frozen_scope(settings: Settings) -> dict[str, Any]:
    scope_path = settings.project_root / SCOPE_RELATIVE_PATH
    package_path = settings.project_root / PACKAGE_RELATIVE_PATH
    scope = _load_object(scope_path)
    package = _load_object(package_path)
    _verify_content_digest(
        scope,
        field="scope_content_sha256",
        expected=EXPECTED_SCOPE_CONTENT_SHA256,
    )
    _verify_content_digest(
        package,
        field="package_content_sha256",
        expected=EXPECTED_PACKAGE_CONTENT_SHA256,
    )
    scope_entry = (package.get("files") or {}).get(scope_path.name)
    if (
        not isinstance(scope_entry, dict)
        or scope_entry.get("sha256") != _sha256_file(scope_path)
        or package.get("frozen_scope_content_sha256") != EXPECTED_SCOPE_CONTENT_SHA256
        or package.get("source_count") != EXPECTED_SOURCE_COUNT
        or package.get("chunk_count") != EXPECTED_CHUNK_COUNT
        or package.get("answer_release_eligible") is not False
        or package.get("successor_must_remain_non_active") is not True
        or package.get("candidate_build_started") is not False
        or package.get("phase2b_authorized") is not False
    ):
        raise ValueError("Phase-2A frozen-scope package boundary changed")
    sources = scope.get("sources")
    if (
        scope.get("schema") != "legalbot.v111.phase2a.frozen-successor-source-scope.v1"
        or scope.get("status") != "OWNER_APPROVED_HELD_RESEARCH_SCOPE_FROZEN_BUILD_NOT_STARTED"
        or scope.get("corpus_id") != CORPUS_ID
        or scope.get("source_scan_id") != EXPECTED_SCAN_ID
        or scope.get("source_scan_manifest_sha256") != EXPECTED_SCAN_MANIFEST_SHA256
        or scope.get("staging_artifact_content_sha256") != EXPECTED_STAGING_ARTIFACT_SHA256
        or scope.get("predecessor_source_manifest_sha256") != EXPECTED_PREDECESSOR_MANIFEST_SHA256
        or scope.get("source_count") != EXPECTED_SOURCE_COUNT
        or scope.get("chunk_count") != EXPECTED_CHUNK_COUNT
        or scope.get("owner_admitted_source_count") != EXPECTED_OWNER_ADMITTED_SOURCE_COUNT
        or scope.get("source_family_counts") != EXPECTED_FAMILY_COUNTS
        or scope.get("selection_policy") != "exact-owner-approved-held-phase2a-successor-scope"
        or scope.get("source_admission_applied") is not True
        or scope.get("answer_release_eligible") is not False
        or scope.get("successor_must_remain_non_active") is not True
        or scope.get("common_legal_currentness_cutoff") is not None
        or scope.get("active_or_previous_write_authorized") is not False
        or scope.get("phase2b_authorized") is not False
        or scope.get("development30_authorized") is not False
        or not isinstance(sources, list)
        or len(sources) != EXPECTED_SOURCE_COUNT
    ):
        raise ValueError("Phase-2A frozen source scope changed")
    source_versions: set[str] = set()
    predecessor_authorities: set[str] = set()
    owner_admitted_authorities: set[str] = set()
    chunk_count = 0
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("Phase-2A frozen source record is invalid")
        material = dict(source)
        supplied = str(material.pop("record_content_sha256", ""))
        if supplied != _sha256_bytes(_canonical_json(material)):
            raise ValueError("Phase-2A frozen source record seal changed")
        source_version_id = str(source.get("source_version_id") or "")
        authority = str(source.get("authority_identity_id") or "")
        if (
            not source_version_id
            or source_version_id in source_versions
            or not authority
            or source.get("answer_release_eligible_in_successor") is not False
        ):
            raise ValueError("Phase-2A frozen source identity is not unique and held")
        source_versions.add(source_version_id)
        source_kind = source.get("source_kind")
        if source_kind == "OWNER_APPROVED_HELD_RESEARCH_SOURCE":
            if authority in owner_admitted_authorities:
                raise ValueError("Phase-2A owner-admitted authority is duplicated")
            owner_admitted_authorities.add(authority)
        elif source_kind == "SEALED_PREDECESSOR_SOURCE":
            predecessor_authorities.add(authority)
        else:
            raise ValueError("Phase-2A frozen source kind changed")
        chunk_count += int(source.get("body_chunk_count") or 0)
    if (
        len(owner_admitted_authorities) != EXPECTED_OWNER_ADMITTED_SOURCE_COUNT
        or predecessor_authorities.intersection(owner_admitted_authorities)
        or chunk_count != EXPECTED_CHUNK_COUNT
    ):
        raise ValueError("Phase-2A frozen source chunk total changed")
    return scope


def _verify_bound_scan(database: Database, scope: Mapping[str, Any]) -> None:
    row = database.fetchone(
        """
        SELECT id,status,expected_file_count,files_accounted,manifest_sha256,
               required_roots_json,roots_seen_json
        FROM source_scans WHERE id=?
        """,
        (scope["source_scan_id"],),
    )
    if (
        row is None
        or row["status"] != "complete"
        or row["manifest_sha256"] != EXPECTED_SCAN_MANIFEST_SHA256
        or int(row["expected_file_count"] or -1) != 3848
        or int(row["files_accounted"] or -2) != 3848
        or row["required_roots_json"] != row["roots_seen_json"]
    ):
        raise ValueError("Phase-2A frozen scope is not bound to the exact complete scan")


def select_phase2a_frozen_scope_rows(
    database: Database,
    settings: Settings,
    *,
    corpus_id: str,
    max_chunks: int | None,
    preferred_small_first: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not is_phase2a_frozen_scope_corpus(corpus_id):
        raise ValueError("Phase-2A frozen source selector received the wrong corpus")
    if max_chunks is not None or preferred_small_first:
        raise ValueError("Phase-2A frozen source scope cannot be reordered or truncated")
    scope = load_phase2a_frozen_scope(settings)
    _verify_bound_scan(database, scope)
    sources = list(scope["sources"])
    source_ids = [str(source["source_version_id"]) for source in sources]
    placeholders = ",".join("?" for _ in source_ids)
    rows = database.fetchall(
        f"""
        SELECT
          sv.id AS source_version_id,
          sv.stable_identifier,
          sv.authority_identity_id,
          sv.title,
          sv.canonical_markdown_path,
          sv.version_sha256,
          sv.licence_name,
          sv.review_status,
          sv.superseded_by,
          sv.canonical_url,
          sv.source_date,
          sv.as_of_date,
          sv.created_at AS last_updated,
          sv.currentness_status,
          sv.metadata_json,
          d.id AS document_id,
          d.lane,
          d.status AS document_status,
          d.subject_primary,
          d.jurisdiction,
          d.content_sha256,
          d.duplicate_of,
          d.retrieval_canonical,
          (
            SELECT COUNT(*) FROM chunks c
            WHERE c.source_version_id=sv.id AND c.stream='body'
          ) AS body_chunk_count
        FROM source_versions sv
        JOIN documents d ON d.id=sv.document_id
        WHERE sv.id IN ({placeholders})
        """,
        tuple(source_ids),
    )
    by_id = {str(row["source_version_id"]): dict(row) for row in rows}
    selected: list[dict[str, Any]] = []
    chunk_count = 0
    for frozen in sources:
        source_version_id = str(frozen["source_version_id"])
        row = by_id.get(source_version_id)
        if row is None:
            raise ValueError("Phase-2A frozen source version disappeared")
        chunks = int(row.get("body_chunk_count") or 0)
        if (
            row.get("document_id") != frozen.get("document_id")
            or row.get("stable_identifier") != frozen.get("stable_identifier")
            or row.get("authority_identity_id") != frozen.get("authority_identity_id")
            or row.get("content_sha256") != frozen.get("content_sha256")
            or row.get("version_sha256") != frozen.get("version_sha256")
            or row.get("canonical_markdown_path") != frozen.get("canonical_markdown_path")
            or chunks != int(frozen.get("body_chunk_count") or -1)
            or row.get("review_status") != "approved"
            or row.get("superseded_by") is not None
            or row.get("document_status") != "citable"
            or row.get("lane") != "primary_authority"
            or row.get("duplicate_of") is not None
            or int(row.get("retrieval_canonical") or 0) != 1
        ):
            raise ValueError("Phase-2A frozen source catalogue binding changed")
        try:
            metadata = json.loads(str(row.get("metadata_json") or "{}"))
        except json.JSONDecodeError as exc:
            raise ValueError("Phase-2A frozen source metadata is invalid") from exc
        if (
            not isinstance(metadata, dict)
            or metadata.get("eligible_for_model_use") is not True
            or metadata.get("ai_use_policy") == "prohibited"
        ):
            raise ValueError("Phase-2A frozen source is no longer index eligible")
        if frozen.get("source_kind") == "OWNER_APPROVED_HELD_RESEARCH_SOURCE":
            owner_binding = metadata.get("phase2a_owner_held_source_admission")
            if (
                not isinstance(owner_binding, dict)
                or owner_binding.get("staging_artifact_content_sha256")
                != EXPECTED_STAGING_ARTIFACT_SHA256
                or owner_binding.get("answer_release_eligible") is not False
                or metadata.get("currentness_verified") is not False
                or metadata.get("answer_release_eligible") is not False
            ):
                raise ValueError("Phase-2A owner-held source release boundary changed")
        markdown_path = settings.project_root / str(row["canonical_markdown_path"])
        if not markdown_path.is_file() or markdown_path.stat().st_size < 1:
            raise ValueError("Phase-2A frozen source canonical Markdown is unavailable")
        row["body_chunk_count"] = chunks
        row["unfiltered_body_chunk_count"] = chunks
        row["frozen_scope_source_kind"] = frozen["source_kind"]
        row["answer_release_eligible_in_successor"] = False
        selected.append(row)
        chunk_count += chunks
    if len(selected) != EXPECTED_SOURCE_COUNT or chunk_count != EXPECTED_CHUNK_COUNT:
        raise ValueError("Phase-2A exact frozen scope selection changed")
    return selected, scope
