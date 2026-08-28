"""Read-only incomplete-index audit. Never mutates staging and never emits source text."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import Settings
from ..db import Database
from ..jobs import CHUNKER_VERSION, INDEX_SCHEMA_VERSION, PARSER_VERSION
from ..quality.policy import POLICY_SHA256
from .embedding_progress import chunk_key, load_checkpoint, update_rolling_digest
from .lancedb import ImmutableLanceRepository
from .models import VECTOR_DIMENSIONS
from .source_manifest import chunk_locator_allowed

AUDIT_SCHEMA = "legalbot.incomplete-index-audit.v1"
ID_LIST_LIMIT = 100
EXPECTED_SELECT_SQL = """
        SELECT
          d.id AS document_id, d.content_sha256 AS document_sha256,
          d.source_identity_id, d.representation_group_id,
          d.retrieval_canonical, d.status AS document_status, d.lane,
          d.subject_primary, d.jurisdiction,
          sv.id AS source_version_id, sv.version_sha256, sv.title,
          sv.author_or_body, sv.source_date, sv.as_of_date, sv.canonical_url,
          sv.created_at AS source_last_updated_at,
          sv.stable_identifier, sv.currentness_status, sv.licence_name,
          sv.licence_url, sv.review_status, sv.metadata_json AS source_metadata_json,
          c.id AS chunk_id, c.ordinal, c.heading_path, c.locator, c.stream,
          c.text_sha256, c.markdown_text, c.metadata_json AS chunk_metadata_json
        FROM chunks c
        JOIN source_versions sv ON sv.id=c.source_version_id
        JOIN documents d ON d.id=sv.document_id
        WHERE c.source_version_id = ?
          AND sv.review_status='approved'
          AND c.stream='body'
          AND d.lane='primary_authority'
          AND d.status='citable'
          AND d.retrieval_canonical=1
          AND json_extract(sv.metadata_json, '$.eligible_for_model_use')=1
          AND COALESCE(json_extract(sv.metadata_json, '$.ai_use_policy'), '')<>'prohibited'
        ORDER BY c.ordinal
        """


@dataclass(frozen=True, slots=True)
class ObservedIndexRow:
    chunk_id: str
    content_sha256: str
    source_version_id: str
    vector_dimensions: int
    lane: str


@dataclass(frozen=True, slots=True)
class ExpectedIndexRow:
    chunk_id: str
    content_sha256: str
    source_version_id: str
    ordinal: int
    lane: str = "authority"


def _bounded_ids(values: Sequence[str], *, limit: int = ID_LIST_LIMIT) -> dict[str, Any]:
    items = list(values)
    return {
        "count": len(items),
        "ids": items[:limit],
        "truncated": len(items) > limit,
    }


def relative_staging_label(build_id: str) -> str:
    return f"builds/.{build_id}.incomplete"


def load_expected_index_rows(
    database: Database,
    *,
    source_ids: Sequence[str],
    allowlists: Mapping[str, Any],
    prompt_safe: Callable[[Any], str],
) -> tuple[ExpectedIndexRow, ...]:
    expected: list[ExpectedIndexRow] = []
    for source_id in source_ids:
        rows = database.fetchall(EXPECTED_SELECT_SQL, (source_id,))
        for row in rows:
            if not chunk_locator_allowed(
                str(row["stable_identifier"]), str(row["locator"] or ""), allowlists
            ):
                continue
            text = prompt_safe(row)
            expected.append(
                ExpectedIndexRow(
                    chunk_id=str(row["chunk_id"]),
                    content_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    source_version_id=str(row["source_version_id"]),
                    ordinal=int(row["ordinal"]),
                    # EXPECTED_SELECT_SQL is deliberately restricted to
                    # citable primary authority, which is written to the
                    # physical authority lane.
                    lane="authority",
                )
            )
    return tuple(expected)


def read_lance_observations(staging: Path) -> tuple[ObservedIndexRow, ...]:
    """Read Lance fragments without creating tables or compacting."""

    lance_root = staging / "lance"
    if not lance_root.is_dir():
        return ()
    observed: list[ObservedIndexRow] = []
    import lance  # type: ignore[import-untyped]

    for lane_dir in sorted(path for path in lance_root.iterdir() if path.is_dir()):
        dataset_path = lane_dir / "chunks.lance"
        if not dataset_path.exists():
            continue
        dataset = lance.dataset(str(dataset_path))
        columns = ["chunk_id", "content_sha256", "source_version_id", "vector"]
        for batch in dataset.to_batches(columns=columns):
            chunk_ids = batch.column("chunk_id").to_pylist()
            hashes = batch.column("content_sha256").to_pylist()
            sources = batch.column("source_version_id").to_pylist()
            vectors = batch.column("vector").to_pylist()
            for chunk_id, digest, source_id, vector in zip(
                chunk_ids, hashes, sources, vectors, strict=True
            ):
                observed.append(
                    ObservedIndexRow(
                        chunk_id=str(chunk_id),
                        content_sha256=str(digest),
                        source_version_id=str(source_id),
                        vector_dimensions=len(vector or ()),
                        lane=lane_dir.name,
                    )
                )
    return tuple(observed)


def compare_index_identities(
    expected: Sequence[ExpectedIndexRow],
    observed: Sequence[ObservedIndexRow],
    *,
    vector_dimensions: int = VECTOR_DIMENSIONS,
) -> dict[str, Any]:
    expected_ids = {row.chunk_id for row in expected}
    observed_ids = [row.chunk_id for row in observed]
    counted = Counter(observed_ids)
    unique_ids = {chunk_id for chunk_id in counted}
    duplicates = sorted(chunk_id for chunk_id, count in counted.items() if count > 1)
    missing = sorted(expected_ids - unique_ids)
    unexpected = sorted(unique_ids - expected_ids)
    expected_by_id = {row.chunk_id: row for row in expected}
    hash_mismatches: list[str] = []
    source_mismatches: list[str] = []
    dimension_mismatches: list[str] = []
    for row in observed:
        wanted = expected_by_id.get(row.chunk_id)
        if wanted is None:
            continue
        if row.content_sha256 != wanted.content_sha256:
            hash_mismatches.append(row.chunk_id)
        if row.source_version_id != wanted.source_version_id:
            source_mismatches.append(row.chunk_id)
        if row.vector_dimensions != vector_dimensions:
            dimension_mismatches.append(row.chunk_id)
    lane_counts = Counter(row.lane for row in observed)
    source_versions = {row.source_version_id for row in observed}
    embedding_complete = (
        bool(expected)
        and not missing
        and not unexpected
        and not duplicates
        and not hash_mismatches
        and not source_mismatches
        and not dimension_mismatches
        and len(observed) == len(expected)
    )
    return {
        "expected_chunks": len(expected),
        "observed_total_rows": len(observed),
        "observed_rows_per_physical_lane": dict(sorted(lane_counts.items())),
        "observed_source_version_count": len(source_versions),
        "unique_chunk_ids": len(unique_ids),
        "duplicate_chunk_ids": duplicates,
        "missing_expected_chunk_ids": missing,
        "unexpected_chunk_ids": unexpected,
        "content_hash_mismatches": hash_mismatches,
        "vector_dimension_mismatches": dimension_mismatches,
        "source_version_mismatches": source_mismatches,
        "embedding_complete": embedding_complete,
    }


def summarize_expected_prefix(
    expected: Sequence[ExpectedIndexRow],
    completed_row_count: int,
) -> dict[str, Any]:
    """Return the deterministic identity of one expected stream prefix."""

    if completed_row_count < 0 or completed_row_count > len(expected):
        raise ValueError("prefix row count is outside the expected stream")
    digest = ""
    lane_counts: Counter[str] = Counter()
    last_key = ""
    for row in expected[:completed_row_count]:
        digest = update_rolling_digest(
            digest,
            chunk_id=row.chunk_id,
            content_sha256=row.content_sha256,
        )
        lane_counts[row.lane] += 1
        last_key = chunk_key(row.source_version_id, row.ordinal, row.chunk_id)
    return {
        "completed_row_count": completed_row_count,
        "last_deterministic_chunk_key": last_key,
        "rolling_digest": digest,
        "physical_lane_counts": dict(sorted(lane_counts.items())),
    }


def compare_ordered_index_prefix(
    expected: Sequence[ExpectedIndexRow],
    observed: Sequence[ObservedIndexRow],
    *,
    vector_dimensions: int = VECTOR_DIMENSIONS,
) -> dict[str, Any]:
    """Verify that every observed row is the exact ordered stream prefix.

    A set comparison is insufficient for resume safety: if Lance committed a
    batch after the latest checkpoint, resuming at the stale checkpoint would
    append duplicate rows. This comparison therefore binds position, chunk,
    prompt-view content, source version, physical lane, and vector shape.
    """

    mismatches: list[dict[str, Any]] = []
    if len(observed) > len(expected):
        mismatches.append(
            {
                "position": len(expected),
                "reason": "observed_stream_longer_than_expected",
                "observed_chunk_id": observed[len(expected)].chunk_id,
            }
        )
    for position, (wanted, actual) in enumerate(zip(expected, observed, strict=False)):
        fields: list[str] = []
        if actual.chunk_id != wanted.chunk_id:
            fields.append("chunk_id")
        if actual.content_sha256 != wanted.content_sha256:
            fields.append("content_sha256")
        if actual.source_version_id != wanted.source_version_id:
            fields.append("source_version_id")
        if actual.vector_dimensions != vector_dimensions:
            fields.append("vector_dimensions")
        if actual.lane != wanted.lane:
            fields.append("lane")
        if fields:
            mismatches.append(
                {
                    "position": position,
                    "reason": "ordered_prefix_identity_mismatch",
                    "fields": fields,
                    "expected_chunk_id": wanted.chunk_id,
                    "observed_chunk_id": actual.chunk_id,
                }
            )
            if len(mismatches) >= ID_LIST_LIMIT:
                break
    summary = summarize_expected_prefix(expected, min(len(observed), len(expected)))
    exact = len(observed) <= len(expected) and not mismatches
    return {
        "exact_ordered_prefix": exact,
        "expected_chunks": len(expected),
        "observed_rows": len(observed),
        "prefix_mismatch_count": len(mismatches),
        "prefix_mismatches": mismatches,
        "prefix_mismatches_truncated": len(mismatches) >= ID_LIST_LIMIT,
        "verified_prefix": summary if exact else None,
    }


def compare_checkpoint_to_expected_prefix(
    checkpoint: Any,
    expected: Sequence[ExpectedIndexRow],
    *,
    observed_row_count: int,
) -> dict[str, Any]:
    """Verify that a durable checkpoint names the exact expected prefix."""

    if checkpoint is None:
        return {
            "checkpoint_prefix_match": False,
            "checkpoint_trails_observed_rows": False,
            "uncheckpointed_observed_rows": observed_row_count,
            "reasons": ["checkpoint_missing"],
        }
    completed = int(checkpoint.completed_row_count)
    reasons: list[str] = []
    if completed < 0 or completed > len(expected):
        reasons.append("checkpoint_count_outside_expected_stream")
        expected_summary = None
    else:
        expected_summary = summarize_expected_prefix(expected, completed)
        if (
            checkpoint.last_deterministic_chunk_key
            != expected_summary["last_deterministic_chunk_key"]
        ):
            reasons.append("checkpoint_last_chunk_key_mismatch")
        if checkpoint.rolling_digest != expected_summary["rolling_digest"]:
            reasons.append("checkpoint_rolling_digest_mismatch")
        expected_counts = Counter(expected_summary["physical_lane_counts"])
        checkpoint_counts = Counter(
            {
                str(key): int(value)
                for key, value in dict(checkpoint.physical_lane_counts).items()
                if int(value) != 0
            }
        )
        if checkpoint_counts != expected_counts:
            reasons.append("checkpoint_lane_counts_mismatch")
    if completed > observed_row_count:
        reasons.append("checkpoint_ahead_of_observed_rows")
    trails = 0 <= completed < observed_row_count
    return {
        "checkpoint_prefix_match": not reasons,
        "checkpoint_trails_observed_rows": trails,
        "uncheckpointed_observed_rows": max(0, observed_row_count - completed),
        "reasons": reasons,
    }


def audit_incomplete_index(
    settings: Settings,
    database: Database,
    build_id: str,
    *,
    observed_rows: Sequence[ObservedIndexRow] | None = None,
    expected_rows: Sequence[ExpectedIndexRow] | None = None,
) -> dict[str, Any]:
    from ..assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
    from .service import _prompt_safe_index_text, _validate_build_id
    from .source_manifest import build_approved_source_manifest

    _validate_build_id(build_id)
    build = database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))
    if build is None:
        raise ValueError("index build is not in the catalogue")
    job_id = str(build["job_id"] or f"index-{build_id}")
    job = database.job(job_id)
    request = json.loads(str(job["request_json"] or "{}")) if job is not None else {}
    source_ids = tuple(str(item) for item in request.get("source_version_ids") or ())
    repository = ImmutableLanceRepository(settings.index_dir)
    staging = repository.staging_path(build_id)
    sealed = repository.builds / build_id
    if staging.exists() and sealed.exists() and staging.resolve() == sealed.resolve():
        raise RuntimeError("refusing to audit a sealed build directory as incomplete staging")
    corpus_id = str(build["corpus_id"] or request.get("corpus_id") or "")
    manifest = build_approved_source_manifest(
        database,
        settings,
        corpus_id=corpus_id,
        max_chunks=request.get("max_chunks"),
        preferred_small_first=bool(request.get("preferred_small_first", True)),
    )
    stored_hash = str(
        build["source_manifest_hash"] or request.get("approved_source_manifest_hash") or ""
    )
    source_manifest_match = str(manifest.get("manifest_sha256") or "") == stored_hash
    if expected_rows is None:
        expected_rows = load_expected_index_rows(
            database,
            source_ids=source_ids
            or tuple(
                str(source.get("source_version_id")) for source in manifest.get("sources") or []
            ),
            allowlists=manifest.get("locator_allowlists") or {},
            prompt_safe=_prompt_safe_index_text,
        )
    if observed_rows is None:
        observed_rows = () if not staging.is_dir() else read_lance_observations(staging)
    comparison = compare_index_identities(expected_rows, observed_rows)
    ordered_prefix = compare_ordered_index_prefix(expected_rows, observed_rows)
    checkpoint = None
    checkpoint_error = None
    if staging.is_dir():
        try:
            loaded = load_checkpoint(staging)
        except (OSError, TypeError, ValueError) as exc:
            loaded = None
            checkpoint_error = type(exc).__name__
        else:
            if loaded is not None:
                checkpoint = {
                    "present": True,
                    "completed_row_count": loaded.completed_row_count,
                    "checkpoint_sha256": loaded.checkpoint_sha256,
                    "last_deterministic_chunk_key": loaded.last_deterministic_chunk_key,
                }
    checkpoint_prefix = compare_checkpoint_to_expected_prefix(
        loaded if staging.is_dir() and checkpoint_error is None else None,
        expected_rows,
        observed_row_count=len(observed_rows),
    )
    exact_embedding_complete = bool(comparison["embedding_complete"]) and bool(
        ordered_prefix["exact_ordered_prefix"]
    )
    checkpoint_at_observed_tail = bool(checkpoint_prefix["checkpoint_prefix_match"]) and not bool(
        checkpoint_prefix["checkpoint_trails_observed_rows"]
    )
    resumable = (
        bool(source_manifest_match)
        and bool(ordered_prefix["exact_ordered_prefix"])
        and (exact_embedding_complete or checkpoint_at_observed_tail)
    )
    bounded = {
        "duplicate_chunk_ids": _bounded_ids(comparison["duplicate_chunk_ids"]),
        "missing_expected_chunk_ids": _bounded_ids(comparison["missing_expected_chunk_ids"]),
        "unexpected_chunk_ids": _bounded_ids(comparison["unexpected_chunk_ids"]),
        "content_hash_mismatches": _bounded_ids(comparison["content_hash_mismatches"]),
        "vector_dimension_mismatches": _bounded_ids(comparison["vector_dimension_mismatches"]),
        "source_version_mismatches": _bounded_ids(comparison["source_version_mismatches"]),
    }
    report = {
        "schema": AUDIT_SCHEMA,
        "build_id": build_id,
        "job_id": job_id,
        "build_status": str(build["status"]),
        "job_status": str(job["status"]) if job is not None else None,
        "failure_reason_code": str(build["failure_reason_code"] or ""),
        "source_manifest_sha256": stored_hash,
        "source_manifest_match": source_manifest_match,
        "embedding_model": str(build["embedding_model"] or ""),
        "parser_version": str(build["parser_version"] or PARSER_VERSION),
        "chunker_version": str(build["chunker_version"] or CHUNKER_VERSION),
        "index_schema_version": str(build["index_schema_version"] or INDEX_SCHEMA_VERSION),
        "policy_sha256": str(build["policy_sha256"] or POLICY_SHA256),
        "assessment_bundle_sha256": str(
            build["assessment_bundle_sha256"] or OWNER_ASSESSMENT_BUNDLE.sha256
        ),
        "vector_dimensions": VECTOR_DIMENSIONS,
        "staging_label": relative_staging_label(build_id),
        "staging_present": staging.is_dir(),
        "checkpoint": checkpoint,
        "checkpoint_error": checkpoint_error,
        "resumable": resumable,
        "checkpoint_reconciliation_required": bool(
            source_manifest_match
            and ordered_prefix["exact_ordered_prefix"]
            and checkpoint_prefix["checkpoint_prefix_match"]
            and checkpoint_prefix["checkpoint_trails_observed_rows"]
        ),
        "expected_chunks": comparison["expected_chunks"],
        "observed_total_rows": comparison["observed_total_rows"],
        "observed_rows_per_physical_lane": comparison["observed_rows_per_physical_lane"],
        "observed_source_version_count": comparison["observed_source_version_count"],
        "unique_chunk_ids": comparison["unique_chunk_ids"],
        "embedding_complete": exact_embedding_complete,
        "exact_ordered_prefix": ordered_prefix["exact_ordered_prefix"],
        "ordered_prefix_verified_row_count": (
            ordered_prefix["verified_prefix"]["completed_row_count"]
            if ordered_prefix["verified_prefix"] is not None
            else 0
        ),
        "ordered_prefix_rolling_digest": (
            ordered_prefix["verified_prefix"]["rolling_digest"]
            if ordered_prefix["verified_prefix"] is not None
            else ""
        ),
        "ordered_prefix_last_deterministic_chunk_key": (
            ordered_prefix["verified_prefix"]["last_deterministic_chunk_key"]
            if ordered_prefix["verified_prefix"] is not None
            else ""
        ),
        "ordered_prefix_lane_counts": (
            ordered_prefix["verified_prefix"]["physical_lane_counts"]
            if ordered_prefix["verified_prefix"] is not None
            else {}
        ),
        "ordered_prefix_mismatches": _bounded_ids(
            [
                json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                for item in ordered_prefix["prefix_mismatches"]
            ]
        ),
        "checkpoint_prefix_match": checkpoint_prefix["checkpoint_prefix_match"],
        "checkpoint_prefix_reasons": checkpoint_prefix["reasons"],
        "checkpoint_trails_observed_rows": checkpoint_prefix["checkpoint_trails_observed_rows"],
        "uncheckpointed_observed_rows": checkpoint_prefix["uncheckpointed_observed_rows"],
        **bounded,
    }
    encoded = json.dumps(
        {key: value for key, value in report.items() if key != "report_sha256"},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    report["report_sha256"] = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    return report
