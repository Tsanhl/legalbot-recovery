"""Read-only incomplete-index audit. Never mutates staging and never emits source text."""

from __future__ import annotations

import hashlib
import json
import re
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
GE_SELECTION_POLICY = "exact-owner-approved-ge-source-versions-and-lanes"
PHYSICAL_AUTHORITY_LANE = "authority"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CATALOGUE_LANES = frozenset({"primary_authority", "official_secondary"})
_GE_SCOPE_MATERIAL_LANES = {
    "primary_authority": "primary_authority",
    "official_guidance": "official_guidance",
    "official_procedure": "procedure_rule",
}
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
          AND d.lane=?
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
    material_lane: str = "primary_authority"
    catalogue_lane: str = "primary_authority"


@dataclass(frozen=True, slots=True)
class ExpectedIndexRow:
    chunk_id: str
    content_sha256: str
    source_version_id: str
    ordinal: int
    lane: str = "authority"
    material_lane: str = "primary_authority"
    catalogue_lane: str = "primary_authority"


@dataclass(frozen=True, slots=True)
class SourceLaneBinding:
    """One frozen source-to-lane identity used by audit and embedding."""

    source_version_id: str
    catalogue_lane: str
    scope_lane: str
    material_lane: str
    physical_lane: str = PHYSICAL_AUTHORITY_LANE

    def as_dict(self) -> dict[str, str]:
        return {
            "source_version_id": self.source_version_id,
            "catalogue_lane": self.catalogue_lane,
            "scope_lane": self.scope_lane,
            "material_lane": self.material_lane,
            "physical_lane": self.physical_lane,
        }


def source_lane_bindings_for_manifest(
    manifest: Mapping[str, Any],
) -> tuple[SourceLaneBinding, ...]:
    """Validate and expose the exact catalogue/scope lanes frozen in a manifest.

    Ordinary and previously frozen candidate manifests remain primary-authority
    only.  The sole mixed-lane exception is the exact owner-approved GE source
    scope, whose official-secondary members keep an official guidance or
    procedure material label while sharing the physical legal-source table.
    """

    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("source_lane_binding_sources_invalid")
    is_ge = manifest.get("selection_policy") == GE_SELECTION_POLICY
    if is_ge:
        if (
            manifest.get("ge_expansion_mode") != "strict_successor"
            or manifest.get("approved_legal_source_lanes_only") is not True
            or manifest.get("successor_must_remain_non_active") is not True
            or manifest.get("answer_release_eligible") is not False
            or manifest.get("active_or_previous_write_authorized") is not False
            or manifest.get("promotion_authorized") is not False
            or manifest.get("index_enqueue_authorized") is not False
            or manifest.get("index_build_authorized") is not False
            or _SHA256_RE.fullmatch(
                str(manifest.get("ge_source_scope_content_sha256") or "")
            )
            is None
            or _SHA256_RE.fullmatch(
                str(manifest.get("ge_source_scope_owner_approval_digest") or "")
            )
            is None
        ):
            raise ValueError("ge_source_lane_boundary_invalid")
    elif manifest.get("authority_lane_only") is not True:
        raise ValueError("ordinary_source_manifest_not_authority_lane_only")

    ge_bindings: tuple[SourceLaneBinding, ...] | None = None
    if is_ge:
        try:
            ge_bindings = parse_source_lane_bindings(
                manifest.get("ge_source_lane_bindings")
            )
        except ValueError as exc:
            raise ValueError("ge_source_lane_binding_invalid") from exc
        if len(ge_bindings) != len(sources):
            raise ValueError("ge_source_lane_inventory_invalid")
    result: list[SourceLaneBinding] = []
    seen: set[str] = set()
    for ordinal, source in enumerate(sources):
        if not isinstance(source, dict):
            raise ValueError("source_lane_binding_member_invalid")
        source_id = str(source.get("source_version_id") or "")
        catalogue_lane = str(source.get("lane") or "")
        if not source_id or source_id in seen or catalogue_lane not in _CATALOGUE_LANES:
            raise ValueError("source_lane_binding_member_invalid")
        seen.add(source_id)
        if is_ge:
            if ge_bindings is None:  # pragma: no cover - guarded above
                raise ValueError("ge_source_lane_binding_invalid")
            frozen = ge_bindings[ordinal]
            scope_lane = frozen.scope_lane
            material_lane = _GE_SCOPE_MATERIAL_LANES.get(scope_lane)
            allowed = (
                scope_lane == "primary_authority" and catalogue_lane == "primary_authority"
            ) or (
                scope_lane == "official_guidance" and catalogue_lane == "official_secondary"
            ) or (
                scope_lane == "official_procedure"
                and catalogue_lane in _CATALOGUE_LANES
            )
            if (
                material_lane is None
                or not allowed
                or frozen.source_version_id != source_id
                or frozen.catalogue_lane != catalogue_lane
                or frozen.material_lane != material_lane
                or frozen.physical_lane != PHYSICAL_AUTHORITY_LANE
                or (
                    source.get("ge_scope_lane") is not None
                    and source.get("ge_scope_lane") != scope_lane
                )
            ):
                raise ValueError("ge_source_lane_mapping_invalid")
        else:
            if catalogue_lane != "primary_authority":
                raise ValueError("ordinary_source_manifest_not_authority_lane_only")
            scope_lane = "primary_authority"
            material_lane = "primary_authority"
        result.append(
            SourceLaneBinding(
                source_version_id=source_id,
                catalogue_lane=catalogue_lane,
                scope_lane=scope_lane,
                material_lane=material_lane,
            )
        )
    if is_ge:
        expected_scope_lanes = sorted({binding.scope_lane for binding in result})
        expected_authority_only = all(
            binding.catalogue_lane == "primary_authority" for binding in result
        )
        if (
            manifest.get("ge_source_scope_lanes") != expected_scope_lanes
            or manifest.get("authority_lane_only") is not expected_authority_only
            or int(manifest.get("source_count") or -1) != len(result)
        ):
            raise ValueError("ge_source_lane_inventory_invalid")
    return tuple(result)


def parse_source_lane_bindings(values: Any) -> tuple[SourceLaneBinding, ...]:
    """Parse the exact JSON lane bindings stored in an index-build request."""

    if not isinstance(values, list) or not values:
        raise ValueError("source_lane_binding_request_invalid")
    expected_fields = {
        "source_version_id",
        "catalogue_lane",
        "scope_lane",
        "material_lane",
        "physical_lane",
    }
    bindings: list[SourceLaneBinding] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, dict) or set(value) != expected_fields:
            raise ValueError("source_lane_binding_request_invalid")
        binding = SourceLaneBinding(
            source_version_id=str(value["source_version_id"]),
            catalogue_lane=str(value["catalogue_lane"]),
            scope_lane=str(value["scope_lane"]),
            material_lane=str(value["material_lane"]),
            physical_lane=str(value["physical_lane"]),
        )
        if (
            not binding.source_version_id
            or binding.source_version_id in seen
            or binding.catalogue_lane not in _CATALOGUE_LANES
            or binding.scope_lane not in _GE_SCOPE_MATERIAL_LANES
            or binding.material_lane != _GE_SCOPE_MATERIAL_LANES[binding.scope_lane]
            or binding.physical_lane != PHYSICAL_AUTHORITY_LANE
        ):
            raise ValueError("source_lane_binding_request_invalid")
        seen.add(binding.source_version_id)
        bindings.append(binding)
    return tuple(bindings)


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
    source_lane_bindings: Sequence[SourceLaneBinding] | None = None,
) -> tuple[ExpectedIndexRow, ...]:
    if source_lane_bindings is None:
        bindings = tuple(
            SourceLaneBinding(
                source_version_id=str(source_id),
                catalogue_lane="primary_authority",
                scope_lane="primary_authority",
                material_lane="primary_authority",
            )
            for source_id in source_ids
        )
    else:
        bindings = tuple(source_lane_bindings)
    if [binding.source_version_id for binding in bindings] != [str(item) for item in source_ids]:
        raise ValueError("source_lane_binding_source_order_mismatch")
    expected: list[ExpectedIndexRow] = []
    for binding in bindings:
        rows = database.fetchall(
            EXPECTED_SELECT_SQL,
            (binding.source_version_id, binding.catalogue_lane),
        )
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
                    lane=binding.physical_lane,
                    material_lane=binding.material_lane,
                    catalogue_lane=binding.catalogue_lane,
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
        columns = [
            "chunk_id",
            "content_sha256",
            "source_version_id",
            "vector",
            "lane_key",
            "catalog_lane",
        ]
        for batch in dataset.to_batches(columns=columns):
            chunk_ids = batch.column("chunk_id").to_pylist()
            hashes = batch.column("content_sha256").to_pylist()
            sources = batch.column("source_version_id").to_pylist()
            vectors = batch.column("vector").to_pylist()
            material_lanes = batch.column("lane_key").to_pylist()
            catalogue_lanes = batch.column("catalog_lane").to_pylist()
            for chunk_id, digest, source_id, vector, material_lane, catalogue_lane in zip(
                chunk_ids,
                hashes,
                sources,
                vectors,
                material_lanes,
                catalogue_lanes,
                strict=True,
            ):
                observed.append(
                    ObservedIndexRow(
                        chunk_id=str(chunk_id),
                        content_sha256=str(digest),
                        source_version_id=str(source_id),
                        vector_dimensions=len(vector or ()),
                        lane=lane_dir.name,
                        material_lane=str(material_lane),
                        catalogue_lane=str(catalogue_lane),
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
    physical_lane_mismatches: list[str] = []
    material_lane_mismatches: list[str] = []
    catalogue_lane_mismatches: list[str] = []
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
        if row.lane != wanted.lane:
            physical_lane_mismatches.append(row.chunk_id)
        if row.material_lane != wanted.material_lane:
            material_lane_mismatches.append(row.chunk_id)
        if row.catalogue_lane != wanted.catalogue_lane:
            catalogue_lane_mismatches.append(row.chunk_id)
    lane_counts = Counter(row.lane for row in observed)
    expected_catalogue_lane_counts = Counter(row.catalogue_lane for row in expected)
    observed_catalogue_lane_counts = Counter(row.catalogue_lane for row in observed)
    expected_material_lane_counts = Counter(row.material_lane for row in expected)
    observed_material_lane_counts = Counter(row.material_lane for row in observed)
    source_versions = {row.source_version_id for row in observed}
    embedding_complete = (
        bool(expected)
        and not missing
        and not unexpected
        and not duplicates
        and not hash_mismatches
        and not source_mismatches
        and not dimension_mismatches
        and not physical_lane_mismatches
        and not material_lane_mismatches
        and not catalogue_lane_mismatches
        and len(observed) == len(expected)
    )
    return {
        "expected_chunks": len(expected),
        "observed_total_rows": len(observed),
        "observed_rows_per_physical_lane": dict(sorted(lane_counts.items())),
        "expected_rows_per_catalogue_lane": dict(sorted(expected_catalogue_lane_counts.items())),
        "observed_rows_per_catalogue_lane": dict(sorted(observed_catalogue_lane_counts.items())),
        "expected_rows_per_material_lane": dict(sorted(expected_material_lane_counts.items())),
        "observed_rows_per_material_lane": dict(sorted(observed_material_lane_counts.items())),
        "observed_source_version_count": len(source_versions),
        "unique_chunk_ids": len(unique_ids),
        "duplicate_chunk_ids": duplicates,
        "missing_expected_chunk_ids": missing,
        "unexpected_chunk_ids": unexpected,
        "content_hash_mismatches": hash_mismatches,
        "vector_dimension_mismatches": dimension_mismatches,
        "source_version_mismatches": source_mismatches,
        "physical_lane_mismatches": physical_lane_mismatches,
        "material_lane_mismatches": material_lane_mismatches,
        "catalogue_lane_mismatches": catalogue_lane_mismatches,
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
        if actual.material_lane != wanted.material_lane:
            fields.append("material_lane")
        if actual.catalogue_lane != wanted.catalogue_lane:
            fields.append("catalogue_lane")
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
    manifest_lane_bindings = source_lane_bindings_for_manifest(manifest)
    manifest_source_ids = tuple(binding.source_version_id for binding in manifest_lane_bindings)
    source_version_id_binding_match = source_ids == manifest_source_ids
    expected_lane_binding_json = [binding.as_dict() for binding in manifest_lane_bindings]
    queued_lane_binding_raw = request.get("source_lane_bindings")
    if queued_lane_binding_raw is None and manifest.get("selection_policy") != GE_SELECTION_POLICY:
        # Pre-binding ordinary jobs are unambiguously authority-only and remain
        # auditable without retroactively changing their frozen request bytes.
        queued_lane_bindings = manifest_lane_bindings
    else:
        try:
            queued_lane_bindings = parse_source_lane_bindings(queued_lane_binding_raw)
        except ValueError:
            queued_lane_bindings = ()
    source_lane_binding_match = (
        [binding.as_dict() for binding in queued_lane_bindings] == expected_lane_binding_json
    )
    if expected_rows is None:
        expected_rows = load_expected_index_rows(
            database,
            source_ids=manifest_source_ids,
            allowlists=manifest.get("locator_allowlists") or {},
            prompt_safe=_prompt_safe_index_text,
            source_lane_bindings=manifest_lane_bindings,
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
        and bool(source_version_id_binding_match)
        and bool(source_lane_binding_match)
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
        "physical_lane_mismatches": _bounded_ids(comparison["physical_lane_mismatches"]),
        "material_lane_mismatches": _bounded_ids(comparison["material_lane_mismatches"]),
        "catalogue_lane_mismatches": _bounded_ids(comparison["catalogue_lane_mismatches"]),
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
        "source_version_id_binding_match": source_version_id_binding_match,
        "source_lane_binding_match": source_lane_binding_match,
        "authority_lane_only": manifest.get("authority_lane_only") is True,
        "approved_legal_source_lanes_only": (
            manifest.get("approved_legal_source_lanes_only") is True
        ),
        "allowed_catalogue_lanes": sorted(
            {binding.catalogue_lane for binding in manifest_lane_bindings}
        ),
        "source_lane_bindings": expected_lane_binding_json,
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
            and source_version_id_binding_match
            and source_lane_binding_match
            and ordered_prefix["exact_ordered_prefix"]
            and checkpoint_prefix["checkpoint_prefix_match"]
            and checkpoint_prefix["checkpoint_trails_observed_rows"]
        ),
        "expected_chunks": comparison["expected_chunks"],
        "observed_total_rows": comparison["observed_total_rows"],
        "observed_rows_per_physical_lane": comparison["observed_rows_per_physical_lane"],
        "expected_rows_per_catalogue_lane": comparison["expected_rows_per_catalogue_lane"],
        "observed_rows_per_catalogue_lane": comparison["observed_rows_per_catalogue_lane"],
        "expected_rows_per_material_lane": comparison["expected_rows_per_material_lane"],
        "observed_rows_per_material_lane": comparison["observed_rows_per_material_lane"],
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
