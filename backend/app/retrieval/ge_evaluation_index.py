"""Evaluation-only access to one sealed, non-ACTIVE GE successor index.

This module deliberately does not use ACTIVE/PREVIOUS, candidate promotion,
the live RetrievalService, or retrieval-v1 gold binding.  Every open and every
search replays the exact visible-GE runtime capability and the held-index
custody chain.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from ..config import Settings
from ..contracts import ContractSchemaRegistry, canonical_json_bytes, load_json_strict
from ..db import Database
from ..evaluation.visible_ge_admission import (
    VisibleGEExecutionBinding,
    require_visible_ge_evaluation_capability,
)
from ..ingestion.models import MaterialLane
from .explicit_reference import CandidateLegislationReferenceResolver
from .hybrid import HybridRetriever
from .incomplete_index_audit import (
    GE_SELECTION_POLICY,
    source_lane_bindings_for_manifest,
)
from .index_build import (
    IndexBuildContext,
    _require_enqueued_source_manifest_unchanged,
    _verify_held_ge_successor_tree,
)
from .models import SearchHit, SearchQuery
from .source_manifest import approved_source_manifest_sha256, source_version_ids

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VERIFIED_VISIBLE_GE_INDEX_CAPABILITY_TOKEN = object()
_GE_EVALUATION_INDEX_FACTORY_TOKEN = object()


@dataclass(frozen=True, slots=True)
class VerifiedGEEvaluationIndexBinding:
    build_id: str
    corpus_id: str
    held_seal_sha256: str
    source_manifest_sha256: str
    source_scope_sha256: str
    source_scope_owner_approval_sha256: str
    build_authorization_decision_id: str
    build_authorization_decision_id_sha256: str
    build_authorization_request_sha256: str
    build_authorization_sha256: str
    source_intake_chain_sha256: str
    capability_manifest_sha256: str
    allowed_material_lanes: frozenset[MaterialLane]


class VisibleGEIndexCapabilityContext:
    """Opaque proof over frozen visible-GE runtime-capability inputs."""

    _binding: VisibleGEExecutionBinding
    _expected_config_sha256: str
    _expected_environment_sha256: str
    _expected_manifest_sha256: str
    _expected_process_instance_id: str
    _issued_capability_sha256: str
    _manifest_bytes: bytes
    _registry_manifest_sha256: str
    _registry_schema_dir: Path
    _token: object

    __slots__ = (
        "_binding",
        "_expected_config_sha256",
        "_expected_environment_sha256",
        "_expected_manifest_sha256",
        "_expected_process_instance_id",
        "_issued_capability_sha256",
        "_manifest_bytes",
        "_registry_manifest_sha256",
        "_registry_schema_dir",
        "_token",
    )

    def __init__(
        self,
        *,
        manifest_bytes: bytes,
        expected_manifest_sha256: str,
        expected_process_instance_id: str,
        expected_config_sha256: str,
        expected_environment_sha256: str,
        binding: VisibleGEExecutionBinding,
        registry: ContractSchemaRegistry,
        issued_capability_sha256: str,
        _token: object,
    ) -> None:
        if _token is not _VERIFIED_VISIBLE_GE_INDEX_CAPABILITY_TOKEN:
            raise TypeError("visible GE index capability is verifier-issued only")
        object.__setattr__(self, "_manifest_bytes", manifest_bytes)
        object.__setattr__(self, "_expected_manifest_sha256", expected_manifest_sha256)
        object.__setattr__(
            self,
            "_expected_process_instance_id",
            expected_process_instance_id,
        )
        object.__setattr__(self, "_expected_config_sha256", expected_config_sha256)
        object.__setattr__(
            self,
            "_expected_environment_sha256",
            expected_environment_sha256,
        )
        object.__setattr__(self, "_binding", binding)
        object.__setattr__(self, "_registry_manifest_sha256", registry.manifest_sha256)
        object.__setattr__(self, "_registry_schema_dir", registry.schema_dir.resolve(strict=True))
        object.__setattr__(self, "_issued_capability_sha256", issued_capability_sha256)
        object.__setattr__(self, "_token", _token)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("visible GE index capability inputs are frozen")

    def __delattr__(self, name: str) -> None:
        del name
        raise AttributeError("visible GE index capability inputs are frozen")

    def __init_subclass__(cls, **kwargs: Any) -> None:
        del kwargs
        raise TypeError("visible GE index capability cannot be subclassed")

    def __repr__(self) -> str:
        return "<VisibleGEIndexCapabilityContext>"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _replay_visible_ge_index_capability(
    capability: VisibleGEIndexCapabilityContext,
) -> tuple[str, VisibleGEExecutionBinding]:
    """Replay one exact proof without dispatching to caller-controlled methods."""

    if (
        type(capability) is not VisibleGEIndexCapabilityContext
        or capability._token is not _VERIFIED_VISIBLE_GE_INDEX_CAPABILITY_TOKEN
    ):
        raise TypeError("visible GE index capability is not verifier-issued")
    if (
        type(capability._binding) is not VisibleGEExecutionBinding
    ):
        raise TypeError("visible GE index capability contains an untrusted verifier type")
    registry = ContractSchemaRegistry(capability._registry_schema_dir)
    if registry.manifest_sha256 != capability._registry_manifest_sha256:
        raise RuntimeError("visible GE index capability schema registry changed after issue")
    decoded = load_json_strict(capability._manifest_bytes)
    if not isinstance(decoded, dict):
        raise RuntimeError("visible GE index capability manifest is not an object")
    observed = require_visible_ge_evaluation_capability(
        decoded,
        expected_manifest_sha256=capability._expected_manifest_sha256,
        expected_process_instance_id=capability._expected_process_instance_id,
        expected_config_sha256=capability._expected_config_sha256,
        expected_environment_sha256=capability._expected_environment_sha256,
        binding=capability._binding,
        now=_utc_now(),
        registry=registry,
    )
    if observed != capability._issued_capability_sha256:
        raise RuntimeError("visible GE index capability changed after issue")
    return observed, capability._binding


def issue_visible_ge_index_capability(
    manifest: Mapping[str, Any],
    *,
    expected_manifest_sha256: str,
    expected_process_instance_id: str,
    expected_config_sha256: str,
    expected_environment_sha256: str,
    binding: VisibleGEExecutionBinding,
    registry: ContractSchemaRegistry,
) -> VisibleGEIndexCapabilityContext:
    """Verify and freeze one visible-GE capability for held-index access."""

    if type(binding) is not VisibleGEExecutionBinding:
        raise TypeError("visible GE execution binding must be the exact trusted type")
    if type(registry) is not ContractSchemaRegistry:
        raise TypeError("visible GE schema registry must be the exact trusted type")
    manifest_bytes = canonical_json_bytes(manifest)
    decoded = load_json_strict(manifest_bytes)
    if not isinstance(decoded, dict):
        raise ValueError("visible GE index capability manifest must be an object")
    observed = require_visible_ge_evaluation_capability(
        decoded,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_process_instance_id=expected_process_instance_id,
        expected_config_sha256=expected_config_sha256,
        expected_environment_sha256=expected_environment_sha256,
        binding=binding,
        now=_utc_now(),
        registry=registry,
    )
    return VisibleGEIndexCapabilityContext(
        manifest_bytes=manifest_bytes,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_process_instance_id=expected_process_instance_id,
        expected_config_sha256=expected_config_sha256,
        expected_environment_sha256=expected_environment_sha256,
        binding=binding,
        registry=registry,
        issued_capability_sha256=observed,
        _token=_VERIFIED_VISIBLE_GE_INDEX_CAPABILITY_TOKEN,
    )


class GEEvaluationIndex:
    """Bound hybrid retriever that cannot be reused outside visible GE evaluation."""

    binding: VerifiedGEEvaluationIndexBinding
    _capability: VisibleGEIndexCapabilityContext
    _connection: Any
    _require_owner_authorization: Callable[[], None]
    _retriever: HybridRetriever

    __slots__ = (
        "_capability",
        "_connection",
        "_require_owner_authorization",
        "_retriever",
        "binding",
    )

    def __init__(
        self,
        *,
        binding: VerifiedGEEvaluationIndexBinding,
        capability: VisibleGEIndexCapabilityContext,
        retriever: HybridRetriever,
        require_owner_authorization: Callable[[], None],
        connection: Any,
        _token: object | None = None,
    ) -> None:
        if (
            type(self) is not GEEvaluationIndex
            or _token is not _GE_EVALUATION_INDEX_FACTORY_TOKEN
            or type(binding) is not VerifiedGEEvaluationIndexBinding
            or type(capability) is not VisibleGEIndexCapabilityContext
        ):
            raise TypeError("GE evaluation index is factory-issued only")
        object.__setattr__(self, "binding", binding)
        object.__setattr__(self, "_capability", capability)
        object.__setattr__(self, "_retriever", retriever)
        object.__setattr__(self, "_require_owner_authorization", require_owner_authorization)
        object.__setattr__(self, "_connection", connection)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("GE evaluation index binding is frozen")

    def __delattr__(self, name: str) -> None:
        del name
        raise AttributeError("GE evaluation index binding is frozen")

    def __init_subclass__(cls, **kwargs: Any) -> None:
        del kwargs
        raise TypeError("GE evaluation index cannot be subclassed")

    def search(self, query: SearchQuery) -> tuple[SearchHit, ...]:
        observed, _binding = _replay_visible_ge_index_capability(self._capability)
        if observed != self.binding.capability_manifest_sha256:
            raise RuntimeError("GE evaluation capability changed after index open")
        self._require_owner_authorization()
        query.validate()
        if (
            not query.filters.material_lanes
            or not query.filters.material_lanes.issubset(self.binding.allowed_material_lanes)
            or query.filters.review_states != frozenset({"approved"})
        ):
            raise ValueError("GE evaluation query exceeds the held legal-source lanes")
        return self._retriever.search(query)


def _json_object(value: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RuntimeError("GE held-index JSON is invalid") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError("GE held-index JSON is not an object")
    return decoded


def _required_ge_index_artifacts(
    binding: VisibleGEExecutionBinding,
) -> tuple[str, str, str, str, str, str]:
    values = (
        str(binding.ge_held_index_seal_sha256 or ""),
        str(binding.ge_source_manifest_sha256 or ""),
        str(binding.ge_source_scope_sha256 or ""),
        str(binding.ge_index_build_authorization_sha256 or ""),
        str(binding.ge_index_build_owner_decision_id_sha256 or ""),
        str(binding.ge_source_intake_chain_sha256 or ""),
    )
    if any(_SHA256_RE.fullmatch(value) is None for value in values):
        raise RuntimeError("visible GE capability lacks the exact held-index artifact set")
    return values


def verify_ge_evaluation_index(
    settings: Settings,
    database: Database,
    *,
    build_id: str,
    capability: VisibleGEIndexCapabilityContext,
) -> VerifiedGEEvaluationIndexBinding:
    """Verify one immutable held index against its job and visible-GE authority."""

    capability_sha256, capability_binding = _replay_visible_ge_index_capability(capability)
    (
        expected_seal_sha256,
        expected_source_manifest_sha256,
        expected_scope_sha256,
        expected_build_authorization_sha256,
        expected_decision_id_sha256,
        expected_intake_chain_sha256,
    ) = _required_ge_index_artifacts(capability_binding)
    build = database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))
    if build is None:
        raise ValueError("GE evaluation index build is absent")
    if (
        str(build["status"]) != "built_unscored"
        or str(build["promotion_decision"] or "") != "not_requested"
        or build["promoted_at"] is not None
        or str(build["candidate_manifest_hash"] or "") != expected_seal_sha256
        or str(build["manifest_sha256"] or "") != expected_seal_sha256
    ):
        raise RuntimeError("GE evaluation index is not sealed non-ACTIVE held evidence")
    job_id = str(build["job_id"] or f"index-{build_id}")
    job = database.job(job_id)
    if job is None or str(job["status"]) != "complete":
        raise RuntimeError("GE evaluation index job is not immutably complete")
    request = _json_object(str(job["request_json"] or "{}"))
    decision_id = str(request.get("ge_index_build_owner_decision_id") or "")
    if (
        request.get("build_id") != build_id
        or request.get("corpus_id") != build["corpus_id"]
        or request.get("ge_index_build_owner_decision_content_sha256")
        != expected_build_authorization_sha256
        or hashlib.sha256(decision_id.encode("utf-8")).hexdigest()
        != expected_decision_id_sha256
        or request.get("ge_source_intake_chain_sha256")
        != expected_intake_chain_sha256
        or request.get("ge_source_scope_content_sha256") != expected_scope_sha256
        or request.get("successor_must_remain_non_active") is not True
    ):
        raise RuntimeError("GE evaluation index request authority differs")
    final = settings.index_dir / "builds" / build_id
    source_path = final / "approved-source-manifest.json"
    if final.is_symlink() or source_path.is_symlink() or not source_path.is_file():
        raise RuntimeError("GE evaluation index source manifest is unavailable")
    source_manifest = _json_object(source_path.read_text(encoding="utf-8"))
    if (
        source_manifest.get("selection_policy") != GE_SELECTION_POLICY
        or source_manifest.get("manifest_sha256") != expected_source_manifest_sha256
        or approved_source_manifest_sha256(source_manifest) != expected_source_manifest_sha256
        or source_manifest.get("ge_source_scope_content_sha256") != expected_scope_sha256
        or source_manifest.get("ge_source_scope_owner_approval_digest")
        != request.get("ge_source_scope_owner_approval_digest")
    ):
        raise RuntimeError("GE evaluation index source identity differs")
    try:
        counts = _json_object(str(build["counts_json"] or "{}"))
    except RuntimeError:
        counts = {}
    ctx = IndexBuildContext(
        settings=settings,
        database=database,
        job_id=job_id,
        build_id=build_id,
        corpus_id=str(build["corpus_id"]),
        manifest=source_manifest,
        source_ids=source_version_ids(source_manifest),
        embedding_model=str(build["embedding_model"]),
        reranker_model=str(build["reranker_model"]),
        build_dir=final,
        timings={},
        counts=counts,
        release_pointer_snapshot=(
            request.get("release_pointer_snapshot_at_enqueue")
            if isinstance(request.get("release_pointer_snapshot_at_enqueue"), dict)
            else None
        ),
    )
    _require_enqueued_source_manifest_unchanged(ctx, request)
    _verify_held_ge_successor_tree(
        ctx,
        final,
        expected_seal_sha256=expected_seal_sha256,
    )
    material_lanes = frozenset(
        MaterialLane(binding.material_lane)
        for binding in source_lane_bindings_for_manifest(source_manifest)
    )
    if not material_lanes or not material_lanes.issubset(
        {
            MaterialLane.PRIMARY_AUTHORITY,
            MaterialLane.OFFICIAL_GUIDANCE,
            MaterialLane.PROCEDURE_RULE,
        }
    ):
        raise RuntimeError("GE evaluation index material-lane set is invalid")
    return VerifiedGEEvaluationIndexBinding(
        build_id=build_id,
        corpus_id=str(build["corpus_id"]),
        held_seal_sha256=expected_seal_sha256,
        source_manifest_sha256=expected_source_manifest_sha256,
        source_scope_sha256=expected_scope_sha256,
        source_scope_owner_approval_sha256=str(
            source_manifest["ge_source_scope_owner_approval_digest"]
        ),
        build_authorization_decision_id=decision_id,
        build_authorization_decision_id_sha256=expected_decision_id_sha256,
        build_authorization_request_sha256=str(
            request["ge_index_build_owner_decision_request_sha256"]
        ),
        build_authorization_sha256=expected_build_authorization_sha256,
        source_intake_chain_sha256=expected_intake_chain_sha256,
        capability_manifest_sha256=capability_sha256,
        allowed_material_lanes=material_lanes,
    )


def open_ge_evaluation_index(
    settings: Settings,
    database: Database,
    *,
    build_id: str,
    as_of_date: date,
    capability: VisibleGEIndexCapabilityContext,
) -> GEEvaluationIndex:
    """Open only the legal-source table after replaying every GE-specific gate."""

    verified = verify_ge_evaluation_index(
        settings,
        database,
        build_id=build_id,
        capability=capability,
    )
    build = database.fetchone(
        "SELECT embedding_model,reranker_model,chunk_count FROM index_builds WHERE id=?",
        (build_id,),
    )
    if build is None:  # pragma: no cover - verified above in the same local database
        raise RuntimeError("GE evaluation index build disappeared")
    from .service import (
        PHYSICAL_AUTHORITY_LANE,
        _embedding_provider,
        _import_lancedb,
        _LanceLexicalBackend,
        _LanceVectorBackend,
        _reranker_provider,
    )

    lane_path = settings.index_dir / "builds" / build_id / "lance" / PHYSICAL_AUTHORITY_LANE
    module = _import_lancedb()
    connection = module.connect(str(lane_path))
    table = connection.open_table("chunks")
    count_rows = getattr(table, "count_rows", None)
    expected_rows = int(build["chunk_count"] or 0)
    if (
        not callable(count_rows)
        or expected_rows < 1
        or int(count_rows()) != expected_rows
    ):
        raise RuntimeError("GE evaluation legal-source table count differs from its held seal")
    embedder = _embedding_provider(settings, str(build["embedding_model"]))
    reranker = _reranker_provider(settings, str(build["reranker_model"]))
    reference_resolver = CandidateLegislationReferenceResolver.from_path(
        settings.index_dir / "builds" / build_id / "approved-source-manifest.json"
    )
    retriever = HybridRetriever(
        embedder=embedder,
        lexical_backend=_LanceLexicalBackend(table, as_of_date),
        vector_backend=_LanceVectorBackend(table, as_of_date),
        reranker=reranker,
        reference_resolver=reference_resolver,
    )

    def require_owner_authorization() -> None:
        current = verify_ge_evaluation_index(
            settings,
            database,
            build_id=build_id,
            capability=capability,
        )
        if current != verified:
            raise RuntimeError("GE evaluation held-index binding changed after index open")

    return GEEvaluationIndex(
        binding=verified,
        capability=capability,
        retriever=retriever,
        require_owner_authorization=require_owner_authorization,
        connection=connection,
        _token=_GE_EVALUATION_INDEX_FACTORY_TOKEN,
    )


__all__ = [
    "GEEvaluationIndex",
    "VerifiedGEEvaluationIndexBinding",
    "VisibleGEIndexCapabilityContext",
    "issue_visible_ge_index_capability",
    "open_ge_evaluation_index",
    "verify_ge_evaluation_index",
]
