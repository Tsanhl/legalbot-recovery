"""Owner-gated authority for one exact non-ACTIVE GE successor index.

The GE source-scope document remains a non-authorising review artifact.  A
build may use it only after this module replays a create-only owner decision
whose request binds the exact scope, source manifest, intake chain, and lane
inventory.  Self-sealed request/resolution JSON is deliberately insufficient:
an action-specific trusted signature verifier must also succeed.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from ..config import Settings
from ..db import Database
from ..governance.owner_stop import (
    OwnerDecisionRequest,
    OwnerDecisionResolution,
    require_owner_resolution,
    seal_owner_decision_request,
)
from ..governance.v111_decision_generation import read_private_owner_decision_member
from .ge_source_scope import load_ge_source_scope, validate_ge_source_scope
from .incomplete_index_audit import GE_SELECTION_POLICY, source_lane_bindings_for_manifest
from .source_manifest import approved_source_manifest_sha256

GE_INDEX_BUILD_APPROVE_OPTION = "approve-exact-ge-scope-and-held-index-build"
GE_INDEX_BUILD_DECISION_PURPOSE = "exact_non_active_ge_successor_index_build"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_VERIFIED_GE_INDEX_BUILD_AUTHORIZATION_TOKEN = object()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _require_sha256(value: Any, *, code: str) -> str:
    digest = str(value or "")
    if _SHA256_RE.fullmatch(digest) is None:
        raise ValueError(code)
    return digest


@dataclass(frozen=True, slots=True)
class GEIndexBuildDecisionBinding:
    """Path-free identities covered by the owner's exact decision."""

    build_id: str
    corpus_id: str
    source_scope_content_sha256: str
    source_scope_owner_approval_sha256: str
    source_manifest_sha256: str
    source_version_id_set_sha256: str
    source_lane_binding_sha256: str
    intake_chain_sha256: str
    expansion_mode: str
    predecessor_build_id: str
    predecessor_index_build_record_sha256: str
    predecessor_seal_sha256: str
    predecessor_build_manifest_sha256: str
    predecessor_source_manifest_file_sha256: str
    predecessor_source_manifest_sha256: str
    predecessor_source_version_id_set_sha256: str
    predecessor_member_set_sha256: str
    predecessor_member_sequence_sha256: str
    predecessor_source_count: int
    predecessor_chunk_count: int
    added_source_version_id_set_sha256: str
    added_member_set_sha256: str
    added_source_count: int
    added_chunk_count: int
    successor_member_set_sha256: str
    successor_member_sequence_sha256: str
    successor_source_count: int
    successor_chunk_count: int
    preservation_proof_sha256: str


class VerifiedGEIndexBuildAuthorization:
    """Opaque proof that the stored owner decision was replayed successfully."""

    __slots__ = (
        "binding",
        "decision_id",
        "request_content_sha256",
        "resolution_content_sha256",
    )

    def __init__(
        self,
        *,
        binding: GEIndexBuildDecisionBinding,
        decision_id: str,
        request_content_sha256: str,
        resolution_content_sha256: str,
        _token: object,
    ) -> None:
        if _token is not _VERIFIED_GE_INDEX_BUILD_AUTHORIZATION_TOKEN:
            raise TypeError("GE index-build authorization is verifier-issued only")
        self.binding = binding
        self.decision_id = decision_id
        self.request_content_sha256 = request_content_sha256
        self.resolution_content_sha256 = resolution_content_sha256

    def __repr__(self) -> str:
        return "<VerifiedGEIndexBuildAuthorization>"


def ge_source_intake_chain_sha256(scope: Mapping[str, Any]) -> str:
    """Digest every exact source-intake/currentness/rights link in the scope."""

    validate_ge_source_scope(scope, require_approved=True)
    sources = scope.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("ge_index_build_scope_sources_invalid")
    chain: list[dict[str, Any]] = []
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("ge_index_build_scope_sources_invalid")
        chain.append(
            {
                "source_version_id": source.get("source_version_id"),
                "catalogue_lane": source.get("catalogue_lane"),
                "scope_lane": source.get("scope_lane"),
                "content_sha256": source.get("content_sha256"),
                "version_sha256": source.get("version_sha256"),
                "record_content_sha256": source.get("record_content_sha256"),
                "catalogue_review_binding_sha256": source.get(
                    "catalogue_review_binding_sha256"
                ),
                "currentness_binding_sha256": source.get("currentness_binding_sha256"),
                "rights_binding_sha256": source.get("rights_binding_sha256"),
                "research_intake_binding_sha256": source.get(
                    "research_intake_binding_sha256"
                ),
                "research_intake_marker_sha256": source.get(
                    "research_intake_marker_sha256"
                ),
                "ge_source_provenance_chain_sha256": source.get(
                    "ge_source_provenance_chain_sha256"
                ),
                "ge_source_provenance_component_sha256": source.get(
                    "ge_source_provenance_component_sha256"
                ),
                "research_owner_review_manifest_sha256": source.get(
                    "research_owner_review_manifest_sha256"
                ),
                "research_rights_state": source.get("research_rights_state"),
            }
        )
    return _sha256(
        {
            "schema": "legalbot.ge-source-intake-chain.v1",
            "scope_content_sha256": scope["scope_content_sha256"],
            "predecessor_proof_sha256": scope["predecessor"]["content_sha256"],
            "predecessor_member_set_sha256": scope[
                "predecessor_member_set_sha256"
            ],
            "added_member_set_sha256": scope["added_member_set_sha256"],
            "successor_member_set_sha256": scope["successor_member_set_sha256"],
            "preservation_proof_sha256": scope["preservation_proof_sha256"],
            "sources": chain,
        }
    )


def ge_index_build_decision_binding(
    settings: Settings,
    database: Database,
    manifest: Mapping[str, Any],
    *,
    build_id: str,
) -> GEIndexBuildDecisionBinding:
    """Derive the exact owner-decision inputs from one validated GE manifest."""

    if _SAFE_ID_RE.fullmatch(build_id) is None:
        raise ValueError("ge_index_build_id_invalid")
    if manifest.get("selection_policy") != GE_SELECTION_POLICY:
        raise ValueError("ge_index_build_manifest_policy_invalid")
    manifest_sha256 = _require_sha256(
        manifest.get("manifest_sha256"), code="ge_index_build_manifest_sha256_invalid"
    )
    if approved_source_manifest_sha256(manifest) != manifest_sha256:
        raise ValueError("ge_index_build_manifest_seal_invalid")
    corpus_id = str(manifest.get("corpus_id") or "")
    if _SAFE_ID_RE.fullmatch(corpus_id) is None:
        raise ValueError("ge_index_build_corpus_id_invalid")
    scope = load_ge_source_scope(settings, database, corpus_id)
    scope_sha256 = _require_sha256(
        scope.get("scope_content_sha256"), code="ge_index_build_scope_sha256_invalid"
    )
    owner_approval_sha256 = _require_sha256(
        scope.get("owner_approval_digest"),
        code="ge_index_build_scope_owner_approval_invalid",
    )
    source_set_sha256 = _require_sha256(
        scope.get("source_version_id_set_sha256"),
        code="ge_index_build_source_set_sha256_invalid",
    )
    if (
        manifest.get("ge_expansion_mode") != "strict_successor"
        or
        manifest.get("ge_source_scope_content_sha256") != scope_sha256
        or manifest.get("ge_source_scope_owner_approval_digest")
        != owner_approval_sha256
        or manifest.get("ge_source_version_id_set_sha256") != source_set_sha256
        or manifest.get("ge_predecessor_build_id")
        != scope.get("predecessor_build_id")
        or manifest.get("ge_predecessor_seal_sha256")
        != scope.get("predecessor_seal_sha256")
        or manifest.get("ge_predecessor_build_manifest_sha256")
        != scope.get("predecessor_build_manifest_sha256")
        or manifest.get("ge_predecessor_source_manifest_file_sha256")
        != scope.get("predecessor_source_manifest_file_sha256")
        or manifest.get("ge_predecessor_source_manifest_sha256")
        != scope.get("predecessor_source_manifest_sha256")
        or manifest.get("ge_predecessor_index_build_record_sha256")
        != scope.get("predecessor_index_build_record_sha256")
        or manifest.get("ge_predecessor_source_version_id_set_sha256")
        != scope.get("predecessor_source_version_id_set_sha256")
        or manifest.get("ge_predecessor_member_set_sha256")
        != scope.get("predecessor_member_set_sha256")
        or manifest.get("ge_predecessor_member_sequence_sha256")
        != scope.get("predecessor_member_sequence_sha256")
        or manifest.get("ge_added_source_version_id_set_sha256")
        != scope.get("added_source_version_id_set_sha256")
        or manifest.get("ge_added_member_set_sha256")
        != scope.get("added_member_set_sha256")
        or manifest.get("ge_successor_member_set_sha256")
        != scope.get("successor_member_set_sha256")
        or manifest.get("ge_successor_member_sequence_sha256")
        != scope.get("successor_member_sequence_sha256")
        or manifest.get("ge_preservation_proof_sha256")
        != scope.get("preservation_proof_sha256")
        or manifest.get("ge_source_lane_bindings")
        != scope.get("source_lane_bindings")
        or manifest.get("ge_predecessor_source_count")
        != scope.get("predecessor_source_count")
        or manifest.get("ge_predecessor_chunk_count")
        != scope.get("predecessor_chunk_count")
        or manifest.get("ge_added_source_count") != scope.get("added_source_count")
        or manifest.get("ge_added_chunk_count") != scope.get("added_chunk_count")
        or manifest.get("source_count") != scope.get("source_count")
        or manifest.get("chunk_count") != scope.get("chunk_count")
    ):
        raise ValueError("ge_index_build_scope_manifest_binding_invalid")
    bindings = source_lane_bindings_for_manifest(manifest)
    scope_sources = scope.get("sources")
    if not isinstance(scope_sources, list):
        raise ValueError("ge_index_build_scope_sources_invalid")
    expected_added_members = [
        {
            "source_version_id": str(source.get("source_version_id") or ""),
            "catalogue_lane": str(source.get("catalogue_lane") or ""),
            "scope_lane": str(source.get("scope_lane") or ""),
            "record_content_sha256": str(source.get("record_content_sha256") or ""),
        }
        for source in scope_sources
        if isinstance(source, dict)
    ]
    predecessor = scope.get("predecessor")
    if not isinstance(predecessor, dict) or not isinstance(
        predecessor.get("source_members"), list
    ):
        raise ValueError("ge_index_build_predecessor_members_invalid")
    predecessor_members = predecessor["source_members"]
    predecessor_count = int(scope.get("predecessor_source_count") or 0)
    manifest_sources = manifest.get("sources")
    if not isinstance(manifest_sources, list):
        raise ValueError("ge_index_build_manifest_sources_invalid")
    manifest_added_members = [
        {
            "source_version_id": str(source.get("source_version_id") or ""),
            "catalogue_lane": str(source.get("lane") or ""),
            "scope_lane": str(source.get("ge_scope_lane") or ""),
            "record_content_sha256": str(
                source.get("ge_scope_record_content_sha256") or ""
            ),
        }
        for source in manifest_sources[predecessor_count:]
        if isinstance(source, dict)
    ]
    if (
        manifest_sources[:predecessor_count] != predecessor_members
        or manifest_added_members != expected_added_members
        or [binding.as_dict() for binding in bindings]
        != scope.get("source_lane_bindings")
        or len(manifest_sources) != len(bindings)
    ):
        raise ValueError("ge_index_build_scope_member_binding_invalid")
    lane_binding_sha256 = _sha256(
        {
            "schema": "legalbot.ge-index-source-lane-bindings.v1",
            "bindings": [binding.as_dict() for binding in bindings],
        }
    )
    return GEIndexBuildDecisionBinding(
        build_id=build_id,
        corpus_id=corpus_id,
        source_scope_content_sha256=scope_sha256,
        source_scope_owner_approval_sha256=owner_approval_sha256,
        source_manifest_sha256=manifest_sha256,
        source_version_id_set_sha256=source_set_sha256,
        source_lane_binding_sha256=lane_binding_sha256,
        intake_chain_sha256=ge_source_intake_chain_sha256(scope),
        expansion_mode="strict_successor",
        predecessor_build_id=str(scope["predecessor_build_id"]),
        predecessor_index_build_record_sha256=str(
            scope["predecessor_index_build_record_sha256"]
        ),
        predecessor_seal_sha256=str(scope["predecessor_seal_sha256"]),
        predecessor_build_manifest_sha256=str(
            scope["predecessor_build_manifest_sha256"]
        ),
        predecessor_source_manifest_file_sha256=str(
            scope["predecessor_source_manifest_file_sha256"]
        ),
        predecessor_source_manifest_sha256=str(
            scope["predecessor_source_manifest_sha256"]
        ),
        predecessor_source_version_id_set_sha256=str(
            scope["predecessor_source_version_id_set_sha256"]
        ),
        predecessor_member_set_sha256=str(scope["predecessor_member_set_sha256"]),
        predecessor_member_sequence_sha256=str(
            scope["predecessor_member_sequence_sha256"]
        ),
        predecessor_source_count=int(scope["predecessor_source_count"]),
        predecessor_chunk_count=int(scope["predecessor_chunk_count"]),
        added_source_version_id_set_sha256=str(
            scope["added_source_version_id_set_sha256"]
        ),
        added_member_set_sha256=str(scope["added_member_set_sha256"]),
        added_source_count=int(scope["added_source_count"]),
        added_chunk_count=int(scope["added_chunk_count"]),
        successor_member_set_sha256=str(scope["successor_member_set_sha256"]),
        successor_member_sequence_sha256=str(
            scope["successor_member_sequence_sha256"]
        ),
        successor_source_count=int(scope["source_count"]),
        successor_chunk_count=int(scope["chunk_count"]),
        preservation_proof_sha256=str(scope["preservation_proof_sha256"]),
    )


def ge_index_build_decision_id(binding: GEIndexBuildDecisionBinding) -> str:
    identity = _sha256(
        {
            "schema": "legalbot.ge-index-build-owner-decision-identity.v1",
            "purpose": GE_INDEX_BUILD_DECISION_PURPOSE,
            **asdict(binding),
        }
    )
    return f"ge-held-index-build-{identity[:24]}"


def build_ge_index_build_decision_request(
    *,
    binding: GEIndexBuildDecisionBinding,
    created_at: datetime,
) -> OwnerDecisionRequest:
    """Build the exact owner request; this never creates a resolution."""

    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("GE index-build owner decision timestamp must be timezone-aware")
    decision_id = ge_index_build_decision_id(binding)
    return seal_owner_decision_request(
        decision_id=decision_id,
        category="policy",
        scope_id=f"ge-held-index:{decision_id.rsplit('-', 1)[-1]}",
        reason_codes=(
            "EXACT_GE_SOURCE_SCOPE_OWNER_DECISION_REQUIRED",
            "EXACT_GE_INTAKE_CHAIN_OWNER_DECISION_REQUIRED",
            "STRICT_GE_PREDECESSOR_PRESERVATION_REQUIRED",
            "NON_ACTIVE_HELD_INDEX_BUILD_AUTHORITY_REQUIRED",
        ),
        evidence=(
            {
                "evidence_id": "ge-index-build-identity",
                "kind": "index_build_identity",
                "sha256": hashlib.sha256(binding.build_id.encode("utf-8")).hexdigest(),
                "summary_code": "EXACT_GE_INDEX_BUILD_IDENTITY",
            },
            {
                "evidence_id": "ge-source-scope",
                "kind": "ge_source_scope",
                "sha256": binding.source_scope_content_sha256,
                "summary_code": "EXACT_GE_SOURCE_SCOPE",
            },
            {
                "evidence_id": "ge-source-scope-owner-approval",
                "kind": "owner_scope_approval",
                "sha256": binding.source_scope_owner_approval_sha256,
                "summary_code": "EXACT_SCOPE_APPROVAL_REFERENCE",
            },
            {
                "evidence_id": "ge-approved-source-manifest",
                "kind": "approved_source_manifest",
                "sha256": binding.source_manifest_sha256,
                "summary_code": "EXACT_GE_SOURCE_MANIFEST",
            },
            {
                "evidence_id": "ge-source-version-set",
                "kind": "source_version_set",
                "sha256": binding.source_version_id_set_sha256,
                "summary_code": "EXACT_GE_SOURCE_VERSION_SET",
            },
            {
                "evidence_id": "ge-source-lane-bindings",
                "kind": "source_lane_bindings",
                "sha256": binding.source_lane_binding_sha256,
                "summary_code": "EXACT_GE_SOURCE_LANES",
            },
            {
                "evidence_id": "ge-source-intake-chain",
                "kind": "source_intake_chain",
                "sha256": binding.intake_chain_sha256,
                "summary_code": "EXACT_GE_INTAKE_CHAIN",
            },
            {
                "evidence_id": "ge-predecessor-index-record",
                "kind": "index_build_record",
                "sha256": binding.predecessor_index_build_record_sha256,
                "summary_code": "EXACT_GE_PREDECESSOR_DB_ROW",
            },
            {
                "evidence_id": "ge-predecessor-seal",
                "kind": "index_seal",
                "sha256": binding.predecessor_seal_sha256,
                "summary_code": "EXACT_GE_PREDECESSOR_SEAL",
            },
            {
                "evidence_id": "ge-predecessor-build-manifest",
                "kind": "index_build_manifest",
                "sha256": binding.predecessor_build_manifest_sha256,
                "summary_code": "EXACT_GE_PREDECESSOR_BUILD_MANIFEST",
            },
            {
                "evidence_id": "ge-predecessor-source-manifest-file",
                "kind": "approved_source_manifest_file",
                "sha256": binding.predecessor_source_manifest_file_sha256,
                "summary_code": "EXACT_GE_PREDECESSOR_SOURCE_FILE",
            },
            {
                "evidence_id": "ge-predecessor-source-members",
                "kind": "source_member_sequence",
                "sha256": binding.predecessor_member_sequence_sha256,
                "summary_code": "EXACT_GE_PREDECESSOR_MEMBERS",
            },
            {
                "evidence_id": "ge-added-source-members",
                "kind": "source_member_set",
                "sha256": binding.added_member_set_sha256,
                "summary_code": "NONEMPTY_GE_ADDITIONS",
            },
            {
                "evidence_id": "ge-successor-source-members",
                "kind": "source_member_sequence",
                "sha256": binding.successor_member_sequence_sha256,
                "summary_code": "EXACT_GE_SUCCESSOR_MEMBERS",
            },
            {
                "evidence_id": "ge-predecessor-preservation",
                "kind": "source_preservation_proof",
                "sha256": binding.preservation_proof_sha256,
                "summary_code": "STRICT_GE_SUPERSET_PRESERVATION",
            },
            {
                "evidence_id": "ge-expansion-inventory",
                "kind": "strict_successor_inventory",
                "sha256": _sha256(
                    {
                        "schema": "legalbot.ge-strict-successor-inventory.v1",
                        "expansion_mode": binding.expansion_mode,
                        "predecessor_build_id": binding.predecessor_build_id,
                        "predecessor_source_count": binding.predecessor_source_count,
                        "predecessor_chunk_count": binding.predecessor_chunk_count,
                        "predecessor_member_set_sha256": (
                            binding.predecessor_member_set_sha256
                        ),
                        "predecessor_member_sequence_sha256": (
                            binding.predecessor_member_sequence_sha256
                        ),
                        "added_source_count": binding.added_source_count,
                        "added_chunk_count": binding.added_chunk_count,
                        "added_member_set_sha256": binding.added_member_set_sha256,
                        "successor_source_count": binding.successor_source_count,
                        "successor_chunk_count": binding.successor_chunk_count,
                        "successor_member_set_sha256": (
                            binding.successor_member_set_sha256
                        ),
                        "successor_member_sequence_sha256": (
                            binding.successor_member_sequence_sha256
                        ),
                        "preservation_proof_sha256": (
                            binding.preservation_proof_sha256
                        ),
                    }
                ),
                "summary_code": "EXACT_GE_EXPANSION_COUNTS_AND_MEMBERS",
            },
            {
                "evidence_id": "ge-corpus-identity",
                "kind": "corpus_identity",
                "sha256": hashlib.sha256(binding.corpus_id.encode("utf-8")).hexdigest(),
                "summary_code": "EXACT_GE_CORPUS_IDENTITY",
            },
        ),
        options=(
            {
                "option_id": "keep-ge-scope-and-index-build-closed",
                "outcome_code": "KEEP_GE_INDEX_BUILD_CLOSED",
                "recommended": True,
                "consequence_codes": (
                    "NO_INDEX_ENQUEUE",
                    "NO_INDEX_BUILD",
                    "NO_EVALUATION_INDEX_USE",
                ),
            },
            {
                "option_id": GE_INDEX_BUILD_APPROVE_OPTION,
                "outcome_code": "AUTHORIZE_EXACT_NON_ACTIVE_GE_INDEX_BUILD",
                "recommended": False,
                "consequence_codes": (
                    "EXACT_SOURCE_SCOPE_ONLY",
                    "EXACT_INTAKE_CHAIN_ONLY",
                    "STRICT_PREDECESSOR_SOURCE_PRESERVATION",
                    "NONEMPTY_PROVENANCE_QUALIFIED_ADDITIONS",
                    "NON_ACTIVE_UNSCORED_HELD_EVIDENCE_ONLY",
                    "NO_PROMOTION_OR_POINTER_WRITE",
                ),
            },
        ),
        blocked_actions=(
            "ge-index-enqueue",
            "ge-index-build",
            "ge-index-recovery",
            "ge-evaluation-index-open",
        ),
        created_at=created_at,
    )


def _verify_trusted_ge_index_build_authorization_signature(
    _request: OwnerDecisionRequest,
    _resolution: OwnerDecisionResolution,
) -> None:
    """Bootstrap seam: self-sealed JSON cannot supply owner authority."""

    raise PermissionError(
        "OWNER_DECISION_REQUIRED:trusted_ge_index_build_authorization_verifier_missing"
    )


def load_verified_ge_index_build_authorization(
    settings: Settings,
    database: Database,
    *,
    manifest: Mapping[str, Any],
    build_id: str,
    decision_id: str,
    decision_content_sha256: str,
) -> VerifiedGEIndexBuildAuthorization:
    """Replay the exact immutable owner decision and return an opaque proof."""

    supplied_content_sha256 = _require_sha256(
        decision_content_sha256,
        code="ge_index_build_decision_content_sha256_invalid",
    )
    binding = ge_index_build_decision_binding(
        settings, database, manifest, build_id=build_id
    )
    expected_decision_id = ge_index_build_decision_id(binding)
    if decision_id != expected_decision_id:
        raise PermissionError("OWNER_DECISION_REQUIRED:ge_index_build_decision_id_mismatch")

    def read_pair() -> tuple[OwnerDecisionRequest, OwnerDecisionResolution]:
        try:
            request = OwnerDecisionRequest.model_validate_json(
                read_private_owner_decision_member(
                    settings.owner_decision_root, decision_id, "request.json"
                )
            )
            resolution = OwnerDecisionResolution.model_validate_json(
                read_private_owner_decision_member(
                    settings.owner_decision_root, decision_id, "resolution.json"
                )
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise PermissionError(
                "OWNER_DECISION_REQUIRED:ge_index_build_decision_unavailable"
            ) from exc
        return request, resolution

    request, resolution = read_pair()
    expected_request = build_ge_index_build_decision_request(
        binding=binding,
        created_at=request.created_at,
    )
    if request != expected_request:
        raise PermissionError("OWNER_DECISION_REQUIRED:ge_index_build_request_binding_invalid")
    try:
        verified_resolution = require_owner_resolution(request, resolution)
    except PermissionError as exc:
        raise PermissionError(
            "OWNER_DECISION_REQUIRED:ge_index_build_resolution_binding_invalid"
        ) from exc
    if (
        verified_resolution.selected_option_id != GE_INDEX_BUILD_APPROVE_OPTION
        or verified_resolution.seal_sha256 != supplied_content_sha256
        or verified_resolution.decided_at.tzinfo is None
        or verified_resolution.decided_at.utcoffset() is None
        or verified_resolution.decided_at < request.created_at
    ):
        raise PermissionError("OWNER_DECISION_REQUIRED:ge_index_build_not_authorized")
    _verify_trusted_ge_index_build_authorization_signature(request, verified_resolution)
    final_request, final_resolution = read_pair()
    if final_request != request or final_resolution != verified_resolution:
        raise RuntimeError("GE index-build owner decision changed during verification")
    return VerifiedGEIndexBuildAuthorization(
        binding=binding,
        decision_id=decision_id,
        request_content_sha256=request.seal_sha256,
        resolution_content_sha256=verified_resolution.seal_sha256,
        _token=_VERIFIED_GE_INDEX_BUILD_AUTHORIZATION_TOKEN,
    )


__all__ = [
    "GE_INDEX_BUILD_APPROVE_OPTION",
    "GE_INDEX_BUILD_DECISION_PURPOSE",
    "GEIndexBuildDecisionBinding",
    "VerifiedGEIndexBuildAuthorization",
    "build_ge_index_build_decision_request",
    "ge_index_build_decision_binding",
    "ge_index_build_decision_id",
    "ge_source_intake_chain_sha256",
    "load_verified_ge_index_build_authorization",
]
