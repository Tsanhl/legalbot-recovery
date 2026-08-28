"""Safe owner-review contracts for staged official research.

The service deliberately has no source-approval, index-build or promotion
operation.  Accepted candidates enter a second, ordinary source-intake review;
source-update resolutions can be recorded only against the exact ACTIVE build
whose sealed source manifest demonstrably addresses the reviewed observation.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from ..config import Settings
from ..db import Database
from ..retrieval.lancedb import ImmutableLanceRepository
from ..retrieval.source_manifest import approved_source_manifest_sha256
from .models import OWNER_DECISION_REQUIRED

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVIEWER_REF = re.compile(r"^reviewer:[0-9a-f]{64}$")


class OwnerDecisionRequired(RuntimeError):
    """A rights, identity or currentness judgment must stop for the owner."""

    def __init__(self) -> None:
        super().__init__(OWNER_DECISION_REQUIRED)


@dataclass(frozen=True, slots=True)
class ResearchCandidateOwnerView:
    id: str
    task_id: str
    source_id: str
    source_identity: str
    content_sha256: str | None
    metadata_sha256: str
    status: str
    comparison_state: str | None
    rights_state: str
    system_verification_sha256: str | None
    identity_review_state: str
    currentness_review_state: str
    reviewer_ref: str | None
    review_manifest_sha256: str | None
    intake_review_id: str | None
    content_type: str | None
    disposition: str | None
    network_fetch_state: str | None
    additional_permission_required: bool | None
    owner_decision_required: bool
    has_quarantined_content: bool
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class SourceUpdateOwnerView:
    id: str
    task_id: str
    candidate_id: str | None
    source_id: str
    authority_identity_id: str
    pinned_index_build_id: str | None
    pinned_source_manifest_sha256: str | None
    observed_active_build_id: str | None
    baseline_version_sha256: str | None
    remote_content_sha256: str | None
    comparison_state: str
    stale_active: bool
    scope_kind: str
    legal_locator: str | None
    proposition_sha256: str | None
    materiality_status: str
    review_status: str
    reviewer_ref: str | None
    review_manifest_sha256: str | None
    recompare_required: bool
    change_summary_code: str | None
    created_at: str


class ResearchReviewService:
    """Owner-facing review service over explicit path/text-free projections."""

    def __init__(self, settings: Settings, database: Database) -> None:
        self.settings = settings
        self.database = database

    def candidates(self, *, limit: int = 200) -> tuple[ResearchCandidateOwnerView, ...]:
        return tuple(
            ResearchCandidateOwnerView(
                id=str(row["id"]),
                task_id=str(row["task_id"]),
                source_id=str(row["source_id"]),
                source_identity=str(row["source_identity"]),
                content_sha256=_optional(row["content_sha256"]),
                metadata_sha256=str(row["metadata_sha256"]),
                status=str(row["status"]),
                comparison_state=_optional(row["comparison_state"]),
                rights_state=str(row["rights_state"]),
                system_verification_sha256=_optional(row["system_verification_sha256"]),
                identity_review_state=str(row["identity_review_state"]),
                currentness_review_state=str(row["currentness_review_state"]),
                reviewer_ref=_optional(row["reviewer_ref"]),
                review_manifest_sha256=_optional(row["review_manifest_sha256"]),
                intake_review_id=_optional(row["intake_review_id"]),
                content_type=_optional(row["content_type"]),
                disposition=_optional(row["disposition"]),
                network_fetch_state=_optional(row["network_fetch_state"]),
                additional_permission_required=(
                    bool(row["additional_permission_required"])
                    if row["additional_permission_required"] is not None
                    else None
                ),
                owner_decision_required=bool(row["owner_decision_required"]),
                has_quarantined_content=bool(row["has_quarantined_content"]),
                created_at=str(row["created_at"]),
                updated_at=str(row["updated_at"]),
            )
            for row in self.database.research_candidates(limit=limit)
        )

    def updates(self, *, limit: int = 200) -> tuple[SourceUpdateOwnerView, ...]:
        return tuple(
            SourceUpdateOwnerView(
                id=str(row["id"]),
                task_id=str(row["task_id"]),
                candidate_id=_optional(row["candidate_id"]),
                source_id=str(row["source_id"]),
                authority_identity_id=str(row["authority_identity_id"]),
                pinned_index_build_id=_optional(row["pinned_index_build_id"]),
                pinned_source_manifest_sha256=_optional(row["pinned_source_manifest_sha256"]),
                observed_active_build_id=_optional(row["observed_active_build_id"]),
                baseline_version_sha256=_optional(row["baseline_version_sha256"]),
                remote_content_sha256=_optional(row["remote_content_sha256"]),
                comparison_state=str(row["comparison_state"]),
                stale_active=bool(row["stale_active"]),
                scope_kind=str(row["scope_kind"]),
                legal_locator=_optional(row["legal_locator"]),
                proposition_sha256=_optional(row["proposition_sha256"]),
                materiality_status=str(row["materiality_status"]),
                review_status=str(row["review_status"]),
                reviewer_ref=_optional(row["reviewer_ref"]),
                review_manifest_sha256=_optional(row["review_manifest_sha256"]),
                recompare_required=bool(row["recompare_required"]),
                change_summary_code=_optional(row["change_summary_code"]),
                created_at=str(row["created_at"]),
            )
            for row in self.database.source_update_observations(limit=limit)
        )

    def system_verify_candidate(self, candidate_id: str) -> str:
        """Seal the path-free candidate envelope for subsequent owner review."""

        row = self._candidate(candidate_id)
        payload = {
            "schema": "legalbot.research-candidate-system-verification.v1",
            "candidate_id": row.id,
            "task_id": row.task_id,
            "source_id": row.source_id,
            "source_identity": row.source_identity,
            "content_sha256": row.content_sha256,
            "metadata_sha256": row.metadata_sha256,
            "status": row.status,
            "comparison_state": row.comparison_state,
            "rights_state": row.rights_state,
            "content_type": row.content_type,
            "disposition": row.disposition,
            "network_fetch_state": row.network_fetch_state,
            "additional_permission_required": row.additional_permission_required,
            "owner_decision_required": row.owner_decision_required,
            "has_quarantined_content": row.has_quarantined_content,
        }
        digest = hashlib.sha256(_canonical_json(payload)).hexdigest()
        self.database.mark_research_candidate_system_verified(
            candidate_id, verification_manifest_sha256=digest
        )
        return digest

    def review_candidate(
        self,
        candidate_id: str,
        *,
        decision: Literal["accept_for_source_intake", "reject"],
        rights_state: Literal["verified", "metadata_only", "licensed", "rejected"],
        identity_review_state: Literal["candidate_matched", "ambiguous", "rejected"],
        currentness_review_state: Literal[
            "verified",
            "requires_source_review",
            "metadata_only",
            "not_applicable",
            "rejected",
        ],
        reviewer_ref: str,
        review_manifest_sha256: str,
    ) -> str | None:
        if not _REVIEWER_REF.fullmatch(reviewer_ref):
            raise ValueError("research candidate reviewer reference is invalid")
        if not _SHA256.fullmatch(review_manifest_sha256):
            raise ValueError("research candidate review manifest SHA-256 is invalid")
        candidate = self._candidate(candidate_id)
        if candidate.status != "system_verified" or candidate.system_verification_sha256 is None:
            raise RuntimeError("research candidate requires system verification")
        if decision == "accept_for_source_intake" and (
            rights_state not in {"verified", "licensed"}
            or identity_review_state != "candidate_matched"
            or currentness_review_state not in {"verified", "not_applicable"}
        ):
            raise OwnerDecisionRequired()
        review_id = _stable_id("candidate-owner-review", candidate_id, review_manifest_sha256)
        self.database.record_research_candidate_review(
            candidate_id,
            review_id=review_id,
            decision="approved" if decision == "accept_for_source_intake" else "rejected",
            rights_state=rights_state,
            review_manifest_sha256=review_manifest_sha256,
            identity_review_state=identity_review_state,
            currentness_review_state=currentness_review_state,
            reviewer_ref=reviewer_ref,
        )
        if decision == "reject":
            return None
        return f"review-research-intake-{candidate_id}"

    def review_update(
        self,
        observation_id: str,
        *,
        materiality_status: Literal["non_material", "material", "unknown"],
        review_status: Literal["approved", "rejected", "not_required"],
        scope_kind: Literal["authority", "proposition"],
        legal_locator: str | None,
        proposition_sha256: str | None,
        reviewer_ref: str,
        review_manifest_sha256: str,
    ) -> str:
        if not _REVIEWER_REF.fullmatch(reviewer_ref):
            raise ValueError("source update reviewer reference is invalid")
        if not _SHA256.fullmatch(review_manifest_sha256):
            raise ValueError("source update review manifest SHA-256 is invalid")
        review_id = _stable_id("source-update-review", observation_id, review_manifest_sha256)
        self.database.record_source_update_review(
            observation_id,
            review_id=review_id,
            review_status=review_status,
            materiality_status=materiality_status,
            reviewer_ref=reviewer_ref,
            review_manifest_sha256=review_manifest_sha256,
            scope_kind=scope_kind,
            legal_locator=legal_locator,
            proposition_sha256=proposition_sha256,
        )
        return review_id

    def resolve_material_update(
        self,
        observation_id: str,
        *,
        evidence_sha256: str,
        reviewer_ref: str,
    ) -> str:
        """Record that the exact newly promoted ACTIVE source manifest resolves an update."""

        if not _SHA256.fullmatch(evidence_sha256):
            raise ValueError("source update resolution evidence SHA-256 is invalid")
        if not _REVIEWER_REF.fullmatch(reviewer_ref):
            raise ValueError("source update resolution reviewer reference is invalid")
        observation = self._update(observation_id)
        if observation.review_status != "approved" or observation.materiality_status != "material":
            raise RuntimeError("source update is not an expert-verified material update")
        if observation.stale_active:
            raise RuntimeError("stale ACTIVE observation must be recomputed before resolution")
        pointer = ImmutableLanceRepository(self.settings.index_dir).read_active()
        database_active = self.database.active_index_id()
        if pointer is None or pointer.build_id != database_active:
            raise RuntimeError("ACTIVE pointer and catalogue disagree for update resolution")
        if database_active in {
            observation.pinned_index_build_id,
            observation.observed_active_build_id,
        }:
            raise RuntimeError("source update requires a newly promoted ACTIVE build")
        build = self.database.fetchone(
            "SELECT source_manifest_hash FROM index_builds WHERE id=? AND status='active'",
            (database_active,),
        )
        if build is None:
            raise RuntimeError("ACTIVE source manifest is unavailable")
        manifest_path = (
            self.settings.index_dir
            / "builds"
            / str(database_active)
            / "approved-source-manifest.json"
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest_sha = str(manifest.get("manifest_sha256") or "")
        if (
            not _SHA256.fullmatch(manifest_sha)
            or approved_source_manifest_sha256(manifest) != manifest_sha
            or str(build["source_manifest_hash"] or "") != manifest_sha
        ):
            raise RuntimeError("ACTIVE approved-source manifest is not sealed consistently")
        matching = [
            source
            for source in manifest.get("sources", [])
            if source.get("authority_identity_id") == observation.authority_identity_id
        ]
        if observation.comparison_state == "withdrawn":
            if matching:
                raise RuntimeError("withdrawn authority remains present in ACTIVE")
            resolution_kind = "authority_removed"
        else:
            if not matching:
                raise RuntimeError("updated authority is absent from newly promoted ACTIVE")
            if observation.remote_content_sha256 and not any(
                observation.remote_content_sha256
                in {
                    str(source.get("content_sha256") or ""),
                    str(source.get("version_sha256") or ""),
                }
                for source in matching
            ):
                raise RuntimeError("ACTIVE authority does not contain the reviewed remote version")
            resolution_kind = (
                "proposition_reverified"
                if observation.scope_kind == "proposition"
                else "updated_authority_included"
            )
        resolution_id = _stable_id(
            "source-update-resolution", observation_id, str(database_active), evidence_sha256
        )
        self.database.record_source_update_resolution(
            observation_id,
            resolution_id=resolution_id,
            resolved_by_build_id=str(database_active),
            source_manifest_sha256=manifest_sha,
            resolution_kind=resolution_kind,
            authority_identity_id=observation.authority_identity_id,
            legal_locator=observation.legal_locator,
            proposition_sha256=observation.proposition_sha256,
            evidence_sha256=evidence_sha256,
            reviewer_ref=reviewer_ref,
        )
        return resolution_id

    def _candidate(self, candidate_id: str) -> ResearchCandidateOwnerView:
        matches = [item for item in self.candidates(limit=500) if item.id == candidate_id]
        if not matches:
            raise KeyError(candidate_id)
        return matches[0]

    def _update(self, observation_id: str) -> SourceUpdateOwnerView:
        matches = [item for item in self.updates(limit=500) if item.id == observation_id]
        if not matches:
            raise KeyError(observation_id)
        return matches[0]


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _stable_id(prefix: str, *parts: str) -> str:
    material = "\0".join((f"legalbot-{prefix}-v1", *parts)).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(material).hexdigest()[:40]}"


def _optional(value: Any) -> str | None:
    text = str(value or "")
    return text or None
