"""Build-keyed diagnostic subject views over one canonical authority store."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import Settings
from ..db import Database
from .lancedb import ImmutableLanceRepository
from .source_manifest import MANIFEST_SCHEMA, approved_source_manifest_sha256


@dataclass(frozen=True, slots=True)
class SubjectReadinessSnapshot:
    build_id: str | None
    source_manifest_sha256: str | None
    source_policy_id: str | None
    current_law_as_of_date: str | None
    diagnostic_only: bool
    subjects: tuple[dict[str, Any], ...]


class SubjectReadinessService:
    """Derive counts for triage; counts never establish legal answerability."""

    def __init__(self, settings: Settings, database: Database) -> None:
        self.settings = settings
        self.database = database

    def snapshot(self) -> SubjectReadinessSnapshot:
        pointer = ImmutableLanceRepository(self.settings.index_dir).read_active()
        database_active = self.database.active_index_id()
        pointer_id = pointer.build_id if pointer else None
        if pointer_id != database_active:
            raise RuntimeError("ACTIVE pointer and catalogue disagree")
        if database_active is None:
            return SubjectReadinessSnapshot(None, None, None, None, True, ())
        row = self.database.fetchone(
            "SELECT id,status,source_manifest_hash,corpus_id FROM index_builds WHERE id=?",
            (database_active,),
        )
        if row is None or row["status"] != "active":
            raise RuntimeError("ACTIVE catalogue row is unavailable")
        manifest_path = (
            self.settings.index_dir / "builds" / database_active / "approved-source-manifest.json"
        )
        manifest = _load_manifest(manifest_path)
        digest = str(manifest["manifest_sha256"])
        if row["source_manifest_hash"] and row["source_manifest_hash"] != digest:
            raise RuntimeError("ACTIVE subject view source manifest changed")

        grouped: dict[str, dict[str, Any]] = defaultdict(_empty_subject)
        authority_subjects: dict[str, str] = {}
        for source in manifest["sources"]:
            source_version_id = str(source["source_version_id"])
            catalogue = self.database.fetchone(
                """
                SELECT d.subject_primary, d.lane
                FROM source_versions sv JOIN documents d ON d.id=sv.document_id
                WHERE sv.id=?
                """,
                (source_version_id,),
            )
            if catalogue is None:
                raise RuntimeError("ACTIVE subject source is absent from the catalogue")
            subject = str(catalogue["subject_primary"] or "general")
            entry = grouped[subject]
            entry["source_count"] += 1
            entry["chunk_count"] += int(source.get("body_chunk_count") or 0)
            if source.get("identity_verified") is True:
                entry["identity_verified_source_count"] += 1
            if source.get("currentness_verified") is True:
                entry["currentness_verified_source_count"] += 1
            if source.get("full_current_law_verification_eligible") is True:
                entry["full_current_law_source_count"] += 1
            extent = str(source.get("provision_extent_status") or "unverified")
            if extent in {
                "england_and_wales_verified",
                "uk_with_england_wales_verified",
            }:
                entry["extent_verified_source_count"] += 1
            if source.get("subsequent_treatment_check_required") is True:
                entry["later_treatment_required_source_count"] += 1
            if source.get("subsequent_treatment_verified") is True:
                entry["later_treatment_verified_source_count"] += 1
            authority_id = str(source.get("authority_identity_id") or "")
            if authority_id:
                authority_subjects[authority_id] = subject
            entry["reviewed_case_span_count"] += self._reviewed_case_span_count(source_version_id)

        for gap in self.database.fetchall(
            """
            SELECT subject, COUNT(*) AS n FROM knowledge_gaps
            WHERE status NOT IN ('resolved','regression_verified','accepted_out_of_scope')
            GROUP BY subject
            """
        ):
            grouped[str(gap["subject"] or "general")]["unresolved_gap_count"] += int(gap["n"])

        latest_by_subject: dict[str, str] = {}
        for observation in self.database.fetchall(
            """
            SELECT id, authority_identity_id, created_at, stale_active,
              materiality_status, review_status
            FROM source_update_observations ORDER BY created_at DESC
            """
        ):
            observation_subject = authority_subjects.get(str(observation["authority_identity_id"]))
            if observation_subject and observation_subject not in latest_by_subject:
                latest_by_subject[observation_subject] = str(observation["created_at"])
            if not observation_subject:
                continue
            if bool(observation["stale_active"]) or str(observation["review_status"]) == "pending":
                grouped[observation_subject]["pending_update_review_count"] += 1
                continue
            if (
                str(observation["review_status"]) == "approved"
                and str(observation["materiality_status"]) in {"material", "unknown"}
                and self.database.fetchone(
                    """
                    SELECT id FROM source_update_resolution_events
                    WHERE observation_id=? AND resolved_by_build_id=?
                    """,
                    (observation["id"], database_active),
                )
                is None
            ):
                grouped[observation_subject]["unresolved_material_update_count"] += 1

        subjects: list[dict[str, Any]] = []
        for subject, values in sorted(grouped.items()):
            subjects.append(
                {
                    "subject": subject,
                    **values,
                    "last_official_update_check": latest_by_subject.get(subject),
                    "diagnostic_only": True,
                }
            )
        return SubjectReadinessSnapshot(
            build_id=database_active,
            source_manifest_sha256=digest,
            source_policy_id=str(manifest.get("selection_policy") or row["corpus_id"] or ""),
            current_law_as_of_date=(
                str(manifest["current_law_as_of_date"])
                if manifest.get("current_law_as_of_date")
                else None
            ),
            diagnostic_only=True,
            subjects=tuple(subjects),
        )

    def _reviewed_case_span_count(self, source_version_id: str) -> int:
        count = 0
        for row in self.database.fetchall(
            "SELECT metadata_json FROM chunks WHERE source_version_id=? AND stream='body'",
            (source_version_id,),
        ):
            try:
                metadata = json.loads(str(row["metadata_json"] or "{}"))
            except (TypeError, json.JSONDecodeError):
                continue
            reviews = metadata.get("case_currentness_reviews")
            if isinstance(reviews, list) and reviews:
                count += 1
        return count


def _empty_subject() -> dict[str, int]:
    return {
        "source_count": 0,
        "chunk_count": 0,
        "identity_verified_source_count": 0,
        "currentness_verified_source_count": 0,
        "full_current_law_source_count": 0,
        "extent_verified_source_count": 0,
        "later_treatment_required_source_count": 0,
        "later_treatment_verified_source_count": 0,
        "reviewed_case_span_count": 0,
        "unresolved_gap_count": 0,
        "pending_update_review_count": 0,
        "unresolved_material_update_count": 0,
    }


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("ACTIVE approved-source manifest is unavailable") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != MANIFEST_SCHEMA
        or not isinstance(payload.get("sources"), list)
    ):
        raise RuntimeError("ACTIVE approved-source manifest is invalid")
    material = {key: value for key, value in payload.items() if key != "manifest_sha256"}
    if payload.get("manifest_sha256") != approved_source_manifest_sha256(material):
        raise RuntimeError("ACTIVE approved-source manifest seal failed")
    return payload
