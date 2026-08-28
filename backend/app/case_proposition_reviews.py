"""Sealed, audited materialisation of proposition-level case currentness reviews.

The source document and canonical Markdown remain immutable.  An approved
manifest may add only validated review records to derived ``chunks.metadata``
before a new index is built.  It never changes source approval/currentness,
builds an index, or promotes a candidate.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .db import Database
from .privacy import scrub_pii
from .types import (
    CASE_PROPOSITION_REVIEWER_ROLES,
    CasePropositionReview,
)

CASE_REVIEW_MANIFEST_SCHEMA = "legalbot.case-proposition-review-manifest.v1"
CASE_REVIEW_IMPORT_REPORT_SCHEMA = "legalbot.case-proposition-review-import-report.v1"


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def case_review_manifest_sha256(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("seal_sha256", None)
    return hashlib.sha256(_canonical_bytes(material)).hexdigest()


class CasePropositionReviewManifest(BaseModel):
    """Independently checked import pack containing no legal prose or names."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: str = Field(default=CASE_REVIEW_MANIFEST_SCHEMA, alias="schema")
    manifest_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    purpose: Literal["case_proposition_currentness"] = "case_proposition_currentness"
    approval_status: Literal["expert_approved"] = "expert_approved"
    approval_reviewer_role: str
    approval_reviewer_ref: str = Field(pattern=r"^reviewer:[0-9a-f]{64}$")
    independent_second_review_status: Literal["confirmed"] = "confirmed"
    independent_second_reviewer_role: str
    independent_second_reviewer_ref: str = Field(pattern=r"^reviewer:[0-9a-f]{64}$")
    material_disagreement_status: Literal["none", "adjudicated"]
    adjudication_ref: str | None = Field(default=None, pattern=r"^adjudication:[0-9a-f]{64}$")
    review_count: int = Field(ge=1, le=100_000)
    reviews: tuple[CasePropositionReview, ...]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("approval_reviewer_role", "independent_second_reviewer_role")
    @classmethod
    def reviewer_role_is_qualified(cls, value: str) -> str:
        if value not in CASE_PROPOSITION_REVIEWER_ROLES:
            raise ValueError("case-review manifest reviewer role is not qualified")
        return value

    @model_validator(mode="after")
    def manifest_is_complete_and_sealed(self) -> Self:
        if self.review_count != len(self.reviews):
            raise ValueError("case-review manifest count disagrees with its reviews")
        if self.approval_reviewer_ref == self.independent_second_reviewer_ref:
            raise ValueError("case-review manifest second reviewer must be independent")
        if self.independent_second_reviewer_ref in {review.reviewer_ref for review in self.reviews}:
            raise ValueError("case-review manifest second reviewer authored a contained review")
        if self.material_disagreement_status == "adjudicated":
            if self.adjudication_ref is None:
                raise ValueError("adjudicated case-review manifest needs a safe reference")
        elif self.adjudication_ref is not None:
            raise ValueError("case-review adjudication reference has no disagreement")
        seals = [review.seal_sha256 for review in self.reviews]
        if len(seals) != len(set(seals)):
            raise ValueError("case-review manifest contains duplicate review seals")
        material = self.model_dump(mode="json", by_alias=True)
        if self.seal_sha256 != case_review_manifest_sha256(material):
            raise ValueError("case-review manifest seal does not match its contents")
        return self


def load_case_review_manifest(path: Path) -> CasePropositionReviewManifest:
    if not path.is_file():
        raise ValueError("case proposition review manifest is missing")
    return CasePropositionReviewManifest.model_validate_json(path.read_bytes())


def _json_object(value: object, *, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value) if isinstance(value, str | bytes | bytearray) else value
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} metadata is malformed") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} metadata is not an object")
    return dict(parsed)


def _stored_reviews(metadata: Mapping[str, Any]) -> tuple[CasePropositionReview, ...]:
    value = metadata.get("case_currentness_reviews", [])
    if not isinstance(value, list):
        raise ValueError("chunk case-currentness review metadata is not a list")
    reviews = tuple(CasePropositionReview.model_validate(item) for item in value)
    seals = [review.seal_sha256 for review in reviews]
    if len(seals) != len(set(seals)):
        raise ValueError("chunk case-currentness review metadata has duplicate seals")
    return reviews


def _review_coordinate(review: CasePropositionReview) -> tuple[str, ...]:
    return (
        review.source_version_id,
        review.chunk_id,
        review.exact_span_sha256,
        review.proposition_hash,
        review.legal_role,
        review.later_treatment_reviewed_as_of_date.isoformat(),
    )


def _validated_materialisation(
    database: Database,
    manifest: CasePropositionReviewManifest,
) -> tuple[list[tuple[str, str]], int, int, list[str], list[str]]:
    """Return deterministic chunk metadata updates after validating all rows."""

    updates_by_chunk: dict[str, dict[str, Any]] = {}
    applied_count = 0
    already_present_count = 0
    source_version_ids: set[str] = set()
    chunk_ids: set[str] = set()
    for review in manifest.reviews:
        row = database.fetchone(
            """
            SELECT c.id AS chunk_id,c.source_version_id,c.locator,c.markdown_text,
                   c.metadata_json AS chunk_metadata_json,
                   sv.review_status,sv.superseded_by,
                   sv.metadata_json AS source_metadata_json,
                   d.lane,d.status AS document_status
            FROM chunks c
            JOIN source_versions sv ON sv.id=c.source_version_id
            JOIN documents d ON d.id=sv.document_id
            WHERE c.id=? AND c.source_version_id=?
            """,
            (review.chunk_id, review.source_version_id),
        )
        if row is None:
            raise ValueError("case review names a missing source-version/chunk pair")
        source_metadata = _json_object(row["source_metadata_json"], label="case source")
        citation_data = source_metadata.get("citation_data")
        if not isinstance(citation_data, dict) or (
            str(citation_data.get("source_type") or "").casefold() != "case"
        ):
            raise ValueError("case review source is not classified as case law")
        if (
            row["review_status"] != "approved"
            or row["superseded_by"] is not None
            or row["lane"] != "primary_authority"
            or row["document_status"] != "citable"
            or source_metadata.get("identity_verified") is not True
            or source_metadata.get("eligible_for_model_use") is not True
            or source_metadata.get("authority_eligible") is False
        ):
            raise ValueError("case review source lacks approved identity or runtime rights")
        if " ".join(str(row["locator"]).split()) != review.legal_locator:
            raise ValueError("case review locator does not match its exact chunk")
        prompt_safe_text = scrub_pii(str(row["markdown_text"]))
        observed_span_sha256 = hashlib.sha256(prompt_safe_text.encode("utf-8")).hexdigest()
        if observed_span_sha256 != review.exact_span_sha256:
            raise ValueError("case review exact-span hash does not match its chunk")
        for authority_id in review.contrary_or_limiting_authority_ids:
            authority = database.fetchone(
                """
                SELECT 1
                FROM documents d
                JOIN source_versions sv ON sv.document_id=d.id
                WHERE d.source_identity_id=?
                  AND d.status='citable'
                  AND d.lane='primary_authority'
                  AND sv.review_status='approved'
                  AND sv.superseded_by IS NULL
                  AND json_extract(sv.metadata_json,'$.identity_verified')=1
                LIMIT 1
                """,
                (authority_id,),
            )
            if authority is None:
                raise ValueError("case review limiting-authority ID is not an approved authority")

        chunk_id = str(row["chunk_id"])
        if chunk_id in updates_by_chunk:
            metadata = updates_by_chunk[chunk_id]
        else:
            metadata = _json_object(row["chunk_metadata_json"], label="case chunk")
        if str(metadata.get("legal_role") or "unclassified") != review.legal_role:
            raise ValueError("case review legal role does not match reviewed chunk metadata")
        existing = list(_stored_reviews(metadata))
        by_seal = {item.seal_sha256: item for item in existing}
        if review.seal_sha256 in by_seal:
            already_present_count += 1
        else:
            coordinate = _review_coordinate(review)
            if any(_review_coordinate(item) == coordinate for item in existing):
                raise ValueError(
                    "a different sealed review already occupies this proposition/date coordinate"
                )
            existing.append(review)
            existing.sort(
                key=lambda item: (
                    item.later_treatment_reviewed_as_of_date,
                    item.proposition_hash,
                    item.seal_sha256,
                )
            )
            metadata["case_currentness_reviews"] = [
                item.model_dump(mode="json", by_alias=True) for item in existing
            ]
            updates_by_chunk[chunk_id] = metadata
            applied_count += 1
        manifest_seals = metadata.get("case_currentness_review_manifest_seals", [])
        if (
            not isinstance(manifest_seals, list)
            or any(
                not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                for value in manifest_seals
            )
            or len(manifest_seals) != len(set(manifest_seals))
        ):
            raise ValueError("chunk case-currentness manifest seals are invalid")
        if manifest.seal_sha256 not in manifest_seals:
            metadata["case_currentness_review_manifest_seals"] = sorted(
                [*manifest_seals, manifest.seal_sha256]
            )
            updates_by_chunk[chunk_id] = metadata
        source_version_ids.add(review.source_version_id)
        chunk_ids.add(review.chunk_id)
    updates = [
        (json.dumps(metadata, ensure_ascii=False, sort_keys=True), chunk_id)
        for chunk_id, metadata in sorted(updates_by_chunk.items())
    ]
    return (
        updates,
        applied_count,
        already_present_count,
        sorted(source_version_ids),
        sorted(chunk_ids),
    )


def materialise_case_proposition_reviews(
    database: Database,
    manifest: CasePropositionReviewManifest,
    *,
    apply: bool,
) -> dict[str, Any]:
    """Validate and optionally materialise one sealed manifest atomically."""

    def validate_catalogue_state() -> tuple[
        list[tuple[str, str]],
        int,
        int,
        list[str],
        list[str],
        bool,
    ]:
        if database.fetchone("SELECT id FROM source_scans WHERE status IN ('queued','running')"):
            raise RuntimeError(
                "source scan is active; case-review import requires a frozen catalogue"
            )
        if database.fetchone("SELECT id FROM index_builds WHERE status='building'"):
            raise RuntimeError(
                "index build is active; case-review import requires a frozen catalogue"
            )
        updates, applied_count, already_present_count, source_ids, chunk_ids = (
            _validated_materialisation(database, manifest)
        )
        if applied_count + already_present_count != len(manifest.reviews):
            raise RuntimeError("case-review materialisation accounting is inconsistent")
        prior_audit = database.fetchone(
            "SELECT manifest_sha256 FROM case_proposition_review_imports WHERE manifest_sha256=?",
            (manifest.seal_sha256,),
        )
        prior_manifest_id = database.fetchone(
            "SELECT manifest_sha256 FROM case_proposition_review_imports WHERE manifest_id=?",
            (manifest.manifest_id,),
        )
        if (
            prior_manifest_id is not None
            and prior_manifest_id["manifest_sha256"] != manifest.seal_sha256
        ):
            raise RuntimeError("case-review manifest ID already belongs to another seal")
        if prior_audit is not None and updates:
            raise RuntimeError("case-review audit exists but chunk materialisation is incomplete")
        return (
            updates,
            applied_count,
            already_present_count,
            source_ids,
            chunk_ids,
            prior_audit is not None,
        )

    audit_status = "dry_run"
    if apply:
        # BEGIN IMMEDIATE serialises writers before validation.  A concurrent
        # importer therefore observes the committed review/audit rather than
        # overwriting metadata prepared from an earlier catalogue snapshot.
        with database.transaction() as connection:
            (
                updates,
                applied_count,
                already_present_count,
                source_ids,
                chunk_ids,
                already_audited,
            ) = validate_catalogue_state()
            safe_report = {
                "schema": CASE_REVIEW_IMPORT_REPORT_SCHEMA,
                "manifest_id": manifest.manifest_id,
                "manifest_sha256": manifest.seal_sha256,
                "review_count": manifest.review_count,
                "approval_reviewer_role": manifest.approval_reviewer_role,
                "approval_reviewer_ref": manifest.approval_reviewer_ref,
                "independent_second_review_status": (manifest.independent_second_review_status),
                "independent_second_reviewer_role": (manifest.independent_second_reviewer_role),
                "independent_second_reviewer_ref": (manifest.independent_second_reviewer_ref),
                "material_disagreement_status": manifest.material_disagreement_status,
                "adjudication_ref": manifest.adjudication_ref,
                "applied_count": applied_count,
                "already_present_count": already_present_count,
                "source_version_ids": source_ids,
                "chunk_ids": chunk_ids,
                "review_seals": sorted(review.seal_sha256 for review in manifest.reviews),
                "source_bytes_changed": False,
                "canonical_markdown_changed": False,
                "source_review_status_changed": False,
                "index_built_or_promoted": False,
                "new_index_required": True,
            }
            if not already_audited:
                for payload, chunk_id in updates:
                    connection.execute(
                        "UPDATE chunks SET metadata_json=? WHERE id=?",
                        (payload, chunk_id),
                    )
                connection.execute(
                    """
                    INSERT INTO case_proposition_review_imports(
                      manifest_sha256,manifest_id,review_count,applied_count,
                      already_present_count,safe_report_json,applied_at
                    ) VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        manifest.seal_sha256,
                        manifest.manifest_id,
                        manifest.review_count,
                        applied_count,
                        already_present_count,
                        json.dumps(safe_report, ensure_ascii=False, sort_keys=True),
                        datetime.now(UTC).isoformat(),
                    ),
                )
                audit_status = "applied"
            else:
                audit_status = "already_applied"
    else:
        (
            _updates,
            applied_count,
            already_present_count,
            source_ids,
            chunk_ids,
            _already_audited,
        ) = validate_catalogue_state()
    return {
        "schema": CASE_REVIEW_IMPORT_REPORT_SCHEMA,
        "apply": apply,
        "audit_status": audit_status,
        "manifest_id": manifest.manifest_id,
        "manifest_sha256": manifest.seal_sha256,
        "review_count": manifest.review_count,
        "approval_reviewer_role": manifest.approval_reviewer_role,
        "approval_reviewer_ref": manifest.approval_reviewer_ref,
        "independent_second_review_status": manifest.independent_second_review_status,
        "independent_second_reviewer_role": manifest.independent_second_reviewer_role,
        "independent_second_reviewer_ref": manifest.independent_second_reviewer_ref,
        "material_disagreement_status": manifest.material_disagreement_status,
        "adjudication_ref": manifest.adjudication_ref,
        "applied_count": applied_count,
        "already_present_count": already_present_count,
        "source_version_ids": source_ids,
        "chunk_ids": chunk_ids,
        "review_seals": sorted(review.seal_sha256 for review in manifest.reviews),
        "source_bytes_changed": False,
        "canonical_markdown_changed": False,
        "source_review_status_changed": False,
        "index_built_or_promoted": False,
        "new_index_required": True,
    }


def write_immutable_import_report(path: Path, report: Mapping[str, Any]) -> None:
    """Write one immutable safe audit artifact, accepting byte-identical reruns."""

    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_text(encoding="utf-8") != payload:
            raise RuntimeError("case-review audit report already exists with different bytes")
        return
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if path.read_text(encoding="utf-8") != payload:
            raise RuntimeError(
                "case-review audit report was concurrently created with different bytes"
            ) from None
        return
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def immutable_import_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Return the byte-stable audit view shared by first and repeated imports."""

    return {
        key: value
        for key, value in report.items()
        if key not in {"apply", "audit_status", "applied_count", "already_present_count"}
    } | {"materialised_review_count": int(report["review_count"])}
