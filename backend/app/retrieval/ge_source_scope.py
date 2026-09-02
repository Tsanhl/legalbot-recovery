"""Exact, owner-approved source scopes for General Enquiries expansion.

This module is deliberately a selector only.  It can snapshot an already
approved catalogue row and verify an immutable scope, but it cannot download,
admit, enqueue, embed, build, promote, or delete anything.  A prepared scope is
non-authorising until an external owner-approval digest is bound into it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any

from ..config import Settings
from ..contracts import canonical_json_bytes, load_json_strict
from ..currentness import case_present_law_currentness_qualifies
from ..db import Database, utc_iso
from .ge_expansion_proof import (
    EXPANSION_MODE,
    load_verified_ge_predecessor,
    replay_ge_predecessor_proof,
    source_member_sequence_sha256,
    source_member_set_sha256,
    source_member_sha256,
    source_version_id_set_sha256,
    validate_ge_predecessor_proof,
)

SCOPE_SCHEMA = "legalbot.ge-source-scope.v2"
SOURCE_SCHEMA = "legalbot.ge-source-scope-member.v1"
INTAKE_SCHEMA = "legalbot.research-source-intake-bridge.v1"
GE_PROVENANCE_SCHEMA = "legalbot.ge-source-provenance-chain.v1"
GE_PROVENANCE_COMPONENT_SCHEMA = (
    "legalbot.ge-source-provenance-component-receipt.v1"
)
SCOPE_FILENAME = "GE-SOURCE-SCOPE.json"
SCOPE_REVIEW_ROOT_RELATIVE = Path("data/evaluations/ge-source-scope-review")
CORPUS_PREFIX = "ge-approved-source-scope-"
CORPUS_RE = re.compile(rf"^{re.escape(CORPUS_PREFIX)}[0-9a-f]{{64}}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMPONENT_ARTIFACT_PARTS = ("research", "ge-source-provenance-components")
_MAX_COMPONENT_ARTIFACT_BYTES = 2 * 1024 * 1024

APPROVED_STATUS = "OWNER_APPROVED_NON_ACTIVE_GE_SOURCE_SCOPE"
PREPARED_STATUS = "OWNER_APPROVAL_REQUIRED_GE_SOURCE_SCOPE"
ALLOWED_CATALOGUE_LANES = frozenset({"primary_authority", "official_secondary"})
ALLOWED_SCOPE_LANES = frozenset(
    {"primary_authority", "official_guidance", "official_procedure"}
)
_CURRENTNESS_STATUSES = frozenset(
    {"current", "historical", "point_in_time", "latest_available_revised_snapshot"}
)
_INTAKE_REQUIRED_FIELDS = frozenset(
    {
        "schema",
        "intake_id",
        "binding_sha256",
        "candidate_id",
        "task_id",
        "source_id",
        "content_sha256",
        "system_verification_sha256",
        "owner_review_id",
        "owner_review_manifest_sha256",
        "rights_state",
        "pending_intake_review_id",
    }
)
_GE_PROVENANCE_REQUIRED_FIELDS = frozenset(
    {
        "schema",
        "chain_id",
        "diagnosis_id",
        "diagnosis_sha256",
        "failure_fingerprint_sha256",
        "diagnosed_result_sha256",
        "research_intent_id",
        "research_intent_sha256",
        "candidate_build_id",
        "candidate_source_manifest_sha256",
        "retrieval_query_sha256",
        "proposition_sha256",
        "retrieval_attempt_artifact_sha256",
        "research_admission_sha256",
        "research_gap_id",
        "research_gap_record_sha256",
        "research_task_id",
        "research_task_record_sha256",
        "candidate_index_build_record_sha256",
        "component_receipt_artifact_sha256",
        "research_candidate_id",
        "source_intake_id",
        "source_version_id",
        "source_intake_receipt_sha256",
        "research_candidate_record_sha256",
        "candidate_system_review_record_sha256",
        "candidate_owner_review_record_sha256",
        "pending_intake_review_record_sha256",
        "source_version_record_sha256",
        "source_document_record_sha256",
        "source_review_record_sha256",
        "source_provenance_marker_sha256",
        "source_object_sha256",
        "source_chunk_set_sha256",
        "source_chunk_count",
        "source_state",
        "source_identity_verified_for_index",
        "source_currentness_verified_for_index",
        "source_authority_eligible_for_index",
        "feeds_current_answer",
        "writes_active",
        "enqueues_embedding",
        "trains_model",
        "opens_unseen",
        "promotion_authorized",
        "content_sha256",
    }
)

_COMPONENT_RECEIPT_REQUIRED_FIELDS = frozenset(
    {
        "schema",
        "diagnosis",
        "diagnosed_result",
        "research_intent",
        "research_admission",
        "candidate_build_binding",
        "retrieval_attempt_artifact",
        "source_intake_receipt",
        "stored_records",
        "vault_object",
        "source_state",
        "authorizes_source_admission",
        "authorizes_indexing",
        "authorizes_promotion",
        "content_sha256",
    }
)
_COMPONENT_RECORD_KEYS = frozenset(
    {
        "research_gap_binding",
        "research_task",
        "candidate_index_build",
        "research_candidate",
        "candidate_system_review",
        "candidate_owner_review",
        "pending_intake_review",
        "staged_source_version",
        "staged_source_document",
        "pending_source_review",
        "staged_source_chunks",
    }
)
_ADMISSION_FIELDS = frozenset(
    {
        "gap_id",
        "task_id",
        "task_status",
        "source_id",
        "candidate_build_id",
        "source_manifest_sha256",
        "query_sha256",
        "retrieval_attempt_artifact_sha256",
        "intent_sha256",
        "status",
        "staging_only",
        "feeds_current_answer",
        "network_action_performed",
        "owner_source_intake_review_required",
        "rights_review_required",
        "currentness_review_required",
        "source_admission_authorized",
        "successor_candidate_state",
        "promotion_authorized",
    }
)
_INTAKE_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "intake_id",
        "binding_sha256",
        "candidate_id",
        "task_id",
        "source_id",
        "content_sha256",
        "system_verification_sha256",
        "owner_review_id",
        "owner_review_manifest_sha256",
        "rights_state",
        "pending_intake_review_id",
        "opaque_relative_path",
        "scan_id",
        "materialization_state",
        "ingestion_status",
        "source_version_id",
        "source_review_id",
        "source_review_status",
        "source_version_review_status",
        "currentness_status",
        "provenance_marker_schema",
        "writes_index",
        "writes_active",
        "approves_source",
        "enqueues_embedding",
        "trains_model",
    }
)

_SCOPE_REQUIRED_FIELDS = frozenset(
    {
        "schema",
        "expansion_mode",
        "status",
        "created_at",
        "purpose",
        "selection_policy",
        "owner_approval_digest",
        "external_owner_approval_bound",
        "source_selection_authorized",
        "source_count",
        "chunk_count",
        "source_version_id_set_sha256",
        "successor_source_version_ids",
        "successor_member_set_sha256",
        "successor_member_sequence_sha256",
        "predecessor",
        "predecessor_build_id",
        "predecessor_seal_sha256",
        "predecessor_build_manifest_sha256",
        "predecessor_source_manifest_file_sha256",
        "predecessor_source_manifest_sha256",
        "predecessor_index_build_record_sha256",
        "predecessor_source_count",
        "predecessor_chunk_count",
        "predecessor_source_version_id_set_sha256",
        "predecessor_member_set_sha256",
        "predecessor_member_sequence_sha256",
        "added_source_count",
        "added_chunk_count",
        "added_source_version_id_set_sha256",
        "added_member_set_sha256",
        "preservation_proof_sha256",
        "source_lane_bindings",
        "scope_lanes",
        "sources",
        "evaluation_content_included",
        "unseen_content_included",
        "user_content_included",
        "training_content_included",
        "index_enqueue_authorized",
        "index_build_authorized",
        "successor_must_remain_non_active",
        "answer_release_eligible",
        "active_or_previous_write_authorized",
        "promotion_authorized",
        "training_authorized",
        "unseen_run_authorized",
        "live_activation_authorized",
        "corpus_id",
        "scope_content_sha256",
    }
)

_RECORD_REQUIRED_FIELDS = frozenset(
    {
        "schema",
        "source_version_id",
        "document_id",
        "authority_identity_id",
        "stable_identifier",
        "canonical_url",
        "content_sha256",
        "version_sha256",
        "canonical_markdown_path",
        "body_chunk_count",
        "catalogue_lane",
        "scope_lane",
        "jurisdiction",
        "document_status",
        "review_status",
        "retrieval_canonical",
        "catalogue_currentness_status",
        "source_date",
        "as_of_date",
        "identity_verified",
        "currentness_verified",
        "currentness_eligible",
        "licence_name",
        "licence_url",
        "eligible_for_model_use",
        "ai_use_policy",
        "material_type",
        "metadata_sha256",
        "catalogue_review_binding_sha256",
        "currentness_binding_sha256",
        "rights_binding_sha256",
        "research_intake_binding_sha256",
        "research_intake_marker_sha256",
        "ge_source_provenance_chain_sha256",
        "ge_source_provenance_component_sha256",
        "research_owner_review_manifest_sha256",
        "research_rights_state",
        "source_origin",
        "contains_evaluation_content",
        "contains_unseen_content",
        "contains_user_content",
        "contains_training_content",
        "record_content_sha256",
    }
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sealed(value: Mapping[str, Any], *, field: str) -> dict[str, Any]:
    result = dict(value)
    if field in result:
        raise ValueError("ge_source_scope_seal_field_already_present")
    result[field] = _sha256(_canonical_json(result))
    return result


def _verify_seal(value: Mapping[str, Any], *, field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if SHA256_RE.fullmatch(supplied) is None or supplied != _sha256(
        _canonical_json(material)
    ):
        raise ValueError(code)
    return supplied


def _require_sha256(value: Any, *, code: str) -> str:
    digest = str(value or "")
    if SHA256_RE.fullmatch(digest) is None:
        raise ValueError(code)
    return digest


def _metadata(value: Any) -> dict[str, Any]:
    try:
        decoded = json.loads(str(value or "{}"))
    except json.JSONDecodeError as exc:
        raise ValueError("ge_source_scope_catalogue_metadata_invalid") from exc
    if not isinstance(decoded, dict):
        raise ValueError("ge_source_scope_catalogue_metadata_invalid")
    return decoded


def _stored_value(value: Any) -> Any:
    if isinstance(value, bytes | bytearray | memoryview):
        content = bytes(value)
        return {
            "type": "bytes",
            "length": len(content),
            "base64": base64.b64encode(content).decode("ascii"),
        }
    if value is None or isinstance(value, bool | str | int | float):
        return value
    raise ValueError("ge_source_scope_stored_record_type_invalid")


def _stored_record_snapshot(row: Any, *, table: str) -> dict[str, Any]:
    return {
        "schema": "legalbot.exact-stored-record.v1",
        "table": table,
        "fields": {
            str(key): _stored_value(row[key]) for key in row.keys()  # noqa: SIM118
        },
    }


def _stored_record_sha256(row: Any, *, table: str) -> str:
    return hashlib.sha256(
        canonical_json_bytes(_stored_record_snapshot(row, table=table))
    ).hexdigest()


def _contract_sha256(value: Mapping[str, Any], *, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop("content_sha256", ""))
    actual = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    if SHA256_RE.fullmatch(supplied) is None or supplied != actual:
        raise ValueError(code)
    return supplied


def ge_source_scope_review_root(settings: Settings) -> Path:
    """Return the repo-local configured review root without owner path data."""

    project_root = settings.project_root.resolve()
    lexical_root = settings.project_root / SCOPE_REVIEW_ROOT_RELATIVE
    if lexical_root.is_symlink():
        raise ValueError("ge_source_scope_review_root_invalid")
    root = lexical_root.resolve()
    try:
        root.relative_to(project_root)
    except ValueError as exc:
        raise ValueError("ge_source_scope_review_root_escaped_project") from exc
    return root


def ge_source_scope_identity_sha256(scope: Mapping[str, Any]) -> str:
    """Digest the immutable selection identity, excluding time/self fields."""

    identity = {
        key: value
        for key, value in scope.items()
        if key not in {"created_at", "corpus_id", "scope_content_sha256"}
    }
    return _sha256(_canonical_json(identity))


def ge_source_scope_corpus_id(scope: Mapping[str, Any]) -> str:
    return f"{CORPUS_PREFIX}{ge_source_scope_identity_sha256(scope)}"


def is_ge_source_scope_corpus(corpus_id: str | None) -> bool:
    return CORPUS_RE.fullmatch(str(corpus_id or "")) is not None


def _source_version_id_set_sha256(source_version_ids: Sequence[str]) -> str:
    values = sorted(source_version_ids)
    if len(values) != len(set(values)) or any(not value for value in values):
        raise ValueError("ge_source_scope_duplicate_source_version")
    return _sha256(
        _canonical_json(
            {
                "schema": "legalbot.ge-source-version-id-set.v1",
                "source_version_ids": values,
            }
        )
    )


def _binding_sha256(schema: str, value: Mapping[str, Any]) -> str:
    return _sha256(_canonical_json({"schema": schema, **dict(value)}))


def _load_catalogue_row(database: Database, source_version_id: str) -> dict[str, Any]:
    row = database.fetchone(
        """
        SELECT
          sv.id AS source_version_id,
          sv.document_id,
          sv.authority_identity_id,
          sv.stable_identifier,
          sv.canonical_url,
          sv.title,
          sv.canonical_markdown_path,
          sv.version_sha256,
          sv.licence_name,
          sv.licence_url,
          sv.review_status,
          sv.superseded_by,
          sv.source_date,
          sv.as_of_date,
          sv.currentness_status,
          sv.metadata_json,
          sv.created_at AS last_updated,
          d.content_sha256,
          d.status AS document_status,
          d.lane AS catalogue_lane,
          d.subject_primary,
          d.jurisdiction,
          d.duplicate_of,
          d.retrieval_canonical,
          (SELECT COUNT(*) FROM chunks c
             WHERE c.source_version_id=sv.id AND c.stream='body') AS body_chunk_count
        FROM source_versions sv
        JOIN documents d ON d.id=sv.document_id
        WHERE sv.id=?
        """,
        (source_version_id,),
    )
    if row is None:
        raise ValueError("ge_source_scope_catalogue_source_missing")
    return dict(row)


def _catalogue_review_binding(database: Database, source_version_id: str) -> str:
    rows = database.fetchall(
        """
        SELECT id,review_type,target_id,status,decision_note,decided_at
        FROM reviews
        WHERE target_id=? AND review_type IN ('source_version','online_source_version')
        ORDER BY id
        """,
        (source_version_id,),
    )
    approved = [row for row in rows if row["status"] == "approved"]
    if len(rows) != 1 or len(approved) != 1 or approved[0]["decided_at"] is None:
        raise ValueError("ge_source_scope_exact_catalogue_review_missing")
    row = approved[0]
    return _binding_sha256(
        "legalbot.ge-source-catalogue-review-binding.v1",
        {
            "id": row["id"],
            "review_type": row["review_type"],
            "target_id": row["target_id"],
            "status": row["status"],
            "decision_note": row["decision_note"],
            "decided_at": row["decided_at"],
        },
    )


def _load_component_receipt(
    settings: Settings, artifact_sha256: str
) -> dict[str, Any]:
    # Local import avoids the source_manifest -> ge_source_scope -> evaluation
    # package initialisation cycle during application collection.
    from ..evaluation.secure_artifact_io import read_private_file_at

    digest = _require_sha256(
        artifact_sha256, code="ge_source_scope_component_artifact_digest_invalid"
    )
    try:
        raw = read_private_file_at(
            settings.evaluation_dir,
            (*_COMPONENT_ARTIFACT_PARTS, f"{digest}.json"),
            required_parent_mode=0o700,
            required_file_mode=0o600,
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise ValueError("ge_source_scope_component_artifact_missing") from exc
    if (
        not raw
        or len(raw) > _MAX_COMPONENT_ARTIFACT_BYTES
        or hashlib.sha256(raw).hexdigest() != digest
    ):
        raise ValueError("ge_source_scope_component_artifact_bytes_differ")
    try:
        decoded = load_json_strict(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("ge_source_scope_component_artifact_invalid") from exc
    if not isinstance(decoded, dict):
        raise ValueError("ge_source_scope_component_artifact_invalid")
    receipt = dict(decoded)
    if (
        set(receipt) != _COMPONENT_RECEIPT_REQUIRED_FIELDS
        or receipt.get("schema") != GE_PROVENANCE_COMPONENT_SCHEMA
        or receipt.get("source_state") != "STAGED_PENDING_SOURCE_ADMISSION"
        or receipt.get("authorizes_source_admission") is not False
        or receipt.get("authorizes_indexing") is not False
        or receipt.get("authorizes_promotion") is not False
    ):
        raise ValueError("ge_source_scope_component_artifact_invalid")
    _contract_sha256(
        receipt, code="ge_source_scope_component_artifact_seal_invalid"
    )
    return receipt


def _component_mapping(value: Any, *, code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(code)
    return dict(value)


def _exact_snapshot(
    records: Mapping[str, Any],
    *,
    name: str,
    table: str,
    expected_sha256: Any,
    current_row: Any | None = None,
) -> dict[str, Any]:
    snapshot = _component_mapping(
        records.get(name), code="ge_source_scope_component_record_invalid"
    )
    fields = snapshot.get("fields")
    if (
        set(snapshot) != {"schema", "table", "fields"}
        or snapshot.get("schema") != "legalbot.exact-stored-record.v1"
        or snapshot.get("table") != table
        or not isinstance(fields, dict)
        or not all(isinstance(key, str) for key in fields)
    ):
        raise ValueError("ge_source_scope_component_record_invalid")
    for stored in fields.values():
        if isinstance(stored, dict):
            if set(stored) != {"type", "length", "base64"} or stored.get("type") != "bytes":
                raise ValueError("ge_source_scope_component_record_invalid")
            try:
                decoded = base64.b64decode(str(stored["base64"]).encode("ascii"), validate=True)
            except (UnicodeEncodeError, ValueError) as exc:
                raise ValueError("ge_source_scope_component_record_invalid") from exc
            if len(decoded) != stored.get("length"):
                raise ValueError("ge_source_scope_component_record_invalid")
        elif stored is not None and not isinstance(stored, bool | str | int | float):
            raise ValueError("ge_source_scope_component_record_invalid")
    snapshot_sha256 = hashlib.sha256(canonical_json_bytes(snapshot)).hexdigest()
    if snapshot_sha256 != expected_sha256:
        raise ValueError("ge_source_scope_component_record_digest_differed")
    if current_row is not None:
        current = _stored_record_snapshot(current_row, table=table)
        if set(current["fields"]) != set(fields):
            raise ValueError("ge_source_scope_component_record_shape_differed")
        if current != snapshot:
            raise ValueError("ge_source_scope_ge_provenance_record_drift")
    return dict(fields)


def _exact_chunk_snapshots(
    records: Mapping[str, Any],
    *,
    current_rows: Sequence[Any],
    source_version_id: str,
    expected_set_sha256: Any,
    expected_count: Any,
) -> None:
    raw = records.get("staged_source_chunks")
    if not isinstance(raw, list) or len(raw) != len(current_rows):
        raise ValueError("ge_source_scope_component_chunk_records_invalid")
    current_sha256s: list[str] = []
    for snapshot, row in zip(raw, current_rows, strict=True):
        if not isinstance(snapshot, dict):
            raise ValueError("ge_source_scope_component_chunk_records_invalid")
        digest = hashlib.sha256(canonical_json_bytes(snapshot)).hexdigest()
        _exact_snapshot(
            {"chunk": snapshot},
            name="chunk",
            table="chunks",
            expected_sha256=digest,
            current_row=row,
        )
        current_sha256s.append(digest)
    set_sha256 = hashlib.sha256(
        canonical_json_bytes(
            {
                "schema": "legalbot.ge-source-chunk-set.v1",
                "source_version_id": source_version_id,
                "chunk_record_sha256s": current_sha256s,
            }
        )
    ).hexdigest()
    if expected_count != len(current_rows) or expected_set_sha256 != set_sha256:
        raise ValueError("ge_source_scope_ge_provenance_chunk_binding_invalid")


def _verify_component_vault_object(
    settings: Settings, vault: Mapping[str, Any], *, content_sha256: str
) -> None:
    if (
        set(vault) != {"relative_path", "content_sha256", "byte_size"}
        or vault.get("content_sha256") != content_sha256
        or not isinstance(vault.get("byte_size"), int)
        or int(vault["byte_size"]) < 1
    ):
        raise ValueError("ge_source_scope_component_vault_binding_invalid")
    relative = PurePosixPath(str(vault.get("relative_path") or ""))
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError("ge_source_scope_component_vault_path_invalid")
    try:
        project_root = settings.project_root.resolve(strict=True)
        vault_root = settings.vault_dir.resolve(strict=True)
        target = project_root.joinpath(*relative.parts).resolve(strict=True)
    except OSError as exc:
        raise ValueError("ge_source_scope_component_vault_object_missing") from exc
    if (
        not target.is_relative_to(vault_root)
        or target.is_symlink()
        or not target.is_file()
        or target.stat().st_size != vault["byte_size"]
    ):
        raise ValueError("ge_source_scope_component_vault_object_invalid")
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != content_sha256:
        raise ValueError("ge_source_scope_component_vault_object_differed")


def _ge_provenance_chain_binding(
    database: Database,
    settings: Settings,
    metadata: Mapping[str, Any],
    *,
    marker: Mapping[str, Any],
    marker_sha256: str,
    content_sha256: str,
    source_version_id: str,
) -> tuple[dict[str, Any], str]:
    provenance = metadata.get("ge_source_provenance_chain")
    if not isinstance(provenance, dict):
        raise ValueError("ge_source_scope_ge_provenance_chain_missing")
    if (
        set(provenance) != _GE_PROVENANCE_REQUIRED_FIELDS
        or provenance.get("schema") != GE_PROVENANCE_SCHEMA
    ):
        raise ValueError("ge_source_scope_ge_provenance_chain_invalid")
    provenance_sha256 = _contract_sha256(
        provenance, code="ge_source_scope_ge_provenance_chain_seal_invalid"
    )
    components = _load_component_receipt(
        settings, str(provenance["component_receipt_artifact_sha256"])
    )
    digest_fields = _GE_PROVENANCE_REQUIRED_FIELDS.difference(
        {
            "schema",
            "chain_id",
            "diagnosis_id",
            "research_intent_id",
            "candidate_build_id",
            "research_gap_id",
            "research_task_id",
            "research_candidate_id",
            "source_intake_id",
            "source_version_id",
            "source_chunk_count",
            "source_state",
            "source_identity_verified_for_index",
            "source_currentness_verified_for_index",
            "source_authority_eligible_for_index",
            "feeds_current_answer",
            "writes_active",
            "enqueues_embedding",
            "trains_model",
            "opens_unseen",
            "promotion_authorized",
        }
    )
    for field in digest_fields:
        _require_sha256(
            provenance.get(field), code="ge_source_scope_ge_provenance_digest_invalid"
        )
    if (
        provenance.get("source_version_id") != source_version_id
        or provenance.get("source_object_sha256") != content_sha256
        or provenance.get("source_provenance_marker_sha256") != marker_sha256
        or provenance.get("source_intake_id") != marker.get("intake_id")
        or provenance.get("research_candidate_id") != marker.get("candidate_id")
        or provenance.get("research_task_id") != marker.get("task_id")
        or provenance.get("source_state") != "STAGED_PENDING_SOURCE_ADMISSION"
        or provenance.get("source_identity_verified_for_index") is not False
        or provenance.get("source_currentness_verified_for_index") is not False
        or provenance.get("source_authority_eligible_for_index") is not False
        or provenance.get("feeds_current_answer") is not False
        or provenance.get("writes_active") is not False
        or provenance.get("enqueues_embedding") is not False
        or provenance.get("trains_model") is not False
        or provenance.get("opens_unseen") is not False
        or provenance.get("promotion_authorized") is not False
    ):
        raise ValueError("ge_source_scope_ge_provenance_binding_invalid")

    diagnosis = _component_mapping(
        components.get("diagnosis"), code="ge_source_scope_component_diagnosis_invalid"
    )
    diagnosed_result = _component_mapping(
        components.get("diagnosed_result"),
        code="ge_source_scope_component_result_invalid",
    )
    intent = _component_mapping(
        components.get("research_intent"),
        code="ge_source_scope_component_intent_invalid",
    )
    admission = _component_mapping(
        components.get("research_admission"),
        code="ge_source_scope_component_admission_invalid",
    )
    intake_receipt = _component_mapping(
        components.get("source_intake_receipt"),
        code="ge_source_scope_component_intake_invalid",
    )
    candidate_binding_receipt = _component_mapping(
        components.get("candidate_build_binding"),
        code="ge_source_scope_component_candidate_binding_invalid",
    )
    retrieval_receipt = _component_mapping(
        components.get("retrieval_attempt_artifact"),
        code="ge_source_scope_component_retrieval_invalid",
    )
    records = _component_mapping(
        components.get("stored_records"),
        code="ge_source_scope_component_records_invalid",
    )
    vault = _component_mapping(
        components.get("vault_object"),
        code="ge_source_scope_component_vault_binding_invalid",
    )
    if set(records) != _COMPONENT_RECORD_KEYS:
        raise ValueError("ge_source_scope_component_records_invalid")

    # The exact diagnosis and selected case result are evidence, not digest
    # shapes.  Rebuild the intent from those full objects before any database
    # or catalogue row can use the chain.
    try:
        from ..evaluation.ge_improvement_loop import build_official_research_intent

        replayed_intent = build_official_research_intent(
            diagnosis=diagnosis,
            diagnosed_result=diagnosed_result,
            candidate_build_id=str(provenance["candidate_build_id"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("ge_source_scope_component_diagnosis_replay_failed") from exc
    if canonical_json_bytes(replayed_intent) != canonical_json_bytes(intent):
        raise ValueError("ge_source_scope_component_intent_replay_differed")
    diagnosis_sha256 = _contract_sha256(
        diagnosis, code="ge_source_scope_component_diagnosis_seal_invalid"
    )
    result_sha256 = _contract_sha256(
        diagnosed_result, code="ge_source_scope_component_result_seal_invalid"
    )
    intent_sha256 = _contract_sha256(
        intent, code="ge_source_scope_component_intent_seal_invalid"
    )
    if (
        provenance.get("diagnosis_id") != diagnosis.get("diagnosis_id")
        or provenance.get("diagnosis_sha256") != diagnosis_sha256
        or provenance.get("failure_fingerprint_sha256")
        != diagnosis.get("failure_fingerprint_sha256")
        or diagnosis.get("result_sha256") != result_sha256
        or provenance.get("diagnosed_result_sha256") != result_sha256
        or provenance.get("research_intent_id") != intent.get("intent_id")
        or provenance.get("research_intent_sha256") != intent_sha256
        or provenance.get("candidate_build_id") != intent.get("candidate_build_id")
        or provenance.get("retrieval_query_sha256")
        != intent.get("retrieval_query_sha256")
        or provenance.get("proposition_sha256") != intent.get("proposition_sha256")
        or provenance.get("retrieval_attempt_artifact_sha256")
        != intent.get("retrieval_attempt_artifact_sha256")
    ):
        raise ValueError("ge_source_scope_component_evidence_binding_invalid")

    if (
        set(admission) != _ADMISSION_FIELDS
        or hashlib.sha256(canonical_json_bytes(admission)).hexdigest()
        != provenance.get("research_admission_sha256")
        or admission.get("gap_id") != provenance.get("research_gap_id")
        or admission.get("task_id") != provenance.get("research_task_id")
        or admission.get("source_id") != marker.get("source_id")
        or admission.get("candidate_build_id") != provenance.get("candidate_build_id")
        or admission.get("source_manifest_sha256")
        != provenance.get("candidate_source_manifest_sha256")
        or admission.get("query_sha256") != provenance.get("retrieval_query_sha256")
        or admission.get("retrieval_attempt_artifact_sha256")
        != provenance.get("retrieval_attempt_artifact_sha256")
        or admission.get("intent_sha256") != provenance.get("research_intent_sha256")
        or admission.get("status") != "ADMITTED"
        or admission.get("staging_only") is not True
        or admission.get("feeds_current_answer") is not False
        or admission.get("network_action_performed") is not False
        or admission.get("owner_source_intake_review_required") is not True
        or admission.get("rights_review_required") is not True
        or admission.get("currentness_review_required") is not True
        or admission.get("source_admission_authorized") is not False
        or admission.get("successor_candidate_state") != "NON_ACTIVE"
        or admission.get("promotion_authorized") is not False
    ):
        raise ValueError("ge_source_scope_component_admission_invalid")
    if (
        set(intake_receipt) != _INTAKE_RECEIPT_FIELDS
        or hashlib.sha256(canonical_json_bytes(intake_receipt)).hexdigest()
        != provenance.get("source_intake_receipt_sha256")
        or intake_receipt.get("schema") != INTAKE_SCHEMA
        or intake_receipt.get("intake_id") != provenance.get("source_intake_id")
        or intake_receipt.get("candidate_id")
        != provenance.get("research_candidate_id")
        or intake_receipt.get("task_id") != provenance.get("research_task_id")
        or intake_receipt.get("source_id") != marker.get("source_id")
        or intake_receipt.get("source_version_id") != source_version_id
        or intake_receipt.get("content_sha256") != content_sha256
        or intake_receipt.get("source_review_status") != "pending"
        or intake_receipt.get("source_version_review_status") != "staged"
        or intake_receipt.get("currentness_status") != "unknown"
        or intake_receipt.get("provenance_marker_schema") != INTAKE_SCHEMA
        or intake_receipt.get("materialization_state")
        not in {"created", "existing_verified"}
        or not intake_receipt.get("ingestion_status")
        or any(
            intake_receipt.get(field) is not False
            for field in (
                "writes_index",
                "writes_active",
                "approves_source",
                "enqueues_embedding",
                "trains_model",
            )
        )
    ):
        raise ValueError("ge_source_scope_component_intake_invalid")
    expected_component_marker = {
        field: intake_receipt[field] for field in _INTAKE_REQUIRED_FIELDS
    }
    if marker != expected_component_marker:
        raise ValueError("ge_source_scope_component_intake_marker_differed")

    gap = database.fetchone(
        "SELECT * FROM research_gap_bindings WHERE id=?",
        (str(provenance["research_gap_id"]),),
    )
    task = database.fetchone(
        "SELECT * FROM research_tasks WHERE id=?",
        (str(provenance["research_task_id"]),),
    )
    candidate_index_build = database.fetchone(
        "SELECT * FROM index_builds WHERE id=?",
        (str(provenance["candidate_build_id"]),),
    )
    candidate = database.fetchone(
        "SELECT * FROM research_candidates WHERE id=?",
        (str(provenance["research_candidate_id"]),),
    )
    system_review = database.fetchone(
        "SELECT * FROM reviews WHERE id=?",
        (f"review-research-system-{provenance['research_candidate_id']}",),
    )
    owner_review = database.fetchone(
        "SELECT * FROM reviews WHERE id=?", (str(marker["owner_review_id"]),)
    )
    intake_review = database.fetchone(
        "SELECT * FROM reviews WHERE id=?",
        (str(intake_receipt["pending_intake_review_id"]),),
    )
    source_version = database.fetchone(
        "SELECT * FROM source_versions WHERE id=?", (source_version_id,)
    )
    document = (
        database.fetchone(
            "SELECT * FROM documents WHERE id=?", (str(source_version["document_id"]),)
        )
        if source_version is not None
        else None
    )
    source_review = database.fetchone(
        "SELECT * FROM reviews WHERE id=?", (str(intake_receipt["source_review_id"]),)
    )
    if (
        gap is None
        or task is None
        or candidate_index_build is None
        or candidate is None
        or system_review is None
        or owner_review is None
        or intake_review is None
        or source_version is None
        or document is None
        or source_review is None
    ):
        raise ValueError("ge_source_scope_ge_provenance_record_missing")

    _exact_snapshot(
        records,
        name="research_gap_binding",
        table="research_gap_bindings",
        expected_sha256=provenance.get("research_gap_record_sha256"),
        current_row=gap,
    )
    _exact_snapshot(
        records,
        name="research_task",
        table="research_tasks",
        expected_sha256=provenance.get("research_task_record_sha256"),
        current_row=task,
    )
    _exact_snapshot(
        records,
        name="candidate_index_build",
        table="index_builds",
        expected_sha256=provenance.get("candidate_index_build_record_sha256"),
        current_row=candidate_index_build,
    )
    _exact_snapshot(
        records,
        name="research_candidate",
        table="research_candidates",
        expected_sha256=provenance.get("research_candidate_record_sha256"),
        current_row=candidate,
    )
    _exact_snapshot(
        records,
        name="candidate_system_review",
        table="reviews",
        expected_sha256=provenance.get("candidate_system_review_record_sha256"),
        current_row=system_review,
    )
    _exact_snapshot(
        records,
        name="candidate_owner_review",
        table="reviews",
        expected_sha256=provenance.get("candidate_owner_review_record_sha256"),
        current_row=owner_review,
    )
    _exact_snapshot(
        records,
        name="pending_intake_review",
        table="reviews",
        expected_sha256=provenance.get("pending_intake_review_record_sha256"),
        current_row=intake_review,
    )
    if (
        str(gap["candidate_build_id"]) != provenance.get("candidate_build_id")
        or str(gap["source_manifest_sha256"])
        != provenance.get("candidate_source_manifest_sha256")
        or str(gap["attempted_retrieval_sha256"])
        != provenance.get("retrieval_attempt_artifact_sha256")
        or str(gap["materiality"]) != "material"
        or str(task["id"]) != marker.get("task_id")
        or str(task["knowledge_gap_id"] or "") != gap["id"]
        or str(task["pinned_index_build_id"] or "")
        != provenance.get("candidate_build_id")
        or str(task["source_manifest_sha256"] or "")
        != provenance.get("candidate_source_manifest_sha256")
        or str(task["query_sha256"]) != provenance.get("retrieval_query_sha256")
        or str(task["source_id"] or "") != marker.get("source_id")
        or str(task["task_type"]) != "gap_research"
        or str(task["status"]) != "review_required"
        or str(candidate_index_build["id"]) != provenance.get("candidate_build_id")
        or str(candidate_index_build["status"]) == "active"
        or str(candidate_index_build["source_manifest_hash"] or "")
        != provenance.get("candidate_source_manifest_sha256")
        or str(candidate["id"]) != marker.get("candidate_id")
        or str(candidate["task_id"]) != task["id"]
        or str(candidate["source_id"]) != marker.get("source_id")
        or str(candidate["content_sha256"] or "") != content_sha256
        or str(candidate["status"]) != "source_intake_pending"
        or str(candidate["rights_state"]) not in {"verified", "licensed"}
        or str(candidate["identity_review_state"]) != "candidate_matched"
        or str(candidate["currentness_review_state"])
        not in {"verified", "not_applicable"}
        or str(system_review["review_type"])
        != "research_candidate_system_verification"
        or str(system_review["target_id"]) != candidate["id"]
        or str(system_review["status"]) != "approved"
        or system_review["decided_at"] is None
        or str(system_review["reason"] or "")
        != f"Deterministic candidate envelope {marker['system_verification_sha256']}"
        or str(owner_review["review_type"]) != "official_research_candidate"
        or str(owner_review["target_id"]) != candidate["id"]
        or str(owner_review["status"]) != "approved"
        or owner_review["decided_at"] is None
        or str(owner_review["reason"] or "")
        != f"Explicit reviewed manifest {marker['owner_review_manifest_sha256']}"
        or str(intake_review["review_type"]) != "research_source_intake"
        or str(intake_review["target_id"]) != candidate["id"]
        or str(intake_review["status"]) != "pending"
        or intake_review["decided_at"] is not None
    ):
        raise ValueError("ge_source_scope_ge_provenance_record_binding_invalid")

    try:
        from ..research.retrieval_attempt import (
            CandidateBuildBinding,
            RetrievalAttemptBinding,
            load_verified_candidate_retrieval_attempt,
            opaque_gap_reference,
        )

        candidate_binding = CandidateBuildBinding(
            candidate_build_id=str(candidate_binding_receipt["candidate_build_id"]),
            candidate_seal_sha256=str(
                candidate_binding_receipt["candidate_seal_sha256"]
            ),
            source_manifest_sha256=str(
                candidate_binding_receipt["source_manifest_sha256"]
            ),
        )
        retrieval_attempt = load_verified_candidate_retrieval_attempt(
            settings=settings,
            artifact_sha256=str(provenance["retrieval_attempt_artifact_sha256"]),
            expected=RetrievalAttemptBinding(
                candidate_build_id=candidate_binding.candidate_build_id,
                candidate_seal_sha256=candidate_binding.candidate_seal_sha256,
                source_manifest_sha256=candidate_binding.source_manifest_sha256,
                case_ref=str(gap["case_id"]),
                issue_ref=str(gap["issue_id"]),
                subject=str(gap["subject"]),
                jurisdiction=str(gap["jurisdiction"]),
                as_of_date=date.fromisoformat(str(gap["as_of_date"])),
                proposition_sha256=str(intent["proposition_sha256"]),
                query_sha256=str(intent["retrieval_query_sha256"]),
            ),
        )
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        raise ValueError("ge_source_scope_component_retrieval_replay_failed") from exc
    if (
        set(candidate_binding_receipt)
        != {"candidate_build_id", "candidate_seal_sha256", "source_manifest_sha256"}
        or asdict(candidate_binding) != candidate_binding_receipt
        or retrieval_attempt.model_dump(mode="json", by_alias=True) != retrieval_receipt
        or gap["case_id"]
        != opaque_gap_reference("case", str(intent.get("case_id") or ""))
        or gap["issue_id"]
        != opaque_gap_reference("issue", str(diagnosis.get("diagnosis_id") or ""))
    ):
        raise ValueError("ge_source_scope_component_retrieval_binding_invalid")

    chunks = database.fetchall(
        "SELECT * FROM chunks WHERE source_version_id=? ORDER BY ordinal, id",
        (source_version_id,),
    )
    if not chunks:
        raise ValueError("ge_source_scope_ge_provenance_chunk_binding_invalid")
    _exact_chunk_snapshots(
        records,
        current_rows=chunks,
        source_version_id=source_version_id,
        expected_set_sha256=provenance.get("source_chunk_set_sha256"),
        expected_count=provenance.get("source_chunk_count"),
    )

    staged_source = _exact_snapshot(
        records,
        name="staged_source_version",
        table="source_versions",
        expected_sha256=provenance.get("source_version_record_sha256"),
    )
    staged_document = _exact_snapshot(
        records,
        name="staged_source_document",
        table="documents",
        expected_sha256=provenance.get("source_document_record_sha256"),
    )
    pending_source_review = _exact_snapshot(
        records,
        name="pending_source_review",
        table="reviews",
        expected_sha256=provenance.get("source_review_record_sha256"),
    )
    current_source_snapshot = _stored_record_snapshot(
        source_version, table="source_versions"
    )["fields"]
    current_document_snapshot = _stored_record_snapshot(document, table="documents")[
        "fields"
    ]
    current_source_review_snapshot = _stored_record_snapshot(
        source_review, table="reviews"
    )["fields"]
    if (
        set(staged_source) != set(current_source_snapshot)
        or set(staged_document) != set(current_document_snapshot)
        or set(pending_source_review) != set(current_source_review_snapshot)
    ):
        raise ValueError("ge_source_scope_component_record_shape_differed")
    staged_metadata = _metadata(staged_source.get("metadata_json"))
    staged_marker = staged_metadata.get("research_source_intake")
    if (
        staged_source.get("id") != source_version_id
        or staged_source.get("document_id") != document["id"]
        or staged_source.get("version_sha256") != content_sha256
        or staged_source.get("review_status") != "staged"
        or staged_source.get("currentness_status") != "unknown"
        or staged_source.get("superseded_by") is not None
        or staged_marker != marker
        or staged_metadata.get("raw_object_sha256") != content_sha256
        or staged_metadata.get("raw_vault_path") != vault.get("relative_path")
        or staged_metadata.get("identity_verified") is not False
        or staged_metadata.get("currentness_verified") is not False
        or staged_metadata.get("authority_eligible") is not False
        or staged_metadata.get("citation_rendering_enabled") is not False
        or staged_document.get("id") != document["id"]
        or staged_document.get("content_sha256") != content_sha256
        or pending_source_review.get("id") != intake_receipt.get("source_review_id")
        or pending_source_review.get("review_type") != "source_version"
        or pending_source_review.get("target_id") != source_version_id
        or pending_source_review.get("status") != "pending"
        or pending_source_review.get("decided_at") is not None
        or current_source_review_snapshot.get("id")
        != pending_source_review.get("id")
        or current_source_review_snapshot.get("review_type") != "source_version"
        or current_source_review_snapshot.get("target_id") != source_version_id
        or current_source_review_snapshot.get("status") != "approved"
        or current_source_review_snapshot.get("decided_at") is None
        or current_source_review_snapshot.get("decision_note")
        != f"Explicit GE provenance chain {provenance_sha256}"
    ):
        raise ValueError("ge_source_scope_component_staged_history_invalid")
    for field in (
        "id",
        "document_id",
        "version_sha256",
        "canonical_markdown_path",
        "processing_fingerprint",
        "created_at",
    ):
        if staged_source.get(field) != current_source_snapshot.get(field):
            raise ValueError("ge_source_scope_component_source_successor_differed")
    mutable_document_fields = {
        "status",
        "retrieval_canonical",
        "dedupe_status",
        "updated_at",
    }
    for field in set(staged_document).difference(mutable_document_fields):
        if staged_document.get(field) != current_document_snapshot.get(field):
            raise ValueError("ge_source_scope_component_document_successor_differed")
    for field in ("id", "review_type", "target_id", "reason", "created_at"):
        if pending_source_review.get(field) != current_source_review_snapshot.get(field):
            raise ValueError("ge_source_scope_component_review_successor_differed")

    receipt_binding = {
        "schema": intake_receipt["schema"],
        "candidate_id": intake_receipt["candidate_id"],
        "task_id": intake_receipt["task_id"],
        "source_id": intake_receipt["source_id"],
        "source_identity": str(candidate["source_identity"]),
        "content_sha256": intake_receipt["content_sha256"],
        "metadata_sha256": str(candidate["metadata_sha256"]),
        "content_object_key": str(candidate["content_object_key"]),
        "system_verification_sha256": intake_receipt[
            "system_verification_sha256"
        ],
        "owner_review_id": intake_receipt["owner_review_id"],
        "owner_review_manifest_sha256": intake_receipt[
            "owner_review_manifest_sha256"
        ],
        "rights_state": intake_receipt["rights_state"],
        "pending_intake_review_id": intake_receipt["pending_intake_review_id"],
    }
    if (
        hashlib.sha256(
            json.dumps(
                receipt_binding,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        != intake_receipt.get("binding_sha256")
    ):
        raise ValueError("ge_source_scope_component_intake_binding_invalid")
    _verify_component_vault_object(settings, vault, content_sha256=content_sha256)

    identity = {
        "diagnosis_sha256": provenance["diagnosis_sha256"],
        "diagnosed_result_sha256": provenance["diagnosed_result_sha256"],
        "research_intent_sha256": provenance["research_intent_sha256"],
        "research_admission_sha256": provenance["research_admission_sha256"],
        "research_gap_record_sha256": provenance["research_gap_record_sha256"],
        "research_task_record_sha256": provenance["research_task_record_sha256"],
        "candidate_index_build_record_sha256": provenance[
            "candidate_index_build_record_sha256"
        ],
        "component_receipt_artifact_sha256": provenance[
            "component_receipt_artifact_sha256"
        ],
        "source_intake_receipt_sha256": provenance["source_intake_receipt_sha256"],
        "research_candidate_record_sha256": provenance[
            "research_candidate_record_sha256"
        ],
        "candidate_system_review_record_sha256": provenance[
            "candidate_system_review_record_sha256"
        ],
        "candidate_owner_review_record_sha256": provenance[
            "candidate_owner_review_record_sha256"
        ],
        "pending_intake_review_record_sha256": provenance[
            "pending_intake_review_record_sha256"
        ],
        "source_version_record_sha256": provenance["source_version_record_sha256"],
        "source_document_record_sha256": provenance["source_document_record_sha256"],
        "source_review_record_sha256": provenance["source_review_record_sha256"],
        "source_provenance_marker_sha256": provenance[
            "source_provenance_marker_sha256"
        ],
        "source_object_sha256": provenance["source_object_sha256"],
        "source_chunk_set_sha256": provenance["source_chunk_set_sha256"],
        "source_chunk_count": provenance["source_chunk_count"],
    }
    expected_chain_id = "ge-source-chain-" + hashlib.sha256(
        canonical_json_bytes(
            {
                "schema": "legalbot.ge-source-provenance-chain-identity.v1",
                **identity,
            }
        )
    ).hexdigest()[:40]
    if provenance.get("chain_id") != expected_chain_id:
        raise ValueError("ge_source_scope_ge_provenance_identity_invalid")
    return provenance, provenance_sha256


def _research_intake_binding(
    database: Database,
    settings: Settings,
    metadata: Mapping[str, Any],
    *,
    content_sha256: str,
    source_version_id: str,
) -> tuple[dict[str, Any], str, str, str]:
    marker = metadata.get("research_source_intake")
    if not isinstance(marker, dict):
        raise ValueError("ge_source_scope_official_research_provenance_missing")
    required_text = (
        "intake_id",
        "binding_sha256",
        "candidate_id",
        "task_id",
        "source_id",
        "content_sha256",
        "system_verification_sha256",
        "owner_review_id",
        "owner_review_manifest_sha256",
        "pending_intake_review_id",
    )
    if (
        set(marker) != _INTAKE_REQUIRED_FIELDS
        or marker.get("schema") != INTAKE_SCHEMA
        or any(not str(marker.get(field) or "") for field in required_text)
        or marker.get("content_sha256") != content_sha256
        or marker.get("rights_state") not in {"verified", "licensed"}
    ):
        raise ValueError("ge_source_scope_official_research_provenance_invalid")
    for field in (
        "binding_sha256",
        "content_sha256",
        "system_verification_sha256",
        "owner_review_manifest_sha256",
    ):
        _require_sha256(
            marker.get(field), code="ge_source_scope_official_research_digest_invalid"
        )
    marker_sha256 = hashlib.sha256(canonical_json_bytes(marker)).hexdigest()
    provenance, provenance_sha256 = _ge_provenance_chain_binding(
        database,
        settings,
        metadata,
        marker=marker,
        marker_sha256=marker_sha256,
        content_sha256=content_sha256,
        source_version_id=source_version_id,
    )
    return (
        marker,
        marker_sha256,
        provenance_sha256,
        str(provenance["component_receipt_artifact_sha256"]),
    )


def _scope_lane_allowed(*, catalogue_lane: str, scope_lane: str, material_type: str) -> bool:
    if catalogue_lane not in ALLOWED_CATALOGUE_LANES or scope_lane not in ALLOWED_SCOPE_LANES:
        return False
    if scope_lane == "primary_authority":
        return catalogue_lane == "primary_authority" and material_type in {
            "case",
            "legislation",
            "rule",
        }
    if scope_lane == "official_guidance":
        return catalogue_lane == "official_secondary" and material_type == "official_guidance"
    return (
        catalogue_lane == "official_secondary" and material_type == "official_guidance"
    ) or (catalogue_lane == "primary_authority" and material_type == "rule")


def _currentness_eligible(row: Mapping[str, Any], metadata: Mapping[str, Any]) -> bool:
    if metadata.get("currentness_verified") is True:
        return True
    if str(metadata.get("material_type") or "") != "case":
        return False
    citation_data = metadata.get("citation_data")
    if not isinstance(citation_data, dict):
        citation_data = {}
    return case_present_law_currentness_qualifies(
        citation_data=citation_data,
        currentness_status=str(row.get("currentness_status") or "unknown"),
        source_metadata=metadata,
    )


def snapshot_ge_source_binding(
    database: Database,
    settings: Settings,
    *,
    source_version_id: str,
    scope_lane: str,
) -> dict[str, Any]:
    """Snapshot one exact, already-approved official source catalogue row."""

    row = _load_catalogue_row(database, source_version_id)
    metadata = _metadata(row.get("metadata_json"))
    chunks = int(row.get("body_chunk_count") or 0)
    material_type = str(metadata.get("material_type") or "")
    catalogue_lane = str(row.get("catalogue_lane") or "")
    currentness_eligible = _currentness_eligible(row, metadata)
    if (
        row.get("review_status") != "approved"
        or row.get("superseded_by") is not None
        or row.get("duplicate_of") is not None
        or row.get("document_status") != "citable"
        or int(row.get("retrieval_canonical") or 0) != 1
        or chunks < 1
        or not _scope_lane_allowed(
            catalogue_lane=catalogue_lane,
            scope_lane=scope_lane,
            material_type=material_type,
        )
        or metadata.get("identity_verified") is not True
        or metadata.get("authority_eligible") is not True
        or metadata.get("citation_rendering_enabled") is not True
        or metadata.get("eligible_for_model_use") is not True
        or str(metadata.get("ai_use_policy") or "") in {"", "prohibited"}
        or not currentness_eligible
        or not str(row.get("jurisdiction") or "")
        or not str(row.get("stable_identifier") or "")
        or not str(row.get("authority_identity_id") or "")
        or not str(row.get("canonical_url") or "").startswith("https://")
        or not str(row.get("licence_name") or "")
        or str(row.get("currentness_status") or "") not in _CURRENTNESS_STATUSES
        or not str(row.get("as_of_date") or "")
    ):
        raise ValueError("ge_source_scope_catalogue_source_not_eligible")

    (
        intake,
        intake_sha256,
        ge_provenance_sha256,
        ge_component_sha256,
    ) = _research_intake_binding(
        database,
        settings,
        metadata,
        content_sha256=str(row["content_sha256"]),
        source_version_id=source_version_id,
    )
    review_binding = _catalogue_review_binding(database, source_version_id)
    currentness_binding = _binding_sha256(
        "legalbot.ge-source-currentness-binding.v1",
        {
            "catalogue_currentness_status": row.get("currentness_status"),
            "source_date": row.get("source_date"),
            "as_of_date": row.get("as_of_date"),
            "identity_verified": metadata.get("identity_verified"),
            "currentness_verified": metadata.get("currentness_verified"),
            "currentness_applicable": metadata.get("currentness_applicable"),
            "approval_as_of_date": metadata.get("approval_as_of_date"),
            "currentness_reviewed_as_of_date": metadata.get(
                "currentness_reviewed_as_of_date"
            ),
            "subsequent_treatment_check_required": metadata.get(
                "subsequent_treatment_check_required"
            ),
            "subsequent_treatment_verified": metadata.get(
                "subsequent_treatment_verified"
            ),
            "currentness_eligible": currentness_eligible,
        },
    )
    rights_binding = _binding_sha256(
        "legalbot.ge-source-rights-binding.v1",
        {
            "licence_name": row.get("licence_name"),
            "licence_url": row.get("licence_url"),
            "eligible_for_model_use": metadata.get("eligible_for_model_use"),
            "ai_use_policy": metadata.get("ai_use_policy"),
            "ai_use_restriction_codes": metadata.get("ai_use_restriction_codes"),
            "research_rights_state": intake.get("rights_state"),
            "research_owner_review_manifest_sha256": intake.get(
                "owner_review_manifest_sha256"
            ),
        },
    )

    relative_markdown = PurePosixPath(str(row.get("canonical_markdown_path") or ""))
    if relative_markdown.is_absolute() or ".." in relative_markdown.parts:
        raise ValueError("ge_source_scope_canonical_markdown_path_invalid")
    markdown = settings.project_root.joinpath(*relative_markdown.parts)
    project_root = settings.project_root.resolve()
    resolved_markdown = markdown.resolve()
    try:
        resolved_markdown.relative_to(project_root)
    except ValueError as exc:
        raise ValueError("ge_source_scope_canonical_markdown_path_invalid") from exc
    if markdown.is_symlink() or not markdown.is_file() or markdown.stat().st_size < 1:
        raise ValueError("ge_source_scope_canonical_markdown_unavailable")

    value = {
        "schema": SOURCE_SCHEMA,
        "source_version_id": row["source_version_id"],
        "document_id": row["document_id"],
        "authority_identity_id": row.get("authority_identity_id"),
        "stable_identifier": row["stable_identifier"],
        "canonical_url": row["canonical_url"],
        "content_sha256": row["content_sha256"],
        "version_sha256": row["version_sha256"],
        "canonical_markdown_path": relative_markdown.as_posix(),
        "body_chunk_count": chunks,
        "catalogue_lane": catalogue_lane,
        "scope_lane": scope_lane,
        "jurisdiction": row["jurisdiction"],
        "document_status": row["document_status"],
        "review_status": row["review_status"],
        "retrieval_canonical": True,
        "catalogue_currentness_status": row["currentness_status"],
        "source_date": row["source_date"],
        "as_of_date": row["as_of_date"],
        "identity_verified": True,
        "currentness_verified": metadata.get("currentness_verified") is True,
        "currentness_eligible": True,
        "licence_name": row["licence_name"],
        "licence_url": row["licence_url"],
        "eligible_for_model_use": True,
        "ai_use_policy": metadata["ai_use_policy"],
        "material_type": material_type,
        "metadata_sha256": _sha256(_canonical_json(metadata)),
        "catalogue_review_binding_sha256": review_binding,
        "currentness_binding_sha256": currentness_binding,
        "rights_binding_sha256": rights_binding,
        "research_intake_binding_sha256": intake["binding_sha256"],
        "research_intake_marker_sha256": intake_sha256,
        "ge_source_provenance_chain_sha256": ge_provenance_sha256,
        "ge_source_provenance_component_sha256": ge_component_sha256,
        "research_owner_review_manifest_sha256": intake[
            "owner_review_manifest_sha256"
        ],
        "research_rights_state": intake["rights_state"],
        "source_origin": "owner_reviewed_official_research_intake",
        "contains_evaluation_content": False,
        "contains_unseen_content": False,
        "contains_user_content": False,
        "contains_training_content": False,
    }
    return _sealed(value, field="record_content_sha256")


def _validate_source_record(source: Mapping[str, Any]) -> None:
    if set(source) != _RECORD_REQUIRED_FIELDS:
        raise ValueError("ge_source_scope_source_fields_invalid")
    _verify_seal(
        source,
        field="record_content_sha256",
        code="ge_source_scope_source_seal_invalid",
    )
    catalogue_lane = str(source.get("catalogue_lane") or "")
    scope_lane = str(source.get("scope_lane") or "")
    material_type = str(source.get("material_type") or "")
    if (
        source.get("schema") != SOURCE_SCHEMA
        or not str(source.get("source_version_id") or "")
        or not str(source.get("document_id") or "")
        or not str(source.get("authority_identity_id") or "")
        or not str(source.get("stable_identifier") or "")
        or not str(source.get("canonical_url") or "").startswith("https://")
        or int(source.get("body_chunk_count") or 0) < 1
        or not _scope_lane_allowed(
            catalogue_lane=catalogue_lane,
            scope_lane=scope_lane,
            material_type=material_type,
        )
        or source.get("document_status") != "citable"
        or source.get("review_status") != "approved"
        or source.get("retrieval_canonical") is not True
        or source.get("identity_verified") is not True
        or source.get("currentness_eligible") is not True
        or source.get("catalogue_currentness_status") not in _CURRENTNESS_STATUSES
        or not str(source.get("as_of_date") or "")
        or source.get("eligible_for_model_use") is not True
        or source.get("ai_use_policy") in {None, "", "prohibited"}
        or not str(source.get("licence_name") or "")
        or source.get("research_rights_state") not in {"verified", "licensed"}
        or source.get("source_origin") != "owner_reviewed_official_research_intake"
        or source.get("contains_evaluation_content") is not False
        or source.get("contains_unseen_content") is not False
        or source.get("contains_user_content") is not False
        or source.get("contains_training_content") is not False
    ):
        raise ValueError("ge_source_scope_source_boundary_invalid")
    for field in (
        "content_sha256",
        "version_sha256",
        "metadata_sha256",
        "catalogue_review_binding_sha256",
        "currentness_binding_sha256",
        "rights_binding_sha256",
        "research_intake_binding_sha256",
        "research_intake_marker_sha256",
        "ge_source_provenance_chain_sha256",
        "ge_source_provenance_component_sha256",
        "research_owner_review_manifest_sha256",
    ):
        _require_sha256(source.get(field), code="ge_source_scope_source_digest_invalid")


_SCOPE_TO_MATERIAL_LANE = {
    "primary_authority": "primary_authority",
    "official_guidance": "official_guidance",
    "official_procedure": "procedure_rule",
}


def _addition_entries(sources: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "origin": "provenance_qualified_ge_addition",
            "source_version_id": str(source["source_version_id"]),
            "member_sha256": str(source["record_content_sha256"]),
        }
        for source in sources
    ]


def _predecessor_entries(proof: Mapping[str, Any]) -> list[dict[str, Any]]:
    members = proof.get("source_members")
    if not isinstance(members, list) or not all(isinstance(member, dict) for member in members):
        raise ValueError("ge_source_scope_predecessor_members_invalid")
    return [
        {
            "origin": "exact_predecessor_member",
            "source_version_id": str(member["source_version_id"]),
            "member_sha256": source_member_sha256(member),
        }
        for member in members
    ]


def _expansion_member_digest(
    entries: Sequence[Mapping[str, Any]], *, ordered: bool
) -> str:
    values = [dict(entry) for entry in entries]
    if not ordered:
        values.sort(key=lambda entry: str(entry["source_version_id"]))
    schema = (
        "legalbot.ge-successor-member-sequence.v1"
        if ordered
        else "legalbot.ge-successor-member-set.v1"
    )
    return _sha256(_canonical_json({"schema": schema, "members": values}))


def _added_member_set_sha256(sources: Sequence[Mapping[str, Any]]) -> str:
    return _expansion_member_digest(_addition_entries(sources), ordered=False)


def _successor_member_digests(
    predecessor: Mapping[str, Any], sources: Sequence[Mapping[str, Any]]
) -> tuple[str, str]:
    entries = [*_predecessor_entries(predecessor), *_addition_entries(sources)]
    return (
        _expansion_member_digest(entries, ordered=False),
        _expansion_member_digest(entries, ordered=True),
    )


def _successor_lane_bindings(
    predecessor: Mapping[str, Any], sources: Sequence[Mapping[str, Any]]
) -> list[dict[str, str]]:
    raw = predecessor.get("source_lane_bindings")
    if not isinstance(raw, list) or not all(isinstance(value, dict) for value in raw):
        raise ValueError("ge_source_scope_predecessor_lanes_invalid")
    bindings = [dict(value) for value in raw]
    for source in sources:
        scope_lane = str(source["scope_lane"])
        bindings.append(
            {
                "source_version_id": str(source["source_version_id"]),
                "catalogue_lane": str(source["catalogue_lane"]),
                "scope_lane": scope_lane,
                "material_lane": _SCOPE_TO_MATERIAL_LANE[scope_lane],
                "physical_lane": "authority",
            }
        )
    return bindings


def _preservation_proof_sha256(
    predecessor: Mapping[str, Any],
    sources: Sequence[Mapping[str, Any]],
    *,
    successor_member_set_sha256: str,
    successor_member_sequence_sha256: str,
) -> str:
    predecessor_members = predecessor.get("source_members")
    if not isinstance(predecessor_members, list) or not all(
        isinstance(member, dict) for member in predecessor_members
    ):
        raise ValueError("ge_source_scope_predecessor_members_invalid")
    return _sha256(
        _canonical_json(
            {
                "schema": "legalbot.ge-source-preservation-proof.v1",
                "expansion_mode": EXPANSION_MODE,
                "predecessor_proof_sha256": predecessor["content_sha256"],
                "predecessor_build_id": predecessor["build_id"],
                "predecessor_member_sha256s": [
                    source_member_sha256(member) for member in predecessor_members
                ],
                "predecessor_member_sequence_sha256": predecessor[
                    "source_member_sequence_sha256"
                ],
                "added_members": _addition_entries(sources),
                "added_member_set_sha256": _added_member_set_sha256(sources),
                "successor_member_set_sha256": successor_member_set_sha256,
                "successor_member_sequence_sha256": successor_member_sequence_sha256,
                "predecessor_is_exact_successor_prefix": True,
                "source_removal_count": 0,
            }
        )
    )


def prepare_ge_source_scope(
    sources: Sequence[Mapping[str, Any]],
    *,
    database: Database,
    settings: Settings,
    predecessor_build_id: str,
    owner_approval_digest: str | None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Create one strict-superset scope without writing or starting an operation."""

    if not sources:
        raise ValueError("ge_source_scope_requires_nonempty_additions")
    predecessor = load_verified_ge_predecessor(
        settings, database, predecessor_build_id
    )
    ordered = sorted(
        (dict(source) for source in sources),
        key=lambda item: (str(item.get("scope_lane") or ""), str(item.get("source_version_id") or "")),
    )
    for source in ordered:
        _validate_source_record(source)
    source_ids = [str(source["source_version_id"]) for source in ordered]
    document_ids = [str(source["document_id"]) for source in ordered]
    stable_identifiers = [str(source["stable_identifier"]) for source in ordered]
    predecessor_members = predecessor["source_members"]
    if not isinstance(predecessor_members, list):  # pragma: no cover - verified above
        raise ValueError("ge_source_scope_predecessor_members_invalid")
    predecessor_source_ids = [
        str(member["source_version_id"]) for member in predecessor_members
    ]
    predecessor_document_ids = [str(member["document_id"]) for member in predecessor_members]
    predecessor_stable_ids = [str(member["stable_identifier"]) for member in predecessor_members]
    if (
        len(document_ids) != len(set(document_ids))
        or len(stable_identifiers) != len(set(stable_identifiers))
        or set(source_ids) & set(predecessor_source_ids)
        or set(document_ids) & set(predecessor_document_ids)
        or set(stable_identifiers) & set(predecessor_stable_ids)
    ):
        raise ValueError("ge_source_scope_duplicate_or_overlapping_source")
    successor_source_ids = [*predecessor_source_ids, *source_ids]
    if not set(predecessor_source_ids) < set(successor_source_ids):
        raise ValueError("ge_source_scope_successor_not_strict_superset")
    added_member_sha256 = _added_member_set_sha256(ordered)
    successor_member_set, successor_member_sequence = _successor_member_digests(
        predecessor, ordered
    )
    lane_bindings = _successor_lane_bindings(predecessor, ordered)
    preservation_sha256 = _preservation_proof_sha256(
        predecessor,
        ordered,
        successor_member_set_sha256=successor_member_set,
        successor_member_sequence_sha256=successor_member_sequence,
    )
    approval = str(owner_approval_digest or "")
    approved = bool(approval)
    if approved:
        _require_sha256(approval, code="ge_source_scope_owner_approval_digest_invalid")
    payload: dict[str, Any] = {
        "schema": SCOPE_SCHEMA,
        "expansion_mode": EXPANSION_MODE,
        "status": APPROVED_STATUS if approved else PREPARED_STATUS,
        "created_at": created_at or utc_iso(),
        "purpose": "general_enquiries_official_knowledge_expansion",
        "selection_policy": "exact-owner-approved-ge-source-versions-and-lanes",
        "owner_approval_digest": approval or None,
        "external_owner_approval_bound": approved,
        "source_selection_authorized": approved,
        "source_count": len(successor_source_ids),
        "chunk_count": int(predecessor["source_chunk_count"])
        + sum(int(source["body_chunk_count"]) for source in ordered),
        "source_version_id_set_sha256": source_version_id_set_sha256(
            successor_source_ids
        ),
        "successor_source_version_ids": successor_source_ids,
        "successor_member_set_sha256": successor_member_set,
        "successor_member_sequence_sha256": successor_member_sequence,
        "predecessor": predecessor,
        "predecessor_build_id": predecessor["build_id"],
        "predecessor_seal_sha256": predecessor["seal_file_sha256"],
        "predecessor_build_manifest_sha256": predecessor[
            "build_manifest_file_sha256"
        ],
        "predecessor_source_manifest_file_sha256": predecessor[
            "source_manifest_file_sha256"
        ],
        "predecessor_source_manifest_sha256": predecessor[
            "source_manifest_sha256"
        ],
        "predecessor_index_build_record_sha256": predecessor[
            "index_build_record_sha256"
        ],
        "predecessor_source_count": predecessor["source_member_count"],
        "predecessor_chunk_count": predecessor["source_chunk_count"],
        "predecessor_source_version_id_set_sha256": predecessor[
            "source_version_id_set_sha256"
        ],
        "predecessor_member_set_sha256": predecessor["source_member_set_sha256"],
        "predecessor_member_sequence_sha256": predecessor[
            "source_member_sequence_sha256"
        ],
        "added_source_count": len(ordered),
        "added_chunk_count": sum(
            int(source["body_chunk_count"]) for source in ordered
        ),
        "added_source_version_id_set_sha256": source_version_id_set_sha256(source_ids),
        "added_member_set_sha256": added_member_sha256,
        "preservation_proof_sha256": preservation_sha256,
        "source_lane_bindings": lane_bindings,
        "scope_lanes": sorted(
            {str(binding["scope_lane"]) for binding in lane_bindings}
        ),
        "sources": ordered,
        "evaluation_content_included": False,
        "unseen_content_included": False,
        "user_content_included": False,
        "training_content_included": False,
        "index_enqueue_authorized": False,
        "index_build_authorized": False,
        "successor_must_remain_non_active": True,
        "answer_release_eligible": False,
        "active_or_previous_write_authorized": False,
        "promotion_authorized": False,
        "training_authorized": False,
        "unseen_run_authorized": False,
        "live_activation_authorized": False,
    }
    payload["corpus_id"] = ge_source_scope_corpus_id(payload)
    payload["scope_content_sha256"] = _sha256(_canonical_json(payload))
    return payload


def validate_ge_source_scope(scope: Mapping[str, Any], *, require_approved: bool = True) -> str:
    if set(scope) != _SCOPE_REQUIRED_FIELDS:
        raise ValueError("ge_source_scope_fields_invalid")
    scope_sha256 = _verify_seal(
        scope,
        field="scope_content_sha256",
        code="ge_source_scope_seal_invalid",
    )
    approved = scope.get("status") == APPROVED_STATUS
    if (
        scope.get("schema") != SCOPE_SCHEMA
        or scope.get("expansion_mode") != EXPANSION_MODE
        or scope.get("status") not in {APPROVED_STATUS, PREPARED_STATUS}
        or scope.get("purpose") != "general_enquiries_official_knowledge_expansion"
        or scope.get("selection_policy")
        != "exact-owner-approved-ge-source-versions-and-lanes"
        or scope.get("external_owner_approval_bound") is not approved
        or scope.get("source_selection_authorized") is not approved
        or scope.get("evaluation_content_included") is not False
        or scope.get("unseen_content_included") is not False
        or scope.get("user_content_included") is not False
        or scope.get("training_content_included") is not False
        or scope.get("index_enqueue_authorized") is not False
        or scope.get("index_build_authorized") is not False
        or scope.get("successor_must_remain_non_active") is not True
        or scope.get("answer_release_eligible") is not False
        or scope.get("active_or_previous_write_authorized") is not False
        or scope.get("promotion_authorized") is not False
        or scope.get("training_authorized") is not False
        or scope.get("unseen_run_authorized") is not False
        or scope.get("live_activation_authorized") is not False
    ):
        raise ValueError("ge_source_scope_boundary_invalid")
    if require_approved and not approved:
        raise ValueError("ge_source_scope_owner_approval_required")
    if approved:
        _require_sha256(
            scope.get("owner_approval_digest"),
            code="ge_source_scope_owner_approval_digest_invalid",
        )
    elif scope.get("owner_approval_digest") is not None:
        raise ValueError("ge_source_scope_pending_approval_boundary_invalid")
    sources = scope.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("ge_source_scope_additions_invalid")
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("ge_source_scope_source_invalid")
        _validate_source_record(source)
    ordered = sorted(
        sources,
        key=lambda item: (
            str(item.get("scope_lane") or ""),
            str(item.get("source_version_id") or ""),
        ),
    )
    if sources != ordered:
        raise ValueError("ge_source_scope_additions_reordered")
    predecessor = scope.get("predecessor")
    if not isinstance(predecessor, dict):
        raise ValueError("ge_source_scope_predecessor_invalid")
    validate_ge_predecessor_proof(predecessor)
    predecessor_members = predecessor.get("source_members")
    if not isinstance(predecessor_members, list) or not all(
        isinstance(member, dict) for member in predecessor_members
    ):
        raise ValueError("ge_source_scope_predecessor_members_invalid")
    source_ids = [str(source["source_version_id"]) for source in sources]
    document_ids = [str(source["document_id"]) for source in sources]
    stable_identifiers = [str(source["stable_identifier"]) for source in sources]
    predecessor_source_ids = [
        str(member["source_version_id"]) for member in predecessor_members
    ]
    predecessor_document_ids = [str(member["document_id"]) for member in predecessor_members]
    predecessor_stable_ids = [str(member["stable_identifier"]) for member in predecessor_members]
    successor_source_ids = [*predecessor_source_ids, *source_ids]
    successor_member_set, successor_member_sequence = _successor_member_digests(
        predecessor, sources
    )
    lane_bindings = _successor_lane_bindings(predecessor, sources)
    preservation_sha256 = _preservation_proof_sha256(
        predecessor,
        sources,
        successor_member_set_sha256=successor_member_set,
        successor_member_sequence_sha256=successor_member_sequence,
    )
    if (
        len(document_ids) != len(set(document_ids))
        or len(stable_identifiers) != len(set(stable_identifiers))
        or set(source_ids) & set(predecessor_source_ids)
        or set(document_ids) & set(predecessor_document_ids)
        or set(stable_identifiers) & set(predecessor_stable_ids)
        or not set(predecessor_source_ids) < set(successor_source_ids)
        or scope.get("predecessor_build_id") != predecessor.get("build_id")
        or scope.get("predecessor_seal_sha256")
        != predecessor.get("seal_file_sha256")
        or scope.get("predecessor_build_manifest_sha256")
        != predecessor.get("build_manifest_file_sha256")
        or scope.get("predecessor_source_manifest_file_sha256")
        != predecessor.get("source_manifest_file_sha256")
        or scope.get("predecessor_source_manifest_sha256")
        != predecessor.get("source_manifest_sha256")
        or scope.get("predecessor_index_build_record_sha256")
        != predecessor.get("index_build_record_sha256")
        or scope.get("predecessor_source_count") != len(predecessor_members)
        or scope.get("predecessor_chunk_count")
        != predecessor.get("source_chunk_count")
        or scope.get("predecessor_source_version_id_set_sha256")
        != predecessor.get("source_version_id_set_sha256")
        or scope.get("predecessor_member_set_sha256")
        != source_member_set_sha256(predecessor_members)
        or scope.get("predecessor_member_sequence_sha256")
        != source_member_sequence_sha256(predecessor_members)
        or scope.get("added_source_count") != len(sources)
        or scope.get("added_chunk_count")
        != sum(int(source["body_chunk_count"]) for source in sources)
        or scope.get("added_source_version_id_set_sha256")
        != source_version_id_set_sha256(source_ids)
        or scope.get("added_member_set_sha256") != _added_member_set_sha256(sources)
        or scope.get("successor_source_version_ids") != successor_source_ids
        or scope.get("successor_member_set_sha256") != successor_member_set
        or scope.get("successor_member_sequence_sha256")
        != successor_member_sequence
        or scope.get("preservation_proof_sha256") != preservation_sha256
        or scope.get("source_lane_bindings") != lane_bindings
        or scope.get("source_count") != len(successor_source_ids)
        or scope.get("chunk_count")
        != int(predecessor["source_chunk_count"])
        + sum(int(source["body_chunk_count"]) for source in sources)
        or scope.get("source_version_id_set_sha256")
        != source_version_id_set_sha256(successor_source_ids)
        or scope.get("scope_lanes")
        != sorted({str(binding["scope_lane"]) for binding in lane_bindings})
        or scope.get("corpus_id") != ge_source_scope_corpus_id(scope)
    ):
        raise ValueError("ge_source_scope_inventory_invalid")
    return scope_sha256


def _safe_scope_path(settings: Settings, path: Path) -> Path:
    root = ge_source_scope_review_root(settings)
    if not root.is_dir():
        raise ValueError("ge_source_scope_review_root_invalid")
    lexical = path.absolute()
    if lexical.name != SCOPE_FILENAME or lexical.is_symlink() or not lexical.is_file():
        raise ValueError("ge_source_scope_file_invalid")
    cursor = lexical.parent
    while cursor != root:
        if cursor.is_symlink():
            raise ValueError("ge_source_scope_file_invalid")
        if cursor == cursor.parent:
            raise ValueError("ge_source_scope_path_outside_review_root")
        cursor = cursor.parent
    resolved = lexical.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("ge_source_scope_path_outside_review_root") from exc
    return resolved


def load_ge_source_scope(
    settings: Settings,
    database: Database,
    corpus_id: str,
    *,
    scope_path: Path | None = None,
) -> dict[str, Any]:
    """Load one exact approved scope from the repo-local GE review root."""

    if not is_ge_source_scope_corpus(corpus_id):
        raise ValueError("ge_source_scope_corpus_invalid")
    root = ge_source_scope_review_root(settings)
    if scope_path is None:
        if not root.is_dir():
            raise ValueError("ge_source_scope_review_root_invalid")
        candidates: list[Path] = []
        for path in root.glob(f"*/{SCOPE_FILENAME}"):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                value = json.loads(path.read_bytes())
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(value, dict) and value.get("corpus_id") == corpus_id:
                candidates.append(path)
        if len(candidates) != 1:
            raise ValueError("ge_source_scope_not_unique")
        selected = _safe_scope_path(settings, candidates[0])
    else:
        selected = _safe_scope_path(settings, scope_path)
    try:
        scope = json.loads(selected.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("ge_source_scope_file_invalid") from exc
    if not isinstance(scope, dict) or scope.get("corpus_id") != corpus_id:
        raise ValueError("ge_source_scope_file_invalid")
    validate_ge_source_scope(scope, require_approved=True)
    predecessor = scope.get("predecessor")
    if not isinstance(predecessor, dict):  # pragma: no cover - validated above
        raise ValueError("ge_source_scope_predecessor_invalid")
    replay_ge_predecessor_proof(settings, database, predecessor)
    return scope


def _predecessor_row_for_successor(
    database: Database,
    settings: Settings,
    *,
    member: Mapping[str, Any],
    lane_binding: Mapping[str, Any],
) -> dict[str, Any]:
    source_version_id = str(member.get("source_version_id") or "")
    row = _load_catalogue_row(database, source_version_id)
    metadata = _metadata(row.get("metadata_json"))
    expected = {
        "source_version_id": source_version_id,
        "document_id": str(member.get("document_id") or ""),
        "stable_identifier": str(member.get("stable_identifier") or ""),
        "title": str(member.get("title") or ""),
        "canonical_markdown_path": str(member.get("canonical_markdown_path") or ""),
        "version_sha256": str(member.get("version_sha256") or ""),
        "licence_name": str(member.get("licence_name") or ""),
        "canonical_url": str(member.get("canonical_url") or ""),
        "source_date": member.get("source_date"),
        "as_of_date": member.get("as_of_date"),
        "last_updated": str(member.get("last_updated") or ""),
        "content_sha256": str(member.get("content_sha256") or ""),
        "document_status": str(member.get("document_status") or ""),
        "catalogue_lane": str(member.get("lane") or ""),
        "jurisdiction": str(member.get("jurisdiction") or ""),
        "body_chunk_count": int(member.get("body_chunk_count") or 0),
        "currentness_status": str(
            member.get("catalogue_currentness_status")
            or member.get("currentness_status")
            or ""
        ),
    }
    actual = {
        key: (int(row[key] or 0) if key == "body_chunk_count" else row.get(key))
        for key in expected
    }
    actual = {
        key: str(value or "")
        if key
        not in {"body_chunk_count", "source_date", "as_of_date"}
        else value
        for key, value in actual.items()
    }
    if (
        actual != expected
        or row.get("review_status") != "approved"
        or row.get("superseded_by") is not None
        or row.get("duplicate_of") is not None
        or int(row.get("retrieval_canonical") or 0) != 1
        or metadata.get("identity_verified") is not True
        or metadata.get("eligible_for_model_use") is not True
        or str(metadata.get("ai_use_policy") or "") in {"", "prohibited"}
        or lane_binding.get("source_version_id") != source_version_id
        or lane_binding.get("catalogue_lane") != member.get("lane")
        or lane_binding.get("physical_lane") != "authority"
    ):
        raise ValueError("ge_source_scope_predecessor_catalogue_member_changed")
    relative_markdown = PurePosixPath(str(member.get("canonical_markdown_path") or ""))
    if relative_markdown.is_absolute() or ".." in relative_markdown.parts:
        raise ValueError("ge_source_scope_predecessor_markdown_path_invalid")
    markdown = settings.project_root.joinpath(*relative_markdown.parts)
    if markdown.is_symlink() or not markdown.is_file() or markdown.stat().st_size < 1:
        raise ValueError("ge_source_scope_predecessor_markdown_unavailable")
    result = dict(row)
    result["body_chunk_count"] = expected["body_chunk_count"]
    result["unfiltered_body_chunk_count"] = expected["body_chunk_count"]
    result["lane"] = result.pop("catalogue_lane")
    result["ge_scope_lane"] = str(lane_binding.get("scope_lane") or "")
    result["ge_predecessor_source_member"] = dict(member)
    result["ge_predecessor_source_member_sha256"] = source_member_sha256(member)
    result["answer_release_eligible_in_successor"] = False
    return result


def select_ge_source_scope_rows(
    database: Database,
    settings: Settings,
    *,
    corpus_id: str,
    max_chunks: int | None,
    preferred_small_first: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Select only exact current catalogue rows bound by an approved GE scope."""

    if max_chunks is not None or preferred_small_first:
        raise ValueError("ge_source_scope_cannot_be_reordered_or_truncated")
    scope = load_ge_source_scope(settings, database, corpus_id)
    selected: list[dict[str, Any]] = []
    predecessor = scope["predecessor"]
    predecessor_members = predecessor["source_members"]
    predecessor_bindings = predecessor["source_lane_bindings"]
    if len(predecessor_members) != len(predecessor_bindings):
        raise ValueError("ge_source_scope_predecessor_inventory_changed")
    for member, lane_binding in zip(
        predecessor_members, predecessor_bindings, strict=True
    ):
        selected.append(
            _predecessor_row_for_successor(
                database,
                settings,
                member=member,
                lane_binding=lane_binding,
            )
        )
    for frozen in scope["sources"]:
        current = snapshot_ge_source_binding(
            database,
            settings,
            source_version_id=str(frozen["source_version_id"]),
            scope_lane=str(frozen["scope_lane"]),
        )
        if current != frozen:
            raise ValueError("ge_source_scope_catalogue_binding_changed")
        row = _load_catalogue_row(database, str(frozen["source_version_id"]))
        row["body_chunk_count"] = int(frozen["body_chunk_count"])
        row["unfiltered_body_chunk_count"] = int(frozen["body_chunk_count"])
        row["lane"] = row.pop("catalogue_lane")
        row["ge_scope_lane"] = frozen["scope_lane"]
        row["ge_scope_record_content_sha256"] = frozen["record_content_sha256"]
        row["ge_scope_content_sha256"] = scope["scope_content_sha256"]
        row["ge_owner_approval_digest"] = scope["owner_approval_digest"]
        row["answer_release_eligible_in_successor"] = False
        selected.append(row)
    if (
        len(selected) != scope["source_count"]
        or sum(int(row["body_chunk_count"]) for row in selected) != scope["chunk_count"]
        or [str(row["source_version_id"]) for row in selected]
        != scope["successor_source_version_ids"]
        or source_version_id_set_sha256(
            [str(row["source_version_id"]) for row in selected]
        )
        != scope["source_version_id_set_sha256"]
    ):
        raise ValueError("ge_source_scope_catalogue_inventory_changed")
    return selected, scope


__all__ = [
    "APPROVED_STATUS",
    "CORPUS_PREFIX",
    "PREPARED_STATUS",
    "SCOPE_FILENAME",
    "SCOPE_REVIEW_ROOT_RELATIVE",
    "SCOPE_SCHEMA",
    "ge_source_scope_corpus_id",
    "ge_source_scope_identity_sha256",
    "ge_source_scope_review_root",
    "is_ge_source_scope_corpus",
    "load_ge_source_scope",
    "prepare_ge_source_scope",
    "select_ge_source_scope_rows",
    "snapshot_ge_source_binding",
    "validate_ge_source_scope",
]
